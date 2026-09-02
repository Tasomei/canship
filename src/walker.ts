/**
 * Project file traversal.
 *
 * Key decision: **if the target is a git repository, ask git for the file list**
 * (`git ls-files -c -o --exclude-standard`).
 * That hands .gitignore parsing back to git itself — zero code, zero mistakes,
 * and we avoid reimplementing those notoriously fiddly matching rules.
 * Only non-git projects fall back to walking the tree by hand.
 */

import { readdirSync, readFileSync, statSync, lstatSync, openSync, readSync, closeSync } from 'node:fs'
import { join, relative, sep, extname, basename } from 'node:path'
import type { GitStatus, ScanFile, SkippedFile } from './types.js'
import { execGitSync, hasContainedGitMetadata, hasGitMetadataAbove, resolveGitExecutable } from './git.js'

/**
 * Per-file size cap.
 *
 * This used to be 512 KiB, which is smaller than plenty of hand-written files —
 * a long SQL migration, a generated types file, a fat JSON config. Anything
 * above it was skipped in silence, so a key sitting at the end of such a file
 * produced a clean report. The cap is now high enough that real source is
 * always read, and whatever still exceeds it is reported as skipped rather
 * than quietly dropped.
 */
const MAX_FILE_BYTES = 2 * 1024 * 1024

/**
 * How deep the walk goes — for every purpose it serves.
 *
 * Set from what real projects actually look like rather than from a guess. At
 * eight, two healthy repositories reported an incomplete scan on their first
 * run: a Next.js app router with route groups reaches nine levels without
 * anyone trying — `apps/dashboard/src/app/[locale]/(app)/(sidebar)/account/…`
 * is ordinary. A limit that fires on ordinary projects is a warning people
 * learn to ignore, which costs more than the limit saves.
 *
 * One walk now answers two questions, so this bounds both: the hunt for
 * gitignored credential files, and — for a non-git project, where git cannot
 * supply the list — every file that gets scanned at all. That second use is
 * newer and stricter than what it replaced, which had no limit; sixteen is
 * kept deliberately rather than inherited, on the grounds that it sits seven
 * levels clear of what the deepest ordinary layout reaches, and that reaching
 * it is never silent.
 *
 * The cap still exists, and reaching it still produces a receipt. It is simply
 * far enough out that reaching it means something.
 */
const MAX_WALK_DEPTH = 16

/** Directories skipped outright when walking by hand */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  '.svelte-kit',
  '.turbo',
  '.vercel',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  '.cache',
  // Build output and tool caches from ecosystems beyond JavaScript. Walking
  // these to look for credential files is pure cost.
  '.dart_tool',
  '.gradle',
  'Pods',
  'target',
  'obj',
  '.terraform',
  '.serverless',
  '.yarn',
  '.pnpm-store',
])

/**
 * Third-party code that happens to live in the repository.
 *
 * Split out of SKIP_DIRS because SKIP_DIRS only ever governed the hand-rolled
 * walk. `git ls-files` answers without consulting it, so whether a dependency
 * tree got scanned came down to whether `.git` existed: the same directory
 * holding `vendor/lib/dep.ts` reported a hardcoded key when it was a git
 * repository and nothing when it was not.
 *
 * Only the dependency directories are applied to both paths, not the whole of
 * SKIP_DIRS. Build output is normally gitignored, so git does not list it
 * anyway, and a project that *does* commit its `dist/` is committing its own
 * code — the vendored trees below are the ones that are somebody else's.
 * Go and Composer projects routinely commit `vendor/`, and reporting the
 * example keys in a third-party test fixture is the false positive the README
 * says costs the user's trust for good.
 */
const VENDORED_DIRS = new Set(['node_modules', 'vendor', 'Pods', '.yarn', '.pnpm-store'])

/** Whether a path runs through a directory holding somebody else's code */
function isVendored(relPath: string): boolean {
  return relPath.split('/').some((segment) => VENDORED_DIRS.has(segment))
}

/**
 * Extensions included in the scan.
 *
 * This list can be wider than v0.1's target stack (Next.js + Supabase): the
 * "hardcoded secret in source" rule is plain text matching and completely
 * language-agnostic, so including mobile and backend languages adds no false
 * positive risk.
 */
const SCAN_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.rb', '.php', '.java', '.rs', '.cs',
  '.dart', '.kt', '.kts', '.swift',
  '.json', '.yaml', '.yml', '.toml',
  '.sql',
  // Firebase security rules (firestore.rules / storage.rules)
  '.rules',
  '.env', '.sh', '.bash', '.ps1',
  '.svelte', '.vue', '.astro',
])

/**
 * Extensions whose contents *are* a credential.
 *
 * The README promised private-key detection long before this list existed, and
 * `.pem` was not in it — so the single most common way to ship a private key
 * was invisible. Certificates (.crt, .cer) are deliberately absent: they are
 * the public half and leak nothing.
 */
const CREDENTIAL_EXTENSIONS = new Set(['.pem', '.key', '.ppk', '.asc', '.p8', '.pkcs8'])

/** Configuration formats that routinely hold connection strings and tokens */
const CONFIG_EXTENSIONS = new Set(['.properties', '.ini', '.conf', '.cfg', '.tfvars', '.tf'])

/**
 * Files where the *name* is the tell and there is no extension to match on.
 * Every one of these is a well-known place to keep a credential, and none of
 * them would be reached by an extension list.
 */
const CREDENTIAL_FILENAMES = new Set([
  '.npmrc',
  '.netrc',
  '_netrc',
  '.pgpass',
  '.htpasswd',
  '.pypirc',
  '.dockercfg',
  '.git-credentials',
  'credentials',
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
])

/**
 * How much of an unknown file to read before deciding what kind of file it is.
 *
 * This window answers one question — text or binary — and nothing else. It used
 * to decide whether the file was worth scanning at all: the probe looked for a
 * credential inside these 4 KiB and the file was opened for real only if it
 * found one. A `terraform.tfstate` with its password at byte 5,000 was
 * therefore never scanned, never listed in `skipped`, and left `partial` false
 * — a silent miss of precisely the file type the probe was added for, and a
 * cap that the README promises is always reported.
 *
 * So the gate is now the cheap, decidable question, and a file that passes it
 * is read in full under MAX_FILE_BYTES like any other. That limit *is*
 * reported when it bites.
 */
const PROBE_BYTES = 4096

/**
 * The escape hatch, written by the user in their own file.
 *
 * It exists because of what changed around it: secret-shaped strings in test
 * directories are no longer waved through, since a real key in `test/` is just
 * as stolen as one anywhere else. That is the right default, and it needs a way
 * out for the projects where the fakes are the point — security fixtures,
 * teaching material, canship's own test data.
 *
 * Deliberately explicit and deliberately per-file: a directory-wide rule is the
 * blanket exemption this replaces.
 *
 * It has to be the whole content of its line. A plain substring search looked
 * fine until canship scanned itself and found that walker.ts and secrets.ts had
 * silently excluded themselves — both merely *mention* the marker, in a comment
 * explaining it. The same trap catches any documentation about this feature,
 * and it turns one stray word in a comment into a blindfold over a whole file.
 */
const IGNORE_FILE_MARKER =
  /^\s*(?:\/\/|#|--|\*\/?|\/\*|<!--)?\s*canship-ignore-file\s*(?:\*\/|-->)?\s*$/

/** Whether any single line of the file is the opt-out marker and nothing else */
function hasIgnoreMarker(lines: string[]): boolean {
  return lines.some((line) => IGNORE_FILE_MARKER.test(line))
}

/** Bun's lockfile is binary and cannot be read as text; every other lockfile is text and is scanned like anything else */
const SKIP_FILENAMES = new Set(['bun.lockb'])

/**
 * Whether a filename belongs to the .env family (.env / .env.local / ...).
 *
 * Compared in lower case. Windows and macOS open `.ENV` and `.env` as the same
 * file, so a case-sensitive check meant a file the runtime happily loads was
 * neither treated as an env file nor picked up by extension — it simply was
 * not there.
 */
export function isEnvFile(name: string): boolean {
  const lower = name.toLowerCase()
  return lower === '.env' || lower.startsWith('.env.')
}

/** Whether this file should be scanned at all */
function shouldScan(relPath: string): boolean {
  const name = basename(relPath)
  if (SKIP_FILENAMES.has(name)) return false
  // .env files have no conventional extension, so let them through separately
  if (isEnvFile(name)) return true
  if (CREDENTIAL_FILENAMES.has(name)) return true
  const ext = extname(name).toLowerCase()
  return SCAN_EXTENSIONS.has(ext) || CREDENTIAL_EXTENSIONS.has(ext) || CONFIG_EXTENSIONS.has(ext)
}

/**
 * Extensions that are certainly not text, so there is nothing to look at.
 *
 * A denylist rather than an allowlist on purpose: being wrong here costs one
 * wasted 4 KB read, while being wrong in the other direction costs a missed
 * credential. Anything not named here gets looked at.
 */
const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.bmp', '.ico', '.icns', '.tiff',
  '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.mov', '.avi', '.flac',
  '.zip', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.tar', '.jar', '.war',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.wasm', '.class', '.pyc', '.o', '.a',
  '.db', '.sqlite', '.sqlite3', '.mo',
])

type ProbeResult =
  | { kind: 'text' }
  | { kind: 'binary' }
  | { kind: 'unreadable'; detail: string }

/**
 * Read the start of an unknown file, and decide only whether it is text,
 * binary, or unreadable.
 *
 * UTF-16 text is full of NUL bytes, so the BOM has to be recognised first —
 * otherwise the file is called binary before the BOM-aware decoder ever runs.
 */
function probeFileType(absPath: string): ProbeResult {
  let fd: number | null = null
  try {
    fd = openSync(absPath, 'r')
    const buf = Buffer.alloc(PROBE_BYTES)
    const read = readSync(fd, buf, 0, PROBE_BYTES, 0)
    const head = buf.subarray(0, read)
    const hasTextBom =
      (head.length >= 2 && head[0] === 0xff && head[1] === 0xfe) ||
      (head.length >= 2 && head[0] === 0xfe && head[1] === 0xff) ||
      (head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf)
    if (hasTextBom) return { kind: 'text' }
    return head.includes(0) ? { kind: 'binary' } : { kind: 'text' }
  } catch (err) {
    return {
      kind: 'unreadable',
      detail: String(err instanceof Error ? err.message : err),
    }
  } finally {
    if (fd !== null) {
      try {
        closeSync(fd)
      } catch {
        /* ignore */
      }
    }
  }
}

/**
 * Prose formats, left out of the probe deliberately.
 *
 * Documentation spells out secret-shaped strings as examples constantly — a
 * README showing `export OPENAI_API_KEY=sk-proj-…` is doing its job — and this
 * project already decided those are not findings. That decision is pinned by
 * the clean fixture, whose README says so in as many words. `.txt` is not in
 * here: it is a generic dump format, not a prose one, and `keys.txt` is a real
 * thing people have. What turns up in one is still reported quietly, since
 * isExampleContext covers `.txt` and holds it at lower confidence.
 */
const PROSE_EXTENSIONS = new Set(['.md', '.mdx', '.rst', '.adoc'])

/**
 * The same decision for prose that carries no extension to decide by.
 *
 * `README`, `LICENSE` and `CHANGELOG` are conventionally written bare, and the
 * probe cannot tell them apart from a data file by name alone. It did not have
 * to while it was reading them looking for a credential and finding none; now
 * that every text file it accepts is scanned in full, they would arrive in the
 * scan with exactly the documentation examples PROSE_EXTENSIONS exists to keep
 * out. Matched on the stem, so `README.txt` is covered too — `.txt` stays
 * probed for everything else, because `keys.txt` is a real thing people have.
 */
const PROSE_FILENAMES = new Set([
  'README', 'LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS', 'CONTRIBUTORS',
  'CONTRIBUTING', 'CHANGELOG', 'CHANGES', 'HISTORY', 'CODEOWNERS', 'CODE_OF_CONDUCT',
])

/**
 * Whether a file is worth looking inside despite its name saying nothing.
 * Known-scannable names are already handled; known-binary ones cannot hold
 * readable text, and prose is excluded above. Everything left over gets probed.
 */
function isWorthProbing(relPath: string): boolean {
  const name = basename(relPath)
  if (SKIP_FILENAMES.has(name)) return false
  if (shouldScan(relPath)) return false
  const ext = extname(name).toLowerCase()
  if (PROSE_FILENAMES.has(basename(name, extname(name)).toUpperCase())) return false
  return !BINARY_EXTENSIONS.has(ext) && !PROSE_EXTENSIONS.has(ext)
}

/**
 * Whether the target is a git repository — and, crucially, whether that
 * question could be answered at all.
 *
 * This used to return a plain boolean, catching every failure as `false`. That
 * made "git is not installed", "git refuses this repository as dubiously
 * owned", and "this is not a repository" one answer, and the git-history rule
 * skips itself on that answer. The result was a repository with a live key in
 * its history scanning to zero findings, zero errors, `partial: false` and exit
 * 0 — a green tick, produced by a check that never ran. That is the exact
 * failure the README puts at the centre of this tool.
 *
 * So the three cases are kept apart. Only `not-a-repo` is silent; `unavailable`
 * is something the caller is obliged to be loud about.
 */
export function detectGitRepo(root: string, gitExecutable: string | null = resolveGitExecutable(root)): GitStatus {
  const hasMetadata = hasGitMetadataAbove(root)
  if (hasMetadata && !hasContainedGitMetadata(root)) return 'unavailable'
  if (gitExecutable === null) return hasMetadata ? 'unavailable' : 'not-a-repo'
  try {
    const out = execGitSync(gitExecutable, root, ['rev-parse', '--is-inside-work-tree'], { stderr: 'pipe' })
    return out.trim() === 'true' ? 'repo' : 'not-a-repo'
  } catch {
    // git could not answer. If there is no .git anywhere above, there is
    // genuinely no repository here and silence is correct. If there is one,
    // something stopped git from reading it, and reporting nothing would be a
    // lie by omission.
    return hasGitMetadataAbove(root) ? 'unavailable' : 'not-a-repo'
  }
}

interface GitFileList {
  files: string[]
  /** Nested repositories and submodules, which git reports as a single entry */
  nestedRepositories: string[]
}

/**
 * Get the file list from git: tracked files plus untracked ones that are not
 * ignored. Returns null on failure so the caller can fall back to walking.
 */
function listViaGit(root: string, gitExecutable: string | null): GitFileList | null {
  if (gitExecutable === null) return null
  try {
    const out = execGitSync(gitExecutable, root, ['ls-files', '-c', '-o', '--exclude-standard', '-z'])
    const staged = execGitSync(gitExecutable, root, ['ls-files', '--stage', '-z'])

    const nested = new Set<string>()
    for (const record of staged.split('\0')) {
      const match = /^160000 [0-9a-f]+ \d\t(.+)$/.exec(record)
      if (match?.[1]) nested.add(match[1])
    }

    const files: string[] = []
    for (const path of out.split('\0').filter(Boolean)) {
      // An untracked nested repository comes back as one directory entry with a
      // trailing slash.
      if (path.endsWith('/')) {
        nested.add(path.replace(/\/+$/, ''))
      } else if (!nested.has(path)) {
        files.push(path)
      }
    }
    return { files, nestedRepositories: [...nested] }
  } catch {
    return null
  }
}

/**
 * Credential files that git will not list.
 *
 * `git ls-files --exclude-standard` hides ignored files, and ignoring
 * credentials is exactly what people are told to do — so the files most likely
 * to hold a secret are precisely the ones git leaves out. They have to be found
 * by walking.
 *
 * The previous version looked in the project root plus a fixed list of
 * directory names, one level deep. A monorepo keeping `services/api/.env` was
 * invisible to it, and reported zero findings with total confidence.
 *
 * Extensionless files get a look inside rather than a guess from the name: a
 * deploy key called `deploy_key` matches no pattern anyone would think to
 * write down.
 */
interface WalkResult {
  /** Every file the walk found, relative to root with / separators */
  all: string[]
  /** Those chosen by looking inside rather than by their name */
  forced: string[]
}

/**
 * One walk, two answers.
 *
 * There used to be two walkers over the same tree — this one and a plain
 * a plain file lister for non-git projects — with the same SKIP_DIRS, the same
 * readdirSync try/catch and the same `skipped.push({reason:
 * 'directory-unreadable'})`, differing only in which files they kept. A non-git
 * project paid for the whole tree twice, and an unreadable directory was
 * recorded twice, so the report told the reader that two directories could not
 * be listed when only one existed.
 *
 * The depth cap now applies to the full list as well as the credential hunt.
 * That is a change, and the right one: reaching it already leaves a receipt, so
 * the limit is disclosed rather than silent either way.
 */
function walkTree(root: string, skipped: SkippedFile[], wantAll: boolean): WalkResult {
  const all: string[] = []
  const found: string[] = []

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_WALK_DEPTH) {
      // A depth cap is fine as resource protection. Reaching one silently is
      // not: everything below this point went unexamined, and without a
      // receipt the report still claims to have covered the project. A .env
      // one level past the cap used to vanish with no trace at all.
      skipped.push({
        path: relative(root, dir).split(sep).join('/') || '.',
        reason: 'directory-unreadable',
        detail: `deeper than the ${MAX_WALK_DEPTH}-level search limit`,
      })
      return
    }
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch (err) {
      if (!isMissing(err)) {
        skipped.push({
          path: relative(root, dir).split(sep).join('/') || '.',
          reason: 'directory-unreadable',
          detail: String(err instanceof Error ? err.message : err),
        })
      }
      return
    }

    for (const entry of entries) {
      const full = join(dir, entry.name)
      const rel = relative(root, full).split(sep).join('/')
      if (entry.isSymbolicLink()) {
        // Never followed: the scan must not silently leave the directory it was
        // pointed at.
        //
        // Silent for the names a real directory is silent for, which means
        // SKIP_DIRS rather than only VENDORED_DIRS. This branch runs before the
        // isDirectory() check below, so the narrower set let a symlinked `dist`,
        // `.next` or `venv` — twenty names a real directory skips without a
        // word — file a receipt, turn the scan partial, and exit 3 on a project
        // with nothing wrong with it. Whether the build output is a link or a
        // directory is not a fact about the project's security.
        if (!SKIP_DIRS.has(entry.name)) {
          skipped.push({ path: rel, reason: 'symlink', detail: 'symbolic links are not followed' })
        }
        continue
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue
        walk(full, depth + 1)
        continue
      }
      if (!entry.isFile()) continue

      // git answers the "every file" question when it can, and then this array
      // is built only to be thrown away.
      if (wantAll) all.push(rel)

      let isCandidate =
        isEnvFile(entry.name) ||
        CREDENTIAL_FILENAMES.has(entry.name) ||
        CREDENTIAL_EXTENSIONS.has(extname(entry.name).toLowerCase())

      // The probe window is read only when the name cannot decide. Unreadable is
      // not "binary", and it owes the reader a receipt either way.
      if (!isCandidate && isWorthProbing(rel)) {
        const probe = probeFileType(full)
        if (probe.kind === 'text') isCandidate = true
        else if (probe.kind === 'unreadable') {
          skipped.push({ path: rel, reason: 'unreadable', detail: probe.detail })
        }
      }

      if (isCandidate) found.push(rel)
    }
  }

  walk(root, 0)
  return { all, forced: found }
}

/** Whether a filesystem error means "not there" rather than "could not read it" */
function isMissing(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/**
 * Decode a file, honouring a byte-order mark.
 *
 * Reading everything as UTF-8 looks harmless until a UTF-16 file turns up.
 * Its ASCII characters arrive interleaved with zero bytes, the binary check
 * sees those and writes the file off, and it is never scanned. Vercel's own Next.js + Supabase template ships
 * types_db.ts in UTF-16 LE, so this is not a hypothetical: the flagship
 * template of the exact stack canship targets had a file it could not read.
 */
function decodeText(buf: Buffer): string {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le')
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    // Big-endian. Node decodes only little-endian, so swap the pairs first.
    const body = Buffer.from(buf.subarray(2))
    if (body.length % 2 !== 0) return buf.toString('utf8')
    body.swap16()
    return body.toString('utf16le')
  }
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return buf.subarray(3).toString('utf8')
  }
  return buf.toString('utf8')
}

/** Rough binary check: a NUL byte is a reliable enough tell */
function looksBinary(content: string): boolean {
  return content.includes('\0')
}

/**
 * Whether the *filename* declares the file to be a template — the
 * `.env.example` family and friends.
 *
 * Split out of isExampleContext because a committed env file answers the two
 * halves of that question differently, and collapsing them cost a real
 * finding. A file *named* `.env.example` is meant to be committed and leaks
 * nothing: it is the file people publish instead of the one holding the keys.
 * A real `.env` that merely *sits in* `tests/` is a committed `.env` like any
 * other — the directory is a reason to doubt the key is real, not a reason to
 * believe the file is a template.
 */
export function isTemplateName(relPath: string): boolean {
  const name = basename(relPath)
  if (/\.(example|sample|template|dist)$/i.test(name)) return true
  if (/^\.env\.(example|sample|template)$/i.test(name)) return true
  return false
}

/**
 * Whether a file is a context where secret-shaped strings are normal:
 * tests, fixtures, examples, documentation.
 *
 * Decided here so every rule shares one definition of the exemption.
 */
export function isExampleContext(relPath: string): boolean {
  const name = basename(relPath)
  if (isTemplateName(relPath)) return true
  if (/\.(md|mdx|txt|rst)$/i.test(name)) return true
  if (/(^|\/)(test|tests|__tests__|spec|specs|fixtures?|mocks?|__mocks__|e2e|examples?|docs?)\//i.test(relPath)) {
    return true
  }
  if (/\.(test|spec)\.[jt]sx?$/i.test(name)) return true
  return false
}

/** What a traversal produced: the files it read, and the ones it could not */
export interface CollectResult {
  files: ScanFile[]
  skipped: SkippedFile[]
  /**
   * How many listed paths were dropped for running through a dependency tree.
   *
   * Counted rather than passed over, because the exclusion is a judgement the
   * user did not make and cannot see: it is not an error, so it does not belong
   * in `skipped`, but a scanner that quietly ignores part of a repository owes
   * the reader a sentence about it.
   */
  vendored: number
  /** Files the user opted out of with the canship-ignore-file marker */
  ignored: string[]
}

/**
 * Collect every file worth scanning and read it into memory.
 *
 * Anything found but not read is returned in `skipped` rather than dropped.
 * The distinction between "checked and clean" and "never looked at" is the
 * whole point: a scanner that cannot tell them apart will eventually tell
 * someone their app is fine because it failed to open the file holding the key.
 */
export function collectFiles(
  root: string,
  isGitRepo: boolean,
  gitExecutable: string | null = resolveGitExecutable(root),
): CollectResult {
  const skipped: SkippedFile[] = []
  const ignored: string[] = []
  // One walk of the tree, whatever git can or cannot say. It answers both
  // questions at once — every file, and the credential files git hides —
  // because two walkers over the same directories charged twice for the I/O
  // and recorded an unreadable directory twice in `skipped`.
  const fromGit = isGitRepo ? listViaGit(root, gitExecutable) : null
  const walked = walkTree(root, skipped, fromGit === null)
  const listed = fromGit?.files ?? walked.all

  // Merge git's list with the credential files git hides, listing nothing twice.
  //
  // Vendored trees are dropped here rather than inside either lister, because
  // that is the one place both answers meet. Applied in only one of them, the
  // same repository covered different files depending on whether git could
  // answer for it.
  // Partitioned in one pass. Filtering the list twice asked the same question
  // of every path twice over, and the two calls could drift apart.
  const candidates = new Set<string>()
  let vendored = 0
  for (const path of fromGit?.nestedRepositories ?? []) {
    if (isVendored(path)) {
      vendored++
      continue
    }
    skipped.push({
      path,
      reason: 'nested-repository',
      detail: 'Git exposes this directory as one opaque entry; run canship on that directory separately',
    })
  }
  for (const path of listed) {
    if (isVendored(path)) vendored++
    else candidates.add(path)
  }
  // Paths chosen by looking at the file rather than at its name. They bypass
  // shouldScan, which only knows about extensions — an extensionless deploy
  // key would otherwise be discovered and then thrown away again.
  const forced = new Set<string>()
  for (const hidden of walked.forced) {
    candidates.add(hidden)
    forced.add(hidden)
  }

  const files: ScanFile[] = []
  for (const relPath of candidates) {
    if (!forced.has(relPath) && !shouldScan(relPath)) continue

    const absPath = join(root, relPath)
    let content: string
    try {
      if (lstatSync(absPath).isSymbolicLink()) {
        // git lists tracked links, so the same boundary is drawn here — without
        // filing the receipt the walk may already have filed.
        if (!skipped.some((entry) => entry.path === relPath && entry.reason === 'symlink')) {
          skipped.push({ path: relPath, reason: 'symlink', detail: 'symbolic links are not followed' })
        }
        continue
      }
      const size = statSync(absPath).size
      if (size > MAX_FILE_BYTES) {
        skipped.push({
          path: relPath,
          reason: 'too-large',
          detail: `${Math.round(size / 1024)} KB, cap is ${MAX_FILE_BYTES / 1024} KB`,
        })
        continue
      }
      content = decodeText(readFileSync(absPath))
    } catch (err) {
      // A file git still lists but that is gone from disk has no contents to
      // miss — this is the ordinary state of any repository with uncommitted
      // deletions, and one real project produced 160 of them. Reporting those
      // as an incomplete scan would be its own false alarm.
      //
      // Anything else — permission denied, a device error, a lock — means the
      // file is there and its contents are unknown, which is not the same as
      // safe.
      if (!isMissing(err)) {
        skipped.push({
          path: relPath,
          reason: 'unreadable',
          detail: String(err instanceof Error ? err.message : err),
        })
      }
      continue
    }
    if (looksBinary(content)) {
      skipped.push({ path: relPath, reason: 'binary' })
      continue
    }
    const lines = content.split(/\r?\n/)
    // An opt-out the user wrote themselves. Not a `skipped` entry — nothing
    // went wrong — but recorded all the same, because a whole file dropping
    // out of the scan should never be invisible. That is the same mistake in a
    // friendlier costume.
    if (hasIgnoreMarker(lines)) {
      ignored.push(relPath)
      continue
    }

    files.push({
      path: relPath,
      content,
      lines,
      isExampleContext: isExampleContext(relPath),
    })
  }

  return { files, skipped, ignored, vendored }
}
