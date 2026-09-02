/**
 * P0-4: .env files committed to git.
 *
 * This rule has to inspect **history**, not just the current state.
 * The usual reaction to discovering a committed .env is `git rm --cached .env`
 * followed by another commit. The file disappears from the working tree while
 * every version of it stays in history. If the repository was ever pushed to a
 * public remote, those keys have already been scraped. A tool that only looks
 * at the current state would report "all clear", which is worse than not
 * checking at all.
 */

import type { Finding, ProjectRule, ScanContext } from '../types.js'
import { isEnvFile, isExampleContext, isTemplateName } from '../walker.js'
import { basename } from 'node:path'
import { findKnownSecret, isPlaceholder } from './patterns.js'
import { looksClearlyPrivate, looksIntentionallyPublic, publicPrefixOf } from './framework.js'
import { parseEnvLine } from './envfile.js'
import { execGitSync, hasContainedGitMetadata } from '../git.js'

/**
 * Template files are meant to be committed and are not a leak.
 *
 * This delegates to the project-wide definition rather than keeping a local
 * one. It used to keep a local one, matching only `.env.example` exactly, and
 * running canship against real repositories showed what that costs: three of
 * six well-known Next.js starters were reported for committing
 * `.env.local.example`, including Vercel's own template. The shared helper
 * already handled it — an exemption that lives in one rule is an exemption the
 * next rule forgets.
 *
 * What it deliberately no longer covers is *location*. This used to ask
 * isExampleContext, which also waves through anything under `test/`, `e2e/`,
 * `fixtures/` or `docs/`, and a committed `e2e/.env` then vanished from the
 * report entirely — not downgraded, absent. That is the worst place to be
 * silent: once the file is deleted from the working tree, no other rule can
 * read it, so this one going quiet means nothing reports it at all. A green
 * tick over a live key in `e2e/.env` is precisely what the header comment
 * calls worse than not checking.
 */
function isEnvTemplate(path: string): boolean {
  return isTemplateName(path)
}

/**
 * Whether this env file merely *lives* where fake keys are normal.
 *
 * A confidence cap, not an exemption — the same signal the secrets rule uses
 * for the same reason. A real key committed to `test/` is exactly as stolen as
 * one in `src/`; it is just less likely to be real, which is what `likely`
 * means. Reported quietly keeps it out of the default output and out of the
 * exit code, so the noise stays opt-in while the finding still exists.
 */
function isScaffolding(path: string): boolean {
  return isExampleContext(path)
}

/**
 * Whether a path can be pasted into a shell command as itself.
 *
 * The fix steps are meant to be *run*, and one of them is a git command with
 * the offending path in it — a path chosen by whoever added the file. Filenames
 * may legally contain semicolons, backticks, `$(…)`, newlines and spaces, so
 * interpolating one produced `git rm --cached x;whoami;#/.env`. canship never
 * runs that, but it prints it for the user to run and `--fix-prompt` hands it
 * to an assistant that may hold a terminal. A leading dash is the quiet half of
 * the same problem: git would read the name as an option.
 *
 * Anything outside this set gets prose instead of a command. Refusing to spell
 * out a runnable line is a small cost; the alternative is shipping one that
 * runs something else.
 */
function shellSafePath(path: string): boolean {
  return /^[A-Za-z0-9._/-]+$/.test(path) && !path.startsWith('-')
}

/** The "stop tracking it" step, as a command only when that is safe to do */
function untrackStep(path: string): string {
  return shellSafePath(path)
    ? `Stop tracking it: git rm --cached -- ${path}`
    : `Stop tracking it with "git rm --cached", putting the filename after a -- separator and quoting it ` +
        `for your shell. It is not written out as a runnable command here because the name contains ` +
        `characters a shell would act on instead of treating as part of a filename.`
}

/** Appended when the finding is only reported because the directory is not an excuse */
const SCAFFOLD_NOTE =
  `This file sits in a test, fixture, example or docs directory, where fake keys are normal — so ` +
  `this is probably scaffolding rather than a leak, and it is reported quietly for that reason. It is ` +
  `not skipped outright because a real key committed to a test directory is exactly as stolen as one in ` +
  `src/. If the values in it are deliberately fake, put canship-ignore-file on a line of its own in that ` +
  `file and canship will skip it and say so.`

/**
 * How strong the evidence is that a committed env file holds a credential.
 *
 * "Any value at all" was the previous bar, and it produced a certain-grade
 * leak report for a file whose entire contents were `NODE_ENV=development`.
 * A rule that cries wolf at the top severity teaches people to skip it, which
 * is expensive here — when this one is right, it is very right.
 *
 *   proof   a value in a known credential format, or a value under a name that
 *           says credential. Nothing to argue about.
 *   hint    something substantial that is neither public nor a placeholder.
 *           Worth mentioning, not worth shouting about.
 *   none    only public values, placeholders, or short settings.
 */
type Evidence = 'proof' | 'hint' | 'none'

/** Long enough that a stray setting like an environment name does not qualify */
const SUBSTANTIAL_VALUE = 12

function evidenceIn(lines: string[]): Evidence {
  let best: Evidence = 'none'

  for (const raw of lines) {
    // Parsed by the same code the exposure rule uses. This used to be a local
    // three-line version that stripped the outer quotes and nothing else, so a
    // trailing `# production` stayed glued to the value — see envfile.ts for
    // what that cost.
    const assignment = parseEnvLine(raw)
    if (!assignment) continue

    const key = assignment.key.toUpperCase()
    const value = assignment.value

    if (!value || isPlaceholder(value)) continue

    // A value in a known credential format is a credential, whatever it is
    // called. Asking about the name first meant that
    // NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_… was dismissed as a public value:
    // the name said browser, and nothing ever looked at what was in it.
    const known = findKnownSecret(value)
    if (known) {
      // A format the provider designs to be public in a front end is not evidence
      // of a committed credential.
      if (known.publicByDesign) continue
      return 'proof'
    }

    // Only now does the name get to excuse it. Values meant for the browser
    // are public by design, and committing one leaks nothing.
    if (publicPrefixOf(key) !== null || looksIntentionallyPublic(key)) continue

    if (looksClearlyPrivate(key)) return 'proof'
    if (value.length >= SUBSTANTIAL_VALUE) best = 'hint'
  }

  return best
}

function git(root: string, gitExecutable: string | null, args: string[]): string | null {
  if (gitExecutable === null) return null
  try {
    return execGitSync(gitExecutable, root, args)
  } catch {
    return null
  }
}

/** Run a git command the rule cannot work without; a failure becomes the engine's incomplete-scan record */
function gitOrThrow(root: string, gitExecutable: string | null, args: string[]): string {
  const out = git(root, gitExecutable, args)
  if (out === null) throw new Error(`git ${args.slice(0, 2).join(' ')} failed in ${root}`)
  return out
}

/**
 * Where the scanned directory sits inside the repository.
 *
 * git speaks two dialects of path at once: a pathspec is relative to the
 * current directory, while `rev:path` is relative to the repository root.
 * Scanning `app/` in a monorepo, history reported `app/.env` and the follow-up
 * query then asked for `app/app/.env`, found nothing, and downgraded a real
 * leak to a guess.
 */
function repoPrefix(root: string, gitExecutable: string | null): string {
  return (git(root, gitExecutable, ['rev-parse', '--show-prefix']) ?? '').trim()
}

/** .env files currently tracked by git */
function trackedEnvFiles(root: string, gitExecutable: string | null): string[] {
  const out = gitOrThrow(root, gitExecutable, ['ls-files', '-z'])
  return out
    .split('\0')
    .filter(Boolean)
    .filter((p) => isEnvFile(basename(p)) && !isEnvTemplate(p))
}

/**
 * One env file seen in history, held in both of the spellings git uses.
 *
 * git answers in two dialects and neither command lets you pick: `ls-files`
 * reports relative to the directory being scanned, `log --name-only` relative
 * to the repository root. Keeping one string and hoping is what made a
 * subdirectory scan compare `.env` against `services/api/.env`, conclude they
 * were different files, and report the same `.env` twice — the second time
 * under a headline saying it had been *removed*, about a file that was sitting
 * right there in the index.
 *
 * That is the worst kind of bug this tool can have. Someone reading "was
 * removed, but it is still in your history" reasonably concludes the working
 * tree is clean and only history needs rewriting; here the live file was still
 * tracked, still holding a live key, and the report had just talked them out
 * of looking. A missed finding costs a favour. A confident false statement
 * costs the premise.
 */
interface HistoricalPath {
  /** Repository-root relative — the only spelling `git show rev:path` accepts */
  repoPath: string
  /** Relative to the scanned directory — what the user sees, and what dedup compares */
  localPath: string
}

/** .env files that appeared in history at some point, even if deleted since */
function historicalEnvFiles(root: string, gitExecutable: string | null, prefix: string): HistoricalPath[] {
  // With rename detection off, a file renamed to .env shows up as an addition too.
  // The NUL separator is what keeps Unicode, spaces and newlines out of git's
  // quoting and out of a line-by-line parse.
  const out = gitOrThrow(root, gitExecutable, [
    'log',
    '--no-ext-diff',
    '--no-textconv',
    '--all',
    '--pretty=format:',
    '--no-renames',
    '--diff-filter=A',
    '--name-only',
    '-z',
    '--',
    '.',
  ])
  const seen = new Map<string, HistoricalPath>()
  for (const repoPath of out.split('\0')) {
    if (!repoPath || !isEnvFile(basename(repoPath)) || isEnvTemplate(repoPath)) continue
    // The pathspec above already restricts the answer to the scanned
    // directory, so every result sits under the prefix. The conditional is
    // there for the root-scan case, where the prefix is empty.
    const localPath = prefix && repoPath.startsWith(prefix) ? repoPath.slice(prefix.length) : repoPath
    if (!seen.has(localPath)) seen.set(localPath, { repoPath, localPath })
  }
  return [...seen.values()]
}

/**
 * How many historical versions of one file to read before giving up.
 *
 * A bound on work, not a claim about history — and the difference has to reach
 * the user. At twenty, silently, "canship checks your git history" quietly
 * meant "canship checks the last twenty versions of it": a key three commits
 * further back scanned to zero findings and `partial: false`. Hitting this now
 * marks the scan incomplete, so the ceiling can be raised or lowered on its
 * merits without the number ever being load-bearing again.
 */
const MAX_HISTORY_REVISIONS = 100

/**
 * The strongest evidence any version of this file ever held.
 *
 * Reading only the revision that *added* the file misses the ordinary shape of
 * this accident: commit a harmless .env, add the key in a later commit, delete
 * the file when you notice. The add snapshot is innocent, every version after
 * it is not, and canship reported nothing at all — while the README promised
 * to check history.
 *
 * Versions are read newest first and stop at the first proof, so the usual
 * case costs one extra git call.
 */
interface HistoryScan {
  evidence: Evidence
  /** Older revisions left unread because the ceiling was reached */
  unread: number
  /** Revisions git show could not read at all */
  unreadable: number
}

function historicalEvidence(
  root: string,
  gitExecutable: string | null,
  entry: HistoricalPath,
): HistoryScan | null {
  // Both dialects are used here, one per command, which is the whole reason
  // the pair is carried around together: the pathspec is relative to the
  // directory being scanned, `rev:path` is relative to the repository root.
  const all =
    (git(root, gitExecutable, [
      'log',
      '--no-ext-diff',
      '--no-textconv',
      '--all',
      '--format=%H',
      '--',
      entry.localPath,
    ]) ?? '')
    .split(/\r?\n/)
    .filter(Boolean)
  if (all.length === 0) return null
  const revs = all.slice(0, MAX_HISTORY_REVISIONS)

  let best: Evidence = 'none'
  let unreadable = 0
  for (const rev of revs) {
    // git does not run textconv or an external diff when it prints a blob, so
    // these change nothing today. They are here because the two `log` calls
    // above carry them and this one reads the same repository's objects: a
    // defence that is applied in two places out of three reads, later, as a
    // decision that the third place did not need it.
    const body = git(root, gitExecutable, [
      'show',
      '--no-ext-diff',
      '--no-textconv',
      `${rev}:${entry.repoPath}`,
    ])
    if (body === null) {
      unreadable++
      continue
    }
    const evidence = evidenceIn(body.split(/\r?\n/))
    // Proof ends the search, and the count of unread revisions goes with it:
    // nothing further back can strengthen a verdict that is already the
    // strongest one available.
    if (evidence === 'proof') return { evidence: 'proof', unread: 0, unreadable }
    if (evidence === 'hint') best = 'hint'
  }
  return { evidence: best, unread: all.length - revs.length, unreadable }
}

/** Whether a remote is configured — if so, the keys have probably left the machine */
function hasRemote(root: string, gitExecutable: string | null): boolean {
  const out = git(root, gitExecutable, ['remote'])
  return out !== null && out.trim().length > 0
}

/**
 * Why the history went unread, in the terms of whichever thing refused.
 *
 * `unavailable` collapses three causes, and they used to arrive as one sentence
 * naming all of them — so a reader with no git installed was told to review
 * their repository for dubious ownership, and a reader whose `.git` file
 * pointed elsewhere was told to install git. A message that covers every cause
 * identifies none of them, and this is the line someone reads when a scan they
 * expected to be clean exits 3 instead.
 */
function unavailableReason(root: string, gitExecutable: string | null): string {
  const unchecked = "so nothing in this repository's history was checked."

  if (gitExecutable === null) {
    return (
      `No trusted git executable was found on PATH, ${unchecked} ` +
      'canship ignores any git inside the scanned project, the current directory or node_modules, ' +
      'because a repository must not supply the program used to read it.'
    )
  }

  if (!hasContainedGitMetadata(root)) {
    return (
      `This checkout's .git metadata points outside the directory and nothing there names this ` +
      `checkout back, ${unchecked} ` +
      'A linked worktree or a submodule is read normally; a .git file naming an unrelated ' +
      'repository is not.'
    )
  }

  return (
    `git could not read this repository, ${unchecked} ` +
    'If git is refusing it for dubious ownership, review the directory before changing safe.directory.'
  )
}

export const gitleakRule: ProjectRule = {
  id: 'gitleak/env-in-git',
  severity: 'P0',

  check(ctx: ScanContext): Finding[] {
    // Throwing is deliberate: the engine turns it into a recorded error and an
    // incomplete scan. Returning [] here — which is what "git failed" used to
    // do — publishes a clean result for a check that never ran.
    if (ctx.git === 'unavailable') {
      throw new Error(unavailableReason(ctx.root, ctx.gitExecutable))
    }
    if (ctx.git === 'not-a-repo') return []
    // Unreachable: 'repo' is only returned after git answered, which requires an
    // executable. Kept because the calls below need it non-null, and a guard
    // that states the invariant is better than a non-null assertion on each.
    if (ctx.gitExecutable === null) {
      throw new Error('no trusted git executable was found, so this repository\'s history was not checked')
    }

    const findings: Finding[] = []
    // Resolved once, then handed to everything that needs to translate between
    // git's two path dialects.
    const prefix = repoPrefix(ctx.root, ctx.gitExecutable)
    const tracked = new Set(trackedEnvFiles(ctx.root, ctx.gitExecutable))
    const historical = historicalEnvFiles(ctx.root, ctx.gitExecutable, prefix)
    const remote = hasRemote(ctx.root, ctx.gitExecutable)

    const remoteNote = remote
      ? `This repository has a remote configured, so these commits have most likely been pushed. ` +
        `Bots scrape public commits within minutes — assume every key in this file is already in someone else's hands.`
      : `This repository has no remote yet, so the damage may still be contained. Fix it before you push.`

    // What case A actually reported. Case B used to skip every tracked path,
    // which is only correct when case A said something about it — and case A
    // stays silent when the *current* contents are clean. Editing the key out
    // of a still-tracked .env is the ordinary way people "fix" this, and it
    // left both branches quiet about a key still sitting in the history.
    const reportedTracked = new Set<string>()

    // ── Case A: the file is still tracked right now ──
    for (const path of tracked) {
      // The contents are readable here, so grade the evidence rather than
      // report the filename.
      const scanned = ctx.files.find((f) => f.path === path)
      const evidence = scanned ? evidenceIn(scanned.lines) : 'hint'
      if (evidence === 'none') continue

      // Location does not excuse the file, it only caps how loudly this is
      // said. See isScaffolding.
      const scaffolding = isScaffolding(path)

      findings.push({
        ruleId: 'gitleak/env-tracked',
        severity: 'P0',
        // Only claim certainty when the file actually holds something that is
        // recognisably a credential. Everything else is a committed env file
        // that might hold one, which is worth saying quietly.
        confidence: evidence === 'proof' && !scaffolding ? 'certain' : 'likely',
        title:
          evidence === 'proof' && !scaffolding
            ? `${path} is committed to git, with a credential in it`
            : `${path} is committed to git`,
        file: path,
        line: null,
        excerpt: null,
        why: [
          evidence === 'proof'
            ? `Environment files hold your credentials, and this one is tracked by git — so every key in it ` +
              `is stored in the repository and visible to anyone who can read it.`
            : `This environment file is tracked by git. Nothing in it matches a credential format canship ` +
              `recognises, so this may be harmless configuration — but .env files are where credentials ` +
              `end up, and a committed one is a habit worth breaking before it matters.`,
          remoteNote,
          ...(scaffolding ? [SCAFFOLD_NOTE] : []),
        ],
        fix: [`Add ${path} to .gitignore.`, untrackStep(path)],
        humanOnly: [
          `Rotate every credential in that file. This is the step people skip, and it is the only one that actually stops the leak.`,
          `Removing it from history entirely requires rewriting the repo (git filter-repo or BFG). Do that only after rotating the keys — rotation is what matters, and history rewriting is disruptive enough that it should be a deliberate decision.`,
        ],
      })
      reportedTracked.add(path)
    }

    // ── Case B: an older version held something, whether or not the file is
    //    still there — the case most often mistaken for "already fixed" ──
    for (const entry of historical) {
      // Compared in the scanned directory's dialect, because that is the one
      // `tracked` speaks. Comparing across dialects is what produced a
      // duplicate report claiming a still-tracked file had been deleted.
      if (reportedTracked.has(entry.localPath)) continue // case A covered it
      const path = entry.localPath
      // Whether the file survives in the working tree decides the wording, not
      // whether this branch runs. Saying "was removed" about a file sitting in
      // the index is the confident false statement this rule must never make.
      const stillTracked = tracked.has(entry.localPath)
      // The old versions are readable even when the current one is clean, and
      // reading them is the difference between knowing and guessing.
      const history = historicalEvidence(ctx.root, ctx.gitExecutable, entry)
      // A ceiling reached is a part of the scan that did not happen. Reported
      // even when the visible versions were clean — especially then, since that
      // is exactly when "nothing found" is least trustworthy.
      if (history && history.unread > 0) {
        ctx.reportIncomplete(
          'gitleak/env-in-history',
          `only the ${MAX_HISTORY_REVISIONS} most recent versions of ${path} were read; ` +
            `${history.unread} older ${history.unread === 1 ? 'version was' : 'versions were'} not checked`,
        )
      }
      if (history && history.unreadable > 0) {
        ctx.reportIncomplete(
          'gitleak/env-in-history',
          `${history.unreadable} historical ${history.unreadable === 1 ? 'version' : 'versions'} of ${path} ` +
            `could not be read with git show; ` +
            `the repository may be incomplete or the file may exceed the Git output limit`,
        )
      }
      // 'hint' rather than a fourth value invented here. When history cannot be
      // read the honest grade is "something may be in there, quietly" — which
      // is what 'hint' already means, and what Case A uses for the same
      // situation. A string outside the union widened the type, made the two
      // branches disagree about how to spell one state, and cost the compiler
      // its exhaustiveness check over `Evidence`.
      const evidence: Evidence = history?.evidence ?? 'hint'
      if (evidence === 'none') continue

      // This is the branch the location exemption used to silence completely.
      // When the file is gone from disk no other rule can see it — quiet is the
      // most this may be, and absent is not an option.
      const scaffolding = isScaffolding(path)

      findings.push({
        ruleId: 'gitleak/env-in-history',
        severity: 'P0',
        // Claiming certainty about a file nobody could read would be the same
        // overreach the tracked branch just stopped making.
        confidence: evidence === 'proof' && !scaffolding ? 'certain' : 'likely',
        title: stillTracked
          ? `${path} is committed to git, and an older version of it held a credential`
          : `${path} was removed, but it is still in your git history`,
        file: path,
        line: null,
        excerpt: null,
        why: [
          stillTracked
            ? `The version of this file in your working tree holds nothing canship recognises as a ` +
              `credential — but git keeps every version of every file it has ever seen, and an earlier one ` +
              `does. Editing the key out of a tracked file changes the latest version and nothing else; the ` +
              `old contents are still one command away for anyone who can clone this repository.`
            : `This file is no longer tracked, so it looks fixed — but git keeps every version of every file ` +
              `it has ever seen. Anyone who clones this repository can still read the old contents with a ` +
              `single command.`,
          remoteNote,
          ...(scaffolding ? [SCAFFOLD_NOTE] : []),
        ],
        fix: stillTracked
          ? [`Add ${path} to .gitignore.`, untrackStep(path)]
          : [`Confirm ${path} is in .gitignore so it does not come back.`],
        humanOnly: [
          `Rotate every credential that was ever in this file. Do this first, and do not skip it — it is the only step that actually revokes access.`,
          `Then, if you need the history cleaned, rewrite it with git filter-repo or BFG Repo-Cleaner. Do this deliberately: it rewrites every commit hash and disrupts anyone else working on the repo.`,
        ],
      })
    }

    return findings
  },
}
