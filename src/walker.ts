/** 发现项目文件，合并 Git 清单与凭据文件遍历结果。 */

import { readdirSync, readFileSync, statSync, lstatSync, openSync, readSync, closeSync } from 'node:fs'
import { join, relative, sep, extname, basename } from 'node:path'
import type { GitStatus, ScanFile, SkippedFile } from './types.js'
import { execGitSync, hasContainedGitMetadata, hasGitMetadataAbove, resolveGitExecutable } from './git.js'

/** 单文件读取上限。 */
const MAX_FILE_BYTES = 2 * 1024 * 1024
const MAX_SCAN_BYTES = 128 * 1024 * 1024
const MAX_SCAN_FILES = 10_000

/** 目录遍历深度上限。 */
const MAX_WALK_DEPTH = 16

/** 手动遍历时直接排除的目录。 */
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
  // 排除其他生态的构建产物和工具缓存。
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

/** 统一排除第三方目录，包括 Git 跟踪的文件。 */
const VENDORED_DIRS = new Set(['node_modules', 'vendor', 'Pods', '.yarn', '.pnpm-store'])

/** 判断路径是否位于第三方目录内。 */
function isVendored(relPath: string): boolean {
  return relPath.split('/').some((segment) => VENDORED_DIRS.has(segment))
}

/** 按扩展名选择候选源码和配置。 */
const SCAN_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.rb', '.php', '.java', '.rs', '.cs',
  '.dart', '.kt', '.kts', '.swift',
  '.json', '.yaml', '.yml', '.toml',
  '.sql',
  // Firebase 规则文件。
  '.rules',
  '.env', '.sh', '.bash', '.ps1',
  '.svelte', '.vue', '.astro',
])

/** 可能直接包含凭据的文件扩展名。 */
const CREDENTIAL_EXTENSIONS = new Set(['.pem', '.key', '.ppk', '.asc', '.p8', '.pkcs8'])

/** 常见凭据配置文件格式。 */
const CONFIG_EXTENSIONS = new Set(['.properties', '.ini', '.conf', '.cfg', '.tfvars', '.tf'])

/** 根据文件名识别无扩展名凭据文件。 */
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

/** 探测窗口只判断文本或二进制，不决定是否含有凭据。 */
const PROBE_BYTES = 4096

/** 整文件忽略标记必须独占注释行。 */
/** 分离空白与注释前缀，避免正则产生高成本回溯。 */
const IGNORE_FILE_MARKER =
  /^\s*(?:(?:\/\/|#|--|\*\/?|\/\*|<!--)\s*)?canship-ignore-file(?:\s*(?:\*\/|-->))?\s*$/

/** 判断是否存在独占行的整文件忽略标记。 */
function hasIgnoreMarker(lines: string[]): boolean {
  return lines.some((line) => IGNORE_FILE_MARKER.test(line))
}

/** 逐行忽略标记仅控制下一行，可指定规则。 */
const IGNORE_LINE_MARKER =
  /^\s*(?:(?:\/\/|#|--|\*\/?|\/\*|<!--)\s*)?canship-ignore-next-line(?:\s+([\w./-]+))?(?:\s*(?:\*\/|-->))?\s*$/

/** 键为被控制行号，空值表示该行全部规则。 */
export type IgnoredLines = Map<number, Set<string> | null>

/** 解析逐行忽略标记，不跳过标记后的空行。 */
export function ignoredLinesOf(lines: string[]): IgnoredLines {
  const found: IgnoredLines = new Map()
  lines.forEach((line, index) => {
    const match = IGNORE_LINE_MARKER.exec(line)
    if (match === null) return
    // 索引从 0 开始，被控制的下一行编号为索引加 2。
    const governed = index + 2
    const ruleId = match[1]
    if (ruleId === undefined) {
      // 不指定规则的标记覆盖该行的全部规则。
      found.set(governed, null)
      return
    }
    if (found.has(governed) && found.get(governed) === null) return
    const rules = found.get(governed) ?? new Set<string>()
    rules.add(ruleId)
    found.set(governed, rules)
  })
  return found
}

/** 跳过二进制锁文件，其余文本锁文件仍参与扫描。 */
const SKIP_FILENAMES = new Set(['bun.lockb'])

/** 不区分大小写识别环境文件名。 */
export function isEnvFile(name: string): boolean {
  const lower = name.toLowerCase()
  return lower === '.env' || lower.startsWith('.env.')
}

/** 根据名称和扩展名决定是否扫描。 */
function shouldScan(relPath: string): boolean {
  const name = basename(relPath)
  if (SKIP_FILENAMES.has(name)) return false
  // 环境文件单独识别，不依赖常规扩展名。
  if (isEnvFile(name)) return true
  if (CREDENTIAL_FILENAMES.has(name)) return true
  const ext = extname(name).toLowerCase()
  return SCAN_EXTENSIONS.has(ext) || CREDENTIAL_EXTENSIONS.has(ext) || CONFIG_EXTENSIONS.has(ext)
}

/** 已知二进制格式不参与文本探测。 */
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

/** 先识别 BOM，再判断未知文件是否为二进制。 */
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
        /* 关闭失败不覆盖原有读取结果。 */
      }
    }
  }
}

/** 排除明确的文档格式，避免将文档示例作为源码扫描。 */
const PROSE_EXTENSIONS = new Set(['.md', '.mdx', '.rst', '.adoc'])

/** 排除没有扩展名的常见文档文件。 */
const PROSE_FILENAMES = new Set([
  'README', 'LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS', 'CONTRIBUTORS',
  'CONTRIBUTING', 'CHANGELOG', 'CHANGES', 'HISTORY', 'CODEOWNERS', 'CODE_OF_CONDUCT',
])

/** 对未知且非二进制、非文档的文件进行探测。 */
function isWorthProbing(relPath: string): boolean {
  const name = basename(relPath)
  if (SKIP_FILENAMES.has(name)) return false
  if (shouldScan(relPath)) return false
  const ext = extname(name).toLowerCase()
  if (PROSE_FILENAMES.has(basename(name, extname(name)).toUpperCase())) return false
  return !BINARY_EXTENSIONS.has(ext) && !PROSE_EXTENSIONS.has(ext)
}

/** 区分非仓库与 Git 检查失败。 */
export function detectGitRepo(root: string, gitExecutable: string | null = resolveGitExecutable(root)): GitStatus {
  const hasMetadata = hasGitMetadataAbove(root)
  if (hasMetadata && !hasContainedGitMetadata(root)) return 'unavailable'
  if (gitExecutable === null) return hasMetadata ? 'unavailable' : 'not-a-repo'
  try {
    const out = execGitSync(gitExecutable, root, ['rev-parse', '--is-inside-work-tree'], { stderr: 'pipe' })
    return out.trim() === 'true' ? 'repo' : 'not-a-repo'
  } catch {
    // 存在元数据但 Git 无法读取时，必须披露检查失败。
    return hasGitMetadataAbove(root) ? 'unavailable' : 'not-a-repo'
  }
}

interface GitFileList {
  files: string[]
  /** Git 作为不透明条目返回的嵌套仓库。 */
  nestedRepositories: string[]
}

/** 读取已跟踪及未忽略文件；失败时回退到目录遍历。 */
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
      // 未跟踪嵌套仓库以带尾斜杠的目录条目返回。
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

/** 补充 Git 忽略的凭据文件。 */
interface WalkResult {
  /** 全部发现路径，相对根目录且使用斜杠。 */
  all: string[]
  /** 通过内容探测识别的额外候选文件。 */
  forced: string[]
}

/** 单次遍历同时收集文件清单和额外候选文件。 */
function walkTree(root: string, skipped: SkippedFile[], wantAll: boolean): WalkResult {
  const all: string[] = []
  const found: string[] = []

  const walk = (dir: string, depth: number): void => {
    if (depth > MAX_WALK_DEPTH) {
      // 达到深度上限时记录缺口，不静默跳过。
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
        // 不跟随符号链接；已排除目录名保持相同排除语义。
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

      // Git 可提供清单时不重复构建完整路径数组。
      if (wantAll) all.push(rel)

      let isCandidate =
        isEnvFile(entry.name) ||
        CREDENTIAL_FILENAMES.has(entry.name) ||
        CREDENTIAL_EXTENSIONS.has(extname(entry.name).toLowerCase())

      // 名称无法判断时探测文件；读取失败必须报告。
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

/** 判断文件是否已经不存在。 */
function isMissing(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/** 按 BOM 解码 UTF-8 或 UTF-16。 */
function decodeText(buf: Buffer): string {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le')
  }
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    // 大端 UTF-16 先交换字节，再按小端解码。
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

/** 以空字符判断明显二进制内容。 */
function looksBinary(content: string): boolean {
  return content.includes('\0')
}

/** 仅根据文件名识别环境模板，与所在目录分开判断。 */
export function isTemplateName(relPath: string): boolean {
  const name = basename(relPath)
  if (/\.(example|sample|template|dist)$/i.test(name)) return true
  if (/^\.env\.(example|sample|template)$/i.test(name)) return true
  return false
}

/** 统一识别测试、示例和文档上下文。 */
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

/** 文件遍历与读取结果。 */
export interface CollectResult {
  files: ScanFile[]
  skipped: SkippedFile[]
  /** 默认排除的第三方路径数。 */
  vendored: number
  /** 由整文件忽略标记排除的文件。 */
  ignored: string[]
}

/** 读取候选文件并记录未读取的路径。 */
export function collectFiles(
  root: string,
  isGitRepo: boolean,
  gitExecutable: string | null = resolveGitExecutable(root),
  limits: { maxBytes?: number; maxFiles?: number } = {},
  honorIgnoreMarkers = true,
): CollectResult {
  const skipped: SkippedFile[] = []
  const ignored: string[] = []
  // 合并 Git 清单和单次目录遍历。
  const fromGit = isGitRepo ? listViaGit(root, gitExecutable) : null
  const walked = walkTree(root, skipped, fromGit === null)
  const listed = fromGit?.files ?? walked.all

  // 合并候选路径并统一排除第三方目录。
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
  // 内容探测选中的路径不再受扩展名筛选限制。
  const forced = new Set<string>()
  for (const hidden of walked.forced) {
    candidates.add(hidden)
    forced.add(hidden)
  }

  const files: ScanFile[] = []
  let bytesRead = 0
  let filesRead = 0
  const maxBytes = limits.maxBytes ?? MAX_SCAN_BYTES
  const maxFiles = limits.maxFiles ?? MAX_SCAN_FILES
  for (const relPath of candidates) {
    if (!forced.has(relPath) && !shouldScan(relPath)) continue

    const absPath = join(root, relPath)
    let content: string
    try {
      if (lstatSync(absPath).isSymbolicLink()) {
        // Git 跟踪的链接也不能被读取，避免重复记录。
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
      // 预算覆盖读取后被识别为二进制或主动忽略的文件。
      if (filesRead >= maxFiles || bytesRead + size > maxBytes) {
        skipped.push({ path: relPath, reason: 'too-large',
          detail: `scan read budget exceeded (${maxFiles} files, ${maxBytes} bytes); remaining candidates were not read` })
        break
      }
      const bytes = readFileSync(absPath)
      bytesRead += bytes.length
      filesRead++
      if (bytesRead > maxBytes) {
        skipped.push({ path: relPath, reason: 'too-large', detail: 'scan read budget exceeded during file read' })
        break
      }
      content = decodeText(bytes)
    } catch (err) {
      // 已删除文件无需报错；其他读取失败均记录。
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
    // 主动排除独立记录，不作为扫描失败；标记由被扫描项目控制，可由调用方关闭。
    if (honorIgnoreMarkers && hasIgnoreMarker(lines)) {
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
