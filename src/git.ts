import { execFileSync } from 'node:child_process'
import { accessSync, constants, existsSync, lstatSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { delimiter, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'

const MAX_GIT_OUTPUT = 32 * 1024 * 1024
const GIT_TIMEOUT_MS = 30_000

function canonical(path: string): string {
  try {
    return realpathSync.native(path)
  } catch {
    return resolve(path)
  }
}

function comparable(path: string): string {
  const resolved = resolve(path)
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved
}

function isWithin(root: string, path: string): boolean {
  const rel = relative(comparable(root), comparable(path))
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel))
}

function gitRootAbove(root: string): string | null {
  let dir = canonical(root)
  for (;;) {
    if (existsSync(join(dir, '.git'))) return dir
    const parent = dirname(dir)
    if (parent === dir) return null
    dir = parent
  }
}

export function hasGitMetadataAbove(root: string): boolean {
  return gitRootAbove(root) !== null
}

/** 限制 Git 元数据文件的读取大小。 */
function readSmallFile(path: string, limit: number): string | null {
  try {
    const stat = lstatSync(path)
    if (!stat.isFile() || stat.size > limit) return null
    return readFileSync(path, 'utf8')
  } catch {
    return null
  }
}

/** 仅解析普通 core 节中的工作区路径，无法确认时保持保守。 */
function coreWorktreeOf(path: string): string | null {
  const text = readSmallFile(path, 256 * 1024)
  if (text === null) return null

  let inCore = false
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line.startsWith('[')) {
      inCore = /^\[core\]$/i.test(line)
      continue
    }
    if (!inCore) continue
    const assignment = /^worktree\s*=\s*(.*)$/i.exec(line)
    if (!assignment) continue
    const value = assignment[1]!.trim()
    const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(value)
    return quoted ? quoted[1]!.replace(/\\(.)/g, '$1') : value
  }
  return null
}

function samePath(a: string, b: string): boolean {
  return comparable(canonical(a)) === comparable(canonical(b))
}

/** 验证外部 Git 元数据回指当前工作区，支持工作树及子模块。 */
function linksBackTo(target: string, boundary: string, marker: string): boolean {
  const named = readSmallFile(join(target, 'gitdir'), 4096)?.trim()
  if (named) {
    const back = isAbsolute(named) ? named : resolve(target, named)
    if (samePath(back, marker)) return true
  }

  // core.worktree 相对 Git 元数据目录解析。
  const worktree = coreWorktreeOf(join(target, 'config'))
  if (worktree === null || worktree === '') return false
  return samePath(isAbsolute(worktree) ? worktree : resolve(target, worktree), boundary)
}

export function hasContainedGitMetadata(root: string): boolean {
  const boundary = gitRootAbove(root)
  if (boundary === null) return false
  const marker = join(boundary, '.git')

  try {
    const stat = lstatSync(marker)
    if (stat.isDirectory()) return isWithin(boundary, canonical(marker))
    if (!stat.isFile()) return false
    if (stat.size > 4096) return false
    const match = /^gitdir:\s*(.+?)\s*$/i.exec(readFileSync(marker, 'utf8'))
    if (!match?.[1]) return false
    const target = isAbsolute(match[1]) ? match[1] : resolve(boundary, match[1])
    if (isWithin(boundary, canonical(target))) return true
    return linksBackTo(canonical(target), boundary, marker)
  } catch {
    return false
  }
}

function untrustedRoots(root: string): string[] {
  const cwd = process.cwd()
  const candidates = [
    root,
    cwd,
    gitRootAbove(root),
    gitRootAbove(cwd),
    process.env.INIT_CWD,
    process.env.npm_config_local_prefix,
  ]
  const roots = new Set<string>()
  for (const candidate of candidates) {
    if (candidate && isAbsolute(candidate)) roots.add(canonical(candidate))
  }
  return [...roots]
}

function cleanPathEntry(entry: string): string {
  const trimmed = entry.trim()
  return trimmed.startsWith('"') && trimmed.endsWith('"') ? trimmed.slice(1, -1) : trimmed
}

function isProjectBin(path: string): boolean {
  const segments = resolve(path)
    .split(/[\\/]+/)
    .map((segment) => segment.toLowerCase())
  return segments.includes('node_modules') || segments.at(-1) === '.bin'
}

function isNetworkPath(path: string): boolean {
  return process.platform === 'win32' && (path.startsWith('\\\\') || path.startsWith('//'))
}

export function resolveGitExecutable(root: string): string | null {
  const executable = process.platform === 'win32' ? 'git.exe' : 'git'
  const unsafe = untrustedRoots(root)

  for (const rawEntry of (process.env.PATH ?? '').split(delimiter)) {
    const entry = cleanPathEntry(rawEntry)
    if (!entry || !isAbsolute(entry) || isNetworkPath(entry) || isProjectBin(entry)) continue

    const candidate = join(entry, executable)
    try {
      if (!statSync(candidate).isFile()) continue
      if (process.platform !== 'win32') accessSync(candidate, constants.X_OK)
      const realCandidate = canonical(candidate)
      if (unsafe.some((boundary) => isWithin(boundary, candidate) || isWithin(boundary, realCandidate))) {
        continue
      }
      return realCandidate
    } catch {
      continue
    }
  }

  return null
}

function gitEnvironment(): NodeJS.ProcessEnv {
  const env = { ...process.env }
  const removed = new Set([
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_COMMON_DIR',
    'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_NAMESPACE',
    'GIT_SHALLOW_FILE',
    'GIT_REPLACE_REF_BASE',
    'GIT_CEILING_DIRECTORIES',
    'GIT_DISCOVERY_ACROSS_FILESYSTEM',
    'GIT_EXEC_PATH',
    'GIT_EXTERNAL_DIFF',
    'GIT_DIFF_OPTS',
    'GIT_CONFIG',
    'GIT_CONFIG_PARAMETERS',
    'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_SYSTEM',
    'GIT_CONFIG_NOSYSTEM',
    'GIT_GLOB_PATHSPECS',
    'GIT_NOGLOB_PATHSPECS',
    'GIT_ICASE_PATHSPECS',
    'GIT_LITERAL_PATHSPECS',
    'GIT_TERMINAL_PROMPT',
    'GIT_OPTIONAL_LOCKS',
    'GIT_NO_LAZY_FETCH',
    'GIT_ALLOW_PROTOCOL',
    'GIT_PROTOCOL_FROM_USER',
    'GIT_NO_REPLACE_OBJECTS',
    'GIT_PAGER',
    'PAGER',
    'GIT_REDIRECT_STDIN',
    'GIT_REDIRECT_STDOUT',
    'GIT_REDIRECT_STDERR',
  ])

  for (const key of Object.keys(env)) {
    if (
      removed.has(key.toUpperCase()) ||
      /^GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+)$/i.test(key) ||
      /^GIT_TRACE/i.test(key)
    ) {
      delete env[key]
    }
  }

  env.GIT_TERMINAL_PROMPT = '0'
  env.GIT_OPTIONAL_LOCKS = '0'
  env.GIT_NO_LAZY_FETCH = '1'
  env.GIT_ALLOW_PROTOCOL = ''
  env.GIT_PROTOCOL_FROM_USER = '0'
  env.GIT_NO_REPLACE_OBJECTS = '1'
  env.GIT_LITERAL_PATHSPECS = '1'
  env.GIT_PAGER = ''
  env.PAGER = ''
  return env
}

export interface GitExecOptions {
  maxBuffer?: number
  stderr?: 'ignore' | 'pipe'
}

/** 统一禁用钩子和文件监视器，并固定工作区。 */
function hardeningArgs(root: string): string[] {
  const worktree = gitRootAbove(root) ?? root
  const noHooks = process.platform === 'win32' ? 'NUL' : '/dev/null'
  return [
    '-c',
    `core.worktree=${worktree}`,
    '-c',
    'core.bare=false',
    '-c',
    'core.fsmonitor=false',
    '-c',
    `core.hooksPath=${noHooks}`,
  ]
}

export function execGitSync(
  executable: string,
  root: string,
  args: string[],
  options: GitExecOptions = {},
): string {
  return execFileSync(executable, [...hardeningArgs(root), ...args], {
    timeout: GIT_TIMEOUT_MS,
    cwd: root,
    encoding: 'utf8',
    maxBuffer: options.maxBuffer ?? MAX_GIT_OUTPUT,
    stdio: ['ignore', 'pipe', options.stderr ?? 'ignore'],
    windowsHide: true,
    env: gitEnvironment(),
  })
}

/** 批量读取 Git 对象并保留原始字节，按字节长度解析帧。 */
export function execGitBatch(
  executable: string,
  root: string,
  args: string[],
  input: string,
  options: GitExecOptions = {},
): Buffer {
  return execFileSync(executable, [...hardeningArgs(root), ...args], {
    timeout: GIT_TIMEOUT_MS,
    cwd: root,
    input,
    maxBuffer: options.maxBuffer ?? MAX_GIT_OUTPUT,
    stdio: ['pipe', 'pipe', options.stderr ?? 'ignore'],
    windowsHide: true,
    env: gitEnvironment(),
  })
}
