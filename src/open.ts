/** 用系统默认程序打开本地报告；只在交互式终端中执行，不经过 shell。 */
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, posix, win32 } from 'node:path'

/** 系统程序目录；用户 PATH 中的绝对目录排在其后，仅用于找到非标准安装位置。 */
const UNIX_SYSTEM_DIRS = ['/usr/bin', '/bin', '/usr/local/bin', '/usr/sbin', '/sbin', '/usr/local/sbin']

export interface OpenerOptions {
  /** 当前工作目录；其下的 PATH 条目视为项目内容。 */
  cwd?: string
  /** 判断程序是否存在，测试时替换。 */
  exists?: (path: string) => boolean
}

function pathValue(env: NodeJS.ProcessEnv): string {
  return Object.entries(env).find(([key]) => key.toLowerCase() === 'path')?.[1] ?? ''
}

/**
 * 可信的类 Unix 程序目录：系统目录加上用户 PATH 中的绝对目录，
 * 排除相对目录、node_modules 以及当前工作目录下的目录，防止扫描的项目提供同名程序。
 */
export function trustedUnixPath(env: NodeJS.ProcessEnv, cwd: string): string[] {
  const inside = (dir: string): boolean => {
    const rel = posix.relative(cwd, dir)
    return rel === '' || (!rel.startsWith('..') && !posix.isAbsolute(rel))
  }
  const user = pathValue(env).split(':').filter(dir =>
    posix.isAbsolute(dir) && !dir.includes('\0') && !/(?:^|\/)node_modules(?:\/|$)/.test(dir) && !inside(dir))
  return [...new Set([...UNIX_SYSTEM_DIRS, ...user.map(dir => posix.normalize(dir).replace(/(.)\/$/, '$1'))])]
}

/** 固定的系统程序路径；Linux 在可信目录中查找 xdg-open，不从当前目录或项目依赖查找。 */
export function openerFor(platform: NodeJS.Platform, path: string, env: NodeJS.ProcessEnv = process.env,
  options: OpenerOptions = {}): { command: string; args: string[] } {
  if (platform === 'win32') {
    const root = Object.entries(env).find(([key]) => key.toLowerCase() === 'systemroot')?.[1]
    if (!root || !/^[a-z]:[\\/]/i.test(root) || root.includes('\0')) throw new Error('Windows system directory is unavailable')
    return { command: win32.join(root, 'explorer.exe'), args: [path] }
  }
  if (platform === 'darwin') return { command: '/usr/bin/open', args: [path] }
  const exists = options.exists ?? existsSync
  // NixOS、Homebrew on Linux 等不在 /usr/bin 安装 xdg-open。
  for (const dir of trustedUnixPath(env, options.cwd ?? process.cwd())) {
    const candidate = posix.join(dir, 'xdg-open')
    if (exists(candidate)) return { command: candidate, args: [path] }
  }
  throw new Error('xdg-open was not found in system directories or PATH outside the project')
}

/** 系统打开脚本的后续命令也不能从项目目录解析；类 Unix 保留用户的可信目录，以便找到浏览器。 */
export function openerEnvironment(platform: NodeJS.Platform, command: string, env: NodeJS.ProcessEnv,
  cwd: string = process.cwd()): NodeJS.ProcessEnv {
  const clean = { ...env }
  for (const key of Object.keys(clean)) if (key.toLowerCase() === 'path') delete clean[key]
  clean.PATH = platform === 'win32'
    ? `${win32.dirname(command)};${win32.join(win32.dirname(command), 'System32')}`
    : trustedUnixPath(env, cwd).join(':')
  return clean
}

/** CI 或输出被重定向时不启动浏览器，避免在无人值守环境中产生副作用。 */
export function canOpen(env: NodeJS.ProcessEnv, interactive: boolean): boolean {
  return interactive && !env['CI']
}

/** 启动后立即分离；失败只返回说明，不影响扫描退出码。 */
export function openReport(path: string, onError: (message: string) => void): void {
  try {
    const { command, args } = openerFor(process.platform, path)
    const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true, shell: false,
      cwd: dirname(command), env: openerEnvironment(process.platform, command, process.env) })
    child.on('error', (err) => onError(`could not open the report with ${command}: ${err.message}`))
    child.unref()
  } catch (err) {
    onError(`could not open the report: ${err instanceof Error ? err.message : String(err)}`)
  }
}
