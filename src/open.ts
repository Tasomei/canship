/** 用系统默认程序打开本地报告；只在交互式终端中执行，不经过 shell。 */
import { spawn } from 'node:child_process'
import { dirname, win32 } from 'node:path'

/** 固定系统程序路径，不从当前目录、项目依赖或 PATH 查找打开程序。 */
export function openerFor(platform: NodeJS.Platform, path: string, env: NodeJS.ProcessEnv = process.env): { command: string; args: string[] } {
  if (platform === 'win32') {
    const root = Object.entries(env).find(([key]) => key.toLowerCase() === 'systemroot')?.[1]
    if (!root || !/^[a-z]:[\\/]/i.test(root) || root.includes('\0')) throw new Error('Windows system directory is unavailable')
    return { command: win32.join(root, 'explorer.exe'), args: [path] }
  }
  if (platform === 'darwin') return { command: '/usr/bin/open', args: [path] }
  return { command: '/usr/bin/xdg-open', args: [path] }
}

/** 系统打开脚本的后续命令也不能从项目目录解析。 */
export function openerEnvironment(platform: NodeJS.Platform, command: string, env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const clean = { ...env }
  for (const key of Object.keys(clean)) if (key.toLowerCase() === 'path') delete clean[key]
  clean.PATH = platform === 'win32'
    ? `${win32.dirname(command)};${win32.join(win32.dirname(command), 'System32')}`
    : '/usr/bin:/bin:/usr/sbin:/sbin'
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
