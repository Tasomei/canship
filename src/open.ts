/** 用系统默认程序打开本地报告；只在交互式终端中执行，不经过 shell。 */
import { spawn } from 'node:child_process'

/** 各平台的打开命令；路径作为独立参数传入，不参与命令解析。 */
export function openerFor(platform: NodeJS.Platform, path: string): { command: string; args: string[] } {
  if (platform === 'win32') return { command: 'explorer.exe', args: [path] }
  if (platform === 'darwin') return { command: 'open', args: [path] }
  return { command: 'xdg-open', args: [path] }
}

/** CI 或输出被重定向时不启动浏览器，避免在无人值守环境中产生副作用。 */
export function canOpen(env: NodeJS.ProcessEnv, interactive: boolean): boolean {
  return interactive && !env['CI']
}

/** 启动后立即分离；失败只返回说明，不影响扫描退出码。 */
export function openReport(path: string, onError: (message: string) => void): void {
  const { command, args } = openerFor(process.platform, path)
  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true, shell: false })
    child.on('error', (err) => onError(`could not open the report with ${command}: ${err.message}`))
    child.unref()
  } catch (err) {
    onError(`could not open the report with ${command}: ${err instanceof Error ? err.message : String(err)}`)
  }
}
