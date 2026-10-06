/** 后续命令保留扫描范围与隐私选项，不继承旧的文件输出请求。 */
import { redactAll } from '../redact.js'

export function followupArgs(argv: readonly string[]): string[] | null {
  const args = argv.filter(arg => !/^(?:--(?:json|fix-prompt|verbose|open)|--(?:report|sarif)(?:=.*)?)$/.test(arg))
  if (args.some(arg => /[\u0000-\u001f\u007f-\u009f\u061c\u200b\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(arg) || redactAll(arg) !== arg)) return null
  return args
}

/** Windows 按 PowerShell 引号规则处理；其他平台按 POSIX shell 处理。 */
export function followupCommand(args: readonly string[], flags: readonly string[], platform: string = process.platform): string {
  const quote = (value: string): string => /^[A-Za-z0-9_./:@=,+%-]+$/.test(value) ? value
    : platform === 'win32' ? `'${value.replace(/'/g, "''")}'` : `'${value.replace(/'/g, "'\"'\"'")}'`
  return ['npx', 'canship', ...args, ...flags.filter(flag => !args.includes(flag))].map(quote).join(' ')
}
