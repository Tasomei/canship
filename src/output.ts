/** 仅更新工具自有输出；同目录临时文件保证写入失败时保留旧内容。 */
import { lstatSync, readFileSync, realpathSync, writeFileSync, renameSync, unlinkSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { randomUUID } from 'node:crypto'

type OutputKind = 'html' | 'sarif' | 'baseline'
function stat(path: string) {
  try { return lstatSync(path) } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

function owned(text: string, kind: OutputKind): boolean {
  if (kind === 'html') return /<title>canship\b/.test(text) && /id="canship-data"/.test(text)
  try {
    const data = JSON.parse(text)
    if (kind === 'baseline') return [2,3,4].includes(data.version) && Array.isArray(data.entries) && data.entries.every((entry: unknown) =>
      entry !== null && typeof entry === 'object' && typeof (entry as Record<string,unknown>).fingerprint === 'string' && typeof (entry as Record<string,unknown>).ruleId === 'string')
    return data.version === '2.1.0' && Array.isArray(data.runs) && data.runs.length > 0 && data.runs.every((run: {tool?:{driver?:{name?:string}}}) => run?.tool?.driver?.name === 'canship')
  } catch { return false }
}

/** 与实际写入共用目标校验；本函数不创建或修改文件。 */
export function inspectOutput(path: string, kind: OutputKind) {
  const requested = resolve(path)
  if (stat(requested)?.isSymbolicLink()) throw new Error('Output target must not be a symbolic link.')
  // 固定父目录的真实位置，兼容 macOS /var 等系统目录别名。
  const target = join(realpathSync(dirname(requested)), basename(requested))
  const before = stat(target)
  if (before && (!before.isFile() || before.size > 16 * 1024 * 1024 || !owned(readFileSync(target,'utf8'),kind))) {
    throw new Error('Refusing to replace a file that is not a recognized canship output. Choose another output path.')
  }
  return { target, before }
}

export function writeOutput(path: string, content: string, kind: OutputKind): void {
  const { target, before } = inspectOutput(path, kind)
  const temporary = join(dirname(target), `.${basename(target)}.${randomUUID()}.tmp`)
  let created = false
  try {
    writeFileSync(temporary, content, {encoding:'utf8',flag:'wx',mode:0o600})
    created = true
    const current = stat(target)
    if (Boolean(before) !== Boolean(current) || (before && current &&
      (before.ino !== current.ino || before.size !== current.size || before.mtimeMs !== current.mtimeMs || current.isSymbolicLink()))) {
      throw new Error('Output changed during generation; the existing file was preserved.')
    }
    renameSync(temporary,target)
    created = false
  } finally {
    if (created) unlinkSync(temporary)
  }
}
