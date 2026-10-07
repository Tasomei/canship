/** 编辑器边界工具不依赖 VS Code，便于独立验证路径和过期状态。 */
import { createHash } from 'node:crypto'
import { lstatSync, realpathSync } from 'node:fs'
import { extname, isAbsolute, join, relative, sep } from 'node:path'
import { maskJsNoise } from '../../../src/mask.js'
import type { Finding } from '../../../src/types.js'

/** 重叠根目录会重复诊断并使失效范围不明确，编辑器要求独立项目根。 */
export function independentRoots(roots: readonly string[]): boolean {
  if (!roots.length || roots.length > 32) return false
  try {
    const canonical = roots.map(root => {
      const path = realpathSync(root)
      if (!lstatSync(path).isDirectory()) throw new Error('Not a directory')
      return process.platform === 'win32' ? path.toLowerCase() : path
    })
    return canonical.every((root, index) => canonical.every((other, at) => {
      if (index === at) return true
      const difference = relative(root, other)
      return difference === '..' || difference.startsWith('..' + sep) || isAbsolute(difference)
    }))
  } catch { return false }
}

export function findingPath(root: string, file: string | null): string | null {
  if (!file || isAbsolute(file) || /^[A-Za-z]:/.test(file) || file.split(/[\\/]/).some(part => part === '..' || part === '.' || !part)) return null
  if (process.platform !== 'win32' && file.includes('\\')) return null
  try {
    const base = realpathSync(root)
    let at = base
    for (const part of file.split(/[\\/]/)) {
      at = join(at, part)
      if (lstatSync(at).isSymbolicLink()) return null
    }
    const canonical = realpathSync(at), inside = relative(base, canonical)
    if (!inside || inside === '..' || inside.startsWith('..' + sep) || isAbsolute(inside) || !lstatSync(canonical).isFile()) return null
    return join(root, ...file.split(/[\\/]/))
  } catch { return null }
}

export function suppressionPreview(file: string, text: string, finding: Finding): { line: number; text: string } | null {
  if (finding.line === null || !finding.sourceFingerprint || !/^[a-z0-9][a-z0-9/_-]*$/i.test(finding.ruleId) || text.length > 2 * 1024 * 1024) return null
  const extension = extname(file).toLowerCase()
  if (!['.js', '.ts', '.mjs', '.cjs', '.sql', '.rules'].includes(extension)) return null
  const lines = text.split(/\r?\n/), line = finding.line - 1, source = lines[line]
  if (source === undefined || createHash('sha256').update(source.trim()).digest('hex') !== finding.sourceFingerprint) return null
  // 不在多行字符串或注释内部插入标记；不支持 JSX、JSON 等歧义位置。
  const masked = maskJsNoise(text).split(/\r?\n/)[line] ?? ''
  const indent = /^\s*/.exec(source)![0]
  if (!source.trim() || masked[indent.length] !== source[indent.length]) return null
  const prefix = extension === '.sql' ? '--' : '//'
  return { line, text: `${indent}${prefix} canship-ignore-next-line ${finding.ruleId}${text.includes('\r\n') ? '\r\n' : '\n'}` }
}

/** 每次请求和文档变更都使旧结果失效。 */
export class Revisions {
  private readonly values = new Map<string, number>()
  next(root: string): number { const value = (this.values.get(root) ?? 0) + 1; this.values.set(root, value); return value }
  current(root: string, value: number): boolean { return this.values.get(root) === value }
  clear(): void { this.values.clear() }
}
