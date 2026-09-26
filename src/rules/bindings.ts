/** 读取静态 ESM 名称映射；不执行模块，类型导入不构成运行时证据。 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'

export interface NamedBinding { local: string; imported: string; spec?: string }
export interface Bindings { imports: NamedBinding[]; exports: NamedBinding[]; stars: string[] }
const cache = new WeakMap<ScanFile, Bindings>()

export function bindingsOf(file: ScanFile): Bindings {
  const cached = cache.get(file)
  if (cached) return cached
  const source = commentsMaskedOf(file)
  const code = noiseMaskedOf(file)
  const result: Bindings = { imports: [], exports: [], stars: [] }
  const lists = /\b(import|export)\s+(type\s+)?\{([^{}]{0,4000})\}(?:\s*from\s*['"]([^'"\r\n]{1,1024})['"])?/g
  for (const match of source.matchAll(lists)) {
    if (match[2] || code.slice(match.index, match.index + match[1]!.length) !== match[1]) continue
    if (match[1] === 'import' && !match[4]) continue
    for (const part of match[3]!.split(',')) {
      const names = /^\s*([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?\s*$/.exec(part)
      if (!names) continue
      const imported = names[1]!
      const local = names[2] ?? imported
      const target = match[1] === 'import' ? result.imports : result.exports
      target.push({ imported, local,
        ...(match[4] ? { spec: match[4] } : {}) })
    }
  }
  for (const match of source.matchAll(/\bimport\s+([A-Za-z_$][\w$]*)\s+from\s*['"]([^'"\r\n]{1,1024})['"]/g)) {
    if (code.slice(match.index, match.index + 6) === 'import' && match[1] !== 'type') {
      result.imports.push({ local: match[1]!, imported: 'default', spec: match[2]! })
    }
  }
  for (const match of source.matchAll(/\bexport\s*\*\s*from\s*['"]([^'"\r\n]{1,1024})['"]/g)) {
    if (code.slice(match.index, match.index + 6) === 'export') result.stars.push(match[1]!)
  }
  cache.set(file, result)
  return result
}

/** 名称只含标识符字符；美元符号仍须按正则字面量处理。 */
export function namePattern(names: Iterable<string>): string {
  return [...names].map(name => name.replace(/\$/g, '\\$')).join('|')
}
