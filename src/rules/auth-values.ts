/** 有界追踪函数内的简单身份赋值；不执行代码，也不推断业务授权。 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'

export interface FunctionSpan { declaration: number; start: number; end: number }
export interface AuthValue {
  kind: 'identity' | 'envelope' | 'input' | 'literal' | 'promise' | 'secret' | 'parameter' | 'unknown' | 'opaque'
  parameters?: number[]
}
interface Assignment { at: number; expression: string; projection: boolean; overLimit: boolean }
const limited = new WeakSet<ScanFile>()
const cache = new WeakMap<ScanFile, Map<number, AuthValues>>()
const reverseCache = new WeakMap<ScanFile, Map<number, number>>()
export const identityFlowLimited = (file: ScanFile): boolean => limited.has(file)

/** 分隔实参，忽略调用、对象及数组内部的逗号。 */
export function argumentExpressions(code: string, source: string, start: number, end: number, pairs: Map<number, number>): string[] {
  const result: string[] = []
  let from = start
  for (let i = start; i < end; i++) {
    if (code[i] === ',') { result.push(source.slice(from, i).trim()); from = i + 1 }
    const close = pairs.get(i)
    if (close !== undefined) i = close
  }
  if (from < end) result.push(source.slice(from, end).trim())
  return result
}

export function authValuesOf(file: ScanFile, body: FunctionSpan, bodies: FunctionSpan[], pairs: Map<number, number>): AuthValues {
  let contexts = cache.get(file)
  if (!contexts) { contexts = new Map(); cache.set(file, contexts) }
  let found = contexts.get(body.start)
  if (!found) { found = new AuthValues(file, body, bodies, pairs); contexts.set(body.start, found) }
  return found
}

class AuthValues {
  private assignments = new Map<string, Assignment[]>()
  private parameters = new Map<string, number>()
  private conditions: Array<{ start: number; end: number }> = []
  private exhausted = false

  constructor(private file: ScanFile, body: FunctionSpan, bodies: FunctionSpan[], pairs: Map<number, number>) {
    const code = noiseMaskedOf(file)
    const source = commentsMaskedOf(file)
    let open = code.indexOf('(', body.declaration)
    let close = pairs.get(open)
    if (code.startsWith('=>', body.declaration)) {
      const window = code.slice(Math.max(0, body.declaration - 300), body.declaration)
      const before = window.trimEnd()
      if (before.endsWith(')')) {
        close = body.declaration - (window.length - before.length) - 1
        let reverse = reverseCache.get(file)
        if (!reverse) { reverse = new Map([...pairs].map(([left, right]) => [right, left])); reverseCache.set(file, reverse) }
        open = reverse.get(close) ?? -1
      } else {
        const single = /([A-Za-z_$][\w$]*)$/.exec(before)?.[1]
        if (single) this.parameters.set(single, 0)
        open = -1
      }
    }
    if (open >= 0 && close !== undefined && close < body.start) {
      argumentExpressions(code, code, open + 1, close, pairs).forEach((part, index) => {
        const name = /^([A-Za-z_$][\w$]*)(?:\s*\??\s*:[^=]+)?$/.exec(part)?.[1]
        if (name) this.parameters.set(name, index)
      })
    }
    const text = code.slice(body.start + 1, body.end)
    const endOf = (start: number): number => {
      for (let i = start; i < body.end; i++) {
        if (/[;\n}]/.test(code[i]!)) return i
        const close = pairs.get(i)
        if (close !== undefined) i = close
      }
      return body.end
    }
    for (const match of text.matchAll(/\b(?:if|for|while|switch|catch)\s*\(/g)) {
      const close = pairs.get(body.start + 1 + match.index + match[0].length - 1)
      if (close === undefined) continue
      let start = close + 1
      while (/\s/.test(code[start] ?? '')) start++
      this.conditions.push({ start, end: pairs.get(start) ?? endOf(start) })
      if (this.conditions.length > 512) { this.exhausted = true; limited.add(file); break }
    }
    let low = 0, high = bodies.length
    while (low < high) { const middle = (low + high) >>> 1; if (bodies[middle]!.declaration <= body.start) low = middle + 1; else high = middle }
    const nested: FunctionSpan[] = []
    for (let i = low; i < bodies.length && bodies[i]!.declaration < body.end; i++) nested.push(bodies[i]!)
    let nestedIndex = 0
    let count = 0
    const declarations = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*|\{[^;=\n]{1,200}\})\s*(?::[^=;\n]{1,120})?=\s*|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?!=|>)/g
    for (const match of text.matchAll(declarations)) {
      const at = body.start + 1 + match.index
      while (nestedIndex < nested.length && nested[nestedIndex]!.end < at) nestedIndex++
      if (nested[nestedIndex] && at >= nested[nestedIndex]!.declaration && at < nested[nestedIndex]!.end) continue
      if (++count > 512) { this.exhausted = true; limited.add(file); break }
      const binding = (match[1] ?? match[2])!
      const projection = /^\{\s*data\s*:\s*\{\s*user(?:\s*:\s*([A-Za-z_$][\w$]*))?\s*\}\s*\}$/.exec(binding)
      const name = projection ? projection[1] ?? 'user' : /^[A-Za-z_$][\w$]*$/.test(binding) ? binding : null
      if (!name) continue
      const from = at + match[0].length
      const end = endOf(from)
      const list = this.assignments.get(name) ?? []
      list.push({ at, expression: end - from <= 4000 ? source.slice(from, end).trim() : '', projection: !!projection, overLimit: end - from > 4000 })
      this.assignments.set(name, list)
    }
  }

  value(expression: string, at: number, depth = 0): AuthValue {
    if (depth >= 8) limited.add(this.file)
    if (this.exhausted || depth >= 8) return { kind: 'opaque' }
    const expr = expression.trim()
    if (/^process\.env\.[A-Z_][A-Z0-9_]*$/.test(expr)) return { kind: 'secret' }
    if (/^(?:true|false|null|undefined|\d|['"`{\[])/.test(expr)) return { kind: 'literal' }
    const callee = /^(?:await\s+)?((?:[A-Za-z_$][\w$]*\.)*(?:getUser|getUserSession|getSession|getServerSession|currentUser|verifyIdToken|auth))\s*\(/.exec(expr)?.[1]
    const identityCall = callee && !/\.(?:body|query|headers|cookies)\b/.test(callee)
    if (identityCall) {
      if (!/^await\s+/.test(expr)) return { kind: 'promise' }
      if (/\|\||&&|\?(?!\.)|\.then\s*\(/.test(expr) || /\.catch\s*\(/.test(expr)) return { kind: 'opaque' }
      return { kind: /\.auth\.getUser\s*\(/.test(expr) ? 'envelope' : 'identity' }
    }
    if (/\.(?:body|query|headers|cookies|searchParams)\b|\.(?:json|text|formData)\s*\(/.test(expr)) return { kind: 'input' }
    const access = /^([A-Za-z_$][\w$]*)((?:\??\.[A-Za-z_$][\w$]*)*)$/.exec(expr)
    if (!access) return { kind: 'opaque' }
    const name = access[1]!
    const list = this.assignments.get(name) ?? []
    let low = 0, high = list.length
    while (low < high) { const middle = (low + high) >>> 1; if (list[middle]!.at < at) low = middle + 1; else high = middle }
    const assignment = list[low - 1]
    let value: AuthValue
    if (assignment) {
      if (assignment.overLimit) { limited.add(this.file); return { kind: 'opaque' } }
      if (this.conditions.some(range => range.start <= assignment.at && assignment.at <= range.end && !(range.start <= at && at <= range.end))) return { kind: 'opaque' }
      value = this.value(assignment.expression, assignment.at, depth + 1)
      if (assignment.projection) value = { kind: value.kind === 'envelope' ? 'identity' : 'opaque' }
    } else if (this.parameters.has(name)) value = { kind: 'parameter', parameters: [this.parameters.get(name)!] }
    else value = { kind: 'unknown' }
    if (value.kind === 'envelope') return { kind: /^\??\.data\??\.user$/.test(access[2]!) ? 'identity' : 'envelope' }
    return value
  }
}

/** 返回所需实参索引；空数组表示已识别身份，null 表示未验证来源。 */
export function identityRequirement(value: AuthValue, allowParameters: boolean): number[] | null {
  if (value.kind === 'identity') return []
  if (allowParameters && value.kind === 'parameter') return value.parameters ?? []
  return null
}
