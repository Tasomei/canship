/** 有界追踪函数内的简单身份赋值；不执行代码，也不推断业务授权。 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf, maskJsNoise } from '../mask.js'

export interface FunctionSpan { declaration: number; start: number; end: number }
export interface AuthValue {
  kind: 'identity' | 'envelope' | 'data' | 'input' | 'literal' | 'promise' | 'secret' | 'parameter' | 'unknown' | 'opaque'
  parameters?: number[]
  /** Supabase 结果中承载身份的字段：getUser 为 user，getClaims 为 claims。 */
  field?: 'user' | 'claims'
}

/** 按属性路径读取 Supabase 结果；只有 data 下的身份字段成为身份，其余字段不可信。 */
function project(value: AuthValue, path: string[]): AuthValue {
  let current = value
  for (const property of path) {
    if (current.kind === 'envelope') current = property === 'data' ? { kind: 'data', field: current.field! } : { kind: 'opaque' }
    else if (current.kind === 'data') current = property === current.field ? { kind: 'identity' } : { kind: 'opaque' }
    else break
  }
  return current
}

/** 服务器环境变量：process.env.X，Hono/Workers 绑定 c.env.X，以及 env.X、env().X 之类的环境配置对象。 */
const SERVER_ENV = /^(?:process\s*\.\s*env|(?:[A-Za-z_$][\w$]*\s*\.\s*)?env(?:\s*\(\s*\))?)\s*\.\s*[A-Z_][A-Z0-9_]*$/

/** 服务器密钥，或只插入一个服务器密钥的模板（如 `Bearer ${process.env.CRON_SECRET}`）。 */
export function isServerSecretExpression(expression: string): boolean {
  const text = expression.trim()
  if (SERVER_ENV.test(text)) return true
  const template = /^`[^`$]*\$\{([^{}`]{1,200})\}[^`$]*`$/.exec(text)
  return template !== null && SERVER_ENV.test(template[1]!.trim())
}

interface Assignment { at: number; expression: string; projection: string[] | null; overLimit: boolean }
const limited = new WeakSet<ScanFile>()
const cache = new WeakMap<ScanFile, Map<number, AuthValues>>()
const reverseCache = new WeakMap<ScanFile, Map<number, number>>()
export const identityFlowLimited = (file: ScanFile): boolean => limited.has(file)

/** 读取简单对象解构；复杂模式保守记录为未知来源，不能退回名称启发式。 */
function bindingNames(pattern: string, path: string[] = []): Array<{ name: string; path: string[] | null }> {
  const text = pattern.trim()
  if (path.length > 8) return (text.match(/[A-Za-z_$][\w$]*/g) ?? []).map(name => ({ name, path: null }))
  if (/^[A-Za-z_$][\w$]*$/.test(text)) return [{ name: text, path }]
  if (text.startsWith('{') && text.endsWith('}')) {
    const parts: string[] = []
    let from = 1, depth = 0
    for (let i = 1; i < text.length - 1; i++) {
      if ('{[('.includes(text[i]!)) depth++
      else if ('}])'.includes(text[i]!)) depth--
      else if (text[i] === ',' && depth === 0) { parts.push(text.slice(from, i)); from = i + 1 }
    }
    parts.push(text.slice(from, -1))
    const result: Array<{ name: string; path: string[] | null }> = []
    for (const part of parts) {
      if (!part.trim()) continue
      const property = /^\s*([A-Za-z_$][\w$]*)(?:\s*:\s*([^=]+))?\s*$/.exec(part)
      if (property) result.push(...bindingNames(property[2] ?? property[1]!, [...path, property[1]!]))
      else for (const name of part.match(/[A-Za-z_$][\w$]*/g) ?? []) result.push({ name, path: null })
    }
    return result
  }
  return (text.match(/[A-Za-z_$][\w$]*/g) ?? []).map(name => ({ name, path: null }))
}

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
      const boundary = Math.min(body.end, start + 4001)
      let previous = ''
      for (let i = start; i < boundary; i++) {
        if (code[i] === ';' || code[i] === '}') return i
        if (code[i] === '\n') {
          let next = i + 1
          while (next < boundary && /\s/.test(code[next]!)) next++
          if (next === boundary && boundary < body.end) return boundary
          if (!/[.?+\-*/%&|^,:([`=]/.test(code[next] ?? '') && !/[=+\-*/%&|^?:,.]/.test(previous)) return i
          i = next - 1
          continue
        }
        if (!/\s/.test(code[i]!)) previous = code[i]!
        const close = pairs.get(i)
        if (close !== undefined) { i = close; previous = code[close]! }
      }
      return boundary
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
    const declarations = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*|[\[{])|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=(?!=|>)/g
    let match: RegExpExecArray | null
    while ((match = declarations.exec(text)) !== null) {
      if (this.exhausted) break
      const at = body.start + 1 + match.index
      while (nestedIndex < nested.length && nested[nestedIndex]!.end < at) nestedIndex++
      if (nested[nestedIndex] && at >= nested[nestedIndex]!.declaration && at < nested[nestedIndex]!.end) continue
      if (++count > 512) { this.exhausted = true; limited.add(file); break }
      let binding = (match[1] ?? match[2])!
      let from = at + match[0].length
      if (match[1]) {
        if (binding === '{' || binding === '[') {
          const start = from - 1
          const close = pairs.get(start)
          if (close === undefined) continue
          if (close - start > 4000) { this.exhausted = true; limited.add(file); break }
          binding = code.slice(start, close + 1)
          from = close + 1
        }
        while (/\s/.test(code[from] ?? '')) from++
        if (code[from] === ':') {
          const type = /^:[^=;\n]{1,120}/.exec(code.slice(from, from + 121))
          if (type) from += type[0].length
        }
        if (code[from] !== '=' || /[=>]/.test(code[from + 1] ?? '')) continue
        from++
      }
      while (/\s/.test(code[from] ?? '')) from++
      declarations.lastIndex = from - body.start - 1
      const end = endOf(from)
      for (const { name, path } of bindingNames(binding)) {
        if (!this.assignments.has(name) && this.assignments.size >= 512) { this.exhausted = true; limited.add(file); break }
        const list = this.assignments.get(name) ?? []
        list.push({ at, expression: end - from <= 4000 ? source.slice(from, end).trim() : '', projection: path, overLimit: end - from > 4000 })
        this.assignments.set(name, list)
      }
    }
  }

  value(expression: string, at: number, depth = 0): AuthValue {
    if (depth >= 8) limited.add(this.file)
    if (this.exhausted || depth >= 8) return { kind: 'opaque' }
    const expr = expression.trim()
    if (expr.length > 4000) { limited.add(this.file); return { kind: 'opaque' } }
    if (SERVER_ENV.test(expr)) return { kind: 'secret' }
    // 仅插入一个服务器密钥的模板（如 `Bearer ${process.env.CRON_SECRET}`）仍按密钥比较处理。
    const template = /^`[^`$]*\$\{([^{}`]{1,200})\}[^`$]*`$/.exec(expr)
    if (template) return this.value(template[1]!, at, depth + 1).kind === 'secret' ? { kind: 'secret' } : { kind: 'literal' }
    if (/^(?:(?:true|false|null|undefined)\b|\d|['"`{\[])/.test(expr)) return { kind: 'literal' }
    const call = /^(?:await\s+)?((?:[A-Za-z_$][\w$]*\.)*(?:getUser|getClaims|getUserSession|getSession|getServerSession|safeGetSession|currentUser|verifyIdToken|auth))\s*\(/.exec(expr)
    const callee = call?.[1]
    const identityCall = callee && !/\.(?:body|query|headers|cookies)\b/.test(callee)
    if (identityCall) {
      if (!/^await\s+/.test(expr)) return { kind: 'promise' }
      const masked = maskJsNoise(expr)
      let depth = 1, end = call![0].length
      for (; end < masked.length && depth > 0; end++) {
        if (masked[end] === '(') depth++
        else if (masked[end] === ')') depth--
      }
      if (depth !== 0 || masked.slice(end).trim() !== '') return { kind: 'opaque' }
      if (/\|\||&&|\?(?!\.)|\.then\s*\(/.test(expr) || /\.catch\s*\(/.test(expr)) return { kind: 'opaque' }
      // Supabase 的 getSession 直接读取 Cookie 中的会话而不重新验证，服务端不能据此确认身份。
      // 来源：https://supabase.com/docs/guides/auth/server-side/nextjs
      if (/\.auth\.getSession\s*\($/.test(call![0])) return { kind: 'opaque' }
      // Supabase 返回 { data: { user } } 或 { data: { claims } }，只有对应字段才是已验证身份。
      const envelope = /\.auth\.(getUser|getClaims)\s*\($/.exec(call![0])?.[1]
      if (envelope) return { kind: 'envelope', field: envelope === 'getUser' ? 'user' : 'claims' }
      return { kind: 'identity' }
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
      value = assignment.projection === null ? { kind: 'opaque' } : project(value, assignment.projection)
    } else if (this.parameters.has(name)) value = { kind: 'parameter', parameters: [this.parameters.get(name)!] }
    else value = { kind: 'unknown' }
    return project(value, access[2]!.split(/\??\./).filter(Boolean))
  }
}

/** 返回所需实参索引；空数组表示已识别身份，null 表示未验证来源。 */
export function identityRequirement(value: AuthValue, allowParameters: boolean): number[] | null {
  if (value.kind === 'identity') return []
  if (allowParameters && value.kind === 'parameter') return value.parameters ?? []
  return null
}
