/** 会话和事件验证共用的函数边界、顺序及异常传播检查。 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { delimiterPairs, functionBodies, type FunctionBody } from './apiauth.js'

export class LocalVerification {
  readonly code: string
  readonly source: string
  readonly pairs: Map<number, number>
  readonly bodies: FunctionBody[]

  constructor(file: ScanFile, private readonly responseExits = false) {
    this.code = noiseMaskedOf(file)
    this.source = commentsMaskedOf(file)
    this.pairs = delimiterPairs(this.code)
    this.bodies = functionBodies(this.code, this.pairs)
  }

  owner(at: number): FunctionBody | undefined {
    return this.bodies.filter(b => b.start < at && at < b.end).sort((a, b) => b.start - a.start)[0]
  }

  skipSpace(at: number): number {
    while (/\s/.test(this.code[at] ?? '')) at++
    return at
  }

  endOf(at: number, limit = this.code.length): number {
    if (this.code[at] === '{') return (this.pairs.get(at) ?? limit - 1) + 1
    for (let i = at; i < limit; i++) {
      if (/[;\n}]/.test(this.code[i]!)) return i
      const end = this.pairs.get(i)
      if (end !== undefined) i = end
    }
    return limit
  }

  /**
   * 块的顶层有无条件退出即算退出，前面可以有记录日志等语句；
   * 嵌套分支、函数中的 return 以及无花括号 if/else/循环控制的 return 不算。
   */
  exits(from: number, to: number): boolean {
    let at = this.skipSpace(from)
    if (this.code[at] !== '{') return /^(?:return|throw)\b|^(?:redirect|notFound)\s*\(/.test(this.code.slice(at, to))
    const end = Math.min(to, this.pairs.get(at) ?? to)
    at = this.skipSpace(at + 1)
    while (at < end) {
      const statement = this.code.slice(at, this.statementEnd(at, end))
      if (/^return\b/.test(statement) && this.responseExits) {
        // 异步钩子 return undefined 并不拒绝请求，须返回响应或传递错误。
        if (/^return\s+(?:(?:await\s+)?(?:reply|res|response)\s*\.[\s\S]*\b(?:send|end|json|sendStatus)\s*\(|(?:c|ctx|context)\s*\.\s*(?:json|text|body|html|redirect|newResponse)\s*\(|new\s+Response\s*\(|next\s*\(\s*[^)\s])/.test(statement)) return true
        return false
      }
      if (/^(?:return|throw)\b|^(?:redirect|notFound)\s*\(/.test(statement)) return true
      if (this.responseExits && /^reply\s*\.\s*(?:(?:code|status)\s*\([^)]*\)\s*\.\s*)?send\s*\(/.test(this.code.slice(at, end))) return true
      const next = this.statementEnd(at, end)
      if (next <= at) return false
      at = this.skipSpace(next)
    }
    return false
  }

  /** 跳过完整语句；分支、循环和函数内的退出不提升为外层退出。 */
  private statementEnd(at: number, limit: number, depth = 0): number {
    if (depth >= 64) return limit
    if (this.code[at] === '{') return (this.pairs.get(at) ?? limit - 1) + 1
    const control = /^(if|for(?:\s+await)?|while|with|switch)\s*\(/.exec(this.code.slice(at, at + 80))
    if (control) {
      const close = this.pairs.get(at + control[0].length - 1)
      if (close === undefined) return limit
      let end = this.statementEnd(this.skipSpace(close + 1), limit, depth + 1)
      const next = this.skipSpace(end)
      if (control[1] === 'if' && /^else\b/.test(this.code.slice(next, next + 5))) {
        end = this.statementEnd(this.skipSpace(next + 4), limit, depth + 1)
      }
      return end
    }
    // 不展开异常控制流或 do 循环，避免 finally、break 等改变退出效果。
    if (/^(?:try|do)\b/.test(this.code.slice(at, at + 8))) return limit
    for (let i = at; i < limit; i++) {
      if (this.code[i] === ';') return i + 1
      const close = this.pairs.get(i)
      if (close !== undefined) { i = close; continue }
      if (this.code[i] !== '\n') continue
      const before = this.code.slice(at, i).trimEnd()
      const after = this.code.slice(i + 1, limit).trimStart()
      if (!before || /[=+\-*/%&|^!?:,.([{<>]$/.test(before)) continue
      if (/^[.?+\-*/%&|^,:<>=([{`]/.test(after)) continue
      // 箭头函数体以及声明头部允许换行，不能据此产生新语句。
      if (/\b(?:const|let|var|function|async|await|new|yield)$/.test(before)) continue
      return i + 1
    }
    return limit
  }

  /** 验证与使用须在同一函数，且不能依赖可选分支或被吞掉的异常。 */
  enforcedBefore(from: number, to: number): boolean {
    const owner = this.owner(from)
    if (from >= to || owner !== this.owner(to)) return false
    const start = owner ? owner.start + 1 : 0
    for (let i = start; i < from; i++) {
      const conditional = /^(?:if|for|while|switch)\s*\(/.exec(this.code.slice(i, i + 32))
      if (conditional && !/[\w$]/.test(this.code[i - 1] ?? '')) {
        const close = this.pairs.get(i + conditional[0].length - 1)
        if (close !== undefined) {
          const body = this.skipSpace(close + 1)
          const end = this.endOf(body)
          if (from < end && to >= end) return false
        }
      }
      const end = this.pairs.get(i)
      if (end === undefined) continue
      if (end < from) { i = end; continue }
      if (end >= to) continue
      // 普通调用的实参会同步求值；可选调用和控制条件不提供必经证明。
      if (this.code[i] === '(' && !/(?:\?\.|\b(?:if|for|while|switch|catch))\s*$/.test(this.code.slice(Math.max(start, i - 20), i))) continue
      if (this.code[i] !== '{' || !/\btry\s*$/.test(this.code.slice(Math.max(start, i - 16), i))) return false
      let next = this.skipSpace(end + 1)
      if (/^catch\b/.test(this.code.slice(next))) {
        next = this.skipSpace(next + 5)
        if (this.code[next] === '(') next = this.skipSpace((this.pairs.get(next) ?? next) + 1)
        const caughtEnd = this.endOf(next)
        if (!this.exits(next, caughtEnd)) return false
        next = this.skipSpace(caughtEnd)
      }
      if (/^finally\b/.test(this.code.slice(next))) return false
    }
    // 短路、三元或未等待的表达式不能伪装成独立验证语句。
    let boundary = start
    for (const [open, close] of this.pairs) {
      if (this.code[open] === '{' && open < from && close > from) boundary = Math.max(boundary, open + 1)
    }
    // 按完整语句移动起点；换行后的 &&、||、三元分支不能脱离其条件。
    while (boundary < from) {
      const next = this.statementEnd(this.skipSpace(boundary), this.code.length)
      if (next <= boundary || next > from) break
      boundary = next
    }
    return !/[?]|&&|\|\||=>/.test(this.code.slice(boundary, from))
  }

  /** 找出当前函数中最后一次赋值；未知或条件覆盖同样会使旧证明失效。 */
  assignment(name: string, at: number): { at: number; from: number; end: number; expression: string; member: boolean } | null {
    const escaped = name.replace(/\$/g, '\\$')
    const pattern = new RegExp(`(?<![\\w$.])(?:const\\s+|let\\s+|var\\s+)?${escaped}((?:\\s*\\.[\\w$]+|\\s*\\[[^\\]]*\\])*)\\s*(?::[^=;{}\\n]{0,100})?=(?![=>])`, 'g')
    let result = null
    for (const m of this.code.slice(0, at).matchAll(pattern)) {
      if (this.owner(m.index) !== this.owner(at)) continue
      const from = this.skipSpace(m.index + m[0].length)
      const end = this.endOf(from)
      if (end <= at) result = { at: m.index, from, end, expression: this.code.slice(from, end).trim(), member: m[1]!.length > 0 }
    }
    return result
  }
}

/** 将中间件片段置于独立函数中，校验调用须先于所有 next() 放行点。 */
export function enforcedVerification(source: string, pattern: RegExp, synchronous: RegExp = /(?!)/): boolean {
  const fragment = new LocalVerification({ path: 'middleware.ts', content: source, lines: source.split('\n'), isExampleContext: false })
  const first = fragment.code.search(/\S/)
  let body = fragment.code[first] === '{' ? { start: first, end: fragment.pairs.get(first) ?? fragment.code.length - 1 }
    : fragment.bodies.find(b => b.declaration >= first)
  if (body) {
    const returned = fragment.bodies.find(b => b.declaration > body!.start && b.end < body!.end &&
      /^\s*return\s+(?:createMiddleware\s*\(\s*)?(?:async\s*)?(?:\([^)]*\)\s*)?$/.test(fragment.code.slice(body!.start + 1, b.declaration)))
    if (returned) body = returned
  }
  const inner = body ? source.slice(body.start + 1, body.end) : source
  const content = `async function __guard__(){\n${inner}\n__continuation__();\n}`
  const context = new LocalVerification({ path: 'middleware.ts', content, lines: content.split('\n'), isExampleContext: false }, true)
  const owner = context.bodies[0]
  let end = content.lastIndexOf('__continuation__')
  for (const m of context.code.matchAll(/(?<![\w$.])next\s*\(\s*\)/g)) {
    if (context.owner(m.index) === owner) end = Math.min(end, m.index)
  }
  const calls = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`)
  for (const m of context.code.matchAll(calls)) {
    if (context.owner(m.index) !== owner || !context.enforcedBefore(m.index, end)) continue
    const close = context.pairs.get(m.index + m[0].length - 1)
    if (close === undefined || /^[.[]|^\?\./.test(context.code.slice(context.skipSpace(close + 1)))) continue
    const before = context.code.slice(Math.max(owner?.start ?? 0, m.index - 300), m.index)
      .replace(/(?:[A-Za-z_$][\w$]*(?:\s*\([^()]*\))?\s*\??\.\s*)*$/, '').trimEnd()
    if (/(?:^|[^\w$.])(?:await|return)$/.test(before) || synchronous.test(m[0])) return true
  }
  return false
}
