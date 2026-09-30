/** 会话和事件验证共用的函数边界、顺序及异常传播检查。 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { delimiterPairs, functionBodies, type FunctionBody } from './apiauth.js'

export class LocalVerification {
  readonly code: string
  readonly source: string
  readonly pairs: Map<number, number>
  readonly bodies: FunctionBody[]
  private openers: Map<number, number> | null = null

  constructor(file: ScanFile) {
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
    for (let i = at + 1; i < end; i++) {
      const close = this.pairs.get(i)
      if (close !== undefined) { i = close; continue }
      if (/[\w$.]/.test(this.code[i - 1] ?? '')) continue
      if (!/^(?:(?:return|throw)\b|(?:redirect|notFound)\s*\()/.test(this.code.slice(i, i + 16))) continue
      if (!this.controlled(i, at)) return true
    }
    return false
  }

  /** 语句是否受无花括号的 if/else/for/while 控制，如 if (x) return。 */
  private controlled(statement: number, blockStart: number): boolean {
    let before = statement - 1
    while (before > blockStart && /\s/.test(this.code[before]!)) before--
    if (/\belse$/.test(this.code.slice(Math.max(blockStart, before - 4), before + 1))) return true
    if (this.code[before] !== ')') return false
    if (!this.openers) {
      this.openers = new Map()
      for (const [open, close] of this.pairs) this.openers.set(close, open)
    }
    const open = this.openers.get(before)
    return open !== undefined && /\b(?:if|for|while|with)\s*$/.test(this.code.slice(Math.max(blockStart, open - 8), open))
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
    const boundary = Math.max(start, this.code.lastIndexOf(';', from - 1) + 1,
      this.code.lastIndexOf('\n', from - 1) + 1, this.code.lastIndexOf('{', from - 1) + 1)
    return !/[?]|&&|\|\|/.test(this.code.slice(boundary, from))
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
