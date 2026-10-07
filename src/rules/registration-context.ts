/** 注册位置的有界上下文；未知分支保留路由，但不能提供跨分支鉴权证明。 */
import type { FunctionBody } from './apiauth.js'

interface Region { start: number; end: number; dead: boolean; owner: boolean }
export interface RegistrationContext {
  readonly limited: boolean
  reachable(at: number): boolean
  covers(guard: number, operation: number): boolean
}

export function registrationContext(code: string, pairs: Map<number, number>, bodies: FunctionBody[]): RegistrationContext {
  const regions: Region[] = []
  const openers = new Map([...pairs].map(([open, close]) => [close, open]))
  const controlBraces = new Set<number>()
  let limited = false
  const space = (at: number) => { while (at < code.length && /\s/.test(code[at]!)) at++; return at }
  const add = (start: number, end: number, dead = false, owner = false) => {
    if (regions.some(region => region.start === start && region.end === end && region.dead === dead && region.owner === owner)) return
    if (regions.length >= 512) { limited = true; return }
    regions.push({ start, end, dead, owner })
  }
  const literal = (text: string): boolean | null => {
    const match = /^\s*(!\s*)?(true|false)\s*$/.exec(text)
    return match ? (match[2] === 'true') !== Boolean(match[1]) : null
  }
  const simpleEnd = (start: number): number => {
    for (let at = start; at < code.length; at++) {
      const quote = code[at]
      if (quote === '"' || quote === "'" || quote === '`') {
        let end = at + 1
        for (; end < code.length; end++) {
          if (quote === '`' && code[end] === '$' && code[end + 1] === '{') {
            const close = pairs.get(end + 1)
            if (close !== undefined) { end = close; continue }
          }
          if (code[end] === quote) break
        }
        if (end === code.length) limited = true
        at = end; continue
      }
      const end = pairs.get(at)
      if (end !== undefined) { at = end; continue }
      if (/[;,}\n]/.test(code[at]!)) return at + (code[at] === ';' ? 1 : 0)
    }
    return code.length
  }
  // 包含 else 的整个语句须一次定位，避免悬挂 else 被借到外层分支。
  const statementEnd = (rawStart: number, depth = 0): number => {
    const start = space(rawStart)
    if (depth >= 32) { limited = true; return code.length }
    if (code[start] === '{') { const end = pairs.get(start); if (end === undefined) limited = true; return (end ?? code.length - 1) + 1 }
    const head = /^(if|for(?:\s+await)?|while|switch|with)\s*\(/.exec(code.slice(start, start + 100))
    if (head) {
      const close = pairs.get(start + head[0].length - 1)
      if (close === undefined) { limited = true; return code.length }
      let end = statementEnd(close + 1, depth + 1)
      const tail = space(end)
      if (head[1] === 'if' && /^else\b/.test(code.slice(tail, tail + 8))) end = statementEnd(tail + 4, depth + 1)
      return end
    }
    return simpleEnd(start)
  }
  for (const body of bodies) add(body.start, body.end + 1, false, true)
  for (const match of code.matchAll(/=>\s*(?!\s*\{)/g)) {
    const start = space(match.index + 2)
    if (code[start] !== '{') add(start, simpleEnd(start), false, true)
  }
  for (const match of code.matchAll(/(?<![\w$.])(if|for(?:\s+await)?|while|switch|catch|with)\s*\(/g)) {
    const open = match.index + match[0].length - 1, close = pairs.get(open)
    if (close === undefined) { limited = true; continue }
    const start = space(close + 1), end = statementEnd(start)
    if (code[start] === '{') controlBraces.add(start)
    const condition = literal(code.slice(open + 1, close))
    if (match[1] === 'if') {
      if (condition !== true) add(start, end, condition === false)
      const next = space(end)
      if (/^else\b/.test(code.slice(next, next + 8))) {
        const alternate = space(next + 4), alternateEnd = statementEnd(alternate)
        if (code[alternate] === '{') controlBraces.add(alternate)
        if (condition !== false) add(alternate, alternateEnd, condition === true)
      }
    } else {
      add(start, end, match[1] === 'while' && condition === false)
      if (match[1] === 'switch' && code[start] === '{') {
        const labels: number[] = []
        for (let at = start + 1; at < end - 1; at++) {
          const nested = pairs.get(at)
          if (nested !== undefined) { at = nested; continue }
          if ((at === 0 || !/[\w$.]/.test(code[at - 1]!)) && /^(?:case|default)\b/.test(code.slice(at, at + 10))) labels.push(at)
        }
        labels.forEach((at, index) => add(at, labels[index + 1] ?? end - 1))
      }
    }
  }
  for (const match of code.matchAll(/(?<![\w$.])(?:try|finally|do|catch)\s*\{/g)) {
    const start = match.index + match[0].length - 1
    controlBraces.add(start); add(start, (pairs.get(start) ?? code.length - 1) + 1)
  }
  // 普通块不隔离无条件注册；方法块则与函数一样不能向外借用中间件。
  for (const [start, end] of pairs) {
    if (code[start] !== '{' || controlBraces.has(start) || bodies.some(body => body.start === start)) continue
    if (/\)\s*(?::[\w\s.<>,[\]|?]+)?$/.test(code.slice(Math.max(0, start - 200), start))) add(start, end + 1, false, true)
  }
  const contains = (region: Region, at: number) => region.start <= at && at < region.end
  const owner = (at: number) => regions.filter(region => region.owner && contains(region, at))
    .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0]
  const inline = (at: number): 'always' | 'conditional' | 'dead' => {
    // 只读当前语句前缀；复杂短路表达式不构成跨调用保护证明。
    let start = at
    for (let cursor = at - 1; cursor >= 0; cursor--) {
      if (at - cursor > 4000) { limited = true; return 'conditional' }
      const open = openers.get(cursor)
      if (open !== undefined) { cursor = open; start = open; continue }
      if (code[cursor] === ';' || code[cursor] === '{') { start = cursor + 1; break }
      if (code[cursor] === '\n' && !/[&|?:=,(.\\]$/.test(code.slice(Math.max(0, cursor - 100), cursor).trimEnd())) { start = cursor + 1; break }
      start = cursor
    }
    let prefix = ''
    for (let cursor = start; cursor < at; cursor++) {
      const close = pairs.get(cursor)
      if (close !== undefined && close < at) { prefix += ' '; cursor = close; continue }
      prefix += code[cursor]
    }
    prefix = prefix.trim()
    const simple = /^(?:const\s+[\w$]+\s*=\s*)?(!?\s*(?:true|false))\s*(&&|\|\|)\s*$/.exec(prefix)
    if (simple) {
      const truth = literal(simple[1]!)!
      return (simple[2] === '&&' ? truth : !truth) ? 'always' : 'dead'
    }
    return /&&|\|\||\?/.test(prefix) ? 'conditional' : 'always'
  }
  const reachable = (at: number) => limited || (!regions.some(region => region.dead && contains(region, at)) && inline(at) !== 'dead')
  return {
    get limited() { return limited },
    reachable,
    covers(guard, operation) {
      if (limited || !reachable(guard) || inline(guard) !== 'always') return false
      const guardOwner = owner(guard)
      if (guardOwner && guardOwner !== owner(operation)) return false
      return regions.filter(region => !region.dead && contains(region, guard)).every(region => contains(region, operation))
    },
  }
}
