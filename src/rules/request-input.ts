/**
 * 有界追踪路由函数内的请求输入：只识别同一函数内的简单赋值、解构与字符串拼接，不跨函数，不执行代码。
 * 所有文本均为屏蔽注释和字符串内容后的代码，偏移与原文一致。
 */
import { namePattern } from './bindings.js'
import type { FunctionBody } from './apiauth.js'

/** direct：请求值经赋值、解构或字符串拼接原样到达；derived：中途经过其他调用，无法确认是否已校验。 */
export type InputLevel = 'direct' | 'derived'

export interface Taint {
  level: InputLevel
  /** 请求输入被读取的位置。 */
  origin: number
  /** 表达式引用的已追踪变量，用于检查使用前是否校验过。 */
  names: Set<string>
}

/** 处理函数参数的角色：请求对象、URL 对象、Cookie 对象，或本身即为调用方可控的值。 */
export interface ParamRoles {
  objects: Map<string, number>
  urls: Map<string, number>
  cookies: Map<string, number>
  values: Map<string, number>
}

const MAX_PASSES = 8
const MAX_ASSIGNMENTS = 512
const MAX_EXPRESSION = 4000

/** 常见请求对象参数名：Next.js、Remix、Astro 的 request/context，Pages Router 的 req，Nuxt/h3 的 event。 */
const REQUEST_OBJECT_NAMES = /^(?:req|request|event|evt|ctx|context)$/

/** 解构参数中携带请求数据的键；locals、platform、fetch 等由服务器提供，不是输入。 */
const DESTRUCTURED_OBJECTS = new Set(['request', 'req', 'event'])
const DESTRUCTURED_URLS = new Set(['url'])
const DESTRUCTURED_COOKIES = new Set(['cookies'])
const DESTRUCTURED_VALUES = new Set(['params', 'query', 'body', 'searchParams'])

/** 不改变输入内容的调用：读取请求体、取参数、类型转换为字符串及大小写、首尾空白处理。 */
const TRANSPARENT_CALLS = new Set([
  'json', 'formData', 'text', 'arrayBuffer', 'blob', 'get', 'getAll', 'String', 'trim', 'trimStart', 'trimEnd',
  'toString', 'toLowerCase', 'toUpperCase', 'URL', 'URLSearchParams', 'decodeURIComponent', 'decodeURI',
  'fromEntries', 'entries', 'readBody', 'readFormData', 'readRawBody', 'getQuery', 'getRouterParam',
  'getRouterParams', 'getHeader', 'getHeaders', 'getRequestHeader', 'getRequestHeaders', 'getCookie',
  'parseCookies', 'getRequestURL',
])

/** h3 读取请求内容的辅助函数，第一个实参为事件对象。 */
const H3_READERS = 'readBody|readFormData|readMultipartFormData|readRawBody|readValidatedBody|getQuery|getValidatedQuery|' +
  'getRouterParams?|getValidatedRouterParams|getHeaders?|getRequestHeaders?|getCookie|parseCookies|getRequestURL'

/**
 * 结果不再携带原始字符串的表达式：数值与布尔转换、长度、比较、转义函数、字面量三元及查表。
 * 查表如 COLUMNS[sort]，只能取到代码中预先写好的值。
 */
const LITERAL = String.raw`(?:'[^']*'|"[^"]*"|\x60[^\x60$]*\x60|-?\d+(?:\.\d+)?|null|undefined|true|false)`
const CLEAN_EXPRESSION = [
  /^(?:await\s+)?(?:Number|parseInt|parseFloat|Boolean|BigInt|isNaN|Math\s*\.\s*\w+|Number\s*\.\s*\w+)\s*\(/,
  /^(?:await\s+)?(?:[\w$]+\s*\.\s*)*(?:escape\w*|quote\w*|sanitiz\w*)\s*\(/i,
  /\.\s*length\s*$/,
  /^(?:!|typeof\b)/,
  /\.\s*(?:includes|test|has|startsWith|endsWith|some|every)\s*\([^?]*\)\s*$/,
  new RegExp(String.raw`^[^?]*\?\s*${LITERAL}\s*:\s*${LITERAL}\s*$`),
  new RegExp(String.raw`^[\w$.]+\s*\[[^\]]*\]\s*(?:(?:\?\?|\|\|)\s*${LITERAL})?\s*$`),
  // 带标签的模板由标签函数处理插值（Prisma.sql、sql、html），String.raw 除外。
  /^(?:await\s+)?(?!String\s*\.\s*raw\b)[\w$]+(?:\s*\.\s*[\w$]+)*\s*\x60/,
]

/** 顶层比较运算，排除箭头函数与三元条件中的比较。 */
function isComparison(expr: string): boolean {
  return !/\?/.test(expr) && !/=>/.test(expr) && /(?:===|!==|==|!=|<=|>=|\binstanceof\b)/.test(expr)
}

/** 读取参数文本中的绑定名称：处理默认值、类型标注和一层对象解构。 */
function parameterList(text: string): string[] {
  const parts: string[] = []
  let depth = 0, from = 0
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if ('{[(<'.includes(ch)) depth++
    else if ('}])>'.includes(ch)) depth--
    else if (ch === ',' && depth === 0) { parts.push(text.slice(from, i)); from = i + 1 }
  }
  parts.push(text.slice(from))
  return parts.map(part => part.trim()).filter(Boolean)
}

/** 对象解构的键到本地名称，如 { request: req, params } → request→req、params→params。 */
function destructuredKeys(pattern: string): Array<{ key: string; local: string }> {
  const inner = pattern.slice(1, pattern.lastIndexOf('}'))
  const result: Array<{ key: string; local: string }> = []
  for (const part of parameterList(inner)) {
    const m = /^(?:\.\.\.)?\s*([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?\s*(?:=[\s\S]*)?$/.exec(part)
    if (m) result.push({ key: m[1]!, local: m[2] ?? m[1]! })
  }
  return result
}

/** 解构模式中的全部绑定名称：去掉键名与默认值后收集标识符。 */
export function patternNames(pattern: string): string[] {
  const text = pattern.trim()
  if (/^[A-Za-z_$][\w$]*$/.test(text)) return [text]
  const stripped = text
    .replace(/[A-Za-z_$][\w$]*\s*:(?!:)/g, ' ')
    .replace(/=[^,}\]]*/g, ' ')
  return stripped.match(/[A-Za-z_$][\w$]*/g) ?? []
}

/**
 * 按参数文本判断角色。Server Function 的全部参数都来自客户端；
 * 路由处理函数只认请求对象及其解构出的请求字段。
 */
export function paramRoles(paramsText: string, paramsStart: number, allInput: boolean): ParamRoles {
  const roles: ParamRoles = { objects: new Map(), urls: new Map(), cookies: new Map(), values: new Map() }
  let offset = 0
  for (const raw of parameterList(paramsText)) {
    const at = paramsStart + Math.max(0, paramsText.indexOf(raw, offset))
    offset = Math.max(offset, paramsText.indexOf(raw, offset) + raw.length)
    // 去掉类型标注与默认值；解构模式保留花括号。
    const param = raw.startsWith('{') || raw.startsWith('[')
      ? raw.slice(0, matchingClose(raw) + 1)
      : raw.replace(/^\.\.\./, '').split(/[:=]/)[0]!.trim()
    if (allInput) {
      for (const name of patternNames(param)) roles.values.set(name, at)
      continue
    }
    if (param.startsWith('{')) {
      for (const { key, local } of destructuredKeys(param)) {
        if (DESTRUCTURED_OBJECTS.has(key)) roles.objects.set(local, at)
        else if (DESTRUCTURED_URLS.has(key)) roles.urls.set(local, at)
        else if (DESTRUCTURED_COOKIES.has(key)) roles.cookies.set(local, at)
        else if (DESTRUCTURED_VALUES.has(key)) roles.values.set(local, at)
      }
    } else if (REQUEST_OBJECT_NAMES.test(param)) roles.objects.set(param, at)
  }
  return roles
}

function matchingClose(text: string): number {
  let depth = 0
  for (let i = 0; i < text.length; i++) {
    if ('{['.includes(text[i]!)) depth++
    else if ('}]'.includes(text[i]!) && --depth === 0) return i
  }
  return text.length - 1
}

/** 函数参数列表的位置；无法确定时返回空值，不猜测参数。 */
export function parametersOf(
  code: string, body: FunctionBody, pairs: Map<number, number>, openers: Map<number, number>,
): { start: number; end: number } | null {
  const fn = /^function\s*\*?\s*(?:[\w$]+\s*)?\(/.exec(code.slice(body.declaration, body.declaration + 200))
  if (fn) {
    const open = body.declaration + fn[0].length - 1
    const close = pairs.get(open)
    return close === undefined ? null : { start: open + 1, end: close }
  }
  // 箭头函数：=> 之前是参数列表或单个参数，可带返回类型标注。
  const window = code.slice(Math.max(0, body.declaration - 200), body.declaration)
  const close = window.lastIndexOf(')')
  if (close !== -1 && /^\s*(?::[^=;{()]*)?$/.test(window.slice(close + 1))) {
    const absolute = body.declaration - window.length + close
    const open = openers.get(absolute)
    return open === undefined ? null : { start: open + 1, end: absolute }
  }
  const single = /([A-Za-z_$][\w$]*)\s*$/.exec(window)
  return single ? { start: body.declaration - window.length + single.index, end: body.declaration - window.length + single.index + single[1]!.length } : null
}

/** 表达式终点：跳过括号，遇到分号、顶层逗号、所在代码块结束或不续行的换行即停。 */
function expressionEnd(code: string, from: number, limit: number, pairs: Map<number, number>): number {
  const stop = Math.min(limit, from + MAX_EXPRESSION)
  for (let i = from; i < stop; i++) {
    const ch = code[i]!
    const close = pairs.get(i)
    if (close !== undefined) { i = close; continue }
    if (ch === ';' || ch === ',' || ch === ')' || ch === ']' || ch === '}') return i
    if (ch === '\n') {
      const before = code.slice(from, i).trimEnd()
      const after = code.slice(i + 1, i + 80).trimStart()
      if (before === '' || /[=+\-*/%&|^!?:,.([{<>]$/.test(before)) continue
      if (/^(?:[.?+\-*/%&|^,:<>=]|\?\?)/.test(after) && !/^(?:\+\+|--)/.test(after)) continue
      return i
    }
  }
  return stop
}

interface Assignment { at: number; names: string[]; expr: string; exprAt: number; iterate: boolean }

/** 一个处理函数内请求输入的流向。 */
export class InputFlow {
  readonly names = new Map<string, Taint>()
  /** 由请求输入拼接成的字符串变量及其全部拼接文本（含字符串内容），用于判断是否像 SQL。 */
  readonly built = new Map<string, Taint & { text: string }>()
  limited = false
  /** 每个变量全部赋值的原文，判断拼接出的字符串是否像 SQL 时包括不含输入的部分。 */
  private readonly assigned = new Map<string, string[]>()
  private sourcePattern: RegExp | null
  private namePatternCache: { key: string; regex: RegExp | null } = { key: '', regex: null }

  constructor(
    private readonly code: string,
    private readonly source: string,
    private readonly span: { start: number; end: number },
    private readonly pairs: Map<number, number>,
    roles: ParamRoles,
  ) {
    for (const [name, at] of roles.values) this.names.set(name, { level: 'direct', origin: at, names: new Set([name]) })
    this.sourcePattern = sourceRegex(roles)
    this.propagate()
  }

  /** 表达式是否携带请求输入；已转换为数值、布尔或查表结果的不算。 */
  taintOf(expr: string, exprAt: number): Taint | null {
    const text = expr.trim()
    if (text === '' || CLEAN_EXPRESSION.some(pattern => pattern.test(text)) || isComparison(text)) return null
    let found: Taint | null = null
    if (this.sourcePattern) {
      this.sourcePattern.lastIndex = 0
      const m = this.sourcePattern.exec(expr)
      if (m) found = mergeTaint(found, { level: 'direct', origin: exprAt + m.index, names: new Set() })
    }
    const refs = this.nameRegex()
    if (refs) {
      refs.lastIndex = 0
      for (const m of expr.matchAll(refs)) {
        const before = expr.slice(0, m.index).trimEnd()
        const after = expr.slice(m.index + m[0].length).trimStart()
        // 对象字面量的键不是引用。
        if (/^:(?!:)/.test(after) && /[{,]$/.test(before)) continue
        const t = this.names.get(m[0])
        if (t) found = mergeTaint(found, t)
      }
    }
    if (!found) return null
    // JSON.parse 只改变形式；schema.parse 等校验调用使结果降为 derived。
    const calls = [...text.replace(/\bJSON\s*\.\s*parse\s*\(/g, '(').matchAll(/([\w$]+)\s*\(/g)].map(m => m[1]!)
    if (calls.some(name => !TRANSPARENT_CALLS.has(name))) found.level = 'derived'
    return found
  }

  /** 字符串拼接：无标签模板的插值或含字符串操作数的 + 拼接中携带请求输入。 */
  builtOf(expr: string, exprAt: number): Taint | null {
    const text = expr.trim()
    const lead = expr.length - expr.trimStart().length
    if (text.startsWith('\x60')) return this.interpolationTaint(exprAt + lead, exprAt + lead + text.length)
    const operands = this.topLevelOperands(expr, exprAt)
    if (operands.length < 2 || !operands.some(o => /^['"\x60]/.test(o.text.trim()))) return null
    let found: Taint | null = null
    for (const operand of operands) {
      const t = operand.text.trim().startsWith('\x60')
        ? this.interpolationTaint(operand.at, operand.at + operand.text.length)
        : this.taintOf(operand.text, operand.at)
      if (t) found = mergeTaint(found, t)
    }
    return found
  }

  assignedText(name: string): string {
    return (this.assigned.get(name) ?? []).join('\n')
  }

  /** 使用前是否检查过内容：条件中除存在性判断外的引用，或作为校验函数实参。 */
  validatedBefore(names: Set<string>, at: number): boolean {
    if (names.size === 0) return false
    const region = this.code.slice(this.span.start, at)
    const pattern = new RegExp(`(?<![\\w$.])(?:${namePattern(names)})(?![\\w$])`)
    for (const m of region.matchAll(/\b(?:if|switch)\s*\(/g)) {
      const open = this.span.start + m.index + m[0].length - 1
      const close = this.pairs.get(open)
      if (close === undefined || close > at) continue
      const condition = this.code.slice(open + 1, close)
      const alternatives = namePattern(names)
      const substantive = condition
        .replace(new RegExp(`!\\s*(?:${alternatives})(?![\\w$.(\\[])`, 'g'), ' ')
        .replace(new RegExp(`(?<![\\w$.])(?:${alternatives})\\s*[!=]==?\\s*(?:null|undefined|''|""|0)`, 'g'), ' ')
        .replace(new RegExp(`\\btypeof\\s+(?:${alternatives})\\b`, 'g'), ' ')
      if (pattern.test(substantive)) return true
    }
    const validator = /(?:\.\s*(?:test|match|includes|has|startsWith|endsWith|parse|safeParse)|(?<![\w$.])(?:valid\w*|sanitiz\w*|escape\w*|is[A-Z]\w*|assert\w*))\s*\(/gi
    for (const m of region.matchAll(validator)) {
      const open = this.span.start + m.index + m[0].length - 1
      const close = this.pairs.get(open)
      if (close !== undefined && close <= at && pattern.test(this.code.slice(open + 1, close))) return true
    }
    return false
  }

  private interpolationTaint(from: number, to: number): Taint | null {
    let found: Taint | null = null
    for (let i = from; i < to - 1; i++) {
      if (this.code[i] !== '$' || this.code[i + 1] !== '{') continue
      const close = this.pairs.get(i + 1)
      if (close === undefined) continue
      const t = this.taintOf(this.code.slice(i + 2, close), i + 2)
      i = close
      if (t) found = mergeTaint(found, t)
    }
    return found
  }

  private topLevelOperands(expr: string, exprAt: number): Array<{ text: string; at: number }> {
    const result: Array<{ text: string; at: number }> = []
    let from = 0
    for (let i = 0; i < expr.length; i++) {
      const close = this.pairs.get(exprAt + i)
      if (close !== undefined) { i = close - exprAt; continue }
      if (expr[i] === '+' && expr[i + 1] !== '+' && expr[i + 1] !== '=' && expr[i - 1] !== '+') {
        result.push({ text: expr.slice(from, i), at: exprAt + from })
        from = i + 1
      }
    }
    result.push({ text: expr.slice(from), at: exprAt + from })
    return result
  }

  private nameRegex(): RegExp | null {
    const key = [...this.names.keys()].sort().join(',')
    if (key !== this.namePatternCache.key) {
      this.namePatternCache = { key, regex: key === '' ? null : new RegExp(`(?<![\\w$.])(?:${namePattern(this.names.keys())})(?![\\w$])`, 'g') }
    }
    return this.namePatternCache.regex
  }

  /** 收集函数内的声明、重新赋值和 for...of，按轮次传播到不再变化或达到上限。 */
  private propagate(): void {
    const assignments = this.assignments()
    for (const a of assignments) for (const name of a.names) {
      const list = this.assigned.get(name) ?? []
      if (list.length < 16) list.push(this.source.slice(a.exprAt, a.exprAt + a.expr.length))
      this.assigned.set(name, list)
    }
    for (let pass = 0; pass < MAX_PASSES; pass++) {
      let changed = false
      for (const a of assignments) {
        const built = a.iterate ? null : this.builtOf(a.expr, a.exprAt)
        const taint = built ?? this.taintOf(a.expr, a.exprAt)
        if (!taint) continue
        for (const name of a.names) {
          const previous = this.names.get(name)
          if (!previous || (previous.level === 'derived' && taint.level === 'direct')) {
            this.names.set(name, { level: taint.level, origin: taint.origin, names: new Set([name, ...taint.names]) })
            changed = true
          }
          const text = this.source.slice(a.exprAt, a.exprAt + a.expr.length)
          const existing = this.built.get(name)
          if (built && a.names.length === 1) {
            if (!existing) {
              this.built.set(name, { level: built.level, origin: built.origin, names: new Set([name, ...built.names]), text })
              changed = true
            } else if (!existing.text.includes(text)) {
              existing.text += `\n${text}`
            }
          }
        }
      }
      if (!changed) return
      if (pass === MAX_PASSES - 1) this.limited = true
    }
  }

  private assignments(): Assignment[] {
    const { code, span, pairs } = this
    const region = code.slice(span.start, span.end)
    const found: Assignment[] = []
    const push = (a: Assignment): void => {
      if (found.length >= MAX_ASSIGNMENTS) { this.limited = true; return }
      found.push(a)
    }
    // 声明：const a = …，const { a, b: c } = …，const [a] = …；同一语句的多个声明逐个读取。
    for (const m of region.matchAll(/\b(?:const|let|var)\s+/g)) {
      let at = span.start + m.index + m[0].length
      for (let guard = 0; guard < 16; guard++) {
        let patternEnd: number
        if (code[at] === '{' || code[at] === '[') {
          const close = pairs.get(at)
          if (close === undefined) break
          patternEnd = close + 1
        } else {
          const id = /^[A-Za-z_$][\w$]*/.exec(code.slice(at, at + 200))
          if (!id) break
          patternEnd = at + id[0].length
        }
        const pattern = code.slice(at, patternEnd)
        const rest = code.slice(patternEnd, patternEnd + 400)
        // for (const x of items)
        const forOf = /^\s+of\s+/.exec(rest)
        if (forOf) {
          const exprAt = patternEnd + forOf[0].length
          const end = expressionEnd(code, exprAt, span.end, pairs)
          push({ at, names: patternNames(pattern), expr: code.slice(exprAt, end), exprAt, iterate: true })
          break
        }
        const eq = /^\s*(?::[^=;]{0,200}?)?=(?![=>])/.exec(rest)
        if (!eq) break
        const exprAt = patternEnd + eq[0].length
        const end = expressionEnd(code, exprAt, span.end, pairs)
        push({ at, names: patternNames(pattern), expr: code.slice(exprAt, end), exprAt, iterate: false })
        if (code[end] !== ',') break
        at = end + 1
        while (/\s/.test(code[at] ?? '')) at++
      }
    }
    // 重新赋值：name = …、name += …；成员赋值与比较不算。
    for (const m of region.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*(\+?=)(?![=>])/g)) {
      const before = region.slice(Math.max(0, m.index - 8), m.index)
      if (/\b(?:const|let|var)\s+$/.test(before)) continue
      const exprAt = span.start + m.index + m[0].length
      const end = expressionEnd(code, exprAt, span.end, pairs)
      push({ at: span.start + m.index, names: [m[1]!], expr: code.slice(exprAt, end), exprAt, iterate: false })
    }
    return found
  }
}

/** 由参数角色构造请求读取表达式的模式。 */
function sourceRegex(roles: ParamRoles): RegExp | null {
  const parts: string[] = []
  if (roles.objects.size > 0) {
    const objects = namePattern(roles.objects.keys())
    parts.push(
      String.raw`(?<![\w$.])(?:${objects})(?:\s*\??\.\s*(?:request|event))?\s*\??\.\s*(?:json|formData|text|arrayBuffer|blob|body|query|params|url|nextUrl|headers|cookies|searchParams)\b`,
      String.raw`(?<![\w$.])(?:${objects})\s*\??\.\s*context\s*\??\.\s*params\b`,
      String.raw`\b(?:${H3_READERS})\s*(?:<[^()]{0,200}>\s*)?\(\s*(?:${objects})\b`,
    )
  }
  if (roles.urls.size > 0) {
    parts.push(String.raw`(?<![\w$.])(?:${namePattern(roles.urls.keys())})\s*\??\.\s*(?:searchParams|pathname|search|href|hash)\b`)
  }
  if (roles.cookies.size > 0) {
    parts.push(String.raw`(?<![\w$.])(?:${namePattern(roles.cookies.keys())})\s*\??\.\s*get(?:All)?\s*\(`)
  }
  return parts.length === 0 ? null : new RegExp(parts.join('|'), 'g')
}

/** 合并两处来源：任一处经过其他调用即整体降为 derived。 */
function mergeTaint(found: Taint | null, t: Taint): Taint {
  if (!found) return { level: t.level, origin: t.origin, names: new Set(t.names) }
  if (t.level === 'derived') found.level = 'derived'
  for (const n of t.names) found.names.add(n)
  return found
}

/** 参数角色是否包含任何请求来源。 */
export function hasInput(roles: ParamRoles): boolean {
  return roles.objects.size + roles.urls.size + roles.cookies.size + roles.values.size > 0
}
