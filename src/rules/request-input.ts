/**
 * 有界追踪路由函数内的请求输入：只识别同一函数内的简单赋值、解构与字符串拼接，不跨函数，不执行代码。
 * 所有文本均为屏蔽注释和字符串内容后的代码，偏移与原文一致。
 */
import type { ScanContext, ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { namePattern } from './bindings.js'
import { lineStartsOf } from './offsets.js'
import { delimiterPairs, functionBodies, routeOf, serverActionRoutes, type FunctionBody, type Route } from './apiauth.js'

/** direct：请求值经赋值、解构或字符串拼接原样到达；derived：中途经过其他调用，无法确认是否已校验。 */
export type InputLevel = 'direct' | 'derived'

export interface Taint {
  level: InputLevel
  /** 请求输入被读取的位置。 */
  origin: number
  /** 表达式引用的已追踪变量，用于检查使用前是否校验过。 */
  names: Set<string>
  /**
   * 值只是请求自身的 URL（request.url、nextUrl 及其副本）：主机固定为本站，只有其中的查询、路径可控。
   * 注入仍按输入处理；判断请求能否改变外部请求或跳转的目标主机时不算。
   */
  ownUrl: boolean
  /**
   * 值是未知函数的返回结果（如用输入查询数据库得到的行）。整体使用仍保留待复核；
   * 取其属性或解构出的字段是函数产出的数据，不再视为请求输入。
   */
  opaque?: boolean
}

/** 处理函数参数的角色：请求对象、URL 对象、Cookie 对象，或本身即为调用方可控的值。 */
export interface ParamRoles {
  objects: Map<string, number>
  urls: Map<string, number>
  cookies: Map<string, number>
  values: Map<string, number>
}

const MAX_VALUE_HOPS = 8
const MAX_ASSIGNMENTS = 512
/**
 * 单条表达式的分析上限。表达式终点靠括号配对跳转查找，开销与长度近似线性；
 * 现代代码中包含长回调的调用很常见，上限过低会把普通文件误报为扫描不完整。
 */
export const MAX_EXPRESSION = 65536

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
 * 结果不再携带原始字符串的表达式；未知处理函数不能仅凭名称豁免。
 * 查表另行核对容器来源，不能将请求对象的索引访问视为安全。
 */
const LITERAL = String.raw`(?:'[^']*'|"[^"]*"|\x60[^\x60$]*\x60|-?\d+(?:\.\d+)?|null|undefined|true|false)`
const CLEAN_EXPRESSION = [
  /^(?:await\s+)?(?:Number|parseInt|parseFloat|Boolean|BigInt|isNaN|Math\s*\.\s*\w+|Number\s*\.\s*\w+)\s*\(/,
  /\.\s*length\s*$/,
  /^(?:!|typeof\b)/,
  /\.\s*(?:includes|test|has|startsWith|endsWith|some|every)\s*\([^?]*\)\s*$/,
  new RegExp(String.raw`^[^?]*\?\s*${LITERAL}\s*:\s*${LITERAL}\s*$`),
  // 带标签的模板由标签函数处理插值（Prisma.sql、sql、html），String.raw 除外。
  /^(?:await\s+)?(?!String\s*\.\s*raw\b)[\w$]+(?:\s*\.\s*[\w$]+)*\s*\x60/,
]

/** 返回值与传入数据相同的校验和复制函数；其余未知函数的返回值视为函数自己产出的数据。 */
const MIRROR_CALLS = new Set([
  'parse', 'safeParse', 'parseAsync', 'safeParseAsync', 'validate', 'validateSync', 'validateAsync', 'cast',
  'structuredClone', 'clone', 'assign',
])

/** 不改变值内容的成员访问：对返回值调用这些仍等于使用返回值本身。 */
const VALUE_MEMBERS = /^\s*\??\.\s*(?:toString|valueOf|href|trim|trimStart|trimEnd|toLowerCase|toUpperCase|normalize)\b/

/** 请求的 Host 头：路由到本站的主机名，按本站地址处理。 */
const HOST_HEADER = /^\s*(?:\??\.\s*get\s*\(\s*['"](?:x-forwarded-)?host['"]\s*\)|\??\.\s*host\b|\[\s*['"](?:x-forwarded-)?host['"]\s*\])/i

/** 请求自身 URL 中调用方可控的部分；主机、协议等部分由本站决定。 */
const URL_INPUT_ACCESS = /\??\.\s*(?:searchParams|pathname|search|hash)\b/
const URL_INPUT_KEYS = new Set(['searchParams', 'pathname', 'search', 'hash'])
const URL_ORIGIN_ACCESS = /^\s*\??\.\s*(?:origin|host|hostname|protocol|port)\b/
const URL_ORIGIN_KEYS = new Set(['origin', 'host', 'hostname', 'protocol', 'port'])

/** 从 open 处的括号起找到配对的右括号；文本已屏蔽字符串内容。 */
function closeOf(text: string, open: number): number {
  const pairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' }
  const stack: string[] = []
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!
    if (pairs[ch]) stack.push(pairs[ch])
    else if (ch === stack[stack.length - 1]) { stack.pop(); if (stack.length === 0) return i }
  }
  return -1
}

/**
 * 表达式整体是否为一次调用：可带 await、new、外层括号及调用后的成员访问，如 (await db.find(id)).url。
 * 返回最后一次调用的函数名，以及调用之后是否还有成员访问；其他形式返回空值。
 */
function callResultOf(expression: string): { callee: string; members: boolean } | null {
  const text = expression.trim().replace(/\s+as\s+[\w$.<>[\]| ]+$/, '').replace(/^(?:(?:await|new)\s+)+/, '')
  let i = 0
  let callee: string | null = null
  let members = false
  if (text[0] === '(') {
    const close = closeOf(text, 0)
    if (close === -1) return null
    const inner = callResultOf(text.slice(1, close))
    if (!inner || inner.members) return null
    callee = inner.callee
    i = close + 1
  } else {
    const head = /^[A-Za-z_$][\w$]*/.exec(text)
    if (!head) return null
    i = head[0].length
  }
  let last = callee === null ? text.slice(0, i) : callee
  while (i < text.length) {
    const rest = text.slice(i)
    const member = /^\s*(?:\??\.)\s*([A-Za-z_$][\w$]*)/.exec(rest)
    if (member) { last = member[1]!; if (callee !== null) members = true; i += member[0].length; continue }
    const open = /^\s*(?:\?\.)?\s*([([])/.exec(rest)
    if (open) {
      const at = i + open[0].length - 1
      const close = closeOf(text, at)
      if (close === -1) return null
      if (open[1] === '(') { callee = last; members = false }
      else if (callee !== null) members = true
      i = close + 1
      continue
    }
    if (/^\s*!/.test(rest) && !/^\s*!=/.test(rest)) { i += rest.indexOf('!') + 1; continue }
    if (rest.trim() === '') break
    return null
  }
  return callee === null ? null : { callee, members }
}

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
export function destructuredKeys(pattern: string): Array<{ key: string; local: string }> {
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
function expressionEnd(code: string, from: number, limit: number, pairs: Map<number, number>, truncated: () => void): number {
  const stop = Math.min(limit, from + MAX_EXPRESSION)
  for (let i = from; i < stop; i++) {
    const ch = code[i]!
    const close = pairs.get(i)
    if (close !== undefined) {
      if (close >= stop) { truncated(); return stop }
      i = close; continue
    }
    if (ch === ';' || ch === ',' || ch === ')' || ch === ']' || ch === '}') return i
    if (ch === '\n') {
      const before = code.slice(from, i).trimEnd()
      const after = code.slice(i + 1, i + 80).trimStart()
      if (before === '' || /[=+\-*/%&|^!?:,.([{<>]$/.test(before)) continue
      if (/^(?:[.?+\-*/%&|^,:<>=]|\?\?)/.test(after) && !/^(?:\+\+|--)/.test(after)) continue
      return i
    }
  }
  if (stop < limit && !/[;,)}\]\n]/.test(code[stop] ?? '')) truncated()
  return stop
}

interface Span { start: number; end: number }
interface LocalFunction extends FunctionBody { usedAt: number }
interface Assignment { at: number; pattern: string; names: string[]; expr: string; exprAt: number; iterate: boolean; append: boolean; declaration?: boolean; scope?: Span; controls?: Span[]; owner?: LocalFunction; indirect?: boolean }

/** 仅接受平坦字面量表，不接受展开、访问器、调用或动态属性。 */
function literalTable(text: string): boolean {
  const value = text.trim()
  const item = new RegExp(`^${LITERAL}$`)
  const property = new RegExp(`^(?:[A-Za-z_$][\\w$]*|'[^']*'|"[^"]*")\\s*:\\s*${LITERAL}$`)
  if (!(value.startsWith('{') && value.endsWith('}')) && !(value.startsWith('[') && value.endsWith(']'))) return false
  return parameterList(value.slice(1, -1)).every(part => (value[0] === '{' ? property : item).test(part))
}

/** 文件级常量表索引只建立一次；重复绑定或可见成员写入使豁免失效。 */
function fixedTablesOf(code: string, source: string, pairs: Map<number, number>): Map<string, number> {
  const result = new Map<string, number>()
  const seen = new Set<string>()
  for (const m of code.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*/g)) {
    const name = m[1]!
    if (seen.has(name)) { result.delete(name); continue }
    seen.add(name)
    const open = m.index + m[0].length
    const close = pairs.get(open)
    if (!m[0].startsWith('const') || close === undefined || close - open > MAX_EXPRESSION) continue
    if (literalTable(source.slice(open, close + 1))) result.set(name, m.index)
  }
  for (const m of code.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)(?:\s*\.\s*[\w$]+|\s*\[[^\]]*\])?\s*(?:\+\+|--|[+*/%&|^-]?=(?![=>]))/g)) {
    if (!/\bconst\s+$/.test(code.slice(Math.max(0, m.index - 20), m.index))) result.delete(m[1]!)
  }
  // 变更方法和对象工具同样会改写表内容。
  for (const m of code.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(?:push|pop|shift|unshift|splice|sort|reverse|fill|copyWithin)\s*\(/g)) {
    result.delete(m[1]!)
  }
  for (const m of code.matchAll(/\b(?:Object\s*\.\s*(?:assign|defineProperty|defineProperties|setPrototypeOf)|Reflect\s*\.\s*(?:set|defineProperty|setPrototypeOf))\s*\(\s*([A-Za-z_$][\w$]*)\b/g)) {
    result.delete(m[1]!)
  }
  return result
}

/** 一个处理函数内请求输入的流向。 */
export class InputFlow {
  private readonly parameters = new Map<string, Taint>()
  limited = false
  private readonly assignmentList = new Map<string, Assignment[]>()
  private sourcePattern: RegExp | null
  private references: RegExp | null = null
  private readonly values = new Map<string, Taint | null>()
  private readonly strings = new Map<string, (Taint & { text: string }) | null>()

  constructor(
    private readonly code: string,
    private readonly source: string,
    private readonly span: { start: number; end: number },
    private readonly pairs: Map<number, number>,
    roles: ParamRoles,
    private readonly fixedTables: Map<string, number>,
  ) {
    for (const [name, at] of roles.values) this.parameters.set(name, { level: 'direct', origin: at, names: new Set([name]), ownUrl: false })
    this.sourcePattern = sourceRegex(roles)
    const assignments = this.assignments().sort((a, b) => a.at - b.at)
    const region = code.slice(span.start, span.end)
    const functions = this.localFunctions(region, assignments)
    const scopes: Span[] = [span]
    for (let i = span.start + 1; i < span.end; i++) {
      const end = code[i] === '{' ? pairs.get(i) : undefined
      if (end !== undefined) scopes.push({ start: i, end })
    }
    const controls: Span[] = []
    for (const m of region.matchAll(/\b(?:if|for|while|switch|catch)\s*\(|\belse\b/g)) {
      const open = span.start + m.index + m[0].length - 1
      let start = m[0] === 'else' ? open + 1 : (pairs.get(open) ?? open) + 1
      while (/\s/.test(code[start] ?? '')) start++
      controls.push({ start, end: pairs.get(start) ?? expressionEnd(code, start, span.end, pairs, () => { this.limited = true }) })
      if (controls.length >= MAX_ASSIGNMENTS) { this.limited = true; break }
    }
    for (const a of assignments) {
      // 函数内赋值不直接覆盖外层；跨函数影响须有引用证据，并降为待复核。
      const owner = functions.filter(f => f.start < a.at && a.at < f.end).at(-1)
      if (owner) a.owner = owner
      a.scope = scopes.filter(s => s.start < a.at && a.at < s.end).at(-1) ?? span
      if (a.owner && a.owner.start > a.scope.start) a.scope = a.owner
      a.controls = controls.filter(s => s.start <= a.at && a.at <= s.end)
      for (const name of a.names) {
        const list = this.assignmentList.get(name) ?? []
        if (!list.some(item => item.exprAt === a.exprAt)) list.push(a)
        this.assignmentList.set(name, list)
      }
    }
    const names = new Set([...this.parameters.keys(), ...this.assignmentList.keys()])
    if (names.size) this.references = new RegExp(`(?<![\\w$.])(?:${namePattern(names)})(?![\\w$])`, 'g')
  }

  /** 只索引当前处理函数；未引用的具名闭包不影响外层值。 */
  private localFunctions(region: string, assignments: Assignment[]): LocalFunction[] {
    const offset = this.span.start
    const bodies = functionBodies(region, delimiterPairs(region)).map(f => ({
      declaration: f.declaration + offset, start: f.start + offset, end: f.end + offset,
    }))
    for (const m of region.matchAll(/=>\s*(?!\s*\{)/g)) {
      const start = offset + m.index + m[0].length
      const end = expressionEnd(this.code, start, this.span.end, this.pairs, () => { this.limited = true })
      bodies.push({ declaration: offset + m.index, start: start - 1, end })
    }
    if (bodies.length > MAX_ASSIGNMENTS) this.limited = true
    return bodies.slice(0, MAX_ASSIGNMENTS).sort((a, b) => a.start - b.start).map(f => {
      const binding = assignments.filter(a => {
        if (!a.declaration || a.exprAt > f.declaration || a.exprAt + a.expr.length < f.end) return false
        const prefix = this.code.slice(a.exprAt, f.declaration).trim()
        // 只把函数表达式自身绑定到变量，不能借用 run(callback) 的返回值变量。
        return prefix === '' || prefix === 'async' || /^(?:async\s*)?(?:\([^;{}]*\)|[\w$]+)\s*(?::[^=;{}]*)?$/.test(prefix)
      }).sort((a, b) => b.exprAt - a.exprAt)[0]
      const declared = /^function\s*\*?\s*([\w$]+)\s*\(/.exec(this.code.slice(f.declaration, f.start))?.[1]
      const before = this.code.slice(this.span.start, f.declaration).trimEnd().replace(/\basync$/, '').trimEnd()
      // 具名函数表达式作为实参时已传出，内部名称无需再被引用。
      const name = binding?.names.length === 1 ? binding.names[0] : /[;{}]$/.test(before) ? declared : undefined
      if (/^\s*\)*\s*(?:\(|\.\s*(?:call|apply)\s*\()/.test(this.code.slice(f.end + 1, this.span.end))) {
        return { ...f, usedAt: f.end }
      }
      if (!name) return { ...f, usedAt: f.end }
      const start = binding?.at ?? f.declaration
      const reference = new RegExp(`(?<![\\w$.])${namePattern([name])}(?![\\w$])`, 'g')
      const use = [...region.matchAll(reference)].find(m => offset + m.index < start || offset + m.index > f.end)
      return { ...f, usedAt: use ? offset + use.index : Infinity }
    })
  }

  /** 表达式是否携带请求输入；已转换为数值、布尔或查表结果的不算。 */
  taintOf(expr: string, exprAt: number, depth = 0): Taint | null {
    if (expr.length > MAX_EXPRESSION) this.limited = true
    const text = expr.trim()
    if (text === '' || CLEAN_EXPRESSION.some(pattern => pattern.test(text)) || isComparison(text)) return null
    const lookup = new RegExp(`^([A-Za-z_$][\\w$]*)\\s*\\[[^\\]]*\\]\\s*(?:(?:\\?\\?|\\|\\|)\\s*${LITERAL})?\\s*$`).exec(text)
    if (lookup && this.isFixedTable(lookup[1]!, exprAt)) return null
    // 字面量索引按同长属性访问处理，支持 req['body']，不猜测动态属性。
    const observed = expr.replace(/\[\s*['"][^'"]*['"]\s*\]/g, (part, offset: number) => {
      const raw = this.source.slice(exprAt + offset, exprAt + offset + part.length)
      const key = /^\[\s*['"]([A-Za-z_$][\w$]*)['"]\s*\]$/.exec(raw)?.[1]
      return key ? `.${key}`.padEnd(part.length) : part
    })
    let found: Taint | null = null
    if (this.sourcePattern) {
      this.sourcePattern.lastIndex = 0
      for (const m of observed.matchAll(this.sourcePattern)) {
        const after = observed.slice(m.index + m[0].length)
        const ownUrl = m[1] === 'url' || m[1] === 'nextUrl'
        if (ownUrl && URL_ORIGIN_ACCESS.test(after)) continue
        const hostAt = exprAt + m.index + m[0].length
        const hostHeader = m[1] === 'headers' && HOST_HEADER.test(this.source.slice(hostAt, hostAt + 80))
        found = mergeTaint(found, { level: 'direct', origin: exprAt + m.index, names: new Set(),
          ownUrl: hostHeader || (ownUrl && !URL_INPUT_ACCESS.test(after.slice(0, 40))) })
      }
    }
    const refs = this.references && new RegExp(this.references.source, 'g')
    if (refs) {
      refs.lastIndex = 0
      for (const m of expr.matchAll(refs)) {
        const before = expr.slice(0, m.index).trimEnd()
        const after = expr.slice(m.index + m[0].length)
        // 对象字面量的键不是引用。
        if (/^\s*:(?!:)/.test(after) && /[{,]$/.test(before)) continue
        const t = this.valueOf(m[0], exprAt, depth)
        if (!t) continue
        // 未知函数返回值的属性、元素或方法调用结果是函数产出的数据；toString、href 等只改变形式，仍是返回值本身。
        if (t.opaque && /^\s*(?:\??\.\s*[\w$]|\?\.\s*\[|\[)/.test(after) && !VALUE_MEMBERS.test(after)) continue
        // 本站 URL 的 origin、host 等不可控；取其查询或路径部分则成为可控输入。
        if (t.ownUrl && URL_ORIGIN_ACCESS.test(after)) continue
        found = mergeTaint(found, t.ownUrl && URL_INPUT_ACCESS.test(after.slice(0, 40)) ? { ...t, ownUrl: false } : t)
      }
    }
    if (!found) return null
    // new URL(request.url).searchParams.get(…) 之类在调用结果上取查询部分。
    if (found.ownUrl && URL_INPUT_ACCESS.test(text)) found.ownUrl = false
    // JSON.parse 只改变形式；schema.parse 等校验调用使结果降为 derived。
    const calls = [...text.replace(/\bJSON\s*\.\s*parse\s*\(/g, '(').matchAll(/([\w$]+)\s*\(/g)].map(m => m[1]!)
    if (calls.some(name => !TRANSPARENT_CALLS.has(name))) found.level = 'derived'
    // 整个表达式是一次未知函数调用：结果整体保留待复核，取其属性则不再是请求输入。
    const call = callResultOf(text)
    if (call && !TRANSPARENT_CALLS.has(call.callee) && !MIRROR_CALLS.has(call.callee)) {
      if (call.members) return null
      found.opaque = true
    }
    return found
  }

  /** 字符串拼接：无标签模板的插值或含字符串操作数的 + 拼接中携带请求输入。 */
  builtOf(expr: string, exprAt: number, depth = 0): Taint | null {
    if (expr.length > MAX_EXPRESSION) this.limited = true
    const text = expr.trim()
    const lead = expr.length - expr.trimStart().length
    if (text.startsWith('\x60')) return this.interpolationTaint(exprAt + lead, exprAt + lead + text.length, depth)
    const operands = this.topLevelOperands(expr, exprAt)
    if (operands.length < 2 || !operands.some(o => /^['"\x60]/.test(o.text.trim()))) return null
    let found: Taint | null = null
    for (const operand of operands) {
      const t = operand.text.trim().startsWith('\x60')
        ? this.interpolationTaint(operand.at, operand.at + operand.text.length, depth)
        : this.taintOf(operand.text, operand.at, depth)
      if (t) found = mergeTaint(found, t)
    }
    return found
  }

  /** 仅保留使用位置可见的赋值；无条件覆盖终止旧值，分支与追加赋值保留可能来源。 */
  assignmentsFor(name: string, at: number): Assignment[] {
    const list = this.assignmentList.get(name) ?? []
    const contains = (s: Span, where: number): boolean => s.start < where && where < s.end
    const bindingAt = (where: number): Assignment | undefined => list.filter(a => a.declaration &&
      a.at <= where && contains(a.scope!, where)).sort((a, b) => b.scope!.start - a.scope!.start || b.at - a.at)[0]
    const binding = bindingAt(at)
    const result: Assignment[] = []
    for (let i = list.length - 1; i >= 0; i--) {
      const a = list[i]!
      if (a.at >= at || a.exprAt + a.expr.length >= at) continue
      if (a.declaration ? a !== binding : bindingAt(a.at) !== binding) continue
      const indirect = a.owner !== undefined && !contains(a.owner, at)
      if (indirect && a.owner!.usedAt >= at) continue
      result.push(indirect ? { ...a, indirect: true } : a)
      if (!indirect && !a.append && contains(a.scope!, at) && a.controls!.every(s => contains(s, at))) break
    }
    return result
  }

  valueOf(name: string, at: number, depth = 0): Taint | null {
    const key = `${name}:${at}:${depth}`
    if (this.values.has(key)) return this.values.get(key)!
    const result = this.resolveValue(name, at, depth)
    this.values.set(key, result)
    return result
  }

  private resolveValue(name: string, at: number, depth: number): Taint | null {
    if (depth >= MAX_VALUE_HOPS) { this.limited = true; return null }
    const assignments = this.assignmentsFor(name, at)
    if (!assignments.length) return this.parameters.get(name) ?? null
    let found: Taint | null = null
    for (const a of assignments) {
      const taint = this.builtOf(a.expr, a.exprAt, depth + 1) ?? this.taintOf(a.expr, a.exprAt, depth + 1)
      if (!taint) continue
      // 从未知函数返回值中解构或遍历得到的是其产出的数据。
      if (taint.opaque && (a.iterate || /^[{[]/.test(a.pattern.trim()))) continue
      const own = this.targetsOf(a, taint).find(([target]) => target === name)
      if (own) found = mergeTaint(found, { ...taint, level: a.indirect ? 'derived' : taint.level, ownUrl: own[1], names: new Set([name, ...taint.names]) })
    }
    // 只有条件赋值时，原始参数仍可能到达使用处。
    if (this.parameters.has(name) && assignments.every(a => a.append || !a.scope || a.scope.start !== this.span.start || a.controls!.length)) {
      found = mergeTaint(found, this.parameters.get(name)!)
    }
    return found
  }

  /** 保留有效拼接及别名的 SQL 文本证据，不借用已被覆盖的旧查询。 */
  builtValue(name: string, at: number, depth = 0): (Taint & { text: string }) | null {
    const key = `${name}:${at}:${depth}`
    if (this.strings.has(key)) return this.strings.get(key)!
    const result = this.resolveBuiltValue(name, at, depth)
    this.strings.set(key, result)
    return result
  }

  private resolveBuiltValue(name: string, at: number, depth: number): (Taint & { text: string }) | null {
    if (depth >= MAX_VALUE_HOPS) { this.limited = true; return null }
    let found: Taint | null = null
    let text = ''
    const append = (part: string): void => {
      if (text.length + part.length + 1 > MAX_EXPRESSION) this.limited = true
      text = `${text}\n${part}`.slice(0, MAX_EXPRESSION)
    }
    for (const a of this.assignmentsFor(name, at)) {
      append(this.source.slice(a.exprAt, a.exprAt + a.expr.length))
      const alias = /^[A-Za-z_$][\w$]*$/.test(a.expr.trim()) ? this.builtValue(a.expr.trim(), a.exprAt, depth + 1) : null
      const t = this.builtOf(a.expr, a.exprAt, depth + 1) ?? alias ?? (a.append ? this.taintOf(a.expr, a.exprAt, depth + 1) : null)
      if (alias) append(alias.text)
      if (t) found = mergeTaint(found, a.indirect ? { ...t, level: 'derived' } : t)
    }
    return found ? { ...found, names: new Set([name, ...found.names]), text } : null
  }

  private isFixedTable(name: string, at: number): boolean {
    const assignments = this.assignmentsFor(name, at)
    if (assignments.length) return assignments.every(a => !a.append &&
      literalTable(this.source.slice(a.exprAt, a.exprAt + a.expr.length))) && this.fixedTables.has(name)
    return (this.fixedTables.get(name) ?? Infinity) < at && !this.parameters.has(name)
  }

  /** 顶层 + 拼接的各操作数；括号与模板插值内部的 + 不拆分。 */
  operandsOf(expr: string, exprAt: number): Array<{ text: string; at: number }> {
    return this.topLevelOperands(expr, exprAt)
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

  private interpolationTaint(from: number, to: number, depth: number): Taint | null {
    let found: Taint | null = null
    for (let i = from; i < to - 1; i++) {
      if (this.code[i] !== '$' || this.code[i + 1] !== '{') continue
      const close = this.pairs.get(i + 1)
      if (close === undefined) continue
      const t = this.taintOf(this.code.slice(i + 2, close), i + 2, depth)
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

  /**
   * 赋值目标及其是否仍只是本站 URL。从本站 URL 解构时按键区分：
   * searchParams、pathname 等为可控输入，origin、host 等不可控，其余保持本站 URL。
   */
  private targetsOf(a: Assignment, taint: Taint): Array<[string, boolean]> {
    if (!taint.ownUrl || !a.pattern.trim().startsWith('{')) return a.names.map(name => [name, taint.ownUrl])
    const targets: Array<[string, boolean]> = []
    for (const { key, local } of destructuredKeys(a.pattern.trim())) {
      if (URL_ORIGIN_KEYS.has(key)) continue
      targets.push([local, !URL_INPUT_KEYS.has(key)])
    }
    return targets
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
          const end = expressionEnd(code, exprAt, span.end, pairs, () => { this.limited = true })
          push({ at, pattern, names: patternNames(pattern), expr: code.slice(exprAt, end), exprAt, iterate: true, append: false, declaration: true })
          break
        }
        const eq = /^\s*(?::[^=;]{0,200}?)?=(?![=>])/.exec(rest)
        if (!eq) break
        const exprAt = patternEnd + eq[0].length
        const end = expressionEnd(code, exprAt, span.end, pairs, () => { this.limited = true })
        push({ at, pattern, names: patternNames(pattern), expr: code.slice(exprAt, end), exprAt, iterate: false, append: false, declaration: true })
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
      const end = expressionEnd(code, exprAt, span.end, pairs, () => { this.limited = true })
      push({ at: span.start + m.index, pattern: m[1]!, names: [m[1]!], expr: code.slice(exprAt, end), exprAt, iterate: false, append: m[2] === '+=' })
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
      String.raw`(?<![\w$.])(?:${objects})(?:\s*\??\.\s*(?:request|event))?\s*\??\.\s*(json|formData|text|arrayBuffer|blob|body|query|params|url|nextUrl|headers|cookies|searchParams)\b`,
      String.raw`(?<![\w$.])(?:${objects})\s*\??\.\s*context\s*\??\.\s*params\b`,
      String.raw`\b(?:${H3_READERS})\s*(?:<[^()]{0,200}>\s*)?\(\s*(?:${objects})\b`,
    )
  }
  if (roles.urls.size > 0) {
    parts.push(String.raw`(?<![\w$.])(?:${namePattern(roles.urls.keys())})\s*\??\.\s*(?:searchParams|pathname|search|hash)\b`)
  }
  if (roles.cookies.size > 0) {
    parts.push(String.raw`(?<![\w$.])(?:${namePattern(roles.cookies.keys())})\s*\??\.\s*get(?:All)?\s*\(`)
  }
  return parts.length === 0 ? null : new RegExp(parts.join('|'), 'g')
}

/** 合并两处来源：任一处经过其他调用即整体降为 derived。 */
function mergeTaint(found: Taint | null, t: Taint): Taint {
  if (!found) return { level: t.level, origin: t.origin, names: new Set(t.names), ownUrl: t.ownUrl, ...(t.opaque ? { opaque: true } : {}) }
  // 只有每一部分都是未知函数返回值时，合并结果才整体视为返回值。
  if (found.opaque && !t.opaque) delete found.opaque
  if (t.level === 'derived') found.level = 'derived'
  // 任一部分是可控输入，合并结果即为可控输入；来源位置取可控的那一处。
  if (found.ownUrl && !t.ownUrl) { found.ownUrl = false; found.origin = t.origin }
  for (const n of t.names) found.names.add(n)
  return found
}

/** 参数角色是否包含任何请求来源。 */
export function hasInput(roles: ParamRoles): boolean {
  return roles.objects.size + roles.urls.size + roles.cookies.size + roles.values.size > 0
}

/** 路由中接收请求的函数及其输入流向。 */
export interface RouteHandler { route: Route; body: FunctionBody; flow: InputFlow }

interface HandlerCandidate { route: Route; body: FunctionBody; roles: ParamRoles }

/** 第一个不小于 value 的下标；数组已按升序排列。 */
export function lowerBound(values: readonly number[], value: number): number {
  let low = 0, high = values.length
  while (low < high) {
    const middle = (low + high) >>> 1
    if (values[middle]! < value) low = middle + 1
    else high = middle
  }
  return low
}

/**
 * 一个路由文件的共享分析结果，供注入、SSRF 与重定向规则共用。
 * 输入追踪按需建立：只有包含待检查调用的函数才分析，一个文件可含数以万计的 Server Function。
 */
export class HandlerFile {
  private readonly flows = new Map<HandlerCandidate, InputFlow>()
  private readonly fixedTables: Map<string, number>

  constructor(
    readonly code: string,
    readonly source: string,
    readonly pairs: Map<number, number>,
    readonly lineStarts: number[],
    private readonly candidates: HandlerCandidate[],
  ) { this.fixedTables = fixedTablesOf(code, source, pairs) }

  get limited(): boolean {
    for (const flow of this.flows.values()) if (flow.limited) return true
    return false
  }

  /** 至少包含一个给定位置的处理函数；positions 必须已按升序排列。 */
  handlersAround(positions: readonly number[]): RouteHandler[] {
    const result: RouteHandler[] = []
    if (positions.length === 0) return result
    for (const candidate of this.candidates) {
      const { body } = candidate
      const first = lowerBound(positions, body.start + 1)
      if (first >= positions.length || positions[first]! >= body.end) continue
      let flow = this.flows.get(candidate)
      if (!flow) {
        flow = new InputFlow(this.code, this.source, { start: body.start, end: body.end }, this.pairs, candidate.roles, this.fixedTables)
        this.flows.set(candidate, flow)
      }
      result.push({ route: candidate.route, body, flow })
    }
    return result
  }
}

const handlerCache = new WeakMap<ScanFile, HandlerFile | null>()

/** 路由文件中接收请求的函数；不是路由或没有接收请求的函数时返回空值。结果按文件对象缓存，生命周期随扫描结束。 */
export function handlerFileOf(file: ScanFile): HandlerFile | null {
  const cached = handlerCache.get(file)
  if (cached !== undefined) return cached
  let result: HandlerFile | null = null
  if (/\.[mc]?[jt]sx?$/.test(file.path)) {
    const route = routeOf(file)
    const routes = route === null ? serverActionRoutes(file) : [route]
    if (routes.length > 0) {
      const code = noiseMaskedOf(file)
      const source = commentsMaskedOf(file)
      const pairs = delimiterPairs(code)
      const openers = new Map<number, number>()
      for (const [open, close] of pairs) openers.set(close, open)
      const bodies = functionBodies(code, pairs).sort((a, b) => a.start - b.start)
      const starts = bodies.map(body => body.start)
      const candidates: HandlerCandidate[] = []
      for (const r of routes) {
        const reachable = r.reachable
        // 只取路由范围内的函数体：按起点二分定位，避免“路由数 × 函数数”的开销。
        const from = reachable ? lowerBound(starts, reachable.start) : 0
        for (let i = from; i < bodies.length; i++) {
          const body = bodies[i]!
          if (reachable && body.start >= reachable.end) break
          if (reachable && body.end > reachable.end) continue
          // Server Function 只有自身参数来自客户端；其中的嵌套函数按普通处理函数判断。
          const action = r.action !== undefined && reachable !== undefined && body.start === reachable.start
          const params = parametersOf(code, body, pairs, openers)
          if (!params) continue
          const roles = paramRoles(source.slice(params.start, params.end), params.start, action)
          if (hasInput(roles)) candidates.push({ route: r, body, roles })
        }
      }
      if (candidates.length > 0) result = new HandlerFile(code, source, pairs, lineStartsOf(file.content), candidates)
    }
  }
  handlerCache.set(file, result)
  return result
}

/** 追踪达到上限时记录一次扫描缺口；三条规则共用同一条记录，由引擎按规则与消息去重。 */
export function reportInputLimit(ctx: ScanContext, file: ScanFile, analysed: HandlerFile): void {
  if (analysed.limited) ctx.reportIncomplete('request-input/tracking',
    `${file.path} reached the request-input tracking limit (8 value hops, 512 assignments or control/function regions, 64 KiB expressions, or bounded URL analysis)`)
}
