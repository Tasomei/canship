/**
 * Express 路由：在导入 express 的文件中识别应用与 Router 实例上的路由注册。
 * 处理函数可以写在其他文件（控制器）中；路由参数中的中间件、实例上先注册的 use() 以及其他文件中的挂载随路由记录，
 * 由鉴权规则判断是否构成保护。不导入 express 的文件不按此识别，避免把普通的 x.get() 当成路由。
 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { bindingsOf } from './bindings.js'
import {
  bindingModule, declarationOf, delimiterPairs, functionBodies, routeOf, serverActionRoutes,
  type FunctionBody, type MiddlewareRef, type Route,
} from './apiauth.js'

const METHODS = 'get|post|put|patch|delete|all|options|head'
/** TypeScript 的泛型实参，如 router.get<Params, Body>(…)。 */
const GENERICS = String.raw`(?:<[^()]{0,300}>\s*)?`

interface Analysed {
  file: ScanFile
  code: string
  source: string
  pairs: Map<number, number>
  openers: Map<number, number>
  bodies: FunctionBody[]
}

const analysedCache = new WeakMap<ScanFile, Analysed>()

function analyse(file: ScanFile): Analysed {
  const cached = analysedCache.get(file)
  if (cached) return cached
  const code = noiseMaskedOf(file)
  const pairs = delimiterPairs(code)
  const openers = new Map<number, number>()
  for (const [open, close] of pairs) openers.set(close, open)
  const result = { file, code, source: commentsMaskedOf(file), pairs, openers, bodies: functionBodies(code, pairs) }
  analysedCache.set(file, result)
  return result
}

interface Arg { text: string; source: string; at: number }

/** 顶层逗号分隔的实参，保留位置；文本取屏蔽字符串后的代码，source 取原文。 */
function argsOf(a: Analysed, open: number, close: number): Arg[] {
  const args: Arg[] = []
  let from = open + 1
  const push = (end: number): void => {
    const raw = a.code.slice(from, end)
    const lead = raw.length - raw.trimStart().length
    const text = raw.trim()
    if (text) args.push({ text, source: a.source.slice(from + lead, from + lead + text.length), at: from + lead })
  }
  for (let i = open + 1; i < close; i++) {
    const end = a.pairs.get(i)
    if (end !== undefined) { i = end; continue }
    if (a.code[i] === ',') { push(i); from = i + 1 }
  }
  push(close)
  return args
}

/** 数组字面量中的中间件逐个展开：[auth, validate]。 */
function flatten(a: Analysed, args: Arg[]): Arg[] {
  return args.flatMap(arg => {
    if (!arg.text.startsWith('[')) return [arg]
    const close = a.pairs.get(arg.at)
    return close === undefined ? [arg] : argsOf(a, arg.at, close)
  })
}

/** 应用目录：别名解析使用，与 Server Function 的判定一致。 */
function scopeOf(path: string): string {
  return /^(.*?\/)?(?:src|app|lib|server|routes|api|controllers)\//.exec(path)?.[1] ?? ''
}

interface ExpressNames { express: Set<string>; router: Set<string> }

/** express 的本地名称：默认、命名空间、带具名的默认导入，以及 require 结果和 Router 的别名。 */
function expressNamesOf(a: Analysed): ExpressNames | null {
  const names: ExpressNames = { express: new Set(), router: new Set() }
  const named = (list: string): void => {
    for (const part of list.split(',')) {
      const m = /^\s*(?:type\s+)?Router\s*(?:(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$/.exec(part)
      if (m) names.router.add(m[1] ?? 'Router')
    }
  }
  for (const m of a.source.matchAll(/\bimport\s+(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^{}]*)\}|\*\s+as\s+([A-Za-z_$][\w$]*))?\s*from\s*['"]express['"]/g)) {
    if (m[1]) names.express.add(m[1])
    if (m[3]) names.express.add(m[3])
    if (m[2]) named(m[2])
  }
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s+(?:([A-Za-z_$][\w$]*)|\{([^{}]*)\})\s*=\s*require\s*\(\s*['"]express['"]\s*\)/g)) {
    if (m[1]) names.express.add(m[1])
    if (m[2]) named(m[2])
  }
  const inline = /\brequire\s*\(\s*['"]express['"]\s*\)/.test(a.source)
  return names.express.size || names.router.size || inline ? names : null
}

/** 应用与 Router 实例：express()、express.Router()、Router()、require('express')()，以及类型标注为 Express/Router 的参数。 */
function instancesOf(a: Analysed, names: ExpressNames): Set<string> {
  const instances = new Set<string>()
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,100})?=\s*(?:new\s+)?([A-Za-z_$][\w$]*)\s*(?:\.\s*(Router)\s*)?\(/g)) {
    if ((names.express.has(m[2]!) && (m[3] === 'Router' || m[3] === undefined)) || (names.router.has(m[2]!) && m[3] === undefined)) instances.add(m[1]!)
  }
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"]express['"]\s*\)\s*(?:\.\s*Router\s*)?\(/g)) instances.add(m[1]!)
  for (const m of a.code.matchAll(/([A-Za-z_$][\w$]*)\s*\??:\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:Express|Router|Application)\b(?!\s*[.<(])/g)) instances.add(m[1]!)
  return instances
}

interface Registration { instance: string; path: string | null; args: Arg[]; at: number }

/** 字符串字面量路径；无插值的模板也接受，其他形式视为动态路径。 */
function literalOf(arg: Arg): string | null {
  const m = /^(['"`])([^'"`$]*)\1$/.exec(arg.source)
  return m ? m[2]! : null
}

/** 实例上的路由注册：app.get(path, …)，以及 router.route(path).get(…).post(…) 链。 */
function registrationsOf(a: Analysed, instances: Set<string>): Registration[] {
  const found: Registration[] = []
  for (const name of instances) {
    const escaped = name.replace(/\$/g, '\\$')
    for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${escaped}\\s*\\.\\s*(?:${METHODS})\\s*${GENERICS}\\(`, 'g'))) {
      const open = m.index + m[0].length - 1
      const close = a.pairs.get(open)
      if (close === undefined) continue
      const args = argsOf(a, open, close)
      // app.get('setting') 是读取配置，路由至少有路径和处理函数。
      if (args.length < 2) continue
      found.push({ instance: name, path: literalOf(args[0]!), args: args.slice(1), at: m.index })
    }
    for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${escaped}\\s*\\.\\s*route\\s*\\(`, 'g'))) {
      const open = m.index + m[0].length - 1
      let close = a.pairs.get(open)
      if (close === undefined) continue
      const pathArg = argsOf(a, open, close)[0]
      const path = pathArg ? literalOf(pathArg) : null
      for (let guard = 0; guard < 16; guard++) {
        const next = new RegExp(`^\\s*\\.\\s*(?:${METHODS})\\s*${GENERICS}\\(`).exec(a.code.slice(close + 1, close + 500))
        if (!next) break
        const methodOpen = close + 1 + next[0].length - 1
        const methodClose = a.pairs.get(methodOpen)
        if (methodClose === undefined) break
        found.push({ instance: name, path, args: argsOf(a, methodOpen, methodClose), at: close + 1 + next[0].search(/[a-z]/) })
        close = methodClose
      }
    }
  }
  return found.sort((x, y) => x.at - y.at)
}

interface Use { instance: string; prefix: string | null; args: Arg[]; at: number }

/** 实例上的 use()：可带路径前缀，其余实参为中间件或被挂载的 Router。 */
function usesOf(a: Analysed, instances: Set<string>): Use[] {
  const found: Use[] = []
  for (const name of instances) {
    for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}\\s*\\.\\s*use\\s*\\(`, 'g'))) {
      const open = m.index + m[0].length - 1
      const close = a.pairs.get(open)
      if (close === undefined) continue
      const args = argsOf(a, open, close)
      const prefix = args[0] ? literalOf(args[0]) : null
      found.push({ instance: name, prefix, args: flatten(a, prefix === null ? args : args.slice(1)), at: m.index })
    }
  }
  return found.sort((x, y) => x.at - y.at)
}

const pathMatches = (prefix: string | null, path: string | null): boolean =>
  prefix === null || prefix === '/' || (path !== null && (path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`)))

/** 表达式终点：跳过括号，遇到分号、顶层逗号或代码块结束即停。 */
function expressionEnd(a: Analysed, from: number): number {
  for (let i = from; i < a.code.length; i++) {
    const end = a.pairs.get(i)
    if (end !== undefined) { i = end; continue }
    const ch = a.code[i]!
    if (ch === ';' || ch === ',' || ch === ')' || ch === ']' || ch === '}') return i
    if (ch === '\n') {
      const after = a.code.slice(i + 1, i + 40).trimStart()
      const before = a.code.slice(from, i).trimEnd()
      if (before === '' || /[=+\-*/%&|^!?:,.([{<>]$/.test(before) || /^(?:[.?+\-*/%&|^,:<>=]|=>)/.test(after)) continue
      return i
    }
  }
  return a.code.length
}

export interface CodeRange { file: ScanFile; start: number; end: number; arrow?: boolean }

/** 实参中的函数表达式：有函数体时取函数体，表达式箭头函数取 => 起的整个表达式。 */
function functionAt(a: Analysed, from: number, to: number): CodeRange | null {
  const body = a.bodies.find(b => b.declaration >= from && b.start < to)
  if (body) return { file: a.file, start: body.start, end: body.end }
  const arrow = a.code.indexOf('=>', from)
  return arrow !== -1 && arrow < to ? { file: a.file, start: arrow, end: to, arrow: true } : null
}

/**
 * 按名称在文件中查找函数：函数声明与变量初始化、exports.name 赋值、对象属性与方法简写（含类方法）。
 * 变量初始化取整个初始化表达式，柯里化与工厂函数（返回中间件的函数）因此也被包含在内。
 */
export function findFunction(a: Analysed, name: string, depth = 0): CodeRange | null {
  if (depth > 3) return null
  const escaped = name.replace(/\$/g, '\\$')
  for (const body of a.bodies) {
    if (declarationOf(a.code, body, a.openers)?.name === name && /^function\b/.test(a.code.slice(body.declaration, body.declaration + 8))) {
      return { file: a.file, start: body.start, end: body.end }
    }
  }
  const assigned = new RegExp(`(?:\\b(?:const|let|var)\\s+${escaped}\\s*(?::[^=;]{0,200})?|(?<![\\w$])(?:module\\s*\\.\\s*)?exports\\s*\\.\\s*${escaped}\\s*)=(?![=>])\\s*`, 'g')
  for (const m of a.code.matchAll(assigned)) {
    const from = m.index + m[0].length
    // const users = require('./users') 是导入，由导入解析处理。
    if (/^(?:await\s+)?(?:require\s*\(|import\s*\()/.test(a.code.slice(from, from + 20))) continue
    const alias = /^([A-Za-z_$][\w$]*)\s*(?:[;,\n}]|$)/.exec(a.code.slice(from, from + 120))
    if (alias && alias[1] !== name && !/^(?:async|function)$/.test(alias[1]!)) {
      const target = findFunction(a, alias[1]!, depth + 1)
      if (target) return target
    }
    return { file: a.file, start: from, end: expressionEnd(a, from) }
  }
  // 对象属性 name: fn，以及方法简写 name(…) { … }（对象与类）。
  for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])(?:async\\s+)?${escaped}\\s*(?:\\(|:\\s*)`, 'g'))) {
    const at = m.index + m[0].length
    if (m[0].endsWith('(')) {
      const close = a.pairs.get(at - 1)
      if (close === undefined) continue
      const brace = /^\s*(?::[^{;=]{0,200})?\{/.exec(a.code.slice(close + 1, close + 260))
      if (!brace) continue
      const open = close + brace[0].length
      const end = a.pairs.get(open)
      if (end !== undefined) return { file: a.file, start: open, end }
      continue
    }
    if (/^(?:async\s+)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(a.code.slice(at, at + 40))) {
      return { file: a.file, start: at, end: expressionEnd(a, at) }
    }
  }
  return null
}

/** 默认导出的函数：export default function / 名称，module.exports = 函数 / 名称。 */
function defaultExport(a: Analysed): CodeRange | null {
  const m = /\bexport\s+default\s+|(?<![\w$.])module\s*\.\s*exports\s*=(?!=)\s*/.exec(a.code)
  if (!m) return null
  const from = m.index + m[0].length
  const name = /^([A-Za-z_$][\w$]*)\s*(?:[;\n]|$)/.exec(a.code.slice(from, from + 120))?.[1]
  if (name && !/^(?:async|function|class)$/.test(name)) return findFunction(a, name)
  return functionAt(a, from, expressionEnd(a, from)) ?? { file: a.file, start: from, end: expressionEnd(a, from) }
}

interface ImportTarget { file: ScanFile; name: string }

/** 本地名称对应的项目模块及导入名：ES 导入（含命名空间）与 require（含解构）。 */
export function importOf(a: Analysed, local: string, files: ScanFile[]): ImportTarget | null {
  const scope = scopeOf(a.file.path)
  const resolve = (spec: string, name: string): ImportTarget | null => {
    const file = bindingModule(spec, a.file, files, scope)
    return file ? { file, name } : null
  }
  const escaped = local.replace(/\$/g, '\\$')
  const es = bindingsOf(a.file).imports.find(binding => binding.local === local && binding.spec)
  if (es) return resolve(es.spec!, es.imported)
  const namespace = new RegExp(`\\bimport\\s+(?:${escaped}\\s*,[^;]*?|\\*\\s+as\\s+${escaped}\\s+|${escaped}\\s*,\\s*\\{[^{}]*\\}\\s*)from\\s*['"]([^'"]+)['"]`).exec(a.source)
  if (namespace) return resolve(namespace[1]!, 'default')
  const whole = new RegExp(`\\b(?:const|let|var)\\s+${escaped}\\s*=\\s*require\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`).exec(a.source)
  if (whole) return resolve(whole[1]!, 'default')
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    for (const part of m[1]!.split(',')) {
      const names = /^\s*([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?\s*$/.exec(part)
      if (names && (names[2] ?? names[1]) === local) return resolve(m[2]!, names[1]!)
    }
  }
  return null
}

/** 一个导入目标中按名称找函数；默认导入取默认导出，或在其中按成员名查找（module.exports = { create }）。 */
function importedFunction(target: ImportTarget, member: string | null): CodeRange | null {
  const ta = analyse(target.file)
  if (member) return findFunction(ta, member)
  return target.name === 'default' ? defaultExport(ta) : findFunction(ta, target.name)
}

/** 处理函数位置：函数表达式本身，或同文件、其他文件中按名称找到的函数；asyncHandler(fn) 之类先拆开包装。 */
function handlerOf(a: Analysed, arg: Arg, files: ScanFile[], depth = 0): CodeRange | null {
  const text = arg.text
  if (/^(?:async\s+)?(?:function\b|\([^()]*\)\s*(?::[^=]{0,200})?=>|[A-Za-z_$][\w$]*\s*=>)/.test(text)) {
    return functionAt(a, arg.at, arg.at + text.length)
  }
  const call = /^([A-Za-z_$][\w$.]*)\s*\(/.exec(text)
  if (call && depth < 3) {
    const open = arg.at + call[0].length - 1
    const close = a.pairs.get(open)
    if (close === arg.at + text.length - 1) {
      const inner = argsOf(a, open, close).at(-1)
      return inner ? handlerOf(a, inner, files, depth + 1) : null
    }
    return null
  }
  const ident = /^([A-Za-z_$][\w$]*)$/.exec(text)
  if (ident) {
    const local = findFunction(a, ident[1]!)
    if (local) return local
    const target = importOf(a, ident[1]!, files)
    return target ? importedFunction(target, null) : null
  }
  const member = /^([A-Za-z_$][\w$]*)\s*\.\s*([A-Za-z_$][\w$]*)$/.exec(text)
  if (member) {
    const target = importOf(a, member[1]!, files)
    return target ? importedFunction(target, member[2]!) : null
  }
  return null
}

const toRefs = (a: Analysed, args: Arg[]): MiddlewareRef[] =>
  args.map(arg => ({ text: arg.source, at: arg.at, file: a.file }))

/** 被挂载的 Router 所在文件：require('./routes/x') 或导入的本地名称。 */
function mountedFile(a: Analysed, arg: Arg, files: ScanFile[]): ScanFile | null {
  const inline = /^require\s*\(\s*['"]([^'"]+)['"]\s*\)$/.exec(arg.source)
  if (inline) return bindingModule(inline[1]!, a.file, files, scopeOf(a.file.path))
  const ident = /^([A-Za-z_$][\w$]*)$/.exec(arg.text)
  return ident ? importOf(a, ident[1]!, files)?.file ?? null : null
}

/** 函数的形参名，按位置排列；无法确定时返回空数组。range 为函数体（以 { 开头）或函数表达式的起点。 */
function paramNamesOf(a: Analysed, range: CodeRange): string[] {
  const code = a.code
  let open: number | undefined
  if (code[range.start] === '{') {
    let i = range.start - 1
    const skip = (): void => { while (i >= 0 && /\s/.test(code[i]!)) i-- }
    skip()
    let arrow = false
    if (code[i] === '>' && code[i - 1] === '=') { arrow = true; i -= 2; skip() }
    if (arrow && /[\w$]/.test(code[i] ?? '')) {
      const end = i + 1
      while (i >= 0 && /[\w$]/.test(code[i]!)) i--
      return [code.slice(i + 1, end)]
    }
    // 返回类型标注 ): Promise<void> {：向前找到参数列表的右括号。
    if (code[i] !== ')') {
      const window = code.slice(Math.max(0, i - 200), i + 1)
      const close = window.lastIndexOf(')')
      if (close === -1) return []
      i -= window.length - 1 - close
    }
    open = a.openers.get(i)
  } else {
    const head = /^\s*(?:async\s+)?(?:function\b[^(]{0,80})?\(/.exec(code.slice(range.start, range.start + 200))
    if (head) open = range.start + head[0].length - 1
    else {
      const single = /^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*=>/.exec(code.slice(range.start, range.start + 200))
      return single ? [single[1]!] : []
    }
  }
  if (open === undefined) return []
  const close = a.pairs.get(open)
  if (close === undefined) return []
  return argsOf(a, open, close).map(arg => /^(?:\.\.\.)?\s*([A-Za-z_$][\w$]*)/.exec(arg.text)?.[1] ?? '')
}

/**
 * 一个实例名及其有效范围：导入 express 的文件中为整个文件，作为参数传入时为接收它的函数。
 * root 是最初创建的实例，挂载它时前缀与中间件也作用于经参数传出的路由；inherited 是传出前已注册的 use() 中间件。
 */
interface Site { a: Analysed; name: string; range: { start: number; end: number } | null; root?: Site; inherited: MiddlewareRef[] }

const within = (site: Site, at: number): boolean => site.range === null || (site.range.start <= at && at <= site.range.end)

/**
 * 把实例作为实参传出的调用：systemEndpoints(api)、require('./routes')(app)、routes.init(app)。
 * 被调用函数中对应位置的形参在该函数范围内即为实例。
 */
function passedSites(site: Site, files: ScanFile[]): Site[] {
  const { a } = site
  const found: Site[] = []
  const uses = usesOf(a, new Set([site.name])).filter(use => within(site, use.at))
  const receive = (range: CodeRange | null, index: number, at: number): void => {
    if (!range) return
    const target = analyse(range.file)
    const name = paramNamesOf(target, range)[index]
    if (!name) return
    // 传出前在实例上注册的、不限路径的中间件对传出后的路由同样生效。
    const earlier = uses.filter(use => use.at < at && (use.prefix === null || use.prefix === '/'))
      .flatMap(use => use.args.filter(arg => mountedFile(a, arg, files) === null))
    found.push({ a: target, name, range: { start: range.start, end: range.end }, root: site.root ?? site,
      inherited: [...site.inherited, ...toRefs(a, earlier)] })
  }
  for (const m of a.source.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\(/g)) {
    if (!within(site, m.index)) continue
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    const index = argsOf(a, open, close).findIndex(arg => arg.text === site.name)
    const module = index === -1 ? null : bindingModule(m[1]!, a.file, files, scopeOf(a.file.path))
    if (module) receive(defaultExport(analyse(module)), index, m.index)
  }
  for (const m of a.code.matchAll(/(?<![\w$.])(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\(/g)) {
    if (!within(site, m.index) || m[1] === site.name || m[2] === 'require' || m[2] === site.name) continue
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    const index = argsOf(a, open, close).findIndex(arg => arg.text === site.name)
    if (index === -1) continue
    if (m[1]) {
      const target = importOf(a, m[1], files)
      receive(target ? importedFunction(target, m[2]!) : null, index, m.index)
    } else {
      const local = findFunction(a, m[2]!)
      if (local) { receive(local, index, m.index); continue }
      const target = importOf(a, m[2]!, files)
      receive(target ? importedFunction(target, null) : null, index, m.index)
    }
  }
  return found
}

interface ExpressIndex { byHandlerFile: Map<ScanFile, Route[]> }
const indexCache = new WeakMap<ScanFile[], ExpressIndex>()

/** 全部文件的 Express 路由，按处理函数所在文件分组；每次扫描只建立一次。 */
function expressIndex(files: ScanFile[]): ExpressIndex {
  const cached = indexCache.get(files)
  if (cached) return cached
  // 实例：导入 express 的文件中直接创建的，以及经参数传入其他函数的（最多三层）。
  const sites: Site[] = []
  const seen = new Set<string>()
  const add = (site: Site): boolean => {
    const key = `${site.a.file.path}\0${site.name}\0${site.range?.start ?? -1}`
    if (seen.has(key)) return false
    seen.add(key)
    sites.push(site)
    return true
  }
  for (const file of files) {
    if (!/\.[mc]?[jt]sx?$/.test(file.path) || !/\bexpress\b/.test(file.content)) continue
    const a = analyse(file)
    const names = expressNamesOf(a)
    if (!names) continue
    for (const name of instancesOf(a, names)) add({ a, name, range: null, inherited: [] })
  }
  let frontier = [...sites]
  for (let level = 0; level < 3 && frontier.length; level++) {
    const next: Site[] = []
    for (const site of frontier) for (const passed of passedSites(site, files)) if (add(passed)) next.push(passed)
    frontier = next
  }

  const byRouterFile = new Map<ScanFile, Route[]>()
  const byRoot = new Map<Site, Route[]>()
  const usesBySite = new Map<Site, Use[]>()
  for (const site of sites) {
    const { a } = site
    const instance = new Set([site.name])
    const uses = usesOf(a, instance).filter(use => within(site, use.at))
    usesBySite.set(site, uses)
    const routes = byRouterFile.get(a.file) ?? []
    for (const reg of registrationsOf(a, instance)) {
      if (!within(site, reg.at)) continue
      const handlerArg = reg.args.at(-1)
      if (!handlerArg) continue
      const handler = handlerOf(a, handlerArg, files)
      if (!handler) continue
      const before = uses.filter(use => use.at < reg.at && pathMatches(use.prefix, reg.path))
        .flatMap(use => use.args.filter(arg => mountedFile(a, arg, files) === null))
      const route: Route = {
        file: handler.file, framework: 'express', url: reg.path ?? '(dynamic path)', scope: scopeOf(handler.file.path),
        reachable: { start: handler.start, end: handler.end },
        middleware: [...site.inherited, ...toRefs(a, before), ...toRefs(a, flatten(a, reg.args.slice(0, -1)))],
        mounts: [],
      }
      routes.push(route)
      const root = site.root ?? site
      byRoot.set(root, [...(byRoot.get(root) ?? []), route])
    }
    if (routes.length) byRouterFile.set(a.file, routes)
  }
  // 同一文件中的本地实例被挂载：app.use('/api', api)，其路由包括经参数传出后注册的。
  const localRoutes = (a: Analysed, arg: Arg): Route[] | undefined => {
    const root = sites.find(other => other.a === a && other.range === null && other.name === arg.text && !other.root)
    return root ? byRoot.get(root) : undefined
  }
  // 挂载：app.use('/admin', requireAuth, adminRouter)；同一实例上更早的 use() 中间件同样生效。
  for (const [site, uses] of usesBySite) {
    const { a } = site
    for (const use of uses) {
      use.args.forEach((arg, index) => {
        const target = mountedFile(a, arg, files)
        const routes = target && target !== a.file ? byRouterFile.get(target) : localRoutes(a, arg)
        if (!routes || routes.length === 0) return
        const isMiddleware = (x: Arg): boolean => mountedFile(a, x, files) === null && localRoutes(a, x) === undefined
        const earlier = uses.filter(other => other.at < use.at && pathMatches(other.prefix, use.prefix))
          .flatMap(other => other.args.filter(isMiddleware))
        const middleware = [...toRefs(a, earlier), ...toRefs(a, use.args.slice(0, index).filter(isMiddleware))]
        for (const route of routes) {
          route.mounts!.push(middleware)
          if (use.prefix && use.prefix !== '/' && route.mounts!.length === 1 && route.url.startsWith('/')) {
            route.url = `${use.prefix.replace(/\/$/, '')}${route.url === '/' ? '' : route.url}`
          }
        }
      })
    }
  }
  const byHandlerFile = new Map<ScanFile, Route[]>()
  for (const routes of byRouterFile.values()) {
    for (const route of routes) {
      const list = byHandlerFile.get(route.file) ?? []
      list.push(route)
      byHandlerFile.set(route.file, list)
    }
  }
  const index = { byHandlerFile }
  indexCache.set(files, index)
  return index
}

/** 处理函数位于该文件中的 Express 路由。 */
export function expressRoutesFor(file: ScanFile, files: ScanFile[]): Route[] {
  return expressIndex(files).byHandlerFile.get(file) ?? []
}

/** 文件中可被直接请求的服务端入口：按文件约定的路由、Server Function，或处理函数位于此处的 Express 路由。 */
export function serverRoutesOf(file: ScanFile, files: ScanFile[]): Route[] {
  const route = routeOf(file)
  if (route) return [route]
  const actions = serverActionRoutes(file)
  return actions.length ? actions : expressRoutesFor(file, files)
}

/** 中间件引用所在文件的解析结果，供鉴权规则查找定义。 */
export function middlewareDefinition(ref: MiddlewareRef, files: ScanFile[]): { name: string; range: CodeRange | null; spec: string | null } {
  const a = analyse(ref.file)
  const root = /^([A-Za-z_$][\w$]*)/.exec(ref.text)?.[1] ?? ''
  const member = /^[A-Za-z_$][\w$]*\s*\.\s*([A-Za-z_$][\w$]*)/.exec(ref.text)?.[1] ?? null
  const callee = member ?? root
  // 外部包：返回包名，由调用方按已知鉴权库判断。
  const es = bindingsOf(ref.file).imports.find(binding => binding.local === root)
  const cjs = new RegExp(`\\b(?:const|let|var)\\s+(?:${root.replace(/\$/g, '\\$')}|\\{[^{}]*\\b${root.replace(/\$/g, '\\$')}\\b[^{}]*\\})\\s*=\\s*require\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`).exec(a.source)
  const named = new RegExp(`\\bimport\\s+${root.replace(/\$/g, '\\$')}\\s*(?:,[^;]*?)?from\\s*['"]([^'"]+)['"]`).exec(a.source)
  const spec = es?.spec ?? cjs?.[1] ?? named?.[1] ?? null
  if (spec && !spec.startsWith('.') && !/^(?:[@~#]|~~|@@|\$lib)\//.test(spec)) return { name: callee, range: null, spec }
  const local = member === null ? findFunction(a, root) : null
  if (local) return { name: callee, range: local, spec: null }
  const target = importOf(a, root, files)
  return { name: callee, range: target ? importedFunction(target, member) : null, spec: null }
}
