/**
 * Node 服务端框架的路由：Express、Hono、Fastify。
 * 在导入框架的文件中识别应用、Router 与插件实例上的路由注册；处理函数可以写在其他文件（控制器）中。
 * 路由参数中的中间件与钩子、实例上先注册的 use()/addHook()、挂载或注册时经过的中间件随路由记录，
 * 由鉴权规则判断是否构成保护。不导入这些框架的文件不按此识别，避免把普通的 x.get() 当成路由；
 * Fastify 插件文件经 register() 或 @fastify/autoload 从注册处进入。
 */
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { bindingsOf } from './bindings.js'
import {
  bindingModule, declarationOf, delimiterPairs, functionBodies, routeOf, serverActionRoutes,
  type FunctionBody, type MiddlewareRef, type Route,
} from './apiauth.js'

export type NodeFramework = 'express' | 'hono' | 'fastify'
export const NODE_FRAMEWORKS: ReadonlySet<string> = new Set<NodeFramework>(['express', 'hono', 'fastify'])

const METHODS = 'get|post|put|patch|delete|all|options|head'
/** TypeScript 的泛型实参，如 router.get<Params, Body>(…)。 */
const GENERICS = String.raw`(?:<[^()]{0,300}>\s*)?`
/** Fastify 在处理函数之前运行、可以拒绝请求的钩子。 */
const FASTIFY_HOOKS = /^(?:onRequest|preParsing|preValidation|preHandler)$/
/** Hono 实例上的链式调用：路由、中间件与子应用挂载。 */
const HONO_CALL = `${METHODS}|on|use|route|openapi`

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
  return /^(.*?\/)?(?:src|app|lib|server|routes|api|controllers|plugins)\//.exec(path)?.[1] ?? ''
}

/** 对象字面量的一项：键值对给出值，方法简写给出函数体。 */
interface Entry { value: Arg | null; range: CodeRange | null }

/** 对象字面量的顶层各项：key: value、简写属性 { handler }，以及方法简写 handler(request, reply) { … }。 */
function entriesOf(a: Analysed, arg: Arg | undefined): Map<string, Entry> {
  const entries = new Map<string, Entry>()
  if (!arg || a.code[arg.at] !== '{') return entries
  const close = a.pairs.get(arg.at)
  if (close === undefined) return entries
  for (const part of argsOf(a, arg.at, close)) {
    const key = /^(?:async\s+)?['"]?([A-Za-z_$][\w$]*)['"]?/.exec(part.source)
    if (!key) continue
    const rest = part.text.slice(key[0].length)
    const colon = /^\s*:\s*/.exec(rest)
    if (colon) {
      const offset = key[0].length + colon[0].length
      entries.set(key[1]!, { value: { text: part.text.slice(offset), source: part.source.slice(offset), at: part.at + offset }, range: null })
    } else if (/^\s*(?:<[^()]{0,200}>\s*)?\(/.test(rest)) {
      // 方法简写：参数括号之后（可带返回类型标注）即为函数体。
      const open = part.at + key[0].length + rest.indexOf('(')
      const close = a.pairs.get(open)
      const brace = close === undefined ? null : /^\s*(?::[^{;=]{0,200})?\{/.exec(a.code.slice(close + 1, close + 260))
      const start = close === undefined || !brace ? undefined : close + brace[0].length
      const end = start === undefined ? undefined : a.pairs.get(start)
      entries.set(key[1]!, { value: null, range: start !== undefined && end !== undefined ? { file: a.file, start, end } : null })
    } else if (rest.trim() === '') {
      entries.set(key[1]!, { value: part, range: null })
    }
  }
  return entries
}

interface FrameworkNames { express: Set<string>; router: Set<string>; hono: Set<string>; openapi: Set<string>; fastify: Set<string>; types: Set<NodeFramework> }

/**
 * 文件中框架的本地名称：express 的默认、命名空间与 require 结果及 Router 别名；Hono 与 OpenAPIHono 构造函数；
 * fastify 工厂函数。只导入类型时记录框架，用于识别类型标注的参数。
 */
function frameworkNamesOf(a: Analysed): FrameworkNames | null {
  const names: FrameworkNames = { express: new Set(), router: new Set(), hono: new Set(), openapi: new Set(), fastify: new Set(), types: new Set() }
  const named = (list: string, wanted: RegExp, into: Set<string>, fallback?: (name: string) => void): void => {
    for (const part of list.split(',')) {
      const m = /^\s*(?:type\s+)?([A-Za-z_$][\w$]*)\s*(?:(?:as|:)\s*([A-Za-z_$][\w$]*))?\s*$/.exec(part)
      if (!m) continue
      if (wanted.test(m[1]!) && !/^\s*type\s/.test(part)) into.add(m[2] ?? m[1]!)
      fallback?.(m[1]!)
    }
  }
  for (const m of a.source.matchAll(/\bimport\s+(type\s+)?(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{([^{}]*)\}|\*\s+as\s+([A-Za-z_$][\w$]*))?\s*from\s*['"](express|hono(?:\/tiny|\/quick)?|@hono\/zod-openapi|fastify)['"]/g)) {
    const typeOnly = Boolean(m[1])
    if (m[5] === 'express') {
      if (!typeOnly && m[2]) names.express.add(m[2])
      if (!typeOnly && m[4]) names.express.add(m[4])
      if (m[3]) named(m[3], /^Router$/, names.router)
      names.types.add('express')
    } else if (m[5] === 'fastify') {
      if (!typeOnly && m[2]) names.fastify.add(m[2])
      if (!typeOnly && m[3]) named(m[3], /^fastify$/, names.fastify)
      names.types.add('fastify')
    } else {
      if (!typeOnly && m[3]) named(m[3], /^(?:Hono|OpenAPIHono)$/, names.hono)
      if (!typeOnly && m[3] && m[5] === '@hono/zod-openapi') named(m[3], /^OpenAPIHono$/, names.openapi)
      names.types.add('hono')
    }
  }
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s+(?:([A-Za-z_$][\w$]*)|\{([^{}]*)\})\s*=\s*require\s*\(\s*['"](express|hono(?:\/tiny|\/quick)?|@hono\/zod-openapi|fastify)['"]\s*\)(?!\s*\()/g)) {
    if (m[3] === 'express') {
      if (m[1]) names.express.add(m[1])
      if (m[2]) named(m[2], /^Router$/, names.router)
    } else if (m[3] === 'fastify') {
      if (m[1]) names.fastify.add(m[1])
      if (m[2]) named(m[2], /^fastify$/, names.fastify)
    } else if (m[2]) {
      named(m[2], /^(?:Hono|OpenAPIHono)$/, names.hono)
      if (m[3] === '@hono/zod-openapi') named(m[2], /^OpenAPIHono$/, names.openapi)
    }
    names.types.add(m[3] === 'express' || m[3] === 'fastify' ? m[3] : 'hono')
  }
  for (const m of a.source.matchAll(/\brequire\s*\(\s*['"](express|fastify)['"]\s*\)/g)) names.types.add(m[1] as NodeFramework)
  return names.types.size ? names : null
}

/** 一个实例：名称、所属框架、路径前缀（Hono 的 basePath），以及创建处之后可接链式调用的位置。 */
interface Instance { name: string; framework: NodeFramework; prefix: string; weak: boolean; chainFrom?: number; openapi?: boolean }

/**
 * 应用与 Router 实例：express()、express.Router()、Router()、require('express')()；new Hono()（可接 basePath）；
 * Fastify()、require('fastify')()。类型标注为框架实例的参数也算，但只在没有更具体的来源时使用（weak）。
 */
function instancesOf(a: Analysed, names: FrameworkNames): Instance[] {
  const found: Instance[] = []
  const add = (instance: Instance): void => { if (!found.some(other => other.name === instance.name)) found.push(instance) }
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=;]{0,100})?=\s*(?:await\s+)?(new\s+)?([A-Za-z_$][\w$]*)\s*(?:\.\s*(Router)\s*)?(<[^()]{0,300}>\s*)?\(/g)) {
    const [, name, isNew, callee, router] = m
    if (!isNew && ((names.express.has(callee!) && (router === 'Router' || router === undefined)) || (names.router.has(callee!) && router === undefined))) {
      add({ name: name!, framework: 'express', prefix: '', weak: false })
    } else if (isNew && names.hono.has(callee!) && router === undefined) {
      const open = m.index + m[0].length - 1
      let close = a.pairs.get(open)
      if (close === undefined) continue
      let prefix = ''
      const base = /^\s*\.\s*basePath\s*\(/.exec(a.code.slice(close + 1, close + 200))
      if (base) {
        const baseOpen = close + base[0].length
        const baseClose = a.pairs.get(baseOpen)
        const arg = baseClose === undefined ? undefined : argsOf(a, baseOpen, baseClose)[0]
        prefix = (arg && pathOf(a, arg)) ?? ''
        if (baseClose !== undefined) close = baseClose
      }
      add({ name: name!, framework: 'hono', prefix, weak: false, chainFrom: close, openapi: names.openapi.has(callee!) })
    } else if (!isNew && names.fastify.has(callee!) && router === undefined) {
      add({ name: name!, framework: 'fastify', prefix: '', weak: false })
    }
  }
  for (const m of a.source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?require\s*\(\s*['"](express|fastify)['"]\s*\)\s*(?:\.\s*(Router)\s*)?\(/g)) {
    if (m[2] === 'express' || !m[3]) add({ name: m[1]!, framework: m[2] as NodeFramework, prefix: '', weak: false })
  }
  const typed: Array<[NodeFramework, string]> = [
    ['express', String.raw`(?:Express|Router|Application)\b(?!\s*[.<(])`],
    ['hono', String.raw`(?:Hono|OpenAPIHono)\b(?!\s*[.(])`],
    ['fastify', String.raw`FastifyInstance\b(?!\s*[.(])`],
  ]
  for (const [framework, type] of typed) {
    if (!names.types.has(framework)) continue
    for (const m of a.code.matchAll(new RegExp(String.raw`([A-Za-z_$][\w$]*)\s*\??:\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?${type}`, 'g'))) {
      add({ name: m[1]!, framework, prefix: '', weak: true, openapi: framework === 'hono' && /\bOpenAPIHono\b/.test(m[0]) })
    }
  }
  return found
}

/** 路由注册：路径、处理函数之前的中间件与钩子、处理函数（实参或方法简写的函数体）。 */
interface Registration { path: string | null; middleware: Arg[]; handler: Arg | null; handlerRange: CodeRange | null; at: number }

/** 字符串字面量路径；无插值的模板也接受，其他形式视为动态路径。 */
function literalOf(arg: Arg): string | null {
  const m = /^(['"`])([^'"`$]*)\1$/.exec(arg.source)
  return m ? m[2]! : null
}

/** 同一文件中的字符串常量：const MCP_PATH = '/mcp'。 */
function constantOf(a: Analysed, name: string): string | null {
  const m = new RegExp(`\\bconst\\s+${name.replace(/\$/g, '\\$')}\\s*(?::\\s*string\\s*)?=\\s*(['"\`])([^'"\`$]*)\\1`).exec(a.source)
  return m ? m[2]! : null
}

/**
 * 路径数组的每一项（Express 的 app.get(['/a', '/b'], …)、Hono 的 app.on('GET', ['/a', '/b'], …)），
 * 每条路径各自判断保护状态；不是数组时只有一项。
 */
function pathsOf(a: Analysed, arg: Arg): Array<string | null> {
  if (!arg.text.startsWith('[')) return [pathOf(a, arg)]
  const close = a.pairs.get(arg.at)
  const items = close === undefined ? [] : argsOf(a, arg.at, close)
  return items.length ? items.map(item => pathOf(a, item)) : [null]
}

/**
 * use() 首个实参是路径或路径数组时返回各前缀，否则返回空值，表示它是中间件。
 * 数组中无法解析的路径不知道作用于哪里，不当作全局前缀，直接略去。
 */
function usePrefixes(a: Analysed, arg: Arg): string[] | null {
  if (arg.text.startsWith('[')) {
    const close = a.pairs.get(arg.at)
    const items = close === undefined ? [] : argsOf(a, arg.at, close)
    if (items.length === 0 || !items.some(item => /^['"`]/.test(item.source))) return null
    return items.map(item => pathOf(a, item)).filter((path): path is string => path !== null)
  }
  const prefix = pathOf(a, arg)
  if (prefix !== null) return [prefix]
  // 动态字符串、环境路径与正则路径不能被误当作无路径的全局中间件。
  if (/^['"`/]|^new\s+RegExp\b|^(?:process\s*\.\s*env|import\s*\.\s*meta\s*\.\s*env|(?:[\w$]+\s*\.\s*)?env)\s*[.[]/.test(arg.source)) return []
  return null
}

/**
 * 路径实参：字面量；同文件字符串常量及只插入这类常量的模板（`${MCP_OAUTH_PATH}/register`）。
 * 数组由 pathsOf 展开，其他形式视为动态路径。
 */
function pathOf(a: Analysed, arg: Arg): string | null {
  if (arg.text.startsWith('[')) return null
  const literal = literalOf(arg)
  if (literal !== null) return literal
  if (/^[A-Za-z_$][\w$]*$/.test(arg.source)) return constantOf(a, arg.source)
  const template = /^`((?:[^`$\\]|\$\{\s*[A-Za-z_$][\w$]*\s*\})*)`$/.exec(arg.source)
  if (!template) return null
  let unresolved = false
  const path = template[1]!.replace(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g, (_whole, name: string) => {
    const value = constantOf(a, name)
    if (value === null) unresolved = true
    return value ?? ''
  })
  return unresolved ? null : path
}

/** 前缀与路径拼接；动态路径保持原样。 */
function joinPath(prefix: string, path: string): string {
  if (!prefix || prefix === '/' || !path.startsWith('/')) return path
  const base = prefix.replace(/\/+$/, '')
  return path === '/' ? base || '/' : `${base}${path}`
}

/**
 * Express 实例上的路由注册：app.get(path, …)，以及 router.route(path).get(…).post(…) 链。
 * 回调可以放在数组中（app.post('/x', [auth, handler])），展开后最后一个为处理函数。
 */
function expressRegistrations(a: Analysed, name: string): Registration[] {
  const found: Registration[] = []
  const escaped = name.replace(/\$/g, '\\$')
  const add = (paths: Array<string | null>, args: Arg[], at: number): void => {
    const callbacks = flatten(a, args)
    if (callbacks.length === 0) return
    for (const path of paths) found.push({ path, middleware: callbacks.slice(0, -1), handler: callbacks.at(-1)!, handlerRange: null, at })
  }
  for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${escaped}\\s*\\.\\s*(?:${METHODS})\\s*${GENERICS}\\(`, 'g'))) {
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    const args = argsOf(a, open, close)
    // app.get('setting') 是读取配置，路由至少有路径和处理函数。
    if (args.length < 2) continue
    add(pathsOf(a, args[0]!), args.slice(1), m.index)
  }
  for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${escaped}\\s*\\.\\s*route\\s*\\(`, 'g'))) {
    const open = m.index + m[0].length - 1
    let close = a.pairs.get(open)
    if (close === undefined) continue
    const pathArg = argsOf(a, open, close)[0]
    const paths = pathArg ? pathsOf(a, pathArg) : [null]
    for (let guard = 0; guard < 16; guard++) {
      const next = new RegExp(`^\\s*\\.\\s*(?:${METHODS})\\s*${GENERICS}\\(`).exec(a.code.slice(close + 1, close + 500))
      if (!next) break
      const methodOpen = close + 1 + next[0].length - 1
      const methodClose = a.pairs.get(methodOpen)
      if (methodClose === undefined) break
      add(paths, argsOf(a, methodOpen, methodClose), close + 1 + next[0].search(/[a-z]/))
      close = methodClose
    }
  }
  return found.sort((x, y) => x.at - y.at)
}

/** 实例上的 use()（Fastify 为前置钩子）：可带路径前缀；mount 表示 Hono 的 route(prefix, sub) 子应用挂载。 */
interface Use { prefix: string | null; args: Arg[]; at: number; mount?: boolean }

/** Express 实例上的 use()：可带路径前缀，其余实参为中间件或被挂载的 Router。 */
function expressUses(a: Analysed, name: string): Use[] {
  const found: Use[] = []
  for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}\\s*\\.\\s*use\\s*\\(`, 'g'))) {
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    const args = argsOf(a, open, close)
    const prefixes = args[0] ? usePrefixes(a, args[0]) : null
    const middleware = flatten(a, prefixes === null ? args : args.slice(1))
    for (const prefix of prefixes ?? [null]) found.push({ prefix, args: middleware, at: m.index })
  }
  return found.sort((x, y) => x.at - y.at)
}

/** OpenAPI 中间件仅接受完整引用、调用或数组，不截取条件表达式的局部证据。 */
function openapiMiddleware(a: Analysed, arg: Arg, depth = 0): Arg[] {
  if (depth >= 8) return []
  if (arg.text.startsWith('[')) {
    const close = a.pairs.get(arg.at)
    if (close === undefined || !/^\s*(?:as\s+const)?\s*$/.test(arg.text.slice(close - arg.at + 1))) return []
    return argsOf(a, arg.at, close).flatMap(item => openapiMiddleware(a, item, depth + 1))
  }
  if (/^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*$/.test(arg.text) || FUNCTION_EXPRESSION.test(arg.text)) return [arg]
  const call = /^[A-Za-z_$][\w$.]*\s*\(/.exec(arg.text)
  return call && a.pairs.get(arg.at + call[0].length - 1) === arg.at + arg.text.length - 1 ? [arg] : []
}

/** 同文件的 OpenAPI 配置；展开、计算属性和可变来源不提供路径或鉴权证明。 */
function openapiEntries(a: Analysed, arg: Arg, depth = 0): Map<string, Entry> {
  if (depth >= 8) return new Map()
  const root = /^([A-Za-z_$][\w$]*)(?:\s*\(|$)/.exec(arg.text)?.[1]
  if (root && a.bodies.some(body => body.start < arg.at && arg.at < body.end &&
      paramNamesOf(a, { file: a.file, start: body.start, end: body.end }).includes(root))) return new Map()
  if (arg.text.startsWith('{')) {
    const close = a.pairs.get(arg.at)
    if (close === undefined || !/^\s*(?:as\s+const|satisfies\s+[\w$.]+)?\s*$/.test(arg.text.slice(close - arg.at + 1))) return new Map()
    if (argsOf(a, arg.at, close).some(part => /^(?:\.\.\.|\[|(?:get|set)\s+)/.test(part.text))) return new Map()
    return entriesOf(a, arg)
  }
  const call = /^([A-Za-z_$][\w$]*)\s*\(/.exec(arg.text)
  if (call) {
    const binding = bindingsOf(a.file).imports.find(item => item.local === call[1])
    if (binding?.imported !== 'createRoute' || binding.spec !== '@hono/zod-openapi') return new Map()
    if (new RegExp(`\\b(?:const|let|var|function)\\s+${call[1]!.replace(/\$/g, '\\$')}(?![\\w$])`).test(a.code)) return new Map()
    const open = arg.at + call[0].length - 1
    const close = a.pairs.get(open)
    if (close !== arg.at + arg.text.length - 1) return new Map()
    const args = argsOf(a, open, close)
    return args.length === 1 ? openapiEntries(a, args[0]!, depth + 1) : new Map()
  }
  if (!/^[A-Za-z_$][\w$]*$/.test(arg.text)) return new Map()
  const name = arg.text.replace(/\$/g, '\\$')
  // 同名声明或形参不借用其他作用域中的配置。
  const declarations = [...a.code.matchAll(new RegExp(`\\b(const|let|var)\\s+${name}\\s*(?::[^=;]{0,200})?=(?![=>])\\s*`, 'g'))]
  if (declarations.length !== 1 || declarations[0]![1] !== 'const') return new Map()
  const declaration = declarations[0]!
  if (declaration.index >= arg.at) return new Map()
  for (const [open, close] of a.pairs) {
    if (a.code[open] === '{' && open < declaration.index && declaration.index < close && !(open < arg.at && arg.at < close)) return new Map()
  }
  // const 不保证对象不可变；成员修改及其别名修改均不能提供保护证明。
  const aliases = new Set([arg.text])
  const assignedAliases = [...a.code.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*(?=[;,\n]|$)/g)]
  for (let pass = 0; pass < 8; pass++) {
    const size = aliases.size
    for (const match of assignedAliases) if (aliases.has(match[2]!)) aliases.add(match[1]!)
    if (aliases.size > 64) return new Map()
    if (aliases.size === size) break
    if (pass === 7) return new Map()
  }
  for (const alias of aliases) {
    const escaped = alias.replace(/\$/g, '\\$')
    const mutable = new RegExp(`(?<![\\w$.])${escaped}\\s*(?:\\.\\s*[\\w$]+|\\[[^\\]]{0,200}\\])+(?:\\s*(?:=|\\?\\?=|\\|\\|=|&&=)|\\s*\\()|\\bdelete\\s+${escaped}(?![\\w$])|\\bObject\\s*\\.\\s*(?:assign|defineProperty|defineProperties)\\s*\\(\\s*${escaped}(?![\\w$])`)
    if (mutable.test(a.code)) return new Map()
  }
  const from = declaration.index + declaration[0].length
  const end = expressionEnd(a, from)
  const text = a.code.slice(from, end).trimEnd()
  return openapiEntries(a, { at: from, text, source: a.source.slice(from, from + text.length) }, depth + 1)
}

/**
 * Hono 实例上的调用：app.get(path, …mw, handler)、app.on(method, path, …)、app.use(path?, …mw)、app.route(prefix, sub)，
 * OpenAPIHono 的 openapi(config, handler, hook?)；配置仅解析内联对象与同文件常量。
 * 以及 new Hono().get(…).post(…) 链；链中省略路径的方法沿用上一个路径。
 */
function honoOps(a: Analysed, name: string, chainFrom: number | undefined, openapi = false): { registrations: Registration[]; uses: Use[] } {
  const registrations: Registration[] = []
  const uses: Use[] = []
  // 路径数组（app.on('POST', ['/a', '/b'], …)）中的每条路径各自登记一条路由。
  type Paths = Array<string | null>
  const visit = (method: string, open: number, close: number, at: number, previous: Paths): Paths => {
    const args = argsOf(a, open, close)
    if (method === 'openapi') {
      if (!openapi || !args[0] || !args[1]) return previous
      const entries = openapiEntries(a, args[0])
      const path = entries.get('path')?.value
      const resolved = path ? literalOf(path) : null
      const routingPath = resolved?.replace(/\/\{(.+?)\}/g, '/:$1') ?? null
      const middleware = entries.get('middleware')?.value
      // 第三个实参是校验回调，不是路由处理函数，也不提供鉴权证明。
      registrations.push({ path: routingPath, middleware: middleware ? openapiMiddleware(a, middleware) : [],
        handler: args[1], handlerRange: null, at })
      return [routingPath]
    }
    if (method === 'use') {
      const prefixes = args[0] ? usePrefixes(a, args[0]) : null
      const middleware = flatten(a, prefixes === null ? args : args.slice(1))
      for (const prefix of prefixes ?? [null]) uses.push({ prefix, args: middleware, at })
      return previous
    }
    if (method === 'route') {
      if (args.length >= 2) uses.push({ prefix: pathOf(a, args[0]!), args: [args[1]!], at, mount: true })
      return previous
    }
    let rest = method === 'on' ? args.slice(1) : args
    let paths = previous
    if (rest[0] && /^['"`[]/.test(rest[0].source)) { paths = pathsOf(a, rest[0]); rest = rest.slice(1) }
    if (rest.length > 0) {
      for (const path of paths) registrations.push({ path, middleware: rest.slice(0, -1), handler: rest.at(-1)!, handlerRange: null, at })
    }
    return paths
  }
  const chain = (after: number, previous: Paths): void => {
    for (let guard = 0; guard < 64; guard++) {
      const next = new RegExp(`^\\s*\\.\\s*(${HONO_CALL})\\s*${GENERICS}\\(`).exec(a.code.slice(after + 1, after + 500))
      if (!next) return
      const open = after + next[0].length
      const close = a.pairs.get(open)
      if (close === undefined) return
      previous = visit(next[1]!, open, close, after + 1 + next[0].search(/[a-z]/), previous)
      after = close
    }
  }
  if (chainFrom !== undefined) chain(chainFrom, [null])
  for (const m of a.code.matchAll(new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}\\s*\\.\\s*(${HONO_CALL})\\s*${GENERICS}\\(`, 'g'))) {
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    chain(close, visit(m[1]!, open, close, m.index, [null]))
  }
  registrations.sort((x, y) => x.at - y.at)
  uses.sort((x, y) => x.at - y.at)
  return { registrations, uses }
}

/** Fastify 的 register 调用：被注册的插件与选项。 */
interface Register { target: Arg; options: Arg | undefined; at: number }

/**
 * Fastify 实例上的调用：fastify.get(path, [options], handler)、fastify.route({ method, url, handler, … })，
 * 选项中的 onRequest/preParsing/preValidation/preHandler 钩子，实例上的 addHook()，以及 register()。
 * 允许 withTypeProvider<…>() 前缀。
 */
function fastifyOps(a: Analysed, name: string): { registrations: Registration[]; uses: Use[]; registers: Register[] } {
  const registrations: Registration[] = []
  const uses: Use[] = []
  const registers: Register[] = []
  const lead = String.raw`(?<![\w$.])${name.replace(/\$/g, '\\$')}\s*\.\s*(?:withTypeProvider\s*<[^()]{0,200}>\s*\(\s*\)\s*\.\s*)?`
  const hooksOf = (entries: Map<string, Entry>): Arg[] => [...entries]
    .filter(([key, entry]) => FASTIFY_HOOKS.test(key) && entry.value)
    .flatMap(([, entry]) => flatten(a, [entry.value!]))
  for (const m of a.code.matchAll(new RegExp(`${lead}(${METHODS}|route|addHook|register)\\s*${GENERICS}\\(`, 'g'))) {
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    const args = argsOf(a, open, close)
    const call = m[1]!
    if (call === 'addHook') {
      const hook = args[0] ? literalOf(args[0]) : null
      if (hook && FASTIFY_HOOKS.test(hook) && args[1]) uses.push({ prefix: null, args: flatten(a, [args[1]]), at: m.index })
    } else if (call === 'register') {
      if (!args[0]) continue
      registers.push({ target: args[0], options: args[1], at: m.index })
      // @fastify/bearer-auth 注册时默认为所在作用域添加 onRequest 校验钩子，addHook: false 时除外。
      const ident = /^[A-Za-z_$][\w$]*$/.exec(args[0].text)?.[0]
      if (ident && packageOf(a, ident) === '@fastify/bearer-auth' && !/^false$/.test(entriesOf(a, args[1]).get('addHook')?.value?.text ?? '')) {
        uses.push({ prefix: null, args: [args[0]], at: m.index })
      }
    } else if (call === 'route') {
      const entries = entriesOf(a, args[0])
      const url = entries.get('url')?.value ?? entries.get('path')?.value
      const handler = entries.get('handler')
      if (!handler) continue
      registrations.push({ path: url ? pathOf(a, url) : null, middleware: hooksOf(entries), handler: handler.value, handlerRange: handler.range, at: m.index })
    } else {
      if (args.length < 2) continue
      const path = pathOf(a, args[0]!)
      // fastify.get(path, handler)、fastify.get(path, { handler, … })、fastify.get(path, options, handler)。
      const options = entriesOf(a, args[1])
      const objectOnly = args.length === 2 && args[1]!.text.startsWith('{')
      const inOptions = objectOnly ? options.get('handler') : undefined
      if (objectOnly && !inOptions) continue
      registrations.push({
        path, middleware: args.length >= 3 || inOptions ? hooksOf(options) : [],
        handler: inOptions ? inOptions.value : args.at(-1)!, handlerRange: inOptions?.range ?? null, at: m.index,
      })
    }
  }
  registrations.sort((x, y) => x.at - y.at)
  uses.sort((x, y) => x.at - y.at)
  return { registrations, uses, registers }
}

/**
 * use() 的路径是否覆盖路由路径。Express 的 use 路径按前缀匹配；Hono 的 use 与普通路由一样注册，
 * 只有 '/admin/*'、'*' 这类通配才覆盖子路径，app.use('/admin', …) 只作用于 /admin 本身。
 * 来源：https://github.com/honojs/hono/blob/main/src/hono-base.ts （use 以原路径调用 #addRoute）
 */
const pathMatches = (prefix: string | null, path: string | null, framework: NodeFramework): boolean => {
  if (prefix === null) return true
  const wildcard = /\*$/.test(prefix)
  if (framework === 'hono' && !wildcard) return path !== null && path.replace(/\/+$/, '') === prefix.replace(/\/+$/, '')
  const base = prefix.replace(/\/?\*$/, '')
  return base === '' || base === '/' || (path !== null && (path === base || path.startsWith(base.endsWith('/') ? base : `${base}/`)))
}

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

/**
 * 泛型箭头函数 <T extends A, U>(…) => … 的泛型参数列表不是括号对，其中的逗号会让表达式提前结束；
 * 从 < 起跳过到配对的 >（不计 =>），返回其后的位置。不以 < 开头时原样返回。
 */
function skipGenerics(code: string, from: number): number {
  if (code[from] !== '<') return from
  let depth = 0
  for (let i = from; i < Math.min(code.length, from + 2000); i++) {
    if (code[i] === '<') depth++
    else if (code[i] === '>' && code[i - 1] !== '=' && --depth === 0) return i + 1
  }
  return from
}

/** 实参中的函数表达式：有函数体时取函数体，表达式箭头函数取 => 起的整个表达式。 */
function functionAt(a: Analysed, from: number, to: number): CodeRange | null {
  const body = a.bodies.find(b => b.declaration >= from && b.start < to)
  if (body) return { file: a.file, start: body.start, end: body.end }
  const arrow = a.code.indexOf('=>', from)
  return arrow !== -1 && arrow < to ? { file: a.file, start: arrow, end: to, arrow: true } : null
}

/** 函数表达式；async 与参数括号之间可以没有空白：async(req, res) => {}。 */
const FUNCTION_EXPRESSION = /^(?:async\b\s*)?(?:function\b|\([^()]*\)\s*(?::[^=]{0,200})?=>|[A-Za-z_$][\w$]*\s*=>)/

/**
 * 按名称在文件中查找函数：函数声明与变量初始化、exports.name 赋值、对象属性与方法简写（含类方法）。
 * 变量初始化取整个初始化表达式，柯里化与工厂函数（返回中间件的函数）因此也被包含在内。
 */
function findFunction(a: Analysed, name: string, depth = 0): CodeRange | null {
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
    return { file: a.file, start: from, end: expressionEnd(a, skipGenerics(a.code, from)) }
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
    if (/^(?:async\b\s*)?(?:function\b|\(|[A-Za-z_$][\w$]*\s*=>)/.test(a.code.slice(at, at + 40))) {
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

/** 导入说明符对应的项目模块。路径别名以所在包为根，按应用目录解析不到时，从最近的上级目录起逐级尝试。 */
function moduleFor(spec: string, file: ScanFile, files: ScanFile[]): ScanFile | null {
  const direct = bindingModule(spec, file, files, scopeOf(file.path))
  if (direct || spec.startsWith('.')) return direct
  const parts = file.path.split('/').slice(0, -1)
  for (let i = parts.length; i >= 0; i--) {
    const found = bindingModule(spec, file, files, i > 0 ? `${parts.slice(0, i).join('/')}/` : '')
    if (found) return found
  }
  return null
}

interface ImportTarget { file: ScanFile; name: string }

/** 本地名称对应的项目模块及导入名：ES 导入（含命名空间）与 require（含解构）。 */
function importOf(a: Analysed, local: string, files: ScanFile[]): ImportTarget | null {
  const resolve = (spec: string, name: string): ImportTarget | null => {
    const file = moduleFor(spec, a.file, files)
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

/** 本地名称来自的外部包：ES 导入、require 及默认导入；项目内模块和路径别名返回空值。 */
function packageOf(a: Analysed, local: string): string | null {
  const escaped = local.replace(/\$/g, '\\$')
  const es = bindingsOf(a.file).imports.find(binding => binding.local === local)
  const cjs = new RegExp(`\\b(?:const|let|var)\\s+(?:${escaped}|\\{[^{}]*\\b${escaped}\\b[^{}]*\\})\\s*=\\s*require\\s*\\(\\s*['"]([^'"]+)['"]\\s*\\)`).exec(a.source)
  const named = new RegExp(`\\bimport\\s+${escaped}\\s*(?:,[^;]*?)?from\\s*['"]([^'"]+)['"]`).exec(a.source)
  const spec = es?.spec ?? cjs?.[1] ?? named?.[1] ?? null
  return spec && !spec.startsWith('.') && !/^(?:[@~#]|~~|@@|\$lib)\//.test(spec) ? spec : null
}

/** 一个导入目标中按名称找函数；默认导入取默认导出，或在其中按成员名查找（module.exports = { create }）。 */
function importedFunction(target: ImportTarget, member: string | null): CodeRange | null {
  const ta = analyse(target.file)
  if (member) return findFunction(ta, member)
  return target.name === 'default' ? defaultExport(ta) : findFunction(ta, target.name)
}

/**
 * 模块中按名称导出的函数，允许重新导出：export { name } from、export * from、
 * const { name } = require(…) 后再导出，以及 module.exports = { ...require(…) } 之类的展开。
 */
function exportedMember(file: ScanFile, name: string, files: ScanFile[], depth: number): CodeRange | null {
  const t = analyse(file)
  const own = findFunction(t, name)
  if (own || depth >= 3) return own
  const escaped = name.replace(/\$/g, '\\$')
  for (const m of t.source.matchAll(/\bexport\s*\{([^{}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) {
    for (const part of m[1]!.split(',')) {
      const names = new RegExp(`^\\s*(?:type\\s+)?([A-Za-z_$][\\w$]*)\\s*(?:as\\s+${escaped})?\\s*$`).exec(part)
      if (!names || (names[1] !== name && !part.includes(' as '))) continue
      const module = moduleFor(m[2]!, file, files)
      if (module) return exportedMember(module, names[1]!, files, depth + 1)
    }
  }
  const spreads = [
    ...[...t.source.matchAll(/\bexport\s*\*\s*from\s*['"]([^'"]+)['"]/g)].map(m => moduleFor(m[1]!, file, files)),
    ...[...t.source.matchAll(/\.\.\.\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g)].map(m => moduleFor(m[1]!, file, files)),
    ...[...t.code.matchAll(/\.\.\.\s*([A-Za-z_$][\w$]*)\s*[,}]/g)].map(m => importOf(t, m[1]!, files)?.file ?? null),
  ]
  for (const module of spreads) {
    const found = module && module !== file ? exportedMember(module, name, files, depth + 1) : null
    if (found) return found
  }
  const imported = importOf(t, name, files)
  return imported && imported.file !== file
    ? exportedMember(imported.file, imported.name === 'default' ? name : imported.name, files, depth + 1)
    : null
}

/**
 * 调用处的被调函数定义：同文件的函数、导入的函数，或导入模块与对象上的方法（svc.deleteUser()、Workspace.delete()）。
 * 只解析项目内模块，外部包与无法定位的调用返回空值。
 */
export function calleeDefinition(file: ScanFile, name: string, member: string | null, files: ScanFile[]): CodeRange | null {
  const a = analyse(file)
  if (member === null) {
    const local = findFunction(a, name)
    if (local) return local
  }
  const target = importOf(a, name, files)
  if (!target || target.file === file) return null
  if (member === null && target.name === 'default') return defaultExport(analyse(target.file))
  return exportedMember(target.file, member ?? target.name, files, 0)
}

/** 处理函数位置：函数表达式本身，或同文件、其他文件中按名称找到的函数；asyncHandler(fn) 之类先拆开包装。 */
function handlerOf(a: Analysed, arg: Arg, files: ScanFile[], depth = 0): CodeRange | null {
  const text = arg.text
  if (FUNCTION_EXPRESSION.test(text)) return functionAt(a, arg.at, arg.at + text.length)
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

/**
 * Fastify 插件函数：函数表达式、本地或导入的函数、require('./x') / import('./x') 的默认导出，
 * 以及 fastify-plugin 之类包装调用中的函数实参。
 */
function pluginOf(a: Analysed, arg: Arg, files: ScanFile[], depth = 0): CodeRange | null {
  if (depth > 3) return null
  const inline = /^(?:await\s+)?(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)$/.exec(arg.source)
  if (inline) {
    const module = moduleFor(inline[1]!, a.file, files)
    return module ? exportedPlugin(analyse(module), files, depth + 1) : null
  }
  if (FUNCTION_EXPRESSION.test(arg.text)) return functionAt(a, arg.at, arg.at + arg.text.length)
  const call = /^([A-Za-z_$][\w$.]*)\s*\(/.exec(arg.text)
  if (call) {
    const open = arg.at + call[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) return null
    for (const inner of argsOf(a, open, close)) {
      const range = pluginOf(a, inner, files, depth + 1)
      if (range) return range
    }
    return null
  }
  const ident = /^([A-Za-z_$][\w$]*)$/.exec(arg.text)
  if (ident) {
    const local = findFunction(a, ident[1]!)
    if (local) {
      const text = a.code.slice(local.start, local.end).trim()
      // const plugin = fp(async (fastify) => {…})：初始化为包装调用时拆开。
      return /^[A-Za-z_$][\w$.]*\s*\(/.test(text) && !FUNCTION_EXPRESSION.test(text) && a.code.startsWith(text, local.start)
        ? pluginOf(a, { text, source: a.source.slice(local.start, local.start + text.length), at: local.start }, files, depth + 1)
        : local
    }
    const target = importOf(a, ident[1]!, files)
    if (!target) return null
    return target.name === 'default' ? exportedPlugin(analyse(target.file), files, depth + 1) : findFunction(analyse(target.file), target.name)
  }
  return handlerOf(a, arg, files)
}

/** 模块默认导出的插件，允许 export default fp(plugin) 之类的包装。 */
function exportedPlugin(t: Analysed, files: ScanFile[], depth: number): CodeRange | null {
  const m = /\bexport\s+default\s+|(?<![\w$.])module\s*\.\s*exports\s*=(?!=)\s*/.exec(t.code)
  if (!m) return null
  const from = m.index + m[0].length
  const end = expressionEnd(t, from)
  const text = t.code.slice(from, end).trimEnd()
  return pluginOf(t, { text, source: t.source.slice(from, from + text.length), at: from }, files, depth)
}

const toRefs = (a: Analysed, args: Arg[]): MiddlewareRef[] =>
  args.map(arg => ({ text: arg.source, at: arg.at, file: a.file }))

/** 被挂载的 Router 所在文件：require('./routes/x') 或导入的本地名称。 */
function mountedFile(a: Analysed, arg: Arg, files: ScanFile[]): ScanFile | null {
  const inline = /^require\s*\(\s*['"]([^'"]+)['"]\s*\)$/.exec(arg.source)
  if (inline) return moduleFor(inline[1]!, a.file, files)
  const ident = /^([A-Za-z_$][\w$]*)$/.exec(arg.text)
  return ident ? importOf(a, ident[1]!, files)?.file ?? null : null
}

/** 函数定义范围的形参名，供其他规则使用。 */
export function functionParams(range: CodeRange): string[] {
  return paramNamesOf(analyse(range.file), range).filter(Boolean)
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
    const head = /^\s*(?:async\b\s*)?(?:function\b[^(]{0,80})?\(/.exec(code.slice(range.start, range.start + 200))
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
 * 一个实例名及其有效范围：导入框架的文件中为整个文件，作为参数传入或被注册为插件时为接收它的函数。
 * root 是最初创建的实例，挂载它时前缀与中间件也作用于经参数传出的路由；inherited 是传出前已注册的中间件与钩子；
 * prefix 是路由路径前缀（Hono 的 basePath、Fastify 注册时的 prefix）。weak 表示仅凭类型标注识别。
 */
interface Site {
  a: Analysed
  name: string
  framework: NodeFramework
  range: { start: number; end: number } | null
  prefix: string
  root?: Site
  inherited: MiddlewareRef[]
  weak?: boolean
  chainFrom?: number
  openapi?: boolean
}

const within = (site: Site, at: number): boolean => site.range === null || (site.range.start <= at && at <= site.range.end)

interface Ops { registrations: Registration[]; uses: Use[]; registers: Register[] }
const opsCache = new WeakMap<Site, Ops>()

/** 实例范围内的注册、中间件与插件注册调用。 */
function opsOf(site: Site): Ops {
  const cached = opsCache.get(site)
  if (cached) return cached
  const { a, name } = site
  let ops: Ops
  if (site.framework === 'express') ops = { registrations: expressRegistrations(a, name), uses: expressUses(a, name), registers: [] }
  else if (site.framework === 'hono') ops = { ...honoOps(a, name, site.chainFrom, site.openapi), registers: [] }
  else ops = fastifyOps(a, name)
  const result = {
    registrations: ops.registrations.filter(reg => within(site, reg.at)),
    uses: ops.uses.filter(use => within(site, use.at)),
    registers: ops.registers.filter(reg => within(site, reg.at)),
  }
  opsCache.set(site, result)
  return result
}

/** 实例上不限路径、作用于之后注册内容的中间件（Express 的 use() 中排除被挂载的 Router）。 */
function generalMiddleware(site: Site, before: number, files: ScanFile[]): MiddlewareRef[] {
  const args = opsOf(site).uses
    .filter(use => !use.mount && use.at < before && (use.prefix === null ||
      (site.framework !== 'hono' && use.prefix === '/') || /^\/?\*$/.test(use.prefix)))
    .flatMap(use => use.args)
    .filter(arg => site.framework !== 'express' || mountedFile(site.a, arg, files) === null)
  return toRefs(site.a, args)
}

/**
 * 把实例作为实参传出的调用：systemEndpoints(api)、require('./routes')(app)、routes.init(app)。
 * 被调用函数中对应位置的形参在该函数范围内即为实例。
 */
function passedSites(site: Site, files: ScanFile[]): Site[] {
  const { a } = site
  const found: Site[] = []
  const receive = (range: CodeRange | null, index: number, at: number): void => {
    if (!range) return
    const target = analyse(range.file)
    const name = paramNamesOf(target, range)[index]
    if (!name) return
    // 传出前在实例上注册的、不限路径的中间件对传出后的路由同样生效。
    found.push({ a: target, name, framework: site.framework, openapi: Boolean(site.openapi), range: { start: range.start, end: range.end }, prefix: site.prefix,
      root: site.root ?? site, inherited: [...site.inherited, ...generalMiddleware(site, at, files)] })
  }
  for (const m of a.source.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\(/g)) {
    if (!within(site, m.index)) continue
    const open = m.index + m[0].length - 1
    const close = a.pairs.get(open)
    if (close === undefined) continue
    const index = argsOf(a, open, close).findIndex(arg => arg.text === site.name)
    const module = index === -1 ? null : moduleFor(m[1]!, a.file, files)
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

/** 项目内的相对路径规范化：处理 . 与 ..。 */
function normalizePath(path: string): string {
  const parts: string[] = []
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') parts.pop()
    else parts.push(part)
  }
  return parts.join('/')
}

/**
 * Fastify register() 注册的插件：插件函数的第一个形参在其中即为子实例，继承注册前父实例上的钩子，
 * 路由带上 prefix 选项。@fastify/autoload 按目录加载：目录名作为前缀，开启 autoHooks 时同目录的 autohooks 文件中的钩子也生效。
 */
function registeredSites(site: Site, files: ScanFile[]): Site[] {
  const { a } = site
  const found: Site[] = []
  for (const reg of opsOf(site).registers) {
    const options = entriesOf(a, reg.options)
    const prefixArg = options.get('prefix')?.value
    const prefix = joinPath(site.prefix, (prefixArg && pathOf(a, prefixArg)) ?? '')
    const inherited = [...site.inherited, ...generalMiddleware(site, reg.at, files)]
    const child = (range: CodeRange | null, childPrefix: string, hooks: MiddlewareRef[]): void => {
      if (!range) return
      const target = analyse(range.file)
      const name = paramNamesOf(target, range)[0]
      if (name) found.push({ a: target, name, framework: 'fastify', range: { start: range.start, end: range.end }, prefix: childPrefix,
        root: site.root ?? site, inherited: [...inherited, ...hooks] })
    }
    const ident = /^[A-Za-z_$][\w$]*$/.exec(reg.target.text)?.[0]
    if (ident && packageOf(a, ident) === '@fastify/autoload') {
      const dirValue = options.get('dir')?.value
      if (!dirValue) continue
      const parts = [...dirValue.source.matchAll(/['"`]([^'"`$]+)['"`]/g)].map(m => m[1]!)
      if (parts.length === 0) continue
      const here = a.file.path.includes('/') ? a.file.path.slice(0, a.file.path.lastIndexOf('/')) : ''
      const dir = normalizePath(`${here}/${parts.join('/')}`)
      const optionPrefix = entriesOf(a, options.get('options')?.value ?? undefined).get('prefix')?.value
      const base = joinPath(prefix, (optionPrefix && pathOf(a, optionPrefix)) ?? '')
      const autoHooks = /^true$/.test(options.get('autoHooks')?.value?.text ?? '')
      const plugins = files.filter(f => f.path.startsWith(`${dir}/`) && /\.[mc]?[jt]s$/.test(f.path) && !/\.d\.[mc]?ts$|\.(?:test|spec)\.[mc]?[jt]s$/.test(f.path))
      // autohooks 文件中的钩子作用于所在目录及其子目录。
      const hooksByDir = new Map<string, MiddlewareRef[]>()
      if (autoHooks) {
        for (const file of plugins.filter(f => /(?:^|\/)autohooks\.[mc]?[jt]s$/.test(f.path))) {
          const range = exportedPlugin(analyse(file), files, 0)
          const name = range ? paramNamesOf(analyse(file), range)[0] : undefined
          if (!range || !name) continue
          const hookSite: Site = { a: analyse(file), name, framework: 'fastify', range: { start: range.start, end: range.end }, prefix: '', inherited: [] }
          hooksByDir.set(file.path.slice(0, file.path.lastIndexOf('/')), generalMiddleware(hookSite, Infinity, files))
        }
      }
      for (const file of plugins) {
        if (/(?:^|\/)autohooks\.[mc]?[jt]s$/.test(file.path)) continue
        const relative = file.path.slice(dir.length + 1)
        const folders = relative.split('/').slice(0, -1)
        const hooks = [...hooksByDir].filter(([folder]) => file.path.startsWith(`${folder}/`)).flatMap(([, refs]) => refs)
        child(exportedPlugin(analyse(file), files, 0), joinPath(base, folders.length ? `/${folders.join('/')}` : '/'), hooks)
      }
      continue
    }
    child(pluginOf(a, reg.target, files), prefix, [])
  }
  return found
}

interface ServerIndex { byHandlerFile: Map<ScanFile, Route[]> }
const indexCache = new WeakMap<ScanFile[], ServerIndex>()

/** 全部文件的 Node 框架路由，按处理函数所在文件分组；每次扫描只建立一次。 */
function serverIndex(files: ScanFile[]): ServerIndex {
  const cached = indexCache.get(files)
  if (cached) return cached
  // 实例：导入框架的文件中直接创建的，以及经参数传入其他函数、经 register() 注册的（最多四层）。
  const sites: Site[] = []
  const seen = new Set<string>()
  const add = (site: Site): boolean => {
    const key = `${site.a.file.path}\0${site.name}\0${site.range?.start ?? -1}\0${site.prefix}\0${Boolean(site.openapi)}`
    if (seen.has(key)) return false
    seen.add(key)
    sites.push(site)
    return true
  }
  for (const file of files) {
    if (!/\.[mc]?[jt]sx?$/.test(file.path) || !/\b(?:express|hono|fastify)\b/.test(file.content)) continue
    const a = analyse(file)
    const names = frameworkNamesOf(a)
    if (!names) continue
    for (const instance of instancesOf(a, names)) {
      add({ a, name: instance.name, framework: instance.framework, openapi: Boolean(instance.openapi), range: null, prefix: instance.prefix, inherited: [],
        weak: instance.weak, ...(instance.chainFrom === undefined ? {} : { chainFrom: instance.chainFrom }) })
    }
  }
  let frontier = [...sites]
  for (let level = 0; level < 4 && frontier.length; level++) {
    const next: Site[] = []
    for (const site of frontier) {
      const children = [...passedSites(site, files), ...(site.framework === 'fastify' ? registeredSites(site, files) : [])]
      for (const child of children) if (add(child)) next.push(child)
    }
    frontier = next
  }
  // 仅凭类型标注识别的实例，在有更具体来源（参数传入、插件注册）覆盖同一位置时让位，避免丢失前缀与继承的中间件。
  const shadowed = (site: Site, at: number): boolean => Boolean(site.weak) && sites.some(other =>
    other !== site && !other.weak && other.a === site.a && other.name === site.name && other.range !== null && within(other, at))

  const byRouterFile = new Map<ScanFile, Route[]>()
  const byRoot = new Map<Site, Route[]>()
  for (const site of sites) {
    const { a } = site
    const { registrations, uses } = opsOf(site)
    const routes = byRouterFile.get(a.file) ?? []
    for (const reg of registrations) {
      if (shadowed(site, reg.at)) continue
      const handler = reg.handlerRange ?? (reg.handler ? handlerOf(a, reg.handler, files) : null)
      if (!handler) continue
      const before = uses.filter(use => !use.mount && use.at < reg.at && pathMatches(use.prefix, reg.path, site.framework))
        .flatMap(use => use.args.filter(arg => site.framework !== 'express' || mountedFile(a, arg, files) === null))
      const url = reg.path === null ? '(dynamic path)' : joinPath(site.prefix, reg.path)
      const callbacks = flatten(a, reg.middleware)
      const root = site.root ?? site
      const add = (range: CodeRange, middleware: Arg[]): void => {
        const route: Route = {
          file: range.file, framework: site.framework, url,
          scope: scopeOf(range.file.path), reachable: { start: range.start, end: range.end },
          middleware: [...site.inherited, ...toRefs(a, before), ...toRefs(a, middleware)],
          mounts: [],
        }
        routes.push(route)
        byRoot.set(root, [...(byRoot.get(root) ?? []), route])
      }
      add(handler, callbacks)
      // 前置回调同样处理请求，包含具名及跨文件处理函数。
      // 它们各自作为入口检查，只受排在其前面的中间件保护。
      callbacks.forEach((callback, index) => {
        const range = handlerOf(a, callback, files)
        if (range) add(range, callbacks.slice(0, index))
      })
    }
    if (routes.length) byRouterFile.set(a.file, routes)
  }
  // 同一文件中的本地实例被挂载：app.use('/api', api)、app.route('/api', api)，其路由包括经参数传出后注册的。
  const localRoutes = (a: Analysed, arg: Arg): Route[] | undefined => {
    const root = sites.find(other => other.a === a && other.range === null && other.name === arg.text && !other.root)
    return root ? byRoot.get(root) : undefined
  }
  // 挂载：app.use('/admin', requireAuth, adminRouter)、app.route('/admin', admin)；同一实例上更早的中间件同样生效。
  for (const site of sites) {
    if (site.framework === 'fastify') continue
    const { a } = site
    const uses = opsOf(site).uses
    for (const use of uses) {
      if (site.framework === 'hono' && !use.mount) continue
      use.args.forEach((arg, index) => {
        const target = mountedFile(a, arg, files)
        const routes = target && target !== a.file ? byRouterFile.get(target) : localRoutes(a, arg)
        if (!routes || routes.length === 0) return
        const isMiddleware = (x: Arg): boolean => mountedFile(a, x, files) === null && localRoutes(a, x) === undefined
        // Hono 子应用的路由都在挂载前缀之下，只有通配路径的中间件能覆盖全部。
        const covers = (other: Use): boolean => site.framework === 'hono'
          ? other.prefix === null || (/\*$/.test(other.prefix) && pathMatches(other.prefix, use.prefix, 'hono'))
          : pathMatches(other.prefix, use.prefix, site.framework)
        const earlier = uses.filter(other => !other.mount && other.at < use.at && covers(other))
          .flatMap(other => site.framework === 'hono' ? other.args : other.args.filter(isMiddleware))
        const middleware = [...site.inherited, ...toRefs(a, earlier), ...toRefs(a, use.args.slice(0, index).filter(isMiddleware))]
        const prefix = joinPath(site.prefix, use.prefix ?? '/')
        for (const route of routes) {
          route.mounts!.push(middleware)
          if (prefix !== '/' && route.mounts!.length === 1 && route.url.startsWith('/')) route.url = joinPath(prefix, route.url)
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

/** 处理函数位于该文件中的 Express、Hono、Fastify 路由。 */
export function nodeRoutesFor(file: ScanFile, files: ScanFile[]): Route[] {
  return serverIndex(files).byHandlerFile.get(file) ?? []
}

/** 文件中可被直接请求的服务端入口：按文件约定的路由、Server Function，或处理函数位于此处的 Node 框架路由。 */
export function serverRoutesOf(file: ScanFile, files: ScanFile[]): Route[] {
  const route = routeOf(file)
  if (route) return [route]
  const actions = serverActionRoutes(file)
  return actions.length ? actions : nodeRoutesFor(file, files)
}

/** 装饰器须来自同文件、同实例和同函数作用域；无法解析的跨文件来源不提供保护证明。 */
function decoratorOf(ref: MiddlewareRef, receiver: string, name: string, files: ScanFile[]): CodeRange | null {
  const a = analyse(ref.file)
  const owner = (at: number) => a.bodies.filter(b => b.start < at && at < b.end).sort((x, y) => y.start - x.start)[0]
  const pattern = new RegExp(`(?<![\\w$.])${receiver.replace(/\$/g, '\\$')}\\s*\\.\\s*decorate\\s*\\(\\s*['"]${name.replace(/\$/g, '\\$')}['"]\\s*,`, 'g')
  let result: CodeRange | null = null
  for (const m of a.source.matchAll(pattern)) {
    if (m.index >= ref.at || owner(m.index) !== owner(ref.at)) continue
    const open = a.source.indexOf('(', m.index)
    const close = a.pairs.get(open)
    const value = close === undefined ? undefined : argsOf(a, open, close)[1]
    result = value ? handlerOf(a, value, files) : null
  }
  return result
}

/** 同一文件、同一实例的插件注册只解析一次。 */
const authPluginCache = new WeakMap<ScanFile, Map<string, Register[]>>()

/** 只接受当前实例在引用前注册的插件，不能借用其他应用的导入。 */
export function registeredAuthPlugin(ref: MiddlewareRef, pkg: string): boolean {
  const a = analyse(ref.file)
  const receiver = /^([A-Za-z_$][\w$]*)\s*\./.exec(ref.text)?.[1]
  if (!receiver) return false
  let cache = authPluginCache.get(ref.file)
  if (!cache) { cache = new Map(); authPluginCache.set(ref.file, cache) }
  let registers = cache.get(receiver)
  if (!registers) { registers = fastifyOps(a, receiver).registers; cache.set(receiver, registers) }
  const owner = (at: number) => a.bodies.filter(b => b.start < at && at < b.end).sort((x, y) => y.start - x.start)[0]
  return registers.some(reg => reg.at < ref.at && owner(reg.at) === owner(ref.at) &&
    /^[A-Za-z_$][\w$]*$/.test(reg.target.text) && packageOf(a, reg.target.text) === pkg)
}

/** @fastify/auth 的组合：fastify.auth([a, b], { relation: 'and' })；默认任一通过即放行。 */
export function authCompositionOf(ref: MiddlewareRef): { refs: MiddlewareRef[]; relation: 'and' | 'or' } | null {
  const a = analyse(ref.file)
  const m = /^[A-Za-z_$][\w$]*\s*\.\s*auth\s*\(/.exec(ref.text)
  if (!m) return null
  const open = ref.at + m[0].length - 1
  const close = a.pairs.get(open)
  if (close === undefined) return null
  const args = argsOf(a, open, close)
  if (!args[0]?.text.startsWith('[')) return null
  const relation = entriesOf(a, args[1]).get('relation')?.value
  return { refs: toRefs(a, flatten(a, [args[0]])), relation: relation && literalOf(relation) === 'and' ? 'and' : 'or' }
}

/**
 * 中间件引用的解析结果，供鉴权规则判断：名称、定义位置、来自的外部包，
 * 以及内联函数（含 createMiddleware(async (c, next) => …) 之类包装中的函数实参）。
 */
export function middlewareDefinition(ref: MiddlewareRef, files: ScanFile[]): {
  name: string; range: CodeRange | null; spec: string | null; inline: CodeRange | null
} {
  const a = analyse(ref.file)
  const text = a.code.slice(ref.at, ref.at + ref.text.length)
  let inline: CodeRange | null = null
  if (FUNCTION_EXPRESSION.test(text)) {
    inline = functionAt(a, ref.at, ref.at + text.length)
    return { name: 'an inline middleware', range: null, spec: null, inline }
  }
  const call = /^[A-Za-z_$][\w$.]*\s*\(/.exec(text)
  if (call) {
    const open = ref.at + call[0].length - 1
    const close = a.pairs.get(open)
    const last = close === undefined ? undefined : argsOf(a, open, close).at(-1)
    if (last && FUNCTION_EXPRESSION.test(last.text)) inline = functionAt(a, last.at, last.at + last.text.length)
  }
  const root = /^([A-Za-z_$][\w$]*)/.exec(ref.text)?.[1] ?? ''
  const member = /^[A-Za-z_$][\w$]*\s*\.\s*([A-Za-z_$][\w$]*)/.exec(ref.text)?.[1] ?? null
  const callee = member ?? root
  const spec = packageOf(a, root)
  // Fastify 实例上的装饰器：fastify.authenticate；实例可能就是 require('fastify')() 的结果。
  if (member && (spec === null || spec === 'fastify')) {
    const decorated = decoratorOf(ref, root, member, files)
    if (decorated) return { name: callee, range: decorated, spec: null, inline }
  }
  // 外部包：返回包名，由调用方按已知鉴权库判断。
  if (spec) return { name: callee, range: null, spec, inline }
  const local = member === null ? findFunction(a, root) : null
  if (local) return { name: callee, range: local, spec: null, inline }
  const target = importOf(a, root, files)
  const range = target ? importedFunction(target, member) ?? (member ? propertyValue(analyse(target.file), member) : null) : null
  return { name: callee, range, spec: null, inline }
}

/** 对象属性的值为调用表达式时的范围：const auth = { required: jwt({ … }) } 中的 jwt({ … })。 */
function propertyValue(a: Analysed, name: string): CodeRange | null {
  const m = new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}\\s*:\\s*(?=[A-Za-z_$][\\w$.]*\\s*\\()`).exec(a.code)
  if (!m) return null
  const from = m.index + m[0].length
  return { file: a.file, start: from, end: expressionEnd(a, from) - 1 }
}
