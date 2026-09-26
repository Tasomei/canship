/** 检查未认证请求可触达的数据操作；结合函数内控制流、客户端类型和中间件判断。 */

import { posix } from 'node:path'
import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { isSupabaseServiceRole } from './framework.js'
import { redactSecret } from '../redact.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { JWT_SOURCE, SB_SECRET_SOURCE } from './patterns.js'

// 识别各框架可被直接请求的服务端路由。

/** Next.js App Router 处理函数及 Pages Router API 文件；Astro 的 src/pages/api 端点在 routeOf 中按导出区分。 */
const APP_ROUTER = /(?:^|\/)app\/api\/(?:.+\/)?route\.[mc]?[jt]sx?$/
const PAGES_ROUTER = /(?:^|\/)pages\/api\/.+\.[mc]?[jt]sx?$/

/**
 * app 目录下任意位置的 route 文件都是处理函数，不限于 api。Remix 的文件夹路由同样叫 route，
 * 因此 api 之外的须按 HTTP 方法导出，且不导出 loader 或 action。
 */
const APP_ROUTE_FILE = /(?:^|\/)app\/(?:.+\/)?route\.[mc]?[jt]sx?$/
const NEXT_METHODS = 'GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS'
const NEXT_METHOD_EXPORT = new RegExp(
  String.raw`\bexport\s+(?:async\s+)?function\s+(?:${NEXT_METHODS})\b|\bexport\s+const\s+(?:${NEXT_METHODS})\b|` +
  // export { handler as GET } 与 Auth.js 的 export const { GET, POST } = handlers；长度有界以免回溯。
  String.raw`\bexport\s+(?:const\s*)?\{[^{}]{0,500}\b(?:${NEXT_METHODS})\b`,
)

/** SvelteKit 端点只能是 +server 文件，文件名本身即可确认框架。 */
const SVELTEKIT_ENDPOINT = /^(.*?\/)?src\/routes\/(?:(.*)\/)?\+server\.[mc]?[jt]s$/

/**
 * SvelteKit 表单 actions 通过 POST 直接调用，与端点同样可被任何人请求。
 * 只检查 actions 对象内的操作；load 为页面读取数据，公开页面读取数据属于正常设计。
 */
const SVELTEKIT_PAGE_SERVER = /^(.*?\/)?src\/routes\/(?:(.*)\/)?\+page\.server\.[mc]?[jt]s$/
const SVELTEKIT_ACTIONS = /\bexport\s+const\s+actions\b\s*(?::[^=;{}]{0,200})?=\s*\{/

/** Nuxt/Nitro 服务端路由。目录名在其他项目中也常见（如 tRPC 的 server/api/routers），须同时出现 h3 处理函数。 */
const NUXT_ROUTE = /^(.*?\/)?server\/(api|routes)\/(.+)\.[mc]?[jt]s$/
const H3_HANDLER = /\b(?:defineEventHandler|eventHandler|defineCachedEventHandler|defineLazyEventHandler)\s*\(/
const NUXT_METHOD_SUFFIX = /\.(?:get|post|put|patch|delete|head|options|connect|trace)$/i

/** Remix 与 React Router 路由模块；只有导出 loader 或 action 的模块可被直接请求。 */
const REMIX_ROUTE = /^(.*?\/)?app\/routes\/(.+)\.[mc]?[jt]sx?$/
const REMIX_EXPORT = /\bexport\s+(?:async\s+)?function\s+(?:loader|action)\b|\bexport\s+const\s+(?:loader|action)\b/

/** Astro 页面目录中导出 HTTP 方法的脚本文件即端点。 */
const ASTRO_ENDPOINT = /^(.*?\/)?src\/pages\/(.+)\.[mc]?[jt]s$/
const ASTRO_EXPORT =
  /\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE|ALL)\b|\bexport\s+const\s+(?:GET|POST|PUT|PATCH|DELETE|ALL)\b/

type Framework = 'next' | 'astro' | 'sveltekit' | 'nuxt' | 'remix'

/** 按 HTTP 方法导出且没有默认导出的脚本是 Astro 端点。 */
function isAstroEndpoint(file: ScanFile): boolean {
  const code = noiseMaskedOf(file)
  return ASTRO_EXPORT.test(code) && !/\bexport\s+default\b/.test(code)
}

/** 一个可被直接请求的服务端路由。 */
interface Route {
  file: ScanFile
  framework: Framework
  url: string
  /** 所属应用根目录（含末尾斜杠），用于别名解析及查找全局鉴权文件。 */
  scope: string
  /** 仅此范围内的操作可被请求触发，如 SvelteKit 的 actions 对象；未设置时为整个文件。 */
  reachable?: { start: number; end: number }
  /** Next.js Server Function 的函数名；没有独立 URL，中间件不能证明其受保护。 */
  action?: string
}

/**
 * Next.js Server Functions（Server Actions）可被直接 POST 调用，官方要求在每个函数内部鉴权。
 * 文件顶部的 'use server' 使全部导出函数成为 Server Function；函数体首行的 'use server' 只标记该函数。
 * 只检查导出函数和内联标记的函数，未导出的辅助函数由调用方负责鉴权，不单独报告。
 */
function serverActionRoutes(file: ScanFile): Route[] {
  if (!/use server/.test(file.content) || !/\.[mc]?[jt]sx?$/.test(file.path)) return []
  const code = noiseMaskedOf(file)
  const source = commentsMaskedOf(file)
  const fileLevel = startsWithDirective(source, 0, 'use server')
  const pairs = delimiterPairs(code)
  // 右括号到左括号的反向索引，供箭头函数向前跳过参数列表。
  const openers = new Map<number, number>()
  for (const [open, close] of pairs) openers.set(close, open)
  const exportedList = new Set<string>()
  for (const m of code.matchAll(/\bexport\s*\{([^{}]{0,1000})\}/g)) {
    for (const part of m[1]!.split(',')) {
      const name = /^\s*([A-Za-z_$][\w$]*)/.exec(part)?.[1]
      if (name) exportedList.add(name)
    }
  }
  const scope = /^(.*?\/)?(?:src|app|lib|actions|server|utils)\//.exec(file.path)?.[1] ?? ''
  const routes: Route[] = []
  for (const body of functionBodies(code, pairs)) {
    const inline = startsWithDirective(source, body.start + 1, 'use server')
    const declared = declarationOf(code, body, openers)
    const exported = fileLevel && declared !== null && (declared.exported || exportedList.has(declared.name))
    if (!inline && !exported) continue
    const name = declared?.name ?? 'anonymous'
    routes.push({
      file, framework: 'next', url: `the server action ${name}`, scope,
      reachable: { start: body.start, end: body.end }, action: name,
    })
  }
  return routes
}

/** 读取指令序列，拒绝字符串拼接、调用和属性访问等普通表达式。 */
function startsWithDirective(source: string, from: number, directive: string): boolean {
  let i = from
  while (i < source.length) {
    while (i < source.length && /\s/.test(source[i]!)) i++
    const quote = source[i++]
    if (quote !== "'" && quote !== '"') return false
    const start = i
    while (i < source.length && source[i] !== quote && !/[\r\n]/.test(source[i]!)) {
      if (source[i] === '\\') i++
      i++
    }
    if (source[i] !== quote) return false
    const value = source.slice(start, i++)
    let newline = false
    while (i < source.length && /\s/.test(source[i]!)) {
      if (/[\r\n]/.test(source[i]!)) newline = true
      i++
    }
    const next = source[i]
    const terminated = next === ';' || next === '}' || next === undefined ||
      (newline && !/[([.`+\-*/%?:,<>=!&|^]/.test(next))
    if (!terminated) return false
    if (value === directive) return true
    if (next === ';') i++
  }
  return false
}

/** 函数声明的名称及是否直接导出；无法识别时为空。 */
function declarationOf(
  code: string,
  body: FunctionBody,
  openers: Map<number, number>,
): { name: string; exported: boolean } | null {
  if (/^function\s*\(/.test(code.slice(body.declaration, body.declaration + 40)) &&
      /\bexport\s+default\s+(?:async\s+)?$/.test(code.slice(Math.max(0, body.declaration - 80), body.declaration))) {
    return { name: 'default', exported: true }
  }
  const named = /^function\s*\*?\s*([A-Za-z_$][\w$]*)/.exec(code.slice(body.declaration, body.declaration + 200))
  if (named) {
    const before = code.slice(Math.max(0, body.declaration - 40), body.declaration)
    return { name: named[1]!, exported: /\bexport\s+(?:default\s+)?(?:async\s+)?$/.test(before) }
  }
  // 箭头函数：从 => 向前逐段读取，参数列表借助括号配对一步跳过，每个函数只读有限长度。
  let i = body.declaration - 1
  const skipSpace = (): void => { while (i >= 0 && /\s/.test(code[i]!)) i-- }
  const readWord = (): string => {
    const end = i + 1
    while (i >= 0 && /[\w$]/.test(code[i]!)) i--
    return code.slice(i + 1, end)
  }
  // 可选的返回类型标注，如 ): Promise<void> =>。
  const window = code.slice(Math.max(0, body.declaration - 200), body.declaration)
  const close = window.lastIndexOf(')')
  if (close !== -1 && /^\s*(?::[^=;{()]*)?$/.test(window.slice(close + 1))) {
    const open = openers.get(body.declaration - window.length + close)
    if (open === undefined) return null
    i = open - 1
  } else {
    skipSpace()
    if (readWord() === '') return null
  }
  skipSpace()
  const maybeAsync = i
  if (readWord() !== 'async') i = maybeAsync
  skipSpace()
  if (code[i] !== '=' || code[i - 1] === '=' || code[i - 1] === '!') return null
  i--
  skipSpace()
  let name = readWord()
  skipSpace()
  // 变量类型标注，如 const createPost: Action = ...。
  if (code[i] === ':') {
    i--
    skipSpace()
    name = readWord()
    skipSpace()
  }
  if (name === '' || !/^(?:const|let|var)$/.test(readWord())) return null
  skipSpace()
  return { name, exported: readWord() === 'export' }
}

/** 登录、注册等入口本身面向未登录用户，与认证路由同样豁免。 */
const AUTH_ACTION_NAMES =
  /^(?:sign[_-]?(?:in|up|out)|log[_-]?(?:in|out)|register|reset[_-]?password|forgot[_-]?password|verify(?:[_-]?(?:email|otp))?|confirm(?:[_-]?email)?|send[_-]?magic[_-]?link)(?:action)?$/i

/** 路由组仅用于组织目录，不构成 URL 路径。 */
function routePathOf(path: string): string {
  return path.replace(/(^|\/)\([^/]+\)(?=\/)/g, '$1').replace(/\/{2,}/g, '/')
}

/** 按框架约定识别路由；不属于任何框架时返回空值。 */
function routeOf(file: ScanFile): Route | null {
  const path = routePathOf(file.path)
  // src/pages/api 同时符合 Next.js Pages Router 与 Astro 的约定：Next.js 默认导出处理函数，Astro 按 HTTP 方法导出。
  if (PAGES_ROUTER.test(file.path) && ASTRO_ENDPOINT.test(path) && isAstroEndpoint(file)) {
    const astro = ASTRO_ENDPOINT.exec(path)!
    return { file, framework: 'astro', url: `/${astro[2]!.replace(/(?:^|\/)index$/, '')}`, scope: astro[1] ?? '' }
  }
  if (PAGES_ROUTER.test(file.path)) {
    const scope = /^(.*?)(?:src\/)?pages\/api\//.exec(path)?.[1] ?? ''
    return { file, framework: 'next', url: nextRouteUrl(path), scope }
  }
  if (APP_ROUTE_FILE.test(path)) {
    const app = nextAppRoute(path)
    const code = noiseMaskedOf(file)
    const handler = APP_ROUTER.test(path) || (NEXT_METHOD_EXPORT.test(code) && !REMIX_EXPORT.test(code))
    if (app && handler) return app.url === null ? null : { file, framework: 'next', url: app.url, scope: app.scope }
  }

  const svelte = SVELTEKIT_ENDPOINT.exec(path)
  if (svelte) return { file, framework: 'sveltekit', url: `/${svelte[2] ?? ''}`, scope: svelte[1] ?? '' }

  const page = SVELTEKIT_PAGE_SERVER.exec(path)
  if (page) {
    const code = noiseMaskedOf(file)
    const actions = SVELTEKIT_ACTIONS.exec(code)
    if (!actions) return null
    const open = actions.index + actions[0].length - 1
    const close = closingDelimiter(code, open, '{', '}')
    return {
      file, framework: 'sveltekit', url: `/${page[2] ?? ''}`, scope: page[1] ?? '',
      reachable: { start: open, end: close ?? code.length },
    }
  }

  const nuxt = NUXT_ROUTE.exec(path)
  if (nuxt && H3_HANDLER.test(noiseMaskedOf(file))) {
    const rest = nuxt[3]!.replace(NUXT_METHOD_SUFFIX, '').replace(/(?:^|\/)index$/, '')
    const url = nuxt[2] === 'api' ? `/api/${rest}` : `/${rest}`
    return { file, framework: 'nuxt', url: url.replace(/\/$/, '') || '/', scope: nuxt[1] ?? '' }
  }

  const remix = REMIX_ROUTE.exec(path)
  if (remix && REMIX_EXPORT.test(noiseMaskedOf(file))) {
    return { file, framework: 'remix', url: remixRouteUrl(remix[2]!), scope: remix[1] ?? '' }
  }

  const astro = ASTRO_ENDPOINT.exec(path)
  if (astro && isAstroEndpoint(file)) {
    const rest = astro[2]!.replace(/(?:^|\/)index$/, '')
    return { file, framework: 'astro', url: `/${rest}`, scope: astro[1] ?? '' }
  }
  return null
}

/**
 * 定位 Next.js 的 app 目录并换算 URL。优先 src/app，否则取第一个 app 目录，
 * 以免 packages/app/src/app 这类布局把外层目录当作应用目录。
 * 下划线开头的私有文件夹及其子目录不参与路由，此时 url 为空；%5F 开头的段表示字面下划线。
 */
function nextAppRoute(path: string): { scope: string; url: string | null } | null {
  const m = /^(.*?\/)?src\/app\/(.+)$/.exec(path) ?? /^(.*?\/)?app\/(.+)$/.exec(path)
  if (!m) return null
  const segments = m[2]!.split('/').slice(0, -1)
  const url = segments.some((segment) => segment.startsWith('_'))
    ? null
    : `/${segments.map((segment) => segment.replace(/^%5F/i, '_')).join('/')}`
  return { scope: m[1] ?? '', url }
}

/** Pages Router 文件路径转换为请求 URL。 */
function nextRouteUrl(path: string): string {
  const m = /(?:^|\/)pages\/(api\/.*)$/.exec(path)
  if (!m) return `/${path}`
  const url = m[1]!
    .replace(/\/route\.[mc]?[jt]sx?$/, '')
    .replace(/\/index\.[mc]?[jt]sx?$/, '')
    .replace(/\.[mc]?[jt]sx?$/, '')
  return `/${url}`
}

/**
 * Remix 扁平路由文件名转换为 URL：点号分隔层级，下划线开头的段不进入 URL（_index、_auth），
 * 段尾下划线仅用于脱离父布局，[.] 表示字面量点号。同时兼容文件夹路由（route.tsx）及 v1 目录写法。
 */
function remixRouteUrl(name: string): string {
  const LITERAL_DOT = '\u0000'
  const segments = name
    .replace(/\/route$/, '')
    .replace(/\[\.\]/g, LITERAL_DOT)
    .split(/[./]/)
    .filter(segment => segment !== '' && !segment.startsWith('_'))
    .map(segment => segment.replace(/_$/, '').replace(/[[\]]/g, '').split(LITERAL_DOT).join('.'))
  if (segments[segments.length - 1] === 'index') segments.pop()
  return `/${segments.join('/')}`
}

/** 仅豁免明确的登录及身份管理入口，不豁免整个命名空间；非 Next.js 框架的认证路由常不在 /api 下。 */
const AUTH_ENDPOINT_NAMES =
  /^(?:\/api)?\/auth\/(?:sign[-_]?in|sign[-_]?up|sign[-_]?out|log[-_]?in|log[-_]?out|register|session|verify|confirm|reset(?:[-_]password)?|forgot(?:[-_]password)?|magic[-_]?link|otp)$/

/** OAuth 回调允许一层提供方路径。 */
const AUTH_CALLBACK = /^(?:\/api)?\/auth\/callback(?:\/[^/]+)?$/

/** 提供方在前的回调，如 /login/github/callback。 */
const PROVIDER_CALLBACK = /^(?:\/api)?\/(?:auth|oauth|login|sign-?in)\/[^/]+\/callback$/

/** nuxt-auth-utils 的 OAuth 处理函数本身就是登录入口。 */
const OAUTH_HANDLER = /\bdefineOAuth\w*EventHandler\s*\(/

function isAuthEndpoint(route: Route): boolean {
  if (route.action !== undefined) return AUTH_ACTION_NAMES.test(route.action)
  // 不按任意捕获路径豁免，仅识别明确的认证处理方式。
  return AUTH_ENDPOINT_NAMES.test(route.url) || AUTH_CALLBACK.test(route.url) ||
    PROVIDER_CALLBACK.test(route.url) || OAUTH_HANDLER.test(noiseMaskedOf(route.file))
}

// 识别鉴权证据。

/** 已知会拒绝无效调用者的验证函数及包装器；require 系列含 requireUserId、requireUserSession 等变体。 */
const AUTH_ENFORCING_CALL =
  /\b(?:NextAuth|require(?:Auth|User|Session|Admin)\w*|withAuth|verifyAuth|ensureAuth|assertAuth(?:enticated)?|verifyIdToken|constructEvent)\s*\(/i

/** 鉴权条件必须涉及身份、凭据或验证调用。 */
const AUTH_CONDITION =
  /\b(?:session|token|user|userid|user_id|authorization|bearer|jwt|auth|signature|CRON_SECRET|WEBHOOK_SECRET|REVALIDATE_SECRET|ADMIN_SECRET)\b|\blocals\s*\.\s*user\b|\b(?:getUser|getSession|getServerSession|currentUser|getAuth|isAuthenticated|checkAuth|verifyAuth|ensureAuth|verifyIdToken|timingSafeEqual)\s*\(/i

/** 属性访问链，允许可选链，如 session?.user。 */
const ACCESS_CHAIN = String.raw`[\w$]+(?:\??\.[\w$]+)*`
/** 否定身份判断：!session?.user、user === null、token !== expected。 */
const NEGATED_IDENTITY = new RegExp(`^!\\s*${ACCESS_CHAIN}(?:\\s*\\([^=]*\\))?$`)
const IDENTITY_IS_EMPTY = new RegExp(`^${ACCESS_CHAIN}\\s*={2,3}\\s*(?:null|undefined|false)$`)
const IDENTITY_MISMATCH =
  new RegExp(`^${ACCESS_CHAIN}\\s*!={1,2}\\s*(?!(?:null|undefined|false)\\b)${ACCESS_CHAIN}$`)

/** 终止请求的语句；SvelteKit 2 的 error(401) 无需 throw 即会中止。 */
const STOPS_REQUEST = /^(?:(?:return|throw|redirect|notFound)\b|error\s*\(\s*40[13]\b)/

/** 明确返回 401/403：Response 状态、SvelteKit error() 及 Nuxt createError 的 statusCode。 */
const DENIED_STATUS =
  /\b(?:return|throw)\b[\s\S]{0,300}\bstatus(?:Code)?\s*[:(=]\s*(?:401|403)\b|\berror\s*\(\s*40[13]\b/i

/** 在已屏蔽文本中匹配分隔符。 */
function closingDelimiter(source: string, start: number, open: string, close: string): number | null {
  let depth = 0
  for (let i = start; i < source.length; i++) {
    const ch = source[i]
    if (ch === open) depth++
    else if (ch === close) {
      depth--
      if (depth === 0) return i
    }
  }
  return null
}

/** 提取条件控制的语句，避免借用后续退出语句。 */
function controlledStatement(source: string, afterCondition: number): string {
  let start = afterCondition
  while (/\s/.test(source[start] ?? '')) start++
  if (source[start] === '{') {
    const end = closingDelimiter(source, start, '{', '}')
    return source.slice(start, end === null ? Math.min(source.length, start + 600) : end + 1)
  }
  const semicolon = source.indexOf(';', start)
  const end = semicolon === -1 ? Math.min(source.length, start + 400) : Math.min(semicolon + 1, start + 400)
  return source.slice(start, end)
}

/** 条件中的单项是否在身份缺失时成立，如 !session?.user。 */
function rejectsMissingIdentity(term: string, returnsDeniedStatus: boolean): boolean {
  const rejects = NEGATED_IDENTITY.test(term) || IDENTITY_IS_EMPTY.test(term) || IDENTITY_MISMATCH.test(term)
  return rejects && (AUTH_CONDITION.test(term) || returnsDeniedStatus)
}

/** 只有拒绝未认证请求的条件分支才能提供保护。 */
function hasConditionalAuthGuard(code: string): boolean {
  const starts = /\bif\s*\(/g
  let match: RegExpExecArray | null
  while ((match = starts.exec(code)) !== null) {
    const open = code.indexOf('(', match.index)
    const close = closingDelimiter(code, open, '(', ')')
    if (close === null) continue

    const condition = code.slice(open + 1, close)
    const statement = controlledStatement(code, close + 1)
    // 只认可分支顶层的退出；嵌套条件中的退出不覆盖整个分支。
    const body = statement.startsWith('{') ? statement.slice(1, -1) : statement
    const pairs = delimiterPairs(body)
    let stopsRequest = false
    for (let i = 0; i < body.length; i++) {
      if (STOPS_REQUEST.test(body.slice(i, i + 16)) &&
          (i === 0 || !/[\w$]/.test(body[i - 1]!))) {
        stopsRequest = true
        break
      }
      if (/^if\s*\(/.test(body.slice(i, i + 16))) break
      const end = pairs.get(i)
      if (end !== undefined) i = end
    }
    let statementStart = close + 1
    while (/\s/.test(code[statementStart] ?? '')) statementStart++
    starts.lastIndex = statementStart + statement.length
    if (!stopsRequest) continue

    const returnsDeniedStatus = DENIED_STATUS.test(statement)
    // 正向身份判断、短路合取及三元条件不能证明未认证请求必然退出；可选链 ?. 不是三元条件。
    const negative = !/&&|\?(?!\.)/.test(condition) &&
      condition.split('||').some(part => rejectsMissingIdentity(part.trim(), returnsDeniedStatus))
    if (negative) return true
  }
  return false
}

/**
 * 文件中是否存在任何鉴权判断，包括嵌套在路径分支内的，如 if (path) { if (!user) error(401) }。
 * 只用于决定是否降低置信度，不证明某个操作受保护，因此 && 组合的条件也逐项检查。
 * 全文只配对一次括号，每个 if 只遍历自己这一层：若逐个 if 重新扫描各自的代码块，
 * 深层嵌套时工作量是“长度 × 深度”，200KB 的 hooks 文件即可让一次扫描耗时约 86 秒。
 */
function containsConditionalAuthCheck(code: string): boolean {
  const pairs = delimiterPairs(code)
  for (const match of code.matchAll(/\bif\s*\(/g)) {
    const open = match.index + match[0].length - 1
    const close = pairs.get(open)
    if (close === undefined) continue

    let start = close + 1
    while (/\s/.test(code[start] ?? '')) start++
    // 代码块取配对的右括号；单条语句最多看 400 个字符。
    let bodyStart = start
    let bodyEnd: number
    if (code[start] === '{') {
      bodyStart = start + 1
      bodyEnd = pairs.get(start) ?? Math.min(code.length, start + 600)
    } else {
      const semicolon = code.slice(start, start + 400).indexOf(';')
      bodyEnd = semicolon === -1 ? Math.min(code.length, start + 400) : start + semicolon + 1
    }

    // 只看这一层：遇到嵌套的 if 即停，由它自己的迭代处理；括号内的内容整体跳过。
    let stop = -1
    for (let i = bodyStart; i < bodyEnd; i++) {
      const window = code.slice(i, i + 16)
      if (STOPS_REQUEST.test(window) && (i === 0 || !/[\w$]/.test(code[i - 1]!))) {
        stop = i
        break
      }
      if (/^if\s*\(/.test(window)) break
      const end = pairs.get(i)
      if (end !== undefined) i = end
    }
    if (stop === -1) continue

    const returnsDeniedStatus = DENIED_STATUS.test(code.slice(stop, stop + 400))
    const condition = code.slice(open + 1, close)
    if (condition.split(/\|\||&&/).some(part => rejectsMissingIdentity(part.trim(), returnsDeniedStatus))) return true
  }
  return false
}

/** 每个文件只分析一次；中间件会被其覆盖的每条路由重复查询。 */
const authSignalCache = new WeakMap<object, boolean>()

function hasAuthSignal(file: { content: string }): boolean {
  const cached = authSignalCache.get(file)
  if (cached !== undefined) return cached
  const code = noiseMaskedOf(file)
  const found = AUTH_ENFORCING_CALL.test(code) || hasConditionalAuthGuard(code)
  authSignalCache.set(file, found)
  return found
}

interface FunctionBody {
  declaration: number
  start: number
  end: number
}

/** 一次配对括号，后续函数边界和语句扫描不重复搜索整个文件。 */
function delimiterPairs(code: string): Map<number, number> {
  const pairs = new Map<number, number>()
  const stack: number[] = []
  for (let i = 0; i < code.length; i++) {
    const ch = code[i]!
    if ('({['.includes(ch)) stack.push(i)
    else if (')}]'.includes(ch)) {
      const open = stack.pop()
      if (open !== undefined && '({['.indexOf(code[open]!) === ')}]'.indexOf(ch)) {
        pairs.set(open, i)
      }
    }
  }
  return pairs
}

/** 常见函数声明及块体箭头函数；无法确认边界时不假设已有鉴权。 */
function functionBodies(code: string, pairs: Map<number, number>): FunctionBody[] {
  const bodies: FunctionBody[] = []
  for (const match of code.matchAll(/\bfunction\s*\*?\s*(?:\w+\s*)?\(|=>\s*\{/g)) {
    let body: number
    if (match[0].startsWith('=>')) body = match.index + match[0].length - 1
    else {
      const close = pairs.get(match.index + match[0].length - 1)
      if (close === undefined) continue
      body = close + 1
      while (/\s/.test(code[body] ?? '')) body++
      // 简单返回类型不含对象字面量；复杂类型保持保守，不猜测边界。
      if (code[body] === ':') {
        const type = /^:[\w\s.<>,[\]|?]+(?=\{)/.exec(code.slice(body))
        if (type) body += type[0].length
      }
    }
    const end = pairs.get(body)
    if (code[body] === '{' && end !== undefined) bodies.push({ declaration: match.index, start: body, end })
  }
  return bodies
}

/** 语句终点：跳过参数及对象字面量，不能把下一条语句的 return 借过来。 */
function statementEnd(code: string, start: number, limit: number, pairs: Map<number, number>): number {
  if (code[start] === '{') return (pairs.get(start) ?? limit) + 1
  for (let i = start; i < limit; i++) {
    if (code[i] === ';' || code[i] === '\n') return i + 1
    const close = pairs.get(i)
    if (close !== undefined) i = close
  }
  return limit
}

/** 只认当前函数顶层、数据操作之前的检查，跳过未执行的函数和可选分支。 */
/**
 * 每个文件只分析一次：一个文件可含数以万计的 Server Action，逐路由重扫全文会使耗时与“路由数 × 文件长度”成正比。
 * 每个操作的判断互不依赖，先对全部操作判断、再按路由范围筛选，与先筛选后判断的结果相同。
 */
const unguardedCache = new WeakMap<ScanFile, DataHit[]>()
function unguardedOpsOf(file: ScanFile): DataHit[] {
  let hit = unguardedCache.get(file)
  if (hit === undefined) {
    hit = unguardedOperations(file, findDataOps(file))
    unguardedCache.set(file, hit)
  }
  return hit
}

/** 行号索引按文件缓存，同一文件的多个 Server Action 共用。 */
const lineStartsCache = new WeakMap<ScanFile, number[]>()
function lineStartsCached(file: ScanFile): number[] {
  let hit = lineStartsCache.get(file)
  if (hit === undefined) {
    hit = lineStartsOf(file.content)
    lineStartsCache.set(file, hit)
  }
  return hit
}

/** 按文件对象缓存布尔判断，生命周期随扫描结束。 */
function cachedByFile(check: (file: ScanFile) => boolean): (file: ScanFile) => boolean {
  const cache = new WeakMap<ScanFile, boolean>()
  return (file) => {
    let hit = cache.get(file)
    if (hit === undefined) {
      hit = check(file)
      cache.set(file, hit)
    }
    return hit
  }
}

function unguardedOperations(file: ScanFile, ops: DataHit[]): DataHit[] {
  if (ops.length === 0) return ops
  const code = noiseMaskedOf(file)
  const pairs = delimiterPairs(code)
  const bodies = functionBodies(code, pairs)
  const declarations = new Map(bodies.map(body => [body.declaration, body]))
  const functionStarts = new Set(bodies.map(body => body.start))
  const guardEnds = new Map<number, number>()
  type Block = Pick<FunctionBody, 'start' | 'end'>
  const blocks: Block[] = [...pairs].filter(([start]) => code[start] === '{')
    .map(([start, end]) => ({ start, end })).sort((a, b) => a.start - b.start)
  const active: Block[] = []
  let blockIndex = 0
  const wrappers = [...code.matchAll(/\b(?:withAuth|NextAuth)\s*\(/g)].map(match => {
    const open = match.index + match[0].length - 1
    return { start: open, end: pairs.get(open) ?? open }
  })

  // 每个函数最多扫描一次，不能对每个数据操作重新遍历整个函数前缀。
  const guardEnd = (owner: Block): number => {
    for (let i = owner.start + 1; i < owner.end; i++) {
      const nested = declarations.get(i)
      if (nested) { i = nested.end; continue }
      if (code.startsWith('=>', i)) {
        i = statementEnd(code, i + 2, owner.end, pairs) - 1
        continue
      }
      if (i > 0 && /[\w$]/.test(code[i - 1]!)) continue
      const conditional = /^if\s*\(/.exec(code.slice(i, i + 32))
      if (conditional) {
        const open = i + conditional[0].length - 1
        const close = pairs.get(open)
        if (close === undefined) return Infinity
        let start = close + 1
        while (/\s/.test(code[start] ?? '')) start++
        const end = statementEnd(code, start, owner.end, pairs)
        if (end <= owner.end && hasConditionalAuthGuard(code.slice(i, end))) return end
        // 只在部分请求中执行的鉴权不能保护后续无条件操作。
        i = Math.min(end, owner.end) - 1
        continue
      }
      const call = AUTH_ENFORCING_CALL.exec(code.slice(i, i + 100))
      // 构造一个包装后的处理函数并不鉴权当前请求；只在包围操作时认它。
      if (call?.index === 0 && !/^(?:withAuth|NextAuth)\b/i.test(call[0]) &&
          !/\bfunction\s*$/.test(code.slice(Math.max(owner.start, i - 30), i))) {
        const prefixStart = Math.max(owner.start + 1, code.lastIndexOf(';', i - 1) + 1,
          code.lastIndexOf('\n', i - 1) + 1)
        const prefix = code.slice(prefixStart, i).trim()
        // 换行不终止短路或三元表达式，不能借换行伪装成独立鉴权。
        if (/(?:&&|\|\||\?|:)\s*$/.test(code.slice(owner.start + 1, prefixStart))) continue
        const awaited = /^(?:await|(?:const|let|var)\s+[\w${},:\s]+?=\s*await)(?:\s+[\w$.]+\.)?$/.test(prefix)
        const synchronous = /^(?:assertAuth(?:enticated)?|constructEvent)\b/i.test(call[0]) &&
          /^(?:(?:const|let|var)\s+[\w$]+\s*=\s*)?(?:[\w$]+\.)*$/.test(prefix)
        if (!awaited && !synchronous) continue
        const close = pairs.get(i + call[0].length - 1)
        if (close !== undefined && close < owner.end) return close + 1
      }
      const close = pairs.get(i)
      if (close !== undefined) i = close
    }
    return Infinity
  }

  return ops.filter(op => {
    // 操作已按源位置排序；用栈维护包围它的代码块，避免逐操作重扫全部函数。
    while (blockIndex < blocks.length && blocks[blockIndex]!.start < op.index) {
      const block = blocks[blockIndex++]!
      while (active.length && active[active.length - 1]!.end < block.start) active.pop()
      active.push(block)
    }
    while (active.length && active[active.length - 1]!.end < op.index) active.pop()
    if (wrappers.some(w => w.start < op.index && w.end > op.index)) return false
    let ownerIndex = active.length - 1
    while (ownerIndex >= 0 && !functionStarts.has(active[ownerIndex]!.start)) ownerIndex--
    // 未识别到函数边界时不借用模块级的鉴权。
    if (ownerIndex < 0) return true
    // 同一函数中包围该操作的 try/条件块可以提供保护，其他分支不能。
    for (let index = ownerIndex; index < active.length; index++) {
      const block = active[index]!
      let end = guardEnds.get(block.start)
      if (end === undefined) {
        end = guardEnd(block)
        guardEnds.set(block.start, end)
      }
      if (end <= op.index) return false
    }
    return true
  })
}

// 识别管理员客户端。

/**
 * 匹配 Supabase 客户端构造，支持简单泛型参数。泛型之后的空白放在可选组内：
 * 两段 \s* 在无泛型时会对同一段空白二次回溯，屏蔽后的长注释即可让单个文件拖慢整次扫描。
 */
const CLIENT_CONSTRUCTOR = /\b(?:createClient|createServerClient)\s*(?:<[^()]{0,200}>\s*)?\(/

const SERVICE_ROLE_ENV = /\bSUPABASE_SERVICE_ROLE(?:_KEY)?\b|\bSERVICE_ROLE_KEY\b|\bSUPABASE_SECRET_KEY\b/
const SERVICE_ROLE_LITERAL = new RegExp(String.raw`['"\`](${JWT_SOURCE}|${SB_SECRET_SOURCE})['"\`]`, 'g')
const ENV_BRACKET_ACCESS = /(?:process\.env|import\.meta\.env)\s*\[\s*['"]([^'"]+)['"]\s*\]/g

/** 从代码标识符和环境索引访问中识别管理员凭据。 */
function referencesServiceRole(code: string, source: string): boolean {
  if (SERVICE_ROLE_ENV.test(code)) return true
  ENV_BRACKET_ACCESS.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = ENV_BRACKET_ACCESS.exec(source)) !== null) {
    if (SERVICE_ROLE_ENV.test(match[1] ?? '')) return true
  }
  return false
}

/** @nuxtjs/supabase 的服务端辅助函数：前者绕过行级策略，后者绑定调用者会话；常带数据库类型泛型。 */
// 泛型之后的空白放在可选组内，避免两段 \s* 在无泛型时产生二次回溯。
const NUXT_SUPABASE_ADMIN = /\bserverSupabaseServiceRole\s*(?:<[^()]{0,200}>\s*)?\(/
const NUXT_SUPABASE_SESSION = /\bserverSupabaseClient\s*(?:<[^()]{0,200}>\s*)?\(/

/** 同时存在客户端构造和管理员密钥引用时视为管理员客户端。 */
const buildsAdminClient = cachedByFile(buildsAdminClientUncached)
function buildsAdminClientUncached(file: ScanFile): boolean {
  const code = noiseMaskedOf(file)
  if (NUXT_SUPABASE_ADMIN.test(code)) return true
  if (!CLIENT_CONSTRUCTOR.test(code)) return false

  const source = commentsMaskedOf(file)
  if (referencesServiceRole(code, source)) return true
  SERVICE_ROLE_LITERAL.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = SERVICE_ROLE_LITERAL.exec(source)) !== null) {
    if (isSupabaseServiceRole(m[1]!)) return true
  }
  return false
}

/** 识别绑定调用者会话的客户端，由数据库策略实施授权。 */
const buildsSessionClient = cachedByFile(buildsSessionClientUncached)
function buildsSessionClientUncached(file: ScanFile): boolean {
  const code = noiseMaskedOf(file)
  if (NUXT_SUPABASE_ADMIN.test(code)) return false
  if (NUXT_SUPABASE_SESSION.test(code)) return true
  if (!CLIENT_CONSTRUCTOR.test(code)) return false
  // 含管理员凭据的客户端不能按会话客户端处理。
  if (referencesServiceRole(code, commentsMaskedOf(file))) return false
  return /\bcookies\b/.test(code)
}

/** 移除扩展名及末尾索引文件名以匹配导入。 */
function moduleKey(path: string): string {
  return path.replace(/\.[mc]?[jt]sx?$/, '').replace(/\/index$/, '')
}

/** 按模块键缓存文件索引，避免每次导入遍历所有文件。 */
const moduleIndexCache = new WeakMap<object, Map<string, ScanFile[]>>()

function moduleIndexOf(allFiles: ScanFile[]): Map<string, ScanFile[]> {
  const hit = moduleIndexCache.get(allFiles)
  if (hit !== undefined) return hit
  const index = new Map<string, ScanFile[]>()
  for (const file of allFiles) {
    const key = moduleKey(file.path)
    const list = index.get(key)
    if (list) list.push(file)
    else index.set(key, [file])
  }
  moduleIndexCache.set(allFiles, index)
  return index
}

const IMPORT_SPEC = /(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]/g

/** 解析相对导入及常见别名，忽略外部包导入。 */
interface ModuleTarget {
  key: string
  /** 是否相对当前应用根目录解析。 */
  alias: boolean
}

function normalizeSpec(spec: string, fromPath: string): ModuleTarget | null {
  if (spec.startsWith('.')) {
    return {
      key: moduleKey(posix.normalize(posix.join(posix.dirname(fromPath), spec))),
      alias: false,
    }
  }
  // SvelteKit 的 $lib 固定指向 src/lib。
  const lib = /^\$lib\/(.+)$/.exec(spec)
  if (lib) return { key: moduleKey(`src/lib/${lib[1]!}`), alias: true }
  // ~~/ 与 @@/ 是 Nuxt 的项目根目录别名。
  const alias = /^(?:[@~#]|~~|@@)\/(.+)$/.exec(spec)
  return alias ? { key: moduleKey(alias[1]!), alias: true } : null
}

/** 通过本地代码、导入关系或 Nuxt 自动导入判断管理员客户端使用情况。 */
function usesAdminClient(route: Route, adminModules: ScanFile[], allFiles: ScanFile[]): boolean {
  return buildsAdminClient(route.file) || importsAnyOf(route, adminModules, allFiles) ||
    autoImportsAnyOf(route, adminModules)
}

/** 通过本地代码、导入关系或 Nuxt 自动导入判断会话客户端使用情况。 */
function usesSessionClient(route: Route, sessionModules: ScanFile[], allFiles: ScanFile[]): boolean {
  // SvelteKit 通常在 hooks 中创建会话客户端并挂到 locals 上，路由不再导入它。
  if (route.framework === 'sveltekit' && /\blocals\s*\.\s*supabase\b/.test(noiseMaskedOf(route.file))) return true
  return buildsSessionClient(route.file) || importsAnyOf(route, sessionModules, allFiles) ||
    autoImportsAnyOf(route, sessionModules)
}

/** Nuxt 自动导入 server/utils 的导出，路由不写 import 也能调用。 */
function autoImportsAnyOf(route: Route, modules: ScanFile[]): boolean {
  if (route.framework !== 'nuxt') return false
  const utils = `${route.scope}server/utils/`
  const code = noiseMaskedOf(route.file)
  return modules.some(module => module.path.startsWith(utils) && exportedNames(module).some(name =>
    new RegExp(`(?<![\\w$.])${name.replace(/\$/g, '\\$')}\\s*\\(`).test(code)))
}

/** 模块顶层导出的函数及变量名。 */
function exportedNames(file: ScanFile): string[] {
  const names = noiseMaskedOf(file).matchAll(
    /\bexport\s+(?:async\s+)?(?:function\s*\*?\s*|const\s+|let\s+|var\s+)([A-Za-z_$][\w$]*)/g)
  return [...names].map(m => m[1]!)
}

/** 获取文件导入及重导出的项目模块。 */
function importedModules(file: ScanFile, allFiles: ScanFile[], aliasScope: string): ScanFile[] {
  const found: ScanFile[] = []
  const source = commentsMaskedOf(file)
  const code = noiseMaskedOf(file)
  IMPORT_SPEC.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = IMPORT_SPEC.exec(source)) !== null) {
    if (!/\b(?:from|import|require)\b/.test(code.slice(m.index, m.index + 10))) continue
    const target = normalizeSpec(m[1]!, file.path)
    if (!target) continue

    const index = moduleIndexOf(allFiles)
    if (!target.alias) {
      found.push(...(index.get(target.key) ?? []))
    } else {
      // 别名仅在所属应用及其源码目录解析，避免跨应用误匹配。
      const prefix = aliasScope
      // app/ 对应 Remix 的 ~/ 及 Nuxt 4 的源码目录。
      for (const key of [
        moduleKey(`${prefix}${target.key}`),
        moduleKey(`${prefix}src/${target.key}`),
        moduleKey(`${prefix}app/${target.key}`),
      ]) {
        found.push(...(index.get(key) ?? []))
      }
    }
  }
  return found
}

/** 按访问集合遍历导入图并判断目标模块是否可达。 */
/** 同一文件的多个 Server Action 共享导入图结果，按模块列表、文件和别名范围缓存。 */
const importsCache = new WeakMap<ScanFile[], WeakMap<ScanFile, Map<string, boolean>>>()

function importsAnyOf(route: Route, modules: ScanFile[], allFiles: ScanFile[]): boolean {
  if (modules.length === 0) return false
  const byFile = importsCache.get(modules) ?? new WeakMap<ScanFile, Map<string, boolean>>()
  importsCache.set(modules, byFile)
  const byScope = byFile.get(route.file) ?? new Map<string, boolean>()
  byFile.set(route.file, byScope)
  const cached = byScope.get(route.scope)
  if (cached !== undefined) return cached
  const result = importsAnyOfUncached(route, modules, allFiles)
  byScope.set(route.scope, result)
  return result
}

function importsAnyOfUncached(route: Route, modules: ScanFile[], allFiles: ScanFile[]): boolean {
  const targetPaths = new Set(modules.map((file) => file.path))
  const visited = new Set<string>()
  const aliasScope = route.scope

  // 使用显式队列避免深层导入链导致调用栈溢出。
  const queue: ScanFile[] = importedModules(route.file, allFiles, aliasScope)
  while (queue.length > 0) {
    const file = queue.pop()!
    if (targetPaths.has(file.path)) return true
    if (visited.has(file.path)) continue
    visited.add(file.path)
    queue.push(...importedModules(file, allFiles, aliasScope))
  }
  return false
}

// 识别实际数据操作。

interface DataHit {
  /** 操作的字符偏移，用于定位行号。 */
  index: number
  /** 是否修改数据，决定疑似结果是否需要报告。 */
  writes: boolean
}

/** 匹配 Supabase 表访问及后续操作。 */
const SUPABASE_TABLE = /\.from\(\s*['"`][^'"`]+['"`]\s*\)\s*\.?\s*(\w+)?/g
const SUPABASE_ADMIN_API = /\bauth\s*\.\s*admin\s*\.\s*(\w+)\s*\(/g
const SUPABASE_WRITES = new Set(['insert', 'update', 'upsert', 'delete'])

/** Prisma 客户端常命名为 prisma 或 db，Next.js 官方示例即使用 db.user.create。 */
const PRISMA_OP =
  /\b(?:prisma|db)\s*\.\s*\$?(\w+)\s*\.\s*(findMany|findFirst|findUnique|findUniqueOrThrow|create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/g
const PRISMA_RAW = /\b(?:prisma|db)\s*\.\s*\$(queryRaw|executeRaw)/g
const PRISMA_WRITES = /^(?:create|createMany|update|updateMany|upsert|delete|deleteMany)$/

const DRIZZLE_OP = /\bdb\s*\.\s*(select|insert|update|delete)\s*\(/g
const MONGO_OP =
  /\.(?:deleteMany|deleteOne|updateMany|updateOne|insertMany|insertOne|findOneAndDelete|findOneAndUpdate)\s*\(/g
const RAW_SQL = /\b(?:sql|query|execute)\s*(?:`|\(\s*['"`])\s*(select|insert|update|delete|drop|truncate)\b/gi
const RAW_SQL_WRITES = /^(?:insert|update|delete|drop|truncate)$/i

/** 按源码顺序收集数据操作。 */
function findDataOps(file: ScanFile): DataHit[] {
  const hits: DataHit[] = []
  const code = noiseMaskedOf(file)
  const push = (index: number, writes: boolean): void => {
    hits.push({ index, writes })
  }

  let m: RegExpExecArray | null

  SUPABASE_TABLE.lastIndex = 0
  while ((m = SUPABASE_TABLE.exec(code)) !== null) {
    push(m.index, SUPABASE_WRITES.has((m[1] ?? '').toLowerCase()))
  }

  SUPABASE_ADMIN_API.lastIndex = 0
  while ((m = SUPABASE_ADMIN_API.exec(code)) !== null) {
    push(m.index, !/^(?:get|list)/i.test(m[1] ?? ''))
  }

  PRISMA_OP.lastIndex = 0
  while ((m = PRISMA_OP.exec(code)) !== null) {
    push(m.index, PRISMA_WRITES.test(m[2] ?? ''))
  }

  PRISMA_RAW.lastIndex = 0
  while ((m = PRISMA_RAW.exec(code)) !== null) {
    push(m.index, (m[1] ?? '') === 'executeRaw')
  }

  DRIZZLE_OP.lastIndex = 0
  while ((m = DRIZZLE_OP.exec(code)) !== null) {
    push(m.index, (m[1] ?? '') !== 'select')
  }

  MONGO_OP.lastIndex = 0
  while ((m = MONGO_OP.exec(code)) !== null) {
    push(m.index, true)
  }

  RAW_SQL.lastIndex = 0
  while ((m = RAW_SQL.exec(commentsMaskedOf(file))) !== null) {
    push(m.index, RAW_SQL_WRITES.test(m[1] ?? ''))
  }

  return hits.sort((a, b) => a.index - b.index)
}

// 检查中间件保护范围。

/**
 * 各应用根目录及源码目录中的中间件。Next.js 16 起 middleware 更名为 proxy，两者均可能存在；
 * Astro 的中间件只在 src 下，可为单文件或 middleware/index 目录形式。
 */
const NEXT_MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?(?:middleware|proxy)\.[mc]?[jt]s$/
const ASTRO_MIDDLEWARE_FILE = /(?:^|\/)src\/middleware(?:\/index)?\.[mc]?[jt]s$/

function isMiddlewareFile(path: string, framework: Framework): boolean {
  return framework === 'astro' ? ASTRO_MIDDLEWARE_FILE.test(path) : NEXT_MIDDLEWARE_FILE.test(path)
}

/** 任一框架的中间件，用于统一校验匹配器。 */
function isAnyMiddlewareFile(path: string): boolean {
  return NEXT_MIDDLEWARE_FILE.test(path) || ASTRO_MIDDLEWARE_FILE.test(path)
}

/** 中间件作用域为所在应用目录。 */
function middlewareScopeOf(path: string): string {
  return path.replace(/(?:src\/)?(?:middleware(?:\/index)?|proxy)\.[mc]?[jt]s$/, '')
}

/**
 * 选择作用域最深的中间件，避免其他应用提供错误保护证据。
 * 同一作用域可能同时存在 middleware 与 proxy（迁移过程中），全部返回，由调用方逐个判断。
 */
function middlewaresFor(ctx: ScanContext, routePath: string, framework: Framework): ScanFile[] {
  let best: ScanFile[] = []
  let bestDepth = -1
  for (const file of ctx.files) {
    if (!isMiddlewareFile(file.path, framework)) continue
    const scope = middlewareScopeOf(file.path)
    if (!routePath.startsWith(scope)) continue
    if (scope.length > bestDepth) {
      best = [file]
      bestDepth = scope.length
    } else if (scope.length === bestDepth) {
      best.push(file)
    }
  }
  return best
}

/** 区分无匹配器、可读模式和无法解析的配置。 */
type MatcherConfig =
  | { kind: 'absent' }
  | { kind: 'patterns'; patterns: string[] }
  | { kind: 'unreadable' }

/** 扫描成对分隔符，跳过字符串内的同名字符。 */
function sliceDelimited(text: string, open: string, close: string): string | null {
  if (text[0] !== open) return null
  let quote: string | null = null
  let depth = 0
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if (quote !== null) {
      if (ch === '\\') i++
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === open) depth++
    else if (ch === close && --depth === 0) return text.slice(0, i + 1)
  }
  return null
}

function sliceBracketed(text: string): string | null {
  return sliceDelimited(text, '[', ']')
}

/** 提取完整引号字符串。 */
function sliceQuoted(text: string): string | null {
  const quote = text[0]
  if (quote !== "'" && quote !== '"' && quote !== '`') return null
  for (let i = 1; i < text.length; i++) {
    if (text[i] === '\\') i++
    else if (text[i] === quote) return text.slice(0, i + 1)
  }
  return null
}

/** 按顶层逗号拆分对象或数组字面量，返回各成员的起点；跳过字符串及嵌套结构。 */
function topLevelMemberStarts(text: string, container: '{' | '['): number[] {
  const starts = [1]
  let quote: string | null = null
  let braces = 0
  let brackets = 0
  let parentheses = 0

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if (quote !== null) {
      if (ch === '\\') i++
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === '{') braces++
    else if (ch === '}') braces--
    else if (ch === '[') brackets++
    else if (ch === ']') brackets--
    else if (ch === '(') parentheses++
    else if (ch === ')') parentheses--
    else if (ch === ',' && parentheses === 0 &&
        (container === '{' ? braces === 1 && brackets === 0 : brackets === 1 && braces === 0)) {
      starts.push(i + 1)
    }
  }
  return starts
}

/** 定位对象字面量顶层指定属性的值。 */
function topLevelPropertyStart(objectText: string, name: string): number | null {
  const property = new RegExp(`^(?:${name}|['"]${name}['"])\\s*:\\s*`)
  for (const start of topLevelMemberStarts(objectText, '{')) {
    let cursor = start
    while (/\s/.test(objectText[cursor] ?? '')) cursor++
    const match = property.exec(objectText.slice(cursor))
    if (match) return cursor + match[0].length
  }
  return null
}

/** 引号内的原始文本，与先前按引号提取的写法保持一致。 */
function quotedValue(text: string): string | null {
  const quoted = sliceQuoted(text)
  return quoted === null || quoted.length < 3 ? null : quoted.slice(1, -1)
}

/**
 * 解析匹配器的一个成员：字符串即路径模式；对象取 source，带 has 或 missing 条件的
 * 只在部分请求上运行，不能证明路由受保护。无法解析时返回空值。
 */
function matcherEntry(text: string): { pattern: string } | { conditional: true } | null {
  const trimmed = text.trimStart()
  if (trimmed.startsWith('{')) {
    const object = sliceDelimited(trimmed, '{', '}')
    if (object === null) return null
    if (topLevelPropertyStart(object, 'has') !== null || topLevelPropertyStart(object, 'missing') !== null) {
      return { conditional: true }
    }
    const source = topLevelPropertyStart(object, 'source')
    const pattern = source === null ? null : quotedValue(object.slice(source))
    return pattern === null ? null : { pattern }
  }
  const pattern = quotedValue(trimmed)
  return pattern === null ? null : { pattern }
}

/** 解析显式导出的匹配器配置。 */
function extractMatcherConfig(file: { content: string }): MatcherConfig {
  const code = noiseMaskedOf(file)
  const declaration = /\bexport\s+const\s+config\b/.exec(code)
  if (!declaration) return { kind: 'absent' }

  const afterDeclaration = declaration.index + declaration[0].length
  const assignment = code.indexOf('=', afterDeclaration)
  if (assignment === -1 || assignment - afterDeclaration > 300) return { kind: 'unreadable' }

  let objectStart = assignment + 1
  while (/\s/.test(code[objectStart] ?? '')) objectStart++
  if (code[objectStart] !== '{') return { kind: 'unreadable' }

  const masked = commentsMaskedOf(file)
  const objectText = sliceDelimited(masked.slice(objectStart), '{', '}')
  if (objectText === null) return { kind: 'unreadable' }

  const valueStart = topLevelPropertyStart(objectText, 'matcher')
  if (valueStart === null) return { kind: 'absent' }

  const rest = objectText.slice(valueStart)
  if (!rest.startsWith('[')) {
    const entry = matcherEntry(rest)
    return entry === null ? { kind: 'unreadable' } : 'pattern' in entry
      ? { kind: 'patterns', patterns: [entry.pattern] } : { kind: 'patterns', patterns: [] }
  }
  const array = sliceBracketed(rest)
  if (array === null) return { kind: 'unreadable' }

  const patterns: string[] = []
  let conditional = 0
  const starts = topLevelMemberStarts(array, '[')
  for (const [index, start] of starts.entries()) {
    // 末尾成员止于右方括号；允许尾随逗号。
    const member = array.slice(start, index + 1 < starts.length ? starts[index + 1]! - 1 : array.length - 1)
    if (member.trim() === '') continue
    // Next.js 忽略变量等非常量成员，这里同样跳过。
    const entry = matcherEntry(member)
    if (entry === null) continue
    if ('pattern' in entry) patterns.push(entry.pattern)
    else conditional++
  }
  // 全部成员都带条件时，匹配器不无条件覆盖任何路由；空数组无法判断含义。
  if (patterns.length === 0 && conditional === 0) return { kind: 'unreadable' }
  return { kind: 'patterns', patterns }
}

/** 限制匹配器长度，避免复杂输入消耗过多资源。 */
const MAX_MATCHER_LENGTH = 300

/** 移除正则分组前缀。 */
function withoutGroupPrefix(body: string): string {
  return body.replace(/^\?(?:[:=!]|<[=!]|<[A-Za-z_]\w*>)/, '')
}

/** 仅按顶层分支符拆分，不拆分嵌套组或字符类。 */
function topLevelBranches(body: string): string[] {
  const parts: string[] = []
  let depth = 0
  let inClass = false
  let start = 0
  for (let i = 0; i < body.length; i++) {
    const ch = body[i]
    if (ch === '\\') {
      i++
      continue
    }
    if (inClass) {
      if (ch === ']') inClass = false
      continue
    }
    if (ch === '[') {
      inClass = true
      continue
    }
    if (ch === '(') depth++
    else if (ch === ')') depth--
    else if (ch === '|' && depth === 0) {
      parts.push(body.slice(start, i))
      start = i + 1
    }
  }
  parts.push(body.slice(start))
  return parts
}

/** 提取分支的首个确定字符；无法确认时返回空值。 */
function firstLiteralOf(branch: string): string | null {
  const ch = branch[0]
  if (ch === undefined) return null
  if (ch === '\\') {
    // 字符类缩写不能作为字面量判断分支互斥。
    if (/[wWdDsSpP]/.test(branch[1] ?? '')) return null
    return branch.slice(0, 2)
  }
  if (ch === '[' || ch === '(' || ch === '.' || ch === '^') return null
  return ch
}

/** 保守判断分支是否可能匹配相同输入。 */
function branchesCanOverlap(branches: string[]): boolean {
  if (branches.length < 2) return false
  const seen = new Set<string>()
  for (const branch of branches) {
    const head = firstLiteralOf(branch.trim())
    if (head === null) return true
    if (seen.has(head)) return true
    seen.add(head)
  }
  return false
}

/** 识别可能产生指数级回溯的重复分组。 */
function hasAmbiguousRepetition(source: string): boolean {
  const open: number[] = []
  for (let i = 0; i < source.length; i++) {
    const ch = source[i]
    if (ch === '\\') {
      i++
      continue
    }
    if (ch === '(') {
      open.push(i)
      continue
    }
    if (ch !== ')') continue
    const start = open.pop()
    if (start === undefined) continue
    const next = source[i + 1] ?? ''
    // 仅重复组与内部歧义组合才构成此类风险。
    if (next !== '+' && next !== '*' && next !== '{') continue
    const body = withoutGroupPrefix(source.slice(start + 1, i))
    if (/(?:^|[^\\])[+*]|\{\d+,\d*\}/.test(body)) return true
    if (branchesCanOverlap(topLevelBranches(body))) return true
  }
  return false
}

/** 判断匹配器是否可安全执行。 */
function isSafeMatcher(pattern: string): boolean {
  return pattern.length <= MAX_MATCHER_LENGTH && !hasAmbiguousRepetition(pattern)
}

/** 将 Next.js 路径匹配器转换为正则。 */
function matcherToRegex(pattern: string): RegExp | null {
  // 参数必须以斜杠开头，避免替换正则分组中的冒号。
  if (!isSafeMatcher(pattern)) return null
  const source = pattern
    .replace(/\/:[A-Za-z_]\w*\*/g, '/.*')
    .replace(/\/:[A-Za-z_]\w*\+/g, '/.+')
    .replace(/\/:[A-Za-z_]\w*/g, '/[^/]+')
  try {
    return new RegExp(`^${source}$`)
  } catch {
    return null
  }
}

/** 按具体路由判断中间件覆盖及鉴权信号；同一作用域任一中间件覆盖即可。 */
function middlewareCovers(ctx: ScanContext, route: Route): boolean {
  return middlewaresFor(ctx, route.file.path, route.framework).some((mw) => covers(ctx, mw, route.url))
}

function covers(ctx: ScanContext, mw: ScanFile, url: string): boolean {
  if (!hasAuthSignal(mw)) return false

  const { config, readable } = compiledMatchersOf(mw)
  // 未指定匹配器时按全部请求处理。
  if (config.kind === 'absent') return true
  // 无法解析的匹配器保守视为可能覆盖，并记录扫描未完成。
  if (config.kind === 'unreadable') {
    ctx.reportIncomplete(
      'api/db-access-without-auth',
      `the middleware matcher in ${mw.path} could not be read, so which routes it covers is ` +
        `unknown; routes under it were treated as protected`,
    )
    return true
  }

  // 所有成员都带 has 或 missing 条件时，中间件不无条件运行于任何路由。
  if (config.patterns.length === 0) return false
  // 仅使用可读模式；完全不可读时保持保守。
  if (readable.length === 0) return true
  return readable.some((re) => re.test(url))
}

/** 中间件的匹配器配置及编译结果，每个文件只解析一次。 */
const matcherCache = new WeakMap<object, { config: MatcherConfig; readable: RegExp[] }>()

function compiledMatchersOf(file: { content: string }): { config: MatcherConfig; readable: RegExp[] } {
  const cached = matcherCache.get(file)
  if (cached !== undefined) return cached
  const config = extractMatcherConfig(file)
  const readable = config.kind === 'patterns'
    ? config.patterns.map(matcherToRegex).filter((re): re is RegExp => re !== null)
    : []
  const compiled = { config, readable }
  matcherCache.set(file, compiled)
  return compiled
}

/**
 * SvelteKit 的 hooks.server 与 Nuxt 的 server/middleware 对所有请求生效，却没有声明式的作用范围：
 * 路径判断写在代码里。其中含鉴权时无法确认是否覆盖该路由，结果降为疑似，而不是直接当作已保护。
 */
function globalGuardFor(ctx: ScanContext, route: Route): string | null {
  const relative = (file: ScanFile): string | null =>
    file.path.startsWith(route.scope) ? file.path.slice(route.scope.length) : null
  const candidates = ctx.files.filter((file) => {
    const path = relative(file)
    if (path === null) return false
    if (route.framework === 'sveltekit') return /^src\/hooks\.server\.[mc]?[jt]s$/.test(path)
    if (route.framework === 'nuxt') return /^server\/middleware\/.+\.[mc]?[jt]s$/.test(path)
    return false
  })
  return candidates.find(containsAuthCheck)?.path ?? null
}

/** 每个文件只分析一次；否则每条路由都会重新分析同一个全局鉴权文件。 */
const authCheckCache = new WeakMap<ScanFile, boolean>()

/** 全局鉴权通常先按路径分支再判断身份，须检查嵌套条件。 */
function containsAuthCheck(file: ScanFile): boolean {
  const cached = authCheckCache.get(file)
  if (cached !== undefined) return cached
  const code = noiseMaskedOf(file)
  const found = AUTH_ENFORCING_CALL.test(code) || containsConditionalAuthCheck(code)
  authCheckCache.set(file, found)
  return found
}

// 生成检测结果。

/** 识别摘录中需提前遮蔽的长凭据形状。 */
const SECRET_SHAPED = /['"`]([A-Za-z0-9_\-.]{32,})['"`]/g

/** 从完整源码行生成摘录，保留上下文。 */
function excerptFor(file: ScanFile, line: number): string {
  const raw = (file.lines[line - 1] ?? '').trim()
  let out = raw
  SECRET_SHAPED.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = SECRET_SHAPED.exec(raw)) !== null) {
    out = out.split(m[1]!).join(redactSecret(m[1]!))
  }
  // 截断由统一输出边界完成。
  return out
}

export const apiAuthRule: ProjectRule = {
  id: 'api/db-access-without-auth',
  severity: 'P0',

  check(ctx: ScanContext): Finding[] {
    // 示例路由仍参与检查，由引擎降低置信度。
    const routes = ctx.files.flatMap((file) => {
      const route = routeOf(file)
      return route === null ? serverActionRoutes(file) : [route]
    })
    if (routes.length === 0) return []

    // 每个中间件只校验一次匹配器。
    for (const middlewareFile of ctx.files.filter((f) => isAnyMiddlewareFile(f.path))) {
      const config = extractMatcherConfig(middlewareFile)
      // 编译失败或不安全的模式都必须记录。
      const refused =
        config.kind === 'patterns' ? config.patterns.filter((p) => matcherToRegex(p) === null) : []
      if (refused.length > 0) {
        ctx.reportIncomplete(
          'api/db-access-without-auth',
          `${refused.length} middleware ${refused.length === 1 ? 'matcher was' : 'matchers were'} not ` +
            `evaluated in ${middlewareFile.path} — ${refused.length === 1 ? 'it' : 'each'} either could ` +
            `not be compiled or could take unbounded time to run, so which routes ${refused.length === 1 ? 'it covers is' : 'they cover is'} unknown`,
        )
      }
    }

    const adminModules = ctx.files.filter(buildsAdminClient)
    const sessionModules = ctx.files.filter(buildsSessionClient)
    const findings: Finding[] = []

    for (const route of routes) {
      const reachable = route.reachable
      const ops = unguardedOpsOf(route.file).filter((op) =>
        reachable === undefined || (op.index > reachable.start && op.index < reachable.end))
      if (ops.length === 0) continue

      const url = route.url
      if (isAuthEndpoint(route)) continue
      // Next.js 与 Astro 的中间件逐路由判断保护范围。
      if ((route.framework === 'next' || route.framework === 'astro') && route.action === undefined &&
          middlewareCovers(ctx, route)) continue
      const globalGuard = globalGuardFor(ctx, route)
      const globalNote = globalGuard === null ? [] : [
        `${globalGuard} contains an authentication check that may cover ${url}. Its path conditions are ` +
          `written in code, so the scan cannot tell which routes it applies to; this finding is reported at ` +
          `lower confidence. Confirm that check runs for ${url}.`,
      ]

      const admin = usesAdminClient(route, adminModules, ctx.files)
      // 存在写操作时优先用其作为证据。
      const hit = ops.find((o) => o.writes) ?? ops[0]!
      // 每个路由只构建一次行号索引。
      const line = lineNumberAt(lineStartsCached(route.file), hit.index)
      const excerpt = excerptFor(route.file, line)

      if (admin) {
        findings.push({
          ruleId: 'api/admin-db-access-without-auth',
          severity: 'P0',
          // 管理员客户端缺少鉴权时使用确定置信度；可能受全局鉴权覆盖时降为疑似。
          confidence: globalGuard === null ? 'certain' : 'likely',
          title: `Anyone can call ${url} and it queries your database as admin`,
          file: route.file.path,
          line,
          excerpt,
          why: [
            ...globalNote,
            `This route references a recognized admin client. Such clients can bypass normal per-user access checks; ` +
              `verify the effective credentials and granted permissions.`,
            `The scan did not recognize an authentication guard protecting this operation or applicable middleware. ` +
              `Indirect wrappers and deployment-level controls may not be recognized; verify them before exposing this route.`,
            `If ${url} is reachable without authentication, callers can trigger the admin-backed operations implemented by this handler.`,
            `If this endpoint is meant to be public — handing out a guest session, taking a waitlist signup — ` +
              `then the problem is not that it is open, it is that it is open *and* holds the admin key. Give it ` +
              `a client that can only do the one thing it needs.`,
          ],
          fix: [
            `Add an authorisation check as the first thing the handler does, and return 401 when it fails. With Supabase auth: const { data: { user } } = await supabase.auth.getUser(); if (!user) return new Response('Unauthorized', { status: 401 });`,
            `Then check that this particular user is allowed to touch this particular data. Being signed in is not the same as being allowed — otherwise any account can read every other account's rows.`,
            `If the route only ever needs the caller's own data, use a client created from the request's session instead of the service_role key. Row Level Security then enforces the boundary for you, and a mistake in the handler cannot leak someone else's data.`,
            `If it is meant to be called by a cron job or another service, compare a shared secret from a request header against an environment variable using crypto.timingSafeEqual.`,
            `If it genuinely has to stay open to anyone, stop using the service_role key here. Use the anon client with a Row Level Security policy that permits exactly this one operation, so a mistake in the handler cannot reach anything else.`,
          ],
          humanOnly: [
            `Check your Supabase and hosting logs for requests to ${url} you cannot account for. If this has been deployed, treat the data it touches as already read.`,
          ],
        })
      } else if (hit.writes) {
        // 会话客户端交由数据库行级策略限制调用者。
        if (usesSessionClient(route, sessionModules, ctx.files)) continue

        findings.push({
          ruleId: 'api/db-write-without-auth',
          severity: 'P1',
          // 公开写入可能是业务设计，保留疑似置信度。
          confidence: 'likely',
          // Server Action 的名称以小写开头，放在句首时首字母大写。
          title: `${url.charAt(0).toUpperCase()}${url.slice(1)} writes to your database with no sign-in check`,
          file: route.file.path,
          line,
          excerpt,
          why: [
            ...globalNote,
            `This route changes data, and the scan did not recognize an authentication guard before the operation. ` +
              `Indirect guards and runtime controls require manual verification.`,
            `If this route is publicly reachable and no other control rejects the caller, unauthenticated requests can trigger this write.`,
            `If this is a public form — a waitlist, a contact box — that may be intentional. It is still worth ` +
              `rate limiting, because an open write endpoint is what gets a database filled with spam overnight.`,
          ],
          fix: [
            `If this route is not meant to be public, check the caller first and return 401 when there is no valid session.`,
            `Verify that the caller owns the row being changed, not just that they are signed in.`,
            `If it is genuinely public, add rate limiting and validate the request body before writing.`,
          ],
        })
      }
    }

    return findings
  },
}
