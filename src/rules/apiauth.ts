/** 检查未认证请求可触达的数据操作；结合函数内控制流、客户端类型和中间件判断。 */

import { posix } from 'node:path'
import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { isSupabaseServiceRole } from './framework.js'
import { redactSecret } from '../redact.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { JWT_SOURCE, SB_SECRET_SOURCE } from './patterns.js'

// 识别 API 路由。

/** App Router 处理函数及 Pages Router API 文件。 */
const APP_ROUTER = /(?:^|\/)app\/api\/(?:.+\/)?route\.[mc]?[jt]sx?$/
const PAGES_ROUTER = /(?:^|\/)pages\/api\/.+\.[mc]?[jt]sx?$/

function isApiRoute(path: string): boolean {
  return APP_ROUTER.test(routePathOf(path)) || PAGES_ROUTER.test(path)
}

/** 路由组仅用于组织目录，不构成 URL 路径。 */
function routePathOf(path: string): string {
  return path.replace(/(^|\/)\([^/]+\)(?=\/)/g, '$1').replace(/\/{2,}/g, '/')
}

/** 仅豁免明确的登录及身份管理入口，不豁免整个命名空间。 */
const AUTH_ENDPOINT_NAMES =
  /^\/api\/auth\/(?:sign[-_]?in|sign[-_]?up|sign[-_]?out|log[-_]?in|log[-_]?out|register|session|verify|confirm|reset(?:[-_]password)?|forgot(?:[-_]password)?|magic[-_]?link|otp)$/

/** OAuth 回调允许一层提供方路径。 */
const AUTH_CALLBACK = /^\/api\/auth\/callback(?:\/[^/]+)?$/

function isAuthEndpoint(url: string): boolean {
  // 不按任意捕获路径豁免，仅识别明确的认证处理方式。
  return AUTH_ENDPOINT_NAMES.test(url) || AUTH_CALLBACK.test(url)
}

/** 将文件路径转换为请求 URL。 */
function routeUrl(path: string): string {
  const m = /(?:^|\/)(?:app|pages)\/(api\/.*)$/.exec(routePathOf(path))
  if (!m) return `/${path}`
  const url = m[1]!
    .replace(/\/route\.[mc]?[jt]sx?$/, '')
    .replace(/\/index\.[mc]?[jt]sx?$/, '')
    .replace(/\.[mc]?[jt]sx?$/, '')
  return `/${url}`
}

// 识别鉴权证据。

/** 已知会拒绝无效调用者的验证函数及包装器。 */
const AUTH_ENFORCING_CALL =
  /\b(?:NextAuth|require(?:Auth|User|Session|Admin)|withAuth|verifyAuth|ensureAuth|assertAuth(?:enticated)?|verifyIdToken|constructEvent)\s*\(/i

/** 鉴权条件必须涉及身份、凭据或验证调用。 */
const AUTH_CONDITION =
  /\b(?:session|token|user|authorization|bearer|jwt|auth|signature|CRON_SECRET|WEBHOOK_SECRET|REVALIDATE_SECRET|ADMIN_SECRET)\b|\blocals\s*\.\s*user\b|\b(?:getUser|getSession|getServerSession|currentUser|getAuth|isAuthenticated|checkAuth|verifyAuth|ensureAuth|verifyIdToken|timingSafeEqual)\s*\(/i

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
      if (/^(?:return|throw|redirect|notFound)\b/.test(body.slice(i, i + 16)) &&
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

    const returnsDeniedStatus =
      /\b(?:return|throw)\b[\s\S]{0,300}\bstatus\s*[:(=]\s*(?:401|403)\b/i.test(statement)
    // 正向身份判断、短路合取及三元条件不能证明未认证请求必然退出。
    const negative = !/&&|\?/.test(condition) && condition.split('||').some(part => {
      const term = part.trim()
      const rejects = /^!\s*[\w$.]+(?:\s*\([^=]*\))?$/.test(term) ||
        /^[\w$.]+\s*={2,3}\s*(?:null|undefined|false)$/.test(term) ||
        /^[\w$.]+\s*!={1,2}\s*(?!(?:null|undefined|false)\b)[\w$.]+$/.test(term)
      return rejects && (AUTH_CONDITION.test(term) || returnsDeniedStatus)
    })
    if (negative) return true
  }
  return false
}

function hasAuthSignal(file: { content: string }): boolean {
  const code = noiseMaskedOf(file)
  return AUTH_ENFORCING_CALL.test(code) || hasConditionalAuthGuard(code)
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

/** 匹配 Supabase 客户端构造，支持简单泛型参数。 */
const CLIENT_CONSTRUCTOR = /\b(?:createClient|createServerClient)\s*(?:<[^()]{0,200}>)?\s*\(/

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

/** 同时存在客户端构造和管理员密钥引用时视为管理员客户端。 */
function buildsAdminClient(file: ScanFile): boolean {
  const code = noiseMaskedOf(file)
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
function buildsSessionClient(file: ScanFile): boolean {
  const code = noiseMaskedOf(file)
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
  const alias = /^[@~#]\/(.+)$/.exec(spec)
  return alias ? { key: moduleKey(alias[1]!), alias: true } : null
}

/** 通过本地代码或导入关系判断管理员客户端使用情况。 */
function usesAdminClient(route: ScanFile, adminModules: ScanFile[], allFiles: ScanFile[]): boolean {
  return buildsAdminClient(route) || importsAnyOf(route, adminModules, allFiles)
}

/** 通过导入关系判断会话客户端使用情况。 */
function usesSessionClient(route: ScanFile, sessionModules: ScanFile[], allFiles: ScanFile[]): boolean {
  return buildsSessionClient(route) || importsAnyOf(route, sessionModules, allFiles)
}

/** 提取路由所属的应用根目录。 */
function moduleScopeOf(routePath: string): string {
  return /^(.*?)(?:src\/)?(?:app|pages)\/api\//.exec(routePathOf(routePath))?.[1] ?? ''
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
      for (const key of [
        moduleKey(`${prefix}${target.key}`),
        moduleKey(`${prefix}src/${target.key}`),
      ]) {
        found.push(...(index.get(key) ?? []))
      }
    }
  }
  return found
}

/** 按访问集合遍历导入图并判断目标模块是否可达。 */
function importsAnyOf(route: ScanFile, modules: ScanFile[], allFiles: ScanFile[]): boolean {
  if (modules.length === 0) return false

  const targetPaths = new Set(modules.map((file) => file.path))
  const visited = new Set<string>()
  const aliasScope = moduleScopeOf(route.path)

  // 使用显式队列避免深层导入链导致调用栈溢出。
  const queue: ScanFile[] = importedModules(route, allFiles, aliasScope)
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

const PRISMA_OP =
  /\bprisma\s*\.\s*\$?(\w+)\s*\.\s*(findMany|findFirst|findUnique|findUniqueOrThrow|create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/g
const PRISMA_RAW = /\bprisma\s*\.\s*\$(queryRaw|executeRaw)/g
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

/** 识别各应用根目录及源码目录中的中间件。 */
const MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?middleware\.[mc]?[jt]s$/

/** 中间件作用域为所在应用目录。 */
function middlewareScopeOf(path: string): string {
  return path.replace(/(?:src\/)?middleware\.[mc]?[jt]s$/, '')
}

/** 选择作用域最深的中间件，避免其他应用提供错误保护证据。 */
function middlewareFor(ctx: ScanContext, routePath: string): ScanFile | null {
  let best: ScanFile | null = null
  let bestDepth = -1
  for (const file of ctx.files) {
    if (!MIDDLEWARE_FILE.test(file.path)) continue
    const scope = middlewareScopeOf(file.path)
    if (!routePath.startsWith(scope)) continue
    if (scope.length > bestDepth) {
      best = file
      bestDepth = scope.length
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

/** 定位配置对象顶层匹配器属性的值。 */
function topLevelMatcherValueStart(objectText: string): number | null {
  const candidates = [1]
  let quote: string | null = null
  let braces = 0
  let brackets = 0
  let parentheses = 0

  for (let i = 0; i < objectText.length; i++) {
    const ch = objectText[i]!
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
    else if (ch === ',' && braces === 1 && brackets === 0 && parentheses === 0) {
      candidates.push(i + 1)
    }
  }

  for (const start of candidates) {
    let cursor = start
    while (/\s/.test(objectText[cursor] ?? '')) cursor++
    const property = /^(?:matcher|['"]matcher['"])\s*:\s*/.exec(objectText.slice(cursor))
    if (property) return cursor + property[0].length
  }
  return null
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

  const valueStart = topLevelMatcherValueStart(objectText)
  if (valueStart === null) return { kind: 'absent' }

  const rest = objectText.slice(valueStart)
  const raw = rest.startsWith('[') ? sliceBracketed(rest) : sliceQuoted(rest)
  if (raw === null) return { kind: 'unreadable' }

  const patterns = [...raw.matchAll(/['"`]([^'"`]+)['"`]/g)].map((m) => m[1]!)
  return patterns.length === 0 ? { kind: 'unreadable' } : { kind: 'patterns', patterns }
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

/** 按具体路由判断中间件覆盖及鉴权信号。 */
function middlewareCovers(ctx: ScanContext, routePath: string, url: string): boolean {
  const mw = middlewareFor(ctx, routePath)
  if (!mw) return false
  if (!hasAuthSignal(mw)) return false

  const config = extractMatcherConfig(mw)
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

  const parsed = config.patterns.map(matcherToRegex)
  const readable = parsed.filter((re): re is RegExp => re !== null)
  // 仅使用可读模式；完全不可读时保持保守。
  if (readable.length === 0) return true
  return readable.some((re) => re.test(url))
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
    const routes = ctx.files.filter((f) => isApiRoute(f.path))
    if (routes.length === 0) return []

    // 每个中间件只校验一次匹配器。
    for (const middlewareFile of ctx.files.filter((f) => MIDDLEWARE_FILE.test(f.path))) {
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
      const ops = unguardedOperations(route, findDataOps(route))
      if (ops.length === 0) continue

      const url = routeUrl(route.path)
      if (isAuthEndpoint(url)) continue
      // 逐路由判断保护范围。
      if (middlewareCovers(ctx, route.path, url)) continue

      const admin = usesAdminClient(route, adminModules, ctx.files)
      // 存在写操作时优先用其作为证据。
      const hit = ops.find((o) => o.writes) ?? ops[0]!
      // 每个路由只构建一次行号索引。
      const line = lineNumberAt(lineStartsOf(route.content), hit.index)
      const excerpt = excerptFor(route, line)

      if (admin) {
        findings.push({
          ruleId: 'api/admin-db-access-without-auth',
          severity: 'P0',
          // 管理员客户端缺少鉴权时使用确定置信度。
          confidence: 'certain',
          title: `Anyone can call ${url} and it queries your database as admin`,
          file: route.path,
          line,
          excerpt,
          why: [
            `This route uses the service_role key, which bypasses every Row Level Security policy you have. ` +
              `Whatever your database would normally refuse, this route performs.`,
            `Nothing in this file checks who is calling — no session lookup, no token check, no 401 anywhere — ` +
              `and no middleware covers it. The URL is not a secret either: it is spelled out by the file path, ` +
              `and it appears in your frontend bundle as soon as anything calls it.`,
            `So a single curl to ${url} gets the same access your admin key has.`,
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
          title: `${url} writes to your database with no sign-in check`,
          file: route.path,
          line,
          excerpt,
          why: [
            `This route changes data, and nothing in the file checks who is calling — no session lookup, no ` +
              `token check, no 401 anywhere.`,
            `Route URLs are not secret; this one is spelled out by its file path. Anyone who sends a request ` +
              `can trigger the same write.`,
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
