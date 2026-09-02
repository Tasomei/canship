/**
 * P0/P1: API routes that reach your database with nothing checking who is calling.
 *
 * This is the failure that follows a leaked key in how often it happens and how
 * much it costs. The assistant writes `app/api/users/route.ts`, gives it the
 * service_role client so the query "just works", and never adds a sign-in
 * check — because during development there is nobody to check. The route ships.
 * Its URL is not a secret: it is spelled out by the file path, and it is in the
 * frontend bundle the moment anything calls it.
 *
 * Detecting this without false positives is the hard part, so the rule is built
 * out of three separate conservative decisions:
 *
 *   1. Only files that really are HTTP route handlers (Next.js app/pages router).
 *   2. Only routes that really touch data. A route using the *service_role*
 *      client is certain-grade, because that key bypasses every RLS policy —
 *      whatever the database would normally refuse, this route performs. Plain
 *      ORM writes are reported at lower confidence.
 *   3. Any hint of an authorisation check anywhere in the file suppresses the
 *      finding. The signal list below is deliberately over-broad: matching too
 *      much causes a miss, matching too little causes a false positive, and the
 *      two are not equally bad.
 *
 * On top of that, Next.js middleware can protect a route from the outside, with
 * nothing visible in the route file at all. That is checked project-wide before
 * anything is reported.
 */

import { posix } from 'node:path'
import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { isSupabaseServiceRole } from './framework.js'
import { redactSecret } from '../redact.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { JWT_SOURCE, SB_SECRET_SOURCE } from './patterns.js'

// ── 1. Is this file an HTTP route handler? ──────────────────────────────────

/** App Router route handlers, and Pages Router API files */
const APP_ROUTER = /(?:^|\/)app\/api\/(?:.+\/)?route\.[mc]?[jt]sx?$/
const PAGES_ROUTER = /(?:^|\/)pages\/api\/.+\.[mc]?[jt]sx?$/

function isApiRoute(path: string): boolean {
  return APP_ROUTER.test(path) || PAGES_ROUTER.test(path)
}

/**
 * Routes that cannot have a sign-in check, because they are how you sign in.
 *
 * `/api/auth/signin` calling the admin client to mint a magic link is the
 * correct implementation of passwordless auth, not a hole — there is nobody to
 * authenticate yet.
 *
 * Only the handlers that genuinely have that property are named. Exempting the
 * whole `/api/auth` namespace was simpler and wrong: `/api/auth/export-all`
 * lives there too, and being under an auth path says nothing about whether a
 * route should be open. A namespace is not an argument.
 *
 * Webhook and cron routes are deliberately *not* exempt either: those are
 * supposed to verify a signature or a shared secret, and one that does not is
 * a real finding.
 *
 * The same reasoning applies one level down, and used not to. Every name here
 * once allowed arbitrary descendants, so `/api/auth/signin/export-all` was
 * exempt while `/api/auth/export-all` — the case the fixture exists to pin —
 * was not. Moving the bulk export one segment deeper turned it invisible. A
 * sub-path is a namespace too, and a namespace is still not an argument.
 */
const AUTH_ENDPOINT_NAMES =
  /^\/api\/auth\/(?:sign[-_]?in|sign[-_]?up|sign[-_]?out|log[-_]?in|log[-_]?out|register|session|verify|confirm|reset(?:[-_]password)?|forgot(?:[-_]password)?|magic[-_]?link|otp)$/

/**
 * The exception that earns its descendants.
 *
 * OAuth callbacks are addressed per provider — `/api/auth/callback/google`,
 * `/api/auth/callback/github` — and every one of them is a real callback with
 * nobody to authenticate yet. One extra segment, no deeper: the provider name
 * is the only thing that legitimately follows.
 */
const AUTH_CALLBACK = /^\/api\/auth\/callback(?:\/[^/]+)?$/

function isAuthEndpoint(url: string): boolean {
  // Deliberately no catch-all case. `/api/auth/[...nextauth]` is a real
  // Auth.js handler and a real place to hide `/api/auth/[...evil]`, and the
  // path cannot tell them apart — so the genuine one is recognised by what is
  // in the file (`import NextAuth`), which is evidence, and the path is not.
  return AUTH_ENDPOINT_NAMES.test(url) || AUTH_CALLBACK.test(url)
}

/**
 * The URL this file is served at. Worth the few lines: "/api/users" lands very
 * differently from "app/api/users/route.ts" when someone is deciding whether to
 * take a finding seriously.
 */
function routeUrl(path: string): string {
  const m = /(?:^|\/)(?:app|pages)\/(api\/.*)$/.exec(path)
  if (!m) return `/${path}`
  const url = m[1]!
    .replace(/\/route\.[mc]?[jt]sx?$/, '')
    .replace(/\/index\.[mc]?[jt]sx?$/, '')
    .replace(/\.[mc]?[jt]sx?$/, '')
  return `/${url}`
}

// ── 2. Does anything in the file look like an authorisation check? ──────────

/** Wrappers and verifiers that reject an invalid caller themselves */
const AUTH_ENFORCING_CALL =
  /\b(?:NextAuth|require(?:Auth|User|Session|Admin)|withAuth|verifyAuth|ensureAuth|assertAuth(?:enticated)?|verifyIdToken|constructEvent)\s*\(/i

/** The condition has to name an identity, a credential or a check — not merely a related word */
const AUTH_CONDITION =
  /\b(?:session|token|user|authorization|bearer|jwt|auth|signature|CRON_SECRET|WEBHOOK_SECRET|REVALIDATE_SECRET|ADMIN_SECRET)\b|\blocals\s*\.\s*user\b|\b(?:getUser|getSession|getServerSession|currentUser|getAuth|isAuthenticated|checkAuth|verifyAuth|ensureAuth|verifyIdToken|timingSafeEqual)\s*\(/i

/** The matching delimiter, in text whose strings and comments are already blanked */
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

/** Only the statements this if controls, so an unrelated 401 or return further down does not count */
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

/**
 * Reading an authentication state is not performing one. A route counts as
 * protected only when an auth condition governs a rejection — a return, a throw,
 * a redirect — or when the branch answers 401 or 403 outright.
 */
function hasConditionalAuthGuard(code: string): boolean {
  const starts = code.matchAll(/\bif\s*\(/g)
  for (const match of starts) {
    const open = code.indexOf('(', match.index)
    const close = closingDelimiter(code, open, '(', ')')
    if (close === null) continue

    const condition = code.slice(open + 1, close)
    const statement = controlledStatement(code, close + 1)
    const stopsRequest = /\b(?:return|throw|redirect|notFound)\b/.test(statement)
    if (!stopsRequest) continue

    const returnsDeniedStatus =
      /\b(?:return|throw)\b[\s\S]{0,300}\bstatus\s*[:(=]\s*(?:401|403)\b/i.test(statement)
    if (AUTH_CONDITION.test(condition) || returnsDeniedStatus) return true
  }
  return false
}

function hasAuthSignal(file: { content: string }): boolean {
  const code = noiseMaskedOf(file)
  return AUTH_ENFORCING_CALL.test(code) || hasConditionalAuthGuard(code)
}

// ── 3. Does the route use a service_role (admin) client? ────────────────────

/**
 * A Supabase client being constructed.
 *
 * The optional type-argument group is not decoration: `createClient<Database>()`
 * is the form Supabase's own documentation recommends for typed projects, and
 * without it the generic swallows the opening parenthesis, so the whole file
 * stops looking like it builds a client. A real repository caught this — the
 * finding was downgraded from certain to likely, and therefore hidden by
 * default.
 */
const CLIENT_CONSTRUCTOR = /\b(?:createClient|createServerClient)\s*(?:<[^()]{0,200}>)?\s*\(/

const SERVICE_ROLE_ENV = /\bSUPABASE_SERVICE_ROLE(?:_KEY)?\b|\bSERVICE_ROLE_KEY\b|\bSUPABASE_SECRET_KEY\b/
const SERVICE_ROLE_LITERAL = new RegExp(String.raw`['"\`](${JWT_SOURCE}|${SB_SECRET_SOURCE})['"\`]`, 'g')
const ENV_BRACKET_ACCESS = /(?:process\.env|import\.meta\.env)\s*\[\s*['"]([^'"]+)['"]\s*\]/g

/** Reads code identifiers and structured env index access, without mistaking prose for a reference */
function referencesServiceRole(code: string, source: string): boolean {
  if (SERVICE_ROLE_ENV.test(code)) return true
  ENV_BRACKET_ACCESS.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = ENV_BRACKET_ACCESS.exec(source)) !== null) {
    if (SERVICE_ROLE_ENV.test(match[1] ?? '')) return true
  }
  return false
}

/**
 * Whether this file constructs a Supabase client with the service_role key.
 * Requires both the key reference and a client constructor, so a file that
 * merely forwards the variable is not mistaken for the client itself.
 */
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

/**
 * Whether this file constructs a Supabase client bound to the caller's session.
 *
 * This matters because of what the rule tells people to do. Its own advice is
 * "use a client created from the request's session instead of the service_role
 * key, and let Row Level Security enforce the boundary". A route that does
 * exactly that runs every query as whoever is calling — signed in or not — and
 * the database decides. Reporting it would mean flagging the fix.
 *
 * Whether RLS is actually switched on is a different question, and
 * supabase/rls-not-enabled is the rule that answers it.
 */
function buildsSessionClient(file: ScanFile): boolean {
  const code = noiseMaskedOf(file)
  if (!CLIENT_CONSTRUCTOR.test(code)) return false
  // A file holding the service_role key is an admin client whatever else it does.
  if (referencesServiceRole(code, commentsMaskedOf(file))) return false
  return /\bcookies\b/.test(code)
}

/** Strip the extension and a trailing /index so a path compares to an import specifier */
function moduleKey(path: string): string {
  return path.replace(/\.[mc]?[jt]sx?$/, '').replace(/\/index$/, '')
}

/**
 * Every file in the scan, indexed by module key.
 *
 * Resolving one import specifier used to filter the whole file list, and the
 * walk below asks per import, per file, per route. On 3,000 library files
 * behind 300 routes that is millions of key derivations for a lookup a map
 * answers outright. Keyed on the array the way the maskers are keyed on the
 * file, so it is built once and dies with the scan.
 */
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

/**
 * Resolve an import specifier to a project-relative module path.
 * Handles relative imports and the `@/`, `~/`, `#/` aliases every Next.js
 * template ships with. Bare package imports return null — node_modules is not
 * scanned and nothing in there is the user's code.
 */
interface ModuleTarget {
  key: string
  /** Whether it resolves from the current Next.js app root */
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

/**
 * Whether the route reaches an admin client, directly or through an import.
 *
 * The import case is not an edge case — it is the shape every Supabase tutorial
 * teaches: one `lib/supabase-admin.ts` holding the service_role client,
 * imported wherever it is needed. Only looking inside the route file would miss
 * almost all of them.
 */
function usesAdminClient(route: ScanFile, adminModules: ScanFile[], allFiles: ScanFile[]): boolean {
  return buildsAdminClient(route) || importsAnyOf(route, adminModules, allFiles)
}

/** The session-scoped counterpart of usesAdminClient */
function usesSessionClient(route: ScanFile, sessionModules: ScanFile[], allFiles: ScanFile[]): boolean {
  return buildsSessionClient(route) || importsAnyOf(route, sessionModules, allFiles)
}

/** The Next.js app root a route belongs to; the empty string for an app at the scan root */
function moduleScopeOf(routePath: string): string {
  return /^(.*?)(?:src\/)?(?:app|pages)\/api\//.exec(routePath)?.[1] ?? ''
}

/** The project files a file imports or re-exports */
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
      // @/, ~/ and #/ resolve inside this app root and its src/ only, so one
      // workspace package cannot vouch for another.
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

/** Whether any target module is reachable across a bounded walk of the project's import graph */
function importsAnyOf(route: ScanFile, modules: ScanFile[], allFiles: ScanFile[]): boolean {
  if (modules.length === 0) return false

  const targetPaths = new Set(modules.map((file) => file.path))
  const visited = new Set<string>()
  const aliasScope = moduleScopeOf(route.path)

  // Walked with an explicit queue rather than by recursion. `visited` bounds
  // how many files are examined but says nothing about how deep the chain is,
  // and one call frame per link is a limit a repository can reach: a 4,000-file
  // chain of re-exports — three lines of codegen, or a deliberate layout in a
  // repository canship has no reason to trust — overflowed the stack. The
  // engine caught the throw, so it was never silent; it did mean the whole
  // rule crashed and every route in the project lost its check at once.
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

// ── 4. Does the route actually touch data? ──────────────────────────────────

interface DataHit {
  /** Character offset of the match, used to resolve a line number */
  index: number
  /**
   * Whether the operation changes data. Writes are what make the
   * lower-confidence tier worth reporting at all.
   */
  writes: boolean
}

/** Supabase / PostgREST: .from('table') followed by an operation */
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

/** Collect every data operation in the file, in source order */
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

// ── 5. Is middleware already protecting these routes? ───────────────────────

/**
 * A Next.js middleware file, anywhere a Next.js app can be rooted.
 *
 * This was anchored with `^`, which only ever found a middleware sitting in the
 * directory canship was pointed at. `APP_ROUTER` next to it is anchored
 * `(?:^|\/)`, so in a monorepo the pair disagreed: `apps/web/app/api/x/route.ts`
 * was recognised as a route, `apps/web/middleware.ts` was not recognised as its
 * protection, and every authenticated route in every workspace package came
 * back P0. The regexes have to agree about where an app may start.
 */
const MIDDLEWARE_FILE = /(?:^|\/)(?:src\/)?middleware\.[mc]?[jt]s$/

/**
 * The directory a middleware file governs: its own, less a trailing `src/`.
 *
 * `apps/web/middleware.ts` and `apps/web/src/middleware.ts` both govern
 * `apps/web/`; a middleware at the root governs everything.
 */
function middlewareScopeOf(path: string): string {
  return path.replace(/(?:src\/)?middleware\.[mc]?[jt]s$/, '')
}

/**
 * The middleware governing a route, or null.
 *
 * Deepest scope wins. Matching any middleware anywhere would be the opposite
 * error to the one above and a worse one: `apps/admin/middleware.ts` would
 * silence the rule for `apps/web`, hiding real findings instead of inventing
 * false ones.
 */
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

/**
 * What a middleware's `matcher` config says, as three distinct answers.
 *
 * `absent` and `unreadable` used to be the same answer — an empty array — and
 * the caller read that one answer as "covers every request". So a matcher the
 * parser choked on silenced the rule for the whole app, exactly as if no
 * matcher had been written at all. They mean opposite things and now say so.
 */
type MatcherConfig =
  | { kind: 'absent' }
  | { kind: 'patterns'; patterns: string[] }
  | { kind: 'unreadable' }

/**
 * From a leading `[`, the text through its matching `]`.
 *
 * Written as a scan rather than `\[[^\]]*\]` because that regex stops at the
 * first `]` in the text, and a `]` inside a matcher string is ordinary:
 * `matcher: ["/dashboard/[a-z]+"]` was cut to `["/dashboard/[a-z]`, which holds
 * one quote, yields no strings, and so read as "no matcher at all" — meaning
 * a middleware guarding only /dashboard was taken to cover the entire API.
 */
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

/** From a leading quote, the text through its closing quote */
function sliceQuoted(text: string): string | null {
  const quote = text[0]
  if (quote !== "'" && quote !== '"' && quote !== '`') return null
  for (let i = 1; i < text.length; i++) {
    if (text[i] === '\\') i++
    else if (text[i] === quote) return text.slice(0, i + 1)
  }
  return null
}

/** Where the value of the config object's top-level matcher property starts */
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

/** Read `export const config = { matcher: ... }` */
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

/**
 * Long enough for any matcher anyone writes on purpose.
 *
 * The documented Next.js exclusion matcher is about seventy characters. A
 * bound here is the cheap half of the defence below: backtracking cost grows
 * with the pattern as well as the input.
 */
const MAX_MATCHER_LENGTH = 300

/** Strip the `?:`, `?=`, `?!`, `?<=`, `?<!`, `?<name>` a group body may open with */
function withoutGroupPrefix(body: string): string {
  return body.replace(/^\?(?:[:=!]|<[=!]|<[A-Za-z_]\w*>)/, '')
}

/**
 * Split a group body on its top-level `|`, ignoring bars nested inside another
 * group or a character class.
 */
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

/**
 * The one literal character a branch has to start with, or null when its first
 * token is not a single literal — a class, a group, a dot, or nothing at all.
 * Null means "could start with anything", which overlaps everything.
 */
function firstLiteralOf(branch: string): string | null {
  const ch = branch[0]
  if (ch === undefined) return null
  if (ch === '\\') {
    // A class shorthand is not a literal. `\w` compared as the two-character
    // string "\\w" is unequal to "a", so `(\w|a)+` read as two disjoint
    // branches and was let through — and then took 7.3 seconds on a
    // 28-character path. Anything that stands for a set of characters overlaps
    // whatever else the alternation offers.
    if (/[wWdDsSpP]/.test(branch[1] ?? '')) return null
    return branch.slice(0, 2)
  }
  if (ch === '[' || ch === '(' || ch === '.' || ch === '^') return null
  return ch
}

/**
 * Whether two branches of an alternation can match the same text.
 *
 * Decided on first characters, which is an approximation in the safe
 * direction: `(foo|bar)` can never take two paths through the same input and
 * is left alone, while `(a|a)` and `(a|ab)` can, and are refused. A branch
 * opening with a class or a group counts as overlapping everything, because
 * proving otherwise needs a real parser.
 */
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

/**
 * A repeated group that can match one input in more than one way — `(a+)+`,
 * `(\w*)*`, `([a-z]+){2,}`, and equally `(a|a)+` or `(a|ab)*`.
 *
 * This is the shape that makes a backtracking engine try every way of splitting
 * the input across the repeats, which is exponential. The matcher is a string
 * taken from a file in the repository being scanned and handed to `new RegExp`,
 * then run against route paths on the main thread — so a pattern like that plus
 * a long path is a scan, or a CI runner, pinned at 100% for as long as the
 * author of the repository would like.
 *
 * The ambiguity used to be looked for only as a nested quantifier, and
 * alternation is the other half of the same idea: `/((a|a|a)+)x` passed this
 * check and then took **162 seconds** on a 30-character path. Both halves are
 * needed, because both produce the same exponential.
 *
 * Scanned rather than pattern-matched, because deciding this needs to know
 * which `(` a `)` belongs to, and a regex cannot count brackets.
 */
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
    // Only a group that repeats can pair with inner ambiguity to go
    // exponential. An unquantified group is ordinary grouping — which is why
    // the matcher Next.js documents, whose groups are never quantified, is
    // still read rather than refused.
    if (next !== '+' && next !== '*' && next !== '{') continue
    const body = withoutGroupPrefix(source.slice(start + 1, i))
    if (/(?:^|[^\\])[+*]|\{\d+,\d*\}/.test(body)) return true
    if (branchesCanOverlap(topLevelBranches(body))) return true
  }
  return false
}

/** Whether a matcher is safe to compile and run against a path */
function isSafeMatcher(pattern: string): boolean {
  return pattern.length <= MAX_MATCHER_LENGTH && !hasAmbiguousRepetition(pattern)
}

/**
 * Turn a Next.js matcher into a regular expression.
 *
 * Matchers are path-to-regexp patterns that may also contain raw regex, and
 * both forms have to work:
 *
 *   /api/:path*                                 named parameters
 *   /((?!api|_next/static|favicon.ico).*)       a negative lookahead
 *
 * Converting the parameter syntax and handing the rest to RegExp covers both,
 * because the raw-regex form already is one.
 */
function matcherToRegex(pattern: string): RegExp | null {
  // The leading slash is not decoration. A path parameter always follows one,
  // and requiring it is what keeps this away from the colon in `(?:` — which
  // appears in the matcher Next.js documents for excluding static files:
  //
  //   /((?!api|_next/static|favicon.ico|.*\.(?:svg|png|jpg)$).*)
  //
  // Rewriting `:svg` there produced `(?[^/]+|png|…)`, an invalid group. The
  // pattern failed to compile, an unreadable matcher counted as coverage, and
  // the whole rule went quiet on every project using that matcher.
  // Refused before compiling, and refused as "unreadable" rather than as an
  // error, because that is already the honest answer: canship did not evaluate
  // this matcher. Running it to find out would be the whole problem.
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

/**
 * Whether Next.js middleware authenticates requests to **this** route.
 *
 * The question has to be asked per route. Asking it once for the whole project
 * produced a hole big enough to drive through: middleware protecting only
 * `/api/admin/:path*` returned "the API is covered", and every unauthenticated
 * route in the project went unreported. One narrow matcher silenced the rule
 * everywhere.
 *
 * This gate remains the biggest false-positive risk here — middleware protects
 * a route from the outside, leaving nothing in the route file to see — so an
 * unreadable matcher still counts as protection.
 */
function middlewareCovers(ctx: ScanContext, routePath: string, url: string): boolean {
  const mw = middlewareFor(ctx, routePath)
  if (!mw) return false
  if (!hasAuthSignal(mw)) return false

  const config = extractMatcherConfig(mw)
  // No matcher at all: middleware runs on every request, this one included.
  if (config.kind === 'absent') return true
  // A matcher canship could not read is still assumed to cover — the note at
  // the top of this function explains why that direction is the careful one —
  // but assuming is not knowing, and the reader is told which this was.
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
  // One unreadable pattern among several used to make everything look covered,
  // which is how a single odd matcher silences the rule for a whole project.
  // Ignore what cannot be read; only fall back to assuming coverage when none
  // of it could be read at all.
  if (readable.length === 0) return true
  return readable.some((re) => re.test(url))
}

// ── Rule ────────────────────────────────────────────────────────────────────

/**
 * Anything quoted and long enough to be a credential.
 * Table names, column lists and dates fall well under this length; JWTs,
 * sk- keys and sb_secret_ tokens are all comfortably above it.
 */
const SECRET_SHAPED = /['"`]([A-Za-z0-9_\-.]{32,})['"`]/g

/**
 * Build the excerpt from the whole source line rather than the regex match:
 * `const { data } = await supabaseAdmin.from('profiles').select('*')` reads
 * naturally, where `.from('profiles').select` does not.
 *
 * Any credential-shaped token on that line is masked first. A hardcoded key
 * sitting on the same line as a query is unlikely — but canship's rule is that
 * no complete secret ever reaches the output, and "unlikely" is not "never".
 */
function excerptFor(file: ScanFile, line: number): string {
  const raw = (file.lines[line - 1] ?? '').trim()
  let out = raw
  SECRET_SHAPED.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = SECRET_SHAPED.exec(raw)) !== null) {
    out = out.split(m[1]!).join(redactSecret(m[1]!))
  }
  // Length is the boundary's job — see sanitize(). Cutting here would risk
  // the same order bug: a credential this masker did not recognise could be
  // sliced through before redaction ever saw it.
  return out
}

export const apiAuthRule: ProjectRule = {
  id: 'api/db-access-without-auth',
  severity: 'P0',

  check(ctx: ScanContext): Finding[] {
    // Example apps are routes too — a deployable demo under examples/ has the
    // same open endpoint. The engine downgrades what they produce.
    const routes = ctx.files.filter((f) => isApiRoute(f.path))
    if (routes.length === 0) return []

    // Said once, before the per-route loop, rather than once per route. A
    // matcher canship declines to run is a question it did not answer — and
    // the answer it falls back to is "covered", which is the quiet direction.
    // Every middleware, not the first one found. `find` was left over from when
    // a project had at most one; once each workspace package could have its
    // own, the second app's refused matchers went unmentioned — and a refused
    // matcher is read as coverage, so that silence hid real routes.
    for (const middlewareFile of ctx.files.filter((f) => MIDDLEWARE_FILE.test(f.path))) {
      const config = extractMatcherConfig(middlewareFile)
      // matcherToRegex(p) === null covers both reasons a matcher goes unread:
      // refused up front for being unsafe to run (isSafeMatcher), or refused
      // after because it failed to compile at all — a matcher with invalid
      // regex syntax passed isSafeMatcher (nothing about it looked like
      // exponential backtracking) and only failed inside matcherToRegex's own
      // try/catch. That case used to slip past this loop silently: the pattern
      // filtered on `!isSafeMatcher(p)` alone called it zero refused matchers,
      // middlewareCovers fell back to its "nothing readable → assume covered"
      // branch, and every route under a middleware with one malformed matcher
      // reported clean with no incomplete notice at all.
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
      if (hasAuthSignal(route)) continue

      const ops = findDataOps(route)
      if (ops.length === 0) continue

      const url = routeUrl(route.path)
      if (isAuthEndpoint(url)) continue
      // Asked per route, not once for the project — see middlewareCovers.
      if (middlewareCovers(ctx, route.path, url)) continue

      const admin = usesAdminClient(route, adminModules, ctx.files)
      // Report the write if there is one — it is the operation people care
      // about, and it makes the excerpt concrete.
      const hit = ops.find((o) => o.writes) ?? ops[0]!
      // One offset per route, so the index is built and used in the same breath.
      const line = lineNumberAt(lineStartsOf(route.content), hit.index)
      const excerpt = excerptFor(route, line)

      if (admin) {
        findings.push({
          ruleId: 'api/admin-db-access-without-auth',
          severity: 'P0',
          // Hard evidence: the route runs queries through a key that bypasses
          // every RLS policy, and nothing in the file or in middleware checks
          // who sent the request.
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
        // A session-scoped client runs as the caller, so the database is
        // already deciding what they may change. See buildsSessionClient.
        if (usesSessionClient(route, sessionModules, ctx.files)) continue

        findings.push({
          ruleId: 'api/db-write-without-auth',
          severity: 'P1',
          // Lower confidence on purpose: the write may be legitimately open
          // (a waitlist, a contact form), and protection can also live in a
          // deployment-level proxy this scan cannot see.
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
