/** 按迁移顺序重放表结构，检查 Supabase 表最终是否启用行级安全。 */

import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { isSupabaseProject } from './framework.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'
import { blank, codesOf, stringOf } from '../mask.js'
import {
  ALTER_POLICY,
  CREATE_POLICY,
  DROP_POLICY,
  bucketDeclarations,
  bucketOnlyCondition,
  configPublicBuckets,
  isAlwaysTrue,
  policyClauses,
  statementEnd,
  identAt,
} from './sqlpolicy.js'
import type { PolicyClauses, PolicyCommand } from './sqlpolicy.js'

/** 默认不通过公共数据接口暴露的内部模式。 */
const INTERNAL_SCHEMAS = new Set([
  'auth',
  'storage',
  'realtime',
  'vault',
  'extensions',
  'graphql',
  'graphql_public',
  'pgbouncer',
  'supabase_functions',
  'supabase_migrations',
  'net',
  'cron',
  'information_schema',
  'pg_catalog',
])

/** 保留源码顺序的结构变更事件。 */
interface SqlEvent {
  kind: 'create' | 'drop' | 'enable-rls' | 'disable-rls' | 'rename' | 'policy' | 'policy-drop' | 'policy-alter' | 'bucket'
  /** 策略名，仅策略事件使用。 */
  policy?: string
  /** 策略子句；alter policy 只含被修改的部分。 */
  clauses?: PolicyClauses
  /** 存储桶公开状态，仅存储桶事件使用。 */
  bucket?: { id: string; public: boolean }
  schema: string
  table: string
  file: string
  /** 事件所属的独立重放作用域。 */
  scope: string
  /** 文件内字符偏移，用于语句排序。 */
  at: number
  line: number
  /** 建表是否使用存在时跳过语义。 */
  idempotent?: boolean
  /** 重命名后的表名。 */
  renamedTo?: string
}

/** 屏蔽非执行 SQL，保留偏移和换行。 */
/** 匿名执行块与函数定义需分别处理。 */
const IS_DO_BLOCK = /\bdo\s+(?:language\s+\w+\s+)?$/i

/** 使用码元比较减少字符串分配。 */
const DASH = 0x2d
const SLASH = 0x2f
const STAR = 0x2a
const SINGLE_QUOTE = 0x27
const DOUBLE_QUOTE = 0x22
const DOLLAR = 0x24
const NEWLINE = 0x0a
const UNDERSCORE = 0x5f

/** 优先检查常见空白码元，再回退到完整空白规则。 */
function isSpaceCode(code: number): boolean {
  if (code === 0x20 || (code >= 0x09 && code <= 0x0d)) return true
  return code > 0x7f && /\s/.test(String.fromCharCode(code))
}

export function maskSqlNoise(sql: string): string {
  const length = sql.length
  const out = codesOf(sql)
  // 复用等长屏蔽原语，保持位置正确。
  const erase = (from: number, to: number): void => blank(out, from, to)

  let i = 0
  while (i < length) {
    const ch = sql.charCodeAt(i)

    if (ch === DASH && sql.charCodeAt(i + 1) === DASH) {
      const end = sql.indexOf('\n', i)
      erase(i, end === -1 ? length : end)
      i = end === -1 ? length : end
      continue
    }

    if (ch === SLASH && sql.charCodeAt(i + 1) === STAR) {
      // PostgreSQL 块注释允许嵌套。
      let depth = 0
      let j = i
      while (j < length) {
        const first = sql.charCodeAt(j)
        const second = sql.charCodeAt(j + 1)
        if (first === SLASH && second === STAR) {
          depth++
          j += 2
        } else if (first === STAR && second === SLASH) {
          depth--
          j += 2
          if (depth === 0) break
        } else {
          j++
        }
      }
      erase(i, j)
      i = j
      continue
    }

    if (ch === SINGLE_QUOTE) {
      // 转义字符串支持反斜杠，普通字符串使用双引号符转义。
      const escaped = i > 0 && /[Ee]/.test(sql[i - 1] ?? '') && !/[A-Za-z0-9_]/.test(sql[i - 2] ?? '')
      let j = i + 1
      while (j < length) {
        const inner = sql.charCodeAt(j)
        if (escaped && inner === 0x5c) {
          j += 2
          continue
        }
        if (inner === SINGLE_QUOTE) {
          if (sql.charCodeAt(j + 1) === SINGLE_QUOTE) {
            j += 2
            continue
          }
          j++
          break
        }
        j++
      }
      erase(i, j)
      i = j
      continue
    }

    if (ch === DOUBLE_QUOTE) {
      // 保留引用标识符并屏蔽内部空白，防止其伪造 SQL 关键字。
      let j = i + 1
      while (j < length && sql.charCodeAt(j) !== DOUBLE_QUOTE) {
        const code = out[j]
        if (code !== undefined && code !== NEWLINE && isSpaceCode(code)) out[j] = UNDERSCORE
        j++
      }
      i = j + 1
      continue
    }

    if (ch === DOLLAR) {
      // 识别美元引号及标签，排除位置参数。
      const tag = /^\$(?:[A-Za-z_]\w*)?\$/.exec(sql.slice(i))?.[0]
      if (tag) {
        const close = sql.indexOf(tag, i + tag.length)
        const end = close === -1 ? length : close + tag.length
        // 函数体不直接执行；匿名执行块中的结构变更参与重放。
        if (!IS_DO_BLOCK.test(sql.slice(0, i))) erase(i, end)
        i = end
        continue
      }
    }

    i++
  }

  return stringOf(out)
}

/** 未引用标识符转为小写，引用标识符保留大小写。 */
function unquote(ident: string): string {
  const quoted = /^"(.*)"$/.exec(ident)
  return quoted ? quoted[1]! : ident.toLowerCase()
}

/** 按 SQL 语法输出标识符，必要时加引号并转义。 */
function renderIdent(name: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`
}

/** 解析删除表列表及级联选项。 */
function parseDropList(raw: string): { schema: string; table: string }[] {
  const out: { schema: string; table: string }[] = []
  for (const part of raw.split(',')) {
    const cleaned = part.replace(/\b(cascade|restrict)\b/gi, '').trim()
    const m = /^(?:("[^"]+"|[a-z_][\w$]*)\s*\.\s*)?("[^"]+"|[a-z_][\w$]*)\s*$/i.exec(cleaned)
    if (!m) continue
    out.push({ schema: m[1] ? unquote(m[1]) : 'public', table: unquote(m[2]!) })
  }
  return out
}

const CREATE_TABLE =
  /\bcreate\s+table\s+(if\s+not\s+exists\s+)?(?:("[^"]+"|[a-z_][\w$]*)\s*\.\s*)?("[^"]+"|[a-z_][\w$]*)/gi

/** 捕获删除语句的全部目标表。 */
const DROP_TABLE = /\bdrop\s+table\s+(?:if\s+exists\s+)?([^;]+)/gi

/** 共享修改表语句的目标前缀。 */
const ALTER_TARGET = String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:("[^"]+"|[a-z_][\w$]*)\s*\.\s*)?("[^"]+"|[a-z_][\w$]*)`

const ENABLE_RLS = new RegExp(`${ALTER_TARGET}\\s+enable\\s+row\\s+level\\s+security`, 'gi')

/** 处理后续迁移关闭行级安全的情况。 */
const DISABLE_RLS = new RegExp(`${ALTER_TARGET}\\s+disable\\s+row\\s+level\\s+security`, 'gi')

/** 重命名时保留原表的安全状态。 */
const RENAME_TABLE = new RegExp(
  `${ALTER_TARGET}\\s+rename\\s+to\\s+("[^"]+"|[a-z_][\\w$]*)`,
  'gi',
)

/** 仅检查实际迁移文件或独立模式定义。 */
function isSqlFile(file: ScanFile): boolean {
  const path = file.path.toLowerCase()
  if (!path.endsWith('.sql')) return false
  const inMigrations = /(?:^|\/)migrations\//.exec(path)
  if (!inMigrations) return true
  const rest = path.slice(inMigrations.index + inMigrations[0].length)
  return !rest.includes('/')
}

const WORKSPACE_CONTAINERS = new Set(['apps', 'packages', 'services', 'projects'])
const EXAMPLE_CONTAINERS = new Set([
  'test',
  'tests',
  '__tests__',
  'spec',
  'specs',
  'fixture',
  'fixtures',
  'mock',
  'mocks',
  '__mocks__',
  'e2e',
  'example',
  'examples',
  'doc',
  'docs',
])

function directoryOf(path: string): string {
  const slash = path.lastIndexOf('/')
  return slash === -1 ? '' : path.slice(0, slash)
}

function insideScope(path: string, scope: string): boolean {
  return scope === '' || path === scope || path.startsWith(`${scope}/`)
}

/** 依据项目布局划分独立数据库范围。 */
function projectScopesOf(files: ScanFile[]): string[] {
  const scopes = new Set<string>([''])

  for (const file of files) {
    const parts = file.path.split('/')
    if (parts.at(-1) === 'package.json') scopes.add(directoryOf(file.path))

    const supabase = parts.lastIndexOf('supabase')
    if (supabase !== -1 && supabase < parts.length - 1) {
      scopes.add(parts.slice(0, supabase).join('/'))
    }

    for (let i = 0; i < parts.length - 2; i++) {
      if (WORKSPACE_CONTAINERS.has(parts[i]!)) scopes.add(parts.slice(0, i + 2).join('/'))
    }

    for (let i = parts.length - 3; i >= 0; i--) {
      if (!EXAMPLE_CONTAINERS.has(parts[i]!)) continue
      scopes.add(parts.slice(0, i + 2).join('/'))
      break
    }
  }

  return [...scopes].sort((a, b) => a.length - b.length)
}

/** 文件归入包含它的最深项目范围。 */
function projectScopeOf(path: string, scopes: string[]): string {
  let best = ''
  for (const scope of scopes) {
    if (scope.length > best.length && insideScope(path, scope)) best = scope
  }
  return best
}

/** 仅在当前项目范围内判断 Supabase 使用证据。 */
function isActiveSupabaseScope(ctx: ScanContext, files: ScanFile[], scope: string): boolean {
  return isSupabaseProject(ctx, files, scope)
}

/** 测试与示例 SQL 使用独立重放作用域。 */
function replayScopeOf(file: ScanFile, projectScope: string): string {
  return `${file.isExampleContext ? 'example' : 'project'}:${projectScope}`
}


export const supabaseRlsRule: ProjectRule = {
  id: 'supabase/rls-not-enabled',
  severity: 'P1',

  check(ctx: ScanContext): Finding[] {
    const projectScopes = projectScopesOf(ctx.files)
    const filesByScope = new Map<string, ScanFile[]>()
    for (const file of ctx.files) {
      const scope = projectScopeOf(file.path, projectScopes)
      const files = filesByScope.get(scope) ?? []
      files.push(file)
      filesByScope.set(scope, files)
    }

    const activeScopes = new Set<string>()
    for (const [scope, files] of filesByScope) {
      if (isActiveSupabaseScope(ctx, files, scope)) activeScopes.add(scope)
    }
    if (activeScopes.size === 0) return []

    const events: SqlEvent[] = []

    // 按路径排序以遵循迁移时间顺序。
    const sqlFiles = ctx.files
      // 普通 PostgreSQL 子项目不受相邻 Supabase 项目的规则影响。
      .filter(
        (file) =>
          isSqlFile(file) && activeScopes.has(projectScopeOf(file.path, projectScopes)),
      )
      .sort((a, b) => a.path.localeCompare(b.path))

    for (const file of sqlFiles) {
      const sql = maskSqlNoise(file.content)
      const scope = replayScopeOf(file, projectScopeOf(file.path, projectScopes))
      // 每个文件只构建一次行号索引。
      const sqlLines = lineStartsOf(sql)
      let m: RegExpExecArray | null

      CREATE_TABLE.lastIndex = 0
      while ((m = CREATE_TABLE.exec(sql)) !== null) {
        const schema = m[2] ? unquote(m[2]) : 'public'
        const table = unquote(m[3]!)
        if (INTERNAL_SCHEMAS.has(schema)) continue
        events.push({
          kind: 'create',
          idempotent: Boolean(m[1]),
          schema,
          table,
          file: file.path,
          scope,
          at: m.index,
          line: lineNumberAt(sqlLines, m.index),
        })
      }

      DROP_TABLE.lastIndex = 0
      while ((m = DROP_TABLE.exec(sql)) !== null) {
        for (const ref of parseDropList(m[1] ?? '')) {
          if (INTERNAL_SCHEMAS.has(ref.schema)) continue
          events.push({ kind: 'drop', ...ref, file: file.path, scope, at: m.index, line: lineNumberAt(sqlLines, m.index) })
        }
      }

      for (const [pattern, kind] of [
        [ENABLE_RLS, 'enable-rls'],
        [DISABLE_RLS, 'disable-rls'],
      ] as const) {
        pattern.lastIndex = 0
        while ((m = pattern.exec(sql)) !== null) {
          const schema = m[1] ? unquote(m[1]) : 'public'
          const table = unquote(m[2]!)
          events.push({ kind, schema, table, file: file.path, scope, at: m.index, line: lineNumberAt(sqlLines, m.index) })
        }
      }

      RENAME_TABLE.lastIndex = 0
      while ((m = RENAME_TABLE.exec(sql)) !== null) {
        const schema = m[1] ? unquote(m[1]) : 'public'
        events.push({
          kind: 'rename',
          schema,
          table: unquote(m[2]!),
          renamedTo: unquote(m[3]!),
          file: file.path,
          scope,
          at: m.index,
          line: lineNumberAt(sqlLines, m.index),
        })
      }

      // 策略按迁移顺序重放，删除和修改会改变最终状态；存储模式中的策略同样需要检查。
      for (const [pattern, kind] of [
        [CREATE_POLICY, 'policy'],
        [DROP_POLICY, 'policy-drop'],
        [ALTER_POLICY, 'policy-alter'],
      ] as const) {
        pattern.lastIndex = 0
        while ((m = pattern.exec(sql)) !== null) {
          const end = statementEnd(sql, m.index)
          events.push({
            kind,
            policy: identAt(file.content, m, 1)!,
            schema: m[2] ? unquote(m[2]) : 'public',
            table: unquote(m[3]!),
            ...(kind === 'policy-drop' ? {} : { clauses: policyClauses(sql, file.content, m.index + m[0].length, end) }),
            file: file.path,
            scope,
            at: m.index,
            line: lineNumberAt(sqlLines, m.index),
          })
        }
      }

      for (const bucket of bucketDeclarations(sql, file.content)) {
        events.push({
          kind: 'bucket', bucket: { id: bucket.id, public: bucket.public }, schema: 'storage', table: 'buckets',
          file: file.path, scope, at: bucket.at, line: lineNumberAt(sqlLines, bucket.at),
        })
      }
    }

    // 同一文件内按语句出现顺序重放。
    const fileOrder = new Map(sqlFiles.map((f, i) => [f.path, i]))
    events.sort((a, b) => (fileOrder.get(a.file)! - fileOrder.get(b.file)!) || a.at - b.at)

    /** 重放结束时仍存在的策略。 */
    interface LivePolicy {
      name: string
      scope: string
      schema: string
      table: string
      file: string
      line: number
      restrictive: boolean
      command: PolicyCommand
      roles: string[]
      using?: string
      check?: string
    }

    /** 重放结束时仍存在的表及其安全状态。 */
    interface LiveTable {
      schema: string
      table: string
      file: string
      line: number
      rls: boolean
    }
    const live = new Map<string, LiveTable>()
    // 使用序列化元组作键，避免路径和标识符造成分隔冲突。
    const keyOf = (scope: string, schema: string, table: string): string =>
      JSON.stringify([scope, schema, table])

    /** 重放结束时仍存在的策略；键含所属表，表改名或删除时随之迁移或移除。 */
    const policies = new Map<string, LivePolicy>()
    const policyKey = (scope: string, schema: string, table: string, name: string): string =>
      JSON.stringify([scope, schema, table, name])
    // 按表索引策略，删表和改表名时不遍历全部策略。
    const byTable = new Map<string, Set<string>>()
    const setPolicy = (k: string, p: LivePolicy): void => {
      policies.set(k, p)
      const tableKey = keyOf(p.scope, p.schema, p.table)
      const set = byTable.get(tableKey) ?? new Set<string>()
      set.add(k)
      byTable.set(tableKey, set)
    }
    const deletePolicy = (k: string): void => {
      const p = policies.get(k)
      if (!p) return
      policies.delete(k)
      byTable.get(keyOf(p.scope, p.schema, p.table))?.delete(k)
    }
    const policiesOn = (key: string): [string, LivePolicy][] =>
      [...(byTable.get(key) ?? [])].map((k) => [k, policies.get(k)!])
    /** 存储桶的最终公开状态，键为作用域和桶名。 */
    const buckets = new Map<string, { public: boolean; file: string; line: number }>()

    for (const ev of events) {
      // 作用域隔离不同数据库及示例迁移。
      const scope = ev.scope
      const key = keyOf(scope, ev.schema, ev.table)
      if (ev.kind === 'create') {
        // 幂等建表不应覆盖已存在表的安全状态。
        if (ev.idempotent && live.has(key)) continue
        live.set(key, { schema: ev.schema, table: ev.table, file: ev.file, line: ev.line, rls: false })
      } else if (ev.kind === 'drop') {
        live.delete(key)
        for (const [k] of policiesOn(key)) deletePolicy(k)
      } else if (ev.kind === 'rename') {
        // 重命名时迁移表名、安全状态和表上的策略。
        const cur = live.get(key)
        if (cur) {
          live.delete(key)
          live.set(keyOf(scope, ev.schema, ev.renamedTo!), { ...cur, table: ev.renamedTo! })
        }
        for (const [k, p] of policiesOn(key)) {
          deletePolicy(k)
          setPolicy(policyKey(scope, ev.schema, ev.renamedTo!, p.name), { ...p, table: ev.renamedTo! })
        }
      } else if (ev.kind === 'enable-rls' || ev.kind === 'disable-rls') {
        const cur = live.get(key)
        if (cur) cur.rls = ev.kind === 'enable-rls'
      } else if (ev.kind === 'policy') {
        const c = ev.clauses ?? {}
        setPolicy(policyKey(scope, ev.schema, ev.table, ev.policy!), {
          name: ev.policy!, scope, schema: ev.schema, table: ev.table, file: ev.file, line: ev.line,
          restrictive: c.restrictive ?? false, command: c.command ?? 'all', roles: c.roles ?? ['public'],
          ...(c.using === undefined ? {} : { using: c.using }), ...(c.check === undefined ? {} : { check: c.check }),
        })
      } else if (ev.kind === 'policy-drop') {
        deletePolicy(policyKey(scope, ev.schema, ev.table, ev.policy!))
      } else if (ev.kind === 'policy-alter') {
        // alter policy 只能改角色、表达式或名称；命令和宽松/限制类型不可修改。
        const k = policyKey(scope, ev.schema, ev.table, ev.policy!)
        const cur = policies.get(k)
        const c = ev.clauses ?? {}
        if (cur) {
          const next: LivePolicy = {
            ...cur, ...(c.roles ? { roles: c.roles } : {}),
            ...(c.using === undefined ? {} : { using: c.using }), ...(c.check === undefined ? {} : { check: c.check }),
          }
          deletePolicy(k)
          const name = c.renamedTo ?? cur.name
          setPolicy(policyKey(scope, ev.schema, ev.table, name), { ...next, name })
        }
      } else if (ev.kind === 'bucket') {
        buckets.set(JSON.stringify([scope, ev.bucket!.id]), { public: ev.bucket!.public, file: ev.file, line: ev.line })
      }
    }

    // config.toml 中的公开存储桶；同名桶以迁移中的最终状态为准。
    for (const file of ctx.files) {
      if (!/(?:^|\/)supabase\/config\.toml$/.test(file.path)) continue
      const projectScope = projectScopeOf(file.path, projectScopes)
      if (!activeScopes.has(projectScope)) continue
      const scope = replayScopeOf(file, projectScope)
      for (const bucket of configPublicBuckets(file.content)) {
        const k = JSON.stringify([scope, bucket.id])
        if (!buckets.has(k)) buckets.set(k, { public: true, file: file.path, line: bucket.line })
      }
    }

    const findings: Finding[] = []
    /** 超过上限而未报告的表数。 */
    let unreported = 0

    for (const entry of live.values()) {
      if (entry.rls) continue
      // 限制结果规模并记录超限状态。
      if (findings.length >= MAX_FINDINGS_PER_FILE) {
        unreported++
        continue
      }
      findings.push({
        ruleId: 'supabase/rls-not-enabled',
        severity: 'P1',
        confidence: 'certain',
        title: `Table "${entry.table}" has no Row Level Security in your migrations`,
        file: entry.file,
        line: entry.line,
        excerpt: null,
        why: [
          `Supabase's browser clients use public identifiers. For exposed tables, database grants and ` +
            `Row Level Security determine which operations and rows a caller can access.`,
          `After replaying the scanned migrations, the final recorded state of ${renderIdent(entry.table)} does not ` +
            `have RLS enabled. It may never have been enabled or may have been disabled by a later migration. ` +
            `Without RLS, any access granted to the caller is not restricted by row policies.`,
          `If you enabled RLS from the Supabase dashboard instead, this file simply cannot show it. ` +
            `Check the Authentication -> Policies page to confirm.`,
        ],
        fix: [
          `Add a migration enabling it: ALTER TABLE ${renderIdent(entry.schema)}.${renderIdent(entry.table)} ENABLE ROW LEVEL SECURITY;`,
          `Enabling RLS with no policies blocks all access, which will look like your app breaking. Add the policies you need alongside it — usually one letting users read their own rows, e.g. USING (auth.uid() = user_id).`,
          `Keep this in a migration rather than only in the dashboard, so the rule travels with your code.`,
        ],
        humanOnly: [
          `Check the real state first: open Table Editor in the Supabase dashboard and look for the "RLS disabled" badge on "${entry.table}". The repository cannot tell you whether RLS was turned on there.`,
          `If this table has been live without RLS, assume its contents have already been read.`,
        ],
      })
    }

    if (unreported > 0) {
      ctx.reportIncomplete(
        'supabase/rls-not-enabled',
        `${unreported} further ${unreported === 1 ? 'table has' : 'tables have'} no Row Level Security ` +
          `in your migrations beyond the ${MAX_FINDINGS_PER_FILE} listed; they were not reported individually`,
      )
    }

    findings.push(...policyFindings(ctx, [...policies.values()], live, keyOf, buckets))
    return findings
  },
}

/** 这些角色本身绕过行级安全，授予它们的恒真策略不扩大访问。 */
const PRIVILEGED_ROLES = new Set(['service_role', 'postgres', 'supabase_admin'])

interface PolicyView {
  name: string
  scope: string
  schema: string
  table: string
  file: string
  line: number
  restrictive: boolean
  command: PolicyCommand
  roles: string[]
  using?: string
  check?: string
}

/** 描述策略适用的调用者。 */
function audienceOf(roles: string[]): string {
  if (roles.includes('public') || roles.includes('anon')) return 'anyone, signed in or not,'
  if (roles.includes('authenticated')) return 'any signed-in user'
  return `the ${roles.join(', ')} role${roles.length === 1 ? '' : 's'}`
}

/**
 * 依据 Supabase 检查规则 0024 与 0025 报告过宽策略和可枚举的公开存储桶。
 * 表在迁移中未开启行级安全时策略不生效，该表已由 rls-not-enabled 报告，不再重复。
 */
function policyFindings(
  ctx: ScanContext,
  policies: PolicyView[],
  live: Map<string, { rls: boolean }>,
  keyOf: (scope: string, schema: string, table: string) => string,
  buckets: Map<string, { public: boolean; file: string; line: number }>,
): Finding[] {
  const lines = new Map(ctx.files.map((file) => [file.path, file.lines]))
  const excerpt = (file: string, line: number): string | null => lines.get(file)?.[line - 1]?.trim() ?? null
  const findings: Finding[] = []
  let unreported = 0
  const push = (finding: Finding): void => {
    if (findings.length >= MAX_FINDINGS_PER_FILE) unreported++
    else findings.push(finding)
  }
  // 按作用域汇总公开存储桶，每条策略只查本作用域。
  const publicBuckets = new Map<string, string[]>()
  for (const [key, bucket] of buckets) {
    if (!bucket.public) continue
    const [scope, id] = JSON.parse(key) as [string, string]
    publicBuckets.set(scope, [...(publicBuckets.get(scope) ?? []), id])
  }

  for (const p of policies) {
    if (p.restrictive || p.roles.every((role) => PRIVILEGED_ROLES.has(role))) continue
    if (live.get(keyOf(p.scope, p.schema, p.table))?.rls === false) continue
    const table = `${renderIdent(p.schema)}.${renderIdent(p.table)}`
    const audience = audienceOf(p.roles)

    // 可枚举的公开存储桶：条件为 true 或仅按桶名筛选的读取策略。
    if (p.schema === 'storage' && p.table === 'objects' && (p.command === 'select' || p.command === 'all') && p.using !== undefined) {
      const onlyBucket = bucketOnlyCondition(p.using)
      const everyBucket = isAlwaysTrue(p.using)
      const listable = (publicBuckets.get(p.scope) ?? []).filter((id) => everyBucket || onlyBucket === id)
      for (const id of listable) {
        push({
          ruleId: 'supabase/public-bucket-listing',
          severity: 'P2',
          confidence: 'certain',
          title: `Policy "${p.name}" lets ${audience} list every file in the public "${id}" bucket`,
          file: p.file,
          line: p.line,
          excerpt: excerpt(p.file, p.line),
          why: [
            `Files in a public bucket can already be downloaded by anyone who has their URL, without any policy. ` +
              `This SELECT policy on storage.objects adds something else: it lets callers list the bucket's contents.`,
            `Listing reveals every file name, including files uploaded by other users that were only meant to be ` +
              `reachable by someone who already had the link.`,
          ],
          fix: [
            `If the app only serves files by URL, drop this policy: public object URLs keep working without it.`,
            `If the app really needs listing, make the bucket private and scope the policy to the owner, e.g. USING (bucket_id = '${id}' AND owner_id = (select auth.uid()::text)).`,
          ],
        })
      }
    }

    const usingTrue = p.using !== undefined && isAlwaysTrue(p.using)
    const checkTrue = p.check !== undefined && isAlwaysTrue(p.check)
    const opensRows = usingTrue && p.command !== 'insert'
    const opensWrites = checkTrue && (p.command === 'insert' || p.command === 'update' || p.command === 'all')
    if (!opensRows && !opensWrites) continue

    // 修改或删除任意行很少是设计；公开读取和公开表单常见，保留为疑似。
    const modifiesAny = usingTrue && (p.command === 'update' || p.command === 'delete' || p.command === 'all')
    const verb = { all: 'read, change and delete', select: 'read', insert: 'insert any data into', update: 'change', delete: 'delete' }[p.command]
    push({
      ruleId: 'supabase/permissive-policy',
      severity: 'P1',
      confidence: modifiesAny ? 'certain' : 'likely',
      title: opensRows
        ? `Policy "${p.name}" lets ${audience} ${verb} every row of ${table}`
        : `Policy "${p.name}" lets ${audience} write any values into ${table}`,
      file: p.file,
      line: p.line,
      excerpt: excerpt(p.file, p.line),
      why: [
        `Row Level Security is on, but this policy's condition is always true, so it does not restrict rows at all. ` +
          `Permissive policies are combined with OR: one always-true policy opens the table for its command ` +
          `whatever the other policies say.`,
        ...(p.command === 'select' || p.command === 'insert'
          ? [`Public read-only tables and open forms can be intentional. If this one is, keep it and consider ` +
              `restricting the columns the API exposes.`]
          : []),
      ],
      fix: [
        `Replace the condition with one that ties each row to its owner, e.g. USING ((select auth.uid()) = user_id)` +
          `${p.command === 'insert' || p.command === 'update' || p.command === 'all' ? ' and WITH CHECK ((select auth.uid()) = user_id)' : ''}.`,
        `If a broad policy is needed as a base, add an AS RESTRICTIVE policy alongside it to limit which rows it reaches.`,
        `Keep the change in a migration, so the rule travels with your code.`,
      ],
      humanOnly: [
        `Check the policy in the Supabase dashboard (Authentication -> Policies); a policy changed there is not visible in the repository.`,
      ],
    })
  }

  if (unreported > 0) {
    ctx.reportIncomplete('supabase/permissive-policy',
      `${unreported} further permissive ${unreported === 1 ? 'policy was' : 'policies were'} not reported individually`)
  }
  return findings
}
