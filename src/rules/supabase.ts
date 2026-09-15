/** 按迁移顺序重放表结构，检查 Supabase 表最终是否启用行级安全。 */

import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { isSupabaseProject } from './framework.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'
import { blank, codesOf, stringOf } from '../mask.js'

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
  kind: 'create' | 'drop' | 'enable-rls' | 'disable-rls' | 'rename'
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
    }

    // 同一文件内按语句出现顺序重放。
    const fileOrder = new Map(sqlFiles.map((f, i) => [f.path, i]))
    events.sort((a, b) => (fileOrder.get(a.file)! - fileOrder.get(b.file)!) || a.at - b.at)

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
      } else if (ev.kind === 'rename') {
        // 重命名时迁移表名和安全状态。
        const cur = live.get(key)
        if (cur) {
          live.delete(key)
          live.set(keyOf(scope, ev.schema, ev.renamedTo!), { ...cur, table: ev.renamedTo! })
        }
      } else {
        const cur = live.get(key)
        if (cur) cur.rls = ev.kind === 'enable-rls'
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
          `Supabase exposes your database to the browser directly, and the anon key that reaches it is ` +
            `public by design — it ships inside your frontend. Row Level Security is the only thing that ` +
            `decides who can read or write a row.`,
          `No "ALTER TABLE ${renderIdent(entry.table)} ENABLE ROW LEVEL SECURITY" appears anywhere in your SQL, and new ` +
            `tables do not get it by default. If that is the real state, anyone who visits your site can list ` +
            `this entire table with a single request — and depending on your policies, write to it too.`,
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

    return findings
  },
}
