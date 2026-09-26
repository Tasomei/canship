/**
 * 解析 Supabase 迁移中的行级安全策略与存储桶声明。结构在屏蔽注释和字符串的 SQL 上识别，
 * 字面量从原文按相同偏移读取；判断标准取自 Supabase 数据库检查规则 0024 与 0025。
 */

/** 单条语句的最大读取长度，避免缺少分号的文件使每次匹配都读到文件末尾。 */
const MAX_STATEMENT = 4000

/** 从起点读到分号为止的语句范围。 */
export function statementEnd(masked: string, from: number): number {
  const semicolon = masked.indexOf(';', from)
  const limit = Math.min(masked.length, from + MAX_STATEMENT)
  return semicolon === -1 || semicolon > limit ? limit : semicolon
}

/** 从左括号起读取成对括号内的范围；屏蔽后的文本中字符串里的括号已不存在。 */
function parenthesized(masked: string, open: number, end: number): { from: number; to: number } | null {
  let depth = 0
  for (let i = open; i < end; i++) {
    if (masked[i] === '(') depth++
    else if (masked[i] === ')' && --depth === 0) return { from: open + 1, to: i }
  }
  return null
}

/** 移除注释、空白与外层括号并转为小写，供恒真判断使用。 */
function normalizeExpression(text: string): string {
  let out = text.replace(/--[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\s+/g, '').toLowerCase()
  while (out.startsWith('(') && out.endsWith(')') && parenthesized(out, 0, out.length)?.to === out.length - 1) {
    out = out.slice(1, -1)
  }
  return out
}

/** 恒为真的条件：true、相同数字相等、相同字符串相等。 */
export function isAlwaysTrue(expression: string): boolean {
  const e = normalizeExpression(expression)
  if (e === 'true') return true
  const numbers = /^(\d+)=(\d+)$/.exec(e)
  if (numbers) return numbers[1] === numbers[2]
  const strings = /^'([^']*)'='([^']*)'$/.exec(e)
  return strings !== null && strings[1] === strings[2]
}

/** 条件仅按存储桶筛选，如 bucket_id = 'avatars'；返回桶名。 */
export function bucketOnlyCondition(expression: string): string | null {
  return /^(?:(?:storage\.)?objects\.)?bucket_id='([^']*)'$/.exec(normalizeExpression(expression))?.[1] ?? null
}

/** 未引用标识符转为小写，引用标识符保留大小写。 */
export function unquoteIdent(ident: string): string {
  const quoted = /^"(.*)"$/.exec(ident)
  return quoted ? quoted[1]!.replace(/""/g, '"') : ident.toLowerCase()
}

const IDENT = String.raw`(?:"[^"]+"|[a-z_][\w$]*)`
const TARGET = String.raw`(${IDENT})\s+on\s+(?:(${IDENT})\s*\.\s*)?(${IDENT})`

// d 标志提供捕获组位置：屏蔽后的引用标识符内空白已被替换，名称须按位置从原文读取。
export const CREATE_POLICY = new RegExp(String.raw`\bcreate\s+policy\s+${TARGET}`, 'gid')
export const DROP_POLICY = new RegExp(String.raw`\bdrop\s+policy\s+(?:if\s+exists\s+)?${TARGET}`, 'gid')
export const ALTER_POLICY = new RegExp(String.raw`\balter\s+policy\s+${TARGET}`, 'gid')

/** 按匹配位置从原文读取标识符。 */
export function identAt(source: string, match: RegExpExecArray, group: number): string | undefined {
  const range = match.indices?.[group]
  return range ? unquoteIdent(source.slice(range[0], range[1])) : undefined
}

export type PolicyCommand = 'all' | 'select' | 'insert' | 'update' | 'delete'

/** 策略子句；alter policy 只包含被修改的部分。 */
export interface PolicyClauses {
  restrictive?: boolean
  command?: PolicyCommand
  roles?: string[]
  using?: string
  check?: string
  renamedTo?: string
}

/**
 * 读取 on 表名之后的子句。子句顺序固定：AS、FOR、TO、USING、WITH CHECK，
 * 因此角色列表只在第一个 USING 或 WITH CHECK 之前查找。
 */
export function policyClauses(masked: string, source: string, from: number, end: number): PolicyClauses {
  const text = masked.slice(from, end)
  const clauses: PolicyClauses = {}
  const firstExpression = text.search(/\busing\s*\(|\bwith\s+check\s*\(/i)
  const head = firstExpression === -1 ? text : text.slice(0, firstExpression)

  // alter policy ... rename to 只改名，其中的 to 不是角色子句。
  const rename = /\brename\s+to\s+("[^"]+"|[a-z_][\w$]*)/id.exec(head)
  if (rename) {
    const [start, stop] = rename.indices![1]!
    clauses.renamedTo = unquoteIdent(source.slice(from + start, from + stop))
    return clauses
  }
  const as = /\bas\s+(permissive|restrictive)\b/i.exec(head)
  if (as) clauses.restrictive = as[1]!.toLowerCase() === 'restrictive'
  const command = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(head)
  if (command) clauses.command = command[1]!.toLowerCase() as PolicyCommand
  const roles = /\bto\s+([\s\S]+)$/i.exec(head)
  if (roles) clauses.roles = roles[1]!.split(',').map((role) => unquoteIdent(role.trim())).filter(Boolean)

  for (const [key, pattern] of [['using', /\busing\s*\(/i], ['check', /\bwith\s+check\s*\(/i]] as const) {
    const at = text.search(pattern)
    if (at === -1) continue
    const open = from + at + text.slice(at).indexOf('(')
    const range = parenthesized(masked, open, end)
    if (range) clauses[key] = source.slice(range.from, range.to)
  }
  return clauses
}

/** 读取原文中的 SQL 字符串字面量值。 */
function literal(source: string): string | null {
  const m = /^\s*'((?:[^']|'')*)'/.exec(source)
  return m ? m[1]!.replace(/''/g, "'") : null
}

/** 按顶层逗号拆分括号内的值列表，返回各值在原文中的范围。 */
function topLevelValues(masked: string, from: number, to: number): { from: number; to: number }[] {
  const values: { from: number; to: number }[] = []
  let depth = 0
  let start = from
  for (let i = from; i < to; i++) {
    const ch = masked[i]
    if (ch === '(') depth++
    else if (ch === ')') depth--
    else if (ch === ',' && depth === 0) {
      values.push({ from: start, to: i })
      start = i + 1
    }
  }
  values.push({ from: start, to })
  return values
}

export interface BucketDeclaration {
  id: string
  public: boolean
  at: number
}

const INSERT_BUCKETS = /\binsert\s+into\s+storage\s*\.\s*buckets\s*\(([^()]{0,500})\)\s*values\s*/gi
const UPDATE_BUCKETS = /\bupdate\s+storage\s*\.\s*buckets\s+set\b/gi

/** SQL 中创建或修改存储桶公开状态的语句，按出现顺序返回。 */
export function bucketDeclarations(masked: string, source: string): BucketDeclaration[] {
  const found: BucketDeclaration[] = []
  let m: RegExpExecArray | null

  INSERT_BUCKETS.lastIndex = 0
  while ((m = INSERT_BUCKETS.exec(masked)) !== null) {
    const columns = m[1]!.split(',').map((c) => unquoteIdent(c.trim()))
    const publicIndex = columns.indexOf('public')
    const idIndex = columns.indexOf('id') !== -1 ? columns.indexOf('id') : columns.indexOf('name')
    const end = statementEnd(masked, m.index)
    let at = m.index + m[0].length
    // values 后可有多组元组。
    while (at < end) {
      while (at < end && /[\s,]/.test(masked[at]!)) at++
      if (masked[at] !== '(') break
      const tuple = parenthesized(masked, at, end)
      if (!tuple) break
      const values = topLevelValues(masked, tuple.from, tuple.to)
      const id = idIndex === -1 ? null : literal(source.slice(values[idIndex]?.from ?? 0, values[idIndex]?.to ?? 0))
      const isPublic = publicIndex !== -1 &&
        source.slice(values[publicIndex]?.from ?? 0, values[publicIndex]?.to ?? 0).trim().toLowerCase() === 'true'
      if (id !== null) found.push({ id, public: isPublic, at: m.index })
      at = tuple.to + 1
    }
    INSERT_BUCKETS.lastIndex = Math.max(INSERT_BUCKETS.lastIndex, end)
  }

  UPDATE_BUCKETS.lastIndex = 0
  while ((m = UPDATE_BUCKETS.exec(masked)) !== null) {
    const end = statementEnd(masked, m.index)
    const statement = masked.slice(m.index, end)
    const setPublic = /\bpublic\s*=\s*(true|false)\b/i.exec(statement)
    // 字符串已被屏蔽为空格，= 之后不能吞掉空白，否则会越过原文中的字面量。
    const where = /\bwhere\s+(?:id|name)\s*=/i.exec(statement)
    const id = where ? literal(source.slice(m.index + where.index + where[0].length, end)) : null
    if (setPublic && id !== null) found.push({ id, public: setPublic[1]!.toLowerCase() === 'true', at: m.index })
    UPDATE_BUCKETS.lastIndex = Math.max(UPDATE_BUCKETS.lastIndex, end)
  }
  return found.sort((a, b) => a.at - b.at)
}

/** supabase/config.toml 中声明为公开的存储桶。 */
export function configPublicBuckets(toml: string): { id: string; line: number }[] {
  const found: { id: string; line: number }[] = []
  let current: { id: string; line: number } | null = null
  toml.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.replace(/#.*$/, '').trim()
    const section = /^\[\s*storage\.buckets\.("?)([^"\]]+)\1\s*\]$/.exec(line)
    if (section) {
      current = { id: section[2]!, line: index + 1 }
      return
    }
    if (line.startsWith('[')) {
      current = null
      return
    }
    if (current && /^public\s*=\s*true$/i.test(line)) found.push(current)
  })
  return found
}
