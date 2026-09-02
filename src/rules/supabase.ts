/**
 * P1-5: Supabase tables created without Row Level Security.
 *
 * This is the single most consequential mistake in the Supabase ecosystem.
 * Supabase exposes your database to the browser through PostgREST, and the anon
 * key needed to reach it is public by design. The *only* thing standing between
 * a visitor and your data is Row Level Security. A table created without it is
 * readable — and often writable — by anyone who opens your site, no attack
 * required.
 *
 * New tables do not have RLS enabled by default, and AI assistants almost never
 * add it, because leaving it off is exactly what makes the code "work" during
 * development.
 *
 * Two design decisions worth knowing:
 *
 * 1. This is a ProjectRule, not a per-file rule. A table can be created in one
 *    migration and have RLS enabled in a later one, so the verdict can only be
 *    reached after reading every SQL file in the project. For the same reason
 *    the statements are replayed **in order** rather than counted: migrations
 *    are append-only, so a table created in one file and dropped three files
 *    later does not exist. Reading a real starter template produced exactly
 *    that false positive.
 *
 * 2. The finding is phrased as "not enabled *in your migrations*" rather than
 *    "not enabled". People routinely toggle RLS in the Supabase dashboard,
 *    which leaves no trace in the repository. Stating the observable fact keeps
 *    the report accurate and un-arguable, the same way the git history rule
 *    does.
 */

import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { isSupabaseProject } from './framework.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'
import { blank } from '../mask.js'

/** Schemas that are not reachable through the public PostgREST API */
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

/** One DDL statement, kept in source order so the schema can be replayed */
interface SqlEvent {
  kind: 'create' | 'drop' | 'enable-rls' | 'disable-rls' | 'rename'
  schema: string
  table: string
  file: string
  /** Which replay this statement belongs to — see replayScopeOf */
  scope: string
  /** Character offset within the file, for ordering statements inside one file */
  at: number
  line: number
  /** create only: whether it was CREATE TABLE IF NOT EXISTS */
  idempotent?: boolean
  /** rename only: the name the table takes from here on */
  renamedTo?: string
}

/**
 * Blank out everything in a SQL file that is not executable code, keeping the
 * length and the newlines so every character offset — and therefore every line
 * number — still points where it did.
 *
 * The previous version stripped comments but kept string literals verbatim, so
 * the DDL patterns read straight through them. That is a sentence of SQL away
 * from a hidden vulnerability:
 *
 *   CREATE TABLE public.live_data (id int);
 *   SELECT 'DROP TABLE public.live_data;';
 *
 * The text inside the quotes was taken for a real statement, the table was
 * removed from the replay, and canship reported nothing about a live table
 * with no RLS. The reverse works too: a CREATE TABLE inside a string or a
 * function body invents a table that does not exist and reports it.
 *
 * Masking rather than deleting matters as much as the lexing. Deleting would
 * shift every offset after it and quietly move findings to the wrong lines.
 *
 * Handled: line comments, block comments (which nest in Postgres), single
 * quoted strings with their doubled-quote escape, E'' strings with backslash
 * escapes, and dollar-quoted bodies. Double-quoted identifiers are stepped
 * over rather than masked — they name real tables.
 */
/** `DO $$ … $$` and `DO LANGUAGE plpgsql $$ … $$` — executed, not declared */
const IS_DO_BLOCK = /\bdo\s+(?:language\s+\w+\s+)?$/i

export function maskSqlNoise(sql: string): string {
  const out = sql.split('')
  // Offset-preserving blanking is the primitive every masker in the codebase
  // shares, and it had been written twice. Preserving offsets is the entire
  // reason masking is used instead of deleting, so it is the one piece that
  // must not exist in two copies free to drift.
  const erase = (from: number, to: number): void => blank(out, from, to)

  let i = 0
  while (i < sql.length) {
    const ch = sql[i]!
    const two = sql.slice(i, i + 2)

    if (two === '--') {
      const end = sql.indexOf('\n', i)
      erase(i, end === -1 ? sql.length : end)
      i = end === -1 ? sql.length : end
      continue
    }

    if (two === '/*') {
      // Postgres block comments nest, so a naive search for the first */ ends
      // one level too early and leaves the rest of the comment looking like code.
      let depth = 0
      let j = i
      while (j < sql.length) {
        const pair = sql.slice(j, j + 2)
        if (pair === '/*') {
          depth++
          j += 2
        } else if (pair === '*/') {
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

    if (ch === "'") {
      // E'...' takes backslash escapes; a plain '...' only doubles the quote.
      const escaped = i > 0 && /[Ee]/.test(sql[i - 1] ?? '') && !/[A-Za-z0-9_]/.test(sql[i - 2] ?? '')
      let j = i + 1
      while (j < sql.length) {
        if (escaped && sql[j] === '\\') {
          j += 2
          continue
        }
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") {
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

    if (ch === '"') {
      // A quoted identifier is a table name, not noise, so its text survives —
      // but only after the spaces inside it are turned into underscores.
      //
      // SQL keywords need whitespace between them; identifiers do not care.
      // So `"DROP TABLE public.orders;"` becomes `"DROP_TABLE_public.orders;"`,
      // which no DDL pattern matches, while `"My Table"` becomes `"My_Table"`
      // and stays a distinct, stable name. Leaving the text alone meant a legal
      // Postgres column name could contain a DROP statement that the replay
      // then obeyed, retiring the real table it was declared in.
      let j = i + 1
      while (j < sql.length && sql[j] !== '"') {
        if (/\s/.test(out[j] ?? '') && out[j] !== '\n') out[j] = '_'
        j++
      }
      i = j + 1
      continue
    }

    if (ch === '$') {
      // $$ … $$ or $tag$ … $tag$. A bare $1 placeholder does not match,
      // because the pattern requires the closing dollar.
      const tag = /^\$(?:[A-Za-z_]\w*)?\$/.exec(sql.slice(i))?.[0]
      if (tag) {
        const close = sql.indexOf(tag, i + tag.length)
        const end = close === -1 ? sql.length : close + tag.length
        // A function body is a definition; a DO block is a statement that runs
        // the moment the migration does. Masking both meant
        // `DO $$ BEGIN CREATE TABLE … END $$;` created a real table that the
        // replay never saw — and an unprotected one at that.
        if (!IS_DO_BLOCK.test(sql.slice(0, i))) erase(i, end)
        i = end
        continue
      }
    }

    i++
  }

  return out.join('')
}

/**
 * An SQL identifier as Postgres itself understands it.
 *
 * Unquoted names are folded to lower case by the server, so `CREATE TABLE Foo`
 * and `ALTER TABLE foo` are the same table. A quoted name is not folded and
 * keeps every character: `"userProfiles"` and `userprofiles` are two different
 * tables.
 *
 * Folding both was one line shorter and wrong in both directions. It made two
 * distinct tables compare equal, so RLS enabled on one could vouch for the
 * other; and it destroyed the only spelling that works in the fix, which this
 * rule hands over as SQL to run. A Prisma or Drizzle schema of camelCase tables
 * was told to run `ALTER TABLE public.userprofiles`, which fails against a
 * table called `userProfiles`, and `public.order` — from a table created as
 * `"Order"` — does not parse at all.
 */
function unquote(ident: string): string {
  const quoted = /^"(.*)"$/.exec(ident)
  return quoted ? quoted[1]! : ident.toLowerCase()
}

/**
 * The same identifier spelled so SQL accepts it back.
 *
 * Anything that is not already a bare lower-case identifier has to be quoted
 * for the fix to run at all — a capital, a space, a hyphen, or a name that
 * happens to be a reserved word.
 */
function renderIdent(name: string): string {
  return /^[a-z_][a-z0-9_$]*$/.test(name) ? name : `"${name.replace(/"/g, '""')}"`
}

/**
 * Split the table list of a DROP TABLE statement.
 * Handles `public.items`, bare `items`, quoted identifiers, and the trailing
 * CASCADE / RESTRICT that Supabase migrations usually carry.
 */
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

/**
 * DROP TABLE, including the comma-separated form. Everything up to the
 * statement terminator is captured and split, so `DROP TABLE a, b CASCADE;`
 * removes both.
 */
const DROP_TABLE = /\bdrop\s+table\s+(?:if\s+exists\s+)?([^;]+)/gi

/** The `[IF EXISTS] [ONLY] [schema.]table` preamble shared by every ALTER TABLE form */
const ALTER_TARGET = String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:("[^"]+"|[a-z_][\w$]*)\s*\.\s*)?("[^"]+"|[a-z_][\w$]*)`

const ENABLE_RLS = new RegExp(`${ALTER_TARGET}\\s+enable\\s+row\\s+level\\s+security`, 'gi')

/**
 * RLS being turned back off.
 *
 * Without this, a migration that enables RLS and a later one that disables it
 * leave the replay believing the table is protected — the exact state where
 * silence is most dangerous, because someone did think about RLS here and then
 * changed their mind.
 */
const DISABLE_RLS = new RegExp(`${ALTER_TARGET}\\s+disable\\s+row\\s+level\\s+security`, 'gi')

/**
 * A table changing its name. The protection follows the table, so the replay
 * has to move the entry rather than lose track of it and report the old name
 * (which no longer exists) while ignoring the new one (which does).
 */
const RENAME_TABLE = new RegExp(
  `${ALTER_TARGET}\\s+rename\\s+to\\s+("[^"]+"|[a-z_][\\w$]*)`,
  'gi',
)

/**
 * Whether a file is SQL that is actually part of the schema.
 *
 * The nesting rule is not pedantry. Supabase applies `supabase/migrations/*.sql`
 * and nothing below it, so a subdirectory is where people park migrations they
 * have replaced — and a real project showed what happens when those are
 * replayed anyway. Its `old_migrations/` folder held a superseded file ending
 * in `DISABLE ROW LEVEL SECURITY`, that folder sorted last, and five tables
 * that the live schema protects were reported as wide open.
 *
 * Files under a migrations directory therefore have to sit directly in it.
 * Anywhere else, any .sql file still counts — plenty of projects keep a plain
 * schema.sql and never use a migrations folder at all.
 */
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

/**
 * The project boundaries the repository layout states outright. A package.json,
 * a supabase/ directory, the usual workspace folders and a standalone fixture
 * must not answer for one another about the state of a different database.
 */
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

/** A file belongs to the deepest boundary that contains it */
function projectScopeOf(path: string, scopes: string[]): string {
  let best = ''
  for (const scope of scopes) {
    if (scope.length > best.length && insideScope(path, scope)) best = scope
  }
  return best
}

/** Ask the existing Supabase evidence check inside one boundary rather than across the monorepo */
function isActiveSupabaseScope(ctx: ScanContext, files: ScanFile[], scope: string): boolean {
  const rebased = files.map((file) =>
    scope === '' ? file : { ...file, path: file.path.slice(scope.length + 1) },
  )
  return isSupabaseProject({ ...ctx, files: rebased })
}

/**
 * Fixtures and teaching SQL replay in a scope of their own.
 *
 * They are scanned — the engine holds whatever they produce at lower
 * confidence, which is the point of not skipping them. But *replaying* them
 * beside the real schema is a different thing entirely, and it was letting them
 * rewrite it: a one-line `ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY;`
 * under `tests/`, sorting after the root `schema.sql` that correctly enabled
 * it, produced a `certain` P1 against the real file. Neither file is under a
 * `supabase/` tree, so both scoped to '' and shared one replay.
 *
 * Confidence cannot repair that. The finding is attributed to the real
 * `schema.sql`, which is not example context, so the engine's downgrade never
 * touches it — a rule whose *inputs* are cross-contaminated produces a wrong
 * answer at full confidence. The separation has to happen here, before the
 * replay, not afterwards.
 */
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

    // Sorted by path so the replay follows migration order — Supabase
    // migrations are timestamp-prefixed, so lexicographic order is chronological.
    const sqlFiles = ctx.files
      // A plain PostgreSQL package stays out of this rule even when it shares a
      // repository with a Supabase app.
      .filter(
        (file) =>
          isSqlFile(file) && activeScopes.has(projectScopeOf(file.path, projectScopes)),
      )
      .sort((a, b) => a.path.localeCompare(b.path))

    for (const file of sqlFiles) {
      const sql = maskSqlNoise(file.content)
      const scope = replayScopeOf(file, projectScopeOf(file.path, projectScopes))
      // Built once per file rather than counted per match. See offsets.ts.
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

    // Statements inside one file also have to replay in the order they appear.
    const fileOrder = new Map(sqlFiles.map((f, i) => [f.path, i]))
    events.sort((a, b) => (fileOrder.get(a.file)! - fileOrder.get(b.file)!) || a.at - b.at)

    /** Tables that exist at the end of the replay, and whether RLS was turned on */
    interface LiveTable {
      schema: string
      table: string
      file: string
      line: number
      rls: boolean
    }
    const live = new Map<string, LiveTable>()
    // An array, stringified, so no separator character has to be trusted not to
    // appear in a path or a table name.
    const keyOf = (scope: string, schema: string, table: string): string =>
      JSON.stringify([scope, schema, table])

    for (const ev of events) {
      // The scope is what stops one database's migrations from answering for
      // another's, and a fixture's from answering for the real one.
      const scope = ev.scope
      const key = keyOf(scope, ev.schema, ev.table)
      if (ev.kind === 'create') {
        // CREATE TABLE IF NOT EXISTS against a table that already exists is a
        // no-op. Treating it as a fresh table would discard the RLS that an
        // earlier migration turned on.
        if (ev.idempotent && live.has(key)) continue
        live.set(key, { schema: ev.schema, table: ev.table, file: ev.file, line: ev.line, rls: false })
      } else if (ev.kind === 'drop') {
        live.delete(key)
      } else if (ev.kind === 'rename') {
        // Follow the table to its new name, protection and all. Losing track
        // here would report a name that no longer exists and ignore the one
        // that does.
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
    /** Unprotected tables found but not reported, once the ceiling is reached */
    let unreported = 0

    for (const entry of live.values()) {
      if (entry.rls) continue
      // The same ceiling secrets.ts keeps, for the same reason: each finding
      // carries several paragraphs, so a machine-generated schema turns a
      // 300 KB input into megabytes of report. Counted rather than dropped, so
      // the number still reaches the reader below.
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
