/** 请求输入进入 SQL 文本或 shell 命令：各框架入口、传播方式、安全写法与置信度。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding, ScanResult } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-injection-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}

async function run(files: Record<string, string>): Promise<{ result: ScanResult; hits: Finding[] }> {
  const result = await scan(project(files))
  return { result, hits: result.findings.filter(f => f.ruleId.startsWith('injection/')) }
}

/** 断言结果的规则、行号与置信度，便于一次核对多条。 */
async function expectHits(files: Record<string, string>, expected: Array<[string, number, Finding['confidence']]>): Promise<Finding[]> {
  const { hits } = await run(files)
  assert.deepEqual(hits.map(f => [f.ruleId, f.line, f.confidence]), expected)
  return hits
}

const route = (body: string): Record<string, string> => ({ 'app/api/items/route.ts': body })

describe('SQL built from request input', () => {
  test('Prisma $queryRawUnsafe with an interpolated search parameter is certain', async () => {
    const [hit] = await expectHits(route(`import { prisma } from '@/lib/db'
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const name = searchParams.get('name')
  const rows = await prisma.$queryRawUnsafe(\`SELECT * FROM users WHERE name = '\${name}'\`)
  return Response.json(rows)
}`), [['injection/sql', 5, 'certain']])
    assert.equal(hit!.severity, 'P1')
    assert.match(hit!.title, /^\/api\/items builds a SQL query from request input$/)
    assert.match(hit!.why[0]!, /read on line 3/)
    assert.match(hit!.excerpt!, /\$queryRawUnsafe/)
  })

  test('tagged templates and placeholders keep values out of the SQL text', async () => {
    await expectHits(route(`export async function POST(req: Request) {
  const { id, name } = await req.json()
  await prisma.$queryRaw\`SELECT * FROM users WHERE name = \${name}\`
  await prisma.$queryRawUnsafe('SELECT * FROM users WHERE id = $1', id)
  await db.execute(sql\`SELECT * FROM users WHERE id = \${id}\`)
  await pool.query('SELECT * FROM users WHERE id = $1', [id])
  await knex('users').whereRaw('id = ?', [id])
  await knex('users').where({ id })
  return new Response('ok')
}`), [])
  })

  test('a query assembled across several statements is followed through the variable', async () => {
    await expectHits({ 'pages/api/items.ts': `import { pool } from '../../lib/pg'
export default async function handler(req, res) {
  const { sort } = req.query
  let q = 'SELECT * FROM items'
  q += ' ORDER BY ' + sort
  const r = await pool.query(q)
  res.json(r.rows)
}` }, [['injection/sql', 6, 'certain']])
  })

  test('numbers and fixed choices stay clean; an unverified escape helper remains likely', async () => {
    await expectHits(route(`const COLUMNS = { newest: 'created_at', name: 'name' }
export async function GET(request) {
  const params = request.nextUrl.searchParams
  const dir = params.get('dir')
  const id = Number(params.get('id'))
  const sort = params.get('sort')
  const name = params.get('name')
  await pool.query(\`SELECT * FROM items ORDER BY created_at \${dir === 'asc' ? 'ASC' : 'DESC'}\`)
  await pool.query(\`SELECT * FROM items WHERE id = \${id}\`)
  await pool.query(\`SELECT * FROM items ORDER BY \${COLUMNS[sort] ?? 'id'}\`)
  await pool.query(\`SELECT * FROM items WHERE name = \${mysql.escape(name)}\`)
  return new Response('ok')
}`), [['injection/sql', 11, 'likely']])
  })

  test('a content check or an intermediate call lowers the finding to likely', async () => {
    await expectHits(route(`export async function GET(request) {
  const id = request.nextUrl.searchParams.get('id')
  if (!/^\\d+$/.test(id)) return new Response('bad', { status: 400 })
  return Response.json(await pool.query(\`SELECT * FROM items WHERE id = \${id}\`))
}
export async function POST(req) {
  const body = schema.parse(await req.json())
  return Response.json(await prisma.$executeRawUnsafe(\`DELETE FROM t WHERE id = \${body.id}\`))
}`), [['injection/sql', 4, 'likely'], ['injection/sql', 8, 'likely']])
  })

  test('a presence check alone does not validate the value', async () => {
    await expectHits(route(`export async function GET(req) {
  const id = req.nextUrl.searchParams.get('id')
  if (!id) return new Response('missing', { status: 400 })
  return Response.json(await db.query('SELECT * FROM t WHERE id = ' + id))
}`), [['injection/sql', 4, 'certain']])
  })

  test('driver calls whose text is not SQL are ignored', async () => {
    await expectHits(route(`export async function GET(req) {
  const id = req.nextUrl.searchParams.get('id')
  const cached = await cache.get(\`user:\${id}\`)
  const match = /a(b)/.exec(\`\${id}\`)
  return Response.json({ cached, match })
}`), [])
  })

  test('Server Function arguments come from the client', async () => {
    await expectHits({ 'app/actions.ts': `'use server'
export async function search(formData: FormData) {
  const term = formData.get('term')
  return db.execute(sql.raw(\`SELECT * FROM posts WHERE title LIKE '%\${term}%'\`))
}
export async function byId(id: string) {
  return prisma.$queryRawUnsafe(\`SELECT * FROM posts WHERE id = \${id}\`)
}
async function helper(id: string) {
  return prisma.$queryRawUnsafe(\`SELECT * FROM posts WHERE id = \${id}\`)
}` }, [['injection/sql', 4, 'certain'], ['injection/sql', 7, 'certain']])
  })

  test('SvelteKit endpoints and form actions are checked, page loads are not', async () => {
    await expectHits({
      'src/routes/api/+server.ts': `export async function GET({ url }) {
  const col = url.searchParams.get('col')
  return json(await knex('t').whereRaw(\`\${col} = 1\`))
}`,
      'src/routes/posts/+page.server.ts': `export async function load({ url }) {
  return { rows: await pool.query(\`SELECT * FROM t WHERE a = \${url.searchParams.get('a')}\`) }
}
export const actions = {
  default: async ({ request }) => {
    const data = await request.formData()
    await pool.query(\`DELETE FROM t WHERE id = \${data.get('id')}\`)
  },
}`,
    }, [['injection/sql', 3, 'certain'], ['injection/sql', 7, 'certain']])
  })

  test('Nuxt, Remix, and Astro request readers are recognised', async () => {
    await expectHits({
      'server/api/items.get.ts': `export default defineEventHandler(async (event) => {
  const { q } = getQuery(event)
  return db.query(\`SELECT * FROM items WHERE name LIKE '%\${q}%'\`)
})`,
      'app/routes/items.$id.tsx': `export async function loader({ params }) {
  return json(await db.query(\`SELECT * FROM items WHERE id = \${params.id}\`))
}`,
      'src/pages/api/items.ts': `export async function GET(context) {
  const id = context.url.searchParams.get('id')
  return new Response(JSON.stringify(await db.query(\`SELECT * FROM t WHERE id = \${id}\`)))
}`,
    }, [['injection/sql', 2, 'certain'], ['injection/sql', 3, 'certain'], ['injection/sql', 3, 'certain']])
  })

  test('query-builder conditions built from input are reported, structured conditions are not', async () => {
    await expectHits(route(`export async function GET(req) {
  const id = req.nextUrl.searchParams.get('id')
  await repo.createQueryBuilder('user').where(\`user.id = \${id}\`).getMany()
  await repo.createQueryBuilder('user').where('user.id = :id', { id }).getMany()
  return new Response('ok')
}`), [['injection/sql', 3, 'certain']])
  })

  test('code outside request handlers is not traced', async () => {
    await expectHits({
      'lib/db.ts': `export async function find(req) {
  const { id } = req.query
  return pool.query(\`SELECT * FROM t WHERE id = \${id}\`)
}`,
      'app/api/items/route.ts': `function byName(name: string) {
  return pool.query(\`SELECT * FROM t WHERE name = '\${name}'\`)
}
export async function GET(request: Request) {
  return Response.json(await byName(new URL(request.url).searchParams.get('name')!))
}`,
    }, [])
  })
})

describe('shell commands built from request input', () => {
  test('promisified exec in a Nuxt handler is certain', async () => {
    const [hit] = await expectHits({ 'server/api/convert.post.ts': `import { exec } from 'node:child_process'
import { promisify } from 'node:util'
const run = promisify(exec)
export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  await run(\`convert \${body.file} out.png\`)
  return 'ok'
})` }, [['injection/command', 6, 'certain']])
    assert.match(hit!.title, /^\/api\/convert runs a shell command built from request input$/)
    assert.match(hit!.fix[0]!, /execFile or spawn with an argument array/)
  })

  test('require, namespaces, aliases, and execa are resolved', async () => {
    await expectHits({
      'pages/api/a.ts': `const { execSync: sh } = require('child_process')
export default function handler(req, res) { sh('ls ' + req.query.dir); res.end() }`,
      'pages/api/b.ts': `import * as cp from 'node:child_process'
export default function handler(req, res) { cp.exec(\`git log \${req.body.ref}\`); res.end() }`,
      'pages/api/c.ts': `import { execaCommand } from 'execa'
export default async function handler(req, res) { await execaCommand(req.query.cmd); res.end() }`,
    }, [['injection/command', 2, 'certain'], ['injection/command', 2, 'certain'], ['injection/command', 2, 'certain']])
  })

  test('spawn and execFile are reported only with shell: true', async () => {
    await expectHits({
      'app/api/safe/route.ts': `import { spawn, execFile } from 'child_process'
export async function POST(req) {
  const { file } = await req.json()
  spawn('convert', [file, 'out.png'])
  execFile('convert', [file])
  return new Response('ok')
}`,
      'app/api/shell/route.ts': `import cp from 'child_process'
export async function POST(req) {
  const { file } = await req.json()
  cp.spawn('convert', [file, 'out.png'], { shell: true })
  return new Response('ok')
}`,
    }, [['injection/command', 4, 'certain']])
  })

  test('exec that is not from child_process, such as RegExp.exec, is ignored', async () => {
    await expectHits(route(`export async function GET(req) {
  const q = req.nextUrl.searchParams.get('q')
  const exec = (s: string) => s
  return Response.json([exec(q), /x/.exec(q)])
}`), [])
  })
})

describe('reporting', () => {
  test('ignore comments, rule selection, and example contexts apply', async () => {
    const vulnerable = `export async function GET(req) {
  const id = req.nextUrl.searchParams.get('id')
  // canship-ignore-next-line injection/sql
  await pool.query(\`SELECT * FROM t WHERE id = \${id}\`)
  return new Response('ok')
}`
    const { hits, result } = await run({ 'app/api/a/route.ts': vulnerable, 'test/app/api/b/route.ts': vulnerable.replace('  // canship-ignore-next-line injection/sql\n', '') })
    assert.deepEqual(hits.map(f => [f.file, f.confidence]), [['test/app/api/b/route.ts', 'likely']])
    assert.deepEqual(result.ignoredFindings.map(f => f.ruleId), ['injection/sql'])
    const skipped = await scan(project({ 'app/api/b/route.ts': vulnerable.replace('  // canship-ignore-next-line injection/sql\n', '') }), { skip: ['injection'] })
    assert.equal(skipped.findings.filter(f => f.ruleId.startsWith('injection/')).length, 0)
  })

  // 曾对每个 Server Function 遍历全部函数体并提前建立输入追踪：2 万个 action 在较慢的 CI 上超过 10 秒。
  test('files with thousands of Server Functions are analysed in linear time', async () => {
    const withSinks = Array.from({ length: 10_000 }, (_, i) =>
      `export async function a${i}(id: string) { redirect(id); await db.$queryRawUnsafe(\`SELECT * FROM t WHERE id = '\${id}'\`); await fetch(id) }\n`).join('')
    const without = Array.from({ length: 20_000 }, (_, i) => `export const b${i} = async (x: string): Promise<void> => { return }\n`).join('')
    const started = Date.now()
    const { hits } = await run({ 'app/sinks.ts': `'use server'\n${withSinks}`, 'app/plain.ts': `'use server'\n${without}` })
    assert.ok(hits.length > 0)
    assert.ok(Date.now() - started < 10_000, `took ${Date.now() - started}ms`)
  })

  test('large handlers stay fast and disclose the tracking limit', async () => {
    const lines = Array.from({ length: 3000 }, (_, i) => `  const v${i} = v${i - 1 < 0 ? 0 : i - 1} + 1`)
    const started = Date.now()
    const { result } = await run(route(`export async function GET(req) {
  const v0 = req.nextUrl.searchParams.get('x')
${lines.slice(1).join('\n')}
  return Response.json(await pool.query(\`SELECT * FROM t WHERE a = \${v2999}\`))
}`))
    assert.ok(Date.now() - started < 10_000, 'the scan took too long')
    assert.ok(result.errors.some(e => e.ruleId === 'request-input/tracking' && e.kind === 'incomplete'))
    assert.equal(result.partial, true)
  })
})
