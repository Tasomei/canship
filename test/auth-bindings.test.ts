/** 验证导入别名、重导出与本地鉴权提示；间接证据不得使报告变成零结果。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan, summarize } from '../src/index.js'
import { bindingsOf } from '../src/rules/bindings.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-bindings-')); roots.push(root)
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), body)
  }
  return root
}
const admin = "import { createClient as makeClient } from '@supabase/supabase-js';\nexport const db = makeClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);"
const imports = "import { db } from '../../../lib/db';\nimport { authorize as check } from '../../../lib/auth';\n"
const operation = "await db.from('items').delete()"
const guard = 'export async function authorize() { const user = await getUser(); if (!user) throw new Error("denied"); return user }'
async function result(body: string, extra: Record<string, string> = {}) {
  return scan(project({ 'lib/db.ts': admin, 'lib/auth.ts': guard,
    'app/api/items/route.ts': imports + body, ...extra }))
}

test('aliased Supabase constructors remain admin evidence through renamed exports', async () => {
  const findings = (await scan(project({ 'lib/db.ts': admin, 'lib/barrel.ts': "export { db as rootClient } from './db';",
    'app/api/items/route.ts': "import { rootClient as db } from '../../../lib/barrel'; export async function DELETE() { " + operation + ' }',
  }))).findings
  assert.equal(findings.length, 1)
  assert.equal(findings[0]!.confidence, 'certain')
  assert.equal(findings[0]!.evidence?.at(-1)?.file, 'lib/db.ts')
  assert.equal(findings[0]!.evidence?.at(-1)?.line, 2)
})

test('an awaited local alias lowers confidence but never hides the finding', async () => {
  const report = await result(`export async function DELETE() { await check(); ${operation} }`)
  assert.equal(report.findings.length, 1)
  assert.equal(report.findings[0]!.confidence, 'likely')
  assert.equal(report.findings[0]!.evidence?.at(-1)?.kind, 'auth-helper')
  assert.equal(summarize(report).exitCode, 2)
})

test('renamed, star and imported-then-exported guards resolve to their definition', async () => {
  for (const barrel of ["export { verify as authorize } from './impl';", "export * from './impl';",
    "import { verify as local } from './impl'; export { local as authorize };"]) {
    const report = await result(`export async function DELETE() { await check(); ${operation} }`, {
      'lib/auth.ts': barrel,
      'lib/impl.ts': guard.replace('authorize', barrel.includes('export *') ? 'authorize' : 'verify'),
    })
    assert.equal(report.findings[0]!.confidence, 'likely')
    assert.equal(report.findings[0]!.evidence?.at(-1)?.file, 'lib/impl.ts')
  }
})

test('an imported auth wrapper adds review evidence for its enclosed handler', async () => {
  const report = await result(`export const DELETE = check(async () => { ${operation} });`, {
    'lib/auth.ts': 'export function authorize(handler) { return async (request) => { await requireAuth(); return handler(request) } }',
  })
  assert.equal(report.findings[0]!.confidence, 'likely')
  assert.match(report.findings[0]!.title, /Review indirect authentication/)
})

for (const body of [
  `export async function DELETE() { ${operation}; await check(); }`,
  `export async function DELETE() { check(); ${operation}; }`,
  `export async function DELETE(req) { if(req.optional) { await check(); } ${operation}; }`,
  `export async function DELETE(req) { req.optional && await check(); ${operation}; }`,
  `export async function DELETE() { async function unused(){ await check() } ${operation}; }`,
  `export async function DELETE(check) { await check(); ${operation}; }`,
  `export const DELETE = async check => { await check(); ${operation}; }`,
  `export const DELETE = async ({ check }) => { await check(); ${operation}; }`,
  `export async function DELETE() { await other.check(); ${operation}; }`,
]) {
  test(`non-protecting or shadowed aliases stay certain: ${body.slice(0, 55)}`, async () => {
    assert.equal((await result(body)).findings[0]!.confidence, 'certain')
  })
}

test('unknown bodies, missing exports and re-export cycles do not supply guard evidence', async () => {
  for (const body of ['export async function authorize() { return true }',
    'export async function authorize() { return true; await requireAuth() }',
    'export async function authorize() { async function unused() { await requireAuth() } return true }',
    'async function authorize() { await requireAuth() }', "export { authorize } from './loop';"]) {
    const report = await result(`export async function DELETE() { await check(); ${operation}; }`, {
      'lib/auth.ts': body, 'lib/loop.ts': "export { authorize } from './auth';",
    })
    assert.equal(report.findings[0]!.confidence, 'certain')
  }
})

test('type-only imports and module text inside strings are not bindings', () => {
  const content = "import type { authorize as check } from './auth';\n" +
    "const text = `import { authorize } from './auth'`;\nexport type { authorize } from './auth';"
  const bindings = bindingsOf({ path: 'x.ts', content, lines: content.split('\n'), isExampleContext: false })
  assert.deepEqual(bindings, { imports: [], exports: [], stars: [] })
})

test('default function imports and exported arrow guards produce review evidence', async () => {
  const report = await scan(project({ 'lib/db.ts': admin,
    'lib/auth.ts': 'export default async function validate() { await requireAuth() }',
    'app/api/items/route.ts': "import { db } from '../../../lib/db'; import check from '../../../lib/auth';" +
      `export async function DELETE() { await check(); ${operation} }`,
  }))
  assert.equal(report.findings[0]!.confidence, 'likely')
  const arrow = await result(`export async function DELETE() { await check(); ${operation} }`, {
    'lib/auth.ts': 'export const authorize = async () => { await requireAuth() }',
  })
  assert.equal(arrow.findings[0]!.confidence, 'likely')
})

test('another unprotected operation in the route retains the blocking finding', async () => {
  const report = await result(`export async function GET() { await check(); ${operation} }\n` +
    `export async function DELETE() { ${operation} }`)
  assert.equal(report.findings[0]!.confidence, 'certain')
  assert.equal(report.findings[0]!.line, 4)
})

test('dollar-named aliases are recognized but shadowing still blocks attribution', async () => {
  for (const name of ['$check', 'check$']) {
    const prefix = "import { db } from '../../../lib/db';\n" + `import { authorize as ${name} } from '../../../lib/auth';\n`
    for (const shadow of [false, true]) {
      const report = await scan(project({ 'lib/db.ts': admin, 'lib/auth.ts': guard,
        'app/api/items/route.ts': prefix + (shadow
          ? `export const DELETE = async ${name} => { await ${name}(); ${operation} }`
          : `export const DELETE = async () => { await ${name}(); ${operation} }`),
      }))
      assert.equal(report.findings[0]!.confidence, shadow ? 'certain' : 'likely')
    }
  }
})
