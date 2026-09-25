// canship-ignore-file
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync, execFileSync } from 'node:child_process'
import { scan } from '../src/engine.js'
import { applyBaseline, buildBaseline } from '../src/baseline.js'
import { renderReport } from '../src/report/terminal.js'
import { renderHtml } from '../src/report/html.js'
import { renderFixPrompt } from '../src/report/prompt.js'
import { PROJECT_RULES } from '../src/rules/index.js'
import { renderSarif } from '../src/report/sarif.js'
import { collectFiles } from '../src/walker.js'

const roots: string[] = []
const KEY = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'
const OTHER = 'sk-proj-Zq7WnEr5TyUiOpAsDfGhJkLxCvBnMwQe2R'
const GH = 'ghp_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn123'
const ROUTE = 'app/api/users/route.ts'
const CLIENT = "import {createClient} from '@supabase/supabase-js';\n" +
  'const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);\n'
const WRITE = "await db.from('users').delete()"
function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-review-test-'))
  roots.push(root)
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function cli(root: string, ...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx',
    fileURLToPath(new URL('../src/cli.ts', import.meta.url)), root, ...args], { encoding: 'utf8' })
}

for (const [name, source] of [
  ['auth in another HTTP method', `export async function GET(){await requireAuth();return Response.json({});}\nexport async function POST(){${WRITE};}`],
  ['auth in an uncalled helper', `async function unused(){await requireAuth();}\nexport async function POST(){${WRITE};}`],
  ['auth after the write', `export async function POST(){${WRITE};await requireAuth();}`],
  ['auth in a nested but uncalled helper', `export async function POST(){async function unused(){await requireAuth();}${WRITE};}`],
  ['auth in an uncalled arrow function', `export async function POST(){const unused=()=>requireAuth();${WRITE};}`],
  ['an auth wrapper that is only constructed', `export async function POST(){const unused=withAuth(async()=>{});${WRITE};}`],
  ['an Auth.js handler that is only constructed', `export async function POST(){const unused=NextAuth({providers:[]});${WRITE};}`],
  ['optional auth in an if branch', `export async function POST(req){if(req.optional){await requireAuth();}${WRITE};}`],
  ['optional auth in a short-circuit expression', `export async function POST(req){req.optional && await requireAuth();${WRITE};}`],
  ['optional auth in a ternary', `export async function POST(req){req.optional ? await requireAuth() : null;${WRITE};}`],
  ['multi-line short-circuit auth', `export async function POST(req){req.optional &&\nawait requireAuth();${WRITE};}`],
  ['multi-line ternary auth', `export async function POST(req){req.optional ?\nawait requireAuth() : null;${WRITE};}`],
  ['a nested conditional exit after whitespace', `export async function POST(req){const user=await getUser();if(!user)${' '.repeat(80)}{if(!req.debug)return new Response(null,{status:401});}${WRITE};}`],
  ['unawaited async auth', `export async function POST(){requireAuth();${WRITE};}`],
  ['a nested conditional exit', `export async function POST(req){const user=await getUser();if(!user){if(req.optional)return new Response(null,{status:401});}${WRITE};}`],
  ['an early return for a signed-in user', `export async function POST(){const user=await getUser();if(user){return Response.json({ok:true});}${WRITE};}`],
  ['an early return when the identity is non-null', `export async function POST(){const user=await getUser();if(user!==null){return Response.json({ok:true});}${WRITE};}`],
  ['an early return after comparing a negated identity with false', `export async function POST(){const user=await getUser();if(!user===false){return Response.json({ok:true});}${WRITE};}`],
] as const) {
  test(`${name} does not hide an unprotected write`, async () => {
    const root = project({ [ROUTE]: CLIENT + source })
    const result = await scan(root)
    assert.ok(result.findings.some(f => f.ruleId === 'api/admin-db-access-without-auth'))
    assert.equal(result.partial, false)
    assert.equal(cli(root, '--json').status, 1)
  })
}

for (const source of [
  `export async function POST(){await requireAuth();${WRITE};}`,
  `export const POST=async()=>{const user=await getUser();if(!user){return new Response('no',{status:401});}${WRITE};}`,
  `export default async function handler(req,res){await requireAuth();${WRITE};}`,
  `export const POST=withAuth(async()=>{${WRITE};});`,
  `export async function POST(): Promise<Response> {await requireAuth();${WRITE};}`,
  `export async function POST(){try{await requireAuth();${WRITE};}catch{return new Response('no',{status:401});}}`,
  `export async function POST(req){if(req.write){await requireAuth();${WRITE};}}`,
]) {
  test(`auth earlier in the same handler still protects the write: ${source.slice(0, 30)}`, async () => {
    const result = await scan(project({ [ROUTE]: CLIENT + source }))
    assert.deepEqual(result.findings.filter(f => f.ruleId.startsWith('api/')), [])
  })
}

test('route groups change neither API detection nor the reported URL', async () => {
  const path = 'app/(dashboard)/(internal)/api/users/route.ts'
  const root = project({ [path]: CLIENT + `export async function POST(){${WRITE};}` })
  const result = await scan(root)
  const finding = result.findings.find(f => f.ruleId === 'api/admin-db-access-without-auth')
  assert.ok(finding)
  assert.equal(finding.file, path)
  assert.ok(JSON.stringify(finding).includes('/api/users'))
  writeFileSync(join(root, 'middleware.ts'), `export function middleware(req){if(!req.user)return new Response(null,{status:401});}\nexport const config={matcher:['/api/:path*']};`)
  assert.equal((await scan(root)).findings.some(f => f.ruleId.startsWith('api/')), false)
})

test('a workspace alias inside a route group still points at its own app', async () => {
  const root = project({
    'apps/web/app/(api)/api/users/route.ts': `import {db} from '@/lib/admin';export async function POST(){${WRITE};}`,
    'apps/web/lib/admin.ts': CLIENT + 'export {db};',
  })
  assert.ok((await scan(root)).findings.some(f => f.ruleId === 'api/admin-db-access-without-auth'))
})

test('the total read budget allows reading at the limit and discloses going over it', () => {
  const root = project({ 'a.ts': 'let a=1;', 'b.ts': 'let b=2;' })
  const exact = collectFiles(root, false, null, { maxFiles: 2, maxBytes: 16 })
  assert.equal(exact.files.length, 2)
  assert.deepEqual(exact.skipped, [])
  for (const limits of [{ maxFiles: 1 }, { maxBytes: 8 }]) {
    const result = collectFiles(root, false, null, limits)
    assert.equal(result.files.length, 1)
    assert.equal(result.skipped.length, 1)
    assert.match(result.skipped[0]!.detail!, /scan read budget exceeded/)
  }
})

test('an excluded rule does not run, so its errors cannot affect completeness', async () => {
  let calls = 0
  const sentinel = { id: 'api/db-access-without-auth', severity: 'P0' as const,
    check(): never { calls++; throw new Error('excluded-rule-sentinel') } }
  PROJECT_RULES.push(sentinel)
  try {
    const result = await scan(project({ 'app.ts': 'export const value=1;' }), { only: ['secrets'] })
    assert.equal(calls, 0)
    assert.equal(result.partial, false)
    assert.deepEqual(result.errors, [])
  } finally { PROJECT_RULES.splice(PROJECT_RULES.indexOf(sentinel), 1) }
})

test('the per-file cap across rules keeps certain findings first', async () => {
  const content = Array.from({ length: 60 }, (_, i) =>
    `const k${i}="${KEY}";\nconst v${i}=process.env.NEXT_PUBLIC_ADMIN_SECRET;`).join('\n')
  const result = await scan(project({ 'keys.ts': content }))
  assert.equal(result.findings.length, 100)
  assert.equal(result.findings.filter(f => f.confidence === 'certain').length, 60)
  assert.equal(result.partial, true)
  assert.ok(result.errors.some(e => e.ruleId === 'engine/findings-limit'))
})

test('SARIF encodes file paths and discloses skip reasons', async () => {
  const result = await scan(project({ '路径 #100%.ts': `const key="${KEY}";` }))
  result.skipped.push({ path: 'large.ts', reason: 'too-large', detail: 'file limit exceeded' })
  result.partial = true
  const log = JSON.parse(renderSarif(result, { version: '0.2.0' }))
  const run = log.runs[0]
  const uri = run.results[0].locations[0].physicalLocation.artifactLocation.uri
  assert.equal(decodeURIComponent(uri), '路径 #100%.ts')
  assert.equal(new URL(uri, 'https://example.invalid/').hash, '')
  assert.equal(run.invocations[0].executionSuccessful, false)
  assert.match(JSON.stringify(run.invocations), /large\.ts.*too-large/)
})

test('a baseline tells apart new keys that redact identically, and lets old findings move lines', async () => {
  const root = project({ 'keys.ts': `const key="${KEY}";` })
  const first = await scan(root)
  const baseline = buildBaseline(first.findings)
  writeFileSync(join(root, 'keys.ts'), `\n\nconst key="${KEY}";`)
  assert.equal(applyBaseline((await scan(root)).findings, baseline).suppressed, 1)
  writeFileSync(join(root, 'keys.ts'), `const key="${KEY.replace('A9dKfM2x', 'B8eLgN3y')}";`)
  const next = await scan(root)
  assert.equal(first.findings[0]?.excerpt, next.findings[0]?.excerpt)
  assert.equal(applyBaseline(next.findings, baseline).kept.length, 1)
  assert.equal(JSON.stringify(baseline).includes(KEY), false)
  assert.equal(JSON.stringify(next).includes(KEY), false)
})

test('several credentials are all redacted before truncation, so no report leaks a raw fragment', async () => {
  const root = project({ 'keys.ts': `const a="${GH}"; ${' '.repeat(60)}const b="${OTHER}";` })
  const result = await scan(root)
  assert.equal(result.findings.length, 2)
  const outputs = [JSON.stringify(result), renderReport(result, { root, showingLikely: true, hiddenLikely: 0 }),
    renderHtml(result, { root, generatedAt: new Date().toISOString() }),
    renderFixPrompt(result.findings) ?? '']
  for (const output of outputs) {
    assert.equal(output.includes(OTHER.slice(0, 19)), false)
    assert.equal(output.includes(GH), false)
  }
})

test('hitting the cap across credential types is recorded as incomplete, and a baseline cannot turn that into a pass', async () => {
  const source = Array.from({ length: 100 }, (_, i) => `const k${i}="${KEY}";`).join('\n')
  const root = project({ 'keys.ts': source })
  const exact = await scan(root)
  assert.equal(exact.findings.length, 100)
  assert.equal(exact.partial, false)
  assert.equal(cli(root, '--baseline-write').status, 0)
  writeFileSync(join(root, 'keys.ts'), source + `\nconst added="${GH}";`)
  const extra = await scan(root)
  assert.equal(extra.findings.length, 100)
  assert.equal(extra.partial, true)
  assert.ok(extra.errors.some(e => e.kind === 'incomplete'))
  assert.equal(cli(root, '--baseline', '--json').status, 3)
})

test('the fix prompt discloses whole-file exclusions', () => {
  const root = project({ 'app.ts': 'export const ok=true;',
    'keys.ts': `// canship-ignore-file\nconst key="${KEY}";` })
  const result = cli(root, '--fix-prompt')
  assert.equal(result.status, 0)
  assert.match(result.stdout, /canship-ignore-file/)
  assert.match(result.stdout, /keys\.ts/)
  assert.doesNotMatch(result.stdout, /Nothing to fix/)
})

test('CLI rule selection overrides the opposite config mode, but both explicit flags together still fail', () => {
  for (const [config, flag, expected] of [
    [{ skip: ['secrets'] }, '--only=secrets', 1],
    [{ only: ['cors'] }, '--skip=cors', 1],
  ] as const) {
    const root = project({ 'keys.ts': `const key="${KEY}";`,
      'canship.config.json': JSON.stringify(config) })
    assert.equal(cli(root, flag, '--json').status, expected)
    assert.equal(cli(root, '--only=secrets', '--skip=cors').status, 3)
  }
})

test('an old baseline fails explicitly and is left untouched', () => {
  const root = project({ 'app.ts': 'export const ok=true;',
    'canship-baseline.json': '{"version":1,"generatedAt":"","entries":[]}' })
  const before = readFileSync(join(root, 'canship-baseline.json'), 'utf8')
  const result = cli(root, '--baseline', '--json')
  assert.equal(result.status, 3)
  assert.match(result.stderr, /reads version 2/)
  assert.match(result.stderr, /--baseline-write/)
  assert.equal(readFileSync(join(root, 'canship-baseline.json'), 'utf8'), before)
})

test('a credential change past the truncation point still yields a new baseline identity', async () => {
  const prefix = `const label="${'x'.repeat(180)}";`
  const root = project({ 'keys.ts': `${prefix}const key="${KEY}";` })
  const first = await scan(root)
  writeFileSync(join(root, 'keys.ts'), `${prefix}const key="${OTHER}";`)
  const next = await scan(root)
  assert.equal(first.findings[0]?.excerpt, next.findings[0]?.excerpt)
  assert.equal(applyBaseline(next.findings, buildBaseline(first.findings)).kept.length, 1)
})

test('credential changes in tracked and historical env files do not reuse an old baseline identity', async () => {
  const root = project({ 'app.ts': 'export const ok=true;', '.env': `OPENAI_KEY=${KEY}\n` })
  // 所有 Git 写入均限于本用例新建的系统临时仓库。
  const git = (...args: string[]) => execFileSync('git', [
    '-c', 'user.name=test', '-c', 'user.email=test@example.com',
    '-c', 'core.hooksPath=', '-c', 'commit.gpgsign=false', ...args,
  ], { cwd: root, stdio: 'ignore' })
  const commit = () => { git('add', '-A', '-f'); git('commit', '-qm', 'fixture') }
  git('init', '-q')
  commit()
  const tracked = await scan(root)
  assert.ok(tracked.findings.some(f => f.ruleId === 'gitleak/env-tracked'))
  writeFileSync(join(root, '.env'), `OPENAI_KEY=${OTHER}\n`)
  const changed = await scan(root)
  assert.ok(applyBaseline(changed.findings, buildBaseline(tracked.findings)).kept
    .some(f => f.ruleId === 'gitleak/env-tracked'))
  // 先只留下旧值的历史记录，再添加新值并再次删除。
  rmSync(join(root, '.env'))
  commit()
  const history = await scan(root)
  assert.ok(history.findings.some(f => f.ruleId === 'gitleak/env-in-history'))
  writeFileSync(join(root, '.env'), `OPENAI_KEY=${OTHER}\n`)
  commit()
  rmSync(join(root, '.env'))
  commit()
  const nextHistory = await scan(root)
  assert.ok(applyBaseline(nextHistory.findings, buildBaseline(history.findings)).kept
    .some(f => f.ruleId === 'gitleak/env-in-history'))
  assert.equal(JSON.stringify(nextHistory).includes(OTHER), false)
})
