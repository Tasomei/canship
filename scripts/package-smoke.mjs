/** 在隔离目录离线安装实际打包产物，验证发布文件及主要 CLI 契约。 */
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const version = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8')).version
const root = mkdtempSync(join(tmpdir(), 'canship-package-smoke-'))
function npm(args, cwd) {
  const executable = process.platform === 'win32' ? process.execPath : 'npm'
  const prefix = process.platform === 'win32' ? [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')] : []
  const result = spawnSync(executable, [...prefix, ...args], { cwd, encoding: 'utf8', shell: false,
    timeout: 60_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
  assert.equal(result.status, 0, 'Package operation failed')
  return result.stdout
}
try {
  const packed = JSON.parse(npm(['pack', '--ignore-scripts', '--json', '--pack-destination', root], repository))[0]
  const expected = ['LICENSE', 'README-zh-CN.md', 'README.md', 'dist/cli.js', 'dist/index.js', 'dist/index.d.ts',
    'package.json', 'schemas/scan-report-v1.schema.json', 'schemas/config-v1.schema.json'].sort()
  assert.deepEqual(packed.files.map(file => file.path).sort(), expected)
  const install = join(root, 'installed')
  mkdirSync(install)
  writeFileSync(join(install, 'package.json'), '{"name":"canship-package-check","private":true}')
  npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', '--no-save', join(root, packed.filename)], install)
  const packageRoot = join(install, 'node_modules/canship')
  const pkg = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'))
  assert.equal(pkg.version, version)
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0)
  assert.equal(pkg.bin.canship, 'dist/cli.js')
  assert.equal(pkg.exports['./schemas/config-v1.schema.json'], './schemas/config-v1.schema.json')
  assert.deepEqual(readFileSync(join(packageRoot, 'schemas/config-v1.schema.json')),
    readFileSync(join(repository, 'schemas/config-v1.schema.json')))
  assert.equal(npm(['exec', '--offline', '--yes=false', '--', 'canship', '--version'], install).trim(), version)
  assert.match(readFileSync(join(packageRoot, 'README.md'), 'utf8'), /A local static scanner/)
  for (const name of ['README.md', 'README-zh-CN.md']) {
    assert.deepEqual(readFileSync(join(packageRoot, name)), readFileSync(join(repository, name)))
  }
  const entry = join(packageRoot, 'dist/cli.js')
  function cli(args) {
    const result = spawnSync(process.execPath, [entry, ...args], { cwd: install, encoding: 'utf8',
      timeout: 30_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
    assert.equal(result.error, undefined)
    return result
  }
  assert.equal(cli(['--version']).stdout.trim(), version)
  const init = cli(['--init'])
  assert.equal(init.status, 0)
  assert.deepEqual(JSON.parse(init.stdout), { all: false })
  const ciPreview = cli(['--init=ci'])
  assert.equal(ciPreview.status, 0)
  assert.ok(ciPreview.stdout.includes(`version: '${version}'`))
  const identity = JSON.parse(cli(['--build-info', '--json']).stdout)
  assert.equal(identity.kind, 'build-info')
  assert.equal(identity.version, version)
  assert.ok(['development','prerelease','release'].includes(identity.channel))
  assert.equal(identity.capabilities.staticScan.network, false)
  assert.match(cli(['--help']).stdout, /--no-excerpts/)
  assert.equal(JSON.parse(cli(['--list-rules', '--json']).stdout).kind, 'rule-catalog')
  const catalog = cli(['--list-rules', '--only=injection/sql', '--json'])
  assert.equal(catalog.status, 0)
  assert.deepEqual(JSON.parse(catalog.stdout).rules.map(rule => rule.id), ['injection/sql'])
  assert.match(JSON.parse(catalog.stdout).rules[0].example.after, /\$1/)
  assert.equal(cli(['--list-rules', '--only=,,,']).status, 3)
  function sample(name, files) {
    const dir = join(root, name)
    mkdirSync(dir)
    for (const [file, content] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, file)), { recursive: true })
      writeFileSync(join(dir, file), content)
    }
    return dir
  }
  const clean = sample('clean', { 'index.ts': 'export const value = 1;' })
  const hookPreview = cli(['--init=pre-commit'])
  assert.equal(hookPreview.status, 0)
  const hookFile = join(root, 'pre-commit')
  writeFileSync(hookFile, hookPreview.stdout)
  const hookResult = spawnSync(process.execPath, [hookFile], { cwd: clean, encoding: 'utf8', timeout: 30_000,
    env: { ...process.env, CANSHIP_CLI: entry }, windowsHide: true })
  assert.equal(hookResult.status, 0, hookResult.stderr)
  assert.match(hookResult.stderr, /not the staged snapshot/)
  const multiple = sample('workspaces', { 'apps/web/firestore.rules': 'match /items/{id} { allow write: if true; }',
    'apps/admin/index.ts': 'export const ok=true;' })
  const workspaces = cli([multiple, '--workspace=apps/web', '--workspace=apps/admin', '--json', '--no-excerpts'])
  assert.equal(workspaces.status, 1)
  const workspaceReport = JSON.parse(workspaces.stdout)
  assert.equal(workspaceReport.kind, 'workspace-report')
  assert.equal(workspaceReport.projects.length, 2)
  assert.equal(workspaceReport.projects[0].report.findings[0].excerpt, null)
  assert.equal(workspaceReport.projects[1].exitCode, 0)
  assert.match(cli(['--init=ci-workspaces']).stdout, /fail-fast: false/)
  // 安装包的配置预览必须保持只读，且采用相同的命令行优先级。
  const configured = sample('configured', {
    'canship.config.json': JSON.stringify({ $schema: './missing-schema.json', only: ['firebase'], baseline: 'missing.json' }),
  })
  const explained = cli([configured, '--explain-config', '--json', '--only=injection/sql', '--no-excerpts'])
  assert.equal(explained.status, 0)
  const effective = JSON.parse(explained.stdout)
  assert.equal(effective.kind, 'effective-config')
  assert.equal(effective.scanPerformed, false)
  assert.deepEqual(effective.rules.enabled, ['injection/sql'])
  assert.equal(effective.rules.source, 'cli')
  assert.equal(effective.settings.noExcerpts.value, true)
  assert.equal(effective.settings.baseline.value, join(configured, 'missing.json'))
  assert.equal(cli([configured, '--explain-config', '--report']).status, 3)
  const invalidConfig = sample('invalid-config', { 'canship.config.json': '{\n  "all": "wrong"\n}' })
  const invalid = cli([invalidConfig, '--explain-config', '--json'])
  assert.equal(invalid.status, 3)
  assert.equal(invalid.stdout, '')
  assert.match(invalid.stderr, /\[CONFIG_INVALID\].*canship\.config\.json:2:3:.*\(\/all\)/)
  // 诊断输出独立于扫描格式；输出路径预检不得创建文件。
  const diagnosticTarget = join(clean, 'diagnostic.html')
  const doctor = cli([clean, '--doctor', '--json', `--report=${diagnosticTarget}`])
  assert.equal(doctor.status, 0)
  assert.equal(JSON.parse(doctor.stdout).kind, 'doctor')
  assert.equal(JSON.parse(doctor.stdout).scanPerformed, false)
  assert.throws(() => readFileSync(diagnosticTarget), { code: 'ENOENT' })
  const badDoctor = cli([configured, '--doctor', '--json'])
  assert.equal(badDoctor.status, 3)
  assert.ok(JSON.parse(badDoctor.stdout).checks.some(check => check.code === 'BASELINE_INVALID'))
  // 从实际安装包按包名导入，验证入口无 CLI 副作用及声明文件可被消费。
  const consumer = join(install, 'consumer.mjs')
  writeFileSync(consumer, `import { scan, summarize, listRules, ScanCancelledError } from 'canship';
import assert from 'node:assert/strict';
const result = await scan(process.argv[2], { noExcerpts: true });
assert.equal(summarize(result).exitCode, 0);
assert.ok(listRules().length > 10);
const phases=[];
await scan(process.argv[2], {onProgress: progress => {phases.push(progress.phase)}});
assert.equal(phases[0],'discovery');assert.equal(phases.at(-1),'complete');
const controller=new AbortController();controller.abort();
await assert.rejects(scan(process.argv[2], {signal:controller.signal}),ScanCancelledError);
console.log('API_OK');
`)
  const api = spawnSync(process.execPath, [consumer, clean], { cwd: install, encoding: 'utf8', timeout: 30_000, windowsHide: true })
  assert.equal(api.status, 0, api.stderr)
  assert.equal(api.stdout.trim(), 'API_OK')
  writeFileSync(join(install, 'consumer.mts'), `import { scan, summarize, listRules } from 'canship';
import type { ScanOptions, ScanResult } from 'canship';
const options: ScanOptions = { only: ['firebase'], noExcerpts: true, signal: new AbortController().signal,
  onProgress: progress => { const completed: number = progress.filesCompleted; void completed; } };
const result: ScanResult = await scan('.', options);
const code: 0 | 1 | 2 | 3 = summarize(result).exitCode;
const id: string = listRules()[0]!.id;
void code; void id;
`)
  writeFileSync(join(install, 'tsconfig.json'), JSON.stringify({ compilerOptions: {
    target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true, types: [],
  }, files: ['consumer.mts'] }))
  const types = spawnSync(process.execPath, [join(repository, 'node_modules/typescript/bin/tsc'), '-p', install],
    { cwd: install, encoding: 'utf8', timeout: 30_000, windowsHide: true })
  assert.equal(types.status, 0, types.stdout + types.stderr)
  const cleanResult = cli([clean, '--json'])
  assert.equal(cleanResult.status, 0)
  assert.equal(JSON.parse(cleanResult.stdout).partial, false)
  assert.deepEqual(JSON.parse(cleanResult.stdout).build.revision, identity.revision)
  const summary = cli([clean, '--share-summary', '--json'])
  assert.equal(summary.status, 0)
  assert.equal(JSON.parse(summary.stdout).kind, 'share-summary')
  assert.equal(JSON.parse(summary.stdout).counts.findings, 0)
  assert.ok(!summary.stdout.includes(clean))
  assert.equal('root' in JSON.parse(summary.stdout), false)
  // 从安装包验证身份实参及异常传播，避免只验证源码版本。
  for (const verified of [false, true]) {
    const target = sample(verified ? 'verified-identity' : 'raw-identity', {
      'app/api/items/route.ts': "import {createClient} from '@supabase/supabase-js';" +
        'const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);' +
        'async function validate(user){if(!user)throw new Error("denied");}' +
        `export async function DELETE(req){const user=${verified ? 'await getUser()' : 'req.body.user'};` +
        'try{await validate(user);}catch{throw new Error("denied");}await db.from("items").delete();}',
    })
    const checked = cli([target, '--json', '--all'])
    assert.equal(checked.status, verified ? 2 : 1)
    const report = JSON.parse(checked.stdout)
    assert.equal(report.partial, false)
    assert.equal(report.findings.length, 1)
    assert.equal(report.findings[0].confidence, verified ? 'likely' : 'certain')
  }
  const open = sample('open', { 'firestore.rules': 'match /items/{id} { allow write: if true; }' })
  assert.equal(cli([open, '--json']).status, 1)
  const excluded = cli([open, '--json', '--exclude=firestore.rules'])
  assert.equal(excluded.status, 3)
  assert.equal(JSON.parse(excluded.stdout).filesScanned, 0)
  assert.deepEqual(JSON.parse(excluded.stdout).exclusions.matched, ['firestore.rules'])
  // 比较安装包生成的真实报告，不修改样本或沿用扫描阻断状态。
  const earlierReport = join(root, 'earlier.json'), laterReport = join(root, 'later.json')
  const fullReport = cli([open, '--json', '--all', '--no-excerpts'])
  assert.equal(fullReport.status, 1)
  writeFileSync(earlierReport, fullReport.stdout)
  writeFileSync(laterReport, fullReport.stdout)
  const comparison = cli([`--compare=${earlierReport}`, `--with=${laterReport}`, '--json'])
  const compared = JSON.parse(comparison.stdout)
  assert.equal(compared.kind, 'report-comparison')
  assert.equal(compared.scanPerformed, false)
  assert.equal(compared.counts.persisting, 1)
  assert.equal(compared.counts.added, 0)
  assert.equal(compared.counts.notObserved, 0)
  assert.equal(comparison.status, identity.revision && identity.dirty === false ? 0 : 2)
  assert.equal(readFileSync(earlierReport, 'utf8'), fullReport.stdout)
  assert.equal(readFileSync(laterReport, 'utf8'), fullReport.stdout)
  writeFileSync(laterReport, '{}')
  assert.equal(cli([`--compare=${earlierReport}`, `--with=${laterReport}`, '--json']).status, 3)
  const readOnly = sample('public-read', { 'firestore.rules': 'match /items/{id} { allow read: if true; }' })
  const hidden = cli([readOnly, '--json'])
  assert.equal(hidden.status, 2)
  assert.equal(JSON.parse(hidden.stdout).hiddenLikely, 1)
  const partial = sample('partial', { 'index.ts': 'export const value = 1;', 'large.ts': ' '.repeat(2 * 1024 * 1024 + 1) })
  assert.equal(cli([partial, '--json']).status, 3)
  const accepted = cli([partial, '--json', '--best-effort'])
  assert.equal(accepted.status, 0)
  assert.equal(JSON.parse(accepted.stdout).partial, true)
  assert.equal(cli([open, '--baseline-write']).status, 0)
  const baseline = cli([open, '--json', '--baseline'])
  assert.equal(baseline.status, 0)
  assert.equal(JSON.parse(baseline.stdout).baselineSuppressed, 1)
  const migrated = cli([open, '--baseline-migrate'])
  assert.equal(migrated.status, 0)
  assert.equal(JSON.parse(migrated.stdout).version, 4)
  const baselineReview = cli([open, '--baseline-review', '--json'])
  assert.equal(baselineReview.status, 0)
  assert.equal(JSON.parse(baselineReview.stdout).counts.retained, 1)
  const pruned = cli([open, '--baseline-prune'])
  assert.equal(pruned.status, 0)
  assert.equal(JSON.parse(pruned.stdout).entries.length, 1)
  const toAccept = JSON.parse(cli([readOnly, '--baseline-review', '--json']).stdout).unaccepted[0].fingerprint
  const policyDeadline = new Date(Date.now() + 86_400_000).toISOString()
  const acceptedOne = cli([readOnly, `--baseline-accept=${toAccept}`, '--baseline-reason=Sample fixture', `--baseline-expires=${policyDeadline}`])
  assert.equal(acceptedOne.status, 0)
  assert.equal(JSON.parse(acceptedOne.stdout).entries[0].count, 1)
  assert.equal(JSON.parse(acceptedOne.stdout).entries[0].reason, 'Sample fixture')
  assert.equal(JSON.parse(acceptedOne.stdout).entries[0].expiresAt, policyDeadline)
  const expiredCandidate = JSON.parse(acceptedOne.stdout)
  expiredCandidate.entries[0].expiresAt = '2000-01-01T00:00:00Z'
  const expiredPath = join(root, 'expired-baseline.json')
  writeFileSync(expiredPath, JSON.stringify(expiredCandidate))
  const returned = cli([readOnly, '--json', `--baseline=${expiredPath}`])
  assert.equal(returned.status, 2)
  assert.equal(JSON.parse(returned.stdout).baselineExpired, 1)
  assert.equal(JSON.parse(returned.stdout).baselineSuppressed, 0)
  assert.throws(() => readFileSync(join(readOnly, 'canship-baseline.json')), { code: 'ENOENT' })
  // 正常扫描不创建结果文件；输出指向项目源码时须保留原内容。
  const sourceBefore = readFileSync(join(clean,'index.ts'),'utf8')
  assert.equal(cli([clean, `--report=${join(clean,'index.ts')}`]).status,3)
  const failedOutput = cli([clean, `--report=${join(clean,'index.ts')}`])
  assert.match(failedOutput.stdout,/exit 3 · report output failed/)
  assert.match(failedOutput.stderr,/\[OUTPUT_WRITE_FAILED\]/)
  assert.equal(readFileSync(join(clean,'index.ts'),'utf8'),sourceBefore)
  const privateExcerpt = sample('excerpt', { 'cors.ts': "const note='PRIVATE_SMOKE_SENTINEL'; app.use(cors({origin:true,credentials:true}));" })
  const html = join(root, 'report.html')
  const sarif = join(root, 'report.sarif')
  const report = cli([privateExcerpt, '--json', '--no-excerpts', `--report=${html}`, `--sarif=${sarif}`])
  assert.equal(report.status, 1)
  assert.equal(JSON.parse(report.stdout).excerptsOmitted, true)
  for (const text of [report.stdout, readFileSync(html, 'utf8'), readFileSync(sarif, 'utf8')]) assert.doesNotMatch(text, /PRIVATE_SMOKE_SENTINEL/)
  assert.equal(JSON.parse(readFileSync(sarif, 'utf8')).version, '2.1.0')
  const reportHtml = readFileSync(html, 'utf8')
  assert.match(reportHtml, /data-filter-conf="likely"/)
  assert.match(reportHtml, /id="finding-[a-f0-9]{64}"/)
  assert.match(reportHtml, /data-copy-ref=/)
  // 从实际安装包验收新增规则及终端视图，不执行样本代码。
  const releaseCases = [
    ['sql-input', 'app/api/items/route.ts',
      "export async function GET(req){const id=req.nextUrl.searchParams.get('id');return prisma.$queryRawUnsafe('SELECT * FROM items WHERE id='+id);}",
      'injection/sql', 'certain', 1],
    ['shell-input', 'app/api/run/route.ts',
      "import {exec} from 'node:child_process';export async function POST(req){const body=await req.json();exec('echo '+body.message);}",
      'injection/command', 'certain', 1],
    ['outbound-input', 'app/api/fetch/route.ts',
      "export async function GET(req){return fetch(req.nextUrl.searchParams.get('url'));}",
      'ssrf/request-url', 'likely', 2],
    ['redirect-input', 'app/api/redirect/route.ts',
      "import {redirect} from 'next/navigation';export async function GET(req){redirect(req.nextUrl.searchParams.get('next'));}",
      'redirect/open', 'certain', 2],
    ['session-trust', 'app/dashboard/page.tsx',
      'export default async function Page(){const {data:{session}}=await supabase.auth.getSession();if(!session)return null;return session.user.id;}',
      'auth/unverified-session', 'certain', 1],
    ['webhook-trust', 'app/api/webhooks/route.ts',
      "import Stripe from 'stripe';export async function POST(req){const event=await req.json();if(event.type==='invoice.paid')await markPaid(event.data.object.id);}",
      'webhook/unverified-signature', 'certain', 1],
  ]
  for (const [name, path, source, rule, confidence, status] of releaseCases) {
    const target = sample(name, { [path]: source })
    const checked = cli([target, '--json', '--all'])
    assert.equal(checked.status, status, name)
    const output = JSON.parse(checked.stdout)
    assert.equal(output.version, version, name)
    assert.equal(output.partial, false, name)
    assert.deepEqual(output.findings.map(f => [f.ruleId, f.confidence]), [[rule, confidence]], name)
    const verbose = cli([target, '--all', '--verbose'])
    assert.equal(verbose.status, status, name)
  }
  // 安装后的构建必须保留反例告警，也不能将正常鉴权误报为开放接口。
  const admin = "import {createClient} from '@supabase/supabase-js';const admin=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);"
  const write = "await admin.from('items').delete().neq('id',0);"
  for (const guarded of [false, true]) {
    const target = sample(`middleware-${guarded}`, {
      'server.ts': `import express from 'express';${admin}const app=express();
        async function requireLogin(req,res,next){${guarded ? '' : 'if(req.headers.authorization)'} await requireAuth(req);next();}
        app.post('/items',requireLogin,async(req,res)=>{${write}res.end();});`,
    })
    const checked = cli([target, '--json', '--all'])
    const output = JSON.parse(checked.stdout)
    assert.equal(output.partial, false)
    assert.deepEqual(output.findings.map(f => f.ruleId), guarded ? [] : ['api/admin-db-access-without-auth'])
    assert.equal(checked.status, guarded ? 0 : 2)
  }
  const proxy = sample('dynamic-middleware-path', {
    'server.ts': `import {Hono} from 'hono';import {bearerAuth} from 'hono/bearer-auth';${admin}const app=new Hono();
      app.use(process.env.PRIVATE_PATH,bearerAuth({token:process.env.AUTH_TOKEN}));
      app.post('/public/items',async(c)=>{${write}return c.json({});});`,
  })
  const exposed = cli([proxy, '--json', '--all'])
  assert.equal(exposed.status, 1)
  assert.equal(JSON.parse(exposed.stdout).partial, false)
  assert.deepEqual(JSON.parse(exposed.stdout).findings.map(f => f.ruleId), ['api/admin-db-access-without-auth'])
  // OpenAPI 文档中的 security 不等于鉴权；真实路由中间件才可保护处理函数。
  for (const guarded of [false, true]) {
    const target = sample(`openapi-${guarded}`, {
      'server.ts': `import {OpenAPIHono,createRoute} from '@hono/zod-openapi';
        import {bearerAuth} from 'hono/bearer-auth';${admin}const app=new OpenAPIHono();
        const route=createRoute({method:'delete',path:'/items/{id}',responses:{},
          ${guarded ? 'middleware:bearerAuth({token:process.env.AUTH_TOKEN})' : 'security:[{bearerAuth:[]}]'}});
        app.openapi(route,async(c)=>{${write}return c.json({});});`,
    })
    const checked = cli([target, '--json', '--all'])
    const output = JSON.parse(checked.stdout)
    assert.equal(output.partial, false)
    assert.deepEqual(output.findings.map(f => f.ruleId), guarded ? [] : ['api/admin-db-access-without-auth'])
    assert.equal(checked.status, guarded ? 0 : 1)
  }
  // 跨文件配置的中间件必须在定义文件中解析，消费者的修改不能借用原配置放行。
  for (const mutated of [false, true]) {
    const target = sample(`openapi-import-${mutated}`, {
      'server.ts': `import {OpenAPIHono} from '@hono/zod-openapi';import {route} from './routes';${admin}
        ${mutated ? 'route.middleware=[];' : ''}
        const app=new OpenAPIHono();app.openapi(route,async(c)=>{${write}return c.json({});});`,
      'routes.ts': "export {route} from './config';",
      'config.ts': `import {createRoute} from '@hono/zod-openapi';import {bearerAuth} from 'hono/bearer-auth';
        export const route=createRoute({method:'delete',path:'/items',middleware:bearerAuth({token:process.env.AUTH_TOKEN}),responses:{}});`,
    })
    const checked = cli([target, '--json', '--all'])
    const output = JSON.parse(checked.stdout)
    assert.equal(output.partial, false)
    assert.deepEqual(output.findings.map(f => f.ruleId), mutated ? ['api/admin-db-access-without-auth'] : [])
    assert.equal(checked.status, mutated ? 1 : 0)
  }
  // 批量入口无法解析时须标记不完整，已解析入口的阻断结果仍优先。
  for (const known of [false, true]) {
    const target = sample(`openapi-batch-${known}`, {
      'server.ts': `import {OpenAPIHono} from '@hono/zod-openapi';${admin}const app=new OpenAPIHono();
        app.openapiRoutes([unknownEntry${known ? `,{route:{method:'delete',path:'/items',responses:{}},handler:async(c)=>{${write}return c.json({});}}` : ''}]);`,
    })
    const checked = cli([target, '--json', '--all'])
    const output = JSON.parse(checked.stdout)
    assert.equal(checked.status, known ? 1 : 3)
    assert.equal(output.partial, true)
    assert.deepEqual(output.errors.map(error => error.ruleId), ['engine/openapi-routes'])
    assert.equal(cli([target, '--json', '--all', '--best-effort']).status, known ? 1 : 0)
  }
  console.log(JSON.stringify({ version, packageFiles: expected.length, runtimeDependencies: 0, smoke: 'passed' }))
} finally {
  // 仅移除本次创建的隔离安装与样本目录。
  rmSync(root, { recursive: true, force: true })
}
