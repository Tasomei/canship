/** 批量入口逐项解析；未知入口记录覆盖缺口，保留已解析项的结果。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import { summarize } from '../src/index.js'
import type { ScanOptions } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
const imports = "import {OpenAPIHono,createRoute,defineOpenAPIRoute} from '@hono/zod-openapi';\n"
const database = "import {createClient} from '@supabase/supabase-js';const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);\n"
const auth = "import {bearerAuth} from 'hono/bearer-auth';\n"
const guard = 'bearerAuth({token:process.env.AUTH_TOKEN})'
const handler = "async(c)=>{await db.from('items').delete();return c.json({});}"
const route = "{method:'delete',path:'/items/{id}',responses:{}}"
const entry = `{route:${route},handler:${handler}}`

async function inspect(source: string, extra: Record<string, string> = {}, options: ScanOptions = {}) {
  const root = mkdtempSync(join(tmpdir(), 'canship-openapi-batch-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"example-api"}', 'src/index.ts': source, ...extra })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return scan(root, options)
}

for (const list of [`[${entry}]`, `[${entry}] as const`]) {
  test(`literal batches expose route handlers: ${list.endsWith('const')}`, async () => {
    const result = await inspect(imports + database + `const app=new OpenAPIHono();app.openapiRoutes(${list});`)
    assert.equal(result.partial, false)
    assert.deepEqual(result.findings.map(f => f.ruleId), ['api/admin-db-access-without-auth'])
    assert.equal(result.findings[0]!.title, 'Anyone can call /items/:id and it queries your database as admin')
  })
}

for (const value of ['false', 'true', '0', 'null', 'enabled']) {
  test(`only literal false disables a batch entry: ${value}`, async () => {
    const result = await inspect(imports + database + `const app=new OpenAPIHono();app.openapiRoutes([{route:${route},handler:${handler},addRoute:${value}}]);`)
    assert.equal(result.partial, false)
    assert.equal(result.findings.length, value === 'false' ? 0 : 1)
  })
}

test('batch middleware protects only its own handler', async () => {
  const result = await inspect(imports + database + auth + 'const app=new OpenAPIHono();app.openapiRoutes([' +
    `{route:{method:'delete',path:'/private',middleware:${guard},responses:{}},handler:${handler}},` +
    `{route:{method:'delete',path:'/public',responses:{}},handler:${handler}}]);`)
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings.map(f => f.title), ['Anyone can call /public and it queries your database as admin'])
})

test('batch hooks and OpenAPI security declarations do not prove authentication', async () => {
  const result = await inspect(imports + database + `const app=new OpenAPIHono();app.openapiRoutes([{route:{method:'delete',path:'/items',security:[{bearerAuth:[]}],responses:{}},` +
    `handler:${handler},hook:(result,c)=>{if(!result.success)return c.json({},401);}}]);`)
  assert.equal(result.partial, false)
  assert.equal(result.findings.length, 1)
})

test('batch arrays and entry constants can be imported through a barrel', async () => {
  const result = await inspect(imports + "import {routes} from './routes';const app=new OpenAPIHono().basePath('/api');app.openapiRoutes(routes);", {
    'src/routes.ts': "export {routes} from './config';",
    'src/config.ts': imports + database + `const item=defineOpenAPIRoute(${entry});export const routes=[item] as const;`,
  })
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings.map(f => [f.ruleId, f.file]), [['api/admin-db-access-without-auth', 'src/config.ts']])
  assert.match(result.findings[0]!.title, /\/api\/items\/:id /)
})

test('imported batch metadata resolves its middleware in the defining module', async () => {
  const result = await inspect(imports + "import routes from './routes';const app=new OpenAPIHono();app.openapiRoutes(routes);", {
    'src/routes.ts': imports + database + auth + `export default [{route:{method:'delete',path:'/items',middleware:${guard},responses:{}},handler:${handler}}];`,
  })
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings, [])
})

test('batch registration composes with ordinary chains and mounted sub-apps', async () => {
  const result = await inspect(imports + database + `const child=new OpenAPIHono().basePath('/v1').openapiRoutes([${entry}])` +
    `.post('/other',${handler});const app=new OpenAPIHono();app.route('/api',child);`)
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings.map(f => f.title), ['/api/v1/items/:id', '/api/v1/other'].map(path =>
    `Anyone can call ${path} and it queries your database as admin`))
})

test('disabled batch entries do not change the following pathless route', async () => {
  const result = await inspect(imports + database + `const app=new OpenAPIHono().get('/before',c=>c.text('ok'))` +
    `.openapiRoutes([{route:${route},handler:${handler},addRoute:false}]).post(${handler});`)
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings.map(f => f.title), ['Anyone can call /before and it queries your database as admin'])
})

test('request-input checks apply to batch handlers', async () => {
  const result = await inspect(imports + "import {pool} from './db';const app=new OpenAPIHono();" +
    "app.openapiRoutes([{route:{method:'get',path:'/search',responses:{}},handler:async(c)=>pool.query('SELECT * FROM items WHERE id='+c.req.query('id'))}]);")
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings.map(f => f.ruleId), ['injection/sql'])
})

for (const value of ['unknownRoutes', 'loadRoutes()', '[unknownEntry]', `[...unknownRoutes,${entry}]`]) {
  test(`unresolved batch input discloses incomplete coverage: ${value.slice(0, 35)}`, async () => {
    const result = await inspect(imports + database + `const app=new OpenAPIHono();app.openapiRoutes(${value});`)
    assert.equal(result.partial, true)
    assert.equal(result.errors.length, 1)
    assert.equal(result.errors[0]!.kind, 'incomplete')
    assert.equal(result.errors[0]!.ruleId, 'engine/openapi-routes')
    if (value.startsWith('[...')) assert.equal(result.findings.length, 1)
    else assert.equal(summarize(result).exitCode, 3)
  })
}

test('unknown batches do not affect scans restricted to unrelated rules', async () => {
  const result = await inspect(imports + 'const app=new OpenAPIHono();app.openapiRoutes(unknownRoutes);', {}, { only: ['secrets'] })
  assert.equal(result.partial, false)
  assert.deepEqual(result.errors, [])
})

for (const only of ['api', 'injection', 'ssrf', 'redirect', 'webhook', 'auth']) {
  test(`route-dependent rule selection preserves batch diagnostics: ${only}`, async () => {
    const result = await inspect(imports + 'const app=new OpenAPIHono();app.openapiRoutes(unknownRoutes);', {}, { only: [only] })
    assert.equal(result.partial, true)
    assert.equal(result.errors.length, 1)
  })
}

test('plain Hono and ordinary objects do not activate batch coverage diagnostics', async () => {
  const result = await inspect("import {Hono} from 'hono';const app=new Hono();app.openapiRoutes(unknownRoutes);const object={};object.openapiRoutes(unknownRoutes);")
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings, [])
})

test('unresolved handlers are not silently accepted as checked', async () => {
  const result = await inspect(imports + `const app=new OpenAPIHono();app.openapiRoutes([{route:${route},handler:unknownHandler}]);`)
  assert.equal(result.partial, true)
  assert.equal(summarize(result).exitCode, 3)
})

test('mutated batch arrays cannot reuse stale entries', async () => {
  const result = await inspect(imports + database + `const routes=[${entry}];routes.push(dynamicEntry);const app=new OpenAPIHono();app.openapiRoutes(routes);`)
  assert.equal(result.partial, true)
})

test('cyclic array aliases terminate and disclose the missing coverage', async () => {
  const result = await inspect(imports + 'const first=second;const second=first;const app=new OpenAPIHono();app.openapiRoutes(first);')
  assert.equal(result.partial, true)
})

test('literal spreads retain all entries and preserve their defining files', async () => {
  const result = await inspect(imports + database + `const first=[${entry}];const app=new OpenAPIHono();app.openapiRoutes([...first]);`)
  assert.equal(result.partial, false)
  assert.equal(result.findings.length, 1)
})

for (const count of [256, 257]) {
  test(`batch entry budget is enforced at ${count}`, async () => {
    const items = Array.from({length:count}, (_, i) => `{route:{method:'get',path:'/items/${i}',responses:{}},handler:c=>c.json({})}`).join(',')
    const result = await inspect(imports + `const app=new OpenAPIHono();app.openapiRoutes([${items}]);`)
    assert.equal(result.partial, count > 256)
    assert.equal(result.errors.length, count > 256 ? 1 : 0)
    assert.equal(summarize(result).exitCode, count > 256 ? 3 : 0)
  })
}

for (const depth of [7, 8]) {
  test(`array spread depth is bounded at ${depth}`, async () => {
    const list = '[...'.repeat(depth) + `[${entry}]` + ']'.repeat(depth)
    const result = await inspect(imports + database + `const app=new OpenAPIHono();app.openapiRoutes(${list});`)
    assert.equal(result.partial, depth === 8)
    assert.equal(result.findings.length, depth === 8 ? 0 : 1)
  })
}

test('disabled unknown entries and empty batches require no handler resolution', async () => {
  const result = await inspect(imports + 'const app=new OpenAPIHono().openapiRoutes([]).openapiRoutes([{addRoute:false,route:unknown,handler:missing}]);')
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings, [])
})

test('method shorthand handlers in imported batch objects retain their source', async () => {
  const result = await inspect(imports + "import {routes} from './config';const app=new OpenAPIHono();app.openapiRoutes(routes);", {
    'src/config.ts': database + `export const routes=[{route:${route},async handler(c){await db.from('items').delete();return c.json({});}}];`,
  })
  assert.equal(result.partial, false)
  assert.deepEqual(result.findings.map(f => [f.ruleId,f.file]), [['api/admin-db-access-without-auth','src/config.ts']])
})

test('coverage diagnostics include a location without copying raw batch expressions', async () => {
  const result = await inspect(imports + "const app=new OpenAPIHono();app.openapiRoutes(loadRoutes('PRIVATE_BATCH_SENTINEL'));")
  assert.equal(result.partial, true)
  assert.match(result.errors[0]!.message, /src\/index.ts:2:/)
  assert.doesNotMatch(JSON.stringify(result.errors), /PRIVATE_BATCH_SENTINEL|loadRoutes/)
})

test('an opaque factory assigned to a named handler remains unresolved', async () => {
  const result = await inspect(imports + `const handle=createHandler();const app=new OpenAPIHono();app.openapiRoutes([{route:${route},handler:handle}]);`)
  assert.equal(result.partial, true)
  assert.equal(summarize(result).exitCode, 3)
})

test('named expression handlers remain supported in batches', async () => {
  const result = await inspect(imports + database + `const handle=async c=>db.from('items').delete();const app=new OpenAPIHono();app.openapiRoutes([{route:${route},handler:handle}]);`)
  assert.equal(result.partial, false)
  assert.equal(result.findings.length, 1)
})
