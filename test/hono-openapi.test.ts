/** OpenAPI 路由只采用可解析的运行时中间件，不将接口文档视为鉴权。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
const imports = "import { OpenAPIHono, createRoute } from '@hono/zod-openapi';\n"
const admin = "import { createClient } from '@supabase/supabase-js';\nconst db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);\n"
const auth = "import { bearerAuth } from 'hono/bearer-auth';\n"
const guard = 'bearerAuth({token:process.env.AUTH_TOKEN})'
const handler = "async(c)=>{await db.from('items').delete();return c.json({ok:true});}"
const config = "{method:'delete',path:'/items/{id}',responses:{200:{description:'OK'}}}"

async function check(source: string, extra: Record<string, string> = {}) {
  const root = mkdtempSync(join(tmpdir(), 'canship-openapi-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"example-api"}', 'src/index.ts': source, ...extra })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  const result = await scan(root)
  assert.equal(result.partial, false)
  return result.findings.filter(f => /^(?:api|injection|ssrf|redirect|webhook)\//.test(f.ruleId))
}

for (const declaration of [config, `createRoute(${config})`]) {
  test(`an inline OpenAPI configuration exposes its handler: ${declaration.startsWith('createRoute')}`, async () => {
    const list = await check(imports + admin + `const app=new OpenAPIHono();app.openapi(${declaration},${handler});`)
    assert.deepEqual(list.map(f => [f.ruleId, f.confidence]), [['api/admin-db-access-without-auth', 'certain']])
    assert.equal(list[0]!.title, 'Anyone can call /items/:id and it queries your database as admin')
  })
}

test('local route constants, factory aliases and base paths are resolved', async () => {
  const list = await check("import {OpenAPIHono as Api,createRoute as defineRoute} from '@hono/zod-openapi';\n" + admin +
    `const route=defineRoute(${config});const alias=route;const app=new Api().basePath('/api').openapi(alias,${handler});`)
  assert.equal(list.length, 1)
  assert.equal(list[0]!.title, 'Anyone can call /api/items/:id and it queries your database as admin')
})

for (const middleware of [guard, `[${guard}] as const`]) {
  test(`resolved route middleware protects the handler: ${middleware.startsWith('[')}`, async () => {
    assert.deepEqual(await check(imports + admin + auth + 'const app=new OpenAPIHono();' +
      `app.openapi(createRoute({method:'delete',path:'/items',middleware:${middleware},responses:{}}),${handler});`), [])
  })
}

test('security declarations and validation hooks do not authenticate the main handler', async () => {
  const list = await check(imports + admin + 'const app=new OpenAPIHono();' +
    `app.openapi({method:'delete',path:'/items',security:[{bearerAuth:[]}],responses:{}},${handler},` +
    "(result,c)=>{if(!result.success)return c.json({error:'invalid'},401);});")
  assert.deepEqual(list.map(f => f.ruleId), ['api/admin-db-access-without-auth'])
})

test('middleware path and registration order remain significant', async () => {
  for (const [path, before, protectedRoute] of [['/items/*', true, true], ['/elsewhere/*', true, false], ['/items/*', false, false]] as const) {
    const middleware = `app.use('${path}',${guard});`
    const list = await check(imports + admin + auth + 'const app=new OpenAPIHono();' +
      (before ? middleware : '') + `app.openapi(${config},${handler});` + (before ? '' : middleware))
    assert.equal(list.length, protectedRoute ? 0 : 1)
  }
})

test('mounted OpenAPI apps preserve prefix and parent protection', async () => {
  for (const guarded of [false, true]) {
    const list = await check(imports + auth + "import {child} from './child';const app=new OpenAPIHono();" +
      (guarded ? `app.use('/api/*',${guard});` : '') + "app.route('/api',child);", {
      'src/child.ts': imports + admin + `export const child=new OpenAPIHono().openapi(${config},${handler});`,
    })
    assert.equal(list.length, guarded ? 0 : 1)
    if (!guarded) assert.equal(list[0]!.title, 'Anyone can call /api/items/:id and it queries your database as admin')
  }
})

test('imported controllers remain request handlers', async () => {
  const list = await check(imports + "import {remove} from './controller';const app=new OpenAPIHono();" +
    `app.openapi(${config},remove);`, { 'src/controller.ts': admin + `export const remove=${handler};` })
  assert.deepEqual(list.map(f => [f.ruleId, f.file]), [['api/admin-db-access-without-auth', 'src/controller.ts']])
})

test('OpenAPI instances passed into registration helpers preserve their kind', async () => {
  const list = await check(imports + "import {register} from './register';const app=new OpenAPIHono();register(app);", {
    'src/register.ts': admin + `export function register(api){api.openapi(${config},${handler});}`,
  })
  assert.deepEqual(list.map(f => [f.ruleId, f.file]), [['api/admin-db-access-without-auth', 'src/register.ts']])
})

test('chains after openapi still register ordinary and OpenAPI routes', async () => {
  const list = await check(imports + admin + `const app=new OpenAPIHono().openapi(${config},${handler})` +
    `.post('/other',${handler}).openapi({method:'post',path:'/last',responses:{}},${handler});`)
  assert.equal(list.length, 3)
  assert.deepEqual(list.map(f => f.title), ['/items/:id', '/other', '/last'].map(path =>
    `Anyone can call ${path} and it queries your database as admin`))
})

test('a shared registration helper retains OpenAPI capability after a plain Hono instance', async () => {
  const list = await check(imports + "import {Hono} from 'hono';import {register} from './register';" +
    'const plain=new Hono();const app=new OpenAPIHono();register(plain);register(app);', {
    'src/register.ts': admin + `export function register(api){api.openapi(${config},${handler});}`,
  })
  assert.deepEqual(list.map(f => [f.ruleId, f.file]), [['api/admin-db-access-without-auth', 'src/register.ts']])
})

test('ordinary objects and plain Hono instances with an openapi method are not new entry points', async () => {
  assert.deepEqual(await check("import {Hono} from 'hono';\n" + admin +
    `const app=new Hono();app.openapi(${config},${handler});const schema={};schema.openapi(${config},${handler});`), [])
})

for (const source of [
  `const route={method:'delete',path:'/items',middleware:${guard},...overrides};`,
  `const route={method:'delete',path:'/items',middleware:${guard},[key]:[]};`,
  `const route={method:'delete',path:'/items',middleware:${guard},get middleware(){return []}};`,
  `const route={method:'delete',path:'/items',middleware:${guard}};route.middleware=[];`,
  `const route={method:'delete',path:'/items',middleware:${guard}};const alias=route;alias.middleware=[];`,
  `const route={method:'delete',path:'/items',middleware:${guard}};Object.assign(route,{middleware:[]});`,
  `let route={method:'delete',path:'/items',middleware:${guard}};route=other;`,
  "import {route} from './route-config';",
  'const route=other;const other=route;',
]) {
  test(`unresolved or mutable route configuration never proves protection: ${source.slice(0, 45)}`, async () => {
    const list = await check(imports + admin + auth + source + `const app=new OpenAPIHono();app.openapi(route,${handler});`)
    assert.equal(list.length, 1)
    assert.equal(list[0]!.ruleId, 'api/admin-db-access-without-auth')
  })
}

test('a shadowed configuration cannot borrow middleware from an outer constant', async () => {
  const list = await check(imports + admin + auth + `const route={path:'/items',middleware:${guard}};` +
    `function register(route){const app=new OpenAPIHono();app.openapi(route,${handler});}`)
  assert.equal(list.length, 1)
})

test('a shadowed createRoute factory does not prove protection', async () => {
  const list = await check(imports + admin + auth +
    `function register(createRoute){const app=new OpenAPIHono();app.openapi(createRoute({path:'/items',middleware:${guard}}),${handler});}`)
  assert.equal(list.length, 1)
})

test('a local guarded route constant provides real middleware evidence', async () => {
  assert.deepEqual(await check(imports + admin + auth +
    `const route=createRoute({method:'delete',path:'/items',middleware:[${guard}] as const,responses:{}});` +
    `const app=new OpenAPIHono();app.openapi(route,${handler});`), [])
})

for (const middleware of [`[${guard}].filter(()=>false)`, `${guard} && []`, `enabled ? [${guard}] : []`]) {
  test(`transformed or conditional middleware is not proof: ${middleware}`, async () => {
    const list = await check(imports + admin + auth + `const app=new OpenAPIHono();` +
      `app.openapi({method:'delete',path:'/items',middleware:${middleware},responses:{}},${handler});`)
    assert.equal(list.length, 1)
  })
}

test('dynamic paths cannot borrow protection from an unrelated literal path', async () => {
  const list = await check(imports + admin + auth + "const path='/private';const app=new OpenAPIHono();" +
    `app.use('/private',${guard});function register(path){app.openapi({method:'delete',path,responses:{}},${handler});}`)
  assert.equal(list.length, 1)
  assert.match(list[0]!.title, /dynamic path/)
})

test('a route configuration outside the current block does not supply a path or middleware', async () => {
  const list = await check(imports + admin + auth +
    `function unused(){const route={path:'/items',middleware:${guard}};}` +
    `const app=new OpenAPIHono();app.openapi(route,${handler});`)
  assert.equal(list.length, 1)
  assert.match(list[0]!.title, /dynamic path/)
})

test('excessive configuration alias depth keeps the handler visible', async () => {
  const aliases = Array.from({length:12}, (_, i) => `const r${i + 1}=r${i};`).join('')
  const list = await check(imports + admin + auth + `const r0={path:'/items',middleware:${guard}};` + aliases +
    `const app=new OpenAPIHono();app.openapi(r12,${handler});`)
  assert.equal(list.length, 1)
})

test('input rules follow direct and validated request values in OpenAPI handlers', async () => {
  const list = await check(imports + "import {pool} from './db';const app=new OpenAPIHono();\n" +
    "app.openapi({method:'get',path:'/search',responses:{}},async(c)=>{return pool.query('SELECT * FROM items WHERE id='+c.req.query('id'));});\n" +
    "app.openapi({method:'post',path:'/fetch',responses:{}},async(c)=>{const {url}=c.req.valid('json');return fetch(url);});\n" +
    "app.openapi({method:'get',path:'/go',responses:{}},c=>c.redirect(c.req.query('next')));\n")
  assert.deepEqual(list.map(f => [f.ruleId, f.confidence]), [
    ['injection/sql', 'certain'], ['ssrf/request-url', 'likely'], ['redirect/open', 'certain'],
  ])
})

test('OpenAPI webhook handlers are checked even when hidden from the generated specification', async () => {
  const list = await check(imports + "import Stripe from 'stripe';const app=new OpenAPIHono();" +
    "app.openapi({method:'post',path:'/webhook',hide:true,responses:{}},async(c)=>{const event=await c.req.json();if(event.type==='invoice.paid')await markPaid(event.data.object.id);});")
  assert.deepEqual(list.map(f => f.ruleId), ['webhook/unverified-signature'])
})
