/** 合成项目验证工厂来源、实例隔离和无法证明的封装；不执行项目代码。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'

const db = "import { PrismaClient } from '@prisma/client'\nconst prisma = new PrismaClient()\n"
const route = "app.post('/items', async (c) => { await prisma.item.create({ data: {} }); return c.json({ ok: true }) })\n"
async function scanFixture(files: Record<string, string>, options: Parameters<typeof scan>[1] = {}) {
  const root = mkdtempSync(join(tmpdir(), 'canship-factories-'))
  try {
    for (const [path, text] of Object.entries({ 'package.json': '{"name":"synthetic-app"}', ...files })) {
      const target = join(root, path); mkdirSync(dirname(target), { recursive: true }); writeFileSync(target, text)
    }
    return await scan(root, options)
  } finally { rmSync(root, { recursive: true, force: true }) }
}
async function inspect(files: Record<string, string>) {
  const result = await scanFixture(files)
  assert.deepEqual(result.errors, [])
  return result.findings.filter(f => f.ruleId === 'api/db-write-without-auth')
}

test('a project factory identifies Hono routes without a framework import in the route file', async () => {
  const found = await inspect({
    'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()\n",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route,
  })
  assert.equal(found.length, 1)
  assert.equal(found[0]!.file, 'src/routes.ts')
  assert.match(found[0]!.title, /^\/items writes/)
})

test('local function and block-arrow factories preserve literal base paths', async () => {
  for (const factory of ["function make() { return new Hono().basePath('/api') }", "const make = () => { return new Hono().basePath('/api') }"]) {
    const found = await inspect({ 'src/app.ts': "import { Hono } from 'hono'\n" + db + factory + '\nconst app = make()\n' + route })
    assert.equal(found.length, 1, factory)
    assert.match(found[0]!.title, /^\/api\/items writes/)
  }
})

test('default exports, named re-exports and delegated factories retain framework identity', async () => {
  const found = await inspect({
    'src/base.ts': "import { Hono } from 'hono'\nexport default function make() { return new Hono() }",
    'src/barrel.ts': "export { default as build } from './base'",
    'src/factory.ts': "import { build } from './barrel'\nexport const make = () => build()",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route,
  })
  assert.equal(found.length, 1)
})

test('Express and Fastify factories expose registered handlers', async () => {
  for (const definition of ["import express from 'express'\nexport const make = () => express.Router()",
    "import { Router as R } from 'express'\nexport const make = () => R()",
    "import fastify from 'fastify'\nexport const make = () => fastify()"] ) {
    const found = await inspect({ 'src/factory.ts': definition,
      'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route })
    assert.equal(found.length, 1, definition)
  }
})

test('factory-produced OpenAPI instances use the existing OpenAPI route parser', async () => {
  const found = await inspect({
    'src/factory.ts': "import { OpenAPIHono } from '@hono/zod-openapi'\nexport const make = () => new OpenAPIHono()",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' +
      "app.openapi({ method: 'post', path: '/items', responses: {} }, async c => { await prisma.item.create({ data: {} }); return c.json({}) })",
  })
  assert.equal(found.length, 1)
})

test('middleware applied to one fresh instance cannot protect another factory result', async () => {
  const found = await inspect({
    'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const guarded = make()\nconst app = make()\n' +
      "guarded.use('*', async (c,next) => { if (!c.get('user')) return c.json({},401); await next() })\n" +
      route.replace('app.post', 'guarded.post').replace("'/items'", "'/protected'") + route,
  })
  assert.equal(found.length, 1)
  assert.match(found[0]!.title, /^\/items writes/)
})

test('names alone, private exports and multiple star exports never prove a router factory', async () => {
  for (const files of [
    { 'src/factory.ts': 'export const make = () => ({ post() {} })' },
    { 'src/factory.ts': "import { Hono } from 'hono'\nconst make = () => new Hono()" },
    { 'src/factory.ts': "export * from './one'; export * from './two'", 'src/one.ts': "import { Hono } from 'hono'; export const make = () => new Hono()", 'src/two.ts': 'export const make = () => ({})' },
  ]) assert.deepEqual(await inspect({ ...files, 'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route }), [])
})

test('conditional, async, parameter-dependent and return-newline factories are not guessed', async () => {
  for (const definition of ['export const make = () => flag ? new Hono() : {}', 'export const make = async () => new Hono()',
    'export const make = (Ctor) => new Ctor()', 'export function make() { return\nnew Hono() }']) {
    assert.deepEqual(await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\n" + definition,
      'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route }), [], definition)
  }
})

test('reassignment, shadowing and type-only imports cannot lend factory identity', async () => {
  for (const extra of ['make = replacement', 'function other(make) { return make() }', 'const { make } = replacement']) {
    assert.deepEqual(await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
      'src/routes.ts': "import { make } from './factory'\n" + db + extra + '\nconst app = make()\n' + route }), [], extra)
  }
  assert.deepEqual(await inspect({ 'src/factory.ts': "import type { Hono } from 'hono'\nexport const make = () => new Hono()",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route }), [])
})

test('cyclic re-exports terminate and disclose incomplete route analysis', async () => {
  const result = await scanFixture({ 'src/a.ts': "export { make } from './b'", 'src/b.ts': "export { make } from './a'",
    'src/routes.ts': "import { make } from './a'\n" + db + 'const app = make()\n' + route })
  assert.deepEqual(result.findings, [])
  assert.equal(result.partial, true)
  assert.deepEqual(result.errors.map(item => [item.ruleId, item.code]), [['engine/router-factories', 'ROUTE_UNRESOLVED']])
})

test('short factory names, const aliases and same-app path aliases are resolved', async () => {
  const found = await inspect({
    'apps/web/src/factory.ts': "import { Hono } from 'hono'\nconst c = () => new Hono()\nexport { c as make }",
    'apps/web/src/routes.ts': "import { make } from '@/factory'\n" + db + 'const app = make()\n' + route,
    'apps/admin/src/factory.ts': 'export const make = () => ({})',
  })
  assert.equal(found.length, 1)
  assert.equal(found[0]!.file, 'apps/web/src/routes.ts')
})

test('a missing sibling alias never borrows a factory from another application or root', async () => {
  const found = await inspect({
    'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
    'apps/web/src/routes.ts': "import { make } from '@/factory'\n" + db + 'const app = make()\n' + route,
  })
  assert.deepEqual(found, [])
})

test('instance reassignment and supplied factory arguments are not treated as zero-argument factories', async () => {
  for (const creation of ["const app = make('different')", 'const app = make(); app = replacement()']) {
    assert.deepEqual(await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
      'src/routes.ts': "import { make } from './factory'\n" + db + creation + '\n' + route }), [])
  }
})

test('modified named default exports and shadowed constructors do not prove returned instances', async () => {
  for (const factory of ["export default function make() { return new Hono() }\nmake = replacement",
    'export default () => new Hono()\nfunction unrelated(Hono) {}']) {
    assert.deepEqual(await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\n" + factory,
      'src/routes.ts': "import make from './factory'\n" + db + 'const app = make()\n' + route }), [])
  }
})

test('the candidate budget is disclosed instead of silently claiming complete coverage', async () => {
  const source = Array.from({ length: 257 }, (_, i) => `const app${i} = make()\napp${i}.get('/status', c => c.text('ok'))`).join('\n')
  const result = await scanFixture({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
    'src/routes.ts': "import { make } from './factory'\n" + source })
  assert.deepEqual(result.findings, [])
  assert.equal(result.partial, true)
  assert.deepEqual(result.errors.map(item => item.code), ['ROUTE_UNRESOLVED'])
})

test('operators and unknown method chains cannot change a receiver while retaining its router identity', async () => {
  for (const suffix of [' && replacement', ' ? replacement : other', '.unknown()', '[0]']) {
    assert.deepEqual(await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
      'src/routes.ts': "import { make } from './factory'\n" + db + `const app = make()${suffix}\n` + route }), [], suffix)
  }
})

test('eight literal basePath calls are accepted and a ninth is disclosed', async () => {
  for (const count of [8, 9]) {
    const result = await scanFixture({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()" + ".basePath('/v')".repeat(count),
      'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route })
    assert.equal(result.partial, count === 9)
    assert.equal(result.findings.length, count === 8 ? 1 : 0)
    assert.equal(result.errors.length, count === 9 ? 1 : 0)
  }
})

test('request-input rules also use the newly discovered factory route', async () => {
  const result = await scanFixture({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' +
      "app.get('/items', async c => { const id = c.req.query('id'); return c.json(await prisma.$queryRawUnsafe('SELECT * FROM items WHERE id=' + id)) })" })
  assert.deepEqual(result.errors, [])
  assert.equal(result.findings.filter(item => item.ruleId === 'injection/sql').length, 1)
})

// 带参数的多语句工厂：按运行环境决定 basePath，体内注册中间件，返回局部实例。
const PARAMETERISED = "import { Hono } from 'hono'\nexport function createApp(name: string, _version: string) {\n  let app\n" +
  "  if (process.env.RUNTIME === 'edge') {\n    app = new Hono().basePath(`/${name}`)\n  }\n  else {\n    app = new Hono()\n  }\n" +
  "  app.use('*', (c, next) => { c.header('X-Source', name); return next() })\n  return app\n}\n"
const SUB_APP = "import { Hono } from 'hono'\n" + db + "export const items = new Hono()\n" +
  "items.post('/', async (c) => { await prisma.item.create({ data: {} }); return c.json({ ok: true }) })\n"
const ENTRY = "import { items } from '../routes/items'\nimport { createApp, serve } from '../lib/app'\n" +
  "const app = createApp('shop', '1')\napp.route('/items', items)\nserve(app, 'shop')\n"

test('parameterised factories with local instances carry mount prefixes even when the instance is passed on', async () => {
  const found = await inspect({ 'lib/app.ts': PARAMETERISED + 'export function serve(target: unknown, label: string) {}\n',
    'routes/items.ts': SUB_APP, 'entry/index.ts': ENTRY })
  assert.equal(found.length, 1)
  assert.equal(found[0]!.file, 'routes/items.ts')
  // 只在某个运行环境生效且依赖参数的前缀不写进 URL。
  assert.match(found[0]!.title, /^\/items writes/)
})

test('base paths agreeing across assignments are kept and differing ones are omitted', async () => {
  for (const [second, title] of [["new Hono().basePath('/api')", /^\/api\/items writes/], ["new Hono().basePath('/v2')", /^\/items writes/]] as const) {
    const factory = "import { Hono } from 'hono'\nexport const make = (flag: boolean) => {\n  let app = new Hono().basePath('/api')\n" +
      `  if (flag) app = ${second}\n  return app\n}\n`
    const found = await inspect({ 'src/factory.ts': factory, 'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make(true)\n' + route })
    assert.equal(found.length, 1, second)
    assert.match(found[0]!.title, title)
  }
})

test('middleware registered inside a factory body is not accepted as protection', async () => {
  const factory = "import { Hono } from 'hono'\nexport function make(name: string) {\n  const app = new Hono()\n" +
    "  app.use('*', async (c, next) => { if (!c.get('user')) return c.json({}, 401); await next() })\n  return app\n}\n"
  const found = await inspect({ 'src/factory.ts': factory, 'src/routes.ts': "import { make } from './factory'\n" + db + "const app = make('x')\n" + route })
  assert.equal(found.length, 1)
})

test('multi-statement factories that cannot prove one fresh returned instance are not guessed', async () => {
  for (const body of [
    'const app = new Hono()\n  const other = new Hono()\n  if (name) return other\n  return app',
    'let app = new Hono()\n  if (name) app = replacement()\n  return app',
    'const app = new Hono()\n  app.fetch = replacement\n  return app',
    'const app = new Hono()\n  Object.assign(app, replacement)\n  return app',
    'let app = new Hono()\n  ;[app] = replacements\n  return app',
    'let app = new Hono()\n  app ||= replacement\n  return app',
    'const app = new Hono()\n  return app.basePath(name)',
    'const app = arguments[0] ?? new Hono()\n  return app',
    'return name\n  const app = new Hono()',
    'const make2 = () => { const app = new Hono(); return app }\n  const app = replacement\n  return app',
  ]) {
    const factory = `import { Hono } from 'hono'\nexport function make(name: string) {\n  ${body}\n}\n`
    assert.deepEqual(await inspect({ 'src/factory.ts': factory, 'src/routes.ts': "import { make } from './factory'\n" + db + "const app = make('x')\n" + route }), [], body)
  }
})

test('arguments beyond the declared parameters, rest and destructured parameters are not guessed', async () => {
  for (const [signature, call] of [['(name: string)', "make('a', 'b')"], ['(...names: string[])', "make('a')"], ['({ name }: { name: string })', "make({ name: 'a' })"]]) {
    const factory = `import { Hono } from 'hono'\nexport function make${signature} {\n  const app = new Hono()\n  return app\n}\n`
    assert.deepEqual(await inspect({ 'src/factory.ts': factory, 'src/routes.ts': "import { make } from './factory'\n" + db + `const app = ${call}\n` + route }), [], signature)
  }
})

test('a factory instance used as a parameter elsewhere in the file still cannot borrow identity', async () => {
  for (const extra of ['function setup(app) { app.get = replacement }', 'const setup = (app: unknown) => app', 'class Setup { run(app) {} }']) {
    assert.deepEqual(await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
      'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + extra + '\n' + route }), [], extra)
  }
  for (const extra of ['register(app, { name: 1 })', 'if (app) { console.log(1) }']) {
    assert.equal((await inspect({ 'src/factory.ts': "import { Hono } from 'hono'\nexport const make = () => new Hono()",
      'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + extra + '\n' + route })).length, 1, extra)
  }
})

test('nine assignments to a factory instance are disclosed as a resolution limit', async () => {
  const assignments = Array.from({ length: 9 }, (_, i) => `  if (flag === ${i}) app = new Hono()\n`).join('')
  const result = await scanFixture({ 'src/factory.ts': `import { Hono } from 'hono'\nexport function make(flag: number) {\n  let app\n${assignments}  return app\n}\n`,
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make(1)\n' + route })
  assert.equal(result.partial, true)
  assert.deepEqual(result.errors.map(item => [item.ruleId, item.code]), [['engine/router-factories', 'ROUTE_UNRESOLVED']])
  assert.deepEqual(result.findings, [])
})

test('large functions returning plain objects are excluded without reporting a resolution limit', async () => {
  const methods = Array.from({ length: 120 }, (_, i) => `  async get${i}() { return service.load(${i}) },\n`).join('')
  for (const definition of [`export const makeHandlers = (service: any) => ({\n${methods}})\n`,
    `export function makeHandlers(service: any) {\n  const handlers = {\n${methods}  }\n  return { ...handlers }\n}\n`]) {
    const result = await scanFixture({ 'src/handlers.ts': definition,
      'src/handlers.test.ts': "import { makeHandlers } from './handlers'\nconst handlers = makeHandlers({})\nhandlers.get('/items', handlers.get0)\n" })
    assert.equal(result.partial, false, definition.slice(0, 40))
    assert.deepEqual(result.errors, [])
  }
})

test('an oversized factory body returning a local instance is disclosed', async () => {
  const filler = Array.from({ length: 700 }, (_, i) => `  const value${i} = name + '${i}'\n`).join('')
  const result = await scanFixture({ 'src/factory.ts': `import { Hono } from 'hono'\nexport function make(name: string) {\n  const app = new Hono()\n${filler}  return app\n}\n`,
    'src/routes.ts': "import { make } from './factory'\n" + db + "const app = make('x')\n" + route })
  assert.equal(result.partial, true)
  assert.deepEqual(result.errors.map(item => [item.ruleId, item.code]), [['engine/router-factories', 'ROUTE_UNRESOLVED']])
})

test('JSONC path mappings override conventional alias guesses without evaluating configuration', async () => {
  const found = await inspect({
    'tsconfig.json': '{ // synthetic configuration\n "compilerOptions": { "baseUrl": ".", "paths": { "@build/*": ["shared/*"], }, }, "include": ["src"], }',
    'shared/factory.ts': "import { Hono } from 'hono'; export const make = () => new Hono()",
    'src/routes.ts': "import { make } from '@build/factory'\n" + db + 'const app = make()\n' + route,
  })
  assert.equal(found.length, 1)
  assert.deepEqual(await inspect({
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@/factory': ['./ordinary.ts'] } } }),
    'ordinary.ts': 'export const make = () => ({})',
    'src/factory.ts': "import { Hono } from 'hono'; export const make = () => new Hono()",
    'src/routes.ts': "import { make } from '@/factory'\n" + db + 'const app = make()\n' + route,
  }), [])
})

test('ambiguous mappings, inherited configurations and framework-name remapping are not guessed', async () => {
  for (const config of [
    { compilerOptions: { paths: { '@build/*': ['./shared/*', './other/*'] } } },
    { extends: './base.json', compilerOptions: { paths: { '@build/*': ['./shared/*'] } } },
  ]) assert.deepEqual(await inspect({ 'tsconfig.json': JSON.stringify(config),
    'shared/factory.ts': "import { Hono } from 'hono'; export const make = () => new Hono()",
    'src/routes.ts': "import { make } from '@build/factory'\n" + db + 'const app = make()\n' + route }), [])
  assert.deepEqual(await inspect({ 'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { hono: ['./fake.ts'] } } }),
    'fake.ts': 'export class Hono {}', 'src/factory.ts': "import { Hono } from 'hono'; export const make = () => new Hono()",
    'src/routes.ts': "import { make } from './factory'\n" + db + 'const app = make()\n' + route }), [])
})

test('explicit workspace dependencies resolve only exported unambiguous runtime entries', async () => {
  for (const exports of ['./src/factory.ts', { '.': { types: './types.d.ts', import: './src/factory.ts', default: './src/factory.ts' } }]) {
    const found = await inspect({
      'package.json': JSON.stringify({ name: 'synthetic-root', workspaces: ['apps/*', 'packages/*'] }),
      'apps/web/package.json': JSON.stringify({ name: 'web', dependencies: { '@synthetic/router': 'workspace:*' } }),
      'packages/router/package.json': JSON.stringify({ name: '@synthetic/router', exports }),
      'packages/router/src/factory.ts': "import { Hono } from 'hono'; export const make = () => new Hono()",
      'apps/web/src/routes.ts': "import { make } from '@synthetic/router'\n" + db + 'const app = make()\n' + route,
    })
    assert.equal(found.length, 1)
  }
})

test('workspace conditions, private subpaths and non-local dependencies cannot borrow a package source', async () => {
  for (const [link, spec, exports] of [
    ['workspace:*', '@synthetic/router', { import: './src/factory.ts', default: './other.ts' }],
    ['workspace:*', '@synthetic/router/private', { '.': './src/factory.ts' }],
    ['^1.0.0', '@synthetic/router', './src/factory.ts'],
    ['workspace:*', '@synthetic/router', { '.': '../outside.ts' }],
  ] as const) {
    assert.deepEqual(await inspect({
      'package.json': JSON.stringify({ name: 'synthetic-root', workspaces: ['apps/*', 'packages/*'] }),
      'apps/web/package.json': JSON.stringify({ name: 'web', dependencies: { '@synthetic/router': link } }),
      'packages/router/package.json': JSON.stringify({ name: '@synthetic/router', exports }),
      'packages/router/src/factory.ts': "import { Hono } from 'hono'; export const make = () => new Hono()",
      'apps/web/src/routes.ts': `import { make } from '${spec}'\n` + db + 'const app = make()\n' + route,
    }), [])
  }
})

test('direct framework instances do not consume the project-factory candidate budget', async () => {
  const source = Array.from({ length: 257 }, (_, i) => `const app${i} = fastify()\napp${i}.get('/status', async () => 'ok')`).join('\n')
  const result = await scanFixture({ 'src/app.ts': "import fastify from 'fastify'\n" + source })
  assert.equal(result.partial, false)
  assert.deepEqual(result.errors, [])
  assert.deepEqual(result.findings, [])
})

test('factory coverage limits do not affect scans that select only content rules', async () => {
  const result = await scanFixture({ 'src/a.ts': "export { make } from './b'", 'src/b.ts': "export { make } from './a'",
    'src/app.ts': "import { make } from './a'; const app = make(); app.get('/status', c => c.text('ok'))" }, { only: ['cors'] })
  assert.equal(result.partial, false)
  assert.deepEqual(result.errors, [])
})
