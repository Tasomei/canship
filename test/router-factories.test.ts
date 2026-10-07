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
