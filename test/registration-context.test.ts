/** 条件注册与函数作用域不能把局部中间件误当作全局鉴权。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan } from '../src/engine.js'

const db = "import { PrismaClient } from '@prisma/client'; const prisma = new PrismaClient();\n"
const frameworks = {
  hono: { setup: "import { Hono } from 'hono'; import { bearerAuth } from 'hono/bearer-auth'; const app = new Hono();\n",
    guard: "app.use('*', bearerAuth({token:process.env.API_TOKEN}));", route: "app.post('/items', async c => { await prisma.item.create({data:{}}); return c.json({}) });" },
  express: { setup: "import express from 'express'; const app = express(); function auth(req,res,next){if(!req.user)return res.status(401).json({});next()}\n",
    guard: 'app.use(auth);', route: "app.post('/items', async (req,res) => { await prisma.item.create({data:{}}); return res.json({}) });" },
  fastify: { setup: "import fastify from 'fastify'; const app = fastify();\n",
    guard: "app.addHook('onRequest', async (req,reply) => { if(!req.user) return reply.code(401).send() });",
    route: "app.post('/items', async () => { await prisma.item.create({data:{}}); return {} });" },
}
async function inspect(source: string, options: Parameters<typeof scan>[1] = {}) {
  const root = mkdtempSync(join(tmpdir(), 'canship-registration-context-'))
  try {
    mkdirSync(join(root, 'src')); writeFileSync(join(root, 'src/server.ts'), db + source)
    return await scan(root, options)
  } finally { rmSync(root, { recursive: true, force: true }) }
}

for (const [name, framework] of Object.entries(frameworks)) {
  test(`${name}: conditional middleware does not protect an unconditional route`, async () => {
    for (const prefix of ['if (false)', 'if (enabled)', 'while (enabled)']) {
      const result = await inspect(framework.setup + `${prefix} { ${framework.guard} }\n` + framework.route)
      assert.equal(result.findings.filter(item => item.ruleId === 'api/db-write-without-auth').length, 1, prefix)
    }
  })
  test(`${name}: a shared branch preserves ordering and a literal-false route is not registered`, async () => {
    assert.equal((await inspect(framework.setup + `if (enabled) { ${framework.guard} ${framework.route} }`)).findings.length, 0)
    assert.equal((await inspect(framework.setup + `if (true) { ${framework.guard} }\n${framework.route}`)).findings.length, 0)
    assert.equal((await inspect(framework.setup + `if (false) { ${framework.route} }`)).findings.length, 0)
  })
  test(`${name}: unused setup functions cannot lend authentication to later routes`, async () => {
    for (const wrapper of [`function unused(){${framework.guard}}`, `const unused = () => {${framework.guard}}`, `const unused = () => ${framework.guard}`]) {
      const result = await inspect(framework.setup + wrapper + '\n' + framework.route)
      assert.equal(result.findings.filter(item => item.ruleId === 'api/db-write-without-auth').length, 1, wrapper)
    }
  })
  test(`${name}: short-circuit middleware cannot become unconditional evidence`, async () => {
    for (const prefix of ['enabled && ', 'enabled || ', 'false && ', 'enabled &&\n']) {
      const result = await inspect(framework.setup + prefix + framework.guard + '\n' + framework.route)
      assert.equal(result.findings.filter(item => item.ruleId === 'api/db-write-without-auth').length, 1, prefix)
    }
  })
}

test('the same helper reached by protected and public call sites retains the public finding', async () => {
  const framework = frameworks.hono
  const helper = "function wire(router){router.post('/items',async c=>{await prisma.item.create({data:{}});return c.json({})})}\n"
  const result = await inspect(framework.setup + helper + `if(enabled){${framework.guard} wire(app)}\nwire(app)`)
  assert.equal(result.findings.filter(item => item.ruleId === 'api/db-write-without-auth').length, 1)
})

test('two parent instances cannot share the first helper invocation authentication', async () => {
  const framework = frameworks.hono
  const helper = "function wire(router){router.post('/items',async c=>{await prisma.item.create({data:{}});return c.json({})})}\n"
  const result = await inspect(framework.setup + 'const other = new Hono();\n' + helper + framework.guard + '\nwire(app); wire(other)')
  assert.equal(result.findings.filter(item => item.ruleId === 'api/db-write-without-auth').length, 1)
})

test('quoted and multiline template expressions keep registration ownership intact', async () => {
  const framework = frameworks.hono
  const wrapped = 'const unused = () => `synthetic\n${' + framework.guard.replace(/;$/, '') + '}\n`;\n'
  assert.equal((await inspect(framework.setup + wrapped + framework.route)).findings.length, 1)
  const literal = "if(false) 'synthetic'\n" + framework.route
  assert.equal((await inspect(framework.setup + literal)).findings.length, 1)
})

test('framework imports and instance declarations inside strings do not create routes', async () => {
  for (const setup of [
    'const example = "import express from \'express\'; const app = express();";',
    'import express from "express"; const example = "const app = express();";',
    'const example = "const express = require(\'express\'); const app = express();";',
  ]) {
    const result = await inspect(setup + '\nconst app = {post(){}};\n' + frameworks.express.route)
    assert.deepEqual(result.findings, [])
    assert.equal(result.partial, false)
  }
})

test('inherited middleware limits are explicit and cannot suppress a potential public write', async () => {
  for (const count of [256, 257]) {
    const framework = frameworks.hono
    const helper = "function wire(router){router.post('/items',async c=>{await prisma.item.create({data:{}});return c.json({})})}\n"
    const result = await inspect(framework.setup + helper + (framework.guard + '\n').repeat(count) + 'wire(app)')
    assert.equal(result.partial, count === 257)
    assert.equal(result.findings.length, count === 257 ? 1 : 0)
    assert.deepEqual(result.errors.map(error => error.code), count === 257 ? ['ROUTE_UNRESOLVED'] : [])
  }
})

test('context limits do not affect scans selecting only content-based rules', async () => {
  const source = frameworks.hono.setup + Array.from({ length: 513 }, (_, i) => `function unused${i}(){}`).join('\n') +
    "\napp.get('/status', c => c.text('ok'));"
  const scoped = await inspect(source, { only: ['cors'] })
  assert.equal(scoped.partial, false)
  const routes = await inspect(source, { only: ['api'] })
  assert.equal(routes.partial, true)
  assert.deepEqual(routes.errors.map(error => error.code), ['ROUTE_UNRESOLVED'])
})
