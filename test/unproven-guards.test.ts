/** 无法证明存在保护时不能静默消除结果：鉴权与验签必须真正执行、等待，路由的每条路径与每个回调都要检查。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

async function findings(files: Record<string, string>): Promise<Finding[]> {
  const root = mkdtempSync(join(tmpdir(), 'canship-unproven-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return (await scan(root)).findings
}
const summary = (list: Finding[]) => list.map(f => [f.ruleId, f.file, f.line, f.confidence])

const DB = "import { PrismaClient } from '@prisma/client'\nexport const prisma = new PrismaClient()\n"
const EXPRESS = "import express from 'express'\nimport { prisma } from './db'\nconst app = express()\n"
const HONO = "import { Hono } from 'hono'\nimport { bearerAuth } from 'hono/bearer-auth'\nimport { prisma } from './db'\nconst app = new Hono()\n"
const FASTIFY = "import Fastify from 'fastify'\nimport { prisma } from './db'\nconst fastify = Fastify()\n"
const WRITE = '  await prisma.item.deleteMany({})\n'

describe('middleware must actually run its authentication', () => {
  test('an auth call inside a local function that is never called does not protect the route', async () => {
    const app = EXPRESS + 'function guard(req, res, next) {\n  const unused = () => requireAuth(req)\n  next()\n}\n' +
      `app.post('/items', guard, async (req, res) => {\n${WRITE}  res.json({})\n})\n`
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': app })), [['api/db-write-without-auth', 'app.ts', 9, 'likely']])
    const called = app.replace('  next()', '  unused()\n  next()')
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': called })), [])
  })

  test('a Fastify hook must await or return jwtVerify', async () => {
    const app = (call: string) => FASTIFY + `fastify.addHook('onRequest', async (req, reply) => {\n  ${call}\n})\n` +
      `fastify.post('/items', async (req) => {\n${WRITE}  return {}\n})\n`
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': app('req.jwtVerify()') })), [['api/db-write-without-auth', 'app.ts', 8, 'likely']])
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': app('await req.jwtVerify()') })), [])
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': app('return req.jwtVerify()') })), [])
  })
})

describe('project session checks must be awaited', () => {
  const session = (sync: boolean) => sync
    ? 'export function validateSessionToken(token: string) {\n  return token ? { id: 1 } : null\n}\n'
    : 'export async function validateSessionToken(token: string) {\n  return token ? { id: 1 } : null\n}\n'
  const route = (call: string, local = '') => "import { prisma as db } from '@/lib/db'\n" +
    (local || "import { validateSessionToken } from '@/lib/session'\n") +
    `export async function POST(request: Request) {\n  const token = request.headers.get('x-session') ?? ''\n  const session = ${call}\n` +
    `  if (!session) return new Response('Unauthorized', { status: 401 })\n  await db.item.deleteMany({})\n  return Response.json({})\n}\n`

  test('an unawaited call to an imported check leaves the write reported', async () => {
    const files = { 'lib/db.ts': DB, 'lib/session.ts': session(false) }
    assert.deepEqual(summary(await findings({ ...files, 'app/api/items/route.ts': route('validateSessionToken(token)') })),
      [['api/db-write-without-auth', 'app/api/items/route.ts', 7, 'likely']])
    assert.deepEqual(summary(await findings({ ...files, 'app/api/items/route.ts': route('await validateSessionToken(token)') })), [])
  })

  test('a synchronous check defined in the same file needs no await', async () => {
    const local = session(true).replace('export ', '')
    assert.deepEqual(summary(await findings({ 'lib/db.ts': DB, 'app/api/items/route.ts': route('validateSessionToken(token)', local) })), [])
    const asyncLocal = session(false).replace('export ', '')
    assert.deepEqual(summary(await findings({ 'lib/db.ts': DB, 'app/api/items/route.ts': route('validateSessionToken(token)', asyncLocal) })),
      [['api/db-write-without-auth', 'app/api/items/route.ts', 9, 'likely']])
  })
})

describe('webhook middleware must verify the signature', () => {
  const app = (middleware: string) => EXPRESS + "import Stripe from 'stripe'\n" + middleware +
    `app.post('/webhook', ${middleware ? 'checkSignature, ' : ''}async (req, res) => {\n  const event = req.body\n` +
    "  if (event.type === 'checkout.session.completed') {\n    await prisma.order.update({ where: { id: event.data.object.id }, data: { paid: true } })\n  }\n  res.json({})\n})\n"
  const webhook = (list: Finding[]) => list.filter(f => f.ruleId.startsWith('webhook/')).map(f => [f.line, f.confidence, f.title.startsWith('Review') ? 'review' : 'open'])

  test('reading the signature header is not verification', async () => {
    const logs = "function checkSignature(req, res, next) {\n  console.log(req.headers['stripe-signature'])\n  next()\n}\n"
    assert.deepEqual(webhook(await findings({ 'db.ts': DB, 'app.ts': app(logs) })), [[11, 'likely', 'review']])
    assert.deepEqual(webhook(await findings({ 'db.ts': DB, 'app.ts': app('') })), [[7, 'certain', 'open']])
  })

  test('constructEvent in the middleware verifies the event unless a failure falls through to next()', async () => {
    const verifies = (onError: string) => "const stripe = new Stripe(process.env.STRIPE_SECRET_KEY)\nfunction checkSignature(req, res, next) {\n  try {\n" +
      "    req.body = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)\n" +
      `  } catch (err) {\n    ${onError}\n  }\n  next()\n}\n`
    assert.deepEqual(webhook(await findings({ 'db.ts': DB, 'app.ts': app(verifies('return res.status(400).send(err.message)')) })), [])
    assert.deepEqual(webhook(await findings({ 'db.ts': DB, 'app.ts': app(verifies('return next()')) })), [[16, 'likely', 'review']])
  })

  test('a helper that returns constructEventAsync from a client factory verifies when the middleware awaits it', async () => {
    const helper = "import Stripe from 'stripe'\nconst getStripe = (env) => new Stripe(env.STRIPE_SECRET_KEY)\n" +
      'export function parseStripeEvent(env, body, signature) {\n' +
      '  return getStripe(env).webhooks.constructEventAsync(body, signature, env.STRIPE_WEBHOOK_SECRET)\n}\n'
    const middleware = "import { parseStripeEvent } from './stripe'\nasync function checkSignature(req, res, next) {\n" +
      "  req.body = await parseStripeEvent(process.env, req.rawBody, req.headers['stripe-signature'])\n  next()\n}\n"
    assert.deepEqual(webhook(await findings({ 'db.ts': DB, 'stripe.ts': helper, 'app.ts': app(middleware) })), [])
  })
})

describe('Hono middleware paths and multi-path routes', () => {
  const route = "app.post('/admin/items', async (c) => {\n" + WRITE + '  return c.json({})\n})\n'

  test("use('/admin') covers only /admin; use('/admin/*') covers its subpaths", async () => {
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': HONO + "app.use('/admin', bearerAuth({ token: 'x' }))\n" + route })),
      [['api/db-write-without-auth', 'app.ts', 7, 'likely']])
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': HONO + "app.use('/admin/*', bearerAuth({ token: 'x' }))\n" + route })), [])
  })

  test('each path in an array is checked; a shared handler is reported once', async () => {
    const on = "app.on('POST', ['/private/items', '/public/items'], async (c) => {\n" + WRITE + '  return c.json({})\n})\n'
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': HONO + "app.use('/private/*', bearerAuth({ token: 'x' }))\n" + on })),
      [['api/db-write-without-auth', 'app.ts', 7, 'likely']])
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': HONO + on })), [['api/db-write-without-auth', 'app.ts', 6, 'likely']])
    const both = "app.use('/private/*', bearerAuth({ token: 'x' }))\napp.use('/public/*', bearerAuth({ token: 'y' }))\n"
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': HONO + both + on })), [])
  })
})

describe('Express callbacks', () => {
  test('handlers in an array and callbacks before the last one are checked', async () => {
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': EXPRESS + `app.post('/items', [async (req, res) => {\n${WRITE}  res.json({})\n}])\n` })),
      [['api/db-write-without-auth', 'app.ts', 5, 'likely']])
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': EXPRESS +
      `app.post('/items', async (req, res, next) => {\n${WRITE}  next()\n}, (req, res) => {\n  res.json({})\n})\n` })),
      [['api/db-write-without-auth', 'app.ts', 5, 'likely']])
  })

  test('a callback before the write that rejects unauthenticated requests still protects it', async () => {
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': EXPRESS +
      "app.post('/items', [(req, res, next) => {\n  if (!req.user) return res.sendStatus(401)\n  next()\n}, async (req, res) => {\n" + WRITE + '  res.json({})\n}])\n' })), [])
  })

  test('async(req, res) without a space is a handler', async () => {
    assert.deepEqual(summary(await findings({ 'db.ts': DB, 'app.ts': EXPRESS + `app.post('/items', async(req, res) => {\n${WRITE}  res.json({})\n})\n` })),
      [['api/db-write-without-auth', 'app.ts', 5, 'likely']])
  })
})

describe('request input through helpers and proxy headers', () => {
  test('a local function that returns its argument keeps the input', async () => {
    const route = (helper: string) => `import { prisma } from '@/lib/db'\n${helper}\nexport async function POST(req: Request) {\n` +
      "  const body = await req.json()\n  const { id } = helper(body)\n  return Response.json(await prisma.$queryRawUnsafe('SELECT * FROM items WHERE id=' + id))\n}\n"
    assert.deepEqual(summary(await findings({ 'lib/db.ts': DB, 'app/api/items/route.ts': route('function helper(value) {\n  return value\n}') })),
      [['injection/sql', 'app/api/items/route.ts', 8, 'likely']])
    assert.deepEqual(summary(await findings({ 'lib/db.ts': DB, 'app/api/items/route.ts': route('const helper = (value) => ({ ...value, at: Date.now() })') })),
      [['injection/sql', 'app/api/items/route.ts', 6, 'likely']])
    // 把形参交给其他调用的函数返回的是那次调用的结果，仍按未知函数处理。
    assert.deepEqual(summary(await findings({ 'lib/db.ts': DB, 'app/api/items/route.ts': route('async function helper(value) {\n  return prisma.item.findFirst({ where: value })\n}') })), [])
  })

  test('X-Forwarded-Host is caller input unless the proxy is known; Host names this site', async () => {
    const route = (header: string) => `export async function GET(request: Request) {\n  const target = request.headers.get('${header}')\n` +
      "  const res = await fetch('https://' + target + '/private')\n  return new Response(await res.text())\n}\n"
    assert.deepEqual(summary(await findings({ 'app/api/proxy/route.ts': route('x-forwarded-host') })), [['ssrf/request-url', 'app/api/proxy/route.ts', 3, 'likely']])
    assert.deepEqual(summary(await findings({ 'app/api/proxy/route.ts': route('host') })), [])
  })
})
