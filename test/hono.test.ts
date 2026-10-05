/** Hono 路由：识别注册、链式与 basePath、子应用挂载、中间件，并接入鉴权、注入、SSRF、重定向和 webhook 规则。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-hono-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return (await scan(root)).findings
}
const summary = (list: Finding[]) => list
  .filter(f => /^(?:api|injection|ssrf|redirect|webhook)\//.test(f.ruleId))
  .map(f => [f.ruleId, f.file, f.line, f.confidence])
const titleOf = (list: Finding[]) => list.find(f => f.ruleId.startsWith('api/'))?.title ?? ''

const HONO = "import { Hono } from 'hono'\n"
const PRISMA = "import { PrismaClient } from '@prisma/client'\nconst prisma = new PrismaClient()\n"
const ADMIN = "import { createClient } from '@supabase/supabase-js'\n" +
  'const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n'

describe('Hono route discovery', () => {
  test('an unprotected write is reported with the registered path', async () => {
    const list = await findings({ 'src/index.ts': HONO + PRISMA + 'const app = new Hono()\n' +
      "app.delete('/users/:id', async (c) => {\n  await prisma.user.delete({ where: { id: c.req.param('id') } })\n  return c.body(null, 204)\n})\nexport default app\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'src/index.ts', 6, 'likely']])
    assert.match(titleOf(list), /^\/users\/:id writes to your database/)
  })

  test('the hono/tiny and hono/quick presets are the same Hono class', async () => {
    for (const preset of ['hono/tiny', 'hono/quick']) {
      const list = await findings({ 'src/index.ts': `import { Hono } from '${preset}'\n` + PRISMA + 'export const app = new Hono()\n' +
        "app.post('/items', async (c) => {\n  await prisma.item.create({ data: {} })\n  return c.text('ok')\n})\n" })
      assert.deepEqual(summary(list), [['api/db-write-without-auth', 'src/index.ts', 6, 'likely']], preset)
    }
  })

  test('routes chained on the constructor and under basePath carry the full path', async () => {
    const list = await findings({ 'src/index.ts': HONO + PRISMA +
      "const app = new Hono<{ Bindings: Env }>().basePath('/api')\n" +
      "  .get('/items', (c) => c.json([]))\n" +
      "  .post('/items', async (c) => {\n    await prisma.item.create({ data: await c.req.json() })\n    return c.json({ ok: true })\n  })\nexport default app\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'src/index.ts', 7, 'likely']])
    assert.match(titleOf(list), /^\/api\/items writes/)
  })

  test('a sub-app mounted with route() takes the prefix and the parent middleware registered before it', async () => {
    const books = HONO + ADMIN + "export const books = new Hono()\nbooks.post('/purge', async (c) => {\n  await admin.from('books').delete().neq('id', 0)\n  return c.text('ok')\n})\n"
    const open = await findings({
      'src/routes/books.ts': books,
      'src/index.ts': HONO + "import { books } from './routes/books'\nconst app = new Hono()\napp.route('/books', books)\nexport default app\n",
    })
    assert.deepEqual(summary(open), [['api/admin-db-access-without-auth', 'src/routes/books.ts', 6, 'certain']])
    assert.match(titleOf(open), /\/books\/purge/)
    const guarded = await findings({
      'src/routes/books.ts': books,
      'src/index.ts': HONO + "import { jwt } from 'hono/jwt'\nimport { books } from './routes/books'\nconst app = new Hono()\n" +
        "app.use('/books/*', jwt({ secret: process.env.JWT_SECRET, alg: 'HS256' }))\napp.route('/books', books)\nexport default app\n",
    })
    assert.deepEqual(summary(guarded), [])
    // 挂载之后才注册的中间件不作用于已挂载的子应用。
    const late = await findings({
      'src/routes/books.ts': books,
      'src/index.ts': HONO + "import { jwt } from 'hono/jwt'\nimport { books } from './routes/books'\nconst app = new Hono()\n" +
        "app.route('/books', books)\napp.use('/books/*', jwt({ secret: process.env.JWT_SECRET, alg: 'HS256' }))\nexport default app\n",
    })
    assert.deepEqual(summary(late), [['api/admin-db-access-without-auth', 'src/routes/books.ts', 6, 'certain']])
  })
})

describe('Hono sign-in endpoints', () => {
  test('authorize endpoints named after a sign-in method are exempt; other authorize endpoints are not', async () => {
    const route = (path: string) => HONO + PRISMA + 'export const auth = new Hono()\n' +
      `auth.post('${path}', async (c) => {\n  await prisma.auditLog.create({ data: { type: 'SIGN_IN_FAIL' } })\n  return c.json({ ok: false }, 401)\n})\n`
    assert.deepEqual(summary(await findings({ 'src/auth.ts': route('/email-password/authorize') })), [])
    assert.deepEqual(summary(await findings({ 'src/auth.ts': route('/passkey/authorize') })), [])
    assert.deepEqual(summary(await findings({ 'src/auth.ts': route('/callback/oidc/org/:orgUrl') })), [])
    assert.deepEqual(summary(await findings({ 'src/auth.ts': route('/documents/:id/authorize') })), [['api/db-write-without-auth', 'src/auth.ts', 6, 'likely']])
  })

  test('paths built from string constants are resolved, so OAuth server endpoints are recognized', async () => {
    const route = (path: string) => HONO + PRISMA + "const OAUTH_PATH = '/mcp/oauth'\nexport const app = new Hono()\n" +
      `app.post(${path}, async (c) => {\n  await prisma.oauthToken.create({ data: {} })\n  return c.json({ ok: true })\n})\n`
    for (const endpoint of ['token', 'revoke', 'register']) {
      assert.deepEqual(summary(await findings({ 'src/oauth.ts': route(`\`\${OAUTH_PATH}/${endpoint}\``) })), [], endpoint)
    }
    const other = await findings({ 'src/oauth.ts': route('`${OAUTH_PATH}/clients`') })
    assert.deepEqual(summary(other), [['api/db-write-without-auth', 'src/oauth.ts', 7, 'likely']])
    assert.match(titleOf(other), /^\/mcp\/oauth\/clients writes/)
  })
})

describe('Hono middleware', () => {
  test('built-in auth middleware, createMiddleware, and inline middleware that reject protect the route', async () => {
    const route = (middleware: string, extra = '') => HONO + PRISMA + extra + 'const app = new Hono()\n' + middleware +
      "app.post('/admin/items', async (c) => {\n  await prisma.item.deleteMany({})\n  return c.text('ok')\n})\nexport default app\n"
    assert.deepEqual(summary(await findings({ 'src/index.ts': route('') })), [['api/db-write-without-auth', 'src/index.ts', 6, 'likely']])
    assert.deepEqual(summary(await findings({ 'src/index.ts': route("app.use('/admin/*', bearerAuth({ token: process.env.API_TOKEN }))\n", "import { bearerAuth } from 'hono/bearer-auth'\n") })), [])
    assert.deepEqual(summary(await findings({ 'src/index.ts': route("app.use('/admin/*', requireUser)\n",
      "import { createMiddleware } from 'hono/factory'\nconst requireUser = createMiddleware(async (c, next) => {\n  const user = c.get('user')\n  if (!user) return c.json({ error: 'unauthorized' }, 401)\n  await next()\n})\n") })), [])
    assert.deepEqual(summary(await findings({ 'src/index.ts': route(
      "app.use('*', async (c, next) => {\n  const token = c.req.header('authorization')\n  if (!token) throw new HTTPException(401)\n  await next()\n})\n",
      "import { HTTPException } from 'hono/http-exception'\n") })), [])
  })

  test('middleware that only logs, or applies to another path, does not protect the route', async () => {
    const list = await findings({ 'src/index.ts': HONO + PRISMA + "import { jwt } from 'hono/jwt'\nconst app = new Hono()\n" +
      "app.use('/admin/*', jwt({ secret: process.env.JWT_SECRET, alg: 'HS256' }))\n" +
      "app.use(async (c, next) => {\n  console.log(c.req.path)\n  await next()\n})\n" +
      "app.post('/public/items', async (c) => {\n  await prisma.item.create({ data: {} })\n  return c.text('ok')\n})\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'src/index.ts', 12, 'likely']])
  })

  test('middleware rejecting a missing or invalid credential with an error helper or throw protects the route', async () => {
    const route = (middleware: string) => HONO + PRISMA + "import { quickError, simpleError, timingSafeEqual, resolveApiKey } from './utils'\nconst app = new Hono()\n" +
      `app.use('/admin/*', async (c, next) => {\n${middleware}  await next()\n})\n` +
      "app.post('/admin/items', async (c) => {\n  await prisma.item.deleteMany({})\n  return c.text('ok')\n})\n"
    const write = (lines: number) => [['api/db-write-without-auth', 'src/index.ts', 6 + lines + 4, 'likely']]
    assert.deepEqual(summary(await findings({ 'src/index.ts': route(
      "  const apikey = await resolveApiKey(c.req.header('capgkey'))\n  if (!apikey) return quickError(401, 'invalid_apikey', 'Invalid apikey')\n") })), [])
    assert.deepEqual(summary(await findings({ 'src/index.ts': route(
      "  const authorizationSecret = c.req.header('apisecret')\n  if (!await timingSafeEqual(authorizationSecret, c.env.API_SECRET)) throw simpleError('invalid_api_secret', 'Invalid')\n") })), [])
    // 与凭据无关的判断、以及两个请求值之间的比较都不构成保护。
    assert.deepEqual(summary(await findings({ 'src/index.ts': route(
      "  const locale = c.req.header('accept-language')\n  if (!locale) throw simpleError('no_locale', 'Missing locale')\n") })), write(2))
    assert.deepEqual(summary(await findings({ 'src/index.ts': route(
      "  if (c.req.query('token') !== c.req.header('token')) throw simpleError('bad', 'Bad token')\n") })), write(1))
  })

  test('an origin check written without semicolons is not mistaken for authentication', async () => {
    const list = await findings({ 'src/index.ts': HONO + PRISMA + "import { quickError, allowedOrigins } from './utils'\n" +
      'async function validateOrigin(c, next) {\n  const origin = c.req.header(\'origin\')\n  if (!origin)\n    return next()\n' +
      "  if (!allowedOrigins.has(origin))\n    return quickError(403, 'forbidden_origin', 'Origin is not allowed')\n  return next()\n}\n" +
      "const app = new Hono()\napp.use('*', validateOrigin)\n" +
      "app.post('/items', async (c) => {\n  await prisma.item.deleteMany({})\n  return c.text('ok')\n})\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'src/index.ts', 16, 'likely']])
  })

  test('a middleware that rejects with c.text(…, 401) protects the route', async () => {
    const list = await findings({ 'src/index.ts': HONO + PRISMA + "import { check } from './check'\nconst app = new Hono()\n" +
      "app.use('/admin/*', async (c, next) => {\n  const ok = await check(c)\n  if (!ok) return c.text('Unauthorized', 401)\n  await next()\n})\n" +
      "app.post('/admin/items', async (c) => {\n  await prisma.item.deleteMany({})\n  return c.text('ok')\n})\n" })
    assert.deepEqual(summary(list), [])
  })

  test('a sub-app middleware comparing the Authorization header with a server secret protects its routes', async () => {
    const jobs = (expected: string) => HONO + PRISMA + "import { env } from './env'\nexport const jobs = new Hono()\n" +
      `jobs.use('*', async (c, next) => {\n  if (c.req.header('authorization') !== ${expected}) {\n    return c.text('Unauthorized', 401)\n  }\n  return next()\n})\n` +
      "jobs.get('/cleanup', async (c) => {\n  await prisma.session.deleteMany({})\n  return c.text('ok')\n})\n"
    assert.deepEqual(summary(await findings({ 'src/jobs.ts': jobs('env().CRON_SECRET') })), [])
    // 与请求自身的值比较不构成保护。
    assert.deepEqual(summary(await findings({ 'src/jobs.ts': jobs("c.req.query('key')") })), [['api/db-write-without-auth', 'src/jobs.ts', 13, 'likely']])
  })

  test('a handler comparing the Authorization header with a Workers secret binding is protected', async () => {
    const route = (secret: string) => HONO + PRISMA + 'const app = new Hono<{ Bindings: { CRON_SECRET: string } }>()\n' +
      "app.post('/cron/cleanup', async (c) => {\n  if (c.req.header('Authorization') !== `Bearer ${" + secret + "}`) return c.text('Unauthorized', 401)\n" +
      "  await prisma.session.deleteMany({})\n  return c.text('ok')\n})\n"
    assert.deepEqual(summary(await findings({ 'src/index.ts': route('c.env.CRON_SECRET') })), [])
    // 先取出环境配置对象再读密钥。
    assert.deepEqual(summary(await findings({ 'src/index.ts': route('c.env.CRON_SECRET').replace("  if (c.req.header", "  const config = env()\n  if (c.req.header").replace('c.env.CRON_SECRET', 'config.CRON_SECRET') })), [])
    // 与请求自身的值比较不构成保护。
    assert.deepEqual(summary(await findings({ 'src/index.ts': route("c.req.query('key')") })), [['api/db-write-without-auth', 'src/index.ts', 7, 'likely']])
  })

  test('an auth-looking middleware from a package lowers confidence and says why', async () => {
    const list = await findings({ 'src/index.ts': HONO + ADMIN + "import { requireSession } from '@acme/session-kit'\nconst app = new Hono()\n" +
      "app.post('/wipe', requireSession(), async (c) => {\n  await admin.from('logs').delete().neq('id', 0)\n  return c.text('ok')\n})\n" })
    assert.deepEqual(summary(list), [['api/admin-db-access-without-auth', 'src/index.ts', 7, 'likely']])
    assert.ok(list[0]!.why.some(p => /requireSession/.test(p) && /could not be followed/.test(p)))
  })
})

describe('guards inside Hono handlers', () => {
  test('a check on c.get(\'user\') set by middleware protects the write; a check on request input does not', async () => {
    const route = (read: string) => HONO + PRISMA + 'const app = new Hono()\n' +
      `app.delete('/items/:id', async (c) => {\n  const user = ${read}\n  if (!user) return c.json({ error: 'unauthorized' }, 401)\n` +
      "  await prisma.item.delete({ where: { id: c.req.param('id') } })\n  return c.body(null, 204)\n})\n"
    assert.deepEqual(summary(await findings({ 'src/index.ts': route("c.get('user')") })), [])
    assert.deepEqual(summary(await findings({ 'src/index.ts': route("c.req.query('user')") })), [['api/db-write-without-auth', 'src/index.ts', 8, 'likely']])
  })
})

describe('request-input rules in Hono handlers', () => {
  test('c.req reads reach SQL, redirects, and server requests; the Host header does not', async () => {
    const list = await findings({ 'src/index.ts': HONO + "import { pool } from './db'\nconst app = new Hono()\n" +
      "app.get('/search', async (c) => c.json(await pool.query(`SELECT * FROM items WHERE name = '${c.req.query('q')}'`)))\n" +
      "app.get('/go', (c) => c.redirect(c.req.query('next')))\n" +
      "app.post('/preview', async (c) => {\n  const { url } = await c.req.json()\n  return c.json(await (await fetch(url)).json())\n})\n" +
      "app.get('/self', async (c) => {\n  const host = c.req.header('host')\n  return c.json(await (await fetch(`https://${host}/health`)).json())\n})\nexport default app\n" })
    assert.deepEqual(summary(list), [
      ['injection/sql', 'src/index.ts', 4, 'certain'],
      ['ssrf/request-url', 'src/index.ts', 8, 'likely'],
      ['redirect/open', 'src/index.ts', 5, 'certain'],
    ])
  })

  test('validated input from c.req.valid() is still followed, at review confidence', async () => {
    const list = await findings({ 'src/index.ts': HONO + "import { zValidator } from '@hono/zod-validator'\nimport { z } from 'zod'\nconst app = new Hono()\n" +
      "app.post('/import', zValidator('json', z.object({ url: z.string() })), async (c) => {\n  const { url } = c.req.valid('json')\n  return c.json(await (await fetch(url)).json())\n})\nexport default app\n" })
    assert.deepEqual(summary(list), [['ssrf/request-url', 'src/index.ts', 7, 'likely']])
  })

  test('Stripe webhooks in Hono are checked for signature verification', async () => {
    const handler = (verify: boolean) => HONO + "import Stripe from 'stripe'\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY)\nconst app = new Hono()\n" +
      "app.post('/webhook', async (c) => {\n" +
      (verify ? "  const body = await c.req.text()\n  const event = stripe.webhooks.constructEvent(body, c.req.header('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET)\n"
        : '  const event = await c.req.json()\n') +
      "  if (event.type === 'checkout.session.completed') await fulfil(event.data.object)\n  return c.json({ received: true })\n})\nexport default app\n"
    assert.deepEqual(summary(await findings({ 'src/index.ts': handler(false) })), [['webhook/unverified-signature', 'src/index.ts', 7, 'certain']])
    assert.deepEqual(summary(await findings({ 'src/index.ts': handler(true) })), [])
  })

  test('a Stripe event verified by route middleware and read from the context is not reported', async () => {
    const middleware = "import { createMiddleware } from 'hono/factory'\nimport { parseStripeEvent } from './stripe'\n" +
      "export function stripeWebhook() {\n  return createMiddleware(async (c, next) => {\n    const signature = c.req.header('stripe-signature')\n" +
      "    if (!signature) return c.text('missing signature', 400)\n    c.set('stripeEvent', await parseStripeEvent(await c.req.text(), signature))\n    await next()\n  })\n}\n"
    const route = (withMiddleware: boolean) => HONO + "import { stripeWebhook } from './middleware'\nconst app = new Hono()\n" +
      `app.post('/stripe', ${withMiddleware ? 'stripeWebhook(), ' : ''}async (c) => {\n  const event = c.get('stripeEvent')\n` +
      "  if (event.type === 'checkout.session.completed') await fulfil(event.data.object)\n  return c.json({ received: true })\n})\nexport default app\n"
    const helper = "import Stripe from 'stripe'\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)\n" +
      'export async function parseStripeEvent(body: string, signature: string) {\n' +
      '  return stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!)\n}\n'
    assert.deepEqual(summary(await findings({ 'src/middleware.ts': middleware, 'src/stripe.ts': helper, 'src/index.ts': route(true) })), [])
    // 解析函数找不到时只看到读取签名头，不能证明已验证：保留待复核。
    const unresolved = await findings({ 'src/middleware.ts': middleware, 'src/index.ts': route(true) })
    assert.deepEqual(summary(unresolved), [['webhook/unverified-signature', 'src/index.ts', 6, 'likely']])
    assert.match(unresolved.find(f => f.ruleId === 'webhook/unverified-signature')!.title, /^Review custom Stripe signature verification/)
    // 没有验签中间件时仍报告；事件不来自请求体，c.json() 是响应而非读取，因此只到 likely。
    assert.deepEqual(summary(await findings({ 'src/middleware.ts': middleware, 'src/index.ts': route(false) })), [['webhook/unverified-signature', 'src/index.ts', 6, 'likely']])
  })
})
