/** Express 路由：识别注册、控制器处理函数、路由级与挂载级中间件，并接入鉴权、注入、SSRF、重定向和 webhook 规则。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-express-'))
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

const PRISMA = "const { PrismaClient } = require('@prisma/client')\nconst prisma = new PrismaClient()\n"
const ADMIN = "import { createClient } from '@supabase/supabase-js'\n" +
  'const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n'
const GUARD = 'function requireAuth(req, res, next) {\n  if (!req.user) return res.status(401).json({ error: "unauthorized" })\n  next()\n}\n'

describe('Express route discovery', () => {
  test('an unprotected write is reported with the registered path', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst app = express()\n" + PRISMA +
      "app.delete('/users/:id', async (req, res) => {\n  await prisma.user.delete({ where: { id: req.params.id } })\n  res.sendStatus(204)\n})\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'server.js', 6, 'likely']])
    assert.match(list.find(f => f.ruleId.startsWith('api/'))!.title, /^\/users\/:id writes to your database/)
  })

  test('an admin client behind an open route is certain P0', async () => {
    const list = await findings({ 'src/routes/admin.ts': "import { Router } from 'express'\n" + ADMIN +
      "export const router = Router()\nrouter.post('/wipe', async (req, res) => {\n  await admin.from('logs').delete().neq('id', 0)\n  res.end()\n})\n" })
    assert.deepEqual(summary(list), [['api/admin-db-access-without-auth', 'src/routes/admin.ts', 6, 'certain']])
  })

  test('TypeScript generic arguments on the method are allowed', async () => {
    const list = await findings({ 'src/api.ts': "import express from 'express'\nconst router = express.Router()\n" + PRISMA +
      "router.post<{}, { ok: boolean }>('/items', async (req, res) => {\n  await prisma.item.create({ data: req.body })\n  res.json({ ok: true })\n})\nexport default router\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'src/api.ts', 6, 'likely']])
  })

  test('routes registered on an app passed into a function are found, across files and levels', async () => {
    const list = await findings({
      'server/index.js': "const express = require('express')\nconst { systemEndpoints } = require('./endpoints/system')\nconst app = express()\nconst api = express.Router()\n" +
        "systemEndpoints(api)\nrequire('./routes')(app)\napp.use('/api', api)\n",
      'server/endpoints/system.js': PRISMA + GUARD +
        "function systemEndpoints(app) {\n  app.delete('/workspaces/:id', [requireAuth], async (req, res) => { await prisma.workspace.delete({ where: { id: req.params.id } }); res.end() })\n" +
        "  app.post('/reset', async (req, res) => { await prisma.workspace.deleteMany({}); res.end() })\n}\nmodule.exports = { systemEndpoints }\n",
      'server/routes/index.js': "const users = require('./users')\nmodule.exports = function (app) {\n  users(app)\n}\n",
      'server/routes/users.js': PRISMA + "module.exports = (app) => {\n  app.post('/users', async (req, res) => { await prisma.user.create({ data: req.body }); res.end() })\n}\n",
    })
    assert.deepEqual(summary(list), [
      ['api/db-write-without-auth', 'server/endpoints/system.js', 9, 'likely'],
      ['api/db-write-without-auth', 'server/routes/users.js', 4, 'likely'],
    ])
    assert.match(list.find(f => f.file === 'server/endpoints/system.js')!.title, /^\/api\/reset writes/)
  })

  test('middleware registered before the app is passed on protects the routes added later', async () => {
    const list = await findings({
      'server/index.js': "const express = require('express')\nconst { adminEndpoints } = require('./endpoints/admin')\n" + GUARD +
        "const app = express()\nconst admin = express.Router()\nadmin.use(requireAuth)\nadminEndpoints(admin)\napp.use('/admin', admin)\n",
      'server/endpoints/admin.js': PRISMA + "function adminEndpoints(router) {\n  router.post('/purge', async (req, res) => { await prisma.log.deleteMany({}); res.end() })\n}\nmodule.exports = { adminEndpoints }\n",
    })
    assert.deepEqual(summary(list), [])
  })

  test('calls that only look like routes are ignored without an express import', async () => {
    const list = await findings({ 'lib/cache.js': PRISMA + "const app = createCache()\napp.get('/key', async () => { await prisma.user.deleteMany({}) })\n" })
    assert.deepEqual(summary(list), [])
  })

  test('route chains, async wrappers, and expression-bodied handlers are followed', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst router = express.Router()\n" + PRISMA +
      "const asyncHandler = (fn) => (req, res, next) => fn(req, res, next).catch(next)\n" +
      "router.route('/items')\n  .get((req, res) => res.json([]))\n  .post(asyncHandler(async (req, res) => {\n    await prisma.item.create({ data: req.body })\n    res.end()\n  }))\n" +
      "router.put('/items/:id', (req, res) => prisma.item.update({ where: { id: req.params.id }, data: req.body }))\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'server.js', 9, 'likely'], ['api/db-write-without-auth', 'server.js', 12, 'likely']])
  })

  test('controller handlers in other files are analysed where they are defined', async () => {
    const list = await findings({
      'routes/users.js': "const express = require('express')\nconst router = express.Router()\nconst users = require('../controllers/users')\n" +
        "router.post('/', users.create)\nrouter.delete('/:id', users.remove)\nmodule.exports = router\n",
      'controllers/users.js': PRISMA + "exports.create = async (req, res) => {\n  res.json(await prisma.user.create({ data: req.body }))\n}\n" +
        "exports.remove = async function (req, res) {\n  await prisma.user.delete({ where: { id: req.params.id } })\n  res.end()\n}\n",
    })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'controllers/users.js', 4, 'likely'], ['api/db-write-without-auth', 'controllers/users.js', 7, 'likely']])
  })

  test('sign-in and registration endpoints are exempt', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst app = express()\n" + PRISMA +
      "app.post('/api/auth/register', async (req, res) => { await prisma.user.create({ data: req.body }); res.end() })\n" +
      "app.post('/login', async (req, res) => { await prisma.session.create({ data: {} }); res.end() })\n" })
    assert.deepEqual(summary(list), [])
  })
})

describe('Express middleware', () => {
  test('a local middleware that rejects missing users protects the route', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst app = express()\n" + PRISMA + GUARD +
      "app.delete('/users/:id', requireAuth, async (req, res) => { await prisma.user.delete({ where: { id: req.params.id } }); res.end() })\n" })
    assert.deepEqual(summary(list), [])
  })

  test('imported middleware, factories, and arrays are resolved', async () => {
    const list = await findings({
      'middleware/auth.js': GUARD + 'function requireRole(role) {\n  return (req, res, next) => {\n    if (!req.user || req.user.role !== role) return res.sendStatus(403)\n    next()\n  }\n}\nmodule.exports = { requireAuth, requireRole }\n',
      'server.js': "const express = require('express')\nconst { requireAuth, requireRole } = require('./middleware/auth')\nconst app = express()\n" + PRISMA +
        "app.post('/a', requireAuth, async (req, res) => { await prisma.a.create({ data: {} }); res.end() })\n" +
        "app.post('/b', requireRole('admin'), async (req, res) => { await prisma.b.create({ data: {} }); res.end() })\n" +
        "app.post('/c', [requireAuth, express.json()], async (req, res) => { await prisma.c.create({ data: {} }); res.end() })\n",
    })
    assert.deepEqual(summary(list), [])
  })

  test('router.use applies to routes registered after it, not before', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst router = express.Router()\n" + PRISMA + GUARD +
      "router.post('/open', async (req, res) => { await prisma.a.create({ data: {} }); res.end() })\n" +
      "router.use(requireAuth)\n" +
      "router.post('/closed', async (req, res) => { await prisma.b.create({ data: {} }); res.end() })\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'server.js', 9, 'likely']])
  })

  test('a mount with middleware protects every route of the mounted router, and adds its prefix', async () => {
    const router = "const express = require('express')\nconst router = express.Router()\n" + PRISMA +
      "router.delete('/:id', async (req, res) => { await prisma.user.delete({ where: { id: req.params.id } }); res.end() })\nmodule.exports = router\n"
    const protectedList = await findings({
      'routes/admin.js': router,
      'server.js': "const express = require('express')\nconst app = express()\n" + GUARD + "app.use('/admin', requireAuth, require('./routes/admin'))\n",
    })
    assert.deepEqual(summary(protectedList), [])
    const openList = await findings({
      'routes/admin.js': router,
      'server.js': "const express = require('express')\nconst adminRoutes = require('./routes/admin')\nconst app = express()\napp.use('/admin', adminRoutes)\n",
    })
    assert.deepEqual(summary(openList), [['api/db-write-without-auth', 'routes/admin.js', 5, 'likely']])
    assert.match(openList.find(f => f.ruleId.startsWith('api/'))!.title, /^\/admin\/:id writes/)
  })

  test('well-known library middleware counts as authentication', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst passport = require('passport')\nconst { requiresAuth } = require('express-openid-connect')\nconst app = express()\n" + PRISMA +
      "app.post('/a', passport.authenticate('jwt', { session: false }), async (req, res) => { await prisma.a.create({ data: {} }); res.end() })\n" +
      "app.post('/b', requiresAuth(), async (req, res) => { await prisma.b.create({ data: {} }); res.end() })\n" })
    assert.deepEqual(summary(list), [])
  })

  test('an auth-looking middleware that cannot be followed lowers confidence and says why', async () => {
    const list = await findings({ 'server.ts': "import express from 'express'\nimport { checkJwt } from '@acme/auth-kit'\n" + ADMIN + "const app = express()\n" +
      "app.post('/wipe', checkJwt, async (req, res) => { await admin.from('logs').delete().neq('id', 0); res.end() })\n" })
    assert.deepEqual(summary(list), [['api/admin-db-access-without-auth', 'server.ts', 6, 'likely']])
    assert.ok(list[0]!.why.some(p => /checkJwt/.test(p) && /could not be followed/.test(p)))
  })

  test('a middleware that does not reject requests does not protect the route', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst app = express()\n" + PRISMA +
      'function logRequest(req, res, next) { console.log(req.path); next() }\n' +
      "app.post('/a', logRequest, async (req, res) => { await prisma.a.create({ data: {} }); res.end() })\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'server.js', 6, 'likely']])
  })

  test('a middleware that lets signed-in users through and redirects the rest protects the route', async () => {
    const pass = "exports.isAuthenticated = (req, res, next) => {\n  if (req.isAuthenticated()) {\n    return next();\n  }\n" +
      "  req.flash('errors', { msg: 'Please sign in.' });\n  res.redirect('/login');\n};\n"
    const route = "const express = require('express')\nconst passportConfig = require('./config/passport')\nconst app = express()\n" + PRISMA +
      "app.post('/account/delete', passportConfig.isAuthenticated, async (req, res) => { await prisma.user.delete({ where: { id: req.user.id } }); res.end() })\n"
    assert.deepEqual(summary(await findings({ 'config/passport.js': pass, 'app.js': route })), [])
    // 仅在已认证时记录日志、随后一律放行，不算拒绝。
    const logOnly = "exports.isAuthenticated = (req, res, next) => {\n  if (req.isAuthenticated()) {\n    return next();\n  }\n  console.log('anonymous');\n  next();\n};\n"
    const list = await findings({ 'config/passport.js': logOnly, 'app.js': route })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'app.js', 6, 'likely']])
  })

  test('session, security-header, and passport setup middleware are not mistaken for authentication', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst session = require('express-session')\nconst lusca = require('lusca')\nconst passport = require('passport')\nconst app = express()\n" + PRISMA +
      "app.use(session({ secret: process.env.SESSION_SECRET }))\napp.use(passport.initialize())\napp.use(passport.session())\napp.use(lusca.xssProtection(true))\n" +
      "app.post('/a', async (req, res) => { await prisma.a.create({ data: {} }); res.end() })\n" })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'server.js', 12, 'likely']])
    assert.ok(!list[0]!.why.some(p => /looks like authentication/.test(p)))
  })
})

describe('request-input rules in Express handlers', () => {
  test('SQL, redirects, server requests, and Mongoose writes are checked', async () => {
    const list = await findings({ 'server.js': "const express = require('express')\nconst axios = require('axios')\nconst app = express()\n" +
      "app.get('/search', async (req, res) => { res.json(await pool.query(`SELECT * FROM items WHERE name = '${req.query.q}'`)) })\n" +
      "app.get('/go', (req, res) => res.redirect(req.query.next))\n" +
      "app.post('/preview', async (req, res) => { res.json((await axios.get(req.body.url)).data) })\n" +
      "app.delete('/notes/:id', async (req, res) => { await Note.findByIdAndDelete(req.params.id); res.end() })\n" })
    assert.deepEqual(summary(list), [
      ['injection/sql', 'server.js', 4, 'certain'],
      ['ssrf/request-url', 'server.js', 6, 'likely'],
      ['api/db-write-without-auth', 'server.js', 7, 'likely'],
      ['redirect/open', 'server.js', 5, 'certain'],
    ])
  })

  test('Stripe webhooks in Express are checked for signature verification', async () => {
    const handler = (verify: boolean) => "const express = require('express')\nconst stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)\nconst app = express()\n" +
      "app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {\n" +
      (verify ? "  let event\n  try {\n    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET)\n  } catch (err) {\n    return res.status(400).send('bad')\n  }\n"
        : '  const event = req.body\n') +
      "  if (event.type === 'checkout.session.completed') fulfil(event.data.object)\n  res.json({ received: true })\n})\n"
    assert.deepEqual(summary(await findings({ 'server.js': handler(false) })), [['webhook/unverified-signature', 'server.js', 6, 'certain']])
    assert.deepEqual(summary(await findings({ 'server.js': handler(true) })), [])
  })
})
