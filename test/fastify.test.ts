/** Fastify 路由：识别简写与完整声明、register 前缀与封装、autoload、钩子与装饰器，并接入鉴权与请求输入规则。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-fastify-'))
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

const PRISMA = "const { PrismaClient } = require('@prisma/client')\nconst prisma = new PrismaClient()\n"
const ADMIN = "const { createClient } = require('@supabase/supabase-js')\n" +
  'const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n'
/** @fastify/jwt 推荐的 authenticate 装饰器。 */
const AUTHENTICATE = "app.decorate('authenticate', async function (request, reply) {\n  try {\n    await request.jwtVerify()\n  } catch (err) {\n    reply.send(err)\n  }\n})\n"

describe('Fastify route discovery', () => {
  test('shorthand routes, options objects, and full declarations are found', async () => {
    const list = await findings({ 'server.js': "const fastify = require('fastify')({ logger: true })\n" + PRISMA +
      "fastify.delete('/users/:id', async (request, reply) => {\n  await prisma.user.delete({ where: { id: request.params.id } })\n  return { ok: true }\n})\n" +
      "fastify.post('/notes', { schema: {} }, async (request) => {\n  await prisma.note.create({ data: request.body })\n})\n" +
      "fastify.route({\n  method: 'PUT',\n  url: '/tags/:id',\n  handler: async (request) => {\n    await prisma.tag.update({ where: { id: request.params.id }, data: request.body })\n  },\n})\n" +
      "fastify.post('/posts', {\n  async handler (request) {\n    await prisma.post.create({ data: request.body })\n  },\n})\n" })
    assert.deepEqual(summary(list), [
      ['api/db-write-without-auth', 'server.js', 5, 'likely'],
      ['api/db-write-without-auth', 'server.js', 9, 'likely'],
      ['api/db-write-without-auth', 'server.js', 15, 'likely'],
      ['api/db-write-without-auth', 'server.js', 20, 'likely'],
    ])
  })

  test('a plugin registered with a prefix carries it, across files', async () => {
    const list = await findings({
      'src/routes/admin.ts': "import type { FastifyInstance } from 'fastify'\n" + ADMIN +
        "export default async function adminRoutes (fastify: FastifyInstance) {\n  fastify.post('/purge', async () => {\n    await admin.from('logs').delete().neq('id', 0)\n  })\n}\n",
      'src/server.ts': "import Fastify from 'fastify'\nimport adminRoutes from './routes/admin'\nconst app = Fastify()\napp.register(adminRoutes, { prefix: '/admin' })\n",
    })
    assert.deepEqual(summary(list), [['api/admin-db-access-without-auth', 'src/routes/admin.ts', 6, 'certain']])
    assert.match(titleOf(list), /\/admin\/purge/)
  })

  test('handlers imported through an @/ alias inside a workspace package are resolved', async () => {
    const list = await findings({
      'apps/api/tsconfig.json': '{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }\n',
      'apps/api/src/controllers/webhook.controller.ts': "import { PrismaClient } from '@prisma/client'\nconst prisma = new PrismaClient()\n" +
        'export async function polarWebhook(request: any) {\n  await prisma.subscription.deleteMany({})\n}\n',
      'apps/api/src/routes/webhook.router.ts': "import * as controller from '@/controllers/webhook.controller'\nimport type { FastifyPluginAsync } from 'fastify'\n" +
        "const webhookRouter: FastifyPluginAsync = async (fastify) => {\n  fastify.route({ method: 'POST', url: '/polar', handler: controller.polarWebhook })\n}\nexport default webhookRouter\n",
      'apps/api/src/app.ts': "import Fastify from 'fastify'\nimport webhookRouter from './routes/webhook.router'\nconst fastify = Fastify()\n" +
        "fastify.register(async (instance) => {\n  instance.register(webhookRouter, { prefix: '/webhook' })\n})\n",
    })
    assert.deepEqual(summary(list), [['api/db-write-without-auth', 'apps/api/src/controllers/webhook.controller.ts', 4, 'likely']])
    assert.match(titleOf(list), /^\/webhook\/polar writes/)
  })

  test('@fastify/autoload loads route plugins with directory prefixes and autohooks', async () => {
    const users = "import type { FastifyPluginAsync } from 'fastify'\n" + PRISMA.replace("const { PrismaClient } = require('@prisma/client')", "import { PrismaClient } from '@prisma/client'") +
      "const users: FastifyPluginAsync = async (fastify) => {\n  fastify.post('/', async (request) => {\n    await prisma.user.create({ data: request.body as any })\n  })\n}\nexport default users\n"
    const app = (autoHooks: boolean) => "import Fastify from 'fastify'\nimport AutoLoad from '@fastify/autoload'\nimport { join } from 'node:path'\nconst app = Fastify()\n" +
      `app.register(AutoLoad, { dir: join(__dirname, 'routes')${autoHooks ? ', autoHooks: true' : ''} })\n`
    const hooks = "export default async function (fastify) {\n  fastify.addHook('onRequest', async (request, reply) => {\n    if (!request.user) return reply.code(401).send({ error: 'unauthorized' })\n  })\n}\n"
    const open = await findings({ 'src/app.ts': app(false), 'src/routes/users/index.ts': users, 'src/routes/users/autohooks.ts': hooks })
    assert.deepEqual(summary(open), [['api/db-write-without-auth', 'src/routes/users/index.ts', 6, 'likely']])
    assert.match(titleOf(open), /^\/users writes/)
    assert.deepEqual(summary(await findings({ 'src/app.ts': app(true), 'src/routes/users/index.ts': users, 'src/routes/users/autohooks.ts': hooks })), [])
  })
})

describe('Fastify hooks and decorators', () => {
  test('the @fastify/jwt authenticate decorator in route options protects the route', async () => {
    const route = (options: string) => "const app = require('fastify')()\n" + ADMIN + AUTHENTICATE +
      `app.route({\n  method: 'POST',\n  url: '/wipe',\n${options}  handler: async () => {\n    await admin.from('logs').delete().neq('id', 0)\n  },\n})\n`
    assert.deepEqual(summary(await findings({ 'server.js': route('') })), [['api/admin-db-access-without-auth', 'server.js', 15, 'certain']])
    assert.deepEqual(summary(await findings({ 'server.js': route('  onRequest: [app.authenticate],\n') })), [])
    // 捕获后只记录日志、不拒绝的装饰器只按名称降低置信度。
    const swallowed = await findings({ 'server.js': route('  onRequest: [app.authenticate],\n').replace('reply.send(err)', 'request.log.warn(err)') })
    assert.deepEqual(summary(swallowed), [['api/admin-db-access-without-auth', 'server.js', 16, 'likely']])
    assert.ok(swallowed[0]!.why.some(p => /authenticate/.test(p) && /could not be followed/.test(p)))
  })

  test('a hook that validates the request in try and rejects every failure in catch protects the plugin', async () => {
    const plugin = (handler: string) => "const { validateManageRequest } = require('./auth')\nmodule.exports = async function (fastify) {\n" +
      `  fastify.addHook('preHandler', async (req, reply) => {\n    try {\n      req.client = await validateManageRequest(req.headers)\n    } catch (e) {\n${handler}    }\n  })\n` +
      "  fastify.delete('/projects/:id', async (request) => {\n    await prisma.project.delete({ where: { id: request.params.id } })\n  })\n}\n"
    const run = (handler: string) => findings({ 'server.js': "const app = require('fastify')()\napp.register(require('./manage'), { prefix: '/manage' })\n", 'manage.js': PRISMA + plugin(handler) })
    const denied = "      if (e instanceof Error) {\n        return reply.status(401).send({ error: e.message })\n      }\n      return reply.status(401).send({ error: 'Unauthorized' })\n"
    assert.deepEqual(summary(await run(denied)), [])
    // 只记录日志、或部分错误放行时不构成保护。
    assert.deepEqual(summary(await run("      req.log.warn(e)\n")), [['api/db-write-without-auth', 'manage.js', 13, 'likely']])
    assert.deepEqual(summary(await run("      if (e instanceof Error) return\n      return reply.status(401).send({ error: 'Unauthorized' })\n")),
      [['api/db-write-without-auth', 'manage.js', 14, 'likely']])
  })

  test('hooks apply within the plugin and to plugins registered after them, not to siblings', async () => {
    const routes = "module.exports = async function (fastify) {\n  fastify.delete('/users/:id', async (request) => {\n    await prisma.user.delete({ where: { id: request.params.id } })\n  })\n}\n"
    const server = (body: string) => "const fastify = require('fastify')\nconst app = fastify()\n" + body
    const hook = "app.addHook('preHandler', async (request, reply) => {\n  if (!request.user) return reply.code(401).send()\n})\n"
    const inPlugin = "module.exports = async function (fastify) {\n  fastify.addHook('onRequest', async (request, reply) => {\n    if (!request.user) return reply.code(401).send()\n  })\n" +
      "  fastify.delete('/users/:id', async (request) => {\n    await prisma.user.delete({ where: { id: request.params.id } })\n  })\n}\n"
    const check = async (server: string, plugin: string) => summary(await findings({ 'server.js': server, 'routes.js': PRISMA + plugin }))
    assert.deepEqual(await check(server("app.register(require('./routes'))\n"), routes), [['api/db-write-without-auth', 'routes.js', 5, 'likely']])
    assert.deepEqual(await check(server(hook + "app.register(require('./routes'))\n"), routes), [])
    assert.deepEqual(await check(server("app.register(require('./routes'))\n"), inPlugin), [])
    assert.deepEqual(await check(server("app.register(async (child) => {\n  child.addHook('onRequest', async (request, reply) => {\n    if (!request.user) return reply.code(401).send()\n  })\n})\napp.register(require('./routes'))\n"), routes),
      [['api/db-write-without-auth', 'routes.js', 5, 'likely']])
  })

  test('@fastify/bearer-auth and @fastify/auth compositions are recognized', async () => {
    const write = "app.post('/items', async () => {\n  await prisma.item.deleteMany({})\n})\n"
    assert.deepEqual(summary(await findings({ 'server.js': "const app = require('fastify')()\n" + PRISMA + write })), [['api/db-write-without-auth', 'server.js', 5, 'likely']])
    assert.deepEqual(summary(await findings({ 'server.js': "const app = require('fastify')()\nconst bearerAuth = require('@fastify/bearer-auth')\n" + PRISMA +
      'app.register(bearerAuth, { keys: new Set([process.env.API_KEY]) })\n' + write })), [])
    const verifier = (name: string, rejects: boolean) => `app.decorate('${name}', async (request, reply) => {\n` +
      (rejects ? "  if (!request.headers.authorization) throw new Error('unauthorized')\n" : '  request.log.info(request.id)\n') + '})\n'
    const composed = (second: boolean, relation = '') => "const app = require('fastify')()\n" + PRISMA + verifier('verifyJwt', true) + verifier('verifyKey', second) +
      `app.post('/items', { preHandler: app.auth([app.verifyJwt, app.verifyKey]${relation}) }, async () => {\n  await prisma.item.deleteMany({})\n})\n`
    assert.deepEqual(summary(await findings({ 'server.js': composed(true) })), [])
    // 默认任一通过即放行：只要有一个不拒绝，组合就不构成保护；relation: 'and' 时一个拒绝即可。
    assert.deepEqual(summary(await findings({ 'server.js': composed(false) })), [['api/db-write-without-auth', 'server.js', 11, 'likely']])
    assert.deepEqual(summary(await findings({ 'server.js': composed(false, ", { relation: 'and' }") })), [])
  })
})

describe('request-input rules in Fastify handlers', () => {
  test('request.query and request.body reach SQL, redirects, and server requests', async () => {
    const list = await findings({ 'server.js': "const app = require('fastify')()\n" +
      "app.get('/search', async (request) => pool.query(`SELECT * FROM items WHERE name = '${request.query.q}'`))\n" +
      "app.get('/go', async (request, reply) => reply.redirect(request.query.next))\n" +
      "app.post('/preview', async (request) => (await fetch(request.body.url)).json())\n" })
    assert.deepEqual(summary(list), [
      ['injection/sql', 'server.js', 2, 'certain'],
      ['ssrf/request-url', 'server.js', 4, 'likely'],
      ['redirect/open', 'server.js', 3, 'certain'],
    ])
  })
})
