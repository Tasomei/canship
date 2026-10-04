/** 大型鉴权包装函数：凭鉴权证据识别为间接鉴权（保留待复核），日志与错误处理包装不算；间接鉴权后的写入不被读取挤掉。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-wrappers-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return (await scan(root)).findings
}
const writes = (list: Finding[]) => list.filter(f => f.ruleId === 'api/db-write-without-auth')
  .map(f => [f.file, f.line, f.title.startsWith('Review indirect') ? 'review' : 'open'])

const DB = "import { PrismaClient } from '@prisma/client'\nexport const prisma = new PrismaClient()\n"
const LOGGING = "export const withLogging = (handler) => async (req, ctx) => {\n  const started = Date.now()\n  try {\n    return await handler(req, ctx)\n  } finally {\n    console.log(Date.now() - started)\n  }\n}\n"
const ROUTE = (wrapper: string, from: string) => `import { ${wrapper} } from '${from}'\nimport { prisma } from '@/lib/db'\n` +
  `export const POST = ${wrapper}(async () => {\n  await prisma.project.delete({ where: { id: '1' } })\n  return Response.json({})\n})\n`

describe('authentication wrappers composed from other wrappers', () => {
  test('a wrapper that hands an authenticating function to a logging wrapper is an indirect guard', async () => {
    const auth = "import { withLogging } from './log'\nimport { getServerSession } from 'next-auth'\n" +
      'export const withWorkspace = (handler, options = {}) => {\n  return withLogging(async (req, ctx) => {\n    const session = await getServerSession()\n' +
      "    if (!session) throw new ApiError({ code: 'unauthorized', message: 'Missing session' })\n    return handler({ req, session })\n  })\n}\n"
    const list = await findings({ 'lib/db.ts': DB, 'lib/log.ts': LOGGING, 'lib/auth.ts': auth, 'app/api/projects/route.ts': ROUTE('withWorkspace', '@/lib/auth') })
    assert.deepEqual(writes(list), [['app/api/projects/route.ts', 4, 'review']])
    assert.ok(list[0]!.evidence?.some(step => step.kind === 'auth-helper' && step.file === 'lib/auth.ts'))
  })

  test('an authenticating middleware passed to a generic composer counts; the composer alone does not', async () => {
    const middleware = 'export function withMiddleware(handler, middleware) {\n  return async (req) => {\n    try {\n' +
      '      const result = middleware ? await middleware(req) : req\n      if (result instanceof Response) return result\n      return await handler(result)\n' +
      "    } catch (error) {\n      return Response.json({ error: 'Unauthorized' }, { status: 401 })\n    }\n  }\n}\n" +
      "async function accountMiddleware(req) {\n  const session = await auth()\n  if (!session) return Response.json({ error: 'forbidden' }, { status: 403 })\n  return req\n}\n" +
      'export const withEmailAccount = (handler) => withMiddleware(handler, accountMiddleware)\nexport const withError = (handler) => withMiddleware(handler)\n'
    assert.deepEqual(writes(await findings({ 'lib/db.ts': DB, 'utils/middleware.ts': middleware, 'app/api/projects/route.ts': ROUTE('withEmailAccount', '@/utils/middleware') })),
      [['app/api/projects/route.ts', 4, 'review']])
    assert.deepEqual(writes(await findings({ 'lib/db.ts': DB, 'utils/middleware.ts': middleware, 'app/api/projects/route.ts': ROUTE('withError', '@/utils/middleware') })),
      [['app/api/projects/route.ts', 4, 'open']])
  })

  test('a generic route factory taking a config object with the handler is an indirect guard', async () => {
    const factory = "export const createAuthedRoute = <TBody extends object, TResponse,>(config: { fn: (args: { body: TBody }) => Promise<TResponse> }) => {\n" +
      "  return async (req, res) => {\n    const auth = await verifyAuthHeader(req.headers.authorization)\n    if (!auth.ok) throw new UnauthorizedError('Invalid credentials')\n" +
      '    res.json(await config.fn({ body: req.body }))\n  }\n}\n'
    const route = "import { createAuthedRoute } from '@/lib/route'\nimport { prisma } from '@/lib/db'\nexport default createAuthedRoute({\n" +
      "  fn: async ({ body }) => {\n    await prisma.comment.create({ data: body })\n    return { ok: true }\n  },\n})\n"
    assert.deepEqual(writes(await findings({ 'lib/db.ts': DB, 'lib/route.ts': factory, 'pages/api/comments.ts': route })), [['pages/api/comments.ts', 5, 'review']])
  })

  test('a logging wrapper is not authentication', async () => {
    assert.deepEqual(writes(await findings({ 'lib/db.ts': DB, 'lib/log.ts': LOGGING, 'app/api/projects/route.ts': ROUTE('withLogging', '@/lib/log') })),
      [['app/api/projects/route.ts', 4, 'open']])
  })
})

describe('choosing the operation to report', () => {
  test('an unprotected read outside the wrapper does not hide writes behind an indirect guard', async () => {
    const auth = "import { getServerSession } from 'next-auth'\nexport const withWorkspace = (handler) => async (req) => {\n  const session = await getServerSession()\n" +
      "  if (!session) return Response.json({ error: 'unauthorized' }, { status: 401 })\n  return handler({ req, session })\n}\n"
    const route = "import { withWorkspace } from '@/lib/auth'\nimport { prisma } from '@/lib/db'\n" +
      "const getOrThrow = async (id: string) => {\n  const row = await prisma.dashboard.findUnique({ where: { id } })\n  if (!row) throw new Error('not found')\n  return row\n}\n" +
      "export const PATCH = withWorkspace(async ({ req }) => {\n  await getOrThrow('1')\n  await prisma.dashboard.update({ where: { id: '1' }, data: {} })\n  return Response.json({})\n})\n"
    assert.deepEqual(writes(await findings({ 'lib/db.ts': DB, 'lib/auth.ts': auth, 'app/api/dashboards/[id]/route.ts': route })),
      [['app/api/dashboards/[id]/route.ts', 10, 'review']])
  })
})
