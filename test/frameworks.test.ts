/** 验证 Next.js 之外各框架的路由识别、URL、别名、鉴权写法与全局鉴权降级。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-frameworks-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}

/** 只关心 API 鉴权规则的结果。 */
async function apiFindings(files: Record<string, string>): Promise<Finding[]> {
  const result = await scan(project(files))
  return result.findings.filter((f) => f.ruleId.startsWith('api/'))
}

/** 标题中的请求路径，如 /api/users。 */
const urlOf = (f: Finding): string => /\/\S*/.exec(f.title)?.[0] ?? ''

const CLIENT = "import { createClient } from '@supabase/supabase-js'\n"
const ADMIN = CLIENT + 'const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n'
const SK_ADMIN = CLIENT + "import { SUPABASE_SERVICE_ROLE_KEY } from '$env/static/private'\n" +
  "const db = createClient('https://x.supabase.co', SUPABASE_SERVICE_ROLE_KEY)\n"
const QUERY = "await db.from('users').select('*')"

/** 断言恰好一条管理员访问结果，并核对路径与置信度。 */
function assertAdmin(findings: Finding[], url: string, confidence: Finding['confidence'] = 'certain'): void {
  assert.equal(findings.length, 1, `expected one finding, got ${findings.map((f) => f.title).join('; ')}`)
  assert.equal(findings[0]!.ruleId, 'api/admin-db-access-without-auth')
  assert.equal(urlOf(findings[0]!), url)
  assert.equal(findings[0]!.confidence, confidence)
}

describe('auth guards the scan recognises in any framework', () => {
  const route = (body: string): Record<string, string> => ({ 'app/api/x/route.ts': ADMIN + body })
  const q = `return Response.json(${QUERY})`

  for (const [name, body] of [
    ['an optional-chained session check that returns 401', `export async function GET(){ const s = await getServerSession(); if (!s?.user) return new Response(null, { status: 401 }); ${q} }`],
    ['an optional-chained session check that redirects', `export async function GET(){ const s = await auth(); if (!s?.user) redirect('/login'); ${q} }`],
    ['a Clerk userId check that redirects', `export async function GET(){ const { userId } = await auth(); if (!userId) redirect('/sign-in'); ${q} }`],
    ['a SvelteKit-style error(401) without throw', `export async function GET({ locals }){ if (!locals.user) error(401, 'no'); ${q} }`],
    ['an awaited requireUserId', `export async function GET(request){ await requireUserId(request); ${q} }`],
  ] as const) {
    test(`${name} protects the query`, async () => {
      assert.deepEqual(await apiFindings(route(body)), [])
    })
  }

  for (const [name, body] of [
    ['an optional-chained check whose branch does not exit', `export async function GET(){ const s = await auth(); if (!s?.user) console.log('anon'); ${q} }`],
    ['an optional-chained check that exits only for signed-in users', `export async function GET(){ const s = await auth(); if (s?.user) return Response.json({}); ${q} }`],
    ['an optional-chained check short-circuited by another condition', `export async function GET(req){ const s = await auth(); if (req.debug && !s?.user) return new Response(null, { status: 401 }); ${q} }`],
  ] as const) {
    test(`${name} does not protect the query`, async () => {
      assertAdmin(await apiFindings(route(body)), '/api/x')
    })
  }
})

describe('Astro endpoints', () => {
  test('an endpoint under src/pages/api is checked', async () => {
    assertAdmin(await apiFindings({
      'src/pages/api/users.ts': ADMIN + `export async function GET() { return new Response(JSON.stringify(${QUERY})) }`,
    }), '/api/users')
  })

  test('an endpoint outside /api is checked too', async () => {
    assertAdmin(await apiFindings({
      'src/pages/users.json.ts': ADMIN + `export const GET = async () => new Response(JSON.stringify(${QUERY}))`,
    }), '/users.json')
  })

  test('a locals.user check protects the endpoint', async () => {
    assert.deepEqual(await apiFindings({
      'src/pages/api/users.ts': ADMIN +
        `export async function GET({ locals }) { if (!locals.user) return new Response(null, { status: 401 }); return new Response(JSON.stringify(${QUERY})) }`,
    }), [])
  })

  // Astro 中间件可为 src/middleware.ts 或 src/middleware/index.ts；修复前后者不被识别，路由被报为 P0 确定。
  const GUARD = "import { defineMiddleware } from 'astro:middleware'\n" +
    'export const onRequest = defineMiddleware(async (ctx, next) => {\n' +
    '  if (!ctx.locals.user) return new Response(null, { status: 401 })\n  return next()\n})\n'
  const ENDPOINT = ADMIN + `export async function GET() { return new Response(JSON.stringify(${QUERY})) }`

  for (const file of ['src/middleware.ts', 'src/middleware/index.ts']) {
    test(`an auth check in ${file} protects the endpoint`, async () => {
      assert.deepEqual(await apiFindings({ 'src/pages/api/users.ts': ENDPOINT, [file]: GUARD }), [])
    })
  }

  test('a helper under src/middleware that is not the entry point does not protect the endpoint', async () => {
    assertAdmin(await apiFindings({ 'src/pages/api/users.ts': ENDPOINT, 'src/middleware/auth.ts': GUARD }), '/api/users')
  })

  test('a Next.js-style proxy.ts does not protect an Astro endpoint', async () => {
    assertAdmin(await apiFindings({ 'src/pages/api/users.ts': ENDPOINT, 'src/proxy.ts': GUARD }), '/api/users')
  })

  test('a script in src/pages that exports no HTTP method is not an endpoint', async () => {
    assert.deepEqual(await apiFindings({
      'src/pages/_helpers.ts': ADMIN + `export async function load() { return ${QUERY} }`,
    }), [])
  })
})

describe('SvelteKit endpoints', () => {
  const endpoint = `export async function GET() { return new Response(JSON.stringify(${QUERY})) }`

  test('a +server.ts endpoint is checked', async () => {
    assertAdmin(await apiFindings({ 'src/routes/api/users/+server.ts': SK_ADMIN + endpoint }), '/api/users')
  })

  test('a route group is left out of the URL', async () => {
    assertAdmin(await apiFindings({ 'src/routes/(app)/api/users/+server.ts': SK_ADMIN + endpoint }), '/api/users')
  })

  test('error(401) on a missing locals.user protects the endpoint', async () => {
    assert.deepEqual(await apiFindings({
      'src/routes/api/users/+server.ts': SK_ADMIN +
        `export async function GET({ locals }) { if (!locals.user) error(401, 'no'); return new Response(JSON.stringify(${QUERY})) }`,
    }), [])
  })

  test('an Auth.js session?.user check protects the endpoint', async () => {
    assert.deepEqual(await apiFindings({
      'src/routes/api/users/+server.ts': SK_ADMIN +
        `export async function GET({ locals }) { const session = await locals.auth(); if (!session?.user) error(401); return new Response(JSON.stringify(${QUERY})) }`,
    }), [])
  })

  test('an admin client imported through $lib is recognised', async () => {
    assertAdmin(await apiFindings({
      'src/lib/server/admin.ts': SK_ADMIN + 'export { db }',
      'src/routes/api/users/+server.ts': `import { db } from '$lib/server/admin'\n` + endpoint,
    }), '/api/users')
  })

  test('an auth check in hooks.server lowers confidence instead of hiding the finding', async () => {
    const [finding] = await apiFindings({
      'src/hooks.server.ts':
        "export const handle = async ({ event, resolve }) => { if (event.url.pathname.startsWith('/api') && !event.locals.user) error(401); return resolve(event) }",
      'src/routes/api/users/+server.ts': SK_ADMIN + endpoint,
    })
    assert.equal(finding?.confidence, 'likely')
    assert.ok(finding.why.some((line) => line.includes('src/hooks.server.ts')), 'the finding should name the hook')
  })

  test('hooks that only populate locals leave the finding certain', async () => {
    assertAdmin(await apiFindings({
      'src/hooks.server.ts':
        'export const handle = async ({ event, resolve }) => { event.locals.user = await getUser(event.cookies); return resolve(event) }',
      'src/routes/api/users/+server.ts': SK_ADMIN + endpoint,
    }), '/api/users', 'certain')
  })

  test('a write through locals.supabase is left to row level security', async () => {
    assert.deepEqual(await apiFindings({
      'src/routes/api/notes/+server.ts':
        "export async function POST({ locals }) { await locals.supabase.from('notes').insert({ a: 1 }); return new Response(null) }",
    }), [])
  })

  test('an OAuth provider callback is a sign-in endpoint', async () => {
    assert.deepEqual(await apiFindings({
      'src/routes/login/github/callback/+server.ts': SK_ADMIN +
        "export async function GET() { await db.from('users').insert({ a: 1 }); return new Response(null) }",
    }), [])
  })
})

describe('Nuxt server routes', () => {
  const handler = `export default defineEventHandler(async () => ${QUERY})`

  test('a server/api route is checked and its method suffix is left out of the URL', async () => {
    assertAdmin(await apiFindings({ 'server/api/users.get.ts': ADMIN + handler }), '/api/users')
  })

  test('a server/routes route is checked', async () => {
    assertAdmin(await apiFindings({ 'server/routes/export/index.ts': ADMIN + handler }), '/export')
  })

  test('requireUserSession protects the route', async () => {
    assert.deepEqual(await apiFindings({
      'server/api/users.get.ts': ADMIN +
        `export default defineEventHandler(async (event) => { await requireUserSession(event); return ${QUERY} })`,
    }), [])
  })

  test('createError with statusCode 401 protects the route', async () => {
    assert.deepEqual(await apiFindings({
      'server/api/users.get.ts': ADMIN +
        `export default defineEventHandler(async (event) => { const s = await getUserSession(event); if (!s.user) throw createError({ statusCode: 401 }); return ${QUERY} })`,
    }), [])
  })

  test('serverSupabaseServiceRole with a type argument is an admin client', async () => {
    assertAdmin(await apiFindings({
      'server/api/users.get.ts':
        `export default defineEventHandler(async (event) => { const db = serverSupabaseServiceRole<Database>(event); return ${QUERY} })`,
    }), '/api/users')
  })

  test('a write through serverSupabaseClient is left to row level security', async () => {
    assert.deepEqual(await apiFindings({
      'server/api/notes.post.ts':
        "export default defineEventHandler(async (event) => { const db = await serverSupabaseClient<Database>(event); await db.from('notes').insert({ a: 1 }); return {} })",
    }), [])
  })

  test('an admin client auto-imported from server/utils is recognised', async () => {
    assertAdmin(await apiFindings({
      'server/utils/admin.ts': ADMIN + 'export const useAdmin = () => db',
      'server/api/users.get.ts': "export default defineEventHandler(async () => await useAdmin().from('users').select('*'))",
    }), '/api/users')
  })

  test('an auth check in server/middleware lowers confidence instead of hiding the finding', async () => {
    const [finding] = await apiFindings({
      'server/middleware/auth.ts':
        "export default defineEventHandler(async (event) => { if (event.path.startsWith('/api/admin')) { const s = await getUserSession(event); if (!s.user) throw createError({ statusCode: 401 }) } })",
      'server/api/users.get.ts': ADMIN + handler,
    })
    assert.equal(finding?.confidence, 'likely')
  })

  test('an OAuth event handler is a sign-in endpoint', async () => {
    assert.deepEqual(await apiFindings({
      'server/routes/auth/github.get.ts': ADMIN +
        "export default defineOAuthGitHubEventHandler({ async onSuccess(event, { user }) { await db.from('users').upsert({ id: user.id }) } })",
    }), [])
  })

  test('a tRPC router under src/server/api is not a Nuxt route', async () => {
    assert.deepEqual(await apiFindings({
      'src/server/api/routers/user.ts': ADMIN +
        `export const userRouter = createTRPCRouter({ all: publicProcedure.query(async () => ${QUERY}) })`,
    }), [])
  })
})

describe('Remix and React Router route modules', () => {
  test('a loader in a flat route file is checked', async () => {
    assertAdmin(await apiFindings({
      'app/routes/api.users.ts': ADMIN + `export async function loader() { return Response.json(${QUERY}) }`,
    }), '/api/users')
  })

  test('an action in a page route is checked and pathless segments are left out of the URL', async () => {
    const findings = await apiFindings({
      'app/routes/_app.notes.$id.tsx': "import { prisma } from '~/db.server'\n" +
        'export async function action({ params }) { await prisma.note.delete({ where: { id: params.id } }); return null }\n' +
        'export default function Note() { return null }',
    })
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.ruleId, 'api/db-write-without-auth')
    assert.equal(urlOf(findings[0]!), '/notes/$id')
  })

  test('requireUserId protects the loader', async () => {
    assert.deepEqual(await apiFindings({
      'app/routes/api.users.ts': ADMIN +
        `export async function loader({ request }) { await requireUserId(request); return Response.json(${QUERY}) }`,
    }), [])
  })

  test('an admin client imported through ~/ is recognised', async () => {
    assertAdmin(await apiFindings({
      'app/utils/admin.server.ts': ADMIN + 'export { db }',
      'app/routes/api.users.ts': `import { db } from '~/utils/admin.server'\nexport const loader = async () => Response.json(${QUERY})`,
    }), '/api/users')
  })

  test('a route module without a loader or action is not requestable', async () => {
    assert.deepEqual(await apiFindings({
      'app/routes/about.tsx': ADMIN + `export default function About() { void ${QUERY}; return null }`,
    }), [])
  })
})

describe('the client detection cannot be made slow', () => {
  test('a long run of whitespace after createClient scans in linear time', async () => {
    // 修复前 200KB 空白使整次扫描耗时约 63 秒。
    const started = Date.now()
    await scan(project({
      'lib/slow.ts': `createClient${' '.repeat(200_000)};\n`,
      'app/api/x/route.ts': 'export async function GET() { return Response.json({}) }',
    }))
    const took = Date.now() - started
    assert.ok(took < 10_000, `took ${took}ms`)
  })

  test('deeply nested conditions in hooks.server are analysed in linear time', async () => {
    // 修复前每个 if 重新扫描自己的代码块，200KB 的嵌套使整次扫描耗时约 86 秒。
    const depth = 15_000
    const started = Date.now()
    await scan(project({
      'src/hooks.server.ts': 'export const handle = async ({ event }) => {\n' +
        'if (event.a) {\n'.repeat(depth) + '}\n'.repeat(depth) + '}\n',
      'src/routes/api/x/+server.ts': SK_ADMIN +
        `export async function GET() { return new Response(JSON.stringify(${QUERY})) }`,
    }))
    const took = Date.now() - started
    assert.ok(took < 10_000, `took ${took}ms`)
  })
})
