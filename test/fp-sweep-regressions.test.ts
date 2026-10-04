/** 真实项目误报排查（2026-10）发现的写法，改写为最小用例；不复制原项目代码。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding, ScanResult } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

async function run(files: Record<string, string>): Promise<ScanResult> {
  const root = mkdtempSync(join(tmpdir(), 'canship-fp-sweep-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return scan(root)
}

const summary = (findings: Finding[]) => findings
  .filter(f => /^(?:injection|ssrf|redirect|webhook)\//.test(f.ruleId))
  .map(f => [f.ruleId, f.file, f.line, f.confidence])

describe('statements without semicolons', () => {
  test('a one-line branch ends at its line, so a later denial is not borrowed', async () => {
    const route = (guard: string) => "import { db } from '@/lib/db'\nexport async function POST(request: Request) {\n" +
      `  const origin = request.headers.get('origin')\n${guard}  await db.item.deleteMany({})\n  return Response.json({ ok: true })\n}\n`
    const writes = (result: ScanResult) => result.findings.filter(f => f.ruleId === 'api/db-write-without-auth').map(f => [f.file, f.line])
    // if (!origin) 放行，之后的 403 只针对不允许的来源，不是鉴权。
    assert.deepEqual(writes(await run({ 'app/api/items/route.ts': route(
      "  if (!origin)\n    return Response.json({ ok: true })\n  if (!allowed(origin))\n    return Response.json({ error: 'forbidden' }, { status: 403 })\n") })),
      [['app/api/items/route.ts', 8]])
  })
})

describe('addresses built with join', () => {
  test('a fixed host joined with input in the query is safe; input at the start is not', async () => {
    const route = (first: string) => `export async function GET(request: Request) {\n  const code = new URL(request.url).searchParams.get('code')\n` +
      `  const url = [${first}, \`?code=\${code}\`].join('')\n  return Response.json(await (await fetch(url)).json())\n}\n`
    const ssrf = (result: ScanResult) => summary(result.findings).filter(f => f[0] === 'ssrf/request-url')
    assert.deepEqual(ssrf(await run({ 'app/api/oauth/route.ts': route("'https://slack.com/api/oauth.v2.access'") })), [])
    assert.deepEqual(ssrf(await run({ 'app/api/oauth/route.ts': route("new URL(request.url).searchParams.get('target')") })),
      [['ssrf/request-url', 'app/api/oauth/route.ts', 4, 'likely']])
  })
})

describe('raw database statements', () => {
  test('a SELECT probe through $executeRaw is a read; other raw statements are writes', async () => {
    const route = (sql: string) => `import { db } from '@/lib/db'\nexport async function GET() {\n  await db.$executeRaw\`${sql}\`\n  return Response.json({ ok: true })\n}\n`
    const writes = (result: ScanResult) => result.findings.filter(f => f.ruleId === 'api/db-write-without-auth').map(f => [f.file, f.line])
    assert.deepEqual(writes(await run({ 'app/api/health/route.ts': route('SELECT 1') })), [])
    assert.deepEqual(writes(await run({ 'app/api/health/route.ts': route('DELETE FROM sessions') })), [['app/api/health/route.ts', 3]])
    assert.deepEqual(writes(await run({ 'app/api/health/route.ts': route('SELECT * INTO archive FROM sessions') })), [['app/api/health/route.ts', 3]])
  })
})

describe('long expressions are ordinary code', () => {
  test('a large call in a declaration does not make a clean scan incomplete', async () => {
    const steps = Array.from({ length: 200 }, (_, i) => `      writer.write({ type: 'step', index: ${i}, label: 'processing step number ${i}' })`).join('\n')
    const result = await run({ 'app/api/chat/route.ts': `export async function POST(request: Request) {
  const { messages } = await request.json()
  const stream = createUIMessageStream({
    execute: async ({ writer }) => {
${steps}
    },
  })
  await fetch('https://api.example.com/usage', { method: 'POST' })
  return new Response(stream)
}` })
    assert.equal(result.partial, false, JSON.stringify(result.errors))
    assert.deepEqual(summary(result.findings), [])
  })

  test('a sink after a large expression is still analysed', async () => {
    const filler = Array.from({ length: 200 }, (_, i) => `    option${i}: 'value number ${i} for configuration',`).join('\n')
    const result = await run({ 'app/api/items/route.ts': `export async function GET(request: Request) {
  const config = {
${filler}
  }
  const sort = new URL(request.url).searchParams.get('sort')
  return Response.json(await prisma.$queryRawUnsafe(\`SELECT * FROM items ORDER BY \${sort}\`, config))
}` })
    assert.equal(result.partial, false)
    assert.deepEqual(summary(result.findings), [['injection/sql', 'app/api/items/route.ts', 205, 'certain']])
  })

  test('a long fixed address before the input is settled without reaching a limit', async () => {
    const path = Array.from({ length: 40 }, (_, i) => `segment${i}`).join('/')
    const result = await run({ 'app/api/proxy/route.ts': `export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get('id')
  const res = await fetch(\`https://api.example.com/${path}?id=\${id}\`)
  return Response.json(await res.json())
}` })
    assert.equal(result.partial, false, JSON.stringify(result.errors))
    assert.deepEqual(summary(result.findings), [])
  })

  test('a long scheme-like prefix still reaches the limit instead of guessing', async () => {
    // 前缀仍可能延伸成协议加主机，不能提前判定安全。
    const result = await run({ 'app/api/proxy/route.ts': `export async function GET(request: Request) {
  const host = new URL(request.url).searchParams.get('host')
  const res = await fetch(\`${'a'.repeat(240)}://\${host}/data\`)
  return Response.json(await res.json())
}` })
    assert.equal(result.partial, true)
  })
})

describe('redirect targets', () => {
  test('a Server Function cannot be triggered by a link, so its arguments are not redirect input', async () => {
    const result = await run({ 'app/actions.ts': `'use server'
import { redirect } from 'next/navigation'
export async function redirectToPath(path: string) {
  return redirect(path)
}` })
    assert.deepEqual(summary(result.findings), [])
  })

  test('each branch of a conditional target is judged on its own', async () => {
    const result = await run({
      'app/api/callback/route.ts': `import { redirect } from 'next/navigation'
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const appUrl = \`https://app.example.com/notifications?\${searchParams}\`
  const wwwUrl = \`https://www.example.com/app/\${searchParams.get('workspace')}\`
  redirect(process.env.V2 ? appUrl : wwwUrl)
}`,
      'pages/api/accept.ts': `export default async function handle(req, res) {
  const { teamId, token } = req.query
  const base = \`/login?next=/api/teams/\${teamId}/accept\`
  const target = token ? \`\${base}&token=\${token}\` : base
  res.redirect(target)
}`,
      'app/api/go/route.ts': `export async function GET(request: Request) {
  const next = new URL(request.url).searchParams.get('next')
  return Response.redirect(process.env.FIXED ? '/home' : next)
}`,
      'app/api/back/route.ts': `export async function GET(request: Request) {
  const next = new URL(request.url).searchParams.get('next')
  return Response.redirect(next || '/')
}`,
    })
    assert.deepEqual(summary(result.findings), [
      ['redirect/open', 'app/api/back/route.ts', 3, 'certain'],
      ['redirect/open', 'app/api/go/route.ts', 3, 'certain'],
    ])
  })

  test('a value looked up with request input is not itself request input', async () => {
    const result = await run({
      'app/q/[slug]/route.ts': `export async function GET(request: Request, { params }) {
  const { slug } = await params
  const link = await db.link.findUnique({ where: { slug } })
  return Response.redirect(link.url)
}`,
      'app/api/saml/route.ts': `export async function GET(request: Request) {
  const query = Object.fromEntries(new URL(request.url).searchParams)
  const { redirect_url } = await oauthController.authorize(query)
  return Response.redirect(redirect_url)
}`,
      'pages/api/export.ts': `export default async function handler(req, res) {
  const job = await getExportJob(req.query.id)
  return res.redirect(302, job.result)
}`,
    })
    assert.deepEqual(summary(result.findings), [])
  })

  test('a helper given the raw value, and a validator that returns it, still carry input', async () => {
    const result = await run({
      'app/routes/login.tsx': `export async function action({ request }) {
  const form = await request.formData()
  return redirect(safeRedirect(form.get('redirectTo')))
}`,
      'app/api/next/route.ts': `export async function POST(request: Request) {
  const data = schema.parse(await request.json())
  return Response.redirect(data.next)
}`,
      // toString() 不改变返回值内容，名为 validate 的函数不能单凭名称证明安全。
      'pages/api/fetch.ts': `export default async function handler(req, res) {
  const target = validateUrl(req.body.url)
  const response = await fetch(target.toString())
  res.json(await response.json())
}`,
    })
    assert.deepEqual(summary(result.findings), [
      ['ssrf/request-url', 'pages/api/fetch.ts', 3, 'likely'],
      ['redirect/open', 'app/api/next/route.ts', 3, 'likely'],
      ['redirect/open', 'app/routes/login.tsx', 3, 'likely'],
    ])
  })
})

describe('server requests and SQL', () => {
  test('the request Host header names this site, not a caller-chosen server', async () => {
    const result = await run({ 'app/routes/healthcheck.tsx': `export async function loader({ request }) {
  const host = request.headers.get('X-Forwarded-Host') ?? request.headers.get('host')
  const url = new URL('/', \`http://\${host}\`)
  await fetch(url.toString(), { method: 'HEAD' })
  return new Response('OK')
}` })
    assert.deepEqual(summary(result.findings), [])
  })

  test('a database row looked up with request input is not request input in SQL', async () => {
    const result = await run({ 'app/api/user/route.ts': `export async function POST(request: Request) {
  const body = await request.json()
  const user = await db.user.findUnique({ where: { id: body.id } })
  return Response.json(await prisma.$queryRawUnsafe(\`SELECT * FROM logs WHERE owner = '\${user.name}'\`))
}` })
    assert.deepEqual(summary(result.findings), [])
  })
})

describe('Stripe verification through a client factory', () => {
  for (const client of ['getStripe()', 'this.stripe', 'stripeClient()']) {
    test(`constructEvent on ${client} verifies the event`, async () => {
      const result = await run({ 'app/api/stripe/webhook/route.ts': `export async function POST(request: Request) {
  const body = await request.text()
  const signature = request.headers.get('stripe-signature')
  const event = ${client}.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)
  if (event.type === 'invoice.payment_succeeded') await processEvent(event)
  return Response.json({ received: true })
}` })
      assert.deepEqual(summary(result.findings), [])
    })
  }
})
