/** 请求输入决定外发请求目标（SSRF）或跳转目标（开放重定向）：只看目标开头是否由输入决定。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-outbound-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}

async function expectHits(files: Record<string, string>, expected: Array<[string, number, Finding['confidence']]>): Promise<Finding[]> {
  const result = await scan(project(files))
  const hits = result.findings.filter(f => /^(?:ssrf|redirect)\//.test(f.ruleId))
  assert.deepEqual(hits.map(f => [f.ruleId, f.line, f.confidence]), expected)
  return hits
}

describe('open redirects', () => {
  test('a query value handed to redirect() is certain P2 and names where it was read', async () => {
    const [hit] = await expectHits({ 'app/auth/confirm/route.ts': `import { redirect } from 'next/navigation'
export async function GET(request) {
  const { searchParams } = new URL(request.url)
  const next = searchParams.get('next') ?? '/'
  redirect(next)
}` }, [['redirect/open', 5, 'certain']])
    assert.equal(hit!.severity, 'P2')
    assert.match(hit!.title, /^\/auth\/confirm redirects to an address taken from the request$/)
    assert.match(hit!.why[0]!, /read on line 3/)
  })

  test('input that can decide the host is reported: origin + input, new URL(input, base), and a lone leading slash', async () => {
    await expectHits({
      'app/a/route.ts': `export async function GET(request) {
  const { searchParams, origin } = new URL(request.url)
  return NextResponse.redirect(\`\${origin}\${searchParams.get('next')}\`)
}`,
      'app/b/route.ts': `export async function GET(req) {
  return NextResponse.redirect(new URL(req.nextUrl.searchParams.get('to'), req.url))
}`,
      'app/c/route.ts': `export async function GET(req) {
  const to = req.nextUrl.searchParams.get('to')
  return NextResponse.redirect(new URL('/' + to, req.url))
}`,
    }, [['redirect/open', 3, 'certain'], ['redirect/open', 2, 'certain'], ['redirect/open', 3, 'certain']])
  })

  test('own URLs and fixed paths stay clean; an unverified redirect helper remains likely', async () => {
    await expectHits({
      'app/auth/confirm/route.ts': `export async function GET(request) {
  const redirectTo = request.nextUrl.clone()
  redirectTo.pathname = '/account'
  if (request.nextUrl.searchParams.get('x')) return NextResponse.redirect(new URL('/login', request.url))
  const { origin } = new URL(request.url)
  if (origin) return NextResponse.redirect(\`\${origin}/dashboard\`)
  return NextResponse.redirect(redirectTo)
}`,
      'app/actions.ts': `'use server'
export async function navigate(data) { redirect(\`/posts/\${data.get('id')}\`) }`,
      'app/routes/login.tsx': `export async function action({ request }) {
  const form = await request.formData()
  return redirect(safeRedirect(form.get('redirectTo'), '/'))
}`,
    }, [['redirect/open', 3, 'likely']])
  })

  test('status-first and event-first signatures use the target argument', async () => {
    await expectHits({
      'src/routes/login/+page.server.ts': `export const actions = {
  default: async ({ url }) => { throw redirect(303, url.searchParams.get('redirectTo') ?? '/') },
}`,
      'server/api/go.get.ts': `export default defineEventHandler(async (event) => {
  return sendRedirect(event, getQuery(event).to as string, 302)
})`,
      'pages/api/go.ts': `export default function handler(req, res) { res.redirect(302, req.query.to) }`,
    }, [['redirect/open', 1, 'certain'], ['redirect/open', 2, 'certain'], ['redirect/open', 2, 'certain']])
  })

  test('query values read through new URL(request.url) in one expression still count as input', async () => {
    await expectHits({ 'app/go/route.ts': `export async function GET(request: Request) {
  const next = new URL(request.url).searchParams.get('next') ?? '/'
  redirect(next)
}` }, [['redirect/open', 3, 'certain']])
  })

  test('a content check before the redirect lowers it to likely', async () => {
    await expectHits({ 'app/go/route.ts': `export async function GET(req) {
  const to = req.nextUrl.searchParams.get('to') ?? '/'
  if (!to.startsWith('/') || to.startsWith('//')) return new Response('bad', { status: 400 })
  redirect(to)
}` }, [['redirect/open', 4, 'likely']])
  })
})

describe('server requests to caller-chosen addresses', () => {
  test('a whole URL from the request is reported for review', async () => {
    const [hit] = await expectHits({ 'app/api/proxy/route.ts': `export async function GET(req) {
  const target = req.nextUrl.searchParams.get('url')
  const res = await fetch(target)
  return new Response(res.body)
}` }, [['ssrf/request-url', 3, 'likely']])
    assert.equal(hit!.severity, 'P1')
    assert.match(hit!.why[0]!, /169\.254\.169\.254/)
  })

  test('input in the host, axios options, and Server Function arguments are reported', async () => {
    await expectHits({
      'pages/api/p.ts': `import axios from 'axios'
export default async function handler(req, res) {
  res.json((await axios.get(\`https://\${req.query.host}/status\`)).data)
}`,
      'server/api/x.post.ts': `export default defineEventHandler(async (event) => {
  const { url } = await readBody(event)
  return axios({ method: 'get', url })
})`,
      'app/actions.ts': `'use server'
export async function importFrom(url: string) { return (await fetch(url)).text() }`,
    }, [['ssrf/request-url', 2, 'likely'], ['ssrf/request-url', 3, 'likely'], ['ssrf/request-url', 3, 'likely']])
  })

  test('input only in the path of a fixed origin, and the request\'s own URL, are not reported', async () => {
    await expectHits({ 'app/api/u/route.ts': `export async function GET(req) {
  const id = req.nextUrl.searchParams.get('id')
  const a = await fetch(\`https://api.example.com/users/\${id}\`)
  const b = await fetch(\`\${process.env.API_URL}/users/\${id}\`)
  const c = await fetch(new URL(\`/users/\${id}\`, process.env.API_URL))
  const d = await fetch(new URL('/api/other', req.url))
  const e = await fetch(req.url)
  return Response.json([a, b, c, d, e])
}` }, [])
  })

  test('a parsed URL whose origin, host or hostname must equal a literal before the request is not reported', async () => {
    const handler = (check: string, setup = '') => ({ 'app/api/download/route.ts': `${setup}export async function GET(req) {
  const url = req.nextUrl.searchParams.get('url')
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return new Response('bad', { status: 400 })
  }
${check}
  const res = await fetch(url)
  return new Response(res.body)
}` })
    // 允许多个固定来源、条件写在布尔常量中，与 midday 的写法一致。
    await expectHits(handler(`  const isRelease = parsed.origin === 'https://github.com' && parsed.pathname.startsWith('/acme/app/releases/')
  const isAsset = parsed.origin === "https://api.github.com" && parsed.pathname.startsWith('/repos/acme/app/')
  if (!isRelease && !isAsset) {
    return new Response('bad', { status: 400 })
  }`), [])
    await expectHits(handler("  if (parsed.hostname !== 'files.example.com') throw new Error('bad host')"), [])
    await expectHits(handler("  if (!(parsed.host === 'a.example.com' || parsed.host === 'b.example.com')) return new Response('bad', { status: 400 })"), [])
    await expectHits(handler('  if (!ALLOWED.includes(parsed.origin)) return new Response(\'bad\', { status: 400 })',
      "const ALLOWED = ['https://a.example.com', 'https://b.example.com']\n"), [])
  })

  test('checks that do not fix the host, do not exit, or come after the request are still reported', async () => {
    const handler = (check: string, after = '') => ({ 'app/api/download/route.ts': `export async function GET(req) {
  const url = req.nextUrl.searchParams.get('url')
  const other = req.nextUrl.searchParams.get('other')
  const parsed = new URL(url)
${check}
  const res = await fetch(url)
${after}  return new Response(res.body)
}` })
    const hit: Array<[string, number, Finding['confidence']]> = [['ssrf/request-url', 6, 'likely']]
    // 只检查路径、与另一个请求值比较、检查后不退出、一个分支未固定主机。
    await expectHits(handler("  if (!parsed.pathname.startsWith('/files/')) return new Response('bad', { status: 400 })"), hit)
    await expectHits(handler('  if (parsed.origin !== other) return new Response(\'bad\', { status: 400 })'), hit)
    await expectHits(handler("  if (parsed.origin !== 'https://files.example.com') console.warn('unexpected host')"), hit)
    await expectHits(handler("  if (!(parsed.origin === 'https://files.example.com' || parsed.protocol === 'https:')) return new Response('bad', { status: 400 })"), hit)
    // 主机由插值构成的模板字符串不是固定字面量。
    await expectHits(handler('  if (parsed.origin !== `https://${other}`) return new Response(\'bad\', { status: 400 })'), hit)
    // 检查位于请求之后，或解析的是另一个输入。
    await expectHits(handler('', "  if (parsed.origin !== 'https://files.example.com') return new Response('bad', { status: 400 })\n"), hit)
    await expectHits({ 'app/api/download/route.ts': `export async function GET(req) {
  const url = req.nextUrl.searchParams.get('url')
  const other = new URL(req.nextUrl.searchParams.get('other'))
  if (other.origin !== 'https://files.example.com') return new Response('bad', { status: 400 })
  const res = await fetch(url)
  return new Response(res.body)
}` }, [['ssrf/request-url', 5, 'likely']])
  })
})
