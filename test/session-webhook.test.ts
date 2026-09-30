/** 服务端信任 Supabase getSession()、未验证签名的 Stripe webhook，以及 getSession 不再算作 API 鉴权。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-session-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}

async function findings(files: Record<string, string>): Promise<Finding[]> {
  return (await scan(project(files))).findings
}
const summary = (list: Finding[]) => list.map(f => [f.ruleId, f.line, f.confidence])

const ADMIN = "import { createClient } from '@supabase/supabase-js'\n" +
  'const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n'

describe('supabase.auth.getSession() on the server', () => {
  test('a server component that redirects on getSession() is certain', async () => {
    const list = await findings({ 'app/dashboard/page.tsx': `import { redirect } from 'next/navigation'
export default async function Page() {
  const supabase = await createClient()
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) redirect('/login')
  return <div>{session.user.email}</div>
}` })
    assert.deepEqual(summary(list), [['auth/unverified-session', 4, 'certain']])
    assert.equal(list[0]!.severity, 'P1')
    assert.match(list[0]!.fix[0]!, /getClaims\(\)/)
  })

  test('proxy helpers are server code; reading the user id without a condition is likely', async () => {
    assert.deepEqual(summary(await findings({
      'lib/supabase/proxy.ts': `export async function updateSession(request) {
  const { data } = await supabase.auth.getSession()
  if (!data.session) return NextResponse.redirect(new URL('/login', request.url))
  return NextResponse.next()
}`,
      'app/api/x/route.ts': `export async function GET() {
  const { data: { session } } = await supabase.auth.getSession()
  return Response.json(await api.list(session?.user.id))
}`,
    })), [['auth/unverified-session', 2, 'certain'], ['auth/unverified-session', 2, 'likely']])
  })

  test('client components, getUser() follow-up, and token forwarding are not reported', async () => {
    assert.deepEqual(summary(await findings({
      'app/nav.tsx': `'use client'
export function Nav() {
  const x = async () => { const { data: { session } } = await supabase.auth.getSession(); if (!session) return }
}`,
      'src/hooks.server.ts': `export const handle = async ({ event, resolve }) => {
  event.locals.safeGetSession = async () => {
    const { data: { session } } = await event.locals.supabase.auth.getSession()
    if (!session) return { session: null, user: null }
    const { data: { user }, error } = await event.locals.supabase.auth.getUser()
    if (error) return { session: null, user: null }
    return { session, user }
  }
  return resolve(event)
}`,
      'app/api/x/route.ts': `export async function GET() {
  const { data: { session } } = await supabase.auth.getSession()
  return fetch(API, { headers: { Authorization: 'Bearer ' + session?.access_token } })
}`,
    })), [])
  })

  test('getSession() no longer counts as a guard for admin database access, and the finding says why', async () => {
    const list = await findings({ 'app/api/admin/route.ts': ADMIN + `export async function DELETE() {
  const supabase = await createClient()
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) return new Response('Unauthorized', { status: 401 })
  await admin.from('users').delete().eq('id', session.user.id)
  return new Response('ok')
}` })
    assert.deepEqual(summary(list), [['api/admin-db-access-without-auth', 7, 'certain'], ['auth/unverified-session', 5, 'certain']])
    assert.ok(list[0]!.why.some(p => /getSession\(\).*not counted as authentication/.test(p)))
  })

  test('getUser(), getClaims(), and NextAuth getServerSession() still count as guards', async () => {
    const guarded = (call: string, name: string) => ADMIN + `export async function DELETE() {
  const ${name} = ${call}
  if (!user) return new Response('Unauthorized', { status: 401 })
  await admin.from('users').delete()
  return new Response('ok')
}`
    assert.deepEqual(summary(await findings({
      'app/api/a/route.ts': guarded('await supabase.auth.getUser()', '{ data: { user } }'),
      'app/api/b/route.ts': guarded('await supabase.auth.getClaims()', '{ data: { claims: user } }'),
      'app/api/c/route.ts': guarded('await getServerSession(authOptions)', 'user'),
    })), [])
  })
})

describe('Stripe webhooks', () => {
  const unverified = `import Stripe from 'stripe'
export async function POST(req: Request) {
  const event = await req.json()
  switch (event.type) {
    case 'checkout.session.completed':
      await grantAccess(event.data.object.customer)
      break
  }
  return new Response('ok')
}`

  test('handling events from the request body without constructEvent is certain', async () => {
    const list = await findings({ 'app/api/webhooks/stripe/route.ts': unverified })
    assert.deepEqual(summary(list), [['webhook/unverified-signature', 5, 'certain']])
    assert.match(list[0]!.title, /^\/api\/webhooks\/stripe acts on Stripe events without verifying the signature$/)
    assert.match(list[0]!.why[0]!, /checkout\.session\.completed/)
  })

  test('constructEvent, events.retrieve, and non-route modules are not reported', async () => {
    assert.deepEqual(summary(await findings({
      'app/api/webhooks/stripe/route.ts': `import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
export async function POST(req: Request) {
  const body = await req.text()
  const event = stripe.webhooks.constructEvent(body, req.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!)
  if (event.type === 'invoice.paid') await markPaid(event.data.object.id)
  return new Response('ok')
}`,
      'pages/api/stripe.ts': `import Stripe from 'stripe'
export default async function handler(req, res) {
  const event = await stripe.events.retrieve(req.body.id)
  if (event.type === 'invoice.paid') await markPaid(event.data.object.id)
  res.end()
}`,
      'lib/stripe.ts': `import Stripe from 'stripe'
export function handle(event) { if (event.type === 'invoice.paid') markPaid() }`,
    })), [])
  })
})
