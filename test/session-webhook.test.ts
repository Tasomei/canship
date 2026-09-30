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

for (const check of [
  'const unused = () => supabase.auth.getUser();',
  'supabase.auth.getUser();',
  'await supabase.auth.getUser();',
  'if (flag) { const {data:{user}}=await supabase.auth.getUser(); if(!user) return null; }',
  'const {data:{user}}=await other.auth.getUser(); if(!user) return null;',
  'const {data:{user}}=await supabase.auth.getUser(otherToken); if(!user) return null;',
]) {
  test(`unrelated or unenforced session verification cannot suppress a finding: ${check}`, async () => {
    const hits = await findings({ 'app/dashboard/page.tsx': `export default async function Page(){
      const {data:{session}}=await supabase.auth.getSession(); ${check}
      if(!session)return null; return session.user.id;
    }` })
    assert.deepEqual(hits.map(f => f.ruleId), ['auth/unverified-session'])
  })
}

test('session verification must precede trusted use', async () => {
  const hits = await findings({ 'app/dashboard/page.tsx': `export default async function Page(){
    const {data:{session}}=await supabase.auth.getSession(); await grantAccess(session.user.id);
    const {data:{user}}=await supabase.auth.getUser(); if(!user)return null;
    return session.user.id;
  }` })
  assert.deepEqual(hits.map(f => f.ruleId), ['auth/unverified-session'])
})

test('a checked identity from the same client precedes trusted session use', async () => {
  const hits = await findings({ 'app/dashboard/page.tsx': `export default async function Page(){
    const {data:{session}}=await supabase.auth.getSession();
    const {data:{user}}=await supabase.auth.getUser(); if(!user)return null;
    if(!session)return null; return session.user.id;
  }` })
  assert.deepEqual(hits, [])
})

for (const extra of [
  'function unused(){return stripe.webhooks.constructEvent(body, signature, secret);}',
  "const signature=req.headers.get('stripe-signature'); const digest=createHmac('sha256',secret).update(body).digest('hex');",
  'stripe.webhooks.constructEvent(otherBody, otherSignature, secret);',
  'if(flag)event=stripe.webhooks.constructEvent(body,signature,secret);',
  'try{event=stripe.webhooks.constructEvent(body,signature,secret);}catch{}',
  'event=stripe.webhooks.constructEventAsync(body,signature,secret);',
  'event=stripe.webhooks.constructEvent(body,signature,secret);event=await req.json();',
  'event=stripe.webhooks.constructEvent(body,signature,secret);event.data=req.body.data;',
]) {
  test(`webhook verification must protect the handled event: ${extra}`, async () => {
    const hits = await findings({ 'app/api/stripe/route.ts': `import Stripe from 'stripe';
      export async function POST(req){let event=await req.json();${extra}
      if(event.type==='invoice.paid')await markPaid(event.data.object.id);return new Response('ok');}` })
    assert.deepEqual(hits.map(f => f.ruleId), ['webhook/unverified-signature'])
  })
}

test('manual signature checks remain review findings instead of being silently exempted', async () => {
  const hits = await findings({ 'app/api/stripe/route.ts': `import Stripe from 'stripe';
    export async function POST(req){ const event=await req.json();
    const digest=createHmac('sha256',secret).update(body).digest();
    if(!timingSafeEqual(digest, signature))return new Response('bad',{status:400});
    if(event.type==='invoice.paid')markPaid(event.data.object.id); }` })
  assert.deepEqual(hits.map(f => [f.ruleId, f.confidence]), [['webhook/unverified-signature', 'likely']])
})

test('a verified GET cannot suppress an unverified POST webhook in the same file', async () => {
  const hits = await findings({ 'app/api/stripe/route.ts': `import Stripe from 'stripe';
    export async function GET(req){const event=stripe.webhooks.constructEvent(body,signature,secret);if(event.type==='invoice.paid')markPaid();}
    export async function POST(req){const event=await req.json();if(event.type==='invoice.paid')markPaid();}` })
  assert.equal(hits.length, 1)
  assert.equal(hits[0]!.line, 3)
})

test('a throwing verifier with a rejecting catch still protects its event', async () => {
  const hits = await findings({ 'app/api/stripe/route.ts': `import Stripe from 'stripe';
    export async function POST(req){let event;try{event=await stripe.webhooks.constructEventAsync(await req.text(),signature,secret);}
    catch{ return new Response('bad', {status:400}); }
    if(event.type==='invoice.paid')markPaid(event.data.object.id);}` })
  assert.deepEqual(hits, [])
})

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

  // 类型标注曾把 let event: Stripe.Event 与其后的 try 一起读成声明，try/catch 检查因此失效。
  const typedTry = (catchBody: string) => `import Stripe from 'stripe'
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
export async function POST(req: Request) {
  const body = await req.text()
  let event: Stripe.Event
  try {
    event = stripe.webhooks.constructEvent(body, req.headers.get('stripe-signature')!, process.env.STRIPE_WEBHOOK_SECRET!)
  } catch (err: any) {
    ${catchBody}
  }
  switch (event.type) {
    case 'checkout.session.completed':
      await fulfil(event.data.object.id)
  }
  return new Response('ok')
}`

  test('a typed event verified in try is accepted when the catch logs and then returns', async () => {
    assert.deepEqual(summary(await findings({ 'app/api/webhooks/route.ts':
      typedTry("console.log(`Webhook Error: ${err.message}`)\n    return new Response('bad', { status: 400 })") })), [])
  })

  test('a catch that swallows the failure, or returns only conditionally, leaves the event unverified', async () => {
    for (const catchBody of ["console.log(err.message)", "if (process.env.STRICT) return new Response('bad', { status: 400 })"]) {
      assert.deepEqual(summary(await findings({ 'app/api/webhooks/route.ts': typedTry(catchBody) })),
        [['webhook/unverified-signature', 12, 'certain']], catchBody)
    }
  })
})

describe('verification guards that log before exiting', () => {
  test('a getUser() error branch that logs and then returns still verifies the session', async () => {
    assert.deepEqual(summary(await findings({ 'src/hooks.server.ts': `export const handle = async ({ event, resolve }) => {
  event.locals.safeGetSession = async () => {
    const { data: { session } } = await event.locals.supabase.auth.getSession()
    if (!session) return { session: null, user: null }
    const { data: { user }, error } = await event.locals.supabase.auth.getUser()
    if (error) { console.error(error); return { session: null, user: null } }
    return { session, user }
  }
  return resolve(event)
}` })), [])
  })
})
