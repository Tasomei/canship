/** 身份来源与实参传递不能用常量、请求输入或未等待的 Promise 冒充。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { apiAuthRule } from '../src/rules/apiauth.js'

const write = "await db.from('items').delete();"
async function analyze(body: string, helper?: string) {
  const contents: Record<string, string> = {
    'lib/db.ts': "import {createClient} from '@supabase/supabase-js';export const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);",
    'app/api/items/route.ts': "import {db} from '../../../lib/db';" +
      (helper ? "import {guard} from '../../../lib/guard';" : '') + `export async function DELETE(req){${body}${write}}`,
  }
  if (helper) contents['lib/guard.ts'] = helper
  const files = Object.entries(contents).map(([path, content]) => ({ path, content, lines: content.split('\n'), isExampleContext: false }))
  return apiAuthRule.check({ root: '.', files, git: 'not-a-repo', gitExecutable: null,
    reportIncomplete() { assert.fail('unexpected incomplete scan') } })
}

for (const value of ['true', '{}', '"guest"', 'req.body.user', 'req.query.user', 'await req.json()', 'req.headers.get("authorization")',
  'getUser()', 'supabase.auth.getUser()', 'await supabase.auth.getUser()',
  'await getUser() === null', 'await getUser()\n || req.body.user', 'await getUser()\n ?? req.body.user']) {
  test(`an invalid identity origin does not suppress the finding: ${value}`, async () => {
    const findings = await analyze(`const user=${value};if(!user)return new Response(null,{status:401});`)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'certain')
  })
}

for (const prefix of [
  'const user=await getUser();const account=user;',
  'const trueUser=await getUser();const account=trueUser;',
  'const {data:{user:account}}=await supabase.auth.getUser();',
  'const result=await supabase.auth.getUser();const account=result.data.user;',
]) {
  test(`verified identity aliases protect direct handlers: ${prefix}`, async () => {
    assert.deepEqual(await analyze(prefix + 'if(!account)throw new Error("denied");'), [])
  })
}

// Supabase 官方示例常见写法：先解构 data，再读取 user 或 claims。
for (const prefix of [
  'const {data}=await supabase.auth.getUser();const account=data.user;',
  'const {data,error}=await supabase.auth.getUser();const account=data?.user;',
  'const {data}=await supabase.auth.getClaims();const account=data?.claims;',
  'const {data:{claims:account}}=await supabase.auth.getClaims();',
  'const {data:claimsData}=await supabase.auth.getClaims();const account=claimsData?.claims?.sub;',
]) {
  test(`Supabase data envelopes protect direct handlers: ${prefix}`, async () => {
    assert.deepEqual(await analyze(prefix + 'if(!account)throw new Error("denied");'), [])
  })
}

test('the official getClaims guard with an error check protects the handler', async () => {
  assert.deepEqual(await analyze('const {data,error}=await supabase.auth.getClaims();if(error||!data?.claims){return new Response(null,{status:401});}'), [])
})

for (const prefix of [
  'const {data}=await supabase.auth.getUser();const account=data.session;',
  'const {data}=await supabase.auth.getClaims();const account=data.user;',
  'const {error:account}=await supabase.auth.getUser();',
  'const {data}=supabase.auth.getClaims();const account=data?.claims;',
  'const {data}=await req.json();const account=data?.claims;',
]) {
  test(`other Supabase result fields are not identities: ${prefix}`, async () => {
    const findings = await analyze(prefix + 'if(!account)return new Response(null,{status:401});')
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'certain')
  })
}

// Vercel Cron 官方写法：https://vercel.com/docs/cron-jobs/manage-cron-jobs
for (const guard of [
  "const authHeader=req.headers.get('authorization');const cronSecret=process.env.CRON_SECRET;if(!cronSecret||authHeader!==`Bearer ${cronSecret}`){return new Response('Unauthorized',{status:401});}",
  "if(req.headers.get('authorization')!==`Bearer ${process.env.CRON_SECRET}`)return new Response(null,{status:401});",
  "if(req.headers.get('x-api-key')!==process.env.API_KEY)return new Response(null,{status:401});",
]) {
  test(`a comparison with a server secret protects the handler: ${guard.slice(0, 60)}`, async () => {
    assert.deepEqual(await analyze(guard), [])
  })
}

for (const guard of [
  "const authHeader=req.headers.get('authorization');if(authHeader!==`Bearer ${req.headers.get('x')}`)return new Response(null,{status:401});",
  "if(req.headers.get('authorization')!==`Bearer ${'known'}`)return new Response(null,{status:401});",
  "if(req.headers.get('authorization')!=='Bearer known')return new Response(null,{status:401});",
  "if(req.headers.get('a')!==req.headers.get('b'))return new Response(null,{status:401});",
]) {
  test(`a comparison without a server secret does not protect the handler: ${guard.slice(0, 60)}`, async () => {
    const findings = await analyze(guard)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'certain')
  })
}

test('overwriting an identity with request input invalidates the check', async () => {
  assert.equal((await analyze('let user=await getUser();user=req.body.user;if(!user)return new Response(null,{status:401});')).length, 1)
})

test('a request-input alias remains untrusted', async () => {
  assert.equal((await analyze('const payload=await req.json();const user=payload.user;if(!user)return new Response(null,{status:401});')).length, 1)
})

for (const declaration of [
  'const {user}=req.body;',
  'const {user:account}=await req.json();const user=account;',
  'const {user,token}=req.body;',
  'const {data:{user}}=await req.json();',
  'const {user={}}=req.body;',
  'const {\n user\n}=await req.json();',
  'const [user]=await req.json();',
]) {
  test(`destructuring does not turn request input into identity: ${declaration}`, async () => {
    assert.equal((await analyze(declaration + 'if(!user)return new Response(null,{status:401});')).length, 1)
  })
}

test('Supabase user destructuring remains recognised alongside other fields', async () => {
  assert.deepEqual(await analyze('const {data:{user},error}=await supabase.auth.getUser();if(!user)throw new Error("denied");'), [])
})

test('semicolon-free destructuring stops at its own closing brace', async () => {
  assert.deepEqual(await analyze('const {data:{user}}=await supabase.auth.getUser()\nif(!user)throw new Error("denied")\nconst {error}=await readMetadata()\n'), [])
})

test('a conditional identity assignment cannot authenticate the other branch', async () => {
  assert.equal((await analyze('let user=req.body.user;if(req.optional){user=await getUser();}if(!user)return new Response(null,{status:401});')).length, 1)
})

const parameterGuard = 'export async function guard(subject){if(!subject)throw new Error("denied");}'
for (const argument of ['true', '{}', 'req.body.user', 'req', 'undefined']) {
  test(`a parameter guard does not accept an unverified argument: ${argument}`, async () => {
    const findings = await analyze(`await guard(${argument});`, parameterGuard)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'certain')
  })
}

test('a verified identity passed to a parameter guard yields review evidence', async () => {
  const findings = await analyze('const account=await getUser();await guard(account);', parameterGuard)
  assert.equal(findings.length, 1)
  assert.equal(findings[0]!.confidence, 'likely')
})

for (const safe of [false, true]) {
  test(`parameter requirements propagate through a helper (verified argument: ${safe})`, async () => {
    const helper = 'async function inner(subject){if(!subject)throw new Error("denied");}export async function guard(value){await inner(value);}'
    const findings = await analyze(`const account=${safe ? 'await getUser()' : 'req.body.user'};await guard(account);`, helper)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, safe ? 'likely' : 'certain')
  })
}

test('a raw token compared with a server secret still supplies a direct guard', async () => {
  assert.deepEqual(await analyze('const token=req.headers.get("authorization");if(token!==process.env.CRON_SECRET)return new Response(null,{status:401});'), [])
})

test('request headers can be inputs to a recognized identity verifier', async () => {
  assert.deepEqual(await analyze('const user=await getUser(req.headers);if(!user)throw new Error("denied");'), [])
})

test('a nested identity call does not validate an unrelated outer return value', async () => {
  assert.equal((await analyze('const user=await makePayload(getUser());if(!user)return new Response(null,{status:401});')).length, 1)
})

test('awaited identity expressions can be passed directly to helpers', async () => {
  assert.equal((await analyze('await guard(await getUser());', parameterGuard))[0]!.confidence, 'likely')
})

for (const count of [511, 512]) {
  test(`identity assignment budget has an exact boundary: ${count + 1}`, async () => {
    const content = `export async function DELETE(){${Array.from({ length: count }, (_, i) => `const value${i}=0;`).join('')}const user=await getUser();if(!user)throw new Error("denied");${write}}`
    const errors: string[] = []
    const findings = await apiAuthRule.check({ root: '.', git: 'not-a-repo', gitExecutable: null,
      files: [{ path: 'app/api/items/route.ts', content, lines: [content], isExampleContext: false }],
      reportIncomplete: (_id, message) => { errors.push(message) } })
    assert.equal(errors.length, count === 511 ? 0 : 1)
    assert.equal(findings.length, count === 511 ? 0 : 1)
    if (errors.length) assert.match(errors[0]!, /512 assignments/)
  })
}

test('long multiline identity expressions stop at the disclosed limit', async () => {
  const content = `export async function DELETE(req){const user=await getUser()\n${'\n'.repeat(100_000)}||req.body.user;if(!user)throw new Error("denied");${write}}`
  const errors: string[] = []
  const start = performance.now()
  const findings = await apiAuthRule.check({ root: '.', git: 'not-a-repo', gitExecutable: null,
    files: [{ path: 'app/api/items/route.ts', content, lines: content.split('\n'), isExampleContext: false }],
    reportIncomplete: (_id, message) => { errors.push(message) } })
  assert.equal(findings.length, 1)
  assert.equal(errors.length, 1)
  assert.match(errors[0]!, /4000 expression characters/)
  assert.ok(performance.now() - start < 5000)
})
