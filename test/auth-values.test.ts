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
  'getUser()', 'supabase.auth.getUser()', 'await supabase.auth.getUser()']) {
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

test('overwriting an identity with request input invalidates the check', async () => {
  assert.equal((await analyze('let user=await getUser();user=req.body.user;if(!user)return new Response(null,{status:401});')).length, 1)
})

test('a request-input alias remains untrusted', async () => {
  assert.equal((await analyze('const payload=await req.json();const user=payload.user;if(!user)return new Response(null,{status:401});')).length, 1)
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
