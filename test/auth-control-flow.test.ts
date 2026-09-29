/** 所有可继续执行的分支都须鉴权；异常恢复与 finally 不能借用其他路径的证据。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { apiAuthRule } from '../src/rules/apiauth.js'

const write = "await db.from('items').delete();"
async function analyze(prefix: string, helper?: string) {
  const content = "import {createClient} from '@supabase/supabase-js';const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);" +
    (helper ? "import {guard} from '../../../lib/auth';" : '') + `export async function DELETE(req){${prefix}${write}}`
  const files = [{ path: 'app/api/items/route.ts', content }, ...(helper ? [{ path: 'lib/auth.ts', content: helper }] : [])]
    .map(file => ({ ...file, lines: file.content.split('\n'), isExampleContext: false }))
  const errors: string[] = []
  const findings = await apiAuthRule.check({ root: '.', files, git: 'not-a-repo', gitExecutable: null,
    reportIncomplete: (_id, message) => { errors.push(message) } })
  return { findings, errors }
}

for (const prefix of [
  'if(req.admin){await requireAuth();}else{await requireAuth();}',
  'if(req.admin){const user=await getUser();if(!user)throw new Error("denied");}else{await requireAuth();}',
  'if(req.admin){return new Response(null,{status:401});}else{await requireAuth();}',
  'try{await requireAuth();}catch{throw new Error("denied");}',
  'try{await requireAuth();}catch{return new Response(null,{status:401});}',
  'try{await requireAuth();}finally{cleanup();}',
]) {
  test(`all continuation paths are protected: ${prefix}`, async () => {
    const { findings, errors } = await analyze(prefix)
    assert.deepEqual(findings, [])
    assert.deepEqual(errors, [])
  })
}

for (const prefix of [
  'if(req.admin){await requireAuth();}else{log();}',
  'try{await requireAuth();}catch{log();}',
  'try{await requireAuth();}catch{if(req.strict)throw new Error("denied");}',
  `try{await requireAuth();}finally{${write}}`,
]) {
  test(`a reachable unprotected path stays blocking: ${prefix}`, async () => {
    const { findings } = await analyze(prefix)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, 'certain')
  })
}

for (const [ending, expected] of [
  ['catch{throw new Error("denied");}', 'likely'],
  ['catch{return new Response(null,{status:401});}', 'certain'],
  ['finally{return true;}', 'certain'],
] as const) {
  test(`helper exception handling preserves caller semantics: ${ending}`, async () => {
    const { findings } = await analyze('await guard();', `export async function guard(){try{await requireAuth();}${ending}}`)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, expected)
  })
}

for (const verified of [false, true]) {
  test(`branch summaries preserve parameter requirements (verified: ${verified})`, async () => {
    const helper = 'async function verify(user){if(!user)throw new Error("denied");}export async function guard(user){if(flag){await verify(user);}else{await verify(user);}}'
    const { findings } = await analyze(`const user=${verified ? 'await getUser()' : 'req.body.user'};await guard(user);`, helper)
    assert.equal(findings.length, 1)
    assert.equal(findings[0]!.confidence, verified ? 'likely' : 'certain')
  })
}

test('deep control-flow proofs stop with an explicit coverage gap', async () => {
  let prefix = 'await requireAuth();'
  for (let i = 0; i < 10; i++) prefix = `if(flag${i}){${prefix}}else{await requireAuth();}`
  const { findings, errors } = await analyze(prefix)
  assert.equal(findings.length, 1)
  assert.ok(errors.some(message => message.includes('control-flow proof limit')))
})
