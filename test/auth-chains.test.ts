/** 鉴权委托须传播拒绝结果，解析深度与符号数均有界。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { apiAuthRule } from '../src/rules/apiauth.js'

const base = 'export async function checkSession(){const user=await getUser();if(!user)throw new Error("denied");return user;}'
async function analyze(modules: Record<string, string>) {
  const files = Object.entries({
    'lib/db.ts': "import {createClient} from '@supabase/supabase-js';export const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);",
    'app/api/items/route.ts': "import {db} from '../../../lib/db';import {guard} from '../../../lib/entry';export async function DELETE(){await guard();await db.from('items').delete();}",
    'lib/base.ts': base, ...modules,
  }).map(([path, content]) => ({ path, content, lines: content.split('\n'), isExampleContext: false }))
  const errors: string[] = []
  const findings = await apiAuthRule.check({ root: '.', files, git: 'not-a-repo', gitExecutable: null,
    reportIncomplete: (_rule, message) => { errors.push(message) } })
  assert.equal(findings.length, 1)
  return { finding: findings[0]!, errors }
}

for (const call of ['await checkSession();', 'return await checkSession();', 'return checkSession();']) {
  test(`cross-file delegation preserves refusal: ${call}`, async () => {
    const { finding, errors } = await analyze({
      'lib/entry.ts': `import {checkSession} from './base';export async function guard(){${call}}`,
    })
    assert.equal(finding.confidence, 'likely')
    assert.deepEqual(finding.evidence?.filter(step => step.kind === 'auth-helper').map(step => step.file), ['lib/entry.ts', 'lib/base.ts'])
    assert.deepEqual(errors, [])
  })
}

for (const call of ['checkSession();', 'await checkSession().catch(()=>null);', 'try{await checkSession();}catch{}',
  'if(optional) await checkSession();', 'return true; await checkSession();']) {
  test(`non-enforcing delegation stays blocking: ${call}`, async () => {
    const { finding } = await analyze({ 'lib/entry.ts': `import {checkSession} from './base';export async function guard(){${call}}` })
    assert.equal(finding.confidence, 'certain')
    assert.ok(!finding.evidence?.some(step => step.kind === 'auth-helper'))
  })
}

test('same-file delegates and a re-export resolve to the terminal guard', async () => {
  const { finding, errors } = await analyze({
    'lib/entry.ts': "export { outer as guard } from './impl';",
    'lib/impl.ts': 'async function inner(){const user=await getUser();if(!user)throw new Error("denied");} export async function outer(){await inner();}',
  })
  assert.equal(finding.confidence, 'likely')
  assert.equal(finding.evidence?.filter(step => step.kind === 'auth-helper').length, 2)
  assert.deepEqual(errors, [])
})

test('mutual recursion without a guard terminates without inventing evidence', async () => {
  const { finding, errors } = await analyze({
    'lib/entry.ts': "import {other} from './other';export async function guard(){await other();}",
    'lib/other.ts': "import {guard} from './entry';export async function other(){await guard();}",
  })
  assert.equal(finding.confidence, 'certain')
  assert.deepEqual(errors, [])
})

test('a shadowed delegate does not borrow the imported guard', async () => {
  const { finding } = await analyze({
    'lib/entry.ts': "import {checkSession} from './base';export async function guard(checkSession){await checkSession();}",
  })
  assert.equal(finding.confidence, 'certain')
})

test('overlong delegation is disclosed and remains blocking', async () => {
  const modules: Record<string, string> = { 'lib/entry.ts': "export {step as guard} from './step0';" }
  for (let i = 0; i < 10; i++) modules[`lib/step${i}.ts`] = i === 9
    ? base.replace('checkSession', 'step')
    : `import {step as next} from './step${i + 1}';export async function step(){await next();}`
  const { finding, errors } = await analyze(modules)
  assert.equal(finding.confidence, 'certain')
  assert.ok(errors.some(message => message.includes('authentication resolution limit')))
})

test('an eight-function delegation chain is accepted at the depth boundary', async () => {
  const modules: Record<string, string> = {}
  for (let i = 0; i < 8; i++) {
    const path = i === 0 ? 'lib/entry.ts' : `lib/step${i}.ts`
    const name = i === 0 ? 'guard' : 'step'
    modules[path] = i === 7 ? base.replace('checkSession', name)
      : `import {step as next} from './step${i + 1}';export async function ${name}(){await next();}`
  }
  const { finding, errors } = await analyze(modules)
  assert.equal(finding.confidence, 'likely')
  assert.equal(finding.evidence?.filter(step => step.kind === 'auth-helper').length, 8)
  assert.deepEqual(errors, [])
})

test('wide re-export graphs stop at the symbol budget', async () => {
  const modules: Record<string, string> = { 'lib/entry.ts': '' }
  for (let i = 0; i < 140; i++) {
    modules['lib/entry.ts'] += `export * from './stub${i}';\n`
    modules[`lib/stub${i}.ts`] = 'export const value=1;'
  }
  const { finding, errors } = await analyze(modules)
  assert.equal(finding.confidence, 'certain')
  assert.equal(errors.length, 1)
  assert.match(errors[0]!, /128 symbols/)
})
