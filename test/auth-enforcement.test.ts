/** 本地鉴权依据实现及调用方式判断，不仅依赖函数名。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { apiAuthRule } from '../src/rules/apiauth.js'
import type { ScanFile } from '../src/types.js'

const operation = "await db.from('records').delete();"
const admin = "import {createClient} from '@supabase/supabase-js'; export const db=createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);"
const throwing = 'const user=await getUser(); if(!user) throw new Error("denied"); return user;'

async function check(helper: string, call: string, options: { name?: string; local?: boolean; wrapper?: boolean; barrel?: boolean; parameters?: string } = {}) {
  const name = options.name ?? 'requireUser'
  const definition = options.wrapper ? helper : `async function ${name}() { ${helper} }`
  const route = "import {db} from '../../../lib/db';\n" +
    (options.local ? definition : `import {${name}} from '../../../lib/auth';`) + '\n' +
    (options.wrapper ? `export const DELETE=${name}(async()=>{${operation}});` : `export async function DELETE(${options.parameters ?? ''}){${call} ${operation}}`)
  const content: Record<string, string> = { 'app/api/records/route.ts': route, 'lib/db.ts': admin }
  if (!options.local) content['lib/auth.ts'] = options.barrel ? `export {${name}} from './impl';` : 'export ' + definition
  if (options.barrel) content['lib/impl.ts'] = 'export ' + definition
  const files: ScanFile[] = Object.entries(content).map(([path, content]) => ({ path, content, lines: content.split('\n'), isExampleContext: false }))
  const findings = await apiAuthRule.check({ root: '.', files, git: 'not-a-repo', gitExecutable: null,
    reportIncomplete() { assert.fail('unexpected incomplete scan') } })
  assert.equal(findings.length, 1)
  assert.equal(findings[0]!.ruleId, 'api/admin-db-access-without-auth')
  return findings[0]!
}

for (const local of [false, true]) {
  for (const helper of [
    'return true;',
    'return getUser();',
    'const user=await getUser(); if(!user) return null; return user;',
    'const user=await getUser(); if(!user) return new Response(null,{status:401}); return user;',
    'const user=await getUser(); if(!user){return null; throw new Error("unreachable");} return user;',
  ]) {
    test(`non-enforcing requireUser remains blocking (local: ${local}): ${helper}`, async () => {
      const finding = await check(helper, 'await requireUser();', { local })
      assert.equal(finding.confidence, 'certain')
      assert.ok(!finding.evidence?.some(step => step.kind === 'auth-helper'))
    })
  }
  test(`a throwing local helper supplies evidence without hiding findings (local: ${local})`, async () => {
    const finding = await check(throwing, 'await requireUser();', { local })
    assert.equal(finding.confidence, 'likely')
    assert.ok(finding.evidence?.some(step => step.kind === 'auth-helper'))
  })
}

test('returning a denial response is not enforcement through an aliased helper', async () => {
  const finding = await check('const user=await getUser(); if(!user) return new Response(null,{status:401});', 'await validate();', { name: 'validate' })
  assert.equal(finding.confidence, 'certain')
})

for (const call of ['requireUser();', 'await requireUser().catch(()=>null);', 'try { await requireUser(); } catch {}', 'if(optional) { await requireUser(); }']) {
  test(`an unawaited, recovered or conditional guard is not sufficient: ${call}`, async () => {
    assert.equal((await check(throwing, call)).confidence, 'certain')
  })
}

test('re-exported throwing guards retain their definition as evidence', async () => {
  const finding = await check(throwing, 'await requireUser();', { barrel: true })
  assert.equal(finding.confidence, 'likely')
  assert.equal(finding.evidence?.at(-1)?.file, 'lib/impl.ts')
})

for (const guarded of [false, true]) {
  test(`withAuth uses its local implementation (guarded: ${guarded})`, async () => {
    const helper = `function withAuth(handler) { return async (request)=>{ ${guarded ? 'const user=await getUser(); if(!user) return new Response(null,{status:401});' : ''} return handler(request); } }`
    const finding = await check(helper, '', { name: 'withAuth', wrapper: true })
    assert.equal(finding.confidence, guarded ? 'likely' : 'certain')
  })
}

for (const local of [false, true]) {
  test(`a handler parameter cannot borrow a same-named guard (local: ${local})`, async () => {
    assert.equal((await check(throwing, 'await requireUser();', { local, parameters: 'requireUser' })).confidence, 'certain')
  })
}

test('a reassigned local guard does not retain its original enforcement evidence', async () => {
  assert.equal((await check(throwing, 'requireUser=async()=>true; await requireUser();', { local: true })).confidence, 'certain')
})
