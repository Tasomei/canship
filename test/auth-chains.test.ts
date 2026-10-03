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

// 解析上限只影响置信度，不会隐藏结果，因此在结果上附注，而不把整次扫描标为不完整。
const LIMIT_NOTE = /stopped following local helpers in this file at its limit/

test('overlong delegation is noted on the finding and remains blocking', async () => {
  const modules: Record<string, string> = { 'lib/entry.ts': "export {step as guard} from './step0';" }
  for (let i = 0; i < 10; i++) modules[`lib/step${i}.ts`] = i === 9
    ? base.replace('checkSession', 'step')
    : `import {step as next} from './step${i + 1}';export async function step(){await next();}`
  const { finding, errors } = await analyze(modules)
  assert.equal(finding.confidence, 'certain')
  assert.ok(finding.why.some(paragraph => LIMIT_NOTE.test(paragraph)))
  assert.deepEqual(errors, [])
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

test('wide re-export graphs stop at the per-helper symbol budget', async () => {
  const modules: Record<string, string> = { 'lib/entry.ts': '' }
  for (let i = 0; i < 140; i++) {
    modules['lib/entry.ts'] += `export * from './stub${i}';\n`
    modules[`lib/stub${i}.ts`] = 'export const value=1;'
  }
  const { finding, errors } = await analyze(modules)
  assert.equal(finding.confidence, 'certain')
  assert.ok(finding.why.some(paragraph => LIMIT_NOTE.test(paragraph) && /64 symbols per helper/.test(paragraph)))
  assert.deepEqual(errors, [])
})

/** 一个只做业务的辅助函数，经宽重导出图解析，会耗尽一个辅助函数的预算。 */
function heavyHelpers(count: number): Record<string, string> {
  const modules: Record<string, string> = { 'lib/heavy.ts': '' }
  for (let h = 0; h < count; h++) modules['lib/heavy.ts'] += `export * from './wide${h}';\n`
  for (let h = 0; h < count; h++) {
    modules[`lib/wide${h}.ts`] = Array.from({ length: 80 }, (_, i) => `export * from './leaf${h}_${i}';`).join('\n')
    for (let i = 0; i < 80; i++) modules[`lib/leaf${h}_${i}.ts`] = 'export const value=1;'
  }
  return modules
}

test('business helpers resolved first do not use up the budget of the real guard', async () => {
  const names = Array.from({ length: 20 }, (_, i) => `trackSale${i}`)
  const { finding, errors } = await analyze({
    ...heavyHelpers(20),
    'lib/entry.ts': "import {checkSession} from './base';export async function checkAccess(){await checkSession();}",
    'app/api/items/route.ts': `import {db} from '../../../lib/db';import {${names.join(',')}} from '../../../lib/heavy';` +
      "import {checkAccess} from '../../../lib/entry';" +
      `export async function DELETE(){${names.map(name => `await ${name}();`).join('')}await checkAccess();await db.from('items').delete();}`,
  })
  assert.equal(finding.confidence, 'likely')
  assert.ok(finding.evidence?.some(step => step.kind === 'auth-helper' && step.file === 'lib/entry.ts'))
  assert.deepEqual(errors, [])
})

test('a wrapper around the exported handler is resolved before other calls', async () => {
  const names = Array.from({ length: 20 }, (_, i) => `syncData${i}`)
  const { finding, errors } = await analyze({
    ...heavyHelpers(20),
    'lib/entry.ts': "import {checkSession} from './base';" +
      'export function withTeam(handler){return async (...args)=>{await checkSession();return handler(...args);};}',
    'app/api/items/route.ts': `import {db} from '../../../lib/db';import {${names.join(',')}} from '../../../lib/heavy';` +
      "import {withTeam} from '../../../lib/entry';" +
      `export const DELETE = withTeam(async () => {${names.map(name => `await ${name}();`).join('')}await db.from('items').delete();});`,
  })
  assert.equal(finding.confidence, 'likely')
  assert.deepEqual(errors, [])
})

for (const declaration of ['const', 'let']) {
  for (const local of [false, true]) {
    test(`an unmodified ${declaration} arrow guard provides evidence (local: ${local})`, async () => {
      const guard = `${declaration} guard=async()=>{const user=await getUser();if(!user)throw new Error("denied");};`
      const modules = local ? {
        'app/api/items/route.ts': "import {db} from '../../../lib/db';" + guard +
          "export async function DELETE(){await guard();await db.from('items').delete();}",
      } : { 'lib/entry.ts': 'export ' + guard }
      const { finding, errors } = await analyze(modules)
      assert.equal(finding.confidence, 'likely')
      assert.deepEqual(errors, [])
    })
  }
}

for (const source of [
  base.replace('checkSession', 'guard') + ';guard=async()=>true;',
  'export let guard=async()=>{const user=await getUser();if(!user)throw new Error("denied");};guard=async()=>true;',
  base.replace('export async function checkSession', 'async function inner') + ';inner=async()=>true;export {inner as guard};',
]) {
  test(`a modified exported binding loses its earlier guard evidence: ${source.slice(0, 40)}`, async () => {
    const { finding } = await analyze({ 'lib/entry.ts': source })
    assert.equal(finding.confidence, 'certain')
    assert.ok(!finding.evidence?.some(step => step.kind === 'auth-helper'))
  })
}

test('a nested same-named declaration cannot use the outer arrow guard', async () => {
  const { finding } = await analyze({
    'app/api/items/route.ts': "import {db} from '../../../lib/db';" +
      'const guard=async()=>{const user=await getUser();if(!user)throw new Error("denied");};' +
      "export async function DELETE(){const guard=async()=>true;await guard();await db.from('items').delete();}",
  })
  assert.equal(finding.confidence, 'certain')
})

// 柯里化包装器：外层箭头函数直接返回处理请求的内层函数，如 withAdmin = (handler) => async (req) => {…}。
const curriedRoute = "import {db} from '../../../lib/db';import {withTeam} from '../../../lib/entry';" +
  "export const DELETE = withTeam(async () => {await db.from('items').delete();});"
for (const [label, wrapper, expected] of [
  ['delegated guard', "import {checkSession} from './base';export const withTeam = (handler) => async (...args) => {await checkSession();return handler(...args);};", 'likely'],
  ['inline session check', "export const withTeam = (handler, { roles = [] } = {}) =>\n  async (req, ctx) => {\n    const session = await getServerSession();\n    if (!session?.user) {\n      return new Response('Unauthorized', { status: 401 });\n    }\n    return handler({ req, session });\n  };", 'likely'],
  ['two-level currying', "import {checkSession} from './base';export const withTeam = (options) => (handler) => async (req) => {await checkSession();return handler(req);};", 'likely'],
  ['no check', "export const withTeam = (handler) => async (...args) => {log('request');return handler(...args);};", 'certain'],
] as const) {
  test(`a curried wrapper around the exported handler is recognised: ${label}`, async () => {
    const { finding, errors } = await analyze({ 'lib/entry.ts': wrapper, 'app/api/items/route.ts': curriedRoute })
    assert.equal(finding.confidence, expected)
    assert.equal(finding.evidence?.some(step => step.kind === 'auth-helper' && step.file === 'lib/entry.ts') ?? false, expected === 'likely')
    assert.deepEqual(errors, [])
  })
}