/** 请求来源、重新赋值、作用域及分析上限的回归用例。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluateCase } from './evaluation/run.js'
import { injectionRule } from '../src/rules/injection.js'
import { ssrfRule } from '../src/rules/outbound.js'
import type { ProjectRule } from '../src/types.js'

const path = 'app/api/items/route.ts'
const sql = (prefix: string, value = 'id') => `export async function POST(req) { ${prefix}; return prisma.$queryRawUnsafe('SELECT * FROM items WHERE id = ' + ${value}); }`

for (const [setup, confidence] of [
  ['function unused() { id = req.body.id; }', null],
  ['const unused = () => { id = req.body.id; };', null],
  ['const unused = () => id = req.body.id;', null],
  ['function unused() { id = req.body.id; unused(); }', null],
  ['function update() { id = req.body.id; } update();', 'likely'],
  ['const update = () => { id = req.body.id; }; update();', 'likely'],
  ['const update = () => id = req.body.id; update();', 'likely'],
  ['function update() { id = req.body.id; } run(update);', 'likely'],
  ['await run(() => { id = req.body.id; });', 'likely'],
  ['const result = run(() => { id = req.body.id; });', 'likely'],
  ['const result = run(function update() { id = req.body.id; });', 'likely'],
  ['(function update() { id = req.body.id; })();', 'likely'],
] as const) {
  test(`nested writes need a use outside their declaration: ${setup}`, async () => {
    const result = await evaluateCase({ id: 'nested-write', origin: 'synthetic', files: { [path]: sql(`let id = 1; ${setup}`) },
      expected: confidence ? [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence }] : [] })
    assert.equal(result.passed, true, JSON.stringify(result))
  })
}

for (const value of ["body['id']", 'body.ids[0]', "req['body']['id']"]) {
  test(`bracket access retains request input: ${value}`, async () => {
    const result = await evaluateCase({ id: 'bracket', origin: 'synthetic', files: { [path]: sql(`const body = await req.json(); const id = ${value}`) },
      expected: [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence: 'certain' }] })
    assert.equal(result.passed, true, JSON.stringify(result))
  })
}

for (const call of ['safeIdentity', 'escapeHtml', 'sanitizeInput', 'quoteValue']) {
  test(`a helper name is not sanitization evidence: ${call}`, async () => {
    const content = `function ${call}(value) { return value; }\n` + sql(`const body = await req.json(); const id = ${call}(body.id)`)
    const result = await evaluateCase({ id: 'helper', origin: 'synthetic', files: { [path]: content },
      expected: [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence: 'likely' }] })
    assert.equal(result.passed, true, JSON.stringify(result))
  })
}

for (const [prefix, unsafe] of [
  ['let id = req.body.id; id = 1', false],
  ['let id = req.body.id; if (req.body.safe) id = 1', true],
  ['let id = req.body.id; if (req.body.safe) { id = 1; }', true],
  ['const id = req.body.id; { const id = 1; }', true],
  ['let id = req.body.id; function unused() { id = 1; }', true],
  ['let id = 1; if (req.body.override) { id = req.body.id; }', true],
] as const) {
  test(`assignment order and scope: ${prefix}`, async () => {
    const result = await evaluateCase({ id: 'assignment', origin: 'synthetic', files: { [path]: sql(prefix) },
      expected: unsafe ? [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence: 'certain' }] : [] })
    assert.equal(result.passed, true, JSON.stringify(result))
  })
}

test('a later assignment cannot taint an earlier query', async () => {
  const content = `export async function POST(req) { let id = 1; await prisma.$queryRawUnsafe('SELECT * FROM items WHERE id = ' + id); id = req.body.id; }`
  const result = await evaluateCase({ id: 'later', origin: 'synthetic', files: { [path]: content }, expected: [] })
  assert.equal(result.passed, true, JSON.stringify(result))
})

test('assignments inside callbacks are followed to sinks in the same callback', async () => {
  const content = `export async function POST(req) {
  const body = await req.json()
  await prisma.$transaction(async (tx) => {
    const q = \`DELETE FROM items WHERE id = '\${body.id}'\`
    await tx.$executeRawUnsafe(q)
  })
}`
  const result = await evaluateCase({ id: 'callback', origin: 'synthetic', files: { [path]: content },
    expected: [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence: 'certain' }] })
  assert.equal(result.passed, true, JSON.stringify(result))
})

for (const mutation of ['COLUMNS.push(req.body.column)', 'Object.assign(COLUMNS, req.body)']) {
  test(`a mutated lookup table is not a fixed choice: ${mutation}`, async () => {
    const table = mutation.startsWith('COLUMNS') ? "const COLUMNS = ['name', 'created_at'];" : "const COLUMNS = { name: 'name' };"
    const content = `${table}\n` + sql(`${mutation}; const id = COLUMNS[req.body.key]`)
    const result = await evaluateCase({ id: 'mutated-table', origin: 'synthetic', files: { [path]: content },
      expected: [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence: 'certain' }] })
    assert.equal(result.passed, true, JSON.stringify(result))
  })
}

test('a fixed lookup cannot sanitize a request-controlled fallback', async () => {
  const content = "const IDS = {one: 1};\n" + sql('const id = IDS[req.body.key] ?? req.body.fallback')
  const result = await evaluateCase({ id: 'lookup-fallback', origin: 'synthetic', files: { [path]: content },
    expected: [{ ruleId: 'injection/sql', file: path, severity: 'P1', confidence: 'certain' }] })
  assert.equal(result.passed, true, JSON.stringify(result))
})

// 通过规则回调核对扫描缺口，不能把达到预算的空结果当成完整扫描。
function analyse(content: string, rule: ProjectRule) {
  const file = { path, content, lines: content.split('\n'), isExampleContext: false }
  const incomplete: string[] = []
  const findings = rule.check({ root: '.', files: [file], git: 'not-a-repo', gitExecutable: null,
    reportIncomplete(id) { incomplete.push(id) } })
  return { findings, incomplete }
}

for (const called of [false, true]) {
  test(`outbound flow applies the same closure boundary: called=${called}`, async () => {
    const { findings } = analyse(`export async function GET(req) {
      let url = 'https://example.com'; function update(){ url=req.body.url; }
      ${called ? 'update();' : ''} return fetch(url);
    }`, ssrfRule)
    assert.deepEqual((await findings).map(f => f.confidence), called ? ['likely'] : [])
  })
}

test('an uncalled expression closure cannot sanitize the outer value', async () => {
  const { findings } = analyse(sql('let id=req.body.id; const unused=()=>id=1;'), injectionRule)
  assert.deepEqual((await findings).map(f => f.confidence), ['certain'])
})

test('a reference after the query does not make an earlier closure assignment visible', async () => {
  const { findings } = analyse(`export async function POST(req) {
    let id=1; function update(){id=req.body.id;}
    await prisma.$queryRawUnsafe('SELECT * FROM items WHERE id='+id); update();
  }`, injectionRule)
  assert.deepEqual(await findings, [])
})

for (const [command, options, expected] of [
  ["'echo ' + body.message", '', 0],
  ["`echo ${body.message}`", '', 0],
  ["'echo ' + body.message", ', {shell:false}', 0],
  ["'echo ' + body.message", ', {shell:true}', 1],
  ['body.command', '', 1],
] as const) {
  test(`Execa distinguishes arguments from a chosen executable or shell: ${command}${options}`, async () => {
    const content = `import {execaCommand} from 'execa'; export async function POST(req){ const body=await req.json(); return execaCommand(${command}${options}); }`
    const hits = await analyse(content, injectionRule).findings
    assert.equal(hits.length, expected)
    if (expected && options === '') {
      assert.match(hits[0]!.title, /executable selected/)
      assert.doesNotMatch(hits[0]!.why.join(' '), /is run through a shell/)
    }
  })
}

// 上限为 64 KiB：超过后才报告扫描不完整，普通的长回调不触发。
test('long expressions disclose truncation', async () => {
  const content = 'export async function POST(req) { const id = req.body.id; const query = `SELECT * FROM items WHERE note = "' +
    'x'.repeat(66000) + '" AND id = ${id}`; return prisma.$queryRawUnsafe(query); }'
  const { incomplete } = analyse(content, injectionRule)
  assert.deepEqual(incomplete, ['request-input/tracking'])
})

test('shared alias branches stay bounded instead of expanding exponentially', async () => {
  let code = 'let v0 = req.body.id;'
  for (let depth = 1; depth <= 8; depth++) {
    code += `let v${depth}=v${depth - 1};`
    for (let branch = 0; branch < 20; branch++) code += `if(req.body.flag){v${depth}=v${depth - 1};}`
  }
  const started = performance.now()
  const { findings, incomplete } = analyse(sql(code, 'v8'), injectionRule)
  await findings
  assert.ok(performance.now() - started < 5000)
  assert.ok(incomplete.includes('request-input/tracking'))
})

for (const aliases of [5, 12]) {
  test(`URL aliases detect or disclose the limit: ${aliases}`, async () => {
    const code = "const v0 = req.nextUrl.searchParams.get('url');" +
      Array.from({ length: aliases }, (_, i) => `const v${i + 1} = v${i};`).join('')
    const { findings, incomplete } = analyse(`export async function GET(req) { ${code} return fetch(v${aliases}); }`, ssrfRule)
    if (aliases === 5) { assert.equal((await findings).length, 1); assert.deepEqual(incomplete, []) }
    else assert.deepEqual(incomplete, ['request-input/tracking'])
  })
}
