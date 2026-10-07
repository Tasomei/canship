/** 只读词法上下文的反例与资源边界，不求值条件或调用项目函数。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { maskJsNoise } from '../src/mask.js'
import { delimiterPairs, functionBodies } from '../src/rules/apiauth.js'
import { registrationContext } from '../src/rules/registration-context.js'
import { nodeRoutesFor, reportOpenapiBatchCoverage } from '../src/rules/routers.js'
import type { ScanContext, ScanFile } from '../src/types.js'

function context(source: string) {
  const code = maskJsNoise(source), pairs = delimiterPairs(code)
  return registrationContext(code, pairs, functionBodies(code, pairs))
}
const guarded = (source: string) => context(source).covers(source.indexOf('guard()'), source.indexOf('operation()'))

test('literal branches and unbraced or nested alternatives have separate reachability', () => {
  for (const [source, active] of [
    ['if(false) operation();', false], ['if(!false) operation();', true],
    ['if(true) {} else operation();', false], ['if(false) {} else operation();', true],
    ['if(false) if(enabled) operation(); else other();', false],
    ["if(false) 'synthetic'; operation();", true],
  ] as const) assert.equal(context(source).reachable(source.indexOf('operation()')), active, source)
  assert.equal(guarded('if(enabled) guard(); operation();'), false)
  assert.equal(guarded('if(enabled){guard();operation()}'), true)
  assert.equal(guarded('if(enabled){guard()}else{operation()}'), false)
})

test('loops, exception branches, methods and independent functions cannot lend evidence outward', () => {
  for (const source of [
    'for(const x of values){guard()} operation()',
    'try{guard()}catch(error){} operation()',
    'try{}catch(error){guard()} operation()',
    'switch(value){case 1:guard();break;case 2:operation()}',
    'class Setup { init(): void {guard()} } operation()',
    'function outer(){guard();function inner(){operation()}}',
  ]) assert.equal(guarded(source), false, source)
  assert.equal(guarded('guard();function registered(){operation()}'), true)
})

test('multiline and mixed short-circuit expressions do not become proof', () => {
  for (const source of ['enabled &&\nguard(); operation()', 'enabled ? guard() : operation()',
    'enabled && guard() || operation()', 'receiver?.(guard()); operation()']) assert.equal(guarded(source), false, source)
  assert.equal(guarded('true && guard(); operation()'), true)
  assert.equal(context('false && operation()').reachable(9), false)
})

test('large context sets and statement prefixes disclose limits without hiding possible routes', () => {
  const source = 'function scope(){}\n'.repeat(513) + 'guard(); operation()'
  const large = context(source)
  assert.equal(large.limited, true)
  assert.equal(large.reachable(source.indexOf('operation()')), true)
  assert.equal(large.covers(source.indexOf('guard()'), source.indexOf('operation()')), false)
  const prefix = 'x'.repeat(4001) + ' && guard(); operation()'
  const long = context(prefix)
  assert.equal(long.covers(prefix.indexOf('guard()'), prefix.indexOf('operation()')), false)
  assert.equal(long.limited, true)
})

test('the project graph cap reports omitted sites instead of exhausting an unbounded graph', () => {
  const content = "import { Hono } from 'hono'; const app = new Hono(); function handler(c){return c.text('ok')} app.get('/status',handler);"
  const files: ScanFile[] = Array.from({ length: 4097 }, (_, i) => ({ path: `src/part-${i}.ts`, content,
    lines: [content], isExampleContext: false }))
  assert.equal(nodeRoutesFor(files[0]!, files).length, 1)
  assert.equal(nodeRoutesFor(files[4096]!, files).length, 0)
  const errors: string[] = []
  reportOpenapiBatchCoverage({ files, reportIncomplete: (rule: string) => { errors.push(rule) } } as unknown as ScanContext)
  assert.deepEqual(errors, ['engine/route-registration'])
})
