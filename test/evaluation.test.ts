/** 评估样本同时纳入常规回归测试。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluationCases } from './evaluation/cases.js'
import { evaluateCase } from './evaluation/run.js'

for (const sample of evaluationCases) {
  test(`评估：${sample.id}`, async () => {
    const result = await evaluateCase(sample)
    assert.deepEqual(result.missing, [], '漏报或结果属性变化')
    assert.deepEqual(result.unexpected, [], '额外结果或误报')
    assert.equal(result.coverageMatches, true, '扫描完整性不符合预期')
  })
}
