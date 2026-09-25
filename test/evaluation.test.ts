/** 评估样本同时纳入常规回归测试。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evaluationCases } from './evaluation/cases.js'
import { evaluateCase } from './evaluation/run.js'

for (const sample of evaluationCases) {
  test(`evaluation: ${sample.id}`, async () => {
    const result = await evaluateCase(sample)
    assert.deepEqual(result.missing, [], 'missed findings or changed finding attributes')
    assert.deepEqual(result.unexpected, [], 'extra findings or false positives')
    assert.equal(result.coverageMatches, true, 'scan completeness differs from the expectation')
  })
}
