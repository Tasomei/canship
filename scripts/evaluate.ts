/** 输出固定样本的匹配结果，不推算真实项目检出率。 */
import { evaluationCases } from '../test/evaluation/cases.js'
import { evaluateCase } from '../test/evaluation/run.js'

const results = []
for (const sample of evaluationCases) results.push(await evaluateCase(sample))
const summary = {
  schemaVersion: 1,
  corpus: 'canship-starter-v3',
  cases: results.length,
  passed: results.filter(result => result.passed).length,
  missing: results.reduce((sum, result) => sum + result.missing.length, 0),
  unexpected: results.reduce((sum, result) => sum + result.unexpected.length, 0),
  scope: 'Fixed synthetic cases and subsets from Supabase, Firebase, Next.js, and cors; not a population accuracy estimate.',
  results,
}
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`)
if (summary.passed !== summary.cases) process.exitCode = 1
