/** 隔离临时项目并逐项比较结果；不执行样本代码，不访问网络。 */
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../../src/engine.js'
import type { EvaluationCase, ExpectedFinding } from './cases.js'

/** 按规则、路径、严重度和置信度匹配，保留重复结果数量。 */
const keyOf = (f: ExpectedFinding) => [f.ruleId, f.file, f.severity, f.confidence].join('|')
function subtract(left: string[], right: string[]): string[] {
  const remaining = [...right]
  return left.filter(item => {
    const at = remaining.indexOf(item)
    if (at < 0) return true
    remaining.splice(at, 1)
    return false
  })
}

export async function evaluateCase(sample: EvaluationCase) {
  const root = mkdtempSync(join(tmpdir(), 'canship-evaluation-'))
  try {
    for (const [path, content] of Object.entries(sample.files)) {
      const target = join(root, path)
      mkdirSync(dirname(target), { recursive: true })
      writeFileSync(target, content)
    }
    const result = await scan(root)
    const expected = sample.expected.map(keyOf)
    const actual = result.findings.map(f => keyOf({ ...f, file: f.file ?? '' }))
    const missing = subtract(expected, actual)
    const unexpected = subtract(actual, expected)
    const coverageMatches = result.partial === (sample.partial ?? false) &&
      result.skipped.length === (sample.skipped ?? 0) && result.errors.length === 0 && result.filesScanned > 0
    return {
      id: sample.id, origin: sample.origin,
      passed: missing.length === 0 && unexpected.length === 0 && coverageMatches,
      expected: expected.length, detected: actual.length, missing, unexpected, coverageMatches,
      durationMs: result.durationMs,
    }
  } finally {
    // 仅移除本次创建的临时样本目录。
    rmSync(root, { recursive: true, force: true })
  }
}
