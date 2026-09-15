/** 验证 SARIF 结构、位置、指纹及扫描状态。
 * canship-ignore-file */

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import type { Finding, ScanResult } from '../src/types.js'
import { renderSarif } from '../src/report/sarif.js'
import { fingerprintOf } from '../src/baseline.js'

function finding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'secrets/hardcoded/openai',
    severity: 'P0',
    confidence: 'certain',
    title: 'OpenAI API key is hardcoded in your source code',
    file: 'lib/db.ts',
    line: 12,
    excerpt: 'const key = "sk-…"',
    why: ['Anyone with this key can spend your credit.'],
    fix: ['Move it to .env'],
    ...over,
  }
}

function result(over: Partial<ScanResult> = {}): ScanResult {
  return {
    findings: [finding()],
    filesScanned: 3,
    durationMs: 1,
    errors: [],
    skipped: [],
    ignored: [],
    ignoredFindings: [],
    ruleSelection: null,
    vendored: 0,
    partial: false,
    ...over,
  }
}

/** 对渲染后的文档进行解析和断言。 */
function sarif(over: Partial<ScanResult> = {}): any {
  return JSON.parse(renderSarif(result(over), { version: '9.9.9' }))
}

describe('the document a code-scanning platform reads', () => {
  test('is SARIF 2.1.0 with one run', () => {
    const log = sarif()
    assert.equal(log.version, '2.1.0')
    assert.match(log.$schema, /sarif-2\.1\.0/)
    assert.equal(log.runs.length, 1)
  })

  test('names the tool and its version', () => {
    const driver = sarif().runs[0].tool.driver
    assert.equal(driver.name, 'canship')
    assert.equal(driver.version, '9.9.9')
    assert.ok(driver.informationUri)
  })

  test('every result names a rule the driver declares', () => {
    // 结果 ID 必须对应工具声明的规则。
    const run = sarif({
      findings: [finding(), finding({ ruleId: 'cors/wildcard-with-credentials', severity: 'P2' })],
    }).runs[0]
    for (const r of run.results) {
      assert.ok(
        run.tool.driver.rules.some((rule: { id: string }) => rule.id === r.ruleId),
        `${r.ruleId} is not declared`,
      )
    }
  })

  test('only rules that fired are declared', () => {
    // 仅声明实际命中的规则。
    assert.equal(sarif().runs[0].tool.driver.rules.length, 1)
  })
})

describe('severity becomes a level', () => {
  test('a certain P0 is an error', () => {
    assert.equal(sarif().runs[0].results[0].level, 'error')
  })

  test('a certain P2 is a warning', () => {
    // 非阻断结果不能映射为错误级别。
    const log = sarif({ findings: [finding({ severity: 'P2' })] })
    assert.equal(log.runs[0].results[0].level, 'warning')
  })

  test('a likely P0 is a warning', () => {
    const log = sarif({ findings: [finding({ confidence: 'likely' })] })
    assert.equal(log.runs[0].results[0].level, 'warning')
  })
})

describe('locations', () => {
  test('a file and line become a physical location', () => {
    const location = sarif().runs[0].results[0].locations[0].physicalLocation
    assert.equal(location.artifactLocation.uri, 'lib/db.ts')
    assert.equal(location.region.startLine, 12)
  })

  test('a finding with no file gets no location rather than a made-up one', () => {
    // 无具体文件时不得生成虚假位置。
    const log = sarif({ findings: [finding({ file: null, line: null })] })
    assert.deepEqual(log.runs[0].results[0].locations, [])
  })

  test('a file with no line gets a location and no region', () => {
    const log = sarif({ findings: [finding({ line: null })] })
    const location = log.runs[0].results[0].locations[0].physicalLocation
    assert.equal(location.artifactLocation.uri, 'lib/db.ts')
    assert.equal(location.region, undefined)
  })
})

describe('fingerprints', () => {
  test('are the baseline fingerprint, not a second identity', () => {
    // SARIF 和基线共用身份算法。
    const f = finding()
    assert.equal(sarif().runs[0].results[0].partialFingerprints.canshipFindingV2, fingerprintOf(f))
  })

  test('do not change when a line moves', () => {
    const moved = sarif({ findings: [finding({ line: 400 })] })
    assert.equal(
      moved.runs[0].results[0].partialFingerprints.canshipFindingV2,
      sarif().runs[0].results[0].partialFingerprints.canshipFindingV2,
    )
  })
})

describe('an incomplete scan is not a successful one', () => {
  test('a complete scan reports success', () => {
    assert.equal(sarif().runs[0].invocations[0].executionSuccessful, true)
  })

  test('a partial scan does not', () => {
    // 不完整扫描不得标记为执行成功。
    assert.equal(sarif({ partial: true }).runs[0].invocations[0].executionSuccessful, false)
  })

  test('errors travel as notifications', () => {
    const log = sarif({
      partial: true,
      errors: [{ ruleId: 'x/y', file: null, message: 'boom', kind: 'crashed' }],
    })
    const notes = log.runs[0].invocations[0].toolExecutionNotifications
    assert.equal(notes.length, 1)
    assert.equal(notes[0].level, 'error')
    assert.match(notes[0].message.text, /boom/)
  })
})

describe('SARIF is not the one silent surface', () => {
  // SARIF 也必须披露各种结果抑制。
  const notes = (log: any): string[] =>
    (log.runs[0].invocations[0].toolExecutionNotifications ?? []).map(
      (n: { message: { text: string } }) => n.message.text,
    )

  test('a baseline that emptied the log is named in it', () => {
    const log = JSON.parse(
      renderSarif(result({ findings: [] }), { version: '1', baselineSuppressed: 19 }),
    )
    assert.equal(log.runs[0].results.length, 0)
    assert.match(notes(log).join('\n'), /19 findings hidden by a baseline/)
  })

  test('a line marker that silenced a finding is named', () => {
    const log = JSON.parse(
      renderSarif(
        result({
          findings: [],
          ignoredFindings: [{ file: 'lib/db.ts', line: 4, ruleId: 'secrets/hardcoded/openai' }],
        }),
        { version: '1' },
      ),
    )
    assert.match(notes(log).join('\n'), /canship-ignore-next-line: lib\/db\.ts:4/)
  })

  test('rule selection is named', () => {
    const log = JSON.parse(
      renderSarif(result({ findings: [] }), {
        version: '1',
        ruleSelection: 'everything except secrets, hiding 9',
      }),
    )
    assert.match(notes(log).join('\n'), /Rule selection in force: everything except secrets/)
  })

  test('excluded files and hidden likely findings are named', () => {
    const log = JSON.parse(
      renderSarif(result({ findings: [], ignored: ['test/fake.ts'] }), {
        version: '1',
        hiddenLikely: 3,
      }),
    )
    const text = notes(log).join('\n')
    assert.match(text, /canship-ignore-file: test\/fake\.ts/)
    assert.match(text, /3 lower-confidence findings not included/)
  })

  test('a clean scan with nothing hidden carries no notifications', () => {
    // 无提示时不输出空通知。
    const log = JSON.parse(renderSarif(result({ findings: [] }), { version: '1' }))
    assert.equal(log.runs[0].invocations[0].toolExecutionNotifications, undefined)
  })
})
