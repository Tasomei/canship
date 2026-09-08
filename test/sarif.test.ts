/**
 * SARIF output tests.
 *
 * canship-ignore-file
 *
 * What a code-scanning platform does with a malformed log is accept it and show
 * nothing, so the failure mode here is silence on a pull request rather than an
 * error anybody sees. These tests pin the shape those platforms actually read:
 * the level, the location, and the fingerprint they use to decide whether a
 * finding is new.
 */

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

/** Render and parse, since every assertion here is about the parsed document */
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
    // A result whose ruleId is not in the driver's rule list is where GitHub
    // stops rendering the description and shows a bare id.
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
    // Declaring every rule canship has fills the code-scanning UI with entries
    // that found nothing and say nothing the results do not.
    assert.equal(sarif().runs[0].tool.driver.rules.length, 1)
  })
})

describe('severity becomes a level', () => {
  test('a certain P0 is an error', () => {
    assert.equal(sarif().runs[0].results[0].level, 'error')
  })

  test('a certain P2 is a warning', () => {
    // Reserved for what canship exits 1 for. A P2 that browsers reject on the
    // user's behalf must not fail somebody's pull request.
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
    // Git-history findings have no file. Pointing them at an arbitrary one
    // would annotate a line that has nothing to do with the problem.
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
    // Both answer "is this the same finding as before" and both must survive a
    // line moving. Two schemes for one question eventually disagree about
    // whether a finding is new.
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
    // A consumer reading zero results from a scan that crashed is owed the
    // same distinction the exit codes make.
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
  // The terminal, the HTML report and --json all name what was hidden. SARIF is
  // the only one a machine reads, and it said none of it: results: [] and
  // executionSuccessful: true, with nothing anywhere to say that nineteen
  // findings had been filed away in a baseline. A code-scanning dashboard
  // showing a clean bill of health for a repository whose service_role key is
  // in a baseline is the most expensive way this tool could be wrong.
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
    // The field has to stay meaningful. If it were always present, nobody would
    // read it.
    const log = JSON.parse(renderSarif(result({ findings: [] }), { version: '1' }))
    assert.equal(log.runs[0].invocations[0].toolExecutionNotifications, undefined)
  })
})
