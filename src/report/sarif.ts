/**
 * SARIF output, so findings land on the pull request instead of in a log.
 *
 * This is the difference between canship being usable in CI and being tolerated
 * there. Without it a failing run is a red cross and a wall of terminal output
 * somebody has to scroll; with it, GitHub code scanning, GitLab and Azure put
 * each finding on the line of the diff that caused it, where the person who
 * wrote that line will actually see it.
 *
 * SARIF 2.1.0, written by hand rather than through a library, because the
 * package has no runtime dependencies and this is a few hundred lines of JSON
 * shape. What is emitted is deliberately the conservative subset that the
 * consumers above agree on.
 */

import type { Finding, ScanResult } from '../types.js'
import { fingerprintOf } from '../baseline.js'
import { BLOCKING } from '../types.js'

/** Where a reader can find out what canship is */
const INFORMATION_URI = 'https://github.com/Tasomei/canship'

export interface SarifOptions {
  /** canship's version, reported as the tool version */
  version: string
}

/**
 * How severe this is, in the three words SARIF has.
 *
 * Severity and confidence both feed this, and they have to: a consumer sees one
 * axis. `error` is reserved for what canship would exit 1 for — a confirmed
 * finding serious enough not to ship — because that is the only class where
 * failing somebody's pull request is the right outcome. Everything else is a
 * `warning`, which annotates without blocking.
 */
function levelOf(f: Finding): 'error' | 'warning' {
  return f.confidence === 'certain' && BLOCKING.has(f.severity) ? 'error' : 'warning'
}

/**
 * The rule metadata for every rule that actually fired.
 *
 * Only the ones present in the results. A driver advertising every rule canship
 * has, including the ones that found nothing, makes the code-scanning UI list
 * dozens of empty rules — and says nothing true that the results do not.
 */
function rulesOf(findings: Finding[]): unknown[] {
  const seen = new Map<string, Finding>()
  for (const f of findings) if (!seen.has(f.ruleId)) seen.set(f.ruleId, f)
  return [...seen.entries()].map(([id, f]) => ({
    id,
    name: id,
    shortDescription: { text: f.title },
    fullDescription: { text: f.why.join(' ') },
    help: {
      text: [...f.why, ...(f.fix.length > 0 ? ['How to fix:', ...f.fix] : [])].join('\n'),
    },
    properties: {
      // Not part of the SARIF vocabulary, so it travels as a property rather
      // than being mangled into one of the three levels above.
      'canship-severity': f.severity,
      'canship-confidence': f.confidence,
    },
    defaultConfiguration: { level: levelOf(f) },
  }))
}

/**
 * One result per finding.
 *
 * `partialFingerprints` is the reason the baseline's fingerprint is reused
 * here rather than a second identity being invented. SARIF consumers use it to
 * recognise the same finding across commits, and they need one that does not
 * move when a line above it moves — which is exactly the property the baseline
 * fingerprint was designed for. Two identity schemes for the same question
 * would eventually disagree about whether a finding is new.
 */
function resultsOf(findings: Finding[]): unknown[] {
  return findings.map((f) => ({
    ruleId: f.ruleId,
    level: levelOf(f),
    message: { text: f.title },
    // A finding with no file — git history, an RLS gap spanning migrations —
    // gets no location rather than a made-up one. SARIF permits that, and
    // pointing it at an arbitrary file would put an annotation on a line that
    // has nothing to do with it.
    locations:
      f.file === null
        ? []
        : [
            {
              physicalLocation: {
                // Already relative and already slash-separated, on Windows too.
                artifactLocation: { uri: f.file },
                ...(f.line === null ? {} : { region: { startLine: f.line } }),
              },
            },
          ],
    partialFingerprints: { canshipFindingV1: fingerprintOf(f) },
  }))
}

/**
 * Render a scan as a SARIF 2.1.0 log.
 *
 * The findings passed in are the ones being shown, so a run without --all
 * produces a log holding what the terminal held. `invocations` carries whether
 * the scan finished: a consumer that reads zero results from an incomplete scan
 * is owed the same distinction the exit codes make, or a crashed rule looks
 * exactly like a clean repository.
 */
export function renderSarif(result: ScanResult, opts: SarifOptions): string {
  const { findings } = result
  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'canship',
            version: opts.version,
            informationUri: INFORMATION_URI,
            rules: rulesOf(findings),
          },
        },
        results: resultsOf(findings),
        invocations: [
          {
            // False when a rule crashed or a file could not be read. It is not
            // about whether findings exist — a scan that finds problems and
            // completes was a successful invocation.
            executionSuccessful: !result.partial,
            ...(result.errors.length > 0
              ? {
                  toolExecutionNotifications: result.errors.map((e) => ({
                    level: e.kind === 'crashed' ? 'error' : 'warning',
                    message: { text: `${e.ruleId}: ${e.message}` },
                  })),
                }
              : {}),
          },
        ],
      },
    ],
  }
  return `${JSON.stringify(log, null, 2)}\n`
}
