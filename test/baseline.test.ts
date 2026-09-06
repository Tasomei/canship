/**
 * Baseline tests.
 *
 * canship-ignore-file
 *
 * The marker above opts this file out of canship's own scan: it holds
 * credential-shaped strings as assertion data.
 *
 * Two properties carry the whole feature, and both are here:
 *
 *   1. A baseline survives ordinary editing. If inserting a line at the top of
 *      a file makes every finding below it look new, nobody keeps the baseline
 *      — so the fingerprint must not depend on the line number.
 *   2. A baseline never becomes a hiding place. It stores no excerpt, it
 *      accepts a fixed number of copies rather than a blanket pardon, and every
 *      output surface reports what it removed.
 *
 * The rest is the reading path, which is deliberately strict: a baseline that
 * cannot be parsed must stop the run, never quietly suppress nothing while the
 * user believes it is in force.
 */

import { test, describe, after } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import type { Finding } from '../src/types.js'
import {
  BASELINE_VERSION,
  BaselineError,
  applyBaseline,
  buildBaseline,
  fingerprintOf,
  readBaseline,
  serializeBaseline,
  writeBaseline,
} from '../src/baseline.js'
import { renderReport } from '../src/report/terminal.js'
import { renderHtml } from '../src/report/html.js'
import type { ScanResult } from '../src/types.js'

const tempDirs: string[] = []
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'canship-baseline-'))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

/** A finding with sensible defaults, so each test states only what it varies */
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

describe('fingerprint identity', () => {
  test('the line number is not part of it', () => {
    // The reason the feature is usable. An import added at the top of a file
    // shifts every finding below it; if that changed the fingerprint, the
    // baseline would report the same untouched problems as new on the next
    // commit and would be deleted by the commit after that.
    assert.equal(fingerprintOf(finding({ line: 12 })), fingerprintOf(finding({ line: 400 })))
  })

  test('a null line matches a numbered one', () => {
    // Project-wide rules report line: null. The absence of a line must not be
    // a different identity from having one, or a rule that learns to locate
    // itself invalidates every baseline in existence.
    assert.equal(fingerprintOf(finding({ line: null })), fingerprintOf(finding({ line: 3 })))
  })

  test('a different excerpt is a different finding', () => {
    // Two different keys declared on one line share a ruleId, a file, a line
    // and a title. The excerpt is the only thing that tells them apart, which
    // is why the engine's dedupe carries it too — without it, accepting one
    // key would accept the other for free.
    assert.notEqual(
      fingerprintOf(finding({ excerpt: 'sk-aaa' })),
      fingerprintOf(finding({ excerpt: 'sk-bbb' })),
    )
  })

  test('rule, file and title each change it', () => {
    const base = fingerprintOf(finding())
    assert.notEqual(base, fingerprintOf(finding({ ruleId: 'secrets/hardcoded/stripe-live' })))
    assert.notEqual(base, fingerprintOf(finding({ file: 'lib/other.ts' })))
    assert.notEqual(base, fingerprintOf(finding({ title: 'Something else entirely' })))
  })

  test('field values cannot be rearranged into each other', () => {
    // The fields are joined with NUL, which the output boundary strips from
    // every string before a finding reaches here. A separator any field could
    // contain would let one finding forge another's identity — and a forged
    // identity in a baseline is a suppression nobody granted.
    assert.notEqual(
      fingerprintOf(finding({ ruleId: 'a', file: 'bc', title: 't', excerpt: 'e' })),
      fingerprintOf(finding({ ruleId: 'ab', file: 'c', title: 't', excerpt: 'e' })),
    )
  })
})

describe('building a baseline', () => {
  test('records every confidence, not just certain ones', () => {
    // A likely finding still exits 2, so leaving it out would leave the build
    // red for a reason the baseline claimed to have settled.
    const built = buildBaseline([finding(), finding({ confidence: 'likely', excerpt: 'sk-bbb' })])
    assert.equal(built.entries.length, 2)
  })

  test('identical findings collapse into one entry with a count', () => {
    const built = buildBaseline([finding({ line: 1 }), finding({ line: 2 }), finding({ line: 3 })])
    assert.equal(built.entries.length, 1)
    assert.equal(built.entries[0]?.count, 3)
  })

  test('holds no excerpt', () => {
    // The security property. This file is meant to be committed, and canship's
    // own README admits redaction cannot be guaranteed for a credential it does
    // not recognise — so writing excerpts here would have canship creating the
    // exact leak it exists to find.
    const text = serializeBaseline(buildBaseline([finding({ excerpt: 'sk-live-REALSECRET' })]))
    assert.equal(text.includes('REALSECRET'), false)
    assert.equal(text.includes('excerpt'), false)
  })

  test('the same findings produce the same file', () => {
    // A diff that churns every line is a diff nobody reads, and this one exists
    // to be reviewed before it is approved.
    const when = new Date('2026-01-01T00:00:00.000Z')
    const findings = [finding({ file: 'z.ts' }), finding({ file: 'a.ts' }), finding({ file: 'm.ts' })]
    const first = serializeBaseline(buildBaseline(findings, when))
    const shuffled = [findings[1]!, findings[2]!, findings[0]!]
    assert.equal(serializeBaseline(buildBaseline(shuffled, when)), first)
  })
})

describe('applying a baseline', () => {
  test('an accepted finding is suppressed', () => {
    const applied = applyBaseline([finding()], buildBaseline([finding()]))
    assert.equal(applied.kept.length, 0)
    assert.equal(applied.suppressed, 1)
    assert.equal(applied.stale, 0)
  })

  test('a new finding survives', () => {
    const applied = applyBaseline(
      [finding(), finding({ file: 'lib/new.ts' })],
      buildBaseline([finding()]),
    )
    assert.deepEqual(
      applied.kept.map((f) => f.file),
      ['lib/new.ts'],
    )
    assert.equal(applied.suppressed, 1)
  })

  test('an accepted finding still moves with its file', () => {
    // The same assertion as the fingerprint test, one level up: this is what
    // the CLI actually calls, so it is what actually has to survive an edit.
    const applied = applyBaseline([finding({ line: 999 })], buildBaseline([finding({ line: 4 })]))
    assert.equal(applied.suppressed, 1)
    assert.equal(applied.kept.length, 0)
  })

  test('accepting two copies does not accept a third', () => {
    // A blanket pardon per fingerprint would mean the second identical key
    // added to a file that already had two is suppressed by a decision nobody
    // made about it.
    const baseline = buildBaseline([finding({ line: 1 }), finding({ line: 2 })])
    const applied = applyBaseline(
      [finding({ line: 1 }), finding({ line: 2 }), finding({ line: 3 })],
      baseline,
    )
    assert.equal(applied.suppressed, 2)
    assert.equal(applied.kept.length, 1)
  })

  test('an entry matching nothing is counted as stale, not as a failure', () => {
    const applied = applyBaseline([], buildBaseline([finding(), finding({ file: 'gone.ts' })]))
    assert.equal(applied.stale, 2)
    assert.equal(applied.kept.length, 0)
    assert.equal(applied.suppressed, 0)
  })

  test('an empty baseline suppresses nothing', () => {
    const applied = applyBaseline([finding()], { version: BASELINE_VERSION, generatedAt: '', entries: [] })
    assert.equal(applied.kept.length, 1)
    assert.equal(applied.suppressed, 0)
  })
})

describe('reading a baseline', () => {
  /** Write `text` to a scratch file and return the path */
  function withFile(text: string): string {
    const path = join(tempDir(), 'canship-baseline.json')
    writeFileSync(path, text, 'utf8')
    return path
  }

  test('a written baseline reads back and still matches', () => {
    const path = join(tempDir(), 'canship-baseline.json')
    const findings = [finding(), finding({ file: 'lib/two.ts', confidence: 'likely' })]
    writeBaseline(path, buildBaseline(findings))
    const applied = applyBaseline(findings, readBaseline(path))
    assert.equal(applied.suppressed, 2)
    assert.equal(applied.kept.length, 0)
    assert.equal(applied.stale, 0)
  })

  test('a missing file is an error, not an empty baseline', () => {
    // Continuing with no suppression is the safe direction for findings, and
    // still wrong: it hides a broken path from someone who believes their
    // baseline is in force.
    assert.throws(() => readBaseline(join(tempDir(), 'absent.json')), BaselineError)
  })

  test('invalid JSON is an error', () => {
    assert.throws(() => readBaseline(withFile('{not json')), BaselineError)
  })

  test('an unknown version is an error rather than a guess', () => {
    assert.throws(
      () => readBaseline(withFile(JSON.stringify({ version: 99, entries: [] }))),
      BaselineError,
    )
  })

  test('a malformed entry fails the file instead of being dropped', () => {
    // Dropping it would mean the findings it covered come back as new with no
    // explanation anywhere.
    assert.throws(
      () =>
        readBaseline(
          withFile(JSON.stringify({ version: BASELINE_VERSION, entries: [{ fingerprint: 'x' }] })),
        ),
      BaselineError,
    )
  })

  test('a non-positive count is malformed', () => {
    const entry = { fingerprint: 'x', ruleId: 'r', file: null, title: 't', count: 0 }
    assert.throws(
      () => readBaseline(withFile(JSON.stringify({ version: BASELINE_VERSION, entries: [entry] }))),
      BaselineError,
    )
  })

  test('a JSON array is not a baseline file', () => {
    assert.throws(() => readBaseline(withFile('[]')), BaselineError)
  })
})

describe('a baseline is never silent', () => {
  /** A finished scan that found nothing, as the CLI hands it to a renderer */
  const emptyScan: ScanResult = {
    findings: [],
    filesScanned: 12,
    durationMs: 5,
    errors: [],
    skipped: [],
    ignored: [],
    ignoredFindings: [],
    ruleSelection: null,
    vendored: 0,
    partial: false,
  }

  test('the terminal does not show a green tick over a baseline', () => {
    // The single most misleading thing this tool could print: "no exposed
    // credentials found" for a repository whose service_role key is sitting in
    // a file that says not to mention it.
    const out = renderReport(emptyScan, {
      root: '/p',
      showingLikely: false,
      hiddenLikely: 0,
      baselineSuppressed: 19,
      baselinePath: '/p/canship-baseline.json',
    })
    assert.equal(out.includes('No exposed credentials found'), false)
    assert.match(out, /19 findings hidden by the baseline/)
    assert.match(out, /still exist/)
  })

  test('the terminal still shows a green tick without one', () => {
    const out = renderReport(emptyScan, { root: '/p', showingLikely: false, hiddenLikely: 0 })
    assert.match(out, /No exposed credentials found/)
  })

  test('the HTML report carries the count with it', () => {
    // This document outlives the run that produced it and gets handed to
    // someone who was not at the terminal.
    const html = renderHtml(emptyScan, {
      root: '/p',
      generatedAt: '2026-01-01T00:00:00.000Z',
      hiddenLikely: 0,
      baselineSuppressed: 19,
      baselinePath: '/p/canship-baseline.json',
    })
    assert.equal(html.includes('verdict clean'), false)
    assert.match(html, /19 findings/)
    assert.match(html, /still exist/)
  })

  test('writing a baseline says what committing it publishes', () => {
    // Pinned because this is a security warning, and a security warning is the
    // kind of line a later tidy-up removes for being wordy. What it guards:
    // every entry names a file, a rule and an unfixed problem, and canship
    // searches gitignored credential files on purpose — so an entry can
    // describe a .env.local the repository does not contain. Recommending
    // "commit this" without that sentence makes canship's own output the leak
    // it exists to find.
    const root = mkdtempSync(join(tmpdir(), 'canship-baseline-cli-'))
    tempDirs.push(root)
    mkdirSync(join(root, 'lib'))
    writeFileSync(
      join(root, 'lib', 'keys.ts'),
      'export const a = "sk-proj-Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s"\n',
      'utf8',
    )
    const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts')
    const stdout = execFileSync('node', ['--import', 'tsx', cli, root, '--baseline-write'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    assert.match(stdout, /still exist/)
    assert.match(stdout, /files git does not track/)
    assert.match(stdout, /public repository/)

    // And the claim that sentence makes has to stay true.
    const written = readFileSync(join(root, 'canship-baseline.json'), 'utf8')
    assert.equal(written.includes('sk-proj-'), false, 'the baseline held a credential value')
    assert.match(written, /"file": "lib\/keys\.ts"/)
  })

  test('a bare --baseline-write writes into the scanned project', () => {
    // Not into the working directory. A baseline belongs to the project, and a
    // bare --baseline-write has to put the file where a bare --baseline will
    // look for it — otherwise `npx canship ./app --baseline-write` writes one
    // place and reads another. This test runs the CLI from somewhere else on
    // purpose, because running it from inside the project cannot tell the two
    // behaviours apart.
    // The working directory stays this repository, which is already a
    // different place from the scanned root — enough to tell the two
    // behaviours apart, and it keeps tsx resolvable.
    const root = mkdtempSync(join(tmpdir(), 'canship-anchor-'))
    tempDirs.push(root)
    const cwd = join(dirname(fileURLToPath(import.meta.url)), '..')
    mkdirSync(join(root, 'lib'))
    writeFileSync(
      join(root, 'lib', 'keys.ts'),
      'export const a = "sk-proj-Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s"\n',
      'utf8',
    )
    const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts')
    execFileSync('node', ['--import', 'tsx', cli, root, '--baseline-write'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    assert.equal(existsSync(join(root, 'canship-baseline.json')), true, 'not written to the project')
    // The working directory is this repository. A baseline appearing here is
    // the bug, and it is not gitignored, so it would be one `git add -A` from
    // being committed.
    assert.equal(
      existsSync(join(cwd, 'canship-baseline.json')),
      false,
      'written to the working directory instead',
    )

    // And the bare read form finds what the bare write form left.
    const out = execFileSync('node', ['--import', 'tsx', cli, root, '--baseline', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const report = JSON.parse(out) as { findings: unknown[]; baselineSuppressed: number }
    assert.equal(report.findings.length, 0)
    assert.equal(report.baselineSuppressed, 1)
  })

  test('a config-file baseline path is relative to the project', () => {
    // Resolving it against the working directory was a real bug, and a quiet
    // one: `npx canship ./app` looked for the baseline beside the caller, which
    // either failed with a confusing exit 3 or found a different project's
    // baseline and suppressed findings with it.
    const root = mkdtempSync(join(tmpdir(), 'canship-cfgpath-'))
    tempDirs.push(root)
    mkdirSync(join(root, 'lib'))
    writeFileSync(
      join(root, 'lib', 'keys.ts'),
      'export const a = "sk-proj-Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s"\n',
      'utf8',
    )
    const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts')
    execFileSync(
      'node',
      ['--import', 'tsx', cli, root, `--baseline-write=${join(root, 'accepted.json')}`],
      { stdio: 'ignore' },
    )
    writeFileSync(join(root, 'canship.config.json'), '{"baseline":"accepted.json"}', 'utf8')
    const out = execFileSync('node', ['--import', 'tsx', cli, root, '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const report = JSON.parse(out) as { findings: unknown[]; baselineSuppressed: number }
    assert.equal(report.baselineSuppressed, 1)
    assert.equal(report.findings.length, 0)
  })

  test('a config-file baseline path cannot leave the project', () => {
    // The config file comes out of the directory being scanned, and that
    // directory is the thing canship is pointed at because it is *not*
    // trusted. Without this, somebody else's repository could aim the baseline
    // read at a path outside it: the contents never reach the report, but the
    // error message names the path and says whether it parsed, which turns a
    // scan into a file-existence probe.
    const root = mkdtempSync(join(tmpdir(), 'canship-traversal-'))
    tempDirs.push(root)
    mkdirSync(join(root, 'lib'))
    writeFileSync(join(root, 'lib', 'keys.ts'), 'export const a = 1\n', 'utf8')
    const cli = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'cli.ts')

    const run = (config: string): { status: number; stderr: string } => {
      writeFileSync(join(root, 'canship.config.json'), config, 'utf8')
      try {
        execFileSync('node', ['--import', 'tsx', cli, root, '--json'], {
          encoding: 'utf8',
          stdio: ['ignore', 'ignore', 'pipe'],
        })
        return { status: 0, stderr: '' }
      } catch (err) {
        const e = err as { status?: number; stderr?: string }
        return { status: e.status ?? -1, stderr: e.stderr ?? '' }
      }
    }

    // A drive letter is only a drive letter on Windows. Everywhere else
    // `C:/Windows/win.ini` is an ordinary relative path — `resolve` puts it
    // *inside* the project, where refusing it would be wrong — so asserting it
    // is refused is a claim about the platform rather than about the check.
    // The first two escape on both.
    const escapes = ['../../../../../evil.json', '/etc/passwd']
    if (process.platform === 'win32') escapes.push('C:/Windows/win.ini')

    for (const escape of escapes) {
      const out = run(JSON.stringify({ baseline: escape }))
      assert.equal(out.status, 3, `${escape} was not refused`)
      assert.match(out.stderr, /must stay inside the project/)
    }

    // A path that stays inside is not refused for that reason. It still fails,
    // because the file is not there — the message is what separates the two.
    const inside = run(JSON.stringify({ baseline: 'sub/accepted.json' }))
    assert.equal(inside.stderr.includes('must stay inside the project'), false)
  })

  test('the HTML report reports staleness', () => {
    const html = renderHtml(emptyScan, {
      root: '/p',
      generatedAt: '2026-01-01T00:00:00.000Z',
      baselineStale: 3,
    })
    assert.match(html, /3 baseline entries no longer match/)
  })
})
