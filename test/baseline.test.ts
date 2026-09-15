/** 验证基线身份、计数、文件校验和抑制信息。
 * canship-ignore-file */

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

/** 构造默认结果，每个用例只覆盖差异字段。 */
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
    // 增加前置行不能改变基线身份。
    assert.equal(fingerprintOf(finding({ line: 12 })), fingerprintOf(finding({ line: 400 })))
  })

  test('a null line matches a numbered one', () => {
    // 未知行号与具体行号不应改变结果身份。
    assert.equal(fingerprintOf(finding({ line: null })), fingerprintOf(finding({ line: 3 })))
  })

  test('a different excerpt is a different finding', () => {
    // 缺少来源摘要时，摘录仍参与区分结果。
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
    // 空字符分隔避免不同字段组合产生相同身份。
    assert.notEqual(
      fingerprintOf(finding({ ruleId: 'a', file: 'bc', title: 't', excerpt: 'e' })),
      fingerprintOf(finding({ ruleId: 'ab', file: 'c', title: 't', excerpt: 'e' })),
    )
  })
})

describe('building a baseline', () => {
  test('records every confidence, not just certain ones', () => {
    // 疑似结果也必须写入基线。
    const built = buildBaseline([finding(), finding({ confidence: 'likely', excerpt: 'sk-bbb' })])
    assert.equal(built.entries.length, 2)
  })

  test('identical findings collapse into one entry with a count', () => {
    const built = buildBaseline([finding({ line: 1 }), finding({ line: 2 }), finding({ line: 3 })])
    assert.equal(built.entries.length, 1)
    assert.equal(built.entries[0]?.count, 3)
  })

  test('holds no excerpt', () => {
    // 基线不得包含源码摘录或完整凭据。
    const text = serializeBaseline(buildBaseline([finding({ excerpt: 'sk-live-REALSECRET' })]))
    assert.equal(text.includes('REALSECRET'), false)
    assert.equal(text.includes('excerpt'), false)
  })

  test('the same findings produce the same file', () => {
    // 相同时间和输入应生成稳定文件。
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
    // 验证基线应用时仍能识别移动后的结果。
    const applied = applyBaseline([finding({ line: 999 })], buildBaseline([finding({ line: 4 })]))
    assert.equal(applied.suppressed, 1)
    assert.equal(applied.kept.length, 0)
  })

  test('accepting two copies does not accept a third', () => {
    // 重复结果按计数匹配，不能无限扩展接受范围。
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
  /** 创建临时基线文件并返回路径。 */
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
    // 缺失基线必须明确失败。
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
    // 无效条目不得被静默丢弃。
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
  /** 构造已完成且无发现的扫描结果。 */
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
    // 基线抑制结果后不能显示无条件通过。
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
    // 独立 HTML 报告也必须披露基线抑制。
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
    // 验证基线文件披露范围的提示。
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

    // 确认基线不包含完整凭据。
    const written = readFileSync(join(root, 'canship-baseline.json'), 'utf8')
    assert.equal(written.includes('sk-proj-'), false, 'the baseline held a credential value')
    assert.match(written, /"file": "lib\/keys\.ts"/)
  })

  test('a bare --baseline-write writes into the scanned project', () => {
    // 默认基线写入扫描项目目录。
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
    // 不得将其他项目的基线写入当前工作目录。
    assert.equal(
      existsSync(join(cwd, 'canship-baseline.json')),
      false,
      'written to the working directory instead',
    )

    // 默认读取应找到默认写入的文件。
    const out = execFileSync('node', ['--import', 'tsx', cli, root, '--baseline', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    const report = JSON.parse(out) as { findings: unknown[]; baselineSuppressed: number }
    assert.equal(report.findings.length, 0)
    assert.equal(report.baselineSuppressed, 1)
  })

  test('a config-file baseline path is relative to the project', () => {
    // 配置中的基线路径以扫描项目为基准。
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
    // 配置路径不能逃出项目目录。
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

    // 驱动器绝对路径只在 Windows 上适用。
    const escapes = ['../../../../../evil.json', '/etc/passwd']
    if (process.platform === 'win32') escapes.push('C:/Windows/win.ini')

    for (const escape of escapes) {
      const out = run(JSON.stringify({ baseline: escape }))
      assert.equal(out.status, 3, `${escape} was not refused`)
      assert.match(out.stderr, /must stay inside the project/)
    }

    // 目录内的缺失文件应报读取错误，而非越界错误。
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
