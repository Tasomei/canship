/**
 * Line-level suppression tests.
 *
 * canship-ignore-file
 *
 * The marker above opts this file out of canship's own scan: it holds
 * credential-shaped strings as assertion data.
 *
 * The property that matters most here is not that the marker works. It is that
 * the marker does not work by accident. `canship-ignore-file` learned this the
 * expensive way — a substring search had walker.ts and secrets.ts excluding
 * themselves, because both merely *mention* the marker in a comment explaining
 * it — and a line marker walks straight back into that trap unless it is held
 * to the same whole-line rule.
 *
 * So half of these tests are about lines that must NOT suppress anything.
 */

import { test, describe, after } from 'node:test'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { scan } from '../src/engine.js'
import { ignoredLinesOf } from '../src/walker.js'

const tempDirs: string[] = []
after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

/** A throwaway project holding one source file, scanned as its own root */
async function scanSource(source: string): Promise<Awaited<ReturnType<typeof scan>>> {
  const root = mkdtempSync(join(tmpdir(), 'canship-ignoreline-'))
  tempDirs.push(root)
  mkdirSync(join(root, 'lib'))
  writeFileSync(join(root, 'lib', 'keys.ts'), source, 'utf8')
  return scan(root)
}

/** Credential-shaped strings, kept out of the test bodies so they read */
const OPENAI = 'sk-proj-Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'
const OPENAI_TWO = 'sk-proj-Zz9yX8wV7uT6sR5qP4oN3mL2kJ1hG0fE9dC8'
const SENDGRID = 'SG.aB3xQ9zK7mNpR2tVwY4hJd.LcF8gH1nT6bE0sU5iO9jXrZaQwMkPvYdN3C'

describe('parsing the markers', () => {
  test('a marker governs the line after it', () => {
    // 1-based, so a marker on line 1 governs line 2.
    const lines = ignoredLinesOf(['// canship-ignore-next-line', 'const a = 1'])
    assert.deepEqual([...lines.keys()], [2])
  })

  test('every comment syntax the file marker accepts', () => {
    for (const wrapper of [
      '// canship-ignore-next-line',
      '# canship-ignore-next-line',
      '-- canship-ignore-next-line',
      '/* canship-ignore-next-line */',
      ' * canship-ignore-next-line',
      '<!-- canship-ignore-next-line -->',
      '   canship-ignore-next-line   ',
    ]) {
      assert.equal(ignoredLinesOf([wrapper]).size, 1, `${wrapper} was not recognised`)
    }
  })

  test('a bare marker covers every rule', () => {
    assert.equal(ignoredLinesOf(['// canship-ignore-next-line']).get(2), null)
  })

  test('a marker may name one rule', () => {
    const rules = ignoredLinesOf(['// canship-ignore-next-line secrets/hardcoded/openai']).get(2)
    assert.deepEqual([...(rules ?? [])], ['secrets/hardcoded/openai'])
  })

  test('a bare marker beats a narrow one on the same line', () => {
    // Two markers stacked above one line. The wider of the two has to win, or
    // the narrow one silently shrinks a suppression the user also wrote.
    const lines = ignoredLinesOf([
      '// canship-ignore-next-line secrets/hardcoded/openai',
      '// canship-ignore-next-line',
      'const a = 1',
    ])
    assert.equal(lines.get(3), null)
  })
})

describe('lines that must not suppress anything', () => {
  test('prose that merely mentions the marker', () => {
    // The exact mistake canship-ignore-file made, and the reason both markers
    // insist on owning their whole line.
    assert.equal(ignoredLinesOf(['// Using canship-ignore-next-line here is wrong']).size, 0)
  })

  test('a marker trailing real code on the same line', () => {
    // The convenient form, deliberately unsupported: it can only work by
    // searching inside a line that also holds code, which is the substring
    // search this rule exists to refuse.
    assert.equal(ignoredLinesOf(['const a = 1 // canship-ignore-next-line']).size, 0)
  })

  test('the file marker is not the line marker', () => {
    assert.equal(ignoredLinesOf(['// canship-ignore-file']).size, 0)
  })

  test('a misspelled marker', () => {
    assert.equal(ignoredLinesOf(['// canship-ignore-nextline']).size, 0)
    assert.equal(ignoredLinesOf(['// canship-ignore-next-lines']).size, 0)
  })
})

describe('suppressing real findings', () => {
  test('a marked line is silenced and an unmarked one is not', async () => {
    const result = await scanSource(
      [
        `export const a = "${OPENAI}"`,
        '// canship-ignore-next-line',
        `export const b = "${OPENAI_TWO}"`,
      ].join('\n'),
    )
    assert.deepEqual(
      result.findings.map((f) => f.line),
      [1],
    )
    assert.equal(result.ignoredFindings.length, 1)
    assert.equal(result.ignoredFindings[0]?.line, 3)
    assert.equal(result.ignoredFindings[0]?.ruleId, 'secrets/hardcoded/openai')
  })

  test('a named rule does not silence a different one', async () => {
    // The reason the rule id is worth having. A line with one known false
    // positive must not go blind to a real finding from another rule.
    const result = await scanSource(
      [
        '// canship-ignore-next-line secrets/hardcoded/openai',
        `export const a = "${SENDGRID}"`,
      ].join('\n'),
    )
    assert.equal(result.ignoredFindings.length, 0)
    assert.equal(result.findings.length, 1)
    assert.equal(result.findings[0]?.ruleId, 'secrets/hardcoded/sendgrid')
  })

  test('a suppressed finding is recorded, never merely dropped', async () => {
    // A finding leaving a security report with nothing said about it is the
    // failure this whole feature had to avoid being.
    const result = await scanSource(
      ['// canship-ignore-next-line', `export const a = "${OPENAI}"`].join('\n'),
    )
    assert.equal(result.findings.length, 0)
    assert.deepEqual(result.ignoredFindings, [
      { file: 'lib/keys.ts', line: 2, ruleId: 'secrets/hardcoded/openai' },
    ])
  })

  test('the record holds no excerpt', async () => {
    // The user's point in writing the marker was that this line should stop
    // being reproduced in reports.
    const result = await scanSource(
      ['// canship-ignore-next-line', `export const a = "${OPENAI}"`].join('\n'),
    )
    assert.equal(JSON.stringify(result.ignoredFindings).includes('sk-proj'), false)
  })

  test('a marker suppresses nothing on a line that has no finding', async () => {
    const result = await scanSource(
      ['// canship-ignore-next-line', 'export const a = 1', `export const b = "${OPENAI}"`].join('\n'),
    )
    assert.equal(result.ignoredFindings.length, 0)
    assert.equal(result.findings.length, 1)
    assert.equal(result.findings[0]?.line, 3)
  })

  test('suppression does not make the scan partial', async () => {
    // A deliberate opt-out is not an incomplete scan. Marking it partial would
    // exit 3 and tell CI the tool failed.
    const result = await scanSource(
      ['// canship-ignore-next-line', `export const a = "${OPENAI}"`].join('\n'),
    )
    assert.equal(result.partial, false)
  })
})

describe('the markers cannot be made slow', () => {
  // Both markers were written as `\s*(?:comment syntax)?\s*marker`, where the
  // two runs of whitespace can both match the same spaces when the comment
  // syntax is absent. That is quadratic in the length of the line, and a scan
  // is a loop over every line of every file — so one long whitespace line in a
  // repository canship was pointed at held the scan for 36 seconds at 200 KB,
  // with the file cap at 2 MiB. Pinned by time because the shape of the regex
  // is the thing that has to stay right, and a future edit that reintroduces
  // the ambiguity would still pass every correctness test above.
  const budgetMs = 1000

  for (const [name, line] of [
    ['whitespace then a non-match', ' '.repeat(200_000) + 'x'],
    ['comment syntax then whitespace', '// ' + ' '.repeat(200_000) + 'x'],
    ['whitespace after a real marker', '// canship-ignore-next-line' + ' '.repeat(200_000) + 'x'],
    ['dashes', '-'.repeat(200_000)],
    ['stars', '*'.repeat(200_000)],
  ] as const) {
    test(`a 200,000-character line of ${name} is answered quickly`, () => {
      const started = Date.now()
      ignoredLinesOf([line])
      const took = Date.now() - started
      assert.ok(took < budgetMs, `took ${took}ms, budget is ${budgetMs}ms`)
    })
  }

  test('the fast form still recognises and rejects the same lines', () => {
    // The rewrite is only safe if it did not change what matches. The suites
    // above cover the cases in prose; this walks the combinations.
    const wrappers = ['', '//', '#', '--', '*', '*/', '/*', '<!--']
    const closers = ['', '*/', '-->']
    const spaces = ['', ' ', '   ', '\t']
    let matched = 0
    for (const w of wrappers) {
      for (const c of closers) {
        for (const s of spaces) {
          if (ignoredLinesOf([`${s}${w}${s}canship-ignore-next-line${s}${c}${s}`]).size === 1) {
            matched++
          }
          // Anything with real content beside the marker must never match.
          assert.equal(
            ignoredLinesOf([`${s}${w}${s}const a = 1 ${c}`]).size,
            0,
            'a line of code was read as a marker',
          )
        }
      }
    }
    assert.ok(matched >= wrappers.length * spaces.length, `only ${matched} combinations matched`)
  })
})
