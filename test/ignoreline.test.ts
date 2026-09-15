/** 验证逐行抑制的语法、范围和输出披露。
 * canship-ignore-file */

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

/** 以独立临时项目扫描单个源文件。 */
async function scanSource(source: string): Promise<Awaited<ReturnType<typeof scan>>> {
  const root = mkdtempSync(join(tmpdir(), 'canship-ignoreline-'))
  tempDirs.push(root)
  mkdirSync(join(root, 'lib'))
  writeFileSync(join(root, 'lib', 'keys.ts'), source, 'utf8')
  return scan(root)
}

/** 集中保存模拟凭据，便于阅读用例。 */
const OPENAI = 'sk-proj-Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'
const OPENAI_TWO = 'sk-proj-Zz9yX8wV7uT6sR5qP4oN3mL2kJ1hG0fE9dC8'
const SENDGRID = 'SG.aB3xQ9zK7mNpR2tVwY4hJd.LcF8gH1nT6bE0sU5iO9jXrZaQwMkPvYdN3C'

describe('parsing the markers', () => {
  test('a marker governs the line after it', () => {
    // 标记位于第一行时控制第二行。
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
    // 无规则限制的标记应覆盖更窄的标记。
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
    // 说明文本不能触发忽略。
    assert.equal(ignoredLinesOf(['// Using canship-ignore-next-line here is wrong']).size, 0)
  })

  test('a marker trailing real code on the same line', () => {
    // 同行包含真实代码的标记不生效。
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
    // 指定规则只能抑制对应问题。
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
    // 被抑制的结果必须留有记录。
    const result = await scanSource(
      ['// canship-ignore-next-line', `export const a = "${OPENAI}"`].join('\n'),
    )
    assert.equal(result.findings.length, 0)
    assert.deepEqual(result.ignoredFindings, [
      { file: 'lib/keys.ts', line: 2, ruleId: 'secrets/hardcoded/openai' },
    ])
  })

  test('the record holds no excerpt', async () => {
    // 忽略记录不得再次输出源码内容。
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
    // 主动忽略不构成扫描未完成。
    const result = await scanSource(
      ['// canship-ignore-next-line', `export const a = "${OPENAI}"`].join('\n'),
    )
    assert.equal(result.partial, false)
  })
})

describe('the markers cannot be made slow', () => {
  // 用长行验证标记解析不会发生高成本回溯。
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
    // 遍历注释包装组合，验证语义保持一致。
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
          // 标记旁存在其他内容时不能匹配。
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
