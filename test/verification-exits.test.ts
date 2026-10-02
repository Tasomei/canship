/** 退出证明必须来自当前分支实际执行的语句。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { LocalVerification } from '../src/rules/verification.js'

for (const [body, expected] of [
  ["flag && redirect('/login');", false],
  ["flag &&\n redirect('/login');", false],
  ["const unused = () => redirect('/login');", false],
  ["const unused = () =>\n redirect('/login');", false],
  ["const unused = function () { return null; };", false],
  ["for await (const item of items) return null;", false],
  ["if (flag) return null; else log();", false],
  ["if (flag) log(); else return null;", false],
  ["while (flag) return null;", false],
  ["flag ? redirect('/login') : log();", false],
  ["log(); return null;", true],
  ["log()\nreturn null", true],
  ["if (flag) log(); return null;", true],
  ["const unused = () => redirect('/login'); return null;", true],
  ["log(); redirect('/login');", true],
  ["throw new Error('invalid');", true],
] as const) {
  test(`unconditional verification exit: ${body}`, () => {
    const content = `async function handler() { ${body} }`
    const context = new LocalVerification({ path: 'route.ts', content, lines: [content], isExampleContext: false })
    const start = content.indexOf('{')
    assert.equal(context.exits(start, content.length), expected)
  })
}
