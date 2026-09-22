/** 验证退出前完成标准输出，包括报告文件写入失败的分支。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const root = mkdtempSync(join(tmpdir(), 'canship-output-drain-'))
after(() => rmSync(root, { recursive: true, force: true }))
for (let file = 0; file < 16; file++) writeFileSync(join(root, `${file}.rules`),
  Array.from({ length: 80 }, (_, line) => `match /items${line}/{id} { allow write: if true; }`).join('\n'))
function run(...args: string[]) {
  return spawnSync(process.execPath, ['--import', 'tsx', '--import',
    new URL('./helpers/slow-stdout.mjs', import.meta.url).href,
    join(repository, 'src/cli.ts'), root, '--json', ...args], {
    cwd: repository, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 20_000,
  })
}
test('大 JSON 报告在异步写出后保持完整', () => {
  const result = run()
  assert.equal(result.status, 1)
  const report = JSON.parse(result.stdout)
  assert.equal(report.findings.length, 1280)
  assert.equal(report.partial, false)
  assert.ok(result.stdout.length > 1024 * 1024)
})
test('报告文件写入失败仍保留已生成的 JSON，退出 3', () => {
  const result = run(`--report=${root}`)
  assert.equal(result.status, 3)
  assert.equal(JSON.parse(result.stdout).findings.length, 1280)
})
