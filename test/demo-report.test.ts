/** 可下载演示仅包含合成数据；渲染器变更必须同步演示文件。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { renderDemoReport } from '../src/report/demo.js'

test('the committed demo matches a deterministic source-only renderer', () => {
  const html = renderDemoReport()
  assert.equal(html, renderDemoReport())
  assert.equal(readFileSync(new URL('../docs/demo.html', import.meta.url), 'utf8').replace(/\r\n/g, '\n'), html)
  assert.match(html, /Synthetic demonstration — no project was scanned/)
  assert.match(html, /Generated from fixed synthetic data/)
  assert.doesNotMatch(html, /Findings describe static evidence in this repository/)
  assert.equal((html.match(/<details class="f"/g) ?? []).length, 4)
  assert.match(html, /data-conf="certain"/)
  assert.match(html, /data-conf="likely"/)
  assert.doesNotMatch(html, /[A-Z]:[\\/]Users[\\/]|\/home\/|\/Users\/|LAPTOP-|@users\.noreply|sk-[A-Za-z0-9_-]{24,}/i)
})

test('demo clipboard prompts carry an explicit warning independent of the surrounding page', () => {
  const html = renderDemoReport()
  const data = JSON.parse(/id="canship-data">([\s\S]*?)<\/script>/.exec(html)![1]!)
  assert.equal(Object.keys(data.prompts).length, 5)
  for (const prompt of Object.values(data.prompts)) assert.match(String(prompt), /^SYNTHETIC DEMONSTRATION ONLY\. No project was scanned\./)
  assert.match(html, /default-src 'none'/)
  assert.doesNotMatch(html, /<iframe\b|<link\b|@import|url\(/i)
})

test('demo check mode is read-only and invalid options do not write output', () => {
  const path = new URL('../docs/demo.html', import.meta.url)
  const before = readFileSync(path)
  for (const [args, expected] of [[['--check'], 0], [['--unknown'], 3]] as const) {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/render-demo.ts', ...args], { encoding: 'utf8', timeout: 15000 })
    assert.equal(result.status, expected, result.stderr)
    assert.deepEqual(readFileSync(path), before)
  }
})
