/** 反馈入口坚持最小复现与隐私提醒，不要求上传完整项目。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('feedback templates provide actionable fields and explicit privacy review', () => {
  for (const name of ['detection', 'runtime']) {
    const text = readFileSync(new URL(`../.github/ISSUE_TEMPLATE/${name}.md`, import.meta.url), 'utf8')
    assert.match(text, /^---\r?\nname: .+\r?\nabout: .+/)
    assert.match(text, /Canship version or development revision/)
    assert.match(text, /synthetic example/)
    assert.match(text, /Do not include real credentials, personal data, internal paths/)
    assert.match(text, /\[ \] I reviewed/)
    assert.match(text, /https:\/\/github.com\/Tasomei\/canship\/security\/policy/)
    assert.doesNotMatch(text, /(?:Required|Your) (?:email|full name|phone)/i)
  }
})
test('private disclosure links to the existing policy without disabling ordinary feedback', () => {
  const text = readFileSync(new URL('../.github/ISSUE_TEMPLATE/config.yml', import.meta.url), 'utf8')
  assert.match(text, /^blank_issues_enabled: true/)
  assert.match(text, /url: https:\/\/github.com\/Tasomei\/canship\/security\/policy/)
  assert.ok(readFileSync(new URL('../SECURITY.md', import.meta.url), 'utf8').includes('Reporting a vulnerability'))
})
