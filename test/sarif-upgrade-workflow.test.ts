/** 云端验收必须限定测试分支、合成输入及独立分类。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('cloud validation is branch-scoped and cannot upload ordinary scan output', () => {
  const workflow = readFileSync(new URL('../.github/workflows/sarif-upgrade-validation.yml', import.meta.url), 'utf8')
  assert.match(workflow, /branches: \[codex\/sarif-upgrade-validation\]/)
  assert.match(workflow, /github\.repository == 'Tasomei\/canship' && github\.ref == 'refs\/heads\/codex\/sarif-upgrade-validation'/)
  assert.match(workflow, /persist-credentials: false/)
  assert.match(workflow, /npm ci --ignore-scripts/)
  assert.match(workflow, /assert\.equal\(readFileSync\(selected\.fixture\.path, 'utf8'\), selected\.fixture\.content\)/)
  assert.match(workflow, /const prepared = prepareUpload\(preview, id\)/)
  assert.match(workflow, /category: canship-upgrade-validation-20261009/)
  assert.match(workflow, /github\/codeql-action\/upload-sarif@1c5b675653bb5c22dbe9b12b556ec555138e09fd/)
  assert.match(workflow, /CANSHIP_SARIF_ID: \$\{\{ steps\.upload\.outputs\.sarif-id \}\}/)
  assert.doesNotMatch(workflow, /pull_request_target|contents: write|npm publish|npm stage|sarif_file:.*canship-report/)
})
