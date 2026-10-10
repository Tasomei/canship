/** 云端验收必须限定测试分支、合成输入及独立分类。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'

test('cloud validation is branch-scoped and cannot upload ordinary scan output', () => {
  const workflow = readFileSync(new URL('../.github/workflows/sarif-upgrade-validation.yml', import.meta.url), 'utf8')
  assert.match(workflow, /branches: \[codex\/sarif-upgrade-validation\]/)
  assert.match(workflow, /github\.repository == 'Tasomei\/canship' && github\.ref == 'refs\/heads\/codex\/sarif-upgrade-validation'/)
  assert.match(workflow, /persist-credentials: false/)
  assert.match(workflow, /npm ci --ignore-scripts/)
  assert.doesNotMatch(workflow, /assert\.equal\(readFileSync/)
  assert.match(workflow, /const prepared = prepareUpload\(preview, id\)/)
  assert.match(workflow, /category: canship-upgrade-validation-20261009/)
  // 作业超时须覆盖上传等待及两段各 10 分钟的轮询。
  assert.ok(Number(/timeout-minutes: (\d+)/.exec(workflow)?.[1]) >= 25)
  assert.match(workflow, /github\/codeql-action\/upload-sarif@1c5b675653bb5c22dbe9b12b556ec555138e09fd/)
  assert.match(workflow, /CANSHIP_SARIF_ID: \$\{\{ steps\.upload\.outputs\.sarif-id \}\}/)
  assert.doesNotMatch(workflow, /pull_request_target|contents: write|npm publish|npm stage|sarif_file:.*canship-report/)
})

test('fixture mismatch diagnostics never include unexpected source text', () => {
  const workflow = readFileSync(new URL('../.github/workflows/sarif-upgrade-validation.yml', import.meta.url), 'utf8')
  const guard = workflow.split(/\r?\n/).find(line => line.trimStart().startsWith("if (readFileSync('synthetic/firestore.rules'"))!
  assert.ok(guard)
  assert.throws(() => runInNewContext(guard, { readFileSync: () => 'PRIVATE_SOURCE_SENTINEL', prepared: { fixture: 'synthetic' } }),
    error => String(error) === 'Error: Synthetic fixture mismatch.')
})
