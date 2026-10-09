/** 合成验收预览须可重现，且不能把本地指纹检查当作云端去重验收。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'

const run = (...args: string[]) => spawnSync(process.execPath,
  ['--import', 'tsx', 'scripts/prepare-sarif-validation.ts', ...args], { encoding: 'utf8', timeout: 15000 })

test('preview produces repeatable synthetic reports with matching fixture locations', () => {
  const first = run(), second = run()
  assert.equal(first.status, 0, first.stderr)
  assert.equal(second.status, 0, second.stderr)
  assert.equal(first.stdout, second.stdout)
  const preview = JSON.parse(first.stdout)
  assert.equal(preview.kind, 'sarif-validation-preview')
  assert.equal(preview.synthetic, true)
  for (const key of ['scanPerformed', 'networkPerformed', 'uploaded']) assert.equal(preview[key], false)
  assert.match(preview.notice, /remains unverified/)
  assert.deepEqual(preview.cases.map((item: { id: string }) => item.id), ['initial', 'repeat', 'moved', 'wording-and-version'])
  const initial = preview.cases[0].sarif.runs[0].results
  for (const item of preview.cases) {
    const results = item.sarif.runs[0].results
    assert.equal(results.length, 2)
    assert.equal(new Set(results.map((result: any) => result.partialFingerprints.canshipFindingV3)).size, 2)
    for (let index = 0; index < results.length; index++) {
      const physical = results[index].locations[0].physicalLocation
      assert.equal(physical.artifactLocation.uri, item.fixture.path)
      assert.equal(item.fixture.content.split('\n')[physical.region.startLine - 1].trim(), 'allow read: if true;')
      assert.equal(results[index].partialFingerprints.canshipFindingV3, initial[index].partialFingerprints.canshipFindingV3)
    }
  }
  assert.deepEqual(preview.cases[0].sarif, preview.cases[1].sarif)
  assert.notEqual(preview.cases[0].sarif.runs[0].tool.driver.version, preview.cases[3].sarif.runs[0].tool.driver.version)
  assert.doesNotMatch(first.stdout, /[A-Z]:[\\/]Users[\\/]|LAPTOP-|@users\.noreply/)
})

test('preview rejects upload-like arguments without output or echoing private input', () => {
  const result = run('--upload=PRIVATE_TARGET_SENTINEL')
  assert.equal(result.status, 3)
  assert.equal(result.stdout, '')
  assert.doesNotMatch(result.stderr, /PRIVATE_TARGET_SENTINEL/)
})
