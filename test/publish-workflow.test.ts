/** 直接执行工作流中的标签选择逻辑，不调用 npm 或访问发布账号。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const workflow = readFileSync(new URL('../.github/workflows/publish.yml', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
const marker = "          node --input-type=module - \"$version\" <<'RELEASE_CHANNEL'\n"
const blocks = workflow.split(marker)
assert.equal(blocks.length, 2)
const script = blocks[1]!.split('\n          RELEASE_CHANNEL')[0]!.replace(/^          /gm, '')
const root = mkdtempSync(join(tmpdir(), 'canship-release-channel-'))
after(() => rmSync(root, { recursive: true, force: true }))
let sequence = 0
function select(version: string) {
  const output = join(root, String(++sequence))
  const result = spawnSync(process.execPath, ['--input-type=module', '-', version], {
    input: script, encoding: 'utf8', timeout: 10_000, windowsHide: true,
    env: { ...process.env, GITHUB_OUTPUT: output, NPM_CONFIG_TAG: 'latest' },
  })
  return { ...result, output: existsSync(output) ? readFileSync(output, 'utf8') : '' }
}

test('stable and prerelease versions select explicit isolated npm channels', () => {
  for (const version of ['0.7.1', '1.0.0', '12.30.400']) {
    const result = select(version)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.output, 'npm_tag=latest\n')
  }
  for (const version of ['0.8.0-alpha.1', '1.0.0-beta.0', '1.0.0-rc.1', '1.0.0-0', '1.0.0-preview-name.3']) {
    const result = select(version)
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.output, 'npm_tag=next\n')
  }
})

test('invalid or ambiguous versions produce no channel output and do not echo input', () => {
  for (const version of ['', 'v1.0.0', '1.0', '01.0.0', '1.00.0', '1.0.01', '1.0.0-01', '1.0.0-rc.01',
    '1.0.0-', '1.0.0-a..b', '1.0.0-rc_1', '1.0.0+build', '1.0.0-rc.1+build', '1.0.0\n',
    '1.0.0\nnpm_tag=latest', '9007199254740992.0.0', 'PRIVATE_VERSION_SENTINEL', '1.0.0-' + 'x'.repeat(256)]) {
    const result = select(version)
    assert.equal(result.status, 1, version)
    assert.equal(result.output, '')
    assert.equal(result.stdout, '')
    assert.doesNotMatch(result.stderr, /PRIVATE_VERSION_SENTINEL|npm_tag=latest/)
  }
})

test('privileged staging consumes only the verified archive and explicit channel', () => {
  const publish = workflow.split('\n  publish:\n')[1]!
  assert.ok(publish)
  assert.doesNotMatch(publish, /actions\/checkout|npm ci|npm install|npm publish|npm stage approve|npm dist-tag/)
  assert.match(publish, /id: package/)
  assert.match(publish, /NPM_TAG: \$\{\{ steps\.package\.outputs\.npm_tag \}\}/)
  assert.match(publish, /case "\$NPM_TAG" in latest\|next\)/)
  assert.match(publish, /npm stage publish "\$RUNNER_TEMP\/package\/\$TARBALL" --tag "\$NPM_TAG" --registry=https:\/\/registry\.npmjs\.org --provenance --ignore-scripts/)
  assert.match(publish, /EXPECTED_SHA256/)
  assert.match(publish, /\$GITHUB_REF_NAME.*v\$version/)
  assert.match(workflow, /tags: \['v\*'\]/)
})
