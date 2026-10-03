/** 实际 CLI 输出须保留鉴权链、置信度及解析缺口。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const sandbox = mkdtempSync(join(tmpdir(), 'canship-auth-output-'))
after(() => rmSync(sandbox, { recursive: true, force: true }))
const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url))
const body = 'const user=await getUser();if(!user)throw new Error("denied");return user;'

function project(name: string, overrides: Record<string, string> = {}) {
  const root = join(sandbox, name)
  const files = {
    'lib/db.ts': "import {createClient} from '@supabase/supabase-js';export const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);",
    'lib/base.ts': `export async function verify(){${body}}`,
    'lib/auth.ts': "import {verify} from './base';export async function guard(){await verify();}",
    'app/api/items/route.ts': "import {db} from '../../../lib/db';import {guard} from '../../../lib/auth';export async function DELETE(){await guard();await db.from('items').delete();}",
    ...overrides,
  }
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), content)
  }
  return root
}

function run(root: string, ...args: string[]) {
  const result = spawnSync(process.execPath, ['--import', 'tsx', cli, root, '--json', ...args], {
    encoding: 'utf8', timeout: 30_000, windowsHide: true,
  })
  assert.equal(result.error, undefined)
  return { status: result.status, report: JSON.parse(result.stdout) }
}

test('JSON and SARIF expose the same relative authentication chain', () => {
  const root = project('chain')
  const sarif = join(sandbox, 'chain.sarif')
  const { status, report } = run(root, '--all', `--sarif=${sarif}`)
  assert.equal(status, 2)
  assert.equal(report.partial, false)
  assert.equal(report.findings.length, 1)
  assert.equal(report.findings[0].confidence, 'likely')
  const evidence = report.findings[0].evidence
  assert.deepEqual(evidence.filter((step: { kind: string }) => step.kind === 'auth-helper').map((step: { file: string }) => step.file), ['lib/auth.ts', 'lib/base.ts'])
  const sarifResult = JSON.parse(readFileSync(sarif, 'utf8')).runs[0].results[0]
  assert.equal(sarifResult.level, 'warning')
  assert.deepEqual(sarifResult.relatedLocations.map((location: { physicalLocation: { artifactLocation: { uri: string } } }) =>
    location.physicalLocation.artifactLocation.uri), evidence.map((step: { file: string }) => step.file))
})

test('hidden indirect-auth findings still exit 2', () => {
  const { status, report } = run(project('hidden'))
  assert.equal(status, 2)
  assert.equal(report.hiddenLikely, 1)
  assert.deepEqual(report.findings, [])
  assert.equal(report.partial, false)
})

test('a helper returning an unused denial response still blocks in the CLI', () => {
  const { status, report } = run(project('returned-denial', {
    'lib/base.ts': 'export async function verify(){const user=await getUser();if(!user)return new Response(null,{status:401});return user;}',
  }))
  assert.equal(status, 1)
  assert.equal(report.findings[0].confidence, 'certain')
})

test('resolution limits are noted on the finding without marking JSON or SARIF output incomplete', () => {
  const files: Record<string, string> = { 'lib/auth.ts': "export {step as guard} from './step0';" }
  for (let i = 0; i < 10; i++) files[`lib/step${i}.ts`] = i === 9 ? `export async function step(){${body}}`
    : `import {step as next} from './step${i + 1}';export async function step(){await next();}`
  const root = project('limit', files)
  const sarif = join(sandbox, 'limit.sarif')
  const { status, report } = run(root, '--all', `--sarif=${sarif}`)
  assert.equal(status, 1)
  assert.equal(report.partial, false)
  assert.deepEqual(report.errors, [])
  assert.ok(report.findings.some((finding: { why: string[] }) =>
    finding.why.some(paragraph => paragraph.includes('stopped following local helpers in this file at its limit'))))
  const invocation = JSON.parse(readFileSync(sarif, 'utf8')).runs[0].invocations[0]
  assert.equal(invocation.executionSuccessful, true)
  const excluded = run(root, '--only=secrets')
  assert.equal(excluded.status, 0)
  assert.equal(excluded.report.partial, false)
  assert.deepEqual(excluded.report.errors, [])
})
