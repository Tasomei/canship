/** 0.8.2 新增的凭据格式：前缀可自证提供方，模板值不报告，摘录中不出现完整值。 */

import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/index.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

// 运行时拼接模拟凭据，避免源码中出现完整凭据形态。
const HEX = '3f9a1c7e5b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a'
const ALNUM = 'Q7wE9rT2yU4iO6pA8sD0fG1hJ3kL5zX7cV9bN2mQ4aS6dF8gH0jK2lZ4xC6vB8nM1'
const hex = (n: number) => HEX.slice(0, n)
const alnum = (n: number) => ALNUM.slice(0, n)

const FORMATS: Array<[string, string, string]> = [
  ['gitlab-token', 'GitLab token', 'gl' + 'pat-' + alnum(20)],
  ['shopify-token', 'Shopify app token or secret', 'shp' + 'at_' + hex(32)],
  ['linear-api-key', 'Linear API key', 'lin' + '_api_' + alnum(40)],
  ['notion-token', 'Notion integration token', 'ntn' + '_' + '48213907562' + alnum(35)],
  ['digitalocean-token', 'DigitalOcean personal access token', 'dop' + '_v1_' + hex(64)],
  ['sentry-user-token', 'Sentry user auth token', 'sntryu' + '_' + hex(64)],
  ['planetscale-credential', 'PlanetScale token or password', 'pscale' + '_pw_' + alnum(40)],
  ['doppler-token', 'Doppler personal token', 'dp' + '.pt.' + alnum(43)],
  ['flyio-token', 'Fly.io access token', 'fo1' + '_' + alnum(43)],
  ['postman-api-key', 'Postman API key', 'PMAK' + '-' + hex(24) + '-' + hex(34)],
  ['heroku-api-key', 'Heroku API key', 'HRKU' + '-AA' + alnum(58)],
  ['webhook-signing-secret', 'Webhook signing secret', 'whsec' + '_' + alnum(32)],
]

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-formats-'))
  roots.push(root)
  const all = { 'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}\n', ...files }
  for (const [path, content] of Object.entries(all)) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}

test('each new format is reported once on its own line with its provider name, and the excerpt is masked', async () => {
  const source = FORMATS.map(([, , value], i) => `export const k${i} = '${value}'`).join('\n') + '\n'
  const result = await scan(project({ 'lib/keys.ts': source }))
  const hits = result.findings.filter(f => f.ruleId.startsWith('secrets/hardcoded/'))
  assert.deepEqual(hits.map(f => [f.ruleId, f.line, f.title]),
    FORMATS.map(([id, name], i) => [`secrets/hardcoded/${id}`, i + 1, `${name} is hardcoded in your source code`]))
  for (const [index, hit] of hits.entries()) assert.ok(!hit.excerpt?.includes(FORMATS[index]![2]), `${hit.ruleId} excerpt is unmasked`)
})

test('templates, short values and prefixes embedded in longer words are not reported', async () => {
  const result = await scan(project({ 'lib/templates.ts': [
    `export const a = '${'gl' + 'pat-'}xxxxxxxxxxxxxxxxxxxx'`,
    `export const b = '${'dop' + '_v1_'}${'0'.repeat(64)}'`,
    `export const c = '${'whsec' + '_'}your_webhook_secret_here'`,
    `export const d = '${'lin' + '_api_'}${alnum(12)}'`,
    `export const e = 'my${'shp' + 'at_'}${hex(32)}'`,
    `export const f = '${'whsec' + '_'}${'x'.repeat(32)}'`,
  ].join('\n') + '\n' }))
  assert.deepEqual(result.findings.filter(f => f.ruleId.startsWith('secrets/')).map(f => [f.ruleId, f.line]), [])
})

test('a known new format in a public environment variable is reported as exposed', async () => {
  const result = await scan(project({ '.env.local': `NEXT_PUBLIC_STRIPE_WEBHOOK_SECRET=${'whsec' + '_' + alnum(32)}\nNEXT_PUBLIC_SENTRY_TOKEN=${'sntryu' + '_' + hex(64)}\n` }))
  assert.deepEqual(result.findings.filter(f => f.ruleId === 'exposure/secret-in-public-env').map(f => f.title), [
    'Your Webhook signing secret is exposed to the browser',
    'Your Sentry user auth token is exposed to the browser',
  ])
})

test('values in form placeholder attributes are example text, while other attributes on the same element are still reported', async () => {
  const key = 'sk' + '-proj-' + alnum(32)
  const result = await scan(project({ 'components/KeyInput.tsx': [
    `export const A = () => <input name="openai" placeholder="${key}" />`,
    `export const B = () => <input placeholder={'${key}'} />`,
    `export const C = () => <input placeholder="Paste your key" defaultValue="${key}" />`,
    `export const html = '<input placeholder="${'whsec' + '_' + alnum(32)}">'`,
  ].join('\n') + '\n' }))
  assert.deepEqual(result.findings.filter(f => f.ruleId.startsWith('secrets/')).map(f => [f.ruleId, f.line]),
    [['secrets/hardcoded/openai', 3]])
})
