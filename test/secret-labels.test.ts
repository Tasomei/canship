/** 多家共用前缀的凭据按周边代码确定提供方；无法确定时使用中性名称和通用轮换说明。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan, listRules } from '../src/index.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

// 运行时拼接模拟凭据，避免源码中出现完整凭据形态。
const LIVE = 'sk' + '_live_' + 'Q7wE9rT2yU4iO6pA8sD0fG1hJ3kL5zX7cV9bN2mQ4'
const RESTRICTED = 'rk' + '_live_' + 'Q7wE9rT2yU4iO6pA8sD0fG1hJ3kL5zX7cV9bN2mQ4'
const DASH = 'sk' + '-' + '3f9a1c7e5b2d4f6a8c0e1b3d5f7a9c2e'
const PROJECT = 'sk' + '-proj-' + 'Hq4Wm8Xr2Tz6Kc9Lp3Vn7Bd5Fs1Jg0Ya'

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-labels-'))
  roots.push(root)
  const all = { 'package.json': '{"name":"x","dependencies":{"next":"15.0.0"}}\n', ...files }
  for (const [path, content] of Object.entries(all)) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return root
}

async function hits(files: Record<string, string>, prefix: RegExp) {
  const result = await scan(project(files))
  return result.findings.filter(f => prefix.test(f.ruleId)).map(f => ({
    rule: f.ruleId, title: f.title, rotate: f.humanOnly?.join(' ') ?? '', why: f.why.join(' '),
  }))
}

describe('sk_live_ keys shared by Stripe and Clerk', () => {
  test('nearby code names the provider; restricted keys stay Stripe; no or conflicting evidence stays neutral', async () => {
    const found = await hits({
      'lib/clerk.ts': `import { createClerkClient } from '@clerk/backend'\nexport const clerk = createClerkClient({ secretKey: '${LIVE}' })\n`,
      'lib/stripe.ts': `import Stripe from 'stripe'\nexport const stripe = new Stripe('${LIVE}')\n`,
      'lib/billing.ts': `export const key = '${LIVE}'\n`,
      'lib/restricted.ts': `// clerk webhook helper\nexport const key = '${RESTRICTED}'\n`,
      'lib/both.ts': `import Stripe from 'stripe'\nimport { clerkClient } from '@clerk/nextjs/server'\nexport const key = '${LIVE}'\n`,
    }, /^secrets\/hardcoded\//)
    const byTitle = found.map(f => [f.rule, f.title])
    assert.deepEqual(byTitle.sort(), [
      ['secrets/hardcoded/stripe-live', 'Clerk secret key is hardcoded in your source code'],
      ['secrets/hardcoded/stripe-live', 'Stripe live secret key is hardcoded in your source code'],
      ['secrets/hardcoded/stripe-live', 'Stripe live secret key is hardcoded in your source code'],
      ['secrets/hardcoded/stripe-live', 'sk_live_ secret key is hardcoded in your source code'],
      ['secrets/hardcoded/stripe-live', 'sk_live_ secret key is hardcoded in your source code'],
    ])
    const clerk = found.find(f => f.title.startsWith('Clerk'))!
    assert.match(clerk.rotate, /dashboard\.clerk\.com/)
    assert.doesNotMatch(clerk.rotate + clerk.why, /stripe/i)
    const neutral = found.find(f => f.title.startsWith('sk_live_'))!
    assert.match(neutral.rotate, /dashboard\.stripe\.com.*dashboard\.clerk\.com/)
  })
})

describe('sk- keys shared by OpenAI and compatible providers', () => {
  test('DeepSeek and other base URLs win over the OpenAI SDK name; OpenAI-only prefixes stay OpenAI', async () => {
    const found = await hits({
      'lib/deepseek.ts': `import OpenAI from 'openai'\nexport const client = new OpenAI({\n  baseURL: 'https://api.deepseek.com',\n  apiKey: '${DASH}',\n})\n`,
      'lib/compatible.ts': `import OpenAI from 'openai'\nexport const client = new OpenAI({ apiKey: '${DASH}',\n  baseURL: 'https://llm.example.net/v1' })\n`,
      'lib/openai.ts': `import OpenAI from 'openai'\nexport const client = new OpenAI({ apiKey: '${DASH}' })\n`,
      'lib/plain.ts': `export const key = '${DASH}'\n`,
      'lib/project.ts': `// deepseek fallback\nexport const key = '${PROJECT}'\n`,
    }, /^secrets\/hardcoded\//)
    assert.deepEqual(found.map(f => [f.rule, f.title]).sort(), [
      ['secrets/hardcoded/openai', 'API key for an OpenAI-compatible service is hardcoded in your source code'],
      ['secrets/hardcoded/openai', 'DeepSeek API key is hardcoded in your source code'],
      ['secrets/hardcoded/openai', 'OpenAI API key is hardcoded in your source code'],
      ['secrets/hardcoded/openai', 'OpenAI API key is hardcoded in your source code'],
      ['secrets/hardcoded/openai', 'OpenAI-style API key is hardcoded in your source code'],
    ])
    const deepseek = found.find(f => f.title.startsWith('DeepSeek'))!
    assert.match(deepseek.rotate, /platform\.deepseek\.com/)
    assert.doesNotMatch(deepseek.rotate, /openai/i)
    assert.match(found.find(f => f.title.startsWith('OpenAI-style'))!.rotate, /provider that issued it/)
  })
})

describe('public environment variables', () => {
  test('the variable name decides the provider before other entries in the file', async () => {
    const found = await hits({
      '.env.local': `STRIPE_WEBHOOK_URL=https://shop.example.com/api/stripe\nNEXT_PUBLIC_CLERK_SECRET_KEY=${LIVE}\nNEXT_PUBLIC_DEEPSEEK_API_KEY=${DASH}\nNEXT_PUBLIC_OPENAI_API_KEY=${DASH}\nNEXT_PUBLIC_PAYMENTS_KEY=${LIVE}\n`,
    }, /^exposure\/secret-in-public-env$/)
    assert.deepEqual(found.map(f => f.title), [
      'Your Clerk secret key is exposed to the browser',
      'Your DeepSeek API key is exposed to the browser',
      'Your OpenAI API key is exposed to the browser',
      'Your sk_live_ secret key is exposed to the browser',
    ])
  })
})

test('the rule catalogue names every provider a shared format can belong to', () => {
  const names = new Map(listRules().map(rule => [rule.id, rule]))
  assert.equal(names.get('secrets/hardcoded/stripe-live')?.name, 'Stripe or Clerk live secret key')
  assert.equal(names.get('secrets/hardcoded/openai')?.name, 'OpenAI or OpenAI-compatible API key')
  assert.match(names.get('secrets/hardcoded/openai')?.limitation ?? '', /nearby code identifies it/)
  assert.doesNotMatch(names.get('secrets/hardcoded/anthropic')?.limitation ?? '', /shared by several providers/)
})
