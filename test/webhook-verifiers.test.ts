/** 非 Stripe 的 webhook 验签：抛错类按导入来源识别，布尔类须 await 并明确拒绝。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

async function findings(files: Record<string, string>): Promise<Finding[]> {
  const root = mkdtempSync(join(tmpdir(), 'canship-webhook-verify-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return (await scan(root)).findings
}
const FILE = 'app/api/webhooks/route.ts'
const writes = async (source: string) => (await findings({ [FILE]: source }))
  .filter(f => f.ruleId === 'api/db-write-without-auth').map(f => f.line)

const DB = "import { db } from '@/lib/db'\n"
const handler = (imports: string, verify: string) => DB + imports +
  `export async function POST(request: Request) {\n  const body = await request.text()\n${verify}  await db.subscription.deleteMany({})\n  return new Response(null, { status: 202 })\n}\n`

describe('webhook signature verification counts as authentication', () => {
  test('Polar validateEvent, including an alias, protects the write', async () => {
    assert.deepEqual(await writes(handler("import { validateEvent } from '@polar-sh/sdk/webhooks'\n",
      "  validateEvent(body, Object.fromEntries(request.headers), process.env.POLAR_WEBHOOK_SECRET ?? '')\n")), [])
    assert.deepEqual(await writes(handler("import { validateEvent as validatePolarEvent } from '@polar-sh/sdk/webhooks'\n",
      "  const event = validatePolarEvent(body, Object.fromEntries(request.headers), process.env.POLAR_WEBHOOK_SECRET ?? '')\n")), [])
  })

  test('Clerk verifyWebhook protects the write when awaited', async () => {
    assert.deepEqual(await writes(handler("import { verifyWebhook } from '@clerk/nextjs/webhooks'\n", '  const evt = await verifyWebhook(request)\n')), [])
  })

  test('a Svix Webhook instance verify protects the write', async () => {
    assert.deepEqual(await writes(handler("import { Webhook } from 'svix'\n",
      "  const wh = new Webhook(process.env.SVIX_SECRET!)\n  const evt = wh.verify(body, Object.fromEntries(request.headers))\n")), [])
  })

  test('an awaited boolean signature check with a 401 protects the write; without await it does not', async () => {
    const receiver = "import { Receiver } from '@upstash/qstash'\nconst receiver = new Receiver({ currentSigningKey: process.env.QSTASH_CURRENT!, nextSigningKey: process.env.QSTASH_NEXT! })\n"
    const check = (awaited: boolean) => `  const isValid = ${awaited ? 'await ' : ''}receiver.verify({ signature: request.headers.get('upstash-signature') ?? '', body })\n` +
      "  if (!isValid) return new Response('Unauthorized', { status: 401 })\n"
    assert.deepEqual(await writes(handler(receiver, check(true))), [])
    // 未 await 时 isValid 是 Promise，恒为真值，校验不会拒绝任何请求。
    assert.deepEqual(await writes(handler(receiver, check(false))), [8])
  })

  test('a project function with the same name is not a webhook verifier', async () => {
    assert.deepEqual(await writes(handler("import { validateEvent } from '@/lib/calendar'\n", '  validateEvent(JSON.parse(body))\n')), [6])
  })
})
