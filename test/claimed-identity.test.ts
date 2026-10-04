/** 自定义的会话获取与凭据校验：只凭名称识别，须配合抛出、跳转或明确的 401/403；按 ID 查数据不算身份。 */

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
  const root = mkdtempSync(join(tmpdir(), 'canship-claimed-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return (await scan(root)).findings
}
const writes = (list: Finding[]) => list.filter(f => f.ruleId === 'api/db-write-without-auth').map(f => [f.file, f.line, f.title.startsWith('Review') ? 'review' : 'open'])

const route = (lookup: string, branch: string) => "import { db } from '@/lib/db'\nimport { validateSessionToken, getAccount, decodeJwt, lucia } from '@/lib/auth'\n" +
  `export async function DELETE(request: Request, { params }: { params: { id: string } }) {\n  ${lookup}\n  if (!session) ${branch}\n` +
  '  await db.item.delete({ where: { id: params.id } })\n  return new Response(null, { status: 204 })\n}\n'
const at = (list: Finding[]) => writes(list).map(([file, line]) => [file, line])
const FILE = 'app/api/items/[id]/route.ts'

describe('claimed identities from project session helpers', () => {
  test('a session validated by a project helper and rejected with 401 or a throw protects the write', async () => {
    const token = "const token = request.headers.get('cookie') ?? ''\n  const { session } = await validateSessionToken(token)"
    assert.deepEqual(at(await findings({ [FILE]: route(token, "return new Response('Unauthorized', { status: 401 })") })), [])
    assert.deepEqual(at(await findings({ [FILE]: route(token, "throw new Error('unauthorized')") })), [])
    assert.deepEqual(at(await findings({ [FILE]: route("const { session } = await lucia.validateSession(request.headers.get('x-session-id'))", "throw new Error('unauthorized')") })), [])
  })

  test('a branch that only returns an ordinary response is not a rejection', async () => {
    const token = "const { session } = await validateSessionToken(request.headers.get('cookie'))"
    assert.deepEqual(at(await findings({ [FILE]: route(token, 'return Response.json({ ok: false })') })), [[FILE, 6]])
  })

  test('lookups by route parameter or data id, and decoding without verification, are not identities', async () => {
    assert.deepEqual(at(await findings({ [FILE]: route('const session = await getAccount(params.id)', "throw new Error('missing')") })), [[FILE, 6]])
    assert.deepEqual(at(await findings({ [FILE]: route("const session = await getAccount(accountId)", "throw new Error('missing')") })), [[FILE, 6]])
    assert.deepEqual(at(await findings({ [FILE]: route("const session = decodeJwt(request.headers.get('authorization'))", "throw new Error('unauthorized')") })), [[FILE, 6]])
  })

  test('a Remix requireUserId helper built on getUserId(request) is recognised as an indirect guard', async () => {
    const list = await findings({
      'app/session.server.ts': "import { redirect } from '@remix-run/node'\nexport async function requireUserId(request: Request) {\n" +
        "  const userId = await getUserId(request)\n  if (!userId) throw redirect('/login')\n  return userId\n}\n",
      'app/db.server.ts': "import { PrismaClient } from '@prisma/client'\nexport const prisma = new PrismaClient()\n",
      'app/routes/notes.$noteId.tsx': "import { requireUserId } from '~/session.server'\nimport { prisma } from '~/db.server'\n" +
        'export async function action({ request, params }) {\n  const userId = await requireUserId(request)\n' +
        '  await prisma.note.deleteMany({ where: { id: params.noteId, userId } })\n  return null\n}\n',
    })
    assert.deepEqual(writes(list), [['app/routes/notes.$noteId.tsx', 5, 'review']])
  })
})
