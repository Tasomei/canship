/** 影响说明只覆盖已观察到的操作，不推断线上可利用性。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import { fingerprintOf } from '../src/baseline.js'
const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'canship-evidence-'))
  roots.push(root)
  for (const [path, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), text)
  }
  return root
}
test('RLS disabled later is not described as never enabled', async () => {
  const result = await scan(project({
    'supabase/migrations/001.sql': 'create table public.items(id int); alter table public.items enable row level security;',
    'supabase/migrations/002.sql': 'alter table public.items disable row level security;',
  }))
  const finding = result.findings.find(f => f.ruleId === 'supabase/rls-not-enabled')!
  assert.ok(finding)
  assert.match(finding.why.join(' '), /final recorded state/)
  assert.match(finding.why.join(' '), /later migration/)
  assert.doesNotMatch(finding.why.join(' '), /No .*ENABLE ROW LEVEL SECURITY.*appears anywhere/)
  assert.match(finding.why.join(' '), /dashboard/)
  assert.equal(fingerprintOf(finding), fingerprintOf({ ...finding, why: ['Changed presentation only.'] }))
})
test('open create access alone is not described as reading, changing and deleting every document', async () => {
  const result = await scan(project({ 'firestore.rules': 'service cloud.firestore { match /notes/{id} { allow create: if true; } }' }))
  const finding = result.findings.find(f => f.ruleId === 'firebase/open-rules')!
  assert.ok(finding)
  assert.match(finding.why.join(' '), /allowed create operations/)
  assert.doesNotMatch(finding.why.join(' '), /read every document|delete all/)
})
test('API wording separates unrecognised auth from verified public access', async () => {
  const result = await scan(project({
    'app/api/users/route.ts': "import { createClient } from '@supabase/supabase-js'; const db=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY); export async function GET(){ return Response.json(await db.from('users').select('*')); }",
  }))
  const finding = result.findings.find(f => f.ruleId === 'api/admin-db-access-without-auth')!
  assert.ok(finding)
  assert.match(finding.why.join(' '), /did not recognize an authentication guard/)
  assert.match(finding.why.join(' '), /If .*reachable without authentication/)
})
