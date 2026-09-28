import { test } from 'node:test'
import assert from 'node:assert/strict'
import { firebaseRulesRule } from '../src/rules/firebase.js'
import { supabaseRlsRule } from '../src/rules/supabase.js'
import type { ScanFile, ScanContext } from '../src/types.js'

function context(path: string, content: string): ScanContext {
  const file: ScanFile = { path, content, lines: content.split('\n'), isExampleContext: false }
  return { root: '', files: [file], git: 'not-a-repo', gitExecutable: null,
    reportIncomplete: () => assert.fail('unexpected incomplete scan') }
}

for (const ops of [['.read'], ['.write'], ['.read', '.write']]) {
  test(`Realtime Database advice targets ${ops.join(' and ')}`, () => {
    const ctx = context('database.rules.json', JSON.stringify({ rules: Object.fromEntries(ops.map(op => [op, true])) }))
    const findings = firebaseRulesRule.check(ctx.files[0]!, ctx)
    assert.equal(findings.length, 1)
    const advice = findings[0]!.fix[0]!
    for (const op of ['.read', '.write']) assert.equal(advice.includes(op), ops.includes(op))
  })
}

for (const condition of ['true', 'request.time < timestamp.date(2099, 1, 1)']) {
  for (const op of ['create', 'update', 'delete']) {
    test(`Firestore ${op} advice uses the appropriate document state: ${condition}`, () => {
      const ctx = context('firestore.rules', `service cloud.firestore { match /documents/{id} { allow ${op}: if ${condition}; } }`)
      const findings = firebaseRulesRule.check(ctx.files[0]!, ctx)
      assert.equal(findings.length, 1)
      const advice = findings[0]!.fix[0]!
      assert.match(advice, /request.auth != null/)
      if (op === 'create') {
        assert.match(advice, /request\.resource\.data\.userId == request\.auth\.uid/)
        assert.doesNotMatch(advice, /(?<!request\.)resource\.data/)
      } else if (op === 'update') {
        assert.match(advice, /resource\.data\.userId == request\.auth\.uid/)
        assert.match(advice, /request\.resource\.data\.userId == resource\.data\.userId/)
      } else {
        assert.match(advice, /resource\.data\.userId == request\.auth\.uid/)
        assert.doesNotMatch(advice, /request\.resource/)
      }
      assert.doesNotMatch(advice, /allow read, write/)
    })
  }
}

test('Storage advice does not use Firestore document fields', () => {
  const ctx = context('storage.rules', 'service firebase.storage { match /files/{id} { allow write: if true; } }')
  const findings = firebaseRulesRule.check(ctx.files[0]!, ctx)
  assert.equal(findings.length, 1)
  assert.doesNotMatch(findings[0]!.fix[0]!, /resource\.data/)
  assert.match(findings[0]!.fix[0]!, /matched path or trusted metadata/)
})

for (const op of ['insert', 'select', 'delete', 'update', 'all']) {
  test(`Postgres ${op} advice only uses supported policy clauses`, async () => {
    const condition = op === 'insert' ? 'with check (true)' : 'using (true)'
    const ctx = context('supabase/migrations/001.sql',
      `create table public.posts (user_id uuid); alter table public.posts enable row level security;
       create policy open_rows on public.posts for ${op} ${condition};`)
    const finding = (await supabaseRlsRule.check(ctx)).find(f => f.ruleId === 'supabase/permissive-policy')
    assert.ok(finding)
    assert.equal(finding.fix[0]!.includes('USING'), op !== 'insert')
    assert.equal(finding.fix[0]!.includes('WITH CHECK'), ['insert', 'update', 'all'].includes(op))
  })
}
