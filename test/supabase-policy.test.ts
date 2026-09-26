/** 验证 Supabase 过宽策略与可枚举公开存储桶：判断标准对应官方检查规则 0024 与 0025，并按迁移顺序重放。 */
import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding } from '../src/types.js'
import { isAlwaysTrue } from '../src/rules/sqlpolicy.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

const TABLE = 'create table public.posts (id bigint primary key, user_id uuid);\nalter table public.posts enable row level security;\n'

async function policyFindings(migrations: Record<string, string>, extra: Record<string, string> = {}): Promise<Finding[]> {
  const root = mkdtempSync(join(tmpdir(), 'canship-policy-'))
  roots.push(root)
  const files = {
    'package.json': '{"dependencies":{"@supabase/supabase-js":"2"}}',
    ...Object.fromEntries(Object.entries(migrations).map(([name, sql]) => [`supabase/migrations/${name}`, sql])),
    ...extra,
  }
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true })
    writeFileSync(join(root, path), content)
  }
  const { findings } = await scan(root)
  return findings.filter((f) => f.ruleId === 'supabase/permissive-policy' || f.ruleId === 'supabase/public-bucket-listing')
}

const summary = (findings: Finding[]): string[] => findings.map((f) => `${f.ruleId} ${f.confidence} L${f.line}`)

describe('always-true expressions', () => {
  for (const expression of ['true', ' ( TRUE ) ', '1=1', '1 = 1', "'a'='a'", '(true) -- open']) {
    test(`${expression.trim()} is always true`, () => assert.equal(isAlwaysTrue(expression), true))
  }
  for (const expression of ['auth.uid() = user_id', '1=2', "'a'='b'", 'true and auth.uid() = user_id', 'false']) {
    test(`${expression} is not`, () => assert.equal(isAlwaysTrue(expression), false))
  }
})

describe('permissive policies', () => {
  test('update using (true) is certain', async () => {
    const found = await policyFindings({ '1_init.sql': TABLE + 'create policy "edit" on public.posts for update using (true);\n' })
    assert.deepEqual(summary(found), ['supabase/permissive-policy certain L3'])
    assert.match(found[0]!.title, /anyone, signed in or not, change every row of public\.posts/)
  })

  test('the documented example: select to authenticated using (true) is likely', async () => {
    const found = await policyFindings({
      '1_init.sql': TABLE + 'create policy "allow_all_select"\non public.posts\nfor select\nto authenticated\nusing (true);\n',
    })
    assert.deepEqual(summary(found), ['supabase/permissive-policy likely L3'])
    assert.match(found[0]!.title, /any signed-in user read every row/)
  })

  test('insert with check (true) is likely', async () => {
    assert.deepEqual(summary(await policyFindings({
      '1_init.sql': TABLE + "create policy \"signup\" on posts for insert to anon with check ('a' = 'a');\n",
    })), ['supabase/permissive-policy likely L3'])
  })

  test('a policy with no FOR clause applies to all commands', async () => {
    assert.deepEqual(summary(await policyFindings({ '1_init.sql': TABLE + 'create policy open on posts using (1=1);\n' })),
      ['supabase/permissive-policy certain L3'])
  })

  test('owner-scoped, restrictive and service-role policies are not reported', async () => {
    assert.deepEqual(await policyFindings({
      '1_init.sql': TABLE +
        'create policy own on posts for update using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);\n' +
        'create policy limit_rows on posts as restrictive for select to authenticated using (true);\n' +
        'create policy backend on posts for all to service_role using (true);\n',
    }), [])
  })

  test('a later migration that drops the policy clears it', async () => {
    assert.deepEqual(await policyFindings({
      '1_init.sql': TABLE + 'create policy "edit" on posts for delete using (true);\n',
      '2_fix.sql': 'drop policy if exists "edit" on public.posts;\n',
    }), [])
  })

  test('a later alter policy that narrows the condition clears it', async () => {
    assert.deepEqual(await policyFindings({
      '1_init.sql': TABLE + 'create policy "edit" on posts for update using (true);\n',
      '2_fix.sql': 'alter policy "edit" on posts using (auth.uid() = user_id);\n',
    }), [])
  })

  test('a renamed policy is still the same policy', async () => {
    const found = await policyFindings({
      '1_init.sql': TABLE + 'create policy "edit" on posts for update using (true);\n',
      '2_rename.sql': 'alter policy "edit" on posts rename to "edit anything";\n',
    })
    assert.equal(found.length, 1)
    assert.match(found[0]!.title, /"edit anything"/)
  })

  test('a policy follows its table through a rename', async () => {
    const found = await policyFindings({
      '1_init.sql': TABLE + 'create policy "edit" on posts for update using (true);\n',
      '2_rename.sql': 'alter table posts rename to articles;\n',
    })
    assert.match(found[0]?.title ?? '', /public\.articles/)
  })

  test('dropping the table removes its policies', async () => {
    assert.deepEqual(await policyFindings({
      '1_init.sql': TABLE + 'create policy "edit" on posts for update using (true);\n',
      '2_drop.sql': 'drop table posts;\n',
    }), [])
  })

  test('a table without RLS is left to the rls-not-enabled finding', async () => {
    assert.deepEqual(await policyFindings({
      '1_init.sql': 'create table posts (id bigint);\ncreate policy "edit" on posts for update using (true);\n',
    }), [])
  })

  test('a policy name or comment that looks like a condition is not one', async () => {
    assert.deepEqual(await policyFindings({
      '1_init.sql': TABLE + "-- create policy x on posts for update using (true);\ncreate policy \"using (true)\" on posts for update using (auth.uid() = user_id);\n",
    }), [])
  })

  test('outside a Supabase project the rule stays silent', async () => {
    const root = mkdtempSync(join(tmpdir(), 'canship-policy-plain-'))
    roots.push(root)
    writeFileSync(join(root, 'schema.sql'), TABLE + 'create policy "edit" on posts for update using (true);\n')
    const { findings } = await scan(root)
    assert.deepEqual(findings.filter((f) => f.ruleId.startsWith('supabase/')), [])
  })
})

describe('public buckets that can be listed', () => {
  const PUBLIC = "insert into storage.buckets (id, name, public)\nvalues ('avatars', 'avatars', true);\n"

  test('the documented example is reported', async () => {
    const found = await policyFindings({
      '1_storage.sql': PUBLIC + 'create policy "Public bucket listing"\non storage.objects\nfor select\nto authenticated\nusing (bucket_id = \'avatars\');\n',
    })
    assert.deepEqual(summary(found), ['supabase/public-bucket-listing certain L3'])
    assert.match(found[0]!.title, /"avatars" bucket/)
  })

  test('a private bucket with the same policy is not reported', async () => {
    assert.deepEqual(await policyFindings({
      '1_storage.sql': "insert into storage.buckets (id, name) values ('avatars', 'avatars');\n" +
        "create policy \"list\" on storage.objects for select using (bucket_id = 'avatars');\n",
    }), [])
  })

  test('a bucket made private later is not reported', async () => {
    assert.deepEqual(await policyFindings({
      '1_storage.sql': PUBLIC + "create policy \"list\" on storage.objects for select using (bucket_id = 'avatars');\n",
      '2_private.sql': "update storage.buckets set public = false where id = 'avatars';\n",
    }), [])
  })

  test('a policy scoped to the owner does not make the bucket listable', async () => {
    assert.deepEqual(await policyFindings({
      '1_storage.sql': PUBLIC + "create policy \"own\" on storage.objects for select using (bucket_id = 'avatars' and owner_id = (select auth.uid()::text));\n",
    }), [])
  })

  test('a public bucket declared in supabase/config.toml counts', async () => {
    const found = await policyFindings(
      { '1_storage.sql': "create policy \"list\" on storage.objects for select using (bucket_id = 'images');\n" },
      { 'supabase/config.toml': '[storage.buckets.images]\npublic = true\nfile_size_limit = "50MiB"\n' },
    )
    assert.deepEqual(found.map((f) => f.ruleId), ['supabase/public-bucket-listing'])
  })

  test('a public bucket with no listing policy is not reported', async () => {
    assert.deepEqual(await policyFindings({ '1_storage.sql': PUBLIC }), [])
  })
})

describe('policy parsing stays linear', () => {
  test('many policies and table drops', async () => {
    const sql = Array.from({ length: 4000 }, (_, i) =>
      `create table t${i} (id int);\nalter table t${i} enable row level security;\ncreate policy p${i} on t${i} for select using (auth.uid() is not null);\n`).join('') +
      Array.from({ length: 4000 }, (_, i) => `drop table t${i};\n`).join('')
    const started = performance.now()
    assert.deepEqual(await policyFindings({ '1_many.sql': sql }), [])
    assert.ok(performance.now() - started < 10_000)
  })

  test('create policy without a terminating semicolon', async () => {
    const started = performance.now()
    await policyFindings({ '1_broken.sql': TABLE + 'create policy p on posts using ('.repeat(20_000) })
    assert.ok(performance.now() - started < 10_000)
  })
})
