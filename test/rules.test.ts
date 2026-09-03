/**
 * Rule tests.
 *
 * canship-ignore-file
 *
 * The marker above opts this file out of canship's own scan: it holds fake
 * credentials as assertion data. It has to sit on a line of its own — a
 * mention in passing does not count, which is what stops a stray word in a
 * comment from blindfolding a file.
 *
 * The fixtures under fixtures/ carry no marker, and must not: the tests point
 * canship at them as project roots and expect the findings.
 *
 * Deliberately split into two groups:
 *   1. the vulnerable fixture — everything that should be caught, is (misses)
 *   2. the clean fixture      — nothing that should be left alone, is flagged
 *
 * The second group is the important one. A missed finding costs the user one
 * favour; a false positive costs their trust permanently, and they will tell
 * other people the tool is noisy. So the clean fixture is packed with patterns
 * that look dangerous but are in fact correct.
 */

import { test, describe, after } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { cpSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { execFileSync } from 'node:child_process'
import type { Finding } from '../src/types.js'
import { scan } from '../src/engine.js'
import { renderFixPrompt } from '../src/report/prompt.js'
import { renderHtml } from '../src/report/html.js'
import { renderReport } from '../src/report/terminal.js'
import { redactSecret, redactAll } from '../src/redact.js'
import {
  isSupabaseServiceRole,
  nameWords,
  looksClearlyPrivate,
  looksIntentionallyPublic,
} from '../src/rules/framework.js'
import { isPlaceholder } from '../src/rules/patterns.js'
import { hasGitMetadataAbove } from '../src/git.js'

const here = dirname(fileURLToPath(import.meta.url))

/** Temporary parents of the fixture copies, removed once the file's tests finish */
const fixtureCopies: string[] = []

/**
 * A fixture, copied out of this repository before anything scans it.
 *
 * A fixture scanned where it lives inherits the git state of the repository
 * around it, and that is not a property these tests are written to assert.
 * `clean-nextjs` holds a committed `.env.local` — it has to, since that file is
 * what several rules are exercised against — so the moment canship itself
 * gained a first commit, the git-tracked-env rule fired on it and the *clean*
 * fixture stopped being clean. Seven tests broke at once, having passed until
 * then only because this project had never been committed. CI found it on the
 * first run, which is exactly the shape of bug a local suite cannot see.
 *
 * Copying to a directory outside any repository restores what the fixtures are
 * for: a result that is a fact about the fixture, not about where it is kept.
 */
function fixture(name: string): string {
  const parent = mkdtempSync(join(tmpdir(), 'canship-fixture-'))
  fixtureCopies.push(parent)
  const target = join(parent, name)
  cpSync(join(here, 'fixtures', name), target, { recursive: true })
  return target
}

after(() => {
  for (const parent of fixtureCopies) rmSync(parent, { recursive: true, force: true })
})

const VULNERABLE = fixture('vulnerable-nextjs')
const CLEAN = fixture('clean-nextjs')
const PLAIN_POSTGRES = fixture('plain-postgres')
const MIDDLEWARE_PROTECTED = fixture('middleware-protected')

describe('the fixtures are scanned as themselves', () => {
  test('no fixture copy sits inside a git repository', () => {
    // Guards the property, not the mechanism: pointing the constants back at
    // test/fixtures/ fails here, and so does a machine whose temporary
    // directory happens to live under a checkout — the second is the version
    // nobody would think to look for.
    for (const [name, path] of Object.entries({
      CLEAN,
      VULNERABLE,
      PLAIN_POSTGRES,
      MIDDLEWARE_PROTECTED,
    })) {
      assert.equal(
        hasGitMetadataAbove(path),
        false,
        `${name} is inside a git repository, so what canship reports about it is partly a fact about that repository`,
      )
    }
  })
})

/**
 * Build a throwaway git repository with the given files committed.
 *
 * The git-history rule cannot be tested against a fixture directory: it asks
 * git what is tracked, and a fixture inside this repository is tracked by
 * *this* repository, not by itself. Real repositories are the only way to
 * exercise it — which is why it went untested long enough to produce four
 * false positives on well-known starters.
 */
function withGitRepo(files: Record<string, string>, run: (root: string) => Promise<void>): Promise<void> {
  const root = mkdtempSync(join(tmpdir(), 'canship-git-'))
  const git = (...args: string[]): void => {
    execFileSync('git', args, { cwd: root, stdio: 'ignore' })
  }
  try {
    git('init', '-q')
    for (const [rel, body] of Object.entries(files)) {
      const abs = join(root, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, body, 'utf8')
    }
    git('add', '-A')
    execFileSync(
      'git',
      ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'init'],
      { cwd: root, stdio: 'ignore' },
    )
    return run(root).finally(() => {
      // Windows keeps git's pack files read-only; a failed cleanup of a temp
      // directory must not fail the test.
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    })
  } catch (err) {
    try {
      rmSync(root, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
    throw err
  }
}


describe('vulnerable fixture — everything that should be caught', () => {
  test('detects a service_role key exposed to the browser', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.filter((f) => f.ruleId === 'exposure/supabase-service-role-in-client')
    assert.ok(hit.length >= 1, 'missed NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY')
    assert.equal(hit[0]!.confidence, 'certain')
    assert.equal(hit[0]!.severity, 'P0')
  })

  test('detects a Stripe live key exposed to the browser', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find(
      (f) => f.ruleId === 'exposure/secret-in-public-env' && f.title.includes('Stripe'),
    )
    assert.ok(hit, 'missed NEXT_PUBLIC_STRIPE_SECRET_KEY')
    assert.equal(hit.confidence, 'certain')
  })

  test('detects an OpenAI key hardcoded in source', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'secrets/hardcoded/openai')
    assert.ok(hit, 'missed the hardcoded key in app/page.tsx')
    assert.equal(hit.file, 'app/page.tsx')
    assert.equal(hit.confidence, 'certain')
  })

  test('says "readable in the browser" for client code, not just "in source"', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'secrets/hardcoded/openai')
    assert.ok(hit)
    // app/page.tsx carries 'use client', so the severity wording has to reflect
    // that any visitor can read the key right now.
    assert.match(hit.title, /browser/i, 'title does not reflect that this is client code')
    assert.match(hit.why.join('\n\n'), /sent to the browser|dev tools/i, 'body does not say visitors can read it')
  })

  test('detects a database connection string with a password', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'secrets/hardcoded/db-connection-string')
    assert.ok(hit, 'missed the connection string in lib/db.ts')
    assert.equal(hit.file, 'lib/db.ts')
  })

  test('does not flag OPENAI_API_KEY in .env without a public prefix', async () => {
    const { findings } = await scan(VULNERABLE)
    const wrong = findings.find((f) => f.file === '.env.local' && f.excerpt?.includes('OPENAI_API_KEY'))
    assert.equal(wrong, undefined, 'a server-side secret in .env is correct usage')
  })

  test('does not flag the anon key', async () => {
    const { findings } = await scan(VULNERABLE)
    const wrong = findings.find((f) => f.excerpt?.includes('ANON_KEY'))
    assert.equal(wrong, undefined, 'the anon key is public by design')
  })

  test('never prints a complete secret', async () => {
    const { findings } = await scan(VULNERABLE)
    const serialized = JSON.stringify(findings)
    // These are the full fake secrets from the fixture. Not one of them may
    // appear verbatim in the report.
    const rawSecrets = [
      'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn',
      'sk_live_51H8xQ2KZvKuab1cdEfGhIjKlMnOpQr',
      'sup3rS3cretPw',
      'ghp_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn123',
      'sb_secret_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn',
    ]
    for (const secret of rawSecrets) {
      assert.ok(
        !serialized.includes(secret),
        `the report leaked the full secret ${secret.slice(0, 10)}… — users screenshot this output`,
      )
    }
  })
})

describe('clean fixture — nothing should be flagged (false positives)', () => {
  test('no certain-confidence findings', async () => {
    const { findings } = await scan(CLEAN)
    const certain = findings.filter((f) => f.confidence === 'certain')
    assert.deepEqual(
      certain.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`),
      [],
      'false positives on a project where every pattern is correct',
    )
  })

  test('none even at likely confidence', async () => {
    const { findings } = await scan(CLEAN)
    assert.deepEqual(
      findings.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`),
      [],
      'the clean fixture should not even produce low-confidence findings',
    )
  })
})

describe('Supabase Row Level Security', () => {
  test('flags tables created without RLS', async () => {
    const { findings } = await scan(VULNERABLE)
    const hits = findings.filter((f) => f.ruleId === 'supabase/rls-not-enabled')
    const tables = hits.map((f) => /"([^"]+)"/.exec(f.title)?.[1]).sort()
    assert.deepEqual(tables, ['invoices', 'orders', 'profiles'], 'wrong set of unsecured tables')
  })

  test('does not flag a table that is secured later in the file', async () => {
    const { findings } = await scan(VULNERABLE)
    const audit = findings.find((f) => f.title.includes('audit_log'))
    assert.equal(audit, undefined, 'audit_log has ENABLE ROW LEVEL SECURITY')
  })

  test('ignores commented-out CREATE TABLE', async () => {
    const { findings } = await scan(VULNERABLE)
    const draft = findings.find((f) => f.title.includes('draft_table'))
    assert.equal(draft, undefined, 'commented-out DDL is not a real table')
  })

  test('states the observable fact, not an absolute claim', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'supabase/rls-not-enabled')
    assert.ok(hit)
    // People toggle RLS in the dashboard, which leaves no trace in the repo.
    // The wording has to stay accurate about what was actually observed.
    assert.match(hit.title, /in your migrations/i, 'title overclaims')
    assert.match(hit.why.join('\n\n'), /dashboard/i, 'does not mention the dashboard caveat')
  })

  test('clean fixture: all tables secured, nothing reported', async () => {
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.ruleId === 'supabase/rls-not-enabled')
    assert.deepEqual(hits.map((f) => f.title), [], 'false positive on correctly secured tables')
  })

  test('does NOT run on a plain Postgres project', async () => {
    // The important one. RLS is only required when the database is exposed to
    // the browser. Flagging an ordinary backend would be a serious false
    // positive.
    const { findings } = await scan(PLAIN_POSTGRES)
    const hits = findings.filter((f) => f.ruleId === 'supabase/rls-not-enabled')
    assert.deepEqual(
      hits.map((f) => f.title),
      [],
      'reported RLS on a project that does not use Supabase',
    )
  })
})

describe('Firebase security rules', () => {
  test('flags "if true" rules', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'firebase/open-rules')
    assert.ok(hit, 'missed allow read, write: if true')
    assert.equal(hit.confidence, 'certain')
    assert.match(hit.title, /read and write/i)
  })

  test('flags test-mode rules with a hardcoded expiry', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'firebase/test-mode-rules')
    assert.ok(hit, 'missed the request.time < timestamp.date(...) rule')
    assert.match(hit.title, /2027-06-01/)
  })

  test('does not flag rules with a real auth check', async () => {
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.ruleId.startsWith('firebase/'))
    assert.deepEqual(hits.map((f) => f.title), [], 'false positive on correctly scoped rules')
  })

  test('does not flag "allow read: if true" paired with "allow write: if false"', async () => {
    // Deliberately public read-only data is a legitimate pattern.
    const { findings } = await scan(CLEAN)
    const hit = findings.find((f) => f.excerpt?.includes('allow read: if true'))
    assert.equal(hit, undefined, 'public read-only data is a valid choice')
  })
})

describe('API routes with no authorisation check', () => {
  test('flags a route that queries as admin with nothing checking the caller', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find(
      (f) => f.ruleId === 'api/admin-db-access-without-auth' && f.file === 'app/api/users/route.ts',
    )
    assert.ok(hit, 'missed app/api/users/route.ts')
    assert.equal(hit.confidence, 'certain')
    assert.equal(hit.severity, 'P0')
  })

  test('follows the import into the admin client module', async () => {
    // The route file itself contains no service_role reference — it imports
    // supabaseAdmin from lib/. Looking only inside route files would miss
    // nearly every real project, because that is the shape every Supabase
    // tutorial teaches.
    const { findings } = await scan(VULNERABLE)
    const route = (await import('node:fs')).readFileSync(
      join(VULNERABLE, 'app', 'api', 'users', 'route.ts'),
      'utf8',
    )
    assert.ok(!/SERVICE_ROLE/.test(route), 'fixture no longer tests cross-file resolution')
    const hit = findings.find(
      (f) => f.ruleId === 'api/admin-db-access-without-auth' && f.file === 'app/api/users/route.ts',
    )
    assert.ok(hit, 'did not resolve the admin client through the import')
  })

  test('names the URL, not the file path', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find(
      (f) => f.ruleId === 'api/admin-db-access-without-auth' && f.file === 'app/api/users/route.ts',
    )
    assert.ok(hit)
    assert.match(hit.title, /\/api\/users/, 'the title should say what to curl')
    assert.match(hit.excerpt ?? '', /\.from\('profiles'\)/, 'excerpt should show the query')
  })

  test('flags an unauthenticated destructive write at lower confidence', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'api/db-write-without-auth')
    assert.ok(hit, 'missed the prisma delete in app/api/posts/[id]/route.ts')
    // Not certain: an open write can be deliberate, and protection can live in
    // a proxy this scan cannot see.
    assert.equal(hit.confidence, 'likely')
    assert.equal(hit.severity, 'P1')
  })

  test('is not silenced by middleware whose matcher excludes /api', async () => {
    // The regression test that matters most here. The vulnerable fixture ships
    // the matcher printed in the Next.js documentation:
    //   matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)']
    // It authenticates every page and no API route at all. Reading it as
    // "there is auth middleware, so the API is covered" would silence every
    // finding in this fixture.
    const { findings } = await scan(VULNERABLE)
    const hits = findings.filter((f) => f.ruleId.startsWith('api/'))
    assert.equal(hits.length, 3, 'the excluding matcher was misread as protection')
  })

  test('does not flag a route that identifies the caller first', async () => {
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.startsWith('app/api/chat'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on a route that checks the session')
  })

  test('does not flag a route that touches no data', async () => {
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.startsWith('app/api/health'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'an unauthenticated route with no query is not a finding')
  })

  test('treats webhook signature verification as a real authorisation check', async () => {
    // A webhook cannot have a sign-in check — Stripe is not signed in. It
    // authenticates the caller by verifying the signature instead.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.includes('webhooks'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on a signature-verified webhook')
  })

  test('does not flag a route that middleware protects', async () => {
    // The route in this fixture is indistinguishable from the vulnerable one:
    // admin client, whole table, no check of its own. It is safe only because
    // middleware.ts covers /api/:path*. Protection living outside the file it
    // protects is the biggest false-positive risk this rule carries.
    const { findings } = await scan(MIDDLEWARE_PROTECTED)
    assert.deepEqual(
      findings.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`),
      [],
      'reported a route that middleware already authenticates',
    )
  })
})

describe('CORS', () => {
  test('flags an origin echoed straight back alongside credentials', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'cors/reflected-origin-with-credentials')
    assert.ok(hit, 'missed the reflected origin in lib/cors.ts')
    assert.equal(hit.file, 'lib/cors.ts')
    assert.equal(hit.confidence, 'certain')
    assert.equal(hit.severity, 'P1')
  })

  test('says the wildcard pairing is broken, not that it is an exploit', async () => {
    // "*" with credentials is forbidden by the specification, so browsers
    // reject the response. It is a bug, and the wording has to say so — the
    // reason to report it is that the obvious fix creates the real hole.
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'cors/wildcard-with-credentials')
    assert.ok(hit, 'missed the wildcard/credentials pair in next.config.js')
    assert.equal(hit.severity, 'P2')
    assert.match(hit.title, /rejected by every browser/i, 'title overclaims the impact')
    assert.match(hit.why.join('\n\n'), /echo the caller's Origin header back/i, 'does not warn about the usual "fix"')
  })

  test('does not flag a wildcard on its own', async () => {
    // A public API with Access-Control-Allow-Origin: * is ordinary and correct.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.ruleId.startsWith('cors/'))
    assert.deepEqual(hits.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`), [], 'noise on correct CORS')
  })

  test('does not flag an allowlist that compares before echoing', async () => {
    // The hard case: a safe implementation reads the Origin header too. What
    // separates it from the bug is that it decides, rather than echoes.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file === 'lib/cors.ts')
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on an allowlist check')
  })

  test('does not read client-side credentials settings as server policy', async () => {
    // axios withCredentials and fetch credentials: 'include' say what this code
    // sends, not what the server accepts. Treating them as server policy would
    // pair them with the public wildcard in the same file.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file === 'lib/api-client.ts')
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'confused a client setting for a server header')
  })

  test('pairs credentials with the nearest origin, not any nearby one', async () => {
    // clean-nextjs/next.config.js serves one public route with "*" and, six
    // lines later, an authenticated route with a named origin. Those are two
    // responses; only the second has credentials.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file === 'next.config.js')
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'paired credentials with an unrelated wildcard')
  })
})

describe('findings that only real repositories exposed', () => {
  // Every test here comes from running canship against six popular Next.js +
  // Supabase projects. It produced four true positives and six false
  // positives, which is the wrong ratio for a tool whose entire claim is that
  // it does not cry wolf.

  test('a committed env file holding a real credential is reported', async () => {
    await withGitRepo(
      // Deliberately random-looking. An "AbCdEf" run reads as a placeholder —
      // correctly — and would have made this test fail for the wrong reason.
      { '.env.local': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n' },
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId === 'gitleak/env-tracked')
        assert.ok(hit, 'missed a real secret committed to git')
      },
    )
  })

  test('.env.local.example is not a leak', async () => {
    // Reported on three of six starters, Vercel's own template among them.
    // The exemption existed — in walker.ts — but this rule kept a narrower
    // private copy that only matched ".env.example" exactly.
    await withGitRepo(
      {
        '.env.local.example':
          'NEXT_PUBLIC_SUPABASE_URL=your-project-url\nSUPABASE_SERVICE_ROLE_KEY=your-service-role-key\n',
      },
      async (root) => {
        const { findings } = await scan(root)
        const hits = findings.filter((f) => f.ruleId.startsWith('gitleak/'))
        assert.deepEqual(hits.map((f) => f.title), [], 'reported a template file as a leak')
      },
    )
  })

  test('a template in a test directory is still not a leak', async () => {
    // The half of the old exemption that was right: a file named .env.example
    // is published on purpose, wherever it happens to sit.
    await withGitRepo(
      {
        'test/.env.example': 'STRIPE_SECRET_KEY=your-stripe-key\n',
        'test/spec.ts': 'export const a = 1\n',
      },
      async (root) => {
        const { findings } = await scan(root)
        const hits = findings.filter((f) => f.ruleId.startsWith('gitleak/'))
        assert.deepEqual(hits.map((f) => f.title), [], 'a template is a template wherever it lives')
      },
    )
  })

  test('an env file in a test directory is committed all the same', async () => {
    // The location exemption used to drop these before anything read them, so
    // a real key under e2e/ produced no finding at all. Quietly, because the
    // directory makes a fake key likely — not because it makes one harmless.
    await withGitRepo(
      {
        'e2e/.env': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n',
        'e2e/spec.ts': 'export const a = 1\n',
      },
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId === 'gitleak/env-tracked')
        assert.ok(hit, 'a committed env file under e2e/ went unreported entirely')
        assert.equal(hit.confidence, 'likely', 'a test directory is a doubt, not an acquittal')
      },
    )
  })

  test('an env file deleted from a test directory is still in history', async () => {
    // The case this rule exists for, in the directory the exemption hid. Once
    // the file is gone from disk no other rule can read it, so going quiet
    // here meant a key sitting in history was reported by nothing at all — a
    // green tick over a live credential.
    await withGitRepo(
      {
        'e2e/.env': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n',
        'e2e/spec.ts': 'export const a = 1\n',
      },
      async (root) => {
        rmSync(join(root, 'e2e', '.env'))
        execFileSync(
          'git',
          ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-aqm', 'remove'],
          { cwd: root, stdio: 'ignore' },
        )
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId === 'gitleak/env-in-history')
        assert.ok(hit, 'a key left in history under e2e/ was reported by nothing at all')
        assert.equal(hit.confidence, 'likely')
      },
    )
  })

  test('a committed env file holding only public values is not a leak', async () => {
    // .env.test carrying three NEXT_PUBLIC_ variables. The name is not an
    // example name, so no filename rule saves this one — only reading it does.
    await withGitRepo(
      {
        '.env.test':
          'NEXT_PUBLIC_SUPABASE_URL=http://localhost:54321\n' +
          'NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.local\n' +
          'NEXT_PUBLIC_SITE_URL=http://localhost:3000\n',
      },
      async (root) => {
        const { findings } = await scan(root)
        const hits = findings.filter((f) => f.ruleId.startsWith('gitleak/'))
        assert.deepEqual(hits.map((f) => f.title), [], 'values meant for the browser leak nothing')
      },
    )
  })

  test('a table dropped by a later migration is not reported', async () => {
    // Migrations are append-only. Reading them as a set rather than a sequence
    // invents tables that no longer exist.
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.title.includes('legacy_notes'))
    assert.equal(hit, undefined, 'reported a table that a later migration dropped')
  })

  test('a commented-out DROP TABLE cannot retire a finding', async () => {
    // The dangerous direction. If comments were honoured, writing
    // "-- DROP TABLE public.orders;" anywhere would silence orders forever.
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'supabase/rls-not-enabled' && f.title.includes('orders'))
    assert.ok(hit, 'a comment hid a live table with no RLS')
  })

  test('a sign-in route is not reported for having no sign-in check', async () => {
    // /api/auth/signin using the admin client to mint a magic link is the
    // correct implementation of passwordless auth. There is nobody to
    // authenticate yet.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.startsWith('app/api/auth/'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on an auth endpoint')
  })

  test('a write through a session-scoped client is not reported', async () => {
    // The rule's own advice is to use the request's session instead of the
    // service_role key and let Row Level Security enforce the boundary. A
    // route that does exactly that was being reported — the tool flagging its
    // own fix. Whether RLS is switched on is supabase/rls-not-enabled's job.
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.startsWith('app/api/notes'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'flagged the architecture the tool recommends')
  })

  test('a value that starts with test_ is not a credential', async () => {
    // .env.test carrying GITHUB_TOKEN=test_token. The separator is what makes
    // this safe to suppress: real keys do not start with "test_", though
    // plenty contain "test" somewhere in the middle.
    await withGitRepo(
      { '.env.test': 'GITHUB_TOKEN=test_token\nSENTRY_AUTH_TOKEN=test_token\nSENTRY_ORG=test_org\n' },
      async (root) => {
        const { findings } = await scan(root)
        assert.deepEqual(findings.map((f) => f.ruleId), [], 'reported obvious scaffolding as a leak')
      },
    )
  })

  test('a type argument does not hide the client constructor', async () => {
    // createClient<Database>() is the form Supabase's documentation
    // recommends. Requiring "(" straight after the name downgraded a real
    // finding from certain to likely, hiding it behind --all.
    const admin = (await import('node:fs')).readFileSync(
      join(VULNERABLE, 'lib', 'supabase-admin.ts'),
      'utf8',
    )
    assert.match(admin, /createClient<Database>\(/, 'fixture no longer covers the generic form')
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'api/admin-db-access-without-auth')
    assert.ok(hit, 'the generic swallowed the constructor')
    assert.equal(hit.confidence, 'certain')
  })
})

describe('redaction is an output-boundary invariant, not a rule responsibility', () => {
  // One line, two providers. Redaction used to be each rule's job, so the
  // OpenAI finding masked the OpenAI key and printed the GitHub token in full,
  // and the GitHub finding did the reverse. Both keys reached the output.
  const OPENAI = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'
  const GITHUB = 'ghp_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn123'

  /**
   * The longest prefix of `secret` that appears anywhere in `text`, or null if
   * nothing recognisable does.
   *
   * Twelve is the floor: every format here carries a fixed prefix — `sk-proj-`,
   * `ghp_` — so a dozen characters is the first point at which the output is
   * showing something specific to *this* key rather than to its provider.
   */
  function longestPrefixIn(text: string, secret: string): string | null {
    for (let n = secret.length; n >= 12; n--) {
      const prefix = secret.slice(0, n)
      if (text.includes(prefix)) return prefix
    }
    return null
  }

  test('both credentials on one line are masked in every finding', async () => {
    const { findings } = await scan(VULNERABLE)
    const hits = findings.filter((f) => f.file === 'lib/multi-secret.ts')
    assert.equal(hits.length, 3, 'the fixture should produce one finding per credential')
    for (const f of hits) {
      assert.ok(!f.excerpt?.includes(OPENAI), 'an excerpt carried the full OpenAI key')
      assert.ok(!f.excerpt?.includes(GITHUB), 'an excerpt carried the full GitHub token')
    }
  })

  test('no output surface can print either credential', async () => {
    // The bug was invisible from any single renderer, so all four are checked.
    // Every one of them reads Finding.excerpt straight through.
    const result = await scan(VULNERABLE)
    const surfaces: Record<string, string> = {
      json: JSON.stringify(result.findings),
      terminal: renderReport(result, { root: VULNERABLE, showingLikely: true, hiddenLikely: 0 }),
      // null only when there is nothing to fix, which is not this fixture.
      prompt: renderFixPrompt(result.findings) ?? '',
      html: renderHtml(result, { root: VULNERABLE, generatedAt: '1970-01-01T00:00:00.000Z' }),
    }
    for (const [name, text] of Object.entries(surfaces)) {
      // Prefixes, not just the whole string. Asserting only on the complete key
      // measures the crudest possible violation: a truncation that cut a key in
      // half published nineteen of its characters to all four of these surfaces
      // while this test stayed green. Twelve characters past the format prefix
      // is already enough to search for.
      for (const secret of [OPENAI, GITHUB]) {
        const leaked = longestPrefixIn(text, secret)
        assert.ok(
          leaked === null,
          `${name} output leaked ${leaked?.length} characters of a credential: ${leaked}`,
        )
      }
    }
  })

  test('redactAll masks a credential nobody asked it about', async () => {
    // The property that makes the boundary safe: the caller does not have to
    // know what is in the string.
    const masked = redactAll(`a ${OPENAI} b ${GITHUB} c`)
    assert.ok(!masked.includes(OPENAI))
    assert.ok(!masked.includes(GITHUB))
    assert.match(masked, /^a .+ b .+ c$/, 'the surrounding text should survive')
  })

  /** Codes rather than a character class, so nothing here can become one by accident */
  const hasControlChar = (s: string): boolean =>
    [...s].some((ch) => {
      const c = ch.codePointAt(0) ?? 0
      return c < 0x20 || (c >= 0x7f && c <= 0x9f)
    })

  test('a paragraph break in an explanation survives to every renderer', async () => {
    // The boundary strips every control character, newline included — and it is
    // right to: `why` interpolates paths and file contents. But rules used to spell their
    // paragraph breaks as \n\n *inside* that string, so the boundary removed
    // those too and two sentences ran together: "…root password.Because the
    // variable…". The README's own example output showed a break the tool could
    // no longer produce.
    const result = await scan(VULNERABLE)
    const hit = result.findings.find((f) => f.ruleId === 'exposure/supabase-service-role-in-client')
    assert.ok(hit, 'the fixture should expose the service_role key')
    assert.ok(hit.why.length > 1, 'this explanation is written as more than one paragraph')

    const terminal = renderReport(result, { root: VULNERABLE, showingLikely: true, hiddenLikely: 0 })
    assert.ok(terminal.includes('root password.'), 'the first paragraph went missing entirely')
    assert.ok(!terminal.includes('root password.Because'), 'two paragraphs ran together in the terminal')

    const html = renderHtml(result, { root: VULNERABLE, generatedAt: '1970-01-01T00:00:00.000Z' })
    assert.ok(html.includes('</p><p>'), 'the HTML report collapsed the explanation into one paragraph')
  })

  test('no paragraph carries a control character of its own', async () => {
    // Why `why` is a list rather than a string with \n\n in it. It interpolates
    // file paths and file contents, and a path may legally contain a newline —
    // so exempting \n at the boundary would let anyone who can add a file to a
    // repository draw extra lines in the report. Breaks live *between*
    // elements, which is the one place only a rule can reach.
    const result = await scan(VULNERABLE)
    let paragraphs = 0
    for (const f of result.findings) {
      for (const p of f.why) {
        paragraphs++
        assert.ok(
          !hasControlChar(p),
          `a why paragraph carried a control character: ${JSON.stringify(p)}`,
        )
      }
    }
    assert.ok(paragraphs > 0, 'the fixture produced no explanations to check')
  })
})

describe('an incomplete scan must not look like a clean one', () => {
  // The worst failure a security scanner has is printing "nothing found" when
  // the honest answer is "nothing was looked at".

  test('a rule that throws is recorded, and the scan is marked partial', async () => {
    const { FILE_RULES } = await import('../src/rules/index.js')
    const exploding: (typeof FILE_RULES)[number] = {
      id: 'test/always-throws',
      severity: 'P0',
      appliesTo: () => true,
      check: () => {
        throw new Error('deliberate failure')
      },
    }
    FILE_RULES.push(exploding)
    try {
      const result = await scan(CLEAN)
      assert.ok(result.errors.length > 0, 'a crashed rule left no trace')
      assert.equal(result.errors[0]!.ruleId, 'test/always-throws')
      assert.match(result.errors[0]!.message, /deliberate failure/)
      assert.equal(result.partial, true, 'a crashed check still counted as a complete scan')
    } finally {
      FILE_RULES.pop()
    }
  })

  test('a partial scan with no findings does not render the green verdict', async () => {
    const result = {
      findings: [],
      filesScanned: 10,
      durationMs: 1,
      errors: [{ ruleId: 'x/y', file: null, message: 'boom', kind: 'crashed' as const }],
      skipped: [],
      ignored: [],
      vendored: 0,
      partial: true,
    }
    const text = renderReport(result, { root: '/app', showingLikely: true, hiddenLikely: 0 })
    assert.ok(!text.includes('No exposed credentials found'), 'claimed clean on an unfinished scan')
    assert.match(text, /not everything was checked/i, 'did not say what was missed')
    assert.match(text, /x\/y/, 'did not name the check that failed')

    const hiddenText = renderReport(result, { root: '/app', showingLikely: false, hiddenLikely: 1 })
    assert.match(hiddenText, /No certain findings/i)
    assert.match(hiddenText, /lower-confidence finding hidden/i)

    const html = renderHtml(result, {
      root: '/app',
      generatedAt: '1970-01-01T00:00:00.000Z',
      hiddenLikely: 1,
    })
    assert.match(html, /No certain findings/i)
    assert.match(html, /not everything was checked/i)
  })

  test('a file too large to read is reported, not dropped', async () => {
    const root = mkdtempSync(join(tmpdir(), 'canship-big-'))
    try {
      // Comfortably over the cap, with the key at the very end — the position
      // that a "just read the first chunk" shortcut would miss.
      writeFileSync(
        join(root, 'huge.ts'),
        `// ${'x'.repeat(3 * 1024 * 1024)}\nconst k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n`,
        'utf8',
      )
      const result = await scan(root)
      assert.equal(result.findings.length, 0, 'the file was not read, so there is nothing to find')
      assert.equal(result.partial, true, 'an unread file is not a clean file')
      assert.deepEqual(
        result.skipped.map((s) => [s.path, s.reason]),
        [['huge.ts', 'too-large']],
      )
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('a file git still lists but that is gone from disk is not an incomplete scan', async () => {
    // Uncommitted deletions are an everyday state — one real project produced
    // 160 of them. Counting those as unreadable would make "partial" fire on
    // healthy repositories, which is how a warning becomes noise and then gets
    // ignored on the day it matters.
    // The surviving file matters: without it the repository scans to zero
    // files, which is its own kind of incomplete scan and would mask whether
    // the deletion was handled correctly.
    await withGitRepo(
      { 'app/gone.ts': 'export const a = 1\n', 'app/stays.ts': 'export const b = 2\n' },
      async (root) => {
        rmSync(join(root, 'app', 'gone.ts'))
        const result = await scan(root)
        assert.deepEqual(result.skipped, [], 'a deleted file was reported as unreadable')
        assert.equal(result.filesScanned, 1, 'the surviving file should still have been read')
        assert.equal(result.partial, false, 'an ordinary uncommitted deletion marked the scan partial')
      },
    )
  })

  test('CI gets exit code 3 for an incomplete scan, and 0 only with --best-effort', async () => {
    const root = mkdtempSync(join(tmpdir(), 'canship-exit-'))
    const run = (extra: string[]): number => {
      try {
        execFileSync('node', ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), root, ...extra], {
          stdio: 'ignore',
        })
        return 0
      } catch (err) {
        return (err as { status?: number }).status ?? -1
      }
    }
    try {
      writeFileSync(join(root, 'huge.ts'), `// ${'x'.repeat(3 * 1024 * 1024)}\n`, 'utf8')
      assert.equal(run([]), 3, 'an unfinished scan passed CI as if it were clean')
      assert.equal(run(['--best-effort']), 0, '--best-effort should accept a partial scan')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('scanning nothing at all is never reported as clean', async () => {
    // The sharpest version of "found nothing" versus "checked nothing", and
    // the easiest to hit by accident: the headline command is `npx canship`
    // with no argument, so the wrong working directory is the ordinary user
    // error rather than an exotic one. It used to print a green tick and exit
    // 0 — a scanner telling someone their project is clean while having read
    // none of it.
    const root = mkdtempSync(join(tmpdir(), 'canship-empty-'))
    try {
      const result = await scan(root)
      assert.equal(result.filesScanned, 0)
      assert.equal(result.partial, true, 'a scan that read nothing claimed to be complete')

      const text = renderReport(result, { root, showingLikely: true, hiddenLikely: 0 })
      assert.doesNotMatch(text, /No exposed credentials found/, 'an empty scan showed the clean verdict')
      assert.match(text, /No files were scanned/, 'the report did not say it had read nothing')

      // The prompt is the output that gets acted on by something which cannot
      // see the terminal, so it has to carry the same warning — and name the
      // real cause rather than blaming unreadable files that do not exist.
      const prompt = renderFixPrompt([], { partial: result.partial, filesScanned: 0 })
      assert.ok(prompt !== null, 'the fix prompt said nothing about an empty scan')
      assert.match(prompt, /zero files/)

      const code = (() => {
        try {
          execFileSync('node', ['--import', 'tsx', join(here, '..', 'src', 'cli.ts'), root], {
            stdio: 'ignore',
          })
          return 0
        } catch (err) {
          return (err as { status?: number }).status ?? -1
        }
      })()
      assert.equal(code, 3, 'an empty scan passed CI as if it were clean')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })
})

describe('places a credential can hide that an extension list never reaches', () => {
  const PRIVATE_KEY =
    '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAx7Vv2mQpLk8ZnR4tYwCdEfGhIjKlMnOpQrStUvWxYz0123456\n' +
    '-----END RSA PRIVATE KEY-----\n'

  /** Scan a throwaway directory built from the given files */
  async function scanFiles(files: Record<string, string>): Promise<Awaited<ReturnType<typeof scan>>> {
    const root = mkdtempSync(join(tmpdir(), 'canship-walk-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      return await scan(root)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  test('a .pem private key is read', async () => {
    // The README advertised private-key detection while .pem was missing from
    // the extension list, so the commonest way to ship one was invisible.
    const { findings } = await scanFiles({ 'server.pem': PRIVATE_KEY })
    assert.ok(
      findings.some((f) => f.ruleId === 'secrets/hardcoded/private-key'),
      'a private key in a .pem file was never opened',
    )
  })

  test('an extensionless deploy key is found by looking, not by guessing', async () => {
    const { findings } = await scanFiles({ deploy_key: PRIVATE_KEY })
    assert.ok(
      findings.some((f) => f.ruleId === 'secrets/hardcoded/private-key'),
      'no name or suffix rule reaches this file — only reading it does',
    )
  })

  test('an extensionless file that is not a key is left alone', async () => {
    // app.ts is the control. It keeps the scan from reaching zero files —
    // which is now reported as an incomplete scan in its own right — so the
    // count below is evidence about README and LICENSE specifically rather
    // than about an empty directory.
    const result = await scanFiles({
      README: 'just some notes\n',
      LICENSE: 'MIT\n',
      'app.ts': 'export const a = 1\n',
    })
    assert.equal(result.filesScanned, 1, 'probing pulled in files with nothing to check')
    assert.equal(result.partial, false)
  })

  test('a gitignored .env buried in a monorepo is still found', async () => {
    // The old search looked at the root plus a fixed list of directory names,
    // one level down. services/web/.env was invisible to it, and the report
    // said zero findings with complete confidence.
    await withGitRepo(
      {
        '.gitignore': '.env\n**/.env\n',
        'app.ts': 'export const a = 1\n',
        'services/web/.env': 'NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n',
      },
      async (root) => {
        const { findings } = await scan(root)
        assert.ok(
          findings.some((f) => f.file === 'services/web/.env'),
          'a secret exposed to the browser three levels down went unreported',
        )
      },
    )
  })

  test('a gitignored .env holding a server-side secret is correct usage', async () => {
    // The counterpart. Finding these files must not turn into reporting them:
    // keeping a secret in an ignored .env is the thing everyone is told to do.
    await withGitRepo(
      {
        '.gitignore': '.env\n**/.env\n',
        'app.ts': 'export const a = 1\n',
        'services/api/.env': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n',
      },
      async (root) => {
        const { findings } = await scan(root)
        assert.deepEqual(findings.map((f) => f.ruleId), [], 'reported a correctly ignored .env')
      },
    )
  })

  test('a credential in a test directory is reported, at lower confidence', async () => {
    // Test directories used to be waved through entirely. A real key committed
    // to test/ is exactly as stolen as one in src/ — it is just less likely to
    // be real, which is what "likely" means.
    const { findings } = await scanFiles({
      'test/integration.ts': "const k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n",
    })
    const hit = findings.find((f) => f.ruleId === 'secrets/hardcoded/openai')
    assert.ok(hit, 'a real-looking key in test/ was waved through')
    assert.equal(hit.confidence, 'likely', 'a fixture key should not be certain-grade')
    assert.match(hit.title, /test or example file/i)
  })

  test('merely mentioning the opt-out does not trigger it', async () => {
    // Found by canship scanning itself: walker.ts and secrets.ts had quietly
    // excluded themselves, because both *explain* the marker in a comment. A
    // substring search turns one stray word into a blindfold over a whole
    // file — and a very quiet one. The marker has to be the whole line.
    const marker = `canship-ignore` + `-file`
    const { findings } = await scanFiles({
      'docs.ts': `// Add ${marker} to a line of its own to exclude a file.\nconst k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n`,
    })
    assert.ok(
      findings.some((f) => f.ruleId === 'secrets/hardcoded/openai'),
      'a passing mention of the marker disabled the file',
    )
  })

  test('opted-out files are listed, never silently dropped', async () => {
    const marker = `canship-ignore` + `-file`
    const root = mkdtempSync(join(tmpdir(), 'canship-opt-'))
    try {
      writeFileSync(join(root, 'fixture.ts'), `// ${marker}\nconst a = 1\n`, 'utf8')
      // A file that is actually scanned, so "partial" below reports on the
      // opt-out rather than on the directory having nothing left in it.
      writeFileSync(join(root, 'app.ts'), 'export const a = 1\n', 'utf8')
      const result = await scan(root)
      assert.deepEqual(result.ignored, ['fixture.ts'], 'the exclusion left no trace')
      // Deliberate is not broken: this must not make the scan look failed.
      assert.equal(result.partial, false)
      const text = renderReport(result, { root, showingLikely: true, hiddenLikely: 0 })
      assert.match(text, /excluded by canship-ignore-file/, 'the report said nothing about it')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('the file-level opt-out silences a file completely', async () => {
    // Built by concatenation so this test does not disable itself.
    const marker = `canship-ignore` + `-file`
    const { findings } = await scanFiles({
      'test/integration.ts': `// ${marker}\nconst k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n`,
    })
    assert.deepEqual(findings.map((f) => f.ruleId), [], 'the opt-out was ignored')
  })
})

describe('variable names are read as words, not as a regex accident', () => {
  // `\b` sits between a word character and a non-word one, and `_` is a word
  // character. So /\bSECRET\b/ never matched STRIPE_SECRET_KEY and
  // /\bSERVICE_ROLE\b/ never matched SUPABASE_SERVICE_ROLE_KEY. Both patterns
  // read as if they worked. Neither matched a single realistic name, which
  // made two of this project's lists dead code for as long as they existed.

  test('a name splits into its words', () => {
    assert.deepEqual(nameWords('SUPABASE_SERVICE_ROLE_KEY'), ['SUPABASE', 'SERVICE', 'ROLE', 'KEY'])
    assert.deepEqual(nameWords('nextPublicApiKey'), ['NEXT', 'PUBLIC', 'API', 'KEY'])
  })

  test('credential words are recognised inside snake_case', () => {
    for (const name of ['STRIPE_SECRET_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'DB_PASSWORD']) {
      assert.equal(looksClearlyPrivate(name), true, `${name} should read as a credential`)
    }
  })

  test('a word is a word, not a substring', () => {
    // The reason for matching whole words rather than searching for the text:
    // SECRETARY contains SECRET.
    assert.equal(looksClearlyPrivate('SECRETARY_EMAIL'), false)
  })

  test('public markers are recognised too', () => {
    assert.equal(looksIntentionallyPublic('SUPABASE_ANON_KEY'), true)
    assert.equal(looksIntentionallyPublic('STRIPE_PUBLISHABLE_KEY'), true)
    assert.equal(looksIntentionallyPublic('INTERNAL_SECRET'), false)
  })

  test('a private-sounding public variable is reported once the name is readable', async () => {
    // NEXT_PUBLIC_INTERNAL_SECRET with a value matching no known key format.
    // The name is the only evidence there is, so this is a lower-confidence
    // finding — but it used to be no finding at all.
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'exposure/private-name-in-public-env')
    assert.ok(hit, 'the name heuristic is still not reading snake_case')
    assert.equal(hit.confidence, 'likely')
  })

  test('the public prefix does not exempt the variable it prefixes', async () => {
    // The trap that only appears once tokenisation works: every NEXT_PUBLIC_
    // name contains the word PUBLIC, so testing the whole name marks all of
    // them intentionally public and silences the branch everywhere. The
    // question has to be asked of the name after the prefix.
    const { findings } = await scan(VULNERABLE)
    assert.ok(
      findings.some((f) => f.ruleId === 'exposure/private-name-in-public-env'),
      'the prefix exempted the variable it was prefixing',
    )
    // And the genuinely public ones stay quiet.
    const anon = findings.find((f) => f.excerpt?.includes('ANON_KEY'))
    assert.equal(anon, undefined, 'the anon key is public by design')
  })

  test('a trailing comment does not hide the key it annotates', async () => {
    // NEXT_PUBLIC_GITHUB_TOKEN=ghp_… # production. The comment used to stay
    // glued to the value, which then matched no known format — so the most
    // dangerous line in the file was reported as nothing.
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find(
      (f) => f.ruleId === 'exposure/secret-in-public-env' && f.title.includes('GitHub'),
    )
    assert.ok(hit, 'an annotated key went unreported')
    assert.equal(hit.confidence, 'certain')
  })

  test('a # inside a quoted value is part of the password', async () => {
    // The counterpart: stripping comments must not corrupt values. The clean
    // fixture holds DATABASE_PASSWORD="p@ss#word-2026".
    const { findings } = await scan(CLEAN)
    assert.deepEqual(findings.map((f) => f.ruleId), [], 'a quoted # was read as a comment')
  })

  test('a UTF-16 source file is decoded, not written off as binary', async () => {
    // Vercel's own Next.js + Supabase template ships types_db.ts in UTF-16 LE.
    // Read as UTF-8 its text comes out as e\0x\0p\0, the NUL check calls it
    // binary, and the file is never scanned — in the flagship template of the
    // exact stack canship targets.
    const root = mkdtempSync(join(tmpdir(), 'canship-bom-'))
    try {
      const text = "const k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n"
      writeFileSync(join(root, 'types_db.ts'), Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]))
      const result = await scan(root)
      assert.equal(result.filesScanned, 1, 'the file was written off as binary')
      assert.equal(result.partial, false)
      assert.ok(
        result.findings.some((f) => f.ruleId === 'secrets/hardcoded/openai'),
        'a key in a UTF-16 file went unread',
      )
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('a comment mentioning a variable is not a variable', async () => {
    // Found by canship on its own source: a comment giving an example of the
    // pattern being matched became a finding. A commented-out *key* is still
    // leaked; a commented-out *name* is prose, and nothing ships.
    const root = mkdtempSync(join(tmpdir(), 'canship-cmt-'))
    try {
      writeFileSync(
        join(root, 'note.ts'),
        "'use client'\n// e.g. process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\nexport const a = 1\n",
        'utf8',
      )
      const { findings } = await scan(root)
      assert.deepEqual(findings.map((f) => f.ruleId), [], 'a comment was read as code')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })
})

describe('SQL is read as SQL, not as text that happens to contain keywords', () => {
  /** Scan a throwaway Supabase-looking project with one migration */
  async function migration(body: string): Promise<string[]> {
    const root = mkdtempSync(join(tmpdir(), 'canship-sql-'))
    try {
      writeFileSync(join(root, 'm.sql'), body, 'utf8')
      writeFileSync(join(root, 'c.ts'), "import { createClient } from '@supabase/supabase-js'\n", 'utf8')
      const { findings } = await scan(root)
      return findings
        .filter((f) => f.ruleId === 'supabase/rls-not-enabled')
        .map((f) => /"([^"]+)"/.exec(f.title)?.[1] ?? '')
        .sort()
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  test('a DROP inside a string literal does not drop anything', async () => {
    // One sentence of SQL used to be enough to hide a vulnerability: the text
    // inside the quotes was read as a statement, the table left the replay, and
    // canship said nothing about a live table with no RLS.
    assert.deepEqual(
      await migration("CREATE TABLE public.live_data (id int);\nSELECT 'DROP TABLE public.live_data;';\n"),
      ['live_data'],
    )
  })

  test('a CREATE inside a string literal does not invent a table', async () => {
    assert.deepEqual(
      await migration("SELECT 'CREATE TABLE public.ghost (id int);';\nCREATE TABLE public.real_one (id int);\n"),
      ['real_one'],
    )
  })

  test('block comments nest, the way Postgres says they do', async () => {
    // Stopping at the first */ leaves the tail of the comment looking like code.
    assert.deepEqual(
      await migration('CREATE TABLE public.t (id int);\n/* outer /* inner */ DROP TABLE public.t; */\n'),
      ['t'],
    )
  })

  test('a dollar-quoted function body is not schema', async () => {
    assert.deepEqual(
      await migration(
        'CREATE TABLE public.t (id int);\nCREATE FUNCTION f() RETURNS void AS $$ CREATE TABLE public.fake (id int); $$ LANGUAGE sql;\n',
      ),
      ['t'],
    )
  })

  test('a doubled quote does not end the string early', async () => {
    assert.deepEqual(
      await migration("CREATE TABLE public.t (id int);\nSELECT 'it''s fine; DROP TABLE public.t;';\n"),
      ['t'],
    )
  })

  test('RLS turned back off is RLS that is off', async () => {
    // The state where silence is most expensive: somebody did think about RLS
    // here, and then changed their mind.
    assert.deepEqual(
      await migration(
        'CREATE TABLE public.accounts (id int);\nALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.accounts DISABLE ROW LEVEL SECURITY;\n',
      ),
      ['accounts'],
    )
  })

  test('protection follows a table through a rename', async () => {
    assert.deepEqual(
      await migration(
        'CREATE TABLE public.old_n (id int);\nALTER TABLE public.old_n ENABLE ROW LEVEL SECURITY;\nALTER TABLE public.old_n RENAME TO new_n;\n',
      ),
      [],
      'a rename lost the protection that came with the table',
    )
    assert.deepEqual(
      await migration('CREATE TABLE public.old_n (id int);\nALTER TABLE public.old_n RENAME TO new_n;\n'),
      ['new_n'],
      'an unprotected table should be reported under the name it actually has',
    )
  })

  test('ALTER TABLE IF EXISTS still counts', async () => {
    assert.deepEqual(
      await migration(
        'CREATE TABLE public.accounts (id int);\nALTER TABLE IF EXISTS public.accounts ENABLE ROW LEVEL SECURITY;\n',
      ),
      [],
    )
  })

  test('the fixtures cover the same ground end to end', async () => {
    const { findings } = await scan(VULNERABLE)
    const tables = findings
      .filter((f) => f.ruleId === 'supabase/rls-not-enabled')
      .map((f) => /"([^"]+)"/.exec(f.title)?.[1])
    // invoices: enabled then disabled. orders: named in a string that must not
    // count as a DROP. payment_receipts and ghost_from_body must not appear —
    // one is protected through a rename, the other exists only inside a
    // function body.
    assert.ok(tables.includes('invoices'), 'a table whose RLS was switched off went unreported')
    assert.ok(tables.includes('orders'), 'a string literal retired a real finding')
    assert.ok(!tables.includes('payment_receipts'), 'a rename lost its protection')
    assert.ok(!tables.includes('ghost_from_body'), 'a function body invented a table')
  })
})

describe('what silences the API check has to be what actually protects the route', () => {
  const ADMIN_ROUTE =
    "import { createClient } from '@supabase/supabase-js'\n" +
    'const a = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n' +
    'export async function GET(){ const { data } = await a.from("users").select("*"); return Response.json(data) }\n'

  const middleware = (matcher: string): string =>
    'export function middleware(req){ const s = req.cookies.get("s"); if(!s) return new Response("no",{status:401}) }\n' +
    `export const config = { matcher: ${matcher} }\n`

  async function scanProject(files: Record<string, string>): Promise<string[]> {
    const root = mkdtempSync(join(tmpdir(), 'canship-mw-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      const { findings } = await scan(root)
      return findings.map((f) => f.ruleId)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  test('middleware covering one narrow path does not cover the rest', async () => {
    // The hole this closes: the answer used to be one boolean for the whole
    // project, so middleware protecting only /api/admin/* reported "the API is
    // covered" and every unauthenticated route went unreported.
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'middleware.ts': middleware('["/api/admin/:path*"]'),
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  test('middleware that does cover the route still silences it', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'middleware.ts': middleware('["/api/:path*"]'),
    })
    assert.deepEqual(found, [], 'a route genuinely behind middleware was reported')
  })

  test('a comment is not an authorisation check', async () => {
    // A note reminding you the check is missing, read as the check itself.
    const found = await scanProject({
      'app/api/users/route.ts': `// TODO validate token\n${ADMIN_ROUTE}`,
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  test('a string that mentions a session is not a session lookup', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': `const msg = "your session expired"\n${ADMIN_ROUTE}`,
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  test('sitting under /api/auth is not an argument', async () => {
    // Sign-in cannot check a caller; a bulk export next to it has no excuse.
    const exported = await scanProject({ 'app/api/auth/export-all/route.ts': ADMIN_ROUTE })
    assert.deepEqual(exported, ['api/admin-db-access-without-auth'])

    const signin = await scanProject({ 'app/api/auth/signin/route.ts': ADMIN_ROUTE })
    assert.deepEqual(signin, [], 'sign-in has nobody to authenticate yet')
  })

  test('the fixture covers the narrowed exemption end to end', async () => {
    const { findings } = await scan(VULNERABLE)
    assert.ok(
      findings.some((f) => f.file === 'app/api/auth/export-all/route.ts'),
      'a dangerous route under /api/auth was waved through',
    )
  })
})

describe('a comment, a template, and a setting are not what they resemble', () => {
  async function scanFiles(files: Record<string, string>): Promise<string[]> {
    const root = mkdtempSync(join(tmpdir(), 'canship-f-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      const { findings } = await scan(root)
      return findings.map((f) => `${f.confidence}:${f.ruleId}`)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  const CREDS = "res.setHeader('Access-Control-Allow-Credentials', 'true')\n"

  test('a commented-out Firebase rule is not an open database', async () => {
    assert.deepEqual(await scanFiles({ 'firestore.rules': '// allow read, write: if true;\n' }), [])
  })

  test('a real Firebase rule still is', async () => {
    assert.deepEqual(
      await scanFiles({ 'firestore.rules': 'match /x/{id} { allow read, write: if true; }\n' }),
      ['certain:firebase/open-rules'],
    )
  })

  test('the clean fixture keeps its leftover comment quiet', async () => {
    const { findings } = await scan(CLEAN)
    assert.deepEqual(findings.map((f) => f.ruleId), [])
  })

  test('a template literal wrapping the Origin header is reflection', async () => {
    // The one shape of reflection canship could not see: every backtick was
    // read as a literal, so the most direct echo there is looked safe.
    assert.deepEqual(
      await scanFiles({
        's.js': "res.setHeader('Access-Control-Allow-Origin', `${req.headers.origin}`)\n" + CREDS,
      }),
      ['certain:cors/reflected-origin-with-credentials'],
    )
  })

  test('a template that builds an origin is not one that echoes it', async () => {
    assert.deepEqual(
      await scanFiles({
        's.js': "res.setHeader('Access-Control-Allow-Origin', `https://${sub}.app.com`)\n" + CREDS,
      }),
      [],
    )
  })

  test('an allowlist that reads the request header is still an allowlist', async () => {
    // Caught while fixing the template case: the value used to be captured
    // only as far as the first `)`, which turned
    // `ALLOWED.includes(req.headers.origin) ? … : …` into what looked like a
    // bare property path ending in "origin".
    assert.deepEqual(
      await scanFiles({
        's.js':
          "res.setHeader('Access-Control-Allow-Origin', ALLOWED.includes(req.headers.origin) ? req.headers.origin : ALLOWED[0])\n" +
          CREDS,
      }),
      [],
      'a textbook allowlist was reported as reflection',
    )
  })

  test('a committed .env holding only a setting is not a leak', async () => {
    // NODE_ENV=development was reported as a certain-confidence credential
    // leak. A rule that shouts at that gets skipped on the day it is right.
    await withGitRepo({ '.env': 'NODE_ENV=development\n' }, async (root) => {
      const { findings } = await scan(root)
      assert.deepEqual(findings.filter((f) => f.ruleId.startsWith('gitleak/')).map((f) => f.title), [])
    })
  })

  test('a committed .env holding a credential still is', async () => {
    await withGitRepo(
      { '.env': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n' },
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId === 'gitleak/env-tracked')
        assert.ok(hit)
        assert.equal(hit.confidence, 'certain')
      },
    )
  })

  test('a committed .env that might hold one is reported quietly', async () => {
    await withGitRepo({ '.env': 'APP_REGION=us-east-1-prod-cluster\n' }, async (root) => {
      const { findings } = await scan(root)
      const hit = findings.find((f) => f.ruleId === 'gitleak/env-tracked')
      assert.ok(hit, 'a committed env file should still be mentioned')
      assert.equal(hit.confidence, 'likely', 'no credential was found, so do not claim one')
    })
  })

  test('history is asked about the directory being scanned, not the repository', async () => {
    // Scanning one package of a monorepo used to report .env files belonging
    // to its siblings, because the history query carried no pathspec.
    await withGitRepo(
      {
        'app/index.ts': 'export const a = 1\n',
        'sibling/.env': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n',
      },
      async (root) => {
        const { findings } = await scan(join(root, 'app'))
        assert.deepEqual(
          findings.filter((f) => f.ruleId.startsWith('gitleak/')).map((f) => f.title),
          [],
          'reported a file outside the scanned directory',
        )
      },
    )
  })
})

describe('the CLI contract', () => {
  // Everything a CI pipeline actually depends on: the exit code, the shape of
  // --json, and the flags composing. None of it was covered until now, which
  // is uncomfortable for the part of the tool whose whole job is to be the
  // gate in front of a deploy.
  const CLI = join(here, '..', 'src', 'cli.ts')

  interface Run {
    status: number
    stdout: string
  }

  function run(args: string[]): Run {
    try {
      const stdout = execFileSync('node', ['--import', 'tsx', CLI, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      })
      return { status: 0, stdout }
    } catch (err) {
      const e = err as { status?: number; stdout?: string }
      return { status: e.status ?? -1, stdout: e.stdout ?? '' }
    }
  }

  test('a clean project exits 0', () => {
    assert.equal(run([CLEAN]).status, 0)
  })

  test('a project with a confirmed serious issue exits 1', () => {
    assert.equal(run([VULNERABLE]).status, 1)
  })

  test('a confirmed P2 exits 2, not 1', () => {
    // Severity decides whether shipping is a mistake. A CORS pairing browsers
    // reject on your behalf is a bug to fix, not a reason to fail a deploy —
    // and it used to fail one, because the exit code counted certainty.
    const root = mkdtempSync(join(tmpdir(), 'canship-cli-'))
    try {
      writeFileSync(
        join(root, 's.js'),
        "const h = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' }\n",
        'utf8',
      )
      const result = run([root])
      assert.equal(result.status, 2, 'a P2 blocked a deploy')
      assert.match(result.stdout, /nothing exposed/, 'the verdict overstated a configuration bug')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('an unknown flag exits 3 rather than scanning anyway', () => {
    assert.equal(run([CLEAN, '--nonsense']).status, 3)
  })

  test('a path that is not a directory exits 3', () => {
    assert.equal(run([join(CLEAN, 'package-does-not-exist')]).status, 3)
  })

  test('--help and --version exit 0 and say something', () => {
    const help = run(['--help'])
    assert.equal(help.status, 0)
    assert.match(help.stdout, /Exit codes/)
    assert.match(help.stdout, /static scanner for exposed credentials and open access rules/)
    assert.doesNotMatch(help.stdout, /find the secrets/)
    assert.match(help.stdout, /--all\s+Show likely findings/)
    assert.match(help.stdout, /--best-effort\s+Allow exit 0 for an incomplete scan with no findings/)
    assert.match(help.stdout, /findings still exit 1 or 2/)
    assert.match(help.stdout, /0\s+no findings; scan complete, or partial accepted with --best-effort/)
    assert.match(help.stdout, /3\s+invalid arguments, tool error, or incomplete scan without --best-effort/)

    const version = run(['--version'])
    assert.equal(version.status, 0)
    assert.match(version.stdout.trim(), /^\d+\.\d+\.\d+/)
  })

  /**
   * The test above pins --help to literals, which stops it regressing but says
   * nothing about the READMEs: both documents could describe a flag that no
   * longer exists, or miss one that does, and stay green. Two of the three were
   * already out of step once — --help still carried the old tagline and the old
   * --best-effort wording after both READMEs had been corrected.
   *
   * So compare the three as sets. Wording is deliberately not compared: the
   * documents explain at different lengths and in different languages, and a
   * test that demanded identical sentences would be rewritten every time one of
   * them was improved. What must not drift is which options exist.
   */
  describe('the documented options match the ones the CLI has', () => {
    const readme = (name: string): string => readFileSync(join(here, '..', name), 'utf8')

    /**
     * Options named in a README's own option table.
     *
     * Scoped to the table rather than the whole document because prose
     * elsewhere names other programs' flags, and `git rm --cached` is not one
     * of canship's options. The table's rows are the only ones whose first cell
     * opens with a backticked dash.
     */
    const documented = (markdown: string): Set<string> => {
      const found = new Set<string>()
      for (const line of markdown.split(/\r?\n/)) {
        if (!/^\|\s*`-/.test(line)) continue
        const firstCell = line.slice(1, line.indexOf('|', 1))
        for (const match of firstCell.matchAll(/`(--?[A-Za-z][\w-]*)/g)) found.add(match[1]!)
      }
      return found
    }

    /** Options named in the Options block of --help, past any `[=F]` placeholder */
    const offered = (help: string): Set<string> => {
      const block = help.slice(help.indexOf('Options'), help.indexOf('Exit codes'))
      const found = new Set<string>()
      for (const match of block.matchAll(/(?<![\w-])(--?[A-Za-z][\w-]*)/g)) found.add(match[1]!)
      return found
    }

    const sorted = (options: Set<string>): string[] => [...options].sort()

    test('--help and both READMEs name the same options', () => {
      const help = sorted(offered(run(['--help']).stdout))

      // Non-empty is asserted separately: two extractors that both silently
      // matched nothing would agree perfectly and prove nothing at all.
      assert.ok(help.length >= 7, `--help named only ${help.length} options`)
      assert.deepEqual(sorted(documented(readme('README.md'))), help)
      assert.deepEqual(sorted(documented(readme('README.zh-CN.md'))), help)
    })

    test('--help and both READMEs describe the same exit codes', () => {
      const codes = (text: string): string[] =>
        [...new Set([...text.matchAll(/(?:^|[|`\s])`?([0-3])`?(?=[|\s])/g)].map((m) => m[1]!))].sort()

      const help = run(['--help']).stdout
      const helpCodes = codes(help.slice(help.indexOf('Exit codes')))

      assert.deepEqual(helpCodes, ['0', '1', '2', '3'])
      for (const name of ['README.md', 'README.zh-CN.md']) {
        const table = readme(name)
        const start = table.indexOf('| `0` |')
        assert.ok(start !== -1, `${name} has no exit-code table`)
        assert.deepEqual(
          codes(table.slice(start, table.indexOf('\n\n', start))),
          ['0', '1', '2', '3'],
          `${name} documents a different set of exit codes`,
        )
      }
    })
  })

  test('--json emits the fields a pipeline reads', () => {
    const result = run([VULNERABLE, '--json'])
    const parsed = JSON.parse(result.stdout) as Record<string, unknown>
    for (const key of ['version', 'filesScanned', 'partial', 'errors', 'skipped', 'ignored', 'hiddenLikely', 'findings']) {
      assert.ok(key in parsed, `--json dropped ${key}`)
    }
    assert.ok(Array.isArray(parsed['findings']))
  })

  test('--all widens what is shown without changing what was found', () => {
    const shown = JSON.parse(run([VULNERABLE, '--json']).stdout) as { findings: unknown[]; hiddenLikely: number }
    const all = JSON.parse(run([VULNERABLE, '--json', '--all']).stdout) as { findings: unknown[]; hiddenLikely: number }
    assert.ok(all.findings.length > shown.findings.length, '--all should reveal the hidden findings')
    assert.ok(shown.hiddenLikely > 0)
    assert.equal(all.hiddenLikely, 0)
  })

  test('a hidden likely finding never becomes a clean machine result', () => {
    const root = mkdtempSync(join(tmpdir(), 'canship-likely-'))
    const report = join(root, 'report.html')
    try {
      const route = join(root, 'app', 'api', 'users', 'route.ts')
      mkdirSync(dirname(route), { recursive: true })
      writeFileSync(
        route,
        'export async function DELETE(){ await prisma.user.deleteMany(); return Response.json({ ok: true }) }\n',
        'utf8',
      )

      const jsonRun = run([root, '--json'])
      const parsed = JSON.parse(jsonRun.stdout) as { findings: unknown[]; hiddenLikely: number }
      assert.equal(jsonRun.status, 2)
      assert.deepEqual(parsed.findings, [])
      assert.equal(parsed.hiddenLikely, 1)

      const terminal = run([root])
      assert.equal(terminal.status, 2)
      assert.doesNotMatch(terminal.stdout, /No exposed credentials found/)
      assert.match(terminal.stdout, /lower-confidence finding hidden/)

      const reportRun = run([root, '--json', `--report=${report}`])
      assert.equal(reportRun.status, 2)
      const html = readFileSync(report, 'utf8')
      assert.doesNotMatch(html, /verdict clean[^>]*>No exposed credentials found/)
      assert.match(html, /lower-confidence finding hidden/)

      const prompt = run([root, '--fix-prompt'])
      assert.equal(prompt.status, 2)
      assert.doesNotMatch(prompt.stdout, /Nothing to fix/)
      assert.match(prompt.stdout, /--all --fix-prompt/)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* a temp directory that will not delete is not a test failure */
      }
    }
  })

  test('--report writes a file, and composes with --json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'canship-rep-'))
    const target = join(dir, 'r.html')
    try {
      const result = run([VULNERABLE, '--json', `--report=${target}`])
      // stdout stays machine-readable even though a report was written
      JSON.parse(result.stdout)
      const html = readFileSync(target, 'utf8')
      assert.match(html, /<!doctype html>/i)
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('--fix-prompt says so when there is nothing to fix', () => {
    const result = run([CLEAN, '--fix-prompt'])
    assert.equal(result.status, 0)
    assert.match(result.stdout, /Nothing to fix/)
  })
})

describe('failures found only by pointing canship at real repositories', () => {
  async function scanProject(files: Record<string, string>): Promise<string[]> {
    const root = mkdtempSync(join(tmpdir(), 'canship-real-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      const { findings } = await scan(root)
      return findings.map((f) => f.ruleId)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  test('the matcher from the Next.js docs does not silence the rule', async () => {
    // The one Next.js prints for excluding static files. Rewriting `:svg`
    // inside `(?:svg|png|…)` produced an invalid group, the pattern failed to
    // compile, an unreadable matcher counted as coverage — and every API route
    // in every project using that matcher went unreported. Found by a scan of
    // a real project quietly losing a finding it had made an hour earlier.
    const found = await scanProject({
      'app/api/users/route.ts':
        "import { createClient } from '@supabase/supabase-js'\n" +
        'const a = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n' +
        'export async function GET(){ const { data } = await a.from("users").select("*"); return Response.json(data) }\n',
      'middleware.ts':
        'export function middleware(req){ const s = req.cookies.get("s"); if(!s) return new Response("no",{status:401}) }\n' +
        'export const config = { matcher: ["/((?!api|_next/static|favicon.ico|.*\\.(?:svg|png|jpg)$).*)"] }\n',
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  test('a superseded migration in a subfolder is not part of the schema', async () => {
    // Supabase applies supabase/migrations/*.sql and nothing below it, so a
    // subdirectory is where replaced migrations go to retire. One real project
    // kept an old_migrations/ folder whose last statement was DISABLE ROW
    // LEVEL SECURITY; replaying it reported five tables that the live schema
    // protects as wide open.
    const found = await scanProject({
      'c.ts': "import { createClient } from '@supabase/supabase-js'\n",
      'supabase/migrations/00000000000000_schema.sql':
        'CREATE TABLE IF NOT EXISTS scouts (id uuid);\nALTER TABLE scouts ENABLE ROW LEVEL SECURITY;\n',
      'supabase/migrations/old_migrations/20250110_create.sql':
        'CREATE TABLE IF NOT EXISTS scouts (id uuid);\nALTER TABLE scouts DISABLE ROW LEVEL SECURITY;\n',
    })
    assert.deepEqual(found, [], 'a retired migration overruled the live schema')
  })

  test('a migration directly in migrations/ still counts', async () => {
    const found = await scanProject({
      'c.ts': "import { createClient } from '@supabase/supabase-js'\n",
      'supabase/migrations/0001_init.sql': 'CREATE TABLE IF NOT EXISTS scouts (id uuid);\n',
    })
    assert.deepEqual(found, ['supabase/rls-not-enabled'])
  })

  test('a plain schema.sql outside any migrations folder still counts', async () => {
    const found = await scanProject({
      'c.ts': "import { createClient } from '@supabase/supabase-js'\n",
      'db/schema.sql': 'CREATE TABLE IF NOT EXISTS scouts (id uuid);\n',
    })
    assert.deepEqual(found, ['supabase/rls-not-enabled'])
  })
})

describe('gaps a second review found, each one a way to a false clean', () => {
  const SB = 'sb_secret_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'
  const GH = 'ghp_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn123'
  const OA = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'
  const SK = 'sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6'
  const ADMIN_ROUTE =
    "import { createClient } from '@supabase/supabase-js'\n" +
    'const a = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n' +
    'export async function GET(){ const { data } = await a.from("users").select("*"); return Response.json(data) }\n'
  const CREDS = "res.setHeader('Access-Control-Allow-Credentials', 'true')\n"

  async function scanProject(files: Record<string, string>): Promise<Awaited<ReturnType<typeof scan>>> {
    const root = mkdtempSync(join(tmpdir(), 'canship-gap-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      return await scan(root)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }
  const ids = async (files: Record<string, string>): Promise<string[]> =>
    (await scanProject(files)).findings.map((f) => f.ruleId)

  test('a format the code already recognises is in the pattern table', async () => {
    // framework.ts has known sb_secret_ since it was written — but only for
    // classifying a client-exposed value. The table below is what the
    // hardcoded-secret rule and the redaction boundary both walk, and it was
    // not in there. Detection and redaction failed together, from one omission.
    assert.deepEqual(await ids({ 'a.ts': `const k = '${SB}'\n` }), ['secrets/hardcoded/supabase-secret-key'])
  })

  test('and therefore cannot be printed beside another credential', async () => {
    const result = await scanProject({ 'a.ts': `const c = { sb: '${SB}', gh: '${GH}' }\n` })
    assert.ok(!JSON.stringify(result.findings).includes(SB), 'the Supabase key reached the output in full')
  })

  test('a real key in .env.example is reported', async () => {
    // Three rules each had a good reason to skip this file, and between them
    // nothing looked inside — at the one env file people commit on purpose.
    assert.deepEqual(await ids({ '.env.example': `OPENAI_API_KEY=${OA}\n` }), ['secrets/hardcoded/openai'])
  })

  test('a directory past the search depth leaves a receipt', async () => {
    // Past the cap, which real projects do not reach — a Next.js app router
    // with route groups tops out around nine levels, and the limit sits well
    // clear of that so that hitting it means something.
    const deep = Array.from({ length: 18 }, (_, i) => `d${i}`).join('/')
    const result = await scanProject({
      'app.ts': 'export const a = 1\n',
      [`${deep}/.env`]: `STRIPE_SECRET_KEY=${SK}\n`,
    })
    assert.equal(result.partial, true, 'the search stopped and said nothing')
    assert.ok(result.skipped.length > 0)
  })

  test('a string inside a template interpolation is still a string', async () => {
    assert.deepEqual(
      await ids({ 'app/api/u/route.ts': 'const m = `${"your session expired"}`\n' + ADMIN_ROUTE }),
      ['api/admin-db-access-without-auth'],
    )
    assert.deepEqual(
      await ids({ 'app/api/u/route.ts': 'const m = `${/* validate token */ 1}`\n' + ADMIN_ROUTE }),
      ['api/admin-db-access-without-auth'],
    )
  })

  test('a commented-out matcher does not stand in for the real one', async () => {
    assert.deepEqual(
      await ids({
        'app/api/u/route.ts': ADMIN_ROUTE,
        'middleware.ts':
          "// matcher: ['/api/:path*']\n" +
          'export function middleware(req){ const s = req.cookies.get("s"); if(!s) return new Response("no",{status:401}) }\n' +
          "export const config = { matcher: ['/dashboard/:path*'] }\n",
      }),
      ['api/admin-db-access-without-auth'],
    )
  })

  test('a catch-all under /api/auth proves nothing by its path alone', async () => {
    assert.deepEqual(await ids({ 'app/api/auth/[...evil]/route.ts': ADMIN_ROUTE }), [
      'api/admin-db-access-without-auth',
    ])
  })

  test('but a real Auth.js handler is still recognised', async () => {
    // Only actually constructing the handler is evidence; an unused import cannot
    // authenticate a route.
    assert.deepEqual(
      await ids({ 'app/api/auth/[...nextauth]/route.ts': "import NextAuth from 'next-auth'\n" + ADMIN_ROUTE }),
      ['api/admin-db-access-without-auth'],
    )
    const handler =
      "import NextAuth from 'next-auth'\n" +
      'const authHandler = NextAuth({ providers: [] })\n' +
      'export { authHandler as GET, authHandler as POST }\n'
    assert.deepEqual(
      await ids({ 'app/api/auth/[...nextauth]/route.ts': handler + ADMIN_ROUTE }),
      [],
    )
  })

  test('an origin with a fallback still reflects the caller', async () => {
    assert.deepEqual(
      await ids({
        's.js': "res.setHeader('Access-Control-Allow-Origin', req.headers.origin || process.env.APP_ORIGIN)\n" + CREDS,
      }),
      ['cors/reflected-origin-with-credentials'],
    )
    // And a configured origin on its own is still correct.
    assert.deepEqual(
      await ids({ 's.js': "res.setHeader('Access-Control-Allow-Origin', process.env.APP_ORIGIN)\n" + CREDS }),
      [],
    )
  })

  test('a commented-out safe origin does not win the pairing', async () => {
    assert.deepEqual(
      await ids({
        's.js':
          "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n" +
          "// 'Access-Control-Allow-Origin': 'https://app.com'\n" +
          CREDS,
      }),
      ['cors/reflected-origin-with-credentials'],
    )
  })

  test('a quoted identifier cannot smuggle a DROP statement', async () => {
    // A legal Postgres column name that contains a whole DDL statement. The
    // replay obeyed it and retired the very table it was declared in.
    assert.deepEqual(
      await ids({
        'c.ts': "import { createClient } from '@supabase/supabase-js'\n",
        'db.sql': 'CREATE TABLE public.orders (\n  id bigint,\n  "DROP TABLE public.orders;" text\n);\n',
      }),
      ['supabase/rls-not-enabled'],
    )
  })

  test('a DO block runs, so its DDL counts', async () => {
    assert.deepEqual(
      await ids({
        'c.ts': "import { createClient } from '@supabase/supabase-js'\n",
        'db.sql': 'DO $$ BEGIN\n  CREATE TABLE public.hidden (id int);\nEND $$;\n',
      }),
      ['supabase/rls-not-enabled'],
    )
  })

  test('an uppercase .ENV is an env file', async () => {
    assert.deepEqual(await ids({ '.ENV': `NEXT_PUBLIC_STRIPE_SECRET_KEY=${SK}\n` }), [
      'exposure/secret-in-public-env',
    ])
  })

  test('a credential word is not excused by a public one beside it', async () => {
    assert.deepEqual(await ids({ '.env.local': 'NEXT_PUBLIC_ANALYTICS_PASSWORD=Zp9Kx7Mv2Qa8Rt4Nb6\n' }), [
      'exposure/private-name-in-public-env',
    ])
  })

  test('a hash with no space before it still starts a comment', async () => {
    // What dotenv does, and disagreeing with the runtime hid the value.
    assert.deepEqual(await ids({ '.env.local': `NEXT_PUBLIC_OPENAI_API_KEY=${OA}#production\n` }), [
      'exposure/secret-in-public-env',
    ])
  })

  test('a deny in a child match does not retract the parent public read', async () => {
    assert.deepEqual(
      await ids({
        'firestore.rules':
          'match /{document=**} {\n  allow read: if true;\n\n  match /private/{id} {\n    allow write: if false;\n  }\n}\n',
      }),
      ['firebase/open-rules'],
    )
    // A deny in the same scope still means what it meant.
    assert.deepEqual(
      await ids({ 'firestore.rules': 'match /pub/{id} {\n  allow read: if true;\n  allow write: if false;\n}\n' }),
      [],
    )
  })

  test('a key added after the first commit is still in history', async () => {
    // Commit a harmless .env, add the key later, delete the file when you
    // notice. Reading only the revision that added the file saw nothing.
    await withGitRepo({ '.env': 'NODE_ENV=development\n', 'a.ts': 'export const a = 1\n' }, async (root) => {
      const git = (...args: string[]): void => {
        execFileSync('git', ['-c', 'user.email=t@e.com', '-c', 'user.name=t', ...args], { cwd: root, stdio: 'ignore' })
      }
      writeFileSync(join(root, '.env'), `STRIPE_SECRET_KEY=${SK}\n`, 'utf8')
      git('add', '-A')
      git('commit', '-q', '-m', 'add the key')
      rmSync(join(root, '.env'))
      git('add', '-A')
      git('commit', '-q', '-m', 'remove it again')

      const { findings } = await scan(root)
      const hit = findings.find((f) => f.ruleId === 'gitleak/env-in-history')
      assert.ok(hit, 'a key that entered history after the first commit went unreported')
      assert.equal(hit.confidence, 'certain')
    })
  })

  test('a known credential format outranks a public-looking name', async () => {
    await withGitRepo(
      { '.env': `NEXT_PUBLIC_STRIPE_SECRET_KEY=${SK}\n`, 'a.ts': 'export const a = 1\n' },
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId === 'gitleak/env-tracked')
        assert.ok(hit, 'the name said browser, so nothing looked at the value')
        assert.equal(hit.confidence, 'certain')
      },
    )
  })

  test('history for a subdirectory asks git the right question', async () => {
    // A pathspec is relative to the current directory; `rev:path` is relative
    // to the repository root. Using one form for both looked for app/app/.env.
    await withGitRepo({ 'app/.env': `STRIPE_SECRET_KEY=${SK}\n`, 'app/x.ts': 'export const a = 1\n' }, async (root) => {
      rmSync(join(root, 'app', '.env'))
      execFileSync('git', ['-c', 'user.email=t@e.com', '-c', 'user.name=t', 'commit', '-aqm', 'remove'], {
        cwd: root,
        stdio: 'ignore',
      })
      const { findings } = await scan(join(root, 'app'))
      const hit = findings.find((f) => f.ruleId === 'gitleak/env-in-history')
      assert.ok(hit)
      assert.equal(hit.confidence, 'certain', 'the history content could not be read')
    })
  })

  test('a credential in a filename does not reach the output', async () => {
    const result = await scanProject({ [`${OA}.ts`]: `const g = '${GH}'\n` })
    assert.ok(!JSON.stringify(result.findings).includes(OA), 'the path carried a key straight through')
  })

  test('the fix prompt says when the scan did not finish', async () => {
    // This output exists to be pasted into an assistant, which will act on it
    // and report success. "Nothing to fix" on a broken scan is the one place
    // the result must not stay silent about that.
    const prompt = renderFixPrompt([], { partial: true })
    assert.ok(prompt !== null, 'an incomplete scan produced no prompt at all')
    assert.match(prompt, /did not finish/i)
  })
})

describe('dogfooding — canship on its own repository', () => {
  // These tests come from the first dogfooding run, where canship reported its
  // own fixtures and the example connection string inside its own source
  // comments. The exemption logic lived only in the secrets rule at the time;
  // the exposure rule had missed it entirely.
  const SELF = join(here, '..')

  test('produces no certain-confidence finding on its own source', async () => {
    const { findings } = await scan(SELF)
    const certain = findings.filter((f) => f.confidence === 'certain')
    assert.deepEqual(
      certain.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`),
      [],
      'canship produced false positives on its own repository',
    )
  })

  test('anything it does report about itself is confined to the fixtures', async () => {
    // The fixtures really do contain secret-shaped strings, and reporting them
    // at lower confidence is accurate rather than wrong — they cannot carry
    // canship-ignore-file, because the tests scan them as project roots and
    // need the findings. What must never happen is a finding escaping into
    // src/: that would be the tool misreading its own implementation.
    const { findings } = await scan(SELF)
    const outsideFixtures = findings.filter((f) => !f.file?.includes('test/fixtures/'))
    assert.deepEqual(
      outsideFixtures.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`),
      [],
      'a finding escaped the fixtures',
    )
  })

  test('the scan of its own repository is complete', async () => {
    const result = await scan(SELF)
    assert.equal(result.partial, false, `canship could not finish scanning itself: ${JSON.stringify(result.errors)}`)
  })
})

describe('credentials pointing nowhere useful are not reported', () => {
  test('ignores connection strings for localhost / example.com / docker', async () => {
    const { findings } = await scan(CLEAN)
    const hit = findings.filter((f) => f.ruleId.includes('db-connection-string'))
    assert.deepEqual(hit.map((f) => `${f.file}:${f.line}`), [], 'noise on worthless targets')
  })

  test('but still reports connection strings for a real host', async () => {
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'secrets/hardcoded/db-connection-string')
    assert.ok(hit, 'a connection string with a real host was missed')
  })
})

describe('Supabase JWT role detection', () => {
  const anon =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnN0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6MjAxNTM2MDAwMH0.dGhpc19pc19hX2Zha2Vfc2lnbmF0dXJlX2Zvcl90ZXN0aW5nX29ubHk'
  const service =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFiY2RlZmdoaWprbG1ub3BxcnN0Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTcwMDAwMDAwMCwiZXhwIjoyMDE1MzYwMDAwfQ.dGhpc19pc19hX2Zha2Vfc2lnbmF0dXJlX2Zvcl90ZXN0aW5nX29ubHk'

  test('identifies service_role', () => {
    assert.equal(isSupabaseServiceRole(service), true)
  })

  test('lets anon through', () => {
    assert.equal(isSupabaseServiceRole(anon), false)
  })

  test('supports the newer sb_secret_ format', () => {
    assert.equal(isSupabaseServiceRole('sb_secret_abc123def456ghi789'), true)
  })

  test('does not misfire on non-JWT strings', () => {
    assert.equal(isSupabaseServiceRole('hello world'), false)
    assert.equal(isSupabaseServiceRole('eyJnotavalidjwt'), false)
  })
})

describe('placeholder detection', () => {
  test('recognises common placeholders', () => {
    assert.equal(isPlaceholder('sk-your-openai-key-here'), true)
    assert.equal(isPlaceholder('sk_live_xxxxxxxxxxxxxxxxxxxxxxxx'), true)
    assert.equal(isPlaceholder('sk-proj-REPLACE_ME_WITH_REAL_KEY'), true)
    assert.equal(isPlaceholder('sk-aaaaaaaaaaaaaaaaaaaaaaaa'), true)
  })

  test('does not mistake a realistic key for a placeholder', () => {
    assert.equal(isPlaceholder('sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'), false)
  })
})

describe('--fix-prompt', () => {
  test('returns null when there is nothing to fix', () => {
    assert.equal(renderFixPrompt([]), null)
  })

  test('never contains a full secret', async () => {
    const { findings } = await scan(VULNERABLE)
    const prompt = renderFixPrompt(findings)
    assert.ok(prompt)
    for (const secret of [
      'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn',
      'sk_live_51H8xQ2KZvKuab1cdEfGhIjKlMnOpQr',
      'sup3rS3cretPw',
    ]) {
      assert.ok(!prompt.includes(secret), 'the fix prompt leaked a secret; prompts get pasted and logged')
    }
  })

  test('tells the assistant not to echo secrets', async () => {
    const { findings } = await scan(VULNERABLE)
    const prompt = renderFixPrompt(findings)!
    assert.match(prompt, /Do not print any secret/i)
  })

  test('keeps human-only steps outside the pasteable section', async () => {
    const { findings } = await scan(VULNERABLE)
    const prompt = renderFixPrompt(findings)!
    const endOfPrompt = prompt.indexOf('--- End of prompt ---')
    assert.ok(endOfPrompt > 0, 'missing the end-of-prompt marker')

    const pasteable = prompt.slice(0, endOfPrompt)
    // Rotation is the step that actually revokes access, and an assistant
    // cannot do it. If it appeared inside the pasted block, the assistant would
    // claim it was handled.
    assert.ok(
      !/rotate/i.test(pasteable),
      'a rotation step leaked into the section meant for the AI assistant',
    )
    assert.match(prompt.slice(endOfPrompt), /rotate/i, 'rotation steps are missing entirely')
  })

  test('deduplicates identical human steps', async () => {
    const { findings } = await scan(VULNERABLE)
    const prompt = renderFixPrompt(findings)!
    // Asserted on whole lines rather than a substring: two different steps can
    // legitimately mention the same dashboard, and counting occurrences of a
    // phrase turned that into a failure the moment a second rule pointed at
    // the same page.
    const steps = prompt
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.startsWith('- Rotate'))
    assert.equal(
      new Set(steps).size,
      steps.length,
      `the same manual step was listed more than once:\n${steps.join('\n')}`,
    )
    assert.ok(steps.length > 0, 'the prompt should carry the rotation steps')
  })

  test('rotation wording reads as a sentence', async () => {
    const { findings } = await scan(VULNERABLE)
    const prompt = renderFixPrompt(findings)!
    assert.ok(
      !prompt.includes('Rotate this Database connection string with password'),
      'rotateLabel is not being applied',
    )
    assert.match(prompt, /Rotate this database password/i)
  })
})

describe('HTML report', () => {
  const opts = { root: '/tmp/project', generatedAt: '2026-08-23T00:00:00.000Z' }

  test('is fully self-contained — no external requests', async () => {
    const result = await scan(VULNERABLE)
    const html = renderHtml(result, opts)
    // Must work offline, from file://, and behind a restrictive network.
    assert.ok(!/<script\s+src=/i.test(html), 'external script')
    assert.ok(!/<link[^>]+stylesheet/i.test(html), 'external stylesheet')
    assert.ok(!/@import/i.test(html), 'CSS @import')
    assert.ok(!/https?:\/\/(?!(?:platform|console|dashboard|github|app)\.)/.test(html.replace(/<a href="[^"]*"/g, '')), 'unexpected external URL')
  })

  test('never contains a full secret', async () => {
    const result = await scan(VULNERABLE)
    const html = renderHtml(result, opts)
    for (const secret of [
      'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn',
      'sk_live_51H8xQ2KZvKuab1cdEfGhIjKlMnOpQr',
      'sup3rS3cretPw',
    ]) {
      assert.ok(!html.includes(secret), 'the HTML report leaked a secret')
    }
  })

  test('escapes HTML in user-controlled data', () => {
    // File paths and code excerpts come from the scanned project. canship is a
    // security tool; a report that executes a project's content would be an
    // embarrassing hole. A file literally named <script> must stay inert.
    const hostile: Finding = {
      ruleId: 'test/hostile',
      severity: 'P0',
      confidence: 'certain',
      title: 'Title with <script>alert(1)</script>',
      file: '<img src=x onerror=alert(2)>.ts',
      line: 1,
      excerpt: `const x = "</pre><script>alert(3)</script>"`,
      why: ['Why with <b>markup</b> & an ampersand'],
      fix: ['Fix step with <script>alert(4)</script>'],
      humanOnly: ['Manual step with <script>alert(5)</script>'],
    }
    const html = renderHtml(
      { findings: [hostile], filesScanned: 1, durationMs: 1, errors: [], skipped: [], ignored: [],
    vendored: 0, partial: false },
      opts,
    )
    // Check that no new element can be created from user data. Testing for the
    // substring "onerror=alert" would be wrong: once escaped it is inert text,
    // and the escaped form legitimately contains it.
    assert.ok(!html.includes('<script>alert'), 'unescaped script tag reached the report')
    assert.ok(!html.includes('<img'), 'unescaped img tag reached the report')
    assert.ok(!html.includes('</pre><script>'), 'excerpt broke out of its code block')
    // Escaped, not stripped — the user still needs to see what was found.
    assert.ok(html.includes('&lt;img src=x onerror=alert(2)&gt;'), 'expected escaping, not stripping')
    assert.ok(html.includes('&lt;script&gt;'), 'expected the markup to be escaped, not stripped')
  })

  test('a clean result does not claim the app is secure', async () => {
    const result = await scan(CLEAN)
    const html = renderHtml(result, opts)
    assert.match(html, /not that your app is secure/i)
  })

  test('warns that the report still exposes project structure', async () => {
    const result = await scan(VULNERABLE)
    const html = renderHtml(result, opts)
    assert.match(html, /file paths and project/i)
    // The banner also has to state the limit of the redaction itself. Masking
    // covers the formats canship has patterns for and nothing else, and a
    // reader deciding who to forward this to needs that in front of them.
    assert.match(html, /recognises are masked/i)
    assert.match(html, /pattern for can still appear/i)
  })
})

describe('redaction', () => {
  test('keeps the ends but not the body', () => {
    const secret = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'
    const out = redactSecret(secret)
    assert.ok(!out.includes(secret))
    assert.ok(out.startsWith('sk-pro'))
  })

  test('masks short strings entirely, leaving no plaintext', () => {
    assert.equal(redactSecret('abc').includes('abc'), false)
  })
})

describe('a third review — checks that went quiet instead of failing', () => {
  const SK = 'sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6'

  const ADMIN_ROUTE =
    "import { createClient } from '@supabase/supabase-js'\n" +
    'const a = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n' +
    'export async function GET(){ const { data } = await a.from("users").select("*"); return Response.json(data) }\n'

  /** A temp tree with no repository in it */
  async function tree(files: Record<string, string>): Promise<Awaited<ReturnType<typeof scan>>> {
    const root = mkdtempSync(join(tmpdir(), 'canship-r3-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      return await scan(root)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  /** Rule ids from one family, so an unrelated rule firing cannot fail the test */
  async function ids(files: Record<string, string>, prefix = ''): Promise<string[]> {
    const { findings } = await tree(files)
    return findings.filter((f) => f.ruleId.startsWith(prefix)).map((f) => f.ruleId)
  }

  /** A repository, plus whatever commits the test needs on top of the first */
  function withRepo(
    files: Record<string, string>,
    after: (root: string, commit: (msg: string) => void) => void,
    run: (root: string) => Promise<void>,
  ): Promise<void> {
    const root = mkdtempSync(join(tmpdir(), 'canship-r3g-'))
    const git = (...args: string[]): void => {
      execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', ...args], {
        cwd: root,
        stdio: 'ignore',
      })
    }
    const clean = (): void => {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
    try {
      git('init', '-q')
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      git('add', '-A', '-f')
      git('commit', '-q', '-m', 'init')
      after(root, (msg) => {
        git('add', '-A', '-f')
        git('commit', '-q', '-m', msg)
      })
      return run(root).finally(clean)
    } catch (err) {
      clean()
      throw err
    }
  }

  test('a repository git cannot read is an incomplete scan, not a clean one', async () => {
    // A .git git refuses stands in for every way this happens in the field:
    // git not installed, dubious ownership, a permission problem. All of them
    // used to be answered as "not a repository", and the history rule skips
    // itself on that answer without a word — so a repository with a live key
    // in its history scanned to zero findings, zero errors and exit 0.
    const result = await tree({
      '.git/not-really': 'this is not a git directory\n',
      'app.ts': 'export const a = 1\n',
    })
    assert.equal(result.partial, true, 'a repository git could not read scanned as complete')
    assert.ok(
      result.errors.some((e) => e.ruleId.startsWith('gitleak/')),
      'the history check went quiet instead of saying it could not run',
    )
  })

  test('a directory that is simply not a repository stays silent', async () => {
    // The other half, and the reason the two cases have to be told apart. Most
    // scans are of plain directories; warning on those makes the warning worth
    // nothing on the day it means something.
    const result = await tree({ 'app.ts': 'export const a = 1\n' })
    assert.deepEqual(
      result.errors.filter((e) => e.ruleId.startsWith('gitleak/')),
      [],
      'a plain directory was reported as a git failure',
    )
  })

  test('editing the key out of a tracked .env does not clean the history', async () => {
    // The ordinary way people "fix" this. Case A reads only the current
    // contents and found them clean; case B skipped every tracked path on the
    // grounds that case A had it covered. Between them, nothing was said.
    await withRepo(
      { '.env': `STRIPE_SECRET_KEY=${SK}\n`, 'app.ts': 'export const a = 1\n' },
      (root, commit) => {
        writeFileSync(join(root, '.env'), 'NODE_ENV=development\n', 'utf8')
        commit('clean it up')
      },
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId.startsWith('gitleak/'))
        assert.ok(hit, 'a key left in history was reported by neither branch')
        // The file is still in the index, so "was removed" would be the
        // confident false statement this rule exists never to make.
        assert.doesNotMatch(hit.title, /was removed/, 'claimed a still-tracked file had been deleted')
      },
    )
  })

  test('history deeper than the ceiling is admitted, not silently cut off', async () => {
    await withRepo(
      { '.env': `STRIPE_SECRET_KEY=${SK}\n`, 'app.ts': 'export const a = 1\n' },
      (root, commit) => {
        for (let i = 0; i < 100; i++) {
          writeFileSync(join(root, '.env'), `NODE_ENV=development\nBUILD=${i}\n`, 'utf8')
          commit(`touch ${i}`)
        }
        rmSync(join(root, '.env'))
        commit('remove')
      },
      async (root) => {
        const result = await scan(root)
        assert.equal(result.partial, true, 'a ceiling was reached and the scan still called itself complete')
        const note = result.errors.find((e) => e.kind === 'incomplete')
        assert.ok(note, 'nothing said how much of the history went unread')
        assert.match(note.message, /not checked/, 'the note did not say what was missed')
      },
    )
  })

  test('a token or session that is never checked does not stand in for a check', async () => {
    // `const token = await request.json()` silenced a route that held the
    // service_role key and checked nobody. The word is present; nothing is
    // being authorised with it.
    assert.deepEqual(
      await ids({ 'app/api/u/route.ts': ADMIN_ROUTE.replace('{ const', '{ const token = 1; const') }, 'api/'),
      ['api/admin-db-access-without-auth'],
    )
    assert.deepEqual(
      await ids({ 'app/api/u/route.ts': ADMIN_ROUTE.replace('{ const', '{ const session = 401; const') }, 'api/'),
      ['api/admin-db-access-without-auth'],
    )
    assert.deepEqual(
      await ids(
        {
          'app/api/u/route.ts': ADMIN_ROUTE.replace(
            '{ const',
            '{ const session = await getServerSession(); console.log(session); const',
          ),
        },
        'api/',
      ),
      ['api/admin-db-access-without-auth'],
    )
  })

  test('a session that is actually consulted still silences the rule', async () => {
    // The other direction, and the more expensive mistake. Narrowing these
    // signals must not start reporting routes that really are protected.
    const guards = [
      'const { data: { session } } = await a.auth.getSession(); if (!session) return new Response("no", { status: 401 });',
      'const session = await getServerSession(); if (session.user == null) return new Response("no", { status: 401 });',
      'const token = req.headers.get("authorization"); if (!token) return new Response("no", { status: 401 });',
    ]
    for (const guard of guards) {
      assert.deepEqual(
        await ids({ 'app/api/u/route.ts': ADMIN_ROUTE.replace('{ const', `{ ${guard} const`) }, 'api/'),
        [],
        `a real check was not recognised: ${guard}`,
      )
    }
  })

  test('a sub-path under an auth endpoint is not an auth endpoint', async () => {
    // /api/auth/export-all was already pinned as reportable. Moving the same
    // bulk export one segment deeper used to turn it invisible.
    for (const at of ['app/api/auth/signin/export-all/route.ts', 'app/api/auth/session/export-all/route.ts']) {
      assert.deepEqual(await ids({ [at]: ADMIN_ROUTE }, 'api/'), ['api/admin-db-access-without-auth'], at)
    }
  })

  test('the endpoints that are how you sign in are still exempt', async () => {
    for (const at of [
      'app/api/auth/signin/route.ts',
      'app/api/auth/callback/route.ts',
      'app/api/auth/callback/google/route.ts',
    ]) {
      assert.deepEqual(await ids({ [at]: ADMIN_ROUTE }, 'api/'), [], at)
    }
  })

  test('an origin function that never looks at the origin is origin: true', async () => {
    const cases = [
      'app.use(cors({ origin: (_o, callback) => callback(null, true), credentials: true }))',
      'app.use(cors({ origin: function (o, cb) { cb(null, true) }, credentials: true }))',
    ]
    for (const c of cases) {
      assert.deepEqual(
        await ids({ 's.js': `import cors from "cors"\n${c}\n` }, 'cors/'),
        ['cors/reflected-origin-with-credentials'],
        c,
      )
    }
  })

  test('an origin function that does look is an allowlist, and correct', async () => {
    const cases = [
      'app.use(cors({ origin: (o, cb) => A.includes(o) ? cb(null, true) : cb(new Error("no")), credentials: true }))',
      'app.use(cors({ origin: function (o, cb) { if (A.indexOf(o) !== -1) { cb(null, true) } else { cb(new Error("no")) } }, credentials: true }))',
      'app.use(cors({ origin: (o, cb) => cb(null, A.includes(o)), credentials: true }))',
    ]
    for (const c of cases) {
      assert.deepEqual(
        await ids({ 's.js': `import cors from "cors"\nconst A = ["https://a.com"]\n${c}\n` }, 'cors/'),
        [],
        c,
      )
    }
  })

  test('two Supabase apps in one repository do not answer for each other', async () => {
    // apps/b enabling RLS on its own public.users marked apps/a's unprotected
    // table as protected, so scanning the whole repository reported less than
    // scanning one app inside it.
    const client =
      "import { createClient } from '@supabase/supabase-js'\n" +
      'export const s = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY)\n'
    const found = await ids(
      {
        'apps/a/client.ts': client,
        'apps/a/supabase/migrations/1_init.sql': 'CREATE TABLE public.users (id uuid primary key);\n',
        'apps/b/client.ts': client,
        'apps/b/supabase/migrations/1_init.sql':
          'CREATE TABLE public.users (id uuid primary key);\nALTER TABLE public.users ENABLE ROW LEVEL SECURITY;\n',
      },
      'supabase/',
    )
    assert.deepEqual(found, ['supabase/rls-not-enabled'], "app B's migration answered for app A's table")
  })

  test('a Supabase workspace does not activate RLS checks in a plain PostgreSQL sibling', async () => {
    const result = await tree({
      'package.json': JSON.stringify({ private: true, workspaces: ['apps/*'] }),
      'apps/web/package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2.0.0' } }),
      'apps/web/client.ts': "import { createClient } from '@supabase/supabase-js'\n",
      'apps/web/supabase/migrations/1_init.sql': 'CREATE TABLE public.profiles (id uuid primary key);\n',
      'apps/backend/package.json': JSON.stringify({ dependencies: { pg: '^8.0.0' } }),
      'apps/backend/schema.sql': 'CREATE TABLE public.internal_jobs (id bigint primary key);\n',
    })
    const files = result.findings
      .filter((finding) => finding.ruleId === 'supabase/rls-not-enabled')
      .map((finding) => finding.file)
    assert.deepEqual(files, ['apps/web/supabase/migrations/1_init.sql'])
  })

  test('a filename a shell would act on is not handed back as a command', async () => {
    // The fix steps are meant to be run, and the path in them is chosen by
    // whoever added the file.
    await withRepo(
      { 'x;whoami;#/.env': `STRIPE_SECRET_KEY=${SK}\n`, 'app.ts': 'export const a = 1\n' },
      () => {},
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId.startsWith('gitleak/'))
        assert.ok(hit, 'the leak itself went unreported')
        for (const step of hit.fix) {
          assert.ok(
            !/git rm --cached\s+\S*;/.test(step),
            `a runnable command carried a shell separator: ${step}`,
          )
        }
      },
    )
  })

  test('an ordinary filename still gets a command, with a -- separator', async () => {
    await withRepo(
      { '.env': `STRIPE_SECRET_KEY=${SK}\n`, 'app.ts': 'export const a = 1\n' },
      () => {},
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId.startsWith('gitleak/'))
        assert.ok(hit)
        assert.ok(
          hit.fix.some((s) => s.includes('git rm --cached -- .env')),
          'the usual case lost its runnable fix, or its -- separator',
        )
      },
    )
  })

  test('a credential word outranks a public one in client code too', async () => {
    // checkEnvFile already knew this and named this very variable in a comment.
    // The branch reading process.env did the opposite: "analytics" excused
    // "password".
    assert.deepEqual(
      await ids({ 'a.tsx': "'use client'\nexport const A = process.env.NEXT_PUBLIC_ANALYTICS_PASSWORD\n" }, 'exposure/'),
      ['exposure/private-name-in-public-env'],
    )
  })

  test('a publishable key is still not a secret', async () => {
    // The guard on the change above: PRIVATE_PHRASES holds no bare KEY, so the
    // keys that are meant to be public stay unreported.
    assert.deepEqual(
      await ids({ 'a.tsx': "'use client'\nexport const A = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY\n" }, 'exposure/'),
      [],
    )
  })
})

describe('bounds and precedence, decided rather than inherited', () => {
  const CLI = join(here, '..', 'src', 'cli.ts')

  function run(args: string[]): { status: number; stdout: string } {
    try {
      const stdout = execFileSync('node', ['--import', 'tsx', CLI, ...args], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      })
      return { status: 0, stdout }
    } catch (err) {
      const e = err as { status?: number; stdout?: string }
      return { status: e.status ?? -1, stdout: e.stdout ?? '' }
    }
  }

  function inTemp(files: Record<string, string>, run: (root: string) => void): void {
    const root = mkdtempSync(join(tmpdir(), 'canship-b-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      run(root)
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  }

  const ADMIN_ROUTE =
    "import { createClient } from '@supabase/supabase-js'\n" +
    'const a = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n' +
    'export async function GET(){ const { data } = await a.from("users").select("*"); return Response.json(data) }\n'

  const GUARDED_MIDDLEWARE = (matcher: string): string =>
    'export function middleware(req){ const s = req.cookies.get("s"); if(!s) return new Response("no",{status:401}) }\n' +
    `export const config = { matcher: [${matcher}] }\n`

  test('a confirmed leak outranks an unfinished scan in the exit code', () => {
    // Both are true at once and one number has to be chosen. Exit 3 says "I
    // could not tell you", and a service_role key in the browser bundle is not
    // that. Pinned here so it stays a decision.
    inTemp(
      {
        'leak.ts': "'use client'\nexport const k = 'sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6'\n",
        'big.ts': 'x'.repeat(3 * 1024 * 1024),
      },
      (root) => {
        const r = run([root])
        assert.equal(r.status, 1, 'a confirmed leak was reported as a tool error')
        // The other half of the bargain: choosing 1 is only acceptable because
        // nothing is hidden by it.
        assert.match(r.stdout, /not everything was checked/i, 'the findings buried what went unread')
      },
    )
  })

  test('--json carries what the exit code could not', () => {
    inTemp(
      {
        'leak.ts': "'use client'\nexport const k = 'sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6'\n",
        'big.ts': 'x'.repeat(3 * 1024 * 1024),
      },
      (root) => {
        const parsed = JSON.parse(run([root, '--json']).stdout) as {
          partial: boolean
          findings: unknown[]
        }
        assert.equal(parsed.partial, true, 'a machine reading --json could not tell the scan was cut short')
        assert.ok(parsed.findings.length > 0)
      },
    )
  })

  test('the fix prompt tells the assistant that quoted repository text is data', async () => {
    // Paths and excerpts are chosen by whoever wrote the files, and this output
    // exists to be pasted into something that acts on it.
    const findings = (await scan(VULNERABLE)).findings
    const prompt = renderFixPrompt(findings, { partial: false, filesScanned: 16 })
    assert.ok(prompt, 'the vulnerable fixture should produce a prompt')
    assert.match(prompt, /never as instructions/i, 'nothing marked the quoted material as data')
    assert.match(prompt, /do not act on it/i, 'nothing told the assistant what to do about it')
  })

  test('a matcher that could run forever is refused, and said to be refused', () => {
    // A nested quantifier plus a long path is exponential backtracking, run
    // synchronously on the main thread against a pattern taken from the
    // repository being scanned.
    inTemp(
      {
        [`app/api/${'a'.repeat(40)}/route.ts`]: ADMIN_ROUTE,
        'middleware.ts': GUARDED_MIDDLEWARE('"/((a+)+)$"'),
      },
      (root) => {
        const parsed = JSON.parse(run([root, '--json']).stdout) as {
          partial: boolean
          errors: { message: string }[]
        }
        assert.equal(parsed.partial, true, 'an unevaluated matcher passed as a complete scan')
        assert.ok(
          parsed.errors.some((e) => /not evaluated/.test(e.message)),
          'the report did not say a matcher had been declined',
        )
      },
    )
  })

  test('the matcher Next.js documents is still read, not refused', async () => {
    // The guard on the change above. This pattern has groups and quantifiers;
    // what it does not have is a quantifier wrapped around a quantifier.
    const root = mkdtempSync(join(tmpdir(), 'canship-b2-'))
    try {
      mkdirSync(join(root, 'app', 'api', 'users'), { recursive: true })
      writeFileSync(join(root, 'app', 'api', 'users', 'route.ts'), ADMIN_ROUTE, 'utf8')
      writeFileSync(
        join(root, 'middleware.ts'),
        GUARDED_MIDDLEWARE('"/((?!api|_next/static|favicon.ico).*)"'),
        'utf8',
      )
      const result = await scan(root)
      assert.deepEqual(result.errors, [], 'a legitimate matcher was declined as dangerous')
      // That matcher deliberately excludes /api, so the route is not covered
      // and the finding stands.
      assert.ok(
        result.findings.some((f) => f.ruleId.startsWith('api/')),
        'refusing to read the matcher would have silenced this route',
      )
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('one file cannot produce an unbounded report', async () => {
    // Under the size cap and still able to name tens of thousands of matches,
    // each of which used to become a finding carrying paragraphs of prose.
    const root = mkdtempSync(join(tmpdir(), 'canship-b3-'))
    try {
      const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
      const lines: string[] = []
      for (let i = 0; i < 3000; i++) {
        let body = ''
        for (let j = 0; j < 24; j++) body += alphabet[(i * 7919 + j * 104729) % alphabet.length]
        lines.push(`export const k${i} = "sk_live_${body}"`)
      }
      writeFileSync(join(root, 'keys.ts'), lines.join('\n'), 'utf8')
      const result = await scan(root)
      assert.ok(result.findings.length <= 100, `report grew to ${result.findings.length} findings`)
      assert.equal(result.partial, true, 'a truncated report claimed to be complete')
      assert.ok(
        result.errors.some((e) => e.kind === 'incomplete' && /not reported/.test(e.message)),
        'the ceiling was reached without saying so',
      )
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })

  test('a line number is still correct once it is no longer counted from zero', async () => {
    // The binary search replaced a scan from the start of the file per match.
    // Same answer, or the excerpt belongs to the wrong line.
    const root = mkdtempSync(join(tmpdir(), 'canship-b4-'))
    try {
      writeFileSync(
        join(root, 'a.ts'),
        ['// one', '// two', 'export const k = "sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6"', '// four'].join('\n'),
        'utf8',
      )
      const { findings } = await scan(root)
      const hit = findings.find((f) => f.ruleId.startsWith('secrets/'))
      assert.ok(hit, 'the key went unreported')
      assert.equal(hit.line, 3, 'the finding pointed at the wrong line')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* ignore */
      }
    }
  })
})
