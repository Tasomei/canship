/** 验证规则检测、误报边界、输出脱敏和命令行契约。
 * canship-ignore-file */

import { test, describe, after } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { cpSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
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

/** 保存临时夹具目录，测试结束后统一清理。 */
const fixtureCopies: string[] = []

/** 将夹具复制到仓库外，避免其结果受当前 Git 历史影响。 */
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
    // 验证夹具确实位于仓库之外。
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

/** 创建包含已提交文件的独立临时仓库。 */
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
      // 临时目录可能受 Windows 文件锁影响，清理失败不改变断言结果。
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    })
  } catch (err) {
    try {
      rmSync(root, { recursive: true, force: true })
    } catch {
      /* 临时目录清理失败不覆盖测试结果。 */
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
    // 客户端指令应使报告明确说明浏览器可读取凭据。
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
    // 完整模拟凭据不得原样出现在输出中。
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
    // 结论只描述仓库中的可见证据，不推断控制台状态。
    assert.match(hit.title, /in your migrations/i, 'title overclaims')
    assert.match(hit.why.join('\n\n'), /dashboard/i, 'does not mention the dashboard caveat')
  })

  test('clean fixture: all tables secured, nothing reported', async () => {
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.ruleId === 'supabase/rls-not-enabled')
    assert.deepEqual(hits.map((f) => f.title), [], 'false positive on correctly secured tables')
  })

  test('does NOT run on a plain Postgres project', async () => {
    // 普通后端数据库不能仅因未启用行级安全而报告。
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
    // 显式公开只读数据属于合法配置。
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
    // 管理员客户端可能通过导入间接使用。
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
    // 普通公开写入可能合法，因此保留疑似置信度。
    assert.equal(hit.confidence, 'likely')
    assert.equal(hit.severity, 'P1')
  })

  test('is not silenced by middleware whose matcher excludes /api', async () => {
    // 排除 API 的中间件匹配器不能保护 API。
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
    // Webhook 通过签名认证，无需用户登录。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.includes('webhooks'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on a signature-verified webhook')
  })

  test('does not flag a route that middleware protects', async () => {
    // 路由自身没有鉴权时，中间件仍可提供保护。
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
    // 通配符与凭据组合是浏览器拒绝的配置错误。
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'cors/wildcard-with-credentials')
    assert.ok(hit, 'missed the wildcard/credentials pair in next.config.js')
    assert.equal(hit.severity, 'P2')
    assert.match(hit.title, /rejected by every browser/i, 'title overclaims the impact')
    assert.match(hit.why.join('\n\n'), /echo the caller's Origin header back/i, 'does not warn about the usual "fix"')
  })

  test('does not flag a wildcard on its own', async () => {
    // 单独公开通配符来源属于正常配置。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.ruleId.startsWith('cors/'))
    assert.deepEqual(hits.map((f) => `${f.ruleId} @ ${f.file}:${f.line}`), [], 'noise on correct CORS')
  })

  test('does not flag an allowlist that compares before echoing', async () => {
    // 允许列表判断与直接回显应区分。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file === 'lib/cors.ts')
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on an allowlist check')
  })

  test('does not read client-side credentials settings as server policy', async () => {
    // 客户端携带凭据不等于服务端允许跨域凭据。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file === 'lib/api-client.ts')
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'confused a client setting for a server header')
  })

  test('pairs credentials with the nearest origin, not any nearby one', async () => {
    // 不同响应的来源和凭据设置不能交叉配对。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file === 'next.config.js')
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'paired credentials with an unrelated wildcard')
  })
})

describe('findings that only real repositories exposed', () => {
  // 覆盖实际项目中发现的检测边界。

  test('a committed env file holding a real credential is reported', async () => {
    await withGitRepo(
      // 使用非占位格式的模拟值，避免测试因占位识别而失效。
      { '.env.local': 'STRIPE_SECRET_KEY=sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6\n' },
      async (root) => {
        const { findings } = await scan(root)
        const hit = findings.find((f) => f.ruleId === 'gitleak/env-tracked')
        assert.ok(hit, 'missed a real secret committed to git')
      },
    )
  })

  test('.env.local.example is not a leak', async () => {
    // 环境模板命名使用统一判断。
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
    // 模板按文件名豁免，与所在目录无关。
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
    // 测试目录中的环境凭据仍需报告。
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
    // 已删除示例文件中的凭据仍需检查历史。
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
    // 仅含公开值的环境文件不应报告。
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
    // 迁移按顺序重放，已删除表不再报告。
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.title.includes('legacy_notes'))
    assert.equal(hit, undefined, 'reported a table that a later migration dropped')
  })

  test('a commented-out DROP TABLE cannot retire a finding', async () => {
    // 注释中的删除语句不能改变模式状态。
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'supabase/rls-not-enabled' && f.title.includes('orders'))
    assert.ok(hit, 'a comment hid a live table with no RLS')
  })

  test('a sign-in route is not reported for having no sign-in check', async () => {
    // 登录入口可执行必要的身份创建操作。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.startsWith('app/api/auth/'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'false positive on an auth endpoint')
  })

  test('a write through a session-scoped client is not reported', async () => {
    // 会话客户端交由数据库策略实施访问控制。
    const { findings } = await scan(CLEAN)
    const hits = findings.filter((f) => f.file?.startsWith('app/api/notes'))
    assert.deepEqual(hits.map((f) => f.ruleId), [], 'flagged the architecture the tool recommends')
  })

  test('a value that starts with test_ is not a credential', async () => {
    // 明确测试前缀属于占位符。
    await withGitRepo(
      { '.env.test': 'GITHUB_TOKEN=test_token\nSENTRY_AUTH_TOKEN=test_token\nSENTRY_ORG=test_org\n' },
      async (root) => {
        const { findings } = await scan(root)
        assert.deepEqual(findings.map((f) => f.ruleId), [], 'reported obvious scaffolding as a leak')
      },
    )
  })

  test('a type argument does not hide the client constructor', async () => {
    // 带泛型参数的客户端构造仍需识别。
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
  // 同一行不同提供方的凭据必须全部脱敏。
  const OPENAI = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'
  const GITHUB = 'ghp_9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn123'

  /** 查找残留凭据前缀，检测截断导致的部分泄露。 */
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
    // 各输出渠道均需满足统一脱敏约束。
    const result = await scan(VULNERABLE)
    const surfaces: Record<string, string> = {
      json: JSON.stringify(result.findings),
      terminal: renderReport(result, { root: VULNERABLE, showingLikely: true, hiddenLikely: 0 }),
      // 有修复步骤的夹具应生成提示。
      prompt: renderFixPrompt(result.findings) ?? '',
      html: renderHtml(result, { root: VULNERABLE, generatedAt: '1970-01-01T00:00:00.000Z' }),
    }
    for (const [name, text] of Object.entries(surfaces)) {
      // 同时检查完整值和足够长的前缀。
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
    // 脱敏调用者无需提前知道文本中的凭据。
    const masked = redactAll(`a ${OPENAI} b ${GITHUB} c`)
    assert.ok(!masked.includes(OPENAI))
    assert.ok(!masked.includes(GITHUB))
    assert.match(masked, /^a .+ b .+ c$/, 'the surrounding text should survive')
  })

  /** 按码位检查控制字符。 */
  const hasControlChar = (s: string): boolean =>
    [...s].some((ch) => {
      const c = ch.codePointAt(0) ?? 0
      return c < 0x20 || (c >= 0x7f && c <= 0x9f)
    })

  test('a paragraph break in an explanation survives to every renderer', async () => {
    // 段落数组应在各报告中保留段落结构。
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
    // 每段内部不得包含控制字符。
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
  // 规则异常必须留下记录并标记未完成。

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
      ignoredFindings: [],
      ruleSelection: null,
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
      // 将凭据放在超限文件尾部，防止仅探测头部造成假通过。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('a file git still lists but that is gone from disk is not an incomplete scan', async () => {
    // 普通未提交删除不构成读取错误。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('scanning nothing at all is never reported as clean', async () => {
    // 零文件扫描必须明确标记未完成。
    const root = mkdtempSync(join(tmpdir(), 'canship-empty-'))
    try {
      const result = await scan(root)
      assert.equal(result.filesScanned, 0)
      assert.equal(result.partial, true, 'a scan that read nothing claimed to be complete')

      const text = renderReport(result, { root, showingLikely: true, hiddenLikely: 0 })
      assert.doesNotMatch(text, /No exposed credentials found/, 'an empty scan showed the clean verdict')
      assert.match(text, /No files were scanned/, 'the report did not say it had read nothing')

      // 修复提示也必须说明没有实际扫描输入。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })
})

describe('a Supabase admin JWT is found outside JavaScript too', () => {
  const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url')
  const jwt = (role: string): string =>
    `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss: 'supabase', ref: 'qwertyuiopasdfghjklz', role, iat: 1700000000, exp: 2015360000 })}` +
    '.Zk3pQ9vR2mX7tL8wN4bY6cH1dJ5gF0sA'

  async function adminHits(files: Record<string, string>): Promise<Finding[]> {
    const root = mkdtempSync(join(tmpdir(), 'canship-jwt-'))
    try {
      for (const [rel, body] of Object.entries(files)) {
        const abs = join(root, rel)
        mkdirSync(dirname(abs), { recursive: true })
        writeFileSync(abs, body, 'utf8')
      }
      const { findings } = await scan(root)
      return findings.filter((f) => f.ruleId === 'exposure/supabase-service-role-in-client')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }

  // 修复前只检查前端源码，同一个管理员 JWT 写在以下文件中不会被报告。
  for (const [file, body] of [
    ['docker-compose.yml', `services:\n  api:\n    environment:\n      SUPABASE_SERVICE_ROLE_KEY: ${jwt('service_role')}\n`],
    ['worker.py', `KEY = '${jwt('service_role')}'\n`],
    ['config/settings.json', `{"supabaseKey": "${jwt('service_role')}"}\n`],
  ] as const) {
    test(`in ${file}`, async () => {
      const hits = await adminHits({ [file]: body })
      assert.equal(hits.length, 1)
      assert.equal(hits[0]!.confidence, 'certain')
      assert.equal(hits[0]!.line, body.split('\n').findIndex((l) => l.includes('eyJ')) + 1)
      assert.ok(!hits[0]!.excerpt?.includes(jwt('service_role')), 'the key was not redacted')
    })
  }

  test('an anon JWT outside JavaScript is not reported', async () => {
    assert.deepEqual(await adminHits({ 'docker-compose.yml': `ANON: ${jwt('anon')}\n` }), [])
  })

  test('a server-only env file holding the admin key is where it belongs', async () => {
    assert.deepEqual(await adminHits({ '.env.local': `SUPABASE_SERVICE_ROLE_KEY=${jwt('service_role')}\n` }), [])
  })
})

describe('places a credential can hide that an extension list never reaches', () => {
  const PRIVATE_KEY =
    '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIEowIBAAKCAQEAx7Vv2mQpLk8ZnR4tYwCdEfGhIjKlMnOpQrStUvWxYz0123456\n' +
    '-----END RSA PRIVATE KEY-----\n'

  /** 根据输入构造并扫描临时目录。 */
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  }

  test('a .pem private key is read', async () => {
    // 常见私钥文件扩展名必须参与扫描。
    const { findings } = await scanFiles({ 'server.pem': PRIVATE_KEY })
    assert.ok(
      findings.some((f) => f.ruleId === 'secrets/hardcoded/private-key'),
      'a private key in a .pem file was never opened',
    )
  })

  /** 包管理配置中的令牌需有对应检测模式。 */
  test('an npm token in .npmrc is reported', async () => {
    const { findings } = await scanFiles({
      '.npmrc': '//registry.npmjs.org/:_authToken=npm_aB3xY9zQ1wE5rT7yU2iO4pA6sD8fG0hJ2kL4\n',
    })
    assert.ok(
      findings.some((f) => f.ruleId === 'secrets/hardcoded/npm-token'),
      'an npm token can publish packages as you, and went unreported',
    )
  })

  test('a template npm token is not', async () => {
    // 令牌占位符不得误报。
    const { findings } = await scanFiles({
      '.npmrc': '//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n',
      'setup.md': 'Set `npm_yourTokenHereReplaceMe0123456789ab` before publishing.\n',
    })
    assert.deepEqual(
      findings.filter((f) => f.ruleId === 'secrets/hardcoded/npm-token'),
      [],
      'a placeholder was reported as a live npm token',
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
    // 提供正常文件，避免零文件状态干扰断言。
    const result = await scanFiles({
      README: 'just some notes\n',
      LICENSE: 'MIT\n',
      'app.ts': 'export const a = 1\n',
    })
    assert.equal(result.filesScanned, 1, 'probing pulled in files with nothing to check')
    assert.equal(result.partial, false)
  })

  test('a gitignored .env buried in a monorepo is still found', async () => {
    // 递归发现工作区中被 Git 忽略的环境文件。
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
    // 被忽略的服务端环境凭据属于正常使用。
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
    // 测试凭据降低置信度，但不丢弃。
    const { findings } = await scanFiles({
      'test/integration.ts': "const k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n",
    })
    const hit = findings.find((f) => f.ruleId === 'secrets/hardcoded/openai')
    assert.ok(hit, 'a real-looking key in test/ was waved through')
    assert.equal(hit.confidence, 'likely', 'a fixture key should not be certain-grade')
    assert.match(hit.title, /test or example file/i)
  })

  test('merely mentioning the opt-out does not trigger it', async () => {
    // 仅提及忽略标记的注释不能排除整文件。
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
      // 保留一个可扫描文件，单独验证忽略语义。
      writeFileSync(join(root, 'app.ts'), 'export const a = 1\n', 'utf8')
      const result = await scan(root)
      assert.deepEqual(result.ignored, ['fixture.ts'], 'the exclusion left no trace')
      // 主动忽略不应产生未完成状态。
      assert.equal(result.partial, false)
      const text = renderReport(result, { root, showingLikely: true, hiddenLikely: 0 })
      assert.match(text, /excluded by canship-ignore-file/, 'the report said nothing about it')
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('the file-level opt-out silences a file completely', async () => {
    // 拼接标记，避免测试源码自身被忽略。
    const marker = `canship-ignore` + `-file`
    const { findings } = await scanFiles({
      'test/integration.ts': `// ${marker}\nconst k = 'sk-proj-A9dKfM2xQwRt7YuIoPa1SdFgHjKlZxCvBn'\n`,
    })
    assert.deepEqual(findings.map((f) => f.ruleId), [], 'the opt-out was ignored')
  })
})

describe('variable names are read as words, not as a regex accident', () => {
  // 下划线不构成正则词边界，变量名需独立分词。

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
    // 普通单词中的片段不能匹配私密词。
    assert.equal(looksClearlyPrivate('SECRETARY_EMAIL'), false)
  })

  test('public markers are recognised too', () => {
    assert.equal(looksIntentionallyPublic('SUPABASE_ANON_KEY'), true)
    assert.equal(looksIntentionallyPublic('STRIPE_PUBLISHABLE_KEY'), true)
    assert.equal(looksIntentionallyPublic('INTERNAL_SECRET'), false)
  })

  test('a private-sounding public variable is reported once the name is readable', async () => {
    // 仅凭变量名判断的私密值使用疑似置信度。
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find((f) => f.ruleId === 'exposure/private-name-in-public-env')
    assert.ok(hit, 'the name heuristic is still not reading snake_case')
    assert.equal(hit.confidence, 'likely')
  })

  test('the public prefix does not exempt the variable it prefixes', async () => {
    // 移除公开前缀后再判断变量用途。
    const { findings } = await scan(VULNERABLE)
    assert.ok(
      findings.some((f) => f.ruleId === 'exposure/private-name-in-public-env'),
      'the prefix exempted the variable it was prefixing',
    )
    // 按设计公开的变量仍不报告。
    const anon = findings.find((f) => f.excerpt?.includes('ANON_KEY'))
    assert.equal(anon, undefined, 'the anon key is public by design')
  })

  test('a trailing comment does not hide the key it annotates', async () => {
    // 行尾注释不应混入凭据值。
    const { findings } = await scan(VULNERABLE)
    const hit = findings.find(
      (f) => f.ruleId === 'exposure/secret-in-public-env' && f.title.includes('GitHub'),
    )
    assert.ok(hit, 'an annotated key went unreported')
    assert.equal(hit.confidence, 'certain')
  })

  test('a # inside a quoted value is part of the password', async () => {
    // 引号内井号必须保留为值的一部分。
    const { findings } = await scan(CLEAN)
    assert.deepEqual(findings.map((f) => f.ruleId), [], 'a quoted # was read as a comment')
  })

  test('a UTF-16 source file is decoded, not written off as binary', async () => {
    // 带 BOM 的 UTF-16 源码应被正确解码。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('a comment mentioning a variable is not a variable', async () => {
    // 注释中的变量名示例不能视为实际访问。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })
})

describe('SQL is read as SQL, not as text that happens to contain keywords', () => {
  /** 构造含单条迁移的临时 Supabase 项目。 */
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  }

  test('a DROP inside a string literal does not drop anything', async () => {
    // 字符串内的 SQL 不能改变结构重放。
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
    // 块注释需完整处理嵌套层级。
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
    // 后续关闭行级安全必须反映在最终状态中。
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
    // 分别验证关闭保护、无效字符串语句及被删除表。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  }

  test('middleware covering one narrow path does not cover the rest', async () => {
    // 中间件必须逐路由判断覆盖。
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

  // 按 Next.js 16.3.6 自身的 getMiddlewareMatchers 实测：'/api' 只匹配 /api，不匹配 /api/users。
  // 官方文档称 '/about' 会匹配 '/about/team'，与实现不符，不能据此放宽。
  test('a bare path matcher covers only that exact path', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'middleware.ts': middleware('["/api"]'),
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  // Next.js 16 将 middleware 更名为 proxy；修复前 proxy 中的鉴权不被识别，路由被报为 P0 确定。
  for (const file of ['proxy.ts', 'src/proxy.ts']) {
    test(`a Next.js ${file} covers the route like middleware does`, async () => {
      const found = await scanProject({
        'app/api/users/route.ts': ADMIN_ROUTE,
        [file]: middleware('["/api/:path*"]').replace('function middleware', 'function proxy'),
      })
      assert.deepEqual(found, [], 'a route behind proxy was reported')
    })
  }

  test('a proxy whose matcher excludes the route does not cover it', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'proxy.ts': middleware('["/dashboard/:path*"]').replace('function middleware', 'function proxy'),
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  test('a proxy.ts outside the app root is not Next.js middleware', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'lib/net/proxy.ts': middleware('["/api/:path*"]'),
    })
    assert.deepEqual(found, ['api/admin-db-access-without-auth'])
  })

  test('an unguarded middleware beside a guarded proxy does not hide the guard', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'middleware.ts': 'export function middleware(){ return }\n',
      'proxy.ts': middleware('["/api/:path*"]').replace('function middleware', 'function proxy'),
    })
    assert.deepEqual(found, [])
  })

  test('matcher objects read their source', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'middleware.ts': middleware('[{ source: "/api/:path*", locale: false }]'),
    })
    assert.deepEqual(found, [])
  })

  // has/missing 条件使中间件只在部分请求上运行；修复前数组中的全部字符串（含 header 名）都被当作路径。
  for (const condition of ['has', 'missing']) {
    test(`a matcher object with ${condition} conditions does not cover the route`, async () => {
      const found = await scanProject({
        'app/api/users/route.ts': ADMIN_ROUTE,
        'middleware.ts': middleware(`[{ source: "/api/:path*", ${condition}: [{ type: "header", key: "x-internal" }] }]`),
      })
      assert.deepEqual(found, ['api/admin-db-access-without-auth'])
    })
  }

  test('an unconditional matcher entry still covers beside a conditional one', async () => {
    const found = await scanProject({
      'app/api/users/route.ts': ADMIN_ROUTE,
      'middleware.ts': middleware('[{ source: "/admin", has: [{ type: "cookie", key: "a" }] }, "/api/:path*"]'),
    })
    assert.deepEqual(found, [])
  })

  test('a comment is not an authorisation check', async () => {
    // 提醒添加鉴权的注释不构成鉴权。
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
    // 身份入口的相邻导出接口不享受豁免。
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
        /* 临时目录清理失败不覆盖测试结果。 */
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
    // 单一模板插值中的来源回显仍需识别。
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
    // 允许列表表达式不能被截断成直接回显。
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
    // 普通环境设置不属于凭据。
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
    // 子目录扫描只检查该目录范围内的历史。
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
  // 验证退出码、机器输出结构和选项组合。
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
    // 确定的低严重度问题不阻断发布。
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
        /* 临时目录清理失败不覆盖测试结果。 */
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

  /** 同时核对帮助文本和两份 README 的选项与退出码。 */
  describe('the documented options match the ones the CLI has', () => {
    const readme = (name: string): string => readFileSync(join(here, '..', name), 'utf8')

    /** 仅提取 README 选项表，避免混入其他工具参数。 */
    const documented = (markdown: string): Set<string> => {
      const found = new Set<string>()
      for (const line of markdown.split(/\r?\n/)) {
        if (!/^\|\s*`-/.test(line)) continue
        const firstCell = line.slice(1, line.indexOf('|', 1))
        for (const match of firstCell.matchAll(/`(--?[A-Za-z][\w-]*)/g)) found.add(match[1]!)
      }
      return found
    }

    /** 提取帮助文本中实际提供的选项。 */
    const offered = (help: string): Set<string> => {
      const block = help.slice(help.indexOf('Options'), help.indexOf('Exit codes'))
      const found = new Set<string>()
      for (const match of block.matchAll(/(?<![\w-])(--?[A-Za-z][\w-]*)/g)) found.add(match[1]!)
      return found
    }

    const sorted = (options: Set<string>): string[] => [...options].sort()

    test('--help and both READMEs name the same options', () => {
      const help = sorted(offered(run(['--help']).stdout))

      // 先断言提取结果非空，避免两个空集合造成假通过。
      assert.ok(help.length >= 7, `--help named only ${help.length} options`)
      assert.deepEqual(sorted(documented(readme('README.md'))), help)
      assert.deepEqual(sorted(documented(readme('README-zh-CN.md'))), help)
    })

    test('--help and both READMEs describe the same exit codes', () => {
      const codes = (text: string): string[] =>
        [...new Set([...text.matchAll(/(?:^|[|`\s])`?([0-3])`?(?=[|\s])/g)].map((m) => m[1]!))].sort()

      const help = run(['--help']).stdout
      const helpCodes = codes(help.slice(help.indexOf('Exit codes')))

      assert.deepEqual(helpCodes, ['0', '1', '2', '3'])
      for (const name of ['README.md', 'README-zh-CN.md']) {
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('--report writes a file, and composes with --json', () => {
    const dir = mkdtempSync(join(tmpdir(), 'canship-rep-'))
    const target = join(dir, 'r.html')
    try {
      const result = run([VULNERABLE, '--json', `--report=${target}`])
      // 写入报告后标准输出仍需为合法 JSON。
      JSON.parse(result.stdout)
      const html = readFileSync(target, 'utf8')
      assert.match(html, /<!doctype html>/i)
    } finally {
      try {
        rmSync(dir, { recursive: true, force: true })
      } catch {
        /* 临时目录清理失败不覆盖测试结果。 */
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  }

  test('the matcher from the Next.js docs does not silence the rule', async () => {
    // 正则非捕获分组不能被路径参数替换破坏。
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
    // 嵌套归档迁移不属于直接执行的迁移集合。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  }
  const ids = async (files: Record<string, string>): Promise<string[]> =>
    (await scanProject(files)).findings.map((f) => f.ruleId)

  test('a format the code already recognises is in the pattern table', async () => {
    // 共享格式表必须包含已有的私密密钥格式。
    assert.deepEqual(await ids({ 'a.ts': `const k = '${SB}'\n` }), ['secrets/hardcoded/supabase-secret-key'])
  })

  test('and therefore cannot be printed beside another credential', async () => {
    const result = await scanProject({ 'a.ts': `const c = { sb: '${SB}', gh: '${GH}' }\n` })
    assert.ok(!JSON.stringify(result.findings).includes(SB), 'the Supabase key reached the output in full')
  })

  test('a real key in .env.example is reported', async () => {
    // 环境模板中的实际凭据仍需检查。
    assert.deepEqual(await ids({ '.env.example': `OPENAI_API_KEY=${OA}\n` }), ['secrets/hardcoded/openai'])
  })

  test('a directory past the search depth leaves a receipt', async () => {
    // 超深目录必须显式披露。
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
    // 仅导入认证库不等于构造认证处理函数。
    assert.deepEqual(
      await ids({ 'app/api/auth/[...nextauth]/route.ts': "import NextAuth from 'next-auth'\n" + ADMIN_ROUTE }),
      ['api/admin-db-access-without-auth'],
    )
    const handler =
      "import NextAuth from 'next-auth'\n" +
      "import { createClient } from '@supabase/supabase-js'\n" +
      'const a = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)\n' +
      'const authHandler = NextAuth({ providers: [], callbacks: { async signIn() { await a.from("users").select("*"); return true } } })\n' +
      'export { authHandler as GET, authHandler as POST }\n'
    assert.deepEqual(
      await ids({ 'app/api/auth/[...nextauth]/route.ts': handler }),
      [],
    )
    // Auth.js 只保护它构造的处理函数，独立 DELETE 仍必须接受检查。
    assert.deepEqual(
      await ids({ 'app/api/auth/[...nextauth]/route.ts': handler +
        'export async function DELETE(){ return a.from("users").delete() }\n' }),
      ['api/admin-db-access-without-auth'],
    )
  })

  test('an origin with a fallback still reflects the caller', async () => {
    assert.deepEqual(
      await ids({
        's.js': "res.setHeader('Access-Control-Allow-Origin', req.headers.origin || process.env.APP_ORIGIN)\n" + CREDS,
      }),
      ['cors/reflected-origin-with-credentials'],
    )
    // 固定来源配置本身仍应通过。
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
    // 引用标识符内的 SQL 不能改变重放结果。
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
    // 环境注释解析应与运行时保持一致。
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
    // 同级拒绝规则仍按原语义生效。
    assert.deepEqual(
      await ids({ 'firestore.rules': 'match /pub/{id} {\n  allow read: if true;\n  allow write: if false;\n}\n' }),
      [],
    )
  })

  test('a key added after the first commit is still in history', async () => {
    // 检查后续提交加入的凭据，不能只检查首次添加版本。
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
    // 分别使用扫描相对路径和仓库对象路径。
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
    // 扫描失败时修复提示不能宣称无需修复。
    const prompt = renderFixPrompt([], { partial: true })
    assert.ok(prompt !== null, 'an incomplete scan produced no prompt at all')
    assert.match(prompt, /did not finish/i)
  })
})

describe('dogfooding — canship on its own repository', () => {
  // 自扫描应区分真实源码与故意包含问题的夹具。
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
    // 夹具保留疑似结果，用于验证实际规则行为。
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
    // 凭据轮换必须位于人工步骤区。
    assert.ok(
      !/rotate/i.test(pasteable),
      'a rotation step leaked into the section meant for the AI assistant',
    )
    assert.match(prompt.slice(endOfPrompt), /rotate/i, 'rotation steps are missing entirely')
  })

  test('deduplicates identical human steps', async () => {
    const { findings } = await scan(VULNERABLE)
    const prompt = renderFixPrompt(findings)!
    // 按完整步骤去重，避免错误合并提及相同平台的不同操作。
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
    // HTML 报告必须离线可用。
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
    // 来自项目的路径和内容必须转义。
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
    ignoredFindings: [],
      ruleSelection: null, vendored: 0, partial: false },
      opts,
    )
    // 验证输入不能构造新的 HTML 元素。
    assert.ok(!html.includes('<script>alert'), 'unescaped script tag reached the report')
    assert.ok(!html.includes('<img'), 'unescaped img tag reached the report')
    assert.ok(!html.includes('</pre><script>'), 'excerpt broke out of its code block')
    // 保留转义后的证据文本。
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
    // 明确脱敏仅覆盖已识别格式。
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

  /** 构造非仓库临时目录。 */
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  }

  /** 仅提取目标规则族，隔离无关规则结果。 */
  async function ids(files: Record<string, string>, prefix = ''): Promise<string[]> {
    const { findings } = await tree(files)
    return findings.filter((f) => f.ruleId.startsWith(prefix)).map((f) => f.ruleId)
  }

  /** 构造可追加提交的临时仓库。 */
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
        /* 临时目录清理失败不覆盖测试结果。 */
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
    // 存在元数据但不可读取时不能视为非仓库。
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
    // 普通非仓库目录不应触发 Git 失败提示。
    const result = await tree({ 'app.ts': 'export const a = 1\n' })
    assert.deepEqual(
      result.errors.filter((e) => e.ruleId.startsWith('gitleak/')),
      [],
      'a plain directory was reported as a git failure',
    )
  })

  test('editing the key out of a tracked .env does not clean the history', async () => {
    // 修改当前值不能消除历史中的凭据。
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
        // 仍被跟踪的文件不能描述为已删除。
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
    // 读取名为令牌的变量不等于鉴权。
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
    // 收紧鉴权判断时仍需保留合法保护方式。
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
    // 身份路径下更深的业务接口不享受入口豁免。
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
    // 不同应用的迁移不能互相提供保护。
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
    // 修复命令中的路径可能含特殊字符。
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
    // 源码引用与环境值判断采用相同私密词优先级。
    assert.deepEqual(
      await ids({ 'a.tsx': "'use client'\nexport const A = process.env.NEXT_PUBLIC_ANALYTICS_PASSWORD\n" }, 'exposure/'),
      ['exposure/private-name-in-public-env'],
    )
  })

  test('a publishable key is still not a secret', async () => {
    // 按设计公开的键仍不能误报。
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
        /* 临时目录清理失败不覆盖测试结果。 */
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
    // 确定严重问题的退出码优先于扫描未完成。
    inTemp(
      {
        'leak.ts': "'use client'\nexport const k = 'sk_live_51Nc7RtKm9Zp3WqLvB8Hd2Ys6'\n",
        'big.ts': 'x'.repeat(3 * 1024 * 1024),
      },
      (root) => {
        const r = run([root])
        assert.equal(r.status, 1, 'a confirmed leak was reported as a tool error')
        // 退出码优先级不能隐藏完整性提示。
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
    // 引用的项目内容必须标识为数据。
    const findings = (await scan(VULNERABLE)).findings
    const prompt = renderFixPrompt(findings, { partial: false, filesScanned: 16 })
    assert.ok(prompt, 'the vulnerable fixture should produce a prompt')
    assert.match(prompt, /never as instructions/i, 'nothing marked the quoted material as data')
    assert.match(prompt, /do not act on it/i, 'nothing told the assistant what to do about it')
  })

  test('a matcher that could run forever is refused, and said to be refused', () => {
    // 拒绝可能产生高成本回溯的匹配器。
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
    // 正常分组和量词组合仍应可用。
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
      // 排除 API 的匹配器不能提供保护。
      assert.ok(
        result.findings.some((f) => f.ruleId.startsWith('api/')),
        'refusing to read the matcher would have silenced this route',
      )
    } finally {
      try {
        rmSync(root, { recursive: true, force: true })
      } catch {
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('one file cannot produce an unbounded report', async () => {
    // 单文件大小合规也可能产生大量匹配。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })

  test('a line number is still correct once it is no longer counted from zero', async () => {
    // 行号索引优化必须保持定位正确。
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
        /* 临时目录清理失败不覆盖测试结果。 */
      }
    }
  })
})

describe('the fix prompt is not silent either', () => {
  // 修复提示也需披露被基线隐藏的结果。
  test('a baseline that emptied the list is named', () => {
    const out = renderFixPrompt([], { partial: false, baselineSuppressed: 3 })
    assert.notEqual(out, null)
    assert.match(out ?? '', /3 findings were hidden by a baseline/)
    assert.match(out ?? '', /still exist/)
  })

  test('a line marker is named with its location', () => {
    const out = renderFixPrompt([], {
      partial: false,
      silenced: ['lib/keys.ts:2 (secrets/hardcoded/stripe-live)'],
    })
    assert.match(out ?? '', /silenced by a canship-ignore-next-line marker/)
    assert.match(out ?? '', /lib\/keys\.ts:2/)
  })

  test('a rule selection is named', () => {
    const out = renderFixPrompt([], {
      partial: false,
      ruleSelection: 'everything except secrets, hiding 1',
    })
    assert.match(out ?? '', /rules were selected before this list was produced/)
  })

  test('the notes come before the paste marker', () => {
    // 抑制说明位于面向助手的粘贴区之前。
    const out =
      renderFixPrompt([{ ruleId: "secrets/hardcoded/openai", severity: "P0", confidence: "certain", title: "t", file: "lib/db.ts", line: 1, excerpt: null, why: ["w"], fix: ["f"] }], {
        partial: false,
        silenced: ['lib/keys.ts:2 (secrets/hardcoded/openai)'],
      }) ?? ''
    assert.ok(
      out.indexOf('silenced by a canship-ignore-next-line') < out.indexOf('Paste everything below'),
      'the suppression note came after the paste marker',
    )
  })

  test('a genuinely clean scan still says nothing', () => {
    // 没有相关状态时不输出多余提示。
    assert.equal(renderFixPrompt([], { partial: false }), null)
  })
})

describe('AI provider keys', () => {
  // 假密钥在运行时由哈希生成，源码中不出现凭据形状的字面量。
  const body = (seed: string, length: number): string => {
    let out = ''
    for (let i = 0; out.length < length; i++) out += createHash('sha256').update(`${seed}${i}`).digest('base64').replace(/[^A-Za-z0-9]/g, '')
    return out.slice(0, length)
  }
  const KEYS = {
    openrouter: `sk-or-v1-${body('or', 64)}`,
    groq: `gsk_${body('groq', 52)}`,
    huggingface: `hf_${body('hf', 34)}`,
    replicate: `r8_${body('r8', 37)}`,
    xai: `xai-${body('xai', 80)}`,
    perplexity: `pplx-${body('pplx', 48)}`,
  }

  async function scanSource(content: string): Promise<Finding[]> {
    const root = mkdtempSync(join(tmpdir(), 'canship-ai-keys-'))
    try {
      writeFileSync(join(root, 'client.ts'), content, 'utf8')
      return (await scan(root)).findings
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  }

  for (const [id, key] of Object.entries(KEYS)) {
    test(`${id}: a key is reported and redacted`, async () => {
      const findings = await scanSource(`const client = new Client({ apiKey: '${key}' })\n`)
      assert.deepEqual(findings.map((f) => f.ruleId), [`secrets/hardcoded/${id}`])
      assert.equal(findings[0]!.confidence, 'certain')
      assert.ok(!findings[0]!.excerpt?.includes(key), 'the key was printed in full')
      assert.ok(!redactAll(`key=${key}`).includes(key))
    })
  }

  test('an OpenRouter key is not reported as an OpenAI key', async () => {
    const findings = await scanSource(`const k = '${KEYS.openrouter}'\n`)
    assert.ok(!findings.some((f) => f.ruleId === 'secrets/hardcoded/openai'))
  })

  // 各服务官方文档中的示例写法。
  for (const example of ['gsk_your_groq_api_key_here', 'hf_...', 'xai-...', 'pplx-1234567890abcdef', 'sk-or-v1-your-key-here', 'sk-or-v1-...']) {
    test(`the documentation example ${example} is not reported`, async () => {
      assert.deepEqual(await scanSource(`const k = '${example}'\n`), [])
    })
  }

  test('a Replicate token of the wrong length is not a Replicate token', async () => {
    assert.deepEqual(await scanSource(`const k = 'r8_${body('short', 20)}'\n`), [])
  })
})
