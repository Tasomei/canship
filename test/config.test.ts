/** 验证配置解析、规则选择及规则注册表的一致性。
 * canship-ignore-file */

import { test, describe, after } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { cpSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { scan } from '../src/engine.js'
import { ConfigError, parseConfig, loadConfig, CONFIG_FILENAME } from '../src/config.js'
import { RULE_IDS, isKnownSelector, ruleMatches } from '../src/rules/index.js'

const here = dirname(fileURLToPath(import.meta.url))
const tempDirs: string[] = []
after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true })
})

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'canship-config-'))
  tempDirs.push(dir)
  return dir
}

const OPENAI = 'sk-proj-Ab3xQ9zK7mNpR2tVwY4hJdLcF8gH1nT6bE0s'
const SENDGRID = 'SG.aB3xQ9zK7mNpR2tVwY4hJd.LcF8gH1nT6bE0sU5iO9jXrZaQwMkPvYdN3C'

/** 构造含两类模拟凭据的临时项目。 */
function twoSecrets(): string {
  const root = tempDir()
  mkdirSync(join(root, 'lib'))
  writeFileSync(
    join(root, 'lib', 'keys.ts'),
    `export const a = "${OPENAI}"\nexport const b = "${SENDGRID}"\n`,
    'utf8',
  )
  return root
}

describe('matching a selector against a rule id', () => {
  test('an exact id matches itself', () => {
    assert.equal(ruleMatches('secrets/hardcoded/openai', 'secrets/hardcoded/openai'), true)
  })

  test('a namespace matches everything under it', () => {
    assert.equal(ruleMatches('secrets', 'secrets/hardcoded/openai'), true)
    assert.equal(ruleMatches('secrets/hardcoded', 'secrets/hardcoded/openai'), true)
  })

  test('a half-typed id matches nothing', () => {
    // 规则选择器必须按完整名称或命名空间边界匹配。
    assert.equal(ruleMatches('secrets/hardcoded/open', 'secrets/hardcoded/openai'), false)
    assert.equal(ruleMatches('cors/w', 'cors/wildcard-with-credentials'), false)
  })

  test('a namespace is not matched by a longer string', () => {
    assert.equal(ruleMatches('secrets/hardcoded/openai', 'secrets'), false)
  })
})

describe('parsing a config file', () => {
  const at = 'canship.config.json'

  test('an empty object is a valid config', () => {
    assert.deepEqual(parseConfig('{}', at), {})
  })

  test('every supported setting round-trips', () => {
    const config = parseConfig(
      JSON.stringify({ baseline: 'b.json', skip: ['secrets'], all: true }),
      at,
    )
    assert.deepEqual(config, { baseline: 'b.json', skip: ['secrets'], all: true })
  })

  test('a refused setting is named rather than ignored', () => {
    // 明确拒绝不可配置的设置。
    assert.throws(() => parseConfig('{"bestEffort":true}', at), ConfigError)
  })

  test('an unknown setting is an error, not something to ignore', () => {
    // 未知键不能静默忽略。
    assert.throws(() => parseConfig('{"skipp":["secrets"]}', at), ConfigError)
  })

  test('a rule id that names nothing is an error', () => {
    // 未知规则不能造成全部规则被误关闭。
    assert.throws(() => parseConfig('{"skip":["secrets/typo"]}', at), ConfigError)
    assert.throws(() => parseConfig('{"only":["nonsense"]}', at), ConfigError)
  })

  test('only and skip cannot both be set', () => {
    assert.throws(() => parseConfig('{"only":["secrets"],"skip":["cors"]}', at), ConfigError)
  })

  test('wrong types are rejected', () => {
    assert.throws(() => parseConfig('{"all":"yes"}', at), ConfigError)
    assert.throws(() => parseConfig('{"skip":"secrets"}', at), ConfigError)
    assert.throws(() => parseConfig('{"baseline":""}', at), ConfigError)
    assert.throws(() => parseConfig('{"skip":[1]}', at), ConfigError)
  })

  test('a JSON array or invalid JSON is not a config', () => {
    assert.throws(() => parseConfig('[]', at), ConfigError)
    assert.throws(() => parseConfig('nope{', at), ConfigError)
  })

  test('no config file is normal and silent', () => {
    assert.deepEqual(loadConfig(tempDir()), { config: {}, path: null })
  })

  test('a config file is read from the scanned directory', () => {
    // 配置从扫描目录加载。
    const root = tempDir()
    writeFileSync(join(root, CONFIG_FILENAME), '{"all":true}', 'utf8')
    assert.equal(loadConfig(root).config.all, true)
  })
})

describe('rule selection changes what a scan reports', () => {
  test('nothing selected leaves ruleSelection null', async () => {
    const result = await scan(twoSecrets())
    assert.equal(result.ruleSelection, null)
    assert.equal(result.findings.length, 2)
  })

  test('skip removes one rule and records the cost', async () => {
    const result = await scan(twoSecrets(), { skip: ['secrets/hardcoded/openai'] })
    assert.deepEqual(
      result.findings.map((f) => f.ruleId),
      ['secrets/hardcoded/sendgrid'],
    )
    assert.deepEqual(result.ruleSelection, {
      only: [],
      skip: ['secrets/hardcoded/openai'],
      removed: 1,
    })
  })

  test('a namespace selector covers everything under it', async () => {
    const result = await scan(twoSecrets(), { skip: ['secrets'] })
    assert.equal(result.findings.length, 0)
    assert.equal(result.ruleSelection?.removed, 0)
    assert.deepEqual(result.ruleSelection?.skip, ['secrets'])
  })

  test('only keeps exactly what it names', async () => {
    const result = await scan(twoSecrets(), { only: ['secrets/hardcoded/sendgrid'] })
    assert.deepEqual(
      result.findings.map((f) => f.ruleId),
      ['secrets/hardcoded/sendgrid'],
    )
  })

  test('a selection is never silent', async () => {
    // 规则未执行时仍须披露选择条件。
    const result = await scan(twoSecrets(), { skip: ['secrets'] })
    assert.notEqual(result.ruleSelection, null)
    assert.equal(result.ruleSelection?.removed, 0)
    assert.deepEqual(result.ruleSelection?.skip, ['secrets'])
  })

  test('a selection does not make the scan partial', async () => {
    const result = await scan(twoSecrets(), { skip: ['secrets'] })
    assert.equal(result.partial, false)
  })
})

describe('RULE_IDS covers every id a scan can produce', () => {
  /** 将夹具复制到仓库外，避免继承当前 Git 状态。 */
  function fixture(name: string): string {
    const parent = mkdtempSync(join(tmpdir(), 'canship-config-fixture-'))
    tempDirs.push(parent)
    const target = join(parent, name)
    cpSync(join(here, 'fixtures', name), target, { recursive: true })
    return target
  }

  test('every rule id the vulnerable fixture produces is listed', async () => {
    // 所有实际输出的规则 ID 必须已注册。
    const result = await scan(fixture('vulnerable-nextjs'))
    assert.ok(result.findings.length > 0, 'the fixture produced no findings to check')
    for (const f of result.findings) {
      assert.ok(RULE_IDS.includes(f.ruleId), `RULE_IDS is missing ${f.ruleId}`)
    }
  })

  test('every listed id is selectable', () => {
    for (const id of RULE_IDS) {
      assert.equal(isKnownSelector(id), true, `${id} is listed but not selectable`)
    }
  })

  test('every namespace is selectable on its own', () => {
    for (const namespace of new Set(RULE_IDS.map((id) => id.split('/')[0]!))) {
      assert.equal(isKnownSelector(namespace), true, `${namespace} is not selectable`)
    }
  })

  test('the list has no duplicates', () => {
    assert.equal(new Set(RULE_IDS).size, RULE_IDS.length)
  })

  test('every hand-written id is one a rule can actually emit', () => {
    // 所有显式注册 ID 也必须对应实际实现。
    const sources = ['apiauth', 'cors', 'exposure', 'firebase', 'gitleak', 'supabase']
      .map((name) => readFileSync(join(here, '..', 'src', 'rules', `${name}.ts`), 'utf8'))
      .join('\n')
    for (const id of RULE_IDS) {
      if (id.startsWith('secrets/hardcoded/')) continue
      assert.ok(sources.includes(`'${id}'`), `${id} is in RULE_IDS but no rule emits it`)
    }
  })
})

describe('the scanned project cannot lower the exit code', () => {
  /** 构造含确定严重问题及可选配置的项目。 */
  function project(config?: string): string {
    const root = tempDir()
    mkdirSync(join(root, 'lib'))
    writeFileSync(join(root, 'lib', 'keys.ts'), `export const a = "${OPENAI}"\n`, 'utf8')
    if (config !== undefined) writeFileSync(join(root, CONFIG_FILENAME), config, 'utf8')
    return root
  }

  const cli = join(here, '..', 'src', 'cli.ts')
  const run = (root: string, args: string[] = []): { status: number; stderr: string } => {
    try {
      execFileSync('node', ['--import', 'tsx', cli, root, ...args], {
        stdio: ['ignore', 'ignore', 'pipe'],
        encoding: 'utf8',
      })
      return { status: 0, stderr: '' }
    } catch (err) {
      const e = err as { status?: number; stderr?: string }
      return { status: e.status ?? -1, stderr: e.stderr ?? '' }
    }
  }

  test('bestEffort is refused in the config file', () => {
    // 项目配置不能自行接受扫描未完成。
    const out = run(project('{"bestEffort":true}'))
    assert.equal(out.status, 3)
    assert.match(out.stderr, /"bestEffort" is not allowed here/)
  })

  test('the flag still works', () => {
    // 拒绝配置键不影响对应命令行选项。
    assert.equal(run(project(), ['--best-effort']).status, 1, 'findings still exit 1')
  })

  test('--no-config ignores a config that would hide the finding', () => {
    // 不可信项目可忽略其自带配置。
    const root = project('{"skip":["secrets"]}')
    assert.equal(run(root).status, 0, 'the config should hide it by default')
    assert.equal(run(root, ['--no-config']).status, 1, '--no-config should restore it')
  })

  test('--no-ignore-markers restores findings that source markers hide', () => {
    // --no-config 管不到源码中的标记，二者须同时用于不可信项目。
    const line = tempDir()
    mkdirSync(join(line, 'lib'))
    writeFileSync(join(line, 'lib', 'keys.ts'), `// canship-ignore-next-line\nexport const a = "${OPENAI}"\n`, 'utf8')
    const file = tempDir()
    mkdirSync(join(file, 'lib'))
    writeFileSync(join(file, 'lib', 'keys.ts'), `// canship-ignore-file\nexport const a = "${OPENAI}"\n`, 'utf8')
    // 另放一个普通文件，避免零文件扫描被判为未完成。
    writeFileSync(join(file, 'lib', 'ok.ts'), 'export const ok = 1\n', 'utf8')

    for (const root of [line, file]) {
      assert.equal(run(root, ['--no-config']).status, 0, 'a marker should hide it even with --no-config')
      assert.equal(run(root, ['--no-config', '--no-ignore-markers']).status, 1, '--no-ignore-markers should restore it')
    }
  })
})

describe('the config file is bounded', () => {
  // 自动读取的配置也必须有大小限制。
  test('an oversized config is refused rather than read', () => {
    const root = tempDir()
    mkdirSync(join(root, 'lib'))
    writeFileSync(join(root, 'lib', 'x.ts'), 'export const a = 1\n', 'utf8')
    // 构造略超上限的输入，避免测试占用过多资源。
    writeFileSync(
      join(root, CONFIG_FILENAME),
      `{"baseline":"${'a'.repeat(1024 * 1024 + 16)}"}`,
      'utf8',
    )
    assert.throws(() => loadConfig(root), ConfigError)
    try {
      loadConfig(root)
    } catch (err) {
      assert.match((err as Error).message, /over the \d+-byte limit/)
    }
  })

  test('a config at a normal size still loads', () => {
    const root = tempDir()
    writeFileSync(join(root, CONFIG_FILENAME), '{"all":true}', 'utf8')
    assert.equal(loadConfig(root).config.all, true)
  })

  test('a very deep baseline path is answered quickly', () => {
    // 限制缺失路径的祖先查找深度。
    const root = tempDir()
    mkdirSync(join(root, 'lib'))
    writeFileSync(join(root, 'lib', 'x.ts'), 'export const a = 1\n', 'utf8')
    writeFileSync(
      join(root, CONFIG_FILENAME),
      JSON.stringify({ baseline: `${'a/'.repeat(20_000)}b.json` }),
      'utf8',
    )
    const cli = join(here, '..', 'src', 'cli.ts')
    const started = Date.now()
    try {
      execFileSync('node', ['--import', 'tsx', cli, root, '--json'], { stdio: 'ignore' })
    } catch {
      /* 缺失基线应以退出码 3 结束。 */
    }
    const took = Date.now() - started
    assert.ok(took < 15_000, `took ${took}ms`)
  })
})
