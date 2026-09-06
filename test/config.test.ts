/**
 * Configuration and rule-selection tests.
 *
 * canship-ignore-file
 *
 * The marker above opts this file out of canship's own scan: it holds
 * credential-shaped strings as assertion data.
 *
 * The load-bearing test in here is the last one. RULE_IDS is a hand-written
 * list of every id a finding can carry, and a hand-written list of things
 * scattered across seven rule files is wrong the moment somebody adds an
 * eighth. It is what config validation checks selectors against, so a missing
 * entry does not fail quietly — it makes canship reject a rule id that is
 * printing in the user's own report. So the list is pinned to what a real scan
 * actually produces.
 */

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

/** A throwaway project holding two credentials from two different rules */
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
    // Without the slash boundary, `secrets/hardcoded/open` would turn off
    // `secrets/hardcoded/openai`, and a truncated id silently disabling a rule
    // is the failure this area exists to avoid.
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
    // Silently dropping it is how somebody keeps believing it is in force.
    assert.throws(() => parseConfig('{"bestEffort":true}', at), ConfigError)
  })

  test('an unknown setting is an error, not something to ignore', () => {
    // Ignoring it is how "skipp" spends a year looking like it works.
    assert.throws(() => parseConfig('{"skipp":["secrets"]}', at), ConfigError)
  })

  test('a rule id that names nothing is an error', () => {
    // In "only" a typo disables every rule except one that does not exist,
    // which is a scan that checks nothing and reports it as clean.
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
    // Not the working directory: `npx canship ./app` has to mean the same
    // thing as running it from inside ./app.
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
    assert.equal(result.ruleSelection?.removed, 2)
  })

  test('only keeps exactly what it names', async () => {
    const result = await scan(twoSecrets(), { only: ['secrets/hardcoded/sendgrid'] })
    assert.deepEqual(
      result.findings.map((f) => f.ruleId),
      ['secrets/hardcoded/sendgrid'],
    )
  })

  test('a selection is never silent', async () => {
    // A turned-off rule is a check that did not happen. If the result cannot
    // say so, a config file committed a year ago decides what "clean" means.
    const result = await scan(twoSecrets(), { skip: ['secrets'] })
    assert.notEqual(result.ruleSelection, null)
    assert.equal(result.ruleSelection?.removed, 2)
  })

  test('a selection does not make the scan partial', async () => {
    const result = await scan(twoSecrets(), { skip: ['secrets'] })
    assert.equal(result.partial, false)
  })
})

describe('RULE_IDS covers every id a scan can produce', () => {
  /** The fixtures, copied out of this repository so git state is not an input */
  function fixture(name: string): string {
    const parent = mkdtempSync(join(tmpdir(), 'canship-config-fixture-'))
    tempDirs.push(parent)
    const target = join(parent, name)
    cpSync(join(here, 'fixtures', name), target, { recursive: true })
    return target
  }

  test('every rule id the vulnerable fixture produces is listed', async () => {
    // The guard that keeps a hand-written list from drifting. A new finding id
    // that nobody added to RULE_IDS fails here, rather than becoming an id
    // that --skip refuses while the user is reading it in their own report.
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
    // The guard above only sees ids the fixture happens to trigger, so a
    // hand-written id that is a typo of a real one would sail through it. This
    // half checks the other direction: every literal in the list appears in the
    // rule source that emits it. The secrets ids are derived from
    // SECRET_PATTERNS rather than written out, so they cannot drift and are
    // excluded here.
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
  /** A project holding one certain P0 and, optionally, a config file */
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
    // It turns an incomplete scan from exit 3 into exit 0, and exit 3 is the
    // whole point of canship's exit codes. A file inside the repository being
    // scanned must not be able to switch off the signal that says the scan
    // could not finish — arranging for a scan to be incomplete is easy.
    const out = run(project('{"bestEffort":true}'))
    assert.equal(out.status, 3)
    assert.match(out.stderr, /"bestEffort" is not allowed here/)
  })

  test('the flag still works', () => {
    // Refusing the setting must not break the switch it belongs to.
    assert.equal(run(project(), ['--best-effort']).status, 1, 'findings still exit 1')
  })

  test('--no-config ignores a config that would hide the finding', () => {
    // The recourse for scanning code you do not control.
    const root = project('{"skip":["secrets"]}')
    assert.equal(run(root).status, 0, 'the config should hide it by default')
    assert.equal(run(root, ['--no-config']).status, 1, '--no-config should restore it')
  })
})
