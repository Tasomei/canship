/**
 * Project configuration, so a team's settings live in the repository.
 *
 * Everything canship does was reachable only through flags, which means a
 * decision a team makes once — this baseline, that rule is noise for us — has
 * to be retyped correctly by every person and every CI job, and is nowhere to
 * be reviewed when it changes.
 *
 * **JSON, and only JSON.** The obvious convenience would be `canship.config.js`,
 * and it is not available: the README's first promise is that the scan does not
 * execute project code, and a JS config file is project code. A scanner that
 * runs a file from the repository it is auditing has given up the property that
 * makes it safe to point at something you do not trust.
 *
 * `package.json` is not read either. canship scans Python, Go, Ruby and PHP
 * trees that have no package.json at all, and reading configuration out of a
 * file the rules also inspect means two different parsers with two different
 * ideas of what a broken file means.
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { isKnownSelector } from './rules/index.js'

/** The file canship looks for in the scanned directory */
export const CONFIG_FILENAME = 'canship.config.json'

/**
 * Settings a project can commit.
 *
 * Every field is optional, and a flag always wins over the file. The reverse
 * would mean a committed setting silently overriding what someone typed just
 * now, which is the wrong way round for a tool people reach for when something
 * looks wrong.
 */
export interface Config {
  /** Path to a baseline, as if --baseline had been passed */
  baseline?: string
  /** Run only these rules. Mutually exclusive with `skip`. */
  only?: string[]
  /** Run everything except these rules. Mutually exclusive with `only`. */
  skip?: string[]
  /** Show likely findings, as if --all had been passed */
  all?: boolean
}

/**
 * Settings this file is deliberately not allowed to carry.
 *
 * `bestEffort` was here for one commit and is the reason this list exists. It
 * turns an incomplete scan from exit 3 into exit 0 — and exit 3 is the whole
 * point of canship's exit codes: "found nothing" and "checked nothing" must not
 * share one. A file inside the scanned repository could therefore switch off
 * the signal that says the scan could not finish, and arranging for a scan to
 * be incomplete is easy (an unreadable file, a nested repository, anything over
 * the size cap).
 *
 * The others below hide findings, which is what they are for, and a project's
 * own maintainers writing them is the intended use. Accepting an incomplete
 * scan is different in kind: it is a judgement the person running canship makes
 * about their own tolerance, not a property of the project being scanned. So it
 * stays a flag.
 *
 * Named rather than silently ignored, because a setting that stops working
 * without saying so is how someone keeps believing it is in force.
 */
const REFUSED_KEYS = new Map([
  [
    'bestEffort',
    'accepting an incomplete scan is a decision for whoever runs canship, not for the project being scanned — pass --best-effort instead',
  ],
])

/** An unusable config file. Distinct so the CLI can name the file that is wrong. */
export class ConfigError extends Error {}

/** The keys this version understands */
const KNOWN_KEYS = new Set(['baseline', 'only', 'skip', 'all'])

/** Read and check a list of rule selectors */
function selectors(value: unknown, field: string, path: string): string[] {
  if (!Array.isArray(value)) {
    throw new ConfigError(`${path}: "${field}" must be an array of rule ids`)
  }
  const out: string[] = []
  for (const entry of value) {
    if (typeof entry !== 'string' || entry === '') {
      throw new ConfigError(`${path}: "${field}" must contain only rule ids`)
    }
    // A typo here is not harmless. In "only" it disables everything except a
    // rule that does not exist, which is every rule — a scan that checks
    // nothing and reports it as clean.
    if (!isKnownSelector(entry)) {
      throw new ConfigError(`${path}: "${field}" names no known rule: ${entry}`)
    }
    out.push(entry)
  }
  return out
}

function boolean(value: unknown, field: string, path: string): boolean {
  if (typeof value !== 'boolean') throw new ConfigError(`${path}: "${field}" must be true or false`)
  return value
}

/**
 * Parse a config file's text.
 *
 * Exported separately from reading it so the parse can be tested without a
 * filesystem, and so the CLI can name the path in every message.
 */
export function parseConfig(text: string, path: string): Config {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    throw new ConfigError(`${path} is not valid JSON`)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ConfigError(`${path} must contain a JSON object`)
  }
  const raw = parsed as Record<string, unknown>

  // An unknown key is an error rather than something to ignore. Ignoring it is
  // how "skipp" spends a year looking like it works.
  for (const key of Object.keys(raw)) {
    const refused = REFUSED_KEYS.get(key)
    if (refused !== undefined) {
      throw new ConfigError(`${path}: "${key}" is not allowed here — ${refused}`)
    }
    if (!KNOWN_KEYS.has(key)) {
      throw new ConfigError(`${path}: unknown setting "${key}"`)
    }
  }

  const config: Config = {}
  if (raw['baseline'] !== undefined) {
    if (typeof raw['baseline'] !== 'string' || raw['baseline'] === '') {
      throw new ConfigError(`${path}: "baseline" must be a file path`)
    }
    config.baseline = raw['baseline']
  }
  if (raw['only'] !== undefined) config.only = selectors(raw['only'], 'only', path)
  if (raw['skip'] !== undefined) config.skip = selectors(raw['skip'], 'skip', path)
  if (raw['all'] !== undefined) config.all = boolean(raw['all'], 'all', path)

  // Refused rather than resolved in some order, because both orders are
  // defensible and neither is guessable from the file.
  if (config.only !== undefined && config.skip !== undefined) {
    throw new ConfigError(`${path}: "only" and "skip" cannot both be set`)
  }
  return config
}

/**
 * How large this file may be.
 *
 * It is read out of the directory being scanned, with no flag asking for it,
 * which makes it the most reachable attacker-controlled input canship has —
 * more so than the baseline, which at least requires --baseline. Uncapped, a
 * 200 MB config was read and parsed in full before the first validation
 * rejected it: eleven seconds and two hundred megabytes to reach an error
 * message. It also fed the `baseline` path, which is walked one ancestor at a
 * time when it does not exist.
 *
 * A megabyte is far more than any real config needs — the whole schema is four
 * keys — and small enough that reading it is never the expensive part of a scan.
 */
const MAX_CONFIG_BYTES = 1024 * 1024

/**
 * Load the config from a scanned directory, or an empty config if there is none.
 *
 * Absence is normal and silent. A file that exists and cannot be read is not:
 * continuing with defaults would run a scan under settings nobody chose, and
 * report it as if they had.
 */
export function loadConfig(root: string): { config: Config; path: string | null } {
  const path = join(root, CONFIG_FILENAME)
  if (!existsSync(path)) return { config: {}, path: null }
  let text: string
  try {
    const size = statSync(path).size
    if (size > MAX_CONFIG_BYTES) {
      throw new ConfigError(
        `${path} is ${size} bytes, over the ${MAX_CONFIG_BYTES}-byte limit`,
      )
    }
    text = readFileSync(path, 'utf8')
  } catch (err) {
    // The size refusal already says the right thing; only a filesystem failure
    // needs wrapping.
    if (err instanceof ConfigError) throw err
    throw new ConfigError(
      `could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
  return { config: parseConfig(text, path), path }
}
