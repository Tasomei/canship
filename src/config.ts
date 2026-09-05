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

import { existsSync, readFileSync } from 'node:fs'
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
  /** Accept an incomplete scan, as if --best-effort had been passed */
  bestEffort?: boolean
}

/** An unusable config file. Distinct so the CLI can name the file that is wrong. */
export class ConfigError extends Error {}

/** The keys this version understands */
const KNOWN_KEYS = new Set(['baseline', 'only', 'skip', 'all', 'bestEffort'])

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
  if (raw['bestEffort'] !== undefined) {
    config.bestEffort = boolean(raw['bestEffort'], 'bestEffort', path)
  }

  // Refused rather than resolved in some order, because both orders are
  // defensible and neither is guessable from the file.
  if (config.only !== undefined && config.skip !== undefined) {
    throw new ConfigError(`${path}: "only" and "skip" cannot both be set`)
  }
  return config
}

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
    text = readFileSync(path, 'utf8')
  } catch (err) {
    throw new ConfigError(
      `could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
  return { config: parseConfig(text, path), path }
}
