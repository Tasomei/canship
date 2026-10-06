/** 仅解析 JSON 项目配置，不执行目标项目代码。 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { isKnownSelector } from './rules/index.js'
import { configOffset, configPosition } from './config-location.js'

/** 扫描目录中的配置文件名。 */
export const CONFIG_FILENAME = 'canship.config.json'

/** 所有设置均可省略，显式命令行参数优先。 */
export interface Config {
  /** 基线路径。 */
  baseline?: string
  /** 仅执行匹配规则；与 skip 互斥。 */
  only?: string[]
  /** 排除匹配规则；与 only 互斥。 */
  skip?: string[]
  /** 显示疑似结果。 */
  all?: boolean
}

/** 接受不完整扫描必须由调用方通过命令行决定。 */
const REFUSED_KEYS = new Map([
  [
    'bestEffort',
    'accepting an incomplete scan is a decision for whoever runs canship, not for the project being scanned — pass --best-effort instead',
  ],
])

/** 配置读取或校验错误。 */
export class ConfigError extends Error {
  constructor(message: string, readonly location: { line: number; column: number; pointer: string | null } | null = null) {
    super(message)
  }
}

/** 支持的配置键。 */
const KNOWN_KEYS = new Set(['$schema', 'baseline', 'only', 'skip', 'all'])

type InvalidConfig = (message: string, field: string, index?: number) => never

/** 校验规则选择器列表。 */
function selectors(value: unknown, field: string, invalid: InvalidConfig): string[] {
  if (!Array.isArray(value)) {
    invalid(`"${field}" must be an array of rule ids`, field)
  }
  const out: string[] = []
  for (const [index, entry] of value.entries()) {
    if (typeof entry !== 'string' || entry === '') {
      invalid(`"${field}" must contain only rule ids`, field, index)
    }
    // 拒绝未知规则，防止拼写错误改变扫描范围。
    if (!isKnownSelector(entry)) {
      invalid(`"${field}" names no known rule`, field, index)
    }
    out.push(entry)
  }
  return out
}

function boolean(value: unknown, field: string, invalid: InvalidConfig): boolean {
  if (typeof value !== 'boolean') invalid(`"${field}" must be true or false`, field)
  return value
}

/** 独立解析配置文本，便于测试和定位错误。 */
export function parseConfig(text: string, path: string): Config {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch (error) {
    // 只提取解析器的位置数字，不转发可能包含源码的错误原文。
    const message = error instanceof Error ? error.message : ''
    const match = /\b(?:in|after) JSON at position (\d+)(?: \(line \d+ column \d+\))?$/.exec(message)
    const offset = match ? Number(match[1]) : message === 'Unexpected end of JSON input' ? text.length : null
    const position = offset !== null && offset <= text.length ? configPosition(text, offset) : null
    throw new ConfigError(`${path}${position ? `:${position.line}:${position.column}` : ''} is not valid JSON`,
      position ? { ...position, pointer: null } : null)
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new ConfigError(`${path} must contain a JSON object`)
  }
  const raw = parsed as Record<string, unknown>
  const invalid: InvalidConfig = (message, field, index) => {
    const pointer = '/' + field.replace(/~/g, '~0').replace(/\//g, '~1') + (index === undefined ? '' : `/${index}`)
    const position = configPosition(text, configOffset(text, field, index))
    throw new ConfigError(`${path}:${position.line}:${position.column}: ${message} (${pointer})`, { ...position, pointer })
  }

  // 拒绝未知配置键。
  for (const key of Object.keys(raw)) {
    const refused = REFUSED_KEYS.get(key)
    if (refused !== undefined) {
      invalid(`"${key}" is not allowed here — ${refused}`, key)
    }
    if (!KNOWN_KEYS.has(key)) {
      invalid(`unknown setting "${key}"`, key)
    }
  }

  const config: Config = {}
  // Schema 地址仅供编辑器使用，扫描器不读取或请求该地址。
  if (raw['$schema'] !== undefined && (typeof raw['$schema'] !== 'string' || raw['$schema'] === '')) {
    invalid('"$schema" must be a non-empty string', '$schema')
  }
  if (raw['baseline'] !== undefined) {
    if (typeof raw['baseline'] !== 'string' || raw['baseline'] === '') {
      invalid('"baseline" must be a file path', 'baseline')
    }
    config.baseline = raw['baseline']
  }
  if (raw['only'] !== undefined) config.only = selectors(raw['only'], 'only', invalid)
  if (raw['skip'] !== undefined) config.skip = selectors(raw['skip'], 'skip', invalid)
  if (raw['all'] !== undefined) config.all = boolean(raw['all'], 'all', invalid)

  // 两种规则选择模式不能同时设置。
  if (config.only !== undefined && config.skip !== undefined) {
    invalid('"only" and "skip" cannot both be set', 'skip')
  }
  return config
}

/** 限制配置文件大小，避免无界读取。 */
const MAX_CONFIG_BYTES = 1024 * 1024

/** 配置不存在时使用默认值；读取或解析失败必须报告。 */
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
    // 保留大小限制错误，仅包装文件系统异常。
    if (err instanceof ConfigError) throw err
    throw new ConfigError(
      `could not read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    )
  }
  return { config: parseConfig(text, path), path }
}
