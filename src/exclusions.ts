/** 使用字面相对路径排除文件或子树，不执行通配符或正则表达式。 */
export const MAX_EXCLUSIONS = 64
export const MAX_EXCLUSION_LENGTH = 512
const SEGMENT = String.raw`[^\s/\\](?:[^/\\]*[^\s/\\])?`
export const EXCLUSION_PATH_PATTERN = String.raw`^(?![!])(?!.*[:*?\[\]{}\u0000-\u001f\u007f-\u009f\u2028\u2029])(?!(?:.*[/\\])?\.{1,2}(?:[/\\]|$))` +
  SEGMENT + String.raw`(?:[/\\]` + SEGMENT + String.raw`)*[/\\]?$`
const PATH = new RegExp(EXCLUSION_PATH_PATTERN)

export function isExclusionPath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_EXCLUSION_LENGTH && PATH.test(value)
}

export function createExclusions(values: readonly string[] = []) {
  if (values.length > MAX_EXCLUSIONS || !values.every(isExclusionPath)) throw new TypeError('Exclusions must be at most 64 literal relative paths without traversal, wildcards or control characters.')
  const requested = [...new Set(values.map(value => value.replace(/\\/g, '/').replace(/\/$/, '')))]
  const matched = new Set<string>()
  return {
    requested,
    matches(path: string): boolean {
      const normalized = path.replace(/\\/g, '/').replace(/\/$/, '')
      let excluded = false
      for (const prefix of requested) if (normalized === prefix || normalized.startsWith(prefix + '/')) {
        matched.add(prefix)
        excluded = true
      }
      return excluded
    },
    matched: () => [...matched].sort(),
  }
}
