/** 展示已解析的配置，不读取源码、基线内容或 Git 历史。 */
import { cleanForOutput } from '../engine.js'
import { VERSION } from '../build-info.js'
import { RULE_CATALOG } from '../rules/catalog.js'
import { ruleMatches } from '../rules/index.js'

type Source = 'cli' | 'config' | 'default'
interface Setting<T> { value: T; source: Source }
interface ConfigExplanationInput {
  root: string
  configPath: string | null
  configDisabled: boolean
  only: string[]
  skip: string[]
  ruleSource: Source
  pathExclusions?: { paths: string[]; source: Source }
  settings: {
    all: Setting<boolean>
    baseline: Setting<string | null>
    honorIgnoreMarkers: Setting<boolean>
    noExcerpts: Setting<boolean>
    bestEffort: Setting<boolean>
  }
}

export function explainConfig(input: ConfigExplanationInput) {
  const enabled = RULE_CATALOG.filter(rule =>
    (input.only.length === 0 || input.only.some(selector => ruleMatches(selector, rule.id))) &&
    !input.skip.some(selector => ruleMatches(selector, rule.id)))
  const ids = new Set(enabled.map(rule => rule.id))
  const excluded = RULE_CATALOG.filter(rule => !ids.has(rule.id)).map(rule => rule.id)
  const warnings: string[] = []
  if (input.pathExclusions?.paths.length) warnings.push('Configured paths are excluded before file-content and environment-history checks; excluded issues cannot affect scan status.')
  if (excluded.length) warnings.push(`${excluded.length} rule IDs are excluded; their findings will not affect scan status.`)
  if (!enabled.some(rule => rule.reportsFindings)) warnings.push('No finding-producing rules are enabled.')
  if (!input.settings.all.value) warnings.push('Likely findings are hidden, but still affect scan status. Use --all to show them.')
  if (input.settings.baseline.value !== null) warnings.push('A baseline is configured and may suppress findings. Its contents and validity have not been checked.')
  if (input.settings.honorIgnoreMarkers.value) warnings.push('Source ignore markers may suppress files or findings. Use --no-ignore-markers to disregard them.')
  if (input.settings.bestEffort.value) warnings.push('Incomplete coverage with no findings may exit 0; findings still exit 1 or 2.')
  return {
    schemaVersion: 1,
    kind: 'effective-config' as const,
    version: VERSION,
    scanPerformed: false,
    exclusions: { source: input.pathExclusions?.source ?? 'default', paths: (input.pathExclusions?.paths ?? []).map(cleanForOutput) },
    root: cleanForOutput(input.root),
    config: {
      status: input.configDisabled ? 'disabled' : input.configPath === null ? 'absent' : 'loaded',
      path: input.configPath === null ? null : cleanForOutput(input.configPath),
    },
    rules: {
      source: input.ruleSource,
      only: [...new Set(input.only)],
      skip: [...new Set(input.skip)],
      enabled: [...ids],
      excluded,
      nonReporting: enabled.filter(rule => !rule.reportsFindings).map(rule => rule.id),
    },
    settings: {
      ...input.settings,
      baseline: {
        ...input.settings.baseline,
        value: input.settings.baseline.value === null ? null : cleanForOutput(input.settings.baseline.value),
      },
    },
    warnings,
  }
}

export function renderConfigExplanation(report: ReturnType<typeof explainConfig>): string {
  const lines = [
    'canship effective configuration',
    'No scan performed. Exit 0 confirms configuration resolution only.',
    '',
    `Root: ${report.root}`,
    `Config: ${report.config.status}${report.config.path === null ? '' : ` (${report.config.path})`}`,
    `Path exclusions [${report.exclusions.source}]: ${report.exclusions.paths.join(', ') || 'none'}`,
    '',
    'Settings (source: cli / config / default):',
    ...Object.entries(report.settings).map(([key, setting]) => `  ${key}: ${setting.value ?? 'none'} [${setting.source}]`),
    '',
    `Rules [${report.rules.source}]: ${report.rules.enabled.length} enabled, ${report.rules.excluded.length} excluded`,
    ...report.rules.enabled.map(id => `  + ${id}${report.rules.nonReporting.includes(id) ? ' (public identifier; not reported)' : ''}`),
    ...report.rules.excluded.map(id => `  - ${id}`),
    '',
    ...report.warnings.map(warning => `Note: ${warning}`),
    'Paths remain visible. Review this output before sharing.',
  ]
  return lines.join('\n') + '\n'
}
