/** 显式工作区逐个扫描，配置、基线和跨文件证据不跨项目共享。 */
import { lstatSync, realpathSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { CONFIG_FILENAME, loadConfig } from './config.js'
import { applyBaseline, DEFAULT_BASELINE_PATH, readBaseline } from './baseline.js'
import { insideProject } from './project-path.js'
import { isExclusionPath } from './exclusions.js'
import { scan, cleanForOutput } from './engine.js'
import { scanExitCode, summarize } from './summary.js'
import { VERSION, getBuildInfo } from './build-info.js'
import { createJsonReport } from './report/json.js'
import type { JsonReport } from './report/json.js'
import type { ScanOptions, ScanResult } from './types.js'
import { ScanCancelledError, ScanProgressError } from './scan-control.js'
import { renderReport } from './report/terminal.js'
import { followupArgs } from './report/commands.js'

export const MAX_WORKSPACES = 32
export class WorkspaceError extends Error {}

/** 不接受目录越界、重叠或链接，防止同一文件被当作多个项目扫描。 */
export function resolveWorkspaces(root: string, paths: readonly string[]) {
  if (!paths.length || paths.length > MAX_WORKSPACES || !paths.every(isExclusionPath)) throw new WorkspaceError('Select 1–32 literal project-relative workspace directories; no globs or traversal.')
  let base: string
  try { base = realpathSync(root); if (!lstatSync(base).isDirectory()) throw new Error() }
  catch { throw new WorkspaceError('Workspace root must be an accessible directory.') }
  const selected: { path: string; root: string }[] = []
  const keys: string[] = []
  for (const raw of paths) {
    const path = raw.replace(/\\/g, '/').replace(/\/$/, '')
    const key = process.platform === 'win32' ? path.toLowerCase() : path
    if (keys.some(old => old === key || old.startsWith(key + '/') || key.startsWith(old + '/'))) throw new WorkspaceError('Workspace directories must be distinct and must not overlap.')
    let at = base
    try {
      for (const segment of path.split('/')) {
        at = join(at, segment)
        const info = lstatSync(at)
        if (info.isSymbolicLink() || !info.isDirectory()) throw new Error()
      }
    } catch { throw new WorkspaceError(`Workspace ${selected.length + 1} must be an accessible directory without symbolic links.`) }
    keys.push(key); selected.push({ path, root: at })
  }
  return selected
}

export interface WorkspaceOptions {
  all: boolean
  noConfig: boolean
  noExcerpts: boolean
  noIgnoreMarkers: boolean
  bestEffort: boolean
  baselineDefault: boolean
  only: string[]
  skip: string[]
  exclude: string[]
}
type Source = 'cli' | 'config' | 'default'
interface ProjectResult {
  path: string
  config: { status: 'loaded' | 'absent' | 'disabled'; sources: Record<'all' | 'rules' | 'exclude' | 'baseline', Source> } | null
  summary: ReturnType<typeof summarize> | null
  report: JsonReport | null
  error: { code: string; message: string } | null
  exitCode: 0 | 1 | 2 | 3
}
type Scanner = (root: string, options: ScanOptions) => Promise<ScanResult>

/** 配置只允许工作区内的常规文件；缺失与无法读取分别处理。 */
function regularConfig(root: string): void {
  try { if (!lstatSync(join(root, CONFIG_FILENAME)).isFile()) throw new WorkspaceError('Invalid workspace configuration file.') }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
}

async function scanProjects(selected: { path: string; root: string }[], options: WorkspaceOptions, scanner: Scanner,
  validate: (project: { path: string; root: string }) => void) {
  const projects: ProjectResult[] = []
  // 固定全局选项，外部进度回调不能改变后续项目的扫描范围。
  const settings = { ...options, only: [...options.only], skip: [...options.skip], exclude: [...options.exclude] }
  for (const project of selected) {
    let configuration: ProjectResult['config'] = null
    let stage = 'WORKSPACE_UNAVAILABLE'
    try {
      // 前一项目运行期间可能修改目录；读取配置前重新验证边界。
      validate(project)
      stage = 'CONFIG_INVALID'
      if (!settings.noConfig) regularConfig(project.root)
      const loaded = settings.noConfig ? { config: {}, path: null } : loadConfig(project.root)
      const config = loaded.config
      const selectedRules = settings.only.length > 0 || settings.skip.length > 0
      const sources: NonNullable<ProjectResult['config']>['sources'] = {
        all: settings.all ? 'cli' : config.all === undefined ? 'default' : 'config',
        rules: selectedRules ? 'cli' : config.only !== undefined || config.skip !== undefined ? 'config' : 'default',
        exclude: settings.exclude.length ? 'cli' : config.exclude === undefined ? 'default' : 'config',
        baseline: settings.baselineDefault ? 'cli' : config.baseline === undefined ? 'default' : 'config',
      }
      configuration = { status: settings.noConfig ? 'disabled' : loaded.path === null ? 'absent' : 'loaded', sources }
      stage = 'BASELINE_INVALID'
      const baselinePath = settings.baselineDefault ? resolve(project.root, DEFAULT_BASELINE_PATH)
        : config.baseline === undefined ? null : insideProject(project.root, config.baseline)
      let baseline = null
      if (baselinePath !== null) {
        // 显式默认基线同样不得通过链接读到其他项目。
        insideProject(project.root, baselinePath)
        if (!lstatSync(baselinePath).isFile()) throw new WorkspaceError('Invalid workspace baseline file.')
        baseline = readBaseline(baselinePath)
      }
      stage = 'WORKSPACE_SCAN_FAILED'
      let result = await scanner(project.root, { only: selectedRules ? settings.only : config.only ?? [],
        skip: selectedRules ? settings.skip : config.skip ?? [], exclude: settings.exclude.length ? settings.exclude : config.exclude ?? [],
        honorIgnoreMarkers: !settings.noIgnoreMarkers })
      let baselineSuppressed = 0, baselineStale = 0, baselineExpired = 0
      if (baseline) {
        const applied = applyBaseline(result.findings, baseline)
        result = { ...result, findings: applied.kept }
        baselineSuppressed = applied.suppressed; baselineStale = applied.stale; baselineExpired = applied.expired
      }
      const summary = summarize(result), exitCode = scanExitCode(result, settings.bestEffort)
      const all = settings.all || config.all === true
      const shown = all ? result.findings : result.findings.filter(f => f.confidence === 'certain')
      const report = createJsonReport({ ...result, findings: settings.noExcerpts ? shown.map(f => ({ ...f, excerpt: null })) : shown },
        { root: cleanForOutput(project.path), version: VERSION, build: getBuildInfo(), hiddenLikely: result.findings.length - shown.length,
          baselineSuppressed, baselineStale, baselineExpired, excerptsOmitted: settings.noExcerpts })
      projects.push({ path: cleanForOutput(project.path), config: configuration, summary, report, error: null, exitCode })
    } catch (error) {
      if (error instanceof ScanCancelledError || error instanceof ScanProgressError) throw error
      // 原始错误可能包含配置值、路径或源码，不合并进工作区报告。
      projects.push({ path: cleanForOutput(project.path), config: configuration, summary: null, report: null, exitCode: 3,
        error: { code: stage, message: 'This workspace could not be scanned. Run its individual scan locally for details.' } })
    }
  }
  const failed = projects.filter(project => project.error !== null).length
  const exitCode = failed ? 3 : projects.some(project => project.exitCode === 1) ? 1 : projects.some(project => project.exitCode === 2) ? 2 : projects.some(project => project.exitCode === 3) ? 3 : 0
  return { schemaVersion: 1, kind: 'workspace-report' as const, version: VERSION, exitCode,
    partial: projects.some(project => project.error !== null || project.summary?.partial),
    scope: 'Only explicitly selected workspace directories were scanned; parent and sibling project configuration and sources were not inherited.',
    counts: { projects: projects.length, failed, findings: projects.reduce((sum, p) => sum + (p.summary?.findings ?? 0), 0),
      blocking: projects.reduce((sum, p) => sum + (p.summary?.blocking ?? 0), 0), hiddenLikely: projects.reduce((sum, p) => sum + (p.report?.hiddenLikely ?? 0), 0) }, projects }
}

export function scanWorkspaces(root: string, paths: readonly string[], options: WorkspaceOptions, scanner: Scanner = scan) {
  return scanProjects(resolveWorkspaces(root, paths), options, scanner, project => {
    const checked = resolveWorkspaces(root, [project.path])[0]!
    if (checked.root !== project.root) throw new WorkspaceError('Workspace directory changed.')
  })
}

/** 编辑器复用相同配置与基线流程；低层公共 scan() 的无配置语义不变。 */
export async function scanConfiguredProject(root: string, options: WorkspaceOptions, scanner: Scanner = scan): Promise<ProjectResult> {
  const result = await scanProjects([{ root: resolve(root), path: '.' }], options, scanner, project => {
    if (!lstatSync(realpathSync(project.root)).isDirectory()) throw new WorkspaceError('Project root is unavailable.')
  })
  return result.projects[0]!
}

export function renderWorkspaces(report: Awaited<ReturnType<typeof scanWorkspaces>>, root: string, paths: string[], readFlags: string[], verbose: boolean): string {
  const lines = ['canship workspaces', report.scope, 'Counts exclude failed workspaces; incomplete coverage is reported separately.', '']
  for (const [index, project] of report.projects.entries()) {
    lines.push(`Workspace: ${project.path}`)
    if (project.config) lines.push(`Config: ${project.config.status}; sources: ` + Object.entries(project.config.sources).map(([key, value]) => `${key}=${value}`).join(', '))
    if (project.error) lines.push(`[${project.error.code}] ${project.error.message}`, '')
    else if (project.report) lines.push(renderReport(project.report, { root: project.path, showingLikely: project.report.hiddenLikely === 0,
      hiddenLikely: project.report.hiddenLikely, baselineSuppressed: project.report.baselineSuppressed,
      baselineStale: project.report.baselineStale, baselineExpired: project.report.baselineExpired,
      verbose, exitCode: project.exitCode, rerunArgs: followupArgs([resolve(root, paths[index]!), ...readFlags]) }), '')
  }
  lines.push(`${report.counts.projects} workspaces · ${report.counts.failed} failed · ${report.counts.findings} findings · ${report.counts.hiddenLikely} hidden likely`,
    `exit ${report.exitCode} · coverage ${report.partial ? 'incomplete' : 'complete within selected workspaces'}`, '')
  return lines.join('\n')
}
