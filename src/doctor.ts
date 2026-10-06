/** 只读预检环境与显式文件目标，不扫描源码或输出用户配置内容。 */
import { accessSync, constants, existsSync, lstatSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { VERSION } from './build-info.js'
import { CONFIG_FILENAME, ConfigError, loadConfig } from './config.js'
import { readBaseline } from './baseline.js'
import { insideProject } from './project-path.js'
import { inspectOutput } from './output.js'
import { execGitSync, hasContainedGitMetadata, hasGitMetadataAbove, resolveGitExecutable } from './git.js'

interface DoctorOptions {
  root: string
  noConfig: boolean
  baseline: string | null
  report: string | null
  sarif: string | null
}
interface Check {
  id: string
  status: 'ok' | 'warning' | 'error' | 'skipped'
  code: string
  message: string
  nextStep: string | null
}

export function diagnose(options: DoctorOptions) {
  const checks: Check[] = []
  const add = (id: string, status: Check['status'], code: string, message: string, nextStep: string | null = null) =>
    checks.push({ id, status, code, message, nextStep })
  const node = process.versions.node
  if (Number(node.split('.')[0]) >= 18) add('node', 'ok', 'NODE_SUPPORTED', `Node.js ${node} meets the >=18 runtime requirement.`)
  else add('node', 'error', 'NODE_UNSUPPORTED', 'This Node.js version does not meet the >=18 requirement.', 'Use a supported Node.js version.')

  let rootReady = false
  try {
    if (!statSync(options.root).isDirectory()) throw new Error('not a directory')
    accessSync(options.root, constants.R_OK | constants.X_OK)
    rootReady = true
    add('root', 'ok', 'ROOT_ACCESSIBLE', 'The target directory passes read-access checks; file coverage has not been tested.')
  } catch {
    add('root', 'error', 'SCAN_ROOT_UNAVAILABLE', 'The target is not an accessible directory.', 'Check the target path and directory permissions.')
  }

  let configReady = false
  let configuredBaseline: string | undefined
  if (!rootReady) add('config', 'skipped', 'ROOT_REQUIRED', 'Configuration was not read because the target directory is unavailable.')
  else if (options.noConfig) {
    configReady = true
    add('config', 'skipped', 'CONFIG_DISABLED', 'Project configuration is disabled by --no-config.')
  } else {
    try {
      const configPath = join(options.root, CONFIG_FILENAME)
      if (existsSync(configPath) && !statSync(configPath).isFile()) throw new Error('not a file')
      const loaded = loadConfig(options.root)
      configuredBaseline = loaded.config.baseline
      configReady = true
      add('config', 'ok', loaded.path === null ? 'CONFIG_ABSENT' : 'CONFIG_VALID',
        loaded.path === null ? 'No project configuration was found; defaults apply.' : 'Project configuration is valid. Use --explain-config to review effective settings.')
    } catch (error) {
      const location = error instanceof ConfigError ? error.location : null
      add('config', 'error', 'CONFIG_INVALID', 'Project configuration could not be read or validated.' +
        (location ? ` Check line ${location.line}, column ${location.column}.` : ''), 'Run --explain-config for detailed configuration diagnostics.')
    }
  }

  if (!configReady) add('baseline', 'skipped', 'CONFIG_REQUIRED', 'The effective baseline cannot be determined until configuration is valid.')
  else {
    try {
      const path = options.baseline ?? (configuredBaseline === undefined ? null : insideProject(options.root, configuredBaseline))
      if (path === null) add('baseline', 'skipped', 'BASELINE_DISABLED', 'No baseline is configured.')
      else {
        // 在读取前拒绝非常规文件，避免命名管道等特殊目标阻塞诊断。
        if (!statSync(path).isFile()) throw new Error('not a file')
        const baseline = readBaseline(path)
        add('baseline', baseline.version === 2 ? 'warning' : 'ok', baseline.version === 2 ? 'BASELINE_LEGACY' : 'BASELINE_VALID',
          `Baseline v${baseline.version} is structurally valid (${baseline.entries.length} entries); matching and stale entries require a scan.`,
          baseline.version === 2 ? 'Review --baseline-migrate output before saving it to a different file.' : null)
      }
    } catch {
      add('baseline', 'error', 'BASELINE_INVALID', 'The baseline is missing, unreadable, invalid, or outside the configured project boundary.',
        'Check the baseline path and format. Use --baseline-migrate only for a valid v2/v3 baseline; do not overwrite it blindly.')
    }
  }

  if (!rootReady) add('git', 'skipped', 'ROOT_REQUIRED', 'Git was not checked because the target directory is unavailable.')
  else {
    const metadata = hasGitMetadataAbove(options.root)
    const executable = resolveGitExecutable(options.root)
    if (!executable) add('git', metadata ? 'error' : 'warning', 'GIT_UNAVAILABLE',
      'No Git executable outside project-controlled paths was found.', 'Install Git in a trusted system location to enable local Git checks.')
    else {
      try {
        execGitSync(executable, options.root, ['--version'], { maxBuffer: 8192 })
        if (!metadata) add('git', 'ok', 'GIT_NOT_APPLICABLE', 'Git is available; this directory has no local Git metadata. History checks do not apply.')
        else if (!hasContainedGitMetadata(options.root)) add('git', 'error', 'GIT_METADATA_UNSAFE',
          'Local Git metadata could not be associated safely with this worktree.', 'Check worktree or submodule metadata; scan nested repositories separately.')
        else {
          const inside = execGitSync(executable, options.root, ['rev-parse', '--is-inside-work-tree'], { maxBuffer: 8192 }).trim()
          if (inside !== 'true') throw new Error('not a worktree')
          const shallow = execGitSync(executable, options.root, ['rev-parse', '--is-shallow-repository'], { maxBuffer: 8192 }).trim()
          if (shallow !== 'true' && shallow !== 'false') throw new Error('unknown repository state')
          add('git', shallow === 'true' ? 'warning' : 'ok', shallow === 'true' ? 'GIT_SHALLOW' : 'GIT_METADATA_READABLE',
            shallow === 'true' ? 'This is a shallow checkout; historical coverage may be incomplete.' : 'Local worktree metadata is readable. Commit history and objects have not been scanned.',
            shallow === 'true' ? 'Use a complete local checkout when full historical coverage is required.' : null)
        }
      } catch {
        add('git', 'error', 'GIT_CHECK_FAILED', 'Git could not read the selected worktree metadata.',
          'Check the system Git installation, repository permissions and local metadata. No remote was contacted.')
      }
    }
  }

  const destinations = new Set<string>()
  for (const [kind, path] of [['html', options.report], ['sarif', options.sarif]] as const) {
    if (path === null) {
      add(kind, 'skipped', 'OUTPUT_NOT_REQUESTED', 'No output path was requested.')
      continue
    }
    try {
      const { target } = inspectOutput(path, kind)
      if (!lstatSync(dirname(target)).isDirectory()) throw new Error('not a directory')
      accessSync(dirname(target), constants.W_OK | constants.X_OK)
      const key = process.platform === 'win32' ? target.toLowerCase() : target
      if (destinations.has(key)) {
        add(kind, 'error', 'OUTPUT_PATH_CONFLICT', 'HTML and SARIF must use different output paths.', 'Choose a distinct destination for each format.')
      } else {
        destinations.add(key)
        add(kind, 'ok', 'OUTPUT_PREFLIGHT_OK', 'The destination passes read-only preflight. No file was created; actual write success is not guaranteed.')
      }
    } catch {
      add(kind, 'error', 'OUTPUT_PATH_INVALID', 'The destination is linked, unrelated, inaccessible, or has a missing parent directory.',
        'Choose a new file in an existing writable directory, or a recognized Canship output of the same format.')
    }
  }
  return {
    schemaVersion: 1,
    kind: 'doctor' as const,
    version: VERSION,
    scanPerformed: false,
    exitCode: checks.some(check => check.status === 'error') ? 3 as const : 0 as const,
    checks,
    limitations: ['No source scan, history scan, baseline matching, or test write was performed.',
      'Exit 0 means no preflight errors were found, not that the project is safe or scan coverage is complete.'],
  }
}

export function renderDoctor(report: ReturnType<typeof diagnose>): string {
  return ['canship environment diagnostics', 'No scan performed; no files written.', '',
    ...report.checks.flatMap(check => [`[${check.status}] ${check.id}: ${check.message} (${check.code})`,
      ...(check.nextStep ? [`  Next: ${check.nextStep}`] : [])]), '', ...report.limitations,
    `exit ${report.exitCode} · ${report.exitCode === 3 ? 'preflight errors' : 'no preflight errors'}`, ''].join('\n')
}
