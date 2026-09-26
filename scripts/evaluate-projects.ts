/** 离线评估已下载的应用目录，只输出发现元数据，不输出源码和本机路径。 */
import { readFileSync, realpathSync, readdirSync } from 'node:fs'
import { resolve, relative, isAbsolute, sep } from 'node:path'
import { scan } from '../src/engine.js'
import { hasGitMetadataAbove } from '../src/git.js'
import type { Confidence, Severity } from '../src/types.js'
import { projectCanaries, scanWithCanary } from '../test/evaluation/project-canaries.js'
import type { ProjectFinding } from '../test/evaluation/project-canaries.js'
import type { ScanResult } from '../src/types.js'

interface Snapshot {
  id: string
  sourceFiles: number
  expectedFindings: Array<{ rule: string; severity: Severity; confidence: Confidence; file: string; line: number }>
}
const manifest = JSON.parse(readFileSync(new URL('../test/evaluation/projects.json', import.meta.url), 'utf8')) as { projects: Snapshot[] }

/** 比较全部结果，禁止只核对新增样本而遗漏对原项目的误报。 */
function evaluate(id: string, report: ScanResult, expected: ProjectFinding[]) {
  const findings = report.findings.map(f => ({ rule: f.ruleId, severity: f.severity, confidence: f.confidence, file: f.file, line: f.line }))
  const normalized = (items: ProjectFinding[]) => items.map(item => JSON.stringify(item)).sort().join('\n')
  return { id, filesScanned: report.filesScanned, durationMs: report.durationMs,
    partial: report.partial, errors: report.errors.length, skipped: report.skipped.length,
    findings, passed: !report.partial && report.filesScanned > 0 && normalized(findings) === normalized(expected) }
}
/** 不接受缺失文件、额外文件或链接，避免残缺快照被当作完整应用。 */
function sourceFileCount(root: string): number {
  let count = 0
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) throw new Error('Linked snapshot entry')
    if (entry.isDirectory()) count += sourceFileCount(resolve(root, entry.name))
    else if (entry.isFile()) count++
    else throw new Error('Opaque snapshot entry')
    if (count > 1000) throw new Error('Snapshot file limit')
  }
  return count
}
async function main(): Promise<void> {
  if (process.argv.length !== 3) throw new Error('Missing snapshot directory')
  const parent = realpathSync(resolve(process.argv[2]!))
  const results = []
  for (const source of manifest.projects) {
    const root = realpathSync(resolve(parent, source.id))
    const path = relative(parent, root)
    if (path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path) || hasGitMetadataAbove(root)) throw new Error('Invalid snapshot scope')
    if (sourceFileCount(root) !== source.sourceFiles) throw new Error('Incomplete or modified snapshot')
    results.push(evaluate(source.id, await scan(root), source.expectedFindings))
    for (const canary of projectCanaries(source.id)) {
      results.push(evaluate(`${source.id}/${canary.id}`, await scanWithCanary(root, canary),
        [...source.expectedFindings, ...canary.expected]))
    }
  }
  process.stdout.write(`${JSON.stringify({ cases: results.length, passed: results.filter(item => item.passed).length, results }, null, 2)}\n`)
  if (results.some(item => !item.passed)) process.exitCode = 1
}
main().catch(() => {
  process.stderr.write('Project evaluation failed. Supply a complete snapshot directory outside Git.\n')
  process.exitCode = 1
})
