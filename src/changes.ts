/** 只读比较本地 Git 状态；变更视图不缩小实际扫描范围。 */
import { execGitSync, hasContainedGitMetadata, resolveGitExecutable } from './git.js'
import { cleanForOutput } from './engine.js'
import { verdictOf } from './report/shared.js'
import type { ScanResult } from './types.js'

export interface ChangedFiles { baseCommit: string; mergeBase: string; paths: Set<string> }
export class ChangeViewError extends Error {}

/** 包含共同祖先以来的提交、暂存、工作区及未忽略的新文件；不拉取远程引用。 */
export function changedFilesSince(root: string, ref: string): ChangedFiles {
  if (!ref || ref.length > 1024 || /[\0\r\n]/.test(ref)) throw new ChangeViewError('Invalid changed-since reference.')
  const git = resolveGitExecutable(root)
  if (!git || !hasContainedGitMetadata(root)) throw new ChangeViewError('Changed-file views require a readable local Git repository.')
  try {
    const baseCommit = execGitSync(git, root, ['rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`]).trim()
    const mergeBase = execGitSync(git, root, ['merge-base', baseCommit, 'HEAD']).trim()
    const hash = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/
    if (!hash.test(baseCommit) || !hash.test(mergeBase)) throw new Error('Invalid object ID')
    const tracked = execGitSync(git, root, ['diff', '--no-ext-diff', '--no-textconv', '--no-renames',
      '--relative', '--name-only', '-z', mergeBase, '--', '.'])
    const untracked = execGitSync(git, root, ['ls-files', '--others', '--exclude-standard', '-z', '--', '.'])
    const paths = new Set((tracked + untracked).split('\0').filter(Boolean).map(cleanForOutput))
    return { baseCommit, mergeBase, paths }
  } catch {
    // Git 异常可能包含路径或输入值，只返回固定诊断。
    throw new ChangeViewError('Cannot compute changed files. Check that the base commit and merge history are available locally.')
  }
}

/** 仓库级或截断证据保留；其余结果按主位置及已知证据位置筛选。 */
export function changedFileView(result: ScanResult, changed: ChangedFiles): ScanResult {
  const findings = result.findings.filter(finding => finding.file === null || finding.evidenceTruncated ||
    changed.paths.has(finding.file) || finding.evidence?.some(step => changed.paths.has(step.file)))
  const verdict = verdictOf(result.findings)
  return { ...result, findings, changeView: {
    baseCommit: changed.baseCommit, mergeBase: changed.mergeBase, changedFiles: changed.paths.size,
    hiddenFindings: result.findings.length - findings.length, totalFindings: result.findings.length,
    totalBlocking: verdict.blocking, totalLikely: verdict.unsure,
  } }
}
