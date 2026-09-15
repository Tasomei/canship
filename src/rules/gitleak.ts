/** 检查当前跟踪及历史版本中的环境文件凭据。 */

import type { Finding, ProjectRule, ScanContext } from '../types.js'
import { isEnvFile, isExampleContext, isTemplateName } from '../walker.js'
import { basename } from 'node:path'
import { findKnownSecret, isPlaceholder } from './patterns.js'
import { looksClearlyPrivate, looksIntentionallyPublic, publicPrefixOf } from './framework.js'
import { parseEnvLine } from './envfile.js'
import { execGitBatch, execGitSync, hasContainedGitMetadata } from '../git.js'
import { createHash } from 'node:crypto'

/** 复用模板文件判断；模板本身不视为误提交。 */
function isEnvTemplate(path: string): boolean {
  return isTemplateName(path)
}

/** 示例目录仅降低置信度，不直接豁免。 */
function isScaffolding(path: string): boolean {
  return isExampleContext(path)
}

/** 判断路径能否安全出现在可复制的命令中。 */
function shellSafePath(path: string): boolean {
  return /^[A-Za-z0-9._/-]+$/.test(path) && !path.startsWith('-')
}

/** 仅为安全路径生成取消跟踪命令。 */
function untrackStep(path: string): string {
  return shellSafePath(path)
    ? `Stop tracking it: git rm --cached -- ${path}`
    : `Stop tracking it with "git rm --cached", putting the filename after a -- separator and quoting it ` +
        `for your shell. It is not written out as a runnable command here because the name contains ` +
        `characters a shell would act on instead of treating as part of a filename.`
}

/** 说明示例目录中的结果为何仍需审阅。 */
const SCAFFOLD_NOTE =
  `This file sits in a test, fixture, example or docs directory, where fake keys are normal — so ` +
  `this is probably scaffolding rather than a leak, and it is reported quietly for that reason. It is ` +
  `not skipped outright because a real key committed to a test directory is exactly as stolen as one in ` +
  `src/. If the values in it are deliberately fake, put canship-ignore-file on a line of its own in that ` +
  `file and canship will skip it and say so.`

/** 凭据证据分为确定、疑似和无证据。 */
type Evidence = 'proof' | 'hint' | 'none'

/** 排除过短的普通设置值。 */
const SUBSTANTIAL_VALUE = 12

function evidenceIn(lines: string[]): Evidence {
  let best: Evidence = 'none'

  for (const raw of lines) {
    // 复用环境赋值解析，正确处理引号及注释。
    const assignment = parseEnvLine(raw)
    if (!assignment) continue

    const key = assignment.key.toUpperCase()
    const value = assignment.value

    if (!value || isPlaceholder(value)) continue

    // 已知凭据格式优先于变量名用途判断。
    const known = findKnownSecret(value)
    if (known) {
      // 按设计公开的标识符不作为凭据证据。
      if (known.publicByDesign) continue
      return 'proof'
    }

    // 无法确认格式时再根据公开用途排除。
    if (publicPrefixOf(key) !== null || looksIntentionallyPublic(key)) continue

    if (looksClearlyPrivate(key)) return 'proof'
    if (value.length >= SUBSTANTIAL_VALUE) best = 'hint'
  }

  return best
}

function git(root: string, gitExecutable: string | null, args: string[]): string | null {
  if (gitExecutable === null) return null
  try {
    return execGitSync(gitExecutable, root, args)
  } catch {
    return null
  }
}

/** 通过单个 Git 进程批量读取对象，按字节帧解析结果。 */
function batchBlobs(
  root: string,
  gitExecutable: string | null,
  specs: string[],
): (string | null)[] {
  if (gitExecutable === null || specs.length === 0) return specs.map(() => null)
  // 含换行的路径不适用逐行批协议，回退为独立读取。
  if (specs.some((spec) => spec.includes('\n') || spec.includes('\r'))) {
    return specs.map((spec) => git(root, gitExecutable, ['show', '--no-ext-diff', '--no-textconv', spec]))
  }
  let out: Buffer
  try {
    out = execGitBatch(
      gitExecutable,
      root,
      ['cat-file', '--batch', '--buffer'],
      `${specs.join('\n')}\n`,
    )
  } catch {
    // 批次失败时将全部对象标记为不可读。
    return specs.map(() => null)
  }

  const blobs: (string | null)[] = []
  let at = 0
  for (let i = 0; i < specs.length; i++) {
    const newline = out.indexOf(0x0a, at)
    if (newline === -1) break
    const header = out.toString('utf8', at, newline)
    at = newline + 1
    // 缺少合法大小字段时表示对象无法解析。
    const size = Number(header.slice(header.lastIndexOf(' ') + 1))
    if (!Number.isInteger(size) || size < 0) {
      blobs.push(null)
      continue
    }
    blobs.push(out.toString('utf8', at, at + size))
    // 对象后的分隔换行不属于对象内容。
    at += size + 1
  }
  // 截断响应的剩余对象标记为不可读。
  while (blobs.length < specs.length) blobs.push(null)
  return blobs
}

/** 必需的 Git 查询失败时抛出异常，由引擎记录。 */
function gitOrThrow(root: string, gitExecutable: string | null, args: string[]): string {
  const out = git(root, gitExecutable, args)
  if (out === null) throw new Error(`git ${args.slice(0, 2).join(' ')} failed in ${root}`)
  return out
}

/** 获取扫描目录在仓库中的路径前缀。 */
function repoPrefix(root: string, gitExecutable: string | null): string {
  return (git(root, gitExecutable, ['rev-parse', '--show-prefix']) ?? '').trim()
}

/** 列出当前跟踪的环境文件。 */
function trackedEnvFiles(root: string, gitExecutable: string | null): string[] {
  const out = gitOrThrow(root, gitExecutable, ['ls-files', '-z'])
  return out
    .split('\0')
    .filter(Boolean)
    .filter((p) => isEnvFile(basename(p)) && !isEnvTemplate(p))
}

/** 保存仓库相对路径和扫描目录相对路径。 */
interface HistoricalPath {
  /** 相对仓库根目录的对象路径。 */
  repoPath: string
  /** 相对扫描目录的展示和去重路径。 */
  localPath: string
}

/** 列出历史中出现过的环境文件，包括已删除文件。 */
function historicalEnvFiles(root: string, gitExecutable: string | null, prefix: string): HistoricalPath[] {
  // 禁用重命名检测并使用空字符分隔，保留原始文件名。
  const out = gitOrThrow(root, gitExecutable, [
    'log',
    '--no-ext-diff',
    '--no-textconv',
    '--all',
    '--pretty=format:',
    '--no-renames',
    '--diff-filter=A',
    '--name-only',
    '-z',
    '--',
    '.',
  ])
  const seen = new Map<string, HistoricalPath>()
  for (const repoPath of out.split('\0')) {
    if (!repoPath || !isEnvFile(basename(repoPath)) || isEnvTemplate(repoPath)) continue
    // 按扫描范围去除仓库路径前缀。
    const localPath = prefix && repoPath.startsWith(prefix) ? repoPath.slice(prefix.length) : repoPath
    if (!seen.has(localPath)) seen.set(localPath, { repoPath, localPath })
  }
  return [...seen.values()]
}

/** 每个文件最多检查的历史版本数。 */
const MAX_HISTORY_REVISIONS = 100

/** 历史版本中的最强证据及未完成统计。 */
interface HistoryScan {
  evidence: Evidence
  /** 用于区分历史版本的新凭据，不保存历史原文。 */
  sourceFingerprint?: string
  /** 超过检查上限的版本数下界。 */
  unread: number
  /** 无法读取的历史版本数。 */
  unreadable: number
}

function historicalEvidence(
  root: string,
  gitExecutable: string | null,
  entry: HistoricalPath,
): HistoryScan | null {
  // 路径筛选使用扫描相对路径，对象读取使用仓库相对路径。
  const all =
    (git(root, gitExecutable, [
      'log',
      '--no-ext-diff',
      '--no-textconv',
      '--all',
      '--format=%H',
      `--max-count=${MAX_HISTORY_REVISIONS + 1}`,
      '--',
      entry.localPath,
    ]) ?? '')
    .split(/\r?\n/)
    .filter(Boolean)
  if (all.length === 0) return null
  const revs = all.slice(0, MAX_HISTORY_REVISIONS)

  // 一次读取所有选定版本，避免逐版本启动进程。
  const bodies = batchBlobs(
    root,
    gitExecutable,
    revs.map((rev) => `${rev}:${entry.repoPath}`),
  )

  let best: Evidence = 'none'
  let unreadable = 0
  const hintHashes = new Set<string>()
  for (const body of bodies) {
    if (body === null) {
      unreadable++
      continue
    }
    const evidence = evidenceIn(body.split(/\r?\n/))
    // 已确认凭据后无需继续寻找更强证据。
    if (evidence === 'proof') return {
      evidence: 'proof', unread: 0, unreadable,
      sourceFingerprint: createHash('sha256').update(body.trim(), 'utf8').digest('hex'),
    }
    if (evidence === 'hint') {
      best = 'hint'
      hintHashes.add(createHash('sha256').update(body.trim(), 'utf8').digest('hex'))
    }
  }
  return {
    evidence: best, unread: all.length - revs.length, unreadable,
    sourceFingerprint: createHash('sha256').update([...hintHashes].sort().join('\n')).digest('hex'),
  }
}

/** 检查是否配置远程仓库，用于提示可能的传播范围。 */
function hasRemote(root: string, gitExecutable: string | null): boolean {
  const out = git(root, gitExecutable, ['remote'])
  return out !== null && out.trim().length > 0
}

/** 根据 Git 状态说明历史检查失败原因。 */
function unavailableReason(root: string, gitExecutable: string | null): string {
  const unchecked = "so nothing in this repository's history was checked."

  if (gitExecutable === null) {
    return (
      `No trusted git executable was found on PATH, ${unchecked} ` +
      'canship ignores any git inside the scanned project, the current directory or node_modules, ' +
      'because a repository must not supply the program used to read it.'
    )
  }

  if (!hasContainedGitMetadata(root)) {
    return (
      `This checkout's .git metadata points outside the directory and nothing there names this ` +
      `checkout back, ${unchecked} ` +
      'A linked worktree or a submodule is read normally; a .git file naming an unrelated ' +
      'repository is not.'
    )
  }

  return (
    `git could not read this repository, ${unchecked} ` +
    'If git is refusing it for dubious ownership, review the directory before changing safe.directory.'
  )
}

export const gitleakRule: ProjectRule = {
  id: 'gitleak/env-in-git',
  severity: 'P0',

  check(ctx: ScanContext): Finding[] {
    // Git 不可用时必须记录失败，不能返回空结果。
    if (ctx.git === 'unavailable') {
      throw new Error(unavailableReason(ctx.root, ctx.gitExecutable))
    }
    if (ctx.git === 'not-a-repo') return []
    // 有效仓库必须对应可用的 Git 可执行文件。
    if (ctx.gitExecutable === null) {
      throw new Error('no trusted git executable was found, so this repository\'s history was not checked')
    }

    const findings: Finding[] = []
    // 路径前缀仅解析一次。
    const prefix = repoPrefix(ctx.root, ctx.gitExecutable)
    const tracked = new Set(trackedEnvFiles(ctx.root, ctx.gitExecutable))
    const historical = historicalEnvFiles(ctx.root, ctx.gitExecutable, prefix)
    const remote = hasRemote(ctx.root, ctx.gitExecutable)

    const remoteNote = remote
      ? `This repository has a remote configured, so these commits have most likely been pushed. ` +
        `Bots scrape public commits within minutes — assume every key in this file is already in someone else's hands.`
      : `This repository has no remote yet, so the damage may still be contained. Fix it before you push.`

    // 仅记录已报告的当前文件，当前无问题时仍检查历史。
    const reportedTracked = new Set<string>()

    // 检查当前跟踪的文件。
    for (const path of tracked) {
      // 根据实际内容确定证据强度。
      const scanned = ctx.files.find((f) => f.path === path)
      const evidence = scanned ? evidenceIn(scanned.lines) : 'hint'
      if (evidence === 'none') continue

      // 示例路径只降低置信度。
      const scaffolding = isScaffolding(path)

      findings.push({
        ruleId: 'gitleak/env-tracked',
        severity: 'P0',
        // 只有非示例中的明确凭据使用确定置信度。
        confidence: evidence === 'proof' && !scaffolding ? 'certain' : 'likely',
        title:
          evidence === 'proof' && !scaffolding
            ? `${path} is committed to git, with a credential in it`
            : `${path} is committed to git`,
        file: path,
        line: null,
        excerpt: null,
        why: [
          evidence === 'proof'
            ? `Environment files hold your credentials, and this one is tracked by git — so every key in it ` +
              `is stored in the repository and visible to anyone who can read it.`
            : `This environment file is tracked by git. Nothing in it matches a credential format canship ` +
              `recognises, so this may be harmless configuration — but .env files are where credentials ` +
              `end up, and a committed one is a habit worth breaking before it matters.`,
          remoteNote,
          ...(scaffolding ? [SCAFFOLD_NOTE] : []),
        ],
        fix: [`Add ${path} to .gitignore.`, untrackStep(path)],
        humanOnly: [
          `Rotate every credential in that file. This is the step people skip, and it is the only one that actually stops the leak.`,
          `Removing it from history entirely requires rewriting the repo (git filter-repo or BFG). Do that only after rotating the keys — rotation is what matters, and history rewriting is disruptive enough that it should be a deliberate decision.`,
        ],
      })
      reportedTracked.add(path)
    }

    // 检查历史版本，无论当前文件是否仍存在。
    for (const entry of historical) {
      // 以扫描相对路径去重。
      if (reportedTracked.has(entry.localPath)) continue // 当前状态已报告。
      const path = entry.localPath
      // 文件是否仍被跟踪仅影响说明文字。
      const stillTracked = tracked.has(entry.localPath)
      // 当前内容正常时仍需检查历史。
      const history = historicalEvidence(ctx.root, ctx.gitExecutable, entry)
      // 达到历史上限必须披露扫描缺口。
      if (history && history.unread > 0) {
        ctx.reportIncomplete(
          'gitleak/env-in-history',
          `only the ${MAX_HISTORY_REVISIONS} most recent versions of ${path} were read; ` +
            `at least ${history.unread} older ${history.unread === 1 ? 'version was' : 'versions were'} not checked`,
        )
      }
      if (history && history.unreadable > 0) {
        ctx.reportIncomplete(
          'gitleak/env-in-history',
          `${history.unreadable} historical ${history.unreadable === 1 ? 'version' : 'versions'} of ${path} ` +
            `could not be read from the repository; ` +
            `the repository may be incomplete or the file may exceed the Git output limit`,
        )
      }
      // 无法读取历史时保留疑似证据，不宣称确定泄露。
      const evidence: Evidence = history?.evidence ?? 'hint'
      if (evidence === 'none') continue

      // 已删除的示例文件仍可存在历史风险。
      const scaffolding = isScaffolding(path)

      findings.push({
        ruleId: 'gitleak/env-in-history',
        ...(history?.sourceFingerprint === undefined ? {} : { sourceFingerprint: history.sourceFingerprint }),
        severity: 'P0',
        // 证据或上下文不足时降低置信度。
        confidence: evidence === 'proof' && !scaffolding ? 'certain' : 'likely',
        title: stillTracked
          ? `${path} is committed to git, and an older version of it held a credential`
          : `${path} was removed, but it is still in your git history`,
        file: path,
        line: null,
        excerpt: null,
        why: [
          stillTracked
            ? `The version of this file in your working tree holds nothing canship recognises as a ` +
              `credential — but git keeps every version of every file it has ever seen, and an earlier one ` +
              `does. Editing the key out of a tracked file changes the latest version and nothing else; the ` +
              `old contents are still one command away for anyone who can clone this repository.`
            : `This file is no longer tracked, so it looks fixed — but git keeps every version of every file ` +
              `it has ever seen. Anyone who clones this repository can still read the old contents with a ` +
              `single command.`,
          remoteNote,
          ...(scaffolding ? [SCAFFOLD_NOTE] : []),
        ],
        fix: stillTracked
          ? [`Add ${path} to .gitignore.`, untrackStep(path)]
          : [`Confirm ${path} is in .gitignore so it does not come back.`],
        humanOnly: [
          `Rotate every credential that was ever in this file. Do this first, and do not skip it — it is the only step that actually revokes access.`,
          `Then, if you need the history cleaned, rewrite it with git filter-repo or BFG Repo-Cleaner. Do this deliberately: it rewrites every commit hash and disrupts anyone else working on the repo.`,
        ],
      })
    }

    return findings
  },
}
