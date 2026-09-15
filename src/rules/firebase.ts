/** 检查 Firebase 无条件访问规则和带固定截止日期的测试规则。 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { basename } from 'node:path'
import { noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'

/** 判断是否为 Firebase 规则文件。 */
function isRulesFile(file: ScanFile): boolean {
  const name = basename(file.path).toLowerCase()
  if (name.endsWith('.rules')) return true
  // 识别默认规则文件名及规则扩展名。
  return name === 'firestore.rules' || name === 'storage.rules'
}

/** 根据文件路径确定规则产品名称。 */
function productOf(path: string): string {
  const name = basename(path).toLowerCase()
  if (name.includes('storage')) return 'Storage'
  if (name.includes('firestore')) return 'Firestore'
  return 'Firebase'
}

/** 匹配无条件开放的操作声明。 */
const ALLOW_IF_TRUE = /\ballow\s+([a-z,\s]+?)\s*:\s*if\s+true\s*;/gi

/** 区分写入与公开只读访问。 */
const WRITE_OPS = new Set(['write', 'create', 'update', 'delete'])

/** 拆分允许操作列表。 */
function parseOps(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
}

/** 屏蔽路径通配符中的花括号，避免破坏代码块配对。 */
function neutralizePathWildcards(content: string): string {
  return content.replace(/\{[a-zA-Z_]\w*(?:\s*=\s*\*\*)?\}/g, (m) => '_'.repeat(m.length))
}

/** 定位包含目标位置的最内层匹配块。 */
function enclosingMatchBlock(neutralized: string, index: number): string {
  const matchStart = neutralized.slice(0, index).lastIndexOf('match ')
  if (matchStart < 0) return neutralized
  const braceStart = neutralized.indexOf('{', matchStart)
  if (braceStart < 0 || braceStart > index) return neutralized

  let depth = 0
  for (let i = braceStart; i < neutralized.length; i++) {
    if (neutralized[i] === '{') depth++
    else if (neutralized[i] === '}') {
      depth--
      if (depth === 0) return neutralized.slice(braceStart, i + 1)
    }
  }
  return neutralized.slice(braceStart)
}

/** 移除子匹配块，避免子级拒绝覆盖父级规则判断。 */
function ownStatements(block: string): string {
  let out = ''
  let i = 0
  while (i < block.length) {
    const rest = block.slice(i)
    const nested = /^\s*match\s+[^{]*\{/.exec(rest)
    if (nested && i > 0) {
      // 跳过完整子级代码块。
      let depth = 0
      let j = i + nested[0].length - 1
      for (; j < block.length; j++) {
        if (block[j] === '{') depth++
        else if (block[j] === '}') {
          depth--
          if (depth === 0) {
            j++
            break
          }
        }
      }
      i = j
      continue
    }
    out += block[i]
    i++
  }
  return out
}

/** 公开读取且显式拒绝写入时视为只读设计。 */
function blockDeniesWrites(block: string): boolean {
  const denial = /\ballow\s+([a-z,\s]+?)\s*:\s*if\s+false\s*;/gi
  let m: RegExpExecArray | null
  while ((m = denial.exec(block)) !== null) {
    if (parseOps(m[1] ?? '').some((op) => WRITE_OPS.has(op))) return true
  }
  return false
}

/** 提取测试模式的固定到期日期。 */
const TEST_MODE =
  /\ballow\s+([a-z,\s]+?)\s*:\s*if\s+request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)\s*;/gi

/** 将操作列表转换为展示文本。 */
function describeOps(raw: string): string {
  const ops = parseOps(raw)
  if (ops.includes('write') && ops.includes('read')) return 'read and write'
  if (ops.length === 1) return ops[0]!
  return ops.join(' and ')
}


export const firebaseRulesRule: Rule = {
  id: 'firebase/open-rules',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    // 示例上下文由引擎降低置信度。
    return isRulesFile(file)
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const findings: Finding[] = []
    const product = productOf(file.path)
    // 达到结果上限时记录扫描缺口。
    const capReached = (): boolean => {
      if (findings.length < MAX_FINDINGS_PER_FILE) return false
      ctx.reportIncomplete(
        'firebase/open-rules',
        `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} open rules; the rest were not reported`,
      )
      return true
    }
    // 屏蔽注释及字符串，避免示例文本触发规则。
    const content = noiseMaskedOf(file)
    // 再屏蔽路径通配符。
    const neutralized = neutralizePathWildcards(content)
    // 每个文件只构建一次行号索引。
    const contentLines = lineStartsOf(content)

    // 检查无条件访问。
    ALLOW_IF_TRUE.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = ALLOW_IF_TRUE.exec(content)) !== null) {
      if (capReached()) break
      const rawOps = m[1] ?? ''
      const canWrite = parseOps(rawOps).some((op) => WRITE_OPS.has(op))

      // 显式拒绝写入的公开读取不报告为开放写入。
      if (!canWrite && blockDeniesWrites(ownStatements(enclosingMatchBlock(neutralized, m.index)))) continue

      const ops = describeOps(rawOps)
      findings.push({
        ruleId: 'firebase/open-rules',
        severity: 'P1',
        // 开放写入为确定结果，公开读取需人工确认。
        confidence: canWrite ? 'certain' : 'likely',
        title: canWrite
          ? `Your ${product} rules let anyone ${ops} this data`
          : `Your ${product} rules make this data publicly readable`,
        file: file.path,
        line: lineNumberAt(contentLines, m.index),
        excerpt: m[0].trim(),
        why: canWrite
          ? [
              `"if true" grants access unconditionally — no sign-in, no ownership check, nothing. The Firebase ` +
                `client SDK talks to your database straight from the browser, so these rules are the only access ` +
                `control that exists.`,
              `Anyone who finds your project id can read every document here, overwrite it, or delete all of it. ` +
                `Project ids are not secret; they ship inside your frontend bundle.`,
            ]
          : [
              `"if true" grants read access unconditionally, so anyone who finds your project id can list every ` +
                `document in this collection. Project ids are not secret; they ship inside your frontend bundle.`,
              `Writes are still denied by default, so this is only a problem if the data is not meant to be ` +
                `public. If it is a public catalogue or announcements, ignore this — and consider adding ` +
                `"allow write: if false;" to make that intent explicit.`,
            ],
        fix: canWrite
          ? [
              `Decide who should actually have access. For per-user data the usual rule is: allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`,
              `For data that is genuinely public, restrict it to reads only: allow read: if true; allow write: if false;`,
              `Test your rules with the Firebase emulator before deploying, so you do not lock yourself out.`,
              `If this database has been open for a while, assume the data has already been copied.`,
            ]
          : [
              `If this data is meant to be public, add "allow write: if false;" to the same block. That documents the intent and silences this warning.`,
              `If it is not meant to be public, require sign-in: allow read: if request.auth != null;`,
            ],
      })
    }

    // 检查带日期的测试模式。
    TEST_MODE.lastIndex = 0
    while ((m = TEST_MODE.exec(content)) !== null) {
      if (capReached()) break
      const rawOps = m[1] ?? ''
      const ops = describeOps(rawOps)
      const year = Number(m[2])
      const month = Number(m[3])
      const day = Number(m[4])
      // 按扫描时间判断是否到期。
      const expiry = new Date(year, month - 1, day)
      const expired = expiry.getTime() < Date.now()
      const dateStr = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`

      findings.push({
        ruleId: 'firebase/test-mode-rules',
        severity: 'P1',
        // 固定日期测试模式均作为确定配置问题。
        confidence: 'certain',
        title: expired
          ? `Your ${product} rules are in test mode and expired on ${dateStr}`
          : `Your ${product} rules allow ${ops} to anyone until ${dateStr}`,
        file: file.path,
        line: lineNumberAt(contentLines, m.index),
        excerpt: m[0].trim(),
        why: expired
          ? [
              `This is the "test mode" rule Firebase creates during setup. The date has passed, so this rule ` +
                `now denies everything. Whatever part of your app depends on it is broken — and it was fully ` +
                `public up until ${dateStr}.`,
              `Assume anything stored here before that date was readable by anyone.`,
            ]
          : [
              `This is the "test mode" rule Firebase creates during setup. Until ${dateStr}, it grants ${ops} ` +
                `access to anyone, with no sign-in required. After that date it flips to denying everything, and ` +
                `your app will break instead.`,
              `Neither state is what you want in production.`,
            ],
        fix: [
          `Replace the date check with a real authorisation rule. For per-user data: allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;`,
          `Test the new rules with the Firebase emulator before deploying.`,
          expired
            ? `Note that your app is currently denied access here, so fixing this also fixes whatever stopped working.`
            : `Do this before ${dateStr}, otherwise your app breaks on that date.`,
        ],
      })
    }

    return findings
  },
}
