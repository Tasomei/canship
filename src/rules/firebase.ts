/** 检查 Firebase 无条件访问规则和带固定截止日期的测试规则。 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { basename } from 'node:path'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'

/** 判断是否为 Firebase 规则文件。 */
function isRulesFile(file: ScanFile): boolean {
  return basename(file.path).toLowerCase().endsWith('.rules')
}

/**
 * Realtime Database 规则是 JSON，顶层为 rules 对象；官方示例带 // 与块注释，
 * 因此按屏蔽注释后的文本判断，不依赖文件名（默认 database.rules.json，可在 firebase.json 中改名）。
 */
function isRealtimeRulesFile(file: ScanFile): boolean {
  if (!file.path.toLowerCase().endsWith('.json')) return false
  if (!/"\.(?:read|write)"/.test(file.content)) return false
  return /^\s*\{\s*"rules"\s*:\s*\{/.test(commentsMaskedOf(file))
}

/** 条件为布尔 true 或字符串 "true" 时无条件放行。 */
function grantsEveryone(value: string | undefined): boolean {
  return value === 'true' || value === '"true"'
}

function deniesEveryone(value: string | undefined): boolean {
  return value === 'false' || value === '"false"'
}

/** 解码 JSON 键；未闭合或转义错误的键按原文去掉引号处理。 */
function decodeKey(token: string): string {
  try {
    return JSON.parse(token) as string
  } catch {
    return token.replace(/^"|"$/g, '')
  }
}

interface RealtimeNode {
  key: string
  /** .read、.write 等规则键的原始值文本及位置。 */
  rules: Map<string, { value: string; index: number }>
}

/**
 * 一次遍历读取每个节点的 .read 与 .write，在节点闭合时判断，同级的显式拒绝写入可一并考虑。
 * 规则自上而下级联：父节点放行后子节点无法撤销，因此开放节点覆盖其全部子路径。
 */
function checkRealtimeRules(file: ScanFile, ctx: ScanContext): Finding[] {
  const text = commentsMaskedOf(file)
  const lineStarts = lineStartsOf(text)
  const findings: Finding[] = []
  const stack: RealtimeNode[] = []
  let pendingKey: { key: string; index: number } | null = null

  const report = (node: RealtimeNode): void => {
    const read = node.rules.get('.read')
    const write = node.rules.get('.write')
    const openRead = grantsEveryone(read?.value)
    const openWrite = grantsEveryone(write?.value)
    if (!openRead && !openWrite) return
    // 公开读取且同级显式拒绝写入视为只读设计，与 Firestore 规则的处理一致。
    if (!openWrite && deniesEveryone(write?.value)) return
    if (findings.length >= MAX_FINDINGS_PER_FILE) {
      ctx.reportIncomplete('firebase/open-rules',
        `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} open rules; the rest were not reported`)
      return
    }
    // 路径取 rules 以下的键，根节点为 /。
    const segments = stack.slice(2).map((entry) => entry.key).concat(stack.length >= 2 ? [node.key] : [])
    const path = `/${segments.join('/')}`.replace(/\/{2,}/g, '/')
    const at = (openWrite ? write! : read!).index
    const line = lineNumberAt(lineStarts, at)
    const ops = openRead && openWrite ? 'read and write' : openWrite ? 'write' : 'read'
    findings.push({
      ruleId: 'firebase/open-rules',
      severity: 'P1',
      confidence: openWrite ? 'certain' : 'likely',
      title: openWrite
        ? `Your Realtime Database rules let anyone ${ops} ${path === '/' ? 'your entire database' : path}`
        : `Your Realtime Database rules make ${path === '/' ? 'your entire database' : path} publicly readable`,
      file: file.path,
      line,
      excerpt: (file.lines[line - 1] ?? '').trim(),
      why: [
        `This rule grants ${ops} access to everyone, with no sign-in required. The Firebase client SDK talks to ` +
          `your database straight from the browser, so these rules are the only access control that exists.`,
        `Realtime Database rules cascade: access granted at ${path} also applies to everything beneath it, ` +
          `and a stricter rule deeper down cannot take it back.`,
        ...(openWrite ? [] : [
          `If this data is meant to be public, add ".write": false next to it to make that intent explicit.`,
        ]),
      ],
      fix: [
        `Require sign-in and ownership instead, for example: ".read": "auth !== null && auth.uid === $uid" under a "$uid" node.`,
        `Test the new rules with the Firebase emulator before deploying.`,
        ...(openWrite ? [`If this database has been open for a while, assume the data has already been copied or changed.`] : []),
      ],
    })
  }

  let i = 0
  while (i < text.length) {
    const ch = text[i]!
    if (ch === '"') {
      // 读取字符串并判断其为键还是值。
      let j = i + 1
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1
      const token = text.slice(i, j + 1)
      let k = j + 1
      while (k < text.length && /\s/.test(text[k]!)) k++
      if (text[k] === ':' && pendingKey === null) pendingKey = { key: decodeKey(token), index: i }
      else if (pendingKey !== null) {
        stack[stack.length - 1]?.rules.set(pendingKey.key, { value: token, index: pendingKey.index })
        pendingKey = null
      }
      i = j + 1
      continue
    }
    if (ch === '{') {
      stack.push({ key: pendingKey?.key ?? '', rules: new Map() })
      pendingKey = null
    } else if (ch === '}') {
      const node = stack.pop()
      if (node) report(node)
    } else if (pendingKey !== null && /[A-Za-z0-9-]/.test(ch)) {
      // true、false、null 与数字字面量。
      let j = i
      while (j < text.length && /[A-Za-z0-9.+-]/.test(text[j]!)) j++
      stack[stack.length - 1]?.rules.set(pendingKey.key, { value: text.slice(i, j), index: pendingKey.index })
      pendingKey = null
      i = j
      continue
    }
    i++
  }
  return findings.sort((a, b) => (a.line ?? 0) - (b.line ?? 0))
}

/** 根据文件路径确定规则产品名称。 */
function productOf(path: string): string {
  const name = basename(path).toLowerCase()
  if (name.includes('storage')) return 'Storage'
  if (name.includes('firestore')) return 'Firestore'
  return 'Firebase'
}

/**
 * 操作列表：逗号分隔的单词，数量和长度有界。旧写法 [a-z,\s]+? 与前后空白对同一段空白有多种划分，
 * allow 后接 1 万个空格即需约 100 秒；Firebase 的操作只有七种，边界不影响识别。
 */
const OPS = String.raw`([a-z]{1,16}(?:\s*,\s*[a-z]{1,16}){0,8})`

/** 匹配无条件开放的操作声明。 */
const ALLOW_IF_TRUE = new RegExp(String.raw`\ballow\s+${OPS}\s*:\s*if\s+true\s*;`, 'gi')

/** 显式拒绝的操作声明。 */
const ALLOW_IF_FALSE = new RegExp(String.raw`\ballow\s+${OPS}\s*:\s*if\s+false\s*;`, 'gi')

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

interface MatchBlock {
  open: number
  close: number
}

/**
 * 一次遍历找出全部 match 块。块头取上一个分隔符到左花括号之间的文本，每个字符只属于一个块头；
 * 旧实现对每条语句回扫文件、并在每个字符处重试正则，168KB 的规则文件需约 77 秒。
 */
function matchBlocksOf(neutralized: string): MatchBlock[] {
  const blocks: MatchBlock[] = []
  const stack: { open: number; isMatch: boolean }[] = []
  let lastDelimiter = -1
  for (let i = 0; i < neutralized.length; i++) {
    const ch = neutralized[i]
    if (ch === '{') {
      stack.push({ open: i, isMatch: /^\s*match\b/.test(neutralized.slice(lastDelimiter + 1, i)) })
      lastDelimiter = i
    } else if (ch === '}') {
      const top = stack.pop()
      if (top?.isMatch) blocks.push({ open: top.open, close: i })
      lastDelimiter = i
    } else if (ch === ';') {
      lastDelimiter = i
    }
  }
  // 未闭合的块延伸到文件末尾。
  for (const top of stack) if (top.isMatch) blocks.push({ open: top.open, close: neutralized.length })
  return blocks.sort((a, b) => a.open - b.open)
}

/** 为升序位置找出最内层 match 块的序号；不在任何块内时为 -1。 */
function innermostBlocks(blocks: MatchBlock[], positions: number[]): number[] {
  const owners: number[] = []
  const active: number[] = []
  let next = 0
  for (const at of positions) {
    while (next < blocks.length && blocks[next]!.open < at) {
      while (active.length && blocks[active[active.length - 1]!]!.close < blocks[next]!.open) active.pop()
      active.push(next++)
    }
    while (active.length && blocks[active[active.length - 1]!]!.close < at) active.pop()
    owners.push(active.length ? active[active.length - 1]! : -1)
  }
  return owners
}

/** 提取测试模式的固定到期日期。 */
const TEST_MODE = new RegExp(
  String.raw`\ballow\s+${OPS}\s*:\s*if\s+request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)\s*;`,
  'gi',
)

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
    return isRulesFile(file) || isRealtimeRulesFile(file)
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    if (!isRulesFile(file)) return checkRealtimeRules(file, ctx)
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

    // 块结构和写入拒绝只计算一次；子级 match 块中的拒绝不影响父级判断。
    const blocks = matchBlocksOf(neutralized)
    const denials = [...neutralized.matchAll(ALLOW_IF_FALSE)]
      .filter((d) => parseOps(d[1] ?? '').some((op) => WRITE_OPS.has(op)))
    const denyingBlocks = new Set(innermostBlocks(blocks, denials.map((d) => d.index)))
    const opens = [...content.matchAll(ALLOW_IF_TRUE)]
    const openOwners = innermostBlocks(blocks, opens.map((o) => o.index))

    // 检查无条件访问。
    let m: RegExpExecArray | null
    for (const [index, open] of opens.entries()) {
      m = open
      if (capReached()) break
      const rawOps = m[1] ?? ''
      const canWrite = parseOps(rawOps).some((op) => WRITE_OPS.has(op))

      // 显式拒绝写入的公开读取不报告为开放写入。
      if (!canWrite && denyingBlocks.has(openOwners[index]!)) continue

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
              `Anyone can perform the allowed ${ops} operations on this matched path without authentication. ` +
                `Other operations depend on their own rules. Project ids are public identifiers, not access controls.`,
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
