/** 检测公开环境变量和客户端代码中的私密值。 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { redactLine, redactSecret } from '../redact.js'
import { basename } from 'node:path'
import { isEnvFile } from '../walker.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'
import { JWT_SOURCE, findKnownSecret, isPlaceholder } from './patterns.js'
import { parseEnvLine } from './envfile.js'
import { commentsMaskedOf } from '../mask.js'
import {
  looksClearlyPrivate,
  isClientCode,
  isSupabaseServiceRole,
  publicPrefixOf,
} from './framework.js'

/** 复用共享 JWT 模式，避免检测与脱敏规则不一致。 */
const JWT_SHAPED = new RegExp(String.raw`\b${JWT_SOURCE}\b`, 'g')

interface EnvEntry {
  key: string
  value: string
  line: number
}

/** 限制存活结果对象数量；超额时优先保留确定结果。 */
class FindingBuffer {
  readonly items: Finding[] = []
  overflow = false

  push(finding: Finding): void {
    if (this.items.length < MAX_FINDINGS_PER_FILE) {
      this.items.push(finding)
      return
    }
    this.overflow = true
    if (finding.confidence !== 'certain') return
    const index = this.items.findIndex(item => item.confidence === 'likely')
    if (index !== -1) this.items[index] = finding
  }
}

/** 解析环境赋值，支持导出前缀和引号。 */
function parseEnv(file: ScanFile): EnvEntry[] {
  const entries: EnvEntry[] = []
  file.lines.forEach((raw, i) => {
    const assignment = parseEnvLine(raw)
    if (assignment) entries.push({ ...assignment, line: i + 1 })
  })
  return entries
}

export const exposureRule: Rule = {
  id: 'exposure/public-env',
  severity: 'P0',

  appliesTo(): boolean {
    // 所有文本文件都检查管理员 JWT；公开变量引用只在前端源码中检查。示例由引擎统一降低置信度。
    return true
  },

  /** 使用有界缓冲区保留结果，超限时记录扫描缺口。 */
  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const name = basename(file.path)
    const findings = isEnvFile(name)
      ? checkEnvFile(file)
      : FRONTEND_SOURCE.test(name) ? checkSourceFile(file) : checkOtherFile(file)
    if (!findings.overflow) return findings.items

    ctx.reportIncomplete(
      'exposure/public-env',
      `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} values exposed to the browser; ` +
        `the rest were not reported`,
    )
    return findings.items
  },
}

/** 检查公开环境变量的值。 */
function checkEnvFile(file: ScanFile): FindingBuffer {
  const findings = new FindingBuffer()

  for (const entry of parseEnv(file)) {
    const prefix = publicPrefixOf(entry.key)
    if (!prefix) continue
    if (!entry.value || isPlaceholder(entry.value)) continue

    const rawLine = file.lines[entry.line - 1] ?? ''

    // 管理员密钥具有明确权限风险。
    if (isSupabaseServiceRole(entry.value)) {
      findings.push({
        ruleId: 'exposure/supabase-service-role-in-client',
        severity: 'P0',
        confidence: 'certain',
        title: 'Your Supabase admin key is exposed to the browser',
        file: file.path,
        line: entry.line,
        excerpt: `${entry.key}=${redactSecret(entry.value)}`,
        why: [
          `This is the service_role key. It bypasses every Row Level Security policy in your database — ` +
            `it is effectively your database root password.`,
          `Because the variable name starts with ${prefix}, its value is compiled into your website's ` +
            `JavaScript bundle. Anyone who opens your site can read it from their browser's dev tools and ` +
            `then read, modify, or delete every row in your database.`,
        ],
        fix: [
          `Rename this variable to SUPABASE_SERVICE_ROLE_KEY (drop the ${prefix} prefix).`,
          `Only reference it from server-side code — API routes, server actions, or server components. Never from a component with 'use client'.`,
          `For anything the browser needs, use the anon key (NEXT_PUBLIC_SUPABASE_ANON_KEY) together with Row Level Security policies.`,
        ],
        humanOnly: [
          `Rotate the service_role key in your Supabase dashboard (Project Settings -> API). If your site has ever been deployed with this key, assume it is already compromised — renaming the variable does not revoke it.`,
        ],
      })
      continue
    }

    // 识别已知私密凭据格式。
    const known = findKnownSecret(entry.value)
    if (known) {
      // 按设计公开的标识符不作为密钥泄露报告。
      if (known.publicByDesign) continue
      findings.push({
        ruleId: 'exposure/secret-in-public-env',
        severity: 'P0',
        confidence: 'certain',
        title: `Your ${known.name} is exposed to the browser`,
        file: file.path,
        line: entry.line,
        excerpt: `${entry.key}=${redactSecret(entry.value)}`,
        why: [
          `Variables prefixed with ${prefix} are compiled into the JavaScript your website sends to every ` +
            `visitor. This one is not a public identifier — it is a real credential.`,
          known.impact,
        ],
        fix: [
          `Rename this variable to drop the ${prefix} prefix, so it stays on the server.`,
          `Move any code that uses it into an API route or server action.`,
        ],
        humanOnly: [
          `Rotate this ${known.rotateLabel ?? known.name}${known.rotateAt ? ` at ${known.rotateAt}` : ''} — the current one must be considered public.`,
        ],
      })
      continue
    }

    // 移除公开前缀后判断私密词，私密信号优先。
    const rest = entry.key.slice(prefix.length)
    if (looksClearlyPrivate(rest)) {
      findings.push({
        ruleId: 'exposure/private-name-in-public-env',
        severity: 'P0',
        confidence: 'likely',
        title: `"${entry.key}" looks like a secret but is exposed to the browser`,
        file: file.path,
        line: entry.line,
        excerpt: redactLine(rawLine, entry.value),
        why: [
          `The name contains a word that usually marks a private credential, but the ${prefix} prefix ` +
            `means its value ships to every visitor's browser.`,
          `If this value really is meant to be public, you can ignore this.`,
        ],
        fix: [
          `If it is a secret: drop the ${prefix} prefix and use it only from server-side code.`,
          `If it is genuinely public: rename it so the name does not say "secret" — future you will thank you.`,
        ],
      })
    }
  }

  return findings
}

/** 可引用公开环境变量的前端源码。 */
const FRONTEND_SOURCE = /\.(ts|tsx|js|jsx|mjs|cjs|svelte|vue|astro)$/

/**
 * 配置、脚本及其他语言源码中的管理员 JWT。其他凭据格式由 secrets 规则覆盖全部文本文件，
 * 管理员 JWT 此前只在前端源码中检查，写在 docker-compose.yml 或 Python 脚本中的不会被报告。
 */
function checkOtherFile(file: ScanFile): FindingBuffer {
  const findings = new FindingBuffer()
  file.lines.forEach((line, i) => pushServiceRoleJwts(findings, file, line, i, false))
  return findings
}

/** 报告当前行中的 Supabase 管理员 JWT。 */
function pushServiceRoleJwts(findings: FindingBuffer, file: ScanFile, line: string, i: number, clientSide: boolean): void {
  // 使用共享模式查找当前行的 JWT。
  JWT_SHAPED.lastIndex = 0
  const jwtMatches = line.match(JWT_SHAPED)
  if (!jwtMatches) return
  for (const jwt of jwtMatches) {
    if (!isSupabaseServiceRole(jwt)) continue
    findings.push({
      ruleId: 'exposure/supabase-service-role-in-client',
      severity: 'P0',
      confidence: 'certain',
      title: clientSide
        ? 'Your Supabase admin key is hardcoded in a client component'
        : 'Your Supabase admin key is hardcoded in source code',
      file: file.path,
      line: i + 1,
      excerpt: redactLine(line, jwt),
      why: [
        `This is the service_role key — it bypasses every Row Level Security policy and is effectively ` +
          `your database root password.`,
        clientSide
          ? `This file starts with 'use client', so it is shipped to the browser in full. Any visitor can read this key.`
          : `Hardcoding it in source means it is in your git history, and it will be bundled anywhere this file is imported from client code.`,
      ],
      fix: [
        `Remove the key from the source file entirely.`,
        `Put it in .env as SUPABASE_SERVICE_ROLE_KEY (no public prefix) and read it via process.env on the server only.`,
      ],
      humanOnly: [
        `Rotate the key in your Supabase dashboard (Project Settings -> API) — the current one must be treated as compromised.`,
      ],
    })
  }
}

/** 检查源码中的私密值。 */
function checkSourceFile(file: ScanFile): FindingBuffer {
  const findings = new FindingBuffer()

  // 判断是否有明确的客户端代码信号。
  const clientSide = isClientCode(file)

  // 复用注释掩码并保留偏移。
  const commentless = commentsMaskedOf(file).split(/\r?\n/)

  file.lines.forEach((line, i) => {
    pushServiceRoleJwts(findings, file, line, i, clientSide)

    // 识别点访问和字符串索引访问中的公开私密变量。
    const envRef =
      /(?:process\.env|import\.meta\.env)(?:\.([A-Z_][A-Z0-9_]*)|\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\])/g
    let m: RegExpExecArray | null
    while ((m = envRef.exec(commentless[i] ?? '')) !== null) {
      const varName = (m[1] ?? m[2])!

      const varPrefix = publicPrefixOf(varName)
      if (!varPrefix) continue
      // 判断变量名时排除公开前缀。
      const varRest = varName.slice(varPrefix.length)
      // 私密词优先于公开用途词，避免漏报。
      if (!looksClearlyPrivate(varRest)) continue
      findings.push({
        ruleId: 'exposure/private-name-in-public-env',
        severity: 'P0',
        confidence: 'likely',
        title: `"${varName}" looks like a secret but is readable in the browser`,
        file: file.path,
        line: i + 1,
        excerpt: line.trim(),
        why: [
          `This variable has a public prefix, so its value is embedded in the JavaScript bundle that every ` +
            `visitor downloads — but its name suggests it holds a credential.`,
        ],
        fix: [
          `Drop the public prefix and move the code that uses it to the server.`,
          `If the value really is public, rename it so it does not read as a secret.`,
        ],
      })
    }
  })

  return findings
}
