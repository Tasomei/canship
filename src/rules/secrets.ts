/** 检测源码中的硬编码凭据；普通环境文件交由公开暴露和 Git 规则处理。 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { redactLine } from '../redact.js'
import { basename } from 'node:path'
import { isEnvFile } from '../walker.js'
import { SECRET_PATTERNS, isPlaceholder, isCommentedOut, secretPartOf } from './patterns.js'
import { isClientCode } from './framework.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'


export const secretsRule: Rule = {
  id: 'secrets/hardcoded',
  severity: 'P0',

  appliesTo(file: ScanFile): boolean {
    // 环境模板仍检查硬编码凭据，普通环境文件不重复处理。
    if (isEnvFile(basename(file.path))) return file.isExampleContext
    return true
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const findings: Finding[] = []
    // 每个文件只构建一次行号索引。
    const lineStarts = lineStartsOf(file.content)

    for (const pat of SECRET_PATTERNS) {
      // 按设计公开的标识符不作为泄露报告。
      if (pat.publicByDesign) continue
      // 重置共享全局正则的匹配位置。
      pat.pattern.lastIndex = 0
      let match: RegExpExecArray | null

      while ((match = pat.pattern.exec(file.content)) !== null) {
        const secret = match[0]
        if (isPlaceholder(secretPartOf(match, pat))) continue
        if (pat.ignoreIf?.(match)) continue
        // 达到结果上限后停止，并记录未报告部分。
        if (findings.length >= MAX_FINDINGS_PER_FILE) {
          ctx.reportIncomplete(
            'secrets/hardcoded',
            `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} credential-shaped strings; ` +
              `the rest were not reported`,
          )
          return findings
        }

        const line = lineNumberAt(lineStarts, match.index)
        const rawLine = file.lines[line - 1] ?? ''

        // 客户端与服务端代码的暴露影响不同。
        const clientSide = isClientCode(file)

        const parts: string[] = [pat.impact]
        if (clientSide) {
          parts.push(
            `This file is client-side code — it is sent to the browser in full. ` +
              `Any visitor can open dev tools and read this key straight out of your bundle. ` +
              `You do not need to be attacked for this to leak; it is already public to everyone who loads the page.`,
          )
        } else {
          parts.push(
            `Hardcoding it in source means it goes into your git history, and it will be bundled into the browser ` +
              `if this file is ever imported from client-side code.`,
          )
        }
        if (isCommentedOut(rawLine)) {
          parts.push(
            `Commenting the line out does not help — the key is still in the file, and if this file is in git, it is in your history forever.`,
          )
        }

        const fix = [
          `Remove the key from this file.`,
          clientSide
            ? `Move the code that uses it to the server (an API route or server action), and keep the key in .env without a public prefix.`
            : `Put it in .env and read it with process.env (never with a NEXT_PUBLIC_ prefix).`,
          `Make sure .env is listed in .gitignore.`,
        ]

        // 凭据轮换归入需人工执行的步骤。
        const humanOnly = [
          `Rotate this ${pat.rotateLabel ?? pat.name}${pat.rotateAt ? ` at ${pat.rotateAt}` : ''}. Treat the old one as compromised — ` +
            (clientSide
              ? `if this page has ever been deployed, assume the key is already in someone else's hands.`
              : `if this file was ever pushed, assume it has already been scraped.`),
        ]

        // 示例凭据保留为疑似结果，可通过忽略标记排除。
        const scaffolding = file.isExampleContext

        findings.push({
          ruleId: `secrets/hardcoded/${pat.id}`,
          severity: 'P0',
          confidence: scaffolding ? 'likely' : 'certain',
          title: scaffolding
            ? `${pat.name} is hardcoded in a test or example file`
            : clientSide
              ? `${pat.name} is hardcoded in code that runs in the browser`
              : `${pat.name} is hardcoded in your source code`,
          file: file.path,
          line,
          excerpt: redactLine(rawLine, secret),
          why: parts,
          fix,
          humanOnly,
        })
      }
    }

    return findings
  },
}
