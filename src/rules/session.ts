/**
 * 服务端代码用 supabase.auth.getSession() 的结果判断身份。getSession 直接读取 Cookie 中的会话而不重新验证，
 * 伪造的 Cookie 同样能通过；服务端应使用 getClaims() 或 getUser()。
 * 来源：https://supabase.com/docs/guides/auth/server-side/nextjs
 */
import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { noiseMaskedOf, commentsMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { namePattern } from './bindings.js'
import { serverRoutesOf } from './routers.js'
import { patternNames, destructuredKeys } from './request-input.js'
import { authValuesOf, identityRequirement } from './auth-values.js'
import { LocalVerification } from './verification.js'

const GET_SESSION = /\.auth\s*\.\s*getSession\s*\(/g

/** 同一客户端的已等待验证结果必须用于失败退出，且之前未使用会话身份。 */
function verifiedSession(file: ScanFile, context: LocalVerification, sessionAt: number, names: string[]): boolean {
  const { code, pairs, bodies } = context
  const body = context.owner(sessionAt)
  if (!body) return false
  const client = /([\w$.]+)\s*$/.exec(code.slice(body.start, sessionAt))?.[1]
  if (!client) return false
  const values = authValuesOf(file, body, bodies, pairs)
  const reads = new RegExp(`(?<![\\w$.])(?:${namePattern(names)})(?![\\w$]|\\s*:)`, 'g')
  const verification = /\b(?:const|let)\s+(\{[^;=]{1,500}\}|[A-Za-z_$][\w$]*)\s*=\s*await\s+([\w$.]+)\.auth\.(?:getUser|getClaims)\s*\(/g
  for (const call of code.matchAll(verification)) {
    if (call[2] !== client || context.owner(call.index) !== body) continue
    const close = pairs.get(call.index + call[0].length - 1)
    if (close === undefined) continue
    // 显式令牌可能来自另一身份，不能证明 Cookie 中的当前会话已验证。
    if (code.slice(call.index + call[0].length, close).trim() !== '') continue
    const guardAt = context.skipSpace(code[close + 1] === ';' ? close + 2 : close + 1)
    const condition = /^if\s*\(/.exec(code.slice(guardAt))
    if (!condition) continue
    const conditionClose = pairs.get(guardAt + condition[0].length - 1)
    if (conditionClose === undefined) continue
    const branchAt = context.skipSpace(conditionClose + 1)
    const branchEnd = context.endOf(branchAt)
    if (!context.exits(branchAt, branchEnd) || !context.enforcedBefore(call.index, guardAt)) continue
    const test = code.slice(guardAt + condition[0].length, conditionClose).trim()
    const errorNames = call[1]!.startsWith('{')
      ? destructuredKeys(call[1]!).filter(k => k.key === 'error').map(k => k.local)
      : [`${call[1]}.error`]
    if (/&&|\?(?!\.)/.test(test) || !test.split('||').some(term => {
      const t = term.trim()
      return errorNames.includes(t) || (t.startsWith('!') && identityRequirement(values.value(t.slice(1), guardAt), false) !== null)
    })) continue
    const sessionClose = pairs.get(code.indexOf('(', sessionAt)) ?? code.indexOf(')', sessionAt)
    // 会话存在性检查只拒绝缺失值，不应借此将后续身份使用视为已验证。
    let before = code.slice(sessionClose + 1, branchEnd)
    before = before.replace(/\bif\s*\(\s*!\s*([\w$.?]+)\s*\)\s*(?:return|throw|redirect)\b[^;\n]*/g, (text, subject: string) => {
      const rest = text.slice(text.indexOf(')') + 1).replace(/\b[\w$]+\s*:/g, '')
      return names.some(n => subject === n || subject.startsWith(`${n}.`)) && !new RegExp(reads.source).test(rest)
        ? ' '.repeat(text.length) : text
    })
    if (new RegExp(reads.source).test(before)) continue
    if (!context.enforcedBefore(guardAt, body.end - 1)) continue
    return true
  }
  return false
}

/** 服务端文件：路由与 Server Function、中间件与 Proxy 及其辅助模块、Next.js 服务端组件、*.server 模块、server 目录。 */
const SERVER_PATH = [
  /(?:^|\/)(?:middleware|proxy)\.[mc]?[jt]s$/,
  /(?:^|\/)app\/(?:.+\/)?(?:page|layout|template|default)\.[mc]?[jt]sx?$/,
  /\.server\.[mc]?[jt]s$/,
  /(?:^|\/)server\/.+\.[mc]?[jt]s$/,
]

function isServerFile(file: ScanFile, files: ScanFile[]): boolean {
  if (!/\.[mc]?[jt]sx?$/.test(file.path)) return false
  // 'use client' 组件在浏览器运行，那里的 getSession 只用于界面状态。
  if (/^\s*(?:(?:'use strict'|"use strict");?\s*)?['"]use client['"]/.test(commentsMaskedOf(file))) return false
  return SERVER_PATH.some(pattern => pattern.test(file.path)) || serverRoutesOf(file, files).length > 0
}

export const sessionRule: Rule = {
  id: 'auth/unverified-session',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    return file.content.includes('getSession')
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    // 是否为服务端代码需要全部文件：Express 处理函数可能在不导入 express 的控制器文件中。
    if (!isServerFile(file, ctx.files)) return []
    const code = noiseMaskedOf(file)
    const context = new LocalVerification(file)
    const { pairs, bodies } = context
    const lineStarts = lineStartsOf(file.content)
    const findings: Finding[] = []
    for (const m of code.matchAll(GET_SESSION)) {
      // 所在的最内层函数；顶层调用按整个文件处理。
      const body = bodies.filter(b => b.start < m.index && m.index < b.end).sort((a, b) => b.start - a.start)[0]
      const start = body?.start ?? 0
      const end = body?.end ?? code.length

      // 接收结果的变量：const { data: { session } } = await supabase.auth.getSession()
      const statement = code.slice(Math.max(start, m.index - 300), m.index)
      const declaration = /\b(?:const|let|var)\s+((?:\{[^;=]*\})|[A-Za-z_$][\w$]*)\s*(?::[^=;]{0,200})?=\s*(?:await\s+)?\(?\s*(?:await\s+)?[\w$.?\s]*$/.exec(statement)
      if (!declaration) continue
      const names = patternNames(declaration[1]!)
      if (names.length === 0) continue
      const refs = new RegExp(`(?<![\\w$.])(?:${namePattern(names)})(?![\\w$])`)
      const after = code.slice(m.index, end)

      // 用于条件判断即是据此决定身份；只读取其中的 user 也在信任未验证的身份。
      let decides = false
      for (const condition of after.matchAll(/\bif\s*\(/g)) {
        const open = m.index + condition.index + condition[0].length - 1
        const close = pairs.get(open)
        if (close !== undefined && refs.test(code.slice(open + 1, close))) { decides = true; break }
      }
      const readsUser = new RegExp(`(?<![\\w$.])(?:${namePattern(names)})(?:\\??\\.\\s*(?:session|data))*\\??\\.\\s*user\\b`).test(after)
      if (!decides && !readsUser) continue
      if (verifiedSession(file, context, m.index, names)) continue

      const line = lineNumberAt(lineStarts, m.index)
      findings.push({
        ruleId: 'auth/unverified-session', severity: 'P1', confidence: decides ? 'certain' : 'likely',
        title: 'Server code trusts supabase.auth.getSession() to identify the user',
        file: file.path, line, excerpt: (file.lines[line - 1] ?? '').trim(),
        why: [
          'On the server, getSession() reads the session straight from the request cookie without verifying it. ' +
            'Anyone can put a forged or expired session in their cookies, so a check based on it can be passed by a caller who is not signed in.',
          decides
            ? 'The result is used in a condition here, so it decides who gets through.'
            : 'The user from this session is read here, so an unverified user id may be trusted.',
        ],
        fix: [
          'Use supabase.auth.getClaims() (verifies the token signature) or supabase.auth.getUser() (asks the Auth server) to decide who the caller is.',
          'Keep getSession() only where you need the access token itself, not to decide access.',
        ],
      })
    }
    return findings
  },
}
