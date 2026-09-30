/**
 * 服务端代码用 supabase.auth.getSession() 的结果判断身份。getSession 直接读取 Cookie 中的会话而不重新验证，
 * 伪造的 Cookie 同样能通过；服务端应使用 getClaims() 或 getUser()。
 * 来源：https://supabase.com/docs/guides/auth/server-side/nextjs
 */
import type { Finding, Rule, ScanFile } from '../types.js'
import { noiseMaskedOf, commentsMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { namePattern } from './bindings.js'
import { delimiterPairs, functionBodies, routeOf, serverActionRoutes } from './apiauth.js'
import { patternNames } from './request-input.js'

const GET_SESSION = /\.auth\s*\.\s*getSession\s*\(/g
const VERIFIED = /\.auth\s*\.\s*(?:getUser|getClaims)\s*\(/

/** 服务端文件：路由与 Server Function、中间件与 Proxy 及其辅助模块、Next.js 服务端组件、*.server 模块、server 目录。 */
const SERVER_PATH = [
  /(?:^|\/)(?:middleware|proxy)\.[mc]?[jt]s$/,
  /(?:^|\/)app\/(?:.+\/)?(?:page|layout|template|default)\.[mc]?[jt]sx?$/,
  /\.server\.[mc]?[jt]s$/,
  /(?:^|\/)server\/.+\.[mc]?[jt]s$/,
]

function isServerFile(file: ScanFile): boolean {
  if (!/\.[mc]?[jt]sx?$/.test(file.path)) return false
  // 'use client' 组件在浏览器运行，那里的 getSession 只用于界面状态。
  if (/^\s*(?:(?:'use strict'|"use strict");?\s*)?['"]use client['"]/.test(commentsMaskedOf(file))) return false
  return SERVER_PATH.some(pattern => pattern.test(file.path)) || routeOf(file) !== null || serverActionRoutes(file).length > 0
}

export const sessionRule: Rule = {
  id: 'auth/unverified-session',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    return file.content.includes('getSession') && isServerFile(file)
  },

  check(file: ScanFile): Finding[] {
    const code = noiseMaskedOf(file)
    const pairs = delimiterPairs(code)
    const bodies = functionBodies(code, pairs)
    const lineStarts = lineStartsOf(file.content)
    const findings: Finding[] = []
    for (const m of code.matchAll(GET_SESSION)) {
      // 所在的最内层函数；顶层调用按整个文件处理。
      const body = bodies.filter(b => b.start < m.index && m.index < b.end).sort((a, b) => b.start - a.start)[0]
      const start = body?.start ?? 0
      const end = body?.end ?? code.length
      const region = code.slice(start, end)
      // 随后又用 getUser 或 getClaims 验证的（如 Supabase SvelteKit 指南的 safeGetSession）不报告。
      if (VERIFIED.test(region)) continue

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
