/** 共享前端环境变量、客户端代码和 Supabase 识别逻辑。 */

import type { ScanContext, ScanFile } from '../types.js'
import { isEnvFile } from '../walker.js'
import { parseEnvLine } from './envfile.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'

/** 框架用于向客户端公开变量的前缀。 */
export const PUBLIC_PREFIXES = [
  'NEXT_PUBLIC_',
  'VITE_',
  'REACT_APP_',
  'EXPO_PUBLIC_',
  'NUXT_PUBLIC_',
  'GATSBY_',
  'VUE_APP_',
  'PUBLIC_',
]

/** 按分隔符拆分变量名，避免下划线影响词边界判断。 */
export function nameWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toUpperCase())
}

/** 以边界标记构造短语，避免私密词误匹配普通单词。 */
function namePhrase(key: string): string {
  return `_${nameWords(key).join('_')}_`
}

/** 表示按设计公开用途的词语。 */
const PUBLIC_PHRASES = [
  'ANON',
  'PUBLISHABLE',
  'PUBLIC',
  'CLIENT_ID',
  'MEASUREMENT',
  'TRACKING',
  'ANALYTICS',
  'SENTRY_DSN',
  'MAPBOX',
]

/** 明确的私密词；不将泛化的键或令牌词一律视为私密。 */
const PRIVATE_PHRASES = [
  'SECRET',
  'SERVICE_ROLE',
  'SERVICE_KEY',
  'PRIVATE_KEY',
  'PASSWORD',
  'PASSWD',
  'CREDENTIAL',
  'CREDENTIALS',
]

/** 判断变量是否表达公开用途。 */
export function looksIntentionallyPublic(key: string): boolean {
  const phrase = namePhrase(key)
  return PUBLIC_PHRASES.some((p) => phrase.includes(`_${p}_`))
}

/** 判断变量名是否明确表达私密用途。 */
export function looksClearlyPrivate(key: string): boolean {
  const phrase = namePhrase(key)
  return PRIVATE_PHRASES.some((p) => phrase.includes(`_${p}_`))
}

/** 返回匹配的公开前缀。 */
export function publicPrefixOf(key: string): string | null {
  return PUBLIC_PREFIXES.find((p) => key.startsWith(p)) ?? null
}

/** 根据客户端指令和文件类型判断代码是否面向浏览器。 */
export function isClientCode(file: ScanFile): boolean {
  if (/\.(svelte|vue)$/.test(file.path)) return true
  // 跳过许可及注释头，检查首条实际语句。
  let inBlockComment = false
  for (const line of file.lines) {
    let rest = line
    if (inBlockComment) {
      const close = rest.indexOf('*/')
      if (close === -1) continue
      inBlockComment = false
      rest = rest.slice(close + 2)
    }
    // 同一行块注释结束后的代码仍需检查。
    rest = rest.replace(/\/\*[\s\S]*?\*\//g, ' ')
    const opens = rest.indexOf('/*')
    if (opens !== -1) {
      inBlockComment = true
      rest = rest.slice(0, opens)
    }
    const trimmed = rest.trim()
    if (trimmed === '' || trimmed.startsWith('//')) continue
    // 客户端指令必须位于首条实际语句。
    return /^['"]use client['"]/.test(trimmed)
  }
  return false
}

/** 仅在具有 Supabase 使用证据的项目中启用相关规则。 */
/** 共享非全局关键词模式，不维护匹配位置。 */
const MENTIONS_SUPABASE = /supabase/i

/** files 指定候选文件；scope 指定应用路径范围。 */
export function isSupabaseProject(
  ctx: ScanContext,
  files: ScanFile[] = ctx.files,
  scope = '',
): boolean {
  const isSupabaseUrlName = (name: string): boolean =>
    name === 'SUPABASE_URL' || name.endsWith('_SUPABASE_URL')

  for (const file of files) {
    // 按作用域重新计算路径，掩码仍使用原文件对象。
    const path = scope === '' ? file.path : file.path.slice(scope.length + 1)
    if (path === 'supabase' || path.startsWith('supabase/')) return true
    if (path.includes('/supabase/migrations/')) return true

    const name = path.slice(path.lastIndexOf('/') + 1)
    if (isEnvFile(name)) {
      for (const line of file.lines) {
        const entry = parseEnvLine(line)
        if (entry && isSupabaseUrlName(entry.key)) return true
      }
      continue
    }

    if (name === 'package.json') {
      try {
        const pkg = JSON.parse(file.content) as Record<string, unknown>
        for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
          const dependencies = pkg[field]
          if (
            typeof dependencies === 'object' &&
            dependencies !== null &&
            '@supabase/supabase-js' in dependencies
          ) {
            return true
          }
        }
      } catch {
        // 无效 JSON 不提供项目证据，避免将说明文本误判为依赖。
      }
      continue
    }

    // 先检查关键词，避免为无关文件构造掩码。
    if (!MENTIONS_SUPABASE.test(file.content)) continue

    const commentsRemoved = commentsMaskedOf(file)
    const code = noiseMaskedOf(file)
    const supabaseImport =
      /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s*)['"]@supabase\/(?:supabase-js|ssr)(?:\/[^'"]*)?['"]/g
    for (const match of commentsRemoved.matchAll(supabaseImport)) {
      // 导入必须位于真实代码中，不能来自字符串示例。
      const start = match.index
      if (start !== undefined && /\b(?:from|import|require)\b/.test(code.slice(start, start + 10))) {
        return true
      }
    }

    if (/\b(?:[A-Z][A-Z0-9_]*_)?SUPABASE_URL\b/.test(code)) return true

    // 字符串索引访问需同时确认代码语境和变量名。
    const bracketAccess = /(?:process\.env|import\.meta\.env)\s*\[\s*['"]([^'"]+)['"]\s*\]/g
    for (const match of commentsRemoved.matchAll(bracketAccess)) {
      const start = match.index
      if (
        start !== undefined &&
        /(?:process\.env|import\.meta\.env)/.test(code.slice(start, start + 20)) &&
        isSupabaseUrlName(match[1] ?? '')
      ) {
        return true
      }
    }
    if (/\bcreateServerClient\s*\(/.test(code) && /\bsupabase\b/i.test(code)) return true
  }
  return false
}

/** 解码 JWT 载荷；无效输入返回空值。 */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = Buffer.from(parts[1]!, 'base64url').toString('utf8')
    const parsed: unknown = JSON.parse(payload)
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/** 识别 Supabase 管理员 JWT 及新版私密密钥格式。 */
export function isSupabaseServiceRole(value: string): boolean {
  if (value.startsWith('sb_secret_')) return true
  if (!value.startsWith('eyJ')) return false
  return decodeJwtPayload(value)?.['role'] === 'service_role'
}
