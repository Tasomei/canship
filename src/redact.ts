/** 统一脱敏可识别的凭据；不保证识别未知格式。 */

import { JWT_SOURCE, SECRET_PATTERNS } from './rules/patterns.js'

/** 脱敏后保留的首尾字符数。 */
const KEEP_HEAD = 6
const KEEP_TAIL = 2

/** 保留少量首尾字符和长度以便识别凭据。 */
export function redactSecret(secret: string): string {
  if (secret.length <= KEEP_HEAD + KEEP_TAIL + 4) {
    // 短值全部遮蔽，避免保留完整内容。
    return '•'.repeat(Math.max(secret.length, 8))
  }
  const head = secret.slice(0, KEEP_HEAD)
  const tail = secret.slice(-KEEP_TAIL)
  return `${head}…(${secret.length} chars)…${tail}`
}

/** 替换行内指定凭据，其余凭据由统一输出边界处理。 */
export function redactLine(line: string, secret: string): string {
  const trimmed = line.trim()
  // 保留完整行；统一输出边界先脱敏所有凭据，再进行截断。
  if (!secret) return trimmed
  return trimmed.split(secret).join(redactSecret(secret))
}

/** 按 JWT 外形整体脱敏，不依赖角色解码结果。 */
const JWT_SHAPED = new RegExp(String.raw`\b${JWT_SOURCE}\b`, 'g')

/** 使用共享凭据模式清理文本中的所有匹配。 */
export function redactAll(text: string): string {
  let out = text
  for (const pat of SECRET_PATTERNS) {
    // 每次新建正则，避免共享匹配位置状态。
    const re = new RegExp(pat.pattern.source, pat.pattern.flags)
    out = out.replace(re, (match) => redactSecret(match))
  }
  return out.replace(new RegExp(JWT_SHAPED.source, JWT_SHAPED.flags), (m) => redactSecret(m))
}

/** 限制展示长度，必须在完整脱敏之后调用。 */
export function truncate(s: string, max = 120): string {
  return s.length <= max ? s : `${s.slice(0, max)}…`
}
