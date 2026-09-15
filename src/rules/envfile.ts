/** 共享环境文件解析逻辑，统一处理引号、转义和行尾注释。 */

/** 环境文件中的单条键值赋值。 */
export interface EnvAssignment {
  key: string
  value: string
}

/** 按环境文件语义读取值。 */
export function parseEnvValue(raw: string): string {
  const value = raw.trim()
  const quote = value[0]

  if (quote === '"' || quote === "'" || quote === '`') {
    // 读取到配对引号；引号中的井号属于值。
    let out = ''
    for (let i = 1; i < value.length; i++) {
      const ch = value[i]!
      if (ch === '\\' && quote === '"' && i + 1 < value.length) {
        // 双引号内解析换行等转义，支持私钥值。
        const next = value[++i]!
        out += next === 'n' ? '\n' : next === 'r' ? '\r' : next === 't' ? '\t' : next
        continue
      }
      if (ch === quote) break
      out += ch
    }
    return out
  }

  // 无引号值在第一个井号处结束。
  const comment = value.indexOf('#')
  return (comment === -1 ? value : value.slice(0, comment)).trim()
}

/** 解析赋值行；空行、注释或非赋值行返回空值。 */
export function parseEnvLine(raw: string): EnvAssignment | null {
  const line = raw.trim()
  if (!line || line.startsWith('#')) return null
  const m = /^(?:export\s+)?([\w.-]+)\s*=\s*(.*)$/.exec(line)
  if (!m) return null
  return { key: m[1]!, value: parseEnvValue(m[2] ?? '') }
}
