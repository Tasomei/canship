/** 仅对已通过 JSON.parse 的配置定位字段，不替代 JSON 语法校验。 */
export function configOffset(text: string, field: string, item?: number): number {
  const tokens = /"(?:\\.|[^"\\])*"|[{}\[\]:,]|[^\s{}\[\]:,"]+/g
  let depth = 0
  let previous = ''
  let currentField = ''
  let index = 0
  let offset = 0
  for (const token of text.matchAll(tokens)) {
    const value = token[0]
    if (depth === 1 && value.startsWith('"') && (previous === '{' || previous === ',')) {
      currentField = JSON.parse(value) as string
      index = 0
      // 重复字段遵循 JSON.parse 的末次值语义。
      if (currentField === field) offset = token.index
    } else if (depth === 2 && currentField === field && item !== undefined &&
        (previous === '[' || previous === ',') && value !== ']') {
      if (index === item) offset = token.index
      index++
    }
    if (value === '{' || value === '[') depth++
    if (value === '}' || value === ']') depth--
    previous = value
  }
  return offset
}

/** 行列从 1 起算；列按 UTF-16 代码单元计数。 */
export function configPosition(text: string, offset: number): { line: number; column: number } {
  const prefix = text.slice(0, offset)
  const lines = prefix.split(/\r\n|\r|\n/)
  return { line: lines.length, column: lines[lines.length - 1]!.length + 1 }
}
