/** 共享字符偏移到行号的转换逻辑。 */

/** 单次构建行起点数组，每次匹配通过二分查询定位。 */
export function lineStartsOf(content: string): number[] {
  const starts = [0]
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') starts.push(i + 1)
  }
  return starts
}

/** 将字符偏移转换为从 1 开始的行号。 */
export function lineNumberAt(lineStarts: number[], index: number): number {
  let lo = 0
  let hi = lineStarts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (lineStarts[mid]! <= index) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}
