/** 屏蔽非代码文本并保留长度和换行，模板插值中的代码继续参与分析。 */

/** 使用 UTF-16 码元比较，减少逐字符字符串分配。 */
const SLASH = 0x2f
const STAR = 0x2a
const DOUBLE_QUOTE = 0x22
const SINGLE_QUOTE = 0x27
const BACKTICK = 0x60
const BACKSLASH = 0x5c
const DOLLAR = 0x24
const OPEN_BRACE = 0x7b
const CLOSE_BRACE = 0x7d
const NEWLINE = 0x0a
const SPACE = 0x20

/** 固定长度的码元缓冲区，保留代理对和原始偏移。 */
export type MaskBuffer = Uint16Array

/** 复制源码为可原地修改的缓冲区。 */
export function codesOf(src: string): MaskBuffer {
  const out = new Uint16Array(src.length)
  for (let i = 0; i < src.length; i++) out[i] = src.charCodeAt(i)
  return out
}

/** 分块转换字符串，避免超过调用参数上限。 */
const CHUNK = 8192

/** 将缓冲区转换为等长字符串。 */
export function stringOf(out: MaskBuffer): string {
  let text = ''
  for (let i = 0; i < out.length; i += CHUNK) {
    const end = i + CHUNK < out.length ? i + CHUNK : out.length
    text += String.fromCharCode.apply(null, out.subarray(i, end) as unknown as number[])
  }
  return text
}

/** 屏蔽指定区间，但保留换行。 */
export function blank(out: MaskBuffer, from: number, to: number): void {
  const end = to < out.length ? to : out.length
  for (let i = from; i < end; i++) {
    if (out[i] !== NEWLINE) out[i] = SPACE
  }
}

/** 跳过字符串及反斜杠转义，返回结束位置。 */
function endOfString(src: string, start: number, quote: number): number {
  const length = src.length
  let i = start + 1
  while (i < length) {
    const ch = src.charCodeAt(i)
    if (ch === BACKSLASH) {
      i += 2
      continue
    }
    if (ch === quote) return i + 1
    i++
  }
  return length
}

/** 屏蔽模板文本并保留插值表达式。 */
function maskTemplate(src: string, out: MaskBuffer, start: number): number {
  const length = src.length
  let i = start + 1
  let literalFrom = i

  while (i < length) {
    const ch = src.charCodeAt(i)
    if (ch === BACKSLASH) {
      i += 2
      continue
    }
    if (ch === BACKTICK) {
      blank(out, literalFrom, i)
      return i + 1
    }
    if (ch === DOLLAR && src.charCodeAt(i + 1) === OPEN_BRACE) {
      blank(out, literalFrom, i)
      // 递归处理插值中的字符串、注释和嵌套模板。
      let depth = 0
      let j = i + 1
      while (j < length) {
        const inner = src.charCodeAt(j)
        if (inner === SLASH) {
          const next = src.charCodeAt(j + 1)
          if (next === SLASH) {
            const end = src.indexOf('\n', j)
            const stop = end === -1 ? length : end
            blank(out, j, stop)
            j = stop
            continue
          }
          if (next === STAR) {
            const close = src.indexOf('*/', j + 2)
            const stop = close === -1 ? length : close + 2
            blank(out, j, stop)
            j = stop
            continue
          }
        }
        if (inner === DOUBLE_QUOTE || inner === SINGLE_QUOTE) {
          const stop = endOfString(src, j, inner)
          blank(out, j + 1, stop - 1)
          j = stop
          continue
        }
        if (inner === BACKTICK) {
          // 嵌套模板仍需保留其中的表达式。
          j = maskTemplate(src, out, j)
          continue
        }
        if (inner === OPEN_BRACE) depth++
        else if (inner === CLOSE_BRACE) {
          depth--
          if (depth === 0) {
            j++
            break
          }
        }
        j++
      }
      i = j
      literalFrom = i
      continue
    }
    i++
  }

  blank(out, literalFrom, length)
  return length
}

/** 仅屏蔽注释，保留规则需要读取的字符串内容。 */
export function maskJsComments(src: string): string {
  const length = src.length
  const out = codesOf(src)
  let i = 0
  while (i < length) {
    const ch = src.charCodeAt(i)

    if (ch === SLASH) {
      const next = src.charCodeAt(i + 1)
      if (next === SLASH) {
        const end = src.indexOf('\n', i)
        const stop = end === -1 ? length : end
        blank(out, i, stop)
        i = stop
        continue
      }
      if (next === STAR) {
        const close = src.indexOf('*/', i + 2)
        const stop = close === -1 ? length : close + 2
        blank(out, i, stop)
        i = stop
        continue
      }
    }
    // 跳过字符串，避免将 URL 中的斜杠误判为注释。
    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE || ch === BACKTICK) {
      i = endOfString(src, i, ch)
      continue
    }
    i++
  }
  return stringOf(out)
}

/** 屏蔽注释和字符串内容，适用于类 JavaScript 语法。 */
export function maskJsNoise(src: string): string {
  const length = src.length
  const out = codesOf(src)
  let i = 0

  while (i < length) {
    const ch = src.charCodeAt(i)

    if (ch === SLASH) {
      const next = src.charCodeAt(i + 1)
      if (next === SLASH) {
        const end = src.indexOf('\n', i)
        const stop = end === -1 ? length : end
        blank(out, i, stop)
        i = stop
        continue
      }
      if (next === STAR) {
        const close = src.indexOf('*/', i + 2)
        const stop = close === -1 ? length : close + 2
        blank(out, i, stop)
        i = stop
        continue
      }
    }

    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
      const stop = endOfString(src, i, ch)
      // 保留引号及原始偏移，只屏蔽字符串内容。
      blank(out, i + 1, stop - 1)
      i = stop
      continue
    }

    if (ch === BACKTICK) {
      i = maskTemplate(src, out, i)
      continue
    }

    i++
  }

  return stringOf(out)
}

/** 按文件对象缓存掩码，缓存生命周期随扫描结束。 */
const commentCache = new WeakMap<object, string>()
const noiseCache = new WeakMap<object, string>()

/** 缓存仅屏蔽注释的文本。 */
export function commentsMaskedOf(file: { content: string }): string {
  const hit = commentCache.get(file)
  if (hit !== undefined) return hit
  const masked = maskJsComments(file.content)
  commentCache.set(file, masked)
  return masked
}

/** 缓存同时屏蔽注释和字符串的文本。 */
export function noiseMaskedOf(file: { content: string }): string {
  const hit = noiseCache.get(file)
  if (hit !== undefined) return hit
  const masked = maskJsNoise(file.content)
  noiseCache.set(file, masked)
  return masked
}
