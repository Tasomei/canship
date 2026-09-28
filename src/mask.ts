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

interface RegexContext {
  allowed: boolean
  control: boolean
  member: boolean
  parentheses: boolean[]
  failedUntil: number
}

const REGEX_PREFIX_WORDS = new Set(['return', 'throw', 'case', 'delete', 'void', 'typeof', 'instanceof', 'in', 'of', 'new', 'yield', 'await', 'else', 'do'])
const CONTROL_WORDS = new Set(['if', 'while', 'for', 'with', 'switch', 'catch'])
const regexContext = (): RegexContext => ({ allowed: true, control: false, member: false, parentheses: [], failedUntil: -1 })

function valueEnded(context: RegexContext): void {
  context.allowed = false
  context.control = false
  context.member = false
}

/** 只在表达式起点读取正则，字符类、转义及标志均不参与代码分析。 */
function regexAt(src: string, start: number, context: RegexContext): { close: number; end: number } | null {
  if (!context.allowed || start < context.failedUntil || src[start + 1] === '=') return null
  let inClass = false
  for (let i = start + 1; i < src.length; i++) {
    const ch = src[i]
    if (ch === '\n' || ch === '\r') { context.failedUntil = i; return null }
    if (ch === '\\') { i++; continue }
    if (ch === '[') inClass = true
    else if (ch === ']') inClass = false
    else if (ch === '/' && !inClass) {
      let end = i + 1
      while (end < src.length && /[A-Za-z]/.test(src[end]!)) end++
      valueEnded(context)
      return { close: i, end }
    }
  }
  context.failedUntil = src.length
  return null
}

/** 更新表达式上下文；控制语句的右括号与调用表达式区别处理。 */
function advanceCode(src: string, at: number, context: RegexContext): number {
  const ch = src[at]!
  if (/\s/.test(ch)) return at + 1
  if (/[A-Za-z_$\u0080-\uffff]/.test(ch)) {
    let end = at + 1
    while (end < src.length && /[\w$\u0080-\uffff]/.test(src[end]!)) end++
    const word = src.slice(at, end)
    context.control = !context.member && CONTROL_WORDS.has(word)
    context.allowed = !context.member && REGEX_PREFIX_WORDS.has(word)
    context.member = false
    return end
  }
  if (ch === '(') { context.parentheses.push(context.control); context.allowed = true }
  else if (ch === ')') context.allowed = context.parentheses.pop() ?? false
  else if (ch === '.' || ch === '?' && src[at + 1] === '.') {
    context.allowed = false
    context.control = false
    context.member = true
    return at + (ch === '?' ? 2 : 1)
  } else if ((ch === '+' || ch === '-') && src[at + 1] === ch) {
    context.control = false
    context.member = false
    return at + 2
  } else context.allowed = !/[\d\]}]/.test(ch)
  context.control = false
  context.member = false
  return at + 1
}

/** 模板与插值状态分开入栈，避免深层嵌套耗尽调用栈。 */
type TemplateFrame =
  | { kind: 'literal'; from: number }
  | { kind: 'expression'; depth: number; lexical: RegexContext }

/** 遍历模板；两种模式都屏蔽插值注释，仅完整掩码屏蔽字符串内容。 */
function maskTemplate(src: string, out: MaskBuffer, start: number, maskStrings = true): number {
  const length = src.length
  const stack: TemplateFrame[] = [{ kind: 'literal', from: start + 1 }]
  let i = start + 1

  while (i < length && stack.length > 0) {
    const frame = stack[stack.length - 1]!
    const ch = src.charCodeAt(i)
    if (frame.kind === 'literal') {
      if (ch === BACKSLASH) {
        i = Math.min(i + 2, length)
        continue
      }
      if (ch === BACKTICK) {
        if (maskStrings) blank(out, frame.from, i)
        stack.pop()
        const parent = stack[stack.length - 1]
        if (parent?.kind === 'expression') valueEnded(parent.lexical)
        i++
        continue
      }
      if (ch === DOLLAR && src.charCodeAt(i + 1) === OPEN_BRACE) {
        if (maskStrings) blank(out, frame.from, i)
        stack.push({ kind: 'expression', depth: 1, lexical: regexContext() })
        i += 2
        continue
      }
      i++
      continue
    }

    // 先跳过注释，注释中的引号和括号不参与边界判断。
    if (ch === SLASH) {
      const next = src.charCodeAt(i + 1)
      if (next === SLASH || next === STAR) {
        const close = next === SLASH ? src.indexOf('\n', i) : src.indexOf('*/', i + 2)
        const stop = close === -1 ? length : close + (next === STAR ? 2 : 0)
        blank(out, i, stop)
        i = stop
        continue
      }
      const regex = regexAt(src, i, frame.lexical)
      if (regex) {
        if (maskStrings) blank(out, i + 1, regex.close)
        i = regex.end
        continue
      }
    }
    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
      const stop = endOfString(src, i, ch)
      if (maskStrings) blank(out, i + 1, stop - 1)
      valueEnded(frame.lexical)
      i = stop
      continue
    }
    if (ch === BACKTICK) {
      stack.push({ kind: 'literal', from: i + 1 })
      i++
      continue
    }
    if (ch === OPEN_BRACE) frame.depth++
    else if (ch === CLOSE_BRACE) {
      frame.depth--
      if (frame.depth === 0) {
        stack.pop()
        const parent = stack[stack.length - 1]!
        if (parent.kind === 'literal') parent.from = i + 1
      }
    }
    i = advanceCode(src, i, frame.lexical)
  }

  const last = stack[stack.length - 1]
  if (maskStrings && last?.kind === 'literal') blank(out, last.from, length)
  return i
}

/** 仅屏蔽注释，保留规则需要读取的字符串内容。 */
export function maskJsComments(src: string): string {
  const length = src.length
  const out = codesOf(src)
  let i = 0
  const lexical = regexContext()
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
    if (ch === SLASH) {
      const regex = regexAt(src, i, lexical)
      if (regex) { i = regex.end; continue }
    }
    // 跳过字符串，避免将 URL 中的斜杠误判为注释。
    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
      i = endOfString(src, i, ch)
      valueEnded(lexical)
      continue
    }
    if (ch === BACKTICK) {
      i = maskTemplate(src, out, i, false)
      valueEnded(lexical)
      continue
    }
    i = advanceCode(src, i, lexical)
  }
  return stringOf(out)
}

/** 屏蔽注释和字符串内容，适用于类 JavaScript 语法。 */
export function maskJsNoise(src: string): string {
  const length = src.length
  const out = codesOf(src)
  let i = 0
  const lexical = regexContext()

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

    if (ch === SLASH) {
      const regex = regexAt(src, i, lexical)
      if (regex) {
        blank(out, i + 1, regex.close)
        i = regex.end
        continue
      }
    }

    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
      const stop = endOfString(src, i, ch)
      // 保留引号及原始偏移，只屏蔽字符串内容。
      blank(out, i + 1, stop - 1)
      valueEnded(lexical)
      i = stop
      continue
    }

    if (ch === BACKTICK) {
      i = maskTemplate(src, out, i)
      valueEnded(lexical)
      continue
    }

    i = advanceCode(src, i, lexical)
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
