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
const LESS_THAN = 0x3c
const GREATER_THAN = 0x3e
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
}

/** 同一次扫描共享失败位置，避免多个插值上下文反复扫描同一行。 */
interface ScanState { failedUntil: number }

const REGEX_PREFIX_WORDS = new Set(['return', 'throw', 'case', 'delete', 'void', 'typeof', 'instanceof', 'in', 'of', 'new', 'yield', 'await', 'else', 'do'])
const CONTROL_WORDS = new Set(['if', 'while', 'for', 'with', 'switch', 'catch'])
const regexContext = (): RegexContext => ({ allowed: true, control: false, member: false, parentheses: [] })

function valueEnded(context: RegexContext): void {
  context.allowed = false
  context.control = false
  context.member = false
}

/** 只在表达式起点读取正则，字符类、转义及标志均不参与代码分析。 */
function regexAt(src: string, start: number, context: RegexContext, state: ScanState): { close: number; end: number } | null {
  // 表达式起点的 /= 仍是正则；复合赋值前必有值，不会处于允许状态。
  if (!context.allowed || start < state.failedUntil) return null
  let inClass = false
  for (let i = start + 1; i < src.length; i++) {
    const ch = src[i]
    if (ch === '\n' || ch === '\r') { state.failedUntil = i; return null }
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
  state.failedUntil = src.length
  return null
}

/** 更新表达式上下文；控制语句的右括号与调用表达式区别处理。 */
function advanceCode(src: string, at: number, context: RegexContext): number {
  const ch = src[at]!
  if (/\s/.test(ch)) return at + 1
  if (/[A-Za-z_$\u0080-￿]/.test(ch)) {
    let end = at + 1
    while (end < src.length && /[\w$\u0080-￿]/.test(src[end]!)) end++
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
  // 小于号后的斜杠通常是 HTML 或 JSX 结束标签，不作为正则起点。
  } else context.allowed = !/[\d\]}<]/.test(ch)
  context.control = false
  context.member = false
  return at + 1
}

/**
 * JSX 起始标签：片段或标签名后接空白、斜杠或右尖括号。
 * TSX 泛型参数 <T,>、<T = X>、<T extends X> 及函数类型 <T>(x: T) => T 不作为元素；
 * 无法确认时按普通代码处理，不扩大屏蔽范围。
 */
const JSX_START = /<(?:>|([A-Za-z_$][\w$.:-]*)(?=[\s/>])(?!\s*(?:,|=|extends\b)))/y

function jsxStartsAt(src: string, at: number): boolean {
  JSX_START.lastIndex = at
  const match = JSX_START.exec(src)
  if (!match) return false
  const name = match[1]
  if (!name || !/^[A-Z]/.test(name)) return true
  const after = at + 1 + name.length
  return !/^>\s*\(/.test(src.slice(after, after + 64))
}

/** 代码、模板文本、JSX 标签与 JSX 文本分别入栈，避免深层嵌套耗尽调用栈。 */
type Frame =
  | { kind: 'code'; depth: number; lexical: RegexContext; nested: boolean }
  | { kind: 'literal'; from: number }
  | { kind: 'tag'; closing: boolean }
  | { kind: 'children'; from: number }

export interface MaskOptions {
  /** 识别 JSX 标签与文本；仅用于 .js、.jsx、.tsx 等允许 JSX 的文件。 */
  jsx?: boolean
}

/** 两种模式都屏蔽注释；仅完整掩码屏蔽字符串、正则、模板及 JSX 文本内容。 */
function maskSource(src: string, maskStrings: boolean, jsx: boolean): string {
  const length = src.length
  const out = codesOf(src)
  const state: ScanState = { failedUntil: -1 }
  const stack: Frame[] = [{ kind: 'code', depth: 0, lexical: regexContext(), nested: false }]
  const text = (from: number, to: number): void => { if (maskStrings) blank(out, from, to) }
  const expression = (): Frame => ({ kind: 'code', depth: 1, lexical: regexContext(), nested: true })
  const skipComment = (at: number): number => {
    const star = src.charCodeAt(at + 1) === STAR
    const close = star ? src.indexOf('*/', at + 2) : src.indexOf('\n', at)
    const stop = close === -1 ? length : close + (star ? 2 : 0)
    blank(out, at, stop)
    return stop
  }
  // 元素结束后回到父级：JSX 文本继续，或表达式已取得值。
  const elementClosed = (at: number): void => {
    const parent = stack[stack.length - 1]
    if (parent?.kind === 'children') parent.from = at
    else if (parent?.kind === 'code') valueEnded(parent.lexical)
  }

  let i = 0
  while (i < length) {
    const frame = stack[stack.length - 1]!
    const ch = src.charCodeAt(i)

    if (frame.kind === 'literal') {
      if (ch === BACKSLASH) {
        i = Math.min(i + 2, length)
        continue
      }
      if (ch === BACKTICK) {
        text(frame.from, i)
        stack.pop()
        const parent = stack[stack.length - 1]
        if (parent?.kind === 'code') valueEnded(parent.lexical)
        i++
        continue
      }
      if (ch === DOLLAR && src.charCodeAt(i + 1) === OPEN_BRACE) {
        text(frame.from, i)
        stack.push(expression())
        i += 2
        continue
      }
      i++
      continue
    }

    if (frame.kind === 'children') {
      if (ch === OPEN_BRACE) {
        text(frame.from, i)
        stack.push(expression())
        i++
        continue
      }
      if (ch === LESS_THAN && src.charCodeAt(i + 1) === SLASH) {
        text(frame.from, i)
        stack.push({ kind: 'tag', closing: true })
        i += 2
        continue
      }
      if (ch === LESS_THAN && jsxStartsAt(src, i)) {
        text(frame.from, i)
        stack.push({ kind: 'tag', closing: false })
        i++
        continue
      }
      i++
      continue
    }

    if (frame.kind === 'tag') {
      if (ch === SLASH && (src.charCodeAt(i + 1) === SLASH || src.charCodeAt(i + 1) === STAR)) {
        i = skipComment(i)
        continue
      }
      if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
        // JSX 属性字符串没有反斜杠转义。
        const close = src.indexOf(src[i]!, i + 1)
        const stop = close === -1 ? length : close + 1
        text(i + 1, close === -1 ? length : close)
        i = stop
        continue
      }
      if (ch === OPEN_BRACE) {
        stack.push(expression())
        i++
        continue
      }
      if (ch === LESS_THAN && !frame.closing && jsxStartsAt(src, i)) {
        // 属性值可以直接是元素。
        stack.push({ kind: 'tag', closing: false })
        i++
        continue
      }
      if (ch === SLASH && src.charCodeAt(i + 1) === GREATER_THAN && !frame.closing) {
        stack.pop()
        elementClosed(i + 2)
        i += 2
        continue
      }
      if (ch === GREATER_THAN) {
        stack.pop()
        if (frame.closing) {
          if (stack[stack.length - 1]?.kind === 'children') stack.pop()
          elementClosed(i + 1)
        } else {
          stack.push({ kind: 'children', from: i + 1 })
        }
        i++
        continue
      }
      i++
      continue
    }

    // 先跳过注释，注释中的引号和括号不参与边界判断。
    if (ch === SLASH) {
      const next = src.charCodeAt(i + 1)
      if (next === SLASH || next === STAR) {
        i = skipComment(i)
        continue
      }
      const regex = regexAt(src, i, frame.lexical, state)
      if (regex) {
        text(i + 1, regex.close)
        i = regex.end
        continue
      }
    }
    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
      const stop = endOfString(src, i, ch)
      // 保留引号及原始偏移，只屏蔽字符串内容。
      text(i + 1, stop - 1)
      valueEnded(frame.lexical)
      i = stop
      continue
    }
    if (ch === BACKTICK) {
      stack.push({ kind: 'literal', from: i + 1 })
      i++
      continue
    }
    if (jsx && ch === LESS_THAN && frame.lexical.allowed && jsxStartsAt(src, i)) {
      stack.push({ kind: 'tag', closing: false })
      i++
      continue
    }
    if (ch === OPEN_BRACE) frame.depth++
    else if (ch === CLOSE_BRACE) {
      frame.depth--
      if (frame.nested && frame.depth === 0) {
        stack.pop()
        const parent = stack[stack.length - 1]!
        if (parent.kind === 'literal' || parent.kind === 'children') parent.from = i + 1
        i++
        continue
      }
    }
    i = advanceCode(src, i, frame.lexical)
  }

  const last = stack[stack.length - 1]
  if (last?.kind === 'literal' || last?.kind === 'children') text(last.from, length)
  return stringOf(out)
}

/** 仅屏蔽注释，保留规则需要读取的字符串内容。 */
export function maskJsComments(src: string, options: MaskOptions = {}): string {
  return maskSource(src, false, options.jsx === true)
}

/** 屏蔽注释和字符串内容，适用于类 JavaScript 语法。 */
export function maskJsNoise(src: string, options: MaskOptions = {}): string {
  return maskSource(src, true, options.jsx === true)
}

/** 允许 JSX 的文件；.ts 中的尖括号可能是类型断言，不按 JSX 处理。 */
const JSX_FILE = /\.(?:jsx|tsx|js|mjs|cjs)$/i
const maskOptionsOf = (file: { path?: string }): MaskOptions => ({ jsx: typeof file.path === 'string' && JSX_FILE.test(file.path) })

/** 按文件对象缓存掩码，缓存生命周期随扫描结束。 */
const commentCache = new WeakMap<object, string>()
const noiseCache = new WeakMap<object, string>()

/** 缓存仅屏蔽注释的文本。 */
export function commentsMaskedOf(file: { content: string; path?: string }): string {
  const hit = commentCache.get(file)
  if (hit !== undefined) return hit
  const masked = maskJsComments(file.content, maskOptionsOf(file))
  commentCache.set(file, masked)
  return masked
}

/** 缓存同时屏蔽注释和字符串的文本。 */
export function noiseMaskedOf(file: { content: string; path?: string }): string {
  const hit = noiseCache.get(file)
  if (hit !== undefined) return hit
  const masked = maskJsNoise(file.content, maskOptionsOf(file))
  noiseCache.set(file, masked)
  return masked
}
