/**
 * 请求输入决定服务器外发请求的目标（SSRF）或跳转目标（开放重定向）。
 * 只看输入能否决定目标地址的开头：固定站点后只拼接路径或查询参数的不报告，请求自身的 URL 也不算输入。
 */
import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { lineNumberAt } from './offsets.js'
import { argumentExpressions } from './auth-values.js'
import type { Route } from './apiauth.js'
import { MAX_EXPRESSION, handlerFileOf, lowerBound, reportInputLimit, type HandlerFile, type InputFlow, type Taint } from './request-input.js'

/** 服务端 HTTP 客户端：fetch、Nuxt 的 $fetch/ofetch、axios、got、ky、needle 及 Node http(s)。 */
const FETCH_CALL = /(?<![\w$.])(?:fetch|\$fetch|ofetch|axios|got|ky|needle)\s*(?:<[^()]{0,200}>\s*)?\(/g
const FETCH_METHOD = /(?<![\w$.])(?:axios|got|ky|needle|http|https|undici)\s*\.\s*(?:get|post|put|patch|delete|head|request|stream)\s*(?:<[^()]{0,200}>\s*)?\(/g

/** 跳转接口：Next.js/Remix/SvelteKit 的 redirect、Response.redirect、res.redirect、Fastify 的 reply.redirect、Hono 的 c.redirect 与 h3 的 sendRedirect。 */
const REDIRECT_CALL = /(?<![\w$.])(?:redirect|permanentRedirect|sendRedirect)\s*\(|(?<![\w$.])(?:NextResponse|Response|res|reply|response|ctx|context|c|Astro)\s*\.\s*redirect\s*\(/g

type Kind = 'ssrf' | 'redirect'
interface Call { kind: Kind; at: number; open: number; close: number; name: string }

function callsIn(code: string, pairs: Map<number, number>): Call[] {
  const calls: Call[] = []
  const add = (regex: RegExp, kind: Kind): void => {
    regex.lastIndex = 0
    for (const m of code.matchAll(regex)) {
      const open = m.index + m[0].length - 1
      const close = pairs.get(open)
      if (close !== undefined) calls.push({ kind, at: m.index, open, close, name: m[0] })
    }
  }
  add(FETCH_CALL, 'ssrf')
  add(FETCH_METHOD, 'ssrf')
  add(REDIRECT_CALL, 'redirect')
  return calls
}

/** 输入写在这些开头之后即可决定目标主机：空、只有未知前缀（X 表示非输入插值）、协议加未结束的主机名。 */
const HOST_OPEN = /^(?:X?|[a-z][\w+.-]*:\/\/[^/?#\\]*)$/i
/** 跳转还接受相对形式：/ 后接输入可构成 //evil.example，// 或 \\ 开头同样由输入决定主机。 */
const REDIRECT_OPEN = /^(?:\/|[/\\]{2}[^/?#\\]*)$/
/** 仍可能延伸成上述开头的前缀；不满足时后续输入不再决定目标，可提前结束。 */
const HOST_OPENABLE = /^(?:X?|[a-z][\w+.-]*(?::(?:\/(?:\/[^/?#\\]*)?)?)?)$/i
const REDIRECT_OPENABLE = /^(?:[/\\](?:[/\\][^/?#\\]*)?)?$/

/** 判断表达式开头是否由请求输入决定；返回决定开头的输入。 */
function controlsStart(expr: string, at: number, flow: InputFlow, source: string, kind: Kind, depth = 0): Taint | null {
  const lead = expr.length - expr.trimStart().length
  const text = expr.trim()
  const start = at + lead
  if (text === '') return null
  if (depth >= 8) { flow.limited = true; return null }
  if (text.length > MAX_EXPRESSION) { flow.limited = true; return null }
  const open = (prefix: string): boolean => HOST_OPEN.test(prefix) || (kind === 'redirect' && REDIRECT_OPEN.test(prefix))

  // a ? b : c、a ?? b、a || b：目标可能是任一分支，逐个判断；条件本身不是目标。
  const branches = alternativesOf(text)
  if (branches) {
    for (const branch of branches) {
      const t = controlsStart(branch.text, start + branch.at, flow, source, kind, depth + 1)
      if (t) return t
    }
    return null
  }

  // new URL(input, base)：输入为绝对地址或 // 开头时基址被忽略。
  const url = /^new\s+URL\s*\(/.exec(text)
  if (url) {
    const argsStart = start + url[0].length
    const close = matchingParen(text, url[0].length - 1)
    if (close === null) return null
    // 只有整个表达式就是 new URL(…) 时才按基址规则判断；new URL(…).searchParams 等继续按普通表达式处理。
    if (close === text.length - 1) {
      const first = splitTopLevel(text.slice(url[0].length, close))[0]
      return first === undefined ? null : controlsStart(first, argsStart, flow, source, 'redirect', depth + 1)
    }
  }
  if (text.startsWith('\x60')) return templateStart(text, start, flow, source, open, kind, depth)

  const joined = joinedElements(text, start)
  const operands = joined ?? flow.operandsOf(text, start)
  if (operands.length > 1 || (joined && operands.length > 0)) {
    let prefix = ''
    for (const operand of operands) {
      const inner = operand.text.trim()
      if (/^['"]/.test(inner)) { prefix += source.slice(operand.at + operand.text.indexOf(inner) + 1, operand.at + operand.text.indexOf(inner) + inner.length - 1); continue }
      const t = inner.startsWith('\x60')
        ? templateStart(inner, operand.at + operand.text.indexOf(inner), flow, source, open, kind, depth)
        : controlsStart(inner, operand.at + operand.text.indexOf(inner), flow, source, kind, depth + 1)
      if (t) return open(prefix) ? t : null
      prefix += 'X'
      if (!open(prefix)) return null
    }
    return null
  }

  // 变量：看它的每一次赋值；追加赋值不改变开头。
  if (/^[A-Za-z_$][\w$]*$/.test(text)) {
    const assignments = flow.assignmentsFor(text, at).filter(a => !a.append)
    if (assignments.length === 0) {
      const t = flow.valueOf(text, at)
      return t && !t.ownUrl ? t : null
    }
    for (const a of assignments) {
      // 解构或遍历得到的是右侧的一部分，按统一的取值规则判断（含未知函数返回值的字段）。
      if (a.iterate || /^[{[]/.test(a.pattern.trim())) {
        const t = flow.valueOf(text, at)
        if (t && !t.ownUrl) return t
        continue
      }
      const t = controlsStart(a.expr, a.exprAt, flow, source, kind, depth + 1)
      // 记下变量名，使用前对它的检查才能被识别。
      if (t) return { ...t, level: a.indirect ? 'derived' : t.level, names: new Set([...t.names, text]) }
    }
    return null
  }

  const t = flow.taintOf(text, start)
  return t && !t.ownUrl ? t : null
}

/**
 * 顶层三元表达式的两个结果分支，或 ?? 与 || 的各操作数；不含这些运算时返回空值。
 * 文本已屏蔽字符串内容，括号内部及可选链 ?. 不参与拆分。
 */
function alternativesOf(text: string): Array<{ text: string; at: number }> | null {
  const top: number[] = []
  let depth = 0
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if ('([{'.includes(ch)) depth++
    else if (')]}'.includes(ch)) depth--
    else if (depth === 0) top.push(i)
  }
  const at = (i: number): string => (top.includes(i) ? text[i]! : '')
  // 三元：第一个顶层 ?（不是 ?. 或 ??），再找同层配对的 :。
  for (const i of top) {
    if (text[i] !== '?' || text[i + 1] === '.' || text[i + 1] === '?' || text[i - 1] === '?') continue
    let nested = 0
    for (const j of top) {
      if (j <= i) continue
      if (text[j] === '?' && text[j + 1] !== '.' && text[j + 1] !== '?' && text[j - 1] !== '?') nested++
      else if (text[j] === ':' && nested-- === 0) {
        return [{ text: text.slice(i + 1, j), at: i + 1 }, { text: text.slice(j + 1), at: j + 1 }]
      }
    }
    return null
  }
  const parts: Array<{ text: string; at: number }> = []
  let from = 0
  for (const i of top) {
    const pair = at(i) + at(i + 1)
    if ((pair === '??' || pair === '||') && i >= from) {
      parts.push({ text: text.slice(from, i), at: from })
      from = i + 2
    }
  }
  if (parts.length === 0) return null
  parts.push({ text: text.slice(from), at: from })
  return parts
}

/** 模板：静态文本取原文，非输入插值记作 X，遇到第一个输入插值时按已有前缀判断。 */
function templateStart(text: string, start: number, flow: InputFlow, source: string, open: (prefix: string) => boolean,
  kind: Kind, depth: number): Taint | null {
  let prefix = ''
  for (let i = 1; i < text.length; i++) {
    if (text[i] === '\x60') return null
    if (text[i] === '$' && text[i + 1] === '{') {
      const close = matchingBrace(text, i + 1)
      if (close === null) return null
      const t = flow.taintOf(text.slice(i + 2, close), start + i + 2)
      if (t && !t.ownUrl) {
        if (!open(prefix)) return null
        // 模板以该插值开头时，目标的开头就是插值自身的开头，如 `${base}&token=…` 中 base 以固定路径开头。
        return prefix === '' ? controlsStart(text.slice(i + 2, close), start + i + 2, flow, source, kind, depth + 1) : t
      }
      prefix += 'X'
      i = close
      continue
    }
    prefix += source[start + i]
    if (!HOST_OPENABLE.test(prefix) && !(kind === 'redirect' && REDIRECT_OPENABLE.test(prefix))) return null
    if (prefix.length > 200) { flow.limited = true; return null }
  }
  return null
}

function matchingParen(text: string, open: number): number | null {
  let depth = 0
  for (let i = open; i < text.length; i++) {
    if (text[i] === '(') depth++
    else if (text[i] === ')' && --depth === 0) return i
  }
  return null
}

function matchingBrace(text: string, open: number): number | null {
  let depth = 0
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') depth++
    else if (text[i] === '}' && --depth === 0) return i
  }
  return null
}

/** [a, b, …].join('')：数组元素按顺序拼接，与 + 拼接同样判断开头；其他分隔符或形式返回空值。 */
function joinedElements(text: string, start: number): Array<{ text: string; at: number }> | null {
  if (!text.startsWith('[')) return null
  let depth = 0, close = -1
  for (let i = 0; i < text.length; i++) {
    if ('([{'.includes(text[i]!)) depth++
    else if (')]}'.includes(text[i]!) && --depth === 0) { close = i; break }
  }
  if (close === -1 || text[close] !== ']' || !/^\s*\.\s*join\s*\(\s*(['"\x60])\1\s*\)\s*$/.test(text.slice(close + 1))) return null
  const elements: Array<{ text: string; at: number }> = []
  let from = 1
  depth = 0
  for (let i = 1; i <= close; i++) {
    if (i < close && '([{'.includes(text[i]!)) depth++
    else if (i < close && ')]}'.includes(text[i]!)) depth--
    else if (i === close || (text[i] === ',' && depth === 0)) {
      if (text.slice(from, i).trim() !== '') elements.push({ text: text.slice(from, i), at: start + from })
      from = i + 1
    }
  }
  return elements
}

function splitTopLevel(text: string): string[] {
  const parts: string[] = []
  let depth = 0, from = 0
  for (let i = 0; i < text.length; i++) {
    if ('([{'.includes(text[i]!)) depth++
    else if (')]}'.includes(text[i]!)) depth--
    else if (text[i] === ',' && depth === 0) { parts.push(text.slice(from, i)); from = i + 1 }
  }
  parts.push(text.slice(from))
  return parts
}

/** 目标地址所在的实参：状态码在前的 redirect(303, url)、sendRedirect(event, url)，以及选项对象中的 url。 */
function targetOf(call: Call, analysed: HandlerFile): { expr: string; at: number } | null {
  const { code, pairs } = analysed
  const args = argumentExpressions(code, code, call.open + 1, call.close, pairs)
  if (args.length === 0) return null
  const positions: number[] = []
  let cursor = call.open + 1
  for (const arg of args) {
    const found = code.indexOf(arg, cursor)
    positions.push(found)
    cursor = found + arg.length
  }
  let index = 0
  if (call.kind === 'redirect') {
    if (/sendRedirect/.test(call.name)) index = 1
    else if (/^\d{3}$/.test(args[0]!) && args.length > 1) index = 1
  }
  const expr = args[index]
  if (expr === undefined) return null
  // axios({ url }) 与 got({ url })：取对象中的 url 或 baseURL。
  if (call.kind === 'ssrf' && expr.startsWith('{')) {
    const property = /(?:^|[{,])\s*(?:url|baseURL|href)\s*:\s*/.exec(expr)
    if (!property) {
      // 简写属性 { url }：值就是同名变量。
      const shorthand = /(?:^|[{,])\s*(url|baseURL|href)\s*(?=[,}])/.exec(expr)
      return shorthand ? { expr: shorthand[1]!, at: positions[index]! + shorthand.index + shorthand[0].length - shorthand[1]!.length } : null
    }
    const valueAt = positions[index]! + property.index + property[0].length
    const value = splitTopLevel(expr.slice(property.index + property[0].length))[0]!.replace(/\}\s*$/, '')
    return { expr: value, at: valueAt }
  }
  return { expr, at: positions[index]! }
}

/** 按顶层运算符拆分表达式，跳过括号内的内容。 */
function splitTopLevelOperator(text: string, operator: '&&' | '||'): string[] {
  const parts: string[] = []
  let depth = 0, from = 0
  for (let i = 0; i < text.length; i++) {
    if ('([{'.includes(text[i]!)) depth++
    else if (')]}'.includes(text[i]!)) depth--
    else if (depth === 0 && text.startsWith(operator, i)) { parts.push(text.slice(from, i)); from = i + 2; i++ }
  }
  parts.push(text.slice(from))
  return parts.map(part => part.trim())
}

/** 去掉包住整个表达式的一层括号。 */
function unwrap(text: string): string {
  let current = text.trim()
  while (current.startsWith('(') && matchingParen(current, 0) === current.length - 1) current = current.slice(1, -1).trim()
  return current
}

/** 声明语句的初始化表达式结束处：顶层分号，或不在运算符前后的换行。 */
function initializerEnd(code: string, from: number, limit: number): number {
  let depth = 0
  for (let i = from; i < limit; i++) {
    const ch = code[i]!
    if ('([{'.includes(ch)) depth++
    else if (')]}'.includes(ch)) { if (--depth < 0) return i }
    else if (depth === 0 && ch === ';') return i
    else if (depth === 0 && ch === '\n') {
      const before = code.slice(from, i).trimEnd(), after = code.slice(i + 1, limit).trimStart()
      if (!/(?:&&|\|\||[=?:+,(-])$/.test(before) && !/^(?:&&|\|\||[?:.+])/.test(after)) return i
    }
  }
  return limit
}

/**
 * 外发请求前的主机白名单：先用 new URL() 解析同一输入，再在不满足时 return/throw 的 if 中，
 * 令所有继续执行的分支都要求 origin、host 或 hostname 等于代码中的字符串字面量（或字面量数组之一）。
 * 只认这种能证明目标主机固定的结构，函数名或路径检查都不算。
 */
function allowlistedHost(analysed: HandlerFile, bodyStart: number, callAt: number, targetExpr: string, names: Set<string>): boolean {
  const { code, source, pairs } = analysed
  const region = code.slice(bodyStart, callAt)
  const parsed = new Set<string>()
  for (const m of region.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?::\s*URL\s*)?=\s*new\s+URL\s*\(/g)) {
    const open = bodyStart + m.index + m[0].length - 1
    const close = pairs.get(open)
    const argument = close === undefined ? '' : code.slice(open + 1, close).trim()
    if (names.has(argument)) parsed.add(m[1]!)
  }
  if (parsed.size === 0) return false
  const target = targetExpr.trim()
  const targetOk = names.has(target) || [...parsed].some(p => new RegExp(`^${p}(?:\\s*\\.\\s*(?:href|toString\\s*\\(\\s*\\)))?$`).test(target))
  if (!targetOk) return false
  const isLiteral = (at: number, text: string): boolean => {
    const raw = source.slice(at, at + text.length).trim()
    return /^(['"])[^'"\\\n]*\1$/.test(raw) || /^`[^`$\\]*`$/.test(raw)
  }
  // 当前文件中的字符串字面量数组常量，以及函数体内请求前的布尔常量。
  const literalArray = (expr: string, at: number): boolean => {
    const inner = expr.trim()
    if (inner.startsWith('[')) {
      const items = splitTopLevel(inner.slice(1, -1)).filter(item => item.trim() !== '')
      let cursor = at + code.slice(at).indexOf('[') + 1
      return items.length > 0 && items.every(item => { const itemAt = code.indexOf(item, cursor); cursor = itemAt + item.length; return isLiteral(itemAt, item) })
    }
    const name = /^[A-Za-z_$][\w$]*$/.exec(inner)?.[0]
    if (!name) return false
    const def = new RegExp(`\\bconst\\s+${name}\\s*(?::[^=]+)?=\\s*\\[`).exec(code)
    if (!def) return false
    const open = def.index + def[0].length - 1
    const close = pairs.get(open)
    return close !== undefined && literalArray(code.slice(open, close + 1), open)
  }
  const definitions = new Map<string, { expr: string; at: number }>()
  for (const m of region.matchAll(/\bconst\s+([A-Za-z_$][\w$]*)\s*=\s*/g)) {
    const start = bodyStart + m.index + m[0].length
    const end = initializerEnd(code, start, callAt)
    definitions.set(m[1]!, { expr: code.slice(start, end), at: start })
  }
  const field = `(?:${[...parsed].join('|')})\\s*\\.\\s*(?:origin|host|hostname)`
  // negated 表示原文为 x !== 'lit' 形式的退出条件，继续执行时即 x === 'lit'。
  const fixesHost = (atom: string, at: number, negated = false): boolean => {
    const text = unwrap(atom)
    const offset = at + atom.indexOf(text)
    const operator = negated ? '!==?' : '===?'
    const left = new RegExp(`^${field}\\s*${operator}\\s*([\\s\\S]+)$`).exec(text)
    if (left) return isLiteral(offset + text.length - left[1]!.length, left[1]!)
    const right = new RegExp(`^([\\s\\S]+?)\\s*${operator}\\s*${field}$`).exec(text)
    if (right) return isLiteral(offset, right[1]!)
    if (negated) return false
    const includes = new RegExp(`^([\\s\\S]+?)\\s*\\.\\s*includes\\s*\\(\\s*${field}\\s*\\)$`).exec(text)
    return includes ? literalArray(includes[1]!, offset) : false
  }
  // 一个继续执行的分支（合取式）中只要有一项固定主机即可。
  const branchFixes = (expr: string, at: number, depth = 0): boolean => {
    const text = unwrap(expr)
    const offset = at + expr.indexOf(text)
    const name = /^[A-Za-z_$][\w$]*$/.exec(text)?.[0]
    const definition = name ? definitions.get(name) : undefined
    if (definition && depth < 2) return allFix(definition.expr, definition.at, depth + 1)
    let cursor = offset
    return splitTopLevelOperator(text, '&&').some(atom => { const atomAt = code.indexOf(atom, cursor); cursor = atomAt + atom.length; return fixesHost(atom, atomAt) })
  }
  const allFix = (expr: string, at: number, depth = 0): boolean => {
    let cursor = at
    return splitTopLevelOperator(unwrap(expr), '||').every(branch => { const branchAt = code.indexOf(branch, cursor); cursor = branchAt + branch.length; return branchFixes(branch, branchAt, depth) })
  }
  for (const m of region.matchAll(/\bif\s*\(/g)) {
    const open = bodyStart + m.index + m[0].length - 1
    const close = pairs.get(open)
    if (close === undefined || close >= callAt) continue
    // 退出语句：return 或 throw，可包在花括号中。
    if (!/^\s*(?:\{\s*)?(?:return|throw)\b/.test(code.slice(close + 1, callAt))) continue
    // 位于请求之前已结束的嵌套块中的检查不一定执行。
    let nested = false
    for (const [blockOpen, blockClose] of pairs) {
      if (code[blockOpen] === '{' && blockOpen > bodyStart && blockOpen < m.index + bodyStart && blockClose > m.index + bodyStart && blockClose < callAt) { nested = true; break }
    }
    if (nested) continue
    // 继续执行的条件是退出条件的否定：!A && !B → A || B；!(E) → E；x !== 'lit' → x === 'lit'。
    const condition = unwrap(code.slice(open + 1, close))
    const conditionAt = open + 1 + code.slice(open + 1, close).indexOf(condition)
    if (condition.startsWith('!(') && matchingParen(condition, 1) === condition.length - 1) {
      if (allFix(condition.slice(2, -1), conditionAt + 2)) return true
      continue
    }
    let cursor = conditionAt
    const terms = splitTopLevelOperator(condition, '&&').map(term => { const termAt = code.indexOf(term, cursor); cursor = termAt + term.length; return { term, at: termAt } })
    const continues = terms.map(({ term, at }) => {
      if (term.startsWith('!') && !term.startsWith('!=')) return branchFixes(term.slice(1), at + 1)
      return /!==?/.test(term) && fixesHost(term, at, true)
    })
    if (continues.length > 0 && continues.every(Boolean)) return true
  }
  return false
}

function capitalised(text: string): string {
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}`
}

function ssrfFinding(route: Route, file: ScanFile, line: number, originLine: number): Finding {
  return {
    ruleId: 'ssrf/request-url', severity: 'P1', confidence: 'likely',
    title: `${capitalised(route.url)} sends a server request to an address the caller chooses`,
    file: file.path, line, excerpt: (file.lines[line - 1] ?? '').trim(),
    why: [
      `The address of this outgoing request comes from request input (read on line ${originLine}). A caller can point ` +
        `your server at internal services, cloud metadata endpoints such as 169.254.169.254, or other hosts only your ` +
        `server can reach, and read the response or trigger actions there.`,
      'Fetching a caller-supplied address can be the purpose of the route, as in a link preview or image proxy, so this ' +
        'is reported for review. Even then it needs a host allowlist.',
    ],
    fix: [
      'Build the address from a fixed origin in code and let the request choose only a path segment or query value.',
      'If callers must supply full URLs, parse them with new URL(), allow only https and hosts on an explicit allowlist, ' +
        'and reject private, loopback, and link-local addresses after DNS resolution.',
    ],
  }
}

function redirectFinding(route: Route, file: ScanFile, line: number, originLine: number, certain: boolean): Finding {
  return {
    ruleId: 'redirect/open', severity: 'P2', confidence: certain ? 'certain' : 'likely',
    title: `${capitalised(route.url)} redirects to an address taken from the request`,
    file: file.path, line, excerpt: (file.lines[line - 1] ?? '').trim(),
    why: [
      `The redirect target comes from request input (read on line ${originLine}), and nothing fixes the site it points to. ` +
        `A link to your site can then send visitors anywhere, which makes phishing links look trustworthy and can hand ` +
        `tokens in the URL to another site.`,
      ...(certain ? [] : ['The value passes through other code or a check first; confirm that check rejects other sites, including //host and /\\host forms.']),
    ],
    fix: [
      'Accept only relative paths that start with a single / (reject //, /\\, and anything with a scheme), or compare the target against a fixed list.',
      'When building an absolute URL, use new URL(path, yourOrigin) and redirect only if the result\'s origin equals yourOrigin.',
    ],
  }
}

/** 两条规则共用一次处理函数分析，各自只输出自己的结果。 */
function check(ctx: ScanContext, kind: Kind): Finding[] {
  const findings: Finding[] = []
  for (const file of ctx.files) {
    const analysed = handlerFileOf(file, ctx.files)
    if (!analysed) continue
    const calls = callsIn(analysed.code, analysed.pairs).filter(call => call.kind === kind).sort((a, b) => a.at - b.at)
    if (calls.length === 0) continue
    const positions = calls.map(call => call.at)
    const reported = new Set<number>()
    for (const { route, body, flow } of analysed.handlersAround(positions)) {
      // Server Function 只能由页面脚本以 POST 调用并受 Origin 校验，链接无法替他人触发其中的跳转。
      if (kind === 'redirect' && route.action !== undefined) continue
      // 只看落在该函数内的调用。
      for (let i = lowerBound(positions, body.start + 1); i < calls.length && calls[i]!.at < body.end; i++) {
        const call = calls[i]!
        if (call.close >= body.end || reported.has(call.at)) continue
        const target = targetOf(call, analysed)
        if (!target) continue
        const taint = controlsStart(target.expr, target.at, flow, analysed.source, kind)
        if (!taint) continue
        if (kind === 'ssrf' && allowlistedHost(analysed, body.start, call.at, target.expr, taint.names)) continue
        reported.add(call.at)
        const line = lineNumberAt(analysed.lineStarts, call.at)
        const originLine = lineNumberAt(analysed.lineStarts, taint.origin)
        findings.push(kind === 'ssrf'
          ? ssrfFinding(route, file, line, originLine)
          : redirectFinding(route, file, line, originLine, taint.level === 'direct' && !flow.validatedBefore(taint.names, call.at)))
      }
    }
    reportInputLimit(ctx, file, analysed)
  }
  return findings
}

export const ssrfRule: ProjectRule = { id: 'ssrf/request-url', severity: 'P1', check: ctx => check(ctx, 'ssrf') }
export const redirectRule: ProjectRule = { id: 'redirect/open', severity: 'P2', check: ctx => check(ctx, 'redirect') }
