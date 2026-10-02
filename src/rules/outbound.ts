/**
 * 请求输入决定服务器外发请求的目标（SSRF）或跳转目标（开放重定向）。
 * 只看输入能否决定目标地址的开头：固定站点后只拼接路径或查询参数的不报告，请求自身的 URL 也不算输入。
 */
import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { lineNumberAt } from './offsets.js'
import { argumentExpressions } from './auth-values.js'
import type { Route } from './apiauth.js'
import { handlerFileOf, lowerBound, reportInputLimit, type HandlerFile, type InputFlow, type Taint } from './request-input.js'

/** 服务端 HTTP 客户端：fetch、Nuxt 的 $fetch/ofetch、axios、got、ky、needle 及 Node http(s)。 */
const FETCH_CALL = /(?<![\w$.])(?:fetch|\$fetch|ofetch|axios|got|ky|needle)\s*(?:<[^()]{0,200}>\s*)?\(/g
const FETCH_METHOD = /(?<![\w$.])(?:axios|got|ky|needle|http|https|undici)\s*\.\s*(?:get|post|put|patch|delete|head|request|stream)\s*(?:<[^()]{0,200}>\s*)?\(/g

/** 跳转接口：Next.js/Remix/SvelteKit 的 redirect、Response.redirect、res.redirect 与 h3 的 sendRedirect。 */
const REDIRECT_CALL = /(?<![\w$.])(?:redirect|permanentRedirect|sendRedirect)\s*\(|(?<![\w$.])(?:NextResponse|Response|res|reply|response|ctx|context|Astro)\s*\.\s*redirect\s*\(/g

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

/** 判断表达式开头是否由请求输入决定；返回决定开头的输入。 */
function controlsStart(expr: string, at: number, flow: InputFlow, source: string, kind: Kind, depth = 0): Taint | null {
  const lead = expr.length - expr.trimStart().length
  const text = expr.trim()
  const start = at + lead
  if (text === '') return null
  if (depth >= 8) { flow.limited = true; return null }
  if (text.length > 4000) { flow.limited = true; return null }
  const open = (prefix: string): boolean => HOST_OPEN.test(prefix) || (kind === 'redirect' && REDIRECT_OPEN.test(prefix))

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
  if (text.startsWith('\x60')) return templateStart(text, start, flow, source, open)

  const operands = flow.operandsOf(text, start)
  if (operands.length > 1) {
    let prefix = ''
    for (const operand of operands) {
      const inner = operand.text.trim()
      if (/^['"]/.test(inner)) { prefix += source.slice(operand.at + operand.text.indexOf(inner) + 1, operand.at + operand.text.indexOf(inner) + inner.length - 1); continue }
      const t = inner.startsWith('\x60')
        ? templateStart(inner, operand.at + operand.text.indexOf(inner), flow, source, open)
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
      const t = controlsStart(a.expr, a.exprAt, flow, source, kind, depth + 1)
      // 记下变量名，使用前对它的检查才能被识别。
      if (t) return { ...t, level: a.indirect ? 'derived' : t.level, names: new Set([...t.names, text]) }
    }
    return null
  }

  const t = flow.taintOf(text, start)
  return t && !t.ownUrl ? t : null
}

/** 模板：静态文本取原文，非输入插值记作 X，遇到第一个输入插值时按已有前缀判断。 */
function templateStart(text: string, start: number, flow: InputFlow, source: string, open: (prefix: string) => boolean): Taint | null {
  let prefix = ''
  for (let i = 1; i < text.length; i++) {
    if (text[i] === '\x60') return null
    if (text[i] === '$' && text[i + 1] === '{') {
      const close = matchingBrace(text, i + 1)
      if (close === null) return null
      const t = flow.taintOf(text.slice(i + 2, close), start + i + 2)
      if (t && !t.ownUrl) return open(prefix) ? t : null
      prefix += 'X'
      i = close
      continue
    }
    prefix += source[start + i]
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
    const analysed = handlerFileOf(file)
    if (!analysed) continue
    const calls = callsIn(analysed.code, analysed.pairs).filter(call => call.kind === kind).sort((a, b) => a.at - b.at)
    if (calls.length === 0) continue
    const positions = calls.map(call => call.at)
    const reported = new Set<number>()
    for (const { route, body, flow } of analysed.handlersAround(positions)) {
      // 只看落在该函数内的调用。
      for (let i = lowerBound(positions, body.start + 1); i < calls.length && calls[i]!.at < body.end; i++) {
        const call = calls[i]!
        if (call.close >= body.end || reported.has(call.at)) continue
        const target = targetOf(call, analysed)
        if (!target) continue
        const taint = controlsStart(target.expr, target.at, flow, analysed.source, kind)
        if (!taint) continue
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
