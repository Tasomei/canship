/** 检测携带凭据的跨域来源回显及通配符配置。 */

import type { Finding, Rule, ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'

/** 仅处理设置相关响应头或跨域选项的文件。 */
const CORS_MARKER = /Access-Control-Allow-Origin|\bcors\s*\(/i

/** 识别方法调用、对象属性和键值配置中的来源响应头。 */
const ACAO = /['"]Access-Control-Allow-Origin['"]\s*(?:,|:)\s*(?:value\s*:\s*)?/gi

/** 按括号和引号提取单个值，避免包含同行后续属性或调用。 */
function headerExpression(content: string, start: number): string {
  const closes: string[] = []
  let quote: string | null = null
  let end = start
  for (; end < content.length; end++) {
    const ch = content[end]!
    if (ch === '\n' || ch === '\r') break
    if (quote !== null) {
      if (ch === '\\') end++
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === '(') closes.push(')')
    else if (ch === '[') closes.push(']')
    else if (ch === '{') closes.push('}')
    else if (ch === ')' || ch === ']' || ch === '}') {
      if (closes.at(-1) !== ch) break
      closes.pop()
    } else if (closes.length === 0 && (ch === ',' || ch === ';')) break
  }
  return content.slice(start, end)
}

/** 保留固定来源及未知值，避免将其他配置的通配符与当前凭据配对。 */
const CORS_ORIGIN_OPTION = /\borigin\s*:\s*/gi

/** 识别通过回调无条件放行来源的配置。 */
const CORS_ORIGIN_PROPERTY_START =
  /\borigin\s*:\s*(?:async\s+)?(?:(function)\s*(?:[A-Za-z_$][\w$]*)?\s*)?\(/gi

/** 识别对象方法简写及返回类型。 */
const CORS_ORIGIN_METHOD_START = /\borigin\s*\(/gi

interface OriginCallback {
  index: number
  parametersStart: number
  parametersEnd: number
  params: string
  body: string
}

/** 参数类型可能含嵌套括号，需要成对解析。 */
function closingParameterList(source: string, open: number): number | null {
  let depth = 0
  let quote: string | null = null
  for (let i = open; i < source.length; i++) {
    const ch = source[i]!
    if (quote !== null) {
      if (ch === '\\') i++
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === '(') depth++
    else if (ch === ')') {
      depth--
      if (depth === 0) return i
    }
  }
  return null
}

/** 提取参数列表、返回类型及回调函数体。 */
function readOriginCallback(
  content: string,
  match: RegExpExecArray,
  kind: 'property' | 'method',
): OriginCallback | null {
  const open = match.index + match[0].lastIndexOf('(')
  const close = closingParameterList(content, open)
  if (close === null) return null

  const after = content.slice(close + 1, close + 241)
  const marker = /^\s*(?::\s*[^={\n]+)?\s*(=>|\{)/.exec(after)
  if (!marker) return null

  const token = marker[1]
  const namedFunction = kind === 'property' && match[1] === 'function'
  if (kind === 'method' && token !== '{') return null
  if (namedFunction && token !== '{') return null
  if (kind === 'property' && !namedFunction && token !== '=>') return null

  let bodyStart = close + 1 + marker[0].length
  if (token === '=>') {
    while (/\s/.test(content[bodyStart] ?? '')) bodyStart++
    if (content[bodyStart] === '{') bodyStart++
  }

  return {
    index: match.index,
    parametersStart: open + 1,
    parametersEnd: close,
    params: content.slice(open + 1, close),
    body: content.slice(bodyStart, bodyStart + 400),
  }
}

function originCallbacks(content: string): OriginCallback[] {
  const callbacks: OriginCallback[] = []
  for (const [pattern, kind] of [
    [CORS_ORIGIN_PROPERTY_START, 'property'],
    [CORS_ORIGIN_METHOD_START, 'method'],
  ] as const) {
    pattern.lastIndex = 0
    let match: RegExpExecArray | null
    while ((match = pattern.exec(content)) !== null) {
      const callback = readOriginCallback(content, match, kind)
      if (callback !== null) callbacks.push(callback)
    }
  }
  return callbacks
}

/** 回调放行来源的位置和类型。 */
interface CallbackAnswer {
  index: number
  kind: 'reflected' | 'wildcard'
}

/** 仅拆分顶层参数，保留类型和默认值中的逗号。 */
function splitParameters(params: string): string[] {
  const out: string[] = []
  let start = 0
  let round = 0
  let square = 0
  let curly = 0
  let quote: string | null = null
  for (let i = 0; i < params.length; i++) {
    const ch = params[i]!
    if (quote !== null) {
      if (ch === '\\') i++
      else if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"' || ch === '`') quote = ch
    else if (ch === '(') round++
    else if (ch === ')') round--
    else if (ch === '[') square++
    else if (ch === ']') square--
    else if (ch === '{') curly++
    else if (ch === '}') curly--
    else if (ch === ',' && round === 0 && square === 0 && curly === 0) {
      out.push(params.slice(start, i).trim())
      start = i + 1
    }
  }
  out.push(params.slice(start).trim())
  return out
}

function parameterName(param: string | undefined): string | null {
  return /^([A-Za-z_$][\w$]*)/.exec(param ?? '')?.[1] ?? null
}

/** 回调返回真值或原始来源表示无条件回显。 */
function callbackAnswer(params: string, body: string): CallbackAnswer | null {
  const parsed = splitParameters(params)
  const originName = parameterName(parsed[0])
  const callbackNames = new Set(
    [parameterName(parsed[1]), 'cb', 'callback', 'done', 'next'].filter(
      (name): name is string => name !== null,
    ),
  )
  const answers: CallbackAnswer[] = []

  for (const name of callbackNames) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const call = new RegExp(
      `\\b${escaped}\\s*\\(\\s*null\\s*,\\s*(true|[A-Za-z_$][\\w$]*|'\\*'|\"\\*\"|\\x60\\*\\x60)\\s*\\)`,
      'i',
    )
    const match = call.exec(body)
    if (!match) continue
    const value = match[1] ?? ''
    if (/^['"`]\*['"`]$/.test(value)) {
      answers.push({ index: match.index, kind: 'wildcard' })
    } else if (/^true$/i.test(value) || (originName !== null && value === originName)) {
      answers.push({ index: match.index, kind: 'reflected' })
    }
  }

  return answers.sort((a, b) => a.index - b.index)[0] ?? null
}

/** 识别来源判断或允许列表校验的语法信号。 */
const ORIGIN_IS_CHECKED =
  /\bincludes\s*\(|\bindexOf\s*\(|===|!==|==|!=|\.test\s*\(|\.some\s*\(|\bstartsWith\s*\(|\.match\s*\(|\.has\s*\(|\bif\b|\?|\ballow(?:ed|list)?\b|\bwhitelist\b/i

/** 仅识别服务端凭据配置，不混淆客户端请求选项。 */
const ACAC_HEADER = /['"]Access-Control-Allow-Credentials['"][\s\S]{0,40}?\btrue\b/gi
const CORS_CREDENTIALS_OPTION = /\bcredentials\s*:\s*true\b/g

type OriginKind = 'wildcard' | 'literal' | 'reflected' | 'unknown'

/** 分类来源表达式；无法确认时保留未知状态。 */
function classifyOrigin(raw: string): OriginKind {
  // 仅移除外围结尾标点，保留表达式结构。
  let v = raw.trim().replace(/[\s;,)}\]!]+$/, '')

  // 截取完整字符串值，避免包含同行后续配置。
  const opening = v[0]
  if (opening === '"' || opening === "'" || opening === '`') {
    const close = v.indexOf(opening, 1)
    if (close !== -1) v = v.slice(0, close + 1)
  }
  if (/^['"`]\*['"`]$/.test(v)) return 'wildcard'

  // 单一模板插值等同于其内部表达式。
  const soleInterpolation = /^`\$\{([^}]*)\}`$/.exec(v)
  if (soleInterpolation) {
    v = soleInterpolation[1]!.trim()
  } else if (/^['"`]/.test(v)) {
    // 固定来源字符串按字面量处理。
    return 'literal'
  }
  // 回退表达式仍可能优先回显调用者来源。
  const branches = v.split(/\|\||\?\?/).map((part) => part.trim()).filter(Boolean)
  if (branches.length > 1) {
    const kinds = branches.map(classifyOrigin)
    if (kinds.includes('reflected')) return 'reflected'
    if (kinds.includes('wildcard')) return 'wildcard'
    return 'unknown'
  }

  if (/process\.env|import\.meta\.env/.test(v)) return 'literal'

  // 统一常见框架的属性和请求头访问形式。
  const compact = v.replace(/[\s'"`()[\]]/g, '')
  // 非简单来源访问可能包含允许列表判断，保守处理。
  if (!/^[\w.$]*origin$/i.test(compact)) return 'unknown'
  if (/^origin$/i.test(compact)) return 'reflected'
  return /\b(?:req|request|headers?|ctx|event)/i.test(compact) ? 'reflected' : 'unknown'
}

/** 来源与凭据配置的最大配对行距。 */
const PAIRING_DISTANCE = 25

interface OriginMark {
  line: number
  at: number
  mode: 'header' | 'option'
  kind: OriginKind
  excerpt: string
}

interface CredentialMark {
  line: number
  at: number
  mode: 'header' | 'option'
}

/** 对象选项仅在同一花括号作用域配对；单次遍历处理全部标记。 */
function optionScopes(file: ScanFile, positions: number[]): Map<number, number> {
  const scopes = new Map<number, number>()
  const wanted = [...new Set(positions)].sort((a, b) => a - b)
  if (wanted.length === 0) return scopes
  const content = noiseMaskedOf(file)
  const stack: number[] = [-1]
  let next = 0
  for (let at = 0; at < content.length && next < wanted.length; at++) {
    if (at === wanted[next]) {
      scopes.set(at, stack[stack.length - 1]!)
      next++
    }
    if (content[at] === '{') stack.push(at)
    else if (content[at] === '}' && stack.length > 1) stack.pop()
  }
  return scopes
}

function collectOrigins(file: ScanFile): OriginMark[] {
  const marks: OriginMark[] = []
  let m: RegExpExecArray | null
  // 保留字符串并屏蔽注释，避免注释覆盖真实配置。
  const content = commentsMaskedOf(file)
  // 每个文件只构建一次行号索引。
  const contentLines = lineStartsOf(content)
  const code = noiseMaskedOf(file)
  const callbacks = originCallbacks(content).filter(callback => code[callback.index] === content[callback.index])
  const callbackIndices = new Set(callbacks.map(callback => callback.index))
  const parameterRanges = [...callbacks].sort((a, b) => a.parametersStart - b.parametersStart)
  let parameterRange = 0

  ACAO.lastIndex = 0
  while ((m = ACAO.exec(content)) !== null) {
    // 真实属性引号会保留；示例字符串内部的响应头字样已被屏蔽。
    if (code[m.index] !== content[m.index]) continue
    const line = lineNumberAt(contentLines, m.index)
    const expression = headerExpression(content, ACAO.lastIndex)
    // 不重复遍历表达式内部的响应头字样，保持单次线性读取。
    ACAO.lastIndex += expression.length
    marks.push({ line, at: m.index, mode: 'header', kind: classifyOrigin(expression), excerpt: (file.lines[line - 1] ?? '').trim() })
  }

  CORS_ORIGIN_OPTION.lastIndex = 0
  while ((m = CORS_ORIGIN_OPTION.exec(content)) !== null) {
    if (code[m.index] !== content[m.index]) continue
    // 回调参数的类型注解不是配置属性，例如 origin: string。
    while (parameterRange < parameterRanges.length && parameterRanges[parameterRange]!.parametersEnd < m.index) parameterRange++
    if (parameterRanges[parameterRange] && parameterRanges[parameterRange]!.parametersStart <= m.index) continue
    // 回调属性由下方的参数及函数体分析统一处理。
    if (callbackIndices.has(m.index)) continue
    const line = lineNumberAt(contentLines, m.index)
    const expression = headerExpression(content, CORS_ORIGIN_OPTION.lastIndex)
    CORS_ORIGIN_OPTION.lastIndex += expression.length
    marks.push({
      line,
      at: m.index,
      mode: 'option',
      kind: expression.trim() === 'true' ? 'reflected' : classifyOrigin(expression),
      excerpt: (file.lines[line - 1] ?? '').trim(),
    })
  }

  for (const callback of callbacks) {
    const answer = callbackAnswer(callback.params, callback.body)
    // 受控或未知回调仍占据当前来源位置，不能由其他配置代替。
    const kind = answer !== null && !ORIGIN_IS_CHECKED.test(callback.body.slice(0, answer.index))
      ? answer.kind : 'unknown'
    const line = lineNumberAt(contentLines, callback.index)
    marks.push({ line, at: callback.index, mode: 'option', kind, excerpt: (file.lines[line - 1] ?? '').trim() })
  }

  return marks
}

function collectCredentialLines(file: ScanFile): CredentialMark[] {
  const lines: CredentialMark[] = []
  let m: RegExpExecArray | null
  const content = commentsMaskedOf(file)
  const code = noiseMaskedOf(file)
  // 每个文件只构建一次行号索引。
  const contentLines = lineStartsOf(content)

  ACAC_HEADER.lastIndex = 0
  while ((m = ACAC_HEADER.exec(content)) !== null) {
    if (code[m.index] === content[m.index]) lines.push({ line: lineNumberAt(contentLines, m.index), at: m.index, mode: 'header' })
  }

  CORS_CREDENTIALS_OPTION.lastIndex = 0
  while ((m = CORS_CREDENTIALS_OPTION.exec(content)) !== null) {
    if (code[m.index] === content[m.index]) lines.push({ line: lineNumberAt(contentLines, m.index), at: m.index, mode: 'option' })
  }

  return lines
}

/** 将凭据配置与最近的来源声明配对。 */
function nearestOrigin(origins: OriginMark[], credLine: number): OriginMark | null {
  let best = Infinity
  let closest: OriginMark[] = []
  for (const o of origins) {
    const d = Math.abs(o.line - credLine)
    if (d < best) {
      best = d
      closest = [o]
    } else if (d === best) {
      closest.push(o)
    }
  }
  if (best > PAIRING_DISTANCE || closest.length === 0) return null
  const kinds = new Set(closest.map((o) => o.kind))
  return kinds.size === 1 ? closest[0]! : null
}

export const corsRule: Rule = {
  id: 'cors/credentialed-cross-origin',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    // 示例上下文由引擎统一降低置信度。
    return CORS_MARKER.test(file.content)
  },

  check(file: ScanFile): Finding[] {
    const credentialLines = collectCredentialLines(file)
    if (credentialLines.length === 0) return []

    const origins = collectOrigins(file)
    if (origins.length === 0) return []
    const scopes = optionScopes(file, [...origins, ...credentialLines]
      .filter(mark => mark.mode === 'option').map(mark => mark.at))

    const findings: Finding[] = []
    // 每类配置问题在同一文件中只报告一次。
    const reported = new Set<OriginKind>()

    for (const credential of credentialLines) {
      const candidates = origins.filter(origin => origin.mode === credential.mode &&
        (credential.mode === 'header' || scopes.get(origin.at) === scopes.get(credential.at)))
      const origin = nearestOrigin(candidates, credential.line)
      if (!origin) continue
      if (origin.kind !== 'reflected' && origin.kind !== 'wildcard') continue
      if (reported.has(origin.kind)) continue
      reported.add(origin.kind)

      if (origin.kind === 'reflected') {
        findings.push({
          ruleId: 'cors/reflected-origin-with-credentials',
          severity: 'P1',
          // 明确的来源回显和凭据配置使用确定置信度。
          confidence: 'certain',
          title: 'Any website can make signed-in requests to your API and read the answer',
          file: file.path,
          line: origin.line,
          excerpt: origin.excerpt,
          why: [
            `Your API sends back whatever origin the caller claims to be, and allows credentials at the ` +
              `same time. Together those two say: "every website is trusted, and yes, send the user's ` +
              `session along".`,
            `So a page on any other domain can run a request to your API in a logged-in visitor's browser, ` +
              `have the browser attach their session, and read the response. Their data, from a site you do ` +
              `not control.`,
            `This bites when the session travels automatically — a cookie set with SameSite=None, which is ` +
              `exactly what cross-origin auth requires, or HTTP basic auth. If your API only ever authenticates ` +
              `with an Authorization header the page has to set itself, the browser will not attach it for the ` +
              `attacker and this is far less serious. It is still not a configuration to keep.`,
          ],
          fix: [
            `Keep an explicit list of the origins you actually serve, and compare the incoming Origin against it with === before echoing anything back.`,
            `Never write the request's Origin into the response header unconditionally. That is what makes every site an allowed site.`,
            `If you are using the cors package, replace origin: true with the array of your real origins — cors accepts one directly.`,
            `Where you can, set your session cookies to SameSite=Lax. The browser then refuses to send them on cross-site requests at all, whatever CORS says.`,
          ],
        })
      } else {
        findings.push({
          ruleId: 'cors/wildcard-with-credentials',
          severity: 'P2',
          // 通配符与凭据组合违反浏览器跨域约束。
          confidence: 'certain',
          title: 'This CORS setup is rejected by every browser, so the requests it enables never work',
          file: file.path,
          line: origin.line,
          excerpt: origin.excerpt,
          why: [
            `Allowing every origin with "*" and allowing credentials at the same time is forbidden by the ` +
              `CORS specification. Browsers do not pick one — they reject the response outright.`,
            `So the cross-origin calls this was meant to enable fail, and they fail in the browser console ` +
              `rather than anywhere you would see in a server log.`,
            `The reason this is worth fixing carefully: the change people reach for next is to echo the ` +
              `caller's Origin header back, which makes the error go away and hands every website on the ` +
              `internet permission to use your users' sessions.`,
          ],
          fix: [
            `Name the origins you actually serve, and send back the one that matches: keep them in an array and compare with === before setting the header.`,
            `If the endpoint is genuinely public and needs no session, drop Access-Control-Allow-Credentials instead and keep the wildcard. That combination is valid.`,
            `Do not "fix" this by returning the request's Origin header unchanged — that allows every site, including the one attacking you.`,
          ],
        })
      }
    }

    return findings
  },
}
