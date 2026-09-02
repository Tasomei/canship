/**
 * P1/P2: CORS configured so that other websites can use your users' sessions.
 *
 * The dangerous pattern is not the wildcard. `Access-Control-Allow-Origin: *`
 * on a public API is completely normal, and flagging it would be pure noise.
 * What matters is what the origin is paired with:
 *
 *   reflected origin + credentials  ->  any site can make signed-in requests
 *                                       to your API and read the response
 *   wildcard origin  + credentials  ->  rejected by every browser; the calls
 *                                       you meant to enable silently fail
 *
 * The second is not a vulnerability, it is a bug — but it is worth reporting,
 * because the usual next step when someone debugs it is to echo the Origin
 * header back, which turns the broken config into the open one.
 *
 * Reflection is the hard thing to detect without false positives, because an
 * allowlist check reads the Origin header too. The difference is that a safe
 * implementation does something with the value — compares it, looks it up —
 * while an unsafe one hands it straight back. So the value expression has to be
 * a *bare* read of the request's Origin, with no conditional anywhere in it.
 */

import type { Finding, Rule, ScanFile } from '../types.js'
import { commentsMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'

/** Files worth looking at: they either set the header or configure a cors() middleware */
const CORS_MARKER = /Access-Control-Allow-Origin|\bcors\s*\(/i

/**
 * The response header, in both shapes it is written:
 *   setHeader('Access-Control-Allow-Origin', value)
 *   { 'Access-Control-Allow-Origin': value }
 * and the key/value form Next.js uses in next.config.js headers().
 */
/**
 * The value is captured to the end of the line, not to the first closing
 * bracket.
 *
 * Stopping at `)` looked tidier and quietly broke the most important
 * distinction this rule makes. Given
 *
 *   ALLOWED.includes(req.headers.origin) ? req.headers.origin : ALLOWED[0]
 *
 * the short capture ended at `includes(req.headers.origin`, which reads as a
 * bare property path ending in `origin` — so a textbook allowlist was reported
 * as reflection. classifyOrigin can only tell a decision from an echo if it is
 * shown the whole expression.
 */
const ACAO = /['"]Access-Control-Allow-Origin['"]\s*(?:,|:)\s*(?:value\s*:\s*)?([^\n]+)/gi

/**
 * The `cors` package's option for "reflect whatever origin asked". Same
 * meaning as echoing the header back by hand, and far more common, because it
 * is one word.
 */
const CORS_ORIGIN_OPTION = /\borigin\s*:\s*(true|['"`]\*['"`])/gi

/**
 * The same decision written as a function.
 *
 * `origin: (_origin, callback) => callback(null, true)` is `origin: true` with
 * extra steps — it is what people write when they reach for the callback form
 * and then never use the argument. Only the one-word spelling was recognised,
 * so this one scanned clean.
 *
 * The window is bounded rather than brace-matched: running off the end of the
 * function can only add text, and added text makes the allowlist test below
 * more likely to fire, which is the safe direction.
 */
const CORS_ORIGIN_PROPERTY_START =
  /\borigin\s*:\s*(?:async\s+)?(?:(function)\s*(?:[A-Za-z_$][\w$]*)?\s*)?\(/gi

/** The method-shorthand form: origin(origin, callback): void { ... } */
const CORS_ORIGIN_METHOD_START = /\borigin\s*\(/gi

interface OriginCallback {
  index: number
  params: string
  body: string
}

/** A parameter type may hold parentheses of its own, so the first `)` is not the end */
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

/** From the opening marker, read the whole parameter list, any return type, and the body */
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

/** Where and how a callback lets the caller's origin through unconditionally */
interface CallbackAnswer {
  index: number
  kind: 'reflected' | 'wildcard'
}

/** Top-level parameters, without splitting on a comma inside a type argument or a default */
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

/**
 * The answer the callback hands back to cors. Both `true` and the origin itself
 * are unconditional reflection; a star is the wildcard browsers reject.
 */
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

/**
 * Anything that reads like the function looking at the origin before answering.
 *
 * This is what separates the bug from the correct implementation, and the
 * correct implementation is the common one:
 *
 *   (origin, cb) => ALLOWED.includes(origin) ? cb(null, true) : cb(new Error())
 *
 * Only the text *before* the callback is tested, because that is where a check
 * has to be. A generous list here means the rule stays quiet when it is unsure,
 * which is the trade this whole file is built on.
 */
const ORIGIN_IS_CHECKED =
  /\bincludes\s*\(|\bindexOf\s*\(|===|!==|==|!=|\.test\s*\(|\.some\s*\(|\bstartsWith\s*\(|\.match\s*\(|\.has\s*\(|\bif\b|\?|\ballow(?:ed|list)?\b|\bwhitelist\b/i

/**
 * Credentials switched on, as a response header or as a cors() option.
 *
 * `\b` before "credentials" is doing real work: it stops this matching
 * axios's `withCredentials: true`, which is a *client* setting and says
 * nothing about what the server allows.
 */
const ACAC_HEADER = /['"]Access-Control-Allow-Credentials['"][\s\S]{0,40}?\btrue\b/gi
const CORS_CREDENTIALS_OPTION = /\bcredentials\s*:\s*true\b/g

type OriginKind = 'wildcard' | 'literal' | 'reflected' | 'unknown'

/**
 * Decide what an Access-Control-Allow-Origin value actually is.
 *
 * Only two verdicts lead to a finding, and everything ambiguous returns
 * `unknown` on purpose. The cases this deliberately lets through:
 *
 *   ALLOWED.includes(origin) ? origin : FALLBACK   an allowlist — correct
 *   process.env.APP_ORIGIN                          configured — correct
 *   allowedOrigin                                   a variable holding either
 */
function classifyOrigin(raw: string): OriginKind {
  // Trim the punctuation that closes the surrounding call or object literal.
  // Only trailing characters go, so `includes(x)` keeps its shape.
  // TypeScript's trailing `!` goes too — it asserts non-null and says nothing
  // about where the value came from.
  let v = raw.trim().replace(/[\s;,)}\]!]+$/, '')

  // Capturing to the end of the line is what lets a ternary stay legible, but
  // it also swallows whatever follows on the same line. When both headers are
  // written in one object literal, the origin's value ran on into the
  // credentials entry and stopped looking like "*" at all. A quoted value ends
  // at its closing quote and nowhere else.
  const opening = v[0]
  if (opening === '"' || opening === "'" || opening === '`') {
    const close = v.indexOf(opening, 1)
    if (close !== -1) v = v.slice(0, close + 1)
  }
  if (/^['"`]\*['"`]$/.test(v)) return 'wildcard'

  // A template literal that is nothing but one interpolation is the expression
  // it wraps: `${req.headers.origin}` reflects the caller exactly as surely as
  // req.headers.origin does. Treating every backtick as a literal made that
  // the one shape of reflection canship could not see.
  //
  // A template with text around the hole is different — `https://${sub}.app.com`
  // builds an origin rather than echoing one — so only the bare form unwraps.
  const soleInterpolation = /^`\$\{([^}]*)\}`$/.exec(v)
  if (soleInterpolation) {
    v = soleInterpolation[1]!.trim()
  } else if (/^['"`]/.test(v)) {
    // A quoted origin is the correct shape.
    return 'literal'
  }
  // An expression with alternatives is as dangerous as its first branch.
  //   req.headers.origin || process.env.APP_ORIGIN
  // reflects the caller whenever they send an Origin header, and falls back to
  // the configured value only when they do not — but seeing `process.env`
  // anywhere used to be enough to call the whole thing safe.
  const branches = v.split(/\|\||\?\?/).map((part) => part.trim()).filter(Boolean)
  if (branches.length > 1) {
    const kinds = branches.map(classifyOrigin)
    if (kinds.includes('reflected')) return 'reflected'
    if (kinds.includes('wildcard')) return 'wildcard'
    return 'unknown'
  }

  if (/process\.env|import\.meta\.env/.test(v)) return 'literal'

  // Strip the punctuation that only differs between frameworks, so
  // `req.headers.origin` and `request.headers.get('origin')` compare the same.
  const compact = v.replace(/[\s'"`()[\]]/g, '')
  // Anything left that is not a plain property path — a ternary, a comparison,
  // a function call with arguments — means the value is being decided, not
  // echoed. That is the allowlist case, and it is correct.
  if (!/^[\w.$]*origin$/i.test(compact)) return 'unknown'
  if (/^origin$/i.test(compact)) return 'reflected'
  return /\b(?:req|request|headers?|ctx|event)/i.test(compact) ? 'reflected' : 'unknown'
}

/**
 * How far apart the origin and the credentials setting may be and still count
 * as one configuration. A headers block or a cors() call fits comfortably
 * inside this; two unrelated handlers usually do not.
 */
const PAIRING_DISTANCE = 25

interface OriginMark {
  line: number
  kind: OriginKind
  excerpt: string
}

function collectOrigins(file: ScanFile): OriginMark[] {
  const marks: OriginMark[] = []
  let m: RegExpExecArray | null
  // Comments blanked, string contents kept — the header names and origins are
  // strings, so the full mask would erase what this rule reads. Without this,
  // a commented-out safe origin sitting next to a live reflected one won the
  // nearest-declaration pairing and silenced the finding.
  const content = commentsMaskedOf(file)
  // Built once per file rather than counted per match. See offsets.ts.
  const contentLines = lineStartsOf(content)

  ACAO.lastIndex = 0
  while ((m = ACAO.exec(content)) !== null) {
    const line = lineNumberAt(contentLines, m.index)
    marks.push({ line, kind: classifyOrigin(m[1] ?? ''), excerpt: (file.lines[line - 1] ?? '').trim() })
  }

  CORS_ORIGIN_OPTION.lastIndex = 0
  while ((m = CORS_ORIGIN_OPTION.exec(content)) !== null) {
    const line = lineNumberAt(contentLines, m.index)
    // origin: true means "reflect the caller's origin"; origin: '*' is the wildcard.
    marks.push({
      line,
      kind: (m[1] ?? '') === 'true' ? 'reflected' : 'wildcard',
      excerpt: (file.lines[line - 1] ?? '').trim(),
    })
  }

  for (const callback of originCallbacks(content)) {
    const answer = callbackAnswer(callback.params, callback.body)
    if (answer === null) continue
    // Unconditional only if nothing consulted an allowlist before answering.
    if (ORIGIN_IS_CHECKED.test(callback.body.slice(0, answer.index))) continue
    const line = lineNumberAt(contentLines, callback.index)
    marks.push({ line, kind: answer.kind, excerpt: (file.lines[line - 1] ?? '').trim() })
  }

  return marks
}

function collectCredentialLines(file: ScanFile): number[] {
  const lines: number[] = []
  let m: RegExpExecArray | null
  const content = commentsMaskedOf(file)
  // Built once per file rather than counted per match. See offsets.ts.
  const contentLines = lineStartsOf(content)

  ACAC_HEADER.lastIndex = 0
  while ((m = ACAC_HEADER.exec(content)) !== null) lines.push(lineNumberAt(contentLines, m.index))

  CORS_CREDENTIALS_OPTION.lastIndex = 0
  while ((m = CORS_CREDENTIALS_OPTION.exec(content)) !== null) lines.push(lineNumberAt(contentLines, m.index))

  return lines
}

/**
 * The origin declaration a credentials setting belongs to: the nearest one.
 *
 * Pairing a credentials setting with *any* nearby origin is wrong, and a real
 * next.config.js shows why — one entry serving a public route with "*", the
 * next serving an authenticated route with a named origin and credentials, six
 * lines apart. Those are two separate responses, and only the second one has
 * credentials. Taking the nearest declaration reads that correctly, and a safe
 * declaration standing between the two suppresses the finding rather than
 * being ignored.
 *
 * Returns null when the nearest is too far to be the same configuration, or
 * when two declarations are equally close and they disagree — an ambiguous
 * pairing is not evidence of anything.
 */
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
    // Held at lower confidence by the engine rather than skipped here.
    return CORS_MARKER.test(file.content)
  },

  check(file: ScanFile): Finding[] {
    const credentialLines = collectCredentialLines(file)
    if (credentialLines.length === 0) return []

    const origins = collectOrigins(file)
    if (origins.length === 0) return []

    const findings: Finding[] = []
    // One finding per kind: a file that gets this wrong gets it wrong the same
    // way everywhere, and the fix is to the pattern, not to a line.
    const reported = new Set<OriginKind>()

    for (const credLine of credentialLines) {
      const origin = nearestOrigin(origins, credLine)
      if (!origin) continue
      if (origin.kind !== 'reflected' && origin.kind !== 'wildcard') continue
      if (reported.has(origin.kind)) continue
      reported.add(origin.kind)

      if (origin.kind === 'reflected') {
        findings.push({
          ruleId: 'cors/reflected-origin-with-credentials',
          severity: 'P1',
          // Both halves are read straight out of the file: the origin is handed
          // back unchanged, and credentials are allowed. Nothing is inferred.
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
          // Not a judgement call: the specification forbids this pair, so every
          // browser rejects it.
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
