/**
 * Stripe webhook 路由处理事件却不验证签名。不验证时任何人都能伪造事件，触发发货、开通权限或修改记录。
 * 来源：https://docs.stripe.com/webhooks （Verify events are sent from Stripe）
 */
import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { commentsMaskedOf } from '../mask.js'
import { maskUnusedFunctions } from './apiauth.js'
import type { MiddlewareRef, Route } from './apiauth.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { NODE_FRAMEWORKS, calleeDefinition, middlewareDefinition, serverRoutesOf } from './routers.js'
import { LocalVerification, enforcedVerification } from './verification.js'

/** 按事件类型分支：case 'checkout.session.completed' 或 event.type === 'invoice.paid'。 */
const STRIPE_EVENT = /(?:\bcase\s*|\.type\s*[!=]==?\s*)['"`]((?:checkout\.session|payment_intent|customer\.subscription|customer|invoice|charge|setup_intent|payment_method|subscription_schedule|account|payout|refund|checkout)\.[a-z_.]+)['"`]|['"`]((?:checkout\.session|payment_intent|customer\.subscription|invoice|charge)\.[a-z_.]+)['"`]\s*[!=]==?\s*[\w$.]+\.type\b/

/** 事件须来自验证调用的返回值，异步接口必须等待；不接受未使用的调用。 */
function verifiedEvent(context: LocalVerification, name: string, at: number): boolean {
  const assignment = context.assignment(name, at)
  if (!assignment || assignment.member || !context.enforcedBefore(assignment.at, at)) return false
  // 接收方可以是工厂函数或方法的返回值，如 getStripe().webhooks、this.stripe.webhooks。
  const call = /^(?:(await)\s+)?(?:[\w$]+(?:\s*\([^()]*\))?\s*\??\.\s*)+(constructEvent(?:Async)?|retrieve|parseEventNotification)\s*\(/.exec(assignment.expression)
  if (!call || (call[2] !== 'constructEvent' && !call[1])) return false
  if (call[2] === 'retrieve' && !/\.events\s*\.\s*retrieve/.test(call[0])) return false
  const close = context.pairs.get(assignment.from + call[0].length - 1)
  return close !== undefined && context.code.slice(close + 1, assignment.end).trim() === ''
}

/** 分支对应的事件变量；case 仅使用包围该分支的 switch。 */
function eventName(context: LocalVerification, event: RegExpExecArray): string | null {
  if (event[0].startsWith('.')) return /([A-Za-z_$][\w$]*)\s*$/.exec(context.code.slice(0, event.index))?.[1] ?? null
  if (!event[0].startsWith('case')) return /([A-Za-z_$][\w$]*)\.type\b/.exec(event[0])?.[1] ?? null
  let name: string | null = null
  for (const m of context.code.slice(0, event.index).matchAll(/\bswitch\s*\(\s*([A-Za-z_$][\w$]*)\.type\s*\)\s*\{/g)) {
    const end = context.pairs.get(m.index + m[0].length - 1)
    if (end !== undefined && end > event.index && context.owner(m.index) === context.owner(event.index)) name = m[1]!
  }
  return name
}

/** 读取请求体：请求对象上的 json()/text() 等（含 Hono 的 c.req），不含 c.json()、res.json() 之类的响应。 */
const READS_BODY = /(?<![\w$])(?:req|request)\s*(?:\.\s*raw\s*)?\.\s*(?:json|text|arrayBuffer|formData|parseBody)\s*\(|\breq(?:uest)?\s*\.\s*body\b|\b(?:readBody|readRawBody)\s*\(|\bbuffer\s*\(\s*req\b/

/** 读取 Stripe 签名头；只读取不等于验证。 */
const SIGNATURE_HEADER = /['"]stripe-signature['"]/i

/**
 * 中间件中的验签：真正执行的 constructEvent（同步，失败抛出）或 await 的 constructEventAsync，
 * 且没有吞掉失败后继续放行的 catch（catch 中调用无参数的 next()）。
 */
function middlewareVerifies(code: string): boolean {
  const masked = maskUnusedFunctions(code)
  const verifies = enforcedVerification(masked, /\bconstructEvent(?:Async)?\s*\(/, /^constructEvent\s*\(/)
  if (!verifies) return false
  for (const m of masked.matchAll(/\bcatch\s*(?:\([^()]*\))?\s*\{/g)) {
    const open = m.index + m[0].length - 1
    let close = open
    for (let depth = 0; close < masked.length; close++) {
      if (masked[close] === '{') depth++
      else if (masked[close] === '}' && --depth === 0) break
    }
    const body = masked.slice(open, close)
    if (/\bnext\s*\(\s*\)/.test(body)) return false
  }
  return true
}

/**
 * Express/Hono/Fastify 路由经过的中间件中有验签中间件：事件由它验证后放入上下文。
 * 只读取签名头、交给无法确认的函数时返回 custom，结果保留待复核。
 */
function verifiedByMiddleware(route: Route, files: ScanFile[]): 'verified' | 'custom' | null {
  if (!NODE_FRAMEWORKS.has(route.framework)) return null
  const codeOf = (ref: MiddlewareRef): { file: ScanFile; code: string } | null => {
    const { inline, range } = middlewareDefinition(ref, files)
    const target = inline ?? range
    return target === null ? null : { file: target.file, code: commentsMaskedOf(target.file).slice(target.start, target.end + 1) }
  }
  // 中间件把签名交给项目函数解析（await parseStripeEvent(body, signature)）：被调函数中验签同样算数，只跟进一层。
  const verifies = ({ file, code }: { file: ScanFile; code: string }): boolean => {
    if (middlewareVerifies(code)) return true
    const masked = maskUnusedFunctions(code)
    const calls = [...masked.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\.\s*([A-Za-z_$][\w$]*)\s*)?\(/g)].slice(0, 16)
    return calls.some(m => {
      const call = new RegExp(`(?<![\\w$.])${m[1]!.replace(/\$/g, '\\$')}${m[2] ? `\\s*\\.\\s*${m[2].replace(/\$/g, '\\$')}` : ''}\\s*\\(`)
      if (!enforcedVerification(masked, call)) return false
      const definition = calleeDefinition(file, m[1]!, m[2] ?? null, files)
      return definition !== null && middlewareVerifies(commentsMaskedOf(definition.file).slice(definition.start, definition.end + 1))
    })
  }
  const status = (test: (target: { file: ScanFile; code: string }) => boolean): boolean => {
    const check = (ref: MiddlewareRef): boolean => { const target = codeOf(ref); return target !== null && test(target) }
    const mounts = route.mounts ?? []
    return (route.middleware ?? []).some(check) || (mounts.length > 0 && mounts.every(refs => refs.some(check)))
  }
  if (status(verifies)) return 'verified'
  return status(({ code }) => SIGNATURE_HEADER.test(code)) ? 'custom' : null
}

export const webhookRule: Rule = {
  id: 'webhook/unverified-signature',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    return /stripe/i.test(file.content)
  },

  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const routes = serverRoutesOf(file, ctx.files)
    if (routes.length === 0) return []
    // 一个文件可有多条 Express 路由：取包含该事件分支的那一条。
    const routeAt = (at: number) => routes.find(r => !r.reachable || (r.reachable.start <= at && at <= r.reachable.end))
    const context = new LocalVerification(file)
    const { source, code } = context
    const findings: Finding[] = []
    const reported = new Set<number>()
    for (const event of source.matchAll(new RegExp(STRIPE_EVENT.source, 'g'))) {
      if (code[event.index] !== source[event.index]) continue
      const route = routeAt(event.index)
      if (!route) continue
      const middleware = verifiedByMiddleware(route, ctx.files)
      if (middleware === 'verified') continue
      const owner = context.owner(event.index)
      const name = eventName(context, event)
      if (name && verifiedEvent(context, name, event.index)) continue
      const key = owner?.start ?? 0
      if (reported.has(key)) continue
      reported.add(key)
      const line = lineNumberAt(lineStartsOf(file.content), event.index)
      const region = code.slice(owner?.start ?? 0, owner?.end ?? code.length)
      const readsBody = READS_BODY.test(region)
      // 中间件读取了签名头但看不到可确认的验签调用时，按自定义校验保留待复核。
      const customCheck = middleware === 'custom' || /\bverifyHeader\s*\(/.test(region) ||
        (/\bcreateHmac\s*\(/.test(region) && /\btimingSafeEqual\s*\(/.test(region))
      findings.push({
        ruleId: 'webhook/unverified-signature', severity: 'P1', confidence: readsBody && !customCheck ? 'certain' : 'likely',
        title: customCheck ? `Review custom Stripe signature verification in ${route.url}`
          : `${route.url} acts on Stripe events without verifying the signature`,
        file: file.path, line, excerpt: (file.lines[line - 1] ?? '').trim(),
        why: [
          `This route handles ${event[1] ?? event[2]} and similar events, but the scan could not link this event to a signature-verification result. ` +
            'Without effective verification, callers can submit made-up events and trigger the handler.',
          ...(customCheck ? ['A custom signature check is present; confirm it checks the raw body and rejects invalid signatures before processing this event.'] : []),
          ...(readsBody ? [] : ['The event does not appear to come from the request body here; confirm where it is read and whether it is verified there.']),
        ],
        fix: [
          'Read the raw body (await request.text() in a route handler) and pass it to stripe.webhooks.constructEvent(body, ' +
            "request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET) before handling the event. Return 400 when it throws.",
          'Do not parse the body as JSON before verifying; any change to the raw body makes verification fail.',
        ],
      })
    }
    return findings
  },
}
