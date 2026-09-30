/**
 * Stripe webhook 路由处理事件却不验证签名。不验证时任何人都能伪造事件，触发发货、开通权限或修改记录。
 * 来源：https://docs.stripe.com/webhooks （Verify events are sent from Stripe）
 */
import type { Finding, Rule, ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { lineNumberAt, lineStartsOf } from './offsets.js'
import { routeOf } from './apiauth.js'

/** 按事件类型分支：case 'checkout.session.completed' 或 event.type === 'invoice.paid'。 */
const STRIPE_EVENT = /(?:\bcase\s*|\.type\s*[!=]==?\s*)['"`]((?:checkout\.session|payment_intent|customer\.subscription|customer|invoice|charge|setup_intent|payment_method|subscription_schedule|account|payout|refund|checkout)\.[a-z_.]+)['"`]|['"`]((?:checkout\.session|payment_intent|customer\.subscription|invoice|charge)\.[a-z_.]+)['"`]\s*[!=]==?\s*[\w$.]+\.type\b/

/** 官方库验证、按 id 回源读取事件，或手工 HMAC 校验签名头。 */
const VERIFIED = /\bconstructEvent(?:Async)?\s*\(|\.events\s*\.\s*retrieve\s*\(|\bparseEventNotification\s*\(|\bverifyHeader\s*\(/

const READS_BODY = /\.\s*(?:json|text|arrayBuffer|formData)\s*\(|\breq(?:uest)?\s*\.\s*body\b|\b(?:readBody|readRawBody)\s*\(|\bbuffer\s*\(\s*req\b/

export const webhookRule: Rule = {
  id: 'webhook/unverified-signature',
  severity: 'P1',

  appliesTo(file: ScanFile): boolean {
    return /stripe/i.test(file.content) && routeOf(file) !== null
  },

  check(file: ScanFile): Finding[] {
    const route = routeOf(file)
    if (!route) return []
    const source = commentsMaskedOf(file)
    const code = noiseMaskedOf(file)
    const event = STRIPE_EVENT.exec(source)
    if (!event) return []
    if (VERIFIED.test(code)) return []
    if (/\bcreateHmac\s*\(/.test(code) && /stripe-signature/i.test(source)) return []

    const line = lineNumberAt(lineStartsOf(file.content), event.index)
    const readsBody = READS_BODY.test(code)
    return [{
      ruleId: 'webhook/unverified-signature', severity: 'P1', confidence: readsBody ? 'certain' : 'likely',
      title: `${route.url} acts on Stripe events without verifying the signature`,
      file: file.path, line, excerpt: (file.lines[line - 1] ?? '').trim(),
      why: [
        `This route handles ${event[1] ?? event[2]} and similar events, but nothing checks the Stripe-Signature header. ` +
          'Anyone who finds the URL can post a made-up event and trigger whatever the handler does — mark an order paid, grant a subscription, or change records.',
        ...(readsBody ? [] : ['The event does not appear to come from the request body here; confirm where it is read and whether it is verified there.']),
      ],
      fix: [
        'Read the raw body (await request.text() in a route handler) and pass it to stripe.webhooks.constructEvent(body, ' +
          "request.headers.get('stripe-signature'), process.env.STRIPE_WEBHOOK_SECRET) before handling the event. Return 400 when it throws.",
        'Do not parse the body as JSON before verifying; any change to the raw body makes verification fail.',
      ],
    }]
  },
}
