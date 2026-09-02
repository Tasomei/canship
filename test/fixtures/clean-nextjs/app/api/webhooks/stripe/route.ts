// Test fixture: a webhook. It has no sign-in check and never could — Stripe is
// not signed in. It authenticates the caller by verifying the signature
// instead, which is a real authorisation check and must be recognised as one.
import Stripe from 'stripe'
import { createClient } from '@supabase/supabase-js'

const stripe = new Stripe(process.env['STRIPE_SECRET_KEY']!)

export async function POST(request: Request) {
  const signature = request.headers.get('stripe-signature')!
  const event = stripe.webhooks.constructEvent(
    await request.text(),
    signature,
    process.env['STRIPE_WEBHOOK_SECRET']!,
  )

  const supabase = createClient(
    process.env['SUPABASE_URL']!,
    process.env['SUPABASE_SERVICE_ROLE_KEY']!,
  )
  await supabase.from('subscriptions').upsert({ event_id: event.id })

  return Response.json({ received: true })
}
