// Test fixture: a write with no visible caller check — and correct.
//
// This route is the architecture canship recommends: the session-scoped client
// runs the update as the signed-in caller, so the database refuses rows that
// are not theirs. Reporting this would mean flagging the fix the tool itself
// hands out.
//
// Deliberately free of anything the auth-signal list would match, so the test
// proves the client resolution is what suppresses this, not a stray keyword.
import { createClient } from '@/lib/supabase-server'

export async function POST(request: Request) {
  const supabase = await createClient()
  const { id, body } = await request.json()

  const { error } = await supabase.from('notes').update({ body }).eq('id', id)
  if (error) return Response.json({ error: 'Failed to save' }, { status: 500 })

  return Response.json({ ok: true })
}
