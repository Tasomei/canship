// Test fixture: a passwordless sign-in endpoint. It uses the admin client and
// has no caller check — and it cannot have one, because this is how a caller
// becomes known in the first place.
//
// The generated link is emailed to the address, never returned to the caller.
import { createClient } from '@supabase/supabase-js'

const supabaseAdmin = createClient(
  process.env['SUPABASE_URL']!,
  process.env['SUPABASE_SERVICE_ROLE_KEY']!,
)

export async function POST(request: Request) {
  const { email } = await request.json()
  const { data } = await supabaseAdmin.from('profiles').select('id').eq('email', email)
  return Response.json({ sent: Boolean(data) })
}
