// Test fixture: living under /api/auth does not make a route an auth endpoint.
//
// Exempting the whole namespace was simpler and wrong. Sign-in and callback
// handlers cannot check a caller because there is nobody to check yet; a bulk
// export sitting next to them has no such excuse.
//
// The comment below is the other half of the test: a note reminding you the
// check is missing used to be read as the check itself.
// TODO validate token before shipping
import { supabaseAdmin } from '@/lib/supabase-admin'

export async function GET() {
  const { data } = await supabaseAdmin.from('profiles').select('*')
  return Response.json({ everyone: data })
}
