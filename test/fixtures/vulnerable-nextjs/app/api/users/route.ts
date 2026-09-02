// Test fixture: an API route that reads the whole profiles table through the
// service_role client, with nothing checking who is calling.
//
// This is the canonical vibe-coding failure: the admin client was used because
// it made the query work during development, and the sign-in check was never
// added because there was nobody to check.
import { supabaseAdmin } from '@/lib/supabase-admin'

export async function GET() {
  const { data } = await supabaseAdmin.from('profiles').select('*')
  return Response.json({ users: data })
}
