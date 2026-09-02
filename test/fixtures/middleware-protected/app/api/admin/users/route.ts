// Test fixture: identical in every visible way to the vulnerable fixture's
// route — admin client, no check, whole table. It is safe only because of
// middleware.ts, and it must not be reported.
import { createClient } from '@supabase/supabase-js'

const supabaseAdmin = createClient(
  process.env['SUPABASE_URL']!,
  process.env['SUPABASE_SERVICE_ROLE_KEY']!,
)

export async function GET() {
  const { data } = await supabaseAdmin.from('profiles').select('*')
  return Response.json({ users: data })
}
