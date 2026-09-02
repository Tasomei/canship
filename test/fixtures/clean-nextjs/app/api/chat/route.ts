// Test fixture: correct usage. The admin client is only reached after the
// caller has been identified, and the query is scoped to that caller's own row.
import { createClient } from '@supabase/supabase-js'
import { cookies } from 'next/headers'

export async function POST(request: Request) {
  const accessToken = (await cookies()).get('sb-access-token')?.value
  if (!accessToken) return new Response('Unauthorized', { status: 401 })

  const supabase = createClient(
    process.env['SUPABASE_URL']!,
    process.env['SUPABASE_SERVICE_ROLE_KEY']!,
  )

  const { data: { user } } = await supabase.auth.getUser(accessToken)
  if (!user) return new Response('Unauthorized', { status: 401 })

  const { data } = await supabase.from('messages').select('*').eq('user_id', user.id)
  return Response.json({ messages: data, body: await request.text() })
}
