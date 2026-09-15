// 管理员查询由外部中间件保护，路由内无需重复检查。
import { createClient } from '@supabase/supabase-js'

const supabaseAdmin = createClient(
  process.env['SUPABASE_URL']!,
  process.env['SUPABASE_SERVICE_ROLE_KEY']!,
)

export async function GET() {
  const { data } = await supabaseAdmin.from('profiles').select('*')
  return Response.json({ users: data })
}
