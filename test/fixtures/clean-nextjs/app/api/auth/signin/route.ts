// 登录入口使用管理员客户端完成身份建立，不能要求调用者预先登录。
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
