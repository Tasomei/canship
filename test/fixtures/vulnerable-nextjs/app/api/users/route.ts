// 管理员客户端查询全部资料，缺少调用者检查。
import { supabaseAdmin } from '@/lib/supabase-admin'

export async function GET() {
  const { data } = await supabaseAdmin.from('profiles').select('*')
  return Response.json({ users: data })
}
