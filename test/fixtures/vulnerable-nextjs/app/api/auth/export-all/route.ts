// 身份命名空间中的业务导出接口仍需鉴权。
import { supabaseAdmin } from '@/lib/supabase-admin'

export async function GET() {
  const { data } = await supabaseAdmin.from('profiles').select('*')
  return Response.json({ everyone: data })
}
