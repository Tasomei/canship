// 会话客户端按调用者身份写入，由数据库策略约束访问。
import { createClient } from '@/lib/supabase-server'

export async function POST(request: Request) {
  const supabase = await createClient()
  const { id, body } = await request.json()

  const { error } = await supabase.from('notes').update({ body }).eq('id', id)
  if (error) return Response.json({ error: 'Failed to save' }, { status: 500 })

  return Response.json({ ok: true })
}
