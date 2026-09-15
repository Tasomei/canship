'use client'

// 客户端只使用公开键，敏感操作经服务端执行。
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env['NEXT_PUBLIC_SUPABASE_URL']!,
  process.env['NEXT_PUBLIC_SUPABASE_ANON_KEY']!,
)

export default function Page() {
  async function ask() {
    // 调用服务端接口，凭据不进入浏览器。
    await fetch('/api/chat', { method: 'POST' })
  }

  return <button onClick={ask}>Ask</button>
}
