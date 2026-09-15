// 通过独立模块导出管理员客户端，验证跨文件追踪。
import { createClient } from '@supabase/supabase-js'
import type { Database } from './database.types'

export const supabaseAdmin = createClient<Database>(
  process.env['SUPABASE_URL']!,
  process.env['SUPABASE_SERVICE_ROLE_KEY']!,
  { auth: { persistSession: false } },
)
