// 改编自 Next.js 官方 Supabase 示例；仅调整注释，代码不变。
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

/** 每次调用创建独立客户端，避免跨请求复用。 */
export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options),
            );
          } catch {
            // 服务端组件无法写入 Cookie 时，由代理刷新会话。
          }
        },
      },
    },
  );
}
