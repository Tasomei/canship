// 验证允许列表判断与固定来源配置。

const ALLOWED = ['https://app.example.com', 'https://admin.example.com']

/** 比较允许列表后再返回来源。 */
export function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get('origin') ?? ''
  return {
    'Access-Control-Allow-Origin': ALLOWED.includes(origin) ? origin : ALLOWED[0]!,
    'Access-Control-Allow-Credentials': 'true',
  }
}

/** 使用环境配置指定唯一来源。 */
export function singleOriginHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': process.env['APP_ORIGIN']!,
    'Access-Control-Allow-Credentials': 'true',
  }
}
