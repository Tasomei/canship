// 无条件回显调用者来源，同时允许携带凭据。
export function corsHeaders(req: Request): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': req.headers.get('origin')!,
    'Access-Control-Allow-Credentials': 'true',
  }
}
