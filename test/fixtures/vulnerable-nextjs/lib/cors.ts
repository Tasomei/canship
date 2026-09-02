// Test fixture: the origin is handed straight back to whoever asked for it,
// and credentials are allowed alongside it. Every website on the internet is
// now an allowed origin.
export function corsHeaders(req: Request): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': req.headers.get('origin')!,
    'Access-Control-Allow-Credentials': 'true',
  }
}
