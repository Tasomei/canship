// Test fixture: correct usage, in the two shapes that look most like the
// broken one.
//
// Both read the request's Origin header, which is what makes them the real
// test: the difference from a reflection bug is that these decide what to send
// back rather than echoing it.

const ALLOWED = ['https://app.example.com', 'https://admin.example.com']

/** Allowlist: the header is compared before any of it reaches the response. */
export function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get('origin') ?? ''
  return {
    'Access-Control-Allow-Origin': ALLOWED.includes(origin) ? origin : ALLOWED[0]!,
    'Access-Control-Allow-Credentials': 'true',
  }
}

/** Configured: one origin, set per environment. */
export function singleOriginHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': process.env['APP_ORIGIN']!,
    'Access-Control-Allow-Credentials': 'true',
  }
}
