// Test fixture: middleware that authenticates requests but deliberately does
// not cover /api — this is the matcher printed in the Next.js documentation.
//
// It is the trap this rule has to see through. Treating "there is auth
// middleware" as "the API is protected" would silence every finding in this
// fixture, which is exactly the mistake a naive implementation makes.
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export function middleware(request: NextRequest) {
  const session = request.cookies.get('sb-access-token')
  if (!session) return NextResponse.redirect(new URL('/login', request.url))
  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
}
