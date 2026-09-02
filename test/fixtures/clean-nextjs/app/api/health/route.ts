// Test fixture: a public route that touches no data at all. Nothing to report —
// flagging every unauthenticated route regardless of what it does would be
// noise, and noise is what makes people stop running the tool.
export function GET() {
  return Response.json({ ok: true })
}
