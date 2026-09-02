// Test fixture: a destructive write with no caller check, through an ordinary
// ORM rather than an admin client.
//
// Reported at lower confidence on purpose: an open write can be a deliberate
// design (a waitlist, a contact form), and protection can live in a proxy this
// scan cannot see.
import { prisma } from '@/lib/prisma'

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await prisma.post.delete({ where: { id: params.id } })
  return Response.json({ ok: true })
}
