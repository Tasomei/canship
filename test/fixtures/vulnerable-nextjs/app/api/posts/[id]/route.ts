// 普通数据库客户端执行未鉴权写入，按疑似问题报告。
import { prisma } from '@/lib/prisma'

export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  await prisma.post.delete({ where: { id: params.id } })
  return Response.json({ ok: true })
}
