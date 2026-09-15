// 不访问数据的公开健康检查无需报告。
export function GET() {
  return Response.json({ ok: true })
}
