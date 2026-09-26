/**
 * 显式下载固定公开源码；不安装依赖、不执行样本，不使用个人账号令牌。
 * CI 中可提供工作流自带的只读 GITHUB_TOKEN，仅发送给 api.github.com，用于提高匿名请求的限额。
 */
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { resolve, dirname, join, relative, isAbsolute, sep } from 'node:path'
import { createHash } from 'node:crypto'
import { setTimeout as sleep } from 'node:timers/promises'
const manifest = JSON.parse(readFileSync(new URL('../test/evaluation/projects.json', import.meta.url), 'utf8'))

/** 消息只含固定文本、主机名、状态码或错误码，可安全写入日志。 */
class SnapshotError extends Error {}

/** 限流与服务端临时错误可重试；其他状态码说明请求本身有误。 */
const RETRYABLE = new Set([429, 500, 502, 503, 504])
const ATTEMPTS = 3

async function request(url) {
  const host = new URL(url).host
  const headers = { 'User-Agent': 'canship-evaluation' }
  if (host === 'api.github.com' && process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`
  for (let attempt = 1; ; attempt++) {
    let response
    try {
      response = await fetch(url, { headers, signal: AbortSignal.timeout(30_000) })
    } catch (error) {
      const code = error?.cause?.code ?? error?.name ?? 'network error'
      if (attempt >= ATTEMPTS) throw new SnapshotError(`Request to ${host} failed (${code}).`)
      await sleep(2000 * attempt)
      continue
    }
    if (response.ok) return response
    if (!RETRYABLE.has(response.status) || attempt >= ATTEMPTS) {
      // 403 且剩余限额为 0 时为限流，单独说明以便区分权限问题。
      const limited = response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0'
      throw new SnapshotError(`Request to ${host} failed (${response.status}${limited ? ', rate limited' : ''}).`)
    }
    await sleep(2000 * attempt)
  }
}

async function main() {
  if (process.argv.length !== 3) throw new SnapshotError('Usage: node scripts/fetch-evaluation-projects.mjs <new-directory-outside-git>')
  const destination = resolve(process.argv[2])
  for (let at = destination; ; at = dirname(at)) {
    if (existsSync(join(at, '.git'))) throw new SnapshotError('Snapshot directory must be outside any Git repository.')
    if (dirname(at) === at) break
  }
  if (existsSync(destination)) throw new SnapshotError('Destination already exists; no files were overwritten.')
  mkdirSync(destination, { recursive: true })
  for (const source of manifest.projects) {
    const tree = await (await request(`https://api.github.com/repos/${source.repository}/git/trees/${source.tree}?recursive=1`)).json()
    const files = tree.tree.filter(item => item.type !== 'tree')
    if (tree.truncated || files.length !== source.sourceFiles || files.length > 1000 ||
        files.some(file => !['100644', '100755'].includes(file.mode) || file.size > 5 * 1024 * 1024) ||
        files.reduce((sum, file) => sum + file.size, 0) > 100 * 1024 * 1024) throw new SnapshotError('Snapshot limits or expected file count mismatch.')
    const root = join(destination, source.id)
    mkdirSync(root)
    let index = 0
    await Promise.all(Array.from({ length: 6 }, async () => {
      while (index < files.length) {
        const file = files[index++]
        const target = resolve(root, file.path)
        const path = relative(root, target)
        if (path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path) || /[\\:\r\n\0]/.test(file.path)) throw new SnapshotError('Invalid snapshot path.')
        const remote = `${source.path}/${file.path}`.split('/').map(encodeURIComponent).join('/')
        const bytes = Buffer.from(await (await request(`https://raw.githubusercontent.com/${source.repository}/${source.revision}/${remote}`)).arrayBuffer())
        const hash = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
        if (hash !== file.sha) throw new SnapshotError('Downloaded object does not match its pinned Git hash.')
        mkdirSync(dirname(target), { recursive: true })
        writeFileSync(target, bytes, { flag: 'wx' })
      }
    }))
    console.log(`${source.id}: verified ${files.length} files`)
  }
}
main().catch((error) => {
  // 仅输出本脚本构造的诊断，其他异常可能携带路径或响应内容。
  const reason = error instanceof SnapshotError ? ` ${error.message}` : ''
  console.error(`Snapshot preparation failed.${reason} Check the new destination, network access, and pinned source metadata. Existing files were not overwritten; an incomplete new directory may remain.`)
  process.exitCode = 1
})
