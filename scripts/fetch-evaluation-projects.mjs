/** 显式下载固定公开源码；不安装依赖、不执行样本，不使用账号令牌。 */
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { resolve, dirname, join, relative, isAbsolute, sep } from 'node:path'
import { createHash } from 'node:crypto'
const manifest = JSON.parse(readFileSync(new URL('../test/evaluation/projects.json', import.meta.url), 'utf8'))

async function request(url) {
  const response = await fetch(url, { headers: { 'User-Agent': 'canship-evaluation' }, signal: AbortSignal.timeout(30_000) })
  if (!response.ok) throw new Error(`Public snapshot request failed (${response.status}).`)
  return response
}

async function main() {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/fetch-evaluation-projects.mjs <new-directory-outside-git>')
  const destination = resolve(process.argv[2])
  for (let at = destination; ; at = dirname(at)) {
    if (existsSync(join(at, '.git'))) throw new Error('Snapshot directory must be outside any Git repository.')
    if (dirname(at) === at) break
  }
  if (existsSync(destination)) throw new Error('Destination already exists; no files were overwritten.')
  mkdirSync(destination, { recursive: true })
  for (const source of manifest.projects) {
    const tree = await (await request(`https://api.github.com/repos/${source.repository}/git/trees/${source.tree}?recursive=1`)).json()
    const files = tree.tree.filter(item => item.type !== 'tree')
    if (tree.truncated || files.length !== source.sourceFiles || files.length > 1000 ||
        files.some(file => !['100644', '100755'].includes(file.mode) || file.size > 5 * 1024 * 1024) ||
        files.reduce((sum, file) => sum + file.size, 0) > 100 * 1024 * 1024) throw new Error('Snapshot limits or expected file count mismatch.')
    const root = join(destination, source.id)
    mkdirSync(root)
    let index = 0
    await Promise.all(Array.from({ length: 6 }, async () => {
      while (index < files.length) {
        const file = files[index++]
        const target = resolve(root, file.path)
        const path = relative(root, target)
        if (path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path) || /[\\:\r\n\0]/.test(file.path)) throw new Error('Invalid snapshot path.')
        const remote = `${source.path}/${file.path}`.split('/').map(encodeURIComponent).join('/')
        const bytes = Buffer.from(await (await request(`https://raw.githubusercontent.com/${source.repository}/${source.revision}/${remote}`)).arrayBuffer())
        const hash = createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
        if (hash !== file.sha) throw new Error('Downloaded object does not match its pinned Git hash.')
        mkdirSync(dirname(target), { recursive: true })
        writeFileSync(target, bytes, { flag: 'wx' })
      }
    }))
    console.log(`${source.id}: verified ${files.length} files`)
  }
}
main().catch(() => {
  console.error('Snapshot preparation failed. Check the new destination, network access, and pinned source metadata. Existing files were not overwritten; an incomplete new directory may remain.')
  process.exitCode = 1
})
