/** VSIX 只包含审阅过的文件；验证时不解压、不执行包内代码。 */
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFileSync, lstatSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export const repository = dirname(dirname(fileURLToPath(import.meta.url)))
export const toolRequire = createRequire(join(repository, 'tools/vsix/package.json'))
export const contentBase = 'https://github.com/Tasomei/canship/blob/main/extensions/vscode'
export const sourceFiles = ['LICENSE', 'README-zh-CN.md', 'README.md', 'dist/extension.cjs', 'dist/worker.cjs', 'package.json'].sort()
export const archiveFiles = ['[Content_Types].xml', 'extension.vsixmanifest', 'extension/LICENSE.txt',
  'extension/README-zh-CN.md', 'extension/readme.md', 'extension/dist/extension.cjs', 'extension/dist/worker.cjs', 'extension/package.json'].sort()

export function inspectSources(root) {
  assert.ok(lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink(), 'Expected a regular extension directory')
  for (const name of ['.vscodeignore', ...sourceFiles]) {
    let path = root
    for (const part of name.split('/')) {
      path = join(path, part)
      assert.equal(lstatSync(path).isSymbolicLink(), false, 'Linked package inputs are not allowed')
    }
    assert.ok(lstatSync(path).isFile(), 'Package input must be a regular file')
    assert.ok(lstatSync(path).size <= 10 * 1024 * 1024, 'Package input exceeds the size limit')
  }
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  assert.equal(manifest.name, 'canship'); assert.equal(manifest.publisher, 'Tasomei')
  assert.match(manifest.version, /^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/i)
  assert.equal(manifest.main, './dist/extension.cjs')
  for (const field of ['dependencies', 'optionalDependencies', 'scripts', 'vsce']) {
    assert.equal(Object.keys(manifest[field] ?? {}).length, 0, 'Unreviewed package hooks or dependencies are not allowed')
  }
  assert.equal((manifest.extensionDependencies ?? []).length, 0)
  assert.equal((manifest.extensionPack ?? []).length, 0)
  return manifest
}

export async function readVsix(path) {
  const { openPromise } = toolRequire('yauzl')
  assert.ok(lstatSync(path).isFile() && !lstatSync(path).isSymbolicLink(), 'Expected a regular VSIX file')
  assert.ok(lstatSync(path).size <= 20 * 1024 * 1024, 'VSIX exceeds the size limit')
  const zip = await openPromise(path, { lazyEntries: true, autoClose: false, strictFileNames: true })
  const entries = new Map()
  let total = 0
  try {
    for await (const entry of zip.eachEntry()) {
      assert.ok(archiveFiles.includes(entry.fileName), 'Unexpected VSIX entry')
      assert.equal(entries.has(entry.fileName), false, 'Duplicate VSIX entry')
      assert.notEqual((entry.externalFileAttributes >>> 16) & 0xf000, 0xa000, 'Linked VSIX entry')
      assert.ok(entry.uncompressedSize <= 10 * 1024 * 1024, 'VSIX entry exceeds the size limit')
      const stream = await zip.openReadStreamPromise(entry)
      const chunks = []
      for await (const chunk of stream) {
        total += chunk.length
        assert.ok(total <= 20 * 1024 * 1024, 'Expanded VSIX exceeds the size limit')
        chunks.push(chunk)
      }
      entries.set(entry.fileName, Buffer.concat(chunks))
    }
  } finally { zip.close() }
  assert.deepEqual([...entries.keys()].sort(), archiveFiles)
  return entries
}

export async function verifyVsix(path, root) {
  const manifest = inspectSources(root)
  const entries = await readVsix(path)
  assert.deepEqual(JSON.parse(entries.get('extension/package.json').toString()), manifest)
  for (const [packed, source] of [['extension/LICENSE.txt', 'LICENSE'], ['extension/README-zh-CN.md', 'README-zh-CN.md'],
    ['extension/readme.md', 'README.md'], ['extension/dist/extension.cjs', 'dist/extension.cjs'], ['extension/dist/worker.cjs', 'dist/worker.cjs']]) {
    assert.ok(entries.get(packed).equals(readFileSync(join(root, source))), 'Packaged bytes do not match the reviewed source')
  }
  assert.ok(entries.get('extension/readme.md').toString().includes(`${contentBase}/README-zh-CN.md`))
  assert.ok(entries.get('extension/README-zh-CN.md').toString().includes(`${contentBase}/README.md`))
  const metadata = entries.get('extension.vsixmanifest').toString()
  assert.ok(metadata.includes('Publisher="Tasomei"') && metadata.includes('Id="canship"') && metadata.includes(`Version="${manifest.version}"`))
  return { manifest, entries }
}
