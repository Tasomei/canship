/** 目录链接不依赖 Windows 文件符号链接权限，始终执行边界测试。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, renameSync, symlinkSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import { scan } from '../src/index.js'

const sandbox = mkdtempSync(join(tmpdir(), 'canship-ancestor-link-'))
after(() => rmSync(sandbox, { recursive: true, force: true }))

for (const targetInside of [false, true]) {
  test(`tracked files below a directory link are not read (target inside: ${targetInside})`, async () => {
    const root = join(sandbox, targetInside ? 'inside' : 'outside')
    const original = join(root, 'tracked')
    const target = targetInside ? join(root, 'node_modules', 'target') : join(sandbox, 'external')
    mkdirSync(original, { recursive: true })
    mkdirSync(target, { recursive: true })
    writeFileSync(join(original, 'route.ts'), 'export const original = true;')
    writeFileSync(join(target, 'route.ts'), 'const marker = "BOUNDARY_SENTINEL"; app.use(cors({ origin: true, credentials: true }));')
    execFileSync('git', ['init', '--quiet', root])
    execFileSync('git', ['-C', root, 'add', '--', 'tracked/route.ts'])
    renameSync(original, join(root, 'saved'))
    symlinkSync(target, original, process.platform === 'win32' ? 'junction' : 'dir')
    const result = await scan(root, { only: ['cors'], honorIgnoreMarkers: false })
    assert.equal(result.partial, true)
    assert.ok(result.skipped.some(item => item.path === 'tracked' && item.reason === 'symlink'))
    assert.deepEqual(result.findings, [])
    assert.ok(!JSON.stringify(result).includes('BOUNDARY_SENTINEL'))
  })
}

test('regular tracked files are still scanned', async () => {
  const root = join(sandbox, 'regular')
  mkdirSync(root)
  writeFileSync(join(root, 'route.ts'), 'app.use(cors({ origin: true, credentials: true }));')
  execFileSync('git', ['init', '--quiet', root])
  execFileSync('git', ['-C', root, 'add', '--', 'route.ts'])
  const result = await scan(root, { only: ['cors'] })
  assert.equal(result.partial, false)
  assert.equal(result.findings.length, 1)
})
