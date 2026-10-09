/** 官方工具仅用于本地打包；通过文件清单和字节核对后才交付产物。 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, copyFileSync, rmSync, constants, lstatSync, existsSync } from 'node:fs'
import { join, resolve, dirname } from 'node:path'
import { createHash, randomUUID } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { repository, toolRequire, inspectSources, verifyVsix, sourceFiles, contentBase } from './vsix-support.mjs'

export async function packageExtension(root = join(repository, 'extensions/vscode'), output = join(repository, '.scratch/vsix')) {
  assert.ok(Number(process.versions.node.split('.')[0]) >= 22, 'VSIX packaging requires Node 22 or later')
  const manifest = inspectSources(root)
  const snapshot = new Map(['.vscodeignore', ...sourceFiles].map(name => [name, readFileSync(join(root, name))]))
  const { createVSIX, listFiles, PackageManager } = toolRequire('@vscode/vsce')
  assert.equal(toolRequire('@vscode/vsce/package.json').version, '4.0.0')
  const listed = await listFiles({ cwd: root, packageManager: PackageManager.None })
  assert.deepEqual(listed.map(name => name.replaceAll('\\', '/')).sort(), sourceFiles)
  if (resolve(output) === join(repository, '.scratch/vsix') && existsSync(join(repository, '.scratch'))) {
    assert.equal(lstatSync(join(repository, '.scratch')).isSymbolicLink(), false, 'Linked output parent is not allowed')
  }
  mkdirSync(output, { recursive: true })
  assert.equal(lstatSync(output).isSymbolicLink(), false)
  const temporary = mkdtempSync(join(output, 'build-'))
  const staged = join(temporary, 'review.vsix')
  try {
    // 冻结六个输入，打包过程不再读取工作目录中的其他内容或后续修改。
    const frozen = join(temporary, 'input')
    for (const [name, bytes] of snapshot) {
      const path = join(frozen, name)
      mkdirSync(dirname(path), { recursive: true }); writeFileSync(path, bytes, { flag: 'wx' })
    }
    inspectSources(frozen)
    await createVSIX({ cwd: frozen, packagePath: staged, dependencies: false, followSymlinks: false,
      baseContentUrl: contentBase, baseImagesUrl: 'https://raw.githubusercontent.com/Tasomei/canship/main/extensions/vscode',
      updatePackageJson: false, gitTagVersion: false })
    await verifyVsix(staged, frozen)
    for (const [name, bytes] of snapshot) assert.ok(readFileSync(join(root, name)).equals(bytes), 'Package inputs changed during packaging')
    const path = join(output, `canship-${manifest.version}-${randomUUID()}.vsix`)
    copyFileSync(staged, path, constants.COPYFILE_EXCL)
    return { path, version: manifest.version, files: 8, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') }
  } finally {
    // 仅清理本次创建的打包中间目录，最终产物不覆盖、不删除。
    rmSync(temporary, { recursive: true, force: true })
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('This command takes no arguments.')
  packageExtension().then(result => console.log(JSON.stringify(result))).catch(() => {
    process.stderr.write('VSIX packaging failed; no verified artifact was delivered. Check package inputs and installed tools.\n')
    process.exitCode = 1
  })
}
