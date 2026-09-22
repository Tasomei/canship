/** 公开项目评估记录不得包含本机路径，准备工具不得覆盖已有目录。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
const root = dirname(dirname(fileURLToPath(import.meta.url)))
const manifest = JSON.parse(readFileSync(join(root, 'test/evaluation/projects.json'), 'utf8'))
test('五个固定项目均有完整来源及范围声明', () => {
  assert.equal(manifest.projects.length, 5)
  assert.match(manifest.scope, /history/)
  assert.equal(new Set(manifest.projects.map((p: { id: string }) => p.id)).size, 5)
  for (const project of manifest.projects) {
    assert.match(project.id, /^[a-z0-9-]+$/)
    assert.match(project.revision, /^[a-f0-9]{40}$/)
    assert.match(project.tree, /^[a-f0-9]{40}$/)
    assert.ok(project.sourceFiles > 0)
    assert.equal(project.root, undefined)
    assert.ok(Array.isArray(project.expectedFindings))
  }
})
test('快照准备拒绝覆盖已有目录，且此分支不联网', () => {
  const target = mkdtempSync(join(tmpdir(), 'canship-corpus-existing-'))
  try {
    writeFileSync(join(target, 'keep.txt'), 'keep')
    const result = spawnSync(process.execPath, [join(root, 'scripts/fetch-evaluation-projects.mjs'), target], {
      cwd: root, encoding: 'utf8', timeout: 10_000,
    })
    assert.equal(result.status, 1)
    assert.equal(readFileSync(join(target, 'keep.txt'), 'utf8'), 'keep')
    assert.match(result.stderr, /Existing files were not overwritten/)
  } finally {
    rmSync(target, { recursive: true, force: true })
  }
})

test('残缺源码快照不能被空发现误判为通过', () => {
  const target = mkdtempSync(join(tmpdir(), 'canship-corpus-incomplete-'))
  try {
    for (const project of manifest.projects) {
      mkdirSync(join(target, project.id))
      writeFileSync(join(target, project.id, 'index.ts'), 'export const ok = true;')
    }
    const result = spawnSync(process.execPath, ['--import', 'tsx', join(root, 'scripts/evaluate-projects.ts'), target], {
      cwd: root, encoding: 'utf8', timeout: 10_000,
    })
    assert.equal(result.status, 1)
    assert.equal(result.stdout, '')
    assert.match(result.stderr, /complete snapshot/)
  } finally {
    rmSync(target, { recursive: true, force: true })
  }
})
