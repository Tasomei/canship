/** 公开项目评估记录不得包含本机路径，准备工具不得覆盖已有目录。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { projectCanaries, scanWithCanary } from './evaluation/project-canaries.js'
const root = dirname(dirname(fileURLToPath(import.meta.url)))
const manifest = JSON.parse(readFileSync(join(root, 'test/evaluation/projects.json'), 'utf8'))
for (const source of manifest.projects) {
  for (const canary of projectCanaries(source.id)) {
    test(`project canary ${source.id}/${canary.id} has exact findings and preserves the source`, async () => {
      const target = mkdtempSync(join(tmpdir(), 'canship-canary-test-'))
      try {
        const pkg = '{"dependencies":{"@supabase/supabase-js":"2"}}'
        writeFileSync(join(target, 'package.json'), pkg)
        const result = await scanWithCanary(target, canary)
        assert.equal(result.partial, false)
        assert.deepEqual(result.findings.map(f => ({ rule: f.ruleId, severity: f.severity,
          confidence: f.confidence, file: f.file, line: f.line })), canary.expected)
        assert.equal(readFileSync(join(target, 'package.json'), 'utf8'), pkg)
      } finally { rmSync(target, { recursive: true, force: true }) }
    })
  }
}
test('project canaries reject traversal and existing files', async () => {
  const target = mkdtempSync(join(tmpdir(), 'canship-canary-path-'))
  try {
    writeFileSync(join(target, 'keep.ts'), 'keep')
    const canary = projectCanaries('firebase-auth')[0]!
    await assert.rejects(scanWithCanary(target, { ...canary, file: '../outside.ts' }), /Invalid canary/)
    await assert.rejects(scanWithCanary(target, { ...canary, file: 'keep.ts' }), /overwrite/)
    assert.equal(readFileSync(join(target, 'keep.ts'), 'utf8'), 'keep')
  } finally { rmSync(target, { recursive: true, force: true }) }
})
test('all six pinned projects have a complete source and scope statement', () => {
  assert.equal(manifest.projects.length, 6)
  assert.match(manifest.scope, /history/)
  assert.equal(new Set(manifest.projects.map((p: { id: string }) => p.id)).size, 6)
  for (const project of manifest.projects) {
    assert.match(project.id, /^[a-z0-9-]+$/)
    assert.match(project.revision, /^[a-f0-9]{40}$/)
    assert.match(project.tree, /^[a-f0-9]{40}$/)
    assert.ok(project.sourceFiles > 0)
    assert.equal(project.root, undefined)
    assert.ok(Array.isArray(project.expectedFindings))
  }
})
test('snapshot preparation refuses an existing directory, and this path makes no network request', () => {
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

for (const corruptEmptyHash of [false, true]) {
  test(`snapshot preparation ${corruptEmptyHash ? 'rejects an incorrect empty blob hash' : 'preserves empty files without requesting raw content'}`, () => {
    const parent = mkdtempSync(join(tmpdir(), 'canship-corpus-empty-'))
    const target = join(parent, 'snapshots')
    const content = 'export const ready = true;\n'
    const blobHash = (body: string): string => createHash('sha1')
      .update(`blob ${Buffer.byteLength(body)}\0`).update(body).digest('hex')
    // 在子进程中完全替代 fetch；空文件的 raw 请求和任何未知请求均失败。
    const mock = `
      const projects = ${JSON.stringify(manifest.projects)};
      globalThis.fetch = async (url) => {
        const source = projects.find(p => url === 'https://api.github.com/repos/' + p.repository + '/git/trees/' + p.tree + '?recursive=1');
        if (source) return Response.json({ tree: Array.from({ length: source.sourceFiles }, (_, i) => ({
          type: 'blob', mode: '100644', path: i === 0 ? '.gitkeep' : 'file-' + i + '.ts',
          size: i === 0 ? 0 : ${Buffer.byteLength(content)},
          sha: i === 0 ? ${JSON.stringify(corruptEmptyHash ? '0'.repeat(40) : blobHash(''))} : ${JSON.stringify(blobHash(content))}
        })) });
        if (url.startsWith('https://raw.githubusercontent.com/') && new URL(url).pathname.split('/').at(-1).startsWith('file-') && url.endsWith('.ts')) return new Response(${JSON.stringify(content)});
        throw new Error('Unexpected network request');
      };
    `
    try {
      const result = spawnSync(process.execPath, [
        '--import', `data:text/javascript;base64,${Buffer.from(mock).toString('base64')}`,
        join(root, 'scripts/fetch-evaluation-projects.mjs'), target,
      ], { cwd: root, encoding: 'utf8', timeout: 10_000 })
      assert.equal(result.status, corruptEmptyHash ? 1 : 0, result.stderr)
      if (corruptEmptyHash) {
        assert.match(result.stderr, /does not match its pinned Git hash/)
      } else {
        for (const source of manifest.projects) {
          assert.equal(readFileSync(join(target, source.id, '.gitkeep')).length, 0)
          assert.equal(readFileSync(join(target, source.id, 'file-1.ts'), 'utf8'), content)
          assert.match(result.stdout, new RegExp(`${source.id}: verified ${source.sourceFiles} files`))
        }
      }
    } finally { rmSync(parent, { recursive: true, force: true }) }
  })
}

test('an incomplete source snapshot cannot pass on empty findings', () => {
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
