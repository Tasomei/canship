/** 打开程序的路径边界、符号链接和非标准安装位置。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, realpathSync, symlinkSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative, posix } from 'node:path'
import { openerFor, openerEnvironment, trustedUnixPath } from '../src/open.js'

const identity = (path: string) => path

for (const directory of ['/work/project/..cache', '/work/project/sub/../..cache', '/work/project/bin']) {
  test(`project descendants cannot supply an opener: ${directory}`, () => {
    assert.throws(() => openerFor('linux', 'r.html', { PATH: directory }, {
      cwd: '/work/project', realpath: identity, exists: p => p === posix.join(directory, 'xdg-open'),
    }), /xdg-open was not found/)
    assert.ok(!trustedUnixPath({ PATH: directory }, '/work/project', { realpath: identity }).includes(directory))
  })
}

test('the scan root is excluded even when the command runs from another directory', () => {
  assert.throws(() => openerFor('linux', 'r.html', { PATH: '/target/bin' }, {
    cwd: '/work', root: '/target', realpath: identity, exists: p => p === '/target/bin/xdg-open',
  }), /xdg-open was not found/)
})

test('the physical scan root remains excluded when its supplied path is a symlink', () => {
  const realpath = (p: string) => p === '/alias' ? '/project' : p
  assert.throws(() => openerFor('linux', 'r.html', { PATH: '/project/bin' }, {
    cwd: '/alias', realpath, exists: p => p === '/project/bin/xdg-open',
  }), /xdg-open was not found/)
})

test('unresolvable boundaries fail closed instead of trusting lexical paths', () => {
  for (const failed of ['/project', '/target']) {
    assert.throws(() => openerFor('linux', 'r.html', { PATH: '/opt/tools' }, {
      cwd: '/project', root: '/target', exists: () => true,
      realpath: p => { if (p === failed) throw new Error('unavailable'); return p },
    }), /xdg-open was not found/)
  }
})

test('opener-file symlinks into the project or dependencies are rejected', () => {
  for (const target of ['/project/xdg-open', '/opt/node_modules/tool/xdg-open']) {
    assert.throws(() => openerFor('linux', 'r.html', { PATH: '/opt/tools' }, {
      cwd: '/project', exists: p => p === '/opt/tools/xdg-open',
      realpath: p => p === '/opt/tools/xdg-open' ? target : p,
    }), /xdg-open was not found/)
  }
})

test('real directory links into a project are excluded from the opener and child PATH', () => {
  const root = mkdtempSync(join(tmpdir(), 'canship-opener-boundary-'))
  try {
    mkdirSync(join(root, 'project', 'bin'), { recursive: true })
    writeFileSync(join(root, 'project', 'bin', 'xdg-open'), 'not executed')
    symlinkSync(join(root, 'project', 'bin'), join(root, 'alias'), process.platform === 'win32' ? 'junction' : 'dir')
    // 虚拟 Unix 路径映射到实际目录，以便 Windows 也验证链接解析。
    const native = (p: string) => join(root, p.slice('/virtual/'.length))
    const resolve = (p: string) => p.startsWith('/virtual/')
      ? '/virtual/' + relative(realpathSync(root), realpathSync(native(p))).replace(/\\/g, '/') : p
    const env = { PATH: '/virtual/alias' }
    const options = { cwd: '/virtual/project', realpath: resolve,
      exists: (p: string) => p.startsWith('/virtual/') && existsSync(native(p)) }
    assert.throws(() => openerFor('linux', 'r.html', env, options), /xdg-open was not found/)
    assert.ok(!openerEnvironment('linux', '/usr/bin/xdg-open', env, options.cwd, options).PATH!.includes('/virtual/alias'))
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('trusted external symlinks retain their entry name for launcher dispatch', () => {
  const command = '/run/current-system/sw/bin/xdg-open'
  assert.equal(openerFor('linux', 'r.html', { PATH: '/run/current-system/sw/bin' }, {
    cwd: '/project', exists: p => p === command,
    realpath: p => p.startsWith('/run/current-system/sw/bin') ? p.replace('/run/current-system/sw/bin', '/nix/store/tools/bin') : p,
  }).command, command)
})
