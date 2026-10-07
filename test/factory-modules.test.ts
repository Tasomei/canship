/** 模块解析只使用传入快照；不接触磁盘、环境变量或模块加载器。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { ScanFile } from '../src/types.js'
import { factoryModuleResolver } from '../src/rules/factory-modules.js'

function project(input: Record<string, string>) {
  const files: ScanFile[] = Object.entries(input).map(([path, content]) => ({ path, content, lines: content.split('\n'), isExampleContext: false }))
  const resolve = factoryModuleResolver(files)
  return (spec: string, from = 'src/app.ts') => resolve(spec, files.find(file => file.path === from)!)
}

test('exact mappings and the longest wildcard prefix take precedence', () => {
  const resolve = project({ 'src/app.ts': '', 'one.ts': '', 'two.ts': '', 'three.ts': '',
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@/*': ['./one.ts'], '@/long/*': ['./two.ts'], '@/long/exact': ['./three.ts'] } } }) })
  assert.equal(resolve('@/short').file?.path, 'one.ts')
  assert.equal(resolve('@/long/name').file?.path, 'two.ts')
  assert.equal(resolve('@/long/exact').file?.path, 'three.ts')
})

test('ambiguous source extensions, external paths and unscanned files remain unresolved', () => {
  const resolve = project({ 'src/app.ts': '', 'src/value.ts': '', 'src/value.js': '',
    'tsconfig.json': JSON.stringify({ compilerOptions: { paths: { '@external': ['../../outside.ts'], '@missing': ['./missing.ts'] } } }) })
  for (const spec of ['./value', '@external', '@missing']) {
    assert.equal(resolve(spec).handled, true)
    assert.equal(resolve(spec).file, null)
  }
})

test('nearest configuration and baseUrl do not borrow sibling project mappings', () => {
  const resolve = project({ 'apps/a/src/app.ts': '', 'apps/a/lib/f.ts': '', 'apps/b/lib/f.ts': '',
    'apps/a/tsconfig.json': JSON.stringify({ compilerOptions: { baseUrl: './lib', paths: { build: ['./f'] } } }),
    'apps/b/tsconfig.json': JSON.stringify({ compilerOptions: { baseUrl: './lib', paths: { build: ['./f'] } } }) })
  assert.equal(resolve('build', 'apps/a/src/app.ts').file?.path, 'apps/a/lib/f.ts')
})

test('metadata and mapping limits are distinguished from ordinary unresolved references', () => {
  const large = project({ 'src/app.ts': '', 'tsconfig.json': ' '.repeat(65537) })
  assert.equal(large('build').limited, true)
  const paths = Object.fromEntries(Array.from({ length: 129 }, (_, i) => ['alias' + i, ['./value.ts']]))
  assert.equal(project({ 'src/app.ts': '', 'tsconfig.json': JSON.stringify({ compilerOptions: { paths } }) })('alias1').limited, true)
  assert.equal(project({ 'src/app.ts': '' })('./missing').limited, undefined)
})

test('workspace export maps reject traversal, blocked branches and wildcard targets', () => {
  for (const exports of [{ '.': './src/../factory.ts' }, { '.': './src/*.ts' }, { '.': { import: './factory.ts', default: null } },
    { '.': './factory.ts', browser: './other.ts' }, { '.': null }]) {
    const resolve = project({ 'package.json': '{"workspaces":["apps/*","packages/*"]}', 'apps/web/src/app.ts': '',
      'apps/web/package.json': '{"dependencies":{"@synthetic/router":"workspace:*"}}',
      'packages/router/package.json': JSON.stringify({ name: '@synthetic/router', exports }), 'packages/router/factory.ts': '' })
    assert.equal(resolve('@synthetic/router', 'apps/web/src/app.ts').file, null)
    assert.equal(resolve('@synthetic/router', 'apps/web/src/app.ts').handled, true)
  }
})

test('workspace private subpaths stay private even when the source exists', () => {
  const resolve = project({ 'package.json': '{"workspaces":["apps/*","packages/*"]}', 'apps/web/src/app.ts': '',
    'apps/web/package.json': '{"dependencies":{"@synthetic/router":"workspace:*"}}',
    'packages/router/package.json': '{"name":"@synthetic/router","exports":{".":"./factory.ts","./public":"./factory.ts"}}', 'packages/router/factory.ts': '' })
  assert.equal(resolve('@synthetic/router/public', 'apps/web/src/app.ts').file?.path, 'packages/router/factory.ts')
  assert.equal(resolve('@synthetic/router/factory.ts', 'apps/web/src/app.ts').file, null)
})

test('JSONC keeps quoted punctuation and non-script imports cannot supply executable factory definitions', () => {
  const resolve = project({ 'src/app.ts': '', 'src/view.md': 'export const make = () => new Hono()', 'src/types.d.ts': '', 'lib/f.ts': '',
    'tsconfig.json': '{"note":"comma,} and // are text", "compilerOptions":{"paths":{"build":["lib/f.ts"],},},}' })
  assert.equal(resolve('build').file?.path, 'lib/f.ts')
  assert.equal(resolve('./view.md').file, null)
  assert.equal(resolve('./types.d.ts').file, null)
})

test('duplicate workspace package names and oversized package metadata are not silently selected', () => {
  const base = { 'package.json': '{"workspaces":["apps/*","packages/*"]}', 'apps/web/src/app.ts': '',
    'apps/web/package.json': '{"dependencies":{"@synthetic/router":"workspace:*"}}',
    'packages/one/package.json': '{"name":"@synthetic/router","exports":"./factory.ts"}', 'packages/one/factory.ts': '' }
  const duplicate = project({ ...base, 'packages/two/package.json': '{"name":"@synthetic/router","exports":"./factory.ts"}', 'packages/two/factory.ts': '' })
  assert.equal(duplicate('@synthetic/router', 'apps/web/src/app.ts').file, null)
  const large = project({ ...base, 'packages/two/package.json': ' '.repeat(65537) })
  assert.equal(large('@synthetic/router', 'apps/web/src/app.ts').limited, true)
})
