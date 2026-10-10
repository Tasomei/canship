/** 初始化仅输出模板，不读取或修改项目文件。 */
import { preCommitTemplate } from './precommit.js'
export function renderInit(kind: 'config' | 'ci' | 'ci-workspaces' | 'pre-commit', version: string): string {
  if (kind === 'config') return JSON.stringify({ all: false }, null, 2) + '\n'
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) throw new TypeError('Invalid template scanner version.')
  if (kind === 'pre-commit') return preCommitTemplate(version)
  const matrix = kind === 'ci-workspaces' ? `    strategy:
      fail-fast: false
      matrix:
        project:
          - { name: web, path: apps/web }
          - { name: admin, path: apps/admin }
` : ''
  const target = kind === 'ci-workspaces' ? `          path: \${{ matrix.project.path }}
          category: canship-\${{ matrix.project.name }}
` : ''
  return `name: canship
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
${matrix}\
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Tasomei/canship@8ae4d5f4508fbd68fc2cf440e138c1217064a0e0
        with:
          version: '${version}'
${target}\
          honor-ignore-markers: false
          use-config: false
          upload-sarif: false
`
}
