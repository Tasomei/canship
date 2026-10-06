/** 初始化仅输出模板，不读取或修改项目文件。 */
export function renderInit(kind: 'config' | 'ci', version: string): string {
  if (kind === 'config') return JSON.stringify({ all: false }, null, 2) + '\n'
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) throw new TypeError('Invalid template scanner version.')
  return `name: canship
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Tasomei/canship@7465c9560b8b3692777af080e8cc67b4be2335d7
        with:
          version: '${version}'
          honor-ignore-markers: false
          use-config: false
          upload-sarif: false
`
}
