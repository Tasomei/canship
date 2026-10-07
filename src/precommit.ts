/** 只生成钩子预览；不安装钩子、不修改 Git 配置或系统环境。 */
export function preCommitTemplate(version: string): string {
  return `#!/usr/bin/env node
// 扫描工作区，不代表已验证暂存区快照；扫描器须位于工作区之外。
(async () => {
  const { spawnSync } = await import('node:child_process');
  const { realpathSync, statSync } = await import('node:fs');
  const { isAbsolute, relative, sep } = await import('node:path');
  const fail = message => { process.stderr.write('canship hook: ' + message + '\\n'); process.exitCode = 3; };
  const configured = process.env.CANSHIP_CLI;
  if (!configured || !isAbsolute(configured)) return fail('Set CANSHIP_CLI to a trusted, separately installed dist/cli.js absolute path.');
  let scanner;
  try {
    scanner = realpathSync(configured);
    const rel = relative(realpathSync(process.cwd()), scanner);
    if (!statSync(scanner).isFile() || !(rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel))) return fail('The scanner must be a regular file outside this worktree.');
  } catch { return fail('The configured scanner is unavailable.'); }
  const version = spawnSync(process.execPath, [scanner, '--version'], { encoding: 'utf8', timeout: 10000, maxBuffer: 8192, windowsHide: true });
  if (version.error || version.status !== 0 || version.stdout.trim() !== ${JSON.stringify(version)}) return fail('Scanner version mismatch; review and regenerate this hook after upgrades.');
  process.stderr.write('canship hook: scanning the full working tree, including unstaged changes; not the staged snapshot.\\n');
  const result = spawnSync(process.execPath, [scanner, '.', '--all', '--no-config', '--no-ignore-markers', '--no-excerpts'],
    { stdio: 'inherit', timeout: 120000, windowsHide: true, shell: false });
  if (result.error || result.signal || result.status === null) return fail('The scanner did not complete.');
  process.exitCode = result.status;
})().catch(() => { process.stderr.write('canship hook: setup failed.\\n'); process.exitCode = 3; });
`
}
