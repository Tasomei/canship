/** 仅显式 --write 更新合成演示；默认输出预览，不接触被扫描项目。 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { renderDemoReport } from '../src/report/demo.js'
import { writeOutput } from '../src/output.js'

const args = process.argv.slice(2)
if (args.length > 1 || (args.length === 1 && !['--write', '--check'].includes(args[0]!))) {
  process.stderr.write('Use --write, --check or no option.\n'); process.exitCode = 3
} else {
  const html = renderDemoReport()
  const target = fileURLToPath(new URL('../docs/demo.html', import.meta.url))
  try {
    if (args[0] === '--write') { writeOutput(target, html, 'html'); process.stdout.write('Synthetic demo updated.\n') }
    else if (args[0] === '--check') {
      if (readFileSync(target, 'utf8').replace(/\r\n/g, '\n') !== html) throw new Error('stale')
      process.stdout.write('Synthetic demo matches the current renderer.\n')
    } else process.stdout.write(html)
  } catch { process.stderr.write('Could not verify or update the synthetic demo. Review the file locally.\n'); process.exitCode = 3 }
}
