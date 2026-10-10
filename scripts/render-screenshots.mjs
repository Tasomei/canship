/** 用临时合成项目重新生成 README 截图；只扫描临时目录，显式 --write 才覆盖 docs/images。 */
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repo = fileURLToPath(new URL('..', import.meta.url))
const cli = join(repo, 'dist', 'cli.js')
const display = '~/acme-shop'
const args = process.argv.slice(2)
if (args.length > 1 || (args.length === 1 && args[0] !== '--write')) {
  process.stderr.write('Use --write to replace docs/images, or no option to write into a temporary directory.\n')
  process.exit(3)
}
if (!existsSync(cli)) { process.stderr.write('Run npm run build first.\n'); process.exit(3) }

const chrome = [process.env['CHROME_PATH'], 'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe', '/usr/bin/google-chrome', '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].find(path => path && existsSync(path))
if (!chrome) { process.stderr.write('Set CHROME_PATH to a local Chrome or Edge executable.\n'); process.exit(3) }

const work = mkdtempSync(join(tmpdir(), 'canship-shots-'))
const project = join(work, 'acme-shop')

// 合成凭据在运行时拼接，源码中不出现任何形似真实令牌的字面量。
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url')
const serviceRole = [b64({ alg: 'HS256', typ: 'JWT' }),
  b64({ iss: 'supabase', ref: 'acmeshopsynthetic', role: 'service_role', iat: 1767225600, exp: 2082758400 }),
  Buffer.from('synthetic-signature-not-a-real-key-000000').toString('base64url')].join('.')

const files = {
  '.env.local': ['NEXT_PUBLIC_SUPABASE_URL=https://acmeshopsynthetic.supabase.co',
    `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${serviceRole}`, ''].join('\n'),
  'package.json': JSON.stringify({ name: 'acme-shop', private: true, dependencies: { next: '15.0.0',
    '@supabase/supabase-js': '2.45.0', '@prisma/client': '5.20.0', stripe: '16.0.0' } }, null, 2),
  'lib/supabase-admin.ts': ["import { createClient } from '@supabase/supabase-js'", '',
    'export const supabaseAdmin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)', ''].join('\n'),
  'lib/prisma.ts': ["import { PrismaClient } from '@prisma/client'", '', 'export const prisma = new PrismaClient()', ''].join('\n'),
  // 路由名保持简短，使人工步骤在默认 96 列内不折行。
  'app/api/users/route.ts': ["import { supabaseAdmin } from '@/lib/supabase-admin'", '',
    'export async function GET() {',
    "  const { data } = await supabaseAdmin.from('profiles').select('*')",
    '  return Response.json(data)', '}', ''].join('\n'),
  'app/api/products/route.ts': ["import { NextRequest } from 'next/server'", "import { prisma } from '@/lib/prisma'", '',
    'export async function GET(request: NextRequest) {',
    "  const q = request.nextUrl.searchParams.get('q')",
    '  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM products WHERE name LIKE \'%${q}%\'`)',
    '  return Response.json(rows)', '}', ''].join('\n'),
  'app/api/webhooks/stripe/route.ts': ["import Stripe from 'stripe'", "import { fulfilOrder } from '@/lib/orders'", '',
    'const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)', '',
    'export async function POST(request: Request) {', '  const event = await request.json()',
    "  if (event.type === 'checkout.session.completed') await fulfilOrder(event.data.object)",
    '  return new Response(null, { status: 200 })', '}', ''].join('\n'),
  'app/api/preview/route.ts': ["import { NextRequest } from 'next/server'", '',
    'export async function GET(request: NextRequest) {',
    "  const target = request.nextUrl.searchParams.get('url')",
    '  const response = await fetch(target)', '  return new Response(await response.text())', '}', ''].join('\n'),
  'app/auth/confirm/route.ts': ["import { NextRequest, NextResponse } from 'next/server'", '',
    'export async function GET(request: NextRequest) {',
    "  const next = request.nextUrl.searchParams.get('next') ?? '/'",
    '  return NextResponse.redirect(new URL(next, request.url))', '}', ''].join('\n'),
  'supabase/migrations/20260901000000_init.sql': ['create table public.orders (',
    '  id uuid primary key default gen_random_uuid(),', '  customer_email text not null,',
    '  total_cents integer not null,', '  paid boolean default false', ');', ''].join('\n'),
}
for (const [name, content] of Object.entries(files)) {
  const path = join(project, name)
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, content)
}

/** 把临时目录替换为展示路径，并去掉随提交变化的构建标识。 */
const scrub = text => text.split(project).join(display).split(project.replace(/\\/g, '/')).join(display)
  .replace(/(\d+\.\d+\.\d+\S*) \((?:prerelease|development|release)[^)]*\)/g, '$1')

// 在项目目录内运行，后续命令与 README 中的 npx canship 一致。
const scan = spawnSync(process.execPath, [cli], { cwd: project, encoding: 'utf8',
  env: { ...process.env, FORCE_COLOR: '1', NO_COLOR: '' } })
if (scan.status === 3 || scan.status === null) { process.stderr.write(scan.stderr); process.exit(3) }
const terminal = scrub(scan.stdout)
const reportPath = join(work, 'report.html')
spawnSync(process.execPath, [cli, `--report=${reportPath}`], { cwd: project, encoding: 'utf8',
  env: { ...process.env, NO_COLOR: '1' } })
const report = scrub(readFileSync(reportPath, 'utf8'))
if (report.includes(project) || terminal.includes(project) || /canship-shots-/.test(report + terminal)) {
  process.stderr.write('Temporary path remained in the rendered output.\n'); process.exit(3)
}
writeFileSync(reportPath, report)

// 终端截图：解析颜色码，渲染为窗口样式；页面背景透明，截图尺寸取窗口实际大小。
const escapeHtml = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
// 字重与颜色分开跟踪：22 只结束粗体/暗色，39 只结束颜色，其余属性保持。
const weights = { 1: 'b', 2: 'd' }, colors = { 31: 'r', 32: 'g', 33: 'y', 36: 'c', 90: 'd' }
let weight = '', color = ''
const body = escapeHtml(`$ npx canship\n${terminal.replace(/\n+$/, '')}`).replace(/\u001b\[(\d+)m/g, (_, code) => {
  const n = Number(code)
  const wasOpen = weight || color
  if (weights[n]) weight = weights[n]
  else if (colors[n]) color = colors[n]
  else if (n === 22) weight = ''
  else if (n === 39) color = ''
  else if (n === 0) weight = color = ''
  else return ''
  const classes = [weight, color].filter(Boolean).join(' ')
  return (wasOpen ? '</span>' : '') + (classes ? `<span class="${classes}">` : '')
})
const terminalHtml = `<!doctype html><html lang="en"><meta charset="utf-8"><style>
html,body{margin:0;background:transparent}
.w{background:#1c1c26;border-radius:10px;overflow:hidden;width:max-content}
.t{height:30px;background:#151520;display:flex;gap:8px;align-items:center;padding:0 14px}
.t i{width:12px;height:12px;border-radius:50%;background:#3a3a46;display:block}
pre{margin:0;padding:16px 22px 20px;font:15px/1.55 "Cascadia Mono",Consolas,monospace;color:#d6d6e0}
.b{font-weight:700}.d{color:#8a8a99}.r{color:#f0707f}.y{color:#e8b85c}.g{color:#7fcf8a}.c{color:#7fc6d6}
</style><div class="w"><div class="t"><i></i><i></i><i></i></div><pre>${body}</pre></div>
<script>const r=document.querySelector('.w').getBoundingClientRect();document.body.dataset.size=Math.ceil(r.width)+'x'+Math.ceil(r.height)</script></html>`
const terminalPath = join(work, 'terminal.html')
writeFileSync(terminalPath, terminalHtml)

const shots = args[0] === '--write' ? join(repo, 'docs', 'images') : work
const browser = (page, extra, scheme = 'light') => execFileSync(chrome, ['--headless=new', '--disable-gpu', '--no-first-run',
  '--hide-scrollbars', `--user-data-dir=${join(work, 'profile')}`, `--blink-settings=preferredColorScheme=${scheme === 'light' ? 1 : 0}`,
  ...extra, `file:///${page.replace(/\\/g, '/')}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
// 先在足够大的视口中量出终端窗口尺寸，再按该尺寸截图，避免窗口外出现留白或底色。
const measured = /data-size="(\d+)x(\d+)"/.exec(browser(terminalPath, ['--window-size=1400,4000', '--dump-dom'], 'dark'))
if (!measured) { process.stderr.write('Could not measure the terminal window.\n'); process.exit(3) }
browser(terminalPath, [`--window-size=${measured[1]},${measured[2]}`, '--force-device-scale-factor=2',
  '--default-background-color=00000000', `--screenshot=${join(shots, 'terminal.png')}`], 'dark')
// 报告只截首屏：结论、统计、分类、人工步骤及前几条结果。
browser(reportPath, ['--window-size=1100,1090', '--force-device-scale-factor=2', `--screenshot=${join(shots, 'report.png')}`])
rmSync(join(work, 'profile'), { recursive: true, force: true })
process.stdout.write(`Screenshots written to ${shots}\nScan exit status: ${scan.status}\n`)
if (args[0] === '--write') rmSync(work, { recursive: true, force: true })
