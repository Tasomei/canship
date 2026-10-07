/** 工厂模块仅从已扫描源码解析；不加载配置脚本、依赖或项目外文件。 */
import { posix } from 'node:path'
import type { ScanFile } from '../types.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'
import { bindingModule } from './apiauth.js'

interface Resolution { handled: boolean; file: ScanFile | null; limited?: boolean }
const unknown = (limited = false): Resolution => ({ handled: true, file: null, ...(limited ? { limited: true } : {}) })
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value)
const safePath = (path: string): boolean => Boolean(path) && path.length <= 512 && !/[\\\u0000-\u0020:%?#]/.test(path) && !posix.isAbsolute(path)
const contained = (path: string): boolean => path !== '..' && !path.startsWith('../') && !posix.isAbsolute(path)

/** JSONC 仅移除注释和字符串外的尾逗号，不求值。 */
function metadata(file: ScanFile): Record<string, unknown> | null {
  if (file.content.length > 65536) return null
  let source = commentsMaskedOf(file)
  const code = noiseMaskedOf(file)
  const commas = [...code.matchAll(/,\s*[}\]]/g)].map(match => match.index)
  if (commas.length) {
    const characters = source.split('')
    for (const at of commas) characters[at] = ' '
    source = characters.join('')
  }
  try { const value: unknown = JSON.parse(source); return object(value) ? value : null } catch { return null }
}

/** 条件分支须收敛到同一运行时入口；类型分支不提供运行时证据。 */
function exportTarget(value: unknown, limit: () => void, depth = 0): string | null {
  if (depth >= 8) { limit(); return null }
  if (typeof value === 'string') return value.startsWith('./') && safePath(value) && !value.includes('*') &&
    value.split('/').slice(1).every(part => part !== '.' && part !== '..' && part !== 'node_modules') ? value : null
  if (!object(value)) return null
  if (Object.keys(value).length > 32) { limit(); return null }
  const entries = Object.entries(value).filter(([key]) => key !== 'types' && !key.startsWith('types@'))
  if (!entries.length || entries.some(([key]) => key.startsWith('.'))) return null
  const targets = entries.map(([, item]) => exportTarget(item, limit, depth + 1))
  return targets.every(target => target !== null && target === targets[0]) ? targets[0]! : null
}

export function factoryModuleResolver(files: ScanFile[]): (spec: string, from: ScanFile) => Resolution {
  const byPath = new Map(files.map(file => [file.path, file]))
  const parsed = new Map<ScanFile, Record<string, unknown> | null>()
  let metadataLimited = false
  const json = (file: ScanFile): Record<string, unknown> | null => {
    if (file.content.length > 65536) { metadataLimited = true; return null }
    if (!parsed.has(file)) parsed.set(file, metadata(file))
    return parsed.get(file)!
  }
  const parents = (file: ScanFile): string[] => {
    const found: string[] = []
    for (let dir = posix.dirname(file.path); ; dir = posix.dirname(dir)) {
      found.push(dir)
      if (dir === '.' || posix.dirname(dir) === dir) break
    }
    return found
  }
  const nearest = (file: ScanFile, names: string[]): ScanFile | undefined => {
    for (const dir of parents(file)) for (const name of names) {
      const found = byPath.get(posix.join(dir, name))
      if (found) return found
    }
    return undefined
  }
  const sourceAt = (path: string, from: ScanFile): ScanFile | null => {
    if (!contained(path)) return null
    const relative = posix.relative(posix.dirname(from.path), path)
    return bindingModule(relative.startsWith('.') ? relative : './' + relative, from, files, '')
  }
  const configPath = (spec: string, from: ScanFile): Resolution | null => {
    const config = nearest(from, ['tsconfig.json', 'jsconfig.json'])
    if (!config) return null
    if (config.content.length > 65536) return unknown(true)
    const data = json(config)
    if (!data || 'extends' in data || 'references' in data) return unknown()
    const options = data.compilerOptions
    if (options === undefined) return null
    if (!object(options)) return unknown()
    if (options.paths === undefined) return null
    if (!object(options.paths)) return unknown()
    if (Object.keys(options.paths).length > 128) return unknown(true)
    const matches: { target: unknown; prefix: string; suffix: string; middle: string; exact: boolean }[] = []
    for (const [pattern, target] of Object.entries(options.paths)) {
      if (pattern.length > 512) return unknown(true)
      if (pattern.split('*').length > 2) return unknown()
      const [prefix, suffix = ''] = pattern.split('*')
      const exact = !pattern.includes('*')
      if (exact ? pattern !== spec : !spec.startsWith(prefix!) || !spec.endsWith(suffix) || spec.length < prefix!.length + suffix.length) continue
      matches.push({ target, prefix: prefix!, suffix, exact, middle: exact ? '' : spec.slice(prefix!.length, spec.length - suffix.length) })
    }
    if (!matches.length) return null
    matches.sort((a, b) => Number(b.exact) - Number(a.exact) || b.prefix.length - a.prefix.length)
    const selected = matches[0]!
    if (matches[1] && matches[1].exact === selected.exact && matches[1].prefix.length === selected.prefix.length) return unknown()
    if (!Array.isArray(selected.target) || selected.target.length !== 1 || typeof selected.target[0] !== 'string') return unknown()
    const target = selected.target[0]
    if (!safePath(target) || target.split('*').length > 2 || (selected.exact && target.includes('*'))) return unknown()
    const base = options.baseUrl ?? '.'
    if (typeof base !== 'string' || !safePath(base) || base.includes('*')) return unknown()
    const path = posix.normalize(posix.join(posix.dirname(config.path), base, target.replace('*', selected.middle)))
    return { handled: true, file: sourceAt(path, from) }
  }
  const manifests = files.filter(file => /(?:^|\/)package\.json$/.test(file.path))
  const workspace = (spec: string, from: ScanFile): Resolution | null => {
    const name = spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!
    const subpath = spec === name ? '.' : '.' + spec.slice(name.length)
    const owner = nearest(from, ['package.json'])
    if (!owner) return null
    if (owner.content.length > 65536) return unknown(true)
    const ownerData = json(owner)
    const deps = ownerData?.dependencies
    const link = object(deps) ? deps[name] : undefined
    if (typeof link !== 'string' || !/^workspace:(?:\*|\^|~)$/.test(link)) return null
    const roots = parents(owner).map(dir => byPath.get(posix.join(dir, 'package.json'))).filter((file): file is ScanFile => Boolean(file))
    if (roots.some(file => file.content.length > 65536)) return unknown(true)
    const root = roots.find(file => json(file)?.workspaces !== undefined)
    if (!root) return unknown()
    const raw = json(root)!.workspaces
    const patterns = Array.isArray(raw) ? raw : object(raw) ? raw.packages : null
    if (!Array.isArray(patterns)) return unknown()
    if (patterns.length > 64) return unknown(true)
    if (patterns.some(item => typeof item !== 'string' || !safePath(item) || item.split('*').length > 2)) return unknown()
    const rootDir = posix.dirname(root.path)
    const matched = manifests.filter(file => {
      const dir = posix.relative(rootDir, posix.dirname(file.path))
      return Boolean(dir) && contained(dir) && patterns.some((pattern: string) => {
        const [before, after = ''] = pattern.replace(/\/$/, '').split('*')
        return pattern.includes('*') ? dir.length >= before!.length + after.length && dir.startsWith(before!) && dir.endsWith(after) &&
          !dir.slice(before!.length, dir.length - after.length).includes('/') : dir === before
      }) && json(file)?.name === name
    })
    if (matched.length !== 1) return unknown()
    const manifest = matched[0]!, data = json(manifest)!
    let target: string | null
    if ('exports' in data) {
      const value = data.exports
      if (object(value) && Object.keys(value).some(key => key.startsWith('.')) && Object.keys(value).some(key => !key.startsWith('.'))) return unknown()
      const entry = object(value) && Object.keys(value).some(key => key.startsWith('.')) ? value[subpath] : subpath === '.' ? value : null
      let limited = false
      target = exportTarget(entry, () => { limited = true })
      if (limited) return unknown(true)
    } else target = subpath === '.' && typeof data.main === 'string' && (!data.module || data.module === data.main) ? data.main : null
    if (!target || !safePath(target)) return unknown()
    const dir = posix.dirname(manifest.path), path = posix.normalize(posix.join(dir, target))
    if (!contained(posix.relative(dir, path))) return unknown()
    return { handled: true, file: sourceAt(path, from) }
  }
  const resolve = (spec: string, from: ScanFile): Resolution => {
    if (!spec || spec.length > 512 || /[\\\u0000-\u0020:%?]/.test(spec) || posix.isAbsolute(spec)) return unknown()
    if (spec.startsWith('.')) return { handled: true, file: bindingModule(spec, from, files, '') }
    const configured = configPath(spec, from)
    if (configured) return configured
    const local = workspace(spec, from)
    if (local) return local
    const scope = /^(.*?\/)?(?:src|app|lib|server|routes|api|controllers|plugins)\//.exec(from.path)?.[1] ?? ''
    const file = bindingModule(spec, from, files, scope)
    return { handled: Boolean(file), file }
  }
  return (spec, from) => {
    metadataLimited = false
    const result = resolve(spec, from)
    if (result.file && (!/\.[mc]?[jt]sx?$/.test(result.file.path) || /\.d\.[cm]?ts$/.test(result.file.path))) return unknown()
    return metadataLimited ? unknown(true) : result
  }
}
