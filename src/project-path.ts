/** 配置引用必须保留在项目边界内。 */
import { realpathSync } from 'node:fs'
import { isAbsolute, relative, resolve } from 'node:path'
import { CONFIG_FILENAME } from './config.js'

export class ProjectPathError extends Error {}

export function insideProject(root: string, path: string): string {
  const target = resolve(root, path)
  const inside = relative(realPathOf(root), realPathOf(target))
  if (inside === '' || inside.startsWith('..') || isAbsolute(inside)) {
    throw new ProjectPathError(`${CONFIG_FILENAME}: "baseline" must stay inside the project, and ${path} does not`)
  }
  return target
}

/** 向上查找最近存在的祖先，限制缺失路径的解析深度。 */
function realPathOf(path: string): string {
  let at = path
  const rest: string[] = []
  for (let depth = 0; depth < 64; depth++) {
    try {
      const real = realpathSync(at)
      return rest.length === 0 ? real : resolve(real, ...rest)
    } catch {
      const parent = resolve(at, '..')
      if (parent === at) return path
      rest.unshift(relative(parent, at))
      at = parent
    }
  }
  return path
}
