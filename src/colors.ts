/** 无外部依赖的终端颜色工具。 */

// 通过字符码构造转义符，避免源码包含不可见控制字符。
const ESC = String.fromCharCode(27)

/** 遵循 NO_COLOR，非终端输出默认关闭颜色。 */
const enabled = (() => {
  if (process.env['NO_COLOR']) return false
  if (process.env['FORCE_COLOR']) return true
  return process.stdout.isTTY === true
})()

const wrap =
  (open: number, close: number) =>
  (s: string): string =>
    enabled ? `${ESC}[${open}m${s}${ESC}[${close}m` : s

export const bold = wrap(1, 22)
export const dim = wrap(2, 22)
export const red = wrap(31, 39)
export const green = wrap(32, 39)
export const yellow = wrap(33, 39)
export const cyan = wrap(36, 39)
export const gray = wrap(90, 39)
