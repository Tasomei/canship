/**
 * Minimal ANSI colour helpers.
 *
 * Not pulling in picocolors or chalk is deliberate: canship is distributed via
 * `npx canship`, so every runtime dependency adds to the cold-start download.
 * This much code is not worth a dependency.
 */

// Build ESC from a char code so the source file contains no invisible control
// characters, which tend to confuse editors and patch tools.
const ESC = String.fromCharCode(27)

/**
 * Whether to emit colour at all.
 * Honours the NO_COLOR convention (https://no-color.org/) and switches itself
 * off when the output is piped.
 */
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
