/**
 * Turning a character offset into a line number.
 *
 * Every rule that matches with a regex needs this, and five of them had their
 * own version: four byte-identical copies that counted newlines from the start
 * of the file on every match, and one — in secrets.ts — that built an index
 * once and binary-searched it, with a comment explaining that the counting form
 * "is quadratic in the file". The fix existed in the repository and could not
 * be reached, because it was private to the file that wrote it.
 *
 * The cost was not theoretical. MAX_FILE_BYTES is 2 MiB precisely so that a
 * long SQL migration is read in full, and a 282 KB schema with 5000 CREATE
 * TABLE statements — an ordinary machine-generated file — took 1507 ms against
 * 208 ms for 500, scaling superlinearly exactly as predicted. supabase.ts calls
 * it from four loops over every DDL match; cors.ts from four more.
 *
 * Build `lineStartsOf(content)` once per file, then ask `lineNumberAt` per
 * match.
 */

/**
 * Offset at which each line starts, so a line number costs a binary search.
 *
 * One pass is cheap; one pass per match is quadratic in the file, and a file
 * full of matches is exactly the input that produces a lot of them — the two
 * costs multiplied.
 */
export function lineStartsOf(content: string): number[] {
  const starts = [0]
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') starts.push(i + 1)
  }
  return starts
}

/** Resolve a 1-based line number from a character offset */
export function lineNumberAt(lineStarts: number[], index: number): number {
  let lo = 0
  let hi = lineStarts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (lineStarts[mid]! <= index) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}
