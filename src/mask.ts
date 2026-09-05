/**
 * Blank out the parts of a source file that are not code.
 *
 * Every rule that decides something by searching raw text has the same bug
 * waiting in it: prose counts as code. canship shipped two instances at once —
 * a route with `// TODO validate token` in it was treated as authenticated,
 * and a Firebase rules file containing `// allow read, write: if true;` was
 * reported as wide open. One caused a miss, the other a false positive, and
 * both came from the same place.
 *
 * Masking rather than deleting keeps every character offset intact, so line
 * numbers still point where they did. The output is the same length as the
 * input, with newlines preserved.
 *
 * Template literals are handled with more care than the rest: the literal text
 * is blanked but `${...}` is left alone, because the code inside really is
 * code. `` `Bearer ${token}` `` keeps its `token`, which is the difference
 * between recognising an authorisation header and inventing a finding.
 */

/**
 * The characters the maskers compare against, as UTF-16 code units.
 *
 * Every masker used to ask its questions with string comparisons — `src[i]`
 * against `'/'`, and `src.slice(i, i + 2)` against `'//'`. The second one
 * allocates a two-character string at *every character of every file*, and the
 * buffer those maskers wrote into was `src.split('')`, one string object per
 * character on top of that. Masking was 37% of the CPU of a whole scan, and
 * most of it was garbage.
 *
 * Comparing code units removes both. It is the same algorithm with the same
 * offsets; only the representation of "one character" changed.
 */
const SLASH = 0x2f
const STAR = 0x2a
const DOUBLE_QUOTE = 0x22
const SINGLE_QUOTE = 0x27
const BACKTICK = 0x60
const BACKSLASH = 0x5c
const DOLLAR = 0x24
const OPEN_BRACE = 0x7b
const CLOSE_BRACE = 0x7d
const NEWLINE = 0x0a
const SPACE = 0x20

/**
 * The working buffer: one UTF-16 code unit per character of the source.
 *
 * A Uint16Array rather than an array of one-character strings, for the reason
 * above. The round trip is exact — `charCodeAt` and `fromCharCode` are inverses
 * over every code unit, surrogate halves included — so a file holding emoji or
 * lone surrogates comes back byte for byte.
 */
export type MaskBuffer = Uint16Array

/** Copy the source into a buffer the maskers can blank in place */
export function codesOf(src: string): MaskBuffer {
  const out = new Uint16Array(src.length)
  for (let i = 0; i < src.length; i++) out[i] = src.charCodeAt(i)
  return out
}

/**
 * How many code units are handed to `fromCharCode` at once.
 *
 * It takes them as arguments, and an argument list is bounded by the stack, so
 * a whole file cannot go in one call.
 */
const CHUNK = 8192

/** Turn the buffer back into a string of exactly the same length */
export function stringOf(out: MaskBuffer): string {
  let text = ''
  for (let i = 0; i < out.length; i += CHUNK) {
    const end = i + CHUNK < out.length ? i + CHUNK : out.length
    text += String.fromCharCode.apply(null, out.subarray(i, end) as unknown as number[])
  }
  return text
}

/**
 * Blank a range, leaving newlines so line numbers survive.
 *
 * Exported because every masker in the codebase needs exactly this primitive
 * and maskSqlNoise had written its own identical copy. Preserving offsets is
 * the whole reason masking is used instead of deleting, so it is the one piece
 * that must not exist twice.
 */
export function blank(out: MaskBuffer, from: number, to: number): void {
  const end = to < out.length ? to : out.length
  for (let i = from; i < end; i++) {
    if (out[i] !== NEWLINE) out[i] = SPACE
  }
}

/**
 * Skip a quoted string starting at `start`, returning the index just past it.
 * Handles backslash escapes.
 */
function endOfString(src: string, start: number, quote: number): number {
  const length = src.length
  let i = start + 1
  while (i < length) {
    const ch = src.charCodeAt(i)
    if (ch === BACKSLASH) {
      i += 2
      continue
    }
    if (ch === quote) return i + 1
    i++
  }
  return length
}

/**
 * Blank a template literal's text while preserving its `${...}` expressions.
 * Returns the index just past the closing backtick.
 */
function maskTemplate(src: string, out: MaskBuffer, start: number): number {
  const length = src.length
  let i = start + 1
  let literalFrom = i

  while (i < length) {
    const ch = src.charCodeAt(i)
    if (ch === BACKSLASH) {
      i += 2
      continue
    }
    if (ch === BACKTICK) {
      blank(out, literalFrom, i)
      return i + 1
    }
    if (ch === DOLLAR && src.charCodeAt(i + 1) === OPEN_BRACE) {
      blank(out, literalFrom, i)
      // Walk to the matching brace. The expression inside is code and stays —
      // but the strings and comments *within* it are noise like any other, and
      // leaving them intact left a hole: `${"your session expired"}` reads as a
      // session lookup, and `${/* TODO validate token */ 1}` reads as a token
      // check. Both were enough to mark an unauthenticated route protected.
      let depth = 0
      let j = i + 1
      while (j < length) {
        const inner = src.charCodeAt(j)
        if (inner === SLASH) {
          const next = src.charCodeAt(j + 1)
          if (next === SLASH) {
            const end = src.indexOf('\n', j)
            const stop = end === -1 ? length : end
            blank(out, j, stop)
            j = stop
            continue
          }
          if (next === STAR) {
            const close = src.indexOf('*/', j + 2)
            const stop = close === -1 ? length : close + 2
            blank(out, j, stop)
            j = stop
            continue
          }
        }
        if (inner === DOUBLE_QUOTE || inner === SINGLE_QUOTE) {
          const stop = endOfString(src, j, inner)
          blank(out, j + 1, stop - 1)
          j = stop
          continue
        }
        if (inner === BACKTICK) {
          // A nested template. Recursing keeps its expressions readable too.
          j = maskTemplate(src, out, j)
          continue
        }
        if (inner === OPEN_BRACE) depth++
        else if (inner === CLOSE_BRACE) {
          depth--
          if (depth === 0) {
            j++
            break
          }
        }
        j++
      }
      i = j
      literalFrom = i
      continue
    }
    i++
  }

  blank(out, literalFrom, length)
  return length
}

/**
 * Blank comments only, leaving string contents intact.
 *
 * For the callers that need to *read* a string literal — a middleware matcher,
 * a header name — while still refusing to read one out of a comment. Masking
 * everything would erase the value they came for; masking nothing let a
 * commented-out `matcher: ['/api/:path*']` sitting above the real config
 * convince canship that a middleware protecting only /dashboard covered the
 * entire API.
 */
export function maskJsComments(src: string): string {
  const length = src.length
  const out = codesOf(src)
  let i = 0
  while (i < length) {
    const ch = src.charCodeAt(i)

    if (ch === SLASH) {
      const next = src.charCodeAt(i + 1)
      if (next === SLASH) {
        const end = src.indexOf('\n', i)
        const stop = end === -1 ? length : end
        blank(out, i, stop)
        i = stop
        continue
      }
      if (next === STAR) {
        const close = src.indexOf('*/', i + 2)
        const stop = close === -1 ? length : close + 2
        blank(out, i, stop)
        i = stop
        continue
      }
    }
    // Step over strings without touching them, so a `//` inside one — the `//`
    // of a URL, most often — does not start a comment.
    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE || ch === BACKTICK) {
      i = endOfString(src, i, ch)
      continue
    }
    i++
  }
  return stringOf(out)
}

/**
 * Blank comments and string contents in JavaScript-like source.
 *
 * Also correct enough for Firebase security rules, which use the same comment
 * syntax and the same quoting.
 */
export function maskJsNoise(src: string): string {
  const length = src.length
  const out = codesOf(src)
  let i = 0

  while (i < length) {
    const ch = src.charCodeAt(i)

    if (ch === SLASH) {
      const next = src.charCodeAt(i + 1)
      if (next === SLASH) {
        const end = src.indexOf('\n', i)
        const stop = end === -1 ? length : end
        blank(out, i, stop)
        i = stop
        continue
      }
      if (next === STAR) {
        const close = src.indexOf('*/', i + 2)
        const stop = close === -1 ? length : close + 2
        blank(out, i, stop)
        i = stop
        continue
      }
    }

    if (ch === DOUBLE_QUOTE || ch === SINGLE_QUOTE) {
      const stop = endOfString(src, i, ch)
      // Blank the contents but leave the quotes, so patterns anchored on a
      // quoted position still see the shape of the code.
      blank(out, i + 1, stop - 1)
      i = stop
      continue
    }

    if (ch === BACKTICK) {
      i = maskTemplate(src, out, i)
      continue
    }

    i++
  }

  return stringOf(out)
}

/**
 * The same two maskers, memoised per file.
 *
 * Masking is a full pass that rebuilds the source as a character array, and one
 * scan asks for it repeatedly on the same content: cors.ts wants the
 * comment-blanked copy twice, exposure.ts a third time, and apiauth.ts and
 * firebase.ts want the fully-blanked one — all for files the walker already
 * holds in memory. Keyed on the ScanFile object rather than on its text,
 * because a string cannot be a WeakMap key and the file objects are exactly the
 * right lifetime: the cache dies with the scan.
 */
const commentCache = new WeakMap<object, string>()
const noiseCache = new WeakMap<object, string>()

/** Comments blanked, string contents kept. Computed once per file. */
export function commentsMaskedOf(file: { content: string }): string {
  const hit = commentCache.get(file)
  if (hit !== undefined) return hit
  const masked = maskJsComments(file.content)
  commentCache.set(file, masked)
  return masked
}

/** Comments and string contents both blanked. Computed once per file. */
export function noiseMaskedOf(file: { content: string }): string {
  const hit = noiseCache.get(file)
  if (hit !== undefined) return hit
  const masked = maskJsNoise(file.content)
  noiseCache.set(file, masked)
  return masked
}
