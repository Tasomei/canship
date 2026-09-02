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
 * Blank a range, leaving newlines so line numbers survive.
 *
 * Exported because every masker in the codebase needs exactly this primitive
 * and maskSqlNoise had written its own identical copy. Preserving offsets is
 * the whole reason masking is used instead of deleting, so it is the one piece
 * that must not exist twice.
 */
export function blank(out: string[], from: number, to: number): void {
  for (let i = from; i < to && i < out.length; i++) {
    if (out[i] !== '\n') out[i] = ' '
  }
}

/**
 * Skip a quoted string starting at `start`, returning the index just past it.
 * Handles backslash escapes.
 */
function endOfString(src: string, start: number, quote: string): number {
  let i = start + 1
  while (i < src.length) {
    if (src[i] === '\\') {
      i += 2
      continue
    }
    if (src[i] === quote) return i + 1
    i++
  }
  return src.length
}

/**
 * Blank a template literal's text while preserving its `${...}` expressions.
 * Returns the index just past the closing backtick.
 */
function maskTemplate(src: string, out: string[], start: number): number {
  let i = start + 1
  let literalFrom = i

  while (i < src.length) {
    if (src[i] === '\\') {
      i += 2
      continue
    }
    if (src[i] === '`') {
      blank(out, literalFrom, i)
      return i + 1
    }
    if (src[i] === '$' && src[i + 1] === '{') {
      blank(out, literalFrom, i)
      // Walk to the matching brace. The expression inside is code and stays —
      // but the strings and comments *within* it are noise like any other, and
      // leaving them intact left a hole: `${"your session expired"}` reads as a
      // session lookup, and `${/* TODO validate token */ 1}` reads as a token
      // check. Both were enough to mark an unauthenticated route protected.
      let depth = 0
      let j = i + 1
      while (j < src.length) {
        const ch = src[j]!
        const pair = src.slice(j, j + 2)
        if (pair === '//') {
          const end = src.indexOf('\n', j)
          const stop = end === -1 ? src.length : end
          blank(out, j, stop)
          j = stop
          continue
        }
        if (pair === '/*') {
          const close = src.indexOf('*/', j + 2)
          const stop = close === -1 ? src.length : close + 2
          blank(out, j, stop)
          j = stop
          continue
        }
        if (ch === '"' || ch === "'") {
          const stop = endOfString(src, j, ch)
          blank(out, j + 1, stop - 1)
          j = stop
          continue
        }
        if (ch === '`') {
          // A nested template. Recursing keeps its expressions readable too.
          j = maskTemplate(src, out, j)
          continue
        }
        if (ch === '{') depth++
        else if (ch === '}') {
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

  blank(out, literalFrom, src.length)
  return src.length
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
  const out = src.split('')
  let i = 0
  while (i < src.length) {
    const ch = src[i]!
    const two = src.slice(i, i + 2)

    if (two === '//') {
      const end = src.indexOf('\n', i)
      const stop = end === -1 ? src.length : end
      blank(out, i, stop)
      i = stop
      continue
    }
    if (two === '/*') {
      const close = src.indexOf('*/', i + 2)
      const stop = close === -1 ? src.length : close + 2
      blank(out, i, stop)
      i = stop
      continue
    }
    // Step over strings without touching them, so a `//` inside one — the `//`
    // of a URL, most often — does not start a comment.
    if (ch === '"' || ch === "'" || ch === '`') {
      i = endOfString(src, i, ch)
      continue
    }
    i++
  }
  return out.join('')
}

/**
 * Blank comments and string contents in JavaScript-like source.
 *
 * Also correct enough for Firebase security rules, which use the same comment
 * syntax and the same quoting.
 */
export function maskJsNoise(src: string): string {
  const out = src.split('')
  let i = 0

  while (i < src.length) {
    const ch = src[i]!
    const two = src.slice(i, i + 2)

    if (two === '//') {
      const end = src.indexOf('\n', i)
      const stop = end === -1 ? src.length : end
      blank(out, i, stop)
      i = stop
      continue
    }

    if (two === '/*') {
      const close = src.indexOf('*/', i + 2)
      const stop = close === -1 ? src.length : close + 2
      blank(out, i, stop)
      i = stop
      continue
    }

    if (ch === '"' || ch === "'") {
      const stop = endOfString(src, i, ch)
      // Blank the contents but leave the quotes, so patterns anchored on a
      // quoted position still see the shape of the code.
      blank(out, i + 1, stop - 1)
      i = stop
      continue
    }

    if (ch === '`') {
      i = maskTemplate(src, out, i)
      continue
    }

    i++
  }

  return out.join('')
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
