/** 按常见终端列宽估算中日韩字符及 emoji；不改写原文。 */
import { stripVTControlCharacters } from 'node:util'

const segmenter = typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function'
  ? new Intl.Segmenter('en', { granularity: 'grapheme' }) : null
const wide = /\p{Script=Han}|\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Hangul}|\p{Script=Bopomofo}|[\u3000-\u303f\uff01-\uff60\uffe0-\uffe6]/u
const emoji = /\p{Emoji_Presentation}|\p{Regional_Indicator}|\u20e3|\ufe0f/u
const marks = /[\p{Mark}\u200d\ufe0e\ufe0f]/gu

export function visibleWidth(input: string): number {
  const text = stripVTControlCharacters(input)
  if (/^[\x20-\x7e]*$/.test(text)) return text.length
  const parts = segmenter ? Array.from(segmenter.segment(text), part => part.segment) : Array.from(text)
  let width = 0
  for (const part of parts) {
    if (part === '\t') { width += 8 - width % 8; continue }
    const base = part.replace(marks, '')
    if (!base || /^[\u0000-\u001f\u007f-\u009f]+$/.test(base)) continue
    // 半角假名使用单列；组合附标不增加宽度。
    width += /^[\uff61-\uffdc]+$/.test(base) ? [...base].length : wide.test(base) || emoji.test(part) ? 2 : 1
  }
  return width
}
