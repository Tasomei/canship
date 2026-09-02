/**
 * How much one file may contribute to a report.
 *
 * One number, in one place, because it had become three: secrets.ts and
 * firebase.ts each declared their own `MAX_FINDINGS_PER_FILE = 100` and
 * supabase.ts a `MAX_UNPROTECTED_TABLES = 100`, all meaning the same thing and
 * all free to drift.
 *
 * The reasoning behind the number is the same wherever it is used. Every
 * finding carries several paragraphs of explanation, so the report grows far
 * faster than the input that caused it: a `.rules` file with 3000 open rules
 * produced 3000 findings, 3.6 MB of JSON and 72,010 lines of terminal output.
 * A hundred distinct problems of one kind in one file is already a different
 * conversation than a list, and a crafted file can hold tens of thousands.
 *
 * Reaching it is never silent — every caller reports through
 * `ctx.reportIncomplete`, which the engine deduplicates, so a rule that hits
 * the ceiling from more than one loop still says so exactly once.
 */
export const MAX_FINDINGS_PER_FILE = 100
