import { defineConfig } from 'tsup'
import { readFileSync } from 'node:fs'

/**
 * The version lives in package.json and nowhere else.
 *
 * It used to be written out a second time in src/cli.ts, which is the kind of
 * duplication that stays correct right up until a release and then reports the
 * wrong number to everyone who runs --version.
 */
const { version } = JSON.parse(readFileSync('./package.json', 'utf8')) as { version: string }

export default defineConfig({
  entry: ['src/cli.ts'],
  format: ['esm'],
  target: 'node18',
  // Bundle into a single file to keep the npx download and cold start small
  bundle: true,
  splitting: false,
  clean: true,
  minify: false,
  sourcemap: false,
  define: { __CANSHIP_VERSION__: JSON.stringify(version) },
  // npx executes dist/cli.js directly, so it needs a shebang
  banner: { js: '#!/usr/bin/env node' },
})
