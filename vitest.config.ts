import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@aegis/shared-types': fileURLToPath(
        new URL('./packages/shared-types/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    include: ['{apps,packages}/*/tests/**/*.test.ts'],
    // The gateway writes an audit line per security decision; only show it when a test fails.
    silent: 'passed-only',
    // Suites that use Postgres share one database, so files run one at a time.
    fileParallelism: false,
  },
})
