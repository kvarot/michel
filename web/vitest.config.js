import { defineConfig } from 'vitest/config'

// Vitest runs the pure functions only: no DOM, no component.
export default defineConfig({
  test: { environment: 'node', include: ['src/**/*.test.js'] },
})
