// Vitest config — closes gap R4. INSTALL: copy to workers/vitest.config.mjs
// Add to workers/package.json:  "scripts": { "test": "vitest run" }
// and devDependency:           "vitest": "^2.0.0"
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.mjs', 'test/**/*.test.js'],
    environment: 'node',
    reporters: ['dot'],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      thresholds: { lines: 60, functions: 60, branches: 50, statements: 60 }
    }
  }
});
