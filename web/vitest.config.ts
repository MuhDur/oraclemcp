/// <reference types="vitest/config" />
import { defineConfig } from "vitest/config";

// Dashboard contract tests run headlessly (react-dom/server, no DOM), so a
// plain node environment is enough and keeps the dev dependency surface to
// vitest alone. esbuild handles the react-jsx automatic runtime from tsconfig.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.{ts,tsx}"],
    globals: false
  }
});
