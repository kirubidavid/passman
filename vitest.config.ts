import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    maxWorkers: 1,
    pool: "threads",
    setupFiles: ["./tests/frontend/setup.ts"],
  },
});
