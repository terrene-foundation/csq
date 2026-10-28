// Imported from `vitest/config` (not `vite`) so the `test` block is
// recognized by the TS type-checker. `defineConfig` from vitest is a
// superset of Vite's and returns a compatible config object. The
// `tsc -p tsconfig.node.json` step checks this file.
import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte({ compilerOptions: { hmr: false } })],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    alias: [{ find: /^svelte$/, replacement: "svelte" }],
    server: {
      deps: {
        inline: [/svelte/],
      },
    },
  },
  resolve: {
    conditions: ["browser"],
  },
});
