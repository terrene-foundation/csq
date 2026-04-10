import { defineConfig } from "vite";
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
