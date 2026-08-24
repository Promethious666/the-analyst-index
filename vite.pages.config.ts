import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  base: "/the-analyst-index/",
  root: resolve(projectRoot, "pages-src"),
  publicDir: resolve(projectRoot, "public"),
  plugins: [react()],
  build: {
    outDir: resolve(projectRoot, "docs"),
    emptyOutDir: true,
  },
});
