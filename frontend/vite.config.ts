import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
export default defineConfig({
  plugins: [vue()],
  base: "/static/ui/",
  build: { outDir: "../static/ui", emptyOutDir: true, manifest: true },
});
