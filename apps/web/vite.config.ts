import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";

const version = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf-8")).version as string;
/** The built bundle says which version it is, so the server can tell a half-applied update from a whole one. */
/** One stamp per build, in the bundle and in version.json: a tab that loaded an older build of the same version can tell. */
const builtAt = new Date().toISOString();
const versionFile = { name: "saw-version-file", generateBundle(this: any) {
  this.emitFile({ type: "asset", fileName: "version.json", source: JSON.stringify({ version, built_at: builtAt }) });
} };

export default defineConfig({
  plugins: [react(), versionFile],
  define: { __APP_VERSION__: JSON.stringify(version), __APP_BUILT_AT__: JSON.stringify(builtAt) },
  server: {
    port: 5180,
    proxy: { "/api": { target: "http://127.0.0.1:8100", changeOrigin: false } },
  },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 2000 },
  test: { environment: "jsdom", globals: true },
});
