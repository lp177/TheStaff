import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// In dev, the Vite server (5173) proxies API + WebSocket to the FastAPI
// backend (8000). In production the SPA is built to dist/ and served by FastAPI.
const BACKEND = process.env.THESTAFF_BACKEND || "http://localhost:8000";

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: BACKEND, changeOrigin: true },
      "/ws": { target: BACKEND.replace(/^http/, "ws"), ws: true },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
