import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Standalone dashboard UI for HI WAF. The build lands in ./dist.
// `--mode demo` builds a self-contained copy with sample data and no API (for design review
// and screenshots) into ./dist-demo.
// `npm run dev` proxies the API to a manager on https://localhost:9443 (override with HIWAF_API in .env).
export default defineConfig(({ mode }) => ({
  // '' = also load non-VITE_ keys from .env, for the dev proxy target below
  plugins: [react()],
  base: mode === 'demo' ? './' : '/',
  build: {
    outDir: mode === 'demo' ? 'dist-demo' : 'dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': { target: loadEnv(mode, process.cwd(), '').HIWAF_API || 'https://localhost:9443', secure: false, changeOrigin: true },
    },
  },
}))
