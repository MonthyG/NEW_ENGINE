import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The normal build lands in the manager's embed directory. `--mode demo` builds a self-contained copy
// with sample data and no API (for design review and screenshots) into console/dist-demo.
// `npm run dev` proxies the API to a manager on https://localhost:9443 (override with HIWAF_API).
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === 'demo' ? './' : '/',
  build: {
    outDir: mode === 'demo' ? 'dist-demo' : '../manager/console/dist',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': { target: process.env.HIWAF_API || 'https://localhost:9443', secure: false, changeOrigin: true },
    },
  },
}))
