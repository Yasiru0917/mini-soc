import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Vite configuration.
// - react():       enables JSX + fast refresh while developing.
// - tailwindcss(): Tailwind v4 plugin (v4 needs no tailwind.config.js).
//
// server.proxy: the browser only ever talks to http://localhost:5173.
// Requests to /api/... are forwarded by Vite to FastAPI on port 8000.
// Because browser and API share ONE origin, the login cookie can be
// SameSite=Strict and we don't need to open up CORS at all.
// xfwd adds X-Forwarded-For so the backend logs the real client IP.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', xfwd: true },
    },
  },
})
