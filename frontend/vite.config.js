import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Vite configuration.
// - react():       enables JSX + fast refresh while developing.
// - tailwindcss(): Tailwind v4 plugin (v4 needs no tailwind.config.js).
//
// Phase 3 will add a `server.proxy` entry here so that requests to /api
// are forwarded to the FastAPI backend. That keeps the browser talking to
// ONE origin, which lets us use secure HttpOnly cookies for login.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
  },
})
