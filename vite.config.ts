import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// If you publish to https://<user>.github.io/log-checker/
// keep base as '/log-checker/'. If using a custom subdomain at root,
// change to '/'.
export default defineConfig({
  plugins: [react()],
  base: '/log-checker/',
})
