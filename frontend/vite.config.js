import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const backendTarget = env.VITE_API_TARGET || env.BACKEND_URL || 'http://127.0.0.1:8123'

  return {
    plugins: [react()],
    server: {
      proxy: {
        '/api': {
          // Default to the local backend for normal development. For a LAN exercise,
          // set VITE_API_TARGET=http://<host-ip>:8123 or BACKEND_URL=http://<host-ip>:8123.
          target: backendTarget,
          changeOrigin: true,
          secure: false,
        },
      },
    },
  }
})
