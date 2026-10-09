import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Forward /api/* to the local Express server
      '/api': {
        target: 'http://127.0.0.1:3001',
        changeOrigin: false,
        // Forward cookies so session auth works
        configure: (proxy) => {
          proxy.on('error', (_err, _req, res) => {
            (res as import('node:http').ServerResponse).writeHead(503, { 'Content-Type': 'application/json' });
            (res as import('node:http').ServerResponse).end(JSON.stringify({
              error: 'Backend unavailable. Start the API server with: npm run dev:server',
            }));
          });
        },
      },
    },
  },
})
