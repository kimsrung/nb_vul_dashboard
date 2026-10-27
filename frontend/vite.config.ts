import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const backendUrl = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/docs': {
        target: backendUrl,
        changeOrigin: true,
      },
      '/openapi.json': {
        target: backendUrl,
        changeOrigin: true,
      },
    },
  },
});
