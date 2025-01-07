import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  root: 'src/admin',
  base: '/admin/', // Set back to /admin/
  build: {
    outDir: resolve(__dirname, 'dist/admin'),
    emptyOutDir: true
  },
  server: {
    proxy: {
      '/socket.io': {
        target: 'http://localhost:3000',
        ws: true,
        secure: false
      },
      '^/admin/.*': {  // Changed to match all admin routes
        target: 'http://localhost:3000',
        secure: false,
        changeOrigin: true
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src/admin')
    }
  }
});
