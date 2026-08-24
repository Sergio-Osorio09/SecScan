import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// `base` debe coincidir con el nombre del repositorio para que GitHub Pages
// resuelva los assets. En dev y en Vercel/Cloudflare se sirve desde la raiz.
const base = process.env.DEPLOY_TARGET === 'gh-pages' ? '/SecScan/' : '/';

export default defineConfig({
  base,
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
