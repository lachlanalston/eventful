import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        home:    'index.html',
        results: 'results.html',
      }
    }
  }
})
