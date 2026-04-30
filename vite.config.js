import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  build: {
    outDir: 'docs',
    rollupOptions: {
      input: {
        home:     'index.html',
        results:  'results.html',
        analyzer: 'analyzer.html',
      }
    }
  }
})
