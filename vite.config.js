import { defineConfig } from 'vite'

export default defineConfig({
  base: './',
  build: {
    outDir: 'docs',
    rollupOptions: {
      input: {
        home:               'index.html',
        eventLookup:        'event-lookup.html',
        eventResults:       'event-results.html',
        windowsLogAnalyzer: 'windows-log-analyzer.html',
        macosLogAnalyzer:   'macos-log-analyzer.html',
      }
    }
  }
})
