import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'

// publicFiles are the files of public/ the shell needs (sw.js excepted).
const publicFiles = ['/manifest.webmanifest', '/icons/icon-192.png', '/icons/icon-512.png']

// swManifest writes dist/sw-manifest.json: the files of the shell the service
// worker precaches ("/", publicFiles and every built asset), and a version
// that changes with the built assets so a new build replaces the old cache.
// It also puts back dist/.gitkeep, which emptying dist removes.
function swManifest() {
  return {
    name: 'michel-sw-manifest',
    apply: 'build',
    generateBundle(_options, bundle) {
      const files = Object.keys(bundle)
        .filter((name) => name.startsWith('assets/'))
        .sort()
        .map((name) => `/${name}`)
      const version = files.map((f) => f.replace(/^\/assets\//, '')).join('|')
      let hash = 0
      for (const ch of version) hash = (Math.imul(hash, 31) + ch.codePointAt(0)) | 0
      this.emitFile({
        type: 'asset',
        fileName: 'sw-manifest.json',
        source: `${JSON.stringify({ version: (hash >>> 0).toString(16), files: ['/', ...publicFiles, ...files] }, null, 2)}\n`,
      })
      // go build needs web/dist even without a front.
      this.emitFile({ type: 'asset', fileName: '.gitkeep', source: '' })
    },
  }
}

export default defineConfig({
  plugins: [vue(), vuetify({ autoImport: true }), swManifest()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    // The CSP forbids inline code and data: scripts.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  server: {
    // npm run dev: the API comes from a running "michel serve".
    proxy: { '/api': 'http://127.0.0.1:7331' },
  },
})
