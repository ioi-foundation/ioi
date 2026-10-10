import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createReadStream } from 'node:fs'
import { checkModelIntegrity } from './scripts/avatars/check_model_integrity.mjs'

const appRoot = fileURLToPath(new URL('.', import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), {
    name: 'avatar-model-integrity',
    apply: 'build',
    async buildStart() { await checkModelIntegrity(appRoot); },
  }, {
    name: 'local-avatar-authoring-models',
    configureServer(server) {
      const sources = new Set(['human-authored-v1.glb', 'anime-performance-v1.vrm']);
      server.middlewares.use('/__avatar-authoring', (request, response, next) => {
        const filename = request.url?.split('?')[0].slice(1);
        if (request.method !== 'GET' || !sources.has(filename)) return next();
        const stream = createReadStream(path.join(appRoot, 'assets/avatars/source-models', filename));
        stream.on('error', () => { response.statusCode = 404; response.end(); });
        response.setHeader('Content-Type', 'model/gltf-binary');
        response.setHeader('Cache-Control', 'no-store');
        stream.pipe(response);
      });
    },
  }],
  resolve: {
    alias: [
      { find: 'react', replacement: path.resolve(appRoot, 'node_modules/react') },
      { find: 'react-dom', replacement: path.resolve(appRoot, 'node_modules/react-dom') },
      { find: 'three/addons', replacement: path.resolve(appRoot, 'node_modules/three/examples/jsm') },
      { find: /^three$/, replacement: path.resolve(appRoot, 'node_modules/three/build/three.module.js') },
    ],
    dedupe: ['react', 'react-dom', 'three'],
  },
})
