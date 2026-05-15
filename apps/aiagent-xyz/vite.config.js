import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const appRoot = fileURLToPath(new URL('.', import.meta.url))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      react: path.resolve(appRoot, 'node_modules/react'),
      'react-dom': path.resolve(appRoot, 'node_modules/react-dom'),
    },
    dedupe: ['react', 'react-dom'],
  },
})
