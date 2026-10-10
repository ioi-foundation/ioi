import { build } from 'vite';
import react from '@vitejs/plugin-react';
import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const app = fileURLToPath(new URL('../../', import.meta.url));
const destination = path.resolve(process.env.AVATAR_DEVICE_DIR || '/tmp/aiagent-avatar-device-check');
await build({ configFile: false, root: path.join(app, 'scripts/avatars/device-probe'), publicDir: false, plugins: [react()],
  resolve: { alias: [
    { find: 'react', replacement: path.join(app, 'node_modules/react') },
    { find: 'react-dom', replacement: path.join(app, 'node_modules/react-dom') },
    { find: 'three/addons', replacement: path.join(app, 'node_modules/three/examples/jsm') },
    { find: /^three$/, replacement: path.join(app, 'node_modules/three/build/three.module.js') },
  ], dedupe: ['react', 'react-dom', 'three'] }, build: { outDir: destination, emptyOutDir: true } });
await mkdir(path.join(destination, 'models'), { recursive: true });
await cp(path.join(app, 'public/models/avatars'), path.join(destination, 'models/avatars'), { recursive: true });
await cp(path.join(app, 'public/draco'), path.join(destination, 'draco'), { recursive: true });
await cp(path.join(app, 'public/favicon.svg'), path.join(destination, 'favicon.svg'));
console.log(`Static device check: ${destination}`);
