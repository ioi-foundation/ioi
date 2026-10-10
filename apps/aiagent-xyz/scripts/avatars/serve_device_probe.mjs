import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

const directory = path.resolve(process.env.AVATAR_DEVICE_DIR || '/tmp/aiagent-avatar-device-check');
const host = process.env.AVATAR_DEVICE_HOST || '127.0.0.1';
const port = Number(process.env.AVATAR_DEVICE_PORT || 5174);
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.glb': 'model/gltf-binary', '.vrm': 'model/gltf-binary' };
createServer(async (request, response) => {
  if (!['GET', 'HEAD'].includes(request.method)) { response.writeHead(405); response.end(); return; }
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    const filename = path.resolve(directory, pathname === '/' ? 'index.html' : pathname.slice(1));
    if (!filename.startsWith(directory + path.sep)) throw new Error('Invalid path');
    const bytes = await readFile(filename);
    response.writeHead(200, { 'Content-Type': mime[path.extname(filename)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; worker-src 'self' blob:; style-src 'self'; img-src 'self' data: blob:; connect-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'" });
    response.end(request.method === 'HEAD' ? undefined : bytes);
  } catch { response.writeHead(404); response.end('Not found'); }
}).listen(port, host, () => console.log(`Avatar device check: http://${host}:${port}`));
