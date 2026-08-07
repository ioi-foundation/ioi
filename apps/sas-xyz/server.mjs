import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JsonStore } from './domain/store.mjs';
import { SasService, seedState } from './domain/service.mjs';
import { createOwnerAdapters } from './domain/adapters.mjs';
import { createApiHandler } from './api/handler.mjs';
import { createSessionAuthority, isLoopbackHost } from './auth/session.mjs';

const root = path.dirname(fileURLToPath(import.meta.url)); const production = process.env.NODE_ENV === 'production'; const serveBuiltUi = process.env.IOI_SERVE_BUILT_UI === '1';
const developmentAuthority = process.env.IOI_ENABLE_DEVELOPMENT_AUTHORITY === '1' && !production;
const host = process.env.HOST || '127.0.0.1'; const port = Number(process.env.PORT || 5174);
if (developmentAuthority && !isLoopbackHost(host)) throw new Error('Development authority is restricted to a loopback listener');
if (!production && !developmentAuthority) throw new Error('Server mode is ambiguous: use the explicit loopback development command; network authority is unavailable');
const ownerConfig = { developmentAuthority };
if (production) throw new Error('sas.xyz production is refused: canonical ServiceOrder runtime, settlement, authority, artifact-storage, and governed-production owner contracts are not all registered');
const store = await new JsonStore(process.env.IOI_SAS_STORE_PATH || path.join(root, '.data', 'outcomes.json'), seedState).init();
const service = new SasService(store, createOwnerAdapters(ownerConfig));
const sessionAuthority = createSessionAuthority({ secret: process.env.IOI_SESSION_SECRET || 'sas.xyz-loopback-development-session-secret', developmentAuthority });
const api = createApiHandler(service, { developmentAuthority, sessionAuthority, publicOrigin: process.env.IOI_PUBLIC_ORIGIN || `http://${host}:${port}` });
let vite;
if (!production && !serveBuiltUi) { const { createServer: createViteServer } = await import('vite'); vite = await createViteServer({ root, server: { middlewareMode: true, hmr: false }, appType: 'spa' }); }
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png' };
const serveDist = async (request, response) => {
  const requested = new URL(request.url, 'http://localhost').pathname; const distRoot = path.join(root, 'dist'); const relative = requested === '/' ? 'index.html' : requested.replace(/^\/+/, ''); let filePath = path.resolve(distRoot, relative); if (filePath !== distRoot && !filePath.startsWith(`${distRoot}${path.sep}`)) filePath = path.join(distRoot, 'index.html');
  try { if (!(await stat(filePath)).isFile()) throw new Error('not-file'); } catch { filePath = path.join(root, 'dist', 'index.html'); }
  response.writeHead(200, { 'content-type': mime[path.extname(filePath)] || 'application/octet-stream', 'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff' }); response.end(await readFile(filePath));
};
const server = createServer(async (request, response) => { if (await api(request, response)) return; if (vite) return vite.middlewares(request, response, () => { response.writeHead(404); response.end(); }); return serveDist(request, response); });
server.listen(port, host, () => console.log(`sas.xyz listening on http://${host}:${port} (${developmentAuthority ? 'development authority' : 'network authority'})`));
