#!/usr/bin/env node
// Canonical runtime-native serve (cut 5): serve the source-built Hypervisor app and proxy the
// daemon plane directly. No /api adapter, no seed bundle, no upstream-namespace bridge — every
// data call is the daemon's own /v1 contract. This is the fallback-free runtime: build the app
// (`npm run build`) then `npm run serve:app`.
import http from "node:http";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { join, normalize, extname, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, "..", "dist");
const PORT = Number(process.env.PORT || 4173);
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml", ".woff2": "font/woff2", ".woff": "font/woff",
  ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp", ".ico": "image/x-icon",
  ".map": "application/json", ".wasm": "application/wasm", ".ttf": "font/ttf",
};

function proxyDaemon(req, res) {
  const upstream = http.request(
    DAEMON + req.url,
    { method: req.method, headers: { ...req.headers, host: new URL(DAEMON).host } },
    (r) => { res.writeHead(r.statusCode || 502, r.headers); r.pipe(res); },
  );
  upstream.on("error", (e) => { res.writeHead(502, { "content-type": "application/json" }); res.end(JSON.stringify({ error: "daemon unreachable", detail: e.message })); });
  req.pipe(upstream);
}

async function serveStatic(res, fsPath, fallbackOk = true) {
  try {
    const st = await stat(fsPath);
    if (st.isDirectory()) throw new Error("dir");
    res.writeHead(200, { "content-type": MIME[extname(fsPath)] || "application/octet-stream", "cache-control": extname(fsPath) === ".html" ? "no-cache" : "public, max-age=31536000" });
    createReadStream(fsPath).pipe(res);
  } catch {
    if (fallbackOk) return serveStatic(res, join(DIST, "index.html"), false); // SPA client-route fallback
    res.writeHead(404, { "content-type": "text/plain" }); res.end("not found");
  }
}

const server = http.createServer((req, res) => {
  const pathname = (req.url || "/").split("?")[0];
  // Daemon plane — proxied straight through (the only backend the source app speaks). /v1 is the
  // hypervisor/threads/terminals spine; /supervisor is the env-ops file/git plane the session
  // workbench reads/writes the real scoped workspace through.
  if (pathname.startsWith("/v1/") || pathname.startsWith("/supervisor/")) return proxyDaemon(req, res);
  // Static assets, else SPA fallback to index.html for client-side routes.
  const rel = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, "");
  serveStatic(res, join(DIST, rel === "/" ? "index.html" : rel));
});

server.listen(PORT, () => {
  console.log("============================================================");
  console.log("  IOI HYPERVISOR APP (source-owned, runtime-native)");
  console.log("============================================================");
  console.log(`  Serving:   ${DIST}`);
  console.log(`  Daemon:    ${DAEMON} (proxied at /v1/*)`);
  console.log(`  Local URL: http://localhost:${PORT}`);
  console.log("============================================================");
});
