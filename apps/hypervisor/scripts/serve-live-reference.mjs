#!/usr/bin/env node
// Serve the LIVE reference as the hypervisor app, with an IOI-owned /api adapter in front.
//
// "Start with the reference, work backwards": the app serves the reference's actual live
// bundle (so dark mode + every client interaction work natively — no hand-wired tail, and
// it's pixel-exact). On top of that, an IOI-owned API adapter progressively replaces the
// reference's mocked /api with real IOI behavior, endpoint by endpoint; anything not yet
// ported is transparently proxied to the live reference so nothing breaks mid-migration.
//
// Architecture:
//   browser :PORT ──▶ this server
//                       ├─ /api/* handled by ioi-api-adapter ─▶ IOI behavior (real)
//                       └─ everything else (and unported /api) ─▶ proxy to mirror :MIRROR_PORT
//   mirror :MIRROR_PORT = reference server (bundle + IOI branding + remaining mocks)
//
// Transitional: the harvested bundle stays in the gitignored local mirror (not committed),
// so this mode requires the mirror present. The IOI adapter + serve layer are committed.
//
// Usage: PORT=4173 node apps/hypervisor/scripts/serve-live-reference.mjs
import http from "node:http";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as adapter from "./ioi-api-adapter.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..", "..");
const REF_SERVER = join(REPO_ROOT, "internal-docs", "reverse-engineering", "ioi", "server.js");
const PORT = Number(process.env.PORT || 4173);
const MIRROR_PORT = Number(process.env.MIRROR_PORT || 9301);

if (!existsSync(REF_SERVER)) {
  console.error(
    `Live reference not found at:\n  ${REF_SERVER}\n\n` +
      `The reference bundle is a gitignored local mirror; this serve mode needs it present.`,
  );
  process.exit(1);
}

// 1) Spawn the reference server (bundle + branding + remaining mocks) on an internal port.
const mirror = spawn("node", [REF_SERVER], {
  stdio: "inherit",
  env: { ...process.env, PORT: String(MIRROR_PORT) },
});
mirror.on("exit", (code) => process.exit(code ?? 0));
process.on("SIGINT", () => mirror.kill("SIGINT"));
process.on("SIGTERM", () => mirror.kill("SIGTERM"));

function proxyToMirror(req, res, body) {
  const upstream = http.request(
    { host: "127.0.0.1", port: MIRROR_PORT, method: req.method, path: req.url, headers: req.headers },
    (r) => {
      res.writeHead(r.statusCode || 502, r.headers);
      r.pipe(res);
    },
  );
  upstream.on("error", (e) => {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`mirror unavailable: ${e.message}`);
  });
  upstream.end(body);
}

// 2) Front server: IOI /api adapter first, proxy everything else to the mirror.
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const pathname = (req.url || "").split("?")[0];
    if (pathname.startsWith("/api/")) {
      let handled = null;
      try {
        handled = adapter.handle(pathname, body.toString("utf8"));
      } catch (e) {
        console.error("[ioi-api-adapter]", e);
      }
      if (handled) {
        res.writeHead(200, { "Content-Type": handled.contentType || "application/json" });
        res.end(handled.body);
        return;
      }
    }
    proxyToMirror(req, res, body);
  });
});

// Wait for the mirror to accept connections, then listen.
function waitForMirror(attempt = 0) {
  const probe = http.get({ host: "127.0.0.1", port: MIRROR_PORT, path: "/" }, (r) => {
    r.destroy();
    server.listen(PORT, () =>
      console.log(`[hypervisor] LIVE reference + IOI /api adapter on http://localhost:${PORT}`),
    );
  });
  probe.on("error", () => {
    if (attempt > 50) {
      console.error("[hypervisor] mirror did not come up");
      process.exit(1);
    }
    setTimeout(() => waitForMirror(attempt + 1), 200);
  });
}
waitForMirror();
