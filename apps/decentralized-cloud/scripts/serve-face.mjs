#!/usr/bin/env node
// decentralized.cloud — the public face.
//
// A thin read surface over the running Hypervisor daemon, served the way
// apps/hypervisor serves its product UI: an IOI-owned HTTP server that holds the
// static shell and proxies a fixed allowlist of daemon reads. It owns no database,
// no session plane, no credential vault, no provider integration, no placement
// scorer and no receipt format (ADR 0051 §1, §7). Every number it renders was
// returned by the daemon on this request; nothing is cached, seeded, or fixtured.
//
// The allowlist is exact-match and GET-only. A route that is not on it is refused
// by name rather than passed through, so no mutating daemon call is reachable from
// this surface even by accident.
//
// Usage: node apps/decentralized-cloud/scripts/serve-face.mjs

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(HERE, "..", "public");
const PORT = Number(process.env.IOI_DC_PORT || 4180);
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

// A full candidate sweep has been measured at 38.8s against a single live adapter,
// so the ceiling is generous — but it is a ceiling, and exceeding it is reported as
// a named state rather than a hang.
const DAEMON_TIMEOUT_MS = Number(process.env.IOI_DC_DAEMON_TIMEOUT_MS || 75_000);

// ── The allowlist ────────────────────────────────────────────────────────────
// path → the daemon route it stands for. GET only. `query` lists the query
// parameters that may be forwarded; anything else is dropped, not passed on.
const READS = new Map([
  ["/api/candidate-sources", { daemon: "/v1/hypervisor/cloud-candidates/candidate-sources", query: [] }],
  ["/api/candidates", { daemon: "/v1/hypervisor/cloud-candidates/candidates", query: ["intent_ref"] }],
  ["/api/placement-advisory", { daemon: "/v1/hypervisor/cloud-candidates/placement-advisory", query: ["intent_ref"] }],
  ["/api/venues", { daemon: "/v1/hypervisor/placement/venues", query: [] }],
]);

const STATIC = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/index.html", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/face.css", { file: "face.css", type: "text/css; charset=utf-8" }],
  ["/face.js", { file: "face.js", type: "text/javascript; charset=utf-8" }],
  ["/fonts/IOI.ttf", { file: "fonts/IOI.ttf", type: "font/ttf" }],
  ["/fonts/ABCDiatype-Regular.woff2", { file: "fonts/ABCDiatype-Regular.woff2", type: "font/woff2" }],
  ["/fonts/ABCDiatype-Bold.woff2", { file: "fonts/ABCDiatype-Bold.woff2", type: "font/woff2" }],
  ["/fonts/ABCDiatypeSemi-Mono-Regular.woff2", { file: "fonts/ABCDiatypeSemi-Mono-Regular.woff2", type: "font/woff2" }],
]);

const json = (res, status, body) => {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
};

async function proxyRead(res, entry, url) {
  const target = new URL(DAEMON + entry.daemon);
  for (const key of entry.query) {
    const value = url.searchParams.get(key);
    if (value) target.searchParams.set(key, value);
  }

  const started = Date.now();
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), DAEMON_TIMEOUT_MS);
  try {
    const upstream = await fetch(target, { headers: { accept: "application/json" }, signal: abort.signal });
    const body = await upstream.text();
    res.writeHead(upstream.status, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      // The face never claims freshness the daemon did not give it; this is how long
      // THIS read took, not how old the evidence inside it is. observed_at is the
      // evidence's own timestamp and travels untouched in the body.
      "x-dc-upstream-ms": String(Date.now() - started),
    });
    res.end(body);
  } catch (err) {
    const timedOut = err?.name === "AbortError";
    json(res, 504, {
      state: timedOut ? "candidate_plane_timeout" : "candidate_plane_unreachable",
      reason: timedOut
        ? `the daemon did not answer ${entry.daemon} within ${DAEMON_TIMEOUT_MS}ms — no candidates are shown rather than stale ones being presented as current`
        : `the daemon at ${DAEMON} could not be reached — this surface has no data of its own to fall back on`,
      daemon_route: entry.daemon,
      elapsed_ms: Date.now() - started,
    });
  } finally {
    clearTimeout(timer);
  }
}

async function serveStatic(res, entry) {
  try {
    const body = await readFile(path.join(PUBLIC_DIR, entry.file));
    res.writeHead(200, { "content-type": entry.type, "cache-control": "no-store", "content-length": body.length });
    res.end(body);
  } catch {
    json(res, 404, { state: "asset_absent", reason: `${entry.file} is not on disk` });
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

  if (req.method !== "GET" && req.method !== "HEAD") {
    return json(res, 405, {
      state: "method_not_allowed",
      reason: "this surface is read-only; it exposes no mutating route to any caller",
    });
  }

  const read = READS.get(url.pathname);
  if (read) return proxyRead(res, read, url);

  const asset = STATIC.get(url.pathname);
  if (asset) return serveStatic(res, asset);

  json(res, 404, {
    state: "route_not_on_read_allowlist",
    reason: `${url.pathname} is not one of the four daemon reads this surface exposes`,
    allowed: [...READS.keys()],
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`decentralized.cloud face on http://127.0.0.1:${PORT} → daemon ${DAEMON}`);
  console.log(`read allowlist: ${[...READS.keys()].join(", ")}`);
});
