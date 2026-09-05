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
  // The job door's reads. A job record carries its own refusals and receipts, so the
  // Receipts surface renders from these and never from an example.
  ["/api/jobs", { daemon: "/v1/hypervisor/cloud-jobs", query: [] }],
  // Budgets are READ so the form can offer the ones that exist. "An existing budget,
  // never an amount typed here" was a sentence on an inert form; with the door wired it
  // has to be a mechanism, and the mechanism is that the surface can only show budgets
  // the daemon already has and can only send back a ref it was given.
  ["/api/budgets", { daemon: "/v1/hypervisor/resource/budgets", query: [] }],
]);

// ── The WRITE allowlist, and the one place spend is fenced off ───────────────
//
// Until this cut the surface exposed no mutating route at all and said so. The job
// door changes that, and the change is deliberately as small as it can be: exactly two
// POSTs, exact-match, each with a fixed daemon target.
//
//   /api/jobs          -> POST /v1/hypervisor/cloud-jobs
//        ADMISSION. The daemon's own comment: "admission is a proposal — this record
//        authorizes nothing". No provider is touched and nothing is spent.
//
//   /api/jobs/:id/dry-run -> POST /v1/hypervisor/cloud-jobs/:id/execute
//        A dry run stops at the placement receipt and touches no provider.
//
// THE SPEND FENCE, which is the most important thing in this file.
//
// The daemon's execute route runs a real provider operation UNLESS the request body
// carries `dry_run: true`. This surface therefore does not forward `dry_run` from the
// caller — it OVERWRITES it to true on every execute, server-side, after the body is
// parsed. There is no request a client can send through this door that reaches a
// metered provider operation, because the field that decides it is not the client's
// to set.
//
// That is an enforced boundary rather than a convention. A convention here would read
// as a guarantee and be enforced nowhere, which is the shape this programme has been
// bitten by twice. A real execution is a spend, a spend needs an explicit owner
// authorization naming amount, venue ceiling, offer hash and teardown, and no such
// authorization can arrive through a web form.
const DRY_RUN_ONLY = true;
const WRITES = new Map([
  ["/api/jobs", { daemon: "/v1/hypervisor/cloud-jobs", kind: "admit" }],
]);
const EXECUTE_PATH = /^\/api\/jobs\/([A-Za-z0-9_.:-]{1,128})\/dry-run$/;

// The face's own configuration — not a daemon read. It carries only what the surface
// needs in order to avoid making an unchecked claim: if an operator has declared a
// refresh cadence, the page may say when the next batch is due; if not, it says
// nothing about cadence rather than guessing one.
const REFRESH_CADENCE_S = process.env.IOI_DC_REFRESH_CADENCE_S
  ? Number(process.env.IOI_DC_REFRESH_CADENCE_S)
  : null;

// ── What is served, and from where ───────────────────────────────────────────
// The surface is a built React app. `dist/` is the artifact that ships and the
// artifact every honesty gate reads; the fonts are served from `public/fonts`, which
// is the ONE copy of them in the repo — the build copies rather than duplicates.
//
// IT FAILS CLOSED. If dist/ has not been built, this server refuses the shell by name
// rather than falling back to the pre-port files that are still on disk beside it. A
// fallback would serve a DIFFERENT surface than the one under test while every gate
// reported green, which is this programme's own scar arriving by another road: three
// cold readers once scored a sheet the run had never written. A missing build is a
// state, and it says so.
const DIST_DIR = path.join(HERE, "..", "dist");
const STATIC = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8", from: DIST_DIR }],
  ["/index.html", { file: "index.html", type: "text/html; charset=utf-8", from: DIST_DIR }],
  ["/assets/face.js", { file: "assets/face.js", type: "text/javascript; charset=utf-8", from: DIST_DIR }],
  ["/assets/index.css", { file: "assets/index.css", type: "text/css; charset=utf-8", from: DIST_DIR }],
  ["/fonts/IOI.ttf", { file: "fonts/IOI.ttf", type: "font/ttf", from: PUBLIC_DIR }],
  ["/fonts/ABCDiatype-Regular.woff2", { file: "fonts/ABCDiatype-Regular.woff2", type: "font/woff2", from: PUBLIC_DIR }],
  ["/fonts/ABCDiatype-Bold.woff2", { file: "fonts/ABCDiatype-Bold.woff2", type: "font/woff2", from: PUBLIC_DIR }],
  ["/fonts/ABCDiatypeSemi-Mono-Regular.woff2", { file: "fonts/ABCDiatypeSemi-Mono-Regular.woff2", type: "font/woff2", from: PUBLIC_DIR }],
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
    const body = await readFile(path.join(entry.from, entry.file));
    res.writeHead(200, { "content-type": entry.type, "cache-control": "no-store", "content-length": body.length });
    res.end(body);
  } catch {
    // Named states, and the build's absence is its own. "asset_absent" for a font and
    // "surface_not_built" for the shell are different facts, and a reader — or a gate
    // — that cannot tell them apart will spend its time on the wrong one.
    const unbuilt = entry.from === DIST_DIR;
    json(res, unbuilt ? 503 : 404, {
      state: unbuilt ? "surface_not_built" : "asset_absent",
      reason: unbuilt
        ? `${entry.file} is not in dist/ — run \`npm run build --workspace=decentralized-cloud\`. ` +
          "This server does not fall back to the pre-port files still on disk: serving a " +
          "different surface than the one under test is how a green gate comes to mean nothing."
        : `${entry.file} is not on disk`,
    });
  }
}

// The request body, bounded. A body larger than this is refused before it is parsed:
// a proxy that buffers whatever it is sent is a denial-of-service surface with extra
// steps, and the largest legitimate CloudJobRequest is a few hundred bytes.
const MAX_BODY = 64 * 1024;
async function readBody(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("body_too_large");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text ? JSON.parse(text) : {};
}

async function proxyWrite(res, req, target, kind) {
  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    return json(res, err.message === "body_too_large" ? 413 : 400, {
      state: err.message === "body_too_large" ? "request_body_too_large" : "request_body_not_json",
      reason: err.message === "body_too_large"
        ? `a job request may not exceed ${MAX_BODY} bytes`
        : "the request body did not parse as JSON",
    });
  }

  // THE FENCE. On an execute, `dry_run` is set to true HERE — not read from the body,
  // not defaulted, not trusted. Whatever the caller sent for that field is discarded.
  if (kind === "dry-run") {
    if (!DRY_RUN_ONLY) throw new Error("unreachable: this surface has no non-dry-run lane");
    body = { ...body, dry_run: true };
  }

  const started = Date.now();
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), DAEMON_TIMEOUT_MS);
  try {
    const upstream = await fetch(DAEMON + target, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal: abort.signal,
    });
    const text = await upstream.text();
    res.writeHead(upstream.status, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-dc-upstream-ms": String(Date.now() - started),
    });
    res.end(text);
  } catch (err) {
    const timedOut = err?.name === "AbortError";
    json(res, 504, {
      state: timedOut ? "job_plane_timeout" : "job_plane_unreachable",
      reason: timedOut
        ? `the daemon did not answer ${target} within ${DAEMON_TIMEOUT_MS}ms — whether the job was admitted is UNKNOWN from here, and this surface will not guess`
        : `the daemon at ${DAEMON} could not be reached`,
      daemon_route: target,
      elapsed_ms: Date.now() - started,
    });
  } finally {
    clearTimeout(timer);
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);

  if (req.method === "POST") {
    const write = WRITES.get(url.pathname);
    if (write) return proxyWrite(res, req, write.daemon, write.kind);
    const execute = EXECUTE_PATH.exec(url.pathname);
    if (execute) {
      return proxyWrite(
        res, req,
        `/v1/hypervisor/cloud-jobs/${encodeURIComponent(execute[1])}/execute`,
        "dry-run"
      );
    }
    return json(res, 405, {
      state: "write_not_on_allowlist",
      reason: `${url.pathname} is not one of the two writes this surface exposes`,
      allowed: [...WRITES.keys(), "/api/jobs/:id/dry-run"],
    });
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return json(res, 405, {
      state: "method_not_allowed",
      reason:
        "this surface exposes two POSTs and nothing else: admitting a job proposal, and " +
        "a dry run that stops at the placement receipt. It has no PUT, PATCH or DELETE.",
    });
  }

  // A job read by id. The daemon's own route; the id is bounded by the same pattern
  // the write lane uses, so a path that is not a job id is refused rather than
  // forwarded and refused later somewhere with more privilege.
  const jobById = /^\/api\/jobs\/([A-Za-z0-9_.:-]{1,128})$/.exec(url.pathname);
  if (jobById) {
    return proxyRead(
      res,
      { daemon: `/v1/hypervisor/cloud-jobs/${encodeURIComponent(jobById[1])}`, query: [] },
      url
    );
  }

  if (url.pathname === "/api/face-config") {
    return json(res, 200, {
      refresh_cadence_seconds: REFRESH_CADENCE_S,
      daemon_reads: [...READS.keys()],
      note: REFRESH_CADENCE_S
        ? "an operator process refreshes the showcase intents on this cadence; it is a separate process and is not reachable from this surface"
        : "no refresh cadence is declared to this surface, so it makes no claim about when the next batch lands",
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
