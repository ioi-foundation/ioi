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
import { existsSync, statSync } from "node:fs";
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
// The table lives in src/logic/capability.mjs and is imported by this proxy, by the
// API surface that publishes it, and by the gate that checks it.
//
// It used to live here as two Maps with two path regexes BELOW them — and the regexes
// held the two routes the job door added, so every count written against "the map" was
// wrong by two: in this file's own 404 body ("not one of the four daemon reads"), in
// the header chip, and on the very page that publishes the list. Each of those
// sentences was true when it was written. Prose does not go red.
//
// The asymmetry that mattered is kept, and is now structural rather than maintained:
// the surface cannot widen its own access by editing its own documentation, because
// the documentation and the dispatch are the SAME object instead of two objects that
// agreed by hand until they didn't.
import {
  ROUTES,
  matchRoute,
  readRoutes,
  daemonReadRoutes,
  writeRoutes,
  capabilitySentences,
  DRY_RUN_ONLY,
} from "../src/logic/capability.mjs";

const SENTENCES = capabilitySentences();

// ── The one place spend is fenced off ────────────────────────────────────────
//
// The two writes are on the table above, exact-match, each with a fixed daemon target:
// admission (a proposal, which authorizes nothing) and a dry run that stops at the
// placement receipt and touches no provider.
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
//
// DRY_RUN_ONLY is imported rather than declared here, so that the flag the fence reads
// and the flag the generated sentences read are one flag. Opening a non-dry-run lane
// now changes what the surface SAYS in the same edit that changes what it does.

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
//
// WHICH BUILD THIS SERVER HANDS OUT — stated, never assumed.
//
// The verifier's gate and the designer's exhibit used to share ONE dist/, and a build by
// either rewrote the bytes under the other's run: a contact sheet once captured half of
// one commit and half of the next with nothing in the images saying which, and had to be
// voided. Three straddles of that class in one day, each caught by discipline — and a
// fence that depends on a peer remembering is weaker than one that cannot be crossed.
// So the designer's builds go to a separate, gitignored directory and this server is
// TOLD which one to serve. The default is unchanged: ../dist, the gate's own build. The
// gate pins this variable when it spawns its server rather than inheriting it, so an
// ambient IOI_DC_DIST cannot redirect a gate run to a build it never made, and it checks
// the served face.js against the one it just built. This server, for its part, says
// which directory it serves on every boot, on the same line as the port — and refuses
// to start at all if that directory does not exist: a server with nothing behind it
// must not announce "face on".
const DIST_DIR = process.env.IOI_DC_DIST
  ? path.resolve(process.env.IOI_DC_DIST)
  : path.join(HERE, "..", "dist");
const DIST_SOURCE = process.env.IOI_DC_DIST ? "IOI_DC_DIST" : "default";
if (!existsSync(DIST_DIR) || !statSync(DIST_DIR).isDirectory()) {
  console.error(
    `decentralized.cloud face: refusing to start — ${DIST_DIR} (${DIST_SOURCE}) is not a directory. ` +
    "Build it, or point IOI_DC_DIST at a build that exists."
  );
  process.exit(1);
}
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

// THE BRAND ASSETS PAGE AND ITS FILES, under /brand/. These are built into dist/brand
// from public/brand by the vite copy step, alongside the fonts, so they are served
// from the SAME build the shell is — a gate run sees the brand page of the build it is
// testing, never a fresher one from disk. The names are bounded: one path segment of
// lowercase letters, digits and hyphens, and one of three types. Anything else is
// not a brand asset and falls through to the allowlist refusal below, which is
// where an unknown path belongs.
const BRAND_TYPES = { svg: "image/svg+xml", html: "text/html; charset=utf-8", png: "image/png", js: "text/javascript; charset=utf-8" };
function brandAsset(pathname) {
  if (pathname === "/brand" || pathname === "/brand/") {
    return { file: "brand/index.html", type: BRAND_TYPES.html, from: DIST_DIR };
  }
  const m = /^\/brand\/([a-z0-9-]+)\.(svg|html|png|js)$/.exec(pathname);
  if (!m) return null;
  return { file: `brand/${m[1]}.${m[2]}`, type: BRAND_TYPES[m[2]], from: DIST_DIR };
}

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
        ? `${entry.file} is not in ${DIST_DIR} (${DIST_SOURCE}) — run \`npm run build --workspace=decentralized-cloud\`, ` +
          "or point IOI_DC_DIST at a directory that has been built. " +
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
    // One matcher for both writes, including the parameterised one. The dry-run lane
    // used to be a regex sitting outside the map that the refusal body below counted,
    // so this route was simultaneously enforced and uncounted.
    const write = matchRoute("POST", url.pathname);
    if (write) return proxyWrite(res, req, write.daemon, write.route.kind);
    return json(res, 405, {
      state: "write_not_on_allowlist",
      reason: `${url.pathname} is not one of the ${SENTENCES.writePhrase} this surface exposes`,
      allowed: writeRoutes().map((r) => r.face),
    });
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    return json(res, 405, {
      state: "method_not_allowed",
      reason:
        `this surface exposes ${SENTENCES.writePhrase} and nothing else: ` +
        writeRoutes().map((r) => `POST ${r.face}`).join(", ") +
        ". It has no PUT, PATCH or DELETE.",
    });
  }

  // Every GET on the table, including the parameterised job-by-id read that used to
  // sit in a regex here. The id is bounded by the same pattern the write lane uses —
  // one pattern, declared once — so a path that is not a job id is refused here rather
  // than forwarded and refused later somewhere with more privilege.
  const read = matchRoute("GET", url.pathname);
  if (read) {
    // The one route this surface answers itself. It is on the table because a route
    // absent from the table is a route absent from the count, and the count is the
    // claim the page makes.
    if (!read.daemon) {
      return json(res, 200, {
        refresh_cadence_seconds: REFRESH_CADENCE_S,
        daemon_reads: daemonReadRoutes().map((r) => r.face),
        capability: SENTENCES.whatItDoes,
        note: REFRESH_CADENCE_S
          ? "an operator process refreshes the showcase intents on this cadence; it is a separate process and is not reachable from this surface"
          : "no refresh cadence is declared to this surface, so it makes no claim about when the next batch lands",
      });
    }
    return proxyRead(res, { daemon: read.daemon, query: read.route.query }, url);
  }

  const asset = STATIC.get(url.pathname) || brandAsset(url.pathname);
  if (asset) return serveStatic(res, asset);

  json(res, 404, {
    state: "route_not_on_read_allowlist",
    // This said "the four daemon reads" while seven were enforced. The count is
    // generated now, so it is wrong only if the table is wrong.
    reason: `${url.pathname} is not one of the ${SENTENCES.readPhrase} this surface exposes`,
    allowed: readRoutes().map((r) => r.face),
  });
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`decentralized.cloud face on http://127.0.0.1:${PORT} → daemon ${DAEMON} · serving ${DIST_DIR} (${DIST_SOURCE})`);
  console.log(`allowlist: ${SENTENCES.readAllowlist}; ${SENTENCES.writeSummary}`);
  console.log(`  ${ROUTES.map((r) => `${r.method} ${r.face}`).join("\n  ")}`);
});
