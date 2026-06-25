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
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as adapter from "./ioi-api-adapter.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const AUG_PATH = join(HERE, "ioi-augmentation.js");
// WS-I: injected IOI-native surface tag (mounted beside the cockpit; never edits Ona's DOM).
const AUG_TAG = '<script src="/ioi-augmentation.js" defer></script>';
// Only inject into a real HTML document (one with a </body>). The mirror mislabels some JSON
// endpoints (/segment/*, /changelog/*) as text/html; appending the tag to those corrupts the
// body the SPA later parses with Response.json() — so never append when there's no </body>.
function augmentHtml(html) {
  return html.includes("</body>") ? html.replace("</body>", AUG_TAG + "</body>") : html;
}
const REPO_ROOT = join(HERE, "..", "..", "..");
const REF_SERVER = join(REPO_ROOT, "internal-docs", "reverse-engineering", "ioi", "server.js");
const PORT = Number(process.env.PORT || 4173);
const MIRROR_PORT = Number(process.env.MIRROR_PORT || 9301);
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

// Terminability tracker: any gitpod.v1.* RPC that falls through to the mock mirror (adapter
// returned null) is recorded here. ":4173 functional" ⇔ this set is empty after exercising flows.
// Exposed at GET /__ioi/fallthrough (+ POST /__ioi/fallthrough/reset).
const fallthrough = new Set();
// A Connect end-stream frame: header byte 0x02 + uint32-BE length + payload.
function connectEndStreamFrame(payloadObj = {}) {
  const payload = Buffer.from(JSON.stringify(payloadObj), "utf8");
  const frame = Buffer.alloc(5 + payload.length);
  frame.writeUInt8(0x02, 0);
  frame.writeUInt32BE(payload.length, 1);
  payload.copy(frame, 5);
  return frame;
}

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

// IOI product identity overrides applied to proxied HTML/JSON (the reference ships a demo
// identity; we substitute ours). Applied in the committed serve layer so it survives mirror
// regeneration and never edits the gitignored snapshot.
const IDENTITY_REWRITES = [
  ["Levi Josman", "John Doe"],
  ["josmanlevi", "johndoe"],
];
function rewriteIdentity(text) {
  let out = text;
  for (const [from, to] of IDENTITY_REWRITES) out = out.split(from).join(to);
  return out;
}

// Localize the asset base. The harvested index pins dynamic-chunk + font loads to the real CDN
// via `globalThis.__toAssetUrl = (f) => \`https://app.gitpod.io/static/${f}\`` (plus absolute font
// preloads). Left as-is, every lazy chunk (e.g. /ai's OnaAIPage-*.js) is fetched from app.gitpod.io
// — and a single blip / rotated hash there makes the dynamic import reject → the SPA's "Something
// went wrong" error boundary. The mirror already serves all assets locally, so point the base at
// our own origin (root-relative /static/) for a self-contained, deterministic app.
const ASSET_CDN_BASE = "https://app.gitpod.io/static/";
function localizeAssetBase(html) {
  return html.split(ASSET_CDN_BASE).join("/static/");
}

function proxyToMirror(req, res, body) {
  // Drop accept-encoding so the mirror returns plain text we can rewrite.
  const headers = { ...req.headers };
  delete headers["accept-encoding"];
  const upstream = http.request(
    { host: "127.0.0.1", port: MIRROR_PORT, method: req.method, path: req.url, headers },
    (r) => {
      const ct = String(r.headers["content-type"] || "");
      // Only buffer + rewrite text payloads (HTML pages + JSON fixtures). Stream the rest
      // (the JS/wasm/font/image bundle) untouched.
      const rewritable = ct.includes("text/html") || ct.startsWith("application/json");
      if (!rewritable) {
        res.writeHead(r.statusCode || 502, r.headers);
        r.pipe(res);
        return;
      }
      const parts = [];
      r.on("data", (c) => parts.push(c));
      r.on("end", () => {
        let text = rewriteIdentity(Buffer.concat(parts).toString("utf8"));
        if (ct.includes("text/html")) text = augmentHtml(localizeAssetBase(text)); // localize CDN base + WS-I inject
        const out = Buffer.from(text, "utf8");
        const outHeaders = { ...r.headers, "content-length": String(out.length) };
        // We send a fixed-length body, so drop any chunked/encoding headers from upstream
        // (keeping them alongside content-length corrupts the framing).
        delete outHeaders["content-encoding"];
        delete outHeaders["transfer-encoding"];
        res.writeHead(r.statusCode || 200, outHeaders);
        res.end(out);
      });
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
  req.on("end", async () => {
    const body = Buffer.concat(chunks);
    const pathname = (req.url || "").split("?")[0];
    // T7 — daemon spine passthrough so the native client's /v1/* calls resolve in the hybrid
    // served context (Session Execution Binding, env-files, terminals, environments, threads).
    if (pathname.startsWith("/v1/")) {
      try {
        const upstream = await fetch(DAEMON + req.url, {
          method: req.method,
          headers: { "Content-Type": "application/json" },
          body: ["GET", "HEAD"].includes(req.method) ? undefined : body,
        });
        const text = await upstream.text();
        res.writeHead(upstream.status, { "Content-Type": upstream.headers.get("content-type") || "application/json" });
        res.end(text);
      } catch (e) {
        res.writeHead(502);
        res.end(JSON.stringify({ error: { message: `daemon unreachable: ${e.message}` } }));
      }
      return;
    }
    if (pathname === "/ioi-augmentation.js") {
      try {
        const js = readFileSync(AUG_PATH);
        res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(js);
      } catch {
        res.writeHead(404);
        res.end("");
      }
      return;
    }
    // Terminability introspection.
    if (pathname === "/__ioi/fallthrough") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ proxied: [...fallthrough] }));
      return;
    }
    if (pathname === "/__ioi/fallthrough/reset") {
      fallthrough.clear();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    // WS-3: agent-run conversation history. The reference SPA's conversation pane consumes a
    // base64 protobuf frame protocol (chunks[].frames[] -> Pi protobuf decode); reconstructing that
    // binary wire format is out of scope, so we serve a VALID EMPTY history ({chunks:[],has_more})
    // — the pane renders cleanly (no error boundary, no reconnect), and the agent's real output is
    // visible in the editor + run status. (Rich transcript = declared follow-up: protobuf encoder.)
    if (pathname.startsWith("/__ioi/agent-runs/") && pathname.endsWith("/conversation")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ chunks: [], has_more: false }));
      return;
    }
    // WS-5: editor "Open in VS Code Browser". The reference SPA opens the editor's urlTemplate;
    // we point vscode-browser at this endpoint, which drives the proven daemon editor chain
    // (create service → lease → start openvscode-server → expose lease-auth proxy) and 302s to
    // the live editor URL. Fail-closed with an honest page if the runtime isn't provisioned.
    if (pathname === "/__ioi/editor/open") {
      const envId = new URLSearchParams((req.url || "").split("?")[1] || "").get("environmentId");
      if (!envId) { res.writeHead(400, { "Content-Type": "text/plain" }); res.end("missing environmentId"); return; }
      const dj = async (m, p, b) => {
        const r = await fetch(DAEMON + p, { method: m, headers: b ? { "content-type": "application/json" } : undefined, body: b ? JSON.stringify(b) : undefined });
        return { status: r.status, body: await r.json().catch(() => ({})) };
      };
      const fail = (reason) => {
        res.writeHead(503, { "Content-Type": "text/html" });
        res.end(`<!doctype html><meta charset=utf-8><body style="font:15px system-ui;background:#0d0f14;color:#e6e9ef;padding:3rem"><h2>Editor not ready</h2><p>The VS Code Browser runtime could not start for this environment.</p><pre style="color:#b7791f">${String(reason || "unknown").replace(/[<&]/g, "")}</pre><p style="color:#7a818c">Provision it with <code>node scripts/provision-hypervisor-vscode-browser-host.mjs</code> and retry.</p></body>`);
      };
      try {
        const svc = await dj("POST", "/v1/hypervisor/editor-services", { environment_id: envId, target_profile: "vscode-browser" });
        const serviceId = svc.body.editorService?.service_id || svc.body.service_id;
        if (!serviceId) return fail(svc.body.reason || `editor-service create ${svc.status}`);
        const lease = await dj("POST", "/v1/hypervisor/editor-access-leases", { environment_id: envId, service_id: serviceId, session_id: `editor:${envId}` });
        const leaseId = lease.body.lease_id;
        const leaseRef = lease.body.lease_ref || lease.body.capability_lease_ref;
        const start = await dj("POST", `/v1/hypervisor/editor-services/${encodeURIComponent(serviceId)}/start`, { access_lease_ref: leaseRef, session_ref: `editor:${envId}` });
        if (!start.body.ok) return fail(start.body.reason || "editor service did not reach ready");
        const expose = await dj("POST", `/v1/hypervisor/editor-services/${encodeURIComponent(serviceId)}/expose`, { lease_id: leaseId });
        if (!expose.body.ok || !expose.body.open_url) return fail(expose.body.reason || "editor proxy bind failed");
        res.writeHead(302, { Location: expose.body.open_url });
        res.end();
      } catch (e) {
        fail(e.message);
      }
      return;
    }
    // EventService/WatchEvents is a Connect stream — own it here (UI polls via List*; real push is a
    // follow-up). Emitting the end-stream frame keeps it adapter-owned (no mock fallthrough).
    if (pathname === "/api/gitpod.v1.EventService/WatchEvents") {
      res.writeHead(200, { "Content-Type": "application/connect+json" });
      res.end(connectEndStreamFrame({}));
      return;
    }
    if (pathname.startsWith("/api/")) {
      let handled = null;
      try {
        handled = await adapter.handle(pathname, body.toString("utf8"));
      } catch (e) {
        console.error("[ioi-api-adapter]", e);
      }
      if (handled) {
        res.writeHead(200, { "Content-Type": handled.contentType || "application/json" });
        res.end(handled.body);
        return;
      }
      // Unported → proxied to mock. Record any gitpod.v1.* RPC for the terminability done-bar.
      const m = pathname.match(/^\/api\/(gitpod\.v1\.[A-Za-z]+\/[A-Za-z]+)/);
      if (m) fallthrough.add(m[1]);
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
