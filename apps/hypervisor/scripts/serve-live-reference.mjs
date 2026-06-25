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
import { existsSync, readFileSync, watch as fsWatch } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import * as adapter from "./ioi-api-adapter.mjs";
import { getRun } from "./ioi-agent-runs.mjs";

// Build the V1 conversation replay (newline-delimited JSON) for a run — the exact shape the SPA's
// conversation pane renders: a userInput entry (the prompt), an optional todoGroup of the files the
// agent wrote, and a text summary. Mirrors the harvested reference's bare-/conversation format.
function conversationReplay(run) {
  const lines = [];
  // NOTE: we intentionally do NOT emit the userInput entry. The SPA renders the submitted prompt
  // optimistically as its own user bubble; emitting it again here produced a DUPLICATE prompt. We
  // emit only the agent side (the work it did + its summary), which the pane shows as the response.
  // the files the agent actually changed → a done todo group (concrete evidence of the work).
  const files = [];
  for (const g of run.changedFiles || []) {
    if (Array.isArray(g?.files)) for (const f of g.files) files.push(typeof f === "string" ? f : f?.path);
    else if (typeof g === "string") files.push(g);
    else if (g?.path) files.push(g.path);
  }
  const uniqueFiles = [...new Set(files.filter(Boolean))];
  if (run.status === "done" && uniqueFiles.length) {
    lines.push(JSON.stringify({
      id: `${run.id}-todos`, phase: "PHASE_COMPLETED",
      todoGroup: { groupId: `${run.id}-todos`, todos: uniqueFiles.slice(0, 12).map((p, i) => ({ id: `f${i}`, title: `Wrote ${p}`, phase: "PHASE_DONE" })) },
    }));
  }
  let summary = run.summary;
  if (run.status === "running" || run.status === "waiting") summary = run.activity || "Working in the environment…";
  else if (run.status === "failed") summary = `Run failed: ${run.error || "unknown error"}`;
  else if (!summary) summary = "Run complete.";
  lines.push(JSON.stringify({
    id: `${run.id}-summary`, phase: run.status === "running" || run.status === "waiting" ? "PHASE_RUNNING" : "PHASE_COMPLETED",
    text: { content: summary, sequenceId: 1 },
  }));
  return lines.join("\n") + "\n";
}

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
    // Cut A — env-ops plane: forward the EnvironmentOpsService Connect surface (and any env gateway
    // path) to the daemon, preserving the capability-lease Authorization header. Contract + lease
    // logic live in the daemon (D1); this is a transparent route, not a shim.
    if (pathname.startsWith("/supervisor/")) {
      try {
        const headers = { "Content-Type": req.headers["content-type"] || "application/json" };
        if (req.headers["authorization"]) headers["Authorization"] = req.headers["authorization"];
        const upstream = await fetch(DAEMON + req.url, {
          method: req.method,
          headers,
          body: ["GET", "HEAD"].includes(req.method) ? undefined : body,
        });
        const buf = Buffer.from(await upstream.arrayBuffer());
        res.writeHead(upstream.status, { "Content-Type": upstream.headers.get("content-type") || "application/json" });
        res.end(buf);
      } catch (e) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ code: "unavailable", message: `daemon unreachable: ${e.message}` }));
      }
      return;
    }
    // Telemetry beacons (Segment analytics): the harvested SPA fires /segment/v1/{t,i,...}; with no
    // handler they proxy to the mirror and hang open (real pending requests). Ack them instantly so
    // nothing is left pending. We collect no analytics — this is a local, self-contained app.
    if (pathname.startsWith("/segment/")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true }));
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
    // Agent-run conversation. The SPA's conversation pane is the harvested reference's V1 mode: it
    // fetches the bare `conversationUrl` as a FINITE newline-delimited-JSON replay (userInput /
    // todoGroup / text entries with a top-level {id,phase}) and renders it, then stops loading. We
    // build that replay from the REAL run (the user's prompt, the files the agent wrote, its summary)
    // — so the transcript shows the agent's actual work, not an empty pane. The /live + /history
    // sub-paths are the V2 streaming mode; we are NOT in it (the projection omits conversationUrls),
    // but we answer them defensively and ALWAYS terminate /live with `event: end` (an unterminated
    // /live is exactly what made the pane say "Thinking…" forever).
    if (pathname.startsWith("/__ioi/agent-runs/") && pathname.includes("/conversation")) {
      const runId = pathname.split("/__ioi/agent-runs/")[1].split("/")[0];
      const run = getRun(runId);
      if (pathname.endsWith("/conversation/live")) {
        const state = { chunk_id: `${runId}-live`, todo_groups: [], available_commands: null, clarifying_questions: null, next_steps_proposal: null, user_inputs: [] };
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
        res.write(`event: state\ndata: ${JSON.stringify(state)}\n\n`);
        res.write("event: end\n\n"); // terminate — never an open-ended keepalive (that = perpetual "Thinking…")
        res.end();
        return;
      }
      if (pathname.endsWith("/conversation/history")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ chunks: [], has_more: false }));
        return;
      }
      // bare /conversation — the V1 finite NDJSON replay built from the real run. The SPA's v1 pane
      // fetches this ONCE and does not re-poll, so if we answered immediately during the run it would
      // cache a PHASE_RUNNING entry and show "Thinking…" forever. Briefly wait for the run to settle
      // (runs finish in ~10s) so the single fetch returns the COMPLETED transcript. The pane shows a
      // normal loading state until then, then renders the final prompt + summary + files and stops.
      if (run) {
        const deadline = Date.now() + 30000;
        while ((run.status === "running" || run.status === "waiting") && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 500));
        }
      }
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(run ? conversationReplay(run) : "");
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

// ---- Cut A — env-ops streaming transport: JSON-RPC 2.0 over WebSocket ----------------------------
// The SPA opens ws(s)://<host>/supervisor.v1.EnvironmentOpsService/ (env path dropped by design) and
// speaks JSON-RPC: {id, method:"auth", params:{token}} on open (env derives from the lease), then
// {id, method:"supervisor.v1.EnvironmentOpsService/<M>", params}. Server-streaming methods emit
// {id, result:<chunk>} repeatedly then {id, result:null} to end. Frames are binary UTF-8 JSON.
// Transport only — unary delegates to the daemon EnvironmentOpsService (the contract home, D1);
// terminal bridges the daemon's real openpty terminals; Watch uses a real fs watcher (inotify).
const C = { InvalidArgument: 3, NotFound: 5, Unimplemented: 12, Internal: 13, Unavailable: 14, Unauthenticated: 16 };
const STREAMING = new Set(["AttachTerminal", "ReadTerminal", "Watch"]);

async function djson(method, path, body, token) {
  const headers = { "content-type": "application/json" };
  if (token) headers["authorization"] = `Bearer ${token}`;
  const r = await fetch(DAEMON + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let j = {}; try { j = t ? JSON.parse(t) : {}; } catch { j = {}; }
  return { status: r.status, body: j };
}

function handleSupervisorWs(ws) {
  let env = null;
  let token = null;
  const streams = new Map(); // jsonrpc id -> cleanup fn
  const send = (obj) => { try { ws.send(Buffer.from(JSON.stringify(obj))); } catch { /* closed */ } };
  const ok = (id, result) => send({ jsonrpc: "2.0", id, result });
  const err = (id, code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });

  ws.on("message", async (raw) => {
    let msg;
    try { msg = JSON.parse(Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw)); } catch { return; }
    const { id, method, params } = msg;
    if (typeof id !== "number") return;
    try {
      if (method === "auth") {
        token = params?.token || "";
        const res = await djson("GET", `/v1/hypervisor/ops-lease/${encodeURIComponent(token)}`);
        if (res.body?.active && res.body?.environment_id) { env = res.body.environment_id; ok(id, {}); }
        else err(id, C.Unauthenticated, "invalid or expired env-ops lease");
        return;
      }
      if (!env) { err(id, C.Unauthenticated, "not authenticated"); return; }
      const m = String(method || "").split("/").pop();
      const envRef = `environment:${env}`;

      // --- terminal control (bridge to the daemon's real openpty terminals) ---
      if (m === "CreateTerminal") {
        const cwd = params?.workingDirectory && String(params.workingDirectory).trim() ? params.workingDirectory : undefined;
        const body = { environment_ref: envRef, shell: params?.shell || "bash", cols: params?.initialCols || 80, rows: params?.initialRows || 24 };
        if (cwd) body.cwd = cwd; // else the daemon defaults to the env workspace (empty cwd would fail)
        const r = await djson("POST", "/v1/hypervisor/terminals", body, token);
        return r.body?.terminal_id ? ok(id, { terminalId: r.body.terminal_id }) : err(id, C.Internal, r.body?.reason || "create terminal failed");
      }
      if (m === "ListTerminals") {
        const r = await djson("GET", "/v1/hypervisor/terminals");
        const terminals = (r.body?.terminals || []).filter((t) => t.environment_ref === envRef).map((t) => ({ terminalId: t.terminal_id, shell: t.shell, cols: t.cols, rows: t.rows }));
        return ok(id, { terminals });
      }
      if (m === "WriteTerminal") {
        const data = Buffer.from(params?.data || "", "base64").toString("utf8");
        await djson("POST", `/v1/hypervisor/terminals/${encodeURIComponent(params?.terminalId)}/input`, { data }, token);
        return ok(id, {});
      }
      if (m === "ResizeTerminal") {
        await djson("POST", `/v1/hypervisor/terminals/${encodeURIComponent(params?.terminalId)}/resize`, { cols: params?.cols, rows: params?.rows }, token);
        return ok(id, {});
      }
      if (m === "CloseTerminal") {
        await djson("POST", `/v1/hypervisor/terminals/${encodeURIComponent(params?.terminalId)}/close`, {}, token);
        return ok(id, {});
      }

      // --- terminal output stream (server-streaming): poll the daemon terminal stream (snapshot
      // per `since` offset) and forward new output as connect-style chunks until close/abort ---
      if (m === "AttachTerminal" || m === "ReadTerminal") {
        const termId = params?.terminalId;
        let aborted = false;
        let since = 0;
        let first = !params?.skipHistory;
        streams.set(id, () => { aborted = true; });
        (async () => {
          try {
            while (!aborted) {
              let r;
              try { r = await fetch(`${DAEMON}/v1/hypervisor/terminals/${encodeURIComponent(termId)}/stream?since=${since}`); }
              catch { break; }
              if (r.status === 404) { ok(id, { exited: { exitCode: 0 } }); ok(id, null); break; }
              const text = await r.text();
              let outChunk = ""; let newOffset = since; let running = true;
              for (const f of text.split("\n\n")) {
                let ev = null, data = null;
                for (const line of f.split("\n")) { if (line.startsWith("event: ")) ev = line.slice(7); else if (line.startsWith("data: ")) data = line.slice(6); }
                if (ev === "output" && data) { try { const d = JSON.parse(data); outChunk += d.output || ""; if (typeof d.offset === "number") newOffset = d.offset; if (typeof d.running === "boolean") running = d.running; } catch { /* */ } }
              }
              if (outChunk) {
                const b64 = Buffer.from(outChunk, "utf8").toString("base64");
                if (first) { first = false; ok(id, { replay: { data: b64, cols: 80, rows: 24 } }); }
                else ok(id, { data: { data: b64 } });
              }
              since = newOffset;
              if (!running) { ok(id, { exited: { exitCode: 0 } }); ok(id, null); break; }
              await new Promise((res) => setTimeout(res, 250));
            }
          } catch { /* aborted/closed */ }
        })();
        return;
      }

      // --- Watch (server-streaming): a real fs watcher (inotify) over the env workspace ---
      if (m === "Watch") {
        const envInfo = await djson("GET", `/v1/hypervisor/environments/${encodeURIComponent(env)}`);
        const wsRoot = envInfo.body?.environment?.status?.workspace_root;
        if (!wsRoot) { return err(id, C.Unavailable, "workspace not started"); }
        let timer = null;
        const watcher = fsWatch(wsRoot, { recursive: true }, (_evt, fname) => {
          if (fname && String(fname).includes(".git/")) return; // ignore git internals churn
          ok(id, { fileChanges: { events: [{ path: String(fname || ""), type: "FILE_CHANGE_TYPE_UPDATED", isDirectory: false }] } });
          if (timer) clearTimeout(timer);
          timer = setTimeout(() => ok(id, { gitStatusChanged: {} }), 250);
        });
        streams.set(id, () => { try { watcher.close(); } catch { /* */ } if (timer) clearTimeout(timer); });
        return;
      }

      // --- everything else (files / git / capabilities / exec): delegate to the daemon contract ---
      const r = await djson("POST", `/supervisor/${encodeURIComponent(env)}/supervisor.v1.EnvironmentOpsService/${m}`, params || {}, token);
      if (r.status >= 200 && r.status < 300) {
        if (STREAMING.has(m)) ok(id, null); // shouldn't happen (handled above)
        else ok(id, r.body);
      } else {
        err(id, r.status === 404 ? C.NotFound : r.status === 501 ? C.Unimplemented : C.Internal, r.body?.message || `daemon ${r.status}`);
      }
    } catch (e) {
      err(id, C.Internal, String(e?.message || e));
    }
  });

  ws.on("close", () => { for (const c of streams.values()) { try { c(); } catch { /* */ } } streams.clear(); });
  ws.on("error", () => {});
}

// The env-ops WS transport is GATED OFF by default. The terminal/watch contract works over it
// (verified at the protocol level: PTY echo + fs-watch, lease-secured), BUT the harvested reference
// SPA throws React #306 in its EnvironmentContent component the moment the supervisor probe reports
// "available" — which would regress the working Code/Files/Changes panels. So for the product SPA we
// keep the WS unavailable (probe 404s → available:false → files/git keep working over HTTP). Enable
// with IOI_ENV_OPS_WS=1 for non-SPA clients (CLI/SDK) or a bundle where #306 is fixed.
const ENV_OPS_WS = process.env.IOI_ENV_OPS_WS === "1";
const supervisorWss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  const pathname = (req.url || "").split("?")[0];
  if (ENV_OPS_WS && (pathname === "/supervisor.v1.EnvironmentOpsService/" || pathname.startsWith("/supervisor/"))) {
    supervisorWss.handleUpgrade(req, socket, head, (ws) => handleSupervisorWs(ws));
  } else {
    socket.destroy();
  }
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
