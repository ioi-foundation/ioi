#!/usr/bin/env node
// Serve the product-ui bundle as the hypervisor app, with an IOI-owned /api adapter in front.
//
// "Start with the reference, work backwards": the app serves the reference's actual live
// bundle (so dark mode + every client interaction work natively — no hand-wired tail, and
// it's pixel-exact). On top of that, an IOI-owned API adapter progressively replaces the
// reference's mocked /api with real IOI behavior, endpoint by endpoint; anything not yet
// ported is transparently proxied to the product-ui bundle so nothing breaks mid-migration.
//
// Architecture:
//   browser :PORT ──▶ this server
//                       ├─ /api/* handled by ioi-api-adapter ─▶ IOI behavior (real)
//                       └─ everything else (and unported /api) ─▶ proxy to productUi :PRODUCT_UI_PORT
//   productUi :PRODUCT_UI_PORT = product-ui server (bundle + IOI branding + remaining mocks)
//
// Transitional: the harvested bundle stays in the gitignored local productUi (not committed),
// so this mode requires the productUi present. The IOI adapter + serve layer are committed.
//
// Usage: PORT=4173 node apps/hypervisor/scripts/serve-product-ui.mjs
import http from "node:http";
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import * as adapter from "./ioi-api-adapter.mjs";
import { getRun, listRuns, hydrateRunsFromDaemon, publishRunViaConnector } from "./ioi-agent-runs.mjs";
import { projectRunTimeline } from "./ioi-run-timeline.mjs";

// Build the current conversation entries for a run, in the exact NDJSON shape the SPA's V1 pane
// renders ({id, phase, userInput|todoGroup|text}). Streamed entries are emitted once each (keyed by
// id) as the run progresses. While running we emit only the user prompt (the SPA shows its own
// "Thinking…" placeholder); on completion we emit the files the agent wrote + its summary, which
// replace the placeholder. Mirrors the harvested reference's bare-/conversation wire format.
function conversationFiles(run) {
  const files = [];
  for (const g of run.changedFiles || []) {
    if (Array.isArray(g?.files)) for (const f of g.files) files.push(typeof f === "string" ? f : f?.path);
    else if (typeof g === "string") files.push(g);
    else if (g?.path) files.push(g.path);
  }
  return [...new Set(files.filter(Boolean))];
}
function conversationEntries(run) {
  const out = [];
  // Block phase enum (the SPA's AgentResponseBlock.phase): UNSPECIFIED=0, UPDATE=1, COMPLETED=2,
  // DELTA=3. The SPA computes a text fragment's `completed` as `phase === COMPLETED(2)`; a
  // non-completed agent text renders as a shimmer "Thinking…" placeholder. So agent blocks MUST use
  // the numeric value 2 (an enum NAME string like "PHASE_COMPLETED" is unknown → defaults to 0 →
  // perpetual "Thinking…"). TextOutput.Type: USER_FACING_OUTPUT=1 (THOUGHTS=2 would render as a
  // collapsed thought, not the answer).
  const PHASE_COMPLETED = 2, TEXT_USER_FACING = 1;
  // Echo the userInput with the SAME id the SPA generated for its optimistic pending message
  // (body.userInput.id, captured as run.userInputBlockId). The SPA reconciles its pending turn
  // against the streamed message by this id (exactly as the real upstream reference backend echoes the client id),
  // so there is no duplicate and the pending "Thinking…" resolves once the agent reply follows.
  if (run.prompt && run.userInputBlockId) {
    out.push({ id: run.userInputBlockId, phase: PHASE_COMPLETED, userInput: { id: run.userInputBlockId, inputs: [{ text: { content: run.prompt } }] } });
  }
  const done = run.status === "done" || run.status === "failed";
  if (done) {
    const files = conversationFiles(run);
    if (run.status === "done" && files.length) {
      out.push({ id: `${run.id}-todos`, phase: PHASE_COMPLETED, todoGroup: { groupId: `${run.id}-todos`, todos: files.slice(0, 12).map((p, i) => ({ id: `f${i}`, title: `Wrote ${p}`, completed: true })) } });
    }
    const summary = run.status === "failed" ? `Run failed: ${run.error || "unknown error"}` : (run.summary || "Run complete.");
    out.push({ id: `${run.id}-summary`, phase: PHASE_COMPLETED, text: { content: summary, type: TEXT_USER_FACING } });
  }
  return out;
}

function varint(value) {
  let n = BigInt(value);
  const bytes = [];
  do {
    let byte = Number(n & 0x7fn);
    n >>= 7n;
    if (n) byte |= 0x80;
    bytes.push(byte);
  } while (n);
  return Buffer.from(bytes);
}
function concat(...parts) {
  return Buffer.concat(parts.filter((part) => part && part.length !== 0));
}
function fieldVarint(fieldNo, value) {
  return concat(varint((BigInt(fieldNo) << 3n) | 0n), varint(value));
}
function fieldBytes(fieldNo, bytes) {
  return concat(varint((BigInt(fieldNo) << 3n) | 2n), varint(bytes.length), bytes);
}
function fieldString(fieldNo, value) {
  return fieldBytes(fieldNo, Buffer.from(String(value), "utf8"));
}
function fieldMessage(fieldNo, message) {
  return fieldBytes(fieldNo, message);
}
function encodeUserTextBlock(id, content) {
  // ioi.v1.UserInputBlock:
  //   id = 1
  //   repeated inputs = 30
  // UserInputBlock.Input.text = 20
  const textInput = fieldString(1, content);
  const input = fieldMessage(20, textInput);
  return concat(fieldString(1, id), fieldMessage(30, input));
}
function encodeAgentTextBlock(id, content) {
  // ioi.v1.AgentResponseBlock:
  //   id = 1
  //   phase = 2 (PHASE_COMPLETED)
  //   text = 10, with TextOutput.type = 1 (TYPE_USER_FACING_OUTPUT)
  const textOutput = concat(fieldVarint(1, 1), fieldString(2, content), fieldVarint(3, 1));
  return concat(fieldString(1, id), fieldVarint(2, 2), fieldMessage(10, textOutput));
}
function conversationSummary(run) {
  const summary = run.status === "failed"
    ? `Run failed: ${run.error || "unknown error"}`
    : (run.summary || "Run complete.");
  const files = conversationFiles(run);
  return files.length ? `${summary}\n\nChanged files:\n${files.map((path) => `- ${path}`).join("\n")}` : summary;
}
function frame(kind, payload) {
  // The harvested V2 conversation stream uses a compact frame:
  //   1 = AgentResponseBlock, 2 = UserInputBlock, 3 = AgentMessage
  // followed by protobuf binary for that message.
  return Buffer.concat([Buffer.from([kind]), payload]).toString("base64");
}
// The SPA's workbench terminal is a parser-less <pre> (no xterm.js / ANSI lib anywhere in the
// harvested bundle), so raw VT/ANSI escapes render as literal garbage (boxes + "[?2004h", "[01;32m").
// Sanitize the PTY byte stream in this transport bridge: strip CSI (incl. bracketed-paste + SGR
// color), OSC (window title), other ESC sequences, and stray control bytes — keeping \t \n \r.
// Stateful: a sequence split across poll chunks is held in `tail` so it still strips cleanly next
// poll. The daemon still OWNS execution + emits correct ANSI; this only adapts the bytes for a
// renderer that has no emulator.
function makeTerminalSanitizer() {
  let tail = "";
  // strip CSI | OSC | other-ESC | stray control bytes; keep only \t (09) and \n (0a) — drop \r (0d)
  // too, since the parser-less <pre> would render a lone CR as a box.
  const SEQ = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|[\x00-\x08\x0b-\x1f\x7f]/g;
  const INCOMPLETE = /\x1b(\[[0-9;?]*[ -/]*|\][^\x07\x1b]*)?$/; // trailing partial CSI/OSC/lone ESC
  return (chunk) => {
    let s = tail + chunk;
    tail = "";
    const m = s.match(INCOMPLETE);
    if (m && m[0].length <= 512) { tail = m[0]; s = s.slice(0, s.length - m[0].length); }
    return s.replace(SEQ, "");
  };
}
function conversationChunks(run) {
  const chunks = [];
  if (run?.prompt && run?.userInputBlockId) {
    chunks.push({
      id: `${run.id}-input`,
      previous_id: null,
      frames: [frame(2, encodeUserTextBlock(run.userInputBlockId, run.prompt))],
    });
  }
  const done = run?.status === "done" || run?.status === "failed";
  if (done) {
    chunks.push({
      id: `${run.id}-output`,
      previous_id: chunks[chunks.length - 1]?.id || null,
      frames: [frame(1, encodeAgentTextBlock(`${run.id}-summary`, conversationSummary(run)))],
    });
  }
  if (chunks.length === 0) {
    chunks.push({ id: `${run.id}-empty`, previous_id: null, frames: [] });
  }
  return chunks;
}
function selectConversationChunks(chunks, query) {
  const at = query.get("at");
  if (at) return chunks.filter((chunk) => chunk.id === at).slice(0, 1);
  const before = query.get("before");
  if (before) {
    const idx = chunks.findIndex((chunk) => chunk.id === before);
    return idx > 0 ? chunks.slice(0, idx).reverse() : [];
  }
  const after = query.get("after");
  if (after) {
    const idx = chunks.findIndex((chunk) => chunk.id === after);
    return idx >= 0 ? chunks.slice(idx + 1).reverse() : chunks.slice().reverse();
  }
  return chunks.slice(-1);
}
const HERE = dirname(fileURLToPath(import.meta.url));
const AUG_PATH = join(HERE, "ioi-augmentation.js");
// WS-I: injected IOI-native surface tag (mounted beside the cockpit; never edits the seeded SPA's DOM).
const AUG_TAG = '<script src="/ioi-augmentation.js" defer></script>';
const FEATURE_FLAG_TAG = '<script>try{localStorage.setItem("feature_flag_supervisor_watch_enabled","true")}catch(e){}</script>';
// Only inject into a real HTML document (one with a </body>). The productUi mislabels some JSON
// endpoints (/segment/*, /changelog/*) as text/html; appending the tag to those corrupts the
// body the SPA later parses with Response.json() — so never append when there's no </body>.
function augmentHtml(html) {
  if (!html.includes("</body>")) return html;
  const withFlags = html.includes("<head>") ? html.replace("<head>", `<head>${FEATURE_FLAG_TAG}`) : FEATURE_FLAG_TAG + html;
  return withFlags.replace("</body>", AUG_TAG + "</body>");
}
const REPO_ROOT = join(HERE, "..", "..", "..");
const REF_SERVER = join(HERE, "..", "product-ui", "server.cjs");
const PORT = Number(process.env.PORT || 4173);
const PRODUCT_UI_PORT = Number(process.env.PRODUCT_UI_PORT || 9301);
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

// The browser-facing origin, honoring a reverse tunnel (localhost.run / cloudflared set
// x-forwarded-proto/host). OAuth providers like Slack require an HTTPS redirect, so we must build
// the redirect_uri from the PUBLIC scheme+host, not a hardcoded http://127.0.0.1.
function publicBase(req) {
  const host = req.headers["x-forwarded-host"] || req.headers.host || "127.0.0.1:4173";
  const proto = req.headers["x-forwarded-proto"] || (/\.(lhr\.life|trycloudflare\.com|ngrok[^/]*)$/.test(host) ? "https" : "http");
  return `${proto}://${host}`;
}

// ---- Connections cockpit — the owned surface for ALL external capability bindings ----------------
// Doctrine: Connections owns every binding (MCP, communication, OAuth apps, bearer/PAT, cloud roles,
// service accounts); Org/User Settings > Integrations are thin projections; MCP is one type inside.
// Agents consume only scoped leases — credentials are sealed in the daemon, never exposed.
const CX_ESC = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
function connectionCategory(c) {
  if (c.kind === "mcp") return "MCP servers";
  if (["slack", "discord", "teams", "email"].includes(c.service)) return "Communication channels";
  if (c.kind === "aws-sigv4" || /aws|s3|sts/i.test(c.service || "")) return "Cloud roles";
  if (c.kind === "service-account") return "Service accounts";
  return "APIs & services";
}
function authDescriptor(c) {
  const ap = c.auth_profile || null;
  if (ap && ap.type) return ap.type === "oauth_authcode_pkce" ? (ap.discovered ? "OAuth (auto-discovered + DCR)" : (ap.sealed_client_secret ? "OAuth (confidential BYOA)" : "OAuth + PKCE")) : ap.type;
  if (c.kind === "aws-sigv4") return "AWS SigV4";
  if (c.kind === "service-account") return "Service account";
  if (c.kind === "oidc-workload") return "OIDC workload";
  return c.requires_credential === false ? "open" : "bearer / token";
}
function connectionsShell(inner) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connections · Hypervisor</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:8px}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 26px;max-width:680px}
  .add{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 30px}
  .add a{display:inline-flex;align-items:center;gap:6px;padding:9px 14px;border-radius:9px;border:1px solid #2a2c33;background:#15171c;color:#e6e7ea;text-decoration:none;font-weight:500}
  .add a:hover{border-color:#3a82f6;background:#191b21}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:28px 0 10px;font-weight:600}
  .card{display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:8px}
  .card .main{flex:1;min-width:0}
  .card .name{font-weight:600;color:#fff}
  .card .meta{color:#878a93;font-size:12.5px;margin-top:2px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:8px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .risk{color:#9a9da6;border-color:#2a2c33}
  .act{padding:7px 14px;border-radius:8px;border:0;background:#fff;color:#111;font:inherit;font-weight:600;text-decoration:none;white-space:nowrap}
  .act:hover{background:#eee}
  .act.ghost{background:transparent;color:#9a9da6;border:1px solid #2a2c33}
  .act.ghost:hover{color:#e6e7ea;border-color:#3a3d45}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div><h1>Connections</h1>
<p class="sub">Every external capability binding the workspace can use. Agents receive only scoped, policy-gated capability leases — the underlying credentials are sealed in the daemon and never reach a session.</p>
${inner}</div></body></html>`;
}
function renderConnectionsCockpit(connectors, scmConnectors, leases) {
  const leaseCount = (id) => (leases || []).filter((l) => String(l.backing_provider || "").includes(id) || String(l.resource_refs || "").includes(id)).length;
  const groups = {};
  const push = (cat, html) => { (groups[cat] = groups[cat] || []).push(html); };
  for (const c of connectors || []) {
    const bound = c.auth_posture === "token-lease:bound" || c.auth_posture === "open";
    const risk = (c.org_policy && c.org_policy.risk_posture) || "standard";
    const tools = c.kind === "mcp" ? "tools discovered on connect" : ((c.allowed_tools || []).map((t) => t.name).join(", ") || "—");
    const lc = leaseCount(c.connector_id);
    // Connect target: Slack w/o a client → its setup; OAuth-profile → launcher; else manage.
    const slackNoClient = c.service === "slack" && !(c.auth_profile && c.auth_profile.client_id);
    const connectHref = slackNoClient ? "/__ioi/slack/setup" : `/__ioi/integrations/connect/${encodeURIComponent(c.connector_id)}`;
    const action = bound
      ? `<span class="pill ok">connected</span>`
      : `<a class="act" href="${connectHref}" target="_blank" rel="noopener">Connect ↗</a>`;
    push(connectionCategory(c), `<div class="card"><div class="main">
      <div class="name">${CX_ESC(c.name || c.service)}${bound ? "" : '<span class="pill warn">needs auth</span>'}<span class="pill risk">risk: ${CX_ESC(risk)}</span></div>
      <div class="meta">${CX_ESC(authDescriptor(c))} · <code>${CX_ESC(c.base_url || "")}</code> · tools: ${CX_ESC(tools)}${lc ? ` · ${lc} lease${lc > 1 ? "s" : ""} issued` : ""}</div>
      </div>${action}</div>`);
  }
  for (const c of scmConnectors || []) {
    const bound = c.auth_posture === "token-lease:bound";
    push("Code / SCM", `<div class="card"><div class="main">
      <div class="name">${CX_ESC(c.name || c.kind)}${bound ? "" : '<span class="pill warn">needs auth</span>'}</div>
      <div class="meta">${CX_ESC(c.kind)} · <code>${CX_ESC(c.host || c.remote_url || "")}</code>${c.connected_login ? ` · @${CX_ESC(c.connected_login)}` : ""}</div>
      </div>${bound ? '<span class="pill ok">connected</span>' : '<a class="act ghost" href="/settings/runners?user-settings=git-authentications" target="_blank">Git authentications ↗</a>'}</div>`);
  }
  const order = ["MCP servers", "Communication channels", "Cloud roles", "Service accounts", "APIs & services", "Code / SCM"];
  const cats = Object.keys(groups).sort((a, b) => order.indexOf(a) - order.indexOf(b));
  const body = cats.length
    ? cats.map((cat) => `<h2>${CX_ESC(cat)}</h2>${groups[cat].join("")}`).join("")
    : `<div class="empty">No connections yet — add one above.</div>`;
  const add = `<div class="add">
    <a href="/__ioi/connections/add?type=mcp">+ MCP server</a>
    <a href="/__ioi/slack/setup">+ Connect Slack</a>
    <a href="/__ioi/connections/add?type=bearer">+ API key / service</a>
  </div>`;
  return connectionsShell(add + body);
}

// ---- Automations cockpit — the owned, PROJECT-FIRST surface for HypervisorAutomationSpec ----------
// Doctrine: an automation is project-scoped DURABLE work (spec + runs + receipts + authority/memory/
// connectors + proof), not an org-scoped workflow. This owned surface renders the daemon
// /v1/hypervisor/automations plane natively; the SPA's org-scoped WorkflowService surface is NOT canonical.
function automationsShell(title, inner) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${CX_ESC(title)} · Hypervisor</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
  .wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
  a{color:#8ab4ff}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:8px}
  h1{font-size:26px;margin:0 0 6px;letter-spacing:-.02em}
  .sub{color:#9a9da6;margin:0 0 22px;max-width:680px}
  .row{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 22px}
  .act{padding:8px 14px;border-radius:8px;border:0;background:#fff;color:#111;font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
  .act:hover{background:#eee}
  .act.ghost{background:transparent;color:#cbd0da;border:1px solid #2a2c33}
  .act.ghost:hover{color:#fff;border-color:#3a3d45}
  .act.danger{background:transparent;color:#e06a6a;border:1px solid #5c2a2a}
  .act.danger:hover{background:#2a1212}
  h2{font-size:13px;letter-spacing:.04em;text-transform:uppercase;color:#878a93;margin:26px 0 10px;font-weight:600}
  .card{display:flex;align-items:center;gap:14px;padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin-bottom:8px;text-decoration:none;color:inherit}
  a.card:hover{border-color:#3a82f6;background:#191b21}
  .card .main{flex:1;min-width:0}
  .card .name{font-weight:600;color:#fff}
  .card .meta{color:#878a93;font-size:12.5px;margin-top:3px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;border:1px solid;white-space:nowrap;margin-left:8px}
  .ok{color:#46c277;border-color:#235c3b;background:#11281b}
  .warn{color:#d6a13a;border-color:#5c4a23;background:#28220f}
  .muted{color:#9a9da6;border-color:#2a2c33}
  .empty{color:#6f7280;padding:18px;border:1px dashed #24262d;border-radius:12px}
  .grid{display:grid;grid-template-columns:160px 1fr;gap:8px 16px;padding:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;margin:0 0 18px}
  .grid dt{color:#878a93;font-size:12.5px}
  .grid dd{margin:0;color:#e6e7ea}
  code{font-size:11.5px;color:#aab;background:#0e0f13;padding:1px 5px;border-radius:4px}
  pre{background:#0e0f13;border:1px solid #24262d;border-radius:8px;padding:12px;overflow:auto;font:11.5px/1.5 ui-monospace,monospace;color:#cdd1d8;white-space:pre-wrap;word-break:break-all}
  .reveal{color:#46c277;background:#11281b;border:1px solid #235c3b;border-radius:8px;padding:12px;font:12px ui-monospace,monospace;word-break:break-all}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;color:#878a93;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid #24262d}
  td{padding:8px 10px;border-bottom:1px solid #1b1d23}
  .tabs{display:flex;gap:4px;border-bottom:1px solid #24262d;margin:22px 0 18px}
  .tab{background:transparent;border:0;border-bottom:2px solid transparent;color:#9a9da6;font:inherit;font-weight:600;padding:9px 14px;cursor:pointer}
  .tab:hover{color:#e6e7ea}
  .tab.active{color:#fff;border-bottom-color:#3a82f6}
  .canvas{display:grid;grid-template-columns:1fr 300px;gap:18px;align-items:start}
  .cgraph{display:flex;align-items:center;gap:6px;overflow-x:auto;padding:10px;border:1px solid #24262d;border-radius:12px;background:#101216;min-height:200px}
  .clane{display:flex;flex-direction:column;gap:10px}
  .cedge{color:#4a4d55;font-size:20px;flex:0 0 auto}
  .cnode{min-width:150px;max-width:180px;padding:11px 13px;border:1px solid #2a2c33;border-radius:10px;background:#15171c;cursor:pointer}
  .cnode:hover{border-color:#3a82f6}
  .cnode.sel{border-color:#3a82f6;box-shadow:0 0 0 1px #3a82f6 inset}
  .cnode.ok{border-left:3px solid #46c277}
  .cnode.warn{border-left:3px solid #d6a13a}
  .cnode .ct{font-weight:600;color:#fff;font-size:12.5px}
  .cnode .cs{color:#878a93;font-size:11.5px;margin-top:4px;word-break:break-word}
  .cinsp{padding:14px;border:1px solid #24262d;border-radius:12px;background:#15171c}
  .cinsp h3{margin:0 0 10px;font-size:13px}
  .cmsg{font-size:12px;color:#d6a13a}
  .field{margin:0 0 14px}
  .field label{display:block;color:#c7c9cf;font-size:12.5px;margin-bottom:5px}
  .field input,.field select,.field textarea{width:100%;box-sizing:border-box;padding:10px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit}
  .field textarea{min-height:84px;resize:vertical}
  .two{display:grid;grid-template-columns:1fr 1fr;gap:0 16px}
  form.inline{display:inline}
</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div>${inner}</div></body></html>`;
}
function automationProjectName(a, projectsById) {
  const pid = a.project_ref || a.project_id || "";
  return (projectsById[pid] && projectsById[pid].name) || pid || "—";
}
function renderAutomationsList(automations, projectId, projectsById) {
  const filtName = projectId ? automationProjectName({ project_ref: projectId }, projectsById) : "";
  const newHref = `/__ioi/automations/new${projectId ? `?project=${encodeURIComponent(projectId)}` : ""}`;
  const head = `<h1>Automations</h1>
    <p class="sub">Project-scoped durable work — each automation hangs off a project, runs on the daemon over a real environment, and records a tamper-evident transcript. ${projectId ? `Filtered to <b>${CX_ESC(filtName)}</b> · <a href="/__ioi/automations">show all</a>` : "Showing all projects."}</p>
    <div class="row"><a class="act" href="${newHref}">+ New automation</a></div>`;
  if (!automations.length) {
    return automationsShell("Automations", head + `<div class="empty">No automations yet${projectId ? " for this project" : ""} — create one to get started.</div>`);
  }
  const cards = automations.map((a) => {
    const enabled = a.enabled !== false;
    const steps = Array.isArray(a.steps) ? a.steps.length : 0;
    const model = a.model || "default model";
    return `<a class="card" href="/__ioi/automations/${encodeURIComponent(a.automation_id)}"><div class="main">
      <div class="name">${CX_ESC(a.name || a.automation_id)}<span class="pill ${enabled ? "ok" : "muted"}">${enabled ? "enabled" : "disabled"}</span><span class="pill muted">${CX_ESC(a.trigger_kind || "manual")}</span></div>
      <div class="meta">${CX_ESC(automationProjectName(a, projectsById))} · ${CX_ESC(String(model))} · ${steps} step${steps === 1 ? "" : "s"}</div>
      </div><span class="act ghost">Open →</span></a>`;
  }).join("");
  return automationsShell("Automations", head + cards);
}
function renderAutomationDetail(a, runs, projectsById, webhook) {
  const id = a.automation_id;
  const enabled = a.enabled !== false;
  const pid = a.project_ref || a.project_id || "";
  const v = (x) => (x == null || x === "" ? "—" : (typeof x === "string" ? CX_ESC(x) : CX_ESC(JSON.stringify(x))));
  const connectors = Array.isArray(a.connector_refs) && a.connector_refs.length ? a.connector_refs.map((c) => `<code>${CX_ESC(String(c))}</code>`).join(" ") : "—";
  const steps = Array.isArray(a.steps) && a.steps.length
    ? `<h2>Steps</h2>` + a.steps.map((s, i) => `<div class="card"><div class="main"><div class="name">${i + 1}. ${CX_ESC(s.kind || "step")}</div><div class="meta"><code>${CX_ESC((s.prompt || s.command || s.title || "").slice(0, 200))}</code></div></div></div>`).join("")
    : `<h2>Steps</h2><div class="empty">No steps declared.</div>`;
  const runRows = (runs || []).length
    ? `<table><thead><tr><th>Run</th><th>Status</th><th>Started</th><th>Steps (done/failed)</th><th>Proof</th></tr></thead><tbody>` +
      runs.map((r) => {
        const c = r.counts || {};
        const st = r.status || "—";
        const pill = st === "done" ? "ok" : st === "failed" ? "warn" : "muted";
        return `<tr><td><code>${CX_ESC(r.execution_id || "")}</code></td><td><span class="pill ${pill}">${CX_ESC(st)}</span></td><td>${CX_ESC(r.started_at || "")}</td><td>${c.done || 0}/${c.failed || 0}</td><td><a href="/__ioi/run-timeline/${encodeURIComponent(r.execution_id || "")}" target="_blank" rel="noopener">timeline ↗</a></td></tr>`;
      }).join("") + `</tbody></table>`
    : `<div class="empty">No runs yet — use “Run now”.</div>`;
  const sched = a.schedule_spec && typeof a.schedule_spec === "object" ? a.schedule_spec : null;
  const scheduleHuman = sched
    ? ((sched.type === "cron" || sched.cron) ? `cron ${sched.cron} (${sched.timezone || "UTC"})`
       : sched.every_hours ? `every ${sched.every_hours}h`
       : sched.every_minutes ? `every ${sched.every_minutes}m`
       : (sched.every_seconds || sched.interval_seconds) ? `every ${sched.every_seconds || sched.interval_seconds}s`
       : "scheduled")
    : "manual (no schedule)";
  const back = `<p><a href="/__ioi/automations${pid ? `?project=${encodeURIComponent(pid)}` : ""}">← Automations</a></p>`;
  const pauseResume = sched
    ? (enabled
        ? `<form class="inline" method="post" action="/__ioi/automations/${encodeURIComponent(id)}/pause"><button class="act ghost" type="submit">⏸ Pause schedule</button></form>`
        : `<form class="inline" method="post" action="/__ioi/automations/${encodeURIComponent(id)}/resume"><button class="act" type="submit">▶ Resume schedule</button></form>`)
    : "";
  const actions = `<div class="row">
    <form class="inline" method="post" action="/__ioi/automations/${encodeURIComponent(id)}/run"><button class="act" type="submit">▶ Run now</button></form>
    ${pauseResume}
    <a class="act ghost" href="/projects/${encodeURIComponent(pid)}" target="_blank" rel="noopener">Open project ↗</a>
    <form class="inline" method="post" action="/__ioi/automations/${encodeURIComponent(id)}/delete" onsubmit="return confirm('Delete this automation?')"><button class="act danger" type="submit">Delete</button></form>
  </div>`;
  const spec = `<dl class="grid">
    <dt>Project</dt><dd><a href="/projects/${encodeURIComponent(pid)}" target="_blank" rel="noopener">${CX_ESC(automationProjectName(a, projectsById))}</a> <code>${CX_ESC(pid)}</code></dd>
    <dt>Trigger</dt><dd>${v(a.trigger_kind || "manual")}</dd>
    <dt>Schedule</dt><dd>${CX_ESC(scheduleHuman)}${sched ? ` · ${enabled ? "active" : "paused"}` : ""}</dd>
    <dt>Next run</dt><dd>${v(a.next_run_at)}</dd>
    <dt>Last run</dt><dd>${v(a.last_run_at)}</dd>
    <dt>Agent</dt><dd>${v(a.agent_ref)}</dd>
    <dt>Model</dt><dd>${v(a.model)}</dd>
    <dt>Reasoning</dt><dd>${v(a.reasoning)}</dd>
    <dt>Harness</dt><dd>${v(a.harness_profile_ref)}</dd>
    <dt>Connectors</dt><dd>${connectors}</dd>
    <dt>Memory</dt><dd>${v(a.memory_profile_ref)}</dd>
    <dt>Authority policy</dt><dd>${v(a.authority_policy_ref)}</dd>
    <dt>Runtime policy</dt><dd>${v(a.default_runtime_policy_ref)}</dd>
    <dt>Env class</dt><dd>${v(a.environment_class_id)}</dd>
  </dl>`;
  // Webhook trigger section (authenticated inbound trigger; secret is hash-at-rest, shown once on rotate).
  const wh = webhook || {};
  const whUrl = a.webhook_url ? `${wh.baseUrl || ""}${a.webhook_url}` : "";
  const evRows = (wh.events || []).slice(0, 10).map((e) => {
    const acc = e.accepted === true;
    return `<tr><td>${CX_ESC(e.received_at || "")}</td><td><span class="pill ${acc ? "ok" : "warn"}">${acc ? "accepted" : "rejected"}</span></td><td>${CX_ESC(e.reason || "")}</td><td>${e.run_ref ? `<a href="/__ioi/run-timeline/${encodeURIComponent(e.run_ref)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td></tr>`;
  }).join("");
  const webhookSection = a.webhook_url
    ? `<h2>Webhook trigger</h2>
       <dl class="grid">
         <dt>Endpoint</dt><dd><code>POST ${CX_ESC(whUrl)}</code></dd>
         <dt>Auth</dt><dd>header <code>X-IOI-Trigger-Token: &lt;secret&gt;</code> · secret shown once on rotate</dd>
         <dt>Triggers</dt><dd>${wh.accepted || 0} accepted · ${wh.rejected || 0} rejected</dd>
       </dl>
       <div class="row"><form class="inline" method="post" action="/__ioi/automations/${encodeURIComponent(id)}/webhook-rotate"><button class="act ghost" type="submit">↻ Rotate secret</button></form></div>
       <pre>curl -X POST ${CX_ESC(whUrl)} \\
  -H "X-IOI-Trigger-Token: $TOKEN" \\
  -H "content-type: application/json" \\
  -d '{"event":"ping"}'</pre>
       ${evRows ? `<table><thead><tr><th>Received</th><th>Result</th><th>Reason</th><th>Run</th></tr></thead><tbody>${evRows}</tbody></table>` : `<div class="empty">No trigger events yet.</div>`}`
    : `<h2>Webhook trigger</h2><p class="sub">Trigger this automation from an external service with an authenticated webhook (the secret is sealed; only its hash is stored).</p>
       <form class="inline" method="post" action="/__ioi/automations/${encodeURIComponent(id)}/webhook-rotate"><button class="act" type="submit">Enable webhook trigger</button></form>`;
  // ---- Canvas: a projection/editor over the spec (nodes + inspector). Edits PATCH the daemon
  // record — the Canvas edits the automation, it does not become the automation. ----
  const schedType = sched ? ((sched.type === "cron" || sched.cron) ? "cron" : "interval") : "manual";
  const intN = sched ? (sched.every_hours || sched.every_minutes || sched.every_seconds || sched.interval_seconds || "") : "";
  const intU = sched ? (sched.every_hours ? "hours" : (sched.every_seconds || sched.interval_seconds) ? "seconds" : "minutes") : "minutes";
  const cronExpr = sched && sched.cron ? sched.cron : "";
  const cronTz = (sched && sched.timezone) || "UTC";
  const cronTzOpts = ["UTC", "-08:00", "-07:00", "-06:00", "-05:00", "-04:00", "+01:00", "+02:00", "+05:30", "+08:00", "+09:00", "+10:00"]
    .map((z) => `<option value="${z}"${z === cronTz ? " selected" : ""}>${z === "UTC" ? "UTC (+00:00)" : "UTC" + z}</option>`).join("");
  const lastRun = (runs && runs[0]) || null;
  const runCls = lastRun ? (lastRun.status === "done" ? "ok" : lastRun.status === "failed" ? "warn" : "") : "";
  const triggerSummary = scheduleHuman + (a.webhook_url ? " + webhook" : "");
  const agentSummary = `${a.model || "default model"}${a.reasoning ? " · " + a.reasoning : ""}`;
  const connSummary = Array.isArray(a.connector_refs) && a.connector_refs.length ? a.connector_refs.join(", ") : "none";
  const memSummary = a.memory_profile_ref || "default";
  const authSummary = a.authority_policy_ref || "default";
  const stepCount = Array.isArray(a.steps) ? a.steps.length : 0;
  const deliverySummary = `${stepCount} step${stepCount === 1 ? "" : "s"}${lastRun ? " · last run " + (lastRun.status || "") : ""}`;
  const cnode = (key, icon, title, summary, cls) => `<div class="cnode ${cls || ""}" data-node="${key}" onclick="ioiNode('${key}')"><div class="ct">${icon} ${CX_ESC(title)}</div><div class="cs">${CX_ESC(summary)}</div></div>`;
  const cgraph = `<div class="cgraph">
    <div class="clane">${cnode("trigger", "⏱", "Trigger", triggerSummary, runCls)}</div><div class="cedge">→</div>
    <div class="clane">${cnode("agent", "🤖", "Agent run", agentSummary, runCls)}</div><div class="cedge">→</div>
    <div class="clane">${cnode("connectors", "🔌", "Connectors", connSummary, "")}${cnode("memory", "🧠", "Memory", memSummary, "")}${cnode("authority", "🛡", "Authority", authSummary, "")}</div><div class="cedge">→</div>
    <div class="clane">${cnode("delivery", "📤", "Delivery", deliverySummary, "")}</div>
  </div>`;
  const fi = (cid, label, value, ph) => `<div class="field"><label>${label}</label><input id="${cid}" value="${CX_ESC(value || "")}" placeholder="${ph || ""}"></div>`;
  const firstStep = (Array.isArray(a.steps) && a.steps[0]) || {};
  const inspectors =
    `<div class="cinsp" id="insp-trigger" style="display:none"><h3>Trigger</h3>
       <div class="field"><label>Type</label><select id="cv-sched-type" onchange="cvSchedToggle()"><option value="manual"${schedType === "manual" ? " selected" : ""}>Manual only</option><option value="interval"${schedType === "interval" ? " selected" : ""}>Interval</option><option value="cron"${schedType === "cron" ? " selected" : ""}>Cron</option></select></div>
       <div id="cv-int" style="display:${schedType === "interval" ? "block" : "none"}"><div class="field"><label>Run every</label><input id="cv-interval-n" type="number" min="0" value="${schedType === "interval" ? CX_ESC(String(intN || 0)) : "15"}"></div><div class="field"><label>Unit</label><select id="cv-interval-unit"><option value="minutes"${intU === "minutes" ? " selected" : ""}>minutes</option><option value="hours"${intU === "hours" ? " selected" : ""}>hours</option><option value="seconds"${intU === "seconds" ? " selected" : ""}>seconds</option></select></div></div>
       <div id="cv-crn" style="display:${schedType === "cron" ? "block" : "none"}"><div class="field"><label>Cron</label><input id="cv-cron" value="${CX_ESC(cronExpr)}" placeholder="0 9 * * 1-5" oninput="cvCronPreview()"></div><div class="field"><label>Timezone</label><select id="cv-cron-tz" onchange="cvCronPreview()">${cronTzOpts}</select></div><div class="sub" style="margin:0" id="cv-cron-preview"></div></div>
       <div class="row"><button class="act" onclick="ioiNodeSave('trigger')">Save</button> <span class="cmsg" id="msg-trigger"></span></div></div>` +
    `<div class="cinsp" id="insp-agent" style="display:none"><h3>Agent run</h3>${fi("cv-model", "Model", a.model, "qwen2.5:7b")}<div class="field"><label>Reasoning</label><select id="cv-reasoning"><option value=""${!a.reasoning ? " selected" : ""}>(default)</option><option value="low"${a.reasoning === "low" ? " selected" : ""}>low</option><option value="medium"${a.reasoning === "medium" ? " selected" : ""}>medium</option><option value="high"${a.reasoning === "high" ? " selected" : ""}>high</option></select></div>${fi("cv-agent", "Agent ref", a.agent_ref, "agent:default")}${fi("cv-harness", "Harness profile", a.harness_profile_ref, "harness:…")}<div class="row"><button class="act" onclick="ioiNodeSave('agent')">Save</button> <span class="cmsg" id="msg-agent"></span></div></div>` +
    `<div class="cinsp" id="insp-connectors" style="display:none"><h3>Connectors</h3>${fi("cv-connectors", "Connector refs (comma-separated)", Array.isArray(a.connector_refs) ? a.connector_refs.join(", ") : "", "connector:github, connector:linear")}<div class="row"><button class="act" onclick="ioiNodeSave('connectors')">Save</button> <span class="cmsg" id="msg-connectors"></span></div></div>` +
    `<div class="cinsp" id="insp-memory" style="display:none"><h3>Memory</h3>${fi("cv-memory", "Memory profile ref", a.memory_profile_ref, "memory:project-default")}<div class="row"><button class="act" onclick="ioiNodeSave('memory')">Save</button> <span class="cmsg" id="msg-memory"></span></div></div>` +
    `<div class="cinsp" id="insp-authority" style="display:none"><h3>Authority</h3>${fi("cv-authority", "Authority policy ref", a.authority_policy_ref, "authority:operator")}${fi("cv-runtime", "Runtime policy ref", a.default_runtime_policy_ref, "runtime-policy:local")}<div class="row"><button class="act" onclick="ioiNodeSave('authority')">Save</button> <span class="cmsg" id="msg-authority"></span></div></div>` +
    `<div class="cinsp" id="insp-delivery" style="display:none"><h3>Delivery (first step)</h3><div class="field"><label>Step kind</label><select id="cv-step-kind"><option value="agent"${firstStep.kind !== "command" ? " selected" : ""}>agent (prompt)</option><option value="command"${firstStep.kind === "command" ? " selected" : ""}>command (shell)</option></select></div><div class="field"><label>Step body</label><textarea id="cv-step-body">${CX_ESC(firstStep.prompt || firstStep.command || "")}</textarea></div><div class="row"><button class="act" onclick="ioiNodeSave('delivery')">Save</button> <span class="cmsg" id="msg-delivery"></span></div></div>` +
    `<div class="cinsp" id="insp-none"><h3>Canvas</h3><p class="sub" style="margin:0">Click a node to edit it. Saving writes the automation spec via the daemon — the Canvas edits the automation, it does not become the automation.</p></div>`;
  const canvas = `<div class="canvas">${cgraph}<div>${inspectors}</div></div>`;
  const canvasScript = `<script>
    function ioiTab(t){['overview','runs','webhook','canvas'].forEach(function(k){var p=document.getElementById('panel-'+k);if(p)p.style.display=(k===t)?'block':'none';var b=document.querySelector('.tab[data-tab="'+k+'"]');if(b)b.classList.toggle('active',k===t);});}
    function val(id){var e=document.getElementById(id);return e?e.value:'';}
    function ioiNode(key){var none=document.getElementById('insp-none');if(none)none.style.display='none';['trigger','agent','connectors','memory','authority','delivery'].forEach(function(k){var n=document.querySelector('[data-node="'+k+'"]');if(n)n.classList.toggle('sel',k===key);var i=document.getElementById('insp-'+k);if(i)i.style.display=(k===key)?'block':'none';});}
    function cvSchedToggle(){var t=val('cv-sched-type'),i=document.getElementById('cv-int'),c=document.getElementById('cv-crn');if(i)i.style.display=t==='interval'?'block':'none';if(c)c.style.display=t==='cron'?'block':'none';}
    function cvCronPreview(){var c=(val('cv-cron')||'').trim(),tz=val('cv-cron-tz'),el=document.getElementById('cv-cron-preview');if(!el)return;if(!c){el.textContent='';return;}fetch('/__ioi/automations/cron-preview?cron='+encodeURIComponent(c)+'&tz='+encodeURIComponent(tz)+'&n=3').then(function(r){return r.json();}).then(function(d){el.textContent=d.ok?('next: '+d.runs.join('  ·  ')):('⚠ '+d.error);});}
    function ioiNodeSave(node){var body={};
      if(node==='trigger'){var t=val('cv-sched-type');if(t==='interval'){var n=parseInt(val('cv-interval-n')||'0',10)||0,u=val('cv-interval-unit');body.schedule_spec=n>0?(u==='hours'?{every_hours:n}:u==='seconds'?{every_seconds:n}:{every_minutes:n}):null;}else if(t==='cron'){var cc=(val('cv-cron')||'').trim();body.schedule_spec=cc?{type:'cron',cron:cc,timezone:val('cv-cron-tz')}:null;}else{body.schedule_spec=null;}}
      else if(node==='agent'){body.model=val('cv-model')||null;body.reasoning=val('cv-reasoning')||null;body.agent_ref=val('cv-agent')||null;body.harness_profile_ref=val('cv-harness')||null;}
      else if(node==='connectors'){body.connector_refs=(val('cv-connectors')||'').split(',').map(function(s){return s.trim();}).filter(Boolean);}
      else if(node==='memory'){body.memory_profile_ref=val('cv-memory')||null;}
      else if(node==='authority'){body.authority_policy_ref=val('cv-authority')||null;body.default_runtime_policy_ref=val('cv-runtime')||null;}
      else if(node==='delivery'){var sk=val('cv-step-kind'),sb=(val('cv-step-body')||'').trim();body.steps=sb?[sk==='command'?{kind:'command',command:sb}:{kind:'agent',prompt:sb}]:[];}
      var msg=document.getElementById('msg-'+node);if(msg)msg.textContent='saving…';
      fetch('/__ioi/automations/${encodeURIComponent(id)}/patch',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(d){if(d&&d.ok===false){if(msg)msg.textContent='⚠ '+((d.error&&d.error.message)||d.reason||'invalid');}else{location.reload();}}).catch(function(){if(msg)msg.textContent='save failed';});}
  </script>`;
  const inner = `${back}<h1>${CX_ESC(a.name || id)}<span class="pill ${enabled ? "ok" : "muted"}">${enabled ? "enabled" : "disabled"}</span></h1>
    <p class="sub">${CX_ESC(a.description || "")}</p>${actions}
    <div class="tabs">
      <button class="tab active" data-tab="overview" onclick="ioiTab('overview')">Overview</button>
      <button class="tab" data-tab="runs" onclick="ioiTab('runs')">Runs</button>
      <button class="tab" data-tab="webhook" onclick="ioiTab('webhook')">Webhook</button>
      <button class="tab" data-tab="canvas" onclick="ioiTab('canvas')">Canvas</button>
    </div>
    <div class="tab-panel" id="panel-overview">${spec}${steps}</div>
    <div class="tab-panel" id="panel-runs" style="display:none"><h2>Run history</h2>${runRows}</div>
    <div class="tab-panel" id="panel-webhook" style="display:none">${webhookSection}</div>
    <div class="tab-panel" id="panel-canvas" style="display:none">${canvas}</div>
    ${canvasScript}`;
  return automationsShell(a.name || "Automation", inner);
}
function renderAutomationNewForm(projectId, projects) {
  const opts = (projects || []).map((p) => `<option value="${CX_ESC(p.project_id)}"${p.project_id === projectId ? " selected" : ""}>${CX_ESC(p.name || p.project_id)}</option>`).join("");
  const tzOptions = ["UTC", "-08:00", "-07:00", "-06:00", "-05:00", "-04:00", "+01:00", "+02:00", "+05:30", "+08:00", "+09:00", "+10:00"]
    .map((z) => `<option value="${z}">${z === "UTC" ? "UTC (+00:00)" : "UTC" + z}</option>`).join("");
  const projectField = projects && projects.length
    ? `<div class="field"><label>Project (required — the automation's durable container)</label><select name="project_ref" required>${opts}</select></div>`
    : `<div class="field"><label>Project</label><input name="project_ref" value="${CX_ESC(projectId)}" placeholder="project:my-app" required></div>`;
  const inner = `<p><a href="/__ioi/automations${projectId ? `?project=${encodeURIComponent(projectId)}` : ""}">← Automations</a></p>
    <h1>New automation</h1><p class="sub">A project-scoped spec the daemon runs over a real environment. Start with one step; you can run it manually right away.</p>
    <form method="post" action="/__ioi/automations">
      ${projectField}
      <div class="field"><label>Name</label><input name="name" placeholder="Nightly CONTRIBUTING note" required></div>
      <div class="field"><label>Description</label><input name="description" placeholder="What this automation does"></div>
      <div class="field"><label>Schedule</label>
        <select name="schedule_type" id="ioi-sched-type" onchange="ioiSchedToggle()">
          <option value="manual">Manual only</option>
          <option value="interval">Interval</option>
          <option value="cron">Cron</option>
        </select>
      </div>
      <div id="ioi-sched-interval" style="display:none">
        <div class="two">
          <div class="field"><label>Run every</label><input name="interval_n" type="number" min="0" value="15"></div>
          <div class="field"><label>Unit</label><select name="interval_unit"><option value="minutes">minutes</option><option value="hours">hours</option><option value="seconds">seconds</option></select></div>
        </div>
      </div>
      <div id="ioi-sched-cron" style="display:none">
        <div class="two">
          <div class="field"><label>Cron (min hour dom month dow)</label><input name="cron" id="ioi-cron-expr" placeholder="0 9 * * 1-5" oninput="ioiCronPreview()"></div>
          <div class="field"><label>Timezone</label><select name="cron_tz" id="ioi-cron-tz" onchange="ioiCronPreview()">${tzOptions}</select></div>
        </div>
        <div class="field"><label>Next runs (UTC)</label><div id="ioi-cron-preview" class="sub" style="margin:0">enter a cron expression…</div></div>
      </div>
      <div class="two">
        <div class="field"><label>Model</label><input name="model" placeholder="qwen2.5:7b"></div>
        <div class="field"><label>Reasoning</label><select name="reasoning"><option value="">(default)</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option></select></div>
      </div>
      <div class="two">
        <div class="field"><label>Max concurrency</label><input name="max_concurrency" type="number" min="1" value="1"></div>
        <div class="field"><label>On failure</label><select name="failure_policy"><option value="continue">continue scheduling</option><option value="disable">disable on failure</option></select></div>
      </div>
      <div class="field"><label>Agent ref</label><input name="agent_ref" placeholder="agent:default"></div>
      <div class="two">
        <div class="field"><label>Connector refs (comma-separated)</label><input name="connector_refs" placeholder="connector:github, connector:linear"></div>
        <div class="field"><label>Memory profile ref</label><input name="memory_profile_ref" placeholder="memory:project-default"></div>
      </div>
      <div class="two">
        <div class="field"><label>Step kind</label><select name="step_kind"><option value="agent">agent (prompt)</option><option value="command">command (shell)</option></select></div>
        <div class="field"><label>&nbsp;</label><div class="sub" style="margin:0;font-size:12px">First step runs when you click Run now.</div></div>
      </div>
      <div class="field"><label>Step body</label><textarea name="step_body" placeholder="e.g. Write a CONTRIBUTING.md for this repo."></textarea></div>
      <div class="row"><button class="act" type="submit">Create automation</button></div>
    </form>
    <script>
      function ioiSchedToggle(){var t=document.getElementById('ioi-sched-type').value;document.getElementById('ioi-sched-interval').style.display=(t==='interval')?'block':'none';document.getElementById('ioi-sched-cron').style.display=(t==='cron')?'block':'none';}
      function ioiCronPreview(){var c=document.getElementById('ioi-cron-expr').value.trim(),tz=document.getElementById('ioi-cron-tz').value,el=document.getElementById('ioi-cron-preview');if(!c){el.textContent='enter a cron expression…';return;}fetch('/__ioi/automations/cron-preview?cron='+encodeURIComponent(c)+'&tz='+encodeURIComponent(tz)+'&n=3').then(function(r){return r.json();}).then(function(d){el.textContent=d.ok?('next: '+d.runs.join('  ·  ')):('⚠ '+d.error);}).catch(function(){el.textContent='preview unavailable';});}
    </script>`;
  return automationsShell("New automation", inner);
}

// ---- Applications estate — the owned breadth launcher for the 11 open-application surfaces.
// Beyond the core rail (Home · Projects · Automations), surfaces open from here. Connections is
// re-homed as the "Developer & Integrations" surface (routes to the existing cockpit; NOT rebuilt).
// Catalog: internal-docs/.../surfaces/catalog/README.md. Honest status — live surfaces link, the
// rest are "planned" / "in a session" (no fabricated routes).
function renderApplications() {
  const SURFACES = [
    { icon: "🧰", name: "Workbench", desc: "Code editor, terminal, ports & tasks for a running session.", status: "contextual" },
    { icon: "🖥", name: "Environments", desc: "Provision and operate dev environments.", status: "contextual" },
    { icon: "🧪", name: "Agent Studio", desc: "Author, tune, and evaluate agents.", status: "planned" },
    { icon: "🏗", name: "Foundry", desc: "Build and publish models and tools.", status: "planned" },
    { icon: "📦", name: "ODK", desc: "Operational data kits and recipes.", status: "planned" },
    { icon: "🧩", name: "Domain Apps", desc: "Vertical, form-factored app surfaces.", status: "planned" },
    { icon: "🔌", name: "Developer & Integrations", desc: "Connectors, MCP, sealed credentials, and developer tools.", href: "/__ioi/connections", status: "live" },
    { icon: "🛡", name: "Governance", desc: "Permissions, controls, and release gates.", status: "planned" },
    { icon: "⚙", name: "Operations", desc: "DevOps, issues, jobs, notifications, and resources.", status: "planned" },
    { icon: "📒", name: "Work Ledger", desc: "Run history, proof, lineage, and replay.", href: "/__ioi/run-timeline", status: "live" },
    { icon: "🛒", name: "Marketplace", desc: "Apps, training, and walkthroughs.", status: "planned" },
  ];
  const pillFor = (s) => s.status === "live"
    ? `<span class="pill ok">open</span>`
    : s.status === "contextual" ? `<span class="pill muted">in a session</span>` : `<span class="pill muted">planned</span>`;
  const card = (s) => {
    const inner = `<div class="main"><div class="name">${s.icon} ${CX_ESC(s.name)}${pillFor(s)}</div><div class="meta">${CX_ESC(s.desc)}</div></div>`;
    return s.href ? `<a class="card" href="${s.href}">${inner}<span class="act ghost">Open →</span></a>` : `<div class="card">${inner}</div>`;
  };
  const body = SURFACES.map(card).join("");
  return automationsShell(
    "Applications",
    `<h1>Applications</h1><p class="sub">The IOI surface estate — open applications beyond the core rail (Home · Projects · Automations). Developer &amp; Integrations is the home for connectors, MCP, and credentials.</p>${body}`,
  );
}

// Minimal dark page chrome for the BYOA GitHub App connect flow (custody-first framing).
function githubAppShell(title, inner) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} · Hypervisor</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;background:#0c0d10;color:#e6e7ea;font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center}
  .card{max-width:520px;padding:40px;background:#15171c;border:1px solid #24262d;border-radius:14px;box-shadow:0 12px 40px rgba(0,0,0,.4)}
  h1{font-size:20px;margin:0 0 14px;letter-spacing:-.01em}
  p{margin:0 0 14px;color:#c7c9cf} b{color:#fff;font-weight:600}
  .muted{color:#878a93;font-size:13px}
  .btn{display:inline-block;margin:6px 0 14px;padding:11px 18px;background:#fff;color:#111;border:0;border-radius:9px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
  .btn:hover{background:#eee}
  .brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:#6f7280;margin-bottom:18px}
</style></head><body><div class="card"><div class="brand">IOI Hypervisor · Git authentications</div><h1>${title}</h1>${inner}</div></body></html>`;
}

// Terminability tracker: any ioi.v1.* RPC that falls through to the product-ui server (adapter
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
function connectMessageFrame(payloadObj = {}) {
  const payload = Buffer.from(JSON.stringify(payloadObj), "utf8");
  const frame = Buffer.alloc(5 + payload.length);
  frame.writeUInt8(0x00, 0);
  frame.writeUInt32BE(payload.length, 1);
  payload.copy(frame, 5);
  return frame;
}

const TERMINAL_CHUNK_PATH = "/static/assets/Terminal-CAzwFiqq.js";
const TERMINAL_CHUNK = `
import{a as __toESM}from"./rolldown-runtime-CGYlQKCx.js";
import{n as __reactFactory}from"./@mux-DLaEVubF.js";
import{v_ as __jsxRuntime}from"./vendor-DAwbZtf0.js";
const React=__toESM(__reactFactory(),1);
const jsx=__jsxRuntime();
const enc=new TextEncoder();
const dec=new TextDecoder();
function fromBase64(value){try{const bin=atob(value||"");const bytes=Uint8Array.from(bin,ch=>ch.charCodeAt(0));return dec.decode(bytes)}catch{return""}}
function appendText(setLog,text){if(!text)return;setLog(prev=>{const next=prev+text;return next.length>20000?next.slice(-20000):next})}
// This <pre> has no VT/ANSI emulator, so raw PTY escapes would render as literal garbage. Strip
// them with a tiny char-scan state machine (escaping-free for this template literal): drop CSI
// (incl. SGR color + bracketed-paste), OSC (window title, terminated by BEL or ESC-backslash), other
// 2-char ESC sequences, and stray control bytes; keep tab(9), newline(10), and all printable/UTF-8.
// State persists across poll chunks so a sequence split mid-stream still strips cleanly.
function makeStripper(){
  let mode=0; // 0 normal, 1 after-ESC, 2 in-CSI, 3 in-OSC
  return function(input){
    let out="";
    for(let i=0;i<input.length;i++){
      const c=input.charCodeAt(i);
      if(mode===0){
        if(c===27)mode=1;
        else if(c===9||c===10)out+=input[i];
        else if(c>=32&&c!==127)out+=input[i];
      }else if(mode===1){
        if(c===91)mode=2; else if(c===93)mode=3; else mode=0;
      }else if(mode===2){
        if(c>=64&&c<=126)mode=0;
      }else if(mode===3){
        if(c===7)mode=0; else if(c===27)mode=1;
      }
    }
    return out;
  };
}
export const Terminal=React.forwardRef(function Terminal({environmentId,terminalId,focusOnReady,onExit},ref){
  const [log,setLog]=React.useState("");
  const [line,setLine]=React.useState("");
  const [status,setStatus]=React.useState("connecting");
  const inputRef=React.useRef(null);
  const sinceRef=React.useRef(0);
  const stripRef=React.useRef(null);
  if(!stripRef.current)stripRef.current=makeStripper();
  React.useImperativeHandle(ref,()=>({focus:()=>inputRef.current?.focus()}),[]);
  React.useEffect(()=>{if(focusOnReady)inputRef.current?.focus()},[focusOnReady]);
  React.useEffect(()=>{
    let cancelled=false;
    let timer=null;
    async function poll(){
      if(cancelled||!terminalId)return;
      try{
        const r=await fetch("/v1/hypervisor/terminals/"+encodeURIComponent(terminalId)+"/stream?since="+sinceRef.current);
        if(r.status===404){setStatus("closed");onExit?.();return}
        const text=await r.text();
        for(const frame of text.split("\\n\\n")){
          let ev="",data="";
          for(const row of frame.split("\\n")){
            if(row.startsWith("event: "))ev=row.slice(7);
            else if(row.startsWith("data: "))data=row.slice(6);
          }
          if(ev==="output"&&data){
            const payload=JSON.parse(data);
            if(typeof payload.offset==="number")sinceRef.current=payload.offset;
            appendText(setLog,stripRef.current(payload.output||""));
          }
        }
        setStatus("connected");
      }catch(e){setStatus("reconnecting")}
      if(!cancelled)timer=setTimeout(poll,350);
    }
    poll();
    return()=>{cancelled=true;if(timer)clearTimeout(timer)};
  },[terminalId,onExit]);
  const send=React.useCallback(async()=>{
    const text=line;
    setLine("");
    if(!terminalId||!text.trim())return;
    try{
      await fetch("/v1/hypervisor/terminals/"+encodeURIComponent(terminalId)+"/input",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({data:text+"\\n"})});
    }catch(e){setStatus("input failed")}
  },[terminalId,line]);
  const rows=(log||"").split("\\n").slice(-500).join("\\n");
  return jsx.jsxs("div",{className:"flex size-full flex-col bg-[#0d1117] text-[#d8dee9]",children:[
    jsx.jsxs("div",{className:"flex items-center justify-between border-b border-[#273241] px-3 py-2 text-xs text-[#8b949e]",children:[
      jsx.jsxs("span",{children:["Terminal ",terminalId?terminalId.slice(0,12):"pending"]}),
      jsx.jsxs("span",{children:[status," / ",environmentId||"environment"]})
    ]}),
    jsx.jsx("pre",{className:"min-h-0 flex-1 overflow-auto whitespace-pre-wrap p-3 font-mono text-xs leading-5",children:rows||"$ "}),
    jsx.jsxs("div",{className:"flex items-center gap-2 border-t border-[#273241] p-2",children:[
      jsx.jsx("span",{className:"font-mono text-xs text-[#8b949e]",children:"$"}),
      jsx.jsx("input",{ref:inputRef,value:line,onChange:e=>setLine(e.target.value),onKeyDown:e=>{if(e.key==="Enter")send()},className:"min-w-0 flex-1 bg-transparent font-mono text-sm outline-none",placeholder:"Type a command and press Enter","aria-label":"Terminal input"}),
      jsx.jsx("button",{type:"button",onClick:send,className:"rounded border border-[#3b4658] px-2 py-1 text-xs text-[#d8dee9] hover:bg-[#161b22]",children:"Send"})
    ]})
  ]});
});
`;

// Hypervisor's OWN transcript primitive — the Run Timeline surface. A self-contained, owned page
// (not the seeded SPA chat pane) styled with the reference design tokens (linked from the bundle CSS so
// the look is native). It polls /__ioi/agent-runs/:id/timeline and renders the 6-part governed-work
// turn: request → activity → response → artifacts → proof → follow-ups. Any surface (Workbench,
// Sessions, Agent Studio, Automations, IOI.ai handoffs) routes/embeds this by runId. Client JS avoids
// backticks/${} so it survives the outer template literal; RUN_ID is injected via __RUN_ID__.
const RUN_TIMELINE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Run Timeline · Hypervisor</title>
<link rel="stylesheet" href="/static/assets/SegmentProvider-gQNN48J_.css">
<style>
  :root { color-scheme: light; }
  body { margin:0; background:rgb(var(--surface-base)); color:rgb(var(--content-primary));
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; font-size:14px; line-height:1.5; }
  .rt-wrap { max-width:840px; margin:0 auto; padding:24px 20px 80px; }
  .rt-head { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:8px; }
  .rt-title { font-size:18px; font-weight:600; margin:0; }
  .rt-sub { color:rgb(var(--content-muted)); font-size:12px; margin-top:2px; }
  .rt-sub code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .rt-badge { display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:9999px; font-size:12px; font-weight:500;
    border:1px solid rgb(var(--border-base)); white-space:nowrap; }
  .rt-dot { width:7px; height:7px; border-radius:9999px; background:rgb(var(--content-muted)); }
  .rt-running .rt-dot { background:rgb(var(--content-brand)); animation:rtpulse 1.2s ease-in-out infinite; }
  .rt-done .rt-dot { background:rgb(var(--content-positive)); }
  .rt-failed .rt-dot { background:rgb(var(--content-destructive)); }
  @keyframes rtpulse { 0%,100%{opacity:1} 50%{opacity:.35} }
  .rt-turn { border:1px solid rgb(var(--border-base)); border-radius:12px; background:rgb(var(--surface-base)); margin-top:18px; overflow:hidden; }
  .rt-sec { padding:14px 16px; border-top:1px solid rgb(var(--border-subtle)); }
  .rt-sec:first-child { border-top:0; }
  .rt-label { display:flex; align-items:center; gap:8px; font-size:11px; letter-spacing:.04em; text-transform:uppercase; color:rgb(var(--content-muted)); margin-bottom:8px; }
  .rt-label .n { width:18px; height:18px; border-radius:9999px; display:inline-flex; align-items:center; justify-content:center;
    background:rgb(var(--surface-muted)); color:rgb(var(--content-secondary)); font-size:10px; font-weight:600; }
  .rt-request { background:rgb(var(--surface-muted)); border-radius:8px; padding:10px 12px; }
  .rt-response { font-size:14px; }
  .rt-response.fail { color:rgb(var(--content-destructive)); }
  .rt-steps { list-style:none; margin:0; padding:0; }
  .rt-step { display:flex; align-items:baseline; gap:10px; padding:3px 0; }
  .rt-step .sd { width:8px; height:8px; border-radius:9999px; flex:none; transform:translateY(3px); background:rgb(var(--content-muted)); }
  .rt-step.authority .sd { background:rgb(var(--content-brand)); }
  .rt-step.tool .sd { background:rgb(var(--content-secondary)); }
  .rt-step.done .sd { background:rgb(var(--content-positive)); }
  .rt-step.error .sd { background:rgb(var(--content-destructive)); }
  .rt-step .st { color:rgb(var(--content-muted)); font-size:11px; font-family:ui-monospace,monospace; flex:none; }
  .rt-chip { display:inline-flex; align-items:center; gap:6px; padding:3px 8px; margin:3px 6px 0 0; border-radius:6px;
    background:rgb(var(--surface-muted)); font-size:12px; font-family:ui-monospace,monospace; }
  .rt-kv { display:grid; grid-template-columns:120px 1fr; gap:4px 12px; font-size:12px; }
  .rt-kv dt { color:rgb(var(--content-muted)); }
  .rt-kv dd { margin:0; font-family:ui-monospace,monospace; word-break:break-all; }
  .rt-proof { border:1px solid rgb(var(--border-base)); border-left:3px solid rgb(var(--content-brand)); border-radius:8px; padding:10px 12px; background:rgb(var(--surface-base)); }
  .rt-term { background:#0d1117; color:#d8dee9; border-radius:8px; padding:10px; font-family:ui-monospace,monospace; font-size:12px; white-space:pre-wrap; max-height:220px; overflow:auto; }
  .rt-acts { display:flex; flex-wrap:wrap; gap:8px; }
  .rt-act { display:inline-flex; align-items:center; gap:6px; padding:6px 12px; border-radius:8px; border:1px solid rgb(var(--border-base));
    background:rgb(var(--surface-base)); color:rgb(var(--content-primary)); font-size:13px; text-decoration:none; cursor:pointer; }
  .rt-act:hover { background:rgb(var(--surface-muted)); }
  .rt-muted { color:rgb(var(--content-muted)); font-style:italic; }
  .rt-loading,.rt-error { color:rgb(var(--content-muted)); padding:40px; text-align:center; }
  /* embed mode — mounted inside the workbench pane (replaces the seeded transcript) */
  html.rt-embed, html.rt-embed body { background:transparent; }
  html.rt-embed .rt-wrap { max-width:none; margin:0; padding:12px 14px 32px; }
  html.rt-embed .rt-head { position:sticky; top:0; background:rgb(var(--surface-base)); padding-bottom:8px; z-index:1; }
  /* owned follow-up composer (so the surface owns transcript + send, no seeded pane) */
  .rt-composer { position:sticky; bottom:0; display:flex; gap:8px; max-width:840px; margin:0 auto; padding:12px 14px;
    background:rgb(var(--surface-base)); border-top:1px solid rgb(var(--border-base)); }
  html.rt-embed .rt-composer { max-width:none; }
  .rt-cin { flex:1; border:1px solid rgb(var(--border-base)); border-radius:8px; padding:8px 12px; font-size:13px;
    background:rgb(var(--surface-base)); color:rgb(var(--content-primary)); outline:none; }
  .rt-cbtn { border:0; border-radius:8px; padding:8px 16px; font-size:13px; font-weight:600; cursor:pointer;
    background:rgb(var(--content-brand)); color:#fff; }
  .rt-cbtn:disabled { opacity:.5; cursor:default; }
</style>
</head>
<body>
<div class="rt-wrap"><div id="rt-root"><div class="rt-loading">Loading run timeline…</div></div></div>
<script>
(function(){
  var RUN_ID = "__RUN_ID__";
  var ENV_ID = "__ENV_ID__";
  if (location.search.indexOf("embed=1") >= 0) document.documentElement.classList.add("rt-embed");
  function el(tag, cls, text){ var e=document.createElement(tag); if(cls)e.className=cls; if(text!=null)e.textContent=text; return e; }
  function trunc(s,n){ s=String(s||""); return s.length>n ? s.slice(0,n)+"…" : s; }
  function timeShort(at){ if(!at) return ""; try { var d=new Date(at); return d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"}); } catch(e){ return ""; } }
  function label(n, title){ var d=el("div","rt-label"); d.appendChild(el("span","n",String(n))); d.appendChild(el("span",null,title)); return d; }
  function sec(node){ var s=el("div","rt-sec"); s.appendChild(node); return s; }

  function render(tl){
    var root=document.getElementById("rt-root"); root.textContent="";
    if(!tl){ root.appendChild(el("div","rt-error","Run not found.")); return; }
    ensureComposer();
    var statusCls = tl.status==="done"?"rt-done":(tl.status==="failed"?"rt-failed":(tl.status==="running"?"rt-running":""));

    var head=el("div","rt-head");
    var left=el("div");
    left.appendChild(el("h1","rt-title",tl.title||"Agent session"));
    var sub=el("div","rt-sub");
    sub.appendChild(el("span",null,"Run "+(tl.runId||"")));
    if(tl.environmentId){ sub.appendChild(el("span",null,"  ·  env ")); var c=el("code",null,tl.environmentId); sub.appendChild(c); }
    if(tl.updatedAt){ sub.appendChild(el("span",null,"  ·  updated "+timeShort(tl.updatedAt))); }
    left.appendChild(sub);
    head.appendChild(left);
    var badge=el("span","rt-badge "+statusCls);
    badge.appendChild(el("span","rt-dot"));
    badge.appendChild(el("span",null,(tl.activeStatus||tl.status||"").replace(/…$/,"")||tl.status));
    head.appendChild(badge);
    root.appendChild(head);

    (tl.turns||[]).forEach(function(turn){
      var box=el("div","rt-turn");

      // 1) Request
      var s1=el("div"); s1.appendChild(label(1,"Request"));
      if(turn.request && turn.request.text){ s1.appendChild(el("div","rt-request",turn.request.text)); }
      else { s1.appendChild(el("div","rt-muted","No request recorded.")); }
      box.appendChild(sec(s1));

      // 2) Activity (governed-work steps)
      var s2=el("div"); s2.appendChild(label(2,"Activity"));
      if((turn.activity||[]).length){
        var ul=el("ul","rt-steps");
        turn.activity.forEach(function(a){
          var li=el("li","rt-step "+(a.kind||"status"));
          li.appendChild(el("span","sd"));
          li.appendChild(el("span","sx",a.text));
          if(a.at){ var t=el("span","st",timeShort(a.at)); li.appendChild(t); }
          ul.appendChild(li);
        });
        s2.appendChild(ul);
      } else { s2.appendChild(el("div","rt-muted","No activity recorded.")); }
      box.appendChild(sec(s2));

      // 3) Response
      var s3=el("div"); s3.appendChild(label(3,"Response"));
      if(turn.response && turn.response.text){ s3.appendChild(el("div","rt-response"+(turn.response.failed?" fail":""),turn.response.text)); }
      else { s3.appendChild(el("div","rt-muted", tl.status==="running"||tl.status==="waiting" ? "Awaiting agent response…" : "No response.")); }
      box.appendChild(sec(s3));

      // 4) Artifacts
      var art=turn.artifacts||{};
      var hasArt=(art.files&&art.files.length)||(art.drafts&&art.drafts.length)||(art.terminals&&art.terminals.length);
      var s4=el("div"); s4.appendChild(label(4,"Artifacts"));
      if(hasArt){
        if(art.files&&art.files.length){ var fwrap=el("div"); art.files.forEach(function(f){ fwrap.appendChild(el("span","rt-chip",f)); }); s4.appendChild(fwrap); }
        (art.drafts||[]).forEach(function(d){
          var dl=el("dl","rt-kv");
          dl.appendChild(el("dt",null,"PR draft")); dl.appendChild(el("dd",null,(d.title||d.id)+" ("+(d.reviewState||"")+")"));
          if(d.summary){ dl.appendChild(el("dt",null,"summary")); dl.appendChild(el("dd",null,d.summary)); }
          if(d.remotePublish&&d.remotePublish.supported===false){ dl.appendChild(el("dt",null,"remote")); dl.appendChild(el("dd",null,"unavailable — "+(d.remotePublish.reason||""))); }
          s4.appendChild(dl);
        });
        if(art.terminals&&art.terminals.length){ var pre=el("div","rt-term"); pre.textContent=art.terminals.map(function(t){return t.text;}).join("\\n"); s4.appendChild(pre); }
      } else { s4.appendChild(el("div","rt-muted","No artifacts produced.")); }
      box.appendChild(sec(s4));

      // 5) Proof (governance audit trail)
      var pf=turn.proof||{};
      var s5=el("div"); s5.appendChild(label(5,"Proof"));
      if(pf.authority||pf.proposalRefs&&pf.proposalRefs.length||pf.receipts&&pf.receipts.length||pf.leaseRef||pf.stateRoot){
        var card=el("div","rt-proof"); var kv=el("dl","rt-kv");
        if(pf.stateRoot){ kv.appendChild(el("dt",null,"state root")); kv.appendChild(el("dd",null,pf.stateRoot+" · durable")); }
        if(pf.authority){
          kv.appendChild(el("dt",null,"policy hash")); kv.appendChild(el("dd",null,trunc(pf.authority.policyHash,24)));
          kv.appendChild(el("dt",null,"request hash")); kv.appendChild(el("dd",null,trunc(pf.authority.requestHash,24)));
          if(pf.authority.grantId){ kv.appendChild(el("dt",null,"grant")); kv.appendChild(el("dd",null,pf.authority.grantId)); }
          if(pf.authority.expiresAt){ kv.appendChild(el("dt",null,"expires")); kv.appendChild(el("dd",null,pf.authority.expiresAt)); }
        }
        if(pf.leaseRef){ kv.appendChild(el("dt",null,"capability lease")); kv.appendChild(el("dd",null,pf.leaseRef)); }
        (pf.proposalRefs||[]).forEach(function(r){ kv.appendChild(el("dt",null,"proposal")); kv.appendChild(el("dd",null,r)); });
        (pf.publishReceipts||[]).forEach(function(p){ kv.appendChild(el("dt",null,"published")); kv.appendChild(el("dd",null,p.branch+" → "+p.remoteUrl+" ("+String(p.commit||"").slice(0,10)+")")); });
        kv.appendChild(el("dt",null,"authority receipts")); kv.appendChild(el("dd",null,String((pf.receipts||[]).length)+" recorded"));
        card.appendChild(kv); s5.appendChild(card);
      } else { s5.appendChild(el("div","rt-muted", pf.note || "No governance crossing recorded for this run.")); }
      box.appendChild(sec(s5));

      // 6) Follow-ups
      var s6=el("div"); s6.appendChild(label(6,"Next"));
      if((turn.followUps||[]).length){
        var acts=el("div","rt-acts");
        turn.followUps.forEach(function(f){
          var node = f.href ? el("a","rt-act",f.label) : el("button","rt-act",f.label);
          if(f.href){ node.setAttribute("href",f.href); node.setAttribute("target","_top"); }
          else if(f.post){
            // governed command — POST then refresh the timeline (e.g. wallet-authorized Publish PR)
            node.addEventListener("click",function(){
              node.disabled=true; node.textContent=f.label+"…";
              fetch(f.post,{method:"POST",headers:{"content-type":"application/json"},body:"{}"})
                .then(function(r){return r.json();})
                .then(function(d){ node.textContent = d&&d.ok ? "Published ✓" : (d&&d.reason ? "Failed: "+d.reason : "Failed"); setTimeout(load,800); })
                .catch(function(){ node.disabled=false; node.textContent=f.label; });
            });
          }
          acts.appendChild(node);
        });
        s6.appendChild(acts);
      } else { s6.appendChild(el("div","rt-muted","No follow-up actions available.")); }
      box.appendChild(sec(s6));

      root.appendChild(box);
    });
  }

  function renderEmpty(msg){
    var root=document.getElementById("rt-root"); root.textContent="";
    root.appendChild(el("div","rt-loading",msg));
  }
  // Owned follow-up composer — posts SendToAgentExecution for this run; the timeline poll then picks
  // up the new activity/response. Created once (outside #rt-root, which render() rebuilds each poll).
  function ensureComposer(){
    if(!RUN_ID || document.getElementById("rt-composer")) return;
    var bar=el("div","rt-composer"); bar.id="rt-composer";
    var input=el("input","rt-cin"); input.type="text"; input.placeholder="Send a follow-up to this run…";
    var btn=el("button","rt-cbtn","Send");
    function send(){
      var v=(input.value||"").trim(); if(!v) return;
      input.value=""; btn.disabled=true; btn.textContent="…";
      fetch("/api/ioi.v1.AgentService/SendToAgentExecution",{method:"POST",headers:{"content-type":"application/json"},
        body:JSON.stringify({agentExecutionId:RUN_ID,userInput:{id:"rt-"+Date.now(),inputs:[{text:{content:v}}]}})})
        .then(function(){ btn.disabled=false; btn.textContent="Send"; load(); })
        .catch(function(){ btn.disabled=false; btn.textContent="Send"; });
    }
    btn.addEventListener("click",send);
    input.addEventListener("keydown",function(e){ if(e.key==="Enter"){ e.preventDefault(); send(); } });
    bar.appendChild(input); bar.appendChild(btn);
    document.body.appendChild(bar);
  }
  function load(){
    if(!RUN_ID){
      // env mode and no run yet — resolve env -> latest run (self-healing if the run appears later)
      if(!ENV_ID){ render(null); return; }
      fetch("/__ioi/env-latest-run/"+encodeURIComponent(ENV_ID),{headers:{"accept":"application/json"}})
        .then(function(r){ return r.json(); })
        .then(function(d){ if(d&&d.runId){ RUN_ID=d.runId; load(); } else { renderEmpty("No run for this environment yet."); setTimeout(load, 2000); } })
        .catch(function(){ setTimeout(load, 2500); });
      return;
    }
    fetch("/__ioi/agent-runs/"+encodeURIComponent(RUN_ID)+"/timeline", {headers:{"accept":"application/json"}})
      .then(function(r){ return r.ok ? r.json() : null; })
      .then(function(tl){
        render(tl);
        if(tl && (tl.status==="running"||tl.status==="waiting")) setTimeout(load, 1500);
      })
      .catch(function(){ setTimeout(load, 2500); });
  }
  load();
})();
</script>
</body>
</html>`;

if (!existsSync(REF_SERVER)) {
  console.error(
    `product-ui bundle not found at:\n  ${REF_SERVER}\n\n` +
      `The product-ui bundle is a gitignored local productUi; this serve mode needs it present.`,
  );
  process.exit(1);
}

// 1) Spawn the product-ui server (bundle + branding + remaining mocks) on an internal port.
const productUi = spawn("node", [REF_SERVER], {
  stdio: "inherit",
  env: { ...process.env, PORT: String(PRODUCT_UI_PORT) },
});
productUi.on("exit", (code) => process.exit(code ?? 0));
process.on("SIGINT", () => productUi.kill("SIGINT"));
process.on("SIGTERM", () => productUi.kill("SIGTERM"));

// IOI product identity overrides applied to proxied HTML/JSON (the reference ships a demo
// identity; we substitute ours). Applied in the committed serve layer so it survives productUi
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
// via `globalThis.__toAssetUrl = (f) => \`https://app.ioi.io/static/${f}\`` (plus absolute font
// preloads). Left as-is, every lazy chunk (e.g. /ai's page chunk) is fetched from the upstream CDN
// — and a single blip / rotated hash there makes the dynamic import reject → the SPA's "Something
// went wrong" error boundary. The productUi already serves all assets locally, so point the base at
// our own origin (root-relative /static/) for a self-contained, deterministic app.
const ASSET_CDN_BASE = "https://app.ioi.io/static/";
function localizeAssetBase(html) {
  return html.split(ASSET_CDN_BASE).join("/static/");
}

// Rename the "Personal access tokens" settings surface — which is really about Hypervisor *API*
// tokens (inbound API access to Hypervisor) — to "API access tokens". This removes the collision
// with GitHub's *Personal Access Token* (the outbound git-auth method under Git authentications),
// the exact confusion users hit. The GitHub auth-method label (`Jr.PAT:t=`Personal Access Token``)
// is DELIBERATELY preserved — that one genuinely is a GitHub PAT. Each pair is scoped so it cannot
// match the Jr.PAT case (different casing / trailing `;break` vs `)` / plural).
const API_TOKEN_RENAMES = [
  ["`Personal access tokens`", "`API access tokens`"], // nav label (x2) + table aria-label
  ["`Personal access token`", "`API access token`"], // token-value aria-label
  ["Personal access tokens (PATs)", "API access tokens"], // page/nav description lead-in
  ["Personal Access Token deleted", "API access token deleted"], // delete toast
  ["Delete Personal Access Token", "Delete API access token"], // delete dialog title
  ["`Personal Access Token`)", "`API access token`)"], // $o(e.length,`Personal Access Token`) pluralize
  ["No Personal Access Tokens", "No API access tokens"], // empty state
  ["`Personal Access Tokens`", "`API access tokens`"], // breadcrumb wS(`Personal Access Tokens`)
];
function renameApiTokens(js) {
  for (const [a, b] of API_TOKEN_RENAMES) js = js.split(a).join(b);
  return js;
}
const SETTINGS_BUNDLE_RE = /SegmentProvider-[^/]+\.js/;

function proxyToProductUi(req, res, body) {
  // Drop accept-encoding so the productUi returns plain text we can rewrite.
  const headers = { ...req.headers };
  delete headers["accept-encoding"];
  const upstream = http.request(
    { host: "127.0.0.1", port: PRODUCT_UI_PORT, method: req.method, path: req.url, headers },
    (r) => {
      const ct = String(r.headers["content-type"] || "");
      // Only buffer + rewrite text payloads (HTML pages + JSON fixtures). Stream the rest
      // (the JS/wasm/font/image bundle) untouched — EXCEPT the one settings bundle that carries
      // the "Personal access tokens" copy, which we buffer to rename → "API access tokens".
      const renameJs = ct.includes("javascript") && SETTINGS_BUNDLE_RE.test(req.url || "");
      const rewritable = ct.includes("text/html") || ct.startsWith("application/json");
      if (!rewritable && !renameJs) {
        res.writeHead(r.statusCode || 502, r.headers);
        r.pipe(res);
        return;
      }
      const parts = [];
      r.on("data", (c) => parts.push(c));
      r.on("end", () => {
        let text = Buffer.concat(parts).toString("utf8");
        if (renameJs) text = renameApiTokens(text); // JS bundle: rename only, no identity/HTML rewrite
        else text = rewriteIdentity(text);
        if (!renameJs && ct.includes("text/html")) text = augmentHtml(localizeAssetBase(text)); // localize CDN base + WS-I inject
        const out = Buffer.from(text, "utf8");
        const outHeaders = { ...r.headers, "content-length": String(out.length) };
        // We send a fixed-length body, so drop any chunked/encoding headers from upstream
        // (keeping them alongside content-length corrupts the framing).
        delete outHeaders["content-encoding"];
        delete outHeaders["transfer-encoding"];
        // The renamed settings bundle keeps the same hashed URL, so defeat immutable caching to
        // ensure the browser re-fetches the renamed copy instead of a stale "Personal access tokens".
        if (renameJs) outHeaders["cache-control"] = "no-cache";
        res.writeHead(r.statusCode || 200, outHeaders);
        res.end(out);
      });
    },
  );
  upstream.on("error", (e) => {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`productUi unavailable: ${e.message}`);
  });
  upstream.end(body);
}

function supervisorRoute(pathname) {
  const m = pathname.match(/^\/supervisor\/([^/]+)\/supervisor\.v1\.EnvironmentOpsService\/([^/]+)$/);
  return m ? { env: decodeURIComponent(m[1]), method: decodeURIComponent(m[2]) } : null;
}

async function authorizeSupervisorReq(req, env) {
  const auth = String(req.headers["authorization"] || "");
  const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  if (!token) return { ok: false, status: 401, body: { code: "unauthenticated", message: "missing env-ops lease" } };
  const lease = await djson("GET", `/v1/hypervisor/ops-lease/${encodeURIComponent(token)}`);
  if (!lease.body?.active || lease.body?.environment_id !== env) {
    return { ok: false, status: 401, body: { code: "unauthenticated", message: "invalid or expired env-ops lease" } };
  }
  return { ok: true, token };
}

function terminalInfo(t) {
  return {
    terminalId: t.terminal_id,
    shell: t.shell || "bash",
    workingDirectory: t.cwd || "",
    cols: t.cols || 80,
    rows: t.rows || 24,
    annotations: {},
  };
}

function parseSupervisorBody(body) {
  if (!body || body.length === 0) return {};
  let payload = body;
  if (body.length >= 5 && body[0] === 0x00) {
    const len = body.readUInt32BE(1);
    payload = body.subarray(5, 5 + len);
  }
  const text = payload.toString("utf8").trim();
  return text ? JSON.parse(text) : {};
}

async function handleSupervisorUnary(route, req, body) {
  const { env, method } = route;
  if (!["CreateTerminal", "ListTerminals", "CloseTerminal", "ListTerminalProfiles", "ListCapabilities"].includes(method)) return null;
  const auth = await authorizeSupervisorReq(req, env);
  if (!auth.ok) return { status: auth.status, body: auth.body };
  const params = parseSupervisorBody(body);
  const envRef = `environment:${env}`;
  if (method === "ListCapabilities") return { status: 200, body: { capabilities: ["CAPABILITY_WATCH"] } };
  if (method === "ListTerminalProfiles") {
    const configured = Object.entries(params?.configProfiles || {}).map(([profileName, profile]) => ({
      profileName,
      path: profile?.path || profileName,
      isAutoDetected: false,
    }));
    return {
      status: 200,
      body: {
        profiles: configured.length ? configured : [
          { profileName: "bash", path: "bash", isAutoDetected: true },
          { profileName: "sh", path: "sh", isAutoDetected: true },
        ],
      },
    };
  }
  if (method === "ListTerminals") {
    const r = await djson("GET", "/v1/hypervisor/terminals");
    const terminals = (r.body?.terminals || [])
      .filter((t) => t.environment_ref === envRef)
      .map(terminalInfo);
    return { status: 200, body: { terminals } };
  }
  if (method === "CreateTerminal") {
    const cwd = params?.workingDirectory && String(params.workingDirectory).trim() ? params.workingDirectory : undefined;
    const payload = {
      environment_ref: envRef,
      shell: params?.shell || "bash",
      cols: params?.initialCols || 80,
      rows: params?.initialRows || 24,
    };
    if (cwd) payload.cwd = cwd;
    const r = await djson("POST", "/v1/hypervisor/terminals", payload, auth.token);
    if (!r.body?.terminal_id) return { status: 500, body: { code: "internal", message: r.body?.reason || "create terminal failed" } };
    return { status: 200, body: { terminalId: r.body.terminal_id } };
  }
  if (method === "CloseTerminal") {
    await djson("POST", `/v1/hypervisor/terminals/${encodeURIComponent(params?.terminalId || "")}/close`, {}, auth.token);
    return { status: 200, body: {} };
  }
  return null;
}

async function handleSupervisorStream(route, req, res, body) {
  const { env, method } = route;
  if (!["ReadTerminal", "AttachTerminal", "Watch"].includes(method)) return false;
  const auth = await authorizeSupervisorReq(req, env);
  if (!auth.ok) {
    res.writeHead(auth.status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(auth.body));
    return true;
  }
  const params = parseSupervisorBody(body);
  res.writeHead(200, { "Content-Type": "application/connect+json", "Cache-Control": "no-cache", Connection: "keep-alive" });
  if (method === "Watch") {
    // Daemon-owned watch: poll the daemon's authoritative {porcelain, files} snapshot and emit
    // gitStatusChanged / fileChanges deltas. The watch TRUTH lives in the daemon (works for any
    // provider it can read the workspace for); the serve is a pure transport bridge — no local
    // fs.watch (which only worked because serve was co-located with the workspace).
    const wsUrl = `/v1/hypervisor/environments/${encodeURIComponent(env)}/watch-state`;
    const initial = await djson("GET", wsUrl);
    if (!initial.body?.ok) {
      res.end(connectEndStreamFrame({ error: { code: "unavailable", message: initial.body?.reason || "workspace not started" } }));
      return true;
    }
    let lastPorcelain = initial.body.porcelain || "";
    let lastFiles = Array.isArray(initial.body.files) ? initial.body.files : [];
    const poll = setInterval(async () => {
      let r;
      try { r = await djson("GET", wsUrl); } catch { return; }
      if (!r.body?.ok) return;
      const porcelain = r.body.porcelain || "";
      const files = Array.isArray(r.body.files) ? r.body.files : [];
      try {
        if (porcelain !== lastPorcelain) res.write(connectMessageFrame({ gitStatusChanged: {} }));
        const prev = new Set(lastFiles);
        const now = new Set(files);
        const events = [];
        for (const f of files) if (!prev.has(f)) events.push({ path: f, type: "FILE_CHANGE_TYPE_ADDED", isDirectory: false });
        for (const f of lastFiles) if (!now.has(f)) events.push({ path: f, type: "FILE_CHANGE_TYPE_DELETED", isDirectory: false });
        if (events.length) res.write(connectMessageFrame({ fileChanges: { events } }));
      } catch { clearInterval(poll); return; }
      lastPorcelain = porcelain;
      lastFiles = files;
    }, 700);
    req.on("close", () => clearInterval(poll));
    return true;
  }
  const termId = params?.terminalId;
  let since = 0;
  let first = !params?.skipHistory;
  const sanitize = makeTerminalSanitizer();
  const interval = setInterval(async () => {
    try {
      const r = await fetch(`${DAEMON}/v1/hypervisor/terminals/${encodeURIComponent(termId)}/stream?since=${since}`);
      if (r.status === 404) {
        res.write(connectMessageFrame({ exited: { exitCode: 0 } }));
        res.end(connectEndStreamFrame({}));
        clearInterval(interval);
        return;
      }
      const text = await r.text();
      let outChunk = "";
      let newOffset = since;
      for (const f of text.split("\n\n")) {
        let ev = null, data = null;
        for (const line of f.split("\n")) {
          if (line.startsWith("event: ")) ev = line.slice(7);
          else if (line.startsWith("data: ")) data = line.slice(6);
        }
        if (ev === "output" && data) {
          const d = JSON.parse(data);
          outChunk += d.output || "";
          if (typeof d.offset === "number") newOffset = d.offset;
        }
      }
      if (outChunk) {
        const clean = sanitize(outChunk);
        if (clean) {
          const b64 = Buffer.from(clean, "utf8").toString("base64");
          res.write(connectMessageFrame(first ? { replay: { data: b64, cols: 80, rows: 24 } } : { data: { data: b64 } }));
          first = false;
        }
      }
      since = newOffset;
    } catch {
      res.end(connectEndStreamFrame({}));
      clearInterval(interval);
    }
  }, 250);
  req.on("close", () => clearInterval(interval));
  return true;
}

// Owned login surface (Identity & Auth plane). Posts to the daemon auth plane; the session token
// comes back and is set as an HttpOnly cookie. SSO buttons are injected in Phase 2.
function loginShell(error, ssoConfigs = []) {
  const ssoButtons = (ssoConfigs || []).map((c) =>
    `<a class="sso" href="/__ioi/login/sso/${encodeURIComponent(c.sso_id || c.id)}">Sign in with ${String(c.display_name || c.issuer_url || "SSO").replace(/[<>]/g, "")}</a>`
  ).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · IOI Hypervisor</title><style>
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;background:#0b0c0f;color:#e7e9ee;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{width:360px;background:#15171c;border:1px solid #262a33;border-radius:14px;padding:28px}
.brand{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8a90a0;margin-bottom:6px}
h1{font-size:20px;margin:0 0 18px}label{display:block;font-size:13px;color:#aeb4c2;margin:12px 0 5px}
input{width:100%;padding:10px 12px;border-radius:9px;border:1px solid #2c313c;background:#0e1014;color:#e7e9ee;font-size:14px}
button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:9px;background:#5b7cfa;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
.err{margin-top:14px;color:#ff9b9b;font-size:13px}.hint{margin-top:16px;color:#6a7080;font-size:12px;text-align:center}
.sso{display:block;margin-top:10px;padding:11px;border:1px solid #2c313c;border-radius:9px;background:#1b1e25;color:#e7e9ee;font-size:14px;font-weight:600;text-align:center;text-decoration:none}
.div{margin:18px 0 4px;border-top:1px solid #262a33;text-align:center}.div span{position:relative;top:-10px;background:#15171c;padding:0 10px;color:#6a7080;font-size:12px}
</style></head><body><form class="card" method="POST" action="/__ioi/login">
<div class="brand">IOI Hypervisor</div><h1>Sign in</h1>
<label>Email</label><input name="email" type="email" autocomplete="username" autofocus placeholder="you@org.com">
<label>Password</label><input name="password" type="password" autocomplete="current-password" placeholder="••••••••">
<button type="submit">Sign in</button>
${error ? `<div class="err">${error}</div>` : ""}
${ssoButtons ? `<div class="div"><span>or</span></div>${ssoButtons}` : ""}
<div class="hint">Authenticated by the Hypervisor identity plane · sessions are sealed</div>
</form></body></html>`;
}

// Owned invite-acceptance surface — provisions a member account from the org invite link.
function inviteShell(inviteId, error) {
  const safe = String(inviteId).replace(/[^A-Za-z0-9_-]/g, "");
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Join · IOI Hypervisor</title><style>
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;background:#0b0c0f;color:#e7e9ee;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{width:360px;background:#15171c;border:1px solid #262a33;border-radius:14px;padding:28px}
.brand{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8a90a0;margin-bottom:6px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8a90a0;font-size:13px;margin-bottom:14px}label{display:block;font-size:13px;color:#aeb4c2;margin:12px 0 5px}
input{width:100%;padding:10px 12px;border-radius:9px;border:1px solid #2c313c;background:#0e1014;color:#e7e9ee;font-size:14px}
button{width:100%;margin-top:18px;padding:11px;border:0;border-radius:9px;background:#5b7cfa;color:#fff;font-size:14px;font-weight:600;cursor:pointer}
.err{margin-top:14px;color:#ff9b9b;font-size:13px}
</style></head><body><form class="card" method="POST" action="/__ioi/invite/${safe}">
<div class="brand">IOI Hypervisor</div><h1>Join the organization</h1><div class="sub">You've been invited. Create your account.</div>
<label>Full name</label><input name="name" autocomplete="name" autofocus placeholder="Your name">
<label>Email</label><input name="email" type="email" autocomplete="email" placeholder="you@org.com">
<label>Password</label><input name="password" type="password" autocomplete="new-password" placeholder="Choose a password">
<button type="submit">Create account &amp; join</button>
${error ? `<div class="err">${error}</div>` : ""}
</form></body></html>`;
}

// 2) Front server: IOI /api adapter first, proxy everything else to the productUi.
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const body = Buffer.concat(chunks);
    let pathname = (req.url || "").split("?")[0];
    // Wire bridge: the served SPA's RPC package name is baked into its (immutable) protobuf
    // descriptors, so on the wire it still calls the upstream namespace. Canonicalize any
    // /api/<pkg>.vN.<Service> to the IOI namespace for ALL downstream routing (adapter,
    // special-cases, fallthrough tracker) AND the productUi proxy (rewrite req.url) — so no other
    // code needs to know the upstream package name and the tracked source stays brand-neutral.
    {
      const _canon = pathname.replace(/^\/api\/[a-z][a-z0-9.]*\.v\d+\./, "/api/ioi.v1.");
      if (_canon !== pathname) { req.url = _canon + (req.url || "").slice(pathname.length); pathname = _canon; }
    }
    // Exposure normalization: if reached via a non-local Host without a forwarded header, mark it
    // forwarded so the loopback daemon (behind serve) can apply context-aware auth enforcement.
    if (!req.headers["x-forwarded-host"]) {
      const host = (req.headers.host || "").split(":")[0];
      if (host && host !== "127.0.0.1" && host !== "localhost" && host !== "::1") req.headers["x-forwarded-host"] = req.headers.host;
    }
    if (pathname === TERMINAL_CHUNK_PATH) {
      res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(TERMINAL_CHUNK);
      return;
    }
    // Owned Run Timeline surface (Hypervisor's transcript primitive). /__ioi/run-timeline/:runId
    // (or ?runId=). Any surface routes/embeds this by runId; it polls the timeline projection above.
    if (pathname === "/__ioi/run-timeline" || pathname.startsWith("/__ioi/run-timeline/")) {
      const rest = pathname.startsWith("/__ioi/run-timeline/") ? pathname.slice("/__ioi/run-timeline/".length) : "";
      let runId = "";
      let envId = "";
      if (rest.startsWith("env/")) {
        // /env/:envId — resolve to the env's latest run server-side (the launcher/embed is a plain
        // anchor/iframe; window.open after an async resolve is popup-blocked). Pass env so the page
        // self-heals if the run appears after load.
        envId = decodeURIComponent(rest.slice(4).split("/")[0]);
        const mine = listRuns().filter((r) => r.envId === envId).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
        runId = mine[mine.length - 1]?.id || "";
      } else if (rest.startsWith("draft/")) {
        // /draft/:draftId — contextual deep-link from a PR-draft artifact to the run that produced it.
        const draftId = decodeURIComponent(rest.slice(6).split("/")[0]);
        const owner = listRuns().find((r) => String(r.proposalRef || "").includes(draftId));
        runId = owner?.id || "";
        envId = owner?.envId || "";
      } else {
        runId = rest ? decodeURIComponent(rest.split("/")[0]) : (new URLSearchParams((req.url || "").split("?")[1] || "").get("runId") || "");
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(RUN_TIMELINE_HTML
        .replace(/__RUN_ID__/g, String(runId).replace(/[^A-Za-z0-9_-]/g, ""))
        .replace(/__ENV_ID__/g, String(envId).replace(/[^A-Za-z0-9_-]/g, "")));
      return;
    }
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
    // SCIM 2.0 provisioning — the external IdP calls /scim/v2/* via the public URL; forward to the
    // daemon SCIM server, preserving the SCIM bearer token (the daemon validates it).
    if (pathname.startsWith("/scim/")) {
      try {
        const headers = { "Content-Type": req.headers["content-type"] || "application/json" };
        if (req.headers["authorization"]) headers["Authorization"] = req.headers["authorization"];
        const upstream = await fetch(DAEMON + req.url, { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : body });
        const text = await upstream.text();
        res.writeHead(upstream.status, { "Content-Type": upstream.headers.get("content-type") || "application/json" });
        res.end(text);
      } catch (e) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: `daemon unreachable: ${e.message}` } }));
      }
      return;
    }
    // Cut A — env-ops plane: forward the EnvironmentOpsService Connect surface (and any env gateway
    // path) to the daemon, preserving the capability-lease Authorization header. Contract + lease
    // logic live in the daemon (D1); this is a transparent route, not a shim.
    if (pathname.startsWith("/supervisor/")) {
      try {
        const route = supervisorRoute(pathname);
        if (route && await handleSupervisorStream(route, req, res, body)) return;
        const handled = route ? await handleSupervisorUnary(route, req, body) : null;
        if (handled) {
          res.writeHead(handled.status, { "Content-Type": "application/json" });
          res.end(JSON.stringify(handled.body));
          return;
        }
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
    // Telemetry / error-reporting beacons: the product-ui bundle fires Segment analytics (/segment/v1/*)
    // and a Sentry error tunnel (/sentry-tunnel). With no handler they proxy to the productUi and hang
    // / abort (real pending+failed requests on nearly every surface). Ack them instantly. We collect
    // no analytics and report no errors externally — this is a local, self-contained app.
    if (pathname.startsWith("/segment/") || pathname === "/sentry-tunnel" || pathname.startsWith("/sentry")) {
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
    // ---- Identity & Auth (multi-user IdP): login / logout + session cookie ----
    if (pathname === "/__ioi/login") {
      if (req.method === "POST") {
        const form = new URLSearchParams(body.toString("utf8"));
        try {
          const r = await fetch(`${DAEMON}/v1/hypervisor/auth/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: form.get("email") || "", password: form.get("password") || "" }) });
          const d = await r.json().catch(() => ({}));
          if (r.ok && d.ok && d.session_token) {
            res.writeHead(302, { "Set-Cookie": `ioi_session=${d.session_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`, Location: "/ai" });
            res.end();
            return;
          }
          res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
          res.end(loginShell("Invalid email or password."));
        } catch (e) {
          res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
          res.end(loginShell(`Login service unavailable: ${e.message}`));
        }
        return;
      }
      let cfgs = [];
      try { const r = await fetch(`${DAEMON}/v1/hypervisor/sso-configurations`); const d = await r.json(); cfgs = d.sso_configurations || []; } catch { /* none */ }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(loginShell("", cfgs));
      return;
    }
    // SSO login start — build the PKCE authorize URL via the daemon, redirect to the IdP.
    if (pathname.startsWith("/__ioi/login/sso/") && pathname !== "/__ioi/login/sso/callback") {
      const configId = decodeURIComponent(pathname.slice("/__ioi/login/sso/".length).split("/")[0]);
      const redirectUri = `${publicBase(req)}/__ioi/login/sso/callback`;
      try {
        const r = await fetch(`${DAEMON}/v1/hypervisor/auth/oidc/start`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ config_id: configId, redirect_uri: redirectUri }) });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.ok && d.authorize_url) { res.writeHead(302, { Location: d.authorize_url }); res.end(); return; }
        res.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
        res.end(loginShell(`SSO start failed: ${d.reason || "unknown"}`));
      } catch (e) {
        res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
        res.end(loginShell(`SSO unavailable: ${e.message}`));
      }
      return;
    }
    // SSO login callback — exchange the code for a session, set the cookie.
    if (pathname === "/__ioi/login/sso/callback") {
      const q = new URLSearchParams((req.url || "").split("?")[1] || "");
      const redirectUri = `${publicBase(req)}/__ioi/login/sso/callback`;
      try {
        const r = await fetch(`${DAEMON}/v1/hypervisor/auth/oidc/callback`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: q.get("code") || "", state: q.get("state") || "", redirect_uri: redirectUri }) });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.ok && d.session_token) {
          res.writeHead(302, { "Set-Cookie": `ioi_session=${d.session_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`, Location: "/ai" });
          res.end();
          return;
        }
        res.writeHead(401, { "Content-Type": "text/html; charset=utf-8" });
        res.end(loginShell(`SSO login failed: ${d.reason || "unknown"}`));
      } catch (e) {
        res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
        res.end(loginShell(`SSO callback error: ${e.message}`));
      }
      return;
    }
    // Invite acceptance — provision a member account from the org invite link, then sign in.
    if (pathname.startsWith("/__ioi/invite/")) {
      const inviteId = decodeURIComponent(pathname.slice("/__ioi/invite/".length).split("/")[0]);
      if (req.method === "POST") {
        const form = new URLSearchParams(body.toString("utf8"));
        try {
          const r = await fetch(`${DAEMON}/v1/hypervisor/org-invite/accept`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ invite_id: inviteId, email: form.get("email") || "", name: form.get("name") || "", password: form.get("password") || "" }) });
          const d = await r.json().catch(() => ({}));
          if (r.ok && d.ok && d.session_token) {
            res.writeHead(302, { "Set-Cookie": `ioi_session=${d.session_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`, Location: "/ai" });
            res.end();
            return;
          }
          res.writeHead(403, { "Content-Type": "text/html; charset=utf-8" });
          res.end(inviteShell(inviteId, "This invite link is invalid or expired."));
        } catch (e) {
          res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
          res.end(inviteShell(inviteId, `Invite service unavailable: ${e.message}`));
        }
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(inviteShell(inviteId, ""));
      return;
    }
    if (pathname === "/__ioi/logout") {
      try { await fetch(`${DAEMON}/v1/hypervisor/auth/logout`, { method: "POST", headers: { Cookie: req.headers.cookie || "" } }); } catch { /* best-effort */ }
      res.writeHead(302, { "Set-Cookie": "ioi_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0", Location: "/__ioi/login" });
      res.end();
      return;
    }
    // ---- Page gate: when auth enforcement is ON, redirect unauthenticated HTML navigations to login
    // (the daemon's whoami returns 401 only when enforced + no valid session). Off → 200 → passthrough.
    {
      const accept = req.headers["accept"] || "";
      const isHtmlNav = req.method === "GET" && accept.includes("text/html") && !pathname.startsWith("/api/") && !pathname.startsWith("/__ioi/") && !pathname.startsWith("/static/") && !pathname.startsWith("/assets/") && !pathname.startsWith("/v1/") && pathname !== "/ioi-augmentation.js";
      if (isHtmlNav) {
        try {
          const w = await fetch(`${DAEMON}/v1/hypervisor/auth/whoami`, { headers: { Cookie: req.headers.cookie || "", ...(req.headers["x-forwarded-host"] ? { "X-Forwarded-Host": req.headers["x-forwarded-host"] } : {}) } });
          if (w.status === 401) { res.writeHead(302, { Location: "/__ioi/login" }); res.end(); return; }
        } catch { /* daemon transient — fail open, never lock the operator out */ }
      }
    }
    // Agent-run conversation. The SPA's V1 conversation pane (`sr` in use-conversation-stream) opens
    // the bare `conversationUrl` as a LONG-LIVED newline-delimited-JSON STREAM and reads it with a
    // ReadableStream reader until EOF — at which point it `throw new Error("Stream closed
    // unexpectedly")` and shows the "Retrying in 3s…2s…" banner, then reconnects. So a finite
    // response makes it retry forever. We must HOLD THE STREAM OPEN and push entries as the run
    // progresses: the user prompt, then (on completion) the files the agent wrote + its summary. The
    // final PHASE_COMPLETED entries replace the optimistic "Thinking…" placeholder; keeping the
    // socket open (never EOF) means no "Stream closed"/"Retrying". /history + /live are the V2 mode
    // the product-ui bundle prefers for the native workbench conversation pane.
    // Governed "Publish PR" command — orchestrates the wallet-authorized SCM publish crossing for a
    // run (challenge → mint grant → real git push to the connector remote) and records the receipt.
    if (pathname.startsWith("/__ioi/run-publish/") && req.method === "POST") {
      const runId = decodeURIComponent(pathname.slice("/__ioi/run-publish/".length).split("/")[0]);
      const result = await publishRunViaConnector(runId).catch((e) => ({ ok: false, reason: String(e?.message || e) }));
      res.writeHead(result.ok ? 200 : 409, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(result));
      return;
    }
    // ---- BYOA GitHub App (manifest) connect flow — the "Create & connect GitHub App" button -------
    // No vendor-owned OAuth App: the user creates an App in their OWN account. start → renders an
    // auto-submitting form that POSTs the manifest to github.com; callback ← GitHub redirects with a
    // code we exchange (daemon seals the App key) → redirect to install; installed ← captures the
    // installation_id. The page chrome is intentionally minimal + dark.
    if (pathname === "/__ioi/github-app/start") {
      const qp = new URL(req.url, "http://x").searchParams;
      const owner = qp.get("owner") || ""; // omit for a USER account (e.g. teamioitest)
      let page;
      try {
        const r = await fetch(`${DAEMON}/v1/hypervisor/scm-connect/github-app/manifest`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ owner, callback_base: `http://${req.headers.host || "127.0.0.1:4173"}` }) });
        const d = await r.json();
        const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
        page = githubAppShell("Create your GitHub App", `
          <p>Hypervisor doesn't own a GitHub App — you'll create one in <b>your own</b> account. GitHub will show you exactly what it can access (Contents + Pull requests), then hand the key straight to your daemon. Nothing is shared with us.</p>
          <form id="gh" action="${esc(d.create_url)}" method="post">
            <input type="hidden" name="manifest" value="${esc(JSON.stringify(d.manifest))}">
            <button type="submit" class="btn">Create GitHub App on GitHub →</button>
          </form>
          <p class="muted">You'll be returned here automatically to finish the connection.</p>
          <script>setTimeout(function(){try{document.getElementById('gh').submit()}catch(e){}}, 1200)</script>`);
      } catch (e) {
        page = githubAppShell("Couldn't start", `<p class="muted">Daemon unavailable: ${String(e?.message || e)}</p>`);
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(page);
      return;
    }
    if (pathname === "/__ioi/github-app/callback") {
      const qp = new URL(req.url, "http://x").searchParams;
      const code = qp.get("code") || "";
      let page;
      try {
        const r = await fetch(`${DAEMON}/v1/hypervisor/scm-connect/github-app/conversion`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ code }) });
        const d = await r.json();
        if (d.ok && d.install_url) {
          page = githubAppShell("GitHub App created ✓", `
            <p>Your App <b>${d.app_slug}</b> was created in <b>@${d.connected_login}</b> and its key is sealed in your daemon. One more step: install it on the repositories it may act on.</p>
            <a class="btn" href="${d.install_url}">Install the App →</a>
            <p class="muted">Redirecting you to install…</p>
            <script>setTimeout(function(){location.href=${JSON.stringify(d.install_url)}}, 1500)</script>`);
        } else {
          page = githubAppShell("Couldn't create the App", `<p class="muted">${d.message || d.reason || "conversion failed"}</p>`);
        }
      } catch (e) {
        page = githubAppShell("Couldn't create the App", `<p class="muted">${String(e?.message || e)}</p>`);
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(page);
      return;
    }
    if (pathname === "/__ioi/github-app/installed") {
      const qp = new URL(req.url, "http://x").searchParams;
      const installation_id = qp.get("installation_id") || "";
      let page;
      try {
        const r = await fetch(`${DAEMON}/v1/hypervisor/scm-connect/github-app/installation`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ installation_id }) });
        const d = await r.json();
        page = d.ok
          ? githubAppShell("GitHub App connected ✓", `<p>Installation <b>${d.installation_id}</b> bound to <b>${d.connector_id}</b>${d.verified ? " — installation token minted successfully." : "."}</p><p class="muted">The agent will receive a use-only lease; the App key never leaves your daemon. You can close this tab.</p>`)
          : githubAppShell("Couldn't finish install", `<p class="muted">${d.reason || "installation capture failed"}</p>`);
      } catch (e) {
        page = githubAppShell("Couldn't finish install", `<p class="muted">${String(e?.message || e)}</p>`);
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(page);
      return;
    }
    // ---- OAuth-native MCP Connect ("authorize this integration") — browser plumbing --------------
    // connect/:id → ask the daemon for the provider authorize URL (PKCE) and 302 the browser there;
    // oauth/callback ← the provider redirects back, we hand the code to the daemon to seal tokens.
    if (pathname.startsWith("/__ioi/integrations/connect/")) {
      const cid = decodeURIComponent(pathname.slice("/__ioi/integrations/connect/".length).split("/")[0]);
      const redirect_uri = `${publicBase(req)}/__ioi/integrations/oauth/callback`;
      const start = () => fetch(`${DAEMON}/v1/hypervisor/connectors/${encodeURIComponent(cid)}/oauth/start`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uri }) }).then((r) => r.json());
      try {
        let d = await start();
        // No auth_profile yet → auto-discover + DCR (no per-service app), then retry.
        if (!(d.ok && d.authorize_url)) {
          await fetch(`${DAEMON}/v1/hypervisor/connectors/${encodeURIComponent(cid)}/oauth/discover`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uri }) }).catch(() => {});
          d = await start();
        }
        if (d.ok && d.authorize_url) { res.writeHead(302, { Location: d.authorize_url, "Cache-Control": "no-cache" }); return res.end(); }
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(githubAppShell("Can't connect yet", `<p class="muted">${d.message || d.reason || "could not resolve an OAuth profile for this integration (discovery/DCR unavailable)"}</p>`));
      } catch (e) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(githubAppShell("Can't connect yet", `<p class="muted">${String(e?.message || e)}</p>`));
      }
      return;
    }
    if (pathname === "/__ioi/integrations/oauth/callback") {
      const qp = new URL(req.url, "http://x").searchParams;
      const state = qp.get("state") || "", code = qp.get("code") || "";
      let page;
      try {
        const r = await fetch(`${DAEMON}/v1/hypervisor/connectors/oauth/callback`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ state, code }) });
        const d = await r.json();
        page = d.ok
          ? githubAppShell("Integration connected ✓", `<p>Authorized and sealed (<b>${d.credential_kind}</b>) on <b>${d.connector_id}</b>.</p><p class="muted">The agent receives only scoped capability leases minted from this — the provider credential never leaves your daemon. You can close this tab.</p>`)
          : githubAppShell("Couldn't connect", `<p class="muted">${d.message || d.reason || "authorization failed"}</p>`);
      } catch (e) {
        page = githubAppShell("Couldn't connect", `<p class="muted">${String(e?.message || e)}</p>`);
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(page);
      return;
    }
    // ---- Slack BYOA OAuth setup (confidential client) — Slack has no DCR + needs an https redirect.
    // The client_secret goes browser→daemon (sealed); it never touches the agent or chat. Then we
    // hand off to the standard OAuth-native Connect launcher.
    if (pathname === "/__ioi/slack/setup" && req.method !== "POST") {
      const redirect = `${publicBase(req)}/__ioi/integrations/oauth/callback`;
      const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
      const inp = 'style="width:100%;box-sizing:border-box;margin:4px 0 12px;padding:10px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit"';
      const page = githubAppShell("Connect Slack (BYOA OAuth)", `
        <p>Create a Slack app, then paste its <b>Client ID</b> + <b>Client Secret</b>. The secret is sealed in your daemon — it never touches the agent or this chat.</p>
        <p class="muted">In your Slack app → <b>OAuth &amp; Permissions</b>, add this exact <b>Redirect URL</b>:</p>
        <p><code style="user-select:all;word-break:break-all">${esc(redirect)}</code></p>
        <p class="muted">…and Bot Token Scopes (e.g. <code>chat:write</code>, <code>channels:read</code>).</p>
        <form method="post" action="/__ioi/slack/setup">
          <input name="client_id" placeholder="Client ID" required ${inp}>
          <input name="client_secret" type="password" placeholder="Client Secret" required ${inp}>
          <input name="scopes" value="chat:write,channels:read" ${inp}>
          <button class="btn" type="submit">Seal &amp; continue to authorize →</button>
        </form>`);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(page);
      return;
    }
    if (pathname === "/__ioi/slack/setup" && req.method === "POST") {
      const p = new URLSearchParams(body.toString());
      const client_id = (p.get("client_id") || "").trim();
      const client_secret = (p.get("client_secret") || "").trim();
      const scopes = (p.get("scopes") || "chat:write").trim();
      try {
        const reg = await fetch(`${DAEMON}/v1/hypervisor/connectors`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
          service: "slack", kind: "http", name: "Slack", base_url: "https://slack.com/api",
          allowed_tools: [{ name: "auth.test", method: "POST", path: "/auth.test" }, { name: "chat.postMessage", method: "POST", path: "/chat.postMessage" }],
          auth_profile: { type: "oauth_authcode_pkce", authorization_endpoint: "https://slack.com/oauth/v2/authorize", token_endpoint: "https://slack.com/api/oauth.v2.access", client_id, client_secret, scopes: [scopes] },
        }) }).then((r) => r.json());
        const cid = reg.connector?.connector_id;
        if (!cid) throw new Error(reg.reason || "register failed");
        res.writeHead(302, { Location: `/__ioi/integrations/connect/${encodeURIComponent(cid)}`, "Cache-Control": "no-cache" });
        return res.end();
      } catch (e) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(githubAppShell("Couldn't set up Slack", `<p class="muted">${String(e?.message || e)}</p>`));
        return;
      }
    }
    // ---- Automations cockpit — the owned PROJECT-FIRST surface (daemon HypervisorAutomationSpec) --
    if (pathname === "/__ioi/automations" && req.method === "GET") {
      const projectId = new URL(req.url, "http://x").searchParams.get("project") || "";
      try {
        const [aRes, pRes] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/automations${projectId ? "?project_ref=" + encodeURIComponent(projectId) : ""}`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/projects`).then((r) => r.json()).catch(() => ({})),
        ]);
        const projectsById = {};
        for (const p of pRes.projects || []) projectsById[p.project_id] = p;
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(renderAutomationsList(aRes.automations || [], projectId, projectsById));
      } catch (e) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(automationsShell("Automations", `<div class="empty">Daemon unavailable: ${CX_ESC(String(e?.message || e))}</div>`));
      }
      return;
    }
    if (pathname === "/__ioi/automations.json" && req.method === "GET") {
      // JSON feed for the project-detail panel (the augmentation script fetches this).
      const projectId = new URL(req.url, "http://x").searchParams.get("project") || "";
      const aRes = await fetch(`${DAEMON}/v1/hypervisor/automations${projectId ? "?project_ref=" + encodeURIComponent(projectId) : ""}`).then((r) => r.json()).catch(() => ({}));
      const automations = (aRes.automations || []).map((a) => ({ automation_id: a.automation_id, name: a.name, trigger_kind: a.trigger_kind || "manual", enabled: a.enabled !== false, model: a.model || null, steps: Array.isArray(a.steps) ? a.steps.length : 0 }));
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(JSON.stringify({ automations }));
      return;
    }
    if (pathname === "/__ioi/automations/new" && req.method === "GET") {
      const projectId = new URL(req.url, "http://x").searchParams.get("project") || "";
      const pRes = await fetch(`${DAEMON}/v1/hypervisor/projects`).then((r) => r.json()).catch(() => ({}));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderAutomationNewForm(projectId, pRes.projects || []));
      return;
    }
    if (pathname === "/__ioi/automations/cron-preview" && req.method === "GET") {
      // Proxy the daemon cron-preview (next-runs) for the create form's live preview.
      const qs = new URL(req.url, "http://x").searchParams.toString();
      const r = await fetch(`${DAEMON}/v1/hypervisor/cron-preview?${qs}`).then((x) => x.json()).catch(() => ({ ok: false, error: "daemon unavailable" }));
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(r));
      return;
    }
    if (pathname === "/__ioi/automations" && req.method === "POST") {
      const p = new URLSearchParams(body.toString());
      const stepBody = (p.get("step_body") || "").trim();
      const stepKind = p.get("step_kind") || "agent";
      const steps = stepBody ? [stepKind === "command" ? { kind: "command", command: stepBody } : { kind: "agent", prompt: stepBody }] : [];
      const connectorRefs = (p.get("connector_refs") || "").split(",").map((s) => s.trim()).filter(Boolean);
      // Schedule: type selector → interval | cron | manual (time trigger when scheduled).
      const schedType = p.get("schedule_type") || "manual";
      let schedule_spec = null;
      if (schedType === "interval") {
        const intervalN = parseInt(p.get("interval_n") || "0", 10) || 0;
        const intervalUnit = p.get("interval_unit") || "minutes";
        if (intervalN > 0) schedule_spec = intervalUnit === "hours" ? { every_hours: intervalN } : intervalUnit === "seconds" ? { every_seconds: intervalN } : { every_minutes: intervalN };
      } else if (schedType === "cron") {
        const cron = (p.get("cron") || "").trim();
        if (cron) schedule_spec = { type: "cron", cron, timezone: p.get("cron_tz") || "UTC" };
      }
      const payload = {
        project_ref: (p.get("project_ref") || "").trim(),
        name: (p.get("name") || "automation").trim(),
        description: (p.get("description") || "").trim(),
        trigger_kind: schedule_spec ? "time" : "manual",
        schedule_spec,
        max_concurrency: parseInt(p.get("max_concurrency") || "1", 10) || 1,
        failure_policy: p.get("failure_policy") || "continue",
        model: (p.get("model") || "").trim() || null,
        reasoning: (p.get("reasoning") || "").trim() || null,
        agent_ref: (p.get("agent_ref") || "").trim() || null,
        connector_refs: connectorRefs,
        memory_profile_ref: (p.get("memory_profile_ref") || "").trim() || null,
        steps,
      };
      const r = await fetch(`${DAEMON}/v1/hypervisor/automations`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const j = await r.json().catch(() => ({}));
      const newId = j.automation && j.automation.automation_id;
      if (r.status >= 400 || !newId) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(automationsShell("New automation", `<div class="empty">Create failed: ${CX_ESC((j.error && j.error.message) || ("HTTP " + r.status))}</div><p><a href="/__ioi/automations/new${payload.project_ref ? "?project=" + encodeURIComponent(payload.project_ref) : ""}">← back</a></p>`));
        return;
      }
      res.writeHead(302, { Location: `/__ioi/automations/${encodeURIComponent(newId)}`, "Cache-Control": "no-cache" });
      res.end();
      return;
    }
    if (pathname.startsWith("/__ioi/automations/")) {
      const rest = pathname.slice("/__ioi/automations/".length);
      const [rawId, action] = rest.split("/");
      const id = decodeURIComponent(rawId);
      if (action === "run" && req.method === "POST") {
        // Manual run: the daemon executor creates an env, runs the steps, and records a transcript.
        await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}/runs`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).catch(() => {});
        res.writeHead(302, { Location: `/__ioi/automations/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
      if ((action === "pause" || action === "resume") && req.method === "POST") {
        // Pause/resume the schedule = PATCH enabled (the daemon scheduler skips disabled specs).
        await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: action === "resume" }) }).catch(() => {});
        res.writeHead(302, { Location: `/__ioi/automations/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
      if (action === "patch" && req.method === "POST") {
        // Canvas inspector save → daemon PATCH (returns JSON so the canvas can surface validation errors).
        const r = await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: body.toString() || "{}" }).then((x) => x.json()).catch(() => ({ ok: false, error: { message: "daemon unavailable" } }));
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(JSON.stringify(r));
        return;
      }
      if (action === "webhook-rotate" && req.method === "POST") {
        // Mint/rotate the trigger secret and reveal it ONCE (only its hash is persisted).
        const r = await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}/webhook-rotate`, { method: "POST" }).then((x) => x.json()).catch(() => ({}));
        const token = r.webhook_token || "";
        const url = `${publicBase(req)}/v1/hypervisor/automations/${encodeURIComponent(id)}/webhook`;
        const reveal = token
          ? `<p><a href="/__ioi/automations/${encodeURIComponent(id)}">← ${CX_ESC(id)}</a></p><h1>Webhook secret</h1>
             <p class="sub">Copy this now — it is shown once and only its hash is stored. Send it on every call as the <code>X-IOI-Trigger-Token</code> header.</p>
             <div class="reveal">${CX_ESC(token)}</div>
             <h2>Example</h2>
             <pre>curl -X POST ${CX_ESC(url)} \\
  -H "X-IOI-Trigger-Token: ${CX_ESC(token)}" \\
  -H "content-type: application/json" \\
  -d '{"event":"ping"}'</pre>
             <p><a class="act" href="/__ioi/automations/${encodeURIComponent(id)}">Done</a></p>`
          : `<div class="empty">Could not rotate secret.</div><p><a href="/__ioi/automations/${encodeURIComponent(id)}">← back</a></p>`;
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
        res.end(automationsShell("Webhook secret", reveal));
        return;
      }
      if (action === "delete" && req.method === "POST") {
        const a = await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => ({}));
        const pid = a.automation && (a.automation.project_ref || a.automation.project_id);
        await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
        res.writeHead(302, { Location: `/__ioi/automations${pid ? "?project=" + encodeURIComponent(pid) : ""}`, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
      if (!action && req.method === "GET") {
        try {
          const [aRes, rRes, pRes, wRes] = await Promise.all([
            fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => ({})),
            fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}/runs`).then((r) => r.json()).catch(() => ({})),
            fetch(`${DAEMON}/v1/hypervisor/projects`).then((r) => r.json()).catch(() => ({})),
            fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}/webhook-events`).then((r) => r.json()).catch(() => ({})),
          ]);
          if (!aRes.automation) {
            res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
            res.end(automationsShell("Not found", `<div class="empty">Automation not found.</div><p><a href="/__ioi/automations">← Automations</a></p>`));
            return;
          }
          const projectsById = {};
          for (const p of pRes.projects || []) projectsById[p.project_id] = p;
          const webhook = { events: wRes.events || [], accepted: wRes.accepted_count || 0, rejected: wRes.rejected_count || 0, baseUrl: publicBase(req) };
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
          res.end(renderAutomationDetail(aRes.automation, rRes.runs || [], projectsById, webhook));
        } catch (e) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Automation", `<div class="empty">Daemon unavailable: ${CX_ESC(String(e?.message || e))}</div>`));
        }
        return;
      }
    }

    // ---- Applications estate — the owned breadth launcher (Connections re-homed as Developer & Integrations).
    if (pathname === "/__ioi/applications" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderApplications());
      return;
    }
    // ---- Connections cockpit — the owned full-control surface for the connector estate -----------
    if (pathname === "/__ioi/connections") {
      try {
        const [c, s, l] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/connectors`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/scm-connectors`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/capability-leases`).then((r) => r.json()).catch(() => ({})),
        ]);
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(renderConnectionsCockpit(c.connectors || [], s.connectors || [], l.leases || []));
      } catch (e) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(connectionsShell(`<div class="empty">Daemon unavailable: ${String(e?.message || e)}</div>`));
      }
      return;
    }
    if (pathname === "/__ioi/connections/add" && req.method !== "POST") {
      const type = new URL(req.url, "http://x").searchParams.get("type") || "mcp";
      const inp = 'style="width:100%;box-sizing:border-box;margin:4px 0 12px;padding:10px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit"';
      const form = type === "mcp"
        ? `<h2>Add MCP server</h2><p class="sub">Register an MCP server URL — the daemon auto-discovers its tools and OAuth (Dynamic Client Registration) when you connect. No vendor app needed.</p>
           <form method="post" action="/__ioi/connections/add?type=mcp">
             <input name="name" placeholder="Name (e.g. Linear)" required ${inp}>
             <input name="mcp_url" placeholder="https://mcp.example.com/mcp" required ${inp}>
             <button class="act" type="submit">Add &amp; discover</button></form>`
        : `<h2>Add API key / service</h2><p class="sub">A bearer-token HTTP connector (advanced). The token is sealed in the daemon; the agent only ever gets a scoped lease.</p>
           <form method="post" action="/__ioi/connections/add?type=bearer">
             <input name="name" placeholder="Name (e.g. Linear API)" required ${inp}>
             <input name="base_url" placeholder="https://api.example.com" required ${inp}>
             <input name="tool_name" placeholder="tool name (e.g. create_issue)" required ${inp}>
             <input name="tool_path" placeholder="/v1/issues" required ${inp}>
             <input name="token" type="password" placeholder="API token (sealed)" required ${inp}>
             <button class="act" type="submit">Add + seal token</button></form>`;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(connectionsShell(`<p><a href="/__ioi/connections" style="color:#9a9da6;text-decoration:none">← Connections</a></p>${form}`));
      return;
    }
    if (pathname === "/__ioi/connections/add" && req.method === "POST") {
      const type = new URL(req.url, "http://x").searchParams.get("type") || "mcp";
      const p = new URLSearchParams(body.toString());
      const post = (path, b) => fetch(`${DAEMON}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(b) }).then((r) => r.json());
      try {
        if (type === "mcp") {
          const reg = await post("/v1/hypervisor/connectors", { service: "mcp", kind: "mcp", name: p.get("name"), base_url: p.get("mcp_url") });
          if (reg.connector?.connector_id) await post(`/v1/hypervisor/connectors/${encodeURIComponent(reg.connector.connector_id)}/oauth/discover`, {}).catch(() => {});
        } else {
          const svc = (p.get("name") || "service").toLowerCase().replace(/[^a-z0-9]+/g, "-");
          const reg = await post("/v1/hypervisor/connectors", { service: svc, kind: "http", name: p.get("name"), base_url: p.get("base_url"), allowed_tools: [{ name: p.get("tool_name"), method: "POST", path: p.get("tool_path") }] });
          if (reg.connector?.connector_id) await post(`/v1/hypervisor/connectors/${encodeURIComponent(reg.connector.connector_id)}/credential`, { token: p.get("token") });
        }
        res.writeHead(302, { Location: "/__ioi/connections", "Cache-Control": "no-cache" });
        return res.end();
      } catch (e) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(connectionsShell(`<div class="empty">Couldn't add: ${String(e?.message || e)}</div>`));
        return;
      }
    }
    // Resolve an environment to its latest agent-run id — lets any surface's launcher open the owned
    // Run Timeline for the env in view (Workbench/Sessions/Studio/Automations/IOI.ai all key by env).
    if (pathname.startsWith("/__ioi/env-latest-run/")) {
      const envId = decodeURIComponent(pathname.slice("/__ioi/env-latest-run/".length).split("/")[0]);
      const mine = listRuns().filter((r) => r.envId === envId).sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
      const latest = mine[mine.length - 1] || null;
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify({ ok: !!latest, runId: latest?.id || null, status: latest?.status || null, count: mine.length }));
      return;
    }
    // Owned Run Timeline projection (Hypervisor's transcript primitive) — daemon-truth, 6-part
    // governed-work turns. The UI surface at /__ioi/run-timeline/:id polls this.
    if (pathname.startsWith("/__ioi/agent-runs/") && pathname.endsWith("/timeline")) {
      const runId = pathname.split("/__ioi/agent-runs/")[1].split("/")[0];
      const run = getRun(runId);
      if (!run) { res.writeHead(404, { "Content-Type": "application/json" }); res.end(JSON.stringify({ ok: false, reason: "run not found" })); return; }
      // merge the daemon governance audit trail (authority receipts) — real records, never fabricated
      let authorityReceipts = [];
      try { const r = await djson("GET", "/v1/hypervisor/authority/receipts"); authorityReceipts = r.body?.receipts || []; } catch { /* daemon transient — empty trail */ }
      // is a usable SCM connector registered? (gates the governed "Publish PR" follow-up)
      let hasConnector = false;
      try { const c = await djson("GET", "/v1/hypervisor/scm-connectors"); hasConnector = (c.body?.connectors || []).some((x) => x.auth_posture === "local-none"); } catch { /* */ }
      const timeline = projectRunTimeline(run, { authorityReceipts, hasConnector });
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(timeline));
      return;
    }
    if (pathname.startsWith("/__ioi/agent-runs/") && pathname.includes("/conversation")) {
      const runId = pathname.split("/__ioi/agent-runs/")[1].split("/")[0];
      if (pathname.endsWith("/conversation/history")) {
        const run = getRun(runId);
        const chunks = run ? conversationChunks(run) : [];
        const selected = selectConversationChunks(chunks, new URLSearchParams((req.url || "").split("?")[1] || ""));
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ chunks: selected, has_more: false }));
        return;
      }
      if (pathname.endsWith("/conversation/live")) {
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
        const seen = new Set();
        const pump = () => {
          const run = getRun(runId);
          if (!run) return;
          const chunks = conversationChunks(run);
          const latest = chunks.at(-1);
          const inputChunk = chunks.find((chunk) => chunk.id.endsWith("-input"));
          const userInputs = inputChunk ? [{ chunk_id: inputChunk.id, block_idx: 0 }] : [];
          try {
            res.write(`event: state\ndata: ${JSON.stringify({
              chunk_id: latest?.id || `${runId}-empty`,
              todo_groups: [],
              available_commands: null,
              clarifying_questions: null,
              next_steps_proposal: null,
              user_inputs: userInputs,
            })}\n\n`);
            for (const chunk of chunks) {
              for (const frameValue of chunk.frames || []) {
                const key = `${chunk.id}:${frameValue}`;
                if (seen.has(key)) continue;
                seen.add(key);
                res.write(`event: block\ndata: ${JSON.stringify({ frame: frameValue })}\n\n`);
              }
            }
          } catch {
            // Client closed; the request close handler clears the interval.
          }
        };
        pump();
        const interval = setInterval(() => {
          pump();
          try { res.write(":\n\n"); } catch { clearInterval(interval); }
        }, 1000);
        req.on("close", () => clearInterval(interval));
        return; // keep open; V2 live subscriptions reconnect on EOF.
      }
      // bare /conversation — long-lived NDJSON stream, held open.
      res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-cache", Connection: "keep-alive" });
      const seen = new Set();
      const pump = () => {
        const run = getRun(runId);
        if (!run) return;
        for (const entry of conversationEntries(run)) {
          const key = entry.id; // entries are stable; emit each once, updated entries get a new id suffix
          if (!seen.has(key)) { seen.add(key); try { res.write(JSON.stringify(entry) + "\n"); } catch { /* closed */ } }
        }
      };
      pump();
      const interval = setInterval(() => { pump(); try { res.write("\n"); } catch { clearInterval(interval); } }, 1000); // newline = keepalive (reader skips empty lines)
      req.on("close", () => clearInterval(interval));
      return; // NEVER res.end() — the SPA's reader treats EOF as "Stream closed" and retries.
    }
    // WS-5: editor "Open in VS Code Browser". The product-ui bundle opens the editor's urlTemplate;
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
    if (pathname === "/api/ioi.v1.EventService/WatchEvents") {
      res.writeHead(200, { "Content-Type": "application/connect+json" });
      res.end(connectEndStreamFrame({}));
      return;
    }
    if (pathname.startsWith("/api/")) {
      let handled = null;
      try {
        handled = await adapter.handle(pathname, body.toString("utf8"), req.headers);
      } catch (e) {
        console.error("[ioi-api-adapter]", e);
      }
      if (handled) {
        res.writeHead(handled.status || 200, { "Content-Type": handled.contentType || "application/json" });
        res.end(handled.body);
        return;
      }
      // Unported → proxied to mock. Record any ioi.v1.* RPC for the terminability done-bar.
      const m = pathname.match(/^\/api\/(ioi\.v1\.[A-Za-z]+\/[A-Za-z]+)/);
      if (m) fallthrough.add(m[1]);
    }
    proxyToProductUi(req, res, body);
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
        const sanitize = makeTerminalSanitizer();
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
                const clean = sanitize(outChunk);
                if (clean) {
                  const b64 = Buffer.from(clean, "utf8").toString("base64");
                  if (first) { first = false; ok(id, { replay: { data: b64, cols: 80, rows: 24 } }); }
                  else ok(id, { data: { data: b64 } });
                }
              }
              since = newOffset;
              if (!running) { ok(id, { exited: { exitCode: 0 } }); ok(id, null); break; }
              await new Promise((res) => setTimeout(res, 250));
            }
          } catch { /* aborted/closed */ }
        })();
        return;
      }

      // --- Watch (server-streaming): poll the daemon's authoritative {porcelain, files} snapshot
      // and forward gitStatusChanged / fileChanges deltas. The watch TRUTH lives in the daemon (it
      // owns the workspace), so this generalizes beyond a serve-co-located fs; serve is pure
      // transport (mirrors the terminal-stream poll above). ---
      if (m === "Watch") {
        const wsUrl = `/v1/hypervisor/environments/${encodeURIComponent(env)}/watch-state`;
        const initial = await djson("GET", wsUrl);
        if (!initial.body?.ok) { return err(id, C.Unavailable, initial.body?.reason || "workspace not started"); }
        let aborted = false;
        streams.set(id, () => { aborted = true; });
        let lastPorcelain = initial.body.porcelain || "";
        let lastFiles = Array.isArray(initial.body.files) ? initial.body.files : [];
        (async () => {
          try {
            while (!aborted) {
              await new Promise((res) => setTimeout(res, 700));
              if (aborted) break;
              let r;
              try { r = await djson("GET", wsUrl); } catch { continue; }
              if (!r.body?.ok) continue;
              const porcelain = r.body.porcelain || "";
              const files = Array.isArray(r.body.files) ? r.body.files : [];
              const prev = new Set(lastFiles);
              const now = new Set(files);
              const events = [];
              for (const f of files) if (!prev.has(f)) events.push({ path: f, type: "FILE_CHANGE_TYPE_ADDED", isDirectory: false });
              for (const f of lastFiles) if (!now.has(f)) events.push({ path: f, type: "FILE_CHANGE_TYPE_DELETED", isDirectory: false });
              if (events.length) ok(id, { fileChanges: { events } });
              if (porcelain !== lastPorcelain) ok(id, { gitStatusChanged: {} });
              lastPorcelain = porcelain;
              lastFiles = files;
            }
          } catch { /* aborted/closed */ }
        })();
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

// The env-ops WS transport drives the reference app's supervisor availability probe. The terminal
// tab treats a failed probe as "old environment" even when the HTTP EnvironmentOpsService works, so
// the product app keeps the probe available by default. IOI-owned HTTP handlers still serve the
// unary/streaming Connect surface; WS remains a compatibility transport for the probe and non-SPA
// clients. Set IOI_ENV_OPS_WS=0 to fail the probe closed during low-level bridge debugging.
const ENV_OPS_WS = process.env.IOI_ENV_OPS_WS !== "0";
const supervisorWss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  const pathname = (req.url || "").split("?")[0];
  if (ENV_OPS_WS && (pathname === "/supervisor.v1.EnvironmentOpsService/" || pathname.startsWith("/supervisor/"))) {
    supervisorWss.handleUpgrade(req, socket, head, (ws) => handleSupervisorWs(ws));
  } else {
    socket.destroy();
  }
});

// Wait for the productUi to accept connections, then listen.
function waitForMirror(attempt = 0) {
  const probe = http.get({ host: "127.0.0.1", port: PRODUCT_UI_PORT, path: "/" }, (r) => {
    r.destroy();
    server.listen(PORT, async () => {
      console.log(`[hypervisor] product-ui bundle + IOI /api adapter on http://localhost:${PORT}`);
      // #3 — rehydrate the run-registry cache from the daemon's durable agent-run-transcripts so the
      // Run Timeline + env→run resolvers survive a serve restart (durable truth lives in the daemon).
      const n = await hydrateRunsFromDaemon();
      if (n) console.log(`[hypervisor] rehydrated ${n} durable run transcript(s) from the daemon`);
    });
  });
  probe.on("error", () => {
    if (attempt > 50) {
      console.error("[hypervisor] productUi did not come up");
      process.exit(1);
    }
    setTimeout(() => waitForMirror(attempt + 1), 200);
  });
}
waitForMirror();
