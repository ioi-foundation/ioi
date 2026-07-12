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
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocketServer } from "ws";
import * as adapter from "./ioi-api-adapter.mjs";
import { getRun, listRuns, hydrateRunsFromDaemon, publishRunViaConnector } from "./ioi-agent-runs.mjs";
import { projectRunTimeline } from "./ioi-run-timeline.mjs";
import { bpIcon, ONTOLOGY_APP_ICON_URI, APPROVALS_APP_ICON_URI, PIPELINE_APP_ICON_URI, ISSUES_APP_ICON_URI, EXPLORER_APP_ICON_URI, MODELS_APP_ICON_URI, AIP_GRADIENT_SVG_RAIL, AIP_GRADIENT_SVG_TOOLBAR } from "./bp-icons.mjs";
import { MARKETPLACE_APP_ICON_URI, MK_GLOBE_URI, MK_HERO_URI, MK_STORE_ICON_URI, MK_PACKAGE_URI, MK_WIZ1_URI, MK_ARROW_URI, MK_WIZ2_URI, MK_WIZ3_URI } from "./marketplace-assets.mjs";
import { DSG_APP_TILE_URI, DSG_ROW_DOC_URI, DSG_HERO_URI, DSG_AIP_ICON_URI, DSG_GALLERY_STRIP_URI } from "./designer-assets.mjs";
import { MCH_APP_TILE_URI, MCH_STORE_ICON_URI, MCH_HERO_URI, MCH_EXAMPLES_STRIP_URI } from "./machinery-assets.mjs";
import { MON_APP_TILE_URI, MON_WIZ_STRIP_URI, MON_CARDS_STRIP_URI } from "./monitors-assets.mjs";
import { SRC_APP_TILE_URI, SRC_HERO_URI, SRC_SETUP_STRIP_URI } from "./sources-assets.mjs";
import { CHG_APP_TILE_URI } from "./changes-assets.mjs";
import { EVL_APP_TILE_URI, EVL_HERO_URI } from "./evalsuites-assets.mjs";
import { appCatalog } from "./app-catalog.mjs";
import { bindSurface, boundSurface, boundActionRoute, embeddableRoutes } from "./surface-registry.mjs";
import { escHtml } from "../surfaces/kit.mjs";
import { managerLink, managerResourceLink, objectSetLink, sourcesLink, pipelineNodeLink, lineageLink as semLineageLink, vertexLink as semVertexLink, provenanceReceiptLink, provenanceSetLink, semanticBreadcrumb } from "../surfaces/ontology-context.mjs";
import { ioiGlobalRailHtml, IOI_GRAIL_CSS } from "../surfaces/chrome.mjs";
import { mintTestGrant, awaitingWalletAuthority } from "./lib/wallet-authority.mjs";

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
// The injected UI is authored as per-surface modules (scripts/augmentation/NN-*.js) and served
// as ONE script: ordered raw concatenation inside the shared IIFE (module 00 opens it, 90 closes
// it — function hoisting makes cross-module references safe; mount() runs last). One delivery URL
// for both shell trees, so the module split is invisible at the wire.
const AUG_DIR = join(HERE, "augmentation");
function augmentationBundle() {
  return readdirSync(AUG_DIR).filter((f) => f.endsWith(".js")).sort()
    .map((f) => readFileSync(join(AUG_DIR, f), "utf8")).join("");
}
// WS-I: injected IOI-native surface tag (mounted beside the cockpit; never edits the seeded SPA's DOM).
const AUG_TAG = '<script src="/ioi-augmentation.js" defer></script>';
const FEATURE_FLAG_TAG = '<script>try{localStorage.setItem("feature_flag_supervisor_watch_enabled","true")}catch(e){}</script>';
// Only inject into a real HTML document (one with a </body>). The productUi mislabels some JSON
// endpoints (/segment/*, /changelog/*) as text/html; appending the tag to those corrupts the
// body the SPA later parses with Response.json() — so never append when there's no </body>.
function augmentHtml(html) {
  if (!html.includes("</body>")) return html;
  const withFlags = html.includes("<head>") ? html.replace("<head>", `<head>${FEATURE_FLAG_TAG}`) : FEATURE_FLAG_TAG + html;
  // Idempotent: the OWNED shell tree carries the augmentation tag in its own index.html (the
  // first in-tree ownership fold) — don't double-inject when the document already loads it.
  if (withFlags.includes('src="/ioi-augmentation.js"')) return withFlags;
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
const CX_ESC = escHtml; // canonical escaper lives in surfaces/kit.mjs — one definition estate-wide
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
  .cnwrap{display:grid;grid-template-columns:1fr 380px;gap:18px;align-items:start}
  .cncard{cursor:pointer}
  .cncard:hover{border-color:#3a82f6}
  .cncard.sel{border-color:#3a82f6;box-shadow:0 0 0 1px #3a82f6 inset}
  .cndrawer{position:sticky;top:16px;border:1px solid #24262d;border-radius:12px;background:#15171c;padding:14px 16px;max-height:82vh;overflow:auto;font-size:12.5px}
  .cndrawer h3{margin:0 0 8px;font-size:14px}
  .cndrawer h4{margin:14px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#878a93}
  .cngrid{display:grid;grid-template-columns:110px 1fr;gap:5px 12px}
  .cnk{color:#878a93}
  .cnv{color:#e6e7ea;word-break:break-word}
  .cndrawer table{width:100%;border-collapse:collapse;font-size:12px}
  .cndrawer th{text-align:left;color:#878a93;font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.04em;padding:4px 6px;border-bottom:1px solid #24262d}
  .cndrawer td{padding:5px 6px;border-bottom:1px solid #1b1d23;word-break:break-all}
  @media(max-width:1100px){.cnwrap{grid-template-columns:1fr}.cndrawer{position:static}}
</style></head><body><div class="wrap"><div class="brand">IOI Hypervisor</div><h1>Connections</h1>
<p class="sub">Every external capability binding the workspace can use. Agents receive only scoped, policy-gated capability leases — the underlying credentials are sealed in the daemon and never reach a session.</p>
${inner}</div></body></html>`;
}
function renderConnectionsCockpit(connectors, scmConnectors, leases, devFacts) {
  const leasesFor = (id) => (leases || []).filter((l) => String(l.backing_provider || "").includes(id) || String(l.resource_refs || "").includes(id));
  const groups = {};
  const push = (cat, html) => { (groups[cat] = groups[cat] || []).push(html); };
  // Registry embedded for the detail drawer (source shape: connector/tool registry WITH per-connector
  // drilldown — tool/scope contracts, auth posture, and the actual leases issued against it).
  // SANITIZED: only named fields are serialized — sealed credentials/auth_profile secrets never leave
  // the daemon-side render.
  const reg = [];
  const leaseSlim = (l) => ({
    lease_id: l.lease_id, issued_at: l.issued_at, expires_at: l.expires_at,
    allowed_tools: l.allowed_tools || [], receipt_required: l.receipt_required === true,
    revocation_ref: l.revocation_ref || "", grant_ref: l.grant_ref || "",
    credential_source: l.credential_source || "", authority_provider_ref: l.authority_provider_ref || "",
  });
  for (const c of connectors || []) {
    const bound = c.auth_posture === "token-lease:bound" || c.auth_posture === "open";
    const risk = (c.org_policy && c.org_policy.risk_posture) || "standard";
    const tools = c.kind === "mcp" ? "tools discovered on connect" : ((c.allowed_tools || []).map((t) => t.name).join(", ") || "—");
    const myLeases = leasesFor(c.connector_id);
    // Connect target: Slack w/o a client → its setup; OAuth-profile → launcher; else manage.
    const slackNoClient = c.service === "slack" && !(c.auth_profile && c.auth_profile.client_id);
    const connectHref = slackNoClient ? "/__ioi/slack/setup" : `/__ioi/integrations/connect/${encodeURIComponent(c.connector_id)}`;
    const action = bound
      ? `<span class="pill ok">connected</span>`
      : `<a class="act" href="${connectHref}" target="_blank" rel="noopener" onclick="event.stopPropagation()">Connect ↗</a>`;
    const i = reg.length;
    reg.push({
      t: "connector", connector_id: c.connector_id, name: c.name || c.service, service: c.service || "",
      kind: c.kind || "", base_url: c.base_url || "", auth: authDescriptor(c), auth_posture: c.auth_posture || "",
      bound, risk, requires_credential: c.requires_credential !== false,
      scopes: (c.auth_profile && c.auth_profile.scopes) || [],
      allowed_tools: (c.allowed_tools || []).map((t) => ({ name: t.name, method: t.method || "", path: t.path || "" })),
      org_allowed_tools: (c.org_policy && c.org_policy.allowed_tools) || null,
      connect_href: bound ? "" : connectHref,
      leases: myLeases.map(leaseSlim),
    });
    push(connectionCategory(c), `<div class="card cncard" data-cn="${i}"><div class="main">
      <div class="name">${CX_ESC(c.name || c.service)}${bound ? "" : '<span class="pill warn">needs auth</span>'}<span class="pill risk">risk: ${CX_ESC(risk)}</span></div>
      <div class="meta">${CX_ESC(authDescriptor(c))} · <code>${CX_ESC(c.base_url || "")}</code> · tools: ${CX_ESC(tools)}${myLeases.length ? ` · ${myLeases.length} lease${myLeases.length > 1 ? "s" : ""} issued` : ""}</div>
      </div>${action}</div>`);
  }
  for (const c of scmConnectors || []) {
    const bound = c.auth_posture === "token-lease:bound";
    const i = reg.length;
    reg.push({
      t: "scm", connector_id: c.connector_id || c.kind, name: c.name || c.kind, service: c.kind || "",
      kind: c.kind || "", base_url: c.host || c.remote_url || "", auth: "sealed host token (git-auth)",
      auth_posture: c.auth_posture || "", bound, risk: "standard", requires_credential: true,
      scopes: [], allowed_tools: [], org_allowed_tools: null,
      connected_login: c.connected_login || "", connect_href: bound ? "" : "/settings/runners?user-settings=git-authentications",
      leases: leasesFor(c.connector_id || "").map(leaseSlim),
    });
    push("Code / SCM", `<div class="card cncard" data-cn="${i}"><div class="main">
      <div class="name">${CX_ESC(c.name || c.kind)}${bound ? "" : '<span class="pill warn">needs auth</span>'}</div>
      <div class="meta">${CX_ESC(c.kind)} · <code>${CX_ESC(c.host || c.remote_url || "")}</code>${c.connected_login ? ` · @${CX_ESC(c.connected_login)}` : ""}</div>
      </div>${bound ? '<span class="pill ok">connected</span>' : '<a class="act ghost" href="/settings/runners?user-settings=git-authentications" target="_blank" onclick="event.stopPropagation()">Git authentications ↗</a>'}</div>`);
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
  const drawer = `<div class="cndrawer" id="cn-drawer"><div class="empty" style="padding:12px">Select a connection to inspect its tool contracts, auth posture, and the capability leases issued against it.</div></div>`;
  const script = `<script>
    var CN_REG=${JSON.stringify(reg)};
    function cnEsc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
    function cnRow(k,v){return v?'<div class="cnk">'+cnEsc(k)+'</div><div class="cnv">'+v+'</div>':'';}
    function cnWhen(v){if(!v)return '';if(typeof v==='number'){try{return new Date(v).toISOString();}catch(e){return String(v);}}return String(v);}
    document.querySelectorAll('.cncard').forEach(function(card){card.addEventListener('click',function(){
      var c=CN_REG[parseInt(card.getAttribute('data-cn'),10)];if(!c)return;
      document.querySelectorAll('.cncard').forEach(function(x){x.classList.toggle('sel',x===card);});
      var d=document.getElementById('cn-drawer');
      var h='<h3>'+cnEsc(c.name)+' <span class="pill '+(c.bound?'ok':'warn')+'">'+(c.bound?'connected':'needs auth')+'</span></h3>';
      h+='<h4>Binding</h4><div class="cngrid">'+cnRow('Connector','<code>'+cnEsc(c.connector_id)+'</code>')+cnRow('Kind',cnEsc(c.kind)+(c.service&&c.service!==c.kind?' · '+cnEsc(c.service):''))+cnRow('Endpoint','<code>'+cnEsc(c.base_url)+'</code>')+cnRow('Auth',cnEsc(c.auth))+cnRow('Posture','<code>'+cnEsc(c.auth_posture)+'</code>')+cnRow('Risk',cnEsc(c.risk))+(c.connected_login?cnRow('Identity','@'+cnEsc(c.connected_login)):'')+(c.scopes.length?cnRow('Scopes',cnEsc(c.scopes.join(', '))):'')+'</div>';
      h+='<div class="cnv" style="margin-top:8px;color:#6f7280;font-size:11.5px">Credential sealed in the daemon — never serialized to this page or any session.</div>';
      h+='<h4>Tool contracts ('+c.allowed_tools.length+')</h4>';
      if(c.allowed_tools.length){h+='<table><thead><tr><th>Tool</th><th>Method</th><th>Path</th></tr></thead><tbody>'+c.allowed_tools.map(function(t){return '<tr><td><code>'+cnEsc(t.name)+'</code></td><td>'+cnEsc(t.method)+'</td><td>'+cnEsc(t.path)+'</td></tr>';}).join('')+'</tbody></table><div style="color:#6f7280;font-size:11px;margin-top:4px">Only these declared tools are invokable through the lease gateway'+(c.org_allowed_tools?' (org policy further restricts to: '+cnEsc(c.org_allowed_tools.join(', '))+')':'')+'.</div>';}
      else{h+='<div style="color:#6f7280">'+(c.kind==='mcp'?'Tools are discovered from the MCP server on connect.':(c.t==='scm'?'SCM lanes (publish / PR / revoke) are wallet-authorized crossings, not free-form tools.':'No tools declared — nothing is invokable.'))+'</div>';}
      h+='<h4>Capability leases issued ('+c.leases.length+')</h4>';
      if(c.leases.length){h+=c.leases.slice(0,8).map(function(l){return '<div style="border:1px solid #1b1d23;border-radius:8px;padding:8px;margin:0 0 6px"><div><code>'+cnEsc(l.lease_id)+'</code>'+(l.receipt_required?' <span class="pill ok">receipted</span>':'')+'</div><div class="cngrid" style="margin-top:4px">'+cnRow('Tools',cnEsc((l.allowed_tools||[]).join(', ')))+cnRow('Issued',cnEsc(cnWhen(l.issued_at)))+cnRow('Expires',cnEsc(cnWhen(l.expires_at)))+cnRow('Authority',cnEsc(l.authority_provider_ref))+cnRow('Revocation','<code>'+cnEsc(l.revocation_ref)+'</code>')+'</div></div>';}).join('')+(c.leases.length>8?'<div style="color:#6f7280;font-size:11px">… '+(c.leases.length-8)+' more</div>':'');}
      else{h+='<div style="color:#6f7280">No leases issued against this binding yet.</div>';}
      if(c.connect_href){h+='<h4>Actions</h4><a class="act" href="'+cnEsc(c.connect_href)+'" target="_blank" rel="noopener">Connect ↗</a>';}
      d.innerHTML=h;
    });});
  </script>`;
  // ---- Authority Clients roster (57-oauth2-clients graft, renamed per the naming ledger) — the
  // consumers of scoped authority, grouped by what the lease records actually carry: credential
  // source × authority provider. Per class: lease volume, active-vs-expired, receipt obligation,
  // revocability, tool surface. The records carry NO client-origin/principal binding — said
  // plainly rather than invented; per-lease detail (grant/revocation refs) lives in each
  // connector's drawer below.
  const acNow = Date.now();
  const acGroups = {};
  (leases || []).forEach((l) => {
    const key = `${l.credential_source || "unrecorded source"} · ${l.authority_provider_ref || "—"}`;
    const g = acGroups[key] = acGroups[key] || { n: 0, active: 0, receipted: 0, revocable: 0, tools: new Set() };
    g.n++;
    if (!l.expires_at || Number(l.expires_at) > acNow) g.active++;
    if (l.receipt_required) g.receipted++;
    if (l.revocation_ref) g.revocable++;
    (l.allowed_tools || []).forEach((t) => g.tools.add(t));
  });
  const acCard = ([key, g]) => `<div class="card" style="display:block">
    <div class="row" style="justify-content:space-between;margin:0 0 6px"><b>${CX_ESC(key)}</b><span>
      <span class="pill ${g.active ? "ok" : "muted"}">${g.active} active</span> <span class="pill muted">${g.n - g.active} expired</span>
      ${g.receipted ? `<span class="pill ok">${g.receipted} receipted</span>` : ""} ${g.revocable === g.n ? `<span class="pill ok">all revocable</span>` : `<span class="pill warn">${g.n - g.revocable} without revocation ref</span>`}
    </span></div>
    <div class="sub" style="margin:0;text-transform:none;letter-spacing:0">tools: ${[...g.tools].slice(0, 6).map((t) => `<code>${CX_ESC(t)}</code>`).join(" ") || "none declared"}${g.tools.size > 6 ? ` · +${g.tools.size - 6} more` : ""}</div>
  </div>`;
  const authClients = `<div id="conn-authority-clients"><h2>Authority Clients <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— who holds scoped authority right now, from the lease records themselves; origin binding is not recorded on leases (grouped by credential source · authority provider)</span></h2>
    ${Object.keys(acGroups).length ? Object.entries(acGroups).sort((a, b) => b[1].n - a[1].n).map(acCard).join("") : `<div class="empty">No capability leases issued yet — every authority crossing mints one, and it appears here.</div>`}</div>`;
  // ---- Developer Console (27-developer-console graft; 25-developer-tools folds here) — the
  // external-integration surface as PROBED facts, not promises: the API spine behind the serve
  // /v1 proxy, the MCP gateway's declared tool contracts, and the identity/SCIM endpoints with
  // their live posture. Every pill reflects a probe made at render time.
  const df = devFacts || {};
  const mcpToolList = ((df.mcpTools || {}).tools || []);
  const authPosture = (df.authPol || {}).deployment_auth_posture || "local_development";
  const scimPill = df.scimStatus === 401 ? `<span class="pill ok">reachable · auth required</span>` : df.scimStatus === 200 ? `<span class="pill ok">reachable</span>` : `<span class="pill warn">unreachable (${CX_ESC(String(df.scimStatus || "no answer"))})</span>`;
  const devConsole = `<div id="conn-developer-console"><h2>Developer Console <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— integrate against the estate: API spine, MCP gateway contracts, identity endpoints; every posture pill is a live probe</span></h2>
    <div class="card" style="display:block"><b>API spine</b> <span class="pill ok">proxied at <code>/v1/*</code></span> <span class="pill ${authPosture === "local_development" ? "muted" : authPosture === "authenticated_managed" ? "ok" : "warn"}">${CX_ESC(authPosture)}</span>
      <div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">Same-origin <code>/v1/hypervisor/*</code> resolves through this serve to the daemon; auth posture governs enforcement (<a href="/__ioi/governance">Governance →</a>).</div></div>
    <div class="card" style="display:block"><b>MCP gateway</b> ${df.mcpTools ? `<span class="pill ok">${mcpToolList.length} declared tool contract${mcpToolList.length === 1 ? "" : "s"}</span>` : `<span class="pill warn">did not answer</span>`}
      <div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">${mcpToolList.length ? mcpToolList.slice(0, 8).map((t) => `<code>${CX_ESC(t.name || "")}</code>`).join(" ") + (mcpToolList.length > 8 ? ` · +${mcpToolList.length - 8} more` : "") : "No declared tools."} · endpoint <code>/v1/hypervisor/mcp-gateway/tools</code> — only declared contracts are invokable, through the lease gateway.</div></div>
    <div class="card" style="display:block"><b>Identity &amp; provisioning</b> ${scimPill}
      <div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">SCIM base <code>/scim/v2</code> · OIDC login <code>/v1/hypervisor/auth/oidc/start</code> · session introspection <code>/v1/hypervisor/auth/whoami</code>. Identity authenticates people; it never becomes machine authority.</div></div>
  </div>`;
  // ---- Tool Analytics facet (native primitive, first slice — folds here, no new card). Tool
  // VOLUME from the lease records (how often each tool was actually leased) against the DECLARED
  // surface (connector + MCP gateway contracts); declared-but-never-leased is the real
  // missing-capability list. Latency/error per tool call is not recorded — named, not charted.
  const taLeased = {};
  (leases || []).forEach((l) => (l.allowed_tools || []).forEach((t) => { taLeased[t] = (taLeased[t] || 0) + 1; }));
  const taDeclared = new Set();
  (connectors || []).forEach((c) => (c.allowed_tools || []).forEach((t) => taDeclared.add(typeof t === "string" ? t : (t.name || ""))));
  ((devFacts || {}).mcpTools ? (devFacts.mcpTools.tools || []) : []).forEach((t) => taDeclared.add(t.name || ""));
  taDeclared.delete("");
  const taNever = [...taDeclared].filter((t) => !taLeased[t]).sort();
  const taTop = Object.entries(taLeased).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const toolAnalytics = `<div id="conn-tool-analytics"><h2>Tool Analytics <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— lease volume per tool vs the declared surface; per-call latency/error is not recorded yet (named gap)</span></h2>
    <div class="card" style="display:block"><b>Leased tool volume</b>
      <div class="chips" style="margin:6px 0 0">${taTop.length ? taTop.map(([t, n]) => `<span class="pill ok">${CX_ESC(t)} ×${n}</span>`).join("") : `<span class="sub" style="margin:0">no tool leases yet</span>`}</div></div>
    <div class="card" style="display:block"><b>Declared but never leased</b> ${taNever.length ? `<span class="pill warn">${taNever.length} unused capabilit${taNever.length === 1 ? "y" : "ies"}</span>` : `<span class="pill ok">none — every declared tool has been leased</span>`}
      <div class="chips" style="margin:6px 0 0">${taNever.slice(0, 12).map((t) => `<span class="pill muted">${CX_ESC(t)}</span>`).join("")}${taNever.length > 12 ? `<span class="sub" style="margin:0">+${taNever.length - 12} more</span>` : ""}</div></div>
  </div>`;
  return connectionsShell(add + authClients + devConsole + toolAnalytics + `<div class="cnwrap"><div>` + body + `</div>` + drawer + `</div>` + script);
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
  .chips{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 16px}
  .chiplabel{font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#6f7280;margin:0 4px 0 8px}
  .chip{background:#15171c;border:1px solid #2a2c33;color:#cbd0da;border-radius:999px;padding:4px 11px;font:inherit;font-size:12px;cursor:pointer}
  .chip:hover{border-color:#3a82f6}
  .chip.on{background:#15315c;border-color:#3a82f6;color:#fff}
  .wlwrap{display:grid;grid-template-columns:1fr 340px;gap:18px;align-items:start}
  .wlrow{cursor:pointer}
  .wlrow:hover td{background:#15171c}
  .wlrow.selrow td{background:#191b21}
  .wldrawer{padding:14px 16px;border:1px solid #24262d;border-radius:12px;background:#15171c;position:sticky;top:16px;max-height:80vh;overflow:auto}
  .wldrawer h3{margin:0 0 10px;font-size:14px}
  .wldrawer h4{margin:14px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#878a93}
  .wlgrid{display:grid;grid-template-columns:96px 1fr;gap:5px 12px;font-size:12.5px}
  .wlk{color:#878a93}
  .wlv{color:#e6e7ea;word-break:break-word}
  .wldrawer ul{margin:4px 0 0;padding-left:18px}
  .wlbl{list-style:none;padding-left:0;margin:4px 0 0}
  .wlbl li{padding:3px 0;border-bottom:1px solid #16181d;font-size:12px}
  .wlbl a{color:#7fb0ff;text-decoration:none;word-break:break-all}
  .wlbl a:hover{text-decoration:underline}
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
  // Owner-surface contract: Automations owns DURABLE ORCHESTRATION — the daemon automation records
  // below are the truth (real specs, triggers, steps, projects), authoritative and countable. The
  // captured object-monitoring wizard is a SECONDARY reference grammar (a linked walkthrough for the
  // condition→effect authoring UX), explicitly NOT daemon truth — no captured row is presented here.
  const head = `<h1 id="automations-owner">Automations</h1>
    <p class="sub">Durable orchestration — each automation is a daemon-owned spec that hangs off a project, runs over a real environment, and records a tamper-evident transcript. The <b>${automations.length}</b> record${automations.length === 1 ? "" : "s"} below ${projectId ? `(filtered to <b>${CX_ESC(filtName)}</b> · <a href="/__ioi/automations">show all</a>)` : "across all projects"} are daemon truth. <span class="sub">The <a href="/__ioi/automations/monitors">Automate overview →</a> is the certified reference-faithful landing over this same plane (#51). The <a href="/__apps/monitors">monitor-wizard capture ↗</a> is a secondary reference grammar for authoring condition→effect monitors — a linked walkthrough, not a rebound surface; its example rows are never shown here as daemon automations.</span></p>
    <div class="row"><a class="act" href="${newHref}">+ New automation</a><a class="act ghost" href="/__apps/monitors">Monitor-wizard capture (reference) →</a></div>`;
  if (!automations.length) {
    return automationsShell("Automations", head + `<div class="empty">No daemon automations yet${projectId ? " for this project" : ""} — create one to get started. (The monitor-wizard capture stays a reference; it never fabricates automations here.)</div>`);
  }
  const cards = automations.map((a) => {
    const enabled = a.enabled !== false;
    const steps = Array.isArray(a.steps) ? a.steps.length : 0;
    const model = a.model || "default model";
    const trigger = (a.trigger && (a.trigger.kind || a.trigger.trigger_kind)) || a.trigger_kind || "manual";
    return `<a class="card automation-card" href="/__ioi/automations/${encodeURIComponent(a.automation_id)}"><div class="main">
      <div class="name">${CX_ESC(a.name || a.automation_id)}<span class="pill ${enabled ? "ok" : "muted"}">${enabled ? "enabled" : "disabled"}</span><span class="pill muted">${CX_ESC(trigger)}</span></div>
      <div class="meta">${CX_ESC(automationProjectName(a, projectsById))} · ${CX_ESC(String(model))} · ${steps} step${steps === 1 ? "" : "s"} · <code style="font-size:10.5px">${CX_ESC(a.automation_id)}</code></div>
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
  // ---- Pipeline view (09-pipeline-builder grammar donation, read-only first slice). The
  // automation AS a pipeline: trigger → declared steps → latest run outcome → proof. Rendered
  // from the spec and run records only — the authoring canvas is a later cut; nothing here is a
  // runnable graph editor, and it says so.
  const latest = (runs || [])[0];
  const pnodes = [
    [`trigger · ${a.trigger_kind || "manual"}`, "muted"],
    ...(Array.isArray(a.steps) ? a.steps.map((s, i) => [`${i + 1} · ${s.kind || "step"}`, "ok"]) : []),
    latest ? [`last run · ${latest.status || "—"}`, latest.status === "done" ? "ok" : latest.status === "failed" ? "warn" : "muted"] : ["no runs yet", "muted"],
  ];
  const pipeline = `<div id="auto-pipeline" style="margin:0 0 16px"><div class="sub" style="margin:0 0 6px;text-transform:uppercase;letter-spacing:.04em;font-size:11px">Pipeline <span style="text-transform:none;letter-spacing:0">— read-only view of the declared spec; the authoring canvas is a later cut</span></div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">${pnodes.map(([label, cls], i) => `${i ? `<span style="color:#5f626b">→</span>` : ""}<span class="pill ${cls}" style="padding:5px 12px">${CX_ESC(label)}</span>`).join("")}${latest ? ` <a href="/__ioi/run-timeline/${encodeURIComponent(latest.execution_id || "")}" target="_blank" rel="noopener" style="margin-left:6px">proof ↗</a>` : ""}</div></div>`;
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
    <p class="sub">${CX_ESC(a.description || "")}</p>${pipeline}${actions}
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
// ---- Home full readout (03-home graft). THE Home is the SPA composer home; its injected
// governed-work band (ioi-augmentation.js mountHomeBand) summarizes this page and deep-links here.
// Four strips over live daemon truth — what needs a DECISION (pending approval requests), what is
// BLOCKED (failover runs parked at a wallet gate, failed runs), what to RESUME (sessions with their
// admitted bindings, running work) — plus the newest proof. Read-only: every affordance is a link
// into the surface that owns the action; app breadth stays in Applications. A projection the daemon
// did not answer says so; nothing is fabricated to fill a strip.
function renderHome(ops, ledger, sessions, approvals, failoverRuns) {
  const enc = encodeURIComponent;
  const unavailable = `<div class="empty">Projection unavailable — the daemon did not answer. Nothing is shown rather than fixtures.</div>`;
  const strip = (id, title, note, v, emptyMsg, body) =>
    `<div id="${id}"><h2>${title} <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— ${note}</span></h2>${v === null ? unavailable : body || `<div class="empty">${emptyMsg}</div>`}</div>`;

  // Decisions — the wallet/approval gate queue; every governed run (incl. a triggered failover) parks here.
  const pend = approvals === null ? null : (approvals.approval_requests || []).filter((a) => a.status === "pending");
  const decisionsBody = pend && pend.length ? `<table><thead><tr><th>Request</th><th>Target</th><th>Status</th><th>Act</th></tr></thead><tbody>${pend.slice(0, 8).map((a) => `<tr>
      <td><b>${CX_ESC(a.request_kind || "approval")}</b><div style="color:#878a93;font-size:11px;margin-top:1px"><code>${CX_ESC(a.approval_request_id || a.id || "")}</code></div></td>
      <td><code style="font-size:10.5px">${CX_ESC(a.subject_ref || "—")}</code></td>
      <td><span class="pill warn">pending</span></td>
      <td><a href="/__ioi/governance?tab=approvals">review →</a></td>
    </tr>`).join("")}</tbody></table>` : "";

  // Blocked — failover runs sitting at an authority gate (status awaiting_authority_<gate>) + failed runs.
  const foAll = failoverRuns === null ? null : (failoverRuns.runs || []);
  const parked = foAll === null ? [] : foAll.filter((r) => String(r.status || "").startsWith("awaiting_authority"));
  const fails = ops === null ? [] : ((ops.runs || {}).failures || []);
  const blockedRows = [
    ...parked.slice(0, 6).map((r) => `<tr>
      <td>⛔ failover <code style="font-size:10.5px">${CX_ESC(r.run_ref || "")}</code><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(r.environment_ref || "")}</div></td>
      <td><span class="pill warn">wallet gate: ${CX_ESC(String(r.status || "").replace("awaiting_authority_", ""))}</span></td>
      <td>${CX_ESC(r.failure_condition || "—")}</td>
      <td><a href="/__ioi/operations#ops-failover">inspect →</a></td>
    </tr>`),
    ...fails.slice(0, 6).map((r) => `<tr>
      <td>✖ run <b>${CX_ESC(r.name || r.automation_id || "")}</b><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(r.project_id || "—")} · ${CX_ESC(r.finished_at || "")}</div></td>
      <td><span class="pill warn">failed</span></td>
      <td>${r.timeline_ref ? `<a href="${r.timeline_ref}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td>
      <td><a href="/__ioi/operations">remediate →</a></td>
    </tr>`),
  ].join("");
  const blockedUnavail = failoverRuns === null && ops === null;
  const blockedBody = blockedRows ? `<table><thead><tr><th>What</th><th>State</th><th>Evidence</th><th>Act</th></tr></thead><tbody>${blockedRows}</tbody></table>` : "";

  // Resume — most recent sessions (their admitted harness binding is session truth) + still-running work.
  const sessList = sessions === null ? null : ((sessions.sessions || []).slice().sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))));
  const running = ops === null ? [] : ((ops.runs || {}).recent || []).filter((r) => r.status === "running");
  const sessRow = (s) => {
    const envId = String(s.environment_ref || "").replace(/^environment:/, "");
    const hb = s.harness_binding;
    return `<tr>
      <td><code>${CX_ESC(s.session_ref || "")}</code><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(s.project_ref || "—")} · ${CX_ESC(s.created_at || "")}</div></td>
      <td><span class="pill muted">${CX_ESC(s.lifecycle_state || "—")}</span></td>
      <td>${hb && hb.profile_ref ? `<span class="pill ok">${CX_ESC(hb.harness || "harness")}</span>` : `<span class="pill muted" title="no harness binding recorded at create">execute-time default</span>`}</td>
      <td>${envId ? `<a href="/workspaces/${enc(envId)}" target="_top">workbench</a> · <a href="/__ioi/run-timeline/env/${enc(envId)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td>
    </tr>`;
  };
  const runRow = (r) => `<tr>
      <td>▶ <b>${CX_ESC(r.name || r.automation_id || "")}</b><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(r.project_id || "—")} · started ${CX_ESC(r.started_at || "")}</div></td>
      <td><span class="pill ok">running</span></td>
      <td>—</td>
      <td>${r.timeline_ref ? `<a href="${r.timeline_ref}" target="_blank" rel="noopener">timeline ↗</a>` : "—"} · <a href="/__ioi/operations">operations →</a></td>
    </tr>`;
  const resumeRows = [...running.slice(0, 4).map(runRow), ...(sessList || []).slice(0, 6).map(sessRow)].join("");
  const resumeBody = resumeRows ? `<table><thead><tr><th>Work</th><th>State</th><th>Binding</th><th>Open</th></tr></thead><tbody>${resumeRows}</tbody></table>` : "";

  // Proof — the newest ledger entries, verbatim from the proof stream (newest-first from the daemon).
  const led = ledger === null ? null : (ledger.entries || []);
  const proofBody = led && led.length ? `<table><thead><tr><th>Kind</th><th>Status</th><th>When</th><th>Proof</th></tr></thead><tbody>${led.slice(0, 6).map((e) => `<tr>
      <td>${CX_ESC(e.kind || "")}<div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(e.automation_name || e.subject_ref || e.session_ref || "")}</div></td>
      <td><span class="pill ${(e.status === "done" || e.status === "success" || e.status === "accepted" || e.status === "ok" || e.status === "published") ? "ok" : (e.status === "failed" || e.status === "failure" || e.status === "rejected" || String(e.status || "").includes("missing") || String(e.status || "").includes("mismatch")) ? "warn" : "muted"}">${CX_ESC(e.status || "—")}</span></td>
      <td>${CX_ESC(e.timestamp || "")}</td>
      <td><code>${CX_ESC((e.state_root || "").slice(0, 20) || "—")}</code></td>
    </tr>`).join("")}</tbody></table><p class="sub" style="margin:8px 0 0"><a href="/__ioi/work-ledger">Open Provenance →</a></p>` : "";

  const allDown = ops === null && ledger === null && sessions === null && approvals === null && failoverRuns === null;
  const degraded = allDown ? `<div class="empty" id="home-degraded" style="border-color:#5c4a23;color:#d6a13a">Daemon unreachable — Home shows nothing rather than fixtures. Start the hypervisor daemon and reload.</div>` : "";
  const counts = allDown ? "" : `<div class="chips" style="margin:0 0 18px">
    <span class="chip${pend && pend.length ? " on" : ""}">decisions ${pend === null ? "?" : pend.length}</span>
    <span class="chip${(parked.length + fails.length) ? " on" : ""}">blocked ${blockedUnavail ? "?" : parked.length + fails.length}</span>
    <span class="chip">sessions ${sessList === null ? "?" : sessList.length}</span>
    <span class="chip">proof ${led === null ? "?" : led.length}</span>
  </div>`;
  const inner = `<h1>Governed work — full readout</h1><p class="sub">The expanded view behind Home's governed-work band: what needs a decision, what is blocked, what to resume, and the newest proof — live daemon truth only. The full estate lives in <a href="/__ioi/applications">Applications</a>; new work starts from Home's composer.</p>
    ${degraded}${counts}
    ${strip("home-decisions", "Needs your decision", "governed work parks at the approval gate; approving is an act in Governance, never here", approvals, "Nothing is waiting on you — no pending approval requests.", decisionsBody)}
    ${strip("home-blocked", "Blocked", "runs parked at a wallet gate or failed — each links to the owning surface", blockedUnavail ? null : { any: blockedRows }, "No runs are parked or failing.", blockedBody)}
    ${strip("home-resume", "Resume", "recent sessions and still-running work", sessions, "No sessions yet — open the rail's New Session launcher to start governed work.", resumeBody)}
    ${strip("home-proof", "Newest proof", "the most recent Provenance entries, verbatim", ledger, "No admitted work yet — the proof stream is empty.", proofBody)}`;
  return automationsShell("Governed Work Readout", inner);
}

// ---- Feedback & Annotations (native primitive, first slice over the NEW daemon plane).
// The queue over durable FeedbackEntry records: status chips, consent pills from the
// evidence-eligibility ladder, and the conversion lane that the daemon gates — a never_train
// entry can NEVER convert, and the fail-closed error is surfaced verbatim, not softened.
function renderFeedbackQueue(ov, entries, flash) {
  const enc = encodeURIComponent;
  const byStatus = (ov || {}).by_status || {};
  const ladder = (ov || {}).consent_ladder || ["never_train", "synthetic_only", "redacted_opt_in", "full_private_opt_in", "org_policy"];
  const chips = `<div class="chips" id="fb-chips"><button class="chip on" data-fb="" onclick="fbChip(this)">All ${entries.length}</button>${["open", "triaged", "converted", "dismissed"].map((s) => `<button class="chip" data-fb="${s}" onclick="fbChip(this)">${s} ${byStatus[s] || 0}</button>`).join("")}</div>`;
  const consentPill = (c) => `<span class="pill ${c === "never_train" ? "warn" : "ok"}" title="evidence eligibility — classify BEFORE any train/eval use">${CX_ESC(c || "never_train")}</span>`;
  const row = (e) => {
    const acts = e.status === "open" || e.status === "triaged"
      ? `${e.status === "open" ? `<form class="inline" method="post" action="/__ioi/feedback/${enc(e.id)}/transition"><input type="hidden" name="transition" value="triage"><button class="act ghost" type="submit">Triage</button></form> ` : ""}
         <form class="inline" method="post" action="/__ioi/feedback/${enc(e.id)}/transition"><input type="hidden" name="transition" value="convert"><input name="converted_to_ref" placeholder="eval://… · training-candidate://…" style="width:170px;padding:5px 8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit;font-size:11px;margin-right:4px"><button class="act" type="submit">Convert</button></form>
         <form class="inline" method="post" action="/__ioi/feedback/${enc(e.id)}/transition"><input type="hidden" name="transition" value="dismiss"><button class="act ghost" type="submit">Dismiss</button></form>`
      : e.status === "converted" ? `<span class="sub" style="margin:0">→ <code style="font-size:10px">${CX_ESC(e.converted_to_ref || "")}</code></span>` : `<span class="sub" style="margin:0">terminal</span>`;
    return `<tr data-fb="${CX_ESC(e.status || "")}">
      <td><b>${CX_ESC(e.entry_kind || "feedback")}</b><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(String(e.body || "").slice(0, 80))}</div></td>
      <td><code style="font-size:10px">${CX_ESC(e.subject_ref || "")}</code></td>
      <td>${consentPill(e.consent)}</td>
      <td><span class="pill ${e.status === "converted" ? "ok" : e.status === "open" ? "warn" : "muted"}">${CX_ESC(e.status || "")}</span></td>
      <td>${CX_ESC(e.created_at || "")}</td>
      <td onclick="event.stopPropagation()">${acts}</td>
    </tr>`;
  };
  const form = `<h2>New entry</h2><form method="post" action="/__ioi/feedback"><div class="card" style="display:block">
    <div class="two"><div class="field"><label>Subject ref (required — run/session/app/object; local refs must resolve)</label><input name="subject_ref" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" placeholder="domain-app://… · session:… · authority-action://…"></div>
    <div class="field"><label>Kind</label><select name="entry_kind" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit"><option value="feedback">feedback</option><option value="annotation">annotation</option></select></div></div>
    <div class="field"><label>Body</label><textarea name="body" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" placeholder="What happened / what should be learned."></textarea></div>
    <div class="field"><label>Consent (evidence eligibility — never_train fails conversion closed, by design)</label><select name="consent" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit">${ladder.map((c) => `<option value="${c}">${c}</option>`).join("")}</select></div>
    <div class="row" style="margin-top:6px"><button class="act" type="submit">Record entry</button></div></div></form>`;
  const flashHtml = flash ? `<div class="card" style="display:block;border-color:#5c4a23"><b style="color:#d6a13a">Refused:</b> <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">${CX_ESC(flash)}</span></div>` : "";
  const inner = `<h1>Evaluations</h1><p class="sub">Feedback &amp; annotations — the live slice of Evaluations. Durable operator feedback over real subjects, each carrying its evidence-eligibility consent from the moment it is recorded. Converting an entry into an eval/training candidate is a NAMED handoff the daemon gates on consent — nothing trains here. <a href="/__ioi/work-ledger">Proof stream →</a> · <a href="/__apps/evalsuites">Eval-suite library seed (adopting) →</a> · <a href="/__apps/analysis">Analysis seed (adopting) →</a></p>
    ${flashHtml}${form}
    <h2>Queue (${entries.length})</h2>
    ${entries.length ? `${chips}<table><thead><tr><th>Entry</th><th>Subject</th><th>Consent</th><th>Status</th><th>Created</th><th>Act</th></tr></thead><tbody id="fb-body">${entries.map(row).join("")}</tbody></table><div class="empty" id="fb-empty" style="display:none">No entries in this state.</div>
    <script>function fbChip(b){document.querySelectorAll('#fb-chips .chip').forEach(function(x){x.classList.toggle('on',x===b);});var w=b.getAttribute('data-fb');var n=0;document.querySelectorAll('#fb-body tr').forEach(function(r){var on=!w||r.getAttribute('data-fb')===w;r.style.display=on?'':'none';if(on)n++;});document.getElementById('fb-empty').style.display=n?'none':'';}</script>`
    : `<div class="empty">No feedback yet — record what governed work got right or wrong, with its consent posture, and it becomes safely convertible evidence.</div>`}`;
  return automationsShell("Evaluations", inner);
}

// ============================ EVALUATIONS (owner surface — eval-suite library, declaration-only)
// The Reference UX Port program (post-#31 reset), substrate for the Evaluations owner-family. The reference
// capture (/__apps/evalsuites, /workspace/evals/) is the familiar eval-suite library baseline; this
// IOI-owned owner surface renders the SAME table/list grammar over REAL daemon truth: the inert
// eval-suite contract (a suite DECLARES what it would assess + under what admissibility — never how
// it scores), the real assessment SUBJECTS available (mission runs / failed runs / GoalRun blockers,
// from the Missions plane), the consent ladder + feedback candidate source, and Foundry model_eval
// draft specs as adjacent inputs. NOTHING is scored/executed here — EvalRun execution, verdicts,
// judges, scorecards, auto-mining, the analysis/Quiver canvases, and promotion are NAMED GAPS.
// Naming: Evaluations is the owner surface; /__ioi/feedback stays a compatibility sublane.
function renderEvaluations(suites, suiteOv, subjects, foundryEvalSpecs, feedbackOv, flash) {
  const enc = encodeURIComponent;
  const list = Array.isArray(suites) ? suites : [];
  const ov = suiteOv || {};
  const subjectKinds = ov.subject_kinds || ["mission_run", "failed_run", "goal_run", "goal_run_blocker", "feedback_entry", "session", "domain_app", "surface_object"];
  const evidenceKinds = ov.evidence_kinds || ["proof_ref", "timeline_ref", "receipt_ref", "source_hash", "state_root", "transcript_ref"];
  const ladder = ov.consent_ladder || (feedbackOv || {}).consent_ladder || ["never_train", "synthetic_only", "redacted_opt_in", "full_private_opt_in", "org_policy"];
  const byHealth = ov.by_health || {};
  const subj = subjects || {};
  const missionRuns = Array.isArray(subj.missionRuns) ? subj.missionRuns : [];
  const failedRuns = Array.isArray(subj.failedRuns) ? subj.failedRuns : [];
  const blockers = Array.isArray(subj.blockers) ? subj.blockers : [];
  const drafts = Array.isArray(foundryEvalSpecs) ? foundryEvalSpecs : [];
  const sub = (txt) => `<span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">${txt}</span>`;
  const flashHtml = flash ? `<div class="card" style="display:block;border-color:#5c4a23"><b style="color:#d6a13a">Refused:</b> <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">${CX_ESC(flash)}</span></div>` : "";

  const head = `<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap"><div><h1 style="margin:0">Evaluations</h1><p class="sub" style="margin:4px 0 0">The eval-suite library — declared assessment suites over real subjects, evidence, and consent, as a table/list over IOI daemon truth. A suite declares WHAT it would assess and under WHAT admissibility; <b>nothing scores or executes here</b>. The <a href="/__ioi/evaluations/evalsuites">AIP Evals landing →</a> is the certified reference-faithful shell over this same plane (#54). Reference grammar: <a href="/__apps/evalsuites">Eval-suite library ↗</a> (secondary capture).</p></div><div class="row" style="gap:8px"><a class="act ghost" href="/__ioi/feedback">Feedback &amp; annotations</a><a class="act ghost" href="/__ioi/work-ledger">Proof stream</a></div></div>`;

  const banner = `<div class="row" style="gap:10px;align-items:stretch;margin:12px 0 14px;flex-wrap:wrap">${[
    ["Suites", list.length, false], ["Declared", byHealth.declared || list.filter((s) => s.health === "declared").length, false], ["Empty", byHealth.empty || list.filter((s) => s.health === "empty").length, false], ["Subjects in scope", missionRuns.length + failedRuns.length + blockers.length, false],
  ].map(([l, n, warn]) => `<div style="flex:1;min-width:120px;padding:11px 13px;border:1px solid #24262d;border-radius:10px;background:#15171c"><div style="font-size:20px;font-weight:700;color:#fff">${n}</div><div style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(l)}${warn ? ` <span class="pill warn" style="margin:0">attention</span>` : ""}</div></div>`).join("")}</div>`;

  // Declare form — inert: it records a DECLARATION (no run button, no scoring).
  const checks = (name, opts, cls) => opts.map((o) => `<label style="display:inline-flex;align-items:center;gap:4px;margin:0 10px 4px 0;font-size:12px;color:#c7c9d1"><input type="checkbox" name="${name}" value="${o}"> ${CX_ESC(o)}${cls === "consent" && o === "never_train" ? " ⚠" : ""}</label>`).join("");
  const form = `<details style="margin:0 0 16px"><summary style="cursor:pointer;color:#9ea1ab;font-size:13px">Declare an eval suite <span class="sub" style="margin:0">(inert — records what would be assessed; no scoring/execution)</span></summary>
    <form method="post" action="/__ioi/evaluations"><div class="card" style="display:block;margin-top:8px">
    <div class="field"><label>Name (required)</label><input name="name" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" placeholder="e.g. Failed-run triage rubric v1"></div>
    <div class="field"><label>Subject scope (required — the real subject kinds this suite assesses)</label><div>${checks("subject_scope", subjectKinds, "subject")}</div></div>
    <div class="field"><label>Consent requirements (required — admissible evidence-eligibility rungs; never_train alone fails closed)</label><div>${checks("consent_requirements", ladder, "consent")}</div></div>
    <div class="field"><label>Evidence requirements (optional)</label><div>${checks("evidence_requirements", evidenceKinds, "evidence")}</div></div>
    <div class="two"><div class="field"><label>Rubric refs (optional, space-separated)</label><input name="rubric_refs" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" placeholder="rubric://…"></div>
    <div class="field"><label>Candidate refs (optional — named eval/feedback handoffs)</label><input name="candidate_refs" style="width:100%;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" placeholder="eval://… feedback://…"></div></div>
    <div class="row" style="margin-top:6px"><button class="act" type="submit">Declare suite</button></div></div></form></details>`;

  // Library — the bound seed. Real suites over the inert daemon contract; honest empty otherwise.
  const healthPill = (h) => `<span class="pill ${h === "declared" ? "ok" : "muted"}" style="margin:0">${CX_ESC(h || "empty")}</span>`;
  const suiteRow = (s) => `<tr>
    <td><b>${CX_ESC(s.name || s.id)}</b>${s.description ? `<div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(String(s.description).slice(0, 80))}</div>` : ""}<div class="sub" style="margin:1px 0 0"><code style="font-size:10px">${CX_ESC(s.ref || "")}</code></div></td>
    <td>${(s.subject_scope || []).map((k) => `<span class="pill muted" style="margin:0 3px 3px 0">${CX_ESC(k)}</span>`).join("") || "—"}</td>
    <td>${(s.consent_requirements || []).map((c) => `<span class="pill ${c === "never_train" ? "warn" : "ok"}" style="margin:0 3px 3px 0">${CX_ESC(c)}</span>`).join("") || "—"}</td>
    <td>${(s.evidence_requirements || []).map((e) => `<code style="font-size:10px;margin-right:4px">${CX_ESC(e)}</code>`).join("") || "<span class='sub' style='margin:0'>none</span>"}</td>
    <td>${(s.candidate_refs || []).length}</td>
    <td><span class="pill muted" style="margin:0">${CX_ESC(s.status || "draft")}</span> ${healthPill(s.health)}</td>
    <td><form class="inline" method="post" action="/__ioi/evaluations/${enc(s.id)}/delete"><button class="act ghost" type="submit">Delete</button></form></td>
  </tr>`;
  const library = `<h2 id="eval-suite-library">Eval-suite library ${sub(`— declared suites (${list.length})`)}</h2>`
    + (list.length
      ? `<table><thead><tr><th>Suite</th><th>Subject scope</th><th>Consent required</th><th>Evidence required</th><th>Candidates</th><th>Status</th><th></th></tr></thead><tbody>${list.map(suiteRow).join("")}</tbody></table>`
      : omBoundaryNote(`<b>No eval suites declared yet</b> — declare one above. A suite is an inert declaration (subject scope · admissibility · candidate handoffs); it never scores or executes. This library reads the real daemon eval-suite contract; nothing is fabricated.`));

  // Assessment subjects in scope — REAL Missions execution truth (mission runs / failures / blockers).
  const subjRow = (kind, label, when, proof) => `<tr><td><span class="pill muted" style="margin:0">${CX_ESC(kind)}</span></td><td>${CX_ESC(label)}</td><td class="sub" style="margin:0">${CX_ESC(when || "")}</td><td>${proof ? `<a href="${CX_ESC(proof)}" target="_blank" rel="noopener">proof ↗</a>` : "—"}</td></tr>`;
  const subjRows = [
    ...missionRuns.slice(0, 6).map((r) => subjRow("mission_run", r.name || r.execution_id || "—", r.started_at, r.timeline_ref)),
    ...failedRuns.slice(0, 6).map((r) => subjRow("failed_run", r.name || r.execution_id || "—", r.finished_at, r.timeline_ref)),
    ...blockers.slice(0, 6).map((r) => subjRow("goal_run_blocker", (r.normalized_goal || r.goal_ref || r.goal_run_id || "—"), r.updated_at, r.goal_run_id ? `/__ioi/run-timeline/goal-run/${enc(r.goal_run_id)}` : "")),
  ].join("");
  const totalSubjects = missionRuns.length + failedRuns.length + blockers.length;
  const subjectsPane = `<h2 id="eval-subjects">Assessment subjects in scope ${sub(`— real execution truth a suite can draw on (${totalSubjects})`)}</h2>`
    + (totalSubjects
      ? `<table><thead><tr><th>Kind</th><th>Subject</th><th>When</th><th>Evidence</th></tr></thead><tbody>${subjRows}</tbody></table><p class="sub" style="margin:6px 0 0">Subjects come from <a href="/__ioi/missions">Missions</a>; each carries its own proof/timeline as admissible evidence.</p>`
      : omBoundaryNote(`No mission runs or blockers to assess yet — subjects appear as <a href="/__ioi/missions">Missions</a> produces real runs.`));

  // Consent + candidate inputs (feedback plane) and Foundry model_eval drafts (adjacent, not execution).
  const fbTotal = (feedbackOv || {}).total || 0;
  const consentPane = `<h2 id="eval-inputs">Evidence-eligibility &amp; candidate inputs ${sub(`— the consent ladder that gates admission`)}</h2>`
    + `<div class="chips" style="margin:0 0 8px"><span class="chiplabel">Consent ladder</span>${ladder.map((c) => `<span class="pill ${c === "never_train" ? "warn" : "muted"}" style="margin:0"><code>${CX_ESC(c)}</code></span>`).join(" ")}</div>`
    + `<p class="sub" style="margin:0 0 6px">Candidate evidence is minted in <a href="/__ioi/feedback">Feedback &amp; annotations</a> (${fbTotal} entr${fbTotal === 1 ? "y" : "ies"}) — converting an entry emits a named <code>eval://</code> handoff, gated on consent. This suite library only <b>references</b> those candidates; it never trains or scores.</p>`
    + (drafts.length ? `<div class="chips" style="margin:6px 0 0"><span class="chiplabel">Foundry model_eval drafts</span>${drafts.slice(0, 8).map((d) => `<span class="pill muted" style="margin:0" title="adjacent draft input — not eval execution">${CX_ESC(d.name || d.id || d.spec_id || "spec")}</span>`).join(" ")}</div>` : "");

  const gaps = omBoundaryNote(`Supported here is real daemon truth: the inert eval-suite declaration + real subjects + consent gate + candidate references. <b>Named gaps</b> (no authority contract yet, deliberately not built): EvalRun execution · scoring / verdicts · judge / model evaluation · scorecards · auto-mining failed runs into evals · the object-set analysis canvas (<a href="/__apps/analysis">analysis seed</a>) · Quiver time-series analysis (<a href="/__apps/quiver">quiver seed</a>) · promotion decisions. The <a href="/__apps/evalsuites">eval-suite reference capture ↗</a> is the familiar baseline, never a rebound surface.`);

  return automationsShell("Evaluations", head + flashHtml + banner + form + library + subjectsPane + consentPane + gaps);
}

// ---- Search (67-search graft) — typed cross-estate discovery with open-action handoffs.
// Case-insensitive substring over LIVE daemon projections at query time: no index, no stale
// results, nothing invented; every hit links into the surface that owns it. Sources and their
// coverage are listed on the empty state so what is NOT searchable is visible too.
function renderSearchResults(q, groups, sources) {
  const total = groups.reduce((n, g) => n + g.items.length, 0);
  const form = `<form method="get" action="/__ioi/search" class="row" style="margin:0 0 18px"><input name="q" value="${CX_ESC(q || "")}" placeholder="session refs, projects, automations, models, ontologies, approvals…" style="flex:1;padding:10px 14px;border-radius:10px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit" autofocus><button class="act" type="submit">Search</button></form>`;
  const groupSec = (g) => `<h2>${CX_ESC(g.name)} (${g.items.length})</h2>${g.items.slice(0, 12).map((it) => `<a class="card" href="${it.href}"${it.top ? ' target="_top"' : ""}><div class="main"><div class="name">${CX_ESC(it.label)}</div><div class="meta">${CX_ESC(it.meta || "")}</div></div><span class="act ghost">Open →</span></a>`).join("")}`;
  const body = !q
    ? `<div class="empty">Type a query. Searchable now (live, exact-substring): ${sources.map((s) => `<code>${CX_ESC(s)}</code>`).join(" ")}. Anything else is not indexed — by design there is no stale search truth.</div>`
    : total
      ? groups.filter((g) => g.items.length).map(groupSec).join("")
      : `<div class="empty">No matches for <b>${CX_ESC(q)}</b> across ${sources.length} live projections.</div>`;
  return automationsShell("Search", `<h1>Search</h1><p class="sub">Cross-estate discovery over live daemon projections — each result opens in its owning surface. Matching is exact-substring at query time; nothing is indexed, so nothing is stale.</p>${form}${body}`);
}

// ---- Code Repositories (13-code-repositories graft — folds into the Workbench container, no
// catalog card). Repos as FIRST-CLASS over project truth: every repository-backed project, the
// SCM host bindings with their real auth posture, and the governed-publish trail from the proof
// stream. Publishing itself stays a wallet-authorized crossing on the SCM lanes — nothing here
// mutates a repository.
function renderCodeRepositories(projectsRes, scmRes, ledgerEntries) {
  const enc = encodeURIComponent;
  const projects = (projectsRes || {}).projects || [];
  const scm = (scmRes || {}).connectors || [];
  const publishes = (ledgerEntries || []).filter((e) => String(e.kind || "").includes("publish") || String(e.op || "").includes("publish"));
  const scmStrip = scm.length
    ? scm.map((c) => {
      const bound = c.auth_posture === "token-lease:bound";
      return `<div class="card"><div class="main"><div class="name">${CX_ESC(c.name || c.kind || "scm host")}${bound ? "" : ' <span class="pill warn">needs auth</span>'}</div><div class="meta">${CX_ESC(c.kind || "")} · <code>${CX_ESC(c.host || c.remote_url || "")}</code>${c.connected_login ? ` · @${CX_ESC(c.connected_login)}` : ""} · posture <code>${CX_ESC(c.auth_posture || "unbound")}</code></div></div>${bound ? '<span class="pill ok">bound</span>' : `<a class="act ghost" href="/settings/runners?user-settings=git-authentications" target="_blank">Git authentications ↗</a>`}</div>`;
    }).join("")
    : `<div class="empty">No SCM hosts bound — bind one via <a href="/settings/runners?user-settings=git-authentications" target="_blank">Git authentications ↗</a> to enable governed publish lanes (sealed host token, wallet-authorized crossings).</div>`;
  const repoCard = (p) => {
    const pid = String(p.project_id || "").replace(/^project:/, "");
    return `<div class="card"><div class="main"><div class="name">${CX_ESC(p.project_name || pid || "project")}</div>
      <div class="meta"><code>${CX_ESC(p.repository_url || "no repository_url")}</code> · <code style="font-size:10px">${CX_ESC(p.project_id || "")}</code></div></div>
      <span><a class="act ghost" href="/projects/${enc(p.project_id || pid)}" target="_top">Project →</a> <a class="act ghost" href="/__ioi/automations?project=${enc(pid)}">Automations →</a></span></div>`;
  };
  const pubRows = publishes.slice(0, 10).map((e) => `<tr><td>${CX_ESC(e.kind || e.op || "")}</td><td><span class="pill ${(e.status === "done" || e.status === "published" || e.status === "success") ? "ok" : "muted"}">${CX_ESC(e.status || "—")}</span></td><td>${CX_ESC(e.timestamp || "")}</td><td><code style="font-size:10px">${CX_ESC((e.state_root || "").slice(0, 18) || "—")}</code></td></tr>`).join("");
  const inner = `<h1>Code Repositories</h1><p class="sub">Repository-backed work as first-class truth — every project's repo, the SCM host bindings with their sealed-credential posture, and the governed-publish trail. Publishing is a wallet-authorized crossing; nothing on this page mutates a repository. <a href="/__ioi/workbench">Workbench →</a></p>
    <h2>SCM hosts</h2>${scmStrip}
    <h2>Repositories (${projects.length})</h2>${projects.length ? projects.map(repoCard).join("") : `<div class="empty">No repository-backed projects yet — create a project with a repository_url and it lands here.</div>`}
    <h2>Governed publishes</h2>${publishes.length ? `<table><thead><tr><th>Kind</th><th>Status</th><th>When</th><th>Proof</th></tr></thead><tbody>${pubRows}</tbody></table>` : `<div class="empty">No governed publishes recorded yet — a wallet-authorized publish writes its receipt to the proof stream and appears here.</div>`}`;
  return automationsShell("Code Repositories", inner);
}

// ---- Sessions root (rail root per canon; the P1 gap for the SWE-migration + provider-recovery
// demos). Session lifecycle FACTS over the daemon records: lifecycle chips with counts, each
// session's admitted harness binding (selection is session truth, not UI state), its environment
// join with phase, and the owned proof affordances. List-first slice; no mutation lanes here.
function renderSessionsRoot(sessionsRes, envSummary) {
  const enc = encodeURIComponent;
  const sessions = ((sessionsRes || {}).sessions || []).slice().sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
  const envPhase = {};
  (((envSummary || {}).environments) || []).forEach((e) => { envPhase[e.id] = e.phase || ""; });
  const byState = {};
  sessions.forEach((s) => { const k = s.lifecycle_state || "unknown"; byState[k] = (byState[k] || 0) + 1; });
  const chips = `<div class="chips" id="sess-chips"><button class="chip on" data-ss="" onclick="ssChip(this)">All ${sessions.length}</button>${Object.entries(byState).map(([k, n]) => `<button class="chip" data-ss="${CX_ESC(k)}" onclick="ssChip(this)">${CX_ESC(k)} ${n}</button>`).join("")}</div>`;
  const rows = sessions.slice(0, 60).map((s) => {
    const envId = String(s.environment_ref || "").replace(/^environment:/, "");
    const hb = s.harness_binding;
    return `<tr data-ss="${CX_ESC(s.lifecycle_state || "unknown")}">
      <td><code style="font-size:11px">${CX_ESC(s.session_ref || "")}</code><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(s.project_ref || "no project")} · ${CX_ESC(s.created_at || "")}</div></td>
      <td><span class="pill muted">${CX_ESC(s.lifecycle_state || "—")}</span></td>
      <td>${hb && hb.profile_ref ? `<span class="pill ok">${CX_ESC(hb.harness || "harness")}</span> <code style="font-size:10px">${CX_ESC(hb.model_route_ref || "")}</code><div style="color:#878a93;font-size:10.5px;margin-top:1px" title="${CX_ESC(hb.admission_id || "")}">admitted at create</div>` : `<span class="pill muted" title="no harness binding recorded at create; execution uses the daemon default lane">execute-time default</span>`}</td>
      <td>${envId ? `<code style="font-size:10.5px">${CX_ESC(envId)}</code>${envPhase[envId] ? ` <span class="pill ${envPhase[envId] === "running" ? "ok" : "muted"}">${CX_ESC(envPhase[envId])}</span>` : ""}` : "—"}</td>
      <td>${envId ? `<a href="/workspaces/${enc(envId)}" target="_top">workbench</a> · <a href="/details/${enc(envId)}" target="_top">session</a> · <a href="/__ioi/run-timeline/env/${enc(envId)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td>
    </tr>`;
  }).join("");
  const inner = `<h1>Sessions</h1><p class="sub">Every governed session with its lifecycle facts and ADMITTED harness binding — selection is session truth recorded at create, never UI state. New work starts from the rail's New Session; replay lives in <a href="/__ioi/run-replay">Run Replay</a>. <a href="/__apps/jobs">Run/job queue (daemon-truth rebind) →</a> · <a href="/__apps/incidents">Incident inbox (daemon-truth rebind) →</a></p>
    ${sessions.length ? `${chips}<table><thead><tr><th>Session</th><th>Lifecycle</th><th>Admitted binding</th><th>Environment</th><th>Open</th></tr></thead><tbody id="sess-body">${rows}</tbody></table><div class="empty" id="sess-empty" style="display:none">No sessions in this state.</div>
    <script>function ssChip(b){document.querySelectorAll('#sess-chips .chip').forEach(function(x){x.classList.toggle('on',x===b);});var w=b.getAttribute('data-ss');var n=0;document.querySelectorAll('#sess-body tr').forEach(function(r){var on=!w||r.getAttribute('data-ss')===w;r.style.display=on?'':'none';if(on)n++;});document.getElementById('sess-empty').style.display=n?'none':'';}</script>`
    : `<div class="empty">No sessions yet — launch one from the rail's New Session and it appears here with its admitted binding.</div>`}`;
  return automationsShell("Sessions", inner);
}

function renderApplications() {
  // The autonomous-systems suite + the substrate lane (canon: core-clients-surfaces.md "The
  // Autonomous-Systems Application Suite"; detail: internal-docs/prompts/autonomous-systems-
  // suite/suite-guide.md). Every href opens a REAL surface today; where a suite identity is
  // wider than its current surface, the copy names what is live and what is adopting.
  const SUITE = [
    { icon: "🎨", name: "Studio", desc: "Compose systems & agents — agent lens live (inventory, model routes, runner adapters); system canvas adopting.", href: "/__ioi/agent-studio" },
    { icon: "⚡", name: "Automations", desc: "Durable triggers, schedules, monitors, services — condition → governed effect.", href: "/__ioi/automations" },
    { icon: "🧬", name: "Ontology", desc: "The semantic world-model — Ontology Manager over the typed COM; Object Explorer + ODK substrate linked within.", href: "/__ioi/ontology/manager" },
    { icon: "🌐", name: "Data", desc: "Supply the world-model — sources, syncs, data recipes, datasets, media sets, consent posture.", href: "/__ioi/odk#data-planes" },
    { icon: "🛡", name: "Governance", desc: "Authority — approvals, identity, leases, revocation, release gates, kill switches, budgets, gaps.", href: "/__ioi/governance" },
    { icon: "🚀", name: "Missions", desc: "Fleet of running systems — the mission run queue + incident/blocker inbox over daemon truth.", href: "/__ioi/missions" },
    { icon: "📒", name: "Provenance", desc: "Proof plane — unified receipts stream, state roots, timelines live; lineage canvas adopting.", href: "/__ioi/work-ledger" },
    { icon: "🧪", name: "Evaluations", desc: "Eval-suite library over real subjects/consent + feedback candidate source; scoring & EvalRun adopting.", href: "/__ioi/evaluations" },
    { icon: "📈", name: "Improvement", desc: "Proposals, what-if simulation, apply-under-gates — proposal lane live; change inbox adopting.", href: "/__ioi/agent-studio#improvement-proposals" },
    { icon: "🏗", name: "Foundry", desc: "Model substrate — catalog, routes, draft specs, run plans, promotion previews.", href: "/__ioi/foundry" },
    { icon: "🛒", name: "Marketplace", desc: "Distribution — listings, publish candidates, admission reviews (admission-only).", href: "/__ioi/marketplace" },
    { icon: "🧰", name: "Workbench", desc: "Enter an environment's live console — files, terminal, ports, tasks.", href: "/__ioi/workbench" },
    { icon: "🔌", name: "Developer Console", desc: "Extend the environment — connectors, MCP, sealed credentials, SDK on-ramps, developer tools.", href: "/__ioi/connections" },
  ];
  const SUBSTRATE = [
    { icon: "🖥", name: "Environments", desc: "Lifecycle, readiness, services/ports/tasks, kernel-boundary posture.", href: "/__ioi/environments" },
    { icon: "⚙", name: "Operations", desc: "Infrastructure — scheduler health, providers, placement/failover, storage custody, capacity, spend.", href: "/__ioi/operations" },
  ];
  const card = (s) => {
    const inner = `<div class="main"><div class="name">${s.icon} ${CX_ESC(s.name)}<span class="pill ok">open</span></div><div class="meta">${CX_ESC(s.desc)}</div></div>`;
    return `<a class="card" href="${s.href}">${inner}<span class="act ghost">Open →</span></a>`;
  };
  // Ported application surfaces — rendered from the app catalog (parity-matrix membership), the
  // same projection the shell launcher fetches at /__ioi/api/applications; never a hand list.
  const portedCard = (a) => {
    const ico = a.icon ? `<img src="${a.icon}" alt="" style="width:18px;height:18px;vertical-align:-4px;border-radius:4px"> ` : "◳ ";
    return `<a class="card" href="${a.route}"><div class="main"><div class="name">${ico}${CX_ESC(a.title)}<span class="pill ok">open</span></div><div class="meta">${CX_ESC(a.family)} · ${CX_ESC(a.route)}</div></div><span class="act ghost">Open →</span></a>`;
  };
  const ported = appCatalog().apps;
  return automationsShell(
    "Applications",
    `<h1>Applications</h1><p class="sub">The autonomous-systems suite — compose, ground, govern, run, prove, evaluate, improve, package, distribute, operate. Generated apps land here as launchable entries. Home's governed-work band expands into the <a href="/__ioi/home">full readout</a>.</p>${SUITE.map(card).join("")}
    ${ported.length ? `<h2 style="margin-top:26px">Ported apps</h2><p class="sub">Faithful ports of reference application surfaces inside the suite families — pixel-parity shell over daemon truth.</p>${ported.map(portedCard).join("")}` : ""}
    <h2 style="margin-top:26px">Substrate</h2><p class="sub">The type 1 + 2 hypervisor face — the foundation the suite runs on, kept distinct from it.</p>${SUBSTRATE.map(card).join("")}
    <h2 style="margin-top:26px">Horizon</h2><div class="card"><div class="main"><div class="name">🤖 HypervisorOS<span class="pill muted">horizon</span></div><div class="meta">Embodied systems lane over the same governed substrate — named only; no surfaces yet.</div></div></div>`,
  );
}

// ---- Work Ledger — one chronological PROOF STREAM (runs + webhook receipts) with faceted filters.
// What happened · under whose authority · with which artifacts · how to replay it. Real records only;
// no fabricated rows. Row click opens a right proof drawer. Data comes from GET /v1/hypervisor/work-ledger.
// ---- Provenance lineage — the daemon-backed lane behind the /__apps/lineage monocle graph seed.
// The captured canvas teaches the lineage-graph grammar (resource nodes, derivation edges, layout/
// tools, preview/history/code/build/data-health lenses); here the OWNER surface binds the real
// lineage: every admitted proof entry is a NODE and its cross-object refs are typed EDGES to the
// objects it derives from / acts on. Nodes and edges exist ONLY where a daemon receipt/ref sources
// them — never fabricated. Empty stream → honest empty state.
function renderProvenanceLineage(entries) {
  entries = Array.isArray(entries) ? entries : [];
  // Typed provenance edges: ref field on a proof entry -> the surface that owns the target object.
  const EDGE = [
    ["receipt_ref", "receipt", "/__ioi/work-ledger"],
    ["state_root", "state-root", null],
    ["run_ref", "run", null],
    ["timeline_ref", "run-timeline", null],
    ["session_ref", "session", "/__ioi/workbench#sessions"],
    ["profile_ref", "harness-profile", "/__ioi/agent-studio#harness-profiles"],
    ["domain_app_ref", "domain-app", "/__ioi/domain-apps"],
    ["release_control_ref", "release-control", "/__ioi/governance"],
    ["approval_request_ref", "approval", "/__ioi/governance"],
    ["kill_switch_ref", "kill-switch", "/__ioi/governance"],
    ["subject_ref", "kill-subject", "/__ioi/governance"],
    ["candidate_ref", "publish-candidate", "/__ioi/marketplace"],
    ["listing_id", "listing", "/__ioi/marketplace"],
    ["automation_id", "automation", "/__ioi/operations"],
  ];
  if (!entries.length) {
    return `<h2 id="provenance-lineage">Provenance lineage</h2><p class="sub" style="margin:-4px 0 12px">The lineage graph is the daemon's own derivation edges — a proof entry and the objects it derives from. Explore the graph grammar in the <a href="/__apps/lineage">lineage canvas seed →</a>.</p><div class="empty">No admitted work yet — no lineage edges to derive. Run an automation or a session to create proof entries; each becomes a node with its receipt / state-root / session / release-control edges.</div>`;
  }
  // Edge-type adjacency density across the whole proof stream (daemon truth, counted not faked).
  const counts = {};
  for (const e of entries) for (const [k] of EDGE) if (e[k]) counts[k] = (counts[k] || 0) + 1;
  const edgeChips = EDGE.filter(([k]) => counts[k]).map(([k, label]) => `<span class="pill muted" title="${counts[k]} proof entries carry a ${label} edge">${CX_ESC(label)} · ${counts[k]}</span>`).join("");
  // Sample a real node neighborhood: the newest entry with the richest edge set.
  const richness = (e) => EDGE.reduce((n, [k]) => n + (e[k] ? 1 : 0), 0);
  const sorted = [...entries].sort((a, b) => (richness(b) - richness(a)) || String(b.timestamp || "").localeCompare(String(a.timestamp || "")));
  const node = sorted[0];
  const nodeTitle = node.kind === "harness_execution" ? `${node.harness || "harness"} → ${node.session_ref || "session"}`
    : node.automation_name || node.listing_id || node.subject_ref || node.domain_app_ref || node.id || node.kind;
  const edgeList = EDGE.filter(([k]) => node[k]).map(([k, label, href]) => {
    const val = String(node[k]);
    const target = k === "timeline_ref" ? val : (k === "run_ref" && node.timeline_ref) ? node.timeline_ref : href;
    const cell = target
      ? `<a href="${target}"${/^\/__ioi\/run-timeline/.test(target) ? ' target="_blank" rel="noopener"' : ""}>${CX_ESC(val)} ↗</a>`
      : `<code>${CX_ESC(val)}</code>`;
    return `<li><span class="pill muted">${CX_ESC(label)}</span> ${cell}</li>`;
  }).join("");
  return `<h2 id="provenance-lineage">Provenance lineage</h2>` +
    `<p class="sub" style="margin:-4px 0 12px">The lineage graph is the daemon's own derivation edges — every admitted proof entry is a node; its cross-object refs are typed edges to the objects it derives from or acts on. Explore the graph grammar in the <a href="/__apps/lineage">lineage canvas seed →</a>; the edges below are daemon truth. <b>Named gap:</b> the seed's in-canvas Add-resources / Open-graph resource search lanes are not in the current capture — the interactive canvas stays a scaffold while the edges are surfaced here.</p>` +
    `<h3 style="margin:12px 0 4px;font-size:13px">Lineage edge density <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— typed edges across ${entries.length} proof entries</span></h3><div class="chips" style="margin:2px 0 4px">${edgeChips || '<span class="pill muted">no cross-object edges yet</span>'}</div>` +
    `<h3 style="margin:16px 0 4px;font-size:13px">Sample node neighborhood <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— <code>${CX_ESC(String(node.kind))}</code> · ${CX_ESC(nodeTitle)}${node.state_root ? " · " + CX_ESC(String(node.state_root).slice(0, 22)) : ""}</span></h3>` +
    `<ul class="wlbl" style="max-width:820px">${edgeList || '<li class="sub" style="margin:0">this node carries no outbound edges</li>'}</ul>`;
}

function renderWorkLedger(entries, scopedProject, selCtx) {
  // #64 §14: the proof stream is a read-time projection — the DISPLAY copy (rows, drawer, and
  // the embedded #wl-data JSON) redacts source-contact endpoints to their ORIGIN; the durable
  // receipts on disk are untouched, and repeated reads mint nothing.
  const wlRedact = (e) => {
    if (!e || !e.source_contact || !e.source_contact.endpoint) return e;
    const c = { ...e, source_contact: { ...e.source_contact } };
    try { const u = new URL(c.source_contact.endpoint); c.source_contact.endpoint = `${u.protocol}//${u.host}/…`; } catch { c.source_contact.endpoint = "(endpoint redacted)"; }
    return c;
  };
  entries = (entries || []).map(wlRedact);
  // #64 §9: odk_materialization entries are ADDRESSABLE — by receipt ref (?receipt=) or by the
  // exact object set (?objectSet=); an unmatched selection renders an honest note, never a
  // substituted entry.
  const wlCtx = selCtx || {};
  const wlSelIdx = (wlCtx.receipt || wlCtx.objectSet)
    ? entries.findIndex((e) => e.kind === "odk_materialization" && ((wlCtx.receipt && e.receipt_ref === wlCtx.receipt) || (wlCtx.objectSet && (String(e.materialized_set_ref || "").endsWith(wlCtx.objectSet) || e.id === wlCtx.objectSet))))
    : -1;
  const wlSelNote = (wlCtx.receipt || wlCtx.objectSet) && wlSelIdx < 0
    ? `<div class="empty">No materialization entry matches the requested ${wlCtx.receipt ? `receipt <code>${CX_ESC(wlCtx.receipt)}</code>` : `object set <code>${CX_ESC(wlCtx.objectSet)}</code>`} — nothing substituted (fail-closed).</div>`
    : "";
  // Same surface, optionally scoped to one project (light copy only — NOT a forked per-project UI).
  const scope = scopedProject
    ? `<p class="sub" style="margin:-10px 0 16px"><span class="pill ok">project: ${CX_ESC(scopedProject)}</span> · <a href="/__ioi/work-ledger">view all projects →</a></p>`
    : "";
  const head = `<h1>Provenance</h1><p class="sub"><a href="/__apps/lineage">Lineage canvas seed (adopting) →</a> · The proof plane — one chronological stream of admitted work — runs and trigger receipts across every project and automation, each with its state root and a link to the full timeline.</p><p class="sub" style="margin:-8px 0 0">Graph lenses over materialized truth: <a href="/__ioi/lineage">Data lineage →</a> · <a href="/__ioi/vertex">Vertex graph →</a></p>${scope}`;
  if (!entries.length) {
    const msg = scopedProject
      ? "No admitted work yet for this project. Run one of its automations to create ledger evidence."
      : "No admitted work yet. Run an automation to create ledger evidence.";
    return automationsShell("Provenance", head + renderProvenanceLineage(entries) + `<div class="empty">${msg}</div>`);
  }
  const projects = [...new Set(entries.map((e) => e.project_id).filter(Boolean))];
  const chip = (f, v, label) => `<button class="chip" data-facet="${f}" data-val="${v}" onclick="wlChip(this)">${label}</button>`;
  const filters = `<div class="chips">
    <span class="chiplabel">kind</span>${chip("kind", "run", "Runs")}${chip("kind", "harness_execution", "Harness runs")}${chip("kind", "goal_run", "IOI Agent coordination")}${chip("kind", "goal_run_invocation", "Agent invocations")}${chip("kind", "goal_run_reconciliation", "Reconciliations")}${chip("kind", "memory_lifecycle", "Memory lifecycle")}${chip("kind", "simulation_report", "Simulations")}${chip("kind", "policy_rollout", "Rollouts")}${chip("kind", "rollout_enforcement", "Rollout enforcement")}${chip("kind", "provider_crossing", "Provider crossings")}${chip("kind", "storage_custody", "Storage custody")}${chip("kind", "odk_materialization", "Materializations")}${chip("kind", "trigger", "Trigger events")}${chip("kind", "marketplace_publish", "Publishes")}${chip("kind", "kill_enforcement", "Kill enforcements")}
    <span class="chiplabel">status</span>${chip("status", "done", "Done")}${chip("status", "success", "Success")}${chip("status", "registered", "Registered")}${chip("status", "failed", "Failed")}${chip("status", "failure", "Failure")}${chip("status", "accepted", "Accepted")}${chip("status", "rejected", "Rejected")}
    <span class="chiplabel">project</span><select id="wl-project" onchange="wlFilter()"><option value="">all</option>${projects.map((p) => `<option value="${CX_ESC(p)}">${CX_ESC(p)}</option>`).join("")}</select>
  </div>`;
  const icon = (k) => (k === "run" ? "▶" : k === "harness_execution" ? "🤖" : k === "goal_run" ? "🎯" : k === "goal_run_invocation" ? "🤝" : k === "goal_run_reconciliation" ? "⚖" : k === "memory_lifecycle" ? "🧬" : k === "simulation_report" ? "🔮" : k === "policy_rollout" ? "🚦" : k === "rollout_enforcement" ? "🚫" : k === "improvement_applied" ? "📈" : k === "memory_projection" ? "🧠" : k === "marketplace_publish" ? "🛒" : k === "domain_app_runtime" ? "🧩" : k === "kill_enforcement" ? "🛑" : k === "provider_crossing" ? "🔌" : k === "storage_custody" ? "🗄" : k === "odk_materialization" ? "📦" : "🪝");
  // A ledger row's headline: automation name for runs, else the harness/session/subject it proves.
  const title = (e) => e.kind === "provider_crossing"
    ? `provider ${CX_ESC(e.op || "op")} · ${CX_ESC(e.provider || "")} ${CX_ESC(String(e.account_ref || e.environment_ref || "").slice(-22))}`
    : e.kind === "storage_custody"
    ? `archive ${CX_ESC(e.op || "op")} · ${CX_ESC(e.backend || "")} ${CX_ESC(String(e.archive_ref || e.material_ref || "").slice(-22))}`
    : e.kind === "harness_execution"
    ? `${CX_ESC(e.harness || "harness")} → ${CX_ESC(e.session_ref || "session")}`
    : e.kind === "goal_run" ? `IOI Agent coordination · ${CX_ESC(String(e.normalized_goal || "").slice(0, 48))}`
    : e.kind === "goal_run_invocation" ? `IOI Agent · ${CX_ESC(e.role_key || "role")} · ${CX_ESC(e.harness || "")}`
    : e.kind === "goal_run_reconciliation" ? `IOI Agent reconcile · ${CX_ESC(e.merge_strategy || "")}`
    : e.kind === "memory_lifecycle" ? `memory ${CX_ESC(e.status || "")} · ${CX_ESC(String(e.record_ref || "").slice(-18))} (${CX_ESC(e.from_quality_state || "")} → ${CX_ESC(e.to_quality_state || "")})`
    : e.kind === "memory_projection" ? `intelligence projected · ${CX_ESC(String(e.harness_profile_ref || "").replace("harness-profile:hp_", ""))}`
    : e.kind === "marketplace_publish" ? `publish ${CX_ESC(e.listing_id || e.candidate_ref || "")}`
    : e.kind === "kill_enforcement" ? `kill ${CX_ESC(e.subject_ref || "")}`
    : e.kind === "domain_app_runtime" ? `${CX_ESC(e.action || "runtime")} ${CX_ESC(e.domain_app_ref || "")}`
    : e.kind === "odk_materialization" ? `materialized ${CX_ESC(String(e.object_count == null ? "" : e.object_count))} object${e.object_count === 1 ? "" : "s"} → ${CX_ESC(e.object_type_id || "objects")}`
    : CX_ESC(e.automation_name || "—");
  const rows = entries.map((e, i) => {
    const st = e.status || "";
    const pill = (st === "done" || st === "accepted" || st === "success" || st === "published" || st === "registered") ? "ok" : (st === "failed" || st === "rejected" || st === "failure") ? "warn" : "muted";
    const proof = (e.state_root || "").slice(0, 20) || "—";
    return `<tr class="wlrow" data-kind="${CX_ESC(e.kind)}" data-status="${CX_ESC(st)}" data-project="${CX_ESC(e.project_id || "")}" data-i="${i}" onclick="wlOpen(${i})">
      <td>${icon(e.kind)} ${title(e)}</td>
      <td>${CX_ESC(e.project_id || "—")}</td>
      <td><span class="pill ${pill}">${CX_ESC(st)}</span></td>
      <td>${CX_ESC(e.trigger_kind || e.kind || "")}</td>
      <td>${CX_ESC(e.timestamp || "")}</td>
      <td><code>${CX_ESC(proof)}</code></td>
    </tr>`;
  }).join("");
  const table = `<table><thead><tr><th>Work</th><th>Project</th><th>Status</th><th>Trigger</th><th>When</th><th>Proof</th></tr></thead><tbody>${rows}</tbody></table>`;
  // ---- Proof Explorer facets (native primitive, first slice) — the STATE-ROOT TIMELINE on
  // demand (canon: normal flows abstract chain machinery; Proof Explorer exposes roots and refs
  // when challenged). Chronological strip of the entries that carry a tamper-evident state root;
  // each jumps into the stream row's proof drawer. Counts are honest: rooted vs total.
  const rooted = entries.map((e, i) => ({ e, i })).filter(({ e }) => e.state_root);
  const proofExp = `<div id="wl-proof-explorer" class="card" style="display:block;margin:0 0 14px">
    <div class="row" style="justify-content:space-between;margin:0 0 6px"><b>Proof Explorer — state roots</b><span class="sub" style="margin:0">${rooted.length} of ${entries.length} entries carry a state root</span></div>
    ${rooted.length ? `<div style="display:flex;flex-wrap:wrap;gap:6px">${rooted.slice(0, 10).map(({ e, i }) => `<button class="chip" onclick="wlOpen(${i});document.querySelector('.wlrow[data-i=&quot;${i}&quot;]').scrollIntoView({behavior:'smooth',block:'center'})" title="${CX_ESC(e.timestamp || "")} · ${CX_ESC(e.kind || "")}"><code style="font-size:10px">${CX_ESC(String(e.state_root).slice(0, 18))}</code></button>`).join("")}</div>`
      : `<div class="sub" style="margin:0">No state-rooted entries yet — admitted work writes tamper-evident roots as it lands.</div>`}
  </div>`;
  // Embed the entries for the drawer (escape </script> + < to keep the JSON inside the tag safe).
  const dataTag = `<script id="wl-data" type="application/json">${JSON.stringify(entries).replace(/</g, "\\u003c")}</script>`;
  const drawer = `<div class="wldrawer" id="wl-drawer"><div class="sub" style="margin:0">Select a row to inspect its proof.</div></div>`;
  const script = `<script>
    var WL=[];try{WL=JSON.parse(document.getElementById('wl-data').textContent||'[]');}catch(e){}
    function wlChip(b){b.classList.toggle('on');wlFilter();}
    function wlFilter(){
      var ks=[].slice.call(document.querySelectorAll('.chip.on[data-facet="kind"]')).map(function(b){return b.dataset.val;});
      var ss=[].slice.call(document.querySelectorAll('.chip.on[data-facet="status"]')).map(function(b){return b.dataset.val;});
      var pe=document.getElementById('wl-project');var pr=pe?pe.value:'';
      document.querySelectorAll('.wlrow').forEach(function(r){
        var ok=(!ks.length||ks.indexOf(r.dataset.kind)>=0)&&(!ss.length||ss.indexOf(r.dataset.status)>=0)&&(!pr||r.dataset.project===pr);
        r.style.display=ok?'':'none';
      });
    }
    function wesc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
    function wlOpen(i){
      var e=WL[i];if(!e)return;
      function row(k,v){return (v===0||v)?('<div class="wlk">'+k+'</div><div class="wlv">'+wesc(v)+'</div>'):'';}
      var titles={run:'▶',harness_execution:'🤖',marketplace_publish:'🛒',domain_app_runtime:'🧩',kill_enforcement:'🛑',odk_materialization:'📦'};
      var hd=e.kind==='harness_execution'?((e.harness||'harness')+' → '+(e.session_ref||'session')):e.kind==='odk_materialization'?('materialized '+(e.object_count==null?'':e.object_count)+' → '+(e.object_type_id||'objects')):(e.automation_name||e.listing_id||e.subject_ref||e.domain_app_ref||'—');
      var h='<h3>'+(titles[e.kind]||'🪝')+' '+wesc(hd)+'</h3><div class="wlgrid">';
      h+=row('Kind',e.kind)+row('Project',e.project_id)+row('Status',e.status)+row('Trigger',e.trigger_kind||e.kind)+row('When',e.timestamp);
      if(e.kind==='run'){h+=row('Environment',e.environment_id)+row('Authority',e.authority?JSON.stringify(e.authority):'')+row('Steps',e.counts?JSON.stringify(e.counts):'');}
      if(e.kind==='harness_execution'){h+=row('Harness',e.harness)+row('Session',e.session_ref)+row('Profile',e.profile_ref)+row('Files changed',(e.files_written||[]).join(', '))+row('Receipt',e.receipt_ref);
        if(e.implementation_result){h+=row('Adapter',e.implementation_result.adapter)+row('Model',e.implementation_result.model)+row('Exit code',e.implementation_result.exit_code);}}
      if(e.kind==='trigger'){h+=row('Reason',e.reason)+row('Request',e.request_id);}
      if(e.kind==='provider_crossing'){h+=row('Op',e.op)+row('Provider',e.provider)+row('Account',e.account_ref)+row('Environment',e.environment_ref)+row('Receipt',e.receipt_ref)+row('Grant',e.grant_ref)+row('Candidate',e.candidate_ref)+row('Quote',e.quote_ref)+row('Execution mode',e.execution_mode)+row('Teardown',e.teardown_state)+row('State root',e.state_root_evidence)+row('Cost estimate',e.cost_estimate?JSON.stringify(e.cost_estimate):'');}
      if(e.kind==='storage_custody'){h+=row('Op',e.op)+row('Backend',e.backend)+row('Backend ref',e.backend_ref)+row('Archive',e.archive_ref)+row('Material',e.material_ref)+row('Environment',e.environment_ref)+row('State root',e.state_root)+row('Commitment',e.commitment?(e.commitment.address||''):'')+row('Grant',e.grant_ref)+row('Incident',e.incident_ref)+row('Repair',e.repair_ref)+row('Custody rule',e.custody_rule);}
      if(e.kind==='odk_materialization'){h+=row('Objects',e.object_count)+row('Ontology',e.ontology_ref)+row('Object type',e.object_type_id)+row('Object set',e.materialized_set_ref)+row('Materializing run',e.materializing_run_ref)+row('Sealed session',e.connector_session_ref)+row('Lease plan',e.capability_lease_plan_ref)+row('Projection',e.ontology_projection_id)+row('Pre-output receipt',e.pre_output_receipt_ref)+row('Source',e.source_contact?e.source_contact.endpoint:'')+row('Authority',e.authority_rule);}
      h+='</div><h4>Hashes</h4><div class="wlgrid">'+row('State root',e.state_root)+row('Payload hash',e.payload_hash)+row('Headers hash',e.headers_hash)+'</div>';
      // Backlinks — this ledger entry is an executable cross-reference map: every cross-object
      // ref it names is rendered as a navigable link into the surface that owns that object, so
      // the whole governed lifecycle is traversable from one proof (crosswalk: cross-reference map).
      function bl(label,ref,href){return ref?('<li>'+wesc(label)+': <a href="'+href+'" target="_top">'+wesc(ref)+' ↗</a></li>'):'';}
      var links='';
      if(e.projection_ref){links+=bl('Projection explain',e.projection_ref,'/__ioi/intelligence/projections/'+String(e.projection_ref).replace('memory-projection://','')+'/explain');}
      if(e.simulation_ref){links+=bl('Simulation report',e.simulation_ref,'/__ioi/intelligence/simulations/'+String(e.simulation_ref).replace('simulation-report://',''));}
      if(e.kind==='policy_rollout'){links+=bl('Learned policy',e.policy_ref,'/__ioi/agent-studio#launch-policies')+bl('Base policy',e.base_policy_ref,'/__ioi/agent-studio#launch-policies');}
      if(e.goal_run_ref){links+=bl('GoalRun',e.goal_run_ref,'/__ioi/run-timeline/goal-run/'+String(e.goal_run_ref).replace('goal://',''));}
      if(e.session_ref){links+=bl('Session',e.session_ref,'/__ioi/workbench#sessions');}
      if(e.profile_ref){links+=bl('Harness profile',e.profile_ref,'/__ioi/agent-studio#harness-profiles');}
      if(e.domain_app_ref){links+=bl('Domain app',e.domain_app_ref,'/__ioi/domain-apps');}
      if(e.candidate_ref){links+=bl('Publish candidate',e.candidate_ref,'/__ioi/marketplace');}
      if(e.listing_id){links+=bl('Listing',e.listing_id,'/__ioi/marketplace');}
      if(e.kind==='provider_crossing'){links+=bl('Provider health',e.account_ref||'provider accounts','/__ioi/operations')+bl('Provider accounts',e.account_ref||'environments','/__ioi/environments');if(e.exposure_ref){links+=bl('Spend reconciliation',e.exposure_ref,e.spend_reconciliation_ref||'/__ioi/operations');}}
      if(e.kind==='storage_custody'){links+=bl('Storage backend health',e.backend_ref||'storage backends',e.storage_health_ref||'/__ioi/operations')+bl('Archive custody',e.archive_ref||'environments','/__ioi/environments');}
      if(e.kind==='odk_materialization'){var oid=String(e.ontology_ref||'').replace('ontology://','');var q=oid?('?ontology='+oid):'';var sid=String(e.materialized_set_ref||'').replace('materialized-object-set://','');links+=bl('Ontology Manager',e.ontology_ref,'/__ioi/ontology/manager'+q)+(e.object_type_id&&oid?bl('Object type',e.object_type_id,'/__ioi/ontology/manager?definitionId='+encodeURIComponent(e.object_type_id)+'&definitionKind=object-type&ontology='+oid+'&section=object-types'):'')+(sid&&oid?bl('Object set (Explorer)',e.materialized_set_ref,'/__ioi/ontology/explorer?objectSet='+encodeURIComponent(sid)+'&ontology='+oid):'')+(oid?bl('Pipeline materialized node',e.ontology_ref,'/__ioi/pipeline?node=materialized&ontology='+oid):'')+(sid&&oid?bl('Lineage path',e.materialized_set_ref,'/__ioi/lineage?objectSet='+encodeURIComponent(sid)+'&ontology='+oid):'')+(sid&&oid?bl('Vertex neighborhood',e.materialized_set_ref,'/__ioi/vertex?objectSet='+encodeURIComponent(sid)+'&ontology='+oid):'')+bl('ODK substrate',e.materializing_run_ref,'/__ioi/odk'+q+'#pane-resources');}
      if(e.release_control_ref){links+=bl('Release control',e.release_control_ref,'/__ioi/governance');}
      if(e.approval_request_ref){links+=bl('Approval request',e.approval_request_ref,'/__ioi/governance');}
      if(e.kill_switch_ref){links+=bl('Kill switch',e.kill_switch_ref,'/__ioi/governance');}
      if(e.subject_ref){links+=bl('Subject',e.subject_ref,'/__ioi/governance');}
      if(e.receipt_ref){links+=bl('Receipt',e.receipt_ref,'/__ioi/work-ledger');}
      if(e.timeline_ref){links+='<li>Run Timeline: <a href="'+e.timeline_ref+'" target="_blank" rel="noopener">open ↗</a></li>';}
      if(links){h+='<h4>Backlinks</h4><ul class="wlbl">'+links+'</ul>';}
      var arts=(e.step_results||[]).filter(function(s){return s&&(s.kind==='proposal'||(s.output&&(s.output.command||s.output.file_changed)));});
      h+='<h4>Artifacts</h4>'+(arts.length?('<ul>'+arts.map(function(s){return '<li>'+wesc(s.kind||'step')+': '+wesc(JSON.stringify(s.output).slice(0,140))+'</li>';}).join('')+'</ul>'):'<div class="sub" style="margin:0">—</div>');
      if(e.timeline_ref){h+='<p><a class="act ghost" href="'+e.timeline_ref+'" target="_blank" rel="noopener">Open Run Timeline ↗</a></p>';}
      h+='<details><summary class="sub" style="cursor:pointer">Raw JSON (advanced)</summary><pre>'+wesc(JSON.stringify(e,null,2))+'</pre></details>';
      document.getElementById('wl-drawer').innerHTML=h;
      document.querySelectorAll('.wlrow').forEach(function(r){r.classList.toggle('selrow',r.dataset.i==String(i));});
    }
  </script>`;
  const wlSelScript = wlSelIdx >= 0 ? `<script>wlOpen(${wlSelIdx})</script>` : "";
  return automationsShell("Provenance", head + wlSelNote + renderProvenanceLineage(entries) + filters + proofExp + `<div class="wlwrap"><div>${table}</div>${drawer}</div>` + dataTag + script + wlSelScript);
}

// ---- Operations — the first real Operations estate card: execution health over the automation
// substrate (scheduler · run health · needs-attention · webhook health). Real records only;
// drilldowns into Automation detail / Work Ledger / Run Timeline. No fake incidents/cost/capacity.
function renderOperations(ops, authpol, prov, provReceipts, spendRecon, storageBackends, storageIncidents, akashDepin, failoverRuns, failoverPlans, goalRuns, ledgerEntries) {
  ops = ops || {};
  authpol = authpol || {};
  prov = prov || {};
  provReceipts = provReceipts || {};
  spendRecon = spendRecon || {};
  const sch = ops.scheduler || { automations: [] };
  const runs = ops.runs || {};
  const wh = ops.webhooks || {};
  const enc = encodeURIComponent;
  const schedHuman = (s) => {
    if (!s || typeof s !== "object") return "—";
    if (s.type === "cron" || s.cron) return `cron ${CX_ESC(s.cron || "")} (${CX_ESC(s.timezone || "UTC")})`;
    if (s.every_hours) return `every ${s.every_hours}h`;
    if (s.every_minutes) return `every ${s.every_minutes}m`;
    if (s.every_seconds || s.interval_seconds) return `every ${s.every_seconds || s.interval_seconds}s`;
    return "scheduled";
  };
  const stat = (cls, label) => `<span class="pill ${cls}">${label}</span>`;
  // Scheduler
  const schedRows = (sch.automations || []).map((a) => {
    const en = a.enabled !== false;
    return `<tr><td><a href="/__ioi/automations/${enc(a.automation_id)}">${CX_ESC(a.name || a.automation_id)}</a></td><td>${CX_ESC(a.project_id || "—")}</td><td><span class="pill ${en ? "ok" : "muted"}">${en ? "active" : "paused"}</span></td><td>${schedHuman(a.schedule_spec)}</td><td>${CX_ESC(a.next_run_at || "—")}</td><td>${CX_ESC(a.last_run_at || "—")}</td><td>${CX_ESC(String(a.max_concurrency || 1))} · ${CX_ESC(a.failure_policy || "continue")}</td></tr>`;
  }).join("");
  const schedSection = (sch.automations || []).length
    ? `<table><thead><tr><th>Automation</th><th>Project</th><th>State</th><th>Schedule</th><th>Next run</th><th>Last run</th><th>Concurrency · on-fail</th></tr></thead><tbody>${schedRows}</tbody></table>`
    : `<div class="empty">No scheduled automations yet. Add a time/cron schedule to an automation to populate scheduler health.</div>`;
  // ---- Jobs — one queue over EVERY execution kind (40-job-tracker graft). The reference job
  // tracker's one-list-of-all-jobs grammar lands on the existing Operations surface: automation
  // runs, harness executions, IOI Agent coordination runs, and failover recovery runs, merged
  // newest-first with type chips. Each row carries its own proof affordance (timeline or state
  // root); a failover run parked at a wallet gate says so. Rows come verbatim from the owning
  // projections — no synthesized job states.
  const jobs = [];
  (runs.recent || []).forEach((r) => jobs.push({
    type: "automation", name: r.name || r.automation_id || "run", id: r.execution_id || "",
    project: r.project_id || "—", status: r.status || "", at: r.started_at || "",
    proof: r.timeline_ref ? `<a href="${r.timeline_ref}" target="_blank" rel="noopener">timeline ↗</a>` : "—",
  }));
  (goalRuns || []).forEach((g) => jobs.push({
    type: "ioi-agent", name: `coordination · ${String(g.normalized_goal || "goal").slice(0, 44)}`, id: g.goal_run_id || "",
    project: g.project_ref || "—", status: g.status || "", at: g.created_at || "",
    proof: g.goal_run_id ? `<a href="/__ioi/run-timeline/goal-run/${enc(g.goal_run_id)}" target="_blank" rel="noopener">proof ↗</a>` : "—",
  }));
  (ledgerEntries || []).filter((e) => e.kind === "harness_execution").slice(0, 12).forEach((e) => jobs.push({
    type: "harness", name: `${e.harness || "harness"} → ${e.session_ref || "session"}`, id: e.session_ref || "",
    project: e.project_id || "—", status: e.status || "", at: e.timestamp || "",
    proof: e.state_root ? `<code style="font-size:10px">${CX_ESC(String(e.state_root).slice(0, 18))}</code>` : "—",
  }));
  ((failoverRuns || {}).runs || []).forEach((r) => jobs.push({
    type: "failover", name: `recovery · ${r.failure_condition || "failure"}`, id: r.run_ref || "",
    project: r.environment_ref || "—", status: r.status || "", at: r.started_at || "",
    proof: r.state_root ? `<code style="font-size:10px">${CX_ESC(String(r.state_root).slice(0, 18))}</code>` : "—",
  }));
  // Per-kind cap BEFORE the merged sort so a high-volume kind (hundreds of coordination runs)
  // never starves the others out of the rendered window — every kind that exists is visible.
  const perKind = {};
  const capped = [];
  jobs.sort((a, b) => String(b.at).localeCompare(String(a.at)));
  for (const j of jobs) {
    perKind[j.type] = (perKind[j.type] || 0) + 1;
    if (perKind[j.type] <= 12) capped.push(j);
  }
  const jobPill = (s) => {
    const st = String(s || "");
    if (st.startsWith("awaiting_authority")) return `<span class="pill warn">wallet gate: ${CX_ESC(st.replace("awaiting_authority_", ""))}</span>`;
    const cls = ["done", "succeeded", "restored", "restored_with_warning", "success"].includes(st) ? "ok"
      : ["failed", "refused", "failure", "error"].includes(st) ? "warn" : "muted";
    return `<span class="pill ${cls}">${CX_ESC(st || "—")}</span>`;
  };
  const JOB_TYPES = [["", "All"], ["automation", "Automation"], ["harness", "Harness"], ["ioi-agent", "IOI Agent"], ["failover", "Failover"]];
  const jobCounts = {};
  jobs.forEach((j) => { jobCounts[j.type] = (jobCounts[j.type] || 0) + 1; });
  const jobsChips = `<div class="chips" id="jobs-chips">${JOB_TYPES.map(([v, l]) => `<button class="chip${v === "" ? " on" : ""}" data-job-type="${v}" onclick="jobsChip(this)">${l} ${v === "" ? jobs.length : jobCounts[v] || 0}</button>`).join("")}</div>`;
  const jobRows = capped.slice(0, 48).map((j) => `<tr data-job="${CX_ESC(j.type)}">
      <td>${CX_ESC(j.name)}<div style="color:#878a93;font-size:11px;margin-top:1px"><code style="font-size:10px">${CX_ESC(j.id)}</code></div></td>
      <td><span class="pill muted">${CX_ESC(j.type)}</span></td>
      <td>${CX_ESC(j.project)}</td>
      <td>${jobPill(j.status)}</td>
      <td>${CX_ESC(j.at)}</td>
      <td>${j.proof}</td>
    </tr>`).join("");
  const jobsSection = jobs.length
    ? `${jobsChips}<table><thead><tr><th>Job</th><th>Type</th><th>Project</th><th>Status</th><th>When</th><th>Proof</th></tr></thead><tbody id="jobs-body">${jobRows}</tbody></table><div class="empty" id="jobs-empty" style="display:none">No jobs of this type yet.</div>`
    : `<div class="empty">No jobs yet — automation runs, harness executions, IOI Agent coordination, and failover recovery land here as they happen.</div>`;
  const jobsScript = `<script>
    function jobsChip(b){
      document.querySelectorAll('#jobs-chips .chip').forEach(function(x){x.classList.toggle('on',x===b);});
      var want=b.getAttribute('data-job-type');var shown=0;
      document.querySelectorAll('#jobs-body tr').forEach(function(r){var on=!want||r.getAttribute('data-job')===want;r.style.display=on?'':'none';if(on)shown++;});
      var e=document.getElementById('jobs-empty');if(e)e.style.display=shown?'none':'';
    }
  </script>`;
  // Operate console (source shape: job console = queue/list + selectable status detail + remediation
  // + in-surface proof, not a monitor-only table). Rows select into a sticky drawer that joins the
  // run to its scheduler record IN-PAYLOAD (both come from the one /operations projection) and
  // carries remediation (re-run / pause / resume via the existing automation lanes) + the proof ref.
  const opRuns = [];
  const opRunRow = (r, kind) => {
    const i = opRuns.length;
    opRuns.push({ ...r, kind });
    return `<tr class="wlrow oprow" data-i="${i}"><td>${CX_ESC(r.name || "—")}<div style="color:#878a93;font-size:11px;margin-top:1px"><code>${CX_ESC(r.execution_id || "")}</code></div></td><td>${CX_ESC(r.project_id || "—")}</td><td><span class="pill ${r.status === "done" ? "ok" : r.status === "failed" ? "warn" : "muted"}">${CX_ESC(r.status || "")}</span></td><td>${CX_ESC(r.started_at || "")}</td></tr>`;
  };
  // Run health
  const runStat = `<div style="display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px">${stat("muted", "total " + (runs.total || 0))}${stat("ok", "done " + (runs.done || 0))}${stat("warn", "failed " + (runs.failed || 0))}${stat("muted", "running " + (runs.running || 0))}</div>`;
  const runSection = (runs.total || 0)
    ? runStat + `<table><thead><tr><th>Automation · run</th><th>Project</th><th>Status</th><th>Started</th></tr></thead><tbody>${(runs.recent || []).map((r) => opRunRow(r, "recent")).join("")}</tbody></table>`
    : `<div class="empty">No runs yet. Run an automation to populate run health.</div>`;
  // Needs attention (failures)
  const attnSection = (runs.failures || []).length
    ? `<table><thead><tr><th>Automation · run</th><th>Project</th><th>Status</th><th>Started</th></tr></thead><tbody>${runs.failures.map((r) => opRunRow(r, "failure")).join("")}</tbody></table>`
    : `<div class="empty">Nothing needs attention — no failed runs.</div>`;
  // Webhook health
  const reasons = wh.rejections_by_reason || {};
  const reasonPills = Object.keys(reasons).map((k) => stat("warn", CX_ESC(k) + " " + reasons[k])).join(" ");
  const whStat = `<div style="display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px">${stat("ok", "accepted " + (wh.accepted || 0))}${stat("warn", "rejected " + (wh.rejected || 0))} ${reasonPills}</div>`;
  const whRow = (e) => `<tr><td>${CX_ESC(e.automation_id || "—")}</td><td><span class="pill ${e.accepted ? "ok" : "warn"}">${e.accepted ? "accepted" : "rejected"}</span></td><td>${CX_ESC(e.reason || "")}</td><td><code>${CX_ESC((e.payload_hash || "").slice(0, 18))}</code></td><td>${CX_ESC(e.received_at || "")}</td></tr>`;
  const whSection = ((wh.accepted || 0) + (wh.rejected || 0))
    ? whStat + `<table><thead><tr><th>Automation</th><th>Result</th><th>Reason</th><th>Payload</th><th>Received</th></tr></thead><tbody>${(wh.recent || []).map(whRow).join("")}</tbody></table>`
    : `<div class="empty">No webhook triggers yet. Enable a webhook on an automation to populate webhook health.</div>`;
  // Provider health — BYO ProviderAccount posture (preflight verdicts) + the crossing receipt
  // trail. Spend transparency is stated in-surface: BYO provider spend is customer-borne, never
  // hidden markup. Real records only (daemon /providers + /provider-receipts).
  const provAccounts = prov.accounts || [];
  const provStatusPill = (s) => (s === "available" || s === "credential_verified") ? "ok" : s === "revoked" ? "warn" : "muted";
  const provRows = provAccounts.map((a) => `<tr><td>${CX_ESC(a.display_name || "—")}<div style="color:#878a93;font-size:11px;margin-top:1px"><code>${CX_ESC(a.account_ref || "")}</code></div></td><td><span class="pill muted">${CX_ESC(a.kind || "")}</span></td><td><span class="pill ${provStatusPill(a.status)}">${CX_ESC(a.status || "")}</span><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(a.reason || "")}</div></td><td><span class="pill muted">customer-borne spend</span></td></tr>`).join("");
  const provTable = provAccounts.length
    ? `<table><thead><tr><th>Provider account</th><th>Kind</th><th>Health · preflight</th><th>Spend</th></tr></thead><tbody>${provRows}</tbody></table>`
    : `<div class="empty">No BYO provider accounts yet. Add one under Environments → Provider accounts to run governed work on your own nodes.</div>`;
  const prcs = (provReceipts.receipts || []).slice(0, 8);
  const prcRows = prcs.map((r) => `<tr><td><code>${CX_ESC(r.op || "")}</code></td><td>${CX_ESC(r.provider || "")}</td><td><span class="pill ${r.outcome === "ok" ? "ok" : "warn"}">${CX_ESC(r.outcome || "")}</span></td><td><code style="font-size:10.5px">${CX_ESC(r.account_ref || r.environment_ref || "—")}</code></td><td>${CX_ESC(r.at || "")}</td><td><a href="/__ioi/work-ledger" title="provider crossings in the proof stream">ledger →</a></td></tr>`).join("");
  const prcTable = prcs.length
    ? `<table><thead><tr><th>Op</th><th>Provider</th><th>Outcome</th><th>Target</th><th>At</th><th>Proof</th></tr></thead><tbody>${prcRows}</tbody></table>`
    : `<div class="empty">No provider receipts yet — every provider crossing (success or failure) writes one.</div>`;
  const srB = spendRecon.budget || {};
  const srWarn = spendRecon.incomplete_teardown_warnings || [];
  const srRows = (spendRecon.rows || []).slice(-8).reverse().map((e) => `<tr>
      <td><code style="font-size:10.5px">${CX_ESC(e.exposure_ref || "")}</code><div class="sub" style="margin:1px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(e.environment_ref || "")}</div></td>
      <td>${CX_ESC(e.provider || "")}</td>
      <td><span class="pill ${e.status === "open" ? "warn" : e.status === "closed" ? "ok" : "warn"}">${CX_ESC(e.status || "")}</span></td>
      <td>$${CX_ESC(String(e.usd_per_hour ?? "?"))}/hr <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">(max $${CX_ESC(String(e.max_hourly_usd ?? "?"))})</span></td>
      <td>${CX_ESC(e.teardown_state || "")}</td>
      <td>${(e.receipt_refs || []).length} receipt(s)</td>
    </tr>`).join("");
  const spendSection = `<div id="ops-spend-recon"><h3 style="margin:14px 0 8px">Provider spend reconciliation</h3>
    <p class="sub" style="margin:-2px 0 8px;text-transform:none;letter-spacing:0">${CX_ESC(spendRecon.spend_rule || "customer-borne provider spend — estimates over receipts, never a bill")}</p>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin:0 0 8px">
      <span class="pill ${srB.exists ? "ok" : "muted"}">headroom ${CX_ESC(String(srB.remaining_headroom ?? "—"))}</span>
      <span class="pill muted">reserved (open estimates) ${CX_ESC(String(srB.reserved_open_estimates ?? 0))}</span>
      <span class="pill muted">actual spent ${CX_ESC(String(srB.spent ?? 0))}</span>
      <span class="pill ${(spendRecon.estimated_open_exposure_rate || {}).open_count ? "warn" : "muted"}">open exposures ${CX_ESC(String((spendRecon.estimated_open_exposure_rate || {}).open_count ?? 0))}</span>
      <span class="pill muted">finalized ${CX_ESC(String((spendRecon.teardown_finalized || {}).count ?? 0))}</span>
      ${srWarn.length ? `<span class="pill warn">⚠ incomplete teardowns ${srWarn.length}</span>` : ""}
    </div>
    ${srWarn.map((w) => `<div class="sub" style="margin:0 0 6px;color:#e2b93d;text-transform:none;letter-spacing:0">⚠ ${CX_ESC(w.exposure_ref || "")} — ${CX_ESC(w.warning || "")}</div>`).join("")}
    ${srRows ? `<table><thead><tr><th>Exposure</th><th>Provider</th><th>Status</th><th>Rate (estimate)</th><th>Teardown</th><th>Evidence</th></tr></thead><tbody>${srRows}</tbody></table>` : `<div class="empty">No spend exposures yet — a quote-backed metered create opens one; teardown closes it.</div>`}
  </div>`;
  // Storage backend health — archive/CAS byte custody posture (backends, objects, incidents).
  const stB = (storageBackends || {}).backends || [];
  const stInc = ((storageIncidents || {}).incidents || []).filter((i) => i.status === "open");
  const stRep = ((storageIncidents || {}).repair_receipts || []).slice(0, 5);
  const stRows = stB.map((b) => `<tr><td>${CX_ESC(b.display_name || "—")}<div style="color:#878a93;font-size:11px;margin-top:1px"><code>${CX_ESC(b.account_ref || "")}</code></div></td><td><span class="pill muted">${CX_ESC(b.kind || "")}</span></td><td><span class="pill ${(b.health || {}).state === "available" ? "ok" : (b.health || {}).state === "impaired" ? "warn" : "muted"}">${CX_ESC((b.health || {}).state || b.status || "")}</span></td><td>${CX_ESC(String((b.health || {}).objects ?? 0))} object(s)</td><td>${(b.health || {}).open_incidents ? `<span class="pill warn">⚠ ${(b.health || {}).open_incidents}</span>` : `<span class="pill muted">0</span>`}</td></tr>`).join("");
  const stIncRows = stInc.map((i) => `<div class="sub" style="margin:0 0 6px;color:#e2b93d;text-transform:none;letter-spacing:0">⚠ ${CX_ESC(i.kind || "")} — <code style="font-size:10.5px">${CX_ESC(i.archive_ref || "")}</code> ${CX_ESC((i.detail || "").slice(0, 120))}</div>`).join("");
  const stRepRows = stRep.map((r) => `<div class="sub" style="margin:0 0 4px;text-transform:none;letter-spacing:0">${r.outcome === "repaired" ? "✔" : "✖"} repair ${CX_ESC(r.outcome || "")} — <code style="font-size:10.5px">${CX_ESC(r.archive_ref || "")}</code></div>`).join("");
  const storageSection = `<div id="ops-storage-backends"><h3 style="margin:14px 0 8px">Storage backend health</h3>
    <p class="sub" style="margin:-2px 0 8px;text-transform:none;letter-spacing:0">${CX_ESC((storageBackends || {}).custody_rule || "storage backends hold payload bytes; they do not own operational truth — daemon-admitted sha256 state roots remain restore truth")}</p>
    ${stRows ? `<table><thead><tr><th>Backend</th><th>Kind</th><th>Health</th><th>Archives</th><th>Open incidents</th></tr></thead><tbody>${stRows}</tbody></table>` : `<div class="empty">No storage backends yet. Add one (local_disk · cas · ipfs · filecoin) to export sealed archive bytes off-daemon.</div>`}
    ${stIncRows}${stRepRows}
  </div>`;
  // DePIN posture (Akash) — deployments/bids/leases/endpoints from daemon records.
  const akDeps = (akashDepin || {}).deployments || [];
  const akLeases = (akashDepin || {}).leases || [];
  const akPlans = (akashDepin || {}).redeploy_plans || [];
  const akRow = (d) => {
    const lease = akLeases.find((l) => l.deployment_ref === d.deployment_ref) || {};
    const lastEvent = (d.events || []).slice(-1)[0] || {};
    return `<tr><td><code style="font-size:10.5px">${CX_ESC(d.deployment_ref || "")}</code><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(d.environment_ref || "")}</div></td><td><span class="pill ${d.status === "running" ? "ok" : d.status === "torn_down" ? "muted" : "warn"}">${CX_ESC(d.status || "")}</span></td><td><span class="pill ${lease.state === "open" ? "warn" : "muted"}">${CX_ESC(lease.state || "—")}</span> $${CX_ESC(String(lease.usd_per_hour ?? "?"))}/hr</td><td>${CX_ESC((lastEvent.kind || "—"))}</td></tr>`;
  };
  const akSection = akDeps.length ? `<div id="ops-akash-depin"><h3 style="margin:14px 0 8px">DePIN deployments (Akash)</h3>
    <p class="sub" style="margin:-2px 0 8px;text-transform:none;letter-spacing:0">${CX_ESC((akashDepin || {}).custody_rule || "")}</p>
    <table><thead><tr><th>Deployment</th><th>Status</th><th>Lease</th><th>Last event</th></tr></thead><tbody>${akDeps.slice(0, 8).map(akRow).join("")}</tbody></table>
    ${akPlans.length ? `<div class="sub" style="margin:6px 0 0;text-transform:none;letter-spacing:0">${akPlans.length} redeploy plan(s) — restore admits only by daemon state_root</div>` : ""}
  </div>` : "";
  const foRuns = (failoverRuns || {}).runs || [];
  const foRow = (r) => {
    const repl = r.replacement || {};
    const oldp = r.old_provider || {};
    return `<tr><td><code style="font-size:10.5px">${CX_ESC(r.run_ref || "")}</code><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(r.environment_ref || "")}</div></td><td><span class="pill warn">${CX_ESC(r.failure_condition || "")}</span></td><td>${CX_ESC(oldp.provider_kind || "?")} → ${CX_ESC(repl.provider_kind || "?")}</td><td><span class="pill ${r.status === "restored" ? "ok" : r.status === "refused" ? "err" : "warn"}">${CX_ESC(r.status || "")}</span></td><td><code style="font-size:10px">${CX_ESC((r.state_root || "").slice(0, 24))}</code></td></tr>`;
  };
  const foPlansAll = (failoverPlans || {}).plans || [];
  const foArmed = foPlansAll.filter((p) => p.trigger_state === "armed").length;
  const foTriggered = foPlansAll.filter((p) => p.trigger_state === "triggered").length;
  const foAuto = (foRuns.some((r) => r.triggered_by) || foArmed || foTriggered)
    ? `<p class="sub" style="margin:-2px 0 8px;text-transform:none;letter-spacing:0">Auto-trigger posture: ${foArmed} armed · ${foTriggered} triggered — detection is evidence-cited and a triggered run parks at the wallet gate (never automatic authority).</p>` : "";
  const foSection = (foRuns.length || foArmed || foTriggered) ? `<div id="ops-failover"><h3 style="margin:14px 0 8px">Cross-provider failover runs</h3>${foAuto}
    <p class="sub" style="margin:-2px 0 8px;text-transform:none;letter-spacing:0">Named failure → placement decision → wallet-gated replacement create → state_root-validated restore → old teardown. Restore admits only by daemon-admitted state roots; provider-native ids stay evidence.</p>
    <table><thead><tr><th>Run</th><th>Condition</th><th>Class move</th><th>Status</th><th>State root</th></tr></thead><tbody>${foRuns.slice(0, 8).map(foRow).join("")}</tbody></table>
  </div>` : "";
  const provSection = `<div id="ops-provider-health"><h2>Provider health</h2><p class="sub" style="margin:-4px 0 10px">BYO provider accounts and their preflight posture. ${CX_ESC(prov.spend_rule || "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — never hidden markup")}.</p>${provTable}${spendSection}${storageSection}${akSection}${foSection}<h3 style="margin:14px 0 8px">Recent provider receipts</h3>${prcTable}</div>`;
  // Scheduler records keyed by automation_id, with the schedule pre-humanized server-side so the
  // drawer join needs no client re-implementation of cron/interval rendering.
  const autosById = {};
  for (const a of sch.automations || []) autosById[a.automation_id] = { ...a, schedule_human: schedHuman(a.schedule_spec).replace(/<[^>]*>/g, "") };
  const drawer = `<div class="wldrawer" id="ops-drawer"><div class="sub" style="margin:0">Select a run to inspect its status detail, scheduler posture, proof, and remediation.</div></div>`;
  const script = `<script>
    var OPS_RUNS=${JSON.stringify(opRuns)};var OPS_AUTOS=${JSON.stringify(autosById)};
    function opsEsc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
    function opsRow(k,v){return v?'<div class="wlk">'+opsEsc(k)+'</div><div class="wlv">'+v+'</div>':'';}
    document.querySelectorAll('.oprow').forEach(function(tr){tr.addEventListener('click',function(){
      var r=OPS_RUNS[parseInt(tr.getAttribute('data-i'),10)];if(!r)return;
      document.querySelectorAll('.oprow').forEach(function(x){x.classList.toggle('selrow',x===tr);});
      var a=OPS_AUTOS[r.automation_id]||null;var d=document.getElementById('ops-drawer');
      var dur='';
      if(r.started_at&&r.finished_at){var ms=new Date(r.finished_at)-new Date(r.started_at);if(ms>=0)dur=(ms/1000).toFixed(2)+'s';}
      var h='<h3>'+opsEsc(r.name||r.automation_id)+' <span class="pill '+(r.status==='done'?'ok':r.status==='failed'?'warn':'muted')+'">'+opsEsc(r.status||'')+'</span></h3>';
      h+='<h4>Run</h4><div class="wlgrid">'+opsRow('Execution','<code>'+opsEsc(r.execution_id)+'</code>')+opsRow('Automation','<a href="/__ioi/automations/'+encodeURIComponent(r.automation_id)+'">'+opsEsc(r.automation_id)+'</a>')+opsRow('Project',opsEsc(r.project_id))+opsRow('Started',opsEsc(r.started_at))+opsRow('Finished',opsEsc(r.finished_at))+opsRow('Duration',opsEsc(dur))+'</div>';
      h+='<h4>Scheduler posture</h4>'+(a?('<div class="wlgrid">'+opsRow('State','<span class="pill '+(a.enabled!==false?'ok':'muted')+'">'+(a.enabled!==false?'active':'paused')+'</span>')+opsRow('Schedule',opsEsc(a.schedule_human))+opsRow('Next run',opsEsc(a.next_run_at))+opsRow('Last run',opsEsc(a.last_run_at))+opsRow('Concurrency',opsEsc(String(a.max_concurrency||1)))+opsRow('On failure',opsEsc(a.failure_policy||'continue'))+'</div>'):'<div class="sub" style="margin:0">No schedule — this automation runs on manual/webhook triggers only.</div>');
      h+='<h4>Proof</h4><div class="wlgrid">'+opsRow('Run Timeline',r.timeline_ref?('<a href="'+r.timeline_ref+'" target="_blank" rel="noopener">open transcript ↗</a>'):'—')+opsRow('Ledger','<a href="/__ioi/work-ledger">proof stream →</a>')+'</div>';
      h+='<h4>Remediation</h4><div style="display:flex;gap:8px;flex-wrap:wrap">';
      h+='<form class="inline" method="post" action="/__ioi/automations/'+encodeURIComponent(r.automation_id)+'/run?back=ops"><button class="act" type="submit">▶ Re-run now</button></form>';
      if(a){h+=(a.enabled!==false)?'<form class="inline" method="post" action="/__ioi/automations/'+encodeURIComponent(r.automation_id)+'/pause?back=ops"><button class="act ghost" type="submit">⏸ Pause schedule</button></form>':'<form class="inline" method="post" action="/__ioi/automations/'+encodeURIComponent(r.automation_id)+'/resume?back=ops"><button class="act" type="submit">▶ Resume schedule</button></form>';}
      h+='</div>';
      d.innerHTML=h;
    });});
  </script>`;
  // ---- Work Analytics facet (native primitive, first slice — folds here, no new card). Funnels
  // over the proof stream and run health: status funnel with failure rate, ledger kind histogram,
  // and the improvement handoff into the real proposal lane. Latency beyond per-run duration is
  // not recorded — named, not charted.
  const waKinds = {};
  (ledgerEntries || []).forEach((e) => { const k = e.kind || "?"; waKinds[k] = (waKinds[k] || 0) + 1; });
  const waTotal = runs.total || 0;
  const waFailRate = waTotal ? Math.round(((runs.failed || 0) / waTotal) * 100) : 0;
  const workAnalytics = `<div id="ops-work-analytics"><h2>Work Analytics <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— funnels over the proof stream; deeper latency percentiles are not recorded yet (named gap)</span></h2>
    <div class="chips" style="margin:0 0 8px"><span class="chiplabel">run funnel</span><span class="pill muted">total ${waTotal}</span><span class="pill ok">done ${runs.done || 0}</span><span class="pill warn">failed ${runs.failed || 0}</span><span class="pill muted">running ${runs.running || 0}</span><span class="pill ${waFailRate > 20 ? "warn" : "muted"}">failure rate ${waFailRate}%</span></div>
    <div class="chips" style="margin:0 0 8px"><span class="chiplabel">ledger kinds</span>${Object.entries(waKinds).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, n]) => `<span class="pill muted">${CX_ESC(k)} ${n}</span>`).join("") || `<span class="sub" style="margin:0">no entries yet</span>`}</div>
    <p class="sub" style="margin:4px 0 0">${(runs.failed || 0) > 0 ? `${runs.failed} failed run${runs.failed > 1 ? "s are" : " is an"} improvement candidate${runs.failed > 1 ? "s" : ""} — mine them in <a href="/__ioi/agent-studio">Studio →</a>` : "No failed runs — nothing to mine right now."} · capture operator judgment in <a href="/__ioi/feedback">Feedback &amp; Annotations →</a></p></div>`;
  const inner = `<h1>Operations</h1><p class="sub">Substrate &amp; infrastructure — scheduler health, providers, placement/failover, storage custody, capacity, spend. Select an automation run to inspect and act on it in place. Suite/run work — the mission run queue + incident inbox — lives in <a href="/__ioi/missions">Missions →</a>. <a href="/__ioi/work-ledger">Open Provenance →</a></p>
    <div id="ops-jobs"><h2>Jobs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— automation runs · harness executions · IOI Agent coordination · failover recovery, newest first</span></h2>${jobsSection}${jobsScript}</div>
    ${workAnalytics}
    <h2>Scheduler</h2>${schedSection}
    <div class="wlwrap"><div>
    <h2 style="margin-top:0">Run health</h2>${runSection}
    <h2>Needs attention</h2>${attnSection}
    </div>${drawer}</div>
    <h2>Webhook health</h2>${whSection}
    ${provSection}${script}`;
  const posture = authpol.deployment_auth_posture || "";
  const rtNote = (authpol.rollout_trust || {}).note || "";
  const postureStrip = posture ? `<div class="card" style="display:block;margin:0 0 14px" id="ops-auth-posture"><b>Auth posture</b> <span class="pill ${posture === "authenticated_managed" ? "ok" : posture === "exposed_untrusted" ? "warn" : "muted"}">${CX_ESC(posture)}</span> · enforcement ${authpol.effective_enforced ? `<span class="pill ok">enforced</span>` : `<span class="pill muted">not enforced</span>`} · exposed ${authpol.exposed ? `<span class="pill warn">yes</span>` : `<span class="pill muted">no</span>`}<div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(rtNote)} · <a href="/__ioi/governance">Governance →</a></div></div>` : "";
  return automationsShell("Operations", postureStrip + inner);
}

// ---- Environments — where work runs: env lifecycle, readiness, services/ports/tasks, substrate
// posture, and drilldowns into Sessions / Workbench / Run Timeline. Projection over the existing
// /v1/hypervisor/environments + /environment-classes records (real-only; deleted envs excluded).
const envPhasePill = (p) => (p === "running" ? "ok" : (p === "failed" || p === "blocked") ? "warn" : "muted");
// Pagination strip driven by the daemon summary (offset/limit/total/has_more). Links stay within
// the surface (they reload the owned page in the Open Application slot).
function envPager(base, summary) {
  const offset = summary.offset || 0, limit = summary.limit || 60, total = summary.total_matching || 0;
  const shownLen = (summary.environments || []).length;
  const from = total ? offset + 1 : 0;
  const to = offset + shownLen;
  const prev = offset > 0 ? `<a href="${base}?offset=${Math.max(0, offset - limit)}">← Previous</a>` : `<span class="sub" style="margin:0;opacity:.5">← Previous</span>`;
  const next = summary.has_more ? `<a href="${base}?offset=${offset + limit}">Next →</a>` : `<span class="sub" style="margin:0;opacity:.5">Next →</span>`;
  return `<div class="row" style="justify-content:space-between;align-items:center"><span class="sub" style="margin:0">Showing ${from}-${to} of ${total} active environments</span><span style="display:flex;gap:14px">${prev}${next}</span></div>`;
}

// Environments — substrate bridge. Reads the daemon env-summary projection (counts + a paged slim
// slice); still fetches /environment-classes for posture. Does NOT pull the full env list.
// Placement venue cards — the four explicit choices over the BYO provider plane. Fee bases are
// declared copy (never fee objects); "Let Hypervisor choose" renders planned until the
// decentralized.cloud candidate plane exists. Provider cards show connected-account state,
// verified/unverified + preflight reasons, runtime classes, capability hints, and cost owner.
function renderPlacementVenues(venuesRes, policyRes, spendRecon) {
  const venues = (venuesRes || {}).venues || [];
  if (!venues.length) return "";
  const policy = (policyRes || {}).policy || {};
  const exposuresByAccount = {};
  for (const e of ((spendRecon || {}).rows || [])) {
    (exposuresByAccount[e.account_ref] = exposuresByAccount[e.account_ref] || []).push(e);
  }
  const hintChips = (h) => h ? ["gpu", "persistent_storage", "ip", "snapshot"].map((k) => `<span class="pill muted" title="${CX_ESC(k)}">${CX_ESC(k.replace("persistent_storage", "storage"))}: ${CX_ESC(h[k] || "?")}</span>`).join(" ") : "";
  const providerCard = (p) => `<div style="border:1px solid #1b1d23;border-radius:9px;padding:9px 11px;margin:6px 0">
      <b>${CX_ESC(p.display_name || p.kind)}</b> <span class="pill muted">${CX_ESC(p.kind || "")}</span>
      <span class="pill ${p.status === "verified" ? "ok" : p.connected === false ? "muted" : "warn"}">${CX_ESC(p.status || "")}</span>
      <span class="pill muted">cost owner: ${CX_ESC(p.cost_owner || "customer")}</span>
      <div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(p.reason || p.connect_hint || "")}</div>
      <div class="chips" style="margin-top:4px">${hintChips(p.capability_hints)}</div>
      <div class="sub" style="margin:2px 0 0;text-transform:none;letter-spacing:0">classes: ${CX_ESC(((p.environment_classes || {}).supported || []).join(", ") || (p.environment_classes || {}).note || "—")} · ${CX_ESC(p.lifecycle || "")}</div>
      ${p.account_ref ? `<div class="sub" style="margin:2px 0 0;text-transform:none;letter-spacing:0"><code>${CX_ESC(p.account_ref)}</code></div>` : ""}
      ${(exposuresByAccount[p.account_ref] || []).length ? (() => { const ex = exposuresByAccount[p.account_ref]; const open = ex.filter((e) => e.status === "open"); const warn = ex.filter((e) => e.status === "closed_with_warning"); return `<div class="sub" style="margin:3px 0 0;text-transform:none;letter-spacing:0">spend posture: ${open.length} open exposure(s)${open.length ? ` (est $${open.reduce((a, e) => a + (e.usd_per_hour || 0), 0).toFixed(3)}/hr)` : ""} · ${ex.filter((e) => e.status === "closed").length} finalized${warn.length ? ` · <span style="color:#e2b93d">⚠ ${warn.length} incomplete teardown</span>` : ""} · customer-borne</div>`; })() : ""}
    </div>`;
  const card = (v) => {
    const chosen = policy.venue === v.venue;
    const fee = v.fee || {};
    return `<div class="venue-card${chosen ? " chosen" : ""}" data-venue="${CX_ESC(v.venue)}" style="border:1px solid ${chosen ? "#3c9d64" : "#24262d"};border-radius:12px;background:#0c0d10;padding:12px 14px">
      <b>${CX_ESC(v.display_name)}</b>
      ${v.status === "planned" ? `<span class="pill muted" style="border-style:dashed">planned</span>` : v.status === "advisory" ? `<span class="pill ${v.available ? "ok" : "muted"}">advisory</span>` : v.available ? `<span class="pill ok">available</span>` : `<span class="pill warn">unavailable</span>`}
      ${chosen ? `<span class="pill ok">chosen</span>` : ""}
      <div class="sub" style="margin:4px 0 6px;text-transform:none;letter-spacing:0">${CX_ESC(v.summary || "")}</div>
      <div style="font-size:12px"><b>fee basis: ${CX_ESC(fee.fee_basis || "none")}</b> · cost owner: ${CX_ESC(fee.cost_owner || "customer")}</div>
      <div class="sub" style="margin:2px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(fee.fee_explanation || "")}</div>
      ${v.availability_note ? `<div class="sub" style="margin:4px 0 0;color:#e2b93d;text-transform:none;letter-spacing:0">${CX_ESC(v.availability_note)}</div>` : ""}
      ${v.planned_reason ? `<div class="sub" style="margin:4px 0 0;color:#e2b93d;text-transform:none;letter-spacing:0">${CX_ESC(v.planned_reason)}</div>` : ""}
      ${v.quote_policy ? `<div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(v.quote_policy)}</div>` : ""}
      ${(v.environment_classes || {}).supported && v.environment_classes.supported.length ? `<div class="chips" style="margin-top:6px"><span class="chiplabel">classes</span>${v.environment_classes.supported.map((c) => `<span class="pill muted">${CX_ESC(c)}</span>`).join("")}</div>` : ""}
      ${(v.providers || []).map(providerCard).join("")}
      ${v.status === "advisory" ? renderCandidateCards(v) : ""}
    </div>`;
  };
  return `<div id="env-placement-venues"><h2>Placement</h2><p class="sub" style="margin:-4px 0 10px">Where governed work runs — an explicit choice, never hidden behind auto. Pick a venue in New Session; the chosen policy is daemon truth (<code>placement-venue-policy</code>). ${CX_ESC((venuesRes || {}).spend_rule || "")}</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px">${venues.map(card).join("")}</div></div>`;
}

// Candidate cards for the advisory venue — evidence-bound proposals from LOCAL FACTS
// (never authority, expiring). Honest empty state when nothing is placement-eligible.
function renderCandidateCards(v) {
  const cands = (v.candidates || []).filter((c) => c.placement_eligible);
  const rec = v.recommendation;
  const head = rec
    ? `<div style="font-size:12px;margin-top:8px">advisory recommends <b>${CX_ESC(rec.venue || "")}</b>${rec.display_name ? " · " + CX_ESC(rec.display_name) : ""} <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">(${CX_ESC((rec.reason_codes || []).join(", "))})</span></div>`
    : `<div class="sub" style="margin:8px 0 0;color:#e2b93d;text-transform:none;letter-spacing:0">${CX_ESC(v.no_eligible_candidate || "no eligible candidate — effective venue stays run_local")}</div>`;
  const card = (c) => {
    const rel = c.reliability || {};
    return `<div style="border:1px solid #1b1d23;border-radius:9px;padding:9px 11px;margin:6px 0">
      <b>${CX_ESC(c.display_name || c.provider_kind || "")}</b> <span class="pill muted">${CX_ESC(c.provider_kind || "")}</span>
      <span class="pill ${c.status === "active" ? "ok" : "warn"}">${CX_ESC(c.status || "")}</span>
      <span class="pill muted">spend owner: ${CX_ESC((c.spend_estimate || {}).cost_owner || "customer")}</span>
      <div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(c.runtime_class || "")} · custody ${CX_ESC(((c.custody_plan || {}).supported_postures || []).join("/"))} · ${CX_ESC(c.coverage_state || "")}${rel.ops_ok !== undefined ? ` · ops ${rel.ops_ok}✓/${rel.ops_failed || 0}✗` : ""}${rel.host_reliability !== undefined && rel.host_reliability !== null ? ` · host reliability ${CX_ESC(String(rel.host_reliability))}` : ""}</div>
      ${c.gpu ? `<div style="font-size:12px;margin-top:3px"><b>${CX_ESC(String(c.gpu.count || 1))}x ${CX_ESC(c.gpu.model || "GPU")}</b>${c.gpu.vram_gb ? ` · ${CX_ESC(String(c.gpu.vram_gb))} GB VRAM` : ""}${c.region ? ` · ${CX_ESC(c.region)}` : ""}${c.quote && c.quote.usd_per_hour !== undefined ? ` · <b>$${CX_ESC(String(c.quote.usd_per_hour))}/hr</b> <span class="sub" style="margin:0;text-transform:none;letter-spacing:0">(${CX_ESC(c.quote.basis || "")}; no fee object minted)</span>` : ""}</div>` : ""}
      ${(c.custody_plan || {}).privacy === "marketplace_host_NOT_private" ? `<div class="sub" style="margin:2px 0 0;color:#e2b93d;text-transform:none;letter-spacing:0">marketplace host — NOT private custody</div>` : ""}
      ${c.evidence_mode === "fixture_evidence" ? `<div class="sub" style="margin:2px 0 0;color:#e2b93d;text-transform:none;letter-spacing:0">fixture_evidence — deterministic local fixture, NOT live supply</div>` : ""}
      ${c.evidence_mode === "simulator_evidence" ? `<div class="sub" style="margin:2px 0 0;color:#e2b93d;text-transform:none;letter-spacing:0">simulator_evidence — lifecycle harness (control plane simulated), NOT live supply</div>` : ""}
      ${c.evidence_mode === "live_evidence" ? `<div class="sub" style="margin:2px 0 0;color:#3c9d64;text-transform:none;letter-spacing:0">live quote${c.placement_eligible === true ? " · lifecycle eligible" : ""}</div>` : ""}
      ${c.lifecycle ? `<div class="sub" style="margin:2px 0 0;text-transform:none;letter-spacing:0">lifecycle: ${CX_ESC(c.lifecycle)}${c.execution_blocked_reason ? ` · ${CX_ESC(c.execution_blocked_reason)}` : ""}</div>` : ""}
      <div class="sub" style="margin:2px 0 0;text-transform:none;letter-spacing:0">expires ${CX_ESC(c.expires_at || "")} · <code>${CX_ESC(c.candidate_ref || "")}</code></div>
    </div>`;
  };
  return head + cands.map(card).join("");
}

function renderEnvironments(summary, classes, providerAccounts, venuesRes, policyRes, spendReconRes, storageArchivesRes, decisionsRes, failoverPlansRes) {
  summary = summary || {};
  providerAccounts = providerAccounts || {};
  const enc = encodeURIComponent;
  const envs = summary.environments || [];
  const head = `<h1>Environments</h1><p class="sub">Where work runs — environment lifecycle, readiness, services/ports/tasks, and substrate posture. Open a session or workbench, or jump to its run timeline.</p>`;
  const posture = `<h2>Substrate posture</h2><div class="chips">${(classes || []).map((c) => `<span class="pill ${c.enabled !== false ? "ok" : "muted"}">${CX_ESC(c.id || "")} · ${CX_ESC(c.substrate_class || "")}${c.enabled === false ? " · disabled" : ""}</span>`).join("")}</div>`;
  // Provider accounts — the BYO provider plane lives INSIDE Environments (canon: provider posture
  // is not a peer control plane). Durable ProviderAccount records: kind, health, credential
  // binding, preflight verdict — and the spend rule stated plainly: customer-borne, never markup.
  const pAccounts = providerAccounts.accounts || [];
  const paPill = (s) => s === "verified" ? "ok" : s === "revoked" ? "warn" : "muted";
  const paRows = pAccounts.map((a) => {
    const pf = a.preflight || {};
    const ep = a.endpoint || {};
    const awsPosture = a.kind === "aws" && (ep.region || ep.network)
      ? `${ep.region || "region unset"} · vpc: ${(ep.network && (ep.network.vpc_id || ep.network.posture_label)) || "default"}`
      : a.kind === "gcp" && (ep.project || ep.zone || ep.network)
      ? `${ep.project || "project unset"} · ${ep.zone || "zone unset"} · net: ${(ep.network && (ep.network.network || ep.network.posture_label)) || "default"}`
      : a.kind === "azure" && (ep.subscription_id || ep.location || ep.network)
      ? `${ep.subscription_id || "subscription unset"} · ${ep.location || "location unset"} · vnet: ${(ep.network && (ep.network.vnet || ep.network.posture_label)) || "default"}`
      : a.kind === "k8s" && (ep.cluster || ep.namespace)
      ? `${ep.cluster || "cluster unset"} · ns: ${ep.namespace || "default"}`
      : null;
    const target = a.kind === "baremetal_ssh" ? `${ep.user || "?"}@${ep.host || "?"}:${ep.port || 22}` : (awsPosture || ep.region || ep.endpoint || "—");
    return `<tr><td>${CX_ESC(a.display_name || "—")}<div style="color:#878a93;font-size:11px;margin-top:1px"><code>${CX_ESC(a.account_ref || "")}</code></div></td><td><span class="pill muted">${CX_ESC(a.kind || "")}</span></td><td><code style="font-size:11px">${CX_ESC(target)}</code></td><td><span class="pill ${a.credential_binding_ref ? "ok" : "muted"}">${a.credential_binding_ref ? "bound · sealed" : "unbound"}</span></td><td><span class="pill ${paPill(a.status)}">${CX_ESC(a.status || "")}</span>${pf.at ? `<div style="color:#878a93;font-size:11px;margin-top:1px">preflight ${pf.admit ? "admitted" : "refused"} · ${CX_ESC(pf.at)}</div>` : ""}</td><td><span class="pill muted">customer-borne</span></td></tr>`;
  }).join("");
  const paSection = `<div id="env-provider-accounts"><h2>Provider accounts</h2><p class="sub" style="margin:-4px 0 10px">Bring-your-own compute: durable provider accounts backing environment classes. ${CX_ESC(providerAccounts.spend_rule || "BYO provider spend is customer-borne; the hypervisor records, governs, estimates, and reconciles — it does not hide markup inside provider cost")}.</p>${pAccounts.length
    ? `<table><thead><tr><th>Account</th><th>Kind</th><th>Target</th><th>Credential</th><th>Status · preflight</th><th>Spend</th></tr></thead><tbody>${paRows}</tbody></table>`
    : `<div class="empty">No provider accounts yet. Create one via <code>POST /v1/hypervisor/provider-accounts</code> (kinds: baremetal_ssh · aws · gcp · k8s · vast · akash), bind a sealed credential, and preflight it — spend stays customer-borne.</div>`}</div>`;
  // Archive custody posture — sealed environment materials exported to storage backends.
  const archv = (storageArchivesRes || {}).archives || [];
  const archByEnv = {};
  for (const a of archv) { const k = a.environment_ref || "—"; (archByEnv[k] = archByEnv[k] || []).push(a); }
  const archRows = Object.entries(archByEnv).map(([envRef, list]) => {
    const impaired = list.filter((a) => a.status === "impaired").length;
    const backends = [...new Set(list.map((a) => a.backend_kind))].join(" · ");
    return `<tr><td><code>${CX_ESC(envRef)}</code></td><td>${list.length} sealed archive(s)</td><td>${CX_ESC(backends)}</td><td>${impaired ? `<span class="pill warn">⚠ ${impaired} impaired</span>` : `<span class="pill ok">available</span>`}</td><td><code style="font-size:10.5px">${CX_ESC((list[0].state_root || "").slice(0, 24))}…</code></td></tr>`;
  }).join("");
  const archSection = `<div id="env-archive-custody"><h2>Archive custody</h2><p class="sub" style="margin:-4px 0 10px">${CX_ESC((storageArchivesRes || {}).custody_rule || "storage availability is NOT restore truth — restore admits only after fetch + commitment hash + decrypt + admitted state_root all verify")}.</p>${archRows
    ? `<table><thead><tr><th>Environment</th><th>Archives</th><th>Backends</th><th>Availability</th><th>State root</th></tr></thead><tbody>${archRows}</tbody></table>`
    : `<div class="empty">No archived environment materials yet. Export a daemon-custody snapshot to a storage backend (local_disk · cas · ipfs · filecoin) to populate archive custody.</div>`}</div>`;
  const venueSection = renderPlacementVenues(venuesRes, policyRes, spendReconRes);
  const plDecisions = (decisionsRes || {}).decisions || [];
  const foPlans = (failoverPlansRes || {}).plans || [];
  const decRow = (d) => {
    const sel = d.selected || {};
    return `<tr><td><code style="font-size:10.5px">${CX_ESC(d.decision_ref || "")}</code></td><td>${CX_ESC(d.decision_mode || "")}</td><td>${CX_ESC(sel.provider_kind || "")} <code style="font-size:10px">${CX_ESC((d.selected_candidate_ref || "").slice(0, 34))}</code></td><td>${(d.alternatives_considered || []).length} alt · ${(d.rejected_candidates || []).length} rejected</td><td>${CX_ESC(((d.spend_posture || {}).routing_fee_eligibility) || "")} <span class="pill muted">no fee minted</span></td></tr>`;
  };
  const planRow = (pl) => `<tr><td><code style="font-size:10.5px">${CX_ESC(pl.plan_ref || "")}</code><div style="color:#878a93;font-size:11px">${CX_ESC(pl.environment_ref || "")}</div></td><td><span class="pill ${pl.readiness === "ready_daemon_custody" ? "ok" : "warn"}">${CX_ESC(pl.readiness || "")}</span></td><td><span class="pill ${pl.trigger_state === "armed" ? "warn" : pl.trigger_state === "triggered" ? "err" : "muted"}">${CX_ESC(pl.trigger_state || "manual")}</span></td><td><code style="font-size:10px">${CX_ESC((pl.state_root || "").slice(0, 24))}</code></td><td>${((pl.archive_refs || []).length)} archive(s)</td></tr>`;
  const decisionSection = (plDecisions.length || foPlans.length) ? `<div id="env-placement-decisions"><h2>Placement decisions & failover readiness</h2>
    <p class="sub" style="margin:-4px 0 10px">Explicit optimized-placement decisions (challengeable evidence: selected + alternatives + rejected with reason codes; never authority, never a fee) and per-environment failover readiness (restore truth = daemon-admitted state roots).</p>
    ${plDecisions.length ? `<table><thead><tr><th>Decision</th><th>Mode</th><th>Selected</th><th>Considered</th><th>Fee posture</th></tr></thead><tbody>${plDecisions.slice(0, 6).map(decRow).join("")}</tbody></table>` : ""}
    ${foPlans.length ? `<h3 style="margin:12px 0 8px">Failover readiness</h3><table><thead><tr><th>Plan</th><th>Readiness</th><th>Trigger</th><th>State root</th><th>Archives</th></tr></thead><tbody>${foPlans.slice(0, 6).map(planRow).join("")}</tbody></table>` : ""}
  </div>` : "";
  if (!(summary.total_matching || 0)) {
    return automationsShell("Environments", head + posture + venueSection + decisionSection + paSection + archSection + `<div class="empty">No active environments. Start a session or create an environment from a project to populate this.</div>`);
  }
  // Master-detail lifecycle console (source shape: providers-and-environments is a lifecycle
  // CONSOLE, not a flat list): rows select into a right-hand detail drawer that loads the full
  // daemon env record (component phases, lifecycle observations, ports/services/tasks, isolation,
  // connectivity, restore posture). The drawer fetches the real /v1 record client-side (proxied).
  const rows = envs.map((e, i) => {
    const id = e.id || "";
    return `<tr class="envrow" data-id="${CX_ESC(id)}" data-i="${i}" onclick="envOpen(this)">
      <td><code>${CX_ESC(id)}</code></td>
      <td><span class="pill ${envPhasePill(e.phase)}">${CX_ESC(e.phase || "—")}</span></td>
      <td>${CX_ESC(e.readiness_mode || "—")}</td>
      <td>${CX_ESC(e.project_id || "—")}</td>
      <td>${CX_ESC(e.environment_class_id || "—")} · ${CX_ESC(e.substrate || "")}</td>
      <td>${e.ports_count || 0}p · ${e.services_count || 0}s · ${e.tasks_count || 0}t</td>
      <td onclick="event.stopPropagation()"><a href="/details/${enc(id)}" target="_top">session</a> · <a href="/workspaces/${enc(id)}" target="_top">workbench</a> · <a href="/__ioi/run-timeline/env/${enc(id)}" target="_blank" rel="noopener">timeline ↗</a></td>
    </tr>`;
  }).join("");
  const pager = envPager("/__ioi/environments", summary);
  const table = `<h2>Active environments</h2><p class="sub" style="margin:-4px 0 12px">Select an environment to inspect its live lifecycle detail — component phases, readiness observations, ports/services/tasks, isolation and connectivity posture — read from the daemon record.</p>${pager}<div class="envwrap"><div><table><thead><tr><th>Environment</th><th>Phase</th><th>Readiness</th><th>Project</th><th>Class · substrate</th><th>Ports·Svc·Tasks</th><th>Open</th></tr></thead><tbody>${rows}</tbody></table>${pager}</div><div class="envdrawer" id="env-drawer"><div class="sub" style="margin:0">Select an environment to inspect its lifecycle detail.</div></div></div>`;
  const styles = `<style>.envwrap{display:grid;grid-template-columns:1fr 380px;gap:16px;align-items:start}.envdrawer{position:sticky;top:12px;border:1px solid #24262d;border-radius:12px;background:#0c0d10;padding:14px 16px;max-height:82vh;overflow:auto;font-size:12.5px}.envrow{cursor:pointer}.envrow.selrow{background:#15171c}.envrow:hover{background:#121317}.envd-k{color:#878a93;font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin:12px 0 4px;font-weight:600}.envd-comp{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #16181d}.envd-obs{border-left:2px solid #2a2c33;padding:2px 0 8px 10px;margin-left:3px}@media(max-width:1100px){.envwrap{grid-template-columns:1fr}.envdrawer{position:static}}</style>`;
  const script = `<script>
    function envEsc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
    function envPhaseCls(p){return p==='ready'||p==='running'?'ok':p==='failed'||p==='blocked'?'warn':'muted';}
    function envOpen(row){
      var id=row.getAttribute('data-id');var d=document.getElementById('env-drawer');
      document.querySelectorAll('.envrow').forEach(function(r){r.classList.toggle('selrow',r===row);});
      d.innerHTML='<div class="sub" style="margin:0">Loading '+envEsc(id)+'…</div>';
      fetch('/v1/hypervisor/environments/'+encodeURIComponent(id)).then(function(r){return r.json();}).then(function(j){
        var e=j.environment||j;var st=e.status||{};var comps=st.components||{};
        var h='<h3 style="margin:0 0 2px">'+envEsc(id)+'</h3><div class="meta" style="color:#878a93;margin-bottom:8px">'+envEsc(st.phase||'')+' · '+envEsc((st.provider&&st.provider.substrate_class)||e.spec&&e.spec.environment_class_id||'')+'</div>';
        if(st.blocked_reason){h+='<div class="pill warn">blocked: '+envEsc(st.blocked_reason)+'</div>';}
        h+='<div class="envd-k">Component phases</div>';
        var order=['recipe','provisioner','workspace_content','connectivity','sandbox','resource_isolation','secrets','model_mount','harness','automations','agent_work'];
        var keys=Object.keys(comps).sort(function(a,b){var ia=order.indexOf(a),ib=order.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib);});
        keys.forEach(function(k){var c=comps[k]||{};h+='<div class="envd-comp"><span>'+envEsc(k)+(c.detail?' <span style="color:#6b6e77">· '+envEsc(c.detail)+'</span>':'')+'</span><span class="pill '+envPhaseCls(c.phase)+'">'+envEsc(c.phase||'—')+'</span></div>';});
        var ports=st.ports||[];var svcs=st.services||[];var tasks=st.tasks||[];
        h+='<div class="envd-k">Ports · Services · Tasks</div>';
        if(ports.length||svcs.length||tasks.length){
          h+='<div>'+ports.map(function(p){return '<span class="pill muted">:'+envEsc(p.port||p.container_port||p)+(p.exposed?' exposed':'')+'</span>';}).join(' ')+'</div>';
          h+='<div style="margin-top:4px">'+svcs.map(function(s){return '<span class="pill muted">'+envEsc(s.name||s.id||'svc')+'</span>';}).join(' ')+'</div>';
        } else { h+='<div class="sub" style="margin:0">none exposed</div>'; }
        h+='<div class="envd-k">Isolation · connectivity</div><div>'+envEsc(st.isolation_claim||st.minimum_isolation||'process-scoped')+(st.connectivity_profile?' · '+envEsc(st.connectivity_profile.egress_policy||st.connectivity_profile.connectivity_profile_ref||''):'')+'</div>';
        var obs=(e.lifecycle_observations||[]).slice(-8).reverse();
        h+='<div class="envd-k">Lifecycle observations ('+(e.lifecycle_observations||[]).length+')</div>';
        h+=obs.map(function(o){return '<div class="envd-obs"><span class="pill '+envPhaseCls(o.condition_kind==='admitted'||o.condition_kind==='ready'?'ready':o.condition_kind)+'">'+envEsc(o.component||'')+' · '+envEsc(o.condition_kind||'')+'</span><div style="color:#9a9da6;margin-top:2px">'+envEsc(o.message||'')+'</div><div style="color:#5f626b;font-size:11px">'+envEsc(o.at||'')+'</div></div>';}).join('')||'<div class="sub" style="margin:0">—</div>';
        h+='<div class="envd-k">Open</div><div><a class="act" href="/workspaces/'+encodeURIComponent(id)+'" target="_top">Workbench</a> <a class="act ghost" href="/details/'+encodeURIComponent(id)+'" target="_top">Session</a> <a href="/__ioi/run-timeline/env/'+encodeURIComponent(id)+'" target="_blank" rel="noopener">timeline ↗</a></div>';
        h+='<details style="margin-top:10px"><summary class="sub" style="cursor:pointer">Raw record (advanced)</summary><pre style="white-space:pre-wrap;word-break:break-all;font-size:11px">'+envEsc(JSON.stringify(e,null,2).slice(0,4000))+'</pre></details>';
        d.innerHTML=h;
      }).catch(function(){d.innerHTML='<div class="ioi-ns-err">Could not load the environment record.</div>';});
    }
  </script>`;
  return automationsShell("Environments", styles + head + posture + venueSection + decisionSection + paSection + archSection + table + script);
}

// ---- GoalRun proof page — the multi-harness orchestration ladder as Run Timeline sections.
// Server-rendered from the daemon goal-run + events records (real refs only, nothing fabricated).
function renderGoalRunTimeline(g, invocations, verifications, events) {
  const enc = encodeURIComponent;
  const pill = (cls, label) => `<span class="pill ${cls}">${CX_ESC(label)}</span>`;
  const stPill = (st) => pill(st === "complete" || st === "completed" ? "ok" : (st === "blocked" || st === "failed") ? "warn" : "muted", st || "—");
  const grid = (pairs) => `<dl class="grid">${pairs.map(([k, v]) => `<dt>${CX_ESC(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const code = (v) => v ? `<code>${CX_ESC(String(v))}</code>` : "—";
  const topo = g.role_topology || {};
  const roles = `<div class="chips"><span class="chiplabel">Conductor</span><span class="pill ok">${CX_ESC(topo.conductor_ref || "")}</span></div>
    <div class="chips"><span class="chiplabel">Implementers</span>${(topo.implementer_refs || []).map((r) => `<span class="pill muted">${CX_ESC(r)}</span>`).join("")}</div>
    <div class="chips"><span class="chiplabel">Verifier</span><span class="pill muted">${CX_ESC(topo.verifier_ref || "")} · deterministic</span>${(topo.excluded_implementers || []).map((x) => `<span class="pill warn" title="${CX_ESC(x.reason_code || "")}">excluded: ${CX_ESC(x.harness || x.profile_ref || "")} (${CX_ESC(x.reason_code || "")})</span>`).join("")}</div>`;
  const verdictOf = (inv) => {
    const v = verifications.find((x) => x.harness_invocation_ref === inv.harness_invocation_id);
    return v ? v.verdict : "—";
  };
  const invRows = invocations.map((inv) => {
    const ir = inv.implementation_result || {};
    const evCount = events.filter((e) => e.harness_invocation_ref === inv.harness_invocation_id).length;
    return `<tr>
      <td><b>${CX_ESC(inv.role_key || "")}</b><div style="color:#878a93;font-size:11.5px">${CX_ESC(inv.harness || "")} · <code style="font-size:10.5px">${CX_ESC(inv.model_route_ref || "")}</code></div></td>
      <td>${stPill(inv.status)}</td>
      <td>${pill(verdictOf(inv) === "pass" ? "ok" : verdictOf(inv) === "fail" ? "warn" : "muted", "verify: " + verdictOf(inv))}</td>
      <td>${evCount} events</td>
      <td>${(ir.changed_files || []).map((f) => `<code>${CX_ESC(f)}</code>`).join(" ") || "—"}</td>
      <td>${inv.memory_projection_ref ? `<a href="/__ioi/intelligence/projections/${enc(String(inv.memory_projection_ref).replace("memory-projection://", ""))}/explain" title="explain this projection (vault truth → harness prompt)"><code style="font-size:10px">${CX_ESC(String(inv.memory_projection_ref).slice(0, 40))}…</code></a>` : "—"}</td>
      <td>${ir.transcript_run_ref ? `<a href="/__ioi/run-timeline/${enc(ir.transcript_run_ref)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}<div style="color:#5f626b;font-size:10.5px">${CX_ESC((ir.state_root || "").slice(0, 22))}</div></td>
    </tr>`;
  }).join("");
  const artifacts = invocations.flatMap((inv) => ((inv.implementation_result || {}).candidate_artifact_refs || []).map((r) => `<li><code>${CX_ESC(r)}</code> <span class="pill muted">${CX_ESC(inv.role_key || "")}</span></li>`)).join("");
  const rec = g.reconciliation_ref ? null : null;
  const recSection = g.reconciliation_ref
    ? grid([
        ["Result ref", code(g.reconciliation_ref)],
        ["Final files", (g.final_changed_files || []).map((f) => `<code>${CX_ESC(f)}</code>`).join(" ") || "—"],
        ["Run state", `${stPill(g.status)} ${pill("muted", g.continuation_state || "")}`],
      ])
    : `<div class="empty">Not reconciled yet — candidate artifacts stay isolated until an admitted reconciliation.</div>`;
  const briefs = (g.task_briefs || []).map((b) => `<li><code>${CX_ESC(b.task_brief_id || "")}</code> — ${CX_ESC(b.objective_class || "")} · output contract: changed_files ${b.output_contract && b.output_contract.changed_files_required ? "required" : "optional"}</li>`).join("");
  const projRefs = invocations.map((inv) => inv.memory_projection_ref).filter(Boolean);
  const proof = grid([
    ["GoalRun ref (internal)", code(g.goal_ref)],
    ["Launch policy", g.policy_ref ? code(g.policy_ref) : "—"],
    ["Memory projections", projRefs.length ? projRefs.map((r) => `<a href="/__ioi/intelligence/projections/${enc(String(r).replace("memory-projection://", ""))}/explain"><code style="font-size:10.5px">${CX_ESC(r)}</code></a>`).join("<br>") : "—"],
    ["Admission", code((g.admission || {}).admission_id)],
    ["Admission receipts", (((g.admission || {}).receipt_refs) || []).map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") || "—"],
    ["Capability lease", code(g.capability_lease_ref)],
    ["Verifier evidence", (g.verification_refs || []).map((r) => `<code style="font-size:10.5px">${CX_ESC(r)}</code>`).join("<br>") || "—"],
    ["Ledger", `<a href="/__ioi/work-ledger">proof stream →</a>`],
  ]);
  const inner = `<p><a href="/__ioi/work-ledger">← Work Ledger</a></p>
    <h1>🎯 IOI Agent coordination ${stPill(g.status)}</h1>
    <p class="sub">${CX_ESC(g.orchestration_policy || "")} · ${CX_ESC(g.active_loop_phase || "")} · target <code>${CX_ESC(g.target_session_ref || "")}</code> · <span title="internal orchestration object">GoalRun <code>${CX_ESC(g.goal_run_id || "")}</code></span></p>
    <h2>Goal</h2><div class="grid" style="display:block;padding:14px 16px">${CX_ESC(g.normalized_goal || "")}</div>
    <h2>Roles</h2>${roles}
    <h2>Task briefs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the durable contract (rendered prompts are adapter-private)</span></h2><ul>${briefs || "<li>—</li>"}</ul>
    <h2>Invocations (${invocations.length})</h2>${invocations.length ? `<table><thead><tr><th>Role</th><th>Status</th><th>Verifier</th><th>Events</th><th>Changed files</th><th>Memory projection</th><th>Proof</th></tr></thead><tbody>${invRows}</tbody></table>` : `<div class="empty">Not started.</div>`}
    <h2>Candidate artifacts <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— isolated per implementer until reconciliation</span></h2><ul>${artifacts || "<li>—</li>"}</ul>
    <h2>Reconciliation</h2>${recSection}
    ${(g.blockers || []).length ? `<h2>Blockers (explicit partial)</h2><ul>${g.blockers.map((b) => `<li><span class="pill warn">${CX_ESC(b.reason_code || "")}</span> ${CX_ESC(b.message || "")}</li>`).join("")}</ul>` : ""}
    <h2>Proof</h2>${proof}`;
  return automationsShell(`GoalRun ${g.goal_run_id || ""}`, inner);
}

// Workbench GoalRuns panel — orchestrated multi-harness work for the estate's sessions
// (role topology, invocation posture, final result, proof link). Additive to the grafted
// master-detail shell; honest empty state.
function renderWorkbenchGoalRuns(goalRuns) {
  const enc = encodeURIComponent;
  const rows = (goalRuns || []).slice(0, 10).map((g) => {
    const topo = g.role_topology || {};
    const st = g.status || "draft";
    return `<tr>
      <td>${CX_ESC(String(g.normalized_goal || "").slice(0, 64))}<div style="color:#878a93;font-size:11px"><code>${CX_ESC(g.goal_run_id || "")}</code> → <code>${CX_ESC(g.target_session_ref || "")}</code></div></td>
      <td><span class="pill ${st === "complete" ? "ok" : st === "blocked" ? "warn" : "muted"}">${CX_ESC(st)}</span>${g.partial_result ? ' <span class="pill warn">partial</span>' : ""}</td>
      <td>${(topo.implementer_refs || []).map((r) => `<span class="pill muted">${CX_ESC(String(r).replace("harness-profile:hp_", ""))}</span>`).join(" ")}</td>
      <td>${(g.final_changed_files || []).map((f) => `<code>${CX_ESC(f)}</code>`).join(" ") || "—"}</td>
      <td><a href="/__ioi/run-timeline/goal-run/${enc(g.goal_run_id || "")}" target="_blank" rel="noopener">proof ↗</a></td>
    </tr>`;
  }).join("");
  const body = (goalRuns || []).length
    ? `<table><thead><tr><th>Goal</th><th>Status</th><th>Implementers</th><th>Final files</th><th>Proof</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div class="empty">No IOI Agent runs yet. Start one from New Session — IOI Agent coordinates the harnesses under one governed run.</div>`;
  return `<h2 id="goal-runs">IOI Agent runs</h2><p class="sub" style="margin:-4px 0 12px">IOI Agent–coordinated work — parallel implementer cells over isolated candidate workspaces, verifier-admitted reconciliation into the session workspace. GoalRun refs are the internal proof objects.</p>${body}`;
}

// ---- Workbench — a LAUNCHER into an environment's live console (files/terminal/ports/tasks).
// Reads the daemon env-summary projection (paged); "Open Workbench" navigates top-level to
// /workspaces/:id (the real console; NOT iframed here). No owned terminal/editor.
function renderWorkbench(summary, editorTargets, sessionsRes, goalRuns) {
  summary = summary || {};
  const enc = encodeURIComponent;
  const envs = summary.environments || [];
  const targets = (editorTargets && editorTargets.targets) || [];
  const vb = targets.find((t) => t.target_id === "vscode-browser");
  const vbOpenable = vb?.open_posture?.openable === true;
  const head = `<h1>Workbench</h1><p class="sub">Enter an environment's live console — files, terminal, ports, and tasks. Pick an active environment to get to work, or open its session or run timeline. <a href="/__ioi/environments">Environment posture →</a> · <a href="/__ioi/code">Code Repositories →</a></p>`;
  // Editor targets — the daemon registry with PROBED open posture. An editor that cannot open on
  // this host renders disabled WITH the probe's reason (never hidden, never a dead link).
  const etRows = targets.map((t) => {
    const op = t.open_posture || {};
    const kind = op.open_kind === "in_shell_surface" ? `<span class="pill ok">in-shell surface</span>`
      : op.open_kind === "daemon_hosted_browser_ide" ? `<span class="pill ok">daemon-hosted browser IDE</span>`
      : `<span class="pill muted">external host adapter</span>`;
    const openPill = op.openable
      ? `<span class="pill ok">openable</span>`
      : `<span class="pill warn" title="${CX_ESC(JSON.stringify(op.probe?.evidence || {}))}">not openable — ${CX_ESC(op.probe?.evidence?.note || (op.probe?.evidence?.required_binary ? `${op.probe.evidence.required_binary} not on PATH` : "probe failed"))}</span>`;
    return `<tr>
      <td><b>${CX_ESC(t.profile?.displayName || t.target_id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(t.target_id)}</code></div></td>
      <td>${kind}</td>
      <td>${openPill}</td>
      <td style="font-size:11.5px;color:#878a93">${CX_ESC(op.lease_posture || "—")}</td>
    </tr>`;
  }).join("");
  const editorsPanel = targets.length
    ? `<h2 id="editor-targets">Editors</h2><p class="sub" style="margin:-4px 0 12px">The daemon editor-target registry — every way to open a workspace, with its probed open posture and lease/revocation contract. Only an <b>openable</b> target is offered on environments below.</p><table><thead><tr><th>Editor</th><th>Open kind</th><th>Open posture</th><th>Lease / revocation</th></tr></thead><tbody>${etRows}</tbody></table>`
    : "";
  if (!(summary.total_matching || 0)) {
    return automationsShell("Workbench", head + editorsPanel + `<div class="empty">No active environments to open. Start a session or create an environment from a project, then open its workbench here.</div>` + renderWorkbenchSessions(sessionsRes) + renderWorkbenchGoalRuns(goalRuns));
  }
  // Master-detail working shell (source shape: Workbench is the composition container, not a flat
  // launcher): environment rows select into a detail pane composed ENTIRELY from the three
  // projections already fetched — the env slice, the sessions bound to it (admitted harness
  // bindings), and the probed editor-target open matrix. No fabricated IDE panes: files/terminal/
  // ports live in the real console this pane launches into.
  const rows = envs.map((e, i) => {
    const id = e.id || "";
    const vbLink = vbOpenable
      ? ` <a class="act ghost" href="/__ioi/editor/open?environmentId=${enc(id)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">VS Code Browser ↗</a>`
      : ` <span class="pill muted" title="pinned openvscode runtime not installed on this host — the open lane is fail-closed">VS Code Browser unavailable</span>`;
    return `<tr class="wlrow wbrow" data-i="${i}">
      <td><code>${CX_ESC(id)}</code><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px">${CX_ESC(e.project_id || "—")} · ${CX_ESC(e.environment_class_id || "")}</div></td>
      <td><span class="pill ${envPhasePill(e.phase)}">${CX_ESC(e.phase || "—")}</span> ${CX_ESC(e.readiness_mode || "")}</td>
      <td>${e.ports_count || 0}p · ${e.services_count || 0}s · ${e.tasks_count || 0}t</td>
      <td onclick="event.stopPropagation()"><a class="act" href="/workspaces/${enc(id)}" target="_top">Open Workbench</a>${vbLink} <a class="act ghost" href="/details/${enc(id)}" target="_top">Session</a> <a href="/__ioi/run-timeline/env/${enc(id)}" target="_blank" rel="noopener">timeline ↗</a></td>
    </tr>`;
  }).join("");
  const pager = envPager("/__ioi/workbench", summary);
  const slimEnvs = envs.map((e) => ({
    id: e.id || "", phase: e.phase || "", readiness_mode: e.readiness_mode || "", project_id: e.project_id || "",
    environment_class_id: e.environment_class_id || "", substrate: e.substrate || "",
    ports_count: e.ports_count || 0, services_count: e.services_count || 0, tasks_count: e.tasks_count || 0,
  }));
  const slimSessions = ((sessionsRes && sessionsRes.sessions) || []).map((s) => ({
    session_ref: s.session_ref || "", lifecycle_state: s.lifecycle_state || "", created_at: s.created_at || "",
    project_ref: s.project_ref || "", env_id: String(s.environment_ref || "").replace(/^environment:/, ""),
    harness: (s.harness_binding && s.harness_binding.profile_ref) ? {
      harness: s.harness_binding.harness || "harness", model_route_ref: s.harness_binding.model_route_ref || "",
      profile_ref: s.harness_binding.profile_ref || "", admission_id: s.harness_binding.admission_id || "",
    } : null,
  }));
  const slimTargets = targets.map((t) => {
    const op = t.open_posture || {};
    return {
      target_id: t.target_id, name: (t.profile && t.profile.displayName) || t.target_id,
      open_kind: op.open_kind || "", openable: op.openable === true,
      reason: op.openable ? "" : ((op.probe && op.probe.evidence && (op.probe.evidence.note || (op.probe.evidence.required_binary ? op.probe.evidence.required_binary + " not on PATH" : ""))) || "probe failed"),
      lease_posture: op.lease_posture || "",
    };
  });
  const drawer = `<div class="wldrawer" id="wb-drawer"><div class="sub" style="margin:0">Select an environment to compose its working context — bound sessions, admitted harness bindings, and every editor lane that can open it.</div></div>`;
  const script = `<script>
    var WB_ENVS=${JSON.stringify(slimEnvs)};var WB_SESS=${JSON.stringify(slimSessions)};var WB_TGT=${JSON.stringify(slimTargets)};
    function wbEsc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
    function wbRow(k,v){return v?'<div class="wlk">'+wbEsc(k)+'</div><div class="wlv">'+v+'</div>':'';}
    document.querySelectorAll('.wbrow').forEach(function(tr){tr.addEventListener('click',function(){
      var e=WB_ENVS[parseInt(tr.getAttribute('data-i'),10)];if(!e)return;
      document.querySelectorAll('.wbrow').forEach(function(x){x.classList.toggle('selrow',x===tr);});
      var d=document.getElementById('wb-drawer');var id=e.id;
      var h='<h3><code>'+wbEsc(id)+'</code> <span class="pill '+(e.phase==='running'?'ok':(e.phase==='failed'||e.phase==='blocked')?'warn':'muted')+'">'+wbEsc(e.phase)+'</span></h3>';
      h+='<h4>Context</h4><div class="wlgrid">'+wbRow('Project',wbEsc(e.project_id))+wbRow('Class',wbEsc(e.environment_class_id)+(e.substrate?' · '+wbEsc(e.substrate):''))+wbRow('Readiness',wbEsc(e.readiness_mode))+wbRow('Surface',e.ports_count+' ports · '+e.services_count+' services · '+e.tasks_count+' tasks')+'</div>';
      var sess=WB_SESS.filter(function(s){return s.env_id===id;});
      h+='<h4>Sessions bound ('+sess.length+')</h4>';
      h+=sess.length?sess.map(function(s){return '<div style="border:1px solid #1b1d23;border-radius:8px;padding:8px;margin:0 0 6px"><div><code>'+wbEsc(s.session_ref)+'</code> <span class="pill muted">'+wbEsc(s.lifecycle_state)+'</span></div><div style="color:#878a93;font-size:11.5px;margin-top:3px">'+(s.harness?('<span class="pill ok">'+wbEsc(s.harness.harness)+'</span> <code style="font-size:10.5px">'+wbEsc(s.harness.model_route_ref)+'</code><div style="margin-top:2px" title="'+wbEsc(s.harness.admission_id)+'">admitted harness binding</div>'):'execute-time default harness')+'</div></div>';}).join(''):'<div class="sub" style="margin:0">No session bound to this environment yet.</div>';
      h+='<h4>Open with</h4>'+WB_TGT.map(function(t){
        if(t.target_id==='workbench-native'){return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #16181d"><span>'+wbEsc(t.name)+'</span><a class="act" style="padding:4px 10px" href="/workspaces/'+encodeURIComponent(id)+'" target="_top">Open</a></div>';}
        if(t.target_id==='vscode-browser'&&t.openable){return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #16181d"><span>'+wbEsc(t.name)+'</span><a class="act ghost" style="padding:4px 10px" href="/__ioi/editor/open?environmentId='+encodeURIComponent(id)+'" target="_blank" rel="noopener">Open ↗</a></div>';}
        return '<div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #16181d"><span>'+wbEsc(t.name)+'</span>'+(t.openable?'<span class="pill ok" title="opens from the environment session surface">'+wbEsc(t.open_kind||'openable')+'</span>':'<span class="pill muted" title="'+wbEsc(t.reason)+'">not openable</span>')+'</div>';
      }).join('');
      h+='<h4>Proof</h4><div class="wlgrid">'+wbRow('Run Timeline','<a href="/__ioi/run-timeline/env/'+encodeURIComponent(id)+'" target="_blank" rel="noopener">open transcript ↗</a>')+wbRow('Session detail','<a href="/details/'+encodeURIComponent(id)+'" target="_top">open →</a>')+'</div>';
      d.innerHTML=h;
    });});
  </script>`;
  const table = `${pager}<div class="wlwrap"><div><table><thead><tr><th>Environment</th><th>Phase · readiness</th><th>Ports·Svc·Tasks</th><th>Open</th></tr></thead><tbody>${rows}</tbody></table>${pager}</div>${drawer}</div>`;
  return automationsShell("Workbench", head + editorsPanel + table + renderWorkbenchSessions(sessionsRes) + renderWorkbenchGoalRuns(goalRuns) + script);
}

// Sessions panel — the daemon session records with their ADMITTED harness bindings (selection is
// session truth, not UI state). A session without a binding says so plainly (execute-time default).
function renderWorkbenchSessions(sessionsRes) {
  const sessions = (sessionsRes && sessionsRes.sessions) || [];
  if (!sessions.length) return "";
  const rows = sessions.slice(0, 12).map((s) => {
    const hb = s.harness_binding;
    const envId = String(s.environment_ref || "").replace(/^environment:/, "");
    const binding = hb && hb.profile_ref
      ? `<span class="pill ok">${CX_ESC(hb.harness || "harness")}</span> <code style="font-size:11px">${CX_ESC(hb.model_route_ref || "")}</code><div class="meta" style="color:#878a93;font-size:11px;margin-top:2px" title="${CX_ESC(hb.admission_id || "")}">admitted · <code>${CX_ESC(String(hb.admission_id || "").slice(0, 58))}…</code></div>`
      : `<span class="pill muted" title="no harness binding recorded at create; execution uses the daemon's Lane A default">execute-time default</span>`;
    return `<tr>
      <td><code>${CX_ESC(s.session_ref || "")}</code><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px">${CX_ESC(s.project_ref || "—")} · ${CX_ESC(s.created_at || "")}</div></td>
      <td><span class="pill muted">${CX_ESC(s.lifecycle_state || "—")}</span></td>
      <td>${binding}</td>
      <td>${envId ? `<a class="act ghost" href="/workspaces/${encodeURIComponent(envId)}" target="_top">Open</a>` : "—"}</td>
    </tr>`;
  }).join("");
  return `<h2 id="sessions">Sessions</h2><p class="sub" style="margin:-4px 0 12px">Daemon session records (newest first) with their admitted harness bindings — the selection made at create is receipted daemon truth, shown here, never UI-only state.</p><table><thead><tr><th>Session</th><th>Lifecycle</th><th>Harness binding</th><th>Open</th></tr></thead><tbody>${rows}</tbody></table>`;
}

// ---- Agent Studio — the live agent INVENTORY + CONFIGURATION + ACTIVITY cockpit (estate #3).
// Daemon-backed and honest: agents from /v1/agents, the platform harness adapters from
// /v1/hypervisor/agent-runner-profiles, model routing from /v1/model-mount/{routes,providers},
// and recent activity from /v1/hypervisor/agentops/conversations + /agent-run-transcripts. It does
// NOT fabricate Foundry/marketplace/package/training state, and it does NOT claim a per-agent
// conversation/run join the daemon does not record — that activity is labelled workspace-wide.
const agentShort = (id) => { const m = String(id || "").match(/^agent_([0-9a-f]{8})/); return m ? `agent_${m[1]}` : (id || "agent"); };
const pickv = (o, ...keys) => { for (const k of keys) { if (o && o[k] != null && o[k] !== "") return o[k]; } return undefined; };
// ---- Model routes (the daemon REGISTRY — declared routes, honest availability posture, admitted
// lifecycle controls). Execute-vs-admit is a visible product state: an `active` route can still be
// `credentials_missing`/`unreachable` — the lifecycle and availability chips render independently.
// Every effectful control opens a confirm panel naming the admission, the receipt it will mint,
// and the rollback posture BEFORE firing.
function renderModelRouteRegistry(modelRoutes) {
  const enc = encodeURIComponent;
  modelRoutes = Array.isArray(modelRoutes) ? modelRoutes : [];
  const availPill = (r) => {
    const av = r.availability || {};
    const state = av.state || "declared";
    const cls = state === "available" ? "ok" : state === "declared" ? "muted" : "warn";
    const stale = av.stale ? ` <span class="pill muted">stale</span>` : "";
    return `<span class="pill ${cls}">${CX_ESC(state)}</span>${stale}`;
  };
  const mrConfirm = (r, act, label, admission, rollback, danger) => {
    const rid = r.route_id || "";
    return `<details class="mrc"><summary class="act ghost${danger ? " danger" : ""}">${label}</summary><div class="mrcbody">
      <div class="sub" style="margin:0 0 6px">${admission}<br>Receipt: <code>agentgres://model-route-receipt/*</code> will be minted; the op records a transcript with a state_root.<br>Rollback: ${rollback}</div>
      <form class="inline" method="post" action="/__ioi/agent-studio/model-routes/${enc(rid)}/${act}"><button class="act${danger ? " danger" : ""}" type="submit">Confirm ${label}</button></form>
    </details>`;
  };
  const mrRows = modelRoutes.map((r) => {
    const lc = (r.lifecycle || {}).status || "declared";
    const pb = r.provider_binding || {};
    const probeDesc = pb.transport === "openai_compatible"
      ? "No admission (evidence-gathering only); POSTURE-ONLY — reports whether the declared credential env key resolves. The daemon never sends a secret to the route's base_url, so this transport never reports <code>available</code>."
      : "No admission (evidence-gathering only); the live upstream is asked for its real catalog.";
    const controls = [
      mrConfirm(r, "probe", "Probe", probeDesc, "none needed — probing only updates availability evidence"),
      lc === "active"
        ? mrConfirm(r, "disable", "Disable", `Admission: <code>disable_route</code> under <code>scope:model.route.mutate</code> (relaxed lane).`, "re-enable via the admitted <code>enable_route</code> lane", true)
        : mrConfirm(r, "enable", "Enable", `Admission: <code>enable_route</code> under <code>scope:model.route.mutate</code> + custody + privacy posture refs (planner-validated, fail-closed).`, "disable via the admitted <code>disable_route</code> lane"),
      r.default_route ? "" : mrConfirm(r, "select-default", "Set default", `Admission: <code>select_route</code> under <code>scope:model.route.mutate</code>; the previous default is atomically cleared (exactly-one invariant).`, "select the previous default again"),
    ].filter(Boolean).join(" ");
    return `<tr>
      <td><b>${CX_ESC(r.display_name || r.route_id || "—")}</b>${r.default_route ? ` <span class="pill ok">default</span>` : ""}<div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(r.route_ref || "")}</code> · ${CX_ESC(r.origin || "")}</div></td>
      <td><code>${CX_ESC((r.model || {}).model_id || "—")}</code></td>
      <td><span class="pill muted">${CX_ESC(pb.transport || "—")}</span> <span class="pill muted">${CX_ESC(pb.provider_kind || "—")}</span><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px">${CX_ESC(pb.base_url || "")}</div></td>
      <td><span class="pill ${lc === "active" ? "ok" : "muted"}">${CX_ESC(lc)}</span></td>
      <td>${availPill(r)}</td>
      <td><span class="pill muted">${CX_ESC(r.credential_posture || "—")}</span></td>
      <td>${controls}</td>
    </tr>`;
  }).join("");
  const mrStyles = `<style>.mrc{display:inline-block;position:relative}.mrc summary{list-style:none;cursor:pointer}.mrc summary::-webkit-details-marker{display:none}.mrc[open] .mrcbody{position:absolute;right:0;z-index:30;min-width:340px;background:#15171c;border:1px solid #3a82f6;border-radius:10px;padding:12px;margin-top:6px;box-shadow:0 8px 28px rgba(0,0,0,.5)}</style>`;
  return `<h2 id="model-routes">Model routes</h2><p class="sub" style="margin:-4px 0 12px">The daemon model-route registry — declared routes with probed availability. A route is <b>available</b> only when a live probe matched its model on the real upstream; enable/disable/default are planner-admitted, receipted mutations.</p>${mrStyles}
    ${modelRoutes.length ? `<table><thead><tr><th>Route</th><th>Model</th><th>Binding</th><th>Lifecycle</th><th>Availability</th><th>Credential</th><th>Controls</th></tr></thead><tbody>${mrRows}</tbody></table>` : `<div class="empty">No model routes registered. The daemon seeds the env-default route on first read of <code>/v1/hypervisor/model-routes</code>.</div>`}`;
}

// ---- IOI Agent launch policies — durable routing/admission preference envelopes (the saved
// strategy presets behind New Session). Seeded defaults are PROTECTED (clone to customize);
// every policy is receipt-required. Registry-card shape with confirm-style actions — the same
// grafted pattern as the harness/model registries, not a generic CRUD table.
// ---- IOI Agent intelligence cockpit (Agent Studio) — portable memory, skills, and agent/
// policy-scoped connector context. Ownership boundaries: Developer & Integrations OWNS
// connectors (vault/secrets never appear here); Automations OWNS automations (affinities are a
// readiness section under Launch policies, never a sibling tab).
function intelStatusPill(st) { return `<span class="pill ${st === "active" ? "ok" : st === "revoked" ? "warn" : "muted"}">${CX_ESC(st || "")}</span>`; }
function intelActions(family, id, status) {
  const enc = encodeURIComponent;
  const acts = [];
  if (status === "active") {
    acts.push(`<form class="inline" method="post" action="/__ioi/agent-studio/intel/${family}/${enc(id)}/archive"><button class="act ghost" type="submit">Archive</button></form>`);
    if (family === "memory") acts.push(`<form class="inline" method="post" action="/__ioi/agent-studio/intel/${family}/${enc(id)}/revoke" onsubmit="return confirm('Revoke this entry? It will be excluded from every future projection.')"><button class="act danger" type="submit">Revoke</button></form>`);
  } else {
    acts.push(`<form class="inline" method="post" action="/__ioi/agent-studio/intel/${family}/${enc(id)}/activate"><button class="act" type="submit">Reactivate</button></form>`);
  }
  return acts.join(" ");
}
function renderIntelConnectors(intel) {
  const connectors = intel.connectors || [];
  const leases = intel.leases || [];
  const entries = (intel.entries || []).filter((e) => e.entry_kind === "connector_derived");
  const rows = connectors.map((c) => {
    const bound = c.auth_posture === "token-lease:bound" || c.auth_posture === "open" || c.auth_posture === "local-none";
    const myLeases = leases.filter((l) => String(l.backing_provider || "").includes(c.connector_id) || String(l.resource_refs || "").includes(c.connector_id)).length;
    const derived = entries.filter((e) => (e.connector_refs || []).some((r) => String(r).includes(c.connector_id))).length;
    return `<tr><td><b>${CX_ESC(c.name || c.service)}</b><div style="color:#878a93;font-size:11px"><code>${CX_ESC(c.connector_id)}</code></div></td>
      <td><span class="pill ${bound ? "ok" : "warn"}">${bound ? "lease-ready" : "needs auth"}</span></td>
      <td>${(c.allowed_tools || []).length || (c.kind === "mcp" ? "discovered on connect" : 0)}</td>
      <td>${myLeases}</td>
      <td>${derived ? `<span class="pill ok">${derived} context entr${derived > 1 ? "ies" : "y"}</span>` : "—"}</td></tr>`;
  }).join("");
  return `<h2 id="connectors">Connector access <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— agent/policy-scoped view; connectors are owned and managed in <a href="/__ioi/connections">Developer & Integrations →</a></span></h2>
    <p class="sub" style="margin:-4px 0 12px">What the agent substrate can reach through capability leases, and the connector-derived context memory carries. Vault credentials never appear here.</p>
    ${connectors.length ? `<table><thead><tr><th>Connector</th><th>Lease posture</th><th>Tools</th><th>Leases issued</th><th>Derived context</th></tr></thead><tbody>${rows}</tbody></table>` : `<div class="empty">No connectors registered yet.</div>`}`;
}
function renderIntelSkills(skills) {
  const cards = skills.map((sk) => `<div class="card"><div class="main">
    <div class="name">${CX_ESC(sk.title || sk.skill_id)} ${intelStatusPill(sk.status)}</div>
    <div class="meta"><code>${CX_ESC(sk.skill_ref || "")}</code> · ${CX_ESC(sk.description || "")}</div>
    <div class="chips" style="margin:6px 0 0">${(sk.compatible_harness_refs || []).map((r) => `<span class="pill muted">${CX_ESC(String(r).replace("harness-profile:hp_", ""))}</span>`).join("") || '<span class="pill muted">all harnesses</span>'}${(sk.connector_requirements || []).map((r) => `<span class="pill warn">needs ${CX_ESC(String(r))}</span>`).join("")}</div>
    </div><div>${intelActions("skills", sk.skill_id, sk.status)}</div></div>`).join("");
  const form = `<details style="margin-top:12px"><summary class="act ghost" style="display:inline-block;cursor:pointer">+ New skill</summary>
    <form method="post" action="/__ioi/agent-studio/intel/skills" style="margin-top:10px;max-width:600px">
      <div class="field"><label>Title</label><input name="title" required></div>
      <div class="field"><label>Description / procedure</label><textarea name="body" rows="3"></textarea></div>
      <div class="row"><button class="act" type="submit">Create skill</button></div>
    </form></details>`;
  return `<h2 id="skills">Skills</h2><p class="sub" style="margin:-4px 0 12px">Reusable capability/procedure records — portable across harness and model swaps; projections deliver them as scoped summaries.</p>${skills.length ? cards : `<div class="empty">No skills yet.</div>`}${form}`;
}
const INTEL_MEMORY_CATS = [["", "All"], ["concept", "Concepts"], ["entity", "Entities"], ["workstream", "Workstreams"], ["note", "Notes"], ["preference", "Preferences"], ["correction", "Corrections"], ["connector_derived", "Connector-derived"]];
function renderIntelMemory(entries, proposals, projections, review) {
  const chips = INTEL_MEMORY_CATS.map(([v, l]) => `<button class="chip" data-memcat="${v}" onclick="memCat(this)">${l}</button>`).join("");
  const rows = entries.map((e) => `<div class="card memcard" data-kind="${CX_ESC(e.entry_kind || "")}" data-blob="${CX_ESC(((e.title || "") + " " + (e.body || "") + " " + (e.tags || []).join(" ")).toLowerCase())}"><div class="main">
    <div class="name">${CX_ESC(e.title || e.entry_id)} ${intelStatusPill(e.status)}<span class="pill ${e.quality_state === "accepted" || !e.quality_state ? "ok" : e.quality_state === "disputed" || e.quality_state === "superseded" ? "warn" : "muted"}">${CX_ESC(e.quality_state || "accepted")}</span><span class="pill ${e.sensitivity === "secret" ? "warn" : e.sensitivity === "private" ? "warn" : "muted"}">${CX_ESC(e.sensitivity || "normal")}</span><span class="pill muted">${CX_ESC(e.entry_kind || "")}</span></div>
    <div class="meta"><code>${CX_ESC(e.entry_ref || "")}</code>${e.sensitivity === "secret" ? " · <i>body never projected</i>" : e.body ? ` · ${CX_ESC(String(e.body).slice(0, 96))}` : ""}</div>
    <div class="chips" style="margin:6px 0 0">${(e.compatible_harness_refs || []).map((r) => `<span class="pill muted">${CX_ESC(String(r).replace("harness-profile:hp_", ""))} only</span>`).join("")}${(e.connector_refs || []).map((r) => `<span class="pill muted">via ${CX_ESC(String(r).slice(0, 28))}</span>`).join("")}${e.expires_at ? `<span class="pill warn">expires ${CX_ESC(e.expires_at)}</span>` : ""}${e.supersedes_ref ? `<span class="pill muted">supersedes ${CX_ESC(String(e.supersedes_ref).slice(-14))}</span>` : ""}${e.superseded_by_ref ? `<span class="pill warn">superseded by ${CX_ESC(String(e.superseded_by_ref).slice(-14))}</span>` : ""}${(e.lifecycle_history || []).length ? `<span class="pill muted" title="${CX_ESC((e.lifecycle_history || []).map((h) => `${h.transition}: ${h.reason}`).join(" · "))}">${(e.lifecycle_history || []).length} transition${(e.lifecycle_history || []).length > 1 ? "s" : ""} · receipted</span>` : ""}</div>
    ${e.status === "active" ? `<div class="row" style="margin:6px 0 0;gap:6px">${e.quality_state === "candidate" || e.quality_state === "disputed" ? `<form class="inline" method="post" action="/__ioi/agent-studio/intel/memory/${encodeURIComponent(e.entry_id)}/lifecycle"><input type="hidden" name="transition" value="promote"><input type="hidden" name="reason" value="operator promoted from Studio"><button class="act" style="padding:4px 10px;font-size:11.5px" type="submit">Promote</button></form>` : ""}${e.quality_state !== "disputed" && e.quality_state !== "superseded" ? `<form class="inline" method="post" action="/__ioi/agent-studio/intel/memory/${encodeURIComponent(e.entry_id)}/lifecycle"><input type="hidden" name="transition" value="dispute"><input type="hidden" name="reason" value="operator disputed from Studio"><button class="act ghost" style="padding:4px 10px;font-size:11.5px" type="submit">Dispute</button></form><form class="inline" method="post" action="/__ioi/agent-studio/intel/memory/${encodeURIComponent(e.entry_id)}/lifecycle"><input type="hidden" name="transition" value="mark_stale"><input type="hidden" name="reason" value="operator marked stale from Studio"><button class="act ghost" style="padding:4px 10px;font-size:11.5px" type="submit">Mark stale</button></form>` : ""}</div>` : ""}
    </div><div>${intelActions("memory", e.entry_id, e.status)}</div></div>`).join("");
  const form = `<details style="margin-top:12px"><summary class="act ghost" style="display:inline-block;cursor:pointer">+ New memory entry</summary>
    <form method="post" action="/__ioi/agent-studio/intel/memory" style="margin-top:10px;max-width:640px">
      <div class="field"><label>Title</label><input name="title" required></div>
      <div class="field"><label>Body</label><textarea name="body" rows="2"></textarea></div>
      <div class="two">
        <div class="field"><label>Kind</label><select name="entry_kind">${INTEL_MEMORY_CATS.slice(1).map(([v]) => `<option value="${v}">${v}</option>`).join("")}<option value="fact">fact</option><option value="instruction">instruction</option></select></div>
        <div class="field"><label>Sensitivity</label><select name="sensitivity"><option value="normal">normal</option><option value="private">private — projected only when policy allows</option><option value="secret">secret — never projected</option></select></div>
      </div>
      <div class="two">
        <div class="field"><label>Connector refs (csv, for connector-derived)</label><input name="connector_refs"></div>
        <div class="field"><label>Compatible harness refs (csv, empty = all)</label><input name="compatible_harness_refs"></div>
      </div>
      <div class="row"><button class="act" type="submit">Create entry</button></div>
    </form></details>`;
  const script = `<script>
    function memCat(btn){document.querySelectorAll('[data-memcat]').forEach(function(b){b.classList.toggle('on',b===btn);});memFilter();}
    function memFilter(){var cat=(document.querySelector('[data-memcat].on')||{}).getAttribute?document.querySelector('[data-memcat].on').getAttribute('data-memcat'):'';var q=(document.getElementById('mem-search')||{value:''}).value.toLowerCase();
      document.querySelectorAll('.memcard').forEach(function(c){var okCat=!cat||c.getAttribute('data-kind')===cat;var okQ=!q||c.getAttribute('data-blob').indexOf(q)>=0;c.style.display=(okCat&&okQ)?'':'none';});}
  </script>`;
  const vault = `<div class="row" style="margin:0 0 14px">
      <a class="act" href="/__ioi/agent-studio/vault/export" download>Export vault</a>
      <details style="display:inline-block"><summary class="act ghost" style="display:inline-block;cursor:pointer">Import vault</summary>
        <form method="post" action="/__ioi/agent-studio/vault/import" style="margin-top:8px;max-width:640px">
          <div class="field"><label>Vault bundle JSON (Markdown+frontmatter files inside)</label><textarea name="vault_json" rows="4" placeholder='{"format":"ioi.hypervisor.memory-vault.v1","files":[…]}'></textarea></div>
          <button class="act" type="submit">Import (idempotent · conflict-explicit)</button>
        </form>
      </details>
    </div>`;
  proposals = proposals || [];
  const open = proposals.filter((p) => p.review_state === "proposed");
  const reviewed = proposals.filter((p) => p.review_state !== "proposed").slice(0, 5);
  const propCard = (p, withActions) => `<div class="card"><div class="main">
      <div class="name">${CX_ESC((p.suggested || {}).title || p.operation)} <span class="pill ${p.review_state === "approved" ? "ok" : p.review_state === "rejected" ? "warn" : "muted"}">${CX_ESC(p.review_state)}</span><span class="pill muted">${CX_ESC(p.operation)} · ${CX_ESC(p.mutation_type)}</span><span class="pill muted">${CX_ESC(p.source_authority)}</span></div>
      <div class="meta"><code>${CX_ESC(p.proposal_ref || "")}</code> · ${CX_ESC(p.reason || "")} · confidence ${CX_ESC(String(p.confidence))}${p.source_run_ref ? ` · from <code>${CX_ESC(String(p.source_run_ref))}</code>` : ""}${p.applied_ref ? ` · applied <code>${CX_ESC(p.applied_ref)}</code>` : ""}</div>
      </div><div>${withActions ? `<form class="inline" method="post" action="/__ioi/agent-studio/proposals/${encodeURIComponent(p.mutation_id)}/approve"><button class="act" type="submit">Approve</button></form> <form class="inline" method="post" action="/__ioi/agent-studio/proposals/${encodeURIComponent(p.mutation_id)}/reject"><button class="act ghost" type="submit">Reject</button></form>` : ""}</div></div>`;
  const inbox = `<h2 id="proposal-inbox" style="margin-top:24px">Proposal inbox <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— harnesses/models propose durable memory changes; only an approved proposal writes (with a context_mutation receipt)</span></h2>
    ${open.length ? open.map((p) => propCard(p, true)).join("") : `<div class="empty">No open proposals. Runs propose; nothing writes durable memory silently.</div>`}
    ${reviewed.length ? `<h3 style="margin:14px 0 6px;font-size:12px;color:#878a93">Recently reviewed (evidence)</h3>` + reviewed.map((p) => propCard(p, false)).join("") : ""}`;
  review = review || [];
  const reviewSec = `<h2 id="review-queue" style="margin-top:24px">Review queue <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— deterministic signals only (no LLM judging)</span></h2>
    ${review.length ? review.map((it) => `<div class="card"><div class="main">
      <div class="name" style="font-size:13px">${CX_ESC(it.title || it.ref)} <span class="pill muted">${CX_ESC(it.kind || "")}</span><span class="pill ${it.quality_state === "accepted" ? "ok" : "muted"}">${CX_ESC(it.quality_state || "")}</span></div>
      <div class="meta"><code style="font-size:10px">${CX_ESC(it.ref)}</code>${it.projection_use_count ? ` · used in ${it.projection_use_count} projections` : ""}</div>
      <div class="chips" style="margin:6px 0 0">${(it.signals || []).map((sg) => `<span class="pill warn">${CX_ESC(sg)}</span>`).join("")}</div>
      </div></div>`).join("") : `<div class="empty">Nothing needs review — signals are computed from proposals, confidence, expiry, projection use, connector leases, and redaction frequency.</div>`}`;
  const graph = `<h2 id="memory-graph" style="margin-top:24px">Graph <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— derived read-only projection over the vault (no graph store)</span></h2>
    <input id="graph-search" class="asearch" placeholder="Search nodes…" oninput="graphSearch()">
    <div class="wlwrap"><div id="graph-nodes" style="max-height:420px;overflow:auto"><div class="empty">Loading graph…</div></div>
    <div class="wldrawer" id="graph-detail"><div class="sub" style="margin:0">Select a node to inspect its refs and edges.</div></div></div>
    <script>
      var GRAPH = null;
      function graphLoad(q){
        fetch('/__ioi/agent-studio/intel/graph' + (q ? '?q=' + encodeURIComponent(q) : '')).then(function(r){return r.json();}).then(function(j){
          GRAPH = j;
          var box = document.getElementById('graph-nodes');
          if (!j.nodes || !j.nodes.length) { box.innerHTML = '<div class="empty">No nodes match.</div>'; return; }
          box.innerHTML = '<div class="sub" style="margin:0 0 8px">' + j.counts.nodes + ' nodes · ' + j.counts.edges + ' edges</div>' + j.nodes.slice(0, 200).map(function(n, i){
            return '<div class="card memnode" style="padding:8px 12px;cursor:pointer" data-gi="' + i + '"><div class="main"><div class="name" style="font-size:12.5px">' + esc2(n.label) + ' <span class="pill muted">' + esc2(n.node_kind) + '</span>' + (n.status ? ' <span class="pill ' + (n.status === 'active' || n.status === 'approved' ? 'ok' : 'muted') + '">' + esc2(n.status) + '</span>' : '') + '</div><div class="meta" style="font-size:10.5px;word-break:break-all"><code>' + esc2(n.id) + '</code></div></div></div>';
          }).join('');
          box.querySelectorAll('.memnode').forEach(function(card){ card.addEventListener('click', function(){ graphSelect(parseInt(card.getAttribute('data-gi'), 10)); }); });
        });
      }
      function esc2(s){ return String(s == null ? '' : s).replace(/[&<>"]/g, function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }
      var graphTimer = null;
      function graphSearch(){ if (graphTimer) clearTimeout(graphTimer); graphTimer = setTimeout(function(){ graphLoad(document.getElementById('graph-search').value.trim()); }, 250); }
      function graphSelect(i){
        var n = GRAPH.nodes[i]; if (!n) return;
        var outgoing = GRAPH.edges.filter(function(e){ return e.from === n.id; });
        var incoming = GRAPH.edges.filter(function(e){ return e.to === n.id; });
        var line = function(e, dir){ var other = dir === 'out' ? e.to : e.from; return '<div style="padding:3px 0;border-bottom:1px solid #16181d;font-size:11.5px"><span class="pill muted">' + esc2(e.edge_kind) + (dir === 'out' ? ' →' : ' ←') + '</span> <code style="font-size:10px;word-break:break-all">' + esc2(other) + '</code></div>'; };
        document.getElementById('graph-detail').innerHTML = '<h3 style="margin:0 0 6px">' + esc2(n.label) + '</h3><div class="wlgrid"><div class="wlk">Kind</div><div class="wlv">' + esc2(n.node_kind) + '</div><div class="wlk">Ref</div><div class="wlv"><code style="font-size:10px">' + esc2(n.id) + '</code></div></div>' +
          '<h4 style="margin:10px 0 4px;font-size:11px;text-transform:uppercase;color:#878a93">Edges out (' + outgoing.length + ')</h4>' + (outgoing.map(function(e){ return line(e, 'out'); }).join('') || '<div class="sub" style="margin:0">none</div>') +
          '<h4 style="margin:10px 0 4px;font-size:11px;text-transform:uppercase;color:#878a93">Edges in (' + incoming.length + ')</h4>' + (incoming.map(function(e){ return line(e, 'in'); }).join('') || '<div class="sub" style="margin:0">none</div>');
      }
      graphLoad('');
    </script>`;
  const projList = projections || [];
  const explainSec = `<h2 id="projection-explain" style="margin-top:24px">Projection explain</h2>
    <p class="sub" style="margin:-4px 0 12px">Every projection is explainable — vault truth to harness prompt, with reason codes and receipts.</p>
    ${projList.length ? `<table><thead><tr><th>Projection</th><th>Harness</th><th>Counts</th><th></th></tr></thead><tbody>` + projList.slice(0, 8).map((pr) => `<tr>
      <td><code style="font-size:10.5px">${CX_ESC(pr.projection_ref || "")}</code><div style="color:#878a93;font-size:10.5px">${CX_ESC(pr.goal_run_ref || pr.session_ref || "")}</div></td>
      <td>${CX_ESC(String(pr.harness_profile_ref || "").replace("harness-profile:hp_", ""))}</td>
      <td style="font-size:11px">${CX_ESC(JSON.stringify(pr.counts || {}))}</td>
      <td><a class="act ghost" href="/__ioi/intelligence/projections/${encodeURIComponent(pr.projection_id)}/explain">Explain →</a></td>
    </tr>`).join("") + `</tbody></table>` : `<div class="empty">No projections yet — launch IOI Agent work to create them.</div>`}`;
  return `<h2 id="memory">Memory</h2><p class="sub" style="margin:-4px 0 12px">Durable preferences, facts, concepts, entities, workstreams, notes, and corrections — daemon truth that survives harness/model swaps. Harnesses receive scoped projections, never this raw store.</p>
    ${vault}${inbox}${reviewSec}${graph}${explainSec}<h2 style="margin-top:24px">Entries</h2>
    <input id="mem-search" class="asearch" placeholder="Search memory…" oninput="memFilter()">
    <div class="chips">${chips}</div>
    ${entries.length ? rows : `<div class="empty">No memory yet. IOI Agent runs and operators add entries here.</div>`}${form}${script}`;
}
// ---- Improvement proposals — outcome learning under governance. Mining is a derived
// deterministic projection (propose = explicit action); proposals change NOTHING until an
// operator approves AND applies (receipted); protected seed policies apply via clone only.
function renderImprovementProposals(mining, improvements) {
  const enc = encodeURIComponent;
  const stPill = (st) => `<span class="pill ${st === "applied" ? "ok" : st === "rejected" ? "warn" : st === "approved" ? "ok" : "muted"}">${CX_ESC(st)}</span>`;
  const mined = mining.map((c) => `<div class="card"><div class="main">
      <div class="name" style="font-size:13px">${CX_ESC((c.suggested || {}).title || (c.suggested || {}).display_name || c.signal)} <span class="pill muted">${CX_ESC(c.candidate_kind)}</span><span class="pill warn">${CX_ESC(c.signal)}</span></div>
      <div class="meta">×${CX_ESC(String(c.occurrences || 0))} occurrences · confidence ${CX_ESC(String(c.confidence || 0))} · ${(c.evidence_refs || []).length} evidence ref${(c.evidence_refs || []).length === 1 ? "" : "s"}</div>
      </div><form class="inline" method="post" action="/__ioi/agent-studio/improvements/propose"><input type="hidden" name="candidate_json" value="${CX_ESC(JSON.stringify(c))}"><button class="act ghost" type="submit">Propose</button></form></div>`).join("");
  const props = improvements.map((p) => {
    const gate = p.gate || {};
    const live = p.state === "pending" || p.state === "approved";
    const gateLabel = { no_simulation: "no simulation", simulation_required: "simulation required", simulation_stale: "simulation stale", low_impact: "low impact", awaiting_approval: "awaiting approval", awaiting_release: "awaiting release", ready: "ready to apply" }[gate.posture] || gate.posture || "";
    const gateChip = live && gateLabel ? `<span class="pill ${gate.block_code ? "warn" : "ok"}" title="${CX_ESC(gate.block_code ? `apply blocks: ${gate.block_code}` : "governance gate satisfied")}">${CX_ESC(gateLabel)}</span>` : "";
    const simBtn = `<form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/simulate"><button class="act ghost" type="submit" title="deterministic what-if replay over recent runs — no mutation">Simulate impact</button></form>`;
    const applyBtn = gate.block_code
      ? `<button class="act" type="button" disabled title="apply blocked: ${CX_ESC(gate.block_code)}">Apply</button>`
      : `<form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/apply"><button class="act" type="submit">Apply</button></form>`;
    const acts = p.state === "pending"
      ? `${simBtn} <form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/approve"><button class="act" type="submit">Approve</button></form> <form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/reject"><button class="act ghost" type="submit">Reject</button></form>`
      : p.state === "approved"
        ? `${simBtn} ${applyBtn} <form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/reject"><button class="act ghost" type="submit">Reject</button></form>`
        : "";
    // High-impact governance row: bound control status + one-click create/transition + attach-existing.
    const highPath = live && ["awaiting_approval", "awaiting_release", "ready"].includes(gate.posture);
    const apprId = String(p.approval_request_ref || "").replace("approval-request://", "");
    const relId = String(p.release_control_ref || "").replace("release-control://", "");
    const govRow = highPath ? `<div class="meta" style="margin-top:5px" data-gov="${CX_ESC(p.improvement_id)}">gate:
      ${p.approval_request_ref
        ? `<code style="font-size:10px">${CX_ESC(p.approval_request_ref)}</code> <span class="pill ${gate.approval_status === "approved" ? "ok" : "warn"}">${CX_ESC(gate.approval_status || "?")}</span>${gate.approval_status === "pending" ? ` <form class="inline" method="post" action="/__ioi/agent-studio/governance/approvals/${enc(apprId)}/approve"><button class="act ghost" type="submit">Approve request</button></form>` : ""}`
        : `<form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/governance/request-approval"><button class="act ghost" type="submit">Request approval</button></form>`}
      · ${p.release_control_ref
        ? `<code style="font-size:10px">${CX_ESC(p.release_control_ref)}</code> <span class="pill ${gate.release_state === "open" ? "ok" : "warn"}">${CX_ESC(gate.release_state || "?")}${gate.release_rollout_mode && gate.release_rollout_mode !== "full" ? ` · ${CX_ESC(gate.release_rollout_mode)}` : ""}</span>${gate.release_state !== "open" ? ` <form class="inline" method="post" action="/__ioi/agent-studio/governance/releases/${enc(relId)}/open"><button class="act ghost" type="submit">Open gate</button></form>` : ""}`
        : `<form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/governance/open-release"><button class="act ghost" type="submit">Create release gate</button></form>`}
      · <details style="display:inline-block"><summary style="cursor:pointer;display:inline">attach existing</summary>
        <form class="inline" method="post" action="/__ioi/agent-studio/improvements/${enc(p.improvement_id)}/governance/attach" style="margin-top:4px">
          <input name="approval_request_ref" placeholder="approval-request://appr_…" style="width:220px;font-size:10px">
          <input name="release_control_ref" placeholder="release-control://rel_…" style="width:220px;font-size:10px">
          <button class="act ghost" type="submit">Attach</button>
        </form></details></div>` : "";
    const appliedLink = p.applied_ref
      ? String(p.applied_ref).startsWith("skill-entry://") ? ` · applied: <a href="/__ioi/agent-studio#skills"><code>${CX_ESC(p.applied_ref)}</code></a>`
      : String(p.applied_ref).startsWith("ioi-agent-policy://") ? ` · applied: <a href="/__ioi/agent-studio#launch-policies"><code>${CX_ESC(p.applied_ref)}</code></a>`
      : ` · applied: <code>${CX_ESC(p.applied_ref)}</code>` : "";
    return `<div class="card"><div class="main">
      <div class="name" style="font-size:13px">${CX_ESC((p.suggested || {}).title || (p.suggested || {}).display_name || p.signal)} ${stPill(p.state)}<span class="pill muted">${CX_ESC(p.proposal_kind)}</span><span class="pill warn">${CX_ESC(p.signal || "")}</span>${gateChip}</div>
      <div class="meta"><code style="font-size:10px">${CX_ESC(p.proposal_ref)}</code> · confidence ${CX_ESC(String(p.confidence))}${appliedLink}${(p.receipt_refs || []).length ? ` · <a href="/__ioi/work-ledger">receipt →</a>` : ""}${p.latest_simulation_ref ? ` · <a href="/__ioi/intelligence/simulations/${enc(String(p.latest_simulation_ref).replace("simulation-report://", ""))}">simulation${p.latest_simulation_high_impact ? " ⚠ high impact" : ""} →</a>` : ""}</div>
      <div class="chips" style="margin:6px 0 0">${(p.evidence_refs || []).slice(0, 4).map((r) => `<span class="pill muted" style="font-size:10px">${CX_ESC(String(r).slice(0, 44))}</span>`).join("")}${(p.evidence_refs || []).length > 4 ? `<span class="pill muted">+${(p.evidence_refs || []).length - 4} more</span>` : ""}</div>
      ${govRow}
      </div><div>${acts}</div></div>`;
  }).join("");
  return `<h2 id="improvement-proposals" style="margin-top:28px">Improvement proposals <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— deterministic outcome mining; high-impact changes gate on fresh simulation + approval + release · <a href="/__ioi/improvement/changes">Upgrade Assistant inbox →</a> (the #53 certified projection over this plane) · <a href="/__apps/changes">change-inbox capture ↗</a></span></h2>
    ${improvements.length ? props : `<div class="empty">No improvement proposals yet.</div>`}
    <h3 style="margin:16px 0 6px;font-size:12px;color:#878a93">Mined candidates (derived, not yet proposed)</h3>
    ${mining.length ? mined : `<div class="empty">No deterministic candidates mined from recent outcomes.</div>`}`;
}

function renderAutomationReadiness(affinities) {
  const cards = affinities.map((a) => `<div class="card"><div class="main">
    <div class="name">${CX_ESC(a.title || a.affinity_id)} ${intelStatusPill(a.status)}</div>
    <div class="meta">goal pattern <code>${CX_ESC(a.goal_pattern || "")}</code>${a.preferred_policy_ref ? ` → <code>${CX_ESC(a.preferred_policy_ref)}</code>` : ""}</div>
    <div class="chips" style="margin:6px 0 0">${(a.preferred_harness_refs || []).map((r) => `<span class="pill muted">${CX_ESC(String(r).replace("harness-profile:hp_", ""))}</span>`).join("")}${(a.preferred_automation_refs || []).map((r) => `<span class="pill muted">${CX_ESC(String(r))}</span>`).join("")}${(a.required_connector_refs || []).map((r) => `<span class="pill warn">needs ${CX_ESC(String(r).slice(0, 24))}</span>`).join("")}</div>
    </div><div>${intelActions("affinities", a.affinity_id, a.status)}</div></div>`).join("");
  const form = `<details style="margin-top:12px"><summary class="act ghost" style="display:inline-block;cursor:pointer">+ New affinity</summary>
    <form method="post" action="/__ioi/agent-studio/intel/affinities" style="margin-top:10px;max-width:640px">
      <div class="field"><label>Title</label><input name="title" required></div>
      <div class="two">
        <div class="field"><label>Goal pattern (substring match)</label><input name="goal_pattern" required placeholder="status file"></div>
        <div class="field"><label>Preferred policy ref</label><input name="preferred_policy_ref" placeholder="ioi-agent-policy://pol_fast_local"></div>
      </div>
      <div class="two">
        <div class="field"><label>Preferred automation refs (csv)</label><input name="preferred_automation_refs" placeholder="automation://auto_…"></div>
        <div class="field"><label>Preferred harness refs (csv)</label><input name="preferred_harness_refs"></div>
      </div>
      <div class="row"><button class="act" type="submit">Create affinity</button></div>
    </form></details>`;
  return `<h2 id="automation-readiness" style="margin-top:28px">Automation readiness</h2><p class="sub" style="margin:-4px 0 12px">Affinities between goal patterns, launch policies, and existing <a href="/__ioi/automations">Hypervisor Automations →</a> (which own triggers/schedules/runs). At launch, a matching affinity steers policy/harness selection in the projection.</p>${affinities.length ? cards : `<div class="empty">No automation affinities yet.</div>`}${form}`;
}

function renderLaunchPolicies(policies, profiles) {
  const enc = encodeURIComponent;
  policies = Array.isArray(policies) ? policies : [];
  const chip = (cls, label) => `<span class="pill ${cls}">${CX_ESC(label)}</span>`;
  const cards = policies.map((p) => {
    const hp = p.harness_preferences || {};
    const priv = p.privacy || {};
    const asr = p.assurance || {};
    const active = p.status === "active";
    const ro = p.rollout || null;
    const roActs = ro && ro.state === "active"
      ? `<form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/rollout/promote" onsubmit="return confirm('Promote to FULL rollout — every context using the base policy will see this learned variant?')"><button class="act" type="submit">Promote full</button></form> <form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/rollout/rollback"><button class="act ghost" type="submit">Roll back</button></form>`
      : ro && ro.state === "promoted"
        ? `<form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/rollout/rollback"><button class="act ghost" type="submit">Roll back</button></form>`
        : "";
    const acts = [
      roActs,
      `<form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/clone"><button class="act ghost" type="submit">Clone</button></form>`,
      active
        ? `<form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/disable"><button class="act ghost" type="submit">Disable</button></form>`
        : `<form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/enable"><button class="act" type="submit">Enable</button></form>`,
      p.protected ? "" : `<form class="inline" method="post" action="/__ioi/agent-studio/launch-policies/${enc(p.policy_id)}/delete" onsubmit="return confirm('Delete this policy?')"><button class="act danger" type="submit">Delete</button></form>`,
    ].join(" ");
    return `<div class="card lpcard" data-policy="${CX_ESC(p.policy_id)}"><div class="main">
      <div class="name">${CX_ESC(p.display_name || p.policy_id)}${p.protected ? ' <span class="pill muted" title="seeded default — clone to customize">protected</span>' : ""}${active ? ' <span class="pill ok">active</span>' : ' <span class="pill muted">disabled</span>'}</div>
      <div class="meta"><code>${CX_ESC(p.policy_ref || "")}</code> · ${CX_ESC(p.description || "")}</div>
      <div class="chips" style="margin:6px 0 0">${chip("muted", "strategy: " + (p.strategy_preference || "auto"))}${priv.local_only ? chip("ok", "private local") : ""}${asr.require_compare ? chip("warn", "compare required") : ""}${(asr.min_successful_invocations || 0) > 1 ? chip("warn", "min success: " + asr.min_successful_invocations) : ""}${hp.allow_fallback ? chip("muted", "fallback allowed") : chip("muted", "fail-closed")}${(hp.preferred_harness_refs || []).map((r) => chip("muted", "prefers " + String(r).replace("harness-profile:hp_", ""))).join("")}${chip("ok", "receipts required")}${ro ? chip(ro.state === "active" ? "warn" : ro.state === "promoted" ? "ok" : "muted", `${ro.mode || "?"} rollout · ${ro.state}`) : ""}${ro ? chip("muted", "base " + String(ro.base_policy_ref || "").replace("ioi-agent-policy://", "")) : ""}${ro && ro.proposal_ref ? chip("muted", "learned") : ""}${(p.rollout_display?.cohort_names || []).map((n) => chip("warn", "cohort: " + n)).join("")}${p.rollout_display?.canary_percent != null ? chip("warn", p.rollout_display.canary_percent + "% canary") : ""}${p.rollout_display?.deprecated_raw ? chip("muted", "deprecated raw refs") : ""}</div>
      </div><div>${acts}</div></div>`;
  }).join("");
  const hpOpts = (profiles || []).map((p) => `${p.profile_ref || ""}`).filter(Boolean);
  const form = `<details style="margin-top:12px"><summary class="act ghost" style="display:inline-block;cursor:pointer">+ New policy</summary>
    <form method="post" action="/__ioi/agent-studio/launch-policies" style="margin-top:10px;max-width:640px">
      <div class="field"><label>Name</label><input name="display_name" required placeholder="OpenCode preferred"></div>
      <div class="field"><label>Description</label><input name="description" placeholder="What this policy is for"></div>
      <div class="two">
        <div class="field"><label>Strategy preference</label><select name="strategy_preference"><option value="auto">auto</option><option value="direct">direct</option><option value="compare">compare</option><option value="private_local">private_local</option></select></div>
        <div class="field"><label>Failure policy</label><select name="failure_policy"><option value="partial_ok">partial_ok</option><option value="stop_on_first_failure">stop_on_first_failure</option><option value="require_all">require_all</option><option value="retry_once">retry_once</option></select></div>
      </div>
      <div class="two">
        <div class="field"><label>Preferred harness refs (csv)</label><input name="preferred_harness_refs" placeholder="${CX_ESC(hpOpts[1] || "harness-profile:hp_opencode")}"></div>
        <div class="field"><label>Excluded harness refs (csv)</label><input name="excluded_harness_refs" placeholder=""></div>
      </div>
      <div class="field"><label><input type="checkbox" name="allow_fallback" style="width:auto"> allow fallback when constraints cannot be satisfied</label></div>
      <div class="field"><label><input type="checkbox" name="local_only" style="width:auto"> private local (local trust + local routes only)</label></div>
      <div class="two">
        <div class="field"><label><input type="checkbox" name="require_compare" style="width:auto"> require compare (write only through reconciliation)</label></div>
        <div class="field"><label>Min successful invocations</label><input name="min_successful_invocations" type="number" min="1" max="2" value="1"></div>
      </div>
      <div class="row"><button class="act" type="submit">Create policy</button></div>
      <p class="sub" style="margin:6px 0 0">Receipts are mandatory on every policy; a policy is a routing/admission preference envelope, never a harness.</p>
    </form></details>`;
  return `<h2 id="launch-policies">Launch policies</h2><p class="sub" style="margin:-4px 0 12px">Saved IOI Agent strategy presets — the daemon planner composes a policy with live registry facts, authority, privacy posture, budget, and failure policy at launch. Seeded defaults are protected; clone to customize.</p>${policies.length ? cards : `<div class="empty">No launch policies yet.</div>`}${form}`;
}

// ---- System designs (Studio) — the daemon-backed lane behind the /__apps/designer solution-design
// canvas seed. The captured canvas teaches the composition grammar (typed concept/component/resource
// nodes, save/actions/open, AIP critique, load-from-lineage); here the OWNER surface binds the parts
// that are real daemon truth: the composition-pattern reference library (the daemon's own canonical
// system shapes) and saved system designs (ODK surface descriptors). Every fact is daemon state or a
// named gap — no fabricated nodes/imports.
function renderStudioSystemDesigns(sd) {
  sd = sd || {};
  const patterns = Array.isArray(sd.compositionPatterns) ? sd.compositionPatterns : [];
  const designs = Array.isArray(sd.surfaceDescriptors) ? sd.surfaceDescriptors : [];
  const prettyPattern = (p) => String(p || "").replace(/_/g, " ");
  const patternLib = patterns.length
    ? `<div class="chips" style="margin:2px 0 4px">${patterns.map((p) => `<span class="pill muted" title="daemon composition pattern">${CX_ESC(prettyPattern(p))}</span>`).join("")}</div>`
    : `<div class="empty">The daemon exposes no composition patterns.</div>`;
  const designRows = designs.length
    ? `<table><thead><tr><th>System design</th><th>Pattern</th><th>Ref</th></tr></thead><tbody>${designs.map((d) => `<tr>
        <td><b>${CX_ESC(d.name || d.title || d.id || "—")}</b></td>
        <td><span class="pill muted">${CX_ESC(prettyPattern(d.composition_pattern || d.pattern || "—"))}</span></td>
        <td><code style="font-size:11px">${CX_ESC(d.ref || d.surface_descriptor_ref || d.id || "")}</code></td>
      </tr>`).join("")}</tbody></table>`
    : `<div class="empty">No saved system designs yet. Compose one in the <a href="/__apps/designer">system canvas seed →</a>; the daemon persists an admitted design as an ODK surface descriptor. (The seed's in-canvas Open / Save / reference-library / load-from-lineage lanes are <b>named gaps</b> in the current capture — authored natively or live re-harvested next, never faked.)</div>`;
  return `<h2 id="system-designs">System designs</h2>` +
    `<p class="sub" style="margin:-4px 0 12px">The Studio composition plane — a system design composes typed <b>concept / component / resource</b> nodes into an IOI system shape. Compose in the <a href="/__apps/designer">canvas seed →</a>; the reference library and saved designs below are daemon truth.</p>` +
    `<h3 style="margin:14px 0 4px;font-size:13px">Composition pattern library <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the ${patterns.length} canonical system shapes the daemon recognizes (the reference examples a design starts from)</span></h3>${patternLib}` +
    `<h3 style="margin:16px 0 4px;font-size:13px">Saved system designs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— admitted ODK surface descriptors</span></h3>${designRows}`;
}

function renderAgentStudio(agents, profiles, routes, providers, conversations, runs, selId, q, modelRoutes, launchPolicies, intel) {
  const enc = encodeURIComponent;
  agents = Array.isArray(agents) ? agents : [];
  profiles = Array.isArray(profiles) ? profiles : [];
  routes = Array.isArray(routes) ? routes : [];
  providers = Array.isArray(providers) ? providers : [];
  conversations = Array.isArray(conversations) ? conversations : [];
  runs = Array.isArray(runs) ? runs : [];
  modelRoutes = Array.isArray(modelRoutes) ? modelRoutes : [];
  const qn = String(q || "").trim().toLowerCase();
  const filtered = qn
    ? agents.filter((a) => `${a.id || ""} ${pickv(a, "model_id", "modelId") || ""}`.toLowerCase().includes(qn))
    : agents;
  const activeCount = agents.filter((a) => (a.status || "") === "active").length;
  const head = `<h1>Studio</h1><p class="sub"><a href="/__ioi/studio/designer">System design canvas →</a> (concept/component/resource map) · <a href="/__ioi/studio/machinery">Machinery →</a> (process/state-machine definitions) · reference <a href="/__apps/designer">Designer</a> · <a href="/__apps/machinery">Machinery</a> seeds ↗ · Compose systems &amp; agents. The agent lens is live — the agent estate — every configured agent, its model route and runtime posture, the platform's harness adapters, and recent activity. Author and operate agents here; <a href="/__ioi/automations">put one to work in an Automation →</a></p>`;
  const styles = `<style>.wrap{max-width:1180px}.asgrid{display:grid;grid-template-columns:248px 1fr;gap:20px;align-items:start}.aslist{position:sticky;top:16px;max-height:82vh;overflow:auto;display:flex;flex-direction:column;gap:6px}.asrow{display:block;padding:10px 12px;border:1px solid #24262d;border-radius:10px;background:#15171c;text-decoration:none;color:inherit}.asrow:hover{border-color:#3a82f6}.asrow.sel{border-color:#3a82f6;box-shadow:0 0 0 1px #3a82f6 inset}.asrow .nm{font-weight:600;color:#fff;font-size:12.5px}.asrow .ml{color:#878a93;font-size:11.5px;margin-top:2px;word-break:break-all}.asearch{width:100%;box-sizing:border-box;padding:9px 12px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit;margin-bottom:10px}</style>`;
  if (!agents.length) {
    // Registry truth still renders without agents — routes exist independently of the agent estate.
    return automationsShell("Studio", styles + head + renderStudioSystemDesigns((intel || {}).systemDesigns) + `<div class="empty">No agents yet. An agent is created when you start a session or run an automation — once one exists it will appear here with its model route, runtime posture, and activity.</div>` + renderModelRouteRegistry(modelRoutes) + renderLaunchPolicies(launchPolicies, profiles));
  }
  // Selected agent (query ?agent=, else first of the filtered list).
  const sel = filtered.find((a) => a.id === selId) || filtered[0] || agents[0];
  const qsfx = qn ? `&q=${enc(q)}` : "";
  const list = filtered.length
    ? filtered.map((a) => {
        const on = sel && a.id === sel.id ? " sel" : "";
        const st = (a.status || "") === "active" ? "ok" : "muted";
        return `<a class="asrow${on}" href="/__ioi/agent-studio?agent=${enc(a.id || "")}${qsfx}"><div class="nm">${CX_ESC(agentShort(a.id))} <span class="pill ${st}">${CX_ESC(a.status || "—")}</span></div><div class="ml">${CX_ESC(pickv(a, "model_id", "modelId") || "—")}</div></a>`;
      }).join("")
    : `<div class="empty">No agents match “${CX_ESC(q)}”.</div>`;
  const left = `<div><form method="get" action="/__ioi/agent-studio"><input class="asearch" name="q" value="${CX_ESC(q || "")}" placeholder="Search agents by id or model…"></form><div class="aslist">${list}</div></div>`;

  // ---- Selected agent: configuration + runner posture + primary actions.
  const a = sel || {};
  const dec = a.model_route_decision || a.modelRouteDecision || {};
  const rc = a.runtime_controls || a.runtimeControls || {};
  const rcm = rc.model || {};
  const subs = (a.options && (a.options.subagentNames || a.options.subagent_names)) || [];
  const receipts = a.receipt_refs || a.receiptRefs || [];
  const mcp = pickv(a, "mcpRegistry", "mcp_registry");
  const cfg = (label, val) => `<dt>${label}</dt><dd>${val}</dd>`;
  const code = (v) => v ? `<code>${CX_ESC(v)}</code>` : "—";
  const grid = `<dl class="grid">
    ${cfg("Agent id", code(a.id))}
    ${cfg("Status", `<span class="pill ${(a.status || "") === "active" ? "ok" : "muted"}">${CX_ESC(a.status || "—")}</span>`)}
    ${cfg("Model", code(pickv(a, "model_id", "modelId")))}
    ${cfg("Selected model", code(pickv(rcm, "selected_model") || pickv(a, "requestedModelId", "requested_model_id")))}
    ${cfg("Mode · approval", `${CX_ESC(rc.mode || "—")} · ${CX_ESC(rc.approval_mode || "—")}`)}
    ${cfg("Reasoning effort", CX_ESC(pickv(rcm, "reasoning_effort") || pickv(rc, "reasoning_effort") || "default"))}
    ${cfg("Working dir", code(a.cwd))}
    ${cfg("MCP registry", mcp ? code(mcp) : `<span class="sub" style="margin:0">none bound</span>`)}
    ${cfg("Subagents", subs.length ? subs.map((s) => `<code>${CX_ESC(s)}</code>`).join(" ") : `<span class="sub" style="margin:0">none</span>`)}
    ${cfg("Created · updated", `${CX_ESC(pickv(a, "created_at", "createdAt") || "—")}<br><span class="sub" style="margin:0">${CX_ESC(pickv(a, "updated_at", "updatedAt") || "")}</span>`)}
  </dl>`;
  // Runner posture is grounded in the agent's own model-route decision (real fields, not inferred).
  const postureChips = `<div class="chips"><span class="chiplabel">Runner posture</span>
    <span class="pill muted">runtime: ${CX_ESC(a.runtime || pickv(dec, "local_remote_placement") || "—")}</span>
    <span class="pill muted">provider: ${CX_ESC(pickv(dec, "provider_kind") || "—")}</span>
    <span class="pill ${pickv(dec, "privacy_posture") === "local_only" ? "ok" : "muted"}">privacy: ${CX_ESC(pickv(dec, "privacy_posture") || "—")}</span>
    <span class="pill muted">capability: ${CX_ESC(dec.capability || "—")}</span>
    ${pickv(dec, "never_send_auto_upstream") === true ? `<span class="pill ok">never auto-upstream</span>` : ""}
  </div>`;
  const routeGrid = `<dl class="grid">
    ${cfg("Route", code(pickv(a, "model_route_id", "modelRouteId")))}
    ${cfg("Endpoint", code(pickv(a, "model_route_endpoint_id", "modelRouteEndpointId")))}
    ${cfg("Provider", code(pickv(a, "model_route_provider_id", "modelRouteProviderId")))}
    ${cfg("Route receipt", code(pickv(a, "model_route_receipt_id", "modelRouteReceiptId")))}
    ${cfg("Proof receipts", receipts.length ? `${receipts.length} ref(s)` : "—")}
  </dl>`;
  // Primary actions — workspace-honest. "Use in Automation" is the agent-scoped action; the
  // conversation/run links are the most-recent workspace activity (no per-agent join is recorded).
  const latestRun = runs.slice().sort((x, y) => String(pickv(y, "recorded_at", "started_at") || "").localeCompare(String(pickv(x, "recorded_at", "started_at") || "")))[0];
  const recentConv = conversations[0];
  const actions = `<div class="row">
    <a class="act" href="/__ioi/automations/new">Use in Automation →</a>
    ${recentConv && recentConv.environment_id ? `<a class="act ghost" href="/details/${enc(recentConv.environment_id)}" target="_top">Open recent conversation →</a>` : ""}
    ${latestRun && latestRun.run_id ? `<a class="act ghost" href="/__ioi/run-timeline/${enc(latestRun.run_id)}" target="_blank" rel="noopener">Open latest run timeline ↗</a>` : ""}
  </div>`;

  // ---- Harness profiles — the daemon REGISTRY (selectable runtime harnesses with probed
  // runnability + explicit execution wiring). Runnable ≠ execution-bindable: an adapter-slot
  // profile can be host-present yet unwired; both axes render honestly and independently.
  // Honest annotation: a profile model string with no registry route is marked, never joined.
  const registeredModelIds = new Set(modelRoutes.map((r) => (r.model || {}).model_id).filter(Boolean));
  const profModel = (m) => `<code>${CX_ESC(m)}</code>${registeredModelIds.has(m) ? "" : ` <span class="pill muted" title="no model-route registry entry declares this model">unregistered</span>`}`;
  const hpId = (p) => String(p.profile_ref || "").replace(/^harness-profile:/, "");
  const runPill = (state) => `<span class="pill ${state === "runnable" ? "ok" : state === "not_probed" ? "muted" : "warn"}">${CX_ESC(state || "not_probed")}</span>`;
  const wirePill = (w) => w === "lane_a_host_spawn"
    ? `<span class="pill ok" title="executes through the daemon's Lane A host-spawn path">lane A</span>`
    : w === "terminal_pty"
      ? `<span class="pill muted" title="drives the daemon terminal PTY lane; not an execution binding target">terminal</span>`
      : `<span class="pill warn" title="selectable metadata; execution wiring not yet built — session binding is rejected fail-closed">adapter slot (unwired)</span>`;
  const hpConfirm = (p, act, label, admission, rollback, danger) => {
    const remote = String(p.provider_trust || "").startsWith("remote");
    const needsAcceptance = remote && (act === "enable" || act === "select-default");
    return `<details class="mrc"><summary class="act ghost${danger ? " danger" : ""}">${label}</summary><div class="mrcbody">
      <div class="sub" style="margin:0 0 6px">${admission}<br>Receipt: <code>agentgres://harness-profile-receipt/*</code> will be minted; the op records a transcript with a state_root.<br>Rollback: ${rollback}</div>
      <form class="inline" method="post" action="/__ioi/agent-studio/harness-profiles/${enc(hpId(p))}/${act}">${needsAcceptance ? `<div class="field" style="margin:0 0 6px"><label>provider_trust_acceptance_ref (required for ${CX_ESC(p.provider_trust)})</label><input name="provider_trust_acceptance_ref" placeholder="approval://provider-trust/…" style="width:100%"></div>` : ""}<button class="act${danger ? " danger" : ""}" type="submit">Confirm ${label}</button></form>
    </details>`;
  };
  const profRows = profiles.map((p) => {
    const lc = p.lifecycle_status || "declared";
    const controls = [
      hpConfirm(p, "probe", "Probe", "No admission (evidence-gathering only); host presence is probed — binary on PATH, shim + node, model-upstream reachability. Never fabricated.", "none needed — probing only updates runnability evidence"),
      lc === "active"
        ? hpConfirm(p, "disable", "Disable", `Admission: <code>disable_profile</code> under <code>scope:harness.profile.mutate</code> (relaxed lane).`, "re-enable via the admitted <code>enable_profile</code> lane", true)
        : hpConfirm(p, "enable", "Enable", `Admission: <code>enable_profile</code> under <code>scope:harness.profile.mutate</code>; non-local provider trust requires an explicit provider-trust acceptance (planner-validated, fail-closed).`, "disable via the admitted <code>disable_profile</code> lane"),
      p.default ? "" : hpConfirm(p, "select-default", "Set default", `Admission: <code>select_profile</code> under <code>scope:harness.profile.mutate</code>; the previous default is atomically cleared (exactly-one invariant).`, "select the previous default again"),
    ].filter(Boolean).join(" ");
    return `<tr>
    <td><b>${CX_ESC(p.display_name || p.harness || "—")}</b>${p.default ? ` <span class="pill ok">default</span>` : ""}<div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(p.profile_ref || p.harness || "")}</code></div></td>
    <td>${(p.modes || []).map((m) => CX_ESC(m)).join(" · ") || "—"}</td>
    <td>${(p.models || []).map(profModel).join(" ") || "—"}</td>
    <td>${(p.reasoning || []).map(CX_ESC).join("/") || "—"}</td>
    <td>${p.tool_use ? "✓" : "—"} · ${p.image_input ? "img" : "—"}</td>
    <td><span class="pill ${String(p.provider_trust || "").startsWith("remote") ? "warn" : "ok"}">${CX_ESC(p.provider_trust || "—")}</span></td>
    <td><span class="pill ${lc === "active" ? "ok" : "muted"}">${CX_ESC(lc)}</span></td>
    <td>${runPill(p.runnability_state)} ${wirePill(p.execution_wiring)}</td>
    <td>${controls}</td>
  </tr>`;
  }).join("");
  const matrix = profiles.length
    ? `<h2 id="harness-profiles">Harness profiles</h2><p class="sub" style="margin:-4px 0 12px">The daemon harness-profile registry — every selectable runtime harness with its capability matrix, probed runnability, and execution wiring. <b>runnable</b> means the adapter's host requirements resolve; only a <b>lane A</b> wired profile is execution-bindable today. Enable/disable/default are planner-admitted, receipted mutations.</p><table><thead><tr><th>Harness</th><th>Modes</th><th>Models</th><th>Reasoning</th><th>Tools</th><th>Trust</th><th>Lifecycle</th><th>Runnability</th><th>Controls</th></tr></thead><tbody>${profRows}</tbody></table>`
    : "";

  const registry = renderModelRouteRegistry(modelRoutes);

  // ---- Model-mount substrate (evidence line, demoted — the registry above is the product surface).
  const routeRows = routes.map((r) => `<span class="pill ${(r.status || "") === "active" ? "ok" : "muted"}">${CX_ESC(r.id || "")} · ${CX_ESC(r.role || "")} · ${CX_ESC(r.status || "")}</span>`).join(" ");
  const provChips = providers.slice(0, 16).map((p) => `<span class="pill muted">${CX_ESC(p.id || p.provider_ref || "")} · ${CX_ESC(p.driver || p.provider_kind || "")}</span>`).join(" ");
  const routing = registry + `<div class="chips" style="margin-top:10px"><span class="chiplabel">Mount substrate</span>${routeRows || `<span class="sub" style="margin:0">none</span>`}</div><div class="chips"><span class="chiplabel">Providers (${providers.length})</span>${provChips || `<span class="sub" style="margin:0">none</span>`}</div>`;

  // ---- Recent activity (workspace-wide; honest label — not a per-agent join).
  const convRows = conversations.slice(0, 8).map((c) => {
    const env = c.environment_id || "";
    const st = /^(active|open|running)$/.test(c.status || "") ? "ok" : "muted";
    return `<tr><td>${CX_ESC(c.title || c.conversation_id || "—")}</td><td><span class="pill ${st}">${CX_ESC(c.status || "—")}</span></td><td>${CX_ESC(String(c.turn_count == null ? "—" : c.turn_count))}</td><td>${env ? `<a href="/details/${enc(env)}" target="_top">session</a> · <a href="/__ioi/run-timeline/env/${enc(env)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td></tr>`;
  }).join("");
  const runRows = runs.slice().sort((x, y) => String(pickv(y, "recorded_at", "started_at") || "").localeCompare(String(pickv(x, "recorded_at", "started_at") || ""))).slice(0, 8).map((r) => {
    const st = r.status === "done" ? "ok" : r.status === "failed" ? "warn" : "muted";
    return `<tr><td>${CX_ESC(r.automation_name || r.kind || "—")}</td><td><span class="pill ${st}">${CX_ESC(r.status || "—")}</span></td><td>${CX_ESC(pickv(r, "started_at", "recorded_at") || "")}</td><td>${r.run_id ? `<a href="/__ioi/run-timeline/${enc(r.run_id)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td></tr>`;
  }).join("");
  const activity = `<h2>Recent activity <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— workspace-wide (per-agent linkage is not recorded yet)</span></h2>
    <h3 style="margin:8px 0 6px;font-size:12px;color:#878a93">Conversations (${conversations.length})</h3>${conversations.length ? `<table><thead><tr><th>Title</th><th>Status</th><th>Turns</th><th>Open</th></tr></thead><tbody>${convRows}</tbody></table>` : `<div class="empty">No conversations recorded.</div>`}
    <h3 style="margin:16px 0 6px;font-size:12px;color:#878a93">Runs (${runs.length})</h3>${runs.length ? `<table><thead><tr><th>Run</th><th>Status</th><th>Started</th><th>Proof</th></tr></thead><tbody>${runRows}</tbody></table>` : `<div class="empty">No runs recorded.</div>`}`;

  // ---- Editor-with-tabs shell (source shape: the studio detail is a tabbed edit builder, not one
  // scrolling pane). Pure recomposition of the data already fetched — each tab is a panel over the
  // same daemon truth; #harness-profiles / #model-routes deep-links (Work Ledger backlinks) land on
  // their tab. No create/publish/eval tabs are fabricated: those lanes have no daemon plane yet.
  const tabBar = `<div class="tabs" id="astabs">
    <button class="tab active" data-astab="config" type="button">Configuration</button>
    <button class="tab" data-astab="harness-profiles" type="button">Harness profiles</button>
    <button class="tab" data-astab="model-routes" type="button">Model routes</button>
    <button class="tab" data-astab="launch-policies" type="button">Launch policies</button>
    <button class="tab" data-astab="connectors" type="button">Connectors</button>
    <button class="tab" data-astab="skills" type="button">Skills</button>
    <button class="tab" data-astab="memory" type="button">Memory</button>
    <button class="tab" data-astab="activity" type="button">Activity</button>
  </div>`;
  const panel = (name, on, inner) => `<div class="aspanel${on ? " on" : ""}" data-aspanel="${name}">${inner}</div>`;
  const panels = panel("config", true, `${actions}<h2>Configuration</h2>${grid}${postureChips}<h2>Model route</h2>${routeGrid}`)
    + panel("harness-profiles", false, matrix || `<div class="empty">No harness profiles registered.</div>`)
    + panel("model-routes", false, routing)
    + panel("launch-policies", false, renderLaunchPolicies(launchPolicies, profiles) + renderAutomationReadiness((intel || {}).affinities || []) + renderImprovementProposals((intel || {}).mining || [], (intel || {}).improvements || []))
    + panel("connectors", false, renderIntelConnectors(intel || {}))
    + panel("skills", false, renderIntelSkills((intel || {}).skills || []))
    + panel("memory", false, renderIntelMemory((intel || {}).entries || [], (intel || {}).proposals || [], (intel || {}).projections || [], (intel || {}).review || []))
    + panel("activity", false, activity);
  const tabScript = `<style>.aspanel{display:none}.aspanel.on{display:block}</style><script>
    function asTab(name){
      var found=false;
      document.querySelectorAll('#astabs .tab').forEach(function(b){var on=b.getAttribute('data-astab')===name;b.classList.toggle('active',on);if(on)found=true;});
      if(!found)return asTab('config');
      document.querySelectorAll('.aspanel').forEach(function(p){p.classList.toggle('on',p.getAttribute('data-aspanel')===name);});
    }
    document.querySelectorAll('#astabs .tab').forEach(function(b){b.addEventListener('click',function(){var n=b.getAttribute('data-astab');asTab(n);history.replaceState(null,'','#'+n);});});
    function asFromHash(){var h=(location.hash||'').replace(/^#/,'');if(h)asTab(h);}
    window.addEventListener('hashchange',asFromHash);asFromHash();
  </script>`;
  const right = `<div><div class="row" style="margin-bottom:2px"><h2 style="margin:0">${CX_ESC(agentShort(a.id))}</h2><span class="pill ${(a.status || "") === "active" ? "ok" : "muted"}">${CX_ESC(a.status || "—")}</span></div>${tabBar}${panels}${tabScript}</div>`;
  const body = `<div class="row" style="justify-content:space-between"><span class="sub" style="margin:0">${agents.length} agent${agents.length === 1 ? "" : "s"} · ${activeCount} active${qn ? ` · ${filtered.length} matching “${CX_ESC(q)}”` : ""}</span></div><div class="asgrid">${left}${right}</div>`;
  return automationsShell("Studio", styles + head + renderStudioSystemDesigns((intel || {}).systemDesigns) + body);
}

// ---- Foundry — a CONTROLLED BUILDER over the daemon Foundry object plane (estate surface #4).
// Serve-owned UI over the real /v1/hypervisor/foundry/* plane: draft FoundrySpec + FoundryRunPlan
// authoring, bound only to REAL model-mount substrate. It renders the plane's hard boundary plainly:
// draft-only — no training/eval execution, no inference serving, no promotion or registry mutation,
// no authority bypass. Promotion is shown as a PREVIEW (would_promote:false), never applied.
const FOUNDRY_KINDS = ["model_eval", "model_tune", "tool_build", "inference_endpoint", "ontology"];
async function foundryCatalog() {
  const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => null);
  const [ro, pv, bk, ep] = await Promise.all([
    J("/v1/model-mount/routes"), J("/v1/model-mount/providers"),
    J("/v1/model-mount/backends"), J("/v1/model-mount/endpoints"),
  ]);
  const ids = (v, keys) => {
    const arr = Array.isArray(v) ? v : (v && (v.routes || v.providers || v.backends || v.endpoints)) || [];
    const out = [];
    for (const it of arr) { for (const k of keys) { if (it && it[k]) { out.push(it[k]); break; } } }
    return [...new Set(out)];
  };
  return {
    routes: ids(ro, ["id"]),
    providers: ids(pv, ["id", "provider_ref"]),
    backends: ids(bk, ["backend_id", "id"]),
    endpoints: ids(ep, ["endpoint_id", "id"]),
  };
}
// Build a FoundrySpec payload from a create/edit form (shared by POST create + POST patch).
function foundrySpecPayloadFromForm(p) {
  const list = (k) => p.getAll(k).map((s) => s.trim()).filter(Boolean);
  const csv = (k) => (p.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
  const inputs = {};
  const obj = (p.get("in_objective") || "").trim(); if (obj) inputs.objective = obj;
  const bm = (p.get("in_base_model") || "").trim(); if (bm) inputs.base_model = bm;
  const es = (p.get("in_eval_suite") || "").trim(); if (es) inputs.eval_suite = es;
  const ds = csv("in_dataset_refs"); if (ds.length) inputs.dataset_refs = ds;
  const payload = {
    name: (p.get("name") || "foundry-spec").trim(),
    description: (p.get("description") || "").trim(),
    kind: (p.get("kind") || "model_eval").trim(),
    model_route_refs: list("model_route_refs"),
    provider_refs: list("provider_refs"),
    backend_refs: list("backend_refs"),
    endpoint_refs: list("endpoint_refs"),
    evidence_refs: csv("evidence_refs"),
    inputs,
  };
  const apr = (p.get("authority_policy_ref") || "").trim(); if (apr) payload.authority_policy_ref = apr;
  return payload;
}
function renderFoundryLanding(overview, specs, runPlans, modelRoutes, routeBindings) {
  const enc = encodeURIComponent;
  const o = overview || {}; const sub = o.substrate || {}; const fc = o.foundry || {};
  const note = o.status_note || "Draft-only: no training/eval execution, no promotion or registry mutation in this plane.";
  const head = `<h1>Foundry</h1><p class="sub">The capability factory — the model catalog over real route substrate, plus draft specs and run plans with promotion previews. Nothing here trains, evaluates, serves, or promotes. <a href="/__apps/models">Model registry seed (adopting) →</a></p>`;
  const banner = `<div class="chips"><span class="pill warn">draft-only</span> <span class="sub" style="margin:0">${CX_ESC(note)}</span></div>`;
  const stat = (label, val) => `<div style="flex:1;min-width:104px;padding:12px 14px;border:1px solid #24262d;border-radius:10px;background:#15171c"><div style="font-size:22px;font-weight:700;color:#fff">${CX_ESC(String(val == null ? "—" : val))}</div><div style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(label)}</div></div>`;
  const stats = `<h2>Substrate</h2><div class="row" style="gap:10px;align-items:stretch">${stat("Model routes", sub.model_routes)}${stat("Providers", sub.providers)}${stat("Endpoints", sub.endpoints)}${stat("Backends", sub.backends)}${stat("Receipts", sub.model_mount_receipts)}${stat("Transcripts", sub.agent_transcripts)}${stat("Ledger", sub.work_ledger_entries)}</div>`;
  // ---- Model Catalog (49-model-catalog graft; 47-ml-library folds here) — every registered
  // model route as a catalog entry with its REAL posture: honest availability (probe evidence +
  // staleness), weight custody, credential posture, admission trail, and usage (admitted session
  // bindings). Read-only by design: route ADMIN (enable/disable/probe/select-default) has ONE
  // owner — Agent Studio — and the catalog links there rather than duplicating mutation lanes.
  const bindingsByRoute = {};
  (routeBindings || []).forEach((b) => { const k = b.route_ref || b.model_route_ref || ""; bindingsByRoute[k] = (bindingsByRoute[k] || 0) + 1; });
  const availPill = (r) => {
    const a = r.availability || {}; const st = a.state || "declared";
    const cls = st === "available" ? "ok" : st === "unavailable" ? "warn" : "muted";
    return `<span class="pill ${cls}">${CX_ESC(st)}</span>${a.stale ? ` <span class="pill muted" title="probe evidence is stale — re-probe in Studio">stale probe</span>` : ""}`;
  };
  const routeCard = (r) => {
    const cust = r.custody || {}; const adm = r.admission || {}; const m = r.model || {};
    const probe = (r.availability || {}).probe || {};
    const uses = bindingsByRoute[r.route_ref] || 0;
    const caps = [(m.modalities || []).join("/"), m.context_window ? `ctx ${m.context_window}` : "", m.family || ""].filter(Boolean).join(" · ");
    return `<div class="card" style="display:block" data-model-route="${CX_ESC(r.route_id || "")}">
      <div class="row" style="justify-content:space-between;margin:0 0 6px"><div><b>${CX_ESC(r.display_name || r.route_id || "route")}</b> ${r.default_route ? `<span class="pill ok">default</span>` : ""} <span class="pill ${(r.lifecycle || {}).status === "active" ? "ok" : "muted"}">${CX_ESC((r.lifecycle || {}).status || "—")}</span> ${availPill(r)}</div><code style="font-size:10.5px">${CX_ESC(r.route_ref || "")}</code></div>
      <dl class="wlgrid" style="grid-template-columns:110px 1fr">
        <dt class="wlk">Model</dt><dd class="wlv">${CX_ESC(caps || "no declared capabilities")}</dd>
        <dt class="wlk">Custody</dt><dd class="wlv">${CX_ESC(cust.weight_class || "—")} · mount ${CX_ESC(cust.mount_target || "—")} · ${CX_ESC(cust.execution_privacy_posture || "—")}</dd>
        <dt class="wlk">Credentials</dt><dd class="wlv">${CX_ESC(r.credential_posture || "—")}</dd>
        <dt class="wlk">Probe</dt><dd class="wlv">${probe.kind ? `${CX_ESC(probe.kind)} · ${CX_ESC(probe.checked_at || "")}${probe.evidence && probe.evidence.matched_model ? ` · matched <code>${CX_ESC(probe.evidence.matched_model)}</code>` : ""}` : "never probed — availability is declared, not proven"}</dd>
        <dt class="wlk">Admission</dt><dd class="wlv">${adm.last_admission_id ? `<code style="font-size:10px">${CX_ESC(adm.last_admission_id)}</code>` : "—"}${(adm.mutation_receipt_refs || []).length ? ` · ${(adm.mutation_receipt_refs || []).length} mutation receipt(s)` : ""}</dd>
        <dt class="wlk">Usage</dt><dd class="wlv">${uses ? `${uses} admitted session binding${uses > 1 ? "s" : ""}` : "no session bindings yet"}</dd>
      </dl>
      <div class="row" style="margin-top:8px"><a class="act ghost" href="/__ioi/agent-studio#model-routes">Manage in Studio →</a></div>
    </div>`;
  };
  const catalogGaps = omBoundaryNote(`This is the <b>real model registry</b> — every route's availability (probe evidence + staleness), weight custody, credential posture, and admission trail is daemon truth; route administration (enable/disable/probe/select-default) lives in <a href="/__ioi/agent-studio#model-routes">Agent Studio</a>. Unsupported reference lanes — <b>fine-tuning</b>, prompt playground, live inference evals, deployment automation, training runs, and model cards where not backed by route truth — are <b>named gaps</b> (no authority contract yet), not hidden. Sibling Foundry seeds stay reference-only: the <a href="/__apps/modelstudio">Model Studio</a> canvas and the <a href="/__apps/inference">inference</a> wizard. The <a href="/__apps/models">model registry reference capture ↗</a> is the familiar baseline, never a rebound surface.`);
  const catalogSec = `<div id="foundry-model-catalog"><h2>Model Catalog <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the registered routes with honest availability, custody, and usage; administration lives in Studio · <a href="/__ioi/foundry/models">Model Catalog (reference-faithful) →</a></span></h2>
    ${(modelRoutes || []).length ? (modelRoutes || []).map(routeCard).join("") : `<div class="empty">No model routes registered yet — add one in Studio to populate the catalog.</div>`}${catalogGaps}</div>`;
  const specCard = (s) => `<a class="card" href="/__ioi/foundry/specs/${enc(s.id || "")}"><div class="main"><div class="name">${CX_ESC(s.name || s.id || "spec")} <span class="pill muted">${CX_ESC(s.kind || "")}</span> <span class="pill warn">${CX_ESC(s.status || "draft")}</span></div><div class="meta"><code>${CX_ESC(s.id || "")}</code> · updated ${CX_ESC(s.updated_at || "")}</div></div><span class="act ghost">Open →</span></a>`;
  const planCard = (p) => `<a class="card" href="/__ioi/foundry/run-plans/${enc(p.id || "")}"><div class="main"><div class="name">${CX_ESC(p.name || p.id || "run plan")} <span class="pill warn">${CX_ESC(p.status || "draft")}</span></div><div class="meta">spec <code>${CX_ESC(p.spec_ref || "")}</code> · target ${CX_ESC(p.target_route_ref || p.target_provider_ref || "—")}</div></div><span class="act ghost">Open →</span></a>`;
  // ---- Evals lane (29-evals graft — Foundry sub-surface, never a standalone card). The
  // model_eval-kind specs as the eval workbench's draft plane; scorecards are the future feed
  // into Release Controls (linked), and this plane executes NOTHING — said plainly.
  const evalSpecs = specs.filter((s) => s.kind === "model_eval");
  const evalsSec = `<div id="foundry-evals"><h2>Evals <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— model_eval spec drafts; scorecards feed <a href="/__ioi/governance?tab=releases">Release Controls →</a>; no eval executes in this plane</span></h2>
    ${evalSpecs.length ? evalSpecs.map(specCard).join("") : `<div class="empty">No eval specs yet — create a FoundrySpec with kind <code>model_eval</code> bound to a real model route.</div>`}</div>`;
  const specsSec = `<h2 style="display:flex;justify-content:space-between;align-items:center">Specs (${specs.length}) <a class="act" href="/__ioi/foundry/specs/new">+ New spec</a></h2>${specs.length ? specs.map(specCard).join("") : `<div class="empty">No FoundrySpec drafts yet. Create one bound to a real model route or provider.</div>`}`;
  const plansSec = `<h2>Run plans (${runPlans.length})</h2>${runPlans.length ? runPlans.map(planCard).join("") : `<div class="empty">No FoundryRunPlan drafts yet. Open a spec and draft a run plan from it.</div>`}`;
  return automationsShell("Foundry", head + banner + stats + catalogSec + evalsSec + specsSec + plansSec);
}
function renderFoundrySpecForm(catalog, existing) {
  const enc = encodeURIComponent; const ex = existing || {}; const isEdit = !!existing;
  const action = isEdit ? `/__ioi/foundry/specs/${enc(ex.id)}/patch` : `/__ioi/foundry/specs`;
  const checks = (label, name, ids, current) => `<div class="field"><label>${label}</label>${ids.length ? ids.map((id) => `<label style="display:flex;gap:8px;align-items:center;font-weight:400;margin:3px 0"><input type="checkbox" name="${name}" value="${CX_ESC(id)}" ${(current || []).includes(id) ? "checked" : ""} style="width:auto"> <code>${CX_ESC(id)}</code></label>`).join("") : `<span class="sub" style="margin:0">none available</span>`}</div>`;
  const kindOpts = FOUNDRY_KINDS.map((k) => `<option value="${k}" ${ex.kind === k ? "selected" : ""}>${k}</option>`).join("");
  const inputs = ex.inputs || {};
  const inner = `<p><a href="/__ioi/foundry">← Foundry</a></p><h1>${isEdit ? "Edit" : "New"} FoundrySpec</h1>
    <p class="sub">A draft specification bound to <b>real</b> model substrate. Nothing here is executed or promoted.${isEdit ? ` Editing <code>${CX_ESC(ex.id)}</code>.` : ""}</p>
    <form method="post" action="${action}">
      <div class="two"><div class="field"><label>Name</label><input name="name" value="${CX_ESC(ex.name || "")}" placeholder="local-first eval baseline"></div>
        <div class="field"><label>Kind</label><select name="kind">${kindOpts}</select></div></div>
      <div class="field"><label>Description</label><textarea name="description" placeholder="What this spec captures (no execution).">${CX_ESC(ex.description || "")}</textarea></div>
      <p class="sub" style="margin:6px 0">Bind to real substrate — at least one model route or provider is required:</p>
      <div class="two">${checks("Model routes", "model_route_refs", catalog.routes, ex.model_route_refs)}${checks("Providers", "provider_refs", catalog.providers, ex.provider_refs)}</div>
      <div class="two">${checks("Backends", "backend_refs", catalog.backends, ex.backend_refs)}${checks("Endpoints", "endpoint_refs", catalog.endpoints, ex.endpoint_refs)}</div>
      <h2>Inputs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— named references, not uploads</span></h2>
      <div class="two"><div class="field"><label>Objective</label><input name="in_objective" value="${CX_ESC(inputs.objective || "")}" placeholder="baseline-quality"></div>
        <div class="field"><label>Base model (named)</label><input name="in_base_model" value="${CX_ESC(inputs.base_model || "")}" placeholder="hypervisor:native-local"></div></div>
      <div class="two"><div class="field"><label>Eval suite (named)</label><input name="in_eval_suite" value="${CX_ESC(inputs.eval_suite || "")}" placeholder="smoke"></div>
        <div class="field"><label>Dataset refs (comma-sep, named)</label><input name="in_dataset_refs" value="${CX_ESC((inputs.dataset_refs || []).join(", "))}" placeholder="ds.alpha, ds.beta"></div></div>
      <div class="field"><label>Evidence refs (comma-sep — transcript / receipt / ledger ids)</label><input name="evidence_refs" value="${CX_ESC((ex.evidence_refs || []).join(", "))}" placeholder="run_..., receipt_..."></div>
      <div class="field"><label>Authority policy ref (named-only — never enforced or bypassed here)</label><input name="authority_policy_ref" value="${CX_ESC(ex.authority_policy_ref || "")}" placeholder="policy.foundry.default"></div>
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft spec"}</button> <a class="act ghost" href="/__ioi/foundry">Cancel</a></div>
    </form>`;
  return automationsShell(`${isEdit ? "Edit" : "New"} FoundrySpec`, inner);
}
function renderFoundrySpecDetail(spec, plans) {
  const enc = encodeURIComponent; const s = spec || {};
  const refList = (label, arr) => `<dt>${label}</dt><dd>${arr && arr.length ? arr.map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") : "—"}</dd>`;
  const inputs = s.inputs || {};
  const inputBlock = Object.keys(inputs).length ? `<pre>${CX_ESC(JSON.stringify(inputs, null, 2))}</pre>` : `<span class="sub" style="margin:0">none</span>`;
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(s.id || "")}</code></dd>
    <dt>Kind</dt><dd>${CX_ESC(s.kind || "—")}</dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(s.status || "draft")}</span></dd>
    <dt>Description</dt><dd>${CX_ESC(s.description || "—")}</dd>
    ${refList("Model routes", s.model_route_refs)}${refList("Providers", s.provider_refs)}
    ${refList("Backends", s.backend_refs)}${refList("Endpoints", s.endpoint_refs)}
    ${refList("Evidence refs", s.evidence_refs)}
    <dt>Authority policy</dt><dd>${s.authority_policy_ref ? `<code>${CX_ESC(s.authority_policy_ref)}</code> <span class="sub" style="margin:0">(named-only)</span>` : "—"}</dd>
    <dt>Created · updated</dt><dd>${CX_ESC(s.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(s.updated_at || "")}</span></dd>
  </dl><h2>Inputs</h2>${inputBlock}`;
  const planRows = (plans || []).map((p) => `<tr><td><a href="/__ioi/foundry/run-plans/${enc(p.id || "")}">${CX_ESC(p.name || p.id || "")}</a></td><td><span class="pill warn">${CX_ESC(p.status || "draft")}</span></td><td>${CX_ESC(p.target_route_ref || p.target_provider_ref || "—")}</td></tr>`).join("");
  const plansSec = `<h2>Run plans from this spec</h2>${plans && plans.length ? `<table><thead><tr><th>Plan</th><th>Status</th><th>Target</th></tr></thead><tbody>${planRows}</tbody></table>` : `<div class="empty">No run plans yet.</div>`}`;
  const actions = `<div class="row"><a class="act" href="/__ioi/foundry/run-plans/new?spec=${enc(s.id || "")}">+ New run plan</a> <a class="act ghost" href="/__ioi/foundry/specs/${enc(s.id || "")}/edit">Edit draft</a> <form class="inline" method="post" action="/__ioi/foundry/specs/${enc(s.id || "")}/delete" onsubmit="return confirm('Delete this draft spec?')"><button class="act danger" type="submit">Delete draft</button></form></div>`;
  return automationsShell(s.name || "FoundrySpec", `<p><a href="/__ioi/foundry">← Foundry</a></p><h1>${CX_ESC(s.name || s.id || "")}</h1><p class="sub">FoundrySpec · draft. No execution or promotion.</p>${actions}${grid}${plansSec}`);
}
function renderFoundryRunPlanForm(spec, catalog) {
  const enc = encodeURIComponent; const s = spec || {};
  const sr = s.model_route_refs || []; const sp = s.provider_refs || [];
  const opt = (id, firstSel, inSpec) => `<option value="${CX_ESC(id)}" ${firstSel ? "selected" : ""}>${CX_ESC(id)}${inSpec ? " (from spec)" : ""}</option>`;
  const routeOpts = (catalog.routes || []).map((r) => opt(r, sr[0] === r, sr.includes(r))).join("");
  const provOpts = (catalog.providers || []).map((r) => opt(r, sp[0] === r, sp.includes(r))).join("");
  const inner = `<p><a href="/__ioi/foundry/specs/${enc(s.id || "")}">← ${CX_ESC(s.name || s.id || "")}</a></p><h1>New FoundryRunPlan</h1>
    <p class="sub">A draft plan from <code>${CX_ESC(s.id || "")}</code>. It records a target plus a promotion <b>preview</b> — nothing is dispatched or promoted.</p>
    <form method="post" action="/__ioi/foundry/run-plans"><input type="hidden" name="spec_ref" value="${CX_ESC(s.id || "")}">
      <div class="field"><label>Name</label><input name="name" placeholder="baseline eval plan"></div>
      <div class="field"><label>Description</label><textarea name="description"></textarea></div>
      <div class="two"><div class="field"><label>Target route</label><select name="target_route_ref"><option value="">— none —</option>${routeOpts}</select></div>
        <div class="field"><label>Target provider</label><select name="target_provider_ref"><option value="">— none —</option>${provOpts}</select></div></div>
      <div class="field"><label>Planned steps (comma-sep phase names — opaque, not dispatched)</label><input name="steps" placeholder="prepare, evaluate, report"></div>
      <div class="row"><button class="act" type="submit">Create draft run plan</button> <a class="act ghost" href="/__ioi/foundry/specs/${enc(s.id || "")}">Cancel</a></div>
    </form>`;
  return automationsShell("New FoundryRunPlan", inner);
}
function renderFoundryRunPlanDetail(plan, spec) {
  const enc = encodeURIComponent; const p = plan || {}; const pp = p.promotion_preview || {};
  const steps = Array.isArray(p.steps) ? p.steps : [];
  const stepList = steps.length ? steps.map((st) => `<code>${CX_ESC(typeof st === "string" ? st : (st.phase || JSON.stringify(st)))}</code>`).join(" → ") : `<span class="sub" style="margin:0">none</span>`;
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(p.id || "")}</code></dd>
    <dt>Spec</dt><dd><a href="/__ioi/foundry/specs/${enc(p.spec_ref || "")}">${CX_ESC((spec && spec.name) || p.spec_ref || "")}</a></dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(p.status || "draft")}</span></dd>
    <dt>Target route</dt><dd>${p.target_route_ref ? `<code>${CX_ESC(p.target_route_ref)}</code>` : "—"}</dd>
    <dt>Target provider</dt><dd>${p.target_provider_ref ? `<code>${CX_ESC(p.target_provider_ref)}</code>` : "—"}</dd>
    <dt>Planned steps</dt><dd>${stepList}</dd>
    <dt>Created · updated</dt><dd>${CX_ESC(p.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(p.updated_at || "")}</span></dd>
  </dl>`;
  const preview = `<h2>Promotion preview</h2><div class="reveal" style="color:#d6a13a;background:#28220f;border-color:#5c4a23">would_promote: <b>${pp.would_promote === true ? "true" : "false"}</b> · no mutation performed<br>${CX_ESC(pp.note || "preview only — no promotion, registry alias, or model mutation")}</div>`;
  const actions = `<div class="row"><form class="inline" method="post" action="/__ioi/foundry/run-plans/${enc(p.id || "")}/delete" onsubmit="return confirm('Delete this draft run plan?')"><button class="act danger" type="submit">Delete draft</button></form></div>`;
  return automationsShell(p.name || "FoundryRunPlan", `<p><a href="/__ioi/foundry">← Foundry</a></p><h1>${CX_ESC(p.name || p.id || "")}</h1><p class="sub">FoundryRunPlan · draft. No execution.</p>${actions}${grid}${preview}`);
}

// ---- ODK — a CONTROLLED BUILDER over the daemon ODK object plane (estate surface #5).
// Serve-owned UI over /v1/hypervisor/odk/*: author draft DomainOntology / DataRecipe /
// OntologySurfaceDescriptor / ODKManifest, bound only to real ODK records. Hard boundary rendered
// plainly: draft-only semantic builder — no transformation runs, no generated app runtime, no
// Domain App creation, no training/eval execution, no authority crossing. `domain_app` is offered
// as a descriptor pattern but is labelled descriptor-only (NOT a live Domain App).
const odkJoin = (arr) => (arr || []).map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(", ");
const odkField = (label, name, val, ph) => `<div class="field"><label>${label}</label><input name="${name}" value="${CX_ESC(val || "")}" placeholder="${CX_ESC(ph || "")}"></div>`;
const odkArea = (label, name, val, ph) => `<div class="field"><label>${label}</label><textarea name="${name}" placeholder="${CX_ESC(ph || "")}">${CX_ESC(val || "")}</textarea></div>`;
const odkCsvField = (label, name, arr, ph) => `<div class="field"><label>${label}</label><input name="${name}" value="${CX_ESC(odkJoin(arr))}" placeholder="${CX_ESC(ph || "")}"></div>`;
const odkSelectField = (label, name, opts, cur, emptyMsg) => `<div class="field"><label>${label}</label>${opts.length ? `<select name="${name}">${opts.map((o) => `<option value="${CX_ESC(o.v)}" ${o.v === cur ? "selected" : ""}>${CX_ESC(o.l)}</option>`).join("")}</select>` : `<div class="sub" style="margin:0">${CX_ESC(emptyMsg || "none available")}</div>`}</div>`;
const odkChecks = (label, name, opts, current) => `<div class="field"><label>${label}</label>${opts.length ? opts.map((o) => `<label style="display:flex;gap:8px;align-items:center;font-weight:400;margin:3px 0"><input type="checkbox" name="${name}" value="${CX_ESC(o.v)}" ${(current || []).includes(o.v) ? "checked" : ""} style="width:auto"> ${CX_ESC(o.l)} <code style="opacity:.55">${CX_ESC(o.v)}</code></label>`).join("") : `<span class="sub" style="margin:0">none available — create one first</span>`}</div>`;
// Map an ODK ref (scheme://id) to its detail page link.
function odkRefLink(ref) {
  const m = String(ref || "").match(/^([a-z-]+):\/\/(.+)$/);
  if (!m) return ref ? `<code>${CX_ESC(ref)}</code>` : "—";
  const fam = { ontology: "ontologies", recipe: "data-recipes", "surface-descriptor": "surface-descriptors", odk: "manifests" }[m[1]];
  return fam ? `<a href="/__ioi/odk/${fam}/${encodeURIComponent(m[2])}"><code>${CX_ESC(ref)}</code></a>` : `<code>${CX_ESC(ref)}</code>`;
}
async function odkPickers() {
  const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
  const [o, r, d] = await Promise.all([
    J("/v1/hypervisor/odk/domain-ontologies"), J("/v1/hypervisor/odk/data-recipes"), J("/v1/hypervisor/odk/surface-descriptors"),
  ]);
  const opt = (rec, nameKey) => ({ v: rec.ref, l: rec[nameKey] || rec.name || rec.id });
  return {
    ontologies: (o.ontologies || []).map((x) => opt(x, "domain")),
    recipes: (r.data_recipes || []).map((x) => opt(x, "name")),
    descriptors: (d.surface_descriptors || []).map((x) => opt(x, "name")),
  };
}
// ---- payload builders (form -> daemon JSON), shared by create + patch.
function odkOntologyPayload(p) {
  // The typed CanonicalObjectModel is authored as JSON; a parse failure is marked so the daemon
  // rejects it with a clean error (never silently dropped to an empty model).
  const raw = (p.get("canonical_object_model") || "").trim();
  let com;
  if (!raw) com = { value_types: [], object_types: [], link_types: [], action_types: [] };
  else { try { com = JSON.parse(raw); } catch { com = { __json_parse_error: true }; } }
  return {
    domain: (p.get("domain") || "").trim(), version: (p.get("version") || "0.1.0").trim(), description: (p.get("description") || "").trim(),
    canonical_object_model: com,
  };
}
function odkRecipePayload(p) {
  const csv = (k) => (p.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    name: (p.get("name") || "data-recipe").trim(), description: (p.get("description") || "").trim(),
    ontology_ref: (p.get("ontology_ref") || "").trim(), output_kind: (p.get("output_kind") || "ontology_objects").trim(),
    source_refs: csv("source_refs"), connector_mappings: csv("connector_mappings"), policy_bound_views: csv("policy_bound_views"),
    projection_refs: csv("projection_refs"), evaluation_dataset_refs: csv("evaluation_dataset_refs"),
    worker_plan_refs: csv("worker_plan_refs"), workflow_schema_refs: csv("workflow_schema_refs"),
  };
}
function odkDescriptorPayload(p) {
  return {
    name: (p.get("name") || "surface-descriptor").trim(), description: (p.get("description") || "").trim(),
    composition_pattern: (p.get("composition_pattern") || "list_detail").trim(),
    ontology_ref: (p.get("ontology_ref") || "").trim(),
    recipe_refs: p.getAll("recipe_refs").map((s) => s.trim()).filter(Boolean),
  };
}
function odkManifestPayload(p) {
  const csv = (k) => (p.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    name: (p.get("name") || "odk-manifest").trim(), description: (p.get("description") || "").trim(),
    ontology_refs: p.getAll("ontology_refs").map((s) => s.trim()).filter(Boolean),
    recipe_refs: p.getAll("recipe_refs").map((s) => s.trim()).filter(Boolean),
    surface_descriptor_refs: p.getAll("surface_descriptor_refs").map((s) => s.trim()).filter(Boolean),
    eval_refs: csv("eval_refs"), worker_plan_refs: csv("worker_plan_refs"), mcp_operator_contracts: csv("mcp_operator_contracts"),
  };
}
function odkDetailActions(family, id) {
  const e = encodeURIComponent;
  return `<div class="row"><a class="act ghost" href="/__ioi/odk/${family}/${e(id)}/edit">Edit draft</a> <form class="inline" method="post" action="/__ioi/odk/${family}/${e(id)}/delete" onsubmit="return confirm('Delete this draft?')"><button class="act danger" type="submit">Delete draft</button></form></div>`;
}
// ---- forms
function renderOdkOntologyForm(existing) {
  const ex = existing || {}; const isEdit = !!existing;
  const com = ex.canonical_object_model || { value_types: [], object_types: [], link_types: [], action_types: [] };
  const comJson = JSON.stringify(com, null, 2);
  const action = isEdit ? `/__ioi/odk/ontologies/${encodeURIComponent(ex.id)}/patch` : `/__ioi/odk/ontologies`;
  const shape = `value_types: [{ id, name, base, enum_values? }]   base ∈ string integer double boolean timestamp date enum markdown geo_point attachment
object_types: [{ id, name, title_property?, properties:[{ id, name, value_type, required? }] }]   value_type → a base or a declared value_type id
link_types: [{ id, name, from, to, cardinality }]   from/to → object_type ids · cardinality ∈ one_to_one one_to_many many_to_many
action_types: [{ id, name, kind, applies_to? }]   kind ∈ create_object modify_object delete_object function
Type ids match ^[a-z][a-z0-9_]*$. Health is "ready" only with ≥1 typed object (properties + title) and ≥1 link or action.`;
  const inner = `<p><a href="/__ioi/odk">← ODK</a></p><h1>${isEdit ? "Edit" : "New"} Domain Ontology</h1>
    <p class="sub">The typed semantic root — validated fail-closed by the daemon. Draft-only; nothing is generated or executed.</p>
    <form method="post" action="${action}">
      <div class="two">${odkField("Domain", "domain", ex.domain, "lending")}${odkField("Version", "version", ex.version || "0.1.0")}</div>
      ${odkArea("Description", "description", ex.description)}
      <h2>Canonical object model <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— typed JSON</span></h2>
      <details style="margin:0 0 8px"><summary class="sub" style="cursor:pointer">Shape — value / object / link / action types</summary><pre class="sub" style="white-space:pre-wrap;margin:6px 0 0">${CX_ESC(shape)}</pre></details>
      <div class="field"><label>canonical_object_model (JSON)</label><textarea name="canonical_object_model" rows="16" style="font-family:ui-monospace,monospace;font-size:12px">${CX_ESC(comJson)}</textarea></div>
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft ontology"}</button> <a class="act ghost" href="/__ioi/odk">Cancel</a></div>
    </form>`;
  return automationsShell(`${isEdit ? "Edit" : "New"} Domain Ontology`, inner);
}
function renderOdkRecipeForm(existing, pk, outputKinds) {
  const ex = existing || {}; const isEdit = !!existing;
  const action = isEdit ? `/__ioi/odk/data-recipes/${encodeURIComponent(ex.id)}/patch` : `/__ioi/odk/data-recipes`;
  const okOpts = (outputKinds || []).map((k) => ({ v: k, l: k }));
  const inner = `<p><a href="/__ioi/odk">← ODK</a></p><h1>${isEdit ? "Edit" : "New"} Data Recipe</h1>
    <p class="sub">A repeatable transformation recipe bound to an ontology. Draft-only — no transformation runs.</p>
    <form method="post" action="${action}">
      ${odkField("Name", "name", ex.name, "loan-ingest")}
      ${odkArea("Description", "description", ex.description)}
      <div class="two">${odkSelectField("Ontology (required)", "ontology_ref", pk.ontologies, ex.ontology_ref, "no ontologies yet — create one first")}${odkSelectField("Output kind", "output_kind", okOpts, ex.output_kind || "ontology_objects")}</div>
      ${odkCsvField("Source refs (comma-sep, named)", "source_refs", ex.source_refs, "s3://…, trace-…")}
      <div class="two">${odkCsvField("Connector mappings (named)", "connector_mappings", ex.connector_mappings)}${odkCsvField("Policy-bound views (named)", "policy_bound_views", ex.policy_bound_views)}</div>
      <h2>Named output refs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— resolved only when ODK-local</span></h2>
      <div class="two">${odkCsvField("Projection refs", "projection_refs", ex.projection_refs)}${odkCsvField("Evaluation dataset refs", "evaluation_dataset_refs", ex.evaluation_dataset_refs)}</div>
      <div class="two">${odkCsvField("Worker plan refs", "worker_plan_refs", ex.worker_plan_refs)}${odkCsvField("Workflow schema refs", "workflow_schema_refs", ex.workflow_schema_refs)}</div>
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft recipe"}</button> <a class="act ghost" href="/__ioi/odk">Cancel</a></div>
    </form>`;
  return automationsShell(`${isEdit ? "Edit" : "New"} Data Recipe`, inner);
}
function renderOdkDescriptorForm(existing, pk, patterns) {
  const ex = existing || {}; const isEdit = !!existing;
  const action = isEdit ? `/__ioi/odk/surface-descriptors/${encodeURIComponent(ex.id)}/patch` : `/__ioi/odk/surface-descriptors`;
  const patOpts = (patterns || []).map((p) => ({ v: p, l: p === "domain_app" ? "domain_app — descriptor-only (not a live Domain App)" : p }));
  const inner = `<p><a href="/__ioi/odk">← ODK</a></p><h1>${isEdit ? "Edit" : "New"} Surface Descriptor</h1>
    <p class="sub">A descriptor for a domain surface. <b>domain_app is descriptor-only</b> — this plane creates no live Domain App.</p>
    <form method="post" action="${action}">
      ${odkField("Name", "name", ex.name, "loan list")}
      ${odkArea("Description", "description", ex.description)}
      <div class="two">${odkSelectField("Ontology (required)", "ontology_ref", pk.ontologies, ex.ontology_ref, "create an ontology first")}${odkSelectField("Composition pattern", "composition_pattern", patOpts, ex.composition_pattern || "list_detail")}</div>
      ${odkChecks("Recipe refs (optional)", "recipe_refs", pk.recipes, ex.recipe_refs)}
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft descriptor"}</button> <a class="act ghost" href="/__ioi/odk">Cancel</a></div>
    </form>`;
  return automationsShell(`${isEdit ? "Edit" : "New"} Surface Descriptor`, inner);
}
function renderOdkManifestForm(existing, pk) {
  const ex = existing || {}; const isEdit = !!existing;
  const action = isEdit ? `/__ioi/odk/manifests/${encodeURIComponent(ex.id)}/patch` : `/__ioi/odk/manifests`;
  const inner = `<p><a href="/__ioi/odk">← ODK</a></p><h1>${isEdit ? "Edit" : "New"} ODK Manifest</h1>
    <p class="sub">A builder/conformance bundle. Requires at least one ontology. Draft-only.</p>
    <form method="post" action="${action}">
      ${odkField("Name", "name", ex.name, "lending odk")}
      ${odkArea("Description", "description", ex.description)}
      ${odkChecks("Ontology refs (required)", "ontology_refs", pk.ontologies, ex.ontology_refs)}
      ${odkChecks("Recipe refs", "recipe_refs", pk.recipes, ex.recipe_refs)}
      ${odkChecks("Surface descriptor refs", "surface_descriptor_refs", pk.descriptors, ex.surface_descriptor_refs)}
      <h2>Named contract refs</h2>
      <div class="two">${odkCsvField("Eval refs", "eval_refs", ex.eval_refs)}${odkCsvField("Worker plan refs", "worker_plan_refs", ex.worker_plan_refs)}</div>
      ${odkCsvField("MCP / operator contracts", "mcp_operator_contracts", ex.mcp_operator_contracts)}
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft manifest"}</button> <a class="act ghost" href="/__ioi/odk">Cancel</a></div>
    </form>`;
  return automationsShell(`${isEdit ? "Edit" : "New"} ODK Manifest`, inner);
}
// Reverse lineage (source shape: the ontology workbench demands a LINEAGE view — from any semantic
// node you can trace what references it, not only what it references). Computed in-memory from the
// four family lists the plane already serves — no new daemon endpoint; a record with no inbound
// refs says so plainly instead of hiding the section.
function odkReferencedBy(rec, lists, family) {
  if (!rec || !lists) return "";
  const ref = rec.ref || "";
  const has = (arr, v) => Array.isArray(arr) && arr.includes(v);
  const hits = [];
  if (family === "ontologies") {
    for (const r of lists.data_recipes || []) if (r.ontology_ref === ref) hits.push(["Data Recipe", "data-recipes", r]);
    for (const d of lists.surface_descriptors || []) if (d.ontology_ref === ref) hits.push(["Surface Descriptor", "surface-descriptors", d]);
    for (const m of lists.manifests || []) if (has(m.ontology_refs, ref)) hits.push(["ODK Manifest", "manifests", m]);
  } else if (family === "data-recipes") {
    for (const d of lists.surface_descriptors || []) if (has(d.recipe_refs, ref)) hits.push(["Surface Descriptor", "surface-descriptors", d]);
    for (const m of lists.manifests || []) if (has(m.recipe_refs, ref)) hits.push(["ODK Manifest", "manifests", m]);
  } else if (family === "surface-descriptors") {
    for (const m of lists.manifests || []) if (has(m.surface_descriptor_refs, ref)) hits.push(["ODK Manifest", "manifests", m]);
  } else {
    return "";
  }
  const rows = hits.map(([kind, fam, x]) => `<a class="card" href="/__ioi/odk/${fam}/${encodeURIComponent(x.id)}"><div class="main"><div class="name" style="font-size:13px">${CX_ESC(x.name || x.domain || x.id)} <span class="pill muted">${kind}</span></div><div class="meta"><code>${CX_ESC(x.ref || "")}</code></div></div><span class="act ghost">Open →</span></a>`);
  return `<h2>Referenced by (${hits.length})</h2>` + (hits.length ? rows.join("") : `<div class="empty">No other ODK draft references this record yet.</div>`);
}
// ---- detail pages
// ---- Proof citations (52-data-lineage graft — provenance ON the object). Every proof-stream
// entry whose payload cites this record's ref, verbatim from the Work Ledger: reverse lineage
// above shows which DRAFTS reference it, this shows which GOVERNED WORK touched it.
function odkProofCitations(rec, lists) {
  const ref = (rec || {}).ref || "";
  const cits = ref ? ((lists || {}).ledger || []).filter((e) => JSON.stringify(e).includes(ref)) : [];
  const rows = cits.slice(0, 5).map((e) => `<tr><td>${CX_ESC(e.kind || "")}</td><td><span class="pill ${(e.status === "done" || e.status === "success" || e.status === "ok") ? "ok" : "muted"}">${CX_ESC(e.status || "—")}</span></td><td>${CX_ESC(e.timestamp || "")}</td><td><code style="font-size:10px">${CX_ESC((e.state_root || "").slice(0, 18) || "—")}</code></td></tr>`).join("");
  return `<div id="odk-proof-citations"><h2>Proof citations <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— proof-stream entries citing <code>${CX_ESC(ref)}</code></span></h2>
    ${cits.length ? `<table><thead><tr><th>Kind</th><th>Status</th><th>When</th><th>Proof</th></tr></thead><tbody>${rows}</tbody></table><p class="sub" style="margin:6px 0 0">${cits.length} citation${cits.length === 1 ? "" : "s"} · <a href="/__ioi/work-ledger">Provenance →</a></p>`
      : `<div class="empty">No proof-stream citations yet — receipts cite this ref when governed work touches it.</div>`}</div>`;
}
// ---- Ontology-manager rendering. The typed CanonicalObjectModel is daemon-validated authority;
// health is honest (draft/incomplete allowed); the plane owns NO object instances, so no explorer
// rows are ever shown — the schema/explorer captures stay secondary reference grammars.
function ontologyHealthPill(h) {
  const st = (h && h.status) || "empty";
  const cls = st === "ready" ? "ok" : st === "empty" ? "muted" : "warn";
  return `<span class="pill ${cls}">${CX_ESC(st)}</span>`;
}
function renderOntologyHealth(h) {
  h = h || {}; const c = h.counts || {};
  const counts = `${c.object_types || 0} obj · ${c.value_types || 0} val · ${c.link_types || 0} link · ${c.action_types || 0} act`;
  const gaps = (h.gaps && h.gaps.length)
    ? `<ul style="margin:6px 0 0;padding-left:18px">${h.gaps.map((g) => `<li class="sub" style="margin:0">${CX_ESC(g)}</li>`).join("")}</ul>`
    : `<div class="sub" style="margin:6px 0 0">No gaps — the required semantic pieces are present.</div>`;
  const instances = h.object_instances == null ? 0 : h.object_instances;
  return `<div style="border:1px solid #24262d;border-radius:10px;padding:12px 14px;margin:0 0 14px;background:#15171c">
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><b>Readiness</b> ${ontologyHealthPill(h)} <span class="sub" style="margin:0">${CX_ESC(counts)}</span></div>
    ${gaps}
    <div class="sub" style="margin:8px 0 0"><b>${CX_ESC(String(instances))}</b> object instances — ${CX_ESC(h.object_data_note || "schema only; no object-instance plane is bound.")}</div>
  </div>`;
}
function renderOntologyModel(com) {
  com = com || {}; const esc = CX_ESC; const idc = (x) => `<code>${esc(x || "")}</code>`;
  const arr = (k) => (Array.isArray(com[k]) ? com[k] : []);
  const vts = arr("value_types"), ots = arr("object_types"), lts = arr("link_types"), ats = arr("action_types");
  const valueTable = vts.length
    ? `<table><thead><tr><th>Value type</th><th>Base</th><th>Enum</th></tr></thead><tbody>${vts.map((v) => `<tr><td>${esc(v.name || v.id)} ${idc(v.id)}</td><td><span class="pill muted">${esc(v.base || "string")}</span></td><td>${(v.enum_values && v.enum_values.length) ? v.enum_values.map((e) => `<span class="pill muted">${esc(e)}</span>`).join(" ") : "—"}</td></tr>`).join("")}</tbody></table>`
    : `<div class="empty">No value types.</div>`;
  const objBlocks = ots.length ? ots.map((o) => {
    const props = Array.isArray(o.properties) ? o.properties : [];
    const ptable = props.length
      ? `<table><thead><tr><th>Property</th><th>Value type</th><th>Required</th></tr></thead><tbody>${props.map((p) => `<tr><td>${esc(p.name || p.id)} ${idc(p.id)}${o.title_property === p.id ? ` <span class="pill ok">title</span>` : ""}</td><td><code>${esc(p.value_type || "")}</code></td><td>${p.required ? "yes" : "—"}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty">No properties.</div>`;
    return `<div id="ot-${encodeURIComponent(o.id || "")}" style="border:1px solid #24262d;border-radius:10px;padding:10px 12px;margin:0 0 10px;background:#15171c;scroll-margin-top:16px"><div style="font-weight:600;margin-bottom:4px">${esc(o.name || o.id)} ${idc(o.id)}</div>${ptable}</div>`;
  }).join("") : `<div class="empty">No object types — the model is an empty draft.</div>`;
  const linkTable = lts.length
    ? `<table><thead><tr><th>Link</th><th>From → To</th><th>Cardinality</th></tr></thead><tbody>${lts.map((l) => `<tr><td>${esc(l.name || l.id)} ${idc(l.id)}</td><td><code>${esc(l.from || "")}</code> → <code>${esc(l.to || "")}</code></td><td><span class="pill muted">${esc(l.cardinality || "")}</span></td></tr>`).join("")}</tbody></table>`
    : `<div class="empty">No link types.</div>`;
  const actTable = ats.length
    ? `<table><thead><tr><th>Action / function</th><th>Kind</th><th>Applies to</th></tr></thead><tbody>${ats.map((a) => `<tr><td>${esc(a.name || a.id)} ${idc(a.id)}</td><td><span class="pill muted">${esc(a.kind || "")}</span></td><td>${a.applies_to ? `<code>${esc(a.applies_to)}</code>` : "—"}</td></tr>`).join("")}</tbody></table>`
    : `<div class="empty">No action / function types.</div>`;
  return `<h2>Value types (${vts.length})</h2>${valueTable}<h2>Object types (${ots.length})</h2>${objBlocks}<h2>Link types (${lts.length})</h2>${linkTable}<h2>Actions &amp; functions (${ats.length})</h2>${actTable}`;
}
function renderOdkOntologyDetail(o, lists) {
  const com = o.canonical_object_model || {};
  // Legacy (pre-hardening) untyped string arrays are shown as clearly-labeled, non-authoritative names.
  const legacyChips = (arr) => arr.map((x) => `<span class="pill muted">${CX_ESC(typeof x === "string" ? x : (x.name || x.id || ""))}</span>`).join(" ");
  const legacy = [["objects", com.objects], ["actions", com.actions], ["events", com.events], ["states", com.states], ["roles", com.roles]]
    .filter(([, v]) => Array.isArray(v) && v.length && v.every((x) => typeof x === "string"));
  const legacyBlock = legacy.length
    ? `<h2>Legacy names <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— untyped, pre-hardening; not part of the validated model</span></h2><dl class="grid">${legacy.map(([k, v]) => `<dt>${CX_ESC(k)}</dt><dd>${legacyChips(v)}</dd>`).join("")}</dl>`
    : "";
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(o.id)}</code></dd><dt>Ref</dt><dd><code>${CX_ESC(o.ref)}</code></dd>
    <dt>Domain · version</dt><dd>${CX_ESC(o.domain)} · ${CX_ESC(o.version || "")}</dd>
    <dt>Status · revision</dt><dd><span class="pill warn">${CX_ESC(o.status || "draft")}</span> <span class="pill muted">rev ${CX_ESC(String(o.revision || 1))}</span></dd>
    <dt>Description</dt><dd>${CX_ESC(o.description || "—")}</dd>
    <dt>Created · updated</dt><dd>${CX_ESC(o.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(o.updated_at || "")}</span></dd>
  </dl>`;
  const hist = (o.history && o.history.length)
    ? `<h2>History (${o.history.length})</h2><dl class="grid">${o.history.slice().reverse().map((e) => `<dt>rev ${CX_ESC(String(e.revision || ""))} · ${CX_ESC(e.op || "")}</dt><dd>${CX_ESC(e.summary || "")}<br><span class="sub" style="margin:0">${CX_ESC(e.at || "")}${e.receipt_ref ? ` · <code>${CX_ESC(e.receipt_ref)}</code>` : ""}</span></dd>`).join("")}</dl>`
    : "";
  const explorerNote = `<p class="sub" style="margin:14px 0 0"><b>Object explorer:</b> no rows — this ontology binds no object-instance plane (schema only). The <a href="/__apps/explorer">Object explorer capture ↗</a> is a secondary reference grammar, not a rebound surface.</p>`;
  return automationsShell(o.domain || "Domain Ontology", `<p><a href="/__ioi/odk">← ODK</a></p><h1>${CX_ESC(o.domain || o.id)}</h1><p class="sub">DomainOntology · draft · the typed semantic world-model (daemon-validated).</p>${odkDetailActions("ontologies", o.id)}${renderOntologyHealth(o.health)}${grid}${renderOntologyModel(com)}${legacyBlock}${hist}${explorerNote}${odkReferencedBy(o, lists, "ontologies")}${odkProofCitations(o, lists)}`);
}
function renderOdkRecipeDetail(r, lists) {
  const refrow = (label, arr) => `<dt>${label}</dt><dd>${(arr && arr.length) ? arr.map((x) => odkRefLink(x)).join(" ") : "—"}</dd>`;
  const strrow = (label, arr) => `<dt>${label}</dt><dd>${(arr && arr.length) ? arr.map((x) => `<code>${CX_ESC(typeof x === "string" ? x : JSON.stringify(x))}</code>`).join(" ") : "—"}</dd>`;
  // ---- Explicit handoff chain (data-recipes native; cross-cutting rule: the recipe handoff is
  // EXPLICIT — source sample → policy-bound view → object mapping → validation → lineage →
  // emission). Every stage's posture comes from the record's own fields; validation is a NAMED
  // GAP on this draft plane (it lands with execution), never a green checkmark.
  const inManifests = ((lists || {}).manifests || []).filter((m) => (m.recipe_refs || []).includes(r.ref)).length;
  const emissionN = (r.projection_refs || []).length + (r.evaluation_dataset_refs || []).length;
  const stages = [
    ["Source sample", (r.source_refs || []).length ? "ok" : "muted", `${(r.source_refs || []).length || "no"} source ref${(r.source_refs || []).length === 1 ? "" : "s"}`],
    ["Connector mapping", (r.connector_mappings || []).length ? "ok" : "muted", `${(r.connector_mappings || []).length || "none"} embedded`],
    ["Policy-bound view", (r.policy_bound_views || []).length ? "ok" : "muted", `${(r.policy_bound_views || []).length || "none"} declared`],
    ["Object mapping", r.ontology_ref ? "ok" : "muted", r.ontology_ref ? "bound to ontology" : "no ontology bound"],
    ["Validation", "warn", "named gap — lands with execution, never faked here"],
    ["Lineage", inManifests ? "ok" : "muted", inManifests ? `in ${inManifests} manifest${inManifests === 1 ? "" : "s"}` : "not yet in a manifest"],
    ["Emission", emissionN || r.output_kind ? "ok" : "muted", `${CX_ESC(r.output_kind || "no kind")}${emissionN ? ` · ${emissionN} named ref${emissionN === 1 ? "" : "s"}` : ""}`],
  ];
  const chain = `<div id="recipe-handoff-chain" style="display:flex;flex-wrap:wrap;gap:6px;align-items:stretch;margin:0 0 16px">${stages.map(([name, cls, det], i) => `${i ? `<div style="align-self:center;color:#5f626b">→</div>` : ""}<div style="flex:1;min-width:118px;padding:9px 11px;border:1px solid ${cls === "ok" ? "#235c3b" : cls === "warn" ? "#5c4a23" : "#24262d"};border-radius:10px;background:#15171c"><div style="font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#878a93">${name}</div><div style="font-size:12px;margin-top:3px;color:${cls === "ok" ? "#46c277" : cls === "warn" ? "#d6a13a" : "#9a9da6"}">${det}</div></div>`).join("")}</div>`;
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(r.id)}</code></dd><dt>Ref</dt><dd><code>${CX_ESC(r.ref)}</code></dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(r.status || "draft")}</span></dd>
    <dt>Ontology</dt><dd>${odkRefLink(r.ontology_ref)}</dd>
    <dt>Output kind</dt><dd>${CX_ESC(r.output_kind || "—")}</dd>
    ${strrow("Source refs", r.source_refs)}${strrow("Connector mappings", r.connector_mappings)}${strrow("Policy-bound views", r.policy_bound_views)}
    ${refrow("Projection refs", r.projection_refs)}${refrow("Evaluation dataset refs", r.evaluation_dataset_refs)}
    ${refrow("Worker plan refs", r.worker_plan_refs)}${refrow("Workflow schema refs", r.workflow_schema_refs)}
    <dt>Created · updated</dt><dd>${CX_ESC(r.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(r.updated_at || "")}</span></dd>
  </dl>`;
  return automationsShell(r.name || "Data Recipe", `<p><a href="/__ioi/odk">← ODK</a></p><h1>${CX_ESC(r.name || r.id)}</h1><p class="sub">DataRecipe · draft. No transformation runs.</p>${odkDetailActions("data-recipes", r.id)}${chain}${grid}${odkReferencedBy(r, lists, "data-recipes")}${odkProofCitations(r, lists)}`);
}
function renderOdkDescriptorDetail(d, lists) {
  const isDA = d.composition_pattern === "domain_app";
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(d.id)}</code></dd><dt>Ref</dt><dd><code>${CX_ESC(d.ref)}</code></dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(d.status || "draft")}</span></dd>
    <dt>Composition pattern</dt><dd><span class="pill ${isDA ? "warn" : "muted"}">${CX_ESC(d.composition_pattern || "—")}</span>${isDA ? ` <span class="sub" style="margin:0">descriptor-only — not a live Domain App</span>` : ""}</dd>
    <dt>Ontology</dt><dd>${odkRefLink(d.ontology_ref)}</dd>
    <dt>Recipe refs</dt><dd>${(d.recipe_refs && d.recipe_refs.length) ? d.recipe_refs.map((x) => odkRefLink(x)).join(" ") : "—"}</dd>
    <dt>Created · updated</dt><dd>${CX_ESC(d.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(d.updated_at || "")}</span></dd>
  </dl>`;
  return automationsShell(d.name || "Surface Descriptor", `<p><a href="/__ioi/odk">← ODK</a></p><h1>${CX_ESC(d.name || d.id)}</h1><p class="sub">OntologySurfaceDescriptor · draft.</p>${odkDetailActions("surface-descriptors", d.id)}${grid}${odkReferencedBy(d, lists, "surface-descriptors")}${odkProofCitations(d, lists)}`);
}
function renderOdkManifestDetail(m) {
  const refrow = (label, arr) => `<dt>${label}</dt><dd>${(arr && arr.length) ? arr.map((x) => odkRefLink(x)).join(" ") : "—"}</dd>`;
  const strrow = (label, arr) => `<dt>${label}</dt><dd>${(arr && arr.length) ? arr.map((x) => `<code>${CX_ESC(typeof x === "string" ? x : JSON.stringify(x))}</code>`).join(" ") : "—"}</dd>`;
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(m.id)}</code></dd><dt>Ref</dt><dd><code>${CX_ESC(m.ref)}</code></dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(m.status || "draft")}</span></dd>
    ${refrow("Ontology refs", m.ontology_refs)}${refrow("Recipe refs", m.recipe_refs)}${refrow("Surface descriptor refs", m.surface_descriptor_refs)}
    ${strrow("Eval refs", m.eval_refs)}${strrow("Worker plan refs", m.worker_plan_refs)}${strrow("MCP / operator contracts", m.mcp_operator_contracts)}
    <dt>Created · updated</dt><dd>${CX_ESC(m.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(m.updated_at || "")}</span></dd>
  </dl>`;
  return automationsShell(m.name || "ODK Manifest", `<p><a href="/__ioi/odk">← ODK</a></p><h1>${CX_ESC(m.name || m.id)}</h1><p class="sub">OntologyDevelopmentKitManifest · draft.</p>${odkDetailActions("manifests", m.id)}${grid}`);
}
function odkCard(family, rec, nameKey) {
  const e = encodeURIComponent;
  const sub = family === "surface-descriptors" ? `pattern ${CX_ESC(rec.composition_pattern || "")}`
    : family === "data-recipes" ? `→ ${CX_ESC(rec.ontology_ref || "")}`
    : family === "manifests" ? `${(rec.ontology_refs || []).length} ont · ${(rec.recipe_refs || []).length} rec · ${(rec.surface_descriptor_refs || []).length} sd`
    : (rec.ref ? CX_ESC(rec.ref) : "");
  return `<a class="card" href="/__ioi/odk/${family}/${e(rec.id)}"><div class="main"><div class="name">${CX_ESC(rec[nameKey] || rec.name || rec.id)} <span class="pill warn">${CX_ESC(rec.status || "draft")}</span></div><div class="meta">${sub}</div></div><span class="act ghost">Open →</span></a>`;
}
// Data sources — the DAEMON-PLANE-FIRST shape: a real daemon data-source registry is the authority
// (built as a contract before any UI promise); the capture seeds are secondary references. A
// registration is a validated, receipted DECLARATION — ingestion is explicitly NOT wired (named
// gap), never faked.
function renderDataSourcesSection(dataSources) {
  dataSources = Array.isArray(dataSources) ? dataSources : [];
  const rows = dataSources.map((d) => `<tr>
    <td><b>${CX_ESC(d.name || d.source_id || "—")}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(d.source_ref || "")}</code></div></td>
    <td><span class="pill muted">${CX_ESC(d.kind || "—")}</span></td>
    <td>${d.endpoint ? `<code style="font-size:11px">${CX_ESC(d.endpoint)}</code>` : "<span class=\"sub\" style=\"margin:0\">local</span>"}</td>
    <td><span class="pill muted">${CX_ESC(d.credential_posture || "—")}</span></td>
    <td><span class="pill ${(d.lifecycle || {}).status === "declared" ? "muted" : "ok"}">${CX_ESC((d.lifecycle || {}).status || "declared")}</span> <span class="pill warn" title="ingestion is not wired — declaration only">not ingesting</span></td>
  </tr>`).join("");
  const table = dataSources.length
    ? `<table><thead><tr><th>Source</th><th>Kind</th><th>Endpoint</th><th>Credential</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`
    : `<div class="empty">No data sources declared yet. Register one against the daemon <code>POST /v1/hypervisor/data-sources</code> — a validated, receipted declaration (credentials by posture only; ingestion is a named gap, never faked here).</div>`;
  return `<h2 id="data-sources">Data sources <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the daemon data-source registry (${dataSources.length}) · authority · <a href="/__ioi/data/sources">Data Connection catalog →</a> (the #52 certified landing over this registry)</span></h2>` +
    `<p class="sub" style="margin:-4px 0 10px">Declared external sources are <b>daemon truth</b> — a fail-closed, receipted registry (credentials by posture only). Ingestion is <b>not wired</b> (a named gap requiring a future authority crossing), never faked. The <a href="/__apps/sources">Data Connection capture ↗</a> and <a href="/__apps/ingest">pipeline capture ↗</a> are secondary reference grammars, not rebound surfaces.</p>` +
    table;
}

// ============================ ONTOLOGY MANAGER (reference-UX parity shell) =======================
// The PRIMARY ODK product surface begins from the familiar Ontology Manager grammar (the same IA a
// Palantir user recognizes: object types · properties · link types · action types · value types ·
// groups · interfaces · functions · health · cleanup · configuration + explorer), re-authored over
// IOI DAEMON TRUTH (the PR-#11 ontology-manager contract). Unsupported lanes are shown HONESTLY —
// visible but empty/unavailable, each naming the missing authority contract, never faked. IOI-native
// authority (receipts, policy gates, substrate readiness, conformance, source-neutrality) is threaded
// SIDEWAYS into that familiar IA rather than replacing it.

// The authority-crossing LADDER — CONTRACT-COMPLETE: all four rungs (ConnectorMapping,
// PolicyBoundDataView, TransformationRun plan/dry-run, OntologyProjection) are real inert daemon
// contracts. What remains missing is not a contract but the LIVE CROSSING itself: a materializing
// run under credential authority. object_instances stays 0 everywhere until that future cut.
function omBoundaryNote(text) {
  return `<div style="border:1px dashed #3a3d46;border-radius:10px;padding:10px 12px;margin:0 0 12px;background:#141519;color:#9a9da6;font-size:12.5px">${text}</div>`;
}
function omContractLadder(nMappings, nViews, nRuns, nProjections, nLeasePlans, nLeasesObtained, nSessions, nExecutions, nInstances) {
  const declared = `<tr><td><code>ConnectorMapping</code> <span class="pill ok">declared</span></td><td>declared source fields → typed object properties</td><td class="sub" style="margin:0">${nMappings} mapping${nMappings === 1 ? "" : "s"} · inert (no extraction)</td></tr>`
    + `<tr><td><code>PolicyBoundDataView</code> <span class="pill ok">declared</span></td><td>the capability envelope — who/what may read · transform · distill · train · evaluate · export · publish · route, for what purpose, under which receipt obligations</td><td class="sub" style="margin:0">${nViews} view${nViews === 1 ? "" : "s"} · gate only (nothing runs)</td></tr>`
    + `<tr><td><code>TransformationRun + receipts</code> <span class="pill ok">declared</span></td><td>auditable plan / dry-run against the gate — validates shape, envelope, intent; every act (and every refusal) receipted</td><td class="sub" style="margin:0">${nRuns} run${nRuns === 1 ? "" : "s"} · plan/dry-run only (no source contact)</td></tr>`
    + `<tr><td><code>OntologyProjection</code> <span class="pill ok">declared</span></td><td>the explorer/search/read SHAPE — what an authorized surface would render, search, filter, relate, and act on</td><td class="sub" style="margin:0">${nProjections} projection${nProjections === 1 ? "" : "s"} · shape only, no materialized objects</td></tr>`
    + `<tr><td><code>CapabilityLease plan</code> <span class="pill ok">declared</span></td><td>the EXACT lease scope a materializing run may ask for — subject, purpose, operations, property scope, postures, obligations, bounded TTL; the only gateway is the existing capability-lease primitive</td><td class="sub" style="margin:0">${nLeasePlans} plan${nLeasePlans === 1 ? "" : "s"} · nothing minted, no credential material</td></tr>`
    + `<tr><td><code>CapabilityLease obtained</code> <span class="pill ok">live</span></td><td>the FIRST live crossing — a run cites a declared plan and obtains a REAL wallet-gated lease from the gateway; no source contact, no credential resolution, any bearer token dropped</td><td class="sub" style="margin:0">${nLeasesObtained} lease${nLeasesObtained === 1 ? "" : "s"} obtained · real gateway leases, credential material never surfaced</td></tr>`
    + `<tr><td><code>Sealed connector session</code> <span class="pill ok">live</span></td><td>the credential-handling crossing — the gateway resolves the SEALED credential server-side for the exact lease scope; labels only, material never surfaced</td><td class="sub" style="margin:0">${nSessions} session${nSessions === 1 ? "" : "s"} obtained · no source contact</td></tr>`
    + (nExecutions > 0
      ? `<tr><td><code>Connector execution</code> <span class="pill ok">live</span></td><td>one allowlisted read-only adapter path — the declared endpoint, one bounded batch, receipted before output</td><td class="sub" style="margin:0">${nExecutions} execution${nExecutions === 1 ? "" : "s"} · read-only, all-or-nothing</td></tr>`
      : `<tr><td><code>Connector execution</code> <span class="pill muted">missing</span></td><td>reading the source under an obtained lease + sealed session — one bounded read-only batch, receipted before output</td><td class="sub" style="margin:0">no execution has run for this ontology</td></tr>`)
    + (nInstances > 0
      ? `<tr><td><code>Materialized rows</code> <span class="pill ok">live</span></td><td>registered, receipted object sets — the projection's rows finally exist</td><td class="sub" style="margin:0">${nInstances} object instance${nInstances === 1 ? "" : "s"} · hashes + provenance, never secrets</td></tr>`
      : `<tr><td><code>Materialized rows</code> <span class="pill muted">missing</span></td><td>registered, receipted output that finally lets a projection's rows exist</td><td class="sub" style="margin:0">until an execution registers a batch, object_instances stays 0</td></tr>`);
  return `<table><thead><tr><th>Contract</th><th>What it declares</th><th>Status / unlocks</th></tr></thead><tbody>${declared}</tbody></table>`;
}
// Sealed connector sessions — the credential-handling rung: resolution proven, material never surfaced.
function omConnectorSessions(sessions) {
  sessions = Array.isArray(sessions) ? sessions : [];
  if (!sessions.length) return `<div class="empty">No sealed connector sessions. A lease-holding run may open one — the gateway resolves the <b>sealed</b> credential server-side for the exact lease scope; only labels land here. No source contact; execution is the next cut.</div>`;
  const pill = (st) => `<span class="pill ${st === "session_obtained" ? "ok" : st === "requested" ? "muted" : "warn"}">${CX_ESC(st || "requested")}</span>`;
  const rows = sessions.map((c) => `<tr>
    <td><b>${CX_ESC(c.name || c.id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(c.ref || "")}</code></div></td>
    <td><code>${CX_ESC(c.connector_id || "—")}</code></td>
    <td>${c.session && c.session.session_ref ? `<code>${CX_ESC(c.session.session_ref)}</code>` : "—"}</td>
    <td>${CX_ESC(String(c.ttl_seconds || 0))}s</td>
    <td>${pill(c.status)} <span class="pill warn" title="credential material never surfaced; no source contact">sealed · no contact</span></td>
  </tr>`).join("");
  return `<table><thead><tr><th>Session</th><th>Connector</th><th>Session ref</th><th>TTL</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
}
// Materializing runs bound to the selected ontology — the live lease-acquisition rung.
function omMaterializingRuns(runs) {
  runs = Array.isArray(runs) ? runs : [];
  if (!runs.length) return `<div class="empty">No materializing runs. A run cites a declared lease plan and may obtain a <b>real</b> wallet-gated CapabilityLease from the gateway — no source contact, no credential material, no rows; execution is the next cut.</div>`;
  const pill = (st) => `<span class="pill ${st === "lease_obtained" ? "ok" : st === "planned" ? "muted" : "warn"}">${CX_ESC(st || "planned")}</span>`;
  const rows = runs.map((r) => `<tr>
    <td><b>${CX_ESC(r.name || r.id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(r.ref || "")}</code></div></td>
    <td><code>${CX_ESC(r.subject || "—")}</code></td>
    <td>${r.lease && r.lease.lease_id ? `<code>${CX_ESC(r.lease.lease_id)}</code>` : "—"}</td>
    <td>${CX_ESC(String(r.ttl_seconds || 0))}s</td>
    <td>${pill(r.status)} <span class="pill warn" title="no source contact, no credential material, no rows — execution is the next cut">no execution</span></td>
  </tr>`).join("");
  return `<table><thead><tr><th>Run</th><th>Subject</th><th>Lease</th><th>TTL</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
}
// Capability-lease plans bound to the selected ontology — the declared credential authority, minted never.
function omLeasePlans(plans) {
  plans = Array.isArray(plans) ? plans : [];
  if (!plans.length) return `<div class="empty">No capability-lease plans. A plan declares the <b>exact lease</b> a future materializing run may request from the capability-lease gateway — subject, purpose, operations, scope, bounded TTL. Nothing is minted; no credential material exists here.</div>`;
  const rows = plans.map((p) => `<tr>
    <td><b>${CX_ESC(p.name || p.id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(p.ref || "")}</code></div></td>
    <td><code>${CX_ESC(p.subject || "—")}</code></td>
    <td>${(p.requested_operations || []).map((o) => `<span class="pill muted">${CX_ESC(o)}</span>`).join(" ")}</td>
    <td>${CX_ESC(String(p.ttl_seconds || 0))}s</td>
    <td><span class="pill ${p.status === "declared" ? "ok" : "muted"}">${CX_ESC(p.status || "declared")}</span> <span class="pill warn" title="plan only — no lease minted, no credential material">not minted</span></td>
  </tr>`).join("");
  return `<table><thead><tr><th>Lease plan</th><th>Subject</th><th>Operations</th><th>TTL</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
}
// The DECLARED explorer shape from a ready OntologyProjection — daemon truth about what an
// authorized surface WOULD render. Zero rows, always: projection declared ≠ objects materialized.
function omDeclaredExplorerShape(proj, mset) {
  const cols = (proj.visible_properties || []).map((p) => `<th>${CX_ESC(p)}${p === proj.title_field ? ` <span class="pill ok" style="margin-left:4px">title</span>` : ""}${p === proj.key_field ? ` <span class="pill muted" style="margin-left:4px">key</span>` : ""}</th>`).join("");
  const affordance = (arr, idKey, kind) => (arr || []).map((a) => `<span class="pill ${a.enabled ? "ok" : "muted"}" title="${a.enabled ? "enabled (gated by the policy view)" : "declared, not enabled"}">${CX_ESC(a[idKey] || "")} · ${kind}${a.enabled ? "" : " (declared)"}</span>`).join(" ");
  return `<div style="border:1px solid #24262d;border-radius:10px;padding:12px 14px;margin:0 0 12px;background:#15171c">
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px"><b>${CX_ESC(proj.name || proj.id)}</b> <code style="font-size:11px">${CX_ESC(proj.ref || "")}</code> <span class="pill ${proj.status === "ready" ? "ok" : "warn"}">${CX_ESC(proj.status || "draft")}</span> <span class="pill muted">${CX_ESC(proj.layout || "table")}</span>${(mset && (mset.objects || []).length) ? ` <span class="pill ok">${mset.count} objects · materialized</span> <span class="pill muted" title="registered all-or-nothing behind a pre-output receipt"><code style="font-size:10px">${CX_ESC(mset.ref || "")}</code></span>` : ""}</div>
    <table><thead><tr>${cols}</tr></thead><tbody>${(mset && (mset.objects || []).length) ? mset.objects.slice(0, 20).map((o) => `<tr>${(proj.visible_properties || []).map((vp) => `<td>${CX_ESC(String((o.properties || {})[vp] ?? ""))}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${(proj.visible_properties || []).length || 1}" style="text-align:center;color:#878a93;padding:18px 8px">0 objects — projection declared, nothing materialized. Rows require a future materializing run under credential authority.</td></tr>`}</tbody></table>
    <div class="chips" style="margin-top:8px"><span class="chiplabel">Facets</span>${(proj.facet_properties || []).length ? proj.facet_properties.map((f) => `<span class="pill muted">${CX_ESC(f)}</span>`).join("") : `<span class="sub" style="margin:0">none</span>`}</div>
    <div class="chips"><span class="chiplabel">Sort</span>${(proj.sort_fields || []).length ? proj.sort_fields.map((f) => `<span class="pill muted">${CX_ESC(f)}</span>`).join("") : `<span class="sub" style="margin:0">none</span>`}</div>
    <div class="chips"><span class="chiplabel">Actions</span>${(proj.action_affordances || []).length ? affordance(proj.action_affordances, "action_type_id", "action") : `<span class="sub" style="margin:0">none</span>`}</div>
    <div class="chips"><span class="chiplabel">Links</span>${(proj.relationship_affordances || []).length ? affordance(proj.relationship_affordances, "link_type_id", "link") : `<span class="sub" style="margin:0">none</span>`} <span class="sub" style="margin:0">— link affordances are declare-only in v1 (no object plane resolves rows)</span></div>
    <div class="chips"><span class="chiplabel">Export</span><span class="pill ${proj.export_affordance_enabled ? "ok" : "muted"}">${proj.export_affordance_enabled ? "enabled (receipted, gated)" : "not enabled"}</span></div>
  </div>`;
}
// Transformation runs bound to the selected ontology — daemon truth: auditable plans/dry-runs only.
function omTransformationRuns(runs) {
  runs = Array.isArray(runs) ? runs : [];
  if (!runs.length) return `<div class="empty">No transformation runs. A run is an <b>auditable plan / dry-run</b> against a ready mapping + a ready policy gate — it validates shape, envelope, and intent, and emits receipts. It never contacts a source; live reads are a future connector-adapter cut.</div>`;
  const pill = (st) => `<span class="pill ${st === "dry_run_ready" ? "ok" : st === "blocked" ? "warn" : "muted"}">${CX_ESC(st || "planned")}</span>`;
  const rows = runs.map((r) => `<tr>
    <td><b>${CX_ESC(r.name || r.id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(r.ref || "")}</code></div></td>
    <td><code>${CX_ESC(r.object_type_id || "—")}</code></td>
    <td>${(r.requested_fields || []).length} field${(r.requested_fields || []).length === 1 ? "" : "s"}</td>
    <td><span class="pill muted">${CX_ESC(r.output_intent || "—")}</span></td>
    <td>${pill(r.status)} <span class="pill warn" title="plan/dry-run only — no source contact, no data movement">no source contact</span></td>
  </tr>`).join("");
  return `<table><thead><tr><th>Run</th><th>Object type</th><th>Fields</th><th>Intent</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
}
// Policy-bound data views bound to the selected ontology — daemon truth: the declared capability
// gates over the mapped data. Declarative only; a view authorizes nothing to run.
function omPolicyViews(views) {
  views = Array.isArray(views) ? views : [];
  if (!views.length) return `<div class="empty">No policy-bound data views. A view declares the <b>capability envelope</b> over a ready mapping's would-be data — allowed operations, subjects, purpose, scope, postures, receipt obligations. Declarative only; nothing runs.</div>`;
  const pill = (h) => { const st = (h && h.status) || "incomplete"; return `<span class="pill ${st === "ready" ? "ok" : "warn"}">${CX_ESC(st)}</span>`; };
  const rows = views.map((v) => `<tr>
    <td><b>${CX_ESC(v.name || v.id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(v.ref || "")}</code></div></td>
    <td>${(v.allowed_operations || []).map((o) => `<span class="pill muted">${CX_ESC(o)}</span>`).join(" ")}</td>
    <td>${(v.authority_subjects || []).length} subject${(v.authority_subjects || []).length === 1 ? "" : "s"}</td>
    <td class="sub" style="margin:0">${CX_ESC(v.purpose || "—")}</td>
    <td>${pill(v.health)} <span class="pill warn" title="declarative gate only — nothing is authorized to run">no execution</span></td>
  </tr>`).join("");
  return `<table><thead><tr><th>View</th><th>Operations</th><th>Subjects</th><th>Purpose</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
}
// Connector mappings bound to the selected ontology — daemon truth (declared, inert).
function omConnectorMappings(mappings) {
  mappings = Array.isArray(mappings) ? mappings : [];
  if (!mappings.length) return `<div class="empty">No connector mappings bound to this ontology. A mapping declares how a data source's fields would bind to this object model — validated fail-closed, receipted, and <b>inert</b> (no extraction).</div>`;
  const pill = (h) => { const st = (h && h.status) || "incomplete"; return `<span class="pill ${st === "ready" ? "ok" : "warn"}">${CX_ESC(st)}</span>`; };
  const rows = mappings.map((m) => `<tr>
    <td><b>${CX_ESC(m.name || m.id)}</b><div class="meta" style="color:#878a93;font-size:11.5px;margin-top:2px"><code>${CX_ESC(m.ref || "")}</code></div></td>
    <td><code>${CX_ESC(m.data_source_ref || m.data_source_id || "—")}</code></td>
    <td><code>${CX_ESC(m.object_type_id || "—")}</code></td>
    <td>${(m.field_mappings || []).length + 2} field${((m.field_mappings || []).length + 2) === 1 ? "" : "s"}</td>
    <td>${pill(m.health)} <span class="pill warn" title="inert — no extraction">not extracting</span></td>
  </tr>`).join("");
  return `<table><thead><tr><th>Mapping</th><th>Data source</th><th>Object type</th><th>Fields</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function omUnavailablePane(title, why, contract) {
  return `<h2 id="pane-${title.toLowerCase().replace(/[^a-z]+/g, "-")}">${CX_ESC(title)} <span class="pill muted">unavailable</span></h2>`
    + omBoundaryNote(`${CX_ESC(why)} ${contract ? `Named missing contract: <code>${CX_ESC(contract)}</code>.` : ""} Shown honestly — not faked.`);
}
// The manager's left-rail nav grammar (reference IA). counts is a map of id→count (null = no badge).
function omNav(counts) {
  const items = [
    ["object-types", "Object types"], ["properties", "Properties"], ["link-types", "Link types"],
    ["action-types", "Action types"], ["value-types", "Value types"], ["groups", "Groups"],
    ["interfaces", "Interfaces"], ["functions", "Functions"], ["health-issues", "Health issues"],
    ["cleanup", "Cleanup"], ["configuration", "Ontology configuration"], ["resources", "Resources"],
    ["data", "Data"],
  ];
  return `<nav class="om-nav" style="flex:0 0 208px;position:sticky;top:12px;align-self:flex-start;display:flex;flex-direction:column;gap:1px;border:1px solid #24262d;border-radius:10px;padding:8px;background:#15171c">${items.map(([id, label]) => {
    const c = counts[id];
    return `<a href="#pane-${id}" style="display:flex;justify-content:space-between;align-items:center;padding:6px 9px;border-radius:7px;color:#c9ccd3;font-size:13px;text-decoration:none">${CX_ESC(label)}${c == null ? "" : ` <span class="pill muted" style="margin:0">${c}</span>`}</a>`;
  }).join("")}</nav>`;
}
// ============================ DATA LINEAGE (Monocle parity over real ODK provenance) =============
// The Reference UX Port program (post-#31 reset), substrate for Monocle / Data Lineage. The reference capture
// (/__apps/lineage, /workspace/monocle/) is the familiar baseline; this IOI-owned surface renders
// the SAME lineage-graph grammar — typed nodes + edges + a legend — but every node/edge is REAL
// PROVENANCE from the ODK materialization chain: a materialized object set traced back through its
// run, session, lease, projection, mapping, and datasource, plus per-OBJECT provenance (source hash
// + which source field produced each property) and the auditable receipt chain. No graph data is
// invented: an ontology with no materialized objects shows NO lineage (honest empty), never fake
// nodes. Provenance proof-stream edges are shown "where available". Unsupported Monocle lanes (freeform resource
// search, arbitrary graph expansion, cross-tenant catalog search) are visible but named gaps.
const LINEAGE_NODE_KINDS = [
  ["datasource", "🌐", "Datasource"], ["mapping", "🔗", "Mapping"], ["policy", "🛡", "Policy view"],
  ["plan", "📋", "Transform plan"], ["projection", "🔭", "Projection"], ["lease", "🎟", "Lease + session"],
  ["run", "⚙", "Materializing run"], ["receipt", "🧾", "Receipt"], ["set", "📦", "Object set"], ["object", "▪", "Object"],
];
function lineageLegend() {
  return `<div class="chips" style="margin:0 0 10px"><span class="chiplabel">Nodes</span>${LINEAGE_NODE_KINDS.map(([, ic, l]) => `<span class="pill muted" style="margin:0">${ic} ${CX_ESC(l)}</span>`).join(" ")}</div>`
    + `<div class="chips" style="margin:0 0 12px"><span class="chiplabel">Edges</span>${["mapped_by", "gated_by", "planned_by", "projected_as", "read_under", "produced_by", "receipted_by", "contains", "hashed_as", "mapped_from"].map((e) => `<span class="pill muted" style="margin:0"><code>${e}</code></span>`).join(" ")}</div>`;
}
// ============================ MISSIONS (owner surface for suite/run work — jobs + incidents seeds)
// The Reference UX Port program (post-#31 reset), substrate for the Missions owner-family. The reference
// captures (/__apps/jobs = job-tracker "Builds", /__apps/incidents = issues-app) are the familiar
// baselines; this IOI-owned surface renders the SAME table/list grammar — a run/job status queue and
// a status-lane remediation inbox — but over REAL daemon truth: the operations run queue (recent
// runs, statuses, scheduled missions) and the mission-level incidents (run failures + GoalRun
// blockers, each linking back to its own proof/timeline). Naming: Missions is the owner surface for
// suite/run work; Operations stays substrate/infra (its storage-repair / provider-failover incidents
// live there, NOT here). Nothing is fabricated — empty run queue / zero incidents render honest empty
// states. Unsupported reference lanes (create/assign incidents, edit job definitions, board views,
// SLA/escalation, comments/assignees) are named gaps, not hidden.
function renderMissions(ops, goalRuns) {
  const enc = (s) => encodeURIComponent(String(s || ""));
  const runs = (ops && ops.runs) || {};
  const recent = Array.isArray(runs.recent) ? runs.recent : [];
  const failures = Array.isArray(runs.failures) ? runs.failures : [];
  const scheduled = Array.isArray(ops && ops.scheduler && ops.scheduler.automations) ? ops.scheduler.automations : [];
  const gr = Array.isArray(goalRuns) ? goalRuns : [];
  const blocked = gr.filter((r) => Array.isArray(r.blockers) && r.blockers.length);
  const sub = (txt) => `<span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">${txt}</span>`;
  const statusPill = (st) => { const s = String(st || "").toLowerCase(); const cls = ["done", "succeeded", "ok", "completed"].includes(s) ? "ok" : (["failed", "error", "errored"].includes(s) ? "warn" : "muted"); return `<span class="pill ${cls}" style="margin:0">${CX_ESC(st || "—")}</span>`; };

  const head = `<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap"><div><h1 style="margin:0">Missions</h1><p class="sub" style="margin:4px 0 0">The fleet of running systems — mission runs, their queue and status, and the incidents and blockers that need attention, over IOI daemon truth. Reference grammar: <a href="/__apps/jobs">Builds ↗</a> · <a href="/__apps/incidents">Issues ↗</a> (secondary captures).</p></div><div class="row" style="gap:8px"><a class="act ghost" href="/__ioi/operations">Operations (substrate)</a><a class="act ghost" href="/__ioi/work-ledger">Proof stream</a></div></div>`;

  const total = runs.total || 0, running = runs.running || 0, done = runs.done || 0, failed = runs.failed || 0;
  const incidentCount = failures.length + blocked.length;
  const banner = `<div class="row" style="gap:10px;align-items:stretch;margin:12px 0 14px;flex-wrap:wrap">${[
    ["Runs", total, false], ["Running", running, false], ["Done", done, false], ["Failed", failed, !!failed], ["Incidents", incidentCount, !!incidentCount], ["Scheduled", scheduled.length, false],
  ].map(([l, n, warn]) => `<div style="flex:1;min-width:104px;padding:11px 13px;border:1px solid #24262d;border-radius:10px;background:#15171c"><div style="font-size:20px;font-weight:700;color:#fff">${n}</div><div style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(l)}${warn ? ` <span class="pill warn" style="margin:0">attention</span>` : ""}</div></div>`).join("")}</div>`;

  // Lane A — run/job queue (jobs seed).
  const runRows = recent.map((r) => `<tr><td>${CX_ESC(r.name || r.execution_id || "—")}</td><td>${statusPill(r.status)}</td><td><code style="font-size:10.5px">${CX_ESC(r.project_id || "—")}</code></td><td class="sub" style="margin:0">${CX_ESC(r.started_at || "")}</td><td>${r.timeline_ref ? `<a href="${CX_ESC(r.timeline_ref)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"} · <a href="/__ioi/work-ledger">proof</a></td></tr>`).join("");
  const queue = `<h2 id="missions-queue">Run queue ${sub(`— recent mission runs (${recent.length} of ${total})`)}</h2>`
    + (recent.length ? `<table><thead><tr><th>Mission run</th><th>Status</th><th>Project</th><th>Started</th><th>Proof</th></tr></thead><tbody>${runRows}</tbody></table>`
      : omBoundaryNote(`<b>No mission runs yet</b> — run an automation to populate the queue. This lane reads the real daemon run queue; nothing is fabricated.`));

  // Scheduled missions (only when present — no fabricated schedule rows).
  const schedRows = scheduled.map((a) => `<tr><td>${CX_ESC(a.name || a.automation_id || "—")}</td><td><code style="font-size:10.5px">${CX_ESC((a.schedule_spec && a.schedule_spec.cron) || a.trigger_kind || "—")}</code></td><td>${a.enabled ? `<span class="pill ok" style="margin:0">enabled</span>` : `<span class="pill muted" style="margin:0">paused</span>`}</td><td class="sub" style="margin:0">${CX_ESC(a.next_run_at || "")}</td></tr>`).join("");
  const scheduledPane = scheduled.length ? `<h2 id="missions-scheduled">Scheduled missions ${sub(`— ${scheduled.length}`)}</h2><table><thead><tr><th>Automation</th><th>Schedule</th><th>State</th><th>Next run</th></tr></thead><tbody>${schedRows}</tbody></table>` : "";

  // Lane B — incident / remediation inbox (incidents seed): real run failures + GoalRun blockers.
  const failRows = failures.map((r) => `<tr><td><span class="pill warn" style="margin:0">run failure</span></td><td>${CX_ESC(r.name || r.execution_id || "—")}</td><td><code style="font-size:10.5px">${CX_ESC(r.status || "failed")}</code></td><td class="sub" style="margin:0">${CX_ESC(r.finished_at || r.started_at || "")}</td><td>${r.timeline_ref ? `<a href="${CX_ESC(r.timeline_ref)}" target="_blank" rel="noopener">timeline ↗</a>` : "—"}</td></tr>`).join("");
  const BLOCKER_CAP = 50;
  const blockerRows = blocked.slice(0, BLOCKER_CAP).map((r) => { const b = (r.blockers && r.blockers[0]) || {}; return `<tr><td><span class="pill warn" style="margin:0">blocker</span></td><td>${CX_ESC(r.normalized_goal || r.goal_ref || r.goal_run_id || "—")}</td><td><code style="font-size:10.5px">${CX_ESC(b.reason_code || "—")}${b.role_key ? ` · ${CX_ESC(b.role_key)}` : ""}</code></td><td class="sub" style="margin:0">${CX_ESC(r.updated_at || r.created_at || "")}</td><td>${r.goal_run_id ? `<a href="/__ioi/run-timeline/goal-run/${enc(r.goal_run_id)}" target="_blank" rel="noopener">proof ↗</a>` : "—"}</td></tr>`; }).join("");
  const shown = failures.length + Math.min(blocked.length, BLOCKER_CAP);
  const capNote = shown < incidentCount ? ` (showing first ${shown})` : "";
  const incidents = `<h2 id="missions-incidents">Incidents &amp; blockers ${sub(`— run failures + mission blockers needing remediation (${incidentCount})${capNote} · <a href="/__ioi/missions/incidents">Incidents inbox (reference-faithful) →</a>`)}</h2>`
    + (incidentCount ? `<table><thead><tr><th>Kind</th><th>Subject</th><th>Reason</th><th>When</th><th>Remediation</th></tr></thead><tbody>${failRows}${blockerRows}</tbody></table>`
      : omBoundaryNote(`<b>No incidents</b> — no failed mission runs and no blocked mission runs right now. This lane reads real run failures + GoalRun blockers; it never fabricates incidents or remediation actions.`));

  const gaps = omBoundaryNote(`Supported lanes above are real daemon truth (run queue · scheduled missions · incidents/blockers, each with its remediation proof link). Unsupported reference lanes — creating/assigning incidents, editing job/build definitions, board/kanban views, SLA &amp; escalation policy, comments/assignees — are <b>named gaps</b> (no authority contract yet), not silently hidden. Substrate/infra incidents (storage repair, provider failover) live in <a href="/__ioi/operations">Operations</a>, not here. The <a href="/__apps/jobs">Builds</a> + <a href="/__apps/incidents">Issues</a> captures are the familiar baselines, never rebound surfaces.`);

  return automationsShell("Missions", head + banner + queue + scheduledPane + incidents + gaps);
}
// ============================ VERTEX (Provenance graph/exploration lens over real materialized truth)
// The Reference UX Port program (post-#31 reset), substrate for Vertex. The reference capture (/__apps/vertex,
// /workspace/vertex/) is the familiar baseline; this IOI-owned surface renders the SAME graph
// exploration grammar — a node/relation graph you explore by neighborhood — but every node/edge is
// REAL and CROSS-PLANE: materialized object sets, their projections + runs, the objects themselves,
// AND the threaded Provenance proof-stream `odk_materialization` edges (the #23 payoff) that connect
// ODK materialization to the Provenance plane. Vertex is the GRAPH (nodes · relations · expand a
// node's neighborhood); lineage is the PATH. No graph data is invented: an ontology with no
// materialized objects shows an empty graph. Unsupported Vertex lanes (freeform graph canvas,
// arbitrary path-finding, cross-tenant object search, saved explorations) are named gaps.
const VERTEX_NODE_KINDS = [
  ["set", "📦", "Object set"], ["projection", "🔭", "Projection"], ["run", "⚙", "Materializing run"],
  ["object", "▪", "Object"], ["proof", "🧾", "Proof-stream edge"],
];
function renderVertex(lists, selectedId, vSel) {
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const allSets = Array.isArray(lists.materialized_sets) ? lists.materialized_sets : [];
  const has = new Set(allSets.map((s) => s.ontology_ref));
  // #64: ?objectSet= selects THAT set's neighborhood (its ontology becomes the context) and
  // ?objectId= highlights the object within it; an unresolvable set fails closed honestly.
  const vs = vSel || {};
  const vSetSel = vs.objectSet ? allSets.find((s) => s.id === vs.objectSet || String(s.ref || "").endsWith(vs.objectSet)) || null : null;
  const vSetMissing = !!(vs.objectSet && !vSetSel);
  const selected = (vSetSel ? ontologies.find((x) => x.ref === vSetSel.ontology_ref) : null)
    || ontologies.find((x) => x.id === selectedId) || ontologies.find((x) => has.has(x.ref)) || ontologies[0] || null;
  const oref = selected ? selected.ref : "__none__";
  const oid = selected ? selected.id : "";
  const sets = allSets.filter((s) => s.ontology_ref === oref);
  const projs = (lists.ontology_projections || []).filter((p) => p.ontology_ref === oref);
  const runs = (lists.materializing_runs || []).filter((r) => r.ontology_ref === oref);
  const provStream = Array.isArray(lists.provenance_stream) ? lists.provenance_stream : [];
  const setRefs = new Set(sets.map((s) => s.ref));
  const proofEdges = provStream.filter((e) => e.kind === "odk_materialization" && setRefs.has(e.materialized_set_ref));
  const objectCount = sets.reduce((a, s) => a + (s.count || 0), 0);

  const switcher = ontologies.length
    ? `<div class="chips" style="margin:0 0 14px">${ontologies.map((x) => {
        const on = selected && x.id === selected.id;
        return `<a href="/__ioi/vertex?ontology=${encodeURIComponent(x.id)}" class="pill ${on ? "ok" : "muted"}" style="text-decoration:none;margin:0">${CX_ESC(x.domain || x.id)}${has.has(x.ref) ? ` <span class="pill ok" style="margin-left:4px">graph</span>` : ""}</a>`;
      }).join(" ")}</div>`
    : `<div class="empty">No ontologies yet.</div>`;

  const head = `<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap"><div><h1 style="margin:0">Vertex</h1><p class="sub" style="margin:4px 0 0">Explore the materialized object graph — object sets, projections, objects, and the cross-plane Provenance proof-stream edges as a navigable node/relation graph, over IOI daemon truth. Reference grammar: <a href="/__apps/vertex">Vertex ↗</a> (secondary capture).</p></div><div class="row" style="gap:8px"><a class="act ghost" href="/__ioi/lineage?ontology=${encodeURIComponent(oid)}">Lineage path</a><a class="act ghost" href="/__ioi/pipeline?ontology=${encodeURIComponent(oid)}">Pipeline</a></div></div>`;

  if (vSetMissing) {
    return automationsShell("Vertex", head + switcher + `<div class="empty">No materialized set matches <code>${CX_ESC(vs.objectSet)}</code> — nothing substituted (fail-closed). Pick a set from the <a href="/__ioi/ontology/explorer">Object Explorer</a>.</div>`);
  }
  // HONEST EMPTY — no materialized objects ⇒ no graph. Never fabricate nodes.
  if (!sets.length) {
    const note = omBoundaryNote(`This ontology has materialized <b>no objects</b>, so there is <b>no graph to explore</b> — Vertex renders the real materialized object graph (sets · projections · objects · proof-stream edges), which appears only once a pipeline is built. Build one from the <a href="/__ioi/pipeline?ontology=${encodeURIComponent(oid)}">Pipeline Builder</a>. The <a href="/__apps/vertex">Vertex reference capture ↗</a> is the familiar baseline, never a rebound surface.`);
    return automationsShell("Vertex", head + switcher + `<div class="chips" style="margin:10px 0 12px"><span class="pill muted">empty graph</span> <span class="sub" style="margin:0">${selected ? `No materialized objects for <b>${CX_ESC(selected.domain || selected.id)}</b>.` : "Select or create an ontology."}</span></div>` + note);
  }

  // The primary (selected) set — chosen BEFORE the node inventory so the set chips can mark it.
  const primary = vSetSel || sets.slice().sort((a, b) => String(b.registered_at || "").localeCompare(String(a.registered_at || "")))[0];
  // Graph catalog — node-type counts (the exploration summary).
  const counts = { set: sets.length, projection: projs.length, run: runs.length, object: objectCount, proof: proofEdges.length };
  const catalog = `<div class="row" style="gap:10px;align-items:stretch;margin:0 0 14px;flex-wrap:wrap">${VERTEX_NODE_KINDS.map(([k, ic, l]) => `<div style="flex:1;min-width:118px;padding:11px 13px;border:1px solid #24262d;border-radius:10px;background:#15171c"><div style="font-size:20px;font-weight:700;color:#fff">${ic} ${counts[k]}</div><div style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(l)}${k === "proof" ? " <span class=\"pill ok\" style=\"margin:0\">cross-plane</span>" : ""}</div></div>`).join("")}</div>`;

  // Node inventory (grouped) — the graph's nodes, real refs.
  // #64: graph nodes are real links into their owning surfaces; set chips select the
  // neighborhood HERE (URL-persistent) and the selected set visibly identifies itself.
  const nodeChip = (ic, label, ref, href, on) => href
    ? `<a class="pill ${on ? "ok" : "muted"}" style="margin:0;text-decoration:none" title="${CX_ESC(ref || "")}"${on ? ' aria-current="true" data-vertex-selected="1"' : ""}>${ic} ${CX_ESC(label)}</a>`.replace("<a ", `<a href="${href}" `)
    : `<span class="pill muted" style="margin:0" title="${CX_ESC(ref || "")}">${ic} ${CX_ESC(label)}</span>`;
  const inv = `<h2 id="vertex-nodes">Nodes <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${counts.set + counts.projection + counts.run + counts.object + counts.proof})</span></h2>`
    + `<div class="chips" style="margin:0 0 6px"><span class="chiplabel">Object sets</span>${sets.map((s) => nodeChip("📦", `${s.count || 0} obj`, s.ref, semVertexLink(oid, s.id), primary && s.id === primary.id)).join(" ")}</div>`
    + `<div class="chips" style="margin:0 0 6px"><span class="chiplabel">Projections</span>${projs.map((p) => nodeChip("🔭", p.name || p.id, p.ref, managerResourceLink(oid, "ontology-projection", p.id))).join(" ")}</div>`
    + `<div class="chips" style="margin:0 0 6px"><span class="chiplabel">Runs</span>${runs.filter((r) => r.status === "executed").map((r) => nodeChip("⚙", r.name || r.id, r.ref, pipelineNodeLink(oid, "materialized"))).join(" ") || `<span class="sub" style="margin:0">—</span>`}</div>`
    + `<div class="chips" style="margin:0 0 6px"><span class="chiplabel">Proof edges</span>${proofEdges.length ? proofEdges.map((e) => nodeChip("🧾", e.kind, e.receipt_ref, provenanceReceiptLink(e.receipt_ref))).join(" ") : `<span class="sub" style="margin:0">none</span>`}</div>`;

  // Neighborhood — expand the primary set: its projection, run, cross-plane proof edge, and objects.
  const projById = new Map(projs.map((p) => [p.id, p]));
  const proj = projById.get(primary.ontology_projection_id) || null;
  const proofEdge = proofEdges.find((e) => e.materialized_set_ref === primary.ref) || null;
  const rel = (from, type, to, toRef, href, on) => `<tr${on ? ' style="outline:1px solid #2d72d2" data-vertex-object-selected="1"' : ""}><td><code style="font-size:10.5px">${CX_ESC(from)}</code></td><td><span class="pill muted" style="margin:0">${CX_ESC(type)}</span></td><td>${href ? `<a href="${href}">${CX_ESC(to)} ↗</a>` : CX_ESC(to)}${toRef ? ` <code style="font-size:10px;opacity:.7">${CX_ESC(String(toRef).slice(0, 26))}…</code>` : ""}</td></tr>`;
  const objs = (primary.objects || []).slice(0, 6);
  const relRows = [
    proj ? rel(primary.ref, "projected_by", "Projection", proj.ref, managerResourceLink(oid, "ontology-projection", proj.id)) : "",
    primary.materializing_run_ref ? rel(primary.ref, "produced_by", "Materializing run", primary.materializing_run_ref, pipelineNodeLink(oid, "materialized")) : "",
    proofEdge ? rel(primary.ref, "proven_by", "Proof-stream edge (Provenance)", proofEdge.receipt_ref, provenanceReceiptLink(proofEdge.receipt_ref)) : "",
    ...objs.map((o) => rel(primary.ref, "contains", `Object ${o.object_key || ""}`, o.source_hash, objectSetLink(oid, primary.id, o.object_key ? { objectId: o.object_key } : undefined), vs.objectId && o.object_key === vs.objectId)),
  ].filter(Boolean).join("");
  const neighborhood = `<h2 id="vertex-neighborhood">Neighborhood <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— expand <code>${CX_ESC(primary.ref || "")}</code> (${primary.count || 0} objects)</span></h2>`
    + `<table><thead><tr><th>From</th><th>Relation</th><th>To</th></tr></thead><tbody>${relRows}</tbody></table>`;

  // Cross-plane highlight — the proof-stream edge is what makes this a cross-plane graph.
  const crossPlane = proofEdge
    ? omBoundaryNote(`<b>Cross-plane:</b> this object set is connected to the <a href="${provenanceReceiptLink(proofEdge.receipt_ref)}">Provenance proof stream</a> by a threaded <code>odk_materialization</code> edge (proof <code>${CX_ESC(String(proofEdge.receipt_ref || "").slice(0, 40))}…</code>) — the materialized objects and their receipt are reachable as one graph, not isolated ODK records.`)
    : omBoundaryNote(`This set has no threaded Provenance proof-stream edge yet — the graph is ODK-local until the materialization receipt is threaded.`);

  const gaps = omBoundaryNote(`This is <b>real cross-plane graph truth</b> in the Vertex grammar. Unsupported Vertex lanes — freeform graph canvas, arbitrary path-finding, cross-tenant object search, saved explorations — are <b>reference-only</b>, not bound. The <a href="/__apps/vertex">Vertex reference capture ↗</a> is the familiar baseline, never a rebound surface.`);

  const banner = `<div class="chips" style="margin:10px 0 12px"><span class="pill ok">graph</span> <span class="sub" style="margin:0">${counts.set} object set${counts.set === 1 ? "" : "s"} · ${objectCount} object${objectCount === 1 ? "" : "s"} · ${counts.proof} cross-plane proof edge${counts.proof === 1 ? "" : "s"} for <b>${CX_ESC(selected.domain || selected.id)}</b></span></div>`;
  return automationsShell("Vertex", head + switcher + banner + catalog + inv + neighborhood + crossPlane + gaps);
}

// ============================ STUDIO · DESIGNER (solution-design landing over real composition, #49)
// The Reference UX Port program — the FIRST origin-alignment-queue port (post-#48 clean-pool close).
// The reference is the origin-aligned Solution Designer landing capture
// (http://localhost:9225/workspace/solution-design/ — the /__apps/designer proxy lane manufactures
// CORS noise + a "Failed to load favorites" failure, documented by the #44 sweep). This IOI-owned
// surface reproduces the visible landing shell PIXEL-FAITHFULLY — dark global rail, app header,
// hero band + verbatim illustration, AIP-architect banner card, template-gallery card (verbatim
// capture strip: the reference's own static template-library previews, vendor chrome NOT estate
// data), the View row, and the Recents table — while the DATA region (table rows) renders REAL
// daemon composition truth: one row per domain ontology (the estate's solution designs), each
// carrying its ref, created/updated dates and its concept/component/resource census. Below the fold
// the full composition truth renders with real refs (COM concepts · mapping/policy-view/projection
// components · materialized-set/domain-app resources). Nothing authors/saves here: New Diagram,
// Open Diagram, Browse all, AIP Architect planning, favorites are NAMED GAPS (disabled in place).
// Owner: Studio (/__ioi/agent-studio); dedicated daemon-bound surface, no route rename.
function renderDesignerPort(lists, selectedId) {
  const esc = CX_ESC;
  const enc = (s) => encodeURIComponent(String(s || ""));
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const mappings = Array.isArray(lists.connector_mappings) ? lists.connector_mappings : [];
  const policyViews = Array.isArray(lists.policy_views) ? lists.policy_views : [];
  const projections = Array.isArray(lists.projections) ? lists.projections : [];
  const sets = Array.isArray(lists.materialized_sets) ? lists.materialized_sets : [];
  const domainApps = Array.isArray(lists.domain_apps) ? lists.domain_apps : [];

  const composed = new Set(mappings.map((m) => m.ontology_ref));
  const selected = ontologies.find((x) => x.id === selectedId) || ontologies.find((x) => composed.has(x.ref)) || ontologies[0] || null;
  const oref = selected ? selected.ref : "__none__";
  const oid = selected ? selected.id : "";

  const censusOf = (o) => {
    const com = o.canonical_object_model || {};
    const n = (k) => (Array.isArray(com[k]) ? com[k].length : 0);
    const concepts = n("object_types") + n("value_types") + n("action_types") + n("link_types");
    const components = mappings.filter((m) => m.ontology_ref === o.ref).length
      + policyViews.filter((v) => v.ontology_ref === o.ref).length
      + projections.filter((p) => p.ontology_ref === o.ref).length;
    const resources = sets.filter((s) => s.ontology_ref === o.ref).length
      + domainApps.filter((a) => Array.isArray(a.ontology_refs) && a.ontology_refs.includes(o.ref)).length;
    return { concepts, components, resources };
  };
  const fdate = (iso) => {
    const d = new Date(iso || 0);
    return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  };

  // Recents = real domain ontologies (the estate's solution designs), newest-updated first. The
  // CREATOR / LAST EDITED BY / LAST VIEWED cells are honest em-dashes: the ODK object plane records
  // no principal and no view tracking — named gaps, never invented values.
  const recent = [...ontologies].sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")));
  const gapDash = (why) => `<span class="dsg-dash" title="${esc(why)}">—</span>`;
  const rowsHtml = recent.length ? recent.map((o) => {
    const c = censusOf(o);
    return `<a class="dsg-row" href="/__ioi/studio/designer?ontology=${enc(o.id)}" title="Select this design — its composition truth renders below">
      <span class="dsg-cell name">
        <span class="dsg-rowico" aria-hidden="true"></span>
        <span class="dsg-rowdata">
          <span class="dsg-rowname">${esc(o.domain || o.id)}${o.id === oid ? `<span class="dsg-selpill">selected</span>` : ""}<span class="dsg-rowstar gap" aria-disabled="true" title="Favorites are not recorded on the ODK object plane (named gap)">${bpIcon("star-empty")}</span></span>
          <span class="dsg-rowpath">${esc(o.ref)} · created ${fdate(o.created_at)} · updated ${fdate(o.updated_at)} · ${c.concepts} concept${c.concepts === 1 ? "" : "s"} · ${c.components} component${c.components === 1 ? "" : "s"} · ${c.resources} resource${c.resources === 1 ? "" : "s"}</span>
        </span>
      </span>
      <span class="dsg-cell">${gapDash("No principal is recorded on the ODK object plane (named gap)")}</span>
      <span class="dsg-cell">${gapDash("No principal is recorded on the ODK object plane (named gap)")}</span>
      <span class="dsg-cell">${gapDash("View tracking is not recorded on the ODK object plane (named gap)")}</span>
    </a>`;
  }).join("") : `<div class="dsg-empty">No ontologies yet — there are no solution designs to list. Create one in the <a href="/__ioi/odk">Ontology Manager</a>; this table renders real composition truth and never fabricates rows.</div>`;

  // ---- Below-the-fold: full composition truth for the selected ontology (real refs, no invention).
  const com = (selected && selected.canonical_object_model) || {};
  const arr = (k) => (Array.isArray(com[k]) ? com[k] : []);
  const ots = arr("object_types"), vts = arr("value_types"), ats = arr("action_types"), lts = arr("link_types");
  const myMappings = mappings.filter((m) => m.ontology_ref === oref);
  const myViews = policyViews.filter((v) => v.ontology_ref === oref);
  const myProjections = projections.filter((p) => p.ontology_ref === oref);
  const mySets = sets.filter((s) => s.ontology_ref === oref);
  // DomainApps carry ontology_refs (an ARRAY, derived from the surface descriptor) — filter on membership.
  const myApps = domainApps.filter((a) => Array.isArray(a.ontology_refs) && a.ontology_refs.includes(oref));
  const conceptCount = ots.length + vts.length + ats.length + lts.length;
  const componentCount = myMappings.length + myViews.length + myProjections.length;
  const resourceCount = mySets.length + myApps.length;
  const actionsFor = (otId) => ats.filter((a) => a.applies_to === otId);
  // #64: composition records LINK to their owning surfaces (Manager definitions/typed resources,
  // Explorer sets, domain-app owner routes) — real refs, never fabricated links.
  const refChip = (label, ref, meta, href) => `<li class="dsg-truthitem"><b>${href ? `<a href="${href}">${esc(label)}</a>` : esc(label)}</b>${meta ? ` <span class="dsg-meta">${esc(meta)}</span>` : ""}<code class="dsg-ref">${esc(ref || "")}</code></li>`;

  const switcher = ontologies.length > 1 ? `<div class="dsg-switch">${ontologies.map((x) => `<a class="dsg-schip${selected && x.id === selected.id ? " on" : ""}" href="/__ioi/studio/designer?ontology=${enc(x.id)}">${esc(x.domain || x.id)}${composed.has(x.ref) ? " · composed" : ""}</a>`).join("")}</div>` : "";

  const truth = selected ? `<section class="dsg-truth" id="designer-truth">
    <h2 class="dsg-trutht">Composition truth — <b>${esc(selected.domain || selected.id)}</b> <span class="dsg-truthsub">${conceptCount} concept${conceptCount === 1 ? "" : "s"} · ${componentCount} component${componentCount === 1 ? "" : "s"} · ${resourceCount} resource${resourceCount === 1 ? "" : "s"} · real refs from the daemon ODK plane, nothing invented</span></h2>
    ${switcher}
    <div class="dsg-truthcols">
      <div class="dsg-truthcol" id="designer-concepts"><h3>Concepts <span class="dsg-meta">(${ots.length} object · ${vts.length} value · ${ats.length} action · ${lts.length} link types)</span></h3>
        ${ots.length ? `<ul>${ots.map((ot) => refChip(ot.name || ot.id, ot.id, `${(ot.properties || []).length} props${actionsFor(ot.id).length ? ` · actions: ${actionsFor(ot.id).map((a) => a.name || a.id).join(", ")}` : ""}`, managerLink({ ontology: oid, section: "object-types", definitionKind: "object-type", definitionId: ot.id }))).join("")}${vts.map((v) => refChip(v.name || v.id, v.id, "value type", managerLink({ ontology: oid, section: "value-types", definitionKind: "value-type", definitionId: v.id }))).join("")}${lts.map((l) => refChip(l.name || l.id, l.id, "link type", managerLink({ ontology: oid, section: "link-types", definitionKind: "link-type", definitionId: l.id }))).join("")}</ul>`
          : `<p class="dsg-gapnote">This ontology declares <b>no object types</b> yet — there are no concepts to map. Define them in the <a href="${managerLink({ ontology: oid })}">Ontology Manager</a>; nothing is invented here.</p>`}
      </div>
      <div class="dsg-truthcol" id="designer-components"><h3>Components <span class="dsg-meta">(${myMappings.length} mapping · ${myViews.length} policy view · ${myProjections.length} projection)</span></h3>
        ${componentCount ? `<ul>${myMappings.map((m) => refChip(m.name || m.id, m.ref, `mapping → ${m.object_type_id || ""}`, managerResourceLink(oid, "connector-mapping", m.id))).join("")}${myViews.map((v) => refChip(v.name || v.id, v.ref, `policy view · ${(v.allowed_operations || []).join("/") || "no ops"}`, managerResourceLink(oid, "policy-view", v.id))).join("")}${myProjections.map((p) => refChip(p.name || p.id, p.ref, `projection · ${(p.visible_properties || []).length} props`, managerResourceLink(oid, "ontology-projection", p.id))).join("")}</ul>`
          : `<p class="dsg-gapnote">No components compose this ontology yet — add a connector mapping + projection in the <a href="/__ioi/pipeline?ontology=${enc(oid)}">Pipeline Builder</a>.</p>`}
      </div>
      <div class="dsg-truthcol" id="designer-resources"><h3>Resources <span class="dsg-meta">(${mySets.length} object set · ${myApps.length} surface descriptor)</span></h3>
        ${resourceCount ? `<ul>${mySets.map((s) => refChip(`${s.count || 0} obj`, s.ref, s.object_type_id, objectSetLink(oid, s.id))).join("")}${myApps.map((a) => refChip(a.name || a.domain_app_id, a.domain_app_ref, a.surface_descriptor_ref || "", `/__ioi/domain-apps/${enc(a.domain_app_id)}`)).join("")}</ul>`
          : `<p class="dsg-gapnote">This composition has generated <b>no resources</b> yet — materialize a set from the <a href="/__ioi/pipeline?ontology=${enc(oid)}">pipeline</a>. Surface descriptors appear once a domain app is composed${myApps.length ? "" : " — no domain-app surfaces generated yet (named gap)"}.</p>`}
        ${resourceCount && !myApps.length ? `<p class="dsg-gapnote">Surface descriptors: none — no domain-app surfaces generated yet (named gap).</p>` : ""}
      </div>
    </div>
    <p class="dsg-foot">This is a <b>read-only design map</b> over real composition truth. Unsupported Designer lanes — in-canvas authoring, New Diagram / Open Diagram, save/open, drag-to-reference, AIP Architect planning, favorites, template Browse all — are <b>named gaps</b> (disabled in place above), not silently hidden. Sibling Studio seeds stay reference-only: the <a href="/__apps/machinery">machinery</a> process/state-machine graph (data lanes unbound), the <a href="/__apps/workshop">workshop</a> and module builders. Owner: <a href="/__ioi/agent-studio">Agent Studio</a> · siblings: <a href="/__ioi/studio/machinery">Machinery</a> · <a href="${managerLink({ ontology: oid })}">Ontology Manager</a> (<a href="/__ioi/odk?ontology=${enc(oid)}">ODK substrate</a>) · <a href="/__ioi/pipeline?ontology=${enc(oid)}">Pipeline Builder</a>. Reference: the origin-aligned <a href="http://localhost:9225/workspace/solution-design/" rel="noopener">Solution Designer capture</a> — the <a href="/__apps/designer">/__apps/designer proxy lane ↗</a> is documented insufficient (cross-origin :9225 chunk fetches manufacture CORS noise + a favorites-load failure; #44 sweep evidence).</p>
  </section>` : `<section class="dsg-truth" id="designer-truth"><p class="dsg-gapnote">No ontologies to design over yet — create one in the <a href="/__ioi/ontology/manager?section=create">Ontology Manager</a>. This canvas renders real composition truth; it never fabricates concepts. Owner: <a href="/__ioi/agent-studio">Agent Studio</a>.</p></section>`;

  const globalRail = ioiGlobalRailHtml({ label: "Solution Designer", href: "/__ioi/studio/designer", iconUri: DSG_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="dsg-header">
    <span class="dsg-hchip" aria-hidden="true"></span>
    <h1 class="dsg-htitle">Solution Designer</h1>
    <div class="dsg-hright">
      <span class="dsg-hbtn success gap" aria-disabled="true" title="Diagram authoring is a reference-only lane — nothing is authored or saved on this surface (named gap)">${bpIcon("plus")}<span>New Diagram</span></span>
      <span class="dsg-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)"><span>Help</span>${bpIcon("help")}</span>
    </div>
  </header>`;

  const hero = `<section class="dsg-hero">
    <img class="dsg-heroimg" src="${DSG_HERO_URI}" alt="" aria-hidden="true">
    <div class="dsg-heroct">
      <h3 class="dsg-h1">Solution Designer</h3>
      <p class="dsg-desc">Solution Designer helps you to transform business problems into Foundry solutions using a graph-based interface, with examples, editing tools, and resource links for collaborative and iterative design.</p>
    </div>
  </section>`;

  const aipCard = `<div class="dsg-aipcard">
    <img class="dsg-aipico" src="${DSG_AIP_ICON_URI}" width="60" height="52" alt="" aria-hidden="true">
    <div class="dsg-aipcopy">
      <h4 class="dsg-aipt">Have a workflow in mind? Use AIP Architect to help you plan it.</h4>
      <div class="dsg-aipsub">Answer a few questions to get AIP suggestions on how to implement your workflow in Foundry.</div>
    </div>
    <span class="dsg-planbtn gap" aria-disabled="true" title="AIP Architect planning is a reference-only lane — no planning assistant is bound to this surface (named gap)"><span>Start planning</span>${bpIcon("arrow-right")}</span>
  </div>`;

  // The template gallery is the reference's own static template-library strip (vendor chrome, not
  // estate data) — embedded VERBATIM from the capture, like the #48 marketplace hero. The next-arrow
  // is a real (disabled) control overlaid transparently on its verbatim pixels.
  const gallery = `<div class="dsg-gallery">
    <div class="dsg-galhead"><span class="dsg-galt">Explore our library of reference solution architecture diagrams</span><span class="dsg-browse gap" aria-disabled="true" title="Template browsing is a reference-only lane (named gap)">${bpIcon("manual")}<span>Browse all</span></span></div>
    <img class="dsg-strip" src="${DSG_GALLERY_STRIP_URI}" width="961" height="202" alt="Reference solution-architecture template previews (verbatim capture chrome)">
    <span class="dsg-galarrow gap" aria-disabled="true" title="Template pagination is a reference-only lane (named gap)"></span>
  </div>`;

  const viewRow = `<div class="dsg-viewrow">
    <span class="dsg-viewlbl">View</span>
    <span class="dsg-pill on">Recents</span>
    <span class="dsg-pill gap" aria-disabled="true" title="Favorites are not recorded on the ODK object plane (named gap)">Favorites</span>
    <span class="dsg-open gap" aria-disabled="true" title="Diagram open is a reference-only lane — rows below select a composition instead (named gap)">${bpIcon("folder-open")}<span>Open Diagram</span></span>
  </div>`;

  const table = `<div class="dsg-table">
    <div class="dsg-thead"><span class="dsg-th name">Diagram</span><span class="dsg-th">Creator</span><span class="dsg-th">Last edited by</span><span class="dsg-th">Last viewed</span></div>
    <div class="dsg-rows">${rowsHtml}</div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .dsg-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .dsg-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .dsg-header{flex:0 0 51px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 0 #d3d8de;z-index:6}
    .dsg-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(63,166,218,.1) url('${DSG_APP_TILE_URI}') center/24px no-repeat;box-shadow:inset -1px 0 0 0 rgba(63,166,218,.25)}
    .dsg-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .dsg-hright{margin-left:auto;display:flex;align-items:flex-start;gap:10px;padding-right:20px}
    .dsg-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:18px;cursor:default}
    .dsg-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .dsg-hbtn.success svg{color:#fff}
    .dsg-hbtn.outlined{border:1px solid rgba(95,107,124,.25);padding:0 8px;color:#1c2127}
    .dsg-hbtn.outlined span{line-height:16.1px}
    .dsg-hbtn.outlined svg{color:#5f6b7c}
    .dsg-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .dsg-content{max-width:1090px;margin:0 auto;padding:0 45px}
    .dsg-hero{position:relative;background:#fff;height:179px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .dsg-heroct{position:relative;max-width:1040px;height:100%;margin:0 auto;padding:0 20px;background:linear-gradient(90deg,#fff 575px,rgba(255,255,255,0) 100%)}
    .dsg-heroimg{position:absolute;right:0;top:0;width:650px;height:179px}
    .dsg-h1{position:relative;font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;padding-top:20px}
    .dsg-desc{position:relative;width:625px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:0;padding-top:5px}
    .dsg-aipcard{position:relative;z-index:2;margin-top:-55px;height:92px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px #7961db;display:flex;align-items:flex-start}
    .dsg-aipico{margin:20px 0 0 20px;flex:0 0 60px}
    .dsg-aipcopy{margin-left:15px;min-width:0;flex:1}
    .dsg-aipt{font-size:18px;line-height:21px;font-weight:600;color:#1c2127;margin:24px 0 0}
    .dsg-aipsub{font-size:14px;line-height:18px;color:#1c2127;margin-top:5px}
    .dsg-planbtn{display:inline-flex;align-items:center;gap:9px;height:40px;margin:26px 20px 0 0;padding:0 14px 0 16px;border-radius:4px;background:#7961db;color:#fff;font-size:16px;line-height:20.6px;cursor:default;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1);flex:0 0 auto}
    .dsg-planbtn svg{color:#fff}
    .dsg-gallery{position:relative;margin-top:30px;height:279px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(0,0,0,.15),0 1px 2px rgba(0,0,0,.02)}
    .dsg-galhead{display:flex;align-items:flex-start;padding:20px 20px 0}
    .dsg-galt{flex:1;font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin-top:2.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .dsg-browse{display:inline-flex;align-items:center;gap:8px;height:24px;padding:0 8px;border-radius:4px;color:#215db0;font-size:14px;line-height:16.1px;cursor:default}
    .dsg-browse svg{color:#215db0}
    .dsg-strip{position:absolute;left:20px;top:58px;width:961px;height:202px}
    .dsg-galarrow{position:absolute;left:940px;top:144px;width:30px;height:30px;border-radius:50%;cursor:default}
    .dsg-viewrow{display:flex;align-items:center;margin-top:40px;height:30px}
    .dsg-viewlbl{font-size:14px;line-height:18px;color:#1c2127}
    .dsg-pill{display:inline-flex;align-items:center;height:30px;margin-left:10px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;cursor:default}
    .dsg-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .dsg-pill.gap{background:rgba(143,153,168,.15);color:#1c2127}
    .dsg-open{display:inline-flex;align-items:center;gap:8px;height:30px;margin-left:auto;padding:0 8px;border-radius:4px;color:#1c2127;font-size:14px;line-height:16.1px;cursor:default}
    .dsg-open svg{color:#5f6b7c}
    .dsg-table{margin-top:10px;min-height:714px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .dsg-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .dsg-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .dsg-th.name{width:50%;padding-left:20px}
    .dsg-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .dsg-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .dsg-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .dsg-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .dsg-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .dsg-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .dsg-rowstar{display:none}
    .dsg-selpill{display:inline-block;margin-left:8px;padding:0 6px;border-radius:9px;background:rgba(45,114,210,.15);color:#215db0;font-size:11px;line-height:16px;vertical-align:1px}
    .dsg-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .dsg-dash{color:#5f6b7c}
    .dsg-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .dsg-truth{margin-top:26px;padding-bottom:40px}
    .dsg-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 10px}
    .dsg-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .dsg-switch{margin:0 0 12px;display:flex;gap:8px;flex-wrap:wrap}
    .dsg-schip{display:inline-flex;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .dsg-schip.on{background:rgba(45,114,210,.2);color:#184a90;font-weight:600}
    .dsg-truthcols{display:flex;gap:16px;align-items:flex-start}
    .dsg-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .dsg-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .dsg-truthcol ul{list-style:none;margin:0;padding:0}
    .dsg-truthitem{padding:5px 0;border-bottom:1px solid #eef0f2;font-size:13px}
    .dsg-truthitem:last-child{border-bottom:0}
    .dsg-meta{color:#5f6b7c;font-weight:400;font-size:12px}
    .dsg-ref{display:block;font-size:11px;color:#5f6b7c;margin-top:1px;word-break:break-all}
    .dsg-gapnote{font-size:13px;color:#5f6b7c;margin:4px 0}
    .dsg-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Solution Designer</title><style>${css}</style></head>
    <body><div class="dsg-shell">${globalRail}<div class="dsg-main">${header}<div class="dsg-body">${hero}<main class="dsg-content">${aipCard}${gallery}${viewRow}${table}${truth}</main></div></div></div></body></html>`;
}

// ============================ EVALUATIONS · EVALSUITES (AIP Evals landing — suite-library port, #54)
// The Reference UX Port program — the SIXTH origin-alignment-queue port. The reference is the
// origin-aligned AIP Evals landing capture (http://localhost:9225/workspace/evals/ — the
// /__apps/evalsuites proxy lane renders no data, documented by the #44 sweep; the What's-new modal
// is dismissed by a reference-only pre-capture hook). This IOI-owned surface reproduces the visible
// splash shell PIXEL-FAITHFULLY — dark global rail, app header (teal evals tile · AIP Evals ·
// New-evaluation-suite / Help as named gaps), the 88px hero band (title · one-line description ·
// verbatim illustration under the reference's own 1040px white-gradient overlay), the View row,
// the viewport-height-ruled Recents table, and the marketplace-examples band (verbatim capture
// strip, reused from #50) — while the DATA region renders REAL eval-suite plane truth: one row per
// declared suite (name · ref · subject scopes · declared/complete health · status · created date),
// and below the fold the full suite-library truth (subject scopes · rubric refs · evidence
// requirements · consent requirements · candidate refs — all verbatim daemon records).
// THE SEMANTIC BOUNDARY IS HARD: a DECLARATION LIBRARY, never assessment — no EvalRun execution,
// no scoring, no verdicts, no judge runs, no scorecards, no auto-mining, no promotion; health is
// DECLARED-COMPLETENESS, never a score. Owner: Evaluations (/__ioi/evaluations, linked both ways).
function renderEvalsuitesPort(suitesJson) {
  const esc = CX_ESC;
  const list = Array.isArray(suitesJson && suitesJson.eval_suites) ? suitesJson.eval_suites : [];
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };

  const recent = [...list].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))).slice(0, 12);
  const gapDash = (why) => `<span class="evl-dash" title="${esc(why)}">—</span>`;
  const rowsHtml = recent.length ? recent.map((s) => `<div class="evl-row" title="A DECLARED evaluation suite — a library record; nothing scores or executes here">
      <span class="evl-cell name">
        <span class="evl-rowico" aria-hidden="true"></span>
        <span class="evl-rowdata">
          <span class="evl-rowname">${esc(s.name || s.id)}</span>
          <span class="evl-rowpath">${esc(s.ref || s.id)} · subjects ${esc((s.subject_scope || []).join("/") || "—")} · ${esc(s.health || "declared")} · ${esc(s.status || "draft")} · created ${fdate(s.created_at)}</span>
        </span>
      </span>
      <span class="evl-cell">${gapDash("No principal is recorded on the eval-suite plane (named gap)")}</span>
      <span class="evl-cell">${gapDash("No edit principal is recorded on the eval-suite plane (named gap)")}</span>
      <span class="evl-cell">${gapDash("View tracking is not recorded on the eval-suite plane (named gap)")}</span>
    </div>`).join("") : `<div class="evl-empty">No evaluation suites declared yet — this table renders the real eval-suite plane and never fabricates rows. Suites are declared on the <a href="/__ioi/evaluations">Evaluations substrate</a> (the inert contract: subject scope + consent + evidence requirements + named candidate handoffs).</div>`;

  const byHealth = {}; const byStatus = {};
  for (const s of list) { byHealth[s.health || "declared"] = (byHealth[s.health || "declared"] || 0) + 1; byStatus[s.status || "draft"] = (byStatus[s.status || "draft"] || 0) + 1; }
  const chips = (o) => Object.entries(o).map(([k, n]) => `<span class="evl-chip">${esc(k)} <b>${n}</b></span>`).join("") || '<span class="evl-chip">none</span>';
  const suiteDetail = (s) => `<li class="evl-truthitem"><b>${esc(s.name || s.id)}</b> <span class="evl-meta">${esc(s.health || "declared")} · ${esc(s.status || "draft")}</span>
      <code class="evl-refc">${esc(s.ref || "")}</code>
      <span class="evl-meta">subjects: ${esc((s.subject_scope || []).join(", ") || "—")} · rubrics: ${esc((s.rubric_refs || []).join(", ") || "—")} · evidence: ${esc((s.evidence_requirements || []).join(", ") || "—")} · consent: ${esc((s.consent_requirements || []).join(", ") || "—")} · candidates: ${esc((s.candidate_refs || []).join(", ") || "—")}</span>
    </li>`;

  const truth = `<section class="evl-truth" id="evalsuites-truth">
    <h2 class="evl-trutht">Suite library truth <span class="evl-count">${list.length}</span> <span class="evl-truthsub">the real eval-suite plane — every record is a DECLARATION (subject scope · rubric refs · evidence requirements · consent requirements · named candidate handoffs), nothing invented</span></h2>
    <p class="evl-boundary"><b>The assessment boundary:</b> a suite's <code>health</code> is DECLARED-COMPLETENESS (declared/complete), <b>never a score</b>. Nothing on this surface runs, scores, or judges: EvalRun execution, scoring, verdicts, judge runs, scorecards, auto-mining and promotion are <b>named gaps</b> (a later authority-crossing cut). Candidate refs are LOCAL allowlisted schemes only — the plane rejects external URLs fail-closed.</p>
    <div class="evl-truthcols">
      <div class="evl-truthcol"><h3>By health <span class="evl-meta">(declared-completeness)</span></h3><div class="evl-chips">${chips(byHealth)}</div><h3 style="margin-top:12px">By status</h3><div class="evl-chips">${chips(byStatus)}</div></div>
      <div class="evl-truthcol"><h3>Declared suites <span class="evl-meta">(${list.length}, full records)</span></h3>${list.length ? `<ul>${list.slice(0, 8).map(suiteDetail).join("")}</ul>${list.length > 8 ? `<p class="evl-gapnote">…and ${list.length - 8} more on the substrate.</p>` : ""}` : `<p class="evl-gapnote">No suites declared — honest empty, nothing fabricated.</p>`}</div>
    </div>
    <p class="evl-foot">Unsupported reference lanes — New evaluation suite here, favorites, marketplace example installs — are <b>named gaps disabled in place</b>, never hidden. Suites are declared/edited on the <a href="/__ioi/evaluations">Evaluations owner surface →</a> (with the consent ladder + feedback candidate source at <a href="/__ioi/feedback">Feedback &amp; Annotations</a>); assessment subjects come from real Missions runs/failures/blockers. Reference: the origin-aligned <a href="http://localhost:9225/workspace/evals/" rel="noopener">AIP Evals capture</a> — the <a href="/__apps/evalsuites">/__apps/evalsuites proxy lane ↗</a> is documented insufficient (renders no data; #44 sweep evidence).</p>
  </section>`;

  const globalRail = ioiGlobalRailHtml({ label: "AIP Evals", href: "/__ioi/evaluations/evalsuites", iconUri: EVL_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="evl-header">
    <span class="evl-hchip" aria-hidden="true"></span>
    <h1 class="evl-htitle">AIP Evals</h1>
    <div class="evl-hright">
      <span class="evl-hbtn success gap" aria-disabled="true" title="Suite authoring from this surface is a reference-only lane — suites are declared on the Evaluations substrate (named gap)">${bpIcon("plus")}<span>New evaluation suite</span></span>
      <span class="evl-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)"><span>Help</span>${bpIcon("help")}</span>
    </div>
  </header>`;

  const hero = `<section class="evl-hero">
    <img class="evl-heroimg" src="${EVL_HERO_URI}" alt="" aria-hidden="true">
    <div class="evl-heroct">
      <h3 class="evl-h1">AIP Evals</h3>
      <p class="evl-desc">Create evaluation suites for LLM-backed use-cases.</p>
    </div>
  </section>`;

  const viewRow = `<div class="evl-viewrow">
    <span class="evl-viewlbl">View</span>
    <span class="evl-pill on">Recents</span>
    <span class="evl-pill gap" aria-disabled="true" title="Favorites are not recorded on the eval-suite plane (named gap)">Favorites</span>
  </div>`;

  const table = `<div class="evl-table">
    <div class="evl-thead"><span class="evl-th name">Files</span><span class="evl-th">Creator</span><span class="evl-th">Last edited by</span><span class="evl-th">Last viewed</span></div>
    <div class="evl-rows">${rowsHtml}</div>
  </div>`;

  const examples = `<div class="evl-examples">
    <h5 class="evl-exh">Explore reference examples</h5>
    <div class="evl-exsub">See how AIP Evals can be used to evaluate any AI system.</div>
    <div class="evl-exstripwrap">
      <img class="evl-exstrip" src="${MCH_EXAMPLES_STRIP_URI}" width="562" height="272" alt="Reference marketplace example cards (verbatim capture chrome)">
      <span class="evl-excard c1 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
      <span class="evl-excard c2 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
    </div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .evl-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .evl-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .evl-header{flex:0 0 51px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 0 #d3d8de;z-index:6}
    .evl-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(0,112,103,.1) url('${EVL_APP_TILE_URI}') center/24px no-repeat;box-shadow:inset -1px 0 0 0 rgba(0,112,103,.25)}
    .evl-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .evl-hright{margin-left:auto;display:flex;align-items:flex-start;gap:10px;padding-right:20px}
    .evl-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:18px;cursor:default}
    .evl-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .evl-hbtn.success svg{color:#fff}
    .evl-hbtn.outlined{border:1px solid rgba(95,107,124,.25);padding:0 8px;color:#1c2127}
    .evl-hbtn.outlined span{line-height:16.1px}
    .evl-hbtn.outlined svg{color:#5f6b7c}
    .evl-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .evl-content{max-width:1090px;margin:0 auto;padding:0 45px}
    .evl-hero{position:relative;background:#fff;height:88px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .evl-heroct{position:relative;max-width:1040px;height:100%;margin:0 auto;padding:0 20px;background:linear-gradient(90deg,#fff 575px,rgba(255,255,255,0) 100%)}
    .evl-heroimg{position:absolute;right:0;top:0;width:316.6px;height:88px}
    .evl-h1{position:relative;font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;padding-top:20px}
    .evl-desc{position:relative;width:625px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:6px 0 0}
    .evl-viewrow{display:flex;align-items:center;margin-top:40px;height:30px}
    .evl-viewlbl{font-size:14px;line-height:18px;color:#1c2127}
    .evl-pill{display:inline-flex;align-items:center;height:30px;margin-left:10px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;cursor:default}
    .evl-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .evl-pill.gap{background:rgba(143,153,168,.15);color:#1c2127}
    .evl-table{margin-top:10px;height:max(360px,calc(100vh - 604px));overflow-y:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .evl-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .evl-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .evl-th.name{width:50%;padding-left:20px}
    .evl-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .evl-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .evl-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .evl-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .evl-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .evl-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .evl-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .evl-dash{color:#5f6b7c}
    .evl-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .evl-examples{margin-top:28px}
    .evl-exh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .evl-exsub{font-size:14px;line-height:18px;color:#1c2127;margin-top:12px}
    .evl-exstripwrap{position:relative;margin-top:7px;width:562px;margin-left:-1px}
    .evl-exstrip{display:block}
    .evl-excard{position:absolute;top:1px;width:270px;height:270px;cursor:default}
    .evl-excard.c1{left:1px}.evl-excard.c2{left:291px}
    .evl-truth{margin-top:30px;padding-bottom:40px}
    .evl-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 8px}
    .evl-count{margin-left:8px;font-size:14px;font-weight:400;color:#5f6b7c;background:rgba(143,153,168,.15);border-radius:9px;padding:1px 8px}
    .evl-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .evl-boundary{font-size:13px;line-height:1.55;color:#1c2127;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(200,118,25,.4);padding:12px 14px;margin:0 0 14px}
    .evl-truthcols{display:flex;gap:16px;align-items:flex-start}
    .evl-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .evl-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .evl-truthcol ul{list-style:none;margin:0;padding:0}
    .evl-truthitem{padding:6px 0;border-bottom:1px solid #eef0f2;font-size:13px}
    .evl-truthitem:last-child{border-bottom:0}
    .evl-chips{display:flex;gap:6px;flex-wrap:wrap}
    .evl-chip{display:inline-flex;gap:5px;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .evl-meta{color:#5f6b7c;font-weight:400;font-size:12px}
    .evl-refc{display:block;font-size:11px;color:#5f6b7c;margin-top:1px;word-break:break-all}
    .evl-gapnote{font-size:12px;color:#5f6b7c;margin:8px 0 0;line-height:1.5}
    .evl-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AIP Evals</title><style>${css}</style></head>
    <body><div class="evl-shell">${globalRail}<div class="evl-main">${header}<div class="evl-body">${hero}<main class="evl-content">${viewRow}${table}${examples}${truth}</main></div></div></div></body></html>`;
}

// ============================ IMPROVEMENT · CHANGES (Upgrade Assistant — inbox port, #53)
// The Reference UX Port program — the FIFTH origin-alignment-queue port. The reference is the
// origin-aligned Upgrade Assistant capture (http://localhost:9225/workspace/upgrade-assistant/ —
// the /__apps/changes proxy lane renders thin data, documented by the #44 sweep; the What's-new
// modal is dismissed by a reference-only pre-capture hook). This IOI-owned surface reproduces the
// visible inbox shell PIXEL-FAITHFULLY — dark global rail, app header (upgrade tile · 1-organization
// group / Admin view / Assignee view / Help as named gaps), the slate info banner, the
// Active/Past-due/Archived tab lanes (LIVE ?lane= links), the Filters sidebar (search as a named
// gap · UPGRADE PROGRESS radios WIRED to ?filter= · the reference's UPGRADE-TYPE taxonomy as
// named-gap facets · SORT as named gaps; facet COUNTS are live data, masked) and the grouped list —
// while the DATA region renders REAL Improvement-plane truth: one row per improvement proposal
// (signal · proposal_ref · target_ref · kind pill · state + gate posture · approval/release/
// simulation refs as the proof trail), grouped Pre-published (pending/approved — not yet applied)
// vs Published (applied), with rejected proposals in the Archived lane and Past-due an HONESTLY
// EMPTY lane (no due-date concept on the plane). READ-ONLY: no apply, no approve/reject, no
// deploy, no release-gate mutation — those lanes live on the owner surface
// (/__ioi/agent-studio#improvement-proposals, linked first-class both ways).
function renderChangesPort(proposals, lane, filter) {
  const esc = CX_ESC;
  const all = Array.isArray(proposals) ? proposals : [];
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };

  // Lane + facet semantics over REAL plane truth (the reference's lanes, honestly mapped):
  //   Active   = non-rejected proposals (pending · approved · applied)
  //   Past due = HONESTLY EMPTY (the improvement plane records no due dates — a named gap)
  //   Archived = rejected proposals
  //   filter=action (the reference's default radio) = pending review · filter=all = everything
  const active = all.filter((p) => p.state !== "rejected");
  const archived = all.filter((p) => p.state === "rejected");
  const pendingReview = all.filter((p) => p.state === "pending");
  const laneSet = lane === "archived" ? archived : lane === "pastdue" ? [] : active;
  // The "requiring my action" facet (pending review) scopes the ACTIVE lane only — Archived is
  // terminal (rejected proposals, never pending) and shows its full set regardless of the facet.
  const shown = (lane === "active" && filter !== "all") ? laneSet.filter((p) => p.state === "pending") : laneSet;
  const prePub = shown.filter((p) => p.state !== "applied");
  const published = shown.filter((p) => p.state === "applied");
  const kinds = {};
  for (const p of all) kinds[p.proposal_kind || "?"] = (kinds[p.proposal_kind || "?"] || 0) + 1;

  const rowHtml = (p) => `<div class="chg-row" title="A read-only improvement projection — review/apply/release lanes live on the owner surface (Agent Studio)">
      <span class="chg-cname">
        <span class="chg-rowico" aria-hidden="true"></span>
        <span class="chg-rowdata">
          <span class="chg-rowname">${esc(p.signal || p.proposal_kind || p.improvement_id)}</span>
          <span class="chg-rowsub">${esc(p.proposal_ref)} · target ${esc(p.target_ref || "—")} · created ${fdate(p.created_at)}${p.latest_simulation_high_impact ? " · high-impact simulation" : ""}</span>
        </span>
      </span>
      <span class="chg-ctype"><span class="chg-kindpill">${esc(p.proposal_kind || "?")}</span></span>
      <span class="chg-cdue"><span class="chg-dash" title="No due-date concept on the improvement plane (named gap)">—</span></span>
      <span class="chg-cact">
        <span class="chg-statepill s-${esc(p.state || "pending")}">${esc(p.state || "pending")}</span>
        <span class="chg-proof" title="the proof trail: gate posture + approval/release/simulation refs (real records)">${esc((p.gate || {}).posture || "")}${p.approval_request_ref ? " · appr" : ""}${p.release_control_ref ? " · rel" : ""}${p.latest_simulation_ref ? " · sim" : ""}</span>
      </span>
    </div>`;
  const group = (label, items, mapNote) => `<div class="chg-group">
      <div class="chg-grouphead"><h6 class="chg-grouptitle" title="${esc(mapNote)}">${label}</h6><span class="chg-grouptag">${items.length}</span><span class="chg-groupchev" aria-hidden="true">${bpIcon("caret-down")}</span></div>
      ${items.length ? items.map(rowHtml).join("") : `<div class="chg-emptyrow">No ${label.toLowerCase()} ${lane === "archived" ? "archived proposals" : "upgrades requiring action"}</div>`}
    </div>`;

  const laneTitles = { active: ["Active upgrades", "Current upgrades. Resources are actively updated."], pastdue: ["Past due upgrades", "No due-date concept exists on the improvement plane — this lane is honestly empty (named gap)."], archived: ["Archived upgrades", "Rejected improvement proposals — terminal, never applied."] };
  const [listTitle, listSub] = laneTitles[lane] || laneTitles.active;

  const listBody = lane === "pastdue"
    ? `<div class="chg-emptylane">The improvement plane records no due dates — nothing can be past due. This is a <b>named gap</b>, not an empty query.</div>`
    : `${group("Pre-published", prePub, "pending/approved proposals — real records whose change has NOT yet been applied (the honest mapping of the reference's pre-published group)")}
       <div class="chg-groupdiv"></div>
       ${group("Published", published, "applied proposals — real records whose change IS live in the estate policy plane (the honest mapping of the reference's published group)")}`;

  const truth = `<div class="chg-truth" id="changes-truth">
      <h6 class="chg-trutht">Improvement-plane truth <span class="chg-truthsub">${all.length} proposal${all.length === 1 ? "" : "s"} · ${pendingReview.length} pending review · ${all.filter((p) => p.state === "approved").length} approved · ${all.filter((p) => p.state === "applied").length} applied · ${archived.length} rejected — real records, nothing invented</span></h6>
      <p class="chg-truthp">Kinds: ${Object.entries(kinds).map(([k, n]) => `${esc(k)} (${n})`).join(" · ")}. Every row carries its real proof trail — gate posture, approval-request ref, release-control ref, simulation ref/hash. This surface is a <b>read-only projection</b>: proposing, simulating, approving/rejecting, applying and release-gate control all live on the <a href="/__ioi/agent-studio#improvement-proposals">owner surface (Agent Studio) →</a>; nothing here mutates, applies, deploys or releases. Reference: the origin-aligned <a href="http://localhost:9225/workspace/upgrade-assistant/" rel="noopener">Upgrade Assistant capture</a> — the <a href="/__apps/changes">/__apps/changes proxy lane ↗</a> is documented insufficient (renders thin data; #44 sweep evidence). Sort is a named gap (no due dates); rows order by update recency.</p>
    </div>`;

  const globalRail = ioiGlobalRailHtml({ label: "Upgrade Assistant", href: "/__ioi/improvement/changes", iconUri: CHG_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="chg-header">
    <span class="chg-hchip" aria-hidden="true"></span>
    <h1 class="chg-htitle">Upgrade Assistant</h1>
    <div class="chg-hright">
      <span class="chg-orgbtn gap" aria-disabled="true" title="Organization scoping is a named gap — the estate is a single deployment; the list below is its full improvement truth">${bpIcon("office")}<span>1 organization</span>${bpIcon("caret-down")}</span>
      <span class="chg-adminview gap" aria-disabled="true" title="Admin/assignee principal scoping is a named gap — no assignment concept on the improvement plane">Admin view</span>
      <span class="chg-hbtn outlined gap" aria-disabled="true" title="Reference view toggle (named gap) — the list renders the estate's full improvement truth">Assignee view</span>
      <span class="chg-hbtn outlined helpbtn gap" aria-disabled="true" title="Reference help lane (named gap)">${bpIcon("help")}<span>Help</span>${bpIcon("caret-down")}</span>
    </div>
  </header>`;

  const banner = `<div class="chg-banner"><div class="chg-bannerin"><span class="chg-bannertxt" title="Reference copy (the view-toggle chrome) — principal assignment is a named gap; this surface renders the estate's full improvement truth, verified against the daemon plane">You are viewing resources for which you are personally assigned actions. Enable Admin view to help manage upgrades for organizations where you are a Maintenance Operator.</span><span class="chg-bannerq" aria-hidden="true">${bpIcon("help")}</span></div></div>`;

  const tabs = `<nav class="chg-tabs">
    <a class="chg-tab${lane === "active" ? " on" : ""}" href="/__ioi/improvement/changes?lane=active${filter === "all" ? "&filter=all" : ""}">Active</a>
    <a class="chg-tab${lane === "pastdue" ? " on" : ""}" href="/__ioi/improvement/changes?lane=pastdue${filter === "all" ? "&filter=all" : ""}" title="Honestly empty — no due-date concept on the improvement plane (named gap)">Past due</a>
    <a class="chg-tab${lane === "archived" ? " on" : ""}" href="/__ioi/improvement/changes?lane=archived${filter === "all" ? "&filter=all" : ""}">Archived</a>
  </nav>`;

  const qs = (f) => `/__ioi/improvement/changes?lane=${lane}${f === "all" ? "&filter=all" : ""}`;
  const sidebar = `<aside class="chg-sidebar">
    <div class="chg-fhead"><h6>Filters</h6><span class="chg-fcollapse gap" aria-disabled="true" title="Sidebar collapse is a reference-only lane (named gap)">${bpIcon("menu-closed")}</span></div>
    <div class="chg-search gap" title="Name search is a reference-only lane (named gap)">${bpIcon("search")}<input placeholder="Search by upgrade name…" disabled aria-label="Search by upgrade name (reference-only, not wired)"></div>
    <div class="chg-fdiv"></div>
    <h6 class="chg-fsec">Upgrade progress</h6>
    <a class="chg-radio${filter !== "all" ? "" : " sel"}" href="${qs("all")}"><span class="chg-rdot${filter === "all" ? " on" : ""}"></span><span class="chg-rlabel">All upgrades</span><span class="chg-rcount">${laneSet.length}</span></a>
    <a class="chg-radio${filter !== "all" ? " sel" : ""}" href="${qs("action")}" title="pending-review proposals — the honest mapping of the reference's requiring-my-action facet (no principal assignment on the plane)"><span class="chg-rdot${filter !== "all" ? " on" : ""}"></span><span class="chg-rlabel">Upgrades requiring my action</span><span class="chg-rcount">${laneSet.filter((p) => p.state === "pending").length}</span></a>
    <div class="chg-fdiv"></div>
    <h6 class="chg-fsec">Upgrade type</h6>
    ${["Admin action", "Model migration", "Platform change", "Remediation", "Security", "Version update"].map((t) => `<span class="chg-check gap" aria-disabled="true" title="The reference's upgrade-type taxonomy is a named gap — the estate's real proposal kinds are ${esc(Object.entries(kinds).map(([k, n]) => `${k} (${n})`).join(" · "))}"><span class="chg-cbox"></span><span class="chg-rlabel">${t}</span><span class="chg-rcount">0</span></span>`).join("")}
    <div class="chg-fdiv"></div>
    <h6 class="chg-fsec">Sort</h6>
    ${["Soonest due date", "Latest due date", "Least remaining actions", "Most remaining actions"].map((t, i) => `<span class="chg-radio gap" aria-disabled="true" title="Due-date sorting is a named gap (no due dates on the plane) — rows order by update recency"><span class="chg-rdot${i === 0 ? " on" : ""}"></span><span class="chg-rlabel">${t}</span></span>`).join("")}
  </aside>`;

  const list = `<section class="chg-list">
    <div class="chg-listhead"><h6 class="chg-listtitle">${esc(listTitle)}</h6><div class="chg-listsub">${esc(listSub)}</div></div>
    <div class="chg-cols"><span class="chg-col name">Name</span><span class="chg-col type">Type</span><span class="chg-col due">Due date<span class="chg-sorticon gap" title="Due-date sorting is a named gap (named in the sidebar)">${bpIcon("sort-desc")}</span></span><span class="chg-col act">My actions</span></div>
    <div class="chg-rows">${listBody}${truth}</div>
  </section>`;

  const css = `@font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:400;font-display:block;src:url(/__ioi/fonts/source-sans-pro-400.woff2) format('woff2')}
    @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:600;font-display:block;src:url(/__ioi/fonts/source-sans-pro-600.woff2) format('woff2')}
    @font-face{font-family:'Source-Sans-Pro';font-style:normal;font-weight:700;font-display:block;src:url(/__ioi/fonts/source-sans-pro-700.woff2) format('woff2')}
    :root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .chg-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .chg-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .chg-header{flex:0 0 51px;height:51px;display:flex;align-items:flex-start;background:#fff;z-index:6}
    .chg-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(167,182,194,.1) url('${CHG_APP_TILE_URI}') center/24px no-repeat;box-shadow:inset -1px 0 0 0 rgba(167,182,194,.25)}
    .chg-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:7px 0 0 12px;flex:0 0 auto}
    .chg-hright{margin-left:auto;align-self:stretch;display:flex;align-items:flex-start;padding-right:20px}
    .chg-orgbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;font-size:12px;line-height:16px;color:#1c2127;cursor:default}
    .chg-orgbtn svg{color:#5f6b7c}
    .chg-adminview{margin-left:2px;margin-top:17px;font-size:14px;line-height:16.1px;color:#5f6b7c;cursor:default}
    .chg-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin:10px 0 0 17px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;cursor:default}
    .chg-hbtn.helpbtn{margin-left:2px;gap:8px;padding:0 9px}
    .chg-hbtn.helpbtn svg:last-child{color:#5f6b7c;margin-left:-1px}
    .chg-hbtn.outlined{border:1px solid rgba(95,107,124,.25);background:#fff;color:#1c2127}
    .chg-hbtn.outlined svg{color:#5f6b7c}
    .chg-banner{flex:0 0 30px;display:flex;background:#5f6b7c}
    .chg-bannerin{flex:1;max-width:1210px;margin:0 auto;display:flex;align-items:center;justify-content:flex-start;gap:17px;padding-left:36.4px;height:30px}
    .chg-bannertxt{font-size:14px;line-height:18px;color:#fff}
    .chg-bannerq{display:inline-flex;color:rgba(255,255,255,.75)}
    .chg-tabs{flex:0 0 41px;display:flex;gap:20px;align-items:stretch;background:#fff;padding-left:20px;box-shadow:inset 0 -1px 0 #d3d8de}
    .chg-tab{display:inline-flex;align-items:center;height:40px;align-self:flex-start;font-size:16px;line-height:40px;color:#1c2127;position:relative}
    .chg-tab.on{color:#215db0}
    .chg-tab.on::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:#215db0}
    .chg-body{flex:1 1 auto;min-height:0;display:flex}
    .chg-sidebar{flex:0 0 260px;background:#f6f7f9;padding:15px 20px 0;overflow-y:auto}
    .chg-fhead{display:flex;align-items:center;margin-bottom:36px}
    .chg-fhead h6{font-size:14px;line-height:16px;font-weight:600;color:#1c2127;margin:0 0 0 -4px;flex:1}
    .chg-fcollapse{display:inline-flex;color:#5f6b7c;cursor:default}
    .chg-search{display:flex;align-items:center;gap:6px;width:219px;height:30px;background:#fff;border-radius:4px;padding:0 8px;color:#5f6b7c;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3)}
    .chg-search input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0;min-width:0}
    .chg-search input::placeholder{color:#5f6b7c}
    .chg-fdiv{height:1px;background:#d8dce2;margin:20px -20px 0}
    .chg-fsec{font-size:14px;line-height:16px;font-weight:600;color:#5f6b7c;margin:20px 0 12px;text-transform:uppercase;letter-spacing:0}
    .chg-radio,.chg-check{display:flex;align-items:center;height:18px;margin-bottom:8px;font-size:14px;line-height:18px;color:#1c2127;cursor:default;position:relative}
    a.chg-radio{cursor:pointer;color:#1c2127}
    .chg-rdot{width:16px;height:16px;flex:0 0 16px;border-radius:50%;box-shadow:inset 0 0 0 1px #738091;background:#fff;margin-right:8px}
    .chg-rdot.on{box-shadow:none;background:#2d72d2;position:relative}
    .chg-rdot.on::after{content:"";position:absolute;left:5px;top:5px;width:6px;height:6px;border-radius:50%;background:#fff}
    .chg-cbox{width:16px;height:16px;flex:0 0 16px;border-radius:3px;box-shadow:inset 0 0 0 1px #738091;background:#fff;margin-right:8px}
    .chg-rlabel{flex:1;min-width:0;white-space:nowrap}
    .chg-rcount{position:absolute;right:0;top:1px;font-size:12px;line-height:16px;color:#5f6b7c}
    .chg-list{flex:1;min-width:0;background:#fff;box-shadow:0 0 0 1px rgba(0,0,0,.15),0 0 5px rgba(0,0,0,.02);overflow-y:auto}
    .chg-listhead{padding:8.3px 20px 0}
    .chg-listtitle{font-size:14px;line-height:16px;font-weight:600;color:#1c2127;margin:0}
    .chg-listsub{font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:2.6px}
    .chg-cols{display:flex;height:35px;margin-top:9.3px;background:#f6f7f9;padding:9.3px 0 0}
    .chg-col{font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .chg-col.name{flex:1;padding-left:20px}
    .chg-col.type{width:140px}
    .chg-col.due{width:140px;display:inline-flex;gap:6px}
    .chg-col.act{width:160px}
    .chg-sorticon{display:inline-flex;color:#5f6b7c;margin-top:-2px}
    .chg-rows{min-height:200px}
    .chg-grouphead{display:flex;align-items:center;padding:16px 20px 12px}
    .chg-grouptitle{font-size:14px;line-height:16px;font-weight:600;color:#1c2127;margin:0;border-bottom:1px dotted #1c2127;cursor:default}
    .chg-grouptag{margin-left:8px;font-size:12px;line-height:16px;padding:2px 6px;border-radius:2px;background:rgba(143,153,168,.15);color:#5f6b7c}
    .chg-groupchev{margin-left:auto;display:inline-flex;color:#5f6b7c}
    .chg-groupdiv{height:1px;background:#e5e8eb;margin:10px 0}
    .chg-emptyrow{padding:14px 20px 20px;font-size:14px;font-style:italic;color:#5f6b7c}
    .chg-emptylane{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .chg-row{display:flex;align-items:flex-start;padding:12px 0;border-top:1px solid #eef0f2}
    .chg-cname{flex:1;min-width:0;display:flex;align-items:flex-start;padding-left:20px}
    .chg-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${CHG_APP_TILE_URI}') center/16px no-repeat}
    .chg-rowdata{margin-left:10px;min-width:0;flex:1;padding-right:16px}
    .chg-rowname{display:block;font-size:14px;line-height:18px;font-weight:600;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .chg-rowsub{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .chg-ctype{width:140px}
    .chg-kindpill{display:inline-block;padding:2px 8px;border-radius:2px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px;line-height:16px}
    .chg-cdue{width:140px;font-size:14px}
    .chg-dash{color:#5f6b7c}
    .chg-cact{width:160px;padding-right:14px}
    .chg-statepill{display:inline-block;padding:2px 8px;border-radius:2px;font-size:12px;line-height:16px;background:rgba(143,153,168,.15);color:#1c2127}
    .chg-statepill.s-applied{background:rgba(35,133,81,.15);color:#1c6e42}
    .chg-statepill.s-pending{background:rgba(200,118,25,.15);color:#935610}
    .chg-statepill.s-approved{background:rgba(45,114,210,.15);color:#215db0}
    .chg-statepill.s-rejected{background:rgba(205,66,70,.12);color:#ac2f33}
    .chg-proof{display:block;font-size:11px;color:#5f6b7c;margin-top:3px}
    .chg-truth{padding:18px 20px 30px;border-top:1px solid #e5e8eb;margin-top:16px}
    .chg-trutht{font-size:13px;font-weight:600;color:#1c2127;margin:0 0 6px}
    .chg-truthsub{font-weight:400;color:#5f6b7c;margin-left:6px}
    .chg-truthp{font-size:12px;line-height:1.6;color:#7b8494;margin:0}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Upgrade Assistant</title><style>${css}</style></head>
    <body><div class="chg-shell">${globalRail}<div class="chg-main">${header}${banner}${tabs}<main class="chg-body">${sidebar}${list}</main></div></div></body></html>`;
}

// ============================ DATA · SOURCES (Data Connection landing — declared-catalog port, #52)
// The Reference UX Port program — the FOURTH origin-alignment-queue port (after #49/#50/#51). The
// reference is the origin-aligned Data Connection landing capture
// (http://localhost:9225/workspace/data-ingestion-app/ — the /__apps/sources proxy lane renders no
// data, documented by the #44 sweep; the What's-new modal is dismissed by a reference-only
// pre-capture hook). This IOI-owned surface reproduces the visible landing shell PIXEL-FAITHFULLY —
// dark global rail, tabbed app header (Data Connection · Sources/Syncs/Agents/Listeners/External
// stacks · store dropdown / New source / Help as named gaps · the sync-counter cluster bound to
// REAL materializing-run statuses), hero band + verbatim illustration under the reference's own
// 1040px white-gradient content overlay, the Set-up-new-connections card (VERBATIM option-card
// strip: vendor onboarding chrome, NOT an extraction affordance), the View row, the Recents table,
// and the marketplace-examples band — while the DATA regions render REAL DataSource-registry truth:
// one row per declared source (name · source_ref · kind · credential_posture · lifecycle · created
// date · the wired:false flag), endpoints rendered SAFELY (scheme+host+path only — userinfo/query/
// fragment stripped), and below the fold the full declared-catalog census + the daemon's own
// ingestion note VERBATIM ("declaration only — extraction requires a future authority crossing").
// THE AUTHORITY BOUNDARY IS THE POINT: a DECLARED source catalog — no extraction, no connection
// test, no live connector read, no materialization semantics on this surface.
// Owner family: Data (/__ioi/pipeline ladder · /__ioi/odk builder, linked first-class).
function renderSourcesPort(sourcesJson, mruns, cmJson, dataSourceSel) {
  // #64: mappings resolve per source (data_source_id join) — the semantic layer over declared
  // sources. ?dataSource= is URL-addressable selection (earned `select` capability only); no
  // authoring, no credential lanes, endpoints stay scheme+host+path.
  const srcMappings = (cmJson && Array.isArray(cmJson.connector_mappings)) ? cmJson.connector_mappings : [];
  const mapsOf = (sid) => srcMappings.filter((mm) => mm.data_source_id === sid);
  const esc = CX_ESC;
  const list = Array.isArray(sourcesJson && sourcesJson.data_sources) ? sourcesJson.data_sources : [];
  const runs = Array.isArray(mruns && mruns.materializing_runs) ? mruns.materializing_runs : [];
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };
  // SAFE endpoint rendering: scheme + host + path ONLY — userinfo, query and fragment are stripped
  // (never render a credential-bearing URL part; the registry itself must never hold secrets).
  const safeEndpoint = (ep) => {
    if (!ep) return "";
    try { const u = new URL(ep); return `${u.protocol}//${u.host}${u.pathname}`; } catch { return String(ep).split(/[?#@]/)[0]; }
  };

  // Sync-counter cluster semantics over REAL plane truth: the estate's source→set executions are
  // ODK materializing runs — in-flight (not yet executed/failed) · executed · failed.
  const cInflight = runs.filter((r) => !["executed", "failed"].includes(r.status)).length;
  const cDone = runs.filter((r) => r.status === "executed").length;
  const cFailed = runs.filter((r) => r.status === "failed").length;

  const recent = [...list].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))).slice(0, 12);
  const gapDash = (why) => `<span class="src-dash" title="${esc(why)}">—</span>`;
  const rowsHtml = recent.length ? recent.map((s) => `<div class="src-row${dataSourceSel && s.source_id === dataSourceSel ? " src-sel" : ""}"${dataSourceSel && s.source_id === dataSourceSel ? ' aria-current="true"' : ""} title="A DECLARED source — a registry record, not a connection; extraction requires a future authority crossing (the daemon's own boundary)">
      <span class="src-cell name">
        <span class="src-rowico" aria-hidden="true"></span>
        <span class="src-rowdata">
          <span class="src-rowname">${esc(s.name || s.source_id)}${s.ingestion && s.ingestion.wired === false ? `<span class="src-wired" title="${esc((s.ingestion || {}).note || "declaration only")}">not wired</span>` : ""}</span>
          <span class="src-rowpath">${esc(s.source_ref || s.source_id)} · ${esc(s.kind || "?")} · ${esc(s.credential_posture || "no posture")} · ${esc((s.lifecycle || {}).status || "declared")} · created ${fdate(s.created_at)}${s.endpoint ? ` · ${esc(safeEndpoint(s.endpoint))}` : ""} · ${mapsOf(s.source_id).length ? `<a href="/__ioi/data/sources?dataSource=${encodeURIComponent(s.source_id)}">${mapsOf(s.source_id).length} semantic mapping${mapsOf(s.source_id).length === 1 ? "" : "s"} →</a>` : `<span class="src-dash" title="No connector mapping declares this source — nothing is invented">no semantic mapping declared</span>`}</span>
        </span>
      </span>
      <span class="src-cell">${gapDash("No principal is recorded on the data-source registry (named gap)")}</span>
      <span class="src-cell">${gapDash("No edit principal is recorded on the data-source registry (named gap)")}</span>
      <span class="src-cell">${gapDash("View tracking is not recorded on the data-source registry (named gap)")}</span>
    </div>`).join("") : `<div class="src-empty">No data sources declared yet — this table renders the real DataSource registry and never fabricates rows. Sources are declared against the daemon registry (see the <a href="/__ioi/pipeline">Data ladder</a>).</div>`;

  // Declared-catalog census (below the fold): kinds + credential postures + the wired:false boundary.
  const byKind = {}; const byPosture = {};
  let wiredFalse = 0;
  for (const s of list) {
    byKind[s.kind || "?"] = (byKind[s.kind || "?"] || 0) + 1;
    byPosture[s.credential_posture || "none"] = (byPosture[s.credential_posture || "none"] || 0) + 1;
    if (s.ingestion && s.ingestion.wired === false) wiredFalse++;
  }
  const ingestionNote = (list[0] && list[0].ingestion && list[0].ingestion.note) || "declaration only — extraction requires a future authority crossing (named gap)";
  const chips = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).map(([k, n]) => `<span class="src-chip">${esc(k)} <b>${n}</b></span>`).join("");

  // #64: the selected source's semantic panel — its real mappings with owner links (Manager
  // typed resource · object-type definition · ontology · Pipeline mapping node). Fail-closed on
  // an unknown id; "no semantic mapping declared" is stated, never invented.
  const selSrc = dataSourceSel ? list.find((s) => s.source_id === dataSourceSel) || null : null;
  const selPanel = !dataSourceSel ? "" : `<section class="src-truth" id="source-selected">${selSrc ? (() => {
    const sm = mapsOf(selSrc.source_id);
    const smRows = sm.map((mm) => {
      const ontId = String(mm.ontology_ref || "").replace("ontology://", "");
      return `<li class="src-mapline"><b>${esc(mm.name || mm.id)}</b> <code>${esc(mm.ref || mm.id)}</code> — <a href="${managerResourceLink(ontId, "connector-mapping", mm.id)}">Manager resource</a> · <a href="${managerLink({ ontology: ontId, section: "object-types", definitionKind: "object-type", definitionId: mm.object_type_id })}">object type ${esc(mm.object_type_id || "")}</a> · <a href="${managerLink({ ontology: ontId })}">ontology</a> · <a href="${pipelineNodeLink(ontId, "mapping")}">Pipeline</a></li>`;
    }).join("");
    return `<h2 class="src-trutht">Selected source — ${esc(selSrc.name || selSrc.source_id)} <span class="src-truthsub">${esc(selSrc.source_ref || "")} · ${esc(selSrc.kind || "")} · ${esc(selSrc.credential_posture || "")}</span></h2>
    ${sm.length ? `<ul class="src-maplist">${smRows}</ul>` : `<p class="src-gapnote">No semantic mapping declared for this source — nothing is invented. Declare one through the <a href="/__ioi/pipeline">ODK ladder</a>.</p>`}`;
  })() : `<p class="src-gapnote">No declared source matches <code>${esc(dataSourceSel)}</code> — nothing selected (fail-closed).</p>`}</section>`;

  const truth = `${selPanel}<section class="src-truth" id="sources-catalog">
    <h2 class="src-trutht">Declared source catalog <span class="src-count">${list.length}</span> <span class="src-truthsub">the real DataSource registry — newest 12 shown above; every record is daemon truth, nothing invented</span></h2>
    <p class="src-boundary"><b>The authority boundary:</b> ${wiredFalse} of ${list.length} source${list.length === 1 ? "" : "s"} carry <code>ingestion.wired:false</code> — the daemon's own note, verbatim: <i>“${esc(ingestionNote)}”</i>. This surface is a DECLARED catalog: no extraction, no connection test, no live connector read, no materialization happens here — the governed path runs through the <a href="/__ioi/pipeline">ODK ladder</a> (mapping → policy gate → projection → lease → sealed session → materialized set).</p>
    <div class="src-truthcols">
      <div class="src-truthcol"><h3>By kind</h3><div class="src-chips">${chips(byKind)}</div></div>
      <div class="src-truthcol"><h3>By credential posture</h3><div class="src-chips">${chips(byPosture)}</div><p class="src-gapnote">Credential postures are declared postures — credential VALUES never appear on this surface, in the registry records, or in receipts.</p></div>
      <div class="src-truthcol"><h3>Sync activity (real)</h3><p class="src-gapnote">The header counters are the estate's REAL source→set executions (ODK materializing runs): ${cInflight} in-flight · ${cDone} executed · ${cFailed} failed. Endpoints render scheme+host+path only (userinfo/query/fragment stripped).</p></div>
    </div>
    <p class="src-foot">Unsupported reference lanes — New source here, live-connection setup, static upload, data synthesis, the store menu, Syncs/Agents/Listeners/External-stacks tabs, marketplace example installs — are <b>named gaps disabled in place</b>, never hidden (the set-up cards and example cards are the reference's own onboarding chrome, embedded verbatim, not extraction affordances). Owner family: <a href="/__ioi/pipeline">Data ladder (Pipeline Builder)</a> · <a href="/__ioi/odk">ODK builder</a> — sources are declared there; this catalog renders them. Reference: the origin-aligned <a href="http://localhost:9225/workspace/data-ingestion-app/" rel="noopener">Data Connection capture</a> — the <a href="/__apps/sources">/__apps/sources proxy lane ↗</a> is documented insufficient (renders no data; #44 sweep evidence).</p>
  </section>`;

  const globalRail = ioiGlobalRailHtml({ label: "Data Connection", href: "/__ioi/data/sources", iconUri: SRC_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="src-header">
    <span class="src-hchip" aria-hidden="true"></span>
    <h1 class="src-htitle">Data Connection</h1>
    <span class="src-hdiv" aria-hidden="true"></span>
    <nav class="src-tabs">
      <a class="src-tab" href="/__ioi/data/sources" aria-current="page">Sources</a>
      <span class="src-tab gap" aria-disabled="true" title="Sync scheduling is not a bound lane — the estate's real source→set executions are ODK materializing runs (named gap)">Syncs</span>
      <span class="src-tab gap" aria-disabled="true" title="Connection agents are a reference-only lane (named gap)">Agents</span>
      <span class="src-tab gap" aria-disabled="true" title="Listeners are a reference-only lane (named gap)">Listeners</span>
      <span class="src-tab gap" aria-disabled="true" title="External stacks are a reference-only lane (named gap)">External stacks</span>
    </nav>
    <div class="src-hright">
      <span class="src-hbtn store gap" aria-disabled="true" title="Recent installations — marketplace install lanes are not bound to this surface (named gap)"><span class="src-storeico" aria-hidden="true"></span>${bpIcon("caret-down")}</span>
      <span class="src-hbtn success gap" aria-disabled="true" title="Source declaration from this surface is a reference-only lane — sources are declared against the daemon registry via the ODK ladder (named gap)">${bpIcon("plus")}<span>New source</span></span>
      <span class="src-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)">${bpIcon("help")}<span>Help</span></span>
      <span class="src-counters gap" aria-disabled="true" title="REAL sync activity — the estate's ODK materializing runs: in-flight · executed · failed (live daemon truth, not the capture's zeros)">
        <span class="src-ctag">${bpIcon("refresh", 14)}<span>${cInflight}</span></span>
        <span class="src-ctag">${bpIcon("tick", 14)}<span>${cDone}</span></span>
        <span class="src-ctag">${bpIcon("cross", 14)}<span>${cFailed}</span></span>
      </span>
    </div>
  </header>`;

  const hero = `<section class="src-hero">
    <img class="src-heroimg" src="${SRC_HERO_URI}" alt="" aria-hidden="true">
    <div class="src-heroct">
      <h3 class="src-h1">Data Connection</h3>
      <p class="src-desc">Synchronize and manage data flows between Foundry and external systems.</p>
    </div>
  </section>`;

  const setup = `<div class="src-setupcard">
    <h4 class="src-setuph">Set up new connections</h4>
    <img class="src-setupstrip" src="${SRC_SETUP_STRIP_URI}" width="962" height="222" alt="Reference set-up option cards (verbatim capture chrome — vendor onboarding, not an extraction affordance)">
    <span class="src-opt c1 gap" aria-disabled="true" title="Live-connection setup is not a bound lane — sources are DECLARED records; extraction requires a future authority crossing (named gap)"></span>
    <span class="src-opt c2 gap" aria-disabled="true" title="Static upload is a reference-only lane (named gap)"></span>
    <span class="src-opt c3 gap" aria-disabled="true" title="Data synthesis is a reference-only lane (named gap)"></span>
  </div>`;

  const viewRow = `<div class="src-viewrow">
    <span class="src-viewlbl">View</span>
    <span class="src-pill on">Recents</span>
    <span class="src-pill gap" aria-disabled="true" title="Favorites are not recorded on the data-source registry (named gap)">Favorites</span>
    <a class="src-viewall" href="#sources-catalog" title="The full declared-catalog census below"><span>View all</span>${bpIcon("arrow-right")}</a>
  </div>`;

  const table = `<div class="src-table">
    <div class="src-thead"><span class="src-th name">Files</span><span class="src-th">Creator</span><span class="src-th">Last edited by</span><span class="src-th">Last viewed</span></div>
    <div class="src-rows">${rowsHtml}</div>
  </div>`;

  const examples = `<div class="src-examples">
    <h5 class="src-exh">Explore reference examples</h5>
    <div class="src-exsub">New to Data Connection? Learn what to do with Data Connection using an example data source.</div>
    <div class="src-exstripwrap">
      <img class="src-exstrip" src="${MCH_EXAMPLES_STRIP_URI}" width="562" height="272" alt="Reference marketplace example cards (verbatim capture chrome)">
      <span class="src-excard c1 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
      <span class="src-excard c2 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
    </div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .src-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .src-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .src-header{flex:0 0 48px;height:48px;display:flex;align-items:center;background:#fff;border-bottom:1px solid #d3d8de;z-index:6}
    .src-hchip{width:48px;height:48px;flex:0 0 48px;background:rgba(255,178,102,.1) url('${SRC_APP_TILE_URI}') center/24px no-repeat}
    .src-htitle{font-size:16px;line-height:20.6px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .src-hdiv{width:1px;height:20px;background:#d3d8de;margin:0 16px}
    .src-tabs{display:flex;align-self:stretch;gap:20px}
    .src-tab{display:inline-flex;align-items:center;font-size:16px;line-height:48px;color:#1c2127;cursor:default}
    a.src-tab{cursor:pointer;color:#1c2127}
    .src-hright{margin-left:auto;display:flex;align-items:flex-start;gap:8px;padding-right:8px}
    .src-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:8.5px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;cursor:default}
    .src-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .src-hbtn.success svg{color:#fff}
    .src-hbtn.outlined{border:1px solid rgba(95,107,124,.25);padding:0 8px;color:#1c2127}
    .src-hbtn.outlined svg{color:#5f6b7c}
    .src-hbtn.store{gap:4px;padding:0 7px;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .src-storeico{width:16px;height:16px;flex:0 0 16px;background:url('${MCH_STORE_ICON_URI}') center/16px no-repeat}
    .src-counters{display:inline-flex;align-items:center;gap:3px;height:30px;margin-top:8.5px;padding:0 10px;opacity:1;cursor:default}
    .src-ctag{display:inline-flex;align-items:center;gap:2px;height:20px;padding:2px 6px;border-radius:2px;background:rgba(143,153,168,.15);color:#5f6b7c;font-size:12px;line-height:16px}
    .src-ctag svg{color:#5f6b7c}
    .src-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .src-content{max-width:1090px;margin:0 auto;padding:0 45px}
    .src-hero{position:relative;background:#fff;height:143px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .src-heroct{position:relative;max-width:1040px;height:100%;margin:0 auto;padding:0 20px;background:linear-gradient(90deg,#fff 575px,rgba(255,255,255,0) 100%)}
    .src-heroimg{position:absolute;right:0;top:0;width:519.4px;height:143px}
    .src-h1{position:relative;font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;padding-top:20px}
    .src-desc{position:relative;width:625px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:6px 0 0}
    .src-setupcard{position:relative;z-index:2;margin-top:-55px;height:288.4px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15),0 0 5px rgba(0,0,0,.02)}
    .src-setuph{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0;padding:20px 20px 0}
    .src-setupstrip{position:absolute;left:19px;top:53px}
    .src-opt{position:absolute;top:54px;width:310px;height:215px;cursor:default}
    .src-opt.c1{left:20px}.src-opt.c2{left:345.3px}.src-opt.c3{left:670.7px}
    .src-viewrow{display:flex;align-items:center;margin-top:40px;height:30px}
    .src-viewlbl{font-size:14px;line-height:18px;color:#1c2127}
    .src-pill{display:inline-flex;align-items:center;height:30px;margin-left:10px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;cursor:default}
    .src-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .src-pill.gap{background:rgba(143,153,168,.15);color:#1c2127}
    .src-viewall{margin-left:auto;display:inline-flex;align-items:center;gap:9px;font-size:14px;line-height:18px;color:#215db0}
    .src-viewall svg{color:#215db0}
    .src-table{margin-top:10px;height:max(360px,calc(100vh - 648px));overflow-y:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .src-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .src-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .src-th.name{width:50%;padding-left:20px}
    .src-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .src-row.src-sel{outline:2px solid rgba(45,114,210,.45);outline-offset:-2px;border-radius:4px}
    .src-maplist{margin:6px 0;padding-left:18px}.src-mapline{margin:0 0 6px;font-size:12.5px}
    .src-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .src-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .src-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .src-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .src-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .src-wired{display:inline-block;margin-left:8px;padding:0 6px;border-radius:9px;background:rgba(200,118,25,.15);color:#935610;font-size:11px;line-height:16px;vertical-align:1px}
    .src-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .src-dash{color:#5f6b7c}
    .src-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .src-examples{margin-top:28px}
    .src-exh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .src-exsub{font-size:14px;line-height:18px;color:#1c2127;margin-top:12px}
    .src-exstripwrap{position:relative;margin-top:7px;width:562px;margin-left:-1px}
    .src-exstrip{display:block}
    .src-excard{position:absolute;top:1px;width:270px;height:270px;cursor:default}
    .src-excard.c1{left:1px}.src-excard.c2{left:291px}
    .src-truth{margin-top:30px;padding-bottom:40px}
    .src-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 8px}
    .src-count{margin-left:8px;font-size:14px;font-weight:400;color:#5f6b7c;background:rgba(143,153,168,.15);border-radius:9px;padding:1px 8px}
    .src-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .src-boundary{font-size:13px;line-height:1.55;color:#1c2127;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(200,118,25,.4);padding:12px 14px;margin:0 0 14px}
    .src-truthcols{display:flex;gap:16px;align-items:flex-start}
    .src-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .src-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .src-chips{display:flex;gap:6px;flex-wrap:wrap}
    .src-chip{display:inline-flex;gap:5px;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .src-gapnote{font-size:12px;color:#5f6b7c;margin:8px 0 0;line-height:1.5}
    .src-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Data Connection</title><style>${css}</style></head>
    <body><div class="src-shell">${globalRail}<div class="src-main">${header}<div class="src-body">${hero}<main class="src-content">${setup}${viewRow}${table}${examples}${truth}</main></div></div></div></body></html>`;
}

// ============================ AUTOMATIONS · MONITORS (Automate overview — landing port, #51)
// The Reference UX Port program — the THIRD origin-alignment-queue port (after #49/#50). The
// reference is the origin-aligned Automate overview capture
// (http://localhost:9225/workspace/object-monitoring/ — the /__apps/monitors proxy lane fails with
// a favorites-load error + CORS-blocked session lanes, documented by the #44 sweep). This IOI-owned
// surface reproduces the visible overview shell PIXEL-FAITHFULLY — dark global rail, tabbed app
// header (Automate · Overview active · Automations → the real owner substrate · store dropdown /
// New automation / Help as named gaps), hero band under the reference's own 940px white-gradient
// content overlay, the Getting-started band (View-all → the real substrate) with the wizard card
// (VERBATIM 3-step illustration strip), the template-card gallery and marketplace-examples band
// (VERBATIM capture strips — vendor chrome, never estate data) — while the DATA regions (below the
// fold) render REAL Automations-plane truth: the Active-automations stat band (live counts:
// user-executed · notification lane = honest named gap · paused via enabled=false), the
// Recently-viewed table (one row per real automation: name · id · project · trigger · steps census
// · created date; CREATOR = the real executor_identity.ref; em-dashes where the plane records no
// edit principal/view tracking), and the Recently-triggered feed (real executions: status ·
// started_at · execution/environment refs as proof). NO new scheduler/execution semantics — this
// is a PROJECTION over the existing automation plane; authoring stays on /__ioi/automations.
// Owner: Automations (/__ioi/automations, linked first-class both ways).
function renderMonitorsPort(automations, runsById) {
  const esc = CX_ESC;
  const list = Array.isArray(automations) ? automations : [];
  const fdate = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); };
  const ftime = (iso) => { const d = new Date(iso || 0); return isNaN(d) ? "—" : d.toLocaleString("en-US", { weekday: "short", month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit" }); };

  // Live stat semantics over the REAL plane: paused = enabled === false (the PATCH pause lane's own
  // field); user-executed = executor_identity.kind === "user"; the notification lane has no
  // substrate concept — an HONEST 0 with the gap named in place.
  const paused = list.filter((a) => a.enabled === false);
  const active = list.filter((a) => a.enabled !== false);
  const userExec = list.filter((a) => (a.executor_identity || {}).kind === "user");

  const recent = [...list].sort((a, b) => String(b.created_at || "").localeCompare(String(a.created_at || ""))).slice(0, 12);
  const gapDash = (why) => `<span class="mon-dash" title="${esc(why)}">—</span>`;
  const rowsHtml = recent.length ? recent.map((a) => {
    const steps = Array.isArray(a.steps) ? a.steps.length : 0;
    const trig = (a.trigger || {}).kind || "manual";
    return `<a class="mon-row" href="/__ioi/automations?project=${encodeURIComponent(a.project_id || "")}" title="Open this automation's project lane on the Automations substrate (the real owner surface)">
      <span class="mon-cell name">
        <span class="mon-rowico" aria-hidden="true"></span>
        <span class="mon-rowdata">
          <span class="mon-rowname">${esc(a.name || a.automation_id)}</span>
          <span class="mon-rowpath">${esc(a.automation_id)} · project ${esc(a.project_id || "—")} · trigger ${esc(trig)} · ${steps} step${steps === 1 ? "" : "s"} · created ${fdate(a.created_at)}${a.enabled === false ? " · paused" : ""}</span>
        </span>
      </span>
      <span class="mon-cell">${(a.executor_identity || {}).ref ? `<span title="the automation's declared executor_identity (real daemon truth)">${esc(a.executor_identity.ref)}</span>` : gapDash("No executor identity is recorded on this automation (named gap)")}</span>
      <span class="mon-cell">${gapDash("No edit principal is recorded on the automation plane (named gap)")}</span>
      <span class="mon-cell">${gapDash("View tracking is not recorded on the automation plane (named gap)")}</span>
    </a>`;
  }).join("") : `<div class="mon-empty">No automations yet — this table renders the real automation plane and never fabricates rows. Create one on the <a href="/__ioi/automations">Automations substrate</a>.</div>`;

  // Recently triggered — REAL executions (newest first), status verbatim, execution/environment
  // refs as the proof trail. Honest empty when nothing has run.
  const events = [];
  for (const a of list) {
    for (const r of (runsById[a.automation_id] || [])) {
      events.push({ name: a.name || a.automation_id, started: r.started_at, status: r.status || "unknown", exec: r.execution_id, env: r.environment_id });
    }
  }
  events.sort((x, y) => String(y.started || "").localeCompare(String(x.started || "")));
  const feed = events.slice(0, 10).map((e) => `<div class="mon-evt">
      <span class="mon-evtdot ${e.status === "done" ? "ok" : "warn"}" aria-hidden="true"></span>
      <span class="mon-evtmain"><b>${esc(e.name)}</b><span class="mon-evtwhen">${esc(ftime(e.started))}</span><span class="mon-evtstat">${e.status === "done" ? "Execution completed" : `Execution status: ${esc(e.status)}`}</span></span>
      <code class="mon-evtref" title="execution + environment refs — the real proof trail">${esc(e.exec || "")}${e.env ? ` · ${esc(e.env)}` : ""}</code>
    </div>`).join("");

  const globalRail = ioiGlobalRailHtml({ label: "Automate", href: "/__ioi/automations/monitors", iconUri: MON_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="mon-header">
    <span class="mon-hchip" aria-hidden="true"></span>
    <h1 class="mon-htitle">Automate</h1>
    <nav class="mon-tabs">
      <span class="mon-tab on" aria-current="page">Overview</span>
      <a class="mon-tab" href="/__ioi/automations" title="The full automation plane — the real owner substrate (specs · runs · pause/resume · projects)">Automations</a>
    </nav>
    <div class="mon-hright">
      <span class="mon-hbtn outlined store gap" aria-disabled="true" title="Recent installations — marketplace install lanes are not bound to this surface (named gap)"><span class="mon-storeico" aria-hidden="true"></span>${bpIcon("caret-down")}</span>
      <span class="mon-hbtn success gap" aria-disabled="true" title="Automation authoring from this surface is a reference-only lane — automations are created on the Automations substrate (named gap)">${bpIcon("add")}<span>New automation</span></span>
      <span class="mon-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)">${bpIcon("help")}<span>Help</span></span>
    </div>
  </header>`;

  const hero = `<section class="mon-hero">
    <div class="mon-heroct">
      <h3 class="mon-h1">Create and manage automations</h3>
      <p class="mon-desc">Build business automation by defining conditions that trigger automatic effects.</p>
    </div>
  </section>`;

  // The wizard's 3-step illustration strip + the template-card gallery + the marketplace example
  // cards are the reference's own static content — embedded VERBATIM from the capture (the
  // #48/#49/#50 doctrine). Their interactive faces get transparent DISABLED controls.
  const gettingStarted = `<div class="mon-gsband"><h2 class="mon-gsh">Getting started</h2><a class="mon-viewall" href="/__ioi/automations" title="The full automation plane — the real owner substrate"><span>View all automations</span>${bpIcon("arrow-right")}</a></div>
  <div class="mon-wizcard">
    <div class="mon-wizcopy">
      <h4 class="mon-wizt">Create your first automation</h4>
      <p class="mon-wizsub">Get started by creating a new automation or adding yourself to existing automations.</p>
      <span class="mon-wizbtn gap" aria-disabled="true" title="Automation authoring from this surface is a reference-only lane — automations are created on the Automations substrate (named gap)">${bpIcon("plus")}<span>New automation</span></span>
    </div>
    <img class="mon-wizstrip" src="${MON_WIZ_STRIP_URI}" width="584" height="222" alt="Reference 3-step wizard illustrations (verbatim capture chrome)">
  </div>
  <div class="mon-cardswrap">
    <img class="mon-cardsstrip" src="${MON_CARDS_STRIP_URI}" width="902" height="319" alt="Reference automation template cards (verbatim capture chrome — vendor templates, not estate data)">
    <span class="mon-tplcard c1 gap" aria-disabled="true" title="Template docs are a reference-only lane (named gap)"></span>
    <span class="mon-tplcard c2 gap" aria-disabled="true" title="Template docs are a reference-only lane (named gap)"></span>
    <span class="mon-tplcard c3 gap" aria-disabled="true" title="Template docs are a reference-only lane (named gap)"></span>
  </div>
  <div class="mon-examples">
    <h5 class="mon-exh">Explore reference examples</h5>
    <div class="mon-exsub">Learn how to build automated use cases using example Automations from Marketplace</div>
    <div class="mon-exstripwrap">
      <img class="mon-exstrip" src="${MCH_EXAMPLES_STRIP_URI}" width="562" height="272" alt="Reference marketplace example cards (verbatim capture chrome)">
      <span class="mon-excard c1 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
      <span class="mon-excard c2 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
    </div>
  </div>`;

  const stats = `<div class="mon-statsband"><h2 class="mon-gsh">Active automations<span class="mon-statcount">${active.length}</span></h2><a class="mon-viewallbtn" href="/__ioi/automations">View all</a></div>
  <div class="mon-tiles">
    <div class="mon-tile"><span class="mon-tileico" aria-hidden="true">${bpIcon("people")}</span><span class="mon-tiletxt"><span class="mon-tilet">Owned by you</span><span class="mon-tilesub">Executed on your behalf</span></span><span class="mon-tilen" title="automations whose declared executor_identity.kind is 'user' (real daemon truth)">${userExec.length}</span></div>
    <div class="mon-tile"><span class="mon-tileico" aria-hidden="true">${bpIcon("notifications")}</span><span class="mon-tiletxt"><span class="mon-tilet">For you</span><span class="mon-tilesub">You receive notifications</span></span><span class="mon-tilen" title="No notification-subscription lane exists on the automation plane — an honest 0, not a hidden count (named gap)">0</span></div>
    <div class="mon-tile"><span class="mon-tileico" aria-hidden="true">${bpIcon("time")}</span><span class="mon-tiletxt"><span class="mon-tilet">Paused</span><span class="mon-tilesub">Automation is not evaluated</span></span><span class="mon-tilen" title="automations with enabled=false (the plane's own pause lane)">${paused.length}</span></div>
  </div>`;

  const recents = `<h2 class="mon-gsh mon-rvh" title="Ordered by creation recency — the plane records no view tracking (named gap)">Recently viewed</h2>
  <div class="mon-table">
    <div class="mon-thead"><span class="mon-th name">Files</span><span class="mon-th">Creator</span><span class="mon-th">Last edited by</span><span class="mon-th">Last viewed</span></div>
    <div class="mon-rows">${rowsHtml}</div>
  </div>`;

  const triggered = `<h2 class="mon-gsh mon-rth">Recently triggered</h2>
  <div class="mon-feed">${feed || `<div class="mon-empty">No executions recorded yet — this feed renders real automation executions (status · time · execution/environment refs) and never fabricates events.</div>`}</div>
  <p class="mon-foot">This overview is a <b>read-only projection over the real automation plane</b> — ${list.length} automation${list.length === 1 ? "" : "s"} (${active.length} active · ${paused.length} paused) and their real executions; no scheduler or execution semantics were added by this surface. Authoring, pause/resume, and run history live on the <a href="/__ioi/automations">Automations substrate</a> (the owner surface, linked first-class). Unsupported reference lanes — New automation here, the Recent-installations store menu, template docs, marketplace example installs — are disabled in place, never hidden. The wizard illustrations, template cards, and example cards are the reference's own static content (verbatim capture chrome, never estate data). Reference: the origin-aligned <a href="http://localhost:9225/workspace/object-monitoring/" rel="noopener">Automate capture</a> — the <a href="/__apps/monitors">/__apps/monitors proxy lane ↗</a> is documented insufficient (a favorites-load failure + CORS-blocked session lanes; #44 sweep evidence).</p>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .mon-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .mon-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .mon-header{flex:0 0 50px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 #d1d1d1,0 3px 4px rgba(0,0,0,.04);z-index:6}
    .mon-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(209,152,11,.1) url('${MON_APP_TILE_URI}') center/24px no-repeat;box-shadow:inset -1px 0 0 0 rgba(209,152,11,.25)}
    .mon-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .mon-tabs{display:flex;align-self:stretch;margin-left:22px}
    .mon-tab{display:inline-flex;align-items:center;padding:0;margin-right:20px;font-size:16px;line-height:50px;color:#1c2127;position:relative;cursor:default}
    .mon-tab.on{color:#215db0}
    .mon-tab.on::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:#215db0}
    a.mon-tab{cursor:pointer}
    .mon-hright{margin-left:auto;display:flex;align-items:flex-start;gap:10px;padding-right:16px}
    .mon-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;cursor:default}
    .mon-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .mon-hbtn.success svg{color:#fff}
    .mon-hbtn.outlined{border:1px solid rgba(95,107,124,.25);padding:0 8px;color:#1c2127}
    .mon-hbtn.outlined svg{color:#5f6b7c}
    .mon-hbtn.store{gap:4px;padding:0 7px}
    .mon-storeico{width:16px;height:16px;flex:0 0 16px;background:url('${MCH_STORE_ICON_URI}') center/16px no-repeat}
    .mon-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .mon-content{max-width:990px;margin:0 auto;padding:0 45px}
    .mon-hero{position:relative;background:#fff;height:88px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .mon-heroct{position:relative;max-width:940px;height:100%;margin:0 auto;padding:0 20px;background:linear-gradient(90deg,#fff 575px,rgba(255,255,255,0) 100%)}
    .mon-h1{position:relative;font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;padding-top:20px}
    .mon-desc{position:relative;width:625px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:0;padding-top:5px}
    .mon-gsband{display:flex;align-items:center;margin-top:32.5px}
    .mon-gsh{flex:0 0 auto;font-size:16px;line-height:25px;font-weight:600;color:#1c2127;margin:0}
    .mon-viewall{margin-left:auto;display:inline-flex;align-items:center;gap:9px;font-size:14px;line-height:18px;color:#215db0}
    .mon-viewall svg{color:#215db0}
    .mon-wizcard{position:relative;margin-top:12.5px;height:224px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15),0 0 5px rgba(0,0,0,.02);display:flex}
    .mon-wizcopy{flex:0 0 315px;padding:30px 0 0 30px}
    .mon-wizt{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .mon-wizsub{width:263.4px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:10px 0 0}
    .mon-wizbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:39px;padding:0 8px;border-radius:4px;border:1px solid rgba(28,110,66,.6);color:#1c6e42;font-size:14px;line-height:16.1px;cursor:default}
    .mon-wizbtn svg{color:#1c6e42}
    .mon-wizstrip{position:absolute;left:315px;top:1px}
    .mon-cardswrap{position:relative;margin-top:19px;width:902px;margin-left:-1px}
    .mon-cardsstrip{display:block}
    .mon-tplcard{position:absolute;top:1px;width:290px;height:316px;cursor:default}
    .mon-tplcard.c1{left:1px}.mon-tplcard.c2{left:306px}.mon-tplcard.c3{left:611px}
    .mon-examples{margin-top:29px}
    .mon-exh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .mon-exsub{font-size:14px;line-height:18px;color:#1c2127;margin-top:12px}
    .mon-exstripwrap{position:relative;margin-top:7px;width:562px;margin-left:-1px}
    .mon-exstrip{display:block}
    .mon-excard{position:absolute;top:1px;width:270px;height:270px;cursor:default}
    .mon-excard.c1{left:1px}.mon-excard.c2{left:291px}
    .mon-statsband{display:flex;align-items:center;margin-top:36px}
    .mon-statcount{margin-left:10px;font-size:14px;font-weight:400;color:#5f6b7c;background:rgba(143,153,168,.15);border-radius:9px;padding:1px 8px}
    .mon-viewallbtn{margin-left:auto;display:inline-flex;align-items:center;height:30px;padding:0 10px;border-radius:4px;border:1px solid rgba(95,107,124,.25);color:#1c2127;font-size:14px}
    .mon-tiles{display:flex;gap:20px;margin-top:14px}
    .mon-tile{flex:1;display:flex;align-items:center;height:72px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:0 20px}
    .mon-tileico{display:inline-flex;color:#5f6b7c;margin-right:14px}
    .mon-tiletxt{flex:1;min-width:0}
    .mon-tilet{display:block;font-size:14px;line-height:18px;color:#1c2127}
    .mon-tilesub{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c}
    .mon-tilen{font-size:18px;font-weight:600;color:#1c2127}
    .mon-rvh{margin-top:36px}
    .mon-table{margin-top:14px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .mon-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .mon-th{width:150px;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .mon-th.name{width:450px;padding-left:20px}
    .mon-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .mon-cell{width:150px;padding:19.5px 0 0 11px;font-size:14px;line-height:18px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mon-cell.name{width:450px;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .mon-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .mon-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .mon-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mon-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mon-dash{color:#5f6b7c}
    .mon-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .mon-rth{margin-top:36px}
    .mon-feed{margin-top:14px;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:6px 0}
    .mon-evt{display:flex;align-items:flex-start;padding:10px 20px;border-bottom:1px solid #eef0f2}
    .mon-evt:last-child{border-bottom:0}
    .mon-evtdot{width:10px;height:10px;border-radius:50%;margin:4px 12px 0 0;flex:0 0 10px}
    .mon-evtdot.ok{background:#238551}.mon-evtdot.warn{background:#c87619}
    .mon-evtmain{flex:1;min-width:0}
    .mon-evtmain b{display:block;font-size:14px;line-height:18px}
    .mon-evtwhen{display:block;font-size:12px;color:#5f6b7c}
    .mon-evtstat{display:block;font-size:12px;color:#1c2127;margin-top:1px}
    .mon-evtref{font-size:11px;color:#5f6b7c;margin-left:12px;max-width:340px;word-break:break-all}
    .mon-foot{font-size:12px;line-height:1.6;color:#7b8494;margin:24px 0 40px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Automate</title><style>${css}</style></head>
    <body><div class="mon-shell">${globalRail}<div class="mon-main">${header}<div class="mon-body">${hero}<main class="mon-content">${gettingStarted}${stats}${recents}${triggered}</main></div></div></div></body></html>`;
}

// ============================ STUDIO · MACHINERY (process/state-machine DEFINITIONS — landing port, #50)
// The Reference UX Port program — the SECOND origin-alignment-queue port (after #49 designer).
// The reference is the origin-aligned Machinery landing capture
// (http://localhost:9225/workspace/machinery-app/ — the /__apps/machinery proxy lane fails with
// "Failed to load Machinery Marketplace examples.", documented by the #44 sweep). This IOI-owned
// surface reproduces the visible landing shell PIXEL-FAITHFULLY — dark global rail, app header
// (machinery tile · Recent-installations store dropdown · New graph · Help as named gaps), hero
// band + verbatim illustration under the reference's own 1040px white-gradient content overlay,
// the View row, the viewport-height-ruled Recents table, and the "Explore reference examples"
// band (a VERBATIM capture strip: the reference's own marketplace example cards — vendor chrome,
// NOT estate data and NOT an execution claim) — while the DATA region (table rows) renders REAL
// daemon state-machine DEFINITIONS: one row per machine (name · ref · created/updated dates ·
// declared states/transitions/guards census · health/status), owner_refs rendered honestly when
// present and em-dashes where the plane records no principal/view tracking. Below the fold the
// full DEFINITION truth renders with real records (states initial/normal/final · transitions
// from→to/event/guard · guards · declared inputs/outputs · owners · history · health).
// THE SEMANTIC BOUNDARY IS HARD: definitions, NEVER execution — no run/step/execute, no
// current_state, no scheduling, no Automations/Missions/ODK binding; the daemon's own
// authority_note renders verbatim. Owner: Studio (/__ioi/agent-studio); no route rename.
function renderMachineryPort(machines, selectedId) {
  const esc = CX_ESC;
  const enc = (s) => encodeURIComponent(String(s || ""));
  const list = Array.isArray(machines) ? machines : [];
  const selected = list.find((m) => m.id === selectedId) || list[0] || null;

  const fdate = (iso) => {
    const d = new Date(iso || 0);
    return isNaN(d) ? "—" : d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  };
  const censusOf = (m) => ({
    states: Array.isArray(m.states) ? m.states.length : 0,
    transitions: Array.isArray(m.transitions) ? m.transitions.length : 0,
    guards: Array.isArray(m.guards) ? m.guards.length : 0,
  });

  // Recents = real state-machine DEFINITIONS, newest-updated first. CREATOR renders the declared
  // owner_refs[0] when the record carries one — otherwise an honest em-dash; LAST EDITED BY /
  // LAST VIEWED are em-dashes (the plane records no principal on history and no view tracking).
  const recent = [...list].sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")));
  const gapDash = (why) => `<span class="mch-dash" title="${esc(why)}">—</span>`;
  const rowsHtml = recent.length ? recent.map((m) => {
    const c = censusOf(m);
    const owner = (Array.isArray(m.owner_refs) && m.owner_refs[0]) || "";
    return `<a class="mch-row" href="/__ioi/studio/machinery?machine=${enc(m.id)}" title="Select this definition — its states/transitions/guards render below (definitions only, nothing executes)">
      <span class="mch-cell name">
        <span class="mch-rowico" aria-hidden="true"></span>
        <span class="mch-rowdata">
          <span class="mch-rowname">${esc(m.name || m.id)}${m.id === (selected && selected.id) ? `<span class="mch-selpill">selected</span>` : ""}</span>
          <span class="mch-rowpath">${esc(m.ref)} · created ${fdate(m.created_at)} · updated ${fdate(m.updated_at)} · ${c.states} state${c.states === 1 ? "" : "s"} · ${c.transitions} transition${c.transitions === 1 ? "" : "s"} · ${c.guards} guard${c.guards === 1 ? "" : "s"} · ${esc(m.health || "empty")} · ${esc(m.status || "draft")}</span>
        </span>
      </span>
      <span class="mch-cell">${owner ? `<span title="declared owner_refs[0] — a declaration on the definition, not an execution principal">${esc(owner)}</span>` : gapDash("No principal is recorded on the state-machine plane (named gap)")}</span>
      <span class="mch-cell">${gapDash("No edit principal is recorded on the definition history (named gap)")}</span>
      <span class="mch-cell">${gapDash("View tracking is not recorded on the state-machine plane (named gap)")}</span>
    </a>`;
  }).join("") : `<div class="mch-empty">No state machines defined yet — this plane holds inert process/state-machine <b>definitions</b> (states · transitions · guards · declared inputs/outputs · owners), never a running instance. Definitions are created against the daemon state-machine plane; nothing is fabricated here.</div>`;

  // ---- Below-the-fold: the full DEFINITION truth for the selected machine (real records only).
  const m = selected || {};
  const states = Array.isArray(m.states) ? m.states : [];
  const transitions = Array.isArray(m.transitions) ? m.transitions : [];
  const guards = Array.isArray(m.guards) ? m.guards : [];
  const inputs = Array.isArray(m.inputs) ? m.inputs : [];
  const outputs = Array.isArray(m.outputs) ? m.outputs : [];
  const owners = Array.isArray(m.owner_refs) ? m.owner_refs : [];
  const history = Array.isArray(m.history) ? m.history : [];
  const guardName = (id) => { const g = guards.find((x) => x.id === id); return g ? (g.name || g.id) : id; };
  const kindPill = (k) => `<span class="mch-kpill${k === "initial" ? " ini" : k === "final" ? " fin" : ""}">${esc(k || "normal")}</span>`;

  const switcher = list.length > 1 ? `<div class="mch-switch">${list.map((x) => `<a class="mch-schip${selected && x.id === selected.id ? " on" : ""}" href="/__ioi/studio/machinery?machine=${enc(x.id)}">${esc(x.name || x.id)} · ${esc(x.health || "empty")}</a>`).join("")}</div>` : "";

  const truth = selected ? `<section class="mch-truth" id="machinery-truth">
    <h2 class="mch-trutht">Definition truth — <b>${esc(m.name || m.id)}</b> <span class="mch-truthsub">${esc(m.status || "draft")} · health ${esc(m.health || "empty")} · <code class="mch-ref-inline">${esc(m.ref || "")}</code> · ${states.length} state${states.length === 1 ? "" : "s"} · ${transitions.length} transition${transitions.length === 1 ? "" : "s"} · ${guards.length} guard${guards.length === 1 ? "" : "s"} — real records from the daemon state-machine plane, nothing invented</span></h2>
    <p class="mch-authnote">${esc(m.authority_note || "inert definition — no run/step/execution, no scheduling, no automation binding")}</p>
    ${switcher}
    <div class="mch-truthcols">
      <div class="mch-truthcol" id="machinery-states"><h3>States <span class="mch-meta">(${states.length})</span></h3>
        ${states.length ? `<ul>${states.map((s) => `<li class="mch-truthitem"><b>${esc(s.name || s.id)}</b> ${kindPill(s.kind)}<code class="mch-refc">${esc(s.id)}</code></li>`).join("")}</ul>`
          : `<p class="mch-gapnote">This machine declares <b>no states</b> yet (health <code>empty</code>) — nothing is invented.</p>`}
      </div>
      <div class="mch-truthcol" id="machinery-transitions"><h3>Transitions <span class="mch-meta">(${transitions.length})</span></h3>
        ${transitions.length ? `<ul>${transitions.map((tr) => `<li class="mch-truthitem"><b>${esc(tr.from)} → ${esc(tr.to)}</b> <span class="mch-meta">${tr.event ? `event ${esc(tr.event)}` : "no event"}${tr.guard_ref ? ` · guard ${esc(guardName(tr.guard_ref))}` : ""}</span><code class="mch-refc">${esc(tr.id)}</code></li>`).join("")}</ul>`
          : `<p class="mch-gapnote">No transitions declared yet — an under-declared definition stays honestly incomplete.</p>`}
      </div>
      <div class="mch-truthcol" id="machinery-guards"><h3>Guards · I/O · Owners <span class="mch-meta">(${guards.length} guard · ${inputs.length} in · ${outputs.length} out · ${owners.length} owner)</span></h3>
        ${guards.length || inputs.length || outputs.length || owners.length
          ? `<ul>${guards.map((g) => `<li class="mch-truthitem"><b>${esc(g.name || g.id)}</b> <span class="mch-meta">guard${g.expression ? ` · ${esc(g.expression)}` : ""}</span><code class="mch-refc">${esc(g.id)}</code></li>`).join("")}${inputs.map((i) => `<li class="mch-truthitem"><b>${esc(i.name || i.id || String(i))}</b> <span class="mch-meta">declared input</span></li>`).join("")}${outputs.map((o) => `<li class="mch-truthitem"><b>${esc(o.name || o.id || String(o))}</b> <span class="mch-meta">declared output</span></li>`).join("")}${owners.map((o) => `<li class="mch-truthitem"><b>${esc(o)}</b> <span class="mch-meta">declared owner ref</span></li>`).join("")}</ul>`
          : `<p class="mch-gapnote">No guards, declared inputs/outputs, or owner refs on this definition — honest empty, nothing fabricated.</p>`}
        ${history.length ? `<p class="mch-histnote">History: ${history.length} edit record${history.length === 1 ? "" : "s"} on the definition${history[0] && (history[0].at || history[0].note) ? ` (latest: ${esc(history[0].note || history[0].at || "")})` : ""}.</p>` : ""}
      </div>
    </div>
    <p class="mch-foot">These are <b>definitions, not running processes</b> — nothing here executes, steps, schedules, or carries a current state; run/step/execute, scheduling, Automations/Missions/ODK binding, simulation, and versioning are <b>named gaps</b> (a later authority-crossing cut), and the marketplace example band above is the reference's own example content (verbatim capture chrome), not estate process truth. Unsupported reference lanes — graph authoring (New graph), the Recent-installations store menu, favorites, marketplace example installs — are disabled in place, never hidden. Owner: <a href="/__ioi/agent-studio">Agent Studio</a> · siblings: <a href="/__ioi/studio/designer">Solution Designer</a> · reference-only: <a href="/__apps/workshop">workshop</a> and <a href="/__apps/module">module</a> builders. Reference: the origin-aligned <a href="http://localhost:9225/workspace/machinery-app/" rel="noopener">Machinery capture</a> — the <a href="/__apps/machinery">/__apps/machinery proxy lane ↗</a> is documented insufficient (its Marketplace-examples fetch fails on the proxy origin; #44 sweep evidence).</p>
  </section>` : `<section class="mch-truth" id="machinery-truth"><p class="mch-gapnote">No state machines defined yet — the plane holds inert <b>definitions</b> only; nothing executes and nothing is fabricated. Owner: <a href="/__ioi/agent-studio">Agent Studio</a> · sibling: <a href="/__ioi/studio/designer">Solution Designer</a> · reference: <a href="/__apps/machinery">/__apps/machinery ↗</a>.</p></section>`;

  const globalRail = ioiGlobalRailHtml({ label: "Machinery", href: "/__ioi/studio/machinery", iconUri: MCH_APP_TILE_URI, railVariant: "rv-pipe rv-dsg", viewAll: true, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="mch-header">
    <span class="mch-hchip" aria-hidden="true"></span>
    <h1 class="mch-htitle">Machinery</h1>
    <div class="mch-hright">
      <span class="mch-hbtn store gap" aria-disabled="true" title="Recent installations — marketplace install lanes are not bound to this surface (named gap)"><span class="mch-storeico" aria-hidden="true"></span>${bpIcon("caret-down")}</span>
      <span class="mch-hbtn success gap" aria-disabled="true" title="Graph authoring is a reference-only lane — no process graph is authored, saved, or executed on this surface (named gap)">${bpIcon("plus")}<span>New graph</span></span>
      <span class="mch-hbtn outlined gap" aria-disabled="true" title="Reference help lane (named gap)"><span>Help</span>${bpIcon("help")}</span>
    </div>
  </header>`;

  const hero = `<section class="mch-hero">
    <img class="mch-heroimg" src="${MCH_HERO_URI}" alt="" aria-hidden="true">
    <div class="mch-heroct">
      <h3 class="mch-h1">Machinery</h3>
      <p class="mch-desc">Build, manage and monitor your business processes with precision. Streamline operations and drive efficiency through strategic automations.</p>
    </div>
  </section>`;

  const viewRow = `<div class="mch-viewrow">
    <span class="mch-viewlbl">View</span>
    <span class="mch-pill on">Recents</span>
    <span class="mch-pill gap" aria-disabled="true" title="Favorites are not recorded on the state-machine plane (named gap)">Favorites</span>
  </div>`;

  const table = `<div class="mch-table">
    <div class="mch-thead"><span class="mch-th name">Files</span><span class="mch-th">Creator</span><span class="mch-th">Last edited by</span><span class="mch-th">Last viewed</span></div>
    <div class="mch-rows">${rowsHtml}</div>
  </div>`;

  // The examples band is the reference's own marketplace example content — embedded VERBATIM from
  // the capture (like the #49 template gallery). The card faces get transparent DISABLED controls:
  // installing/opening marketplace examples is a named gap, and the cards are never estate data.
  const examples = `<div class="mch-examples">
    <h5 class="mch-exh">Explore reference examples</h5>
    <div class="mch-exsub">Learn how to build industrial solutions using example workflows with Marketplace.</div>
    <div class="mch-exstripwrap">
      <img class="mch-exstrip" src="${MCH_EXAMPLES_STRIP_URI}" width="562" height="272" alt="Reference marketplace example-resource cards (verbatim capture chrome — vendor examples, not estate process truth)">
      <span class="mch-excard c1 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
      <span class="mch-excard c2 gap" aria-disabled="true" title="Marketplace example installs are a reference-only lane (named gap)"></span>
    </div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .mch-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .rv-dsg .og-gappico{background-color:rgba(45,114,210,.1)}
    .rv-dsg .og-gsecrow{padding:30px 7px 5px 5px}
    .rv-dsg .og-gitem.on{margin-right:-11px}
    .mch-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .mch-header{flex:0 0 51px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 0 #d3d8de;z-index:6}
    .mch-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(20,126,179,.1) url('${MCH_APP_TILE_URI}') center/24px no-repeat;box-shadow:inset -1px 0 0 0 rgba(20,126,179,.25)}
    .mch-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .mch-hright{margin-left:auto;display:flex;align-items:flex-start;gap:10px;padding-right:20px}
    .mch-hbtn{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:10px;padding:0 8px;border-radius:4px;font-size:14px;line-height:18px;cursor:default}
    .mch-hbtn.store{gap:4px;padding:0 7px;background:#f7f8f8;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .mch-hbtn.store svg{color:#5f6b7c}
    .mch-storeico{width:16px;height:16px;flex:0 0 16px;background:url('${MCH_STORE_ICON_URI}') center/16px no-repeat}
    .mch-hbtn.success{background:#238551;color:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),0 1px 2px rgba(17,20,24,.1)}
    .mch-hbtn.success svg{color:#fff}
    .mch-hbtn.outlined{border:1px solid rgba(95,107,124,.25);padding:0 8px;color:#1c2127}
    .mch-hbtn.outlined span{line-height:16.1px}
    .mch-hbtn.outlined svg{color:#5f6b7c}
    .mch-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .mch-content{max-width:1090px;margin:0 auto;padding:0 45px}
    .mch-hero{position:relative;background:#fff;height:106px;box-shadow:0 1px 0 0 rgba(17,20,24,.15)}
    .mch-heroct{position:relative;max-width:1040px;height:100%;margin:0 auto;padding:0 20px;background:linear-gradient(90deg,#fff 575px,rgba(255,255,255,0) 100%)}
    .mch-heroimg{position:absolute;right:0;top:0;width:387.5px;height:106px}
    .mch-h1{position:relative;font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;padding-top:20px}
    .mch-desc{position:relative;width:625px;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:6px 0 0}
    .mch-viewrow{display:flex;align-items:center;margin-top:40px;height:30px}
    .mch-viewlbl{font-size:14px;line-height:18px;color:#1c2127}
    .mch-pill{display:inline-flex;align-items:center;height:30px;margin-left:10px;padding:6px 10px;border-radius:30px;font-size:14px;line-height:18px;cursor:default}
    .mch-pill.on{background:rgba(45,114,210,.3);color:#184a90;font-weight:600}
    .mch-pill.gap{background:rgba(143,153,168,.15);color:#1c2127}
    .mch-table{margin-top:10px;height:max(360px,calc(100vh - 624px));overflow-y:auto;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .mch-thead{display:flex;height:30px;box-shadow:inset 0 -1px 0 #dcdcdd}
    .mch-th{width:16.667%;padding:8px 0 0 11px;font-size:12px;line-height:15.43px;color:#5f6b7c;text-transform:uppercase}
    .mch-th.name{width:50%;padding-left:20px}
    .mch-row{display:flex;height:57px;box-shadow:inset 0 -1px 0 #dcdcdd;color:#1c2127}
    .mch-cell{width:16.667%;padding:19.5px 0 0 11px;font-size:14px;line-height:18px}
    .mch-cell.name{width:50%;padding:11px 0 0 20px;display:flex;align-items:flex-start}
    .mch-rowico{width:16px;height:16px;flex:0 0 16px;margin-top:2px;background:url('${DSG_ROW_DOC_URI}') center/16px no-repeat}
    .mch-rowdata{margin-left:7px;min-width:0;flex:1;padding-right:16px}
    .mch-rowname{display:block;font-size:14px;line-height:18px;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mch-selpill{display:inline-block;margin-left:8px;padding:0 6px;border-radius:9px;background:rgba(45,114,210,.15);color:#215db0;font-size:11px;line-height:16px;vertical-align:1px}
    .mch-rowpath{display:block;font-size:12px;line-height:15.43px;color:#5f6b7c;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mch-dash{color:#5f6b7c}
    .mch-empty{padding:24px 20px;font-size:14px;color:#5f6b7c}
    .mch-examples{margin-top:30px}
    .mch-exh{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .mch-exsub{font-size:14px;line-height:18px;color:#1c2127;margin-top:12px}
    .mch-exstripwrap{position:relative;margin-top:7px;width:562px}
    .mch-exstrip{display:block;margin-left:-1px}
    .mch-excard{position:absolute;top:1px;width:270px;height:270px;cursor:default}
    .mch-excard.c1{left:0}.mch-excard.c2{left:290px}
    .mch-truth{margin-top:26px;padding-bottom:40px}
    .mch-trutht{font-size:18px;font-weight:600;color:#1c2127;margin:0 0 6px}
    .mch-truthsub{font-size:13px;font-weight:400;color:#5f6b7c;margin-left:8px}
    .mch-ref-inline{font-size:11px;color:#5f6b7c}
    .mch-authnote{font-size:12px;color:#7b8494;margin:0 0 10px;font-style:italic}
    .mch-switch{margin:0 0 12px;display:flex;gap:8px;flex-wrap:wrap}
    .mch-schip{display:inline-flex;padding:3px 10px;border-radius:12px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px}
    .mch-schip.on{background:rgba(45,114,210,.2);color:#184a90;font-weight:600}
    .mch-truthcols{display:flex;gap:16px;align-items:flex-start}
    .mch-truthcol{flex:1;min-width:0;background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15);padding:14px 16px}
    .mch-truthcol h3{font-size:14px;font-weight:600;margin:0 0 8px;color:#1c2127}
    .mch-truthcol ul{list-style:none;margin:0;padding:0}
    .mch-truthitem{padding:5px 0;border-bottom:1px solid #eef0f2;font-size:13px}
    .mch-truthitem:last-child{border-bottom:0}
    .mch-kpill{display:inline-block;margin-left:6px;padding:0 6px;border-radius:9px;background:rgba(143,153,168,.15);color:#1c2127;font-size:11px;line-height:16px}
    .mch-kpill.ini{background:rgba(35,133,81,.15);color:#1c6e42}
    .mch-kpill.fin{background:rgba(45,114,210,.15);color:#215db0}
    .mch-meta{color:#5f6b7c;font-weight:400;font-size:12px}
    .mch-refc{display:block;font-size:11px;color:#5f6b7c;margin-top:1px;word-break:break-all}
    .mch-gapnote{font-size:13px;color:#5f6b7c;margin:4px 0}
    .mch-histnote{font-size:12px;color:#7b8494;margin:8px 0 0}
    .mch-foot{font-size:12px;line-height:1.6;color:#7b8494;margin-top:18px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Machinery</title><style>${css}</style></head>
    <body><div class="mch-shell">${globalRail}<div class="mch-main">${header}<div class="mch-body">${hero}<main class="mch-content">${viewRow}${table}${examples}${truth}</main></div></div></div></body></html>`;
}
function renderDataLineage(lists, selectedId, objectSetSel) {
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const allSets = Array.isArray(lists.materialized_sets) ? lists.materialized_sets : [];
  const withLineage = new Set(allSets.map((s) => s.ontology_ref));
  // #64: an explicit ?objectSet= traces THAT exact set (its ontology becomes the context) —
  // never silently substituted; an unresolvable set renders an honest note and stops.
  const setSel = objectSetSel ? allSets.find((s) => s.id === objectSetSel || String(s.ref || "").endsWith(objectSetSel)) || null : null;
  const setSelMissing = !!(objectSetSel && !setSel);
  const selected = (setSel ? ontologies.find((x) => x.ref === setSel.ontology_ref) : null)
    || ontologies.find((x) => x.id === selectedId)
    || ontologies.find((x) => withLineage.has(x.ref)) || ontologies[0] || null;
  const oref = selected ? selected.ref : "__none__";
  const oid = selected ? selected.id : "";
  const sets = allSets.filter((s) => s.ontology_ref === oref);
  const runs = (lists.materializing_runs || []).filter((r) => r.ontology_ref === oref);
  const provStream = Array.isArray(lists.provenance_stream) ? lists.provenance_stream : [];
  // Resolvers for the REAL ladder records the set does not itself carry (mapping/policy/source):
  // a set holds run/session/plan/projection/receipt refs; the projection carries mapping + policy,
  // and the mapping carries the data source — so the full chain resolves to actual daemon refs.
  const projById = new Map((lists.ontology_projections || []).map((p) => [p.id, p]));
  const mapById = new Map((lists.connector_mappings || []).map((m) => [m.id, m]));
  const viewById = new Map((lists.policy_views || []).map((v) => [v.id, v]));
  const planByRef = new Map((lists.capability_lease_plans || []).map((p) => [p.ref, p]));
  const srcById = new Map((lists.data_sources || []).map((d) => [d.source_id, d]));

  const switcher = ontologies.length
    ? `<div class="chips" style="margin:0 0 14px">${ontologies.map((x) => {
        const on = selected && x.id === selected.id; const has = withLineage.has(x.ref);
        return `<a href="/__ioi/lineage?ontology=${encodeURIComponent(x.id)}" class="pill ${on ? "ok" : "muted"}" style="text-decoration:none;margin:0">${CX_ESC(x.domain || x.id)}${has ? ` <span class="pill ok" style="margin-left:4px">lineage</span>` : ""}</a>`;
      }).join(" ")}</div>`
    : `<div class="empty">No ontologies yet.</div>`;

  const head = `<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap"><div><h1 style="margin:0">Data lineage</h1><p class="sub" style="margin:4px 0 0">Where materialized objects came from — the ODK provenance graph as a Monocle-familiar lineage of typed nodes + edges, over IOI daemon truth. Reference grammar: <a href="/__apps/lineage">Monocle lineage ↗</a> (secondary capture).</p></div><div class="row" style="gap:8px"><a class="act ghost" href="/__ioi/vertex?ontology=${encodeURIComponent(oid)}">Explore graph</a><a class="act ghost" href="/__ioi/pipeline?ontology=${encodeURIComponent(oid)}">Open pipeline</a></div></div>`;

  if (setSelMissing) {
    return automationsShell("Data lineage", head + switcher + `<div class="empty">No materialized set matches <code>${CX_ESC(objectSetSel)}</code> for this estate — nothing substituted (fail-closed). Pick a set from the <a href="/__ioi/ontology/explorer">Object Explorer</a>.</div>`);
  }
  // HONEST EMPTY — no materialized objects ⇒ no lineage. Never fabricate nodes.
  if (!sets.length) {
    const note = omBoundaryNote(`This ontology has materialized <b>no objects</b>, so there is <b>no lineage to show</b> — a lineage graph appears only once a pipeline is built (a materializing run registers a receipted object set). Build one from the <a href="/__ioi/pipeline?ontology=${encodeURIComponent(oid)}">Pipeline Builder</a>. The <a href="/__apps/lineage">Monocle reference capture ↗</a> is the familiar baseline, never a rebound surface.`);
    return automationsShell("Data lineage", head + switcher + `<div class="chips" style="margin:10px 0 12px"><span class="pill muted">no lineage</span> <span class="sub" style="margin:0">${selected ? `No materialized objects for <b>${CX_ESC(selected.domain || selected.id)}</b>.` : "Select or create an ontology."}</span></div>` + lineageLegend() + note);
  }

  // The primary lineage path — trace the most recent set back through the chain, resolving each
  // stage to its ACTUAL daemon ref (the set carries run/session/plan/projection/receipt; projection
  // → mapping → source resolves the rest). A ref that no longer resolves shows the ref the set does
  // carry, or "—" — never a fabricated label.
  const primary = setSel || sets.slice().sort((a, b) => String(b.registered_at || "").localeCompare(String(a.registered_at || "")))[0];
  const run = runs.find((r) => r.ref === primary.materializing_run_ref) || null;
  const projection = projById.get(primary.ontology_projection_id) || null;
  const mapping = projection ? mapById.get(projection.connector_mapping_id) : null;
  const view = projection ? viewById.get(projection.policy_view_id) : null;
  const source = mapping ? srcById.get(mapping.data_source_id) : null;
  const plan = planByRef.get(primary.capability_lease_plan_ref) || null;
  const contact = primary.source_contact || {};
  // #64: every resolved lineage node is a LINK into its owning surface; an unresolved record
  // keeps its carried ref as plain text (honest, never a fabricated link).
  const node = (kind, ic, label, ref, detail, href) => `<div style="flex:0 0 auto;min-width:120px;max-width:158px;border:1px solid #235c3b;border-radius:11px;padding:9px 11px;background:#15171c">
    <div style="font-size:15px">${ic} <span style="font-weight:600;font-size:12px">${CX_ESC(label)}</span></div>
    ${ref ? `<div class="sub" style="margin:4px 0 0;font-size:10px">${href ? `<a href="${href}" style="text-decoration:none">` : ""}<code>${CX_ESC(String(ref).length > 32 ? String(ref).slice(0, 32) + "…" : ref)}</code>${href ? " ↗</a>" : ""}</div>` : `<div class="sub" style="margin:4px 0 0;font-size:10px;color:#6f7280">—</div>`}
    ${detail ? `<div class="sub" style="margin:3px 0 0;font-size:10.5px;color:#6f7280">${CX_ESC(detail)}</div>` : ""}
  </div>`;
  const edge = (label) => `<div style="flex:0 0 auto;color:#5f626b;padding:0 5px;font-size:10px;text-align:center">${CX_ESC(label)}<br>→</div>`;
  // Origin-only source contact (#64 §14 — the same redaction discipline as Pipeline/Explorer).
  const contactOrigin = (() => { try { return contact.endpoint ? `${new URL(contact.endpoint).protocol}//${new URL(contact.endpoint).host}/…` : ""; } catch { return "(endpoint redacted)"; } })();
  // History summaries can embed full source URLs (e.g. "GET http://host:port/rows") — redact any
  // embedded URL to its origin before display (#64 §14); receipts on disk stay untouched.
  const redactUrls = (s) => String(s == null ? "" : s).replace(/(https?:\/\/[^\/\s"'<>]+)[^\s"'<>]*/g, "$1/…");
  const path = `<div style="display:flex;align-items:center;gap:0;overflow-x:auto;padding:4px 2px 12px">`
    + node("datasource", "🌐", "Datasource", source ? source.source_ref : "", contactOrigin ? `${contactOrigin} · http ${contact.http_status || "—"}` : (source ? source.kind : ""), source ? sourcesLink(source.source_id) : null)
    + edge("mapped_by")
    + node("mapping", "🔗", "Mapping", mapping ? mapping.ref : "", mapping ? `${primary.object_type_id || ""} · fields → properties` : "mapping retired", mapping ? managerResourceLink(oid, "connector-mapping", mapping.id) : null)
    + edge("gated_by")
    + node("policy", "🛡", "Policy view", view ? view.ref : "", view ? "capability envelope" : "view retired", view ? managerResourceLink(oid, "policy-view", view.id) : null)
    + edge("projected_as")
    + node("projection", "🔭", "Projection", projection ? projection.ref : (primary.ontology_projection_id || ""), "read shape", projection ? managerResourceLink(oid, "ontology-projection", projection.id) : null)
    + edge("leased_by")
    + node("lease", "🎟", "Lease + session", plan ? plan.ref : (primary.capability_lease_plan_ref || ""), primary.connector_session_ref ? `session ${String(primary.connector_session_ref).replace("connector-session://", "").slice(0, 10)}…` : "sealed session", `/__ioi/odk?ontology=${encodeURIComponent(oid)}#pane-resources`)
    + edge("produced_by")
    + node("run", "⚙", "Materializing run", primary.materializing_run_ref || "", `${primary.count || 0} objects`, pipelineNodeLink(oid, "materialized"))
    + edge("receipted_by")
    + node("receipt", "🧾", "Pre-output receipt", primary.pre_output_receipt_ref || "", "before output", provenanceReceiptLink(primary.pre_output_receipt_ref))
    + edge("contains")
    + node("set", "📦", "Object set", primary.ref || "", `${primary.count || 0} objects`, objectSetLink(oid, primary.id))
    + `</div>`;
  const lineageCrumb = semanticBreadcrumb([
    { label: selected.domain || oid, href: managerLink({ ontology: oid }) },
    ...(primary.object_type_id ? [{ label: primary.object_type_id, href: managerLink({ ontology: oid, section: "object-types", definitionKind: "object-type", definitionId: primary.object_type_id }) }] : []),
    { label: `set ${primary.id || ""}` },
  ]);
  const resolvedRefs = [source && source.source_ref, mapping && mapping.ref, view && view.ref, projection && projection.ref, plan && plan.ref].filter(Boolean).length;

  // OBJECT-LEVEL PROVENANCE — the new lineage truth: each object's source hash + mapped_from edges.
  const objs = (primary.objects || []).slice(0, 8);
  const objRows = objs.map((o) => {
    const mapped = Object.entries((o.provenance || {}).mapped_from || {});
    return `<tr>
      <td><code>${CX_ESC(o.object_key || "")}</code></td>
      <td><code style="font-size:10.5px" title="${CX_ESC(o.source_hash || "")}">${CX_ESC(String(o.source_hash || "").slice(0, 20))}…</code></td>
      <td>${mapped.length ? mapped.map(([prop, sf]) => `<span class="pill muted" style="margin:0"><code>${CX_ESC(prop)}</code> <span style="opacity:.6">mapped_from</span> <code>${CX_ESC(String(sf))}</code></span>`).join(" ") : "—"}</td>
    </tr>`;
  }).join("");
  const objPane = `<h2 id="lineage-objects">Object provenance <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— per-object source hash + which source field produced each property (${(primary.objects || []).length} object${(primary.objects || []).length === 1 ? "" : "s"}, first ${objs.length})</span></h2><table><thead><tr><th>Object</th><th>Source hash (sha256)</th><th>Property ← source field</th></tr></thead><tbody>${objRows}</tbody></table>`;

  // Receipt chain — auditable, from the run's own receipt stream.
  const receiptRefs = run ? (run.receipt_refs || []) : [];
  const receiptPane = `<h2 id="lineage-receipts">Receipt chain <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the run's auditable acts (${receiptRefs.length})</span></h2>`
    + (run ? `<dl class="grid">${(run.history || []).slice().reverse().slice(0, 8).map((h) => `<dt>${CX_ESC(h.op || "")}</dt><dd>${CX_ESC(redactUrls(h.summary))}<br><span class="sub" style="margin:0"><code>${CX_ESC(h.receipt_ref || "")}</code></span></dd>`).join("")}</dl>` : `<div class="empty">The materializing run for this set is no longer resolvable.</div>`);

  // Provenance proof-stream edges — the ODK materialization receipts are THREADED into the Provenance
  // proof stream (daemon-side, by reference — no receipt re-minted); each entry that references this
  // chain is a real cross-plane edge. Backing route unchanged.
  const chainRefs = [primary.ref, primary.materializing_run_ref, primary.connector_session_ref, primary.capability_lease_plan_ref].filter(Boolean);
  const provEdges = provStream.filter((e) => chainRefs.some((r) => JSON.stringify(e).includes(r)));
  const provEdgeRows = provEdges.slice(0, 8).map((e) => `<tr>
    <td><span class="pill muted">${CX_ESC(e.kind || "—")}</span></td>
    <td>${CX_ESC(e.status || "")}${e.object_count != null ? ` · ${CX_ESC(String(e.object_count))} objects` : ""}</td>
    <td><code style="font-size:10.5px">${CX_ESC(e.receipt_ref || "—")}</code></td>
    <td class="sub" style="margin:0">${CX_ESC(e.timestamp || "")}</td>
  </tr>`).join("");
  const ledgerPane = `<h2 id="lineage-provenance-stream">Provenance proof-stream edges <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— threaded from the ODK materialization receipts, by reference</span></h2>`
    + (provEdges.length
      ? `<p class="sub" style="margin:0 0 8px">${provEdges.length} Provenance proof-stream entr${provEdges.length === 1 ? "y" : "ies"} reference this lineage chain — projected by reference from the existing materialization receipts (<b>no receipt authority is duplicated</b>).</p><table><thead><tr><th>Kind</th><th>Outcome</th><th>Receipt (existing)</th><th>When</th></tr></thead><tbody>${provEdgeRows}</tbody></table>`
      : omBoundaryNote(`<b>0 Provenance proof-stream edges</b> for this chain — no materialization receipt references it yet. The resolved ladder refs + object provenance above are the authoritative lineage.`));

  const gaps = omBoundaryNote(`This is <b>real provenance</b> in the Monocle lineage grammar. Freeform Monocle lanes — resource search, arbitrary graph expansion, cross-tenant catalog search — are <b>reference-only</b>, not bound. The <a href="/__apps/lineage">Monocle reference capture ↗</a> is the familiar baseline, never a rebound surface.`);

  const banner = `<div class="chips" style="margin:10px 0 12px"><span class="pill ok">lineage</span> <span class="sub" style="margin:0">${sets.length} materialized set${sets.length === 1 ? "" : "s"} · ${sets.reduce((a, s) => a + (s.count || 0), 0)} object instance${sets.reduce((a, s) => a + (s.count || 0), 0) === 1 ? "" : "s"} for <b>${CX_ESC(selected.domain || selected.id)}</b> · newest traced below</span></div>`;
  return automationsShell("Data lineage", head + switcher + lineageCrumb + banner + lineageLegend()
    + `<h2 id="lineage-graph">Lineage <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— provenance path for <code>${CX_ESC(primary.ref || "")}</code> · ${resolvedRefs}/5 upstream ladder refs resolved to live records</span></h2>` + path
    + objPane + receiptPane + ledgerPane + gaps);
}

// ============================ PIPELINE BUILDER: EXTRACTED to surfaces/pipeline/index.mjs =========
// (functional-runtime wave) — the first app module; the surface registry mounts it. The INCIDENTS
// banner below is the next inline surface awaiting extraction.
// ============================ INCIDENTS (#45 — the Missions incident inbox as a faithful
// reference port of the issues-app capture, over REAL daemon truth: run failures + GoalRun
// blockers). Status-lane grammar: open = blockers on non-terminal mission runs + failed runs
// (needing remediation) · closed = blockers recorded on runs that reached a terminal state
// (the blocker no longer blocks) · all = both. Every row is a real goal-run/run: id, reason
// code, timestamps, and a proof link into its own run timeline. Nothing is fabricated — no
// priorities/assignees/SLA are invented (those reference lanes are named gaps disabled in
// place); empty lanes render an honest empty state. Shell geometry is glyph-anchored to the
// reference capture (/__apps/incidents, Closed lane); the row LIST is the live body (excluded
// from shell-pixel certification, verified semantically by the incidents verifier).
function renderIncidentsPort(ops, goalRuns, lane) {
  const enc = encodeURIComponent, esc = CX_ESC;
  const runs = (ops && ops.runs) || {};
  const failures = Array.isArray(runs.failures) ? runs.failures : [];
  const gr = Array.isArray(goalRuns) ? goalRuns : [];
  const TERMINAL = new Set(["complete", "completed", "done", "succeeded", "failed", "cancelled", "canceled"]);
  const DAY = 86400000;
  const ago = (t) => {
    const ms = Date.parse(t || ""); if (!Number.isFinite(ms)) return "";
    const d = Math.max(0, Math.floor((Date.now() - ms) / DAY));
    return d === 0 ? "today" : d === 1 ? "1 day ago" : `${d} days ago`;
  };
  // REAL incidents, in the reference's row shape: title = "<reason> · <subject id>".
  const blockerIncident = (r) => {
    const b = (Array.isArray(r.blockers) && r.blockers[0]) || {};
    return {
      kind: "Blocker", id: r.goal_run_id || "", title: `${b.reason_code || "blocked"} · ${r.goal_run_id || r.goal_ref || "goal-run"}`,
      created: r.created_at || "", updated: r.updated_at || r.created_at || "",
      closed: TERMINAL.has(String(r.status || "").toLowerCase()),
      proof: r.goal_run_id ? `/__ioi/run-timeline/goal-run/${enc(r.goal_run_id)}` : "",
      detail: b.role_key ? `role ${b.role_key}` : (r.status || ""),
    };
  };
  const failureIncident = (r) => ({
    kind: "Run failure", id: r.execution_id || "", title: `${r.status || "failed"} · ${r.name || r.execution_id || "run"}`,
    created: r.started_at || "", updated: r.finished_at || r.started_at || "",
    closed: false, proof: r.timeline_ref || "/__ioi/work-ledger", detail: r.project_id || "",
  });
  const incidents = gr.filter((r) => Array.isArray(r.blockers) && r.blockers.length).map(blockerIncident)
    .concat(failures.map(failureIncident));
  const open = incidents.filter((i) => !i.closed), closed = incidents.filter((i) => i.closed);
  const rowsAll = { open, closed, all: incidents }[lane] || open;
  const rows = rowsAll.slice().sort((a, b) => String(b.updated).localeCompare(String(a.updated)));
  const CAP = 50;
  const shown = rows.slice(0, CAP);

  const laneRow = (key, label, n, slot) => `<a class="in-lane ${slot}${lane === key ? " on" : ""}${key === "all" ? " alt" : ""}" href="/__ioi/missions/incidents?lane=${key}"><span class="in-lname">${label}</span><span class="in-lcount">${n}</span></a>`;
  const facet = (label, kind, slot) => {
    const input = kind === "underline"
      ? `<input class="in-fuline" placeholder="Type a name…" disabled aria-label="${esc(label)} filter (reference-only, not wired)">`
      : kind === "box"
        ? `<input class="in-fbox" placeholder="${label === "Labels" ? "Type a label name…" : "Type a support type name..."}" disabled aria-label="${esc(label)} filter (reference-only, not wired)">`
        : `<span class="in-dates"><input class="in-fdate" placeholder="Start date" disabled aria-label="${esc(label)} start (reference-only)"><input class="in-fdate" placeholder="End date" disabled aria-label="${esc(label)} end (reference-only)"></span>`;
    const inc = kind === "dates" ? "" : `<span class="in-finc gap" title="include/exclude toggle — a reference-only lane (named gap)">include ${bpIcon("caret-down")}</span>`;
    return `<div class="in-facet ${slot}"><div class="in-frow"><span class="in-flabel">${esc(label)}</span>${inc}</div>${input}</div>`;
  };
  const prio = (label, color, slot) => `<label class="in-prio ${slot} gap" title="Priority filtering is a reference-only lane — the daemon records no incident priorities (named gap)"><span class="in-cb" role="checkbox" aria-checked="false" aria-disabled="true"></span><span class="in-ppill" style="background:${color}33"><span class="in-pdot" style="color:${color}">${bpIcon("issue-dot")}</span>${label}</span></label>`;

  const rowHtml = (i) => `<div class="in-row">
    <span class="in-cb fill" role="checkbox" aria-checked="false" aria-disabled="true" title="Bulk incident actions are a reference-only lane (named gap)"></span>
    <span class="in-rico">${bpIcon(i.closed ? "issue-closed" : "warning-sign")}</span>
    <div class="in-rmain"><a class="in-rtitle" href="${esc(i.proof)}">${esc(i.title)}</a><div class="in-rsub">Created&nbsp;&nbsp;${esc(ago(i.created) || "—")} · <a href="${esc(i.proof)}">proof ↗</a>${i.detail ? ` · ${esc(i.detail)}` : ""}</div></div>
    <div class="in-rright"><span class="in-rpill${i.kind === "Blocker" ? "" : " fail"}"><span class="in-pdot">${bpIcon("issue-dot")}</span>${esc(i.kind)}</span><div class="in-rkind">Kind</div></div>
  </div>`;
  const emptyLane = `<div class="in-empty"><b>No ${lane === "all" ? "" : lane + " "}incidents</b> — ${lane === "closed" ? "no mission blocker has been resolved by a terminal run yet" : "no failed mission runs and no blocked mission runs right now"}. This inbox reads real run failures + GoalRun blockers from the daemon; it never fabricates incidents. <a href="/__ioi/missions">Missions overview →</a></div>`;

  const header = `<header class="in-header">
    <span class="in-hchip"></span>
    <h1 class="in-htitle">Issues</h1>
    <div class="in-hright">
      <div class="in-search" title="Issue search is a reference-only lane (named gap)">${bpIcon("search")}<input placeholder="Search issues…" disabled aria-label="Search issues (reference-only, not wired)"></div>
      <button class="in-new gap" disabled title="Creating incidents is a reference-only lane — incidents are DERIVED from real run failures + blockers, never authored here (named gap)">${bpIcon("plus")} New</button>
      <span class="in-cog gap" title="Issue settings — a reference-only lane (named gap)">${bpIcon("cog")}</span>
    </div>
  </header>`;

  const sidebar = `<aside class="in-side">
    ${laneRow("open", "Open", open.length, "l1")}
    ${laneRow("closed", "Closed", closed.length, "l2")}
    ${laneRow("all", "All", incidents.length, "l3")}
    <div class="in-fhead"><span class="in-ftitle">Filters</span><span class="in-fclear gap" title="No filters are wired yet — reference-only lanes (named gap)">Clear filters</span></div>
    <div class="in-flabel in-fprio">Priority</div>
    ${prio("High", "#ff9980", "p1")}
    ${prio("Medium", "#f0b726", "p2")}
    ${prio("Low", "#8abbff", "p3")}
    ${facet("Assignees", "underline", "f1")}
    ${facet("Reporters", "underline", "f2")}
    ${facet("Mentions", "underline", "f3")}
    ${facet("Labels", "box", "f4")}
    ${facet("Support types", "box", "f5")}
    ${facet("Reported on", "dates", "f6")}
    ${facet("Last updated", "dates", "f7")}
  </aside>`;

  const list = `<main class="in-list">
    <div class="in-lhead">
      <span class="in-cb hd" role="checkbox" aria-checked="false" aria-disabled="true" title="Bulk selection — a reference-only lane (named gap)"></span>
      <span class="in-lcounttxt">${shown.length < rows.length ? `${shown.length} of ${rows.length}` : rows.length} ${lane === "all" ? "" : lane + " "}issue${rows.length === 1 ? "" : "s"}</span>
      <span class="in-lmut">filtered by</span>
      <span class="in-lsel gap" title="Saved filters are a reference-only lane (named gap)">select filter ${bpIcon("caret-down")}</span>
      <span class="in-lsort"><span class="in-lmut">Sort by</span> <span class="in-lsortv gap" title="Sort options are a reference-only lane — rows are honestly ordered by most recent update">Most recently updated ${bpIcon("caret-down")}</span></span>
    </div>
    <div class="in-rows" id="incident-rows">${shown.length ? shown.map(rowHtml).join("") : emptyLane}</div>
  </main>`;

  const globalRail = ioiGlobalRailHtml({ label: "Issues", href: "/__ioi/missions/incidents", iconUri: ISSUES_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .in-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .in-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .in-header{flex:0 0 51px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 0 #dce0e5;z-index:6}
    .in-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(167,182,194,.1) url('${ISSUES_APP_ICON_URI}') center no-repeat;background-size:24px}
    .in-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:0 0 0 12px;flex:0 0 auto}
    .in-hright{margin-left:auto;align-self:stretch;display:flex;align-items:flex-start;padding-right:20px}
    .in-hright>*{margin-top:10px}
    .in-search{display:flex;align-items:center;gap:7px;width:400px;height:30px;border-radius:4px;background:#fff;padding:0 7px;color:#5f6b7c;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3)}
    .in-search input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0}
    .in-search input::placeholder{color:#5f6b7c}
    .in-new{display:inline-flex;align-items:center;gap:8px;height:30px;margin-left:15px;padding:0 15px 0 8px;border:0;border-radius:4px;background:#2d72d2;color:#fff;font:inherit;font-size:14px;line-height:16.1px;cursor:not-allowed}
    .in-new svg{color:#fff}
    .in-cog{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;margin-left:5px;border-radius:4px;color:#5f6b7c;cursor:default}
    .in-work{flex:1 1 auto;display:flex;min-height:0}
    .in-side{flex:0 0 250px;width:250px;background:#f6f7f9;border-right:1px solid rgba(16,22,26,.15);position:relative;overflow:hidden}
    .in-lane{position:absolute;left:0;right:0;display:flex;align-items:center;height:30px;padding:0 16px 0 15px;color:#1c2127;font-size:14px;line-height:18.0013px}
    .in-lane.l1{top:5px}.in-lane.l2{top:40px}.in-lane.l3{top:75px}
    .in-lane.alt{background:#edeff2}
    .in-lane.on{background:#2d72d2;color:#fff}
    .in-lname{flex:1}
    .in-lcount{display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:20px;padding:0 4px;border-radius:4px;background:rgba(143,153,168,.15);color:#1c2127;font-size:12px;line-height:16px}
    .in-lane.on .in-lcount{background:#fff;color:#2d72d2}
    .in-fhead{position:absolute;top:138px;left:15px;right:15px;display:flex;align-items:center}
    .in-ftitle{flex:1;font-size:12px;line-height:15.4297px;font-weight:600;color:#5f6b7c;text-transform:uppercase}
    .in-fclear{font-size:12px;line-height:15.4297px;color:#215db0;cursor:default}
    .in-flabel{font-size:12px;line-height:15.4297px;color:#1c2127}
    .in-fprio{position:absolute;top:168.4px;left:15px}
    .in-prio{position:absolute;left:15px;display:flex;align-items:flex-start;height:20px;gap:6px;cursor:not-allowed}
    .in-prio.p1{top:188.8px}.in-prio.p2{top:216.8px}.in-prio.p3{top:244.8px}
    
    .in-ppill{display:inline-flex;align-items:center;gap:4px;height:20px;padding:0 8px;border-radius:4px;font-size:12px;line-height:16px;color:#1c2127}
    .in-pdot{display:inline-flex}
    .in-facet{position:absolute;left:15px;right:16px}
    .in-facet.f1{top:285.8px}.in-facet.f2{top:358.3px}.in-facet.f3{top:430.7px}.in-facet.f4{top:503.1px}.in-facet.f5{top:575.5px}.in-facet.f6{top:647px}.in-facet.f7{top:717.4px}
    .in-frow{display:flex;align-items:center}
    .in-frow .in-flabel{flex:1}
    .in-finc{display:inline-flex;align-items:center;gap:2px;font-size:12px;line-height:15.4297px;color:#2d72d2;cursor:default}
    .in-finc svg{color:#2d72d2}
    .in-fuline{width:219px;height:30px;margin:5px 0 0;border:0;border-radius:4px;background:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3);font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0 10px}
    .in-fbox{width:219px;height:30px;margin:6px 0 0;border:0;border-radius:4px;background:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3);font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0 8px}
    .in-dates{display:flex;gap:2px;margin-top:5px}
    .in-fdate{width:109.5px;height:30px;border:0;border-radius:4px;background:#fff;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3);font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0 8px}
    .in-fuline::placeholder,.in-fbox::placeholder,.in-fdate::placeholder,.in-prio input{color:#5f6b7c}
    .in-list{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;background:#fff}
    .in-lhead{flex:0 0 41px;position:relative;border-bottom:1px solid #e5e8eb}
    .in-lhead>*{position:absolute}
    
    .in-cb{display:inline-block;width:16px;height:16px;border-radius:3px;box-shadow:inset 0 0 0 1px #738091;flex:0 0 16px;cursor:not-allowed}
    .in-cb.hd{position:absolute;left:15px;top:12px;background:#fff}
    .in-cb.fill{background:#eef0f2;box-shadow:none}
    .in-lcounttxt{left:49px;top:5px;font-size:14px;line-height:30px;font-weight:600;color:#1c2127;white-space:nowrap;max-width:100px;overflow:hidden}
    .in-lmut{left:156.5px;top:5px;font-size:14px;line-height:30px;color:#8f99a8;font-style:italic}
    .in-lsort .in-lmut{font-style:normal}
    .in-lsel{left:225.2px;top:5px;display:inline-flex;align-items:center;gap:5px;font-size:14px;line-height:30px;color:#5f6b7c;cursor:default;font-style:italic}
    .in-lsel svg,.in-lsortv svg{color:#1c2127}
    .in-lsort{right:15px;top:5px;display:inline-flex;align-items:center}
    .in-lsort .in-lmut{position:static}
    .in-lsortv{display:inline-flex;align-items:center;gap:0;font-size:14px;line-height:30px;color:#1c2127;margin-left:5px;cursor:default}
    .in-rows{flex:1;overflow-y:auto}
    .in-row{display:flex;align-items:flex-start;padding:11px 15px 0;height:83.4px;border-bottom:1px solid #e5e8eb}
    .in-rico{display:inline-flex;color:#8f99a8;margin:1px 0 0 21px}
    .in-rmain{flex:1;min-width:0;margin-left:10px}
    .in-rtitle{display:block;font-size:14px;line-height:18.0013px;color:#111418;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .in-rsub{font-size:12px;line-height:15.4297px;color:#8f99a8;margin-top:1px}
    .in-rright{flex:0 0 auto;width:224px;margin-left:15px}
    .in-rpill{display:inline-flex;align-items:center;gap:4px;height:20px;padding:0 8px 0 4px;border-radius:4px;background:rgba(255,153,128,.2);font-size:12px;line-height:16px;color:#1c2127}
    .in-rpill .in-pdot{color:#ff9980}
    .in-rpill.fail{background:rgba(205,66,70,.18)}.in-rpill.fail .in-pdot{color:#cd4246}
    .in-rkind{font-size:12px;line-height:15.4297px;color:#8f99a8;margin-top:4px}
    .in-empty{margin:24px;padding:16px 18px;border:1px dashed #d3d8de;border-radius:8px;background:#fbfbfc;color:#5f6b7c;max-width:640px}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Issues — incidents inbox</title><style>${css}</style></head>
    <body><div class="in-shell">${globalRail}<div class="in-main">${header}<div class="in-work">${sidebar}${list}</div></div></div></body></html>`;
}

// ============================ MODEL CATALOG (#47 — the Foundry models seed as a faithful
// reference port over REAL daemon model-route truth: /v1/hypervisor/model-routes). Every card
// and facet row derives from a live route record — identity (display name + default marker),
// availability state + probe evidence + staleness, custody posture, credential posture,
// lifecycle/admission — never the capture's vendor models. The reference's facet sections are
// PINNED SHELL SLOTS (the capture's row counts differ from live truth; the section labels are
// chrome, the rows inside are masked data). Unsupported reference lanes — Registered models,
// Compare models, name search, facet filtering, model detail pages, fine-tuning / playground /
// inference / deployment — are named gaps disabled in place. Route ADMINISTRATION (enable /
// probe / select-default) lives in Agent Studio (linked); this surface is read-only truth.
function renderModelCatalogPort(routesJson) {
  const esc = CX_ESC;
  const routes = (routesJson && routesJson.routes) || [];
  const cap = (s2) => String(s2 || "").replace(/\b\w/g, (c) => c.toUpperCase());
  // Honest facet derivation from route truth (the reference vocabulary over REAL state):
  // lifecycle: availability available -> Stable, else Unavailable (never a faked GA).
  const lifecycleOf = (r) => ((r.availability || {}).state === "available" ? "Stable" : "Unavailable");
  const typesOf = (r) => {
    const t = [];
    for (const m of ((r.model || {}).modalities) || []) t.push(m === "text" ? "text completion" : m);
    const caps = ((r.model || {}).capabilities) || {};
    if (caps.tool_calling) t.push("tool calling");
    if ((caps.reasoning || {}).supported) t.push("reasoning");
    return t.length ? t : ["text completion"];
  };
  const creatorOf = (r) => { const pb = r.provider_binding || {}; return `${pb.provider_kind || "local"}${pb.transport ? " · " + pb.transport : ""}`; };
  const tally = (vals) => { const m = new Map(); for (const v of vals) m.set(v, (m.get(v) || 0) + 1); return [...m.entries()]; };
  const lifecycleRows = tally(routes.map(lifecycleOf));
  const typeRows = tally(routes.flatMap(typesOf));
  const creatorRows = tally(routes.map(creatorOf));
  const maxN = Math.max(1, ...lifecycleRows.map(([, n]) => n), ...typeRows.map(([, n]) => n), ...creatorRows.map(([, n]) => n));
  const facetRow = ([label, n]) => `<label class="mc-frow gap" title="Facet filtering is a reference-only lane (named gap) — the value is REAL route truth"><span class="mc-cb" role="checkbox" aria-checked="false" aria-disabled="true"></span><span class="mc-flab">${esc(cap(label))}</span><span class="mc-fn">${n}</span><span class="mc-fbar"><span class="mc-fbarfill" style="width:${Math.round(70 * n / maxN)}px"></span></span></label>`;
  const facetSection = (slot, label, rows) => `<div class="mc-fsec ${slot}"><div class="mc-fshead"><span class="mc-fslabel">${esc(label)}</span><button class="mc-fclear gap" disabled title="No facet filters are wired — a reference-only lane (named gap)">Clear</button></div><div class="mc-frows">${rows.map(facetRow).join("")}</div></div>`;

  const availPill = (r) => { const a = r.availability || {}; return a.state === "available" ? `${a.stale ? "available · stale probe" : "available"}` : (a.state || "unknown"); };
  const card = (r) => `<div class="mc-card">
    <div class="mc-chead">
      <span class="mc-cico">${bpIcon("model", 20)}</span>
      <div class="mc-ctitles"><div class="mc-ctitle">${esc(r.display_name || (r.model || {}).model_id || r.route_id)}${r.default_route ? " (default)" : ""}</div><div class="mc-csub">${esc((r.model || {}).model_id || "")} · ${esc(creatorOf(r))} · ${esc(availPill(r))}${(r.availability || {}).probe ? ` · probe ${esc(((r.availability || {}).probe || {}).kind || "")} @ ${esc((((r.availability || {}).probe || {}).checked_at || "").slice(0, 19))}` : ""}</div></div>
    </div>
    <div class="mc-ctags">${typesOf(r).map((t) => `<span class="mc-pill">${esc(cap(t))}</span>`).join("")}<span class="mc-pill alt" title="weight custody class — daemon truth">${esc(((r.custody || {}).weight_class || "").replace(/_/g, " ") || "custody unrecorded")}</span><span class="mc-pill alt" title="credential posture — daemon truth">${esc((r.credential_posture || "").replace(/_/g, " "))}</span><span class="mc-pill alt" title="lifecycle + admission — daemon truth">${esc(((r.lifecycle || {}).status || ""))}${(r.admission || {}).last_admission_id ? " · admitted" : ""}</span></div>
  </div>`;

  const globalRail = ioiGlobalRailHtml({ label: "Model Catalog", href: "/__ioi/foundry/models", iconUri: MODELS_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="mc-header">
    <span class="mc-hchip"></span>
    <h1 class="mc-htitle">Model Catalog</h1>
    <span class="mc-tab on" title="The IOI-provided lane IS the live route registry below">IOI-provided models</span>
    <span class="mc-tab gap" title="Registered (externally imported) models are a reference-only lane — no import plane (named gap)">Registered models</span>
  </header>`;

  const hero = `<section class="mc-hero">
    <h2 class="mc-h1">IOI-provided models</h2>
    <p class="mc-sub">Browse large language models in Foundry</p>
    <button class="mc-compare gap" disabled title="Model comparison is a reference-only lane (named gap)">${bpIcon("split-view")}<span>Compare models</span></button>
  </section>`;

  const filters = `<aside class="mc-filters">
    <div class="mc-fhead">Filters</div>
    <div class="mc-search" title="Name search is a reference-only lane — the registry renders complete below (named gap)">${bpIcon("search")}<input placeholder="Search by name..." disabled aria-label="Search by name (reference-only, not wired)"></div>
    ${facetSection("s1", "Lifecycle Status", lifecycleRows)}
    ${facetSection("s2", "Type", typeRows)}
    ${facetSection("s3", "Model creator", creatorRows)}
  </aside>`;

  const catalog = `<section class="mc-list">
    <h3 class="mc-addhead">Additional models</h3>
    <div class="mc-cards">${routes.length ? routes.map(card).join("") : `<div class="mc-empty"><b>No model routes yet</b> — register a route in <a href="/__ioi/agent-studio#model-routes">Agent Studio</a>. This catalog reads the real daemon model-route registry; nothing is fabricated.</div>`}</div>
    <div class="mc-foot">Every card is a real daemon model route (${routes.length}) — identity, availability + probe evidence, weight custody, credential posture, lifecycle/admission. Administration (enable · probe · select default): <a href="/__ioi/agent-studio#model-routes">Agent Studio →</a> · owner surface: <a href="/__ioi/foundry">Foundry →</a> · reference: <a href="/__apps/models" target="_blank" rel="noopener">Model Catalog capture ↗</a></div>
  </section>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .mc-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .mc-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .mc-header{flex:0 0 51px;display:flex;align-items:stretch;background:#fff;box-shadow:0 1px 0 0 #dce0e5;z-index:6}
    .mc-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(124,110,228,.1) url('${MODELS_APP_ICON_URI}') center/24px no-repeat}
    .mc-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:7px 0 0 12px;flex:0 0 auto}
    .mc-tab{display:inline-flex;align-items:center;font-size:14px;line-height:30px;color:#1c2127;margin-left:20px;position:relative;cursor:default;padding:0 0 1px}
    .mc-tab.on{color:#215db0}
    .mc-tab.on::after{content:"";position:absolute;left:0;right:0;bottom:0;height:3px;background:#2d72d2}
    .mc-tab:first-of-type{margin-left:34px}
    .mc-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#fff}
    .mc-hero{padding:0 0 0 60px;border-bottom:1px solid #dce0e5;height:163px}
    .mc-h1{font-size:32px;line-height:41.1459px;font-weight:600;color:#1c2127;margin:30px 0 0}
    .mc-sub{font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:5px 0 0}
    .mc-compare{display:inline-flex;align-items:center;gap:8px;height:30px;margin-top:15px;padding:0 12px 0 9px;border:1px solid rgba(35,133,81,.6);border-radius:4px;background:transparent;color:#1c6e42;font:inherit;font-size:14px;line-height:16.1px;cursor:not-allowed}
    .mc-compare svg{color:#1c6e42}
    .mc-work{display:flex;align-items:flex-start;padding:6.1px 0 40px 55px;gap:30px}
    .mc-filters{flex:0 0 300px;width:300px;height:354px;position:relative;border:1px solid #dce0e5;border-radius:4px;background:#fff;overflow:hidden}
    .mc-fhead{height:50px;padding:16.5px 0 0 19px;font-size:14px;line-height:16px;font-weight:600;color:#1c2127;border-bottom:1px solid #eef0f2}
    .mc-search{position:absolute;left:19px;top:69px;display:flex;align-items:center;gap:5px;width:260px;height:30px;border-radius:4px;background:#fff;padding:0 7px;color:#5f6b7c;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3)}
    .mc-search input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0}
    .mc-search input::placeholder{color:#5f6b7c}
    .mc-fsec{position:absolute;left:19px;width:260px}
    .mc-fsec.s1{top:115px}.mc-fsec.s2{top:185px}.mc-fsec.s3{top:281px}
    .mc-fshead{display:flex;align-items:center;height:24px}
    .mc-fslabel{flex:1;font-size:12px;line-height:15.4297px;font-weight:600;color:#5f6b7c;text-transform:uppercase}
    .mc-fclear{border:0;background:transparent;font:inherit;font-size:14px;line-height:16.1px;color:#2d72d2;padding:0 8px;height:24px;border-radius:4px;cursor:not-allowed}
    .mc-frows{margin-top:6px}
    .mc-frow{display:flex;align-items:center;height:26px;cursor:not-allowed}
    .mc-cb{display:inline-block;width:16px;height:16px;border-radius:3px;box-shadow:inset 0 0 0 1px #738091;flex:0 0 16px;background:#fff}
    .mc-flab{font-size:14px;line-height:18.0013px;color:#1c2127;margin-left:8px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mc-fn{font-size:14px;line-height:18.0013px;color:#1c2127;margin-right:8px}
    .mc-fbar{position:relative;width:70px;height:10px;border-radius:4px;background:rgba(45,114,210,.15);flex:0 0 70px}
    .mc-fbarfill{position:absolute;left:0;top:0;height:10px;border-radius:4px;background:#2d72d2}
    .mc-list{flex:1;min-width:0;max-width:520px}
    .mc-addhead{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:1px 0 0;text-transform:capitalize}
    .mc-cards{margin-top:18px}
    .mc-card{width:360px;border:1px solid #dce0e5;border-radius:4px;background:#fff;margin-bottom:14px}
    .mc-chead{display:flex;align-items:center;padding:15px;border-bottom:1px solid #eef0f2}
    .mc-cico{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:4px;background:rgba(124,110,228,.15);color:#7961db;flex:0 0 32px}
    .mc-ctitles{margin-left:11px;min-width:0}
    .mc-ctitle{font-size:16px;line-height:20.573px;font-weight:600;color:#1c2127;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mc-csub{font-size:11px;line-height:14px;color:#8f99a8;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .mc-ctags{display:flex;flex-wrap:wrap;gap:8px;padding:12px 15px 14px}
    .mc-pill{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:10px;background:#eef0f2;font-size:12px;line-height:16px;color:#1c2127}
    .mc-pill.alt{background:#f6f7f9;color:#5f6b7c}
    .mc-empty{width:420px;padding:16px 18px;border:1px dashed #d3d8de;border-radius:8px;background:#fbfbfc;color:#5f6b7c}
    .mc-foot{margin-top:16px;max-width:480px;color:#7b8494;font-size:12px;line-height:1.5}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Model Catalog</title><style>${css}</style></head>
    <body><div class="mc-shell">${globalRail}<div class="mc-main">${header}<div class="mc-body">${hero}<main class="mc-work">${filters}${catalog}</main></div></div></div></body></html>`;
}

// ============================ MARKETPLACE BROWSE (#48 — the listings seed as a faithful
// reference port over the REAL daemon marketplace substrate: /v1/hypervisor/marketplace).
// The reference's Stores lane is REBOUND to the same substrate (the estate's governed
// listing plane + its live product count), so both sides render the same daemon truth.
// The Stores ROW REGION is masked data; the store card chrome, hero, and the install-wizard
// band are compared shell. Publish/install/hire/settle/runtime semantics do NOT exist here —
// the install wizard is reference chrome (named gap); drafting/publish/admission stay on the
// /__ioi/marketplace substrate (linked first-class). No fake marketplace products, ever.
function renderMarketplaceBrowsePort(listingsJson) {
  const esc = CX_ESC;
  const listings = (listingsJson && listingsJson.listings) || [];
  // The store's product count = PUBLISHED (installable) listings — the same wire semantics
  // as the reference's rebound Stores lane (drafts and in-review listings do not count).
  const published = listings.filter((l) => l.public_state === "published");
  const products = published.length;

  const globalRail = ioiGlobalRailHtml({ label: "Marketplace", href: "/__ioi/marketplace/listings", iconUri: MARKETPLACE_APP_ICON_URI, railVariant: "rv-pipe", viewAll: false, star: false, badges: true, aipGradient: true, acctMuted: true });

  const header = `<header class="mk-header">
    <span class="mk-hchip"></span>
    <h1 class="mk-htitle">Marketplace</h1>
    <div class="mk-hright">
      <div class="mk-search" title="Product search is a reference-only lane — the store table below is the real registry (named gap)">${bpIcon("search")}<input placeholder="Search products..." disabled aria-label="Search products (reference-only, not wired)"></div>
      <span class="mk-hbtn gap" aria-disabled="true" title="Installations are a reference-only lane — nothing installs from this surface (named gap)"><img src="${MK_GLOBE_URI}" width="16" height="16" alt="">Installations</span>
      <span class="mk-hbtn ring gap" aria-disabled="true" title="Reference help lane (named gap)">Help ${bpIcon("help")}</span>
    </div>
  </header>`;

  const hero = `<section class="mk-hero">
    <img class="mk-heroimg" src="${MK_HERO_URI}" alt="" aria-hidden="true">
    <h2 class="mk-h1">Marketplace</h2>
    <p class="mk-sub">Discover and install Foundry products</p>
  </section>`;

  const stores = `<div class="mk-content">
    <div class="mk-storeshead"><h3 class="mk-storest">Stores</h3><div class="mk-search mk-storesearch" title="Store search is a reference-only lane (named gap)">${bpIcon("search")}<input placeholder="Search stores..." disabled aria-label="Search stores (reference-only, not wired)"></div></div>
    <div class="mk-card mk-storecard">
      <div class="mk-thead"><span class="mk-thname">Name</span><span class="mk-thprod">Products<span class="mk-sortico gap" title="Store sorting is a reference-only lane (named gap)">${bpIcon("sort-desc")}</span></span></div>
      <div class="mk-rows">
        <a class="mk-row" href="/__ioi/marketplace" title="The estate's governed listing plane — draft listings, publish candidates, admission reviews (the real substrate)">
          <span class="mk-rowico" style="background-image:url('${MK_STORE_ICON_URI}')"></span>
          <span class="mk-rowmain"><span class="mk-rowname">Estate Marketplace — governed listing plane</span><span class="mk-rowsub">Listings drafted over real substrate. Publish is the governed path: admitted review + open release control + serving runtime, never a hidden lane.</span></span>
          <span class="mk-rowright"><span class="mk-rowcount"><img src="${MK_PACKAGE_URI}" width="16" height="16" alt="">${products} product${products === 1 ? "" : "s"}</span><span class="mk-rowshare gap" title="Store sharing is a reference-only lane (named gap)">${bpIcon("share")}</span></span>
        </a>
      </div>
    </div>
    <div class="mk-card mk-wizcard">
      <div class="mk-wizcopy">
        <h4 class="mk-wizt">Install your first product</h4>
        <p class="mk-wizsub">A store holds a collection of products. Select a store to browse or search for a product to install.</p>
        <p class="mk-wizsub2">Installing from this surface is a reference-only lane (named gap) — products enter the estate through the governed path on the <a href="/__ioi/marketplace">Marketplace substrate</a>: draft → admitted review → open release.</p>
      </div>
      <div class="mk-wizsteps">
        <img class="w1" src="${MK_WIZ1_URI}" width="80" height="78" alt="">
        <img class="wa1" src="${MK_ARROW_URI}" width="34" height="16" alt="">
        <img class="w2" src="${MK_WIZ2_URI}" width="160" height="80" alt="">
        <img class="wa2" src="${MK_ARROW_URI}" width="34" height="16" alt="">
        <img class="w3" src="${MK_WIZ3_URI}" width="125" height="98" alt="">
        <span class="wc1">Choose a product to install</span><span class="wc2">Configure product inputs</span><span class="wc3">Install and explore</span>
      </div>
    </div>
    <div class="mk-foot">The store row is daemon truth: ${listings.length} listing${listings.length === 1 ? "" : "s"} on the governed plane (${published.length} published). Draft/publish/admission: <a href="/__ioi/marketplace">Marketplace substrate →</a> · reference: <a href="/__apps/listings" target="_blank" rel="noopener">Marketplace capture ↗</a></div>
  </div>`;

  const css = `:root{color-scheme:light}*{box-sizing:border-box}
    body{margin:0;background:#fff;color:#1c2127;font:14px/1.28581 Source-Sans-Pro,Helvetica,sans-serif}
    a{color:#215db0;text-decoration:none}
    .mk-shell{display:flex;height:100vh;width:100vw;overflow:hidden}
    ${IOI_GRAIL_CSS}
    .mk-main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
    .mk-header{flex:0 0 51px;display:flex;align-items:center;background:#fff;box-shadow:0 1px 0 0 #dce0e5;z-index:6}
    .mk-hchip{width:50px;height:50px;flex:0 0 50px;background:rgba(215,84,68,.08) url('${MARKETPLACE_APP_ICON_URI}') center/26px no-repeat}
    .mk-htitle{font-size:16px;line-height:36px;font-weight:600;color:#404854;margin:0 0 0 10px;flex:0 0 auto}
    .mk-hright{margin-left:auto;align-self:stretch;display:flex;align-items:flex-start;padding-right:16px}
    .mk-hright>*{margin-top:8.5px}
    .mk-search{display:flex;align-items:center;gap:4px;width:315px;height:30px;border-radius:4px;background:#fff;padding:0 8px;color:#5f6b7c;box-shadow:inset 0 0 0 1px rgba(17,20,24,.2),inset 0 1px 1px rgba(17,20,24,.3)}
    .mk-search input{flex:1;border:0;background:transparent;font:inherit;font-size:14px;color:#1c2127;outline:none;padding:0}
    .mk-search input::placeholder{color:#5f6b7c}
    .mk-hbtn{display:inline-flex;align-items:center;gap:5px;height:30px;margin-left:17px;padding:0 8px;border-radius:4px;font-size:14px;line-height:16.1px;color:#1c2127;cursor:default}
    .mk-hbtn.ring{margin-left:8px;padding:0 8px 0 9px;background:#fff;box-shadow:inset 0 0 0 1px rgba(64,72,84,.33),0 1px 2px rgba(17,20,24,.1)}
    .mk-hbtn.ring svg{color:#5f6b7c;margin-left:-1px}
    .mk-body{flex:1 1 auto;min-width:0;overflow-y:auto;background:#f6f7f9}
    .mk-hero{position:relative;background:#fff;height:105px;border-bottom:1px solid #dce0e5;overflow:hidden}
    .mk-heroimg{position:absolute;right:0;top:-3px;width:385px;height:106px}
    .mk-h1{position:relative;font-size:28px;line-height:32px;font-weight:600;color:#1c2127;margin:0;padding:24px 0 0}
    .mk-sub{position:relative;font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:2px 0 0}
    .mk-hero .mk-h1,.mk-hero .mk-sub{max-width:1210px;margin-left:auto;margin-right:auto;padding-left:45px;padding-right:45px}
    .mk-content{max-width:1210px;margin:0 auto;padding:0 45px}
    .mk-storeshead{display:flex;align-items:center;margin-top:27px}
    .mk-storest{font-size:22px;line-height:25px;font-weight:600;color:#1c2127;margin:0;flex:1}
    .mk-storesearch{width:315px}
    .mk-card{background:#fff;border-radius:4px;box-shadow:0 0 0 1px rgba(17,20,24,.15)}
    .mk-storecard{margin-top:17px;height:495px;overflow:hidden}
    .mk-thead{display:flex;align-items:flex-start;height:40px;padding-top:7.5px;background:#f6f7f9;border-bottom:1px solid #dce0e5;border-radius:4px 4px 0 0}
    .mk-thname{flex:1;font-size:12px;line-height:15.4297px;color:#5f6b7c;padding-left:20px}
    .mk-thprod{width:405px;display:flex;justify-content:space-between;padding:0 11px 0 18.3px;border-left:1px solid #dce0e5;margin-top:-7.5px;padding-top:7.5px;height:40px;font-size:12px;line-height:15.4297px;color:#5f6b7c}
    .mk-sortico{display:inline-flex;color:#5f6b7c;margin-top:-2px}
    .mk-row{display:flex;align-items:flex-start;padding:14px 0 12px;border-bottom:1px solid #eef0f2;color:#1c2127}
    .mk-rowico{width:16px;height:16px;background-size:16px;background-repeat:no-repeat;margin:2px 0 0 20px;flex:0 0 16px}
    .mk-rowmain{flex:1;min-width:0;margin-left:8px}
    .mk-rowname{display:block;font-size:14px;line-height:18.0013px;color:#1c2127}
    .mk-rowsub{display:block;font-size:12px;line-height:15.4297px;color:#8f99a8;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:640px}
    .mk-rowright{width:405px;display:flex;justify-content:space-between;align-items:flex-start;padding:0 14px 0 18.3px;font-size:14px;line-height:18.0013px;color:#1c2127;margin-top:5px}
    .mk-rowcount{display:inline-flex;align-items:center;gap:8px}
    .mk-rowshare{display:inline-flex;color:#5f6b7c;margin-top:2px}
    .mk-wizcard{margin-top:20px;height:215px;display:flex;align-items:flex-start;overflow:hidden;position:relative}
    .mk-wizcopy{flex:0 0 360px;padding:93.5px 0 0 20px}
    .mk-wizt{font-size:16px;line-height:19px;font-weight:600;color:#1c2127;margin:0}
    .mk-wizsub{font-size:14px;line-height:18.0013px;color:#5f6b7c;margin:6px 0 0}
    .mk-wizsub2{font-size:11px;line-height:14px;color:#8f99a8;margin:6px 0 0}
    .mk-wizsteps{position:absolute;inset:0}
    .mk-wizsteps img,.mk-wizsteps span{position:absolute}
    .mk-wizsteps .w1{left:492px;top:55px}.mk-wizsteps .wa1{left:632px;top:86px}.mk-wizsteps .w2{left:686px;top:54px}.mk-wizsteps .wa2{left:866px;top:86px}.mk-wizsteps .w3{left:937.5px;top:45px}
    .mk-wizsteps .wc1{left:469px;top:145px}.mk-wizsteps .wc2{left:689.7px;top:145px}.mk-wizsteps .wc3{left:943.2px;top:145px}
    .mk-wizsteps span{font-size:14px;line-height:18.0013px;color:#1c2127}
    .mk-foot{margin:16px 0 30px;color:#7b8494;font-size:12px;line-height:1.5}`;

  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Marketplace</title><style>${css}</style></head>
    <body><div class="mk-shell">${globalRail}<div class="mk-main">${header}<div class="mk-body">${hero}<main>${stores}</main></div></div></div></body></html>`;
}

function renderOntologyManager(ov, lists, selectedId) {
  const o = ov || {};
  const ontologies = Array.isArray(lists.ontologies) ? lists.ontologies : [];
  const selected = ontologies.find((x) => x.id === selectedId) || ontologies[0] || null;
  const com = (selected && selected.canonical_object_model) || {};
  const arr = (k) => (Array.isArray(com[k]) ? com[k] : []);
  const vts = arr("value_types"), ots = arr("object_types"), lts = arr("link_types"), ats = arr("action_types");
  const funcs = ats.filter((a) => a.kind === "function");
  const nonFuncActs = ats.filter((a) => a.kind !== "function");
  const health = (selected && selected.health) || {};
  const msets = (lists.materialized_sets || []).filter((m) => selected && m.ontology_ref === selected.ref);
  const totalInstances = msets.reduce((a, m) => a + (m.count || 0), 0);
  const rollup = o.ontology_health || {};
  const propCount = ots.reduce((n, x) => n + (Array.isArray(x.properties) ? x.properties.length : 0), 0);
  const idc = (x) => `<code>${CX_ESC(x || "")}</code>`;

  // ---- Ontology switcher: every ontology as a selectable chip carrying its own honest health pill.
  const switcher = ontologies.length
    ? `<div class="chips" style="margin:0 0 14px">${ontologies.map((x) => {
        const on = x.id === (selected && selected.id);
        return `<a href="/__ioi/odk?ontology=${encodeURIComponent(x.id)}" class="pill ${on ? "ok" : "muted"}" style="text-decoration:none;margin:0">${CX_ESC(x.domain || x.id)} ${ontologyHealthPill(x.health || {})}</a>`;
      }).join(" ")}</div>`
    : "";

  // ---- Panes.
  const objectTypesPane = `<h2 id="pane-object-types" style="display:flex;justify-content:space-between;align-items:center">Object types <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${ots.length})</span> <a class="act" href="/__ioi/odk/ontologies/${selected ? encodeURIComponent(selected.id) : "new"}${selected ? "/edit" : ""}">Configure model</a></h2>`
    + omBoundaryNote(totalInstances > 0 ? `<b>${totalInstances} objects</b> materialized across ${msets.length} receipted set${msets.length === 1 ? "" : "s"} — bounded read-only batches under held leases + sealed sessions; hashes + provenance, never secrets.` : `<b>0 objects</b> across all types — the object-instance plane is <b>not bound</b>. Object counts stay 0 until an <code>OntologyProjection</code> exists; nothing here fabricates rows.`)
    + (ots.length ? ots.map((t) => {
        const props = Array.isArray(t.properties) ? t.properties : [];
        return `<div style="border:1px solid #24262d;border-radius:10px;padding:11px 13px;margin:0 0 9px;background:#15171c"><div style="display:flex;justify-content:space-between;align-items:center"><div style="font-weight:600">${CX_ESC(t.name || t.id)} ${idc(t.id)}</div><a class="act ghost" href="/__ioi/odk/ontologies/${encodeURIComponent(selected.id)}">Configure</a></div><div class="sub" style="margin:4px 0 0">${props.length} propert${props.length === 1 ? "y" : "ies"} · <b>${msets.filter((m) => m.object_type_id === t.id).reduce((a, m) => a + (m.count || 0), 0)}</b> objects · title <code>${CX_ESC(t.title_property || "—")}</code></div></div>`;
      }).join("") : `<div class="empty">No object types yet. ${selected ? `<a href="/__ioi/odk/ontologies/${encodeURIComponent(selected.id)}/edit">Add typed object types →</a>` : `<a href="/__ioi/odk/ontologies/new">Create an ontology →</a>`}</div>`);

  const propRows = ots.flatMap((t) => (Array.isArray(t.properties) ? t.properties : []).map((p) => `<tr><td>${CX_ESC(t.name || t.id)}</td><td>${CX_ESC(p.name || p.id)} ${idc(p.id)}</td><td><code>${CX_ESC(p.value_type || "")}</code></td><td>${p.required ? "yes" : "—"}${t.title_property === p.id ? ` <span class="pill ok">title</span>` : ""}</td></tr>`)).join("");
  const sharedValueTypes = vts.filter((v) => ots.filter((t) => (t.properties || []).some((p) => p.value_type === v.id)).length >= 2).length;
  const propertiesPane = `<h2 id="pane-properties">Properties <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${propCount}) · shared value types: ${sharedValueTypes}</span></h2>`
    + (propCount ? `<table><thead><tr><th>Object type</th><th>Property</th><th>Value type</th><th>Required</th></tr></thead><tbody>${propRows}</tbody></table>` : `<div class="empty">No properties declared.</div>`);

  const linkPane = `<h2 id="pane-link-types">Link types <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${lts.length})</span></h2>`
    + (lts.length ? `<table><thead><tr><th>Link</th><th>From → To</th><th>Cardinality</th></tr></thead><tbody>${lts.map((l) => `<tr><td>${CX_ESC(l.name || l.id)} ${idc(l.id)}</td><td><code>${CX_ESC(l.from || "")}</code> → <code>${CX_ESC(l.to || "")}</code></td><td><span class="pill muted">${CX_ESC(l.cardinality || "")}</span></td></tr>`).join("")}</tbody></table>` : `<div class="empty">No link types.</div>`);

  const actionPane = `<h2 id="pane-action-types">Action types <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${nonFuncActs.length})</span></h2>`
    + omBoundaryNote(`Action <b>declarations</b> only — writeback/execution is <b>not wired</b> (needs <code>PolicyBoundDataView</code> + <code>TransformationRun</code>). Declaring an action never runs it.`)
    + (nonFuncActs.length ? `<table><thead><tr><th>Action</th><th>Kind</th><th>Applies to</th></tr></thead><tbody>${nonFuncActs.map((a) => `<tr><td>${CX_ESC(a.name || a.id)} ${idc(a.id)}</td><td><span class="pill muted">${CX_ESC(a.kind || "")}</span></td><td>${a.applies_to ? idc(a.applies_to) : "—"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No action types.</div>`);

  const valuePane = `<h2 id="pane-value-types">Value types <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${vts.length})</span></h2>`
    + (vts.length ? `<table><thead><tr><th>Value type</th><th>Base</th><th>Enum</th></tr></thead><tbody>${vts.map((v) => `<tr><td>${CX_ESC(v.name || v.id)} ${idc(v.id)}</td><td><span class="pill muted">${CX_ESC(v.base || "string")}</span></td><td>${(v.enum_values && v.enum_values.length) ? v.enum_values.map((e) => `<span class="pill muted">${CX_ESC(e)}</span>`).join(" ") : "—"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No value types.</div>`);

  const functionsPane = `<h2 id="pane-functions">Functions <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">(${funcs.length})</span></h2>`
    + omBoundaryNote(`Function <b>declarations</b> only — evaluation/execution is <b>not wired</b> (needs a bound runtime + <code>PolicyBoundDataView</code>).`)
    + (funcs.length ? `<table><thead><tr><th>Function</th><th>Applies to</th></tr></thead><tbody>${funcs.map((a) => `<tr><td>${CX_ESC(a.name || a.id)} ${idc(a.id)}</td><td>${a.applies_to ? idc(a.applies_to) : "—"}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No function declarations.</div>`);

  const healthPane = `<h2 id="pane-health-issues">Health issues <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— readiness projection</span></h2>`
    + (selected ? renderOntologyHealth(selected.health) : `<div class="empty">Select or create an ontology.</div>`)
    + `<div class="sub" style="margin:6px 0 0">Estate rollup — <span class="pill ok">${rollup.ready || 0} ready</span> <span class="pill warn">${rollup.incomplete || 0} incomplete</span> <span class="pill muted">${rollup.empty || 0} empty</span></div>`;

  const cleanupPane = omUnavailablePane("Cleanup", "Unused-type / orphan-reference detection is not built.", "OntologyCleanupScan");

  // ---- Configuration: identity + IOI authority threaded sideways (receipts/history, source-neutral,
  // substrate readiness, conformance).
  const sub = o.substrate || {};
  const receipts = selected ? (selected.receipt_refs || []).length : 0;
  const historyN = selected ? (selected.history || []).length : 0;
  const configPane = `<h2 id="pane-configuration">Ontology configuration</h2>`
    + (selected ? `<dl class="grid">
        <dt>Domain · version</dt><dd>${CX_ESC(selected.domain)} · ${CX_ESC(selected.version || "0.1.0")}</dd>
        <dt>Ref · revision</dt><dd><code>${CX_ESC(selected.ref)}</code> <span class="pill muted">rev ${CX_ESC(String(selected.revision || 1))}</span></dd>
        <dt>Receipts · history</dt><dd><span class="pill ok">${receipts} receipt${receipts === 1 ? "" : "s"}</span> <span class="pill muted">${historyN} history</span> <a class="act ghost" href="/__ioi/odk/ontologies/${encodeURIComponent(selected.id)}">Open detail →</a></dd>
        <dt>Description</dt><dd>${CX_ESC(selected.description || "—")}</dd>
      </dl>` : `<div class="empty">No ontology selected.</div>`)
    + `<h3 style="margin:14px 0 6px">IOI authority</h3>`
    + `<dl class="grid">
        <dt>Source</dt><dd><span class="pill ok">daemon truth</span> <span class="sub" style="margin:0">every pane reads the ontology-manager contract; nothing captured is presented as truth</span></dd>
        <dt>Substrate readiness</dt><dd>${sub.environment_classes || 0} env · ${sub.foundry_specs || 0} specs · ${sub.connectors || 0} connectors · ${sub.work_ledger_entries || 0} ledger</dd>
        <dt>Conformance</dt><dd><span class="pill warn">not generated</span> <span class="sub" style="margin:0">SDK / conformance suite generation is a named gap</span></dd>
        <dt>Authority crossing</dt><dd><span class="pill warn">not crossed</span> <span class="sub" style="margin:0">no ingestion / transform / writeback — object data stays empty until the contracts below exist</span></dd>
      </dl>`;

  // ---- Resources (recipes / descriptors / manifests / connector mappings bound to this ontology)
  //      + Data plane.
  const boundRef = selected ? selected.ref : "__none__";
  const recs = (lists.data_recipes || []).filter((r) => r.ontology_ref === boundRef);
  const descs = (lists.surface_descriptors || []).filter((d) => d.ontology_ref === boundRef);
  const mans = (lists.manifests || []).filter((m) => (m.ontology_refs || []).includes(boundRef));
  const maps = (lists.connector_mappings || []).filter((m) => m.ontology_ref === boundRef);
  const pviews = (lists.policy_views || []).filter((v) => v.ontology_ref === boundRef);
  const truns = (lists.transformation_runs || []).filter((r) => r.ontology_ref === boundRef);
  const projs = (lists.ontology_projections || []).filter((p) => p.ontology_ref === boundRef);
  const lplans = (lists.capability_lease_plans || []).filter((p) => p.ontology_ref === boundRef);
  const mruns = (lists.materializing_runs || []).filter((r) => r.ontology_ref === boundRef);
  const csns = (lists.connector_sessions || []).filter((c) => c.ontology_ref === boundRef);
  const resourceSection = (title, family, items, nameKey, newLabel) => `<h3 style="display:flex;justify-content:space-between;align-items:center;margin:12px 0 6px">${title} (${items.length}) <a class="act ghost" href="/__ioi/odk/${family}/new">+ ${newLabel}</a></h3>${items.length ? items.map((x) => odkCard(family, x, nameKey)).join("") : `<div class="empty">None bound to this ontology.</div>`}`;
  const resourcesPane = `<h2 id="pane-resources">Resources <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— bound to ${selected ? CX_ESC(selected.domain) : "—"}</span></h2>`
    + `<h3 style="margin:12px 0 6px">Connector mappings (${maps.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— source fields → object properties · daemon truth · inert</span></h3>${omConnectorMappings(maps)}`
    + `<h3 style="margin:12px 0 6px">Policy-bound data views (${pviews.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the capability gate over mapped data · daemon truth · declarative</span></h3>${omPolicyViews(pviews)}`
    + `<h3 style="margin:12px 0 6px">Transformation runs (${truns.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— auditable plans/dry-runs against the gate · daemon truth · no source contact</span></h3>${omTransformationRuns(truns)}`
    + `<h3 style="margin:12px 0 6px">Ontology projections (${projs.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— the declared explorer/search shape · daemon truth · no materialized objects</span></h3>${projs.length ? projs.map((p) => `<div class="chips" style="margin:0 0 6px"><b>${CX_ESC(p.name || p.id)}</b> <span class="pill ${p.status === "ready" ? "ok" : p.status === "blocked" ? "warn" : "muted"}">${CX_ESC(p.status || "draft")}</span> <span class="pill muted">${(p.visible_properties || []).length} visible</span> <span class="pill warn" title="shape only — nothing materialized">0 objects</span> <span class="sub" style="margin:0"><code>${CX_ESC(p.ref || "")}</code></span></div>`).join("") : `<div class="empty">No projections. A projection declares what an authorized explorer <b>would</b> render — shape only, never rows.</div>`}`
    + `<h3 style="margin:12px 0 6px">Capability-lease plans (${lplans.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— declared credential authority · gateway: the capability-lease primitive · nothing minted</span></h3>${omLeasePlans(lplans)}`
    + `<h3 style="margin:12px 0 6px">Materializing runs (${mruns.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— live lease acquisition against the gateway · no execution, no rows</span></h3>${omMaterializingRuns(mruns)}`
    + `<h3 style="margin:12px 0 6px">Sealed connector sessions (${csns.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— credential resolution proven, material never surfaced · no source contact</span></h3>${omConnectorSessions(csns)}`
    + `<h3 style="margin:12px 0 6px">Materialized object sets (${msets.length}) <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— bounded, receipted, all-or-nothing · hashes + provenance</span></h3>${msets.length ? `<table><thead><tr><th>Set</th><th>Object type</th><th>Objects</th><th>Registered</th></tr></thead><tbody>${msets.map((m) => `<tr><td><code>${CX_ESC(m.ref || "")}</code></td><td><code>${CX_ESC(m.object_type_id || "")}</code></td><td><b>${m.count || 0}</b></td><td class="sub" style="margin:0">${CX_ESC(m.registered_at || "")}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No materialized sets. Execution registers one bounded batch, all-or-nothing, behind a pre-output receipt.</div>`}`
    + resourceSection("Data recipes", "data-recipes", recs, "name", "New recipe")
    + resourceSection("Surface descriptors", "surface-descriptors", descs, "name", "New descriptor")
    + resourceSection("ODK manifests", "manifests", mans, "name", "New manifest");

  const dataPane = `<div id="pane-data">${renderDataSourcesSection(lists.data_sources || [])}</div>`;

  // ---- Object data / Explorer: with a declared projection the DECLARED SHAPE renders (0 rows,
  //      boundary loud); without one the lane stays honestly unavailable. Plus the ladder.
  const activeProjs = projs.filter((p) => p.status !== "retired");
  const explorerHead = activeProjs.length
    ? `<h2 id="pane-explorer">Object data &amp; Explorer <span class="pill ok">projection declared</span> <span class="pill warn">no materialized objects</span></h2>`
      + omBoundaryNote(`<b>Projection declared, no materialized objects.</b> The explorer shape below is daemon truth — what an authorized surface <b>would</b> render, search, filter, relate, and act on. There are <b>no rows</b>: object_instances stays 0 until a future materializing run executes under credential authority. The <a href="/__apps/explorer">Object Explorer reference grammar ↗</a> is secondary, never a rebound surface.`)
      + activeProjs.map((p) => omDeclaredExplorerShape(p, msets.find((m) => m.ontology_projection_id === p.id))).join("")
    : `<h2 id="pane-explorer">Object data &amp; Explorer <span class="pill muted">unavailable</span></h2>`
      + omBoundaryNote(`This ontology binds <b>no object-instance plane</b>, so there are <b>no rows to explore</b> — declare an OntologyProjection to give this lane its read/search shape; rows still require a future materializing run under credential authority. The <a href="/__apps/explorer">Object Explorer reference grammar ↗</a> is secondary, never a rebound surface.`);
  const explorerPane = explorerHead
    + `<h3 style="margin:12px 0 6px">Authority-crossing ladder <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— five declared rungs + the first live crossing; execution and rows remain</span></h3>` + omContractLadder(maps.length, pviews.length, truns.length, projs.length, lplans.length, mruns.filter((r) => ["lease_obtained", "executed"].includes(r.status)).length, csns.filter((c) => c.status === "session_obtained").length, mruns.filter((r) => r.status === "executed").length, totalInstances);

  const counts = { "object-types": ots.length, "properties": propCount, "link-types": lts.length, "action-types": nonFuncActs.length, "value-types": vts.length, "groups": 0, "interfaces": 0, "functions": funcs.length };
  const panes = objectTypesPane + propertiesPane + linkPane + actionPane + valuePane
    + omUnavailablePane("Groups", "Object-type grouping is not a daemon contract yet.", "OntologyGroup")
    + omUnavailablePane("Interfaces", "Shared type interfaces are not modeled yet.", "OntologyInterface")
    + functionsPane + healthPane + cleanupPane + configPane + resourcesPane + dataPane + explorerPane;

  const head = `<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap"><div><h1 style="margin:0">Ontology Manager</h1><p class="sub" style="margin:4px 0 0">The daemon ontology manager <b>substrate/authoring view</b> — a typed, fail-closed CanonicalObjectModel over IOI authority (object / link / action / value types · functions · health · configuration), and the create/edit lanes. The ported reference surfaces are the <a href="/__ioi/ontology/manager">Ontology Manager →</a> (schema workbench) and the <a href="/__ioi/ontology/explorer">Object Explorer →</a> (object-type + object-set catalog). This ladder also renders as a <a href="/__ioi/pipeline">Pipeline Builder →</a>. Reference grammar: <a href="/__apps/schema">Ontology Manager ↗</a> · <a href="/__apps/explorer">Object Explorer ↗</a> (secondary captures).</p></div><a class="act" href="/__ioi/odk/ontologies/new">+ New Ontology</a></div>`;
  const body = head + switcher + `<div style="display:flex;gap:20px;align-items:flex-start">${omNav(counts)}<div style="flex:1;min-width:0">${panes}</div></div>`;
  return automationsShell("Ontology Manager", body);
}

// ---- SHARED GLOBAL RAIL: MOVED VERBATIM to surfaces/chrome.mjs (imported above) — the rail is
// aligned once and certified in every port shell; it now lives with the surface modules.
// ============================ ONTOLOGY MANAGER + OBJECT EXPLORER: EXTRACTED (Ontology wave) ======
// Both certified ports live as surface modules now — surfaces/ontology-manager/index.mjs and
// surfaces/object-explorer/index.mjs — mounted through the surface registry like Pipeline.
function domainAppPayload(p) {
  const csv = (k) => (p.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
  const payload = {
    name: (p.get("name") || "domain-app").trim(),
    description: (p.get("description") || "").trim(),
    surface_descriptor_ref: (p.get("surface_descriptor_ref") || "").trim(),
    odk_manifest_ref: (p.get("odk_manifest_ref") || "").trim(),
    visibility: (p.get("visibility") || "private").trim(),
    authority_requirement_refs: csv("authority_requirement_refs"),
    operator_contract_refs: csv("operator_contract_refs"),
    receipt_obligations: csv("receipt_obligations"),
    generated_artifact_refs: csv("generated_artifact_refs"),
  };
  const pr = (p.get("project_ref") || "").trim(); if (pr) payload.project_ref = pr;
  const or = (p.get("owner_ref") || "").trim(); if (or) payload.owner_ref = or;
  return payload;
}
// Restored verbatim: #46's serve reshuffle dropped these while live call sites still reference
// them — DOMAIN_APP_VIS/domainAppPickers (domain-apps landing chips + new/edit form pickers,
// crashed GET /__ioi/domain-apps) and ODK_UI (the /__ioi/odk/<family> deep-route dispatch table;
// every ODK family form/detail route threw at request time). All referenced helpers survived the
// reshuffle; the no-undef gate (eslint.config.mjs) now pins this class at commit time.
// Family dispatch config: api path segment, single response key, form + detail + payload.
const ODK_UI = {
  "ontologies": { api: "domain-ontologies", key: "ontology", label: "Domain Ontology", payload: odkOntologyPayload, form: (ex) => renderOdkOntologyForm(ex), detail: (rec, lists) => renderOdkOntologyDetail(rec, lists) },
  "data-recipes": { api: "data-recipes", key: "data_recipe", label: "Data Recipe", payload: odkRecipePayload, form: (ex, pk, ov) => renderOdkRecipeForm(ex, pk, ov.recipe_output_kinds || []), detail: (rec, lists) => renderOdkRecipeDetail(rec, lists) },
  "surface-descriptors": { api: "surface-descriptors", key: "surface_descriptor", label: "Surface Descriptor", payload: odkDescriptorPayload, form: (ex, pk, ov) => renderOdkDescriptorForm(ex, pk, ov.composition_patterns || []), detail: (rec, lists) => renderOdkDescriptorDetail(rec, lists) },
  "manifests": { api: "manifests", key: "manifest", label: "ODK Manifest", payload: odkManifestPayload, form: (ex, pk) => renderOdkManifestForm(ex, pk), detail: (rec) => renderOdkManifestDetail(rec) },
};
const DOMAIN_APP_VIS = ["private", "org", "marketplace_candidate"];
async function domainAppPickers(descriptorRefForManifestFilter) {
  const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
  const [sd, man] = await Promise.all([J("/v1/hypervisor/odk/surface-descriptors"), J("/v1/hypervisor/odk/manifests")]);
  const descriptors = (sd.surface_descriptors || [])
    .filter((d) => d.composition_pattern === "domain_app")
    .map((d) => ({ v: d.ref, l: d.name || d.id }));
  let manifests = man.manifests || [];
  if (descriptorRefForManifestFilter) manifests = manifests.filter((m) => (m.surface_descriptor_refs || []).includes(descriptorRefForManifestFilter));
  return { descriptors, manifests: manifests.map((m) => ({ v: m.ref, l: m.name || m.id })) };
}
function renderDomainAppForm(existing, pk) {
  const ex = existing || {}; const isEdit = !!existing;
  const action = isEdit ? `/__ioi/domain-apps/${encodeURIComponent(ex.domain_app_id)}/patch` : `/__ioi/domain-apps`;
  const visOpts = DOMAIN_APP_VIS.map((v) => ({ v, l: v }));
  const manOpts = [{ v: "", l: "— none —" }, ...pk.manifests];
  const descriptorField = pk.descriptors.length
    ? odkSelectField("Surface descriptor (required — composition_pattern: domain_app)", "surface_descriptor_ref", pk.descriptors, ex.surface_descriptor_ref)
    : `<div class="field"><label>Surface descriptor (required)</label><div class="sub" style="margin:0">No <code>domain_app</code> surface descriptors yet — <a href="/__ioi/odk/surface-descriptors/new">create one in ODK</a> first.</div></div>`;
  const inner = `<p><a href="/__ioi/domain-apps">← Domain Apps</a></p><h1>${isEdit ? "Edit" : "New"} Domain App</h1>
    <p class="sub">A draft <b>candidate</b> over an ODK <code>domain_app</code> descriptor. No runtime is generated or mounted.</p>
    <form method="post" action="${action}">
      ${odkField("Name", "name", ex.name, "Lending App")}
      ${odkArea("Description", "description", ex.description)}
      <div class="two">${descriptorField}${odkSelectField("Visibility", "visibility", visOpts, ex.visibility || "private")}</div>
      <div class="two">${odkSelectField("ODK manifest (optional)", "odk_manifest_ref", manOpts, ex.odk_manifest_ref || "")}${odkField("Project ref (optional)", "project_ref", ex.project_ref)}</div>
      ${odkField("Owner ref (optional)", "owner_ref", ex.owner_ref)}
      <h2>Author-named refs <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— comma-separated; not resolved here</span></h2>
      <div class="two">${odkCsvField("Authority requirement refs", "authority_requirement_refs", ex.authority_requirement_refs)}${odkCsvField("Operator contract refs", "operator_contract_refs", ex.operator_contract_refs)}</div>
      <div class="two">${odkCsvField("Receipt obligations", "receipt_obligations", ex.receipt_obligations)}${odkCsvField("Generated artifact refs", "generated_artifact_refs", ex.generated_artifact_refs)}</div>
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft candidate"}</button> <a class="act ghost" href="/__ioi/domain-apps">Cancel</a></div>
    </form>`;
  return automationsShell(`${isEdit ? "Edit" : "New"} Domain App`, inner);
}
function renderDomainAppDetail(a, runtime, approvals, releases) {
  const enc = encodeURIComponent; const did = a.domain_app_id || "";
  const rt = runtime || null;
  const derived = (label, arr) => `<dt>${label}</dt><dd>${(arr && arr.length) ? arr.map((x) => odkRefLink(x)).join(" ") : "—"}</dd>`;
  const named = (label, arr) => `<dt>${label}</dt><dd>${(arr && arr.length) ? arr.map((x) => `<code>${CX_ESC(x)}</code>`).join(" ") : "—"}</dd>`;
  const grid = `<dl class="grid">
    <dt>Id</dt><dd><code>${CX_ESC(did)}</code></dd><dt>Ref</dt><dd><code>${CX_ESC(a.domain_app_ref)}</code></dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(a.status || "draft")}</span></dd>
    <dt>Visibility</dt><dd><span class="pill muted">${CX_ESC(a.visibility || "private")}</span></dd>
    <dt>Surface descriptor</dt><dd>${odkRefLink(a.surface_descriptor_ref)} <span class="sub" style="margin:0">(composition_pattern: domain_app)</span></dd>
    <dt>ODK manifest</dt><dd>${a.odk_manifest_ref ? odkRefLink(a.odk_manifest_ref) : "—"}</dd>
  </dl>`;
  // ---- Runtime cockpit: mount admission -> internal serving, all governed & receipted.
  const mounted = rt && rt.mounted === true;
  const serving = rt && rt.serving === true;
  const statePill = serving ? `<span class="pill ok">serving</span>` : mounted ? `<span class="pill warn">mounted</span>` : `<span class="pill muted">not mounted</span>`;
  let runtimeBody;
  if (!mounted) {
    const okApprovals = (approvals || []).filter((x) => x.status === "approved" && x.subject_ref === a.domain_app_ref);
    const okReleases = (releases || []).filter((x) => x.state === "open" && x.release_target_ref === a.domain_app_ref);
    if (okApprovals.length && okReleases.length) {
      runtimeBody = `<p class="sub" style="margin:0 0 8px">Mount requires an approved ApprovalRequest and an open ReleaseControl targeting this app.</p>
        <form method="post" action="/__ioi/domain-apps/${enc(did)}/mount"><div class="two">
          <div class="field"><label>Approval request (approved)</label><select name="approval_request_ref">${okApprovals.map((x) => `<option value="${CX_ESC(x.ref)}">${CX_ESC(x.request_kind || "approval")} · ${CX_ESC(x.id)}</option>`).join("")}</select></div>
          <div class="field"><label>Release control (open)</label><select name="release_control_ref">${okReleases.map((x) => `<option value="${CX_ESC(x.ref)}">${CX_ESC(x.id)}</option>`).join("")}</select></div>
        </div><div class="row"><button class="act" type="submit">Mount (governed admission)</button></div></form>`;
    } else {
      runtimeBody = `<div class="empty">To mount, first create an <b>approved</b> ApprovalRequest and an <b>open</b> ReleaseControl targeting <code>${CX_ESC(a.domain_app_ref)}</code> in <a href="/__ioi/governance?tab=approvals">Governance</a>.</div>`;
    }
  } else {
    const rid = rt.id || "";
    const backlinks = `<dl class="wlgrid" style="margin:8px 0"><dt class="wlk">Runtime</dt><dd class="wlv"><code>${CX_ESC(rt.ref || "")}</code></dd><dt class="wlk">Approval</dt><dd class="wlv">${odkGovLink(rt.approval_request_ref)}</dd><dt class="wlk">Release</dt><dd class="wlv">${odkGovLink(rt.release_control_ref)}</dd><dt class="wlk">Receipts</dt><dd class="wlv">${(rt.receipt_refs || []).map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") || "—"}</dd><dt class="wlk">Route</dt><dd class="wlv">${rt.internal_route_ref ? `<code>${CX_ESC(rt.internal_route_ref)}</code>` : "—"} <span class="sub" style="margin:0">(internal only)</span></dd></dl>`;
    const openBtn = serving && rt.internal_route_ref ? `<a class="act" href="${rt.internal_route_ref}">Open app →</a> ` : "";
    const serveBtn = serving
      ? `<form class="inline" method="post" action="/__ioi/domain-apps/${enc(did)}/stop-serving"><button class="act ghost" type="submit">Stop serving</button></form>`
      : `<form class="inline" method="post" action="/__ioi/domain-apps/${enc(did)}/serve"><button class="act" type="submit">Start serving</button></form>`;
    const unmountBtn = `<form class="inline" method="post" action="/__ioi/domain-apps/${enc(did)}/unmount" onsubmit="return confirm('Unmount this runtime?')"><button class="act danger" type="submit">Unmount</button></form>`;
    runtimeBody = backlinks + `<div class="row">${openBtn}${serveBtn} ${unmountBtn}</div><p class="sub" style="margin:8px 0 0">Internally served, descriptor-rendered, read-only — no external ingress, no process, no publish, no connector/object execution.</p>`;
  }
  const runtimeSection = `<h2>Runtime ${statePill}</h2>${runtimeBody}`;
  const provenance = `<h2>Derived provenance</h2><dl class="grid">${derived("Ontology refs", a.ontology_refs)}${derived("Data recipe refs", a.data_recipe_refs)}${derived("MCP contract refs", a.mcp_contract_refs)}</dl>
    <h2>Author-named refs</h2><dl class="grid">${named("Authority requirements", a.authority_requirement_refs)}${named("Operator contracts", a.operator_contract_refs)}${named("Receipt obligations", a.receipt_obligations)}${named("Generated artifacts", a.generated_artifact_refs)}</dl>`;
  const actions = `<div class="row"><a class="act ghost" href="/__ioi/domain-apps/${enc(did)}/edit">Edit draft</a> ${mounted ? "" : `<form class="inline" method="post" action="/__ioi/domain-apps/${enc(did)}/delete" onsubmit="return confirm('Delete this draft?')"><button class="act danger" type="submit">Delete draft</button></form>`}</div>`;
  return automationsShell(a.name || "Domain App", `<p><a href="/__ioi/domain-apps">← Domain Apps</a></p><h1>${CX_ESC(a.name || did)}</h1><p class="sub">DomainApp · governed mount → internal serving. ${mounted ? "" : "No runtime mounted."}</p>${actions}${runtimeSection}${grid}${provenance}`);
}
// Link an approval-request:// / release-control:// ref to the Governance tab that manages it.
function odkGovLink(ref) {
  const m = String(ref || "").match(/^(approval-request|release-control):\/\//);
  const tab = m && m[1] === "release-control" ? "releases" : "approvals";
  return ref ? `<a href="/__ioi/governance?tab=${tab}"><code>${CX_ESC(ref)}</code></a>` : "—";
}
// The internally-served, descriptor-driven, READ-ONLY generated app view.
function renderDomainAppRuntimeView(rt, dapp, descriptor, ontology) {
  const enc = encodeURIComponent;
  const d = dapp || {}; const desc = descriptor || {}; const ont = ontology || {};
  const com = ont.canonical_object_model || {};
  const pattern = desc.composition_pattern || "domain_app";
  const serving = rt && rt.serving === true;
  const chips = (arr, cls) => (arr && arr.length) ? arr.map((x) => `<span class="pill ${cls || "muted"}">${CX_ESC(x)}</span>`).join(" ") : `<span class="sub" style="margin:0">none</span>`;
  const head = `<div class="brand">IOI Hypervisor · generated domain app (read-only)</div><h1>${CX_ESC(d.name || "Domain App")}</h1>`;
  const banner = `<div class="chips"><span class="pill ${serving ? "ok" : "warn"}">${serving ? "serving" : "not serving"}</span> <span class="pill muted">pattern: ${CX_ESC(pattern)}</span> <span class="sub" style="margin:0">Internally served from the ODK surface descriptor + ontology. Read-only — object actions do not execute; no external ingress.</span></div>`;
  if (!serving) {
    return automationsShell(d.name || "Domain App", `${head}${banner}<div class="empty">This runtime is not serving. Start serving from the Domain App detail.</div><p><a href="/__ioi/domain-apps/${enc(d.domain_app_id || "")}">← Domain App</a></p>`);
  }
  const objects = com.objects || [];
  const objList = objects.length
    ? `<table><thead><tr><th>Object</th><th>Available actions (read-only)</th></tr></thead><tbody>${objects.map((o) => `<tr><td><b>${CX_ESC(o)}</b></td><td>${(com.actions || []).map((ac) => `<button class="act ghost" disabled style="opacity:.5;cursor:not-allowed">${CX_ESC(ac)}</button>`).join(" ") || "—"}</td></tr>`).join("")}</tbody></table>`
    : `<div class="empty">The ontology declares no objects yet. Add objects to <code>${CX_ESC(ont.domain || "the ontology")}</code> in ODK.</div>`;
  const model = `<h2>Domain: ${CX_ESC(ont.domain || "—")} <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">v${CX_ESC(ont.version || "")}</span></h2>
    <div class="chips"><span class="chiplabel">States</span>${chips(com.states)}</div>
    <div class="chips"><span class="chiplabel">Events</span>${chips(com.events)}</div>
    <div class="chips"><span class="chiplabel">Roles</span>${chips(com.roles)}</div>
    <h2>Objects</h2>${objList}`;
  const footer = `<p class="sub" style="margin-top:20px">Runtime <code>${CX_ESC(rt.ref || "")}</code> · descriptor <code>${CX_ESC(d.surface_descriptor_ref || "")}</code> · governed by ${odkGovLink(rt.approval_request_ref)} + ${odkGovLink(rt.release_control_ref)} · <a href="/__ioi/work-ledger">Work Ledger</a> · <a href="/__ioi/domain-apps/${enc(d.domain_app_id || "")}">← Domain App</a></p>`;
  return automationsShell(d.name || "Domain App", head + banner + model + footer);
}
function domainAppCard(a) {
  const e = encodeURIComponent;
  return `<a class="card" href="/__ioi/domain-apps/${e(a.domain_app_id)}"><div class="main"><div class="name">${CX_ESC(a.name || a.domain_app_id)} <span class="pill warn">${CX_ESC(a.status || "draft")}</span> <span class="pill muted">${CX_ESC(a.visibility || "private")}</span></div><div class="meta">→ ${CX_ESC(a.surface_descriptor_ref || "")} · mounted:false</div></div><span class="act ghost">Open →</span></a>`;
}
function renderDomainAppsLanding(ov, apps, manifests) {
  const o = ov || {}; const sub = o.substrate || {}; const dm = o.domain_apps || {};
  const note = o.status_note || "Domain Apps are draft candidates over ODK descriptors. No generated runtime is mounted.";
  const head = `<h1>Generated Apps</h1><p class="sub">Draft app <b>candidates</b> over <code>domain_app</code> surface descriptors — bind a descriptor, optionally a manifest, and set visibility. Generated apps are launchable catalog entries (authored in Studio, distributed via Marketplace); nothing here generates or mounts a running app. <a href="/__ioi/odk">Open Grounding →</a></p>`;
  const banner = `<div class="chips"><span class="pill warn">draft-only</span> <span class="sub" style="margin:0">${CX_ESC(note)}</span></div>`;
  const stat = (label, val) => `<div style="flex:1;min-width:120px;padding:12px 14px;border:1px solid #24262d;border-radius:10px;background:#15171c"><div style="font-size:22px;font-weight:700;color:#fff">${CX_ESC(String(val == null ? "—" : val))}</div><div style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(label)}</div></div>`;
  const stats = `<h2>Substrate (ODK)</h2><div class="row" style="gap:10px;align-items:stretch">${stat("domain_app descriptors", sub.odk_domain_app_descriptors)}${stat("Surface descriptors", sub.odk_surface_descriptors)}${stat("Ontologies", sub.odk_domain_ontologies)}${stat("Data recipes", sub.odk_data_recipes)}${stat("Manifests", sub.odk_manifests)}</div>`;
  const byVis = dm.by_visibility || {};
  const visChips = `<div class="chips"><span class="chiplabel">Visibility</span>${DOMAIN_APP_VIS.map((v) => `<span class="pill muted">${v}: ${byVis[v] || 0}</span>`).join("")}</div>`;
  const noDescriptors = (sub.odk_domain_app_descriptors || 0) === 0;
  const newBtn = noDescriptors
    ? `<a class="act ghost" href="/__ioi/odk/surface-descriptors/new">Create a domain_app descriptor in ODK first →</a>`
    : `<a class="act" href="/__ioi/domain-apps/new">+ New domain app</a>`;
  const section = `<h2 style="display:flex;justify-content:space-between;align-items:center">Domain Apps (${apps.length}) ${newBtn}</h2>${apps.length ? apps.map(domainAppCard).join("") : `<div class="empty">No DomainApp candidates yet.${noDescriptors ? " First author a <code>domain_app</code> surface descriptor in ODK." : ""}</div>`}`;
  // ---- Domain Blueprint candidates (domain-blueprints native, projection-only first slice).
  // A blueprint would compile a manifest's closure (ontologies + recipes + descriptors) into a
  // packaged, promotable generated app. NO persisted DomainBlueprint object exists yet — that is
  // a NAMED GAP, and these cards are a projection over real ODK manifests, mutating nothing.
  const bpCard = (m) => {
    const bound = apps.filter((a) => a.odk_manifest_ref === m.ref);
    return `<div class="card" style="display:block">
      <div class="row" style="justify-content:space-between;margin:0 0 6px"><b>${CX_ESC(m.name || m.id || "manifest")}</b><span><span class="pill muted">${(m.ontology_refs || []).length} ontolog${(m.ontology_refs || []).length === 1 ? "y" : "ies"}</span> <span class="pill muted">${(m.recipe_refs || []).length} recipes</span> <span class="pill muted">${(m.surface_descriptor_refs || []).length} descriptors</span> ${bound.length ? `<span class="pill ok">${bound.length} app candidate${bound.length === 1 ? "" : "s"} bound</span>` : `<span class="pill warn">no app candidate bound</span>`}</span></div>
      <div class="sub" style="margin:0;text-transform:none;letter-spacing:0"><code style="font-size:10.5px">${CX_ESC(m.ref || "")}</code> · would compile to a packaged blueprint; packaging/promotion is a later governed lane</div>
    </div>`;
  };
  const blueprints = `<div id="dapps-blueprint-candidates"><h2>Blueprint candidates <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— projected from real ODK manifests; no persisted DomainBlueprint object exists yet (named gap, nothing is fabricated)</span></h2>
    ${(manifests || []).length ? (manifests || []).map(bpCard).join("") : `<div class="empty">No ODK manifests yet — a manifest bundling ontologies, recipes, and descriptors is the raw material a blueprint would compile.</div>`}</div>`;
  return automationsShell("Generated Apps", head + banner + stats + visChips + section + blueprints);
}

// ---- Governance — a read-only CONTROL LENS over the daemon governance projection (estate #7).
// Renders GET /v1/hypervisor/governance/overview: the eight posture/candidate sections + a policy-
// ref coverage strip + first-class governance-gap rows. It is a projection only — no approval/
// kill-switch/release CRUD, no policy store, no Marketplace, no runtime mount, and it never shows a
// gap as "resolved". Outward links route to the owned surfaces that carry the underlying records.
// ---- Governance control cockpit helpers (Approvals inbox / Rules posture / Release-Controls lifecycle).
const GOV_FAMS = {
  "approvals": { api: "approval-requests", key: "approval_request", listKey: "approval_requests", label: "Approval Requests" },
  "releases": { api: "release-controls", key: "release_control", listKey: "release_controls", label: "Release Controls" },
  "kill-switches": { api: "kill-switches", key: "kill_switch", listKey: "kill_switches", label: "Kill Switches" },
  "gates": { api: "improvement-gates", key: "improvement_gate", listKey: "improvement_gates", label: "Improvement Gates" },
  "cohorts": { api: "cohorts", key: "cohort", listKey: "cohorts", label: "Cohorts" },
};
const govTabBar = (tab) => `<div class="tabs">${[["overview", "Overview"], ["approvals", "Approval Requests"], ["releases", "Release Controls"], ["kill-switches", "Kill Switches"], ["gates", "Improvement Gates"], ["cohorts", "Cohorts"]].map(([k, l]) => `<a class="tab${tab === k ? " active" : ""}" href="/__ioi/governance?tab=${k}" style="text-decoration:none">${l}</a>`).join("")}</div>`;
const GOV_INP = 'style="width:100%;box-sizing:border-box;padding:8px 10px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit"';
const govTform = (fam, id, transition, label, cls, extra) => `<form class="inline" method="post" action="/__ioi/governance/${fam}/${encodeURIComponent(id)}/transition"><input type="hidden" name="transition" value="${transition}">${extra || ""}<button class="act ${cls || "ghost"}" type="submit">${label}</button></form>`;
const govDform = (fam, id) => `<form class="inline" method="post" action="/__ioi/governance/${fam}/${encodeURIComponent(id)}/delete" onsubmit="return confirm('Delete this control record?')"><button class="act danger" type="submit">Delete</button></form>`;
const govRefs = (arr) => (arr && arr.length) ? arr.map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") : "—";
function govApprovalCard(a) {
  const id = a.id || ""; const stp = a.status === "approved" ? "ok" : a.status === "pending" ? "warn" : "muted";
  const actions = a.status === "pending"
    ? govTform("approvals", id, "approve", "Approve", "", `<input name="reviewer_ref" placeholder="reviewer" style="width:120px;padding:6px 8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit;margin-right:6px">`) + " " + govTform("approvals", id, "reject", "Reject", "ghost")
    : a.status === "approved" ? govTform("approvals", id, "revoke", "Revoke", "ghost") : "";
  return `<div class="card" style="display:block"><div class="row" style="justify-content:space-between;margin:0 0 8px"><div><b>${CX_ESC(a.request_kind || "approval")}</b> <span class="pill ${stp}">${CX_ESC(a.status || "")}</span> <code>${CX_ESC(id)}</code></div>${govDform("approvals", id)}</div>
    <dl class="wlgrid"><dt class="wlk">Target</dt><dd class="wlv">${CX_ESC(a.subject_ref || "—")}</dd><dt class="wlk">Reason</dt><dd class="wlv">${CX_ESC(a.reason || "—")}</dd><dt class="wlk">Reviewer</dt><dd class="wlv">${CX_ESC(a.reviewer_ref || "—")}${a.decided_at ? " · " + CX_ESC(a.decided_at) : ""}</dd><dt class="wlk">Authority refs</dt><dd class="wlv">${govRefs(a.required_authority_refs)}</dd></dl>
    <div class="row" style="margin-top:8px">${actions || `<span class="sub" style="margin:0">terminal state</span>`}</div></div>`;
}
function govReleaseCard(r) {
  const id = r.id || ""; const open = r.state === "open";
  const actions = (open ? govTform("releases", id, "close", "Close gate", "ghost") : govTform("releases", id, "open", "Open gate", "")) + " " + govTform("releases", id, "request_rollback", "Request rollback", "ghost") + " " + govTform("releases", id, "request_recall", "Request recall", "ghost");
  return `<div class="card" style="display:block"><div class="row" style="justify-content:space-between;margin:0 0 8px"><div><b>Release gate</b> <span class="pill ${open ? "ok" : "muted"}">${CX_ESC(r.state || "closed")}</span> <code>${CX_ESC(id)}</code></div>${govDform("releases", id)}</div>
    <dl class="wlgrid"><dt class="wlk">Target</dt><dd class="wlv">${CX_ESC(r.release_target_ref || "—")}</dd><dt class="wlk">Rollout</dt><dd class="wlv"><span class="pill ${r.rollout_mode === "full" || !r.rollout_mode ? "muted" : "warn"}">${CX_ESC(r.rollout_mode || "full")}</span>${r.canary_percent != null ? ` <span class="pill muted">${CX_ESC(String(r.canary_percent))}%</span>` : ""}${(r.cohort_refs || []).map((x) => ` <code>${CX_ESC(x)}</code>`).join("")}${(r.deprecated_raw_cohort_refs || []).length ? ` <span class="pill warn" title="${CX_ESC(r.cohort_refs_deprecation || "")}">deprecated raw refs</span>` : ""}${r.promoted_at ? ` <span class="pill ok">promoted</span>` : ""}${r.rollback_state ? ` <span class="pill muted">${CX_ESC(r.rollback_state)}</span>` : ""}</dd><dt class="wlk">Flags</dt><dd class="wlv">${r.rollback_requested ? `<span class="pill warn">rollback requested</span>` : ""} ${r.recall_requested ? `<span class="pill warn">recall requested</span>` : ""} ${!r.rollback_requested && !r.recall_requested ? "—" : ""}</dd></dl>
    <div class="row" style="margin-top:8px">${actions}</div></div>`;
}
function govKillCard(k) {
  const id = k.id || ""; const tripped = k.state === "tripped";
  const enfState = k.enforcement_state || null;
  const trans = tripped ? govTform("kill-switches", id, "rearm", "Re-arm", "ghost") : govTform("kill-switches", id, "trip", "Trip", "danger", `<input name="trip_reason" placeholder="reason" style="width:120px;padding:6px 8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit;margin-right:6px">`);
  // Enforce is a SEPARATE effectful step, only available once tripped.
  const enforceBtn = tripped
    ? `<form class="inline" method="post" action="/__ioi/governance/kill-switches/${encodeURIComponent(id)}/enforce" onsubmit="return confirm('Enforce this kill switch? This stops/unmounts the target domain-app runtime(s).')"><button class="act danger" type="submit">Enforce</button></form>`
    : "";
  const enfPill = enfState ? `<span class="pill ${enfState === "enforced" ? "ok" : enfState === "failed" ? "warn" : "muted"}">enforcement: ${CX_ESC(enfState)}</span>` : "";
  const enfBlock = enfState
    ? `<dl class="wlgrid" style="margin:8px 0 0"><dt class="wlk">Enforced</dt><dd class="wlv">${CX_ESC(k.enforced_at || "")} · ${CX_ESC(k.enforcement_result || "")}</dd><dt class="wlk">Affected</dt><dd class="wlv">${(k.affected_runtime_refs || []).map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") || "—"}</dd><dt class="wlk">Receipts</dt><dd class="wlv">${(k.enforcement_receipt_refs || []).map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") || "—"}</dd></dl>`
    : "";
  return `<div class="card" style="display:block"><div class="row" style="justify-content:space-between;margin:0 0 8px"><div><b>Kill switch</b> <span class="pill ${tripped ? "warn" : "muted"}">${CX_ESC(k.state || "armed")}</span> ${enfPill} <code>${CX_ESC(id)}</code></div>${govDform("kill-switches", id)}</div>
    <dl class="wlgrid"><dt class="wlk">Subject</dt><dd class="wlv">${CX_ESC(k.subject_ref || "—")}</dd><dt class="wlk">Revoke path</dt><dd class="wlv">${k.revoke_path ? `<code>${CX_ESC(k.revoke_path)}</code>` : "—"}</dd><dt class="wlk">Reason</dt><dd class="wlv">${CX_ESC(k.trip_reason || "—")}${k.tripped_at ? " · " + CX_ESC(k.tripped_at) : ""}</dd></dl>${enfBlock}
    <p class="sub" style="margin:6px 0 0">Trip records the kill decision; Enforce mutates eligible domain-app runtime targets (stop serving + unmount). Enforce is available only after trip.</p>
    <div class="row" style="margin-top:8px">${trans} ${enforceBtn}</div></div>`;
}
function govGateCard(g) {
  const id = g.id || ""; const b = g.bounds || {}; const stp = g.state === "closed" ? "ok" : g.state === "bounded" ? "warn" : "muted";
  const actions = g.state === "open" ? govTform("gates", id, "bound", "Set bounded", "") : g.state === "bounded" ? govTform("gates", id, "close", "Close", "ghost") + " " + govTform("gates", id, "reopen", "Reopen", "ghost") : govTform("gates", id, "reopen", "Reopen", "ghost");
  return `<div class="card" style="display:block"><div class="row" style="justify-content:space-between;margin:0 0 8px"><div><b>Improvement gate</b> <span class="pill ${stp}">${CX_ESC(g.state || "open")}</span> <code>${CX_ESC(id)}</code></div>${govDform("gates", id)}</div>
    <dl class="wlgrid"><dt class="wlk">Subject</dt><dd class="wlv">${CX_ESC(g.subject_ref || "—")}</dd><dt class="wlk">Bounds</dt><dd class="wlv">max_iter ${CX_ESC(String(b.max_iterations ?? "—"))} · eval≥ ${CX_ESC(String(b.eval_threshold ?? "—"))} · privacy ${CX_ESC(String(b.privacy_posture ?? "—"))}</dd><dt class="wlk">Rollback · promotion</dt><dd class="wlv">${b.rollback_ref ? `<code>${CX_ESC(b.rollback_ref)}</code>` : "—"} · ${b.promotion_policy_ref ? `<code>${CX_ESC(b.promotion_policy_ref)}</code>` : "—"}</dd></dl>
    <div class="row" style="margin-top:8px">${actions}</div></div>`;
}
function govCohortCard(c) {
  const id = c.id || ""; const active = c.status === "active";
  const actions = active ? govTform("cohorts", id, "disable", "Disable", "ghost") : govTform("cohorts", id, "enable", "Enable", "");
  return `<div class="card" style="display:block" data-cohort="${CX_ESC(id)}"><div class="row" style="justify-content:space-between;margin:0 0 8px"><div><b>${CX_ESC(c.display_name || "cohort")}</b> <span class="pill ${active ? "ok" : "muted"}">${CX_ESC(c.status || "")}</span> <span class="pill muted">${CX_ESC(c.scope || "")}</span> <code>${CX_ESC(c.ref || id)}</code></div>${govDform("cohorts", id)}</div>
    <dl class="wlgrid"><dt class="wlk">Members</dt><dd class="wlv">${govRefs(c.member_refs)}</dd><dt class="wlk">Description</dt><dd class="wlv">${CX_ESC(c.description || "—")}</dd><dt class="wlk">Evidence</dt><dd class="wlv">${govRefs(c.evidence_refs)}</dd></dl>
    <p class="sub" style="margin:6px 0 0">Rollout eligibility matches member refs against DAEMON-DERIVED context (authenticated principal · known project) — never arbitrary caller text. Disabled cohorts never match.</p>
    <div class="row" style="margin-top:8px">${actions}</div></div>`;
}
// ---- Approvals queue (06-approvals graft) — the review-inbox grammar over the REAL
// ApprovalRequest records: quick-filter inbox chips with counts, an enriched queue table
// (target resolution link, blast radius from the record's own would_call/required_authority_refs,
// age), a right proof/detail drawer, and in-row decisions. Everything rendered is a record field;
// there is no requester column because the record does not carry one (single-operator estate —
// shown honestly in the drawer). Decisions are the existing daemon transitions.
function govSubjectLink(ref) {
  const r = String(ref || "");
  if (!r) return "—";
  const code = `<code style="font-size:10.5px">${CX_ESC(r)}</code>`;
  if (r.startsWith("domain-app://")) return `<a href="/__ioi/domain-apps/${encodeURIComponent(r.slice("domain-app://".length))}" style="text-decoration:none">${code} →</a>`;
  if (r.startsWith("marketplace-")) return `<a href="/__ioi/marketplace" style="text-decoration:none">${code} →</a>`;
  if (r.startsWith("failover-run://")) return `<a href="/__ioi/operations" style="text-decoration:none">${code} →</a>`;
  if (r.startsWith("fspec_") || r.startsWith("frun_")) return `<a href="/__ioi/foundry" style="text-decoration:none">${code} →</a>`;
  return code;
}
function govAge(iso) {
  const ms = Date.now() - Date.parse(iso || "");
  if (!isFinite(ms) || ms < 0) return "—";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d`;
}
// ============================ APPROVALS INBOX: EXTRACTED to surfaces/approvals/index.mjs =======
// (operational wave PR62 — the governed-action-runtime pilot; the registry mounts GET + actions).
function govApprovalsQueue(records) {
  const enc = encodeURIComponent;
  const byStatus = { pending: 0, approved: 0, rejected: 0, revoked: 0 };
  for (const a of records) if (byStatus[a.status] != null) byStatus[a.status]++;
  const pend = records.filter((a) => a.status === "pending");
  const oldest = pend.length ? pend.reduce((o, a) => (String(a.created_at || "") < String(o.created_at || "") ? a : o)) : null;
  const kinds = {};
  for (const a of pend) kinds[a.request_kind || "approval"] = (kinds[a.request_kind || "approval"] || 0) + 1;
  const chip = (val, label, n, on) => `<button class="chip${on ? " on" : ""}" data-aq-status="${val}" onclick="aqChip(this)">${label} ${n}</button>`;
  const inbox = `<div class="chips" id="aq-inbox">
    ${chip("pending", "Needs decision", byStatus.pending, true)}${chip("approved", "Approved", byStatus.approved, false)}${chip("rejected", "Rejected", byStatus.rejected, false)}${chip("revoked", "Revoked", byStatus.revoked, false)}${chip("", "All", records.length, false)}
    <span class="sub" style="margin:0 0 0 8px">${pend.length ? `oldest pending <b>${govAge(oldest.created_at)}</b> · ${Object.entries(kinds).map(([k, n]) => `${CX_ESC(k)} ×${n}`).join(" · ")}` : "nothing waiting on a decision"} · <a href="/__apps/approvals" target="_blank" rel="noopener">harvest seed preview ↗</a></span>
  </div>`;
  const blast = (a) => {
    const wc = (a.would_call || []).length, ar = (a.required_authority_refs || []).length;
    if (!wc && !ar) return `<span class="sub" style="margin:0">none declared</span>`;
    return `${wc ? `<span class="pill warn">${wc} call${wc > 1 ? "s" : ""}</span>` : ""} ${ar ? `<span class="pill muted">${ar} authorit${ar > 1 ? "ies" : "y"}</span>` : ""}`;
  };
  const decide = (a) => a.status === "pending"
    ? govTform("approvals", a.id, "approve", "Approve", "", `<input name="reviewer_ref" placeholder="reviewer" style="width:96px;padding:5px 8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit;font-size:11.5px;margin-right:4px">`) + " " + govTform("approvals", a.id, "reject", "Reject", "ghost")
    : a.status === "approved" ? govTform("approvals", a.id, "revoke", "Revoke", "ghost") : `<span class="sub" style="margin:0">terminal</span>`;
  const rows = records.map((a, i) => `<tr class="wlrow" data-aq="${CX_ESC(a.status || "")}" data-i="${i}" onclick="aqOpen(${i})" style="${a.status !== "pending" ? "display:none" : ""}">
      <td><b>${CX_ESC(a.request_kind || "approval")}</b><div style="color:#878a93;font-size:11px;margin-top:1px">${CX_ESC(String(a.reason || "").slice(0, 64) || "no reason recorded")} · <code style="font-size:10px">${CX_ESC(a.id || "")}</code></div></td>
      <td onclick="event.stopPropagation()">${govSubjectLink(a.subject_ref)}</td>
      <td>${blast(a)}</td>
      <td title="${CX_ESC(a.created_at || "")}">${govAge(a.created_at)}</td>
      <td><span class="pill ${a.status === "approved" ? "ok" : a.status === "pending" ? "warn" : "muted"}">${CX_ESC(a.status || "")}</span></td>
      <td onclick="event.stopPropagation()">${decide(a)}</td>
    </tr>`).join("");
  const table = records.length
    ? `<div class="wlwrap"><div><table><thead><tr><th>Request</th><th>Target</th><th>Blast radius</th><th>Age</th><th>Status</th><th>Decide</th></tr></thead><tbody id="aq-body">${rows}</tbody></table><div class="empty" id="aq-empty" style="display:${byStatus.pending ? "none" : ""}">Nothing in this view — pick another inbox chip.</div></div>
       <div class="wldrawer" id="aq-drawer"><div class="sub" style="margin:0">Select a request to inspect its full record — blast radius, policy posture, decision history.</div></div></div>`
    : `<div class="empty">No approval requests yet — governed work creates them when it parks at a gate, or record one below.</div>`;
  const gaps = omBoundaryNote(`This is the <b>real decision queue</b> over daemon ApprovalRequest records — status counts, blast radius, age, per-row inspector, and in-row decisions are daemon truth. Unsupported reference lanes — <b>reviewer assignment</b>, delegation, threaded comments, SLA/escalation timers, identity/team review workflows, audit exports — are <b>named gaps</b> (no authority contract yet), not hidden. The <a href="/__apps/approvals">approvals reference capture ↗</a> is the familiar baseline, never a rebound surface.`);
  const dataTag = `<script id="aq-data" type="application/json">${JSON.stringify(records).replace(/</g, "\\u003c")}</script>`;
  const script = `<script>
    var AQ=[];try{AQ=JSON.parse(document.getElementById('aq-data').textContent||'[]');}catch(e){}
    function aqEsc(s){return String(s==null?'':s).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});}
    function aqChip(b){
      document.querySelectorAll('#aq-inbox .chip').forEach(function(x){x.classList.toggle('on',x===b);});
      var want=b.getAttribute('data-aq-status');var shown=0;
      document.querySelectorAll('#aq-body .wlrow').forEach(function(r){var on=!want||r.getAttribute('data-aq')===want;r.style.display=on?'':'none';if(on)shown++;});
      var e=document.getElementById('aq-empty');if(e)e.style.display=shown?'none':'';
    }
    function aqRow(k,v){return v?'<div class="wlk">'+aqEsc(k)+'</div><div class="wlv">'+v+'</div>':'';}
    function aqOpen(i){
      var a=AQ[i];if(!a)return;
      document.querySelectorAll('#aq-body .wlrow').forEach(function(x){x.classList.toggle('selrow',x.getAttribute('data-i')==String(i));});
      var h='<h3>'+aqEsc(a.request_kind||'approval')+' <span class="pill '+(a.status==='approved'?'ok':a.status==='pending'?'warn':'muted')+'">'+aqEsc(a.status)+'</span></h3>';
      h+='<h4>Request</h4><div class="wlgrid">'+aqRow('Ref','<code>'+aqEsc(a.ref||a.id)+'</code>')+aqRow('Target','<code>'+aqEsc(a.subject_ref)+'</code>')+aqRow('Reason',aqEsc(a.reason||'not recorded'))+aqRow('Created',aqEsc(a.created_at))+aqRow('Requester','<span style="color:#878a93">not recorded — single-operator estate</span>')+'</div>';
      h+='<h4>Blast radius</h4>';
      var wc=a.would_call||[];var ar=a.required_authority_refs||[];
      h+=wc.length?('<div class="wlgrid">'+wc.map(function(c,j){return aqRow('would call '+(j+1),'<code style="font-size:10.5px">'+aqEsc(typeof c==='string'?c:JSON.stringify(c))+'</code>');}).join('')+'</div>'):'<div class="sub" style="margin:0">no calls declared</div>';
      h+=ar.length?('<div class="wlgrid" style="margin-top:6px">'+ar.map(function(c,j){return aqRow('authority '+(j+1),'<code style="font-size:10.5px">'+aqEsc(c)+'</code>');}).join('')+'</div>'):'';
      if(a.enforcement_preview){h+='<h4>Policy posture</h4><pre style="font-size:10.5px;max-height:140px;overflow:auto">'+aqEsc(JSON.stringify(a.enforcement_preview,null,1))+'</pre>';}
      h+='<h4>Decision</h4><div class="wlgrid">'+aqRow('Reviewer',aqEsc(a.reviewer_ref||'—'))+aqRow('Decided',aqEsc(a.decided_at||'—'))+aqRow('Updated',aqEsc(a.updated_at||'—'))+'</div>';
      document.getElementById('aq-drawer').innerHTML=h;
    }
  </script>`;
  return inbox + table + gaps + dataTag + script;
}
function govControlTab(fam, records, cohorts, joins) {
  const forms = {
    "approvals": `<div class="two">${`<div class="field"><label>Target ref (required)</label><input name="subject_ref" ${GOV_INP} placeholder="marketplace-publish://… · domain-app://… · frun_… · authority-action://…"></div>`}<div class="field"><label>Request kind</label><input name="request_kind" ${GOV_INP} placeholder="crossing / publish / mount"></div></div><div class="field"><label>Reason</label><input name="reason" ${GOV_INP}></div><div class="field"><label>Required authority refs (comma-sep)</label><input name="required_authority_refs" ${GOV_INP}></div>`,
    "releases": `<div class="field"><label>Release target ref (required)</label><input name="release_target_ref" ${GOV_INP} placeholder="frun_… · improvement-proposal://… · domain-app://… · marketplace-publish://…"></div>
      <div class="two"><div class="field"><label>Rollout mode</label><select name="rollout_mode" ${GOV_INP}><option value="full">full — everyone behind the gate</option><option value="canary">canary — deterministic percentage</option><option value="cohort">cohort — named cohort objects</option></select></div><div class="field"><label>Canary percent (0–100)</label><input name="canary_percent" ${GOV_INP} placeholder="25"></div></div>
      <div class="field"><label>Cohorts (rollout audience — durable cohort:// objects)</label><select name="cohort_refs" multiple size="3" ${GOV_INP}>${(cohorts || []).map((c) => `<option value="${CX_ESC(c.ref)}">${CX_ESC(c.display_name)} · ${CX_ESC(c.scope)} · ${CX_ESC(c.status)}</option>`).join("")}</select>${(cohorts || []).length ? "" : `<div class="sub" style="margin:4px 0 0">No cohorts yet — create one in the Cohorts tab.</div>`}</div>`,
    "kill-switches": `<div class="two"><div class="field"><label>Revocable subject ref (required)</label><input name="subject_ref" ${GOV_INP} placeholder="lease:… · connector:… · agent id · domain-app://…"></div><div class="field"><label>Revoke path (named, not called)</label><input name="revoke_path" ${GOV_INP} placeholder="/v1/hypervisor/authority/revoke"></div></div>`,
    "cohorts": `<div class="two"><div class="field"><label>Display name (required)</label><input name="display_name" ${GOV_INP} placeholder="Canary team"></div><div class="field"><label>Scope</label><select name="scope" ${GOV_INP}><option value="project">project</option><option value="personal">personal</option><option value="org">org</option></select></div></div><div class="field"><label>Member refs (comma-sep: principal:// · project:// · org:// · environment:// · ioi-agent-policy://)</label><input name="member_refs" ${GOV_INP} placeholder="principal://usr_… , project://project:…"></div><div class="field"><label>Description</label><input name="description" ${GOV_INP}></div>`,
    "gates": `<div class="field"><label>Subject ref (required — Foundry spec/run-plan or named)</label><input name="subject_ref" ${GOV_INP} placeholder="fspec_… · frun_… · eval://…"></div><div class="two"><div class="field"><label>Max iterations</label><input name="max_iterations" ${GOV_INP}></div><div class="field"><label>Eval threshold</label><input name="eval_threshold" ${GOV_INP}></div></div><div class="field"><label>Privacy posture</label><input name="privacy_posture" ${GOV_INP} placeholder="local_only"></div>`,
  };
  const cardFn = { "approvals": govApprovalCard, "releases": govReleaseCard, "kill-switches": govKillCard, "gates": govGateCard, "cohorts": govCohortCard }[fam];
  const label = GOV_FAMS[fam].label;
  // ---- Cross-capability lifecycle matrix (release-controls native, first slice): each release
  // gate joined to its target's LIVE object state — a gate over a serving app and a gate over a
  // draft spec are different risks, and the matrix says which is which. Targets without a local
  // join render as named refs, never guessed states.
  const govLiveState = (ref) => {
    const j = joins || {};
    const r = String(ref || "");
    if (r.startsWith("domain-app://")) {
      const a = (j.domain_apps || []).find((x) => x.domain_app_ref === r);
      if (!a) return ["unresolved", "warn"];
      const rt = a.runtime_posture || {};
      return [rt.serving ? "serving (internal)" : rt.mounted ? "mounted" : a.status || "draft", rt.serving || rt.mounted ? "ok" : "muted"];
    }
    if (r.startsWith("marketplace-publish://")) {
      const c = (j.publish_candidates || []).find((x) => x.ref === r || `marketplace-publish://${x.id}` === r);
      return c ? [c.status || "candidate", c.status === "published" ? "ok" : "muted"] : ["unresolved", "warn"];
    }
    if (r.startsWith("marketplace-listing://")) {
      const l = (j.listings || []).find((x) => x.ref === r || `marketplace-listing://${x.id}` === r);
      return l ? [l.status || "listed", "muted"] : ["unresolved", "warn"];
    }
    if (r.startsWith("fspec_")) {
      const s = (j.foundry_specs || []).find((x) => x.id === r);
      return s ? [s.status || "draft", "muted"] : ["unresolved", "warn"];
    }
    if (r.startsWith("frun_")) {
      const pl = (j.foundry_plans || []).find((x) => x.id === r);
      return pl ? [pl.status || "draft", "muted"] : ["unresolved", "warn"];
    }
    return ["named ref — no local join", "muted"];
  };
  const lifecycleMatrix = fam === "releases" && records.length ? `<div id="gov-lifecycle-matrix"><h2>Lifecycle matrix <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— every release gate against its target's live state; unjoined targets stay named, never guessed</span></h2>
    <table><thead><tr><th>Target</th><th>Gate</th><th>Rollout</th><th>Live state</th><th>Promotion</th><th>Flags</th></tr></thead><tbody>
    ${records.map((rc) => {
      const [live, liveCls] = govLiveState(rc.release_target_ref);
      return `<tr>
        <td><code style="font-size:10.5px">${CX_ESC(rc.release_target_ref || "—")}</code></td>
        <td><span class="pill ${rc.state === "open" ? "ok" : "muted"}">${CX_ESC(rc.state || "closed")}</span></td>
        <td>${CX_ESC(rc.rollout_mode || "full")}${rc.canary_percent != null ? ` ${CX_ESC(String(rc.canary_percent))}%` : ""}</td>
        <td><span class="pill ${liveCls}">${CX_ESC(live)}</span></td>
        <td>${rc.promoted_at ? `<span class="pill ok">promoted</span>` : "—"}</td>
        <td>${rc.rollback_requested ? `<span class="pill warn">rollback</span>` : ""}${rc.recall_requested ? ` <span class="pill warn">recall</span>` : ""}${!rc.rollback_requested && !rc.recall_requested ? "—" : ""}</td>
      </tr>`;
    }).join("")}</tbody></table></div>` : "";
  // Approvals renders as the review-inbox QUEUE (06-approvals graft); other families keep cards.
  const list = fam === "approvals" ? govApprovalsQueue(records)
    : fam === "releases" ? lifecycleMatrix + (records.length ? records.map(cardFn).join("") : `<div class="empty">Control present · empty — no ${CX_ESC(label.toLowerCase())} recorded yet.</div>`)
    : records.length ? records.map(cardFn).join("") : `<div class="empty">Control present · empty — no ${CX_ESC(label.toLowerCase())} recorded yet.</div>`;
  return `<h2>New ${CX_ESC(label.replace(/s$/, ""))}</h2><form method="post" action="/__ioi/governance/${fam}"><div class="card" style="display:block">${forms[fam]}<div class="row" style="margin-top:6px"><button class="act" type="submit">Create (record-only)</button></div></div></form>
    <h2>${CX_ESC(label)} (${records.length})</h2>${list}
    <p class="sub" style="margin-top:14px">Transitions record durable governance state. Effectful enforcement exists today for <b>KillSwitch</b> (Enforce, after trip) over domain-app runtimes; other control effects (lease/grant/connector/env revocation) remain later authority-gated crossings.</p>`;
}
function renderGovernance(ov, controls, tab, joins) {
  const o = ov || {};
  tab = tab || "overview";
  controls = controls || {};
  const sub = o.summary || {};
  const ap = o.authority_posture || {};
  const ip = o.identity_posture || {};
  const lp = o.lease_posture || {};
  const aa = o.approval_and_admission_posture || {};
  const prc = o.policy_ref_coverage || {};
  const rc = o.release_control_candidates || {};
  const rt = o.revocation_targets || {};
  const ig = o.improvement_gate_candidates || {};
  const gaps = o.governance_gaps || [];
  const boolPill = (v, onLabel, offLabel) => `<span class="pill ${v === true ? "ok" : "muted"}">${v === true ? (onLabel || "yes") : (offLabel || "no")}</span>`;
  const histChips = (obj, cls) => { const e = Object.entries(obj || {}); return e.length ? e.map(([k, n]) => `<span class="pill ${cls || "muted"}">${CX_ESC(k)}: ${CX_ESC(String(n))}</span>`).join(" ") : `<span class="sub" style="margin:0">none</span>`; };
  const stat = (label, val) => `<div style="flex:1;min-width:112px;padding:12px 14px;border:1px solid #24262d;border-radius:10px;background:#15171c"><div style="font-size:22px;font-weight:700;color:#fff">${CX_ESC(String(val == null ? "—" : val))}</div><div style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(label)}</div></div>`;

  const head = `<h1>Governance</h1><p class="sub">A horizontal control lens over real authority, identity, lease and admission substrate. It surfaces posture, what can be revoked, what a release/improvement gate would govern, and — plainly — the controls that do not exist yet. It reads only; it mutates nothing.</p><p class="sub" style="margin:-8px 0 0"><a href="/__ioi/governance/approvals">▶ Open the Approvals inbox →</a> (the ported reference UX over the real ApprovalRequest queue)</p>`;
  const banner = `<div class="chips"><span class="pill muted">projection-only</span> <span class="sub" style="margin:0">${CX_ESC(o.status_note || "Read projection; creates and mutates nothing.")}</span></div>`;
  const summary = `<div class="row" style="gap:10px;align-items:stretch">
    ${stat("Grants active", `${sub.authority_grants_active ?? "—"} / ${sub.authority_grants_total ?? "—"}`)}
    ${stat("Leases active", `${sub.capability_leases_active ?? "—"} / ${sub.capability_leases_total ?? "—"}`)}
    ${stat("Wallet-gated crossings", sub.wallet_required_crossings)}
    ${stat("Auth enforced", sub.auth_enforced === true ? "yes" : "no")}
    ${stat("Connectors", sub.connectors)}
    ${stat("Governance gaps", sub.governance_gaps)}
  </div>`;

  // 1. Authority posture
  const authGrid = `<dl class="grid">
    <dt>Mode</dt><dd>${CX_ESC(ap.mode || "—")} <span class="sub" style="margin:0">(${CX_ESC(ap.provider || "")})</span></dd>
    <dt>Wallet network</dt><dd>${boolPill(ap.wallet_network_live, "live", "offline")}</dd>
    <dt>Grants</dt><dd>active ${CX_ESC(String((ap.grants || {}).active ?? "—"))} · granted ${CX_ESC(String((ap.grants || {}).granted ?? "—"))} · revoked ${CX_ESC(String((ap.grants || {}).revoked ?? "—"))} · total ${CX_ESC(String((ap.grants || {}).total ?? "—"))}</dd>
    <dt>Standing grants</dt><dd>${(ap.standing_grants || []).length ? (ap.standing_grants || []).map((g) => `<span class="pill ok">${CX_ESC(g.scope || g.ref || "")}</span>`).join(" ") : "—"}</dd>
    <dt>Providers</dt><dd>${(ap.providers || []).map((p) => `<span class="pill ${p.live ? "ok" : "muted"}">${CX_ESC(p.provider_ref || p.mode || "")}${p.status ? " · " + CX_ESC(p.status) : ""}</span>`).join(" ") || "—"}</dd>
    <dt>Wallet-gated crossings</dt><dd>${(ap.wallet_required_crossings || []).map((c) => `<span class="pill warn">${CX_ESC(c)}</span>`).join(" ") || "—"}</dd>
  </dl>`;

  // 2. Identity posture
  const pol = ip.policy || {}; const cp = ip.current_principal || {};
  const posture = ip.deployment_auth_posture || "";
  const posturePill = posture === "authenticated_managed" ? `<span class="pill ok">authenticated_managed</span>`
    : posture === "exposed_untrusted" ? `<span class="pill warn">exposed_untrusted</span>`
    : `<span class="pill muted">${CX_ESC(posture || "local_development")}</span>`;
  const rtrust = ip.rollout_trust || {};
  const idGrid = `<dl class="grid">
    <dt>Deployment posture</dt><dd id="auth-posture">${posturePill} · rollout trust ${rtrust.high_trust_required ? `<span class="pill warn">high-trust sources required</span>` : `<span class="pill muted">local-dev sources allowed</span>`} · explicit override ${rtrust.explicit_override_allowed ? `<span class="pill muted">allowed (labeled)</span>` : `<span class="pill warn">fails closed</span>`}<div class="sub" style="margin:4px 0 0;text-transform:none;letter-spacing:0">${CX_ESC(rtrust.note || "")}</div></dd>
    <dt>Enforcement</dt><dd>${boolPill(ip.effective_enforced, "enforced", "not enforced")} · exposed ${boolPill(ip.exposed, "yes", "no")} · login ${boolPill(ip.login_possible, "possible", "off")}</dd>
    <dt>Policy</dt><dd>mode ${CX_ESC(pol.mode || "—")} · require_auth ${CX_ESC(String(pol.require_authentication ?? "—"))}${(pol.allowed_methods || []).length ? " · methods " + (pol.allowed_methods || []).map((m) => `<code>${CX_ESC(m)}</code>`).join(" ") : ""}</dd>
    <dt>Current principal</dt><dd>authenticated ${boolPill(cp.authenticated, "yes", "no")}${cp.role ? " · role <code>" + CX_ESC(cp.role) + "</code>" : ""}${cp.status ? " · " + CX_ESC(cp.status) : ""}</dd>
  </dl>`;

  // 3. Lease posture
  const leaseGrid = `<dl class="grid">
    <dt>Leases</dt><dd>active ${CX_ESC(String(lp.active ?? "—"))} · revoked ${CX_ESC(String(lp.revoked ?? "—"))} · receipt-required ${CX_ESC(String(lp.receipt_required ?? "—"))} · total ${CX_ESC(String(lp.total ?? "—"))}</dd>
    <dt>By backing provider</dt><dd>${histChips(lp.by_backing_provider)}</dd>
  </dl>`;

  // 4. Approval & admission
  const admGrid = `<dl class="grid">
    <dt>Admission-gated crossings</dt><dd>${CX_ESC(String(aa.admission_gated_crossings_count ?? "—"))} (require wallet authority)</dd>
    <dt>Authority decisions</dt><dd>${histChips(aa.authority_decisions)} · <a href="/__ioi/work-ledger">proof stream →</a></dd>
    <dt>Connectors requiring credential</dt><dd>${CX_ESC(String(aa.connectors_requiring_credential ?? "—"))} · <a href="/__ioi/connections">Developer &amp; Integrations →</a></dd>
  </dl><p class="sub" style="margin:6px 0 0">${CX_ESC(aa.note || "")}</p>`;

  // policy_ref coverage strip
  const cov = (label, got, total) => `<span class="pill ${(got || 0) > 0 ? "ok" : "muted"}">${label}: ${CX_ESC(String(got ?? 0))}/${CX_ESC(String(total ?? 0))}</span>`;
  const coverage = `<div class="chips"><span class="chiplabel">Policy-ref coverage</span>${cov("automations", prc.automations_with_authority_or_runtime_policy, prc.automations_total)} ${cov("foundry specs", prc.foundry_specs_with_authority_policy, prc.foundry_specs_total)} ${cov("domain apps", prc.domain_apps_with_authority_requirements, prc.domain_apps_total)} ${cov("odk manifests", prc.odk_manifests_with_operator_contracts, prc.odk_manifests_total)}</div>`;

  // 5. Release control candidates
  const relGrid = `<dl class="grid">
    <dt>Foundry run plans</dt><dd>${CX_ESC(String(rc.foundry_run_plans ?? "—"))} <span class="pill muted">candidate</span> · <a href="/__ioi/foundry">Foundry →</a></dd>
    <dt>Domain App candidates</dt><dd>${CX_ESC(String(rc.domain_app_candidates ?? "—"))} <span class="pill muted">candidate</span> · <a href="/__ioi/domain-apps">Domain Apps →</a></dd>
    <dt>SCM publish connectors</dt><dd>${CX_ESC(String(rc.scm_publish_connectors ?? "—"))} · <a href="/__ioi/connections">Connections →</a></dd>
  </dl><p class="sub" style="margin:6px 0 0">${CX_ESC(rc.note || "")}</p>`;

  // 6. Revocation targets
  const revGrid = `<dl class="grid">
    <dt>Active authority grants</dt><dd>${CX_ESC(String(rt.active_authority_grants ?? "—"))} <span class="pill ok">revocable</span></dd>
    <dt>Active capability leases</dt><dd>${CX_ESC(String(rt.active_capability_leases ?? "—"))} <span class="pill ok">revocable</span></dd>
    <dt>Connectors · SCM</dt><dd>${CX_ESC(String(rt.connectors ?? "—"))} · ${CX_ESC(String(rt.scm_connectors ?? "—"))} <span class="pill ok">disconnectable</span> · <a href="/__ioi/connections">Connections →</a></dd>
  </dl><p class="sub" style="margin:6px 0 0">${CX_ESC(rt.note || "")}</p>`;

  // 7. Improvement gate candidates
  const impGrid = `<dl class="grid">
    <dt>Foundry specs by kind</dt><dd>${histChips(ig.foundry_specs_by_kind)}</dd>
    <dt>Foundry run plans</dt><dd>${CX_ESC(String(ig.foundry_run_plans ?? "—"))} · <a href="/__ioi/foundry">Foundry →</a></dd>
  </dl><p class="sub" style="margin:6px 0 0">${CX_ESC(ig.note || "")}</p>`;

  // 8. Governance gaps — four distinct states (no vague amber substrate-inactive for present controls).
  const gapPill = (g) => {
    const s = g.status || (g.has_substrate ? "open" : "missing");
    if (s === "present") return `<span class="pill ok">control present${g.count != null ? " · " + g.count : ""}</span>`;
    if (s === "control_empty") return `<span class="pill muted">control present · empty</span>`;
    if (s === "open") return `<span class="pill warn">open gap</span>`;
    return `<span class="pill" style="color:#e06a6a;border-color:#5c2a2a;background:#2a1212">missing control</span>`;
  };
  const famForGap = { approval_request_object: "approvals", release_control_object: "releases", kill_switch_object: "kill-switches", improvement_gate_object: "gates" };
  const gapRows = gaps.map((g) => {
    const fam = famForGap[g.id];
    const manage = fam ? ` · <a href="/__ioi/governance?tab=${fam}">manage →</a>` : "";
    return `<tr><td style="white-space:nowrap">${gapPill(g)}</td><td><b>${CX_ESC(g.title || g.id || "")}</b>${manage}<div class="meta" style="color:#878a93;font-size:12px;margin-top:2px">${CX_ESC(g.detail || "")}</div></td></tr>`;
  }).join("");
  const legend = `<div class="chips" style="margin:0 0 10px"><span class="chiplabel">Legend</span><span class="pill ok">control present</span><span class="pill muted">control present · empty</span><span class="pill warn">open gap</span><span class="pill" style="color:#e06a6a;border-color:#5c2a2a;background:#2a1212">missing control</span></div>`;
  const gapsTable = gaps.length
    ? legend + `<table><thead><tr><th style="width:190px">Status</th><th>Gap / control</th></tr></thead><tbody>${gapRows}</tbody></table>`
    : `<div class="empty">No governance gaps reported.</div>`;

  // Actionable candidates — real candidates awaiting a control object (a distinct, honest state).
  const candPill = (n, label) => `<span class="pill" style="color:#8ab4ff;border-color:#2a4a7c;background:#111a2c">${CX_ESC(String(n || 0))} ${label}</span>`;
  const actionable = `<h2>Actionable candidates <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— awaiting a control object</span></h2><div class="chips">${candPill(rc.foundry_run_plans, "foundry run-plans")} ${candPill(rc.domain_app_candidates, "domain-app candidates")} ${candPill(rc.scm_publish_connectors, "scm publish")} ${candPill((ig.foundry_run_plans || 0), "improvement targets")} · <a href="/__ioi/governance?tab=releases">create release control →</a> · <a href="/__ioi/governance?tab=approvals">create approval →</a></div>`;

  const co = o.control_objects || {};
  const coStrip = `<div class="chips"><span class="chiplabel">Control objects</span>${["approval_requests", "release_controls", "kill_switches", "improvement_gates"].map((k) => `<span class="pill ${(co[k] && co[k].total) ? "ok" : "muted"}">${k.replace(/_/g, " ")}: ${(co[k] && co[k].total) || 0}</span>`).join(" ")}</div>`;

  const overviewBody = coStrip
    + `<h2>Authority posture</h2>${authGrid}`
    + `<h2>Identity posture</h2>${idGrid}`
    + `<h2>Lease posture</h2>${leaseGrid}`
    + `<h2>Approval &amp; admission</h2>${admGrid}`
    + coverage
    + `<h2>Release control candidates</h2>${relGrid}`
    + `<h2>Revocation targets</h2>${revGrid}`
    + `<h2>Improvement gate candidates</h2>${impGrid}`
    + actionable
    + `<h2>Governance gaps &amp; controls <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— present controls, empty controls, and still-open gaps, distinctly</span></h2>${gapsTable}`
    + `<p class="sub" style="margin-top:20px">Related: <a href="/__ioi/operations">Operations</a> · <a href="/__ioi/work-ledger">Work Ledger</a> · <a href="/__ioi/connections">Developer &amp; Integrations</a></p>`;

  const body = (tab !== "overview" && GOV_FAMS[tab])
    ? govControlTab(tab, controls[GOV_FAMS[tab].listKey] || [], controls.cohorts || [], joins)
    : overviewBody;

  const inner = head + banner + summary + govTabBar(tab) + body;
  return automationsShell("Governance", inner);
}

// ---- Marketplace — a source-grafted CATALOG / DETAIL / ADMISSION surface (estate #8, last card).
// Grafts the reference Marketplace+Now composition shape (store-framed catalog -> product detail ->
// install/admission state -> resource-graph handoff) onto the daemon marketplace plane. It is a
// composition amplifier, not an admin table. admission_only_until_runtime_backing is honored end to
// end: the "install/publish/hire" affordances are transformed into "Create candidate / Submit review
// / Create offer / View governance blockers" — NO publish, hire, install, settle, or instantiate.
const MP_STORES = [
  { kind: "agent", label: "Agents Store", icon: "🤖", desc: "Configured agents offered as products." },
  { kind: "domain_app", label: "Domain Apps Store", icon: "🧩", desc: "Domain app candidates over ODK descriptors." },
  { kind: "ontology_pack", label: "ODK Packs Store", icon: "📦", desc: "Ontology development kits." },
  { kind: "data_recipe", label: "Data Recipes Store", icon: "🧪", desc: "Repeatable transformation recipes." },
  { kind: "foundry_capability", label: "Foundry Capabilities Store", icon: "🏗", desc: "Model / tool capability specs & run plans." },
];
const mpStoreOf = (kind) => MP_STORES.find((s) => s.kind === kind) || { label: kind, icon: "◳" };
function marketplaceSubjectLink(kind, ref) {
  const enc = encodeURIComponent; const r = String(ref || "");
  const m = r.match(/^([a-z-]+):\/\/(.+)$/);
  if (kind === "agent") return `<a href="/__ioi/agent-studio?agent=${enc(r)}">${CX_ESC(r)} ↗</a>`;
  if (kind === "domain_app" && m) return `<a href="/__ioi/domain-apps/${enc(m[2])}">${CX_ESC(r)} ↗</a>`;
  if (kind === "ontology_pack" && m) return `<a href="/__ioi/odk/manifests/${enc(m[2])}">${CX_ESC(r)} ↗</a>`;
  if (kind === "data_recipe" && m) return `<a href="/__ioi/odk/data-recipes/${enc(m[2])}">${CX_ESC(r)} ↗</a>`;
  if (kind === "foundry_capability") { const fam = r.startsWith("frun_") ? "run-plans" : "specs"; return `<a href="/__ioi/foundry/${fam}/${enc(r)}">${CX_ESC(r)} ↗</a>`; }
  return r ? `<code>${CX_ESC(r)}</code>` : "—";
}
async function marketplaceSubjectOptions() {
  const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => null);
  const [ag, da, man, rec, fs, fr] = await Promise.all([
    J("/v1/agents"), J("/v1/hypervisor/domain-apps"), J("/v1/hypervisor/odk/manifests"),
    J("/v1/hypervisor/odk/data-recipes"), J("/v1/hypervisor/foundry/specs"), J("/v1/hypervisor/foundry/run-plans"),
  ]);
  const opts = [];
  for (const a of (Array.isArray(ag) ? ag : [])) opts.push({ kind: "agent", v: a.id, l: `${(a.id || "").slice(0, 20)} · ${a.model_id || a.modelId || "agent"}` });
  for (const d of ((da && da.domain_apps) || [])) opts.push({ kind: "domain_app", v: d.domain_app_ref, l: d.name || d.domain_app_id });
  for (const m of ((man && man.manifests) || [])) opts.push({ kind: "ontology_pack", v: m.ref, l: m.name || m.id });
  for (const r of ((rec && rec.data_recipes) || [])) opts.push({ kind: "data_recipe", v: r.ref, l: r.name || r.id });
  for (const s of ((fs && fs.specs) || [])) opts.push({ kind: "foundry_capability", v: s.id, l: `${s.name || s.id} (spec)` });
  for (const p of ((fr && fr.run_plans) || [])) opts.push({ kind: "foundry_capability", v: p.id, l: `${p.name || p.id} (run-plan)` });
  return opts;
}
function marketplacePayloadFromForm(p) {
  const csv = (k) => (p.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    name: (p.get("name") || "marketplace-listing").trim(),
    description: (p.get("description") || "").trim(),
    listing_kind: (p.get("listing_kind") || "agent").trim(),
    subject_ref: (p.get("subject_ref") || "").trim(),
    evidence_refs: csv("evidence_refs"),
  };
}
function renderMarketplaceHome(ov, listings, q, storeFilter) {
  const enc = encodeURIComponent;
  const o = ov || {}; const sub = o.substrate || {}; const mk = o.marketplace || {};
  const byKind = mk.listings_by_kind || {};
  const qn = String(q || "").trim().toLowerCase();
  let shown = listings.filter((l) => !storeFilter || l.listing_kind === storeFilter);
  if (qn) shown = shown.filter((l) => `${l.name || ""} ${l.subject_ref || ""} ${l.listing_kind || ""}`.toLowerCase().includes(qn));
  const styles = `<style>.wrap{max-width:1100px}.mpgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}.mpstores{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin:0 0 20px}.mpstore{display:block;padding:13px 15px;border:1px solid #24262d;border-radius:12px;background:#15171c;text-decoration:none;color:inherit}.mpstore:hover{border-color:#3a82f6}.mpstore.on{border-color:#3a82f6;box-shadow:0 0 0 1px #3a82f6 inset}.mpstore .sn{font-weight:600;color:#fff}.mpstore .sc{color:#878a93;font-size:12px;margin-top:3px}.mpsearch{width:100%;max-width:420px;box-sizing:border-box;padding:9px 12px;border-radius:9px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit}</style>`;
  const head = `<h1>Marketplace</h1><p class="sub">Discover, inspect, and take through admission — agents, domain apps, ODK packs, data recipes, and Foundry capabilities. Nothing is published, hired, installed, or settled here. <a href="/__apps/listings">Store-browse seed (adopting) →</a></p>`;
  const banner = `<div class="chips"><span class="pill warn">publish = admitted review + open release + serving runtime</span> <span class="sub" style="margin:0">${CX_ESC(o.status_note || "A domain_app publishes only with runtime backing; published = read-only distribution metadata.")}</span></div>`;
  const storeCards = MP_STORES.map((s) => `<a class="mpstore${storeFilter === s.kind ? " on" : ""}" href="/__ioi/marketplace?store=${enc(s.kind)}"><div class="sn">${s.icon} ${CX_ESC(s.label)} <span class="pill muted">${byKind[s.kind] || 0}</span></div><div class="sc">${CX_ESC(s.desc)}</div></a>`).join("");
  const stores = `<h2>Stores${storeFilter ? ` · <a href="/__ioi/marketplace">show all</a>` : ""}</h2><div class="mpstores">${storeCards}</div>`;
  const card = (l) => {
    const st = mpStoreOf(l.listing_kind);
    return `<a class="card" href="/__ioi/marketplace/listings/${enc(l.id || "")}" style="align-items:flex-start"><div class="main"><div class="name">${st.icon} ${CX_ESC(l.name || l.id || "listing")}</div><div class="meta"><span class="pill muted">${CX_ESC(l.listing_kind || "")}</span> <span class="pill warn">${CX_ESC(l.status || "draft")}</span> <span class="pill muted">unlisted</span></div><div class="meta" style="margin-top:6px;word-break:break-all">${CX_ESC(l.subject_ref || "")}</div></div><span class="act ghost">Open →</span></a>`;
  };
  const catalog = `<h2 style="display:flex;justify-content:space-between;align-items:center">Listings (${shown.length}) <a class="act" href="/__ioi/marketplace/listings/new">+ Draft listing</a></h2>
    <form method="get" action="/__ioi/marketplace" style="margin:0 0 14px">${storeFilter ? `<input type="hidden" name="store" value="${CX_ESC(storeFilter)}">` : ""}<input class="mpsearch" name="q" value="${CX_ESC(q || "")}" placeholder="Search listings by name, subject, or kind…"></form>
    ${shown.length ? `<div class="mpgrid">${shown.map(card).join("")}</div>` : `<div class="empty">No listings${storeFilter ? ` in ${CX_ESC(mpStoreOf(storeFilter).label)}` : ""} yet. Draft one over a real agent, domain app, ODK pack, recipe, or Foundry capability.</div>`}`;
  const activity = `<h2>Admission activity</h2><div class="chips"><span class="pill muted">publish candidates: ${mk.publish_candidates || 0}</span> <span class="pill muted">admission reviews: ${mk.admission_reviews || 0}</span> <span class="pill muted">managed offers: ${mk.managed_instance_offers || 0}</span> <span class="pill ok">published: ${mk.published || 0}</span></div><p class="sub" style="margin:6px 0 0">Substrate: ${sub.agents || 0} agents · ${sub.domain_apps_marketplace_candidates || 0} domain-app candidates · ${sub.foundry_specs || 0} foundry specs. <a href="/__ioi/governance">Governance posture →</a></p>`;
  return automationsShell("Marketplace", styles + head + banner + stores + catalog + activity);
}
function renderMarketplaceListingForm(existing, opts) {
  const enc = encodeURIComponent; const ex = existing || {}; const isEdit = !!existing;
  const action = isEdit ? `/__ioi/marketplace/listings/${enc(ex.id)}/patch` : `/__ioi/marketplace/listings`;
  const kindOpts = MP_STORES.map((s) => `<option value="${s.kind}" ${ex.listing_kind === s.kind ? "selected" : ""}>${CX_ESC(s.label)}</option>`).join("");
  const subjOpts = opts.map((o) => `<option value="${CX_ESC(o.v)}" data-kind="${o.kind}" ${ex.subject_ref === o.v ? "selected" : ""}>${CX_ESC(o.l)}</option>`).join("");
  const inner = `<p><a href="/__ioi/marketplace">← Marketplace</a></p><h1>${isEdit ? "Edit" : "Draft"} listing</h1>
    <p class="sub">List a real subject as a marketplace product. It stays a draft (<code>unlisted</code>) — nothing is published here.</p>
    <form method="post" action="${action}">
      ${odkField("Name", "name", ex.name, "Coder agent")}
      ${odkArea("Description", "description", ex.description)}
      <div class="two">
        <div class="field"><label>Store / listing kind</label><select id="mp-kind" name="listing_kind">${kindOpts}</select></div>
        <div class="field"><label>Subject (real substrate)</label><select id="mp-subject" name="subject_ref">${subjOpts || `<option value="">— none available —</option>`}</select></div>
      </div>
      ${odkCsvField("Evidence refs (comma-sep — receipts / eval / state-root / local scheme refs)", "evidence_refs", ex.evidence_refs)}
      <div class="row"><button class="act" type="submit">${isEdit ? "Save draft" : "Create draft listing"}</button> <a class="act ghost" href="/__ioi/marketplace">Cancel</a></div>
    </form>
    <script>(function(){var k=document.getElementById('mp-kind'),s=document.getElementById('mp-subject');if(!k||!s)return;function f(){var kk=k.value;Array.prototype.forEach.call(s.options,function(o){if(!o.value){return;}o.hidden=(o.getAttribute('data-kind')!==kk);});var cur=s.options[s.selectedIndex];if(!cur||cur.hidden){for(var i=0;i<s.options.length;i++){if(s.options[i].value&&!s.options[i].hidden){s.selectedIndex=i;return;}}}}k.addEventListener('change',f);f();})();</script>`;
  return automationsShell(`${isEdit ? "Edit" : "Draft"} listing`, inner);
}
function renderMarketplaceListingDetail(listing, candidates, reviewsByCandidate, offers, gov) {
  const enc = encodeURIComponent; const l = listing || {};
  const lid = l.id || ""; const st = mpStoreOf(l.listing_kind);
  const govChips = (g) => g ? `<span class="pill ${g.auth_enforced ? "ok" : "muted"}">auth ${g.auth_enforced ? "enforced" : "not enforced"}</span> <span class="pill ${(g.governance_gaps || 0) > 0 ? "warn" : "ok"}">gaps: ${g.governance_gaps ?? "—"}</span>` : "—";
  const meta = `<dl class="grid">
    <dt>Store</dt><dd>${st.icon} ${CX_ESC(st.label)}</dd>
    <dt>Listing kind</dt><dd><span class="pill muted">${CX_ESC(l.listing_kind || "")}</span></dd>
    <dt>Status</dt><dd><span class="pill warn">${CX_ESC(l.status || "draft")}</span> <span class="pill muted">public_state: ${CX_ESC(l.public_state || "unlisted")}</span></dd>
    <dt>Subject</dt><dd>${marketplaceSubjectLink(l.listing_kind, l.subject_ref)}</dd>
    <dt>Evidence</dt><dd>${(l.evidence_refs || []).length ? (l.evidence_refs || []).map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") : "—"}</dd>
    <dt>Created · updated</dt><dd>${CX_ESC(l.created_at || "")}<br><span class="sub" style="margin:0">${CX_ESC(l.updated_at || "")}</span></dd>
  </dl>`;
  const listingActions = `<div class="row"><a class="act ghost" href="/__ioi/marketplace/listings/${enc(lid)}/edit">Edit</a> <form class="inline" method="post" action="/__ioi/marketplace/listings/${enc(lid)}/delete" onsubmit="return confirm('Delete this listing draft?')"><button class="act danger" type="submit">Delete</button></form></div>`;

  // Admission column — the install/publish analog, transformed to admission-only.
  const candBlocks = candidates.map((c) => {
    const reviews = reviewsByCandidate[c.ref] || [];
    const published = c.publish_state === "published";
    const reasons = (c.blocked_reasons || []).map((r) => `<span class="pill" style="color:#e06a6a;border-color:#5c2a2a;background:#2a1212">${CX_ESC(r)}</span>`).join(" ");
    const g = c.governance_posture_snapshot || {};
    const revRows = reviews.map((rv) => `<tr><td><span class="pill ${rv.decision === "admitted" ? "ok" : rv.decision === "rejected" ? "warn" : "muted"}">${CX_ESC(rv.decision || "")}</span></td><td>${(rv.findings || []).map((f) => `<code>${CX_ESC(f)}</code>`).join(" ") || "—"}</td><td><form class="inline" method="post" action="/__ioi/marketplace/reviews/${enc(rv.id)}/delete"><input type="hidden" name="listing_id" value="${enc(lid)}"><button class="act ghost" type="submit">✕</button></form></td></tr>`).join("");
    const pubPill = published
      ? `<span class="pill ok">published</span>`
      : c.publishable ? `<span class="pill ok">publishable</span>` : `<span class="pill" style="color:#e06a6a;border-color:#5c2a2a;background:#2a1212">not publishable</span>`;
    const runtimeRoute = c.published_runtime_ref ? String(c.published_runtime_ref).replace(/^domain-app-runtime:\/\//, "/__ioi/domain-app-runtime/") : "";
    const publishedBlock = published
      ? `<div class="chips" style="margin:0 0 8px"><span class="chiplabel">Published</span><span class="pill muted">at ${CX_ESC(c.published_at || "")}</span> ${runtimeRoute ? `<a class="act" href="${runtimeRoute}">Open app →</a>` : ""}</div>
         <dl class="wlgrid" style="margin:0 0 8px"><dt class="wlk">Runtime</dt><dd class="wlv"><code>${CX_ESC(c.published_runtime_ref || "")}</code></dd><dt class="wlk">Release</dt><dd class="wlv"><code>${CX_ESC(c.release_control_ref || "")}</code></dd><dt class="wlk">Admission</dt><dd class="wlv"><code>${CX_ESC(c.admission_review_ref || "")}</code></dd><dt class="wlk">Receipts</dt><dd class="wlv">${(c.publish_receipt_refs || []).map((r) => `<code>${CX_ESC(r)}</code>`).join(" ") || "—"}</dd></dl>`
      : `<div class="chips" style="margin:0 0 8px"><span class="chiplabel">Blocked reasons</span>${reasons || `<span class="sub" style="margin:0">none — ready to publish</span>`}</div>
         <div class="chips" style="margin:0 0 10px"><span class="chiplabel">Governance @ candidacy</span>${govChips(g)}</div>`;
    const reviewForm = published ? "" : `<form method="post" action="/__ioi/marketplace/candidates/${enc(c.id)}/reviews" class="row" style="gap:8px;margin-top:8px"><input type="hidden" name="listing_id" value="${enc(lid)}">
        <select name="decision" style="padding:8px;border-radius:8px;border:1px solid #2a2c33;background:#0e0f13;color:#e6e7ea;font:inherit"><option value="pending">pending</option><option value="needs_changes">needs_changes</option><option value="admitted">admitted</option><option value="rejected">rejected</option></select>
        <button class="act ghost" type="submit">Submit admission review</button></form>`;
    const publishBtn = (!published && c.publishable) ? `<form class="inline" method="post" action="/__ioi/marketplace/candidates/${enc(c.id)}/publish"><input type="hidden" name="listing_id" value="${enc(lid)}"><button class="act" type="submit">Publish (runtime-backed)</button></form>` : "";
    return `<div class="card" style="display:block">
      <div class="row" style="justify-content:space-between;margin:0 0 8px"><div><b>Publish candidate</b> <code>${CX_ESC(c.id)}</code> <span class="pill muted">publish_state: ${CX_ESC(c.publish_state || "candidate")}</span> ${pubPill}</div>
        ${published ? "" : `<form class="inline" method="post" action="/__ioi/marketplace/candidates/${enc(c.id)}/delete"><input type="hidden" name="listing_id" value="${enc(lid)}"><button class="act ghost" type="submit">Delete candidate</button></form>`}</div>
      ${publishedBlock}
      <h4 style="margin:6px 0;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#878a93">Admission reviews</h4>
      ${reviews.length ? `<table><tbody>${revRows}</tbody></table>` : `<div class="sub" style="margin:0 0 8px">No reviews yet.</div>`}
      <div class="row" style="margin-top:8px;gap:8px">${publishBtn}</div>${reviewForm}
    </div>`;
  }).join("");
  const admission = `<h2>Publish admission <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— publishes only with admitted review + open ReleaseControl + a mounted&amp;serving runtime</span></h2>
    ${candidates.length ? candBlocks : `<div class="empty">No publish candidate yet.</div>`}
    <form method="post" action="/__ioi/marketplace/listings/${enc(lid)}/candidates" style="margin-top:10px"><button class="act ghost" type="submit">Create publish candidate</button></form>`;

  // Managed instance offers (agent / domain_app only) — always uninstantiated.
  const offerable = l.listing_kind === "agent" || l.listing_kind === "domain_app";
  const offerRows = offers.map((o) => `<tr><td><code>${CX_ESC(o.id)}</code> ${CX_ESC(o.name || "")}</td><td><span class="pill muted">instantiated: ${o.runtime_posture && o.runtime_posture.instantiated ? "true" : "false"}</span></td><td><form class="inline" method="post" action="/__ioi/marketplace/offers/${enc(o.id)}/delete"><input type="hidden" name="listing_id" value="${enc(lid)}"><button class="act ghost" type="submit">✕</button></form></td></tr>`).join("");
  const offersSection = `<h2>Managed instance offers <span class="sub" style="text-transform:none;letter-spacing:0;font-weight:400">— draft offers; never instantiated/hired</span></h2>
    ${offers.length ? `<table><tbody>${offerRows}</tbody></table>` : `<div class="empty">No managed offers.</div>`}
    ${offerable ? `<form method="post" action="/__ioi/marketplace/listings/${enc(lid)}/offers" style="margin-top:10px"><button class="act" type="submit">Create managed offering (draft)</button></form>` : `<p class="sub" style="margin:8px 0 0">Managed offerings apply to agent / domain_app listings only.</p>`}`;

  const handoffs = `<p class="sub" style="margin-top:20px">Resource graph: ${marketplaceSubjectLink(l.listing_kind, l.subject_ref)} · <a href="/__ioi/governance">Governance blockers</a> · <a href="/__ioi/work-ledger">Work Ledger (proof)</a></p>`;
  // Listing-level admission readiness (source shape: the product detail carries its install/
  // admission-state posture up front, not only after a candidate exists). Rendered from the
  // marketplace overview's live governance posture — the same shape candidates snapshot at candidacy.
  const readiness = gov
    ? `<div class="chips" style="margin:0 0 16px"><span class="chiplabel">Admission readiness</span>${govChips(gov)}<span class="sub" style="margin:0">live governance posture — snapshotted onto each publish candidate at candidacy</span></div>`
    : "";
  const inner = `<p><a href="/__ioi/marketplace">← Marketplace</a></p><h1>${st.icon} ${CX_ESC(l.name || lid)}</h1><p class="sub">Marketplace listing · draft. ${CX_ESC(l.description || "")}</p>${listingActions}${meta}${readiness}${admission}${offersSection}${handoffs}`;
  return automationsShell(l.name || "Marketplace listing", inner);
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
  /* Lineage & proof (79-workflow-lineage graft): run-level proof panel + temporal trace. */
  .rt-lineage { border:1px solid rgb(var(--border-base)); border-radius:12px; padding:12px 14px; margin-top:14px; background:rgb(var(--surface-base)); }
  .rt-wf { margin-top:10px; }
  .rt-wf-row { display:flex; align-items:center; gap:10px; padding:2px 0; cursor:pointer; }
  .rt-wf-row:hover .rt-wf-label { color:rgb(var(--content-primary)); }
  .rt-wf-label { width:120px; flex:none; font-size:11px; color:rgb(var(--content-muted)); text-align:right;
    overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .rt-wf-track { flex:1; height:14px; border-radius:4px; background:rgb(var(--surface-muted)); position:relative; }
  .rt-wf-bar { position:absolute; top:2px; bottom:2px; border-radius:3px; background:rgb(var(--content-brand)); opacity:.75; min-width:6px; }
  .rt-wf-bar.fail { background:rgb(var(--content-destructive)); }
  .rt-wf-t { width:74px; flex:none; font-size:10.5px; font-family:ui-monospace,monospace; color:rgb(var(--content-muted)); }
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

    // ---- Lineage & proof (79-workflow-lineage graft) — the run-level chain and its temporal
    // trace, from RECORDED timestamps only. The waterfall positions each turn inside the run
    // window; a turn without timestamps says so rather than being placed. Deep links go to the
    // proof stream (Work Ledger owns receipts/state-root facets) and the owning session.
    var turns = tl.turns||[];
    var receiptsN = 0, filesN = 0;
    turns.forEach(function(t){ receiptsN += ((t.proof||{}).receipts||[]).length; filesN += (((t.artifacts||{}).files)||[]).length; });
    var lin=el("div","rt-lineage");
    var lkv=el("dl","rt-kv");
    function lrow(k,v){ if(!v) return; lkv.appendChild(el("dt",null,k)); lkv.appendChild(el("dd",null,v)); }
    lrow("lineage", (tl.environmentId?("env "+tl.environmentId+"  →  "):"") + (tl.sessionRef?(tl.sessionRef+"  →  "):"") + "run "+(tl.runId||"")+"  →  "+turns.length+" turn"+(turns.length===1?"":"s")+"  →  "+filesN+" artifact"+(filesN===1?"":"s"));
    lrow("state root", tl.stateRoot ? (tl.stateRoot+(tl.durable?" · durable":"")) : null);
    lrow("receipts", receiptsN ? (receiptsN+" across turns — details in each turn's Proof section") : null);
    lin.appendChild(lkv);
    var acts=el("div","rt-acts"); acts.style.marginTop="8px";
    var wl=el("a","rt-act","Proof stream →"); wl.href="/__ioi/work-ledger"; wl.target="_blank"; wl.rel="noopener"; acts.appendChild(wl);
    if(tl.environmentId){ var se=el("a","rt-act","Session →"); se.href="/details/"+encodeURIComponent(tl.environmentId); se.target="_blank"; se.rel="noopener"; acts.appendChild(se); }
    lin.appendChild(acts);
    // Temporal trace: one row per turn, always. Bars only when the run window AND the turn's
    // recorded timestamps allow honest positioning; otherwise the row says "no timing".
    var t0=Date.parse(tl.createdAt||""), t1=Date.parse(tl.updatedAt||"")||Date.now();
    var windowOk = isFinite(t0) && t1>t0;
    if(turns.length){
      var wf=el("div","rt-wf");
      turns.forEach(function(t,ix){
        var times=[];
        (t.activity||[]).forEach(function(a){ var p=Date.parse(a.at||""); if(isFinite(p)) times.push(p); });
        var rp=Date.parse((t.response||{}).at||""); if(isFinite(rp)) times.push(rp);
        var row=el("div","rt-wf-row");
        row.appendChild(el("span","rt-wf-label","turn "+(ix+1)));
        var track=el("div","rt-wf-track");
        if(windowOk && times.length){
          var a0=Math.min.apply(null,times), a1=Math.max.apply(null,times);
          var bar=el("span","rt-wf-bar"+((t.response||{}).failed?" fail":""));
          bar.style.left=Math.max(0,Math.min(99,(a0-t0)/(t1-t0)*100))+"%";
          bar.style.width=Math.max(0.6,Math.min(100,(a1-a0)/(t1-t0)*100))+"%";
          track.appendChild(bar);
          row.appendChild(track);
          row.appendChild(el("span","rt-wf-t",((a1-a0)/1000).toFixed(1)+"s"));
        } else {
          row.appendChild(track);
          row.appendChild(el("span","rt-wf-t","no timing"));
        }
        row.addEventListener("click",function(){ var tgt=document.getElementById("rt-turn-"+ix); if(tgt) tgt.scrollIntoView({behavior:"smooth",block:"start"}); });
        wf.appendChild(row);
      });
      lin.appendChild(wf);
    }
    root.appendChild(lin);

    (tl.turns||[]).forEach(function(turn,turnIx){
      var box=el("div","rt-turn");
      box.id="rt-turn-"+turnIx;

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
// Process-level backstops behind the per-request boundary (surfaceErrorBoundary): WS handlers,
// timers and child-process callbacks aren't covered by it, and one surface's bug must not take
// down the ~100-surface estate process. Log loudly, keep serving; request state is not shared.
process.on("unhandledRejection", (e) => console.error("[hypervisor] unhandled rejection (estate kept alive):", e));
process.on("uncaughtException", (e) => console.error("[hypervisor] uncaught exception (estate kept alive):", e));

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
  req.on("end", () => handleEstateRequest(req, res, Buffer.concat(chunks)).catch((err) => surfaceErrorBoundary(req, res, err)));
});

// ---- App-runtime error boundary (functional-runtime wave) ----
// One surface's renderer exception must fail THAT request (500 + logged), never the estate
// process. Motivating incident (#46): DOMAIN_APP_VIS was deleted with call sites left behind —
// GET /__ioi/domain-apps threw, the async handler's rejection was unhandled, and the whole
// ~100-surface serve died. If headers already streamed, the response just ends; the error page
// is written only when nothing was sent.
function surfaceErrorBoundary(req, res, err) {
  console.error(`[hypervisor] surface error ${req.method} ${req.url}:`, err);
  try {
    if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
    if (!res.writableEnded) res.end("<!doctype html><title>Surface error</title><h1>Surface error</h1><p>This surface failed to render; the rest of the estate is still serving. The serve log carries the stack.</p>");
  } catch { /* client socket already gone */ }
}

// ---- Embedded render mode (native container contract #65) — used ONLY by the Open Application
// slot. The native IOI rail outside the iframe is the ONE platform rail, so the app's duplicated
// reference GLOBAL rail is removed STRUCTURALLY (never merely CSS-hidden — no hidden duplicate
// navigation tree survives in the iframe; the standalone/certified render is byte-untouched
// because bare routes never pass through here), and embed=1 is threaded through every link, row
// onclick, and GET form that lands on another embeddable route, so selection/filter/refresh and
// cross-application semantic links stay embedded. App-local rails, headers, sidebars, tools,
// inspectors and trays are never touched.
function embedSurfaceHtml(html) {
  const routes = embeddableRoutes();
  const addEmbed = (path, qs, hash) => {
    if (!routes.has(path) || /(\?|&)embed=1/.test(qs || "")) return null;
    return `${path}${qs ? `${qs}&embed=1` : "?embed=1"}${hash || ""}`;
  };
  html = html.replace(/href="(\/__ioi\/[^"?#]*)(\?[^"#]*)?(#[^"]*)?"/g, (m, path, qs, hash) => {
    const u = addEmbed(path, qs, hash);
    return u ? `href="${u}"` : m;
  });
  html = html.replace(/location\.href='(\/__ioi\/[^'?#]*)(\?[^'#]*)?(#[^']*)?'/g, (m, path, qs, hash) => {
    const u = addEmbed(path, qs, hash);
    return u ? `location.href='${u}'` : m;
  });
  const embeddablePath = (path) => routes.has(path) || [...routes].some((r) => path.startsWith(r + "/"));
  html = html.replace(/(<form\b[^>]*\baction="(\/__ioi\/[^"?#]*)"[^>]*>)/g, (m, tag, path) => (embeddablePath(path) ? `${tag}<input type="hidden" name="embed" value="1">` : m));
  // Structural rail removal: extracted modules already emit no rail under ctx.embed; flat-handler
  // surfaces have theirs stripped here. The rail aside nests no other <aside>, so the non-greedy
  // match ends at its own closing tag (inspector asides render AFTER the rail and are untouched).
  return html.replace(/<aside class="og-grail[\s\S]*?<\/aside>/, "");
}

// ---- Governed action runtime (operational wave #62) ------------------------------------------
// ONE runtime for every module action: bounded form parsing, action lookup by declared transition
// vocabulary, input allowlisting (undeclared fields are NEVER forwarded), same-origin return
// validation, confirmation enforcement, embed preservation, typed success/refusal results as
// PRG redirects (duplicate-submit protection), and route-local error containment. Modules never
// see the raw request/response.
function safeReturnPath(raw, fallback) {
  if (!raw || typeof raw !== "string" || raw.length > 512) return fallback;
  if (!raw.startsWith("/__ioi/") || raw.startsWith("//")) return fallback;
  if (/[\\"'<>#\r\n\u0000]/.test(raw)) return fallback;
  try { decodeURIComponent(raw); } catch { return fallback; }
  return raw;
}
async function runSurfaceAction(hit, res, body) {
  try {
    const p = new URLSearchParams(body.toString("utf8").slice(0, 16384)); // bounded parse
    const embed = p.get("embed") === "1";
    const back = safeReturnPath(p.get("return"), hit.surface.route);
    const go = (params) => {
      const url = `${back}${back.includes("?") ? "&" : "?"}${params.toString()}${embed ? "&embed=1" : ""}#ap-result`;
      res.writeHead(303, { Location: url, "Cache-Control": "no-cache" });
      res.end();
    };
    const refuse = (code, message, target) => {
      const back2 = safeReturnPath(target, back);
      const url = `${back2}${back2.includes("?") ? "&" : "?"}${new URLSearchParams({ refused: code, reason: String(message || "").slice(0, 200), record: hit.recordId }).toString()}${embed ? "&embed=1" : ""}#ap-result`;
      res.writeHead(303, { Location: url, "Cache-Control": "no-cache" }); res.end();
    };
    // Action selection: transition-discriminated when multiple actions share a route (Approvals),
    // else the single route-matched action (Manager's per-action routes).
    const transition = (p.get("transition") || "").trim();
    const action = hit.actions.length === 1 && !hit.actions[0].transition ? hit.actions[0] : hit.actions.find((a) => a.transition === transition);
    if (!action) return refuse("action_unknown", `unknown transition '${transition.slice(0, 40)}' — declared: ${hit.actions.map((a) => a.transition || a.id).join("|")}`);
    if (action.confirm && p.get("confirm") !== "1") return refuse("confirmation_required", `${action.id} requires explicit confirmation (${action.from} -> ${action.to}) — re-submit with the confirmation checked`);
    const fields = {};
    // Per-field bound: 2000 default; an action may declare fieldMax (hard-capped 8192) for fields
    // that legitimately carry larger opaque blobs — e.g. an externally signed wallet grant
    // (~1.1KB serialized, larger with optional wallet fields). Truncating a signed grant would
    // forward a corrupt artifact, so the bound is declared, never lucked into.
    const fieldCap = Math.min(Number(action.fieldMax) || 2000, 8192);
    for (const f of action.fields || []) { const v = p.get(f); if (v !== null && v !== "") fields[f] = String(v).slice(0, fieldCap); }
    const result = await hit.impl.handleAction({ action, id: hit.recordId, fields, daemon: DAEMON, url: new URL(hit.surface.route + (p.get("ontology") ? `?ontology=${encodeURIComponent(p.get("ontology"))}` : ""), "http://x") });
    if (!result || typeof result !== "object" || !["success", "refusal", "failure"].includes(result.kind)) {
      return refuse("action_result_invalid", "the module returned no typed result — failing closed");
    }
    // A module may name its success/refusal return route (declared success policy); it is always
    // re-validated as a same-origin bounded path — the module never controls the raw redirect.
    if (result.kind === "success") {
      if (!result.receipt_ref) return refuse("receipt_missing", "success without the declared receipt — failing closed", result.redirect);
      const back2 = safeReturnPath(result.redirect, back);
      const url = `${back2}${back2.includes("?") ? "&" : "?"}${new URLSearchParams({ acted: action.id, receipt: result.receipt_ref, record: result.createdOntology || result.created || hit.recordId, result: result.status || "" }).toString()}${embed ? "&embed=1" : ""}#ap-result`;
      res.writeHead(303, { Location: url, "Cache-Control": "no-cache" }); return res.end();
    }
    return refuse(result.code || (result.kind === "failure" ? "action_failed" : "action_refused"), result.message, result.redirect);
  } catch (err) {
    surfaceErrorBoundary({ method: "POST", url: "surface-action" }, res, err);
  }
}

async function handleEstateRequest(req, res, body) {
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
    // ---- Native container contract (#65): ONE choke point renders the embedded mode for EVERY
    // estate surface — flat handlers and bound modules alike. Any /__ioi/* GET carrying embed=1
    // has its final whole-document HTML rewritten (structural global-rail removal + embed
    // threading, embedSurfaceHtml); only chunks that are a complete text/html document are
    // touched — JSON, assets, streams, and partial writes pass through byte-untouched.
    if (req.method === "GET" && pathname.startsWith("/__ioi/")) {
      let embedReq = false;
      try { embedReq = new URL(req.url || "", "http://x").searchParams.get("embed") === "1"; } catch { /* malformed URL → standalone render */ }
      if (embedReq) {
        const endRaw = res.end.bind(res);
        res.end = (chunk, ...rest) => endRaw(typeof chunk === "string" && /^<!doctype html>/i.test(chunk) ? embedSurfaceHtml(chunk) : chunk, ...rest);
      }
    }
    if (pathname === TERMINAL_CHUNK_PATH) {
      res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(TERMINAL_CHUNK);
      return;
    }
    // ---- Vendored font assets for the IOI-owned port surfaces (pixel-certified ports render with the
    // reference's OSS type metrics — Source Sans Pro, SIL OFL; see assets/fonts/LICENSE-NOTES.md).
    // WHITELIST only — no path traversal, no directory serving.
    if (pathname.startsWith("/__ioi/fonts/") && req.method === "GET") {
      const IOI_FONT_WHITELIST = new Set(["source-sans-pro-400.woff2", "source-sans-pro-600.woff2", "source-sans-pro-700.woff2"]);
      const fname = pathname.slice("/__ioi/fonts/".length);
      if (!IOI_FONT_WHITELIST.has(fname)) { res.writeHead(404); res.end("not found"); return; }
      try {
        const buf = readFileSync(join(HERE, "..", "assets", "fonts", fname));
        res.writeHead(200, { "Content-Type": "font/woff2", "Cache-Control": "public, max-age=86400, immutable" });
        res.end(buf);
      } catch { res.writeHead(404); res.end("not found"); }
      return;
    }
    // Test-only fault route (mounted ONLY when the runtime-safety verifier spawns the serve with
    // this flag): proves the error boundary isolates a throwing surface to a 500 on that route.
    if (process.env.IOI_APP_RUNTIME_TEST_ROUTE === "1" && pathname === "/__ioi/__test/boom" && req.method === "GET") {
      throw new Error("intentional test-route failure (app-runtime-safety verifier)");
    }
    // ---- Run Replay index (native primitive, first slice) — the replay LIST over every recorded
    // run: live session runs (serve registry), durable operation/execution transcripts (daemon),
    // and IOI Agent coordination runs. Each row opens its owned timeline; nothing is synthesized.
    if ((pathname === "/__ioi/run-timeline" || pathname === "/__ioi/run-replay") && req.method === "GET" && !(new URLSearchParams((req.url || "").split("?")[1] || "").get("runId"))) {
      const J = (p) => fetch(`${DAEMON}${p}`).then((x) => x.json()).catch(() => ({}));
      const [trRes, grRes] = await Promise.all([J("/v1/hypervisor/agent-run-transcripts"), J("/v1/hypervisor/goal-runs")]);
      const rows = [];
      listRuns().forEach((r) => rows.push({ kind: "session", title: r.title || r.prompt || "agent session", id: r.id, status: r.status || "", at: r.createdAt || "", root: "", href: `/__ioi/run-timeline/${encodeURIComponent(r.id)}` }));
      (trRes.runs || []).forEach((t) => rows.push({ kind: t.kind === "harness-profile-op" || t.kind === "model-route-op" ? "admin-op" : "execution", title: `${t.op || t.kind || "run"}${t.profile_ref ? " · " + t.profile_ref : ""}`, id: t.run_id || "", status: t.status || "", at: t.started_at || t.recorded_at || "", root: t.state_root || "", href: `/__ioi/run-timeline/${encodeURIComponent(t.run_id || "")}` }));
      (grRes.goal_runs || []).forEach((g) => rows.push({ kind: "ioi-agent", title: `coordination · ${String(g.normalized_goal || "goal").slice(0, 48)}`, id: g.goal_run_id || "", status: g.status || "", at: g.created_at || "", root: "", href: `/__ioi/run-timeline/goal-run/${encodeURIComponent(g.goal_run_id || "")}` }));
      rows.sort((a, b) => String(b.at).localeCompare(String(a.at)));
      const counts = {};
      rows.forEach((r) => { counts[r.kind] = (counts[r.kind] || 0) + 1; });
      const chip = (v, l) => `<button class="chip${v === "" ? " on" : ""}" data-rr="${v}" onclick="rrChip(this)">${l} ${v === "" ? rows.length : counts[v] || 0}</button>`;
      const rrRows = rows.slice(0, 60).map((r) => `<tr data-rrk="${CX_ESC(r.kind)}">
          <td>${CX_ESC(r.title)}<div style="color:#878a93;font-size:11px;margin-top:1px"><code style="font-size:10px">${CX_ESC(r.id)}</code></div></td>
          <td><span class="pill muted">${CX_ESC(r.kind)}</span></td>
          <td><span class="pill ${["done", "success", "succeeded"].includes(r.status) ? "ok" : ["failed", "failure", "error"].includes(r.status) ? "warn" : "muted"}">${CX_ESC(r.status || "—")}</span></td>
          <td>${CX_ESC(r.at)}</td>
          <td>${r.root ? `<code style="font-size:10px">${CX_ESC(String(r.root).slice(0, 20))}</code>` : "—"}</td>
          <td><a href="${r.href}" target="_blank" rel="noopener">replay ↗</a></td>
        </tr>`).join("");
      const inner = `<h1>Run Replay</h1><p class="sub">Every recorded run, newest first — live agent sessions, durable operation and execution transcripts, IOI Agent coordination. Each replay opens the owned timeline with its lineage, temporal trace, and proof. <a href="/__ioi/work-ledger">Proof stream →</a></p>
        ${rows.length ? `<div class="chips" id="rr-chips">${chip("", "All")}${chip("session", "Sessions")}${chip("execution", "Executions")}${chip("ioi-agent", "IOI Agent")}${chip("admin-op", "Admitted ops")}</div>
        <table><thead><tr><th>Run</th><th>Kind</th><th>Status</th><th>When</th><th>State root</th><th>Replay</th></tr></thead><tbody id="rr-body">${rrRows}</tbody></table><div class="empty" id="rr-empty" style="display:none">No runs of this kind yet.</div>
        <script>function rrChip(b){document.querySelectorAll('#rr-chips .chip').forEach(function(x){x.classList.toggle('on',x===b);});var w=b.getAttribute('data-rr');var n=0;document.querySelectorAll('#rr-body tr').forEach(function(r){var on=!w||r.getAttribute('data-rrk')===w;r.style.display=on?'':'none';if(on)n++;});document.getElementById('rr-empty').style.display=n?'none':'';}</script>`
        : `<div class="empty">No recorded runs yet — governed work lands here with a replayable timeline as it happens.</div>`}`;
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(automationsShell("Run Replay", inner));
      return;
    }
    // Owned Run Timeline surface (Hypervisor's transcript primitive). /__ioi/run-timeline/:runId
    // (or ?runId=). Any surface routes/embeds this by runId; it polls the timeline projection above.
    if (pathname === "/__ioi/run-timeline" || pathname.startsWith("/__ioi/run-timeline/")) {
      const rest = pathname.startsWith("/__ioi/run-timeline/") ? pathname.slice("/__ioi/run-timeline/".length) : "";
      let runId = "";
      let envId = "";
      if (rest.startsWith("goal-run/")) {
        // GoalRun proof page — the orchestration ladder as sections (Goal, Roles, Invocations,
        // Candidate Artifacts, Reconciliation, Proof), rendered from the daemon records.
        const grid = decodeURIComponent(rest.slice("goal-run/".length).split("/")[0]);
        const [gRes, eRes] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/goal-runs/${encodeURIComponent(grid)}`).then((x) => x.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/goal-runs/${encodeURIComponent(grid)}/events`).then((x) => x.json()).catch(() => ({})),
        ]);
        res.writeHead(gRes.ok ? 200 : 404, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(gRes.ok
          ? renderGoalRunTimeline(gRes.goal_run, eRes.invocations || [], eRes.verifications || [], eRes.events || [])
          : automationsShell("GoalRun", `<div class="empty">GoalRun not found.</div>`));
        return;
      }
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
    // ---- Harvested application seeds (harvest-port-as-seed method, superseding grammar-only
    // recreation): the mapped reference app's BOOTABLE capture artifact served under the estate
    // via live proxy to the local harvest capture. Adoption precedes recreation — the artifact IS
    // the seed; rebinding its data lanes to daemon truth is the next phase, and the interception
    // inventory below is that phase's map. Pure wire proxy: nothing harvested enters the repo.
    // Brand-cased strings are rebranded at the wire; code-token renames defer to the vendor
    // phase (AST-safe, like the shell's renameApiTokens).
    // Capture API families some seed documents call (observed in seed rebind maps). Served
    // same-origin through this proxy so seeds boot under the estate; their upstream is the
    // harvest capture, never fabricated data.
    const MIRROR_API_PREFIXES = ["/multipass/", "/graphql-gateway/", "/compass/", "/documentation/", "/aip-assist/", "/monocle/", "/approvals/", "/workspace/api/", "/log-receiver/", "/interventions/", "/ontology-metadata/", "/magritte-coordinator/", "/issues/", "/foundry-search/", "/marketplace/", "/object-set-service/", "/phonograph2/", "/language-model-service/", "/foundry-ml/", "/artifacts/", "/foundry-catalog/", "/models/", "/build2/", "/foundry-stemma/", "/third-party-applications/", "/developer-console/"];
    if (pathname.startsWith("/__apps/") || pathname.startsWith("/assets/content-addressable-storage/") || MIRROR_API_PREFIXES.some((pref) => pathname.startsWith(pref))) {
      // Per-seed fold flag: some seed documents hardcode the capture ORIGIN for their API layer
      // and only boot when those refs are folded to same-origin (lineage); self-bootstrapped
      // documents (approvals pilot) must be served byte-faithful apart from the brand rebrand.
      const HARVEST_APPS = {
        approvals: { base: "/workspace/approvals-app/", fold: true },   // Governance seed (REBOUND: task-request lanes answer with daemon approval-requests)
        lineage: { base: "/workspace/monocle/", fold: true },            // Provenance seed — bootable lineage-graph editor
        designer: { base: "/workspace/solution-design/", fold: false },  // Studio seed — typed-node system-diagram editor
        monitors: { base: "/workspace/object-monitoring/", fold: false },// Automations seed — condition→effect wizard
        changes: { base: "/workspace/upgrade-assistant/", fold: true },  // Improvement seed (REBOUND: intervention lanes answer with daemon improvement-proposals)
        // ---- Remaining porting queue (adopted on WORKING artifact seeds; editor enrichments
        // for gap surfaces arrive via live re-harvest once auth is refreshed — same lanes).
        schema: { base: "/workspace/ontology/", fold: true },            // Ontology seed — schema workbench (types/functions/health/history)
        explorer: { base: "/workspace/hubble/", fold: true },            // Ontology seed — object explorer + saved sets
        ingest: { base: "/workspace/hyperauto/", fold: true },           // Data seed — source-first pipeline wizard
        sources: { base: "/workspace/data-ingestion-app/", fold: true }, // Data seed — Sources/Syncs/Listeners IA
        evalsuites: { base: "/workspace/evals/", fold: true },           // Evaluations seed — eval-suite library
        analysis: { base: "/workspace/insight/", fold: true },           // Evaluations seed — object-set-first analysis
        jobs: { base: "/workspace/job-tracker/", fold: true },           // Missions seed — run/job status table
        incidents: { base: "/workspace/issues-app/", fold: true },       // Missions seed — status-lane remediation inbox
        listings: { base: "/workspace/marketplace/", fold: true },       // Marketplace seed — store browse + install wizard
        registry: { base: "/workspace/artifacts/", fold: true },         // Marketplace seed — versioned artifact registry
        models: { base: "/workspace/model-catalog/", fold: true },       // Foundry seed — model registry home
        devconsole: { base: "/workspace/developer-console/", fold: false },// Developer Console seed — OAuth app registration + SDK on-ramps (self-bootstrapped)
        widgets: { base: "/workspace/custom-widgets/", fold: false },    // Developer Console seed — widget-set authoring (dev-kit fork; self-bootstrapped)
        // ---- UX-parity sweep (capture-completeness first): recoverable application seeds wired
        // to boot under the estate. Data lanes stay UNBOUND (classified in the parity inventory);
        // fold to same-origin so origin-baked API refs resolve through this proxy. See
        // harvest-seed-inventory.mjs for the canonical map + owner surfaces + unbound-lane notes.
        machinery: { base: "/workspace/machinery-app/", fold: true },    // Studio — process/state-machine graph
        workshop: { base: "/workspace/workshop/", fold: true },          // Studio — application/module builder
        module: { base: "/workspace/module/", fold: true },              // Studio — compute-module builder
        scheduler: { base: "/workspace/scheduler/", fold: true },        // Automations/Operations — schedule table
        pipeline: { base: "/workspace/builder/", fold: true },           // Data — Pipeline Builder canvas
        dataset: { base: "/workspace/dataset/", fold: true },            // Data — dataset preview/table
        objectview: { base: "/workspace/object-view/", fold: true },     // Ontology — object view
        objecteditor: { base: "/workspace/object-view-editor/", fold: true }, // Ontology — object-view editor
        quiver: { base: "/workspace/quiver/", fold: true },              // Evaluations — time-series analysis canvas
        modelstudio: { base: "/workspace/model-studio/", fold: true },   // Foundry — model studio
        inference: { base: "/workspace/foundry-inference-app/", fold: true }, // Foundry — inference app
        developer: { base: "/workspace/developer/", fold: true },        // Developer Console — developer home
        workspaces: { base: "/workspace/code-workspaces/", fold: true }, // Workbench — code workspace IDE
        repositories: { base: "/workspace/code-repositories/", fold: true }, // Workbench — code repositories
        notepad: { base: "/workspace/notepad/", fold: true },            // Workbench — notepad document
        vertex: { base: "/workspace/vertex/", fold: true },              // Provenance/graph — Vertex graph exploration
        map: { base: "/workspace/map/", fold: true },                    // Environments — geospatial map canvas
        slate: { base: "/workspace/slate/", fold: true },                // Domain Apps — Slate app builder
        logic: { base: "/workspace/logic-app/", fold: true },            // Domain Apps — Logic builder
        contour: { base: "/workspace/contour-app/", fold: true },        // Domain Apps — Contour analysis
        fusion: { base: "/workspace/fusion/", fold: true },              // Domain Apps — Fusion spreadsheet
      };
      const CAPTURE = process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225";
      // REBIND (approvals pilot, phase 2): the seed's task-request search lanes are answered
      // with DAEMON approval-requests mapped into the seed's own wire shape. Status filter,
      // sort, and page size from the request body are honored; identity-scoped subcounts stay
      // honest — the daemon records no creator, so myRequests is 0, never faked. Other
      // /approvals/api/* lanes (drilldown, reviewers) still pass through to the capture and
      // degrade honestly (named gap: per-row detail is a later rebind).
      // REBIND (Improvement seed): the change-inbox lanes are answered with DAEMON
      // improvement-proposals mapped into the seed's intervention wire shape. Every fact is
      // daemon truth (kind, signal, gate posture, simulation/approval/release refs, timestamps);
      // no due dates are invented — the daemon has none. Per-proposal stats reflect the real
      // proposal state (applied = complete, else pending). Identity is honestly unknown.
      if (pathname.startsWith("/interventions/api/")) {
        const send = (obj, status = 200) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
        const mapProposal = (pr) => {
          const ts = (t) => ({ userId: "", timestamp: t || pr.created_at || "" });
          // RID suffix must be UUID-shaped (the seed's locator parser rejects underscores).
          // Deterministic + reversible: the 16-hex daemon id doubled into UUID grouping —
          // the REAL id is the first 16 hex chars.
          const hex = String(pr.improvement_id || "").replace(/^imp_/, "").padEnd(16, "0").slice(0, 16);
          const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(0, 4)}-${hex.slice(4, 16)}`;
          const applied = pr.state === "applied";
          const closed = applied || pr.state === "rejected";
          const status = closed
            ? { type: "finishedInterventionStatus", finishedInterventionStatus: { draft: ts(pr.created_at), prePublished: ts(pr.created_at), published: ts(pr.updated_at), finished: ts(pr.reviewed_at || pr.updated_at) } }
            : { type: "publishedInterventionStatus", publishedInterventionStatus: { draft: ts(pr.created_at), prePublished: ts(pr.created_at), published: ts(pr.updated_at) } };
          const gate = pr.gate || {};
          return {
            rid: `ri.interventions.main.intervention.${uuid}`,
            key: `hypervisor:${pr.proposal_kind || "improvement"}`,
            status,
            type: "ADMIN_ACTION",
            // The seed REQUIRES a dueDate (its parser splits it unconditionally); the daemon's
            // gates are event-driven with no deadlines. The date shown is the proposal's REAL
            // last-update time, and the row copy says so — no deadline is invented.
            dueDate: pr.updated_at || pr.created_at || "",
            title: `${pr.proposal_kind || "improvement"} · ${(pr.suggested && pr.suggested.description) || pr.target_ref || pr.improvement_id}`,
            shortDescription: `signal: ${pr.signal || "—"} · gate: ${gate.posture || "—"}${gate.high_impact ? " · high impact" : ""} · confidence ${pr.confidence ?? "—"} · no deadline (date = last update)`,
            longDescriptionMarkdown: [
              `**Proposal** \`${pr.proposal_ref || pr.improvement_id}\` (kind \`${pr.proposal_kind || "—"}\`, state \`${pr.state || "—"}\`)`,
              `**Target** \`${pr.target_ref || "—"}\``,
              `**Gate** posture \`${gate.posture || "—"}\`${gate.block_code ? ` · block \`${gate.block_code}\`` : ""}${gate.high_impact ? " · **high impact**" : ""}`,
              pr.latest_simulation_ref ? `**Simulation** \`${pr.latest_simulation_ref}\` (hash \`${(pr.latest_simulation_hash || "").slice(0, 24)}…\`)` : "**Simulation** none yet",
              pr.approval_request_ref ? `**Approval** \`${pr.approval_request_ref}\`` : "",
              pr.release_control_ref ? `**Release control** \`${pr.release_control_ref}\`` : "",
              (pr.evidence_refs || []).length ? `**Evidence** ${(pr.evidence_refs || []).map((e) => `\`${e}\``).join(", ")}` : "",
            ].filter(Boolean).join("\n\n"),
            remediationMarkdown: applied
              ? `Applied as \`${pr.applied_ref || "—"}\` — receipts: ${(pr.receipt_refs || []).map((e) => `\`${e}\``).join(", ") || "—"}.`
              : `Review and decide in Studio → Improvement proposals (/__ioi/agent-studio#improvement-proposals): simulate impact, then approve/apply under the governance gate.`,
            impactMarkdown: gate.high_impact || pr.latest_simulation_high_impact ? "The daemon's simulation marks this change **high impact** — it requires the full gate (fresh simulation + approval + open release)." : "Not marked high-impact by simulation.",
            impactedResourcesMarkdown: `Target: \`${pr.target_ref || "—"}\`.`,
            troubleshootingMarkdown: "",
            attributions: { registered: ts(pr.created_at), lastUpdated: ts(pr.updated_at) },
            entryType: "COMPASS",
            entrySource: "SUPPLIED_BY_SERVICE",
            isReusable: false,
            supportsFixSuggestions: false,
          };
        };
        try {
          if (pathname === "/interventions/api/interventions/v2/list") {
            const pj = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals`).then((r) => r.json());
            const mapped = (pj.proposals || []).map(mapProposal);
            return send({ interventions: mapped });
          }
          const statsMatch = pathname.match(/^\/interventions\/api\/interventions\/ri\.interventions\.main\.intervention\.([a-z0-9-]+)\/(?:compass\/)?stats\/search$/);
          if (statsMatch) {
            const idHex = statsMatch[1].replace(/-/g, "").slice(0, 16);
            const pj = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals`).then((r) => r.json());
            const pr = (pj.proposals || []).find((x) => String(x.improvement_id || "").replace(/^imp_/, "") === idHex);
            const done = pr && (pr.state === "applied" || pr.state === "rejected") ? 1 : 0;
            const pend = pr && !(pr.state === "applied" || pr.state === "rejected") ? 1 : 0;
            return send({ stats: { numPendingResources: { ignored: 0, nonIgnored: pend }, numCompleteResources: { ignored: 0, nonIgnored: done } } });
          }
          // organizations pass through to the capture (the client scopes the estate by operator
          // organizations; an empty list hides every row — a real identity mapping is the
          // rebind's next phase).
          if (pathname === "/interventions/api/record/visit") return send({});
          // other intervention lanes fall through to the capture passthrough below
        } catch (e) {
          return send({ error: { message: `daemon unreachable: ${e.message}` } }, 502);
        }
      }
      // REBIND (Missions seed, run queue): the /__apps/jobs seed (job-tracker) reads its build
      // table via GraphQL OverviewPageQuery; the serve answers it with the daemon's REAL run
      // estate — goal-runs (drafts excluded: not yet runs), sessions (the daemon's own
      // newest-50 list projection), and automation executions — mapped into the seed's
      // BuildReport wire shape. Every rendered fact is daemon truth: statuses map by closest
      // category (complete/executed/done→SUCCEEDED, blocked/execution_failed→FAILED,
      // active/provisioned→RUNNING, stopped→CANCELED); times are the daemon's own timestamps
      // (a goal-run's finish time is its real last-update-at-completion; sessions record no
      // finish time → finishedAt null, never invented); the Outputs cell carries the daemon
      // ref VERBATIM and deep-links to the estate's own truth surface (run timelines,
      // sessions root); automation executions attribute to their automation by name through
      // the seed's schedule lane. Identity-scoped filters (userIds) match nothing — the
      // daemon maps no seed-user identity yet (identity mapping phase), so "Your builds" is
      // honestly empty until the operator clears the identity filter.
      if (pathname.startsWith("/graphql-gateway/api/graphql") && req.method === "POST") {
        let gqlDoc = null;
        try { gqlDoc = JSON.parse(body || "null"); } catch { /* not JSON — passthrough */ }
        const gqlOp = gqlDoc && !Array.isArray(gqlDoc) ? gqlDoc : null;
        const sendJson = (obj, status = 200) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
        if (gqlOp && gqlOp.operationName === "JobTypeFilterQuery" && String(gqlOp.query || "").includes("jobTypes")) {
          // The job-type filter dropdown carries OUR real run kinds, not the reference
          // platform's build-worker registry.
          return sendJson({ data: { jobTypes: ["goal-run", "session", "automation-run"], transformTypes: [], __typename: "Query" } });
        }
        // REBIND (Foundry model-catalog seed): the model-catalog home lists PALANTIR_PROVIDED
        // reference models from the capture; the serve answers ModelCatalogHomeQuery with the
        // DAEMON model-route registry instead — the catalog shows IOI's real routes, not captured
        // vendor models. The captured response is used ONLY as a valid fragment ENVELOPE (the seed's
        // deep LanguageModelV4 fragments must resolve to render a row); every identity/fact field is
        // overwritten with daemon truth (model id, provider binding, default marker, availability→
        // lifecycle: available=GA, else non-GA — never a faked GA), reference URLs are dropped, and
        // the row count is the registry's own (1 local route today → a 1-model catalog, honest).
        if (gqlOp && gqlOp.operationName === "ModelCatalogHomeQuery") {
          try {
            const [capResp, routesJson] = await Promise.all([
              fetch(`${CAPTURE}/graphql-gateway/api/graphql`, { method: "POST", headers: { "content-type": "application/json" }, body }).then((r) => r.json()).catch(() => null),
              fetch(`${DAEMON}/v1/hypervisor/model-routes`).then((r) => r.json()).catch(() => ({})),
            ]);
            const template = capResp && capResp.data && capResp.data.languageModelsV4 && (capResp.data.languageModelsV4.values || [])[0];
            const routes = (routesJson && routesJson.routes) || [];
            if (!template) return sendJson(capResp || { data: { languageModelsV4: { values: [], nextPageToken: null, __typename: "LanguageModelV4Connection" }, __typename: "Query" } });
            const b64 = (s) => Buffer.from(String(s)).toString("base64");
            const uuidOf = (s) => { let h1 = 0x811c9dc5, h2 = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h1 = Math.imul(h1 ^ s.charCodeAt(i), 0x01000193) >>> 0; h2 = Math.imul(h2 ^ s.charCodeAt(s.length - 1 - i), 0x01000193) >>> 0; } const hx = (h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0")).padEnd(32, "0"); return `${hx.slice(0, 8)}-${hx.slice(8, 12)}-${hx.slice(12, 16)}-${hx.slice(16, 20)}-${hx.slice(20, 32)}`; };
            const models = routes.map((r) => {
              const m = JSON.parse(JSON.stringify(template)); // clone the valid captured fragment structure
              const pb = r.provider_binding || {};
              const id = (r.model || {}).model_id || r.route_id;
              const gaType = (r.availability || {}).state === "available" ? "LanguageModelLifecycleStatus_GA" : "LanguageModelLifecycleStatus_Deprecated";
              m.name = id;
              m.displayName = `${r.display_name || id}${r.default_route ? " (default)" : ""}`;
              m.modelCreator = `${pb.provider_kind || "local"}${pb.transport ? " · " + pb.transport : ""}`;
              m.rid = `ri.language-model-service.main.language-model.${uuidOf(r.route_ref || id)}`;
              m._id = b64(r.route_ref || id);
              if (m.originInfo) { m.originInfo.modelIdentifier = id; m.originInfo.recommended = !!r.default_route; }
              if (m.resolvedDetails) {
                m.resolvedDetails.lifecycleStatus = { __typename: gaType };
                if (m.resolvedDetails.lifecycleStatusV2) m.resolvedDetails.lifecycleStatusV2 = { __typename: gaType };
                if (m.resolvedDetails.properties) { m.resolvedDetails.properties.externalUrl = null; }
              }
              return m;
            });
            return sendJson({ data: { me: capResp.data.me, languageModelsV4: { nextPageToken: null, values: models, __typename: capResp.data.languageModelsV4.__typename }, __typename: "Query" } });
          } catch (e) { return sendJson({ errors: [{ message: `daemon unreachable: ${e.message}` }] }, 502); }
        }
        // Gate on the FIELD, not the operation name: the seed reads buildsV2 through
        // OverviewPageQuery and through its new-builds poller (a different operation with
        // the same field + a minStartTime filter).
        if (gqlOp && String(gqlOp.query || "").includes("buildsV2(")) {
          try {
            // Deterministic UUID-shaped rid tails (the seed's locator parsers reject
            // non-UUID tails): FNV-1a over the daemon ref, forward + reverse, 16 hex.
            const fnv = (s, rev) => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h = Math.imul(h ^ s.charCodeAt(rev ? s.length - 1 - i : i), 0x01000193) >>> 0; } return h.toString(16).padStart(8, "0"); };
            const uuidOf = (s) => { const h = fnv(s, false) + fnv(s, true); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(0, 4)}-${h.slice(4, 16)}`; };
            const b64 = (s) => Buffer.from(String(s)).toString("base64");
            const mkResource = (name, openUrl, icon) => { const rid = `ri.compass.main.resource.${uuidOf("res:" + name)}`; return { rid, collections: [], status: null, trashedStatus: "NOT_TRASHED", type: { iconName: icon, __typename: "ResourceTypeMetadata" }, alias: "", name, openUrl, permissions: { canOpenLink: true, _id: b64(rid + ":perm"), __typename: "ResourcePermissions" }, ancestors: [], path: name, autosaved: false, _id: b64(rid), __typename: "ResourceMetadata" }; };
            const mkOutput = (name, openUrl, icon) => ({ rid: `ri.compass.main.resource.${uuidOf("res:" + name)}`, name, resource: mkResource(name, openUrl, icon), branch: null, branchName: "", __typename: "JobOutput" });
            // workerDetails must be a non-null object (the seed reads
            // jobSpec?.workerDetails.__typename without a null guard); a foreign typename
            // falls through its sync-worker special case.
            const mkJob = (key, status) => ({ status, jobSpec: { rid: `ri.foundry.main.jobspec.${uuidOf("jobspec:" + key)}`, workerDetails: { __typename: "HypervisorWorkerDetails" }, _id: b64("jobspec:" + key), __typename: "JobSpec" }, _id: b64("job:" + key), __typename: "JobReport" });
            const mkBuild = (o) => ({
              kind: o.kind, // interceptor-side filter key, harmless extra field on the wire
              rid: `ri.foundry.main.build.${uuidOf(o.refKey)}`,
              status: o.status,
              started: { time: o.startedAt || "", user: null, __typename: "BuildStartedRecord" },
              finishedAt: o.finishedAt || null,
              outputs: { values: [mkOutput(o.name, o.openUrl, o.icon)], totalNumberOfResults: 1, nextPageToken: null, __typename: "JobOutputsPage" },
              jobs: o.jobs,
              scheduleRun: o.schedule ? { scheduleVersion: { schedule: { rid: `ri.scheduler.main.schedule.${uuidOf("auto:" + o.schedule.id)}`, name: o.schedule.name, _id: b64("sched:" + o.schedule.id), __typename: "Schedule" }, _id: b64("schedv:" + o.schedule.id), __typename: "ScheduleVersion" }, _id: b64("schedrun:" + o.refKey), __typename: "ScheduleRun" } : null,
              _id: b64("build:" + o.refKey),
              __typename: "BuildReport",
            });
            const [grj, ssj, atj] = await Promise.all([
              fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((r) => r.json()),
              fetch(`${DAEMON}/v1/hypervisor/sessions`).then((r) => r.json()),
              fetch(`${DAEMON}/v1/hypervisor/automations`).then((r) => r.json()),
            ]);
            const autoDefs = atj.automations || [];
            const runsPer = await Promise.all(autoDefs.map((a) => fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(a.automation_id)}/runs`).then((r) => r.json()).catch(() => ({}))));
            const rows = [];
            const grStatus = { complete: "SUCCEEDED", blocked: "FAILED", active: "RUNNING" };
            for (const g of grj.goal_runs || []) {
              if (g.status === "draft") continue; // a draft is not yet a run
              const st = grStatus[g.status] || "RUNNING";
              const id = String(g.goal_ref || g.goal_run_id || "").replace(/^goal:\/\//, "");
              rows.push(mkBuild({ kind: "goal-run", refKey: `goal-run:${id}`, status: st, startedAt: g.created_at, finishedAt: g.status === "complete" ? g.updated_at : null, name: g.goal_ref || id, openUrl: `/__ioi/run-timeline/goal-run/${encodeURIComponent(id)}`, icon: "flows", jobs: [mkJob(`goal-run:${id}`, st)] }));
            }
            const ssStatus = { provisioned: "RUNNING", executed: "SUCCEEDED", execution_failed: "FAILED" };
            for (const s of ssj.sessions || []) {
              const st = ssStatus[s.lifecycle_state] || "RUNNING";
              const ref = String(s.session_ref || "");
              rows.push(mkBuild({ kind: "session", refKey: `session:${ref}`, status: st, startedAt: s.created_at, finishedAt: null, name: ref, openUrl: "/__ioi/sessions", icon: "application", jobs: [mkJob(`session:${ref}`, st)] }));
            }
            const axStatus = { done: "SUCCEEDED", failed: "FAILED", running: "RUNNING", stopped: "CANCELED" };
            const stepStatus = { done: "SUCCEEDED", failed: "FAILED", running: "RUNNING", stopped: "CANCELED", pending: "RUNNING" };
            autoDefs.forEach((a, i) => {
              for (const x of (runsPer[i] && runsPer[i].runs) || []) {
                const st = axStatus[x.status] || "RUNNING";
                const jobs = (x.step_results || []).map((sr, k) => mkJob(`aex:${x.execution_id}:${k}`, stepStatus[sr.status] || "RUNNING"));
                rows.push(mkBuild({ kind: "automation-run", refKey: `aex:${x.execution_id}`, status: st, startedAt: x.started_at, finishedAt: x.finished_at || null, name: x.execution_id, openUrl: `/__ioi/run-timeline/${encodeURIComponent(x.execution_id)}`, icon: "automatic-updates", jobs: jobs.length ? jobs : [mkJob(`aex:${x.execution_id}`, st)], schedule: { id: a.automation_id, name: a.name || a.automation_id } }));
              }
            });
            const vars = gqlOp.variables || {};
            const matchOne = (row, f) => {
              if (!f) return true;
              if (Array.isArray(f.userIds) && f.userIds.length) return false; // identity unmapped — honestly no rows
              if (f.minStartTime && String(row.started.time) < String(f.minStartTime)) return false; // new-builds poller window
              if (Array.isArray(f.buildStatuses) && f.buildStatuses.length && !f.buildStatuses.includes(row.status)) return false;
              if (Array.isArray(f.jobTypes) && f.jobTypes.length && !f.jobTypes.includes(row.kind)) return false;
              if (Array.isArray(f.excludedJobTypes) && f.excludedJobTypes.length && f.excludedJobTypes.includes(row.kind)) return false;
              if (Array.isArray(f.transformTypes) && f.transformTypes.length) return false; // runs carry no transform types
              if (Array.isArray(f.branches) && f.branches.length) return false; // runs carry no branches
              for (const k of ["buildRids", "buildInputRids"]) if (Array.isArray(f[k]) && f[k].length && !f[k].includes(row.rid)) return false;
              for (const k of ["outputRids", "jobOutputRids"]) if (Array.isArray(f[k]) && f[k].length && !f[k].some((rid) => row.outputs.values.some((v) => v.rid === rid))) return false;
              return true;
            };
            const filters = Array.isArray(vars.filter) ? vars.filter : [];
            let list = rows.filter((r) => (filters.length ? filters.some((f) => matchOne(r, f)) : true));
            const desc = (vars.sortDirection || "DESCENDING") === "DESCENDING";
            const key = vars.sortType === "BY_FINISHED_TIME" ? (r) => String(r.finishedAt || "") : (r) => String(r.started.time || "");
            list = list.slice().sort((a, b) => (desc ? key(b).localeCompare(key(a)) : key(a).localeCompare(key(b))));
            const from = Number(vars.pageToken || 0) || 0;
            const pageSize = Number(vars.pageSize || 30) || 30;
            const page = list.slice(from, from + pageSize);
            return sendJson({ data: { buildsV2: { values: page, nextPageToken: from + pageSize < list.length ? String(from + pageSize) : null, __typename: "BuildReportsPage" }, __typename: "Query" } });
          } catch (e) {
            return sendJson({ errors: [{ message: `daemon unreachable: ${e.message}` }] }, 502);
          }
        }
        // REBIND (Marketplace seed): the /__apps/listings seed (marketplace) browses stores
        // and products through GraphQL searchMarketplaceProducts / searchResources /
        // remoteMarketplaces; the serve answers with the DAEMON marketplace plane. One local
        // store exists — the estate's own listing plane. Every product fact is daemon truth
        // (listing name/description verbatim, real timestamps); status maps by the plane's
        // own semantics: public_state "published" (admitted review + open release + serving
        // runtime, receipted) → INSTALLABLE; drafts stay unlisted and NEVER appear as
        // installable. Install counts are the plane's truth (no install records → 0). No
        // remote stores exist. Store/product drill-down routes are NOT in the capture cache —
        // named gap (live re-harvest target), not faked here.
        if (gqlOp && (String(gqlOp.query || "").includes("searchMarketplaceProducts(") || String(gqlOp.query || "").includes("LOCAL_MARKETPLACE") || String(gqlOp.query || "").includes("remoteMarketplaces("))) {
          try {
            const fnv = (s, rev) => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h = Math.imul(h ^ s.charCodeAt(rev ? s.length - 1 - i : i), 0x01000193) >>> 0; } return h.toString(16).padStart(8, "0"); };
            const uuidOf = (s) => { const h = fnv(s, false) + fnv(s, true); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(0, 4)}-${h.slice(4, 16)}`; };
            const b64 = (s) => Buffer.from(String(s)).toString("base64");
            const STORE_RID = `ri.marketplace.main.local-store.${uuidOf("hypervisor-marketplace-plane")}`;
            const store = { rid: STORE_RID, _id: b64(STORE_RID), __typename: "LocalMarketplace", metadata: { name: "Estate Marketplace — governed listing plane", parent: null, description: "Listings drafted over real substrate. Publish is the governed path: admitted review + open release control + serving runtime, receipted.", _id: b64(STORE_RID + ":meta"), __typename: "MarketplaceMetadata" } };
            const q = String(gqlOp.query || "");
            if (q.includes("remoteMarketplaces(")) {
              return sendJson({ data: { remoteMarketplaces: { values: [], nextPageToken: null, __typename: "RemoteMarketplacesPage" }, __typename: "Query" } });
            }
            if (q.includes("LOCAL_MARKETPLACE")) {
              return sendJson({ data: { searchResources: { nextPageToken: null, results: [{ resource: { resource: store, _id: b64(STORE_RID + ":res"), __typename: "ResourceWrapper" }, __typename: "SearchResourcesResult" }], __typename: "SearchResourcesPage" }, __typename: "Query" } });
            }
            const lj = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`).then((r) => r.json());
            const listings = lj.listings || [];
            const vars = gqlOp.variables || {};
            // StoreTableQuery pins its status filter in the query TEXT, not variables.
            const wantStatus = Array.isArray(vars.productStatus) ? vars.productStatus
              : (vars.productStatus === undefined && /productStatus:\s*INSTALLABLE/.test(q) ? ["INSTALLABLE"] : null);
            const text = String(vars.productMetadataQuery || "").toLowerCase();
            const statusOf = (l) => (l.public_state === "published" ? "INSTALLABLE" : "UNPUBLISHED_DRAFT");
            const matched = listings.filter((l) => {
              if (text && !(`${l.name} ${l.description} ${l.listing_kind} ${l.subject_ref}`.toLowerCase().includes(text))) return false;
              if (Array.isArray(vars.marketplaceRids) && vars.marketplaceRids.length && !vars.marketplaceRids.includes(STORE_RID)) return false;
              if (wantStatus && wantStatus.length && !wantStatus.includes(statusOf(l))) return false;
              return true;
            });
            const mkProduct = (l) => ({
              id: l.id,
              _id: b64(String(l.ref || l.id)),
              __typename: "MarketplaceProduct",
              status: statusOf(l),
              marketplace: store,
              installationCount: 0,
              attributes: { isFeatured: false, __typename: "MarketplaceProductAttributes" },
              latestVersion: {
                versionId: uuidOf(`${l.ref}:${l.updated_at}`),
                about: { title: [], description: [], fallbackTitle: l.name || l.id, fallbackDescription: `${l.description || ""} — ${l.listing_kind} over ${l.subject_ref} · ${l.public_state}${l.publish_receipt_refs && l.publish_receipt_refs.length ? " · receipted" : ""}`, __typename: "MarketplaceLocalizedTitleAndDescription" },
                thumbnail: null,
                documentation: { attachments: [], __typename: "MarketplaceProductVersionDocumentation" },
                _id: b64(`${l.ref}:v`),
                __typename: "MarketplaceProductVersion",
              },
            });
            const data = { searchMarketplaceProducts: { __typename: "MarketplaceProductSearch" }, __typename: "Query" };
            if (q.includes("values {")) {
              const pageSize = Number(vars.pageSize || 24) || 24;
              data.searchMarketplaceProducts.values = matched.slice(0, pageSize).map(mkProduct);
              data.searchMarketplaceProducts.nextPageToken = null;
            }
            if (q.includes("aggregates {")) {
              data.searchMarketplaceProducts.aggregates = { marketplaceCounts: [{ marketplace: store, productCount: matched.length, __typename: "MarketplaceProductSearch_MarketplaceCount" }], __typename: "MarketplaceProductSearchAggregates" };
            }
            return sendJson({ data });
          } catch (e) {
            return sendJson({ errors: [{ message: `daemon unreachable: ${e.message}` }] }, 502);
          }
        }
        // other GraphQL operations fall through to the capture passthrough
      }
      // Upload honesty: the estate has NO product-zip upload lane — listings are drafted
      // through the daemon API over real substrate; never advertise an affordance that
      // does not exist.
      if (pathname === "/marketplace/api/block-set-transport/permissions/user-upload-quota") {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ isUploadFromMarketplaceEnabled: false }));
      }
      // REBIND (Missions seed, incident lane): the /__apps/incidents seed (issues-app)
      // searches its inbox via /issues/api/search/issues/v2/{search,batch}; the serve answers
      // with the daemon's provider-failure incidents mapped into the seed's issue wire shape.
      // Every fact is daemon truth: title = failure kind + environment ref verbatim, status by
      // closest category (recovered→CLOSED, anything not recovered→OPEN), the detection time
      // is the only timestamp (nothing else is recorded), reporter identity honestly unknown.
      // Severity renders the seed's closest category for a lost-workload provider failure
      // (high); incidents cannot be fabricated through this lane — the daemon exposes no
      // incident-creation API (405), they exist only when the failover machinery records one.
      if (pathname === "/issues/api/search/issues/v2/search" || pathname === "/issues/api/search/issues/v2/batch") {
        const sendJson = (obj, status = 200) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
        try {
          const ij = await fetch(`${DAEMON}/v1/hypervisor/incidents`).then((r) => r.json());
          const fnv = (s, rev) => { let h = 0x811c9dc5; for (let i = 0; i < s.length; i++) { h = Math.imul(h ^ s.charCodeAt(rev ? s.length - 1 - i : i), 0x01000193) >>> 0; } return h.toString(16).padStart(8, "0"); };
          const uuidOf = (s) => { const h = fnv(s, false) + fnv(s, true); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(0, 4)}-${h.slice(4, 16)}`; };
          const issues = (ij.incidents || []).map((inc) => ({
            rid: `ri.issues.main.issue.${uuidOf(String(inc.incident_ref || ""))}`,
            title: `${inc.failure_kind || "provider failure"} · ${inc.environment_ref || ""}`,
            status: inc.status === "recovered" ? "CLOSED" : "OPEN",
            archived: false,
            severity: "HIGH_PRIORITY",
            assignees: [],
            attribution: { userId: "", time: inc.detected_at || "" },
            // Same time on both records: the daemon records only the detection time, and the
            // seed hides the "updated" line when the two are equal — no update time invented.
            lastUpdateAttribution: { userId: "", time: inc.detected_at || "" },
            // The seed's metadata union is data|resource|objectData (a linked platform
            // resource). Incidents reference an ENVIRONMENT, which has no compass resource —
            // a foreign tag falls through every union guard, so the resource cell renders
            // empty instead of a fabricated link.
            metadata: { type: "none" },
          }));
          // The seed's own filter grammar (captured from its search-filter assembly):
          // status/archived/severity/text/label + identity (directAssignee/mentionee/
          // reporter), resource (targetRid/branch/column), dates, and "not" negation.
          const applyOne = (r, f) => {
            if (!f || !f.type) return true;
            if (f.type === "not") return !applyOne(r, f.not);
            if (f.type === "status") { const s = f.status || {}; if (s.type === "exclude") return !(s.exclude || []).includes(r.status); if (s.type === "include") return (s.include || []).includes(r.status); return true; }
            if (f.type === "archived") return (f.archived === "ARCHIVED") === !!r.archived;
            if (f.type === "severity") { const inc = (f.severity && f.severity.severities) || []; return !inc.length || inc.includes(r.severity); }
            if (f.type === "directAssignee" || f.type === "mentionee" || f.type === "reporter") return false; // identity unmapped — honestly no rows
            if (f.type === "label") { const l = f.label || {}; return (l.includeUnlabeled && !(l.labels || []).length) || false; } // rows carry no labels
            if (f.type === "targetRid" || f.type === "branch" || f.type === "column" || f.type === "supportType") return false; // no compass targets / support types
            if (f.type === "text") { const qs = (f.text && f.text.queries) || []; return qs.every((q) => r.title.toLowerCase().includes(String(q).toLowerCase())); }
            if (f.type === "dueDate") return false; // incidents have no due dates — never invented
            if (f.type === "creationDate" || f.type === "updatedDate") { const d = f[f.type === "creationDate" ? "creationDate" : "updatedDate"] || {}; const t = String(r.attribution.time); return (!d.after || t >= d.after) && (!d.before || t <= d.before); }
            return true;
          };
          const applyFilters = (rows, fs) => rows.filter((r) => (fs || []).every((f) => applyOne(r, f)));
          const answer = (q) => {
            const matched = applyFilters(issues, q.filters);
            const dir = ((q.sort || {}).direction || "DESC") === "DESC" ? -1 : 1;
            const sorted = matched.slice().sort((a, b) => dir * String(a.attribution.time).localeCompare(String(b.attribution.time)));
            const from = Number(q.from || 0) || 0;
            const page = sorted.slice(from, from + (Number(q.count || 40) || 40));
            const aggregations = {};
            for (const [name, spec] of Object.entries(q.aggregations || {})) aggregations[name] = { value: applyFilters(issues, [...(q.filters || []), ...((spec && spec.filters) || [])]).length };
            return { aggregations, hits: page.map((v) => ({ value: v })), hitCount: matched.length };
          };
          let reqDoc = {};
          try { reqDoc = JSON.parse(body || "{}"); } catch { /* shape-tolerant */ }
          return sendJson(pathname.endsWith("/batch") ? (Array.isArray(reqDoc) ? reqDoc.map(answer) : []) : answer(reqDoc));
        } catch (e) {
          return sendJson({ error: { message: `daemon unreachable: ${e.message}` } }, 502);
        }
      }
      if (pathname === "/approvals/api/search/task-requests" || pathname === "/approvals/api/search/task-requests/counts") {
        try {
          const gj = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`).then((r) => r.json());
          const mapStatus = (st) => st === "approved" ? "APPROVED" : (st === "denied" || st === "rejected") ? "DISAPPROVED" : (st === "pending" || st === "open") ? "PENDING_APPROVAL" : "CLOSED";
          // The seed bundle renders ONLY its closed type registry (foreign types are dropped by
          // the renderer lookup, verbatim vendor code). Daemon approval-requests are mapped to
          // its closest category — a request for authority over a resource ("access request");
          // every rendered FACT (title = real request_kind + reason, status, time, id) is daemon
          // truth. A native hypervisor task type in the registry is the vendor-phase reshape.
          const rows = (gj.approval_requests || []).map((a) => ({
            taskRid: `ri.approvals.main.task-request.${a.id}`,
            title: `${a.request_kind || "approval"} · ${a.reason || a.subject_ref || a.ref || ""}`,
            taskType: "compass:request-access-to-resource",
            creator: "",
            creationTime: a.created_at || "",
            status: mapStatus(a.status),
            customIndexedData: {},
          }));
          // Honor the seed\'s filter grammar like a real server — a row only appears in views
          // whose filters it satisfies. Identity filters (createdBy/reviewers/notReviewedBy)
          // match nothing: the daemon records no per-user identity on approval requests, so
          // identity-scoped views are honestly empty rather than faked.
          const applyFilter = (row, f) => {
            if (!f || !f.type) return true;
            if (f.type === "status") return (f.status?.statuses || []).includes(row.status);
            if (f.type === "taskType") return (f.taskType?.taskTypes || []).includes(row.taskType);
            if (f.type === "createdBy") return false;
            if (f.type === "notTitle") return !row.title.includes(f.notTitle?.contains || "");
            if (f.type === "title") return row.title.toLowerCase().includes(String(f.title?.contains || "").toLowerCase());
            if (f.type === "reviewers" || f.type === "notReviewedBy") return true; // identity unmapped — do not scope
            return true;
          };
          const applyAll = (filters) => rows.filter((r) => (filters || []).every((f) => applyFilter(r, f)));
          let reqBody = {};
          try { reqBody = JSON.parse(body || "{}"); } catch { /* shape-tolerant */ }
          res.writeHead(200, { "Content-Type": "application/json" });
          if (pathname.endsWith("/counts")) {
            const sub = reqBody.subFilters || {};
            const global = reqBody.globalFilters || [];
            const subCounts = {};
            for (const k of Object.keys(sub)) subCounts[k] = applyAll([...global, ...(sub[k] || [])]).length;
            if (!("all" in subCounts)) subCounts.all = applyAll(global).length;
            if (!("myRequests" in subCounts)) subCounts.myRequests = 0;
            if (!("reviewRequests" in subCounts)) subCounts.reviewRequests = rows.filter((r) => r.status === "PENDING_APPROVAL").length;
            return res.end(JSON.stringify({ totalCount: applyAll(global).length, subCounts }));
          }
          let list = applyAll(reqBody.filters);
          const desc = ((reqBody.sort || {}).order || "DESC") === "DESC";
          list = list.slice().sort((x, y) => desc ? String(y.creationTime).localeCompare(String(x.creationTime)) : String(x.creationTime).localeCompare(String(y.creationTime)));
          const totalCount = list.length;
          if (reqBody.pageSizeLimit) list = list.slice(0, reqBody.pageSizeLimit);
          return res.end(JSON.stringify({ requests: list, totalCount }));
        } catch (e) {
          res.writeHead(502, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: { message: `daemon unreachable: ${e.message}` } }));
        }
      }
      try {
        let target;
        let foldOrigin = false;
        if (pathname.startsWith("/assets/content-addressable-storage/") || MIRROR_API_PREFIXES.some((pref) => pathname.startsWith(pref))) {
          target = CAPTURE + req.url;
        } else {
          const seg = pathname.slice("/__apps/".length).split("/")[0];
          const seedDef = HARVEST_APPS[seg];
          const base = seedDef && seedDef.base;
          foldOrigin = !!(seedDef && seedDef.fold);
          if (!base) { res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" }); return res.end(automationsShell("Unknown seed", `<div class="empty">No harvested seed named <code>${CX_ESC(seg)}</code>. Available: ${Object.keys(HARVEST_APPS).map((k) => `<a href="/__apps/${k}">${k}</a>`).join(" ")}</div>`)); }
          const rest = pathname.slice(("/__apps/" + seg).length) || "/";
          target = CAPTURE + (rest === "/" ? base : base.replace(/\/$/, "") + rest);
        }
        const upstream = await fetch(target, {
          method: req.method,
          headers: req.headers["content-type"] ? { "Content-Type": req.headers["content-type"] } : undefined,
          body: ["GET", "HEAD"].includes(req.method) ? undefined : body,
        });
        const ct = upstream.headers.get("content-type") || "application/octet-stream";
        let buf = Buffer.from(await upstream.arrayBuffer());
        // Narrow, DECLARED wire transforms only (no semantic rewrite, no native replacement):
        //  (a) origin-fold — for fold-flagged seeds, absolute capture-origin refs become
        //      same-origin so the seed's API/chunk calls resolve through this proxy;
        //  (b) brand-cased string rewrite — the capitalized brand token becomes IOI so RENDERED
        //      seed text stays brand-clean. Applied to HTML and to JS (where the SPA holds the
        //      UI strings it renders at runtime); lowercase code identifiers/URLs are left as
        //      deferred code tokens. Static-asset parity accounts for these exact transforms.
        if (ct.includes("text/html")) {
          let html = buf.toString("utf8");
          if (foldOrigin) html = html.replace(/https?:\/\/(?:localhost|127\.0\.0\.1):9225/g, "");
          buf = Buffer.from(html.replace(/Palantir/g, "IOI"), "utf8");
        } else if (/javascript|ecmascript/.test(ct)) {
          let js = buf.toString("utf8");
          if (foldOrigin) js = js.replace(/https?:\/\/(?:localhost|127\.0\.0\.1):9225/g, "");
          buf = Buffer.from(js.replace(/Palantir/g, "IOI"), "utf8");
        }
        res.writeHead(upstream.status, { "Content-Type": ct, "Cache-Control": pathname.startsWith("/assets/") ? "public, max-age=86400" : "no-cache", "content-length": String(buf.length) });
        return res.end(buf);
      } catch {
        res.writeHead(503, { "Content-Type": "text/html; charset=utf-8" });
        return res.end(automationsShell("Harvest capture offline", `<div class="empty">The harvest capture is offline — this seed serves live from the local capture. Start <code>node internal-docs/reverse-engineering/palantir/server.js</code> (:9225, or set <code>IOI_HARVEST_CAPTURE_URL</code>) and reload.</div>`));
      }
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
        const js = augmentationBundle();
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
        const esc = CX_ESC; // the kit escaper (surfaces/kit.mjs) — no local duplicates
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
      const esc = CX_ESC; // the kit escaper (surfaces/kit.mjs) — no local duplicates
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
    // ---- Evaluations · Evalsuites — the AIP Evals landing port (#54). A DECLARATION LIBRARY over
    // the real eval-suite plane: no EvalRun execution, no scoring/verdicts/judging on this surface.
    if (pathname === "/__ioi/evaluations/evalsuites" && req.method === "GET") {
      const sj = await fetch(`${DAEMON}/v1/hypervisor/eval-suites`).then((r) => r.json()).catch(() => ({}));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderEvalsuitesPort(sj));
      return;
    }
    // ---- Improvement · Changes — the Upgrade Assistant inbox port (#53). A read-only projection
    // over the real improvement-proposal plane; apply/approve/release lanes stay on Agent Studio.
    if (pathname === "/__ioi/improvement/changes" && req.method === "GET") {
      const pj = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals`).then((r) => r.json()).catch(() => ({}));
      const qp = new URL(req.url, "http://x").searchParams;
      const lane = ["active", "pastdue", "archived"].includes(qp.get("lane")) ? qp.get("lane") : "active";
      const filter = qp.get("filter") === "all" ? "all" : "action";
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderChangesPort((pj.proposals || []).sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || ""))), lane, filter));
      return;
    }
    // ---- Data · Sources — the Data Connection landing port (#52). A DECLARED source catalog over
    // the real DataSource registry: no extraction, no connection test, no live connector read.
    if (pathname === "/__ioi/data/sources" && req.method === "GET") {
      const [ds, mr, cmj] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/data-sources`).then((r) => r.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/odk/materializing-runs`).then((r) => r.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/odk/connector-mappings`).then((r) => r.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderSourcesPort(ds, mr, cmj, new URL(req.url, "http://x").searchParams.get("dataSource") || ""));
      return;
    }
    // ---- Automations · Monitors — the Automate-overview port (#51). A read-only PROJECTION over
    // the real automation plane (specs + executions); authoring stays on /__ioi/automations.
    if (pathname === "/__ioi/automations/monitors" && req.method === "GET") {
      const aRes = await fetch(`${DAEMON}/v1/hypervisor/automations`).then((r) => r.json()).catch(() => ({}));
      const autos = aRes.automations || [];
      const runsEntries = await Promise.all(autos.map((a) =>
        fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(a.automation_id)}/runs`).then((r) => r.json()).then((j) => [a.automation_id, j.runs || []]).catch(() => [a.automation_id, []])));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderMonitorsPort(autos, Object.fromEntries(runsEntries)));
      return;
    }
    if (pathname.startsWith("/__ioi/automations/")) {
      const rest = pathname.slice("/__ioi/automations/".length);
      const [rawId, action] = rest.split("/");
      const id = decodeURIComponent(rawId);
      // Remediation fired from the Operations console (?back=ops) returns the operator there.
      const backTo = new URL(req.url, "http://x").searchParams.get("back") === "ops"
        ? "/__ioi/operations" : `/__ioi/automations/${encodeURIComponent(id)}`;
      if (action === "run" && req.method === "POST") {
        // Manual run: the daemon executor creates an env, runs the steps, and records a transcript.
        await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}/runs`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).catch(() => {});
        res.writeHead(302, { Location: backTo, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
      if ((action === "pause" || action === "resume") && req.method === "POST") {
        // Pause/resume the schedule = PATCH enabled (the daemon scheduler skips disabled specs).
        await fetch(`${DAEMON}/v1/hypervisor/automations/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: action === "resume" }) }).catch(() => {});
        res.writeHead(302, { Location: backTo, "Cache-Control": "no-cache" });
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

    // ---- App catalog — the registry of ported application surfaces (membership = parity-matrix
    // truth via app-catalog.mjs; every launcher lane renders from this one projection).
    if (pathname === "/__ioi/api/applications" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(appCatalog()));
      return;
    }
    // ---- Applications estate — the owned breadth launcher (Connections re-homed as Developer & Integrations).
    if (pathname === "/__ioi/applications" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderApplications());
      return;
    }
    // ---- Feedback & Annotations — the queue over the daemon feedback plane.
    if (pathname === "/__ioi/feedback" && req.method === "GET") {
      const flash = new URL(req.url, "http://x").searchParams.get("refused") || "";
      const [ov, li] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/feedback/overview`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/feedback-entries`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderFeedbackQueue(ov, li.feedback_entries || [], flash));
      return;
    }
    if (pathname === "/__ioi/feedback" && req.method === "POST") {
      const f = new URLSearchParams(body.toString("utf8"));
      const r = await fetch(`${DAEMON}/v1/hypervisor/feedback-entries`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ subject_ref: f.get("subject_ref") || "", entry_kind: f.get("entry_kind") || "feedback", body: f.get("body") || "", consent: f.get("consent") || "never_train" }) });
      const j = await r.json().catch(() => ({}));
      res.writeHead(302, { Location: r.ok ? "/__ioi/feedback" : `/__ioi/feedback?refused=${encodeURIComponent((j.error && j.error.message) || "invalid")}`, "Cache-Control": "no-cache" });
      return res.end();
    }
    if (pathname.startsWith("/__ioi/feedback/") && pathname.endsWith("/transition") && req.method === "POST") {
      const fid = decodeURIComponent(pathname.slice("/__ioi/feedback/".length).split("/")[0]);
      const f = new URLSearchParams(body.toString("utf8"));
      const payload = { transition: f.get("transition") || "" };
      if (f.get("converted_to_ref")) payload.converted_to_ref = f.get("converted_to_ref");
      const r = await fetch(`${DAEMON}/v1/hypervisor/feedback-entries/${encodeURIComponent(fid)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const j = await r.json().catch(() => ({}));
      res.writeHead(302, { Location: r.ok ? "/__ioi/feedback" : `/__ioi/feedback?refused=${encodeURIComponent((j.error && j.error.message) || "invalid")}`, "Cache-Control": "no-cache" });
      return res.end();
    }
    // ---- Evaluations — owner surface for the Evaluations family (eval-suite library). Renders the
    // inert eval-suite contract + real assessment subjects (Missions) + consent ladder + Foundry
    // model_eval drafts. Declaration-only; nothing scores/executes. /__ioi/feedback stays a sublane.
    if (pathname === "/__ioi/evaluations" && req.method === "GET") {
      const flash = new URL(req.url, "http://x").searchParams.get("refused") || "";
      const [suitesRes, ovRes, opsRes, grRes, foundryRes, fbOvRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/eval-suites`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/eval-suites/overview`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/operations`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/foundry/specs`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/feedback/overview`).then((x) => x.json()).catch(() => ({})),
      ]);
      const runs = (opsRes.runs) || {};
      const subjects = {
        missionRuns: Array.isArray(runs.recent) ? runs.recent : [],
        failedRuns: Array.isArray(runs.failures) ? runs.failures : [],
        blockers: (grRes.goal_runs || []).filter((r) => Array.isArray(r.blockers) && r.blockers.length),
      };
      const foundryEvalSpecs = (foundryRes.specs || foundryRes.model_specs || []).filter((s) => /eval/i.test(s.kind || s.spec_kind || s.intent || s.spec_type || ""));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderEvaluations(suitesRes.eval_suites || [], ovRes, subjects, foundryEvalSpecs, fbOvRes, flash));
      return;
    }
    if (pathname === "/__ioi/evaluations" && req.method === "POST") {
      const f = new URLSearchParams(body.toString("utf8"));
      const splitRefs = (v) => (v || "").split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
      const payload = {
        name: f.get("name") || "",
        subject_scope: f.getAll("subject_scope"),
        consent_requirements: f.getAll("consent_requirements"),
        evidence_requirements: f.getAll("evidence_requirements"),
        rubric_refs: splitRefs(f.get("rubric_refs")),
        candidate_refs: splitRefs(f.get("candidate_refs")),
      };
      const r = await fetch(`${DAEMON}/v1/hypervisor/eval-suites`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const j = await r.json().catch(() => ({}));
      res.writeHead(302, { Location: r.ok ? "/__ioi/evaluations" : `/__ioi/evaluations?refused=${encodeURIComponent((j.error && j.error.message) || "invalid")}`, "Cache-Control": "no-cache" });
      return res.end();
    }
    if (pathname.startsWith("/__ioi/evaluations/") && pathname.endsWith("/delete") && req.method === "POST") {
      const sid = decodeURIComponent(pathname.slice("/__ioi/evaluations/".length).split("/")[0]);
      await fetch(`${DAEMON}/v1/hypervisor/eval-suites/${encodeURIComponent(sid)}`, { method: "DELETE" }).catch(() => {});
      res.writeHead(302, { Location: "/__ioi/evaluations", "Cache-Control": "no-cache" });
      return res.end();
    }
    // ---- Search — typed cross-estate discovery, fan-out over live projections at query time.
    if (pathname === "/__ioi/search" && req.method === "GET") {
      const q = (new URL(req.url, "http://x").searchParams.get("q") || "").trim().toLowerCase();
      const J = (p) => fetch(`${DAEMON}${p}`).then((x) => x.json()).catch(() => ({}));
      const SOURCES = ["projects", "sessions", "automations", "model routes", "connectors", "ontologies", "data recipes", "surface descriptors", "manifests", "domain apps", "approval requests", "failover runs", "environments"];
      let groups = [];
      if (q) {
        const [pj, se, au, mr, cn, on, rc, sd, mf, da, ap, fo, ev] = await Promise.all([
          J("/v1/hypervisor/projects"), J("/v1/hypervisor/sessions"), J("/v1/hypervisor/automations"),
          J("/v1/hypervisor/model-routes"), J("/v1/hypervisor/connectors"), J("/v1/hypervisor/odk/domain-ontologies"),
          J("/v1/hypervisor/odk/data-recipes"), J("/v1/hypervisor/odk/surface-descriptors"), J("/v1/hypervisor/odk/manifests"),
          J("/v1/hypervisor/domain-apps"), J("/v1/hypervisor/governance/approval-requests"), J("/v1/hypervisor/failover/runs"),
          J("/v1/hypervisor/environments-summary?limit=60"),
        ]);
        const hit = (...fields) => fields.some((f) => String(f || "").toLowerCase().includes(q));
        const enc2 = encodeURIComponent;
        groups = [
          { name: "Projects", items: (pj.projects || []).filter((p) => hit(p.project_name, p.project_id, p.repository_url)).map((p) => ({ label: p.project_name || p.project_id, meta: p.repository_url || "", href: `/projects/${enc2(p.project_id || "")}`, top: true })) },
          { name: "Sessions", items: (se.sessions || []).filter((s) => hit(s.session_ref, s.project_ref, s.lifecycle_state)).map((s) => ({ label: s.session_ref, meta: `${s.lifecycle_state || ""} · ${s.project_ref || "no project"}`, href: "/__ioi/sessions" })) },
          { name: "Automations", items: (au.automations || []).filter((a) => hit(a.name, a.automation_id, a.trigger_kind)).map((a) => ({ label: a.name || a.automation_id, meta: a.trigger_kind || "", href: `/__ioi/automations/${enc2(a.automation_id)}` })) },
          { name: "Model routes", items: (mr.routes || []).filter((r) => hit(r.display_name, r.route_id, r.route_ref)).map((r) => ({ label: r.display_name || r.route_id, meta: `${(r.availability || {}).state || ""} · ${(r.custody || {}).weight_class || ""}`, href: "/__ioi/foundry" })) },
          { name: "Connectors", items: (cn.connectors || []).filter((c) => hit(c.name, c.connector_id, c.kind)).map((c) => ({ label: c.name || c.connector_id, meta: c.kind || "", href: "/__ioi/connections" })) },
          { name: "Ontologies", items: (on.ontologies || on.domain_ontologies || []).filter((o) => hit(o.domain, o.id, o.ref)).map((o) => ({ label: o.domain || o.id, meta: o.ref || "", href: `/__ioi/odk/ontologies/${enc2(o.id || "")}` })) },
          { name: "Data recipes", items: (rc.data_recipes || []).filter((r) => hit(r.name, r.id, r.ref)).map((r) => ({ label: r.name || r.id, meta: r.output_kind || "", href: `/__ioi/odk/data-recipes/${enc2(r.id || "")}` })) },
          { name: "Surface descriptors", items: (sd.surface_descriptors || []).filter((d) => hit(d.name, d.id, d.composition_pattern)).map((d) => ({ label: d.name || d.id, meta: d.composition_pattern || "", href: `/__ioi/odk/surface-descriptors/${enc2(d.id || "")}` })) },
          { name: "Manifests", items: (mf.manifests || []).filter((m) => hit(m.name, m.id, m.ref)).map((m) => ({ label: m.name || m.id, meta: m.ref || "", href: `/__ioi/odk/manifests/${enc2(m.id || "")}` })) },
          { name: "Domain apps", items: (da.domain_apps || []).filter((a) => hit(a.name, a.domain_app_id, a.surface_descriptor_ref)).map((a) => ({ label: a.name || a.domain_app_id, meta: a.visibility || "", href: `/__ioi/domain-apps/${enc2(a.domain_app_id || "")}` })) },
          { name: "Approval requests", items: (ap.approval_requests || []).filter((a) => hit(a.subject_ref, a.request_kind, a.id, a.status)).map((a) => ({ label: `${a.request_kind || "approval"} · ${a.subject_ref || ""}`, meta: a.status || "", href: "/__ioi/governance?tab=approvals" })) },
          { name: "Failover runs", items: (fo.runs || []).filter((r) => hit(r.run_ref, r.failure_condition, r.status, r.environment_ref)).map((r) => ({ label: r.run_ref, meta: `${r.status || ""} · ${r.failure_condition || ""}`, href: "/__ioi/operations" })) },
          { name: "Environments", items: ((ev.environments) || []).filter((e) => hit(e.id, e.project_id, e.phase)).map((e) => ({ label: e.id, meta: `${e.phase || ""} · ${e.project_id || ""}`, href: `/workspaces/${enc2(e.id)}`, top: true })) },
        ];
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderSearchResults(q, groups, SOURCES));
      return;
    }
    // ---- Code Repositories (folds into Workbench; repos over project truth + SCM posture).
    if (pathname === "/__ioi/code" && req.method === "GET") {
      const [pjRes, scmRes, ledRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/projects`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/scm-connectors`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/work-ledger`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderCodeRepositories(pjRes, scmRes, ledRes.entries || []));
      return;
    }
    // ---- Sessions root (rail root; session lifecycle facts + admitted bindings).
    if (pathname === "/__ioi/sessions" && req.method === "GET") {
      const [sessRes, envRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/sessions`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/environments-summary?limit=60`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderSessionsRoot(sessRes, envRes));
      return;
    }
    // ---- Home full readout (03-home graft) — deep-link target of the composer home's injected
    // governed-work band. Fetches fail to null (NOT {}) so the renderer can distinguish "daemon
    // did not answer" from an honestly empty projection.
    if (pathname === "/__ioi/home" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((x) => x.json()).catch(() => null);
      const [homeOps, homeLedger, homeSessions, homeApprovals, homeFoRuns] = await Promise.all([
        J("/v1/hypervisor/operations"),
        J("/v1/hypervisor/work-ledger"),
        J("/v1/hypervisor/sessions"),
        J("/v1/hypervisor/governance/approval-requests"),
        J("/v1/hypervisor/failover/runs"),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderHome(homeOps, homeLedger, homeSessions, homeApprovals, homeFoRuns));
      return;
    }
    // ---- Work Ledger — the owned proof stream (estate surface #10).
    if (pathname === "/__ioi/work-ledger" && req.method === "GET") {
      const projectId = new URL(req.url, "http://x").searchParams.get("project") || "";
      const r = await fetch(`${DAEMON}/v1/hypervisor/work-ledger${projectId ? "?project=" + encodeURIComponent(projectId) : ""}`).then((x) => x.json()).catch(() => ({}));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      const wlSel = new URL(req.url, "http://x").searchParams;
      res.end(renderWorkLedger(r.entries || [], projectId, { receipt: wlSel.get("receipt") || "", objectSet: wlSel.get("objectSet") || "" }));
      return;
    }
    // ---- Operations — execution health over the automation substrate (estate surface #9).
    // ---- Missions — owner surface for suite/run work (jobs + incidents seeds). Reads the real
    // operations run queue + goal-runs; renders the run/job queue and the mission-level incident
    // inbox (run failures + GoalRun blockers). Operations stays substrate/infra (separate route).
    if (pathname === "/__ioi/marketplace/listings" && req.method === "GET") {
      const listingsJson = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`).then((x) => x.json()).catch(() => ({}));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderMarketplaceBrowsePort(listingsJson));
      return;
    }
    if (pathname === "/__ioi/foundry/models" && req.method === "GET") {
      const routesJson = await fetch(`${DAEMON}/v1/hypervisor/model-routes`).then((x) => x.json()).catch(() => ({}));
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderModelCatalogPort(routesJson));
      return;
    }
    if (pathname === "/__ioi/missions/incidents" && req.method === "GET") {
      const [opsRes, grRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/operations`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((x) => x.json()).catch(() => ({})),
      ]);
      const qp = new URL(req.url, "http://x").searchParams;
      const lane = ["open", "closed", "all"].includes(qp.get("lane")) ? qp.get("lane") : "open";
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderIncidentsPort(opsRes, grRes.goal_runs || [], lane));
      return;
    }
    if (pathname === "/__ioi/missions" && req.method === "GET") {
      const [opsRes, grRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/operations`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderMissions(opsRes, grRes.goal_runs || []));
      return;
    }
    if (pathname === "/__ioi/operations" && req.method === "GET") {
      const [r, authpol, prov, provReceipts, spendRecon, storageB, storageInc, akashDepin, failoverRuns, failoverPlans2, goalRunsRes, ledgerRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/operations`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/auth/policy`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/providers`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/provider-receipts`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/provider-spend/reconciliation`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/storage-backends`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/storage-incidents`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/akash-deployments`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/failover/runs`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/failover/plans`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/work-ledger`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderOperations(r, authpol, prov, provReceipts, spendRecon, storageB, storageInc, akashDepin, failoverRuns, failoverPlans2, goalRunsRes.goal_runs || [], ledgerRes.entries || []));
      return;
    }
    // ---- Environments — substrate estate; reads the daemon env-summary projection (paged) + classes.
    if (pathname === "/__ioi/environments" && req.method === "GET") {
      const offset = parseInt(new URL(req.url, "http://x").searchParams.get("offset") || "0", 10) || 0;
      const [sRes, cRes, paRes, pvRes, ppRes, srRes, saRes, pdRes, fpRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/environments-summary?limit=60&offset=${offset}`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/environment-classes`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/provider-accounts`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/placement/venues`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/placement/venue-policy`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/provider-spend/reconciliation`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/storage-archives`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/placement/decisions`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/failover/plans`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderEnvironments(sRes, cRes.environmentClasses || [], paRes, pvRes, ppRes, srRes, saRes, pdRes, fpRes));
      return;
    }
    // ---- Workbench — launcher; reads the daemon env-summary projection (paged).
    if (pathname === "/__ioi/workbench" && req.method === "GET") {
      const offset = parseInt(new URL(req.url, "http://x").searchParams.get("offset") || "0", 10) || 0;
      const [sRes, etRes, sessRes, grRes] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/environments-summary?limit=60&offset=${offset}`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/editor-targets`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/sessions`).then((x) => x.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/goal-runs`).then((x) => x.json()).catch(() => ({})),
      ]);
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderWorkbench(sRes, etRes, sessRes, grRes.goal_runs || []));
      return;
    }
    // ---- New Session launcher (02-new-session graft) — the owned rail-modal's daemon-backed
    // context + launch lane. Context is REAL registry/estate truth (projects, recent envs,
    // registry-derived harness matrix, model routes); launch forwards to the daemon session
    // create (harness selection admitted BEFORE provisioning, fail-closed) and then compiles the
    // capability-admitted knob binding (WS-D) so reasoning/speed are daemon objects, not UI state.
    // ---- IOI Agent launch lane (the user-facing product mode). Preview is a straight
    // daemon proxy; launch composes the daemon's two-phase wallet contract with THIS host's
    // wallet signer (the same local wallet-holder pattern as the /ai agent-run lane): phase A
    // provisions + returns the authority challenge, serve mints the grant, phase B executes.
    if (pathname === "/__ioi/api/ioi-agent/preview" && req.method === "POST") {
      const r = await fetch(`${DAEMON}/v1/hypervisor/ioi-agent/launch-preview`, { method: "POST", headers: { "content-type": "application/json" }, body: body.toString() || "{}" }).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : { ok: false, error: { code: "daemon_unavailable" } };
      res.writeHead(r ? r.status : 502, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(j));
      return;
    }
    if (pathname === "/__ioi/api/ioi-agent/launch" && req.method === "POST") {
      // node:http for both phases — undici fetch caps the response-header wait at a fixed 300s,
      // but a synchronous launch legitimately runs to the daemon's execution budgets (compare:
      // up to two 660s-reaped invocations + retry). The relay must outwait the daemon, not undici.
      const daemonLaunch = (payload) => new Promise((resolve) => {
        const target = new URL(`${DAEMON}/v1/hypervisor/ioi-agent/launch`);
        const reqUp = http.request(
          { hostname: target.hostname, port: target.port, path: target.pathname, method: "POST",
            headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) } },
          (r) => {
            let raw = "";
            r.on("data", (c) => { raw += c; });
            r.on("end", () => { let j = {}; try { j = JSON.parse(raw); } catch {} resolve({ status: r.statusCode, j }); });
          },
        );
        reqUp.on("error", () => resolve(null));
        reqUp.write(payload); reqUp.end();
      });
      const phaseA = await daemonLaunch(body.toString() || "{}");
      const a = phaseA ? phaseA.j : { error: { code: "daemon_unavailable" } };
      if (!phaseA || (phaseA.status !== 403 && phaseA.status >= 400) || a.reason !== "execution_authority_required") {
        res.writeHead(phaseA ? phaseA.status : 502, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
        res.end(JSON.stringify(a));
        return;
      }
      // #67 authority preflight: production holds NO signer — the launch parks in the honest
      // awaiting_wallet_authority state carrying the daemon's challenge verbatim; the dev test
      // signer completes it only under IOI_WALLET_TEST_SIGNER=1 (flag-gated dynamic import).
      let grant = null;
      try {
        grant = await mintTestGrant({ policyHash: a.approval.policy_hash, requestHash: a.approval.request_hash });
      } catch (e) {
        res.writeHead(502, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: { code: "wallet_grant_mint_failed", message: String(e?.message || e) } }));
        return;
      }
      if (!grant) {
        res.writeHead(403, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
        res.end(JSON.stringify(awaitingWalletAuthority(a.approval)));
        return;
      }
      const phaseB = await daemonLaunch(JSON.stringify({ launch_id: a.launch_id, wallet_approval_grant: grant }));
      const b = phaseB ? phaseB.j : { ok: false, error: { code: "daemon_unavailable" } };
      res.writeHead(phaseB ? phaseB.status : 502, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(b));
      return;
    }
    // Placement venue policy relay — the picker's durable choice is DAEMON truth, not UI state.
    if (pathname === "/__ioi/api/placement/venue-policy") {
      const method = req.method === "PUT" || req.method === "POST" ? "PUT" : "GET";
      const r = await fetch(`${DAEMON}/v1/hypervisor/placement/venue-policy`, {
        method,
        headers: { "content-type": "application/json" },
        body: method === "PUT" ? (body.toString() || "{}") : undefined,
      }).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : { ok: false, error: { code: "daemon_unavailable" } };
      res.writeHead(r ? r.status : 502, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(j));
      return;
    }
    if (pathname === "/__ioi/api/new-session/context" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((x) => x.json()).catch(() => ({}));
      const [pj, envs, arp, mr, et, lp, plVenues, plPolicy] = await Promise.all([
        J("/v1/hypervisor/projects"),
        J("/v1/hypervisor/environments"),
        J("/v1/hypervisor/agent-runner-profiles"),
        J("/v1/hypervisor/model-routes"),
        J("/v1/hypervisor/editor-targets"),
        J("/v1/hypervisor/ioi-agent/launch-policies?status=active"),
        J("/v1/hypervisor/placement/venues"),
        J("/v1/hypervisor/placement/venue-policy"),
      ]);
      const environments = (envs.environments || [])
        .sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")))
        .slice(0, 15)
        .map((e) => ({
          id: e.id,
          updated_at: e.updated_at,
          provisioner_phase: e.status?.components?.provisioner?.phase || "unknown",
          workspace_phase: e.status?.components?.workspace_content?.phase || "unknown",
        }));
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify({
        projects: (pj.projects || []).map((p) => ({ project_id: p.project_id, name: p.name, repository_url: p.repository_url })),
        environments,
        harness_profiles: arp.profiles || [],
        model_routes: (mr.routes || []).map((r) => ({
          route_ref: r.route_ref,
          display_name: r.display_name,
          model_id: (r.model || {}).model_id,
          transport: (r.provider_binding || {}).transport,
          lifecycle: (r.lifecycle || {}).status,
          availability: (r.availability || {}).state,
          default_route: r.default_route === true,
        })),
        default_route_ref: mr.default_route_ref || null,
        launch_policies: (lp.policies || []).map((p) => ({
          policy_ref: p.policy_ref,
          policy_id: p.policy_id,
          display_name: p.display_name,
          description: p.description,
          strategy_preference: p.strategy_preference,
          protected: p.protected === true,
        })),
        editor_targets: (et.targets || []).map((t) => ({
          target_id: t.target_id,
          display_name: (t.profile || {}).displayName || t.target_id,
          open_kind: (t.open_posture || {}).open_kind,
          openable: (t.open_posture || {}).openable === true,
          reason: (t.open_posture || {}).probe?.evidence?.note || ((t.open_posture || {}).probe?.evidence?.required_binary ? `${(t.open_posture || {}).probe.evidence.required_binary} not on PATH` : ""),
        })),
        placement: { venues: plVenues.venues || [], policy: plPolicy.policy || null, fee_bases: plVenues.fee_bases || {} },
      }));
      return;
    }
    if (pathname === "/__ioi/api/new-session/launch" && req.method === "POST") {
      let b = {}; try { b = JSON.parse(body.toString() || "{}"); } catch { /* fail-closed below */ }
      const sessionBody = {};
      for (const k of ["project_ref", "context_url", "environment_id", "harness_profile_ref", "model_route_ref", "editor_target_ref", "session_ref"]) {
        if (b[k]) sessionBody[k] = b[k];
      }
      const r = await fetch(`${DAEMON}/v1/hypervisor/sessions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sessionBody) }).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : { error: { code: "daemon_unavailable", message: "the daemon did not answer" } };
      let knobBinding = null;
      if (r && r.status < 400 && b.harness_key) {
        // Compile the capability-admitted per-session knob binding (fail-closed on violations;
        // the rejection is reported honestly alongside the created session).
        const kb = await fetch(`${DAEMON}/v1/hypervisor/harness-bindings`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ harness: b.harness_key, model: b.matrix_model, reasoning: b.reasoning, speed: b.speed, session_ref: j.session_ref }),
        }).catch(() => null);
        knobBinding = kb ? await kb.json().catch(() => null) : null;
      }
      res.writeHead(r ? r.status : 502, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify({ ...j, knob_binding: knobBinding }));
      return;
    }
    // ---- Agent Studio — agent inventory + configuration + activity cockpit (estate surface #3).
    if (pathname === "/__ioi/agent-studio" && req.method === "GET") {
      const sp = new URL(req.url, "http://x").searchParams;
      const selId = sp.get("agent") || "";
      const q = sp.get("q") || "";
      const J = (p) => fetch(`${DAEMON}${p}`).then((x) => x.json()).catch(() => ({}));
      const [ag, pr, ro, pv, cv, tr, mr, lp, me, sk, af, cn, cl, mp, mprj, rq, om, imp, rcl, coh, odkov, odksd] = await Promise.all([
        J("/v1/agents"),
        J("/v1/hypervisor/agent-runner-profiles"),
        J("/v1/model-mount/routes"),
        J("/v1/model-mount/providers"),
        J("/v1/hypervisor/agentops/conversations"),
        J("/v1/hypervisor/agent-run-transcripts"),
        J("/v1/hypervisor/model-routes"),
        J("/v1/hypervisor/ioi-agent/launch-policies"),
        J("/v1/hypervisor/memory-entries"),
        J("/v1/hypervisor/skill-entries"),
        J("/v1/hypervisor/automation-affinities"),
        J("/v1/hypervisor/connectors"),
        J("/v1/hypervisor/capability-leases"),
        J("/v1/hypervisor/memory-mutation-proposals"),
        J("/v1/hypervisor/memory-projections"),
        J("/v1/hypervisor/intelligence/review-queue"),
        J("/v1/hypervisor/intelligence/outcome-mining"),
        J("/v1/hypervisor/intelligence/improvement-proposals"),
        J("/v1/hypervisor/governance/release-controls"),
        J("/v1/hypervisor/governance/cohorts"),
        J("/v1/hypervisor/odk/overview"),
        J("/v1/hypervisor/odk/surface-descriptors"),
      ]);
      // Decorate rollout-bound learned variants with their control's cohort names + mode so
      // the policy card can say WHO the rollout applies to.
      for (const pol of (lp.policies || [])) {
        if (!pol.rollout) continue;
        const control = ((rcl || {}).release_controls || []).find((r) => r.ref === pol.rollout.release_control_ref);
        const names = (control?.cohort_refs || []).map((ref) => {
          const c = ((coh || {}).cohorts || []).find((x) => x.ref === ref);
          return c ? `${c.display_name}${c.status !== "active" ? " (disabled)" : ""}` : ref;
        });
        pol.rollout_display = { mode: control?.rollout_mode || pol.rollout.mode, cohort_names: names, canary_percent: control?.canary_percent ?? null, deprecated_raw: (control?.deprecated_raw_cohort_refs || []).length > 0 };
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
      res.end(renderAgentStudio(
        Array.isArray(ag) ? ag : (ag.agents || []),
        pr.profiles || [],
        Array.isArray(ro) ? ro : (ro.routes || []),
        Array.isArray(pv) ? pv : (pv.providers || []),
        cv.conversations || [],
        tr.runs || [],
        selId,
        q,
        mr.routes || [],
        lp.policies || [],
        { entries: me.entries || [], skills: sk.skills || [], affinities: af.affinities || [], connectors: cn.connectors || [], leases: cl.leases || [], proposals: mp.proposals || [], projections: (mprj.projections || []).slice(0, 20), review: (rq.items || []).slice(0, 20), mining: (om.candidates || []).slice(0, 10), improvements: (imp.proposals || []).slice(0, 15), systemDesigns: { compositionPatterns: (odkov || {}).composition_patterns || [], surfaceDescriptors: (odksd || {}).surface_descriptors || (odksd || {}).descriptors || [] } },
      ));
      return;
    }
    // ---- Agent Studio intelligence-cockpit lanes: proxy the daemon intelligence plane.
    {
      const intelAction = pathname.match(/^\/__ioi\/agent-studio\/intel\/(memory|skills|affinities)(?:\/([^/]+)\/(archive|revoke|activate))?$/);
      if (intelAction && req.method === "POST") {
        const [, family, rid, act] = intelAction;
        const api = family === "memory" ? "memory-entries" : family === "skills" ? "skill-entries" : "automation-affinities";
        let target;
        if (rid && act) {
          target = { method: "PATCH", url: `/v1/hypervisor/${api}/${encodeURIComponent(rid)}`, body: JSON.stringify({ status: act === "activate" ? "active" : act === "archive" ? "archived" : "revoked" }) };
        } else {
          const form = new URLSearchParams(body.toString());
          const csv = (k) => (form.get(k) || "").split(",").map((x) => x.trim()).filter(Boolean);
          const payload = { title: form.get("title") || "", body: form.get("body") || "", description: form.get("body") || "" };
          if (family === "memory") {
            payload.entry_kind = form.get("entry_kind") || "note";
            payload.sensitivity = form.get("sensitivity") || "normal";
            if (csv("connector_refs").length) payload.connector_refs = csv("connector_refs");
            if (csv("compatible_harness_refs").length) payload.compatible_harness_refs = csv("compatible_harness_refs");
          }
          if (family === "affinities") {
            payload.goal_pattern = form.get("goal_pattern") || "";
            if (form.get("preferred_policy_ref")) payload.preferred_policy_ref = form.get("preferred_policy_ref");
            if (csv("preferred_automation_refs").length) payload.preferred_automation_refs = csv("preferred_automation_refs");
            if (csv("preferred_harness_refs").length) payload.preferred_harness_refs = csv("preferred_harness_refs");
          }
          target = { method: "POST", url: `/v1/hypervisor/${api}`, body: JSON.stringify(payload) };
        }
        const r = await fetch(`${DAEMON}${target.url}`, { method: target.method, headers: { "content-type": "application/json" }, body: target.body }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          const code = (j.error && j.error.code) || (r ? `HTTP ${r.status}` : "daemon unavailable");
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Intelligence", `<div class="empty">Rejected fail-closed: <code>${CX_ESC(code)}</code>${j.error && j.error.message ? `<br>${CX_ESC(j.error.message)}` : ""}</div><p><a href="/__ioi/agent-studio#${family === "memory" ? "memory" : family}">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: `/__ioi/agent-studio#${family === "memory" ? "memory" : family}`, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- What-if simulation lanes (derived, deterministic; save = receipted report).
    {
      const simAction = pathname.match(/^\/__ioi\/agent-studio\/improvements\/([^/]+)\/simulate$/);
      if (simAction && req.method === "POST") {
        const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals/${encodeURIComponent(simAction[1])}/simulate`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ save: true }) }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        const simId = String(j.report?.simulation_ref || "").replace("simulation-report://", "");
        if (!r || r.status >= 400 || !simId) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Simulation", `<div class="empty">Simulation failed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code></div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: `/__ioi/intelligence/simulations/${encodeURIComponent(simId)}`, "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    {
      const simPage = pathname.match(/^\/__ioi\/intelligence\/simulations\/([^/]+)$/);
      if (simPage && req.method === "GET") {
        const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/simulation-reports/${encodeURIComponent(simPage[1])}`).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        const rep = j.report;
        if (!r || r.status >= 400 || !rep) {
          res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Simulation", `<div class="empty">Simulation report not found.</div>`));
          return;
        }
        const sm = rep.summary || {};
        const scRow = (sc) => `<tr>
          <td><span class="pill muted">${CX_ESC(sc.scenario_kind)}</span><div style="color:#878a93;font-size:10px;word-break:break-all"><code>${CX_ESC(sc.subject_ref || "")}</code></div></td>
          <td style="font-size:11px">${CX_ESC(JSON.stringify(sc.before || {}).slice(0, 160))}</td>
          <td style="font-size:11px">${CX_ESC(JSON.stringify(sc.after || {}).slice(0, 160))}</td>
          <td>${sc.changed ? '<span class="pill warn">changed</span>' : '<span class="pill muted">same</span>'}</td>
        </tr>`;
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(automationsShell("Simulation report", `<p><a href="/__ioi/agent-studio#launch-policies">← Studio · Improvement proposals</a></p>
          <h1>🔮 What-if simulation <span class="pill ok">deterministic</span> <span class="pill muted">non-mutating</span>${rep.governance?.high_impact ? ' <span class="pill warn">high impact</span>' : ""}</h1>
          <p class="sub">${CX_ESC(rep.body_disclosure || "")} · ${CX_ESC(rep.registry_posture || "")}</p>
          <dl class="grid">
            <dt>Proposal</dt><dd><code>${CX_ESC(rep.proposal_ref || "")}</code> · ${CX_ESC(rep.proposal_kind || "")}</dd>
            <dt>Report hash</dt><dd><code style="font-size:10.5px">${CX_ESC(rep.report_hash || "")}</code></dd>
            <dt>Summary</dt><dd>${CX_ESC(String(sm.scenarios))} scenarios · <b>${CX_ESC(String(sm.changed))} changed</b> · ${CX_ESC(String(sm.blockers_removed))} blockers removed · ${CX_ESC(String(sm.blockers_introduced))} introduced</dd>
            <dt>Governance</dt><dd>${CX_ESC(rep.governance?.requirement || "none")}${rep.governance?.enforced ? ' <span class="pill warn">gate enforced at apply</span>' : ""}</dd>
            <dt>Gate targets</dt><dd>${(rep.governance?.satisfiable_target_refs || []).map((x) => `<code>${CX_ESC(x)}</code>`).join(" ")} <span class="sub" style="text-transform:none;letter-spacing:0">— an ApprovalRequest / ReleaseControl targeting either ref satisfies this report's gate</span></dd>
            <dt>Receipts</dt><dd>${(rep.receipt_refs || []).map((x) => `<code>${CX_ESC(x)}</code>`).join(" ")} · <a href="/__ioi/work-ledger">ledger →</a></dd>
          </dl>
          <h2>Scenarios (${(rep.scenarios || []).length})</h2>
          <table><thead><tr><th>Scenario</th><th>Before</th><th>After</th><th>Δ</th></tr></thead><tbody>${(rep.scenarios || []).map(scRow).join("")}</tbody></table>`));
        return;
      }
    }
    // ---- Outcome-learning improvement proposal lanes.
    if (pathname === "/__ioi/agent-studio/improvements/propose" && req.method === "POST") {
      let payload = {};
      try { payload = JSON.parse(new URLSearchParams(body.toString()).get("candidate_json") || "{}"); } catch { payload = {}; }
      const proposal = {
        proposal_kind: payload.candidate_kind,
        signal: payload.signal,
        evidence_refs: payload.evidence_refs || [],
        confidence: payload.confidence,
        suggested: payload.suggested || {},
        reason: `mined: ${payload.signal} × ${payload.occurrences || "?"}`,
      };
      if (payload.target_ref) proposal.target_ref = payload.target_ref;
      const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(proposal) }).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : {};
      if (!r || r.status >= 400) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(automationsShell("Improvement", `<div class="empty">Rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code></div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
        return;
      }
      res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
      res.end();
      return;
    }
    // ---- Learned-policy rollout lanes (promote to full / roll back to base).
    {
      const rolloutAct = pathname.match(/^\/__ioi\/agent-studio\/launch-policies\/([^/]+)\/rollout\/(promote|rollback)$/);
      if (rolloutAct && req.method === "POST") {
        const [, pid, act] = rolloutAct;
        const r = await fetch(`${DAEMON}/v1/hypervisor/ioi-agent/launch-policies/${encodeURIComponent(pid)}/rollout/${act}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Rollout", `<div class="empty"><b>${CX_ESC(act)}</b> rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code></div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Improvement governance gate lanes (controls created/bound through the daemon).
    {
      const govBind = pathname.match(/^\/__ioi\/agent-studio\/improvements\/([^/]+)\/governance\/(request-approval|open-release|attach)$/);
      if (govBind && req.method === "POST") {
        const [, iid, act] = govBind;
        const failPage = (j, label) => {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Governance", `<div class="empty"><b>${CX_ESC(label)}</b> rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || j.reason || "daemon unavailable")}</code></div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
        };
        const pr = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals/${encodeURIComponent(iid)}`).then((r) => r.json()).catch(() => ({}));
        const proposalRef = (pr.proposal || {}).proposal_ref || "";
        const attach = {};
        if (act === "request-approval") {
          const r = await fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ subject_ref: proposalRef, request_kind: "improvement_apply", reason: "gate a high-impact learned improvement" }) }).catch(() => null);
          const j = r ? await r.json().catch(() => ({})) : {};
          if (!r || r.status >= 400 || !(j.approval_request || {}).ref) { failPage(j, "request approval"); return; }
          attach.approval_request_ref = j.approval_request.ref;
        } else if (act === "open-release") {
          const r = await fetch(`${DAEMON}/v1/hypervisor/governance/release-controls`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ release_target_ref: proposalRef, reason: "release gate for a high-impact learned improvement" }) }).catch(() => null);
          const j = r ? await r.json().catch(() => ({})) : {};
          if (!r || r.status >= 400 || !(j.release_control || {}).ref) { failPage(j, "create release gate"); return; }
          attach.release_control_ref = j.release_control.ref;
        } else {
          const form = new URLSearchParams(body.toString());
          for (const key of ["approval_request_ref", "release_control_ref"]) {
            const v = (form.get(key) || "").trim();
            if (v) attach[key] = v;
          }
        }
        const r2 = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals/${encodeURIComponent(iid)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(attach) }).catch(() => null);
        const j2 = r2 ? await r2.json().catch(() => ({})) : {};
        if (!r2 || r2.status >= 400) { failPage(j2, "bind governance refs"); return; }
        res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    {
      const govAct = pathname.match(/^\/__ioi\/agent-studio\/governance\/(approvals|releases)\/([^/]+)\/(approve|reject|open|close)$/);
      if (govAct && req.method === "POST") {
        const [, family, gid, transition] = govAct;
        const path = family === "approvals" ? "approval-requests" : "release-controls";
        const r = await fetch(`${DAEMON}/v1/hypervisor/governance/${path}/${encodeURIComponent(gid)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ transition, reviewer_ref: "principal://operator" }) }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || j.ok === false) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Governance", `<div class="empty"><b>${CX_ESC(transition)}</b> rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || j.reason || "daemon unavailable")}</code></div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    {
      const impAction = pathname.match(/^\/__ioi\/agent-studio\/improvements\/([^/]+)\/(approve|reject|apply)$/);
      if (impAction && req.method === "POST") {
        const [, iid, act] = impAction;
        const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/improvement-proposals/${encodeURIComponent(iid)}/${act}`, { method: "POST", headers: { "content-type": "application/json" }, body: act === "reject" ? JSON.stringify({ reason: "operator rejected" }) : "{}" }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Improvement", `<div class="empty"><b>${CX_ESC(act)}</b> rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code>${j.error && j.error.message ? `<br>${CX_ESC(j.error.message)}` : ""}</div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Memory lifecycle transitions + review queue lanes.
    {
      const lcAction = pathname.match(/^\/__ioi\/agent-studio\/intel\/(memory|skills)\/([^/]+)\/lifecycle$/);
      if (lcAction && req.method === "POST") {
        const [, family, rid] = lcAction;
        const form = new URLSearchParams(body.toString());
        const api = family === "memory" ? "memory-entries" : "skill-entries";
        const payload = { transition: form.get("transition") || "", reason: form.get("reason") || "operator action from Agent Studio" };
        if (form.get("superseded_by_ref")) payload.superseded_by_ref = form.get("superseded_by_ref");
        const r = await fetch(`${DAEMON}/v1/hypervisor/${api}/${encodeURIComponent(rid)}/lifecycle`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Memory lifecycle", `<div class="empty">Transition rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code>${j.error && j.error.message ? `<br>${CX_ESC(j.error.message)}` : ""}</div><p><a href="/__ioi/agent-studio#memory">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#memory", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Memory graph (derived, read-only) + projection explainability lanes.
    if (pathname === "/__ioi/agent-studio/intel/graph" && req.method === "GET") {
      const q = new URL(req.url, "http://x").searchParams.get("q") || "";
      const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/graph${q ? "?q=" + encodeURIComponent(q) : ""}`).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : { ok: false };
      res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
      res.end(JSON.stringify(j));
      return;
    }
    {
      const explainMatch = pathname.match(/^\/__ioi\/intelligence\/projections\/([^/]+)\/explain$/);
      if (explainMatch && req.method === "GET") {
        const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/projections/${encodeURIComponent(explainMatch[1])}/explain`).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Projection", `<div class="empty">Projection not found.</div><p><a href="/__ioi/agent-studio#memory">← Studio</a></p>`));
          return;
        }
        const ctx = j.context || {};
        const dec = j.decisions || {};
        const row = (d) => `<tr><td><b>${CX_ESC((d.meta || {}).title || "")}</b><div style="color:#878a93;font-size:10.5px"><code>${CX_ESC(d.ref)}</code></div></td>
          <td><span class="pill muted">${CX_ESC((d.meta || {}).kind || "")}</span></td>
          <td><span class="pill ${(d.meta || {}).quality_state === "accepted" ? "ok" : "muted"}">${CX_ESC((d.meta || {}).quality_state || "—")}</span></td>
          <td><span class="pill ${(d.meta || {}).sensitivity === "secret" || (d.meta || {}).sensitivity === "private" ? "warn" : "muted"}">${CX_ESC((d.meta || {}).sensitivity || "—")}</span></td>
          <td><span class="pill ${d.decision === "included" ? "ok" : "warn"}">${CX_ESC(d.decision)}</span>${d.reason_code ? ` <code style="font-size:10.5px">${CX_ESC(d.reason_code)}</code>` : ""}</td>
          <td style="font-size:11px;color:#878a93">${d.checks ? d.checks.map((c) => `${c.pass ? "✓" : "✗"} ${CX_ESC(c.check)}`).join("<br>") : "—"}</td></tr>`;
        const table = (title, list) => `<h2>${title} (${(list || []).length})</h2>${(list || []).length ? `<table><thead><tr><th>Record</th><th>Kind</th><th>Quality</th><th>Sensitivity</th><th>Decision</th><th>Checks</th></tr></thead><tbody>${list.map(row).join("")}</tbody></table>` : `<div class="empty">none</div>`}`;
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(automationsShell("Projection explain", `<p><a href="/__ioi/agent-studio#memory">← Agent Studio · Memory</a></p>
          <h1>🧠 Projection explain <span class="pill ok">deterministic</span></h1>
          <p class="sub">Vault truth → harness prompt, decision by decision. ${CX_ESC(j.body_disclosure || "")}</p>
          <dl class="grid">
            <dt>Projection</dt><dd><code>${CX_ESC(j.projection_ref || "")}</code></dd>
            <dt>Memory space</dt><dd><code>${CX_ESC(j.memory_space_ref || "")}</code></dd>
            <dt>Harness · route</dt><dd><code>${CX_ESC(ctx.harness_profile_ref || "")}</code> · <code>${CX_ESC(ctx.model_route_ref || "")}</code></dd>
            <dt>Privacy · policy</dt><dd>${CX_ESC(ctx.privacy_posture || "")} · ${ctx.policy_ref ? `<code>${CX_ESC(ctx.policy_ref)}</code>` : "no policy"}</dd>
            <dt>Bound to</dt><dd>${["goal_run_ref", "session_ref", "launch_ref"].map((k) => ctx[k] ? `<code>${CX_ESC(ctx[k])}</code>` : "").filter(Boolean).join(" · ") || "—"}</dd>
            <dt>Receipts</dt><dd>${(j.receipt_refs || []).map((r2) => `<code>${CX_ESC(r2)}</code>`).join(" ")}</dd>
          </dl>
          ${table("Included", dec.included)}${table("Redacted", dec.redacted)}${table("Excluded", dec.excluded)}`));
        return;
      }
    }
    // ---- Agent Studio portable-vault + mutation-proposal lanes (daemon proxies).
    if (pathname === "/__ioi/agent-studio/vault/export" && req.method === "GET") {
      const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/spaces/ms_workspace_default/export`).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : {};
      res.writeHead(r && r.status < 400 ? 200 : 502, {
        "Content-Type": "application/json",
        "Content-Disposition": 'attachment; filename="ioi-memory-vault.json"',
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(j.vault || j, null, 2));
      return;
    }
    if (pathname === "/__ioi/agent-studio/vault/import" && req.method === "POST") {
      let bundle = {};
      try {
        const form = new URLSearchParams(body.toString());
        bundle = JSON.parse(form.get("vault_json") || body.toString());
      } catch { bundle = {}; }
      const r = await fetch(`${DAEMON}/v1/hypervisor/intelligence/spaces/import`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bundle.vault ? bundle : { vault: bundle }) }).catch(() => null);
      const j = r ? await r.json().catch(() => ({})) : {};
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      if (!r || r.status >= 400) {
        res.end(automationsShell("Vault import", `<div class="empty">Import rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code>${j.error && j.error.message ? `<br>${CX_ESC(j.error.message)}` : ""}</div><p><a href="/__ioi/agent-studio#memory">← Studio</a></p>`));
        return;
      }
      res.end(automationsShell("Vault import", `<h1>Vault imported</h1><dl class="grid">
        <dt>Imported</dt><dd>${CX_ESC(JSON.stringify(j.imported))}</dd>
        <dt>Unchanged (idempotent)</dt><dd>${CX_ESC(String(j.unchanged))}</dd>
        <dt>Conflicts (skipped, explicit)</dt><dd>${(j.conflicts || []).length ? (j.conflicts || []).map((c) => `<code>${CX_ESC(c.ref || c.path)}</code> ${CX_ESC(c.reason_code)}`).join("<br>") : "none"}</dd>
        <dt>Rejected</dt><dd>${(j.rejected || []).length ? (j.rejected || []).map((c) => `<code>${CX_ESC(c.path)}</code> ${CX_ESC(c.reason_code)}`).join("<br>") : "none"}</dd>
      </dl><p><a class="act" href="/__ioi/agent-studio#memory">Back to Memory</a></p>`));
      return;
    }
    {
      const propAction = pathname.match(/^\/__ioi\/agent-studio\/proposals\/([^/]+)\/(approve|reject)$/);
      if (propAction && req.method === "POST") {
        const [, pid, act] = propAction;
        const r = await fetch(`${DAEMON}/v1/hypervisor/memory-mutation-proposals/${encodeURIComponent(pid)}/${act}`, { method: "POST", headers: { "content-type": "application/json" }, body: act === "reject" ? JSON.stringify({ reason: new URLSearchParams(body.toString()).get("reason") || "operator rejected" }) : "{}" }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Proposal", `<div class="empty">Rejected fail-closed: <code>${CX_ESC((j.error && j.error.code) || "daemon unavailable")}</code></div><p><a href="/__ioi/agent-studio#memory">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#memory", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Agent Studio launch-policy management: proxy the daemon policy plane (list is
    // fetched with the studio page; these are the effectful lanes). Redirects land on the tab.
    {
      const lpAction = pathname.match(/^\/__ioi\/agent-studio\/launch-policies\/([^/]+)\/(clone|enable|disable|delete)$/);
      if (lpAction && req.method === "POST") {
        const [, pid, act] = lpAction;
        const target = act === "clone"
          ? { method: "POST", url: `/v1/hypervisor/ioi-agent/launch-policies/${encodeURIComponent(pid)}/clone`, body: "{}" }
          : act === "delete"
            ? { method: "DELETE", url: `/v1/hypervisor/ioi-agent/launch-policies/${encodeURIComponent(pid)}`, body: undefined }
            : { method: "PATCH", url: `/v1/hypervisor/ioi-agent/launch-policies/${encodeURIComponent(pid)}`, body: JSON.stringify({ status: act === "enable" ? "active" : "disabled" }) };
        const r = await fetch(`${DAEMON}${target.url}`, { method: target.method, headers: { "content-type": "application/json" }, body: target.body }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          const code = (j.error && j.error.code) || (r ? `HTTP ${r.status}` : "daemon unavailable");
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Launch policies", `<div class="empty"><b>${CX_ESC(act)}</b> was rejected fail-closed: <code>${CX_ESC(code)}</code>${j.error && j.error.message ? `<br>${CX_ESC(j.error.message)}` : ""}</div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
      if (pathname === "/__ioi/agent-studio/launch-policies" && req.method === "POST") {
        const form = new URLSearchParams(body.toString());
        const csv = (k) => (form.get(k) || "").split(",").map((x) => x.trim()).filter(Boolean);
        const payload = {
          display_name: form.get("display_name") || "",
          description: form.get("description") || "",
          strategy_preference: form.get("strategy_preference") || "auto",
          failure_policy: form.get("failure_policy") || "partial_ok",
          harness_preferences: {
            preferred_harness_refs: csv("preferred_harness_refs"),
            excluded_harness_refs: csv("excluded_harness_refs"),
            allow_fallback: form.get("allow_fallback") === "on",
          },
          privacy: {
            local_only: form.get("local_only") === "on",
            forbid_remote_trust: form.get("local_only") === "on",
            forbid_provider_credentials: form.get("local_only") === "on",
          },
          assurance: {
            require_compare: form.get("require_compare") === "on",
            require_verifier: true,
            min_successful_invocations: parseInt(form.get("min_successful_invocations") || "1", 10) || 1,
            require_reconciliation_before_write: form.get("require_compare") === "on",
          },
        };
        const editId = form.get("policy_id");
        const url = editId ? `/v1/hypervisor/ioi-agent/launch-policies/${encodeURIComponent(editId)}` : "/v1/hypervisor/ioi-agent/launch-policies";
        const r = await fetch(`${DAEMON}${url}`, { method: editId ? "PATCH" : "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          const code = (j.error && j.error.code) || (r ? `HTTP ${r.status}` : "daemon unavailable");
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Launch policies", `<div class="empty">Save was rejected fail-closed: <code>${CX_ESC(code)}</code>${j.error && j.error.message ? `<br>${CX_ESC(j.error.message)}` : ""}</div><p><a href="/__ioi/agent-studio#launch-policies">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#launch-policies", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Agent Studio model-route registry controls: proxy the effectful daemon routes
    // (probe / enable / disable / select-default), then return to the registry section.
    {
      const mrAction = pathname.match(/^\/__ioi\/agent-studio\/model-routes\/([^/]+)\/(probe|enable|disable|select-default)$/);
      if (mrAction && req.method === "POST") {
        const [, mrId, act] = mrAction;
        const r = await fetch(`${DAEMON}/v1/hypervisor/model-routes/${encodeURIComponent(mrId)}/${act}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          const code = (j.error && j.error.code) || (r ? `HTTP ${r.status}` : "daemon unavailable");
          const msg = (j.error && j.error.message) || "";
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Model routes", `<div class="empty"><b>${CX_ESC(act)}</b> was rejected fail-closed: <code>${CX_ESC(code)}</code>${msg ? `<br>${CX_ESC(msg)}` : ""}</div><p><a href="/__ioi/agent-studio#model-routes">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#model-routes", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Agent Studio harness-profile registry controls: proxy the effectful daemon routes
    // (probe / enable / disable / select-default); a provider-trust acceptance ref from the
    // confirm panel is forwarded so the planner can admit non-local-trust enables.
    {
      const hpAction = pathname.match(/^\/__ioi\/agent-studio\/harness-profiles\/([^/]+)\/(probe|enable|disable|select-default)$/);
      if (hpAction && req.method === "POST") {
        const [, hpIdRaw, act] = hpAction;
        const acceptance = new URLSearchParams(body.toString()).get("provider_trust_acceptance_ref");
        const payload = acceptance ? JSON.stringify({ provider_trust_acceptance_ref: acceptance }) : "{}";
        const r = await fetch(`${DAEMON}/v1/hypervisor/harness-profiles/${encodeURIComponent(hpIdRaw)}/${act}`, { method: "POST", headers: { "content-type": "application/json" }, body: payload }).catch(() => null);
        const j = r ? await r.json().catch(() => ({})) : {};
        if (!r || r.status >= 400) {
          const code = (j.error && j.error.code) || (r ? `HTTP ${r.status}` : "daemon unavailable");
          const msg = (j.error && j.error.message) || "";
          res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
          res.end(automationsShell("Harness profiles", `<div class="empty"><b>${CX_ESC(act)}</b> was rejected fail-closed: <code>${CX_ESC(code)}</code>${msg ? `<br>${CX_ESC(msg)}` : ""}</div><p><a href="/__ioi/agent-studio#harness-profiles">← Studio</a></p>`));
          return;
        }
        res.writeHead(302, { Location: "/__ioi/agent-studio#harness-profiles", "Cache-Control": "no-cache" });
        res.end();
        return;
      }
    }
    // ---- Foundry — controlled builder over the daemon Foundry object plane (estate surface #4).
    const HTMLH = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" };
    if (pathname === "/__ioi/foundry" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [ov, sp, rp, mr, mb] = await Promise.all([
        J("/v1/hypervisor/foundry/overview"),
        J("/v1/hypervisor/foundry/specs"),
        J("/v1/hypervisor/foundry/run-plans"),
        J("/v1/hypervisor/model-routes"),
        J("/v1/hypervisor/model-route-session-bindings"),
      ]);
      res.writeHead(200, HTMLH);
      res.end(renderFoundryLanding(ov, sp.specs || [], rp.run_plans || [], mr.routes || [], mb.bindings || []));
      return;
    }
    if (pathname === "/__ioi/foundry/specs/new" && req.method === "GET") {
      res.writeHead(200, HTMLH);
      res.end(renderFoundrySpecForm(await foundryCatalog(), null));
      return;
    }
    if (pathname === "/__ioi/foundry/specs" && req.method === "POST") {
      const payload = foundrySpecPayloadFromForm(new URLSearchParams(body.toString()));
      const r = await fetch(`${DAEMON}/v1/hypervisor/foundry/specs`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
      if (r && r.ok) { res.writeHead(302, { Location: `/__ioi/foundry/specs/${encodeURIComponent(r.spec.id)}`, "Cache-Control": "no-cache" }); return res.end(); }
      res.writeHead(200, HTMLH);
      res.end(automationsShell("New FoundrySpec", `<div class="empty">Create failed: ${CX_ESC((r.error && r.error.message) || "invalid")}</div><p><a href="/__ioi/foundry/specs/new">← back</a></p>`));
      return;
    }
    if (pathname.startsWith("/__ioi/foundry/specs/")) {
      const [rawId, action] = pathname.slice("/__ioi/foundry/specs/".length).split("/");
      const id = decodeURIComponent(rawId);
      if (action === "edit" && req.method === "GET") {
        const [cat, sres] = await Promise.all([foundryCatalog(), fetch(`${DAEMON}/v1/hypervisor/foundry/specs/${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => ({}))]);
        res.writeHead(200, HTMLH);
        res.end(sres.ok ? renderFoundrySpecForm(cat, sres.spec) : automationsShell("Not found", `<div class="empty">Spec not found.</div><p><a href="/__ioi/foundry">← Foundry</a></p>`));
        return;
      }
      if (action === "patch" && req.method === "POST") {
        const payload = foundrySpecPayloadFromForm(new URLSearchParams(body.toString()));
        const r = await fetch(`${DAEMON}/v1/hypervisor/foundry/specs/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
        if (r && r.ok) { res.writeHead(302, { Location: `/__ioi/foundry/specs/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" }); return res.end(); }
        res.writeHead(200, HTMLH);
        res.end(automationsShell("Edit FoundrySpec", `<div class="empty">Save failed: ${CX_ESC((r.error && r.error.message) || "invalid")}</div><p><a href="/__ioi/foundry/specs/${encodeURIComponent(id)}/edit">← back</a></p>`));
        return;
      }
      if (action === "delete" && req.method === "POST") {
        await fetch(`${DAEMON}/v1/hypervisor/foundry/specs/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
        res.writeHead(302, { Location: "/__ioi/foundry", "Cache-Control": "no-cache" });
        return res.end();
      }
      if (req.method === "GET") {
        const [sres, rp] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/foundry/specs/${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/foundry/run-plans?spec_ref=${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => ({})),
        ]);
        res.writeHead(200, HTMLH);
        res.end(sres.ok ? renderFoundrySpecDetail(sres.spec, rp.run_plans || []) : automationsShell("Not found", `<div class="empty">Spec not found.</div><p><a href="/__ioi/foundry">← Foundry</a></p>`));
        return;
      }
    }
    if (pathname === "/__ioi/foundry/run-plans/new" && req.method === "GET") {
      const specId = new URL(req.url, "http://x").searchParams.get("spec") || "";
      const [cat, sres] = await Promise.all([foundryCatalog(), fetch(`${DAEMON}/v1/hypervisor/foundry/specs/${encodeURIComponent(specId)}`).then((r) => r.json()).catch(() => ({}))]);
      res.writeHead(200, HTMLH);
      res.end(sres.ok ? renderFoundryRunPlanForm(sres.spec, cat) : automationsShell("New run plan", `<div class="empty">Pick a spec first.</div><p><a href="/__ioi/foundry">← Foundry</a></p>`));
      return;
    }
    if (pathname === "/__ioi/foundry/run-plans" && req.method === "POST") {
      const p = new URLSearchParams(body.toString());
      const steps = (p.get("steps") || "").split(",").map((s) => s.trim()).filter(Boolean).map((phase) => ({ phase }));
      const payload = { spec_ref: (p.get("spec_ref") || "").trim(), name: (p.get("name") || "foundry-run-plan").trim(), description: (p.get("description") || "").trim(), steps };
      const tr = (p.get("target_route_ref") || "").trim(); if (tr) payload.target_route_ref = tr;
      const tp = (p.get("target_provider_ref") || "").trim(); if (tp) payload.target_provider_ref = tp;
      const r = await fetch(`${DAEMON}/v1/hypervisor/foundry/run-plans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
      if (r && r.ok) { res.writeHead(302, { Location: `/__ioi/foundry/run-plans/${encodeURIComponent(r.run_plan.id)}`, "Cache-Control": "no-cache" }); return res.end(); }
      res.writeHead(200, HTMLH);
      res.end(automationsShell("New FoundryRunPlan", `<div class="empty">Create failed: ${CX_ESC((r.error && r.error.message) || "invalid")}</div><p><a href="/__ioi/foundry">← Foundry</a></p>`));
      return;
    }
    if (pathname.startsWith("/__ioi/foundry/run-plans/")) {
      const [rawId, action] = pathname.slice("/__ioi/foundry/run-plans/".length).split("/");
      const id = decodeURIComponent(rawId);
      if (action === "delete" && req.method === "POST") {
        await fetch(`${DAEMON}/v1/hypervisor/foundry/run-plans/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
        res.writeHead(302, { Location: "/__ioi/foundry", "Cache-Control": "no-cache" });
        return res.end();
      }
      if (req.method === "GET") {
        const pres = await fetch(`${DAEMON}/v1/hypervisor/foundry/run-plans/${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => ({}));
        if (!pres.ok) { res.writeHead(200, HTMLH); res.end(automationsShell("Not found", `<div class="empty">Run plan not found.</div><p><a href="/__ioi/foundry">← Foundry</a></p>`)); return; }
        const sres = await fetch(`${DAEMON}/v1/hypervisor/foundry/specs/${encodeURIComponent(pres.run_plan.spec_ref || "")}`).then((r) => r.json()).catch(() => ({}));
        res.writeHead(200, HTMLH);
        res.end(renderFoundryRunPlanDetail(pres.run_plan, sres.spec || null));
        return;
      }
    }
    // ---- ODK — controlled builder over the daemon ODK object plane (estate surface #5).
    // ---- Studio · Designer — the system-design canvas (designer seed). Read-only typed map over
    // real ODK composition (concepts/components) + generated resources. Owner: /__ioi/agent-studio.
    if (pathname === "/__ioi/studio/designer" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [o, cm, pv, op, ms, da] = await Promise.all([
        J("/v1/hypervisor/odk/domain-ontologies"),
        J("/v1/hypervisor/odk/connector-mappings"),
        J("/v1/hypervisor/odk/policy-bound-data-views"),
        J("/v1/hypervisor/odk/ontology-projections"),
        J("/v1/hypervisor/odk/materialized-object-sets"),
        J("/v1/hypervisor/domain-apps"),
      ]);
      const selectedOntology = new URL(req.url, "http://x").searchParams.get("ontology") || "";
      res.writeHead(200, HTMLH);
      res.end(renderDesignerPort({
        ontologies: o.ontologies || [],
        connector_mappings: cm.connector_mappings || [],
        policy_views: pv.policy_bound_data_views || [],
        projections: op.ontology_projections || [],
        materialized_sets: ms.materialized_object_sets || [],
        domain_apps: da.domain_apps || da.apps || [],
      }, selectedOntology));
      return;
    }
    // ---- Studio · Machinery — read-only process/state-machine DEFINITION view. Owner: agent-studio.
    if (pathname === "/__ioi/studio/machinery" && req.method === "GET") {
      const r = await fetch(`${DAEMON}/v1/hypervisor/state-machines`).then((x) => x.json()).catch(() => ({}));
      const selectedMachine = new URL(req.url, "http://x").searchParams.get("machine") || "";
      res.writeHead(200, HTMLH);
      res.end(renderMachineryPort(r.state_machines || [], selectedMachine));
      return;
    }
    if (pathname === "/__ioi/vertex" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [o, ms, op, mr, wl] = await Promise.all([
        J("/v1/hypervisor/odk/domain-ontologies"),
        J("/v1/hypervisor/odk/materialized-object-sets"),
        J("/v1/hypervisor/odk/ontology-projections"),
        J("/v1/hypervisor/odk/materializing-runs"),
        J("/v1/hypervisor/work-ledger"),
      ]);
      const selectedOntology = new URL(req.url, "http://x").searchParams.get("ontology") || "";
      res.writeHead(200, HTMLH);
      res.end(renderVertex({
        ontologies: o.ontologies || [],
        materialized_sets: ms.materialized_object_sets || [],
        ontology_projections: op.ontology_projections || [],
        materializing_runs: mr.materializing_runs || [],
        provenance_stream: Array.isArray(wl) ? wl : (wl.entries || wl.work_ledger || []),
      }, selectedOntology, { objectSet: new URL(req.url, "http://x").searchParams.get("objectSet") || "", objectId: new URL(req.url, "http://x").searchParams.get("objectId") || "" }));
      return;
    }
    if (pathname === "/__ioi/lineage" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [o, mr, ms, wl, cm, pv, op, lp, dsr] = await Promise.all([
        J("/v1/hypervisor/odk/domain-ontologies"),
        J("/v1/hypervisor/odk/materializing-runs"),
        J("/v1/hypervisor/odk/materialized-object-sets"),
        J("/v1/hypervisor/work-ledger"),
        J("/v1/hypervisor/odk/connector-mappings"),
        J("/v1/hypervisor/odk/policy-bound-data-views"),
        J("/v1/hypervisor/odk/ontology-projections"),
        J("/v1/hypervisor/odk/capability-lease-plans"),
        J("/v1/hypervisor/data-sources"),
      ]);
      const selectedOntology = new URL(req.url, "http://x").searchParams.get("ontology") || "";
      res.writeHead(200, HTMLH);
      res.end(renderDataLineage({
        ontologies: o.ontologies || [],
        materializing_runs: mr.materializing_runs || [],
        materialized_sets: ms.materialized_object_sets || [],
        // Backing proof stream (route stays /v1/hypervisor/work-ledger; the surface is Provenance).
        provenance_stream: Array.isArray(wl) ? wl : (wl.entries || wl.work_ledger || []),
        connector_mappings: cm.connector_mappings || [],
        policy_views: pv.policy_bound_data_views || [],
        ontology_projections: op.ontology_projections || [],
        capability_lease_plans: lp.capability_lease_plans || [],
        data_sources: dsr.data_sources || [],
      }, selectedOntology, new URL(req.url, "http://x").searchParams.get("objectSet") || ""));
      return;
    }
    // ---- Surface registry dispatch — ported application surfaces mount through the explicit
    // table (surface-registry.mjs), not the flat branch chain. This sits exactly where the
    // pipeline branch lived so registry surfaces keep the chain position (after auth/posture
    // gates) the flat branches had. Surface MODULES (surfaces/<slug>/index.mjs) bind in the
    // registry itself under the load(ctx)/render(model, ctx) contract; an unbound surface isn't
    // matched here, so registration is additive and behavior-preserving.
    {
      const hit = boundSurface(pathname, req.method);
      if (hit) {
        const url = new URL(req.url, "http://x");
        const ctx = { url, daemon: DAEMON, embed: url.searchParams.get("embed") === "1" };
        const model = hit.impl.load ? await hit.impl.load(ctx) : null;
        res.writeHead(200, HTMLH);
        // ctx.embed gates the module's own rail emission; the estate-wide embed choke point
        // (handleEstateRequest head) owns link threading — applying it here too would double it.
        res.end(hit.impl.render(model, ctx));
        return;
      }
    }
    // ---- Surface ACTION dispatch (operational wave #62) — the registry-owned action runtime.
    // Matches POST action routes DECLARED by bound modules (e.g. /__ioi/governance/approvals/
    // :id/transition) BEFORE any legacy family handler, so a module owns its own mutations.
    {
      const hit = boundActionRoute(pathname, req.method);
      if (hit) {
        await runSurfaceAction(hit, res, body);
        return;
      }
    }
    // Ontology Manager — reference UX PORT (#34, daemon_wired). Ported schema-workbench shell over the
    // real ODK CanonicalObjectModel; the /__ioi/odk substrate/authoring surface stays as-is.
    if (pathname === "/__ioi/odk" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [ov, o, r, d, m, ds, cm, pv, tr, op, lp, mr, cs, ms] = await Promise.all([
        J("/v1/hypervisor/odk/overview"),
        J("/v1/hypervisor/odk/domain-ontologies"),
        J("/v1/hypervisor/odk/data-recipes"),
        J("/v1/hypervisor/odk/surface-descriptors"),
        J("/v1/hypervisor/odk/manifests"),
        J("/v1/hypervisor/data-sources"),
        J("/v1/hypervisor/odk/connector-mappings"),
        J("/v1/hypervisor/odk/policy-bound-data-views"),
        J("/v1/hypervisor/odk/transformation-runs"),
        J("/v1/hypervisor/odk/ontology-projections"),
        J("/v1/hypervisor/odk/capability-lease-plans"),
        J("/v1/hypervisor/odk/materializing-runs"),
        J("/v1/hypervisor/odk/connector-sessions"),
        J("/v1/hypervisor/odk/materialized-object-sets"),
      ]);
      const selectedOntology = new URL(req.url, "http://x").searchParams.get("ontology") || "";
      res.writeHead(200, HTMLH);
      res.end(renderOntologyManager(ov, {
        ontologies: o.ontologies || [],
        data_recipes: r.data_recipes || [],
        surface_descriptors: d.surface_descriptors || [],
        manifests: m.manifests || [],
        data_sources: ds.data_sources || [],
        connector_mappings: cm.connector_mappings || [],
        policy_views: pv.policy_bound_data_views || [],
        transformation_runs: tr.transformation_runs || [],
        ontology_projections: op.ontology_projections || [],
        capability_lease_plans: lp.capability_lease_plans || [],
        materializing_runs: mr.materializing_runs || [],
        connector_sessions: cs.connector_sessions || [],
        materialized_sets: ms.materialized_object_sets || [],
      }, selectedOntology));
      return;
    }
    if (pathname.startsWith("/__ioi/odk/")) {
      const segs = pathname.slice("/__ioi/odk/".length).split("/").filter((s) => s.length);
      const family = segs[0];
      const cfg = ODK_UI[family];
      if (cfg) {
        const api = `/v1/hypervisor/odk/${cfg.api}`;
        const seg1 = segs[1] || "";
        const seg2 = segs[2] || "";
        // new form
        if (seg1 === "new" && req.method === "GET") {
          const [pk, ov] = await Promise.all([odkPickers(), fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((x) => x.json()).catch(() => ({}))]);
          res.writeHead(200, HTMLH);
          res.end(cfg.form(null, pk, ov));
          return;
        }
        // create (POST to family root)
        if (!seg1 && req.method === "POST") {
          const payload = cfg.payload(new URLSearchParams(body.toString()));
          const rr = await fetch(`${DAEMON}${api}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
          if (rr && rr.ok) { res.writeHead(302, { Location: `/__ioi/odk/${family}/${encodeURIComponent(rr[cfg.key].id)}`, "Cache-Control": "no-cache" }); return res.end(); }
          res.writeHead(200, HTMLH);
          res.end(automationsShell(`New ${cfg.label}`, `<div class="empty">Create failed: ${CX_ESC((rr.error && rr.error.message) || "invalid")}</div><p><a href="/__ioi/odk/${family}/new">← back</a></p>`));
          return;
        }
        // item-scoped (seg1 = id)
        if (seg1) {
          const id = decodeURIComponent(seg1);
          if (seg2 === "edit" && req.method === "GET") {
            const [pk, ov, rec] = await Promise.all([
              odkPickers(),
              fetch(`${DAEMON}/v1/hypervisor/odk/overview`).then((x) => x.json()).catch(() => ({})),
              fetch(`${DAEMON}${api}/${encodeURIComponent(id)}`).then((x) => x.json()).catch(() => ({})),
            ]);
            res.writeHead(200, HTMLH);
            res.end(rec.ok ? cfg.form(rec[cfg.key], pk, ov) : automationsShell("Not found", `<div class="empty">Not found.</div><p><a href="/__ioi/odk">← ODK</a></p>`));
            return;
          }
          if (seg2 === "patch" && req.method === "POST") {
            const payload = cfg.payload(new URLSearchParams(body.toString()));
            const rr = await fetch(`${DAEMON}${api}/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
            if (rr && rr.ok) { res.writeHead(302, { Location: `/__ioi/odk/${family}/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" }); return res.end(); }
            res.writeHead(200, HTMLH);
            res.end(automationsShell(`Edit ${cfg.label}`, `<div class="empty">Save failed: ${CX_ESC((rr.error && rr.error.message) || "invalid")}</div><p><a href="/__ioi/odk/${family}/${encodeURIComponent(id)}/edit">← back</a></p>`));
            return;
          }
          if (seg2 === "delete" && req.method === "POST") {
            await fetch(`${DAEMON}${api}/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
            res.writeHead(302, { Location: "/__ioi/odk", "Cache-Control": "no-cache" });
            return res.end();
          }
          if (!seg2 && req.method === "GET") {
            // Detail also loads the sibling family lists (same endpoints the landing uses) so the
            // renderer can compute REVERSE lineage — which drafts reference this record.
            const J2 = (p) => fetch(`${DAEMON}${p}`).then((x) => x.json()).catch(() => ({}));
            const [rec, oL, rL, dL, mL, wl] = await Promise.all([
              fetch(`${DAEMON}${api}/${encodeURIComponent(id)}`).then((x) => x.json()).catch(() => ({})),
              J2("/v1/hypervisor/odk/domain-ontologies"),
              J2("/v1/hypervisor/odk/data-recipes"),
              J2("/v1/hypervisor/odk/surface-descriptors"),
              J2("/v1/hypervisor/odk/manifests"),
              J2("/v1/hypervisor/work-ledger"),
            ]);
            const lists = {
              ontologies: oL.ontologies || [], data_recipes: rL.data_recipes || [],
              surface_descriptors: dL.surface_descriptors || [], manifests: mL.manifests || [],
              ledger: wl.entries || [],
            };
            res.writeHead(200, HTMLH);
            res.end(rec.ok ? cfg.detail(rec[cfg.key], lists) : automationsShell("Not found", `<div class="empty">Not found.</div><p><a href="/__ioi/odk">← ODK</a></p>`));
            return;
          }
        }
      }
    }
    // ---- Domain-App runtime — the internal, descriptor-driven, read-only served app view.
    if (pathname.startsWith("/__ioi/domain-app-runtime/") && req.method === "GET") {
      const rid = decodeURIComponent(pathname.slice("/__ioi/domain-app-runtime/".length).split("/")[0]);
      const rtRes = await fetch(`${DAEMON}/v1/hypervisor/domain-app-runtimes/${encodeURIComponent(rid)}`).then((x) => x.json()).catch(() => ({}));
      if (!rtRes.ok) { res.writeHead(200, HTMLH); res.end(automationsShell("Domain App", `<div class="empty">Runtime not found.</div><p><a href="/__ioi/domain-apps">← Domain Apps</a></p>`)); return; }
      const rt = rtRes.runtime;
      const dappId = String(rt.domain_app_ref || "").replace(/^domain-app:\/\//, "");
      const dRes = await fetch(`${DAEMON}/v1/hypervisor/domain-apps/${encodeURIComponent(dappId)}`).then((x) => x.json()).catch(() => ({}));
      const dapp = dRes.domain_app || {};
      const sdId = String(dapp.surface_descriptor_ref || "").replace(/^surface-descriptor:\/\//, "");
      const descRes = sdId ? await fetch(`${DAEMON}/v1/hypervisor/odk/surface-descriptors/${encodeURIComponent(sdId)}`).then((x) => x.json()).catch(() => ({})) : {};
      const descriptor = descRes.surface_descriptor || {};
      const ontId = String(descriptor.ontology_ref || "").replace(/^ontology:\/\//, "");
      const ontRes = ontId ? await fetch(`${DAEMON}/v1/hypervisor/odk/domain-ontologies/${encodeURIComponent(ontId)}`).then((x) => x.json()).catch(() => ({})) : {};
      res.writeHead(200, HTMLH);
      res.end(renderDomainAppRuntimeView(rt, dapp, descriptor, ontRes.ontology || {}));
      return;
    }
    // ---- Domain Apps — controlled builder over the daemon Domain Apps object plane (estate #6).
    if (pathname === "/__ioi/domain-apps" && req.method === "GET") {
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [ov, list, mfs] = await Promise.all([J("/v1/hypervisor/domain-apps/overview"), J("/v1/hypervisor/domain-apps"), J("/v1/hypervisor/odk/manifests")]);
      res.writeHead(200, HTMLH);
      res.end(renderDomainAppsLanding(ov, list.domain_apps || [], mfs.manifests || []));
      return;
    }
    if (pathname === "/__ioi/domain-apps/new" && req.method === "GET") {
      res.writeHead(200, HTMLH);
      res.end(renderDomainAppForm(null, await domainAppPickers()));
      return;
    }
    if (pathname === "/__ioi/domain-apps" && req.method === "POST") {
      const payload = domainAppPayload(new URLSearchParams(body.toString()));
      const rr = await fetch(`${DAEMON}/v1/hypervisor/domain-apps`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
      if (rr && rr.ok) { res.writeHead(302, { Location: `/__ioi/domain-apps/${encodeURIComponent(rr.domain_app.domain_app_id)}`, "Cache-Control": "no-cache" }); return res.end(); }
      res.writeHead(200, HTMLH);
      res.end(automationsShell("New Domain App", `<div class="empty">Create failed: ${CX_ESC((rr.error && rr.error.message) || "invalid")}</div><p><a href="/__ioi/domain-apps/new">← back</a></p>`));
      return;
    }
    if (pathname.startsWith("/__ioi/domain-apps/")) {
      const [rawId, action] = pathname.slice("/__ioi/domain-apps/".length).split("/");
      const id = decodeURIComponent(rawId);
      if (action === "edit" && req.method === "GET") {
        const app = await fetch(`${DAEMON}/v1/hypervisor/domain-apps/${encodeURIComponent(id)}`).then((x) => x.json()).catch(() => ({}));
        if (!app.ok) { res.writeHead(200, HTMLH); res.end(automationsShell("Not found", `<div class="empty">Domain App not found.</div><p><a href="/__ioi/domain-apps">← Domain Apps</a></p>`)); return; }
        const pk = await domainAppPickers(app.domain_app.surface_descriptor_ref);
        res.writeHead(200, HTMLH);
        res.end(renderDomainAppForm(app.domain_app, pk));
        return;
      }
      if (action === "patch" && req.method === "POST") {
        const payload = domainAppPayload(new URLSearchParams(body.toString()));
        const rr = await fetch(`${DAEMON}/v1/hypervisor/domain-apps/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
        if (rr && rr.ok) { res.writeHead(302, { Location: `/__ioi/domain-apps/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" }); return res.end(); }
        res.writeHead(200, HTMLH);
        res.end(automationsShell("Edit Domain App", `<div class="empty">Save failed: ${CX_ESC((rr.error && rr.error.message) || "invalid")}</div><p><a href="/__ioi/domain-apps/${encodeURIComponent(id)}/edit">← back</a></p>`));
        return;
      }
      if (action === "delete" && req.method === "POST") {
        await fetch(`${DAEMON}/v1/hypervisor/domain-apps/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
        res.writeHead(302, { Location: "/__ioi/domain-apps", "Cache-Control": "no-cache" });
        return res.end();
      }
      // Governed runtime lifecycle: mount admission -> internal serving. Daemon enforces the gates.
      if (["mount", "unmount", "serve", "stop-serving"].includes(action) && req.method === "POST") {
        const p = new URLSearchParams(body.toString());
        const payload = action === "mount" ? { approval_request_ref: (p.get("approval_request_ref") || "").trim(), release_control_ref: (p.get("release_control_ref") || "").trim() } : {};
        const r = await fetch(`${DAEMON}/v1/hypervisor/domain-apps/${encodeURIComponent(id)}/${action}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
        if (r && r.ok === false && r.error) { res.writeHead(200, HTMLH); res.end(automationsShell("Domain App", `<div class="empty">${CX_ESC(action)} failed: ${CX_ESC(r.error.message || "error")}</div><p><a href="/__ioi/domain-apps/${encodeURIComponent(id)}">← back</a></p>`)); return; }
        res.writeHead(302, { Location: `/__ioi/domain-apps/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" });
        return res.end();
      }
      if (!action && req.method === "GET") {
        const app = await fetch(`${DAEMON}/v1/hypervisor/domain-apps/${encodeURIComponent(id)}`).then((x) => x.json()).catch(() => ({}));
        if (!app.ok) { res.writeHead(200, HTMLH); res.end(automationsShell("Not found", `<div class="empty">Domain App not found.</div><p><a href="/__ioi/domain-apps">← Domain Apps</a></p>`)); return; }
        const dref = app.domain_app.domain_app_ref;
        const [rtRes, apRes, relRes] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/domain-app-runtimes?domain_app_ref=${encodeURIComponent(dref)}`).then((x) => x.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/governance/approval-requests?status=approved`).then((x) => x.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/governance/release-controls`).then((x) => x.json()).catch(() => ({})),
        ]);
        const rt = (rtRes.runtimes || []).find((x) => x.mounted === true) || null;
        res.writeHead(200, HTMLH);
        res.end(renderDomainAppDetail(app.domain_app, rt, apRes.approval_requests || [], relRes.release_controls || []));
        return;
      }
    }
    // ---- Governance — control cockpit over the daemon governance projection + control objects (#7).
    if (pathname === "/__ioi/governance" && req.method === "GET") {
      const tab = new URL(req.url, "http://x").searchParams.get("tab") || "overview";
      const J = (p) => fetch(`${DAEMON}${p}`).then((r) => r.json()).catch(() => ({}));
      const [ov, ap, rl, ks, ig, co, da, mpc, mls, fsp, frp] = await Promise.all([
        J("/v1/hypervisor/governance/overview"),
        J("/v1/hypervisor/governance/approval-requests"),
        J("/v1/hypervisor/governance/release-controls"),
        J("/v1/hypervisor/governance/kill-switches"),
        J("/v1/hypervisor/governance/improvement-gates"),
        J("/v1/hypervisor/governance/cohorts"),
        J("/v1/hypervisor/domain-apps"),
        J("/v1/hypervisor/marketplace/publish-candidates"),
        J("/v1/hypervisor/marketplace/listings"),
        J("/v1/hypervisor/foundry/specs"),
        J("/v1/hypervisor/foundry/run-plans"),
      ]);
      res.writeHead(200, HTMLH);
      res.end(renderGovernance(ov, {
        approval_requests: ap.approval_requests || [],
        release_controls: rl.release_controls || [],
        kill_switches: ks.kill_switches || [],
        improvement_gates: ig.improvement_gates || [],
        cohorts: co.cohorts || [],
      }, tab, {
        domain_apps: da.domain_apps || [],
        publish_candidates: mpc.publish_candidates || mpc.candidates || [],
        listings: mls.listings || [],
        foundry_specs: fsp.specs || [],
        foundry_plans: frp.run_plans || [],
      }));
      return;
    }
    // Approvals inbox — reference UX PORT (#36, daemon_wired). FAITHFUL light faceted inbox (dark global
    // rail + Quick/Additional filter sidebar + request list + on-select detail) over the real
    // ApprovalRequest queue; substrate table stays at /__ioi/governance?tab=approvals.
    // Governance control-object mutations (record-only; the daemon executes no enforcement).
    if (pathname.startsWith("/__ioi/governance/")) {
      const segs = pathname.slice("/__ioi/governance/".length).split("/");
      const fam = segs[0];
      const cfg = GOV_FAMS[fam];
      if (cfg && req.method === "POST") {
        const api = `/v1/hypervisor/governance/${cfg.api}`;
        const p = new URLSearchParams(body.toString());
        // Redirect back to the caller's surface — the ported Approvals inbox (#33) posts a `return`
        // to land back on itself; everything else falls back to the substrate tab. Same-origin only.
        const ret = p.get("return");
        // Same-origin path only, and no characters that could break out of an HTML attribute / a header
        // (defense-in-depth: the href is also CX_ESC'd on the failure-render paths).
        const back = (ret && ret.startsWith("/__ioi/") && !/["'<>\r\n]/.test(ret)) ? ret : `/__ioi/governance?tab=${fam}`;
        // create (POST to family root)
        if (!segs[1]) {
          const csv = (k) => (p.get(k) || "").split(",").map((s) => s.trim()).filter(Boolean);
          let payload = {};
          if (fam === "approvals") payload = { subject_ref: (p.get("subject_ref") || "").trim(), request_kind: (p.get("request_kind") || "").trim(), reason: (p.get("reason") || "").trim(), required_authority_refs: csv("required_authority_refs") };
          else if (fam === "releases") { payload = { release_target_ref: (p.get("release_target_ref") || "").trim(), rollout_mode: (p.get("rollout_mode") || "full").trim() }; const cp = (p.get("canary_percent") || "").trim(); if (cp) payload.canary_percent = parseInt(cp, 10); const refs = p.getAll("cohort_refs").map((x) => x.trim()).filter(Boolean); if (refs.length) payload.cohort_refs = refs; }
          else if (fam === "cohorts") payload = { display_name: (p.get("display_name") || "").trim(), scope: (p.get("scope") || "project").trim(), description: (p.get("description") || "").trim(), member_refs: csv("member_refs") };
          else if (fam === "kill-switches") payload = { subject_ref: (p.get("subject_ref") || "").trim(), revoke_path: (p.get("revoke_path") || "").trim() };
          else if (fam === "gates") { const bounds = {}; const mi = (p.get("max_iterations") || "").trim(); if (mi) bounds.max_iterations = parseInt(mi, 10) || mi; const et = (p.get("eval_threshold") || "").trim(); if (et) bounds.eval_threshold = parseFloat(et) || et; const pp = (p.get("privacy_posture") || "").trim(); if (pp) bounds.privacy_posture = pp; payload = { subject_ref: (p.get("subject_ref") || "").trim(), bounds }; }
          const r = await fetch(`${DAEMON}${api}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
          if (r && r.ok) { res.writeHead(302, { Location: back, "Cache-Control": "no-cache" }); return res.end(); }
          res.writeHead(200, HTMLH);
          res.end(automationsShell("Governance", `<div class="empty">Create failed: ${CX_ESC((r.error && r.error.message) || "invalid")}</div><p><a href="${CX_ESC(back)}">← back</a></p>`));
          return;
        }
        const id = decodeURIComponent(segs[1]);
        const action = segs[2] || "";
        if (action === "transition") {
          const patch = { transition: (p.get("transition") || "").trim() };
          const rv = (p.get("reviewer_ref") || "").trim(); if (rv) patch.reviewer_ref = rv;
          const tr = (p.get("trip_reason") || "").trim(); if (tr) patch.trip_reason = tr;
          const r = await fetch(`${DAEMON}${api}/${encodeURIComponent(id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(patch) }).then((x) => x.json()).catch(() => ({}));
          if (r && r.ok === false && r.error) { res.writeHead(200, HTMLH); res.end(automationsShell("Governance", `<div class="empty">Transition failed: ${CX_ESC(r.error.message || "invalid")}</div><p><a href="${CX_ESC(back)}">← back</a></p>`)); return; }
          res.writeHead(302, { Location: back, "Cache-Control": "no-cache" }); return res.end();
        }
        if (action === "delete") {
          await fetch(`${DAEMON}${api}/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
          res.writeHead(302, { Location: back, "Cache-Control": "no-cache" }); return res.end();
        }
        // Effectful KillSwitch enforcement (after trip).
        if (action === "enforce" && fam === "kill-switches") {
          const r = await fetch(`${DAEMON}${api}/${encodeURIComponent(id)}/enforce`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((x) => x.json()).catch(() => ({}));
          if (r && r.ok === false && r.error) { res.writeHead(200, HTMLH); res.end(automationsShell("Governance", `<div class="empty">Enforce failed: ${CX_ESC(r.error.message || "invalid")}</div><p><a href="${CX_ESC(back)}">← back</a></p>`)); return; }
          res.writeHead(302, { Location: back, "Cache-Control": "no-cache" }); return res.end();
        }
      }
    }
    // ---- Marketplace — source-grafted catalog/detail/admission surface (estate #8, last card).
    if (pathname === "/__ioi/marketplace" && req.method === "GET") {
      const u = new URL(req.url, "http://x");
      const [ov, ls] = await Promise.all([
        fetch(`${DAEMON}/v1/hypervisor/marketplace/overview`).then((r) => r.json()).catch(() => ({})),
        fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`).then((r) => r.json()).catch(() => ({})),
      ]);
      res.writeHead(200, HTMLH);
      res.end(renderMarketplaceHome(ov, ls.listings || [], u.searchParams.get("q") || "", u.searchParams.get("store") || ""));
      return;
    }
    if (pathname === "/__ioi/marketplace/listings/new" && req.method === "GET") {
      res.writeHead(200, HTMLH);
      res.end(renderMarketplaceListingForm(null, await marketplaceSubjectOptions()));
      return;
    }
    if (pathname === "/__ioi/marketplace/listings" && req.method === "POST") {
      const payload = marketplacePayloadFromForm(new URLSearchParams(body.toString()));
      const rr = await fetch(`${DAEMON}/v1/hypervisor/marketplace/listings`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
      if (rr && rr.ok) { res.writeHead(302, { Location: `/__ioi/marketplace/listings/${encodeURIComponent(rr.listing.id)}`, "Cache-Control": "no-cache" }); return res.end(); }
      res.writeHead(200, HTMLH);
      res.end(automationsShell("Draft listing", `<div class="empty">Create failed: ${CX_ESC((rr.error && rr.error.message) || "invalid")}</div><p><a href="/__ioi/marketplace/listings/new">← back</a></p>`));
      return;
    }
    if (pathname.startsWith("/__ioi/marketplace/listings/")) {
      const [rawId, action] = pathname.slice("/__ioi/marketplace/listings/".length).split("/");
      const id = decodeURIComponent(rawId);
      const listingApi = `/v1/hypervisor/marketplace/listings/${encodeURIComponent(id)}`;
      if (action === "edit" && req.method === "GET") {
        const [lr, opts] = await Promise.all([fetch(`${DAEMON}${listingApi}`).then((x) => x.json()).catch(() => ({})), marketplaceSubjectOptions()]);
        res.writeHead(200, HTMLH);
        res.end(lr.ok ? renderMarketplaceListingForm(lr.listing, opts) : automationsShell("Not found", `<div class="empty">Listing not found.</div><p><a href="/__ioi/marketplace">← Marketplace</a></p>`));
        return;
      }
      if (action === "patch" && req.method === "POST") {
        const payload = marketplacePayloadFromForm(new URLSearchParams(body.toString()));
        const rr = await fetch(`${DAEMON}${listingApi}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }).then((x) => x.json()).catch(() => ({}));
        if (rr && rr.ok) { res.writeHead(302, { Location: `/__ioi/marketplace/listings/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" }); return res.end(); }
        res.writeHead(200, HTMLH);
        res.end(automationsShell("Edit listing", `<div class="empty">Save failed: ${CX_ESC((rr.error && rr.error.message) || "invalid")}</div><p><a href="/__ioi/marketplace/listings/${encodeURIComponent(id)}/edit">← back</a></p>`));
        return;
      }
      if (action === "delete" && req.method === "POST") {
        await fetch(`${DAEMON}${listingApi}`, { method: "DELETE" }).catch(() => {});
        res.writeHead(302, { Location: "/__ioi/marketplace", "Cache-Control": "no-cache" });
        return res.end();
      }
      if (action === "candidates" && req.method === "POST") {
        const lr = await fetch(`${DAEMON}${listingApi}`).then((x) => x.json()).catch(() => ({}));
        if (lr.ok) await fetch(`${DAEMON}/v1/hypervisor/marketplace/publish-candidates`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ listing_ref: lr.listing.ref }) }).catch(() => {});
        res.writeHead(302, { Location: `/__ioi/marketplace/listings/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" });
        return res.end();
      }
      if (action === "offers" && req.method === "POST") {
        const lr = await fetch(`${DAEMON}${listingApi}`).then((x) => x.json()).catch(() => ({}));
        if (lr.ok) await fetch(`${DAEMON}/v1/hypervisor/marketplace/instance-offers`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ offer_kind: lr.listing.listing_kind, subject_ref: lr.listing.subject_ref, listing_ref: lr.listing.ref, name: `${lr.listing.name || "offer"} (offer)` }) }).catch(() => {});
        res.writeHead(302, { Location: `/__ioi/marketplace/listings/${encodeURIComponent(id)}`, "Cache-Control": "no-cache" });
        return res.end();
      }
      if (!action && req.method === "GET") {
        const lr = await fetch(`${DAEMON}${listingApi}`).then((x) => x.json()).catch(() => ({}));
        if (!lr.ok) { res.writeHead(200, HTMLH); res.end(automationsShell("Not found", `<div class="empty">Listing not found.</div><p><a href="/__ioi/marketplace">← Marketplace</a></p>`)); return; }
        const listing = lr.listing;
        const [cRes, rRes, oRes, gRes] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/marketplace/publish-candidates`).then((x) => x.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/marketplace/admission-reviews`).then((x) => x.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/marketplace/instance-offers`).then((x) => x.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/marketplace/overview`).then((x) => x.json()).catch(() => ({})),
        ]);
        const candidates = (cRes.publish_candidates || []).filter((c) => c.listing_ref === listing.ref);
        const reviewsByCandidate = {};
        for (const rv of (rRes.admission_reviews || [])) { (reviewsByCandidate[rv.candidate_ref] = reviewsByCandidate[rv.candidate_ref] || []).push(rv); }
        const offers = (oRes.managed_instance_offers || []).filter((o) => o.subject_ref === listing.subject_ref);
        const gov = (gRes.governance_posture) || null;
        res.writeHead(200, HTMLH);
        res.end(renderMarketplaceListingDetail(listing, candidates, reviewsByCandidate, offers, gov));
        return;
      }
    }
    if (pathname.startsWith("/__ioi/marketplace/candidates/") && req.method === "POST") {
      const [rawId, action] = pathname.slice("/__ioi/marketplace/candidates/".length).split("/");
      const id = decodeURIComponent(rawId);
      const p = new URLSearchParams(body.toString());
      const back = `/__ioi/marketplace/listings/${encodeURIComponent(p.get("listing_id") || "")}`;
      if (action === "delete") {
        await fetch(`${DAEMON}/v1/hypervisor/marketplace/publish-candidates/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
      } else if (action === "reviews") {
        await fetch(`${DAEMON}/v1/hypervisor/marketplace/admission-reviews`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ candidate_ref: `marketplace-publish://${id}`, decision: (p.get("decision") || "pending").trim() }) }).catch(() => {});
      } else if (action === "publish") {
        const r = await fetch(`${DAEMON}/v1/hypervisor/marketplace/publish-candidates/${encodeURIComponent(id)}/publish`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }).then((x) => x.json()).catch(() => ({}));
        if (r && r.ok === false && r.error) {
          const reasons = (r.error.blocked_reasons || []).join(", ");
          res.writeHead(200, HTMLH);
          res.end(automationsShell("Marketplace", `<div class="empty">Publish blocked: ${CX_ESC(r.error.message || "")}${reasons ? " — " + CX_ESC(reasons) : ""}</div><p><a href="${CX_ESC(back)}">← back</a></p>`));
          return;
        }
      }
      res.writeHead(302, { Location: back, "Cache-Control": "no-cache" });
      return res.end();
    }
    if (pathname.startsWith("/__ioi/marketplace/reviews/") && req.method === "POST") {
      const [rawId] = pathname.slice("/__ioi/marketplace/reviews/".length).split("/");
      const id = decodeURIComponent(rawId);
      const p = new URLSearchParams(body.toString());
      await fetch(`${DAEMON}/v1/hypervisor/marketplace/admission-reviews/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
      res.writeHead(302, { Location: `/__ioi/marketplace/listings/${encodeURIComponent(p.get("listing_id") || "")}`, "Cache-Control": "no-cache" });
      return res.end();
    }
    if (pathname.startsWith("/__ioi/marketplace/offers/") && req.method === "POST") {
      const [rawId] = pathname.slice("/__ioi/marketplace/offers/".length).split("/");
      const id = decodeURIComponent(rawId);
      const p = new URLSearchParams(body.toString());
      await fetch(`${DAEMON}/v1/hypervisor/marketplace/instance-offers/${encodeURIComponent(id)}`, { method: "DELETE" }).catch(() => {});
      res.writeHead(302, { Location: `/__ioi/marketplace/listings/${encodeURIComponent(p.get("listing_id") || "")}`, "Cache-Control": "no-cache" });
      return res.end();
    }
    // ---- Connections cockpit — the owned full-control surface for the connector estate -----------
    if (pathname === "/__ioi/connections") {
      try {
        const [c, s, l, mcpTools, authPol, scimStatus] = await Promise.all([
          fetch(`${DAEMON}/v1/hypervisor/connectors`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/scm-connectors`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/capability-leases`).then((r) => r.json()).catch(() => ({})),
          fetch(`${DAEMON}/v1/hypervisor/mcp-gateway/tools`).then((r) => r.json()).catch(() => null),
          fetch(`${DAEMON}/v1/hypervisor/auth/policy`).then((r) => r.json()).catch(() => null),
          fetch(`${DAEMON}/scim/v2/ServiceProviderConfig`).then((r) => r.status).catch(() => 0),
        ]);
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        res.end(renderConnectionsCockpit(c.connectors || [], s.connectors || [], l.leases || [], { mcpTools, authPol, scimStatus }));
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
      if (!run) {
        // Transcript-plane fallback: adapter/goal-run ops post agent-run transcripts (hpo_*)
        // rather than registry runs; project the durable transcript into the timeline shape so
        // proof links from Work Ledger / IOI Agent results open a real page (never a 404).
        // Real fields only — request/activity/artifacts come straight off the transcript.
        try {
          const tRes = await fetch(`${DAEMON}/v1/hypervisor/agent-run-transcripts/${encodeURIComponent(runId)}`).then((x) => x.json()).catch(() => null);
          const tr = tRes?.run || (tRes?.run_id ? tRes : null);
          if (tr && tr.run_id === runId) {
            const out = (tr.step_results || [])[0]?.output || {};
            const isAgentRun = String(tr.op || "").startsWith("goal_run");
            const files = out.files_written || out.final_changed_files || [];
            const timeline = {
              schema_version: "ioi.hypervisor.run-timeline.v1",
              runId,
              environmentId: null,
              sessionRef: out.session_ref || null,
              title: isAgentRun ? "IOI Agent coordination" : `Harness run · ${out.harness || tr.profile_ref || ""}`,
              status: tr.status || "done",
              phase: tr.status === "failed" ? "AGENT_EXECUTION_PHASE_FAILED" : "AGENT_EXECUTION_PHASE_STOPPED",
              activeStatus: null,
              stateRoot: tr.state_root || null,
              durable: !!tr.state_root,
              createdAt: tr.started_at,
              updatedAt: tr.recorded_at || tr.finished_at,
              turns: [{
                id: `${runId}-t1`,
                request: null,
                activity: [{ kind: "step", text: `${tr.op || "run"} · ${out.harness || tr.profile_ref || ""} · ${out.exit_status || tr.status || ""}`, at: tr.recorded_at }],
                response: { text: out.exit_status === "failure" ? "Run failed." : "Run complete.", at: tr.recorded_at, failed: out.exit_status === "failure" },
                artifacts: { files: (files || []).map((f) => ({ path: f })), drafts: [], terminals: [] },
                proof: {
                  authority: null,
                  receipts: [],
                  leaseRef: null,
                  proposalRefs: [],
                  publishReceipts: [],
                  stateRoot: tr.state_root || null,
                  note: out.receipt_ref ? `Receipt: ${out.receipt_ref}` : null,
                },
                followUps: [],
              }],
            };
            res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-cache" });
            res.end(JSON.stringify(timeline));
            return;
          }
        } catch { /* fall through to 404 */ }
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, reason: "run not found" }));
        return;
      }
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
    // UNIVERSAL CAPTURE FALLBACK (Phase 1 — boot-depth: guarantee every relative seed asset is
    // present). A GET made BY a booted /__apps seed page (Referer under /__apps/) for a same-origin
    // path not matched by any estate route above is served from the local capture if it exists —
    // so a seed is NEVER blocked by a routing-allowlist gap. Scoped to seed-origin requests, so it
    // can never shadow an estate route or the product-ui bundle. Declared transforms only
    // (capitalized brand rewrite on html/js); assets are byte-faithful otherwise.
    {
      const ref = String(req.headers["referer"] || "");
      const fromSeed = /\/__apps\//.test(ref);
      const estate = /^\/(__ioi|__apps|v1|api|scim|graphql-gateway|sentry-tunnel|supervisor\.v1|assets\/content-addressable-storage)\b/.test(pathname);
      if (req.method === "GET" && fromSeed && !estate) {
        const capBase = process.env.IOI_HARVEST_CAPTURE_URL || process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225";
        try {
          const capResp = await fetch(capBase + req.url, { redirect: "manual" });
          if (capResp.status === 200) {
            const ct = capResp.headers.get("content-type") || "application/octet-stream";
            let buf = Buffer.from(await capResp.arrayBuffer());
            if (/text\/html|javascript|ecmascript/.test(ct)) buf = Buffer.from(buf.toString("utf8").replace(/Palantir/g, "IOI"), "utf8");
            res.writeHead(200, { "Content-Type": ct, "Cache-Control": "no-cache", "content-length": String(buf.length) });
            return res.end(buf);
          }
        } catch { /* capture offline or absent → fall through to the mock */ }
      }
    }
    proxyToProductUi(req, res, body);
}

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
