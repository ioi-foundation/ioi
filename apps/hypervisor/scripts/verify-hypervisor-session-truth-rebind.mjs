#!/usr/bin/env node
// verify-hypervisor-session-truth-rebind — M13.4: the SPA session view's panes (request, activity,
// artifacts, proof band) read DAEMON truth, and the operator's parked decision is reachable from
// the session the run was submitted in. The served /__ioi/sessions readout stays the operator's
// inspection lane. (check:session-truth-rebind; ADR 0052; bounded-alpha-profile.md step 7.)
//
// What this proves without an authority node: the timeline projection the SPA session pane
// renders is built from the daemon's session record (lifecycle state, receipt refs, authority
// profile), the daemon's session events (workspace diff) and the receipts the record names; a run
// that failed CLOSED for lack of an authority node shows exactly that, with no fabricated receipt.
// The awaiting-approval card shape and its approve/deny endpoints are proved on the pure projection
// (a parked run record) and live in the alpha journey's deployment mode.
//
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary absent).

import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { projectRunTimeline } from "./ioi-run-timeline.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((resolve, reject) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); s.on("error", reject); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.status < 500) return; } catch { /* */ } await sleep(300); } throw new Error(`timeout ${url}`); };

// ---- 1. the pure projection: a parked run renders the approval card; a decided run does not ----
const parked = { id: "agent_x1", name: "Parked", status: "awaiting_operator_approval", prompt: "Create HELLO.md", sessionRef: "session:ai-agent_x1", envId: "env_1", createdAt: "2026-09-07T00:00:00Z", updatedAt: "2026-09-07T00:00:01Z", statusVersion: 3, activityLog: [{ text: "Waiting for your approval", at: "2026-09-07T00:00:01Z" }],
  pendingApproval: { kind: "session_execute", session_ref: "session:ai-agent_x1", intent: "Create HELLO.md", policy_hash: "sha256:" + "ab".repeat(32), request_hash: "sha256:" + "cd".repeat(32), audience: "ef".repeat(32), required_scopes: ["scope:hypervisor.live-route.session-execute"], requested_at: "2026-09-07T00:00:01Z", decision: null } };
const tl = projectRunTimeline(parked, {});
const ap = tl?.turns?.[0]?.approval;
ok("a parked run projects an AWAITING approval card with the exact effect, both commitments, the daemon audience and the approve/deny endpoints", ap?.state === "awaiting" && ap.policyHash === parked.pendingApproval.policy_hash && ap.requestHash === parked.pendingApproval.request_hash && ap.audience === parked.pendingApproval.audience && ap.approveUrl === "/__ioi/runs/agent_x1/approve" && ap.denyUrl === "/__ioi/runs/agent_x1/deny" && tl.phase === "AGENT_EXECUTION_PHASE_PENDING", JSON.stringify(ap).slice(0, 160));
const decided = projectRunTimeline({ ...parked, status: "denied", pendingApproval: { ...parked.pendingApproval, decision: "denied", decided_at: "2026-09-07T00:00:05Z" } }, {});
ok("a decided run projects the decision and NO approve/deny endpoint (nothing to sign)", decided.turns[0].approval.state === "denied" && decided.turns[0].approval.approveUrl === null && decided.turns[0].approval.denyUrl === null, JSON.stringify(decided.turns[0].approval).slice(0, 120));
const bound = projectRunTimeline({ ...parked, status: "done", changedFiles: [] }, {
  session: { session_ref: "session:ai-agent_x1", lifecycle_state: "executed", latest_receipt_refs: ["receipt://x/execute"], authority_profile: { connection_refs: [] } },
  sessionReceipts: [{ id: "receipt://x/execute", kind: "hypervisor.session.execute", exit_status: "0", capability_lease_ref: "lease://x", authority_scope_refs: ["scope:hypervisor.live-route.session-execute"] }],
  sessionEvents: { workspace_diff: { changed_file_groups: [{ kind: "added", files: ["HELLO.md"] }] } },
});
const pb = bound.turns[0].proof;
ok("the proof band is built FROM the daemon records: session lifecycle + receipt refs, the named receipts (kind, lease, scopes) and the workspace diff become artifacts when the cache has none", pb.session?.lifecycleState === "executed" && pb.session.latestReceiptRefs.length === 1 && pb.daemonReceipts[0]?.capabilityLeaseRef === "lease://x" && pb.leaseRef === "lease://x" && bound.turns[0].artifacts.files.includes("HELLO.md") && bound.turns[0].artifacts.daemonFiles[0]?.source === "daemon-runtime", JSON.stringify({ session: pb.session, files: bound.turns[0].artifacts.files }).slice(0, 200));

// ---- 2. live: an isolated daemon + serve; a run that fails closed shows the daemon's truth --------
const plane = await startIsolatedPlane({ baseEnv: process.env, env: { IOI_HYPERVISOR_MODEL: "qwen2.5:7b", IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1" } });
if (!plane) { console.error("BLOCKED: daemon binary absent"); process.exit(2); }
const DAEMON = plane.daemonUrl;
let serve = null;
let SERVE = "";
try {
  const token = fs.readFileSync(path.join(plane.dataDir, "isolated-daemon.log"), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
  const boot = await fetch(`${DAEMON}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token, password: "truth-rebind-pass-1", email: "rebind@ioi.local" }) });
  const bootBody = await boot.json();
  const sessionToken = bootBody.session_token || "";
  const cookie = `ioi_session=${sessionToken}`;
  const authed = sessionToken.startsWith("ioi_sess_");
  ok("an isolated daemon boots and the operator bootstraps", boot.status < 300 && authed, `${boot.status}`);
  const servePort = await freePort();
  const productUiPort = await freePort();
  SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], { cwd: APP, env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(productUiPort), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_HYPERVISOR_LOCAL_APPROVER_KEY_PATH: "" }, stdio: ["ignore", "pipe", "pipe"] });
  await waitFor(`${SERVE}/__ioi/login`, 60000);
  const jd = (base, p, init = {}) => fetch(`${base}${p}`, { ...init, redirect: "manual", headers: { ...(init.body ? { "content-type": "application/json" } : {}), cookie, ...(init.headers || {}) } }).then(async (r) => { const text = await r.text(); let body = {}; try { body = text ? JSON.parse(text) : {}; } catch { body = { _raw: text }; } return { status: r.status, body, text }; });
  const create = await jd(SERVE, "/api/ioi.v1.AgentService/CreateAgentSession", { method: "POST", body: JSON.stringify({ initialInput: { inputs: [{ text: { content: "Create a file named REBIND.md" } }] }, environmentClassId: "local-workspace-v0" }) });
  const runId = create.body?.agentExecutionId || "";
  const envId = create.body?.environment?.id || create.body?.environment?.environmentId || "";
  ok("the SPA composer creates a run against a real environment and session", create.status === 200 && runId && envId, `${create.status} ${runId}`);
  let timeline = null;
  const deadline = Date.now() + 90000;
  while (Date.now() < deadline) {
    const t = await jd(SERVE, `/__ioi/agent-runs/${encodeURIComponent(runId)}/timeline`);
    timeline = t.body;
    if (["failed", "done", "denied", "awaiting_operator_approval"].includes(timeline?.status)) break;
    await sleep(1000);
  }
  const turn = timeline?.turns?.[0] || {};
  const sessionRef = timeline?.sessionRef || "";
  const daemonSession = await jd(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`);
  const ds = daemonSession.body?.session || {};
  ok("the timeline the SPA session pane renders names the daemon's session and its lifecycle state, read from the daemon record under the caller's identity", daemonSession.status === 200 && turn.proof?.session?.ref === ds.session_ref && turn.proof?.session?.lifecycleState === ds.lifecycle_state && turn.proof.session.source === "daemon-runtime", `${daemonSession.status} · ${turn.proof?.session?.ref} ${turn.proof?.session?.lifecycleState} vs daemon ${ds.lifecycle_state}`);
  ok("the receipt refs on the proof band are exactly the daemon record's latest_receipt_refs", JSON.stringify(turn.proof?.session?.latestReceiptRefs || []) === JSON.stringify(ds.latest_receipt_refs || []), `${(ds.latest_receipt_refs || []).length} ref(s)`);
  ok("WITHOUT an authority node the run fails CLOSED and the pane shows that: no approval card, no execute receipt, no fabricated artifact", timeline?.status === "failed" && !turn.approval && (turn.proof?.daemonReceipts || []).every((r) => r.kind !== "hypervisor.session.execute") && (turn.artifacts?.files || []).length === 0, `${timeline?.status} · ${String(turn.response?.text || "").slice(0, 100)}`);
  const events = await jd(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/events`);
  ok("the artifacts pane is fed by the daemon's session events (workspace diff), not by the serve's cache alone", events.status === 200 && Array.isArray(turn.artifacts?.daemonFiles), `${events.status} · ${(turn.artifacts?.daemonFiles || []).length} daemon file(s)`);
  const readout = await jd(SERVE, "/__ioi/sessions");
  ok("the served Sessions readout remains the operator's inspection lane and lists the same daemon session", readout.status === 200 && readout.text.includes(sessionRef), `${readout.status}`);
  const page = await jd(SERVE, `/__ioi/run-timeline/env/${encodeURIComponent(envId)}`);
  ok("the session pane's timeline page (the SPA /details lane's frame) serves for the environment the run was submitted in", page.status === 200 && page.text.includes("Run Timeline"), `${page.status}`);
} finally {
  try { serve?.kill("SIGTERM"); } catch { /* */ }
  try { await plane.stop(); } catch { /* */ }
}

const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
console.log(`\n${results.length - fails.length}/${results.length} passed`);
emitVerifierCensus({ verifierId: "session-truth-rebind", sourceUrl: import.meta.url, results });
process.exit(fails.length ? 1 : 0);
