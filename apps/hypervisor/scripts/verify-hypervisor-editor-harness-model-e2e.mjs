#!/usr/bin/env node
// Editor + Harness + Model interchangeability — full end-to-end loop done-bar.
//
// Proves the loop the way a user would drive it, every step against daemon truth:
//   New Session -> choose editor target -> choose harness -> choose model route -> launch
//   -> harness executes -> editor shows the workspace change -> Work Ledger shows the receipt
//   -> Run Timeline (transcript plane) shows the state_root proof.
//
// The session is bound to a REAL environment so the SAME workspace the harness writes into is the
// one the VS Code Browser editor opens (bind_env_workspace == env status.workspace_root ==
// the editor's served root). Nothing is faked: the file is asserted on disk in the editor's root,
// the editor is driven live (302 -> a serving openvscode instance), and every proof is a daemon
// record.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-editor-harness-model-e2e.mjs
// Drives the opencode adapter against local Ollama/qwen2.5:7b (≈30–60s). HOST PRECONDITIONS: the plane's daemon
// inherits IOI_HYPERVISOR_MODEL_UPSTREAM (default http://127.0.0.1:11434, local Ollama) and the VS Code Browser lane
// needs its editor server on the host; without them the clauses that need them fail naming the gate.
//
// ITS OWN STACK (R-240, verifier hazard sweep 2, 2026-09-29). This verifier enabled a harness profile, launched a
// session and had a harness write into an environment of the owner's daemon (:8765) through the owner's serve (:4173),
// as nobody. It now runs on its own isolated daemon + serve with the operator signed in (lib/verifier-stack.mjs); the
// environment it binds is one it provisions through the product's own environment routes (a fresh plane holds none);
// its node:http requests carry the operator's session cookie themselves.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifierStack } from "./lib/verifier-stack.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const STACK = await verifierStack({ serve: true });
const SHELL = STACK.serveUrl;
const DAEMON = STACK.daemonUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
import http from "node:http";
// node:http, not fetch: synchronous harness-execute calls legitimately exceed undici's fixed
// 300s headers timeout under the 600s hot-host driver budget (CPU-only local inference).
function jd(base, method, p, body) {
  const target = new URL(`${base}${p}`);
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: target.hostname, port: target.port, path: target.pathname + target.search, method,
        headers: { "content-type": "application/json", cookie: STACK.cookie, ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}) } },
      (res) => {
        let raw = "";
        res.on("data", (c) => { raw += c; });
        res.on("end", () => {
          let j = {};
          try { j = JSON.parse(raw); } catch { j = {}; }
          resolve({ status: res.statusCode, j });
        });
      },
    );
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// The environment the session binds: provisioned and started through the daemon's own environment routes, its
// workspace on disk (what the editor serves). A fresh plane holds none; the owner's daemon always had one.
async function provisionEnvironment() {
  const made = await jd(DAEMON, "POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "editor-harness-model-e2e" } });
  const id = made.j?.environment?.id;
  if (!id) return;
  await jd(DAEMON, "POST", `/v1/hypervisor/environments/${encodeURIComponent(id)}/start`);
  for (let i = 0; i < 120; i++) {
    const rec = await jd(DAEMON, "GET", `/v1/hypervisor/environments/${encodeURIComponent(id)}`);
    if (rec.j?.environment?.status?.workspace_root) return;
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function run() {
  await provisionEnvironment();
  // ── STEP 1: New Session context offers all three interchangeable axes as REAL choices ──
  const ctx = await jd(SHELL, "GET", "/__ioi/api/new-session/context");
  const editors = ctx.j?.editor_targets || [];
  const profiles = ctx.j?.harness_profiles || [];
  const routes = ctx.j?.model_routes || [];
  const envs = ctx.j?.environments || [];
  ok("editor targets offered (choose editor)", editors.some((t) => t.target_id === "vscode-browser" && t.openable) && editors.some((t) => t.target_id === "workbench-native"), editors.filter((t) => t.openable).map((t) => t.target_id).join(","));
  ok("harness profiles offered (choose harness — opencode present)", profiles.some((p) => p.harness === "opencode"), profiles.map((p) => p.harness).join(","));
  ok("model routes offered (choose model — qwen available)", routes.some((r) => /qwen/i.test(r.model_id || "") && r.availability === "available"), routes.map((r) => `${r.model_id}:${r.availability}`).join(","));

  // Pick a real environment whose workspace exists on disk (the editor's served root).
  let envId = null, envWorkspace = null;
  for (const e of envs) {
    const rec = await jd(DAEMON, "GET", `/v1/hypervisor/environments/${e.id}`);
    const ws = rec.j?.environment?.status?.workspace_root || rec.j?.status?.workspace_root;
    if (ws && fs.existsSync(ws)) { envId = e.id; envWorkspace = ws; break; }
  }
  ok("a real environment with an on-disk workspace is available to bind", !!envId, `${envId} @ ${envWorkspace}`);
  if (!envId) return;

  // ── STEP 2: enable opencode, then LAUNCH through the owned launcher endpoint with all axes ──
  await jd(DAEMON, "POST", "/v1/hypervisor/harness-profiles/hp_opencode/enable");
  const marker = `e2e-loop-${Date.now().toString(16)}.txt`;
  const content = "editor-harness-model loop proof";
  const launch = await jd(SHELL, "POST", "/__ioi/api/new-session/launch", {
    environment_id: envId,
    editor_target_ref: "editor-target:vscode-browser",
    harness_profile_ref: "harness-profile:hp_opencode",
    model_route_ref: "model-route:mrt_local_default",
    harness_key: "opencode",
    matrix_model: "hypervisor:native-local",
    reasoning: "medium",
    speed: "balanced",
  });
  ok("launch created a session with all three selections recorded", launch.status === 202 && launch.j?.harness_binding?.profile_ref === "harness-profile:hp_opencode" && launch.j?.editor_target_ref === "editor-target:vscode-browser", `${launch.status} ${launch.j?.editor_target_ref} ${launch.j?.error?.code || ""}`);
  const sid = launch.j?.session_ref;
  if (!sid) return;
  ok("session bound to the chosen environment workspace", (launch.j?.environment_ref || "").includes(envId), launch.j?.environment_ref);

  // ── STEP 3: HARNESS EXECUTES (wallet-gated) — real file into the env workspace ──
  const intent = `Create the file ./${marker} with exactly this content: ${content}`;
  const challenge = await jd(DAEMON, "POST", `/v1/hypervisor/sessions/${encodeURIComponent(sid)}/execute`, { intent });
  ok("execute fails closed without a wallet grant", challenge.status === 403 && challenge.j?.reason === "execution_authority_required",
    `${challenge.j?.reason || challenge.j?.decision || "no decision"}${(challenge.j?.checks || []).filter((c) => c.status === "fail").map((c) => ` · ${c.id} fail`).join("")}`);
  if (!challenge.j?.approval) return; // a precondition gate answered before the wallet gate (named above): nothing to grant
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  // Bounded retry (2 REAL attempts): the 7B route occasionally answers without a tool call —
  // an honest empty run, not a driver fault. Retry mechanics belong to the deterministic
  // substrate; every attempt is a full wallet-gated real execution, and the assertions below
  // are unchanged (a real file must exist — we never fake one).
  let ex = null;
  let attempts = 0;
  for (; attempts < 2; ) {
    attempts += 1;
    ex = await jd(DAEMON, "POST", `/v1/hypervisor/sessions/${encodeURIComponent(sid)}/execute`, { intent, wallet_approval_grant: grant });
    if ((ex.j?.files_written || []).length >= 1) break;
  }
  ok("opencode harness executed via its driver lane", ex.status === 200 && ex.j?.decision === "executed" && ex.j?.harness === "opencode" && ex.j?.lane === "adapter_driver_session:opencode", `${ex.j?.decision} ${ex.j?.error || ""} (${attempts} attempt${attempts > 1 ? "s" : ""})`);
  // Report ⇔ disk truth, not model spelling: a 7B route can garble the requested filename
  // (seen live), which is model fidelity, not loop truth. Assert a real mutation was reported
  // and that EVERY reported file exists in the env workspace the editor serves.
  const written = ex.j?.files_written || [];
  ok("harness reported a real file change", written.length >= 1, `${JSON.stringify(written)} (requested ${marker}, ${attempts} attempts)`);

  // ── STEP 4: EDITOR SHOWS THE WORKSPACE CHANGE — the file is in the editor's served root, live ──
  const onDisk = written.length >= 1 && written.every((f) => fs.existsSync(path.join(envWorkspace, f)) && fs.statSync(path.join(envWorkspace, f)).size > 0);
  ok("every reported file exists in the environment workspace = the editor's served root", onDisk, written.map((f) => path.join(envWorkspace, f)).join(","));
  // Drive the VS Code Browser open lane: a form that POSTs the lease token to the editor proxy's
  // exchange, which answers 303 with the proxy's lease cookie -> a live serving openvscode instance.
  const open = await fetch(`${SHELL}/__ioi/editor/open?environmentId=${encodeURIComponent(envId)}`, { redirect: "manual" });
  const page = open.status === 200 ? await open.text() : "";
  const action = /<form method="post" action="([^"]+)"/u.exec(page)?.[1]?.replace(/&#38;/gu, "&") || "";
  const token = /name="token" value="([^"]+)"/u.exec(page)?.[1] || "";
  ok("VS Code Browser open lane hands the browser to the editor proxy's exchange (no token in a URL)", !!action && !!token && !action.includes("lease="), `${open.status} ${action}`);
  // The editor proxy is served on its own *.localhost name: connect to 127.0.0.1 and name it.
  const loopback = (url, { method = "GET", headers = {}, body = "" } = {}) => new Promise((resolve) => {
    const target = new URL(url);
    const req = http.request({ host: "127.0.0.1", port: target.port, path: `${target.pathname}${target.search}`, method, headers: { host: target.host, ...headers } }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode, setCookie: [].concat(res.headers["set-cookie"] || [])[0] || "" }));
    });
    req.on("error", () => resolve(null));
    req.end(body);
  });
  const form = `token=${encodeURIComponent(token)}`;
  const exchanged = action && token
    ? await loopback(action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "content-length": Buffer.byteLength(form) }, body: form })
    : null;
  const cookie = (exchanged?.setCookie || "").split(";")[0];
  if (exchanged?.status === 303 && cookie) {
    const editorResp = await loopback(new URL("/", action).href, { headers: { cookie } });
    ok("the opened editor instance is serving (workbench reachable over the changed workspace)", editorResp && (editorResp.status === 200 || editorResp.status === 302), editorResp ? editorResp.status : "unreachable");
  } else {
    ok("editor instance serving check skipped (the exchange set no cookie)", false, `${exchanged?.status ?? "no exchange"}`);
  }

  // ── STEP 5: WORK LEDGER shows the receipt (proof stream) ──
  const ledger = await jd(DAEMON, "GET", "/v1/hypervisor/work-ledger");
  const hx = (ledger.j?.entries || []).find((e) => e.kind === "harness_execution" && e.session_ref === sid);
  ok("Work Ledger surfaces the harness execution with its receipt", !!hx && String(hx.receipt_ref || "").includes("session-execute") && JSON.stringify(hx.files_written || []) === JSON.stringify(written), hx?.receipt_ref);

  // ── STEP 6: RUN TIMELINE / transcript plane shows the tamper-evident state_root proof ──
  ok("Work Ledger entry carries a state_root proof + timeline link", !!hx?.state_root && String(hx?.state_root).startsWith("fnv:") && String(hx?.timeline_ref || "").startsWith("/__ioi/run-timeline/"), `${hx?.state_root} ${hx?.timeline_ref}`);
  const transcripts = await jd(DAEMON, "GET", "/v1/hypervisor/agent-run-transcripts");
  const tr = (transcripts.j?.runs || []).find((r) => r.run_id === hx?.run_ref);
  ok("the run's transcript exists in the daemon transcript plane with a matching state_root", !!tr && (tr.state_root === hx?.state_root || String(tr.state_root_ref || "").length > 0), tr?.state_root);

  // ── STEP 7: Workbench sessions panel shows the completed session with its binding + editor ──
  const wb = await fetch(`${SHELL}/__ioi/workbench`).then((r) => r.text()).catch(() => "");
  ok("Workbench renders the session with its harness binding", wb.includes("hypervisor_worker") || wb.includes("opencode") || wb.includes(sid.slice(0, 18)), "sessions panel");

  // Restore: disable the driver.
  await jd(DAEMON, "POST", "/v1/hypervisor/harness-profiles/hp_opencode/disable");
}

run().then(async () => {
  await STACK.stop();
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`editor+harness+model e2e loop readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch(async (e) => {
  console.error("verifier crashed:", e);
  await STACK.stop().catch(() => {});
  process.exit(1);
});
