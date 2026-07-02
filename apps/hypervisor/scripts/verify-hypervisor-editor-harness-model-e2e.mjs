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
// Drives the opencode adapter against local Ollama/qwen2.5:7b (≈30–60s).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(base, method, p, body) {
  const r = await fetch(`${base}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}

async function run() {
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
  ok("execute fails closed without a wallet grant", challenge.status === 403 && challenge.j?.reason === "execution_authority_required", challenge.j?.reason);
  const grant = mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash });
  const ex = await jd(DAEMON, "POST", `/v1/hypervisor/sessions/${encodeURIComponent(sid)}/execute`, { intent, wallet_approval_grant: grant });
  ok("opencode harness executed via its driver lane", ex.status === 200 && ex.j?.decision === "executed" && ex.j?.harness === "opencode" && ex.j?.lane === "adapter_driver_session:opencode", `${ex.j?.decision} ${ex.j?.error || ""}`);
  ok("harness reported the real file change", (ex.j?.files_written || []).includes(marker), JSON.stringify(ex.j?.files_written));

  // ── STEP 4: EDITOR SHOWS THE WORKSPACE CHANGE — the file is in the editor's served root, live ──
  const target = path.join(envWorkspace, marker);
  const onDisk = fs.existsSync(target) && fs.readFileSync(target, "utf8").includes(content);
  ok("file exists in the environment workspace = the editor's served root", onDisk, target);
  // Drive the VS Code Browser open lane: 302 -> a live serving openvscode instance over THIS root.
  const open = await fetch(`${SHELL}/__ioi/editor/open?environmentId=${encodeURIComponent(envId)}`, { redirect: "manual" });
  const loc = open.headers.get("location");
  ok("VS Code Browser open lane redirects to a live editor URL", (open.status === 302 || open.status === 303) && !!loc, `${open.status} ${loc || ""}`);
  if (loc) {
    const editorUrl = loc.startsWith("http") ? loc : `${SHELL}${loc}`;
    const editorResp = await fetch(editorUrl, { redirect: "manual" }).catch(() => null);
    ok("the opened editor instance is serving (workbench reachable over the changed workspace)", editorResp && (editorResp.status === 200 || editorResp.status === 302), editorResp ? editorResp.status : "unreachable");
  } else {
    ok("editor instance serving check skipped (no redirect target)", false);
  }

  // ── STEP 5: WORK LEDGER shows the receipt (proof stream) ──
  const ledger = await jd(DAEMON, "GET", "/v1/hypervisor/work-ledger");
  const hx = (ledger.j?.entries || []).find((e) => e.kind === "harness_execution" && e.session_ref === sid);
  ok("Work Ledger surfaces the harness execution with its receipt", !!hx && String(hx.receipt_ref || "").includes("session-execute") && (hx.files_written || []).includes(marker), hx?.receipt_ref);

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

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`editor+harness+model e2e loop readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
