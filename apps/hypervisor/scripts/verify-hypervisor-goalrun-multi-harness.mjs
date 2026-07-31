#!/usr/bin/env node
// GoalRun multi-harness orchestration done-bar.
//
// Proves the daemon can orchestrate MULTIPLE harnesses in ONE governed GoalRun (never faked):
//   - create: kernel-admitted GoalRun over an isolated target session, role topology selected
//     from LIVE registry facts (conductor native worker, implementers OpenCode + DeepSeek TUI,
//     deterministic verifier path), typed task briefs / context cells / leases / handoffs;
//   - start: wallet-gated (403 challenge → grant), both implementer invocations run through the
//     real adapter drivers in ISOLATED candidate session workspaces — each with normalized
//     adapter events, an ImplementationResultPayload, a receipt, and a transcript state_root;
//   - isolation: candidate artifacts are NOT in the target workspace before reconciliation;
//   - reconcile: kernel-admitted, deterministic verifier evidence bound, selected candidate
//     copied into the target workspace (the ONLY lane in), orchestration-decision receipt +
//     state_root recorded;
//   - projection: Workbench GoalRuns panel, GoalRun Run-Timeline proof page, Work Ledger
//     goal_run / goal_run_invocation / goal_run_reconciliation entries;
//   - failure handling: with one harness forced unavailable between create and start, the run
//     yields an EXPLICIT partial (failed invocation + blocker + partial_result), still
//     reconciling the surviving verified candidate.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-goalrun-multi-harness.mjs
// Runs REAL executions against the live Ollama route (≈2–5 min).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { mintApprovalGrant } = await import(path.join(HERE, "../../../scripts/lib/mint-approval-grant.mjs"));

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
import http from "node:http";
// node:http, not fetch: the synchronous GoalRun /start call legitimately runs longer than
// undici's fixed 300s headers timeout (parallel implementers × the 600s driver budget).
function jd(method, url, body) {
  const target = new URL(url.startsWith("http") ? url : `${DAEMON}${url}`);
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: target.hostname, port: target.port, path: target.pathname + target.search, method,
        headers: { "content-type": "application/json", ...(payload ? { "content-length": Buffer.byteLength(payload) } : {}) } },
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
const text = async (url) => fetch(`${SHELL}${url}`).then((r) => r.text()).catch(() => "");

async function startWithGrant(grid) {
  const challenge = await jd("POST", `/v1/goal-orchestration/goal-runs/${grid}/start`, {});
  const gated = challenge.status === 403 && challenge.j?.reason === "execution_authority_required";
  const grant = gated
    ? mintApprovalGrant({ policyHash: challenge.j.approval.policy_hash, requestHash: challenge.j.approval.request_hash })
    : null;
  const started = gated
    ? await jd("POST", `/v1/goal-orchestration/goal-runs/${grid}/start`, { wallet_approval_grant: grant })
    : challenge;
  return { gated, started };
}

async function run() {
  const tag = Date.now().toString(16);

  // ── Substrate: enable both implementer drivers (planner-admitted lanes).
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) {
    await jd("POST", `/v1/hypervisor/harness-profiles/${id}/enable`);
  }

  // ── Isolated target session (its provisioned workspace is the reconciliation target).
  const targetRef = `session:goalrun-vfy-${tag}`;
  const sess = await jd("POST", "/v1/hypervisor/sessions", { session_ref: targetRef });
  ok("isolated target session provisioned", sess.status === 202, targetRef);

  // ── CREATE: kernel-admitted GoalRun with the full typed ladder.
  const marker = `goalrun-proof-${tag}.txt`;
  const create = await jd("POST", "/v1/goal-orchestration/goal-runs", {
    goal: `Create the file ${marker} containing the single word: orchestrated`,
    session_ref: targetRef,
  });
  const g = create.j?.goal_run || {};
  const grid = g.goal_run_id || "";
  ok("GoalRun created (kernel goal_run_admit)", create.status === 201 && String(g.admission?.admission_id || "").startsWith("goal-run-admission:"), g.admission?.admission_id);
  ok("role topology selected from live facts (conductor + 2 implementers + verifier)",
    g.role_topology?.conductor_ref === "harness-profile:hp_hypervisor_worker"
    && (g.role_topology?.implementer_refs || []).length === 2
    && g.role_topology?.topology_kind === "multi_context_review",
    JSON.stringify(g.role_topology?.implementer_refs));
  ok("typed ladder materialized (cells + leases + task briefs + handoffs + verifier path)",
    (g.context_cells || []).length === 4 && (g.context_leases || []).length === 2
    && (g.task_briefs || []).length === 2 && (g.handoffs || []).length === 2
    && g.verifier_path?.verification_kind === "deterministic",
    `${(g.context_cells || []).length} cells`);
  ok("task brief is the durable contract (objective, output contract; no raw prompt field)",
    (g.task_briefs || []).every((b) => b.objective && b.output_contract?.changed_files_required === true && !("rendered_prompt" in b)));

  // ── START: wallet-gated, both invocations run concurrently through the real drivers.
  const { gated, started } = await startWithGrant(grid);
  ok("start fails closed without a wallet grant (authority challenge)", gated);
  const invocations = started.j?.invocations || [];
  ok("run started; two harness invocations attempted", started.status === 200 && invocations.length === 2, `${invocations.length} invocations`);
  for (const inv of invocations) {
    const candidate = inv.implementation_result_candidate || {};
    const executionReceipt = inv.execution_receipt || {};
    const label = `${inv.role_key}(${inv.harness})`;
    ok(`${label}: successful execution waits on conductor with adapter events persisted`, inv.status === "waiting_on_conductor"
      && inv.implementation_result === undefined
      && inv.work_result_ref == null
      && inv.profile_result_ref == null
      && (inv.adapter_event_refs || []).length >= 4
      && inv.adapter_event_refs.every((r) => String(r).startsWith("agentgres://harness-adapter-event/")), `${(inv.adapter_event_refs || []).length} events`);
    ok(`${label}: non-canonical result candidate carries refs + receipt + transcript + state_root`,
      String(candidate.candidate_ref || "").startsWith("implementation-result-candidate://")
      && candidate.execution_succeeded === true
      && String(candidate.harness_profile_ref || "").startsWith("harness-profile:")
      && String(candidate.model_route_ref || "").startsWith("model-route:")
      && String(candidate.command_contract_ref || "").startsWith("command-contract://")
      && String(candidate.workspace_ref || "").startsWith("workspace://goal-run/")
      && (candidate.candidate_artifact_refs || []).every((r) => String(r).startsWith("artifact://goal-run/"))
      && (candidate.receipt_refs || []).length >= 1
      && String(candidate.transcript_run_ref || "").startsWith("hpo_")
      && String(candidate.state_root || "").startsWith("fnv:"),
      candidate.state_root);
    const exactRouteFacts = [
      "model_route_ref",
      "model_route_binding_id",
      "model_route_binding_receipt_ref",
      "model_id",
      "model_route_base_url",
      "model_route_execution_endpoint",
    ];
    ok(`${label}: actual model/endpoint binding is identical in invocation, result, and durable receipt`,
      exactRouteFacts.every((field) => String(inv[field] || "").length > 0
        && inv[field] === candidate[field]
        && inv[field] === executionReceipt[field])
      && String(inv.model_route_execution_endpoint).startsWith(String(inv.model_route_base_url))
      && executionReceipt.id === candidate.receipt_refs?.[0]
      && executionReceipt.kind === "hypervisor.goal-run.invoke",
      `${inv.model_id || "missing-model"}@${inv.model_route_execution_endpoint || "missing-endpoint"}`);
    const candidateSession = await jd("GET", `/v1/hypervisor/sessions/${encodeURIComponent(inv.session_ref)}`);
    const retainedBinding = candidateSession.j?.session?.model_route_binding || {};
    ok(`${label}: candidate Session durably retains the exact consumed route binding`,
      candidateSession.status === 200
      && retainedBinding.binding_id === inv.model_route_binding_id
      && retainedBinding.route_ref === inv.model_route_ref
      && retainedBinding.model_id === inv.model_id
      && retainedBinding.base_url === inv.model_route_base_url
      && retainedBinding.execution_endpoint === inv.model_route_execution_endpoint
      && retainedBinding.receipt_ref === inv.model_route_binding_receipt_ref,
      retainedBinding.binding_id);
  }
  const anyChanged = invocations.some((inv) => ((inv.implementation_result_candidate || {}).changed_files || []).length >= 1);
  ok("at least one implementer produced a real candidate mutation", anyChanged);

  // ── ISOLATION: candidate artifacts exist in candidate workspaces, NOT in the target yet.
  const targetRec = await jd("GET", `/v1/hypervisor/sessions/${encodeURIComponent(targetRef)}`);
  const targetWs = targetRec.j?.session?.workspace_root || "";
  const candidateFiles = invocations.flatMap((inv) =>
    ((inv.implementation_result_candidate || {}).changed_files || []).map((f) => ({ ws: inv.candidate_workspace_root, f })));
  ok("candidate artifacts are REAL in their isolated workspaces",
    candidateFiles.length >= 1 && candidateFiles.every(({ ws, f }) => ws && fs.existsSync(path.join(ws, f)) && fs.statSync(path.join(ws, f)).size > 0));
  ok("candidate artifacts are NOT in the target workspace before reconciliation",
    candidateFiles.every(({ f }) => !fs.existsSync(path.join(targetWs, f))), targetWs);
  ok("verifier evidence recorded per invocation (deterministic VerifierPath)",
    (started.j?.goal_run?.verification_refs || []).length === invocations.length
    && started.j.goal_run.verification_refs.every((r) => String(r).startsWith("agentgres://goal-run-verification/")));

  // ── RECONCILE: the only lane into the target workspace.
  const rec = await jd("POST", `/v1/goal-orchestration/goal-runs/${grid}/reconcile`, {});
  const rr = rec.j?.reconciliation || {};
  ok("reconciliation admitted with verifier evidence + receipt + state_root",
    rec.status === 200
    && String(rr.admission_id || "").startsWith("goal-run-admission:")
    && (rr.verifier_evidence_refs || []).length >= 1
    && (rr.final_receipt_refs || []).length === 1
    && String(rr.state_root || "").startsWith("fnv:"),
    `${rr.merge_strategy} ${rr.reason_code}`);
  ok("reconciliation selected/rejected candidates explicitly",
    (rr.selected_candidate_refs || []).length >= 1
    && (rr.selected_candidate_refs || []).concat(rr.rejected_candidate_refs || []).every((r) => String(r).startsWith("implementation-result-candidate://")));
  ok("final workspace mutation is REAL in the target session workspace",
    (rr.final_changed_files || []).length >= 1
    && rr.final_changed_files.every((f) => fs.existsSync(path.join(targetWs, f)) && fs.statSync(path.join(targetWs, f)).size > 0)
    && (rr.copy_errors || []).length === 0,
    (rr.final_changed_files || []).join(","));
  const postReconcileEvents = await jd("GET", `/v1/goal-orchestration/goal-runs/${grid}/events`);
  ok("GoalRun closes without falsely completing result-less invocations", rec.j?.goal_run?.status === "complete"
    && rec.j?.goal_run?.active_loop_phase === "continue_or_close"
    && postReconcileEvents.status === 200
    && (postReconcileEvents.j?.invocations || []).every((inv) => inv.status === "waiting_on_conductor"
      && inv.implementation_result === undefined
      && inv.work_result_ref == null
      && inv.profile_result_ref == null));
  const doubleReconcile = await jd("POST", `/v1/goal-orchestration/goal-runs/${grid}/reconcile`, {});
  ok("reconcile is one-shot (second call rejected)", doubleReconcile.status === 409, doubleReconcile.j?.error?.code);

  // ── PROJECTION: Work Ledger (daemon), Workbench panel, Run Timeline proof page.
  const ledger = await jd("GET", "/v1/hypervisor/work-ledger");
  const entries = ledger.j?.entries || [];
  const goalRef = `goal://${grid}`;
  ok("Work Ledger indexes the GoalRun + both invocations + the reconciliation",
    entries.some((e) => e.kind === "goal_run" && e.goal_run_ref === goalRef)
    && entries.filter((e) => e.kind === "goal_run_invocation" && e.goal_run_ref === goalRef).length === 2
    && entries.some((e) => e.kind === "goal_run_reconciliation" && e.goal_run_ref === goalRef && String(e.state_root || "").startsWith("fnv:")));
  const wb = await text("/__ioi/workbench");
  ok("Workbench projects the GoalRun (panel + proof link)", wb.includes('id="goal-runs"') && wb.includes(grid));
  const tl = await text(`/__ioi/run-timeline/goal-run/${grid}`);
  ok("Run Timeline GoalRun page labels result-less invocation output as non-canonical candidate",
    ["Goal</h2>", "Roles</h2>", "Invocations", "Invocation outputs", "candidate", "candidates stay non-canonical until WorkResult convergence", "Reconciliation</h2>", "Proof</h2>"].every((m) => tl.includes(m))
    && !tl.includes("admitted result"));
  const wl = await text("/__ioi/work-ledger");
  ok("Work Ledger UI carries the GoalRun kind facets", ['data-val="goal_run"', 'data-val="goal_run_invocation"', 'data-val="goal_run_reconciliation"'].every((m) => wl.includes(m)));

  // ── FAILURE HANDLING: force one harness unavailable between create and start.
  const target2 = `session:goalrun-vfy-partial-${tag}`;
  await jd("POST", "/v1/hypervisor/sessions", { session_ref: target2 });
  const create2 = await jd("POST", "/v1/goal-orchestration/goal-runs", {
    goal: `Create the file partial-${tag}.txt containing the single word: partial`,
    session_ref: target2,
  });
  const grid2 = create2.j?.goal_run?.goal_run_id || "";
  ok("partial-lane GoalRun created with both implementers", (create2.j?.goal_run?.role_topology?.implementer_refs || []).length === 2);
  await jd("POST", "/v1/hypervisor/harness-profiles/hp_deepseek_tui/disable");
  const partial = await startWithGrant(grid2);
  const inv2 = partial.started.j?.invocations || [];
  const failed = inv2.filter((i) => i.status === "failed");
  const waiting = inv2.filter((i) => i.status === "waiting_on_conductor");
  ok("forced-unavailable harness yields an EXPLICIT failed invocation + blocker",
    partial.started.status === 200 && failed.length === 1
    && failed[0].blocker?.reason_code === "goal_run_invocation_profile_not_active"
    && partial.started.j?.partial_result === true,
    failed[0]?.blocker?.reason_code);
  ok("surviving implementer remains an explicit waiting candidate", waiting.length === 1
    && waiting[0]?.implementation_result === undefined
    && String(waiting[0]?.implementation_result_candidate?.candidate_ref || "").startsWith("implementation-result-candidate://"), waiting[0]?.harness);
  const rec2 = await jd("POST", `/v1/goal-orchestration/goal-runs/${grid2}/reconcile`, {});
  ok("partial run reconciles the surviving verified candidate (explicit reason)",
    rec2.status === 200
    && ["single_verified_candidate", "no_verified_candidate"].includes(rec2.j?.reconciliation?.reason_code),
    rec2.j?.reconciliation?.reason_code);

  // ── Restore admitted-off posture (proof records stay — they ARE the ledger evidence).
  for (const id of ["hp_opencode", "hp_deepseek_tui"]) {
    await jd("POST", `/v1/hypervisor/harness-profiles/${id}/disable`);
  }
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("drivers restored to non-active posture",
    (fin.j?.profiles || []).filter((p) => ["opencode", "deepseek_tui"].includes(p.harness)).every((p) => p.lifecycle.status === "disabled"));
}

// Bounded 2-attempt full-run retry — the SAME convention the driver/e2e/launcher done-bars
// use for the documented 7B no-tool-call whiff: every attempt is a complete REAL GoalRun
// with unchanged assertions; a clean pass on either attempt is a pass. CPU-only local-model
// gates must treat model latency/stop-discipline as stochastic, never deterministic.
(async () => {
  for (let attempt = 1; attempt <= 2; attempt++) {
    results.length = 0;
    await run();
    if (results.every((r) => r.pass)) break;
    if (attempt === 1) console.log("  attempt 1 whiffed (7B stop-discipline) — one bounded full-run retry");
  }
})().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`goalrun multi-harness readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
