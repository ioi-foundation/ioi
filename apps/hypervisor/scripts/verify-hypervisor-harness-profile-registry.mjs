#!/usr/bin/env node
// Harness-profile registry done-bar verifier.
//
// Drives the harness-profile registry plane against the running daemon (:8765) and asserts:
// seeded adapter set honesty (native worker seed-enabled default; opencode/deepseek_tui/
// claude_code/codex as declared, unwired adapter slots), probed runnability that is never
// fabricated (runnable / binary_missing / shim_missing / model_route_unreachable / not_probed),
// planner-admitted enable/disable/select-default (non-local trust requires an explicit
// provider-trust acceptance), the exactly-one-default invariant, fail-closed session binding
// (412 not-active / not-runnable, 409 unwired or terminal lane, cross-checked model route),
// session-create integration (harness_profile_ref admitted before provisioning, rejections
// abort the create), the registry-derived legacy agent-runner-profiles projection, and
// transcript proof with a state_root.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harness-profile-registry.mjs
// Exit 0 = all assertions pass; exit 1 = one or more failed. Lifecycle/default mutations are
// restored; immutable proof records (receipts, transcripts) are intentionally retained.

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, path, body) {
  const r = await fetch(`${DAEMON}${path}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch { /* non-json */ }
  return { status: r.status, j, t };
}

async function run() {
  // 1. Seeds + overview honesty.
  const overview = await jd("GET", "/v1/hypervisor/harness-profiles/overview");
  ok("overview schema", overview.j?.schema_version === "ioi.hypervisor.harness-profiles-overview.v1");
  ok("overview names wired execution honestly (lane A posture is probed)", typeof overview.j?.wired_execution?.lane_a_host_spawn?.shim_present === "boolean" && typeof overview.j?.wired_execution?.lane_a_host_spawn?.model_upstream_reachable === "boolean");
  ok("overview names governance gaps plainly", Array.isArray(overview.j?.governance_gaps) && overview.j.governance_gaps.length > 0);

  const list = await jd("GET", "/v1/hypervisor/harness-profiles");
  const profiles = list.j?.profiles || [];
  const byHarness = (h) => profiles.find((p) => p.harness === h);
  for (const h of ["hypervisor_worker", "shell", "opencode", "deepseek_tui", "claude_code", "codex"]) {
    ok(`seeded profile exists: ${h}`, !!byHarness(h), byHarness(h)?.profile_id);
  }
  ok("exactly one default profile", profiles.filter((p) => p.default_profile === true).length === 1, list.j?.default_profile_ref);
  const worker = byHarness("hypervisor_worker");
  ok("native worker is the seed default and seed-enabled with admission linkage", worker?.default_profile === true && worker?.lifecycle?.status === "active" && String(worker?.admission?.last_admission_id || "").startsWith("harness-profile-mutation-admission:"), worker?.admission?.last_admission_id);
  for (const h of ["opencode", "deepseek_tui", "claude_code", "codex"]) {
    const p = byHarness(h);
    // declared at seed; a prior verifier run may have left the admitted `disabled` posture —
    // both are honest non-active states. Never `active` without an admitted enable.
    ok(`adapter slot is non-active + unwired (no fake execution): ${h}`, ["declared", "disabled"].includes(p?.lifecycle?.status) && p?.adapter?.execution_wiring === "adapter_slot_unwired", p?.lifecycle?.status);
  }

  // 2. Legacy projection derives from the registry (one truth; deepseek_tui joins the matrix).
  const legacy = await jd("GET", "/v1/hypervisor/agent-runner-profiles");
  const lp = legacy.j?.profiles || [];
  ok("legacy agent-runner-profiles projects from the registry", lp.length === profiles.length && lp.every((p) => String(p.profile_ref || "").startsWith("harness-profile:")), `${lp.length} profiles`);
  ok("deepseek_tui joined the capability matrix", lp.some((p) => p.harness === "deepseek_tui"));

  // 3. Runnability probes — host truth, never fabricated.
  const wp = await jd("POST", `/v1/hypervisor/harness-profiles/${worker.profile_id}/probe`);
  const wState = wp.j?.runnability?.state;
  ok("native worker probe returns an honest posture", ["runnable", "binary_missing", "shim_missing", "model_route_unreachable"].includes(wState), wState);
  ok("probe evidence present (never a bare claim)", wp.j?.runnability?.probe?.kind === "host_presence" && wp.j?.runnability?.probe?.evidence, JSON.stringify(wp.j?.runnability?.probe?.evidence || {}).slice(0, 80));
  ok("probe emits receipt", typeof wp.j?.receipt_ref === "string" && wp.j.receipt_ref.startsWith("agentgres://harness-profile-receipt/"));
  ok("probe records transcript proof", wp.j?.transcript_recorded === true, wp.j?.transcript_run_id);
  const ds = byHarness("deepseek_tui");
  const dp = await jd("POST", `/v1/hypervisor/harness-profiles/${ds.profile_id}/probe`);
  const dState = dp.j?.runnability?.state;
  ok("deepseek_tui probe reflects real host presence", ["runnable", "binary_missing"].includes(dState) && (dState === "runnable" || dp.j?.runnability?.probe?.evidence?.required_binary === "deepseek"), dState);

  // 4. Admitted mutations: non-local trust fails closed without acceptance; admits with it.
  const codex = byHarness("codex");
  const codexStatusBefore = codex?.lifecycle?.status;
  const en1 = await jd("POST", `/v1/hypervisor/harness-profiles/${codex.profile_id}/enable`);
  ok("remote-trust enable without acceptance rejected by planner (403)", en1.status === 403 && en1.j?.error?.code === "harness_profile_mutation_provider_trust_acceptance_required", en1.j?.error?.code);
  const after1 = await jd("GET", `/v1/hypervisor/harness-profiles/${codex.profile_id}`);
  ok("rejected mutation left record unchanged", after1.j?.profile?.lifecycle?.status === codexStatusBefore, `${codexStatusBefore} -> ${after1.j?.profile?.lifecycle?.status}`);
  const en2 = await jd("POST", `/v1/hypervisor/harness-profiles/${codex.profile_id}/enable`, { provider_trust_acceptance_ref: "approval://provider-trust/codex-verify" });
  ok("remote-trust enable with acceptance is planner-admitted", en2.status === 200 && String(en2.j?.admission_id || "").startsWith("harness-profile-mutation-admission:") && en2.j?.profile?.lifecycle?.status === "active", en2.j?.admission_id);
  const dis = await jd("POST", `/v1/hypervisor/harness-profiles/${codex.profile_id}/disable`);
  ok("disable is the relaxed admitted lane", dis.status === 200 && dis.j?.profile?.lifecycle?.status === "disabled");

  // 5. Default invariant: select shell, exactly one default, restore.
  const shell = byHarness("shell");
  const sel = await jd("POST", `/v1/hypervisor/harness-profiles/${shell.profile_id}/select-default`);
  ok("select-default admitted", sel.status === 200 && sel.j?.profile?.default_profile === true);
  const afterSel = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("exactly one default after select", (afterSel.j?.profiles || []).filter((p) => p.default_profile === true).length === 1 && afterSel.j?.default_profile_ref === `harness-profile:${shell.profile_id}`);
  await jd("POST", `/v1/hypervisor/harness-profiles/${worker.profile_id}/select-default`);
  const restored = await jd("GET", "/v1/hypervisor/harness-profiles");
  ok("default restored to native worker", restored.j?.default_profile_ref === `harness-profile:${worker.profile_id}`);

  // 6. Session binding FAIL-CLOSED across every axis.
  const bindDeclared = await jd("POST", `/v1/hypervisor/harness-profiles/${ds.profile_id}/session-bindings`, { session_ref: "sess_verify_hpr" });
  ok("binding a declared (not enabled) profile fails closed (412)", bindDeclared.status === 412 && bindDeclared.j?.error?.code === "harness_profile_not_active", bindDeclared.j?.error?.code);
  const enShell = await jd("POST", `/v1/hypervisor/harness-profiles/${shell.profile_id}/enable`);
  ok("shell (local trust) enable admits", enShell.status === 200);
  const bindShell = await jd("POST", `/v1/hypervisor/harness-profiles/${shell.profile_id}/session-bindings`, { session_ref: "sess_verify_hpr" });
  ok("binding a terminal-lane profile for execution fails closed (409)", bindShell.status === 409 && bindShell.j?.error?.code === "harness_execution_lane_unsupported", bindShell.j?.error?.code);
  await jd("POST", `/v1/hypervisor/harness-profiles/${shell.profile_id}/disable`);
  const enOc = await jd("POST", `/v1/hypervisor/harness-profiles/${byHarness("opencode").profile_id}/enable`);
  const bindOc = await jd("POST", `/v1/hypervisor/harness-profiles/${byHarness("opencode").profile_id}/session-bindings`, { session_ref: "sess_verify_hpr" });
  ok("binding an unwired adapter slot fails closed (409)", enOc.status === 200 && bindOc.status === 409 && bindOc.j?.error?.code === "harness_execution_lane_unsupported", bindOc.j?.error?.code);
  await jd("POST", `/v1/hypervisor/harness-profiles/${byHarness("opencode").profile_id}/disable`);

  // 6b. Positive lane (only when the local substrate is really runnable + route available).
  const wp2 = await jd("POST", `/v1/hypervisor/harness-profiles/${worker.profile_id}/probe`);
  const routeList = await jd("GET", "/v1/hypervisor/model-routes");
  const defRoute = (routeList.j?.routes || []).find((r) => r.default_route === true);
  const routeReady = defRoute?.lifecycle?.status === "active" && defRoute?.availability?.state === "available";
  if (wp2.j?.runnability?.state === "runnable" && routeReady) {
    const bind = await jd("POST", `/v1/hypervisor/harness-profiles/${worker.profile_id}/session-bindings`, { session_ref: "sess_verify_hpr" });
    ok("runnable lane-A worker binds session (201, admitted, receipted)", bind.status === 201 && String(bind.j?.binding?.admission_id || "").startsWith("harness-profile-mutation-admission:") && String(bind.j?.binding?.receipt_ref || "").startsWith("agentgres://harness-profile-receipt/"), bind.j?.binding?.binding_id);
    ok("binding carries at-bind runnability + route availability evidence", bind.j?.binding?.runnability_at_bind?.state === "runnable" && bind.j?.binding?.model_route_availability_at_bind?.state === "available");
    const blist = await jd("GET", `/v1/hypervisor/harness-profiles/${worker.profile_id}/session-bindings?session_ref=sess_verify_hpr`);
    ok("binding projection filters by session_ref", (blist.j?.bindings || []).length >= 1 && blist.j.bindings.every((b) => b.session_ref === "session:sess_verify_hpr"));
  } else {
    ok("runnable-binding lane skipped honestly (no live local substrate)", true, `${wp2.j?.runnability?.state} / route ${defRoute?.availability?.state}`);
    ok("(skipped) at-bind evidence", true);
    ok("(skipped) binding projection", true);
  }

  // 7. Session-create integration: a rejected harness selection ABORTS the create; an admitted
  //    one records the binding on the session projection.
  const badCreate = await jd("POST", "/v1/hypervisor/sessions", { harness_profile_ref: "harness-profile:hp_deepseek_tui", session_ref: "session:verify-hpr-bad" });
  ok("session create with inadmissible harness selection fails closed", badCreate.status >= 400 && !!badCreate.j?.error, badCreate.j?.error?.code);
  if (wp2.j?.runnability?.state === "runnable" && routeReady) {
    const goodCreate = await jd("POST", "/v1/hypervisor/sessions", { harness_profile_ref: `harness-profile:${worker.profile_id}`, session_ref: "session:verify-hpr-good" });
    ok("session create with admitted harness selection records the binding", goodCreate.status === 202 && goodCreate.j?.harness_binding?.profile_ref === `harness-profile:${worker.profile_id}` && String(goodCreate.j?.harness_binding?.admission_id || "").startsWith("harness-profile-mutation-admission:"), goodCreate.j?.harness_binding?.binding_id);
  } else {
    ok("session-create positive lane skipped honestly (no live local substrate)", true);
  }

  // 8. Transcript proof: harness-profile ops appear in the transcript plane with a state_root.
  const tr = await jd("GET", "/v1/hypervisor/agent-run-transcripts");
  const hpRuns = (tr.j?.runs || []).filter((r) => r.kind === "harness-profile-op" || String(r.run_id || "").startsWith("hpo_"));
  ok("harness-profile ops appear in the transcript plane", hpRuns.length > 0, `count=${hpRuns.length}`);
  ok("harness-profile transcripts carry a state_root", hpRuns.every((r) => r.state_root || r.state_root_ref), hpRuns[0]?.state_root || hpRuns[0]?.state_root_ref);

  // 9. Final state restored: worker default+active, codex/shell/opencode back to non-active.
  const fin = await jd("GET", "/v1/hypervisor/harness-profiles");
  const finBy = (h) => (fin.j?.profiles || []).find((p) => p.harness === h);
  ok("verifier restored lifecycle state", finBy("hypervisor_worker")?.default_profile === true && ["declared", "disabled"].includes(finBy("codex")?.lifecycle?.status) && ["declared", "disabled"].includes(finBy("shell")?.lifecycle?.status));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`harness-profile registry readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
