#!/usr/bin/env node
// WorkResult + OutcomeDelta plane done-bar — build step 1 of the contract-first sequence
// (docs/architecture/_meta/execution-horizons.md), ISOLATED per the standing verifier doctrine:
// every successful and rejected admission journey runs on a throwaway daemon
// (lib/isolated-daemon.mjs) and the REAL daemon's record/receipt counts are asserted UNCHANGED.
//
// Asserts:
//   1. GENERIC ENVELOPE — the plane admits results across ALL canonical result profiles
//      (research first — proving the seam is not software-shaped); software_implementation is
//      ONE profile reached via result_payload_ref; the overview projects the declaration
//      vocabularies (a consuming surface derives pickers from the daemon, never a copy).
//   2. FAIL-CLOSED, TYPED, BOUNDED — unknown vocabulary members, wrong-typed fields, oversized
//      values, and plaintext-secret keys refuse typed; refusals persist NOTHING.
//   3. ATOMIC + RECEIPTED — record-first/receipt-second with exact receipt-file evidence; the
//      receipt is returned explicitly beside the record.
//   4. DELTA-BINDS-RESULT — an OutcomeDelta admits only against an EXISTING WorkResult;
//      unresolvable/missing/foreign-scheme proposers refuse typed; canon-named future proposer
//      planes (attempt/finding/participant-lease) refuse with their own named gap; status and
//      admission_receipt_ref are plane-owned.
//   5. ASSURANCE HONESTY — the overview names that admission is NOT acceptance/verification
//      (the receipt-is-not-proof ladder), and that room/transition authority is build steps 2-3.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-work-result-plane.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { startIsolatedPlane, receiptFileCount } from "./lib/isolated-daemon.mjs";

const REAL_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const RESULT_FAMILY = "work-result-registry";
const RESULT_RECEIPTS = "work-result-registry-receipts";
const DELTA_FAMILY = "outcome-delta-registry";
const DELTA_RECEIPTS = "outcome-delta-registry-receipts";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  const realBefore = await fetch(`${REAL_DAEMON}/v1/hypervisor/work-results`).then((r) => r.json()).catch(() => null);
  const realCounts = [RESULT_FAMILY, RESULT_RECEIPTS, DELTA_FAMILY, DELTA_RECEIPTS].map((f) => receiptFileCount(REAL_DATA_DIR, f));

  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.error("BLOCKED: target/debug/hypervisor-daemon is not built — cargo build -p ioi-node --bin hypervisor-daemon"); process.exit(2); }
  const { daemonUrl, dataDir } = plane;
  async function jd(method, p, body) {
    const r = await fetch(`${daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, j: await r.json().catch(() => ({})) };
  }
  const counts = () => [RESULT_FAMILY, RESULT_RECEIPTS, DELTA_FAMILY, DELTA_RECEIPTS].map((f) => receiptFileCount(dataDir, f)).join("/");

  try {
    // 1. Empty plane + vocabulary projection + assurance honesty.
    const list0 = await jd("GET", "/v1/hypervisor/work-results");
    ok("isolated plane serves an EMPTY work-result registry", list0.status === 200 && Array.isArray(list0.j.work_results) && list0.j.work_results.length === 0);
    const ov = await jd("GET", "/v1/hypervisor/work-results/overview");
    ok("overview projects the CANONICAL declaration vocabularies (profiles/classes/statuses/next-actions/reproduction/delta-kinds/target-schemes)", ov.j.schema_version === "ioi.hypervisor.work-results-overview.v1" && (ov.j.result_profiles || []).length === 9 && ov.j.result_profiles.includes("research") && ov.j.result_profiles.includes("software_implementation") && (ov.j.outcome_classes || []).length === 6 && (ov.j.statuses || []).length === 6 && (ov.j.next_actions || []).includes("update_frontier") && (ov.j.delta_kinds || []).length === 9 && (ov.j.delta_target_schemes || []).includes("frontier"));
    ok("overview is ASSURANCE-HONEST: admission ≠ acceptance (receipt is not proof); transitions + attempt/finding proposers + the room aggregate are named gaps", JSON.stringify(ov.j.governance_gaps || []).match(/receipt is not proof/i) !== null && JSON.stringify(ov.j.governance_gaps || []).match(/build step/i) !== null);

    // 2. Fail-closed sweep — every refusal typed, NOTHING persisted.
    const REFUSALS = [
      [{ result_profile: "research", outcome_class: "positive", status: "completed" }, "work_result_goal_ref_required"],
      [{ goal_ref: "goal://g", result_profile: "prose", outcome_class: "positive", status: "completed" }, "work_result_profile_invalid"],
      [{ goal_ref: "goal://g", result_profile: "research", outcome_class: "great", status: "completed" }, "work_result_outcome_class_invalid"],
      [{ goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "done" }, "work_result_status_invalid"],
      [{ goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", next_action: "panic" }, "work_result_next_action_invalid"],
      [{ goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", finding_refs: "finding://x" }, "work_result_field_type_invalid"],
      [{ goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", goal_run_ref: 7 }, "work_result_field_type_invalid"],
      [{ goal_ref: "g".repeat(301), result_profile: "research", outcome_class: "positive", status: "completed" }, "work_result_field_too_long"],
      [{ goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", password: "hunter2" }, "work_result_plaintext_secret_rejected"],
    ];
    for (const [body, code] of REFUSALS) {
      const r = await jd("POST", "/v1/hypervisor/work-results", body);
      ok(`refusal typed: ${code}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code);
    }
    ok("EVERY refusal persisted NOTHING (0 records, 0 receipts)", counts() === "0/0/0/0", counts());

    // 3. GENERIC admission — research FIRST (the seam is not software-shaped).
    const research = await jd("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://g-materials-survey", result_profile: "research",
      outcome_class: "negative", status: "completed",
      claim_refs: ["finding://candidate-alloy-fails-fatigue"],
      supporting_evidence_refs: ["artifact://lab-run-14", "receipt://sim-batch-9"],
      uncertainty: { method: "bootstrap", ci95: [0.61, 0.83] },
      next_action: "replicate",
    });
    const rr = research.j.work_result;
    ok("a RESEARCH result admits with no software fields (negative outcome is first-class)", research.status === 201 && rr?.schema_version === "ioi.hypervisor.work-result.v1" && rr?.result_profile === "research" && rr?.outcome_class === "negative" && rr?.next_action === "replicate" && rr?.uncertainty?.method === "bootstrap");
    ok("the admission receipt is returned EXPLICITLY beside the record and recorded on it", research.j.work_result_receipt?.schema_version === "ioi.hypervisor.work-result-receipt.v1" && research.j.work_result_receipt?.receipt_ref === rr?.admission_receipt_ref && research.j.work_result_receipt?.subject_ref === rr?.work_result_id);
    const software = await jd("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://g-fix-bug", result_profile: "software_implementation",
      result_payload_ref: "artifact://implementation-result/run-77",
      outcome_class: "positive", status: "completed",
    });
    ok("software_implementation is ONE profile via result_payload_ref (the ImplementationResultPayload seam preserved)", software.status === 201 && software.j.work_result?.result_payload_ref === "artifact://implementation-result/run-77");
    ok("ATOMIC evidence exact: 2 records, 2 receipts", counts() === "2/2/0/0", counts());
    const rid = rr.work_result_id.replace("work-result://", "");
    const got = await jd("GET", `/v1/hypervisor/work-results/${rid}`);
    ok("record reads back by id", got.status === 200 && got.j.work_result?.goal_ref === "goal://g-materials-survey");

    // 4. DELTA-BINDS-RESULT — the invariant, fail-closed in every direction.
    const dBase = { goal_ref: "goal://g-materials-survey", delta_kind: "update", target_ref: "frontier://alloy-survey-lane" };
    const noProp = await jd("POST", "/v1/hypervisor/outcome-deltas", dBase);
    ok("delta without a proposer → outcome_delta_unbound_result", noProp.status === 400 && noProp.j.error?.code === "outcome_delta_unbound_result");
    const ghost = await jd("POST", "/v1/hypervisor/outcome-deltas", { ...dBase, proposed_by_ref: "work-result://wr_ghost" });
    ok("delta bound to a NONEXISTENT result → refused, nothing created", ghost.status === 400 && ghost.j.error?.code === "outcome_delta_unbound_result");
    const futureProp = await jd("POST", "/v1/hypervisor/outcome-deltas", { ...dBase, proposed_by_ref: "attempt://a1" });
    ok("canon-named future proposer plane (attempt://) → its OWN named gap", futureProp.status === 400 && futureProp.j.error?.code === "outcome_delta_proposer_kind_unavailable");
    const badTarget = await jd("POST", "/v1/hypervisor/outcome-deltas", { ...dBase, proposed_by_ref: rr.work_result_id, target_ref: "wat://x" });
    ok("non-canonical target scheme → typed refusal", badTarget.status === 400 && badTarget.j.error?.code === "outcome_delta_target_scheme_invalid");
    const selfStatus = await jd("POST", "/v1/hypervisor/outcome-deltas", { ...dBase, proposed_by_ref: rr.work_result_id, status: "admitted" });
    ok("caller-supplied status → plane-owned refusal (no self-admitted deltas)", selfStatus.status === 400 && selfStatus.j.error?.code === "outcome_delta_status_plane_owned");
    const forged = await jd("POST", "/v1/hypervisor/outcome-deltas", { ...dBase, proposed_by_ref: rr.work_result_id, admission_receipt_ref: "receipt://forged" });
    ok("caller-supplied admission_receipt_ref → plane-owned refusal", forged.status === 400 && forged.j.error?.code === "outcome_delta_receipt_plane_owned");
    ok("every delta refusal persisted NOTHING (still 2/2/0/0)", counts() === "2/2/0/0", counts());

    const delta = await jd("POST", "/v1/hypervisor/outcome-deltas", { ...dBase, proposed_by_ref: rr.work_result_id, payload_ref: "state-delta://survey-lane-close" });
    const dd = delta.j.outcome_delta;
    ok("a delta bound to the ADMITTED result admits as `proposed` with its explicit receipt", delta.status === 201 && dd?.status === "proposed" && dd?.proposed_by_ref === rr.work_result_id && delta.j.outcome_delta_receipt?.receipt_ref === dd?.admission_receipt_ref);
    ok("delta evidence exact: 1 delta record, 1 delta receipt (results untouched)", counts() === "2/2/1/1", counts());
    const dGot = await jd("GET", `/v1/hypervisor/outcome-deltas/${dd.outcome_delta_id.replace("outcome-delta://", "")}`);
    ok("delta reads back by id with the binding intact", dGot.status === 200 && dGot.j.outcome_delta?.proposed_by_ref === rr.work_result_id);
  } finally {
    await plane.stop();
  }

  // 5. ISOLATION PROOF — the real daemon is untouched by every journey above.
  const realAfter = await fetch(`${REAL_DAEMON}/v1/hypervisor/work-results`).then((r) => r.json()).catch(() => null);
  const realCountsAfter = [RESULT_FAMILY, RESULT_RECEIPTS, DELTA_FAMILY, DELTA_RECEIPTS].map((f) => receiptFileCount(REAL_DATA_DIR, f));
  ok("REAL daemon work-result plane unchanged (route may 404 on a pre-plane daemon — trivially unchanged)", (realBefore === null && realAfter === null) || (realBefore?.work_results || []).length === (realAfter?.work_results || []).length);
  ok("REAL daemon record/receipt file counts unchanged across all four families", realCounts.join("/") === realCountsAfter.join("/"), `${realCounts.join("/")} before/after`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`work-result plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
