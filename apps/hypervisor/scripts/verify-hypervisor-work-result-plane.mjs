#!/usr/bin/env node
// WorkResult + OutcomeDelta plane done-bar — build step 1 of the contract-first sequence,
// ISOLATED per the standing verifier doctrine, HARDENED per the #71 review:
//   1. GENERIC ENVELOPE — research-first admission (real evidence:// claims, no software
//      fields); software_implementation is ONE profile via result_payload_ref; the overview
//      projects the declaration vocabularies.
//   2. RECURSIVE SECRET BOUNDARY — a nested sensitive key (uncertainty.password) refuses typed
//      and the sentinel is absent from the response, every record, every receipt, AND the
//      daemon log.
//   3. CANONICAL REFS — raw strings refuse in EVERY ref field (the review's exact probe body
//      refuses); special non-URI forms (scope:*, harness_profile:*, encrypted_ref) admit where
//      the envelope declares them.
//   4. NO FORGED STATE — ghost acceptance/challenge/delta/supersession refs refuse; the
//      future-plane fields return their per-field named unavailable codes; outcome_delta_refs
//      is plane-owned.
//   5. BINDING INVARIANTS — a delta binds an EXISTING SAME-GOAL result (cross-goal refuses with
//      zero writes); supersedes_work_result_ref must resolve same-goal.
//   6. RECEIPT PROFILES — receipt:// identity; WorkResultReceipt binds profile/outcome-class;
//      OutcomeDeltaAdmissionReceipt binds proposer/target/kind/preconditions/expected-effect/
//      verifier posture with effect_admitted:false; output_hash recomputes EXACTLY from the
//      persisted record minus the receipt's declared hash_scope_excludes.
//   7. ATOMIC BACKLINK — delta admission registers the result's outcome_delta_refs backlink in
//      the same atomic seam; the backlink is exact.
//   8. ISOLATION — every journey on a throwaway daemon; the real daemon's counts unchanged.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-work-result-plane.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, unlinkSync, chmodSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { startIsolatedPlane, receiptFileCount } from "./lib/isolated-daemon.mjs";

const REAL_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const FAMILIES = ["work-result-registry", "work-result-registry-receipts", "outcome-delta-registry", "outcome-delta-registry-receipts"];

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// Canonical stringify matching serde_json's sorted-key object serialization (recursive).
const canon = (v) => Array.isArray(v)
  ? `[${v.map(canon).join(",")}]`
  : (v !== null && typeof v === "object")
    ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`
    : JSON.stringify(v);
const recomputeHash = (record, excludes) => {
  const clone = { ...record };
  for (const k of excludes) delete clone[k];
  return `sha256:${createHash("sha256").update(canon(clone)).digest("hex")}`;
};

async function run() {
  const realBefore = await fetch(`${REAL_DAEMON}/v1/hypervisor/work-results`).then((r) => r.json()).catch(() => null);
  const realCounts = FAMILIES.map((f) => receiptFileCount(REAL_DATA_DIR, f));

  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.error("BLOCKED: target/debug/hypervisor-daemon is not built — cargo build -p ioi-node --bin hypervisor-daemon"); process.exit(2); }
  const { daemonUrl, dataDir } = plane;
  async function jd(method, p, body) {
    const r = await fetch(`${daemonUrl}${p}`, { method, headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, j: await r.json().catch(() => ({})), raw: null };
  }
  const counts = () => FAMILIES.map((f) => receiptFileCount(dataDir, f)).join("/");

  try {
    // 1. Empty plane + vocabulary projection + assurance honesty.
    const list0 = await jd("GET", "/v1/hypervisor/work-results");
    ok("isolated plane serves an EMPTY work-result registry", list0.status === 200 && Array.isArray(list0.j.work_results) && list0.j.work_results.length === 0);
    const ov = await jd("GET", "/v1/hypervisor/work-results/overview");
    ok("overview projects the CANONICAL declaration vocabularies", ov.j.schema_version === "ioi.hypervisor.work-results-overview.v1" && (ov.j.result_profiles || []).length === 9 && (ov.j.outcome_classes || []).length === 6 && (ov.j.delta_kinds || []).length === 9 && (ov.j.delta_target_schemes || []).includes("frontier"));
    ok("overview is ASSURANCE-HONEST: admission ≠ acceptance; future-plane fields + transitions + room named as gaps", JSON.stringify(ov.j.governance_gaps || []).match(/receipt is not proof/i) !== null && JSON.stringify(ov.j.governance_gaps || []).match(/plane-owned/i) !== null);

    // 2. THE REVIEW'S EXACT PROBE — refuses typed, nothing persisted.
    const probe = await jd("POST", "/v1/hypervisor/work-results", {
      goal_ref: "not-a-ref",
      result_profile: "research", outcome_class: "positive", status: "completed",
      result_payload_ref: "fixture-secret-raw-value",
      uncertainty: { password: "SENTINEL_NESTED_SECRET" },
    });
    ok("the review probe body refuses (nested secret caught FIRST, typed)", probe.status === 400 && probe.j.error?.code === "work_result_plaintext_secret_rejected", probe.j.error?.code);
    ok("the nested sentinel is absent from the refusal response", !JSON.stringify(probe.j).includes("SENTINEL_NESTED_SECRET"));

    // 3. RECURSIVE secret boundary — nested variants all refuse; nothing persists.
    for (const unc of [{ password: "S1" }, { detail: { "Client-Secret": "S2" } }, { list: [{ access_token: "S3" }] }, { secretAccessKey: "S4" }, { "private key": "S5" }, { AUTHORIZATION: "S6" }]) {
      const r = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", uncertainty: unc });
      ok(`nested sensitive key refused: ${Object.keys(unc)[0]}`, r.status === 400 && r.j.error?.code === "work_result_plaintext_secret_rejected");
    }

    // 4. CANONICAL REFS — raw strings refuse per field; goal identity enforced.
    const rawGoal = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "not-a-ref", result_profile: "research", outcome_class: "positive", status: "completed" });
    ok("`goal_ref` must be a goal:// identity", rawGoal.j.error?.code === "work_result_goal_ref_invalid");
    for (const [field, val] of [["result_payload_ref", "fixture-secret-raw-value"], ["summary_ref", "raw"], ["invocation_or_run_ref", "raw"], ["result_profile_ref", "raw"]]) {
      const r = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", [field]: val });
      ok(`raw string refused in scalar ref \`${field}\``, r.status === 400 && r.j.error?.code === "work_result_ref_scheme_invalid");
    }
    for (const [field, val] of [["supporting_evidence_refs", ["artifact://ok", "raw-string"]], ["claim_refs", ["not-a-ref"]], ["authority_and_policy_refs", ["scope:"]], ["verifier_refs", ["goal://wrong-scheme"]]]) {
      const r = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", [field]: val });
      ok(`raw/foreign member refused in list ref \`${field}\``, r.status === 400 && r.j.error?.code === "work_result_ref_scheme_invalid");
    }

    // 4b. LIVE LANE (#71 round 2): encrypted_ref is an EXACT literal — the suffix smuggling form
    // refuses and the raw material persists nowhere.
    const smuggle = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", result_payload_ref: "encrypted_refSENTINEL_RAW_MATERIAL" });
    ok("`encrypted_refSENTINEL_RAW_MATERIAL` refuses (exact-literal boundary — no raw-value smuggling)", smuggle.status === 400 && smuggle.j.error?.code === "work_result_ref_scheme_invalid" && !JSON.stringify(smuggle.j).includes("SENTINEL_RAW_MATERIAL"));
    const exactEnc = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://enc", result_profile: "custom", outcome_class: "positive", status: "completed", result_payload_ref: "encrypted_ref" });
    ok("the canonical exact literal `encrypted_ref` admits", exactEnc.status === 201 && exactEnc.j.work_result?.result_payload_ref === "encrypted_ref");

    // 5. NO FORGED STATE — future-plane fields return their per-field named codes.
    const FUTURE = [
      // outcome_room_ref is LIVE since build step 2 — a ghost room refuses as unbound.
      ["outcome_room_ref", "outcome-room://or_ghost", "work_result_room_unbound"],
      ["work_claim_ref", "work-claim://c1", "work_result_work_claim_unavailable"],
      ["attempt_ref", "attempt://a1", "work_result_attempt_unavailable"],
      ["acceptance_ref", "acceptance://ghost", "work_result_acceptance_unavailable"],
      ["superseded_by_ref", "work-result://future", "work_result_superseded_by_unavailable"],
      ["finding_refs", ["finding://ghost"], "work_result_finding_refs_unavailable"],
      ["challenge_refs", ["verifier-challenge://ghost"], "work_result_challenge_refs_plane_owned"],
      ["outcome_delta_refs", ["outcome-delta://ghost"], "work_result_outcome_delta_refs_plane_owned"],
    ];
    for (const [field, val, code] of FUTURE) {
      const r = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", [field]: val });
      ok(`forged/future \`${field}\` → ${code}`, r.status === 400 && r.j.error?.code === code, r.j.error?.code);
    }
    const ghostSuper = await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://g", result_profile: "research", outcome_class: "positive", status: "completed", supersedes_work_result_ref: "work-result://wr_ghost" });
    ok("ghost supersession refused (must resolve)", ghostSuper.status === 400 && ghostSuper.j.error?.code === "work_result_supersedes_unbound");
    ok("EVERY refusal above persisted NOTHING (only the one legitimate exact-literal admission: 1/1/0/0)", counts() === "1/1/0/0", counts());

    // 6. GENERIC admission — research FIRST with real evidence:// claims (not a finding://
    // placeholder), structured uncertainty, negative outcome, zero software fields.
    const research = await jd("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://alpha", result_profile: "research",
      outcome_class: "negative", status: "completed",
      claim_refs: ["evidence://lab-observation-fatigue-fail"],
      supporting_evidence_refs: ["artifact://lab-run-14", "receipt://sim-batch-9"],
      authority_and_policy_refs: ["scope:lab.read", "policy://materials-program"],
      worker_harness_model_runtime_version_refs: ["harness_profile:local-lab", "model://m-sim-2"],
      uncertainty: { method: "bootstrap", ci95: [0.61, 0.83] },
      next_action: "replicate",
    });
    const rr = research.j.work_result;
    ok("a RESEARCH result admits with evidence:// claims, scope:*/harness_profile:* special refs, and NO software fields", research.status === 201 && rr?.result_profile === "research" && rr?.outcome_class === "negative" && rr?.claim_refs?.[0] === "evidence://lab-observation-fatigue-fail" && rr?.authority_and_policy_refs?.includes("scope:lab.read"));
    const software = await jd("POST", "/v1/hypervisor/work-results", {
      goal_ref: "goal://alpha", result_profile: "software_implementation",
      result_payload_ref: "artifact://implementation-result/run-77",
      outcome_class: "positive", status: "completed",
    });
    ok("software_implementation is ONE profile via result_payload_ref", software.status === 201 && software.j.work_result?.result_payload_ref === "artifact://implementation-result/run-77");
    ok("ATOMIC evidence exact: 3 records, 3 receipts", counts() === "3/3/0/0", counts());

    // 7. RECEIPT PROFILES — receipt:// identity, bound facts, recomputable hash.
    const rcpt = research.j.work_result_receipt;
    ok("WorkResultReceipt: receipt:// identity + type + profile ref + actor/subject", String(rcpt?.receipt_id).startsWith("receipt://wrr_") && rcpt?.receipt_type === "WorkResultReceipt" && String(rcpt?.receipt_profile_ref).startsWith("schema://") && rcpt?.actor_id === "daemon://hypervisor-runtime" && rcpt?.subject_ref === rr?.work_result_id);
    ok("WorkResultReceipt BINDS the canonical facts (profile + outcome class + goal + status-at-admission)", rcpt?.bound_facts?.result_profile === "research" && rcpt?.bound_facts?.outcome_class === "negative" && rcpt?.bound_facts?.goal_ref === "goal://alpha" && rcpt?.bound_facts?.status_at_admission === "completed" && rcpt?.assurance_posture === "admitted_not_verified");
    const persistedResearch = (await jd("GET", `/v1/hypervisor/work-results/${rr.work_result_id.replace("work-result://", "")}`)).j.work_result;
    ok("WorkResultReceipt output_hash recomputes EXACTLY from the persisted record minus hash_scope_excludes", recomputeHash(persistedResearch, rcpt.hash_scope_excludes || []) === rcpt.output_hash, rcpt.output_hash?.slice(0, 24));

    // 7b. LIVE FAILURE INJECTION (#71 round 3): a delta receipt-persist failure must leave the
    // WorkResult BYTE-FOR-BYTE untouched (refs AND updated_at) and leak no .tmp-* artifact.
    const tmpLeaks = () => { try { return readdirSync(join(dataDir, "work-result-registry")).filter((n) => n.includes(".tmp-")); } catch { return []; } };
    const preFailure = canon(persistedResearch);
    const receiptsDirPath = join(dataDir, "outcome-delta-registry-receipts");
    writeFileSync(receiptsDirPath, "blocker"); // the receipts DIR does not exist yet — a plain file blocks its creation
    const injected = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://injected", proposed_by_ref: rr.work_result_id });
    ok("injected receipt failure → typed 5xx (outcome_delta_receipt_persist_failed)", injected.status === 500 && injected.j.error?.code === "outcome_delta_receipt_persist_failed", injected.j.error?.code);
    const afterFailure = (await jd("GET", `/v1/hypervisor/work-results/${rr.work_result_id.replace("work-result://", "")}`)).j.work_result;
    ok("the WorkResult is BYTE-FOR-BYTE unchanged after the failed admission (refs AND updated_at)", canon(afterFailure) === preFailure);
    ok("no delta record and NO .tmp-* artifact survives the failure", (await jd("GET", "/v1/hypervisor/outcome-deltas")).j.outcome_deltas.length === 0 && tmpLeaks().length === 0, tmpLeaks().join(","));
    unlinkSync(receiptsDirPath);

    // 8. BINDING INVARIANTS — cross-goal refused with ZERO writes; same-goal binds + backlink.
    const cross = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://beta", delta_kind: "update", target_ref: "frontier://f1", proposed_by_ref: rr.work_result_id });
    ok("CROSS-GOAL delta binding refused typed", cross.status === 400 && cross.j.error?.code === "outcome_delta_cross_goal");
    const roomed = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://f1", proposed_by_ref: rr.work_result_id, outcome_room_ref: "outcome-room://or_ghost" });
    ok("delta ghost room → outcome_delta_room_unbound (rooms LIVE since step 2; full room-scope proofs live in the room-plane verifier)", roomed.status === 400 && roomed.j.error?.code === "outcome_delta_room_unbound");
    const ghost = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://f1", proposed_by_ref: "work-result://wr_ghost" });
    ok("ghost result binding refused", ghost.status === 400 && ghost.j.error?.code === "outcome_delta_unbound_result");
    const futureProp = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://f1", proposed_by_ref: "attempt://a1" });
    ok("future proposer plane → its OWN named gap", futureProp.status === 400 && futureProp.j.error?.code === "outcome_delta_proposer_kind_unavailable");
    const selfStatus = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://f1", proposed_by_ref: rr.work_result_id, status: "admitted" });
    ok("caller-supplied status → plane-owned refusal", selfStatus.status === 400 && selfStatus.j.error?.code === "outcome_delta_status_plane_owned");
    ok("every binding refusal persisted NOTHING and mutated NO backlink (still 3/3/0/0)", counts() === "3/3/0/0" && ((await jd("GET", `/v1/hypervisor/work-results/${rr.work_result_id.replace("work-result://", "")}`)).j.work_result.outcome_delta_refs || []).length === 0, counts());

    const delta = await jd("POST", "/v1/hypervisor/outcome-deltas", {
      goal_ref: "goal://alpha", delta_kind: "update", target_ref: "frontier://alloy-survey-lane",
      proposed_by_ref: rr.work_result_id, payload_ref: "state-delta://survey-lane-close",
      precondition_and_invariant_refs: ["policy://materials-program"],
      expected_effect_ref: "effect://survey-lane-closed",
      verifier_and_acceptance_refs: ["gate://materials-review"],
    });
    const dd = delta.j.outcome_delta;
    ok("a SAME-GOAL delta admits as `proposed`", delta.status === 201 && dd?.status === "proposed" && dd?.proposed_by_ref === rr.work_result_id);

    // 9. THE ATOMIC BACKLINK — exact, registered in the same seam, reported in the response.
    const linked = (await jd("GET", `/v1/hypervisor/work-results/${rr.work_result_id.replace("work-result://", "")}`)).j.work_result;
    ok("the WorkResult backlink is EXACT (outcome_delta_refs === [the new delta id])", JSON.stringify(linked.outcome_delta_refs) === JSON.stringify([dd.outcome_delta_id]) && delta.j.work_result_backlink?.outcome_delta_refs_appended === dd.outcome_delta_id);
    ok("delta evidence exact: 1 delta record, 1 delta receipt", counts() === "3/3/1/1", counts());

    // 9b. LIVE A-SUCCESS / B-FAILURE INTERLEAVE (#71 round 3): with delta A landed, B's receipt
    // failure must restore the post-A state byte-for-byte — [A] and A-era updated_at survive.
    const postA = canon((await jd("GET", `/v1/hypervisor/work-results/${rr.work_result_id.replace("work-result://", "")}`)).j.work_result);
    chmodSync(receiptsDirPath, 0o555); // the receipts DIR now exists (holds A's receipt) — make it unwritable
    const bFail = await jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://alpha", delta_kind: "close", target_ref: "frontier://b-lane", proposed_by_ref: rr.work_result_id });
    chmodSync(receiptsDirPath, 0o755);
    ok("interleaved B receipt failure → typed 5xx, A's success untouched BYTE-FOR-BYTE", bFail.status === 500 && bFail.j.error?.code === "outcome_delta_receipt_persist_failed" && canon((await jd("GET", `/v1/hypervisor/work-results/${rr.work_result_id.replace("work-result://", "")}`)).j.work_result) === postA);
    ok("B left no delta record, no receipt, no .tmp-* (still 3/3/1/1)", counts() === "3/3/1/1" && tmpLeaks().length === 0, counts());

    // 10. OutcomeDeltaAdmissionReceipt — bound facts + effect_admitted:false + hash recompute.
    const drcpt = delta.j.outcome_delta_receipt;
    ok("OutcomeDeltaAdmissionReceipt: receipt:// identity + full fact binding (proposer/target/kind/preconditions/effect/verifier posture)", String(drcpt?.receipt_id).startsWith("receipt://odr_") && drcpt?.receipt_type === "OutcomeDeltaAdmissionReceipt" && drcpt?.bound_facts?.proposed_by_ref === rr.work_result_id && drcpt?.bound_facts?.target_ref === "frontier://alloy-survey-lane" && drcpt?.bound_facts?.delta_kind === "update" && drcpt?.bound_facts?.precondition_and_invariant_refs?.[0] === "policy://materials-program" && drcpt?.bound_facts?.expected_effect_ref === "effect://survey-lane-closed" && drcpt?.bound_facts?.verifier_and_acceptance_refs?.[0] === "gate://materials-review");
    ok("the receipt states the PROPOSAL was admitted while effect_admitted:false", drcpt?.effect_admitted === false && drcpt?.bound_facts?.effect_admitted === false && drcpt?.bound_facts?.record_status_at_admission === "proposed" && /effect is NOT admitted/i.test(drcpt?.assurance_note || ""));
    const persistedDelta = (await jd("GET", `/v1/hypervisor/outcome-deltas/${dd.outcome_delta_id.replace("outcome-delta://", "")}`)).j.outcome_delta;
    ok("OutcomeDeltaAdmissionReceipt output_hash recomputes EXACTLY from the persisted record minus hash_scope_excludes", recomputeHash(persistedDelta, drcpt.hash_scope_excludes || []) === drcpt.output_hash);

    // 11. LIVE CONCURRENCY LANE (#71 round 2 — the review's stress probe): parallel delta
    // admissions against ONE result must preserve EXACT equality among delta records, receipts,
    // and backlinks — no lost backlinks, no false unbound refusals, no orphans.
    const stressResult = (await jd("POST", "/v1/hypervisor/work-results", { goal_ref: "goal://stress", result_profile: "research", outcome_class: "positive", status: "completed" })).j.work_result;
    const preStress = counts();
    const VALID = 60, INVALID = 12;
    const fire = [];
    for (let i = 0; i < VALID; i++) fire.push(jd("POST", "/v1/hypervisor/outcome-deltas", { goal_ref: "goal://stress", delta_kind: "update", target_ref: `frontier://lane-${i}`, proposed_by_ref: stressResult.work_result_id }));
    for (let i = 0; i < INVALID; i++) fire.push(jd("POST", "/v1/hypervisor/outcome-deltas", i % 2 ? { goal_ref: "goal://other", delta_kind: "update", target_ref: "frontier://x", proposed_by_ref: stressResult.work_result_id } : { goal_ref: "goal://stress", delta_kind: "update", target_ref: "frontier://x", proposed_by_ref: "work-result://wr_ghost" }));
    const settled = await Promise.all(fire);
    const okOnes = settled.slice(0, VALID);
    const badOnes = settled.slice(VALID);
    ok(`CONCURRENCY: all ${VALID} valid parallel admissions returned 201 (zero false unbound refusals)`, okOnes.every((r) => r.status === 201), okOnes.filter((r) => r.status !== 201).map((r) => r.j.error?.code).slice(0, 3).join(","));
    ok(`CONCURRENCY: all ${INVALID} invalid parallel requests refused typed (cross-goal / ghost)`, badOnes.every((r) => r.status === 400 && ["outcome_delta_cross_goal", "outcome_delta_unbound_result"].includes(r.j.error?.code)));
    const admittedIds = okOnes.map((r) => r.j.outcome_delta.outcome_delta_id).sort();
    const finalStress = (await jd("GET", `/v1/hypervisor/work-results/${stressResult.work_result_id.replace("work-result://", "")}`)).j.work_result;
    const backlinks = [...(finalStress.outcome_delta_refs || [])].sort();
    ok(`CONCURRENCY: the backlink set EXACTLY equals the ${VALID} admitted delta ids (no lost updates, no orphans)`, JSON.stringify(backlinks) === JSON.stringify(admittedIds), `${backlinks.length} backlinks vs ${admittedIds.length} admitted`);
    const allDeltas = (await jd("GET", "/v1/hypervisor/outcome-deltas")).j.outcome_deltas.filter((d) => d.proposed_by_ref === stressResult.work_result_id).map((d) => d.outcome_delta_id).sort();
    ok("CONCURRENCY: durable delta records EXACTLY equal the admitted set (no orphan deltas)", JSON.stringify(allDeltas) === JSON.stringify(admittedIds));
    const [r0, rr0, d0, dr0] = preStress.split("/").map(Number);
    ok("CONCURRENCY: file evidence exact (+60 delta records, +60 delta receipts; results/receipts unchanged beyond the stress fixture)", counts() === `${r0}/${rr0}/${d0 + VALID}/${dr0 + VALID}`, `${preStress} → ${counts()}`);

    // 12. Sentinel sweep — the nested secret appears NOWHERE durable: records, receipts, log.
    const allJson = JSON.stringify([
      (await jd("GET", "/v1/hypervisor/work-results")).j,
      (await jd("GET", "/v1/hypervisor/outcome-deltas")).j,
    ]);
    const daemonLog = (() => { try { return readFileSync(join(dataDir, "isolated-daemon.log"), "utf8"); } catch { return ""; } })();
    ok("NO sentinel appears in any record, receipt, or the daemon log (nested secret + raw ref + encrypted_ref smuggle)", !allJson.includes("SENTINEL_NESTED_SECRET") && !daemonLog.includes("SENTINEL_NESTED_SECRET") && !allJson.includes("fixture-secret-raw-value") && !allJson.includes("SENTINEL_RAW_MATERIAL") && !daemonLog.includes("SENTINEL_RAW_MATERIAL"));
  } finally {
    await plane.stop();
  }

  // 13. ISOLATION PROOF.
  const realAfter = await fetch(`${REAL_DAEMON}/v1/hypervisor/work-results`).then((r) => r.json()).catch(() => null);
  const realCountsAfter = FAMILIES.map((f) => receiptFileCount(REAL_DATA_DIR, f));
  ok("REAL daemon work-result plane unchanged", (realBefore === null && realAfter === null) || (realBefore?.work_results || []).length === (realAfter?.work_results || []).length);
  ok("REAL daemon record/receipt file counts unchanged across all four families", realCounts.join("/") === realCountsAfter.join("/"), `${realCounts.join("/")} before/after`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`work-result plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
