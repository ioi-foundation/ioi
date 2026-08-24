#!/usr/bin/env node
//
// The approval-habituation campaign (WS4).
//
// The threat here is not a broken bound; it is an operator who has approved the
// same-looking request forty times. This gate holds the two properties that make
// a standing envelope legible under automation:
//
//   1. routine in-envelope activity produces NO authority decision to approve —
//      one envelope record and N activity receipts, never N signatures; and
//   2. the one request that widens is separated from the thirty-nine that do not
//      by a TYPED delta, not by the operator's attention.
//
// It also holds the property that makes the delta trustworthy: every widening
// the engine can name is a code the daemon's own containment check actually
// refuses with. A delta surface that could highlight something enforcement would
// admit — or stay silent about something it would refuse — is worse than none.
//
//   --mutation  prove each finding fails on its own
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const enginePath = join(repo, "apps/hypervisor/scripts/lib/authority-delta.mjs");
const providerRoutes = readFileSync(
  join(repo, "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs"),
  "utf8",
);

const sha = (character) => `sha256:${character.repeat(64)}`;
const PROVIDER = "akash1ggfvyhr9sar4uxjs4hth3p4kzrwk7lysnenj3g";
const IMAGE = sha("3");
const ENVELOPE = {
  standing_envelope_ref: "standing-envelope://acme/u1",
  body_hash: sha("e"),
  facet_template: {
    provider_id: "pacc_18cd245812ad55b9",
    operations: ["create", "delete", "reconcile"],
    provider_selector: { mode: "exact", provider_addresses: [PROVIDER], selection: "only_qualified_bid_from_exact_provider" },
    per_operation_deposit_microusd: 1_000_000,
    pricing_ceiling: { amount: "1000", denom: "uact" },
    sdl_hashes: [sha("a")],
    image_digests: [IMAGE],
    registry_hosts: ["ghcr.io"],
    result_destination_refs: ["connector://result/aft-u1"],
    result_transport_certificate_hashes: [sha("c")],
    auto_topup: false,
    teardown_policy: "always_teardown_required",
    max_duration_seconds: 7200,
  },
  aggregate_bounds: { max_usages: 200 },
};
const routineFacets = () => ({
  provider_selector: { mode: "exact", selection: "only_qualified_bid_from_exact_provider" },
  provider_address: PROVIDER,
  deposit_usd: 1,
  ceiling_amount: "1000",
  ceiling_denom: "uact",
  sdl_hash: sha("a"),
  image_digest: IMAGE,
  registry_host: "ghcr.io",
  result_credential_ref: "connector://result/aft-u1",
  result_tls_server_certificate_sha256: sha("c"),
  auto_topup: false,
  teardown_policy: "always_teardown_required",
  max_duration_seconds: 7200,
});
const request = (overrides = {}) => ({
  envelope: ENVELOPE, op: "create", provider_id: "pacc_18cd245812ad55b9",
  facets: { ...routineFacets(), ...overrides },
});

// The widenings a hostile proposer would try to slip past a habituated operator.
const WIDENINGS = [
  ["provider", { provider_address: "akash19zzh7whjt4vfwxd5wtj3tjtyatnpntfhldshd8" }, "standing_provider_address_outside_envelope"],
  ["destination", { result_credential_ref: "connector://result/exfil" }, "standing_result_destination_outside_envelope"],
  ["image", { image_digest: sha("9") }, "standing_image_outside_envelope"],
  ["registry", { registry_host: "registry.attacker.example" }, "standing_registry_outside_envelope"],
  ["ttl", { max_duration_seconds: 86_400 }, "standing_duration_outside_envelope"],
  ["deposit", { deposit_usd: 25 }, "standing_deposit_outside_envelope"],
  ["ceiling", { ceiling_amount: "1000000" }, "standing_ceiling_outside_envelope"],
  ["auto-topup", { auto_topup: true }, "standing_auto_topup_outside_envelope"],
  ["teardown", { teardown_policy: "best_effort" }, "standing_teardown_outside_envelope"],
  ["transport", { result_tls_server_certificate_sha256: sha("9") }, "standing_result_transport_outside_envelope"],
];

function probe(engine) {
  const failures = [];
  const { computeAuthorityDelta, admissionForDelta, AUTHORITY_DELTA_CODES } = engine;

  // 1. Two hundred routine draws are one decision, not two hundred.
  let authorityDecisions = 0;
  let activityReceipts = 0;
  for (let index = 0; index < 200; index += 1) {
    const delta = computeAuthorityDelta(request());
    const admission = admissionForDelta(delta);
    if (admission.decision !== "admit") failures.push("routine_in_envelope_draw_required_approval");
    if (delta.widened || delta.widenings.length > 0) failures.push("routine_in_envelope_draw_reported_a_delta");
    if (admission.decision !== "admit") authorityDecisions += 1;
    activityReceipts += 1;
  }
  if (authorityDecisions !== 0) failures.push("routine_activity_produced_authority_decisions");
  if (activityReceipts !== 200) failures.push("routine_activity_produced_no_receipts");

  // 2. One widening hidden among thirty-nine near-identical routine requests is
  //    separated by the delta, not by the operator noticing.
  for (const [name, overrides, code] of WIDENINGS) {
    const batch = [];
    for (let index = 0; index < 40; index += 1) {
      batch.push(index === 17 ? request(overrides) : request());
    }
    const deltas = batch.map((candidate) => computeAuthorityDelta(candidate));
    const flagged = deltas.map((delta, index) => (delta.widened ? index : -1)).filter((index) => index >= 0);
    if (flagged.length !== 1 || flagged[0] !== 17) failures.push(`hidden_widening_not_isolated:${name}`);
    const admission = admissionForDelta(deltas[17]);
    if (admission.decision === "admit") failures.push(`hidden_widening_admitted:${name}`);
    if (!deltas[17].widenings.some((entry) => entry.code === code)) failures.push(`hidden_widening_miscoded:${name}`);
  }

  // 3. Prompt volume grants nothing, and paraphrase is not a different effect.
  const widened = request(WIDENINGS[0][1]);
  const decisions = new Set();
  for (let index = 0; index < 500; index += 1) {
    decisions.add(admissionForDelta(computeAuthorityDelta(widened)).decision);
  }
  if (decisions.size !== 1 || decisions.has("admit")) failures.push("prompt_volume_changed_the_decision");
  const paraphrased = request({ ...WIDENINGS[0][1] });
  const first = JSON.stringify(computeAuthorityDelta(widened).widenings);
  const second = JSON.stringify(computeAuthorityDelta(paraphrased).widenings);
  if (first !== second) failures.push("identical_effect_produced_different_deltas");

  // 4. Step-up narrows to exactly the facets the policy names; anything else denies.
  const stepUp = admissionForDelta(computeAuthorityDelta(request({ max_duration_seconds: 86_400 })), {
    step_up_facets: ["max_duration_seconds"],
  });
  if (stepUp.decision !== "step_up_required") failures.push("named_step_up_facet_not_escalated");
  const mixed = admissionForDelta(
    computeAuthorityDelta(request({ max_duration_seconds: 86_400, result_credential_ref: "connector://result/exfil" })),
    { step_up_facets: ["max_duration_seconds"] },
  );
  if (mixed.decision !== "deny") failures.push("unnamed_widening_escalated_instead_of_denied");

  // 5. Every code the delta can name is one the daemon actually refuses with.
  //    Without this the surface is decorative: it could highlight a "widening"
  //    enforcement admits, or miss one it refuses.
  const enforced = new Set(
    [...providerRoutes.matchAll(/"(standing_[a-z0-9_]*outside_envelope)"/gu)].map((match) => match[1]),
  );
  const claimed = new Set(AUTHORITY_DELTA_CODES);
  for (const code of claimed) if (!enforced.has(code)) failures.push(`delta_names_an_unenforced_code:${code}`);
  for (const code of enforced) if (!claimed.has(code)) failures.push(`enforced_code_absent_from_delta:${code}`);

  return [...new Set(failures)].sort();
}

const baseline = await import(`${pathToFileURL(enginePath)}?baseline=${process.pid}`);
const baselineFailures = probe(baseline);
if (baselineFailures.length > 0) {
  console.error(JSON.stringify({ check: "check:approval-habituation", verdict: "FAIL", failures: baselineFailures }, null, 2));
  process.exit(1);
}

if (process.argv.includes("--mutation")) {
  const source = readFileSync(enginePath, "utf8");
  const mutations = [
    {
      name: "widening_reported_as_within_envelope",
      expected: "hidden_widening_not_isolated:provider",
      source: source.replace("if (widened) widenings.push", "if (false) widenings.push"),
    },
    {
      name: "widening_admitted_silently",
      expected: "hidden_widening_admitted:provider",
      source: source.replace('if (!delta.widened) return { decision: "admit", reason_codes: [], escalated_facets: [] };',
        'return { decision: "admit", reason_codes: [], escalated_facets: [] };'),
    },
    {
      name: "unnamed_widening_escalated_instead_of_denied",
      expected: "unnamed_widening_escalated_instead_of_denied",
      source: source.replace("const everyWideningEscalatable = delta.widenings.every((entry) => escalatable.has(entry.facet));",
        "const everyWideningEscalatable = delta.widenings.some((entry) => escalatable.has(entry.facet));"),
    },
    {
      name: "destination_widening_dropped_from_the_delta",
      expected: "enforced_code_absent_from_delta:standing_result_destination_outside_envelope",
      source: source.replace('["result_credential_ref", "result_destination_refs", "standing_result_destination_outside_envelope"],\n', ""),
    },
    {
      name: "deposit_ceiling_treated_as_unbounded",
      expected: "hidden_widening_not_isolated:deposit",
      source: source.replace("depositMicrousd > (template.per_operation_deposit_microusd ?? 0)", "false"),
    },
  ];
  const survived = [];
  for (const mutation of mutations) {
    if (mutation.source === source) { survived.push({ name: mutation.name, error: "mutation did not change the engine" }); continue; }
    const encoded = Buffer.from(mutation.source).toString("base64");
    let failures;
    try {
      failures = probe(await import(`data:text/javascript;base64,${encoded}#${mutation.name}`));
    } catch (error) {
      failures = [`engine_threw:${String(error.message).slice(0, 60)}`];
    }
    if (!failures.includes(mutation.expected)) survived.push({ name: mutation.name, expected: mutation.expected, failures });
  }
  if (survived.length > 0) {
    console.error(JSON.stringify({ check: "mutate:approval-habituation", verdict: "FAIL", survived }, null, 2));
    process.exit(1);
  }
  console.log(JSON.stringify({
    check: "mutate:approval-habituation", verdict: "PASS",
    mutations: mutations.map(({ name, expected }) => ({ mutation: name, detected_by: expected })),
  }, null, 2));
} else {
  console.log(JSON.stringify({
    check: "check:approval-habituation",
    verdict: "PASS",
    routine_draws_requiring_approval: 0,
    routine_activity_receipts: 200,
    hidden_widenings_isolated: WIDENINGS.length,
    step_up_prompts_that_changed_the_decision: 0,
    delta_codes_agreeing_with_daemon_enforcement: baseline.AUTHORITY_DELTA_CODES.length,
    claim_boundary: "This holds the deterministic half of the habituation defence: the delta is computed from bytes and every code it can name is one the daemon's containment check refuses with. It does not claim an operator-facing surface renders that delta; presentation is an unbuilt M03/M08 unit and is named, not assumed.",
  }, null, 2));
}
