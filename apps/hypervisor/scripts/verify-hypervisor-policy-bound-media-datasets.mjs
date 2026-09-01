#!/usr/bin/env node
// M05.9 — the deterministic blocking lane for policy-bound media, demonstration and trajectory
// datasets.
//
// WHAT THIS GATE IS FOR. Four Data-owned families became registered contracts, and then a runtime.
// A contract can say a snapshot is policy-bound; only a run against a live daemon can show that a
// snapshot naming a view nobody resolved is REFUSED. Every assertion below is an observation of a
// real admission through the real chain — no shape-checking, no fixture replay.
//
// SELF-GRADING DEFENCES CARRIED ACROSS FROM THE M05.7/M05.8 HARNESSES:
//   * every content hash is recomputed HERE from the registered invariant profile's own material
//     list, so a verifier that agreed with a broken producer would still disagree with the contract;
//   * durable truth is read back ACROSS A REAL PROCESS RESTART, and the read index is deleted first
//     so the rebuild is positively detected rather than assumed;
//   * every refusal is counted BY EFFECT — the stream is re-read and its head and record count must
//     be unchanged, because a refusal that still appended is not a refusal;
//   * there is no env-overridable ROOT, and zero assertions is a FAILURE, not a pass.
//
// THE PRINT FORMAT IS A CONTRACT. The mutation battery greps `FAIL  ${reddens}`, so `ok  `/`FAIL  `
// and the assertion names below are load-bearing for the battery, not decoration.
//
// NO NUMERIC PERFORMANCE ASSERTION APPEARS HERE, deliberately. Per ADR 0039's own acceptance record
// and the M05.9 guide, a throughput or latency tripwire waits for repeated matched release-host
// baselines and a planted slowdown mutation. This lane asserts FUNCTION, not speed.

import fs from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import {
  corpusBytesResolver,
  generateCorpus,
  nearDuplicateClosureFailures,
  payloadBytes,
  similarityFingerprint,
} from "./lib/synthetic-media-corpus.mjs";
// THE SHARED SPINE. The daemon lifecycle and the M05.7/M05.8/M10.3 owner seams live in ONE module
// that this blocking gate and the scheduled scale soak both drive. They were duplicated once, and
// the soak's header claimed a shared spine that did not exist — a false material claim about the
// evidence itself. Two copies could diverge silently and each go green about a different runtime.
import {
  OWNER,
  ROUTES_V1,
  canonicalJson,
  code,
  createLane,
  resolveDaemonBinary,
  seedOwners,
  sha256,
} from "./lib/m059-media-lane.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const MUTATE = process.argv.includes("--mutate");
const ANCHORS = process.argv.includes("--anchors");
const SUMMARIZE = process.argv.includes("--summarize");
const RESTORE = process.argv.includes("--restore");
const ONLY = (process.argv.find((arg) => arg.startsWith("--only=")) ?? "")
  .replace("--only=", "")
  .split(",")
  .map((id) => id.trim())
  .filter(Boolean);

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const pointer = (document, jsonPath) => {
  let current = document;
  for (const segment of jsonPath.slice(2).split(".")) current = current?.[segment];
  return current === undefined ? null : current;
};

const INVARIANT_DIR = path.join(ROOT, "docs/architecture/_meta/schemas/invariants");

/** The commitment, rebuilt from the REGISTERED profile's own material list and domain constant. */
function registeredCommitment(file, ruleId, document) {
  const rules = JSON.parse(fs.readFileSync(path.join(INVARIANT_DIR, file), "utf8")).rules;
  const rule = rules.find((r) => r.rule_id === ruleId);
  const material = {};
  for (const [field, descriptor] of Object.entries(rule.expression.material_fields)) {
    material[field] = Object.hasOwn(descriptor, "value") ? descriptor.value : pointer(document, descriptor.path);
  }
  return sha256(canonicalJson(material));
}

// THE DAEMON LIFECYCLE COMES FROM THE SHARED LANE, not from a private copy in this file. This
// blocking gate and the scheduled scale soak must be about ONE runtime: two lifecycles could drift
// apart and each report green about a different spine, which is the failure the estate's
// no-second-spine rule exists to prevent.
const lane = createLane({ root: ROOT, label: "ioi-m059-media-verifier" });
const req = (...args) => lane.req(...args);
const rebuildDaemon = () => lane.rebuildDaemon();
const startDaemon = () => lane.start();
const stopDaemon = () => lane.stop();
const cleanup = () => lane.cleanup();

process.on("exit", cleanup);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    cleanup();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

// The route set is the lane's, so the gate and the soak cannot address different surfaces.
const OWNER_PASSWORD = "m059-a-v1";
const SNAPS = ROUTES_V1.SNAPS;
const EPISODES = ROUTES_V1.EPISODES;
const SPLITS = ROUTES_V1.SPLITS;
const CENSUSES = ROUTES_V1.CENSUSES;
const IMPACT = ROUTES_V1.IMPACT;
const T_ADMIT = "2026-09-01T08:00:00Z";

const LABEL_CLICK = "label-class://acme/action/click";
const LABEL_SCROLL = "label-class://acme/action/scroll";
const LABEL_FIELD = "label-class://acme/field/ticket-id";
const LABEL_EXCEPTION = "label-class://acme/exception/operator-abort";

// ---------------------------------------------------------------------------------- fixture bodies

const snapshotBody = (key, family, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family,
  effective_at: T_ADMIT,
  acquisition_class: "imported_recording",
  capture_binding: {
    actor_ref: "actor://acme.operator-01",
    session_ref: "session://acme.desk-a",
    device_ref: "device://acme.workstation-07",
    environment_ref: "environment://acme.sandbox/revision/4",
    application_ref: null,
    world_revision_ref: null,
  },
  capture_rights_revision_ref: "",
  learning_source_rights_claim_revision_refs: [],
  consent_bindings: [],
  policy_bound_data_view_revision_refs: [],
  timebase: {
    temporal_verification_profile_ref: "temporal-verification-profile://acme.wallet-anchored/v1",
    profile_hash: sha256("tvp"),
    timebase_id: "acme-desk-tb-1",
    clock_class: "authenticated_wallet_time",
    epoch_ref: "epoch://acme.desk",
    tick_unit: "millisecond",
    declared_monotonic: true,
    discontinuities: [
      { kind: "gap", at_tick: 412000, span_ticks: 1800, evidence_ref: "artifact://acme/gap-1" },
      { kind: "clock_regression", at_tick: 700000, span_ticks: 40, evidence_ref: "artifact://acme/reg-1" },
      { kind: "reorder", at_tick: 810000, span_ticks: 12, evidence_ref: "artifact://acme/reo-1" },
      { kind: "rate_change", at_tick: 905000, span_ticks: 60, evidence_ref: "artifact://acme/rate-1" },
    ],
  },
  valid_time: { from: "2026-08-31T09:00:00Z", to: "2026-08-31T11:30:00Z" },
  artifact_bindings: [
    {
      artifact_ref: "artifact://acme/recording-a",
      sha256: sha256("rec-a"),
      media_type: "video/mp4",
      size_bytes: 51200000,
      manifest_root: sha256("man-a"),
      role: "recording",
    },
    {
      artifact_ref: "artifact://acme/control-a",
      sha256: sha256("ctl-a"),
      media_type: "application/jsonl",
      size_bytes: 240000,
      manifest_root: sha256("man-b"),
      role: "control_stream",
    },
  ],
  availability: {
    availability_manifest_ref: "availability-manifest://acme/1",
    retention_class_ref: "retention-class://bounded_retention",
    verifier_contract_ref: "verifier-contract://ioi/media-snapshot/v1",
    failure_behavior: "fail_closed",
  },
  information_flow_label_refs: ["ifc-label://acme/internal"],
  quarantine: {
    quarantine_state: "accepted",
    pii_decision_receipt_refs: ["receipt://acme.pii/desk-1"],
    rejected_segment_count: 3,
  },
  redaction: {
    recipe_revision_ref: "",
    creates_permission: false,
    severs_lineage: false,
    source_privacy_class: "confidential",
    output_privacy_class: "confidential",
  },
  deduplication: {
    exact_key_algorithm: "jcs_sha256",
    near_duplicate_method: "perceptual-frame-hash-hamming-8",
    excluded_count: 11,
  },
  quality_findings: [
    { finding_class: "truncated_file", severity: "refused", evidence_ref: "artifact://acme/trunc-1" },
    { finding_class: "corrupt_chunk", severity: "refused", evidence_ref: "artifact://acme/corrupt-1" },
    { finding_class: "variable_rate_segment", severity: "excluded", evidence_ref: "artifact://acme/vrate-1" },
  ],
  source_impact_lineage: {
    data_recipe_revision_refs: [],
    connector_mapping_revision_refs: [],
    transformation_run_refs: [],
  },
  raw_census: {
    source_seconds: 9000,
    file_count: 5,
    byte_count: 71000000,
    frame_or_sample_count: 270000,
    chunk_count: 900,
  },
  accepted_census: {
    source_seconds: 8100,
    file_count: 2,
    byte_count: 51440000,
    frame_or_sample_count: 243000,
    chunk_count: 810,
  },
  registry_status: "active",
  ...over,
});

const CONTROLLER_LABEL = "label://acme/ep/click-0007";
const INFERRED_LABEL = "label://acme/ep/inferred-0011";

const episodeBody = (key, family, snapshotRef, snapshotHash, over = {}) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family,
  effective_at: T_ADMIT,
  media_snapshot_revision_ref: snapshotRef,
  media_snapshot_content_hash: snapshotHash,
  bounds: {
    timebase_id: "acme-desk-tb-1",
    start_tick: 120000,
    end_tick: 486000,
    boundary_evidence_ref: "artifact://acme/ep-bounds",
  },
  streams: [
    {
      stream_role: "observation",
      schema_ref: "schema://acme/frame/v1",
      channel: "screen",
      sample_count: 10980,
      sync_evidence_ref: "artifact://acme/sync-1",
    },
    {
      stream_role: "action",
      schema_ref: "schema://acme/action/v1",
      channel: "controller",
      sample_count: 412,
      sync_evidence_ref: "artifact://acme/sync-1",
    },
  ],
  synchronization: {
    method: "shared_timebase",
    frame_action_offset_ticks: -16,
    max_observed_skew_ticks: 22,
    declared_skew_envelope_ticks: 40,
  },
  labels: [
    {
      label_ref: CONTROLLER_LABEL,
      label_class: LABEL_CLICK,
      value_ref: "value://acme/click",
      label_provenance_class: "controller_recorded",
      epistemic_status: "controller_ground_truth",
      is_controller_ground_truth: true,
      confidence: null,
      uncertainty_kind: "none",
      attributed_to_ref: "device://acme.workstation-07",
      corrected_by_ref: null,
    },
    {
      label_ref: INFERRED_LABEL,
      label_class: LABEL_SCROLL,
      value_ref: "value://acme/scroll",
      label_provenance_class: "video_inferred",
      epistemic_status: "uncertain_attributed_label",
      is_controller_ground_truth: false,
      confidence: 0.71,
      uncertainty_kind: "model",
      attributed_to_ref: "model://acme.vision-labeler/v3",
      corrected_by_ref: null,
    },
  ],
  exception_labels: [
    { exception_class: "operator_abort", at_tick: 470000, evidence_ref: "artifact://acme/abort-1" },
  ],
  determinism: {
    determinism_class: "seeded_deterministic",
    preprocessor_code_root: sha256("pre-code"),
    preprocessor_config_root: sha256("pre-config"),
    declared_randomness_seed: "acme-seed-1",
  },
  registry_status: "active",
  ...over,
});

// THE COMPACT LANE'S CORPUS IS GENERATED, NOT HAND-WRITTEN, so its numbers are summed from bytes
// rather than typed beside them. The previous hand-written body is exactly what let the first
// version of this contract look policed: every row carried `sha256(<a short id string>)` — a digest
// of a LABEL, not of any bytes — beside a `byte_count` nothing produced, and its two "duplicate"
// rows had unique digests, so no exact duplicate was ever present to detect.
const COMPACT_CORPUS = generateCorpus({
  profile: "interactive-learned",
  seed: "m059-compact-lane",
  sessions: 2,
  episodesPerSession: 1,
});

/** The corpus root, recomputed exactly as the registered invariant and the runtime both define it. */
const corpusRoot = (body) =>
  sha256(
    canonicalJson({
      domain: "ioi.media-corpus-content-root-jcs-sha256.v1",
      file_dispositions: body.file_dispositions,
      distinct_payloads: body.distinct_payloads,
      near_duplicate_exclusions: body.near_duplicate_exclusions,
      deduplication_policy: body.deduplication_policy,
      raw: body.raw,
      accepted: body.accepted,
      rejected: body.rejected,
      deduplicated: body.deduplicated,
    }),
  );

/** Re-anchor a body after a deliberate corpus edit, so the intended refusal fires and not the root's. */
const reroot = (body) => {
  body.corpus_content_root = corpusRoot(body);
  return body;
};

// The real subscription lease every census in this gate reports its backpressure against. It is
// admitted in `run()` before the first census body is built; a ref nobody created now REFUSES.
const LEASE_NS = "media-corpus-gate";
const LEASE_TAIL = "sub_gate";
const LEASE = { ref: `subscription-lease://${LEASE_NS}/${LEASE_TAIL}`, window: 4096 };

const censusBody = (key, family, over = {}) => {
  const corpus = COMPACT_CORPUS;
  const body = {
    owner_ref: OWNER,
    idempotency_key: key,
    family,
    effective_at: T_ADMIT,
    claimed_scale: "compact_deterministic_fixture",
    profile: "interactive-learned",
    corpus_content_root: "",
    raw: structuredClone(corpus.raw),
    accepted: structuredClone(corpus.accepted),
    rejected: structuredClone(corpus.rejected),
    deduplicated: structuredClone(corpus.deduplicated),
    deduplication_policy: structuredClone(corpus.deduplication_policy),
    file_dispositions: structuredClone(corpus.file_dispositions),
    distinct_payloads: structuredClone(corpus.distinct_payloads),
    near_duplicate_exclusions: structuredClone(corpus.near_duplicate_exclusions),
    profile_required_label_classes: [...corpus.required_label_classes],
    observed_label_classes: [...corpus.observed_label_classes],
    runtime_evidence: {
      peak_resident_bytes: 402653184,
      // RESOLVED, NOT NAMED. A hand-written lease ref beside a hand-written window is two agreeing
      // strings about a lease nobody created; this one is admitted through the real subscription
      // plane in `run()` and the runtime reads the window back off it.
      projection_subscription_lease_ref: LEASE.ref,
      max_undelivered_events_declared: LEASE.window,
      queue_high_water: LEASE.window - 225,
      backpressure_lag_outcomes: ["typed_gap"],
      durability_class_achieved: "replicated_same_host",
      interruption_count: 1,
      resume_count: 1,
      restart_equivalence: {
        pre_restart_root: sha256("restart-root"),
        post_restart_root: sha256("restart-root"),
        roots_equal: true,
      },
      corrupt_inputs_refused: 1,
      truncated_inputs_refused: 1,
      variable_rate_inputs_handled: 1,
    },
    degeneracy_findings: [],
    ...over,
  };
  return reroot(body);
};

// ------------------------------------------------------------------------------------ owner seeds
// SEEDED THROUGH THE SHARED LANE. The ontology, mapping, recipe, route rights, source-rights claims
// and transformation run this gate binds are admitted by `lib/m059-media-lane.mjs` — the same code
// the scheduled scale soak runs. A private copy here would let the two harnesses seed subtly
// different owners and still both report green.

/** Re-read a family stream and return {head, count} so a refusal can be counted BY EFFECT. */
const streamState = (base, family) => lane.streamState(base, family);

async function refusesWithoutAppending(base, family, name, expectedCode, send) {
  const before = await streamState(base, family);
  const response = await send();
  const after = await streamState(base, family);
  const refused = response.status >= 400;
  const sameCode = expectedCode ? code(response.j) === expectedCode : true;
  ok(
    name,
    refused && sameCode && after.count === before.count,
    `status=${response.status} code=${code(response.j)} records ${before.count}->${after.count}`,
  );
  return response;
}

// ---------------------------------------------------------------------------------------- the run

async function run() {
  await startDaemon();
  const boot = await lane.bootstrap(OWNER_PASSWORD);
  ok(
    "the isolated daemon bootstraps an owner session",
    !!boot.sessionToken,
    `token=${boot.sessionToken ? "present" : "absent"}`,
  );

  const seeds = await seedOwners(req, { prefix: "m059" });
  ok(
    "the M05.7/M10.3 owner seams seed real admitted revisions for this run to bind",
    !!seeds.recipe.revision_ref && !!seeds.captureClaim.revision_ref && !!seeds.run.transformation_run_id,
    `recipe=${seeds.recipe.revision_ref} claim=${seeds.captureClaim.revision_ref} run=${seeds.run.transformation_run_id}`,
  );

  const baseSnapshot = (key, family, over = {}) =>
    snapshotBody(key, family, {
      capture_rights_revision_ref: seeds.captureClaim.revision_ref,
      learning_source_rights_claim_revision_refs: [seeds.learnedClaim.revision_ref],
      redaction: {
        recipe_revision_ref: seeds.recipe.revision_ref,
        creates_permission: false,
        severs_lineage: false,
        source_privacy_class: "confidential",
        output_privacy_class: "confidential",
      },
      source_impact_lineage: {
        data_recipe_revision_refs: [seeds.recipe.revision_ref],
        connector_mapping_revision_refs: [seeds.mapping.revision_ref],
        transformation_run_refs: [seeds.run.transformation_run_id],
      },
      ...over,
    });

  // ============================================================ A · identity and immutability
  const admitted = await req("POST", SNAPS, baseSnapshot("m059-snap-1", "acme.desk"));
  const snapshot = admitted.j?.media_snapshot ?? {};
  ok(
    "A1 a media snapshot is admitted through the owner-scoped chain and returns its exact revision",
    admitted.status === 201 && /^media-snapshot:\/\/acme\.desk\/revision\/1$/u.test(snapshot.revision_ref ?? ""),
    `status=${admitted.status} revision=${snapshot.revision_ref} code=${code(admitted.j)} ${admitted.j?.error?.message ?? ""}`,
  );
  ok(
    "A2 the served commitment is the one the REGISTERED invariant profile computes over these bytes",
    snapshot.content_hash ===
      registeredCommitment(
        "policy-bound-media-snapshot.v1.invariants.json",
        "policy_bound_media_snapshot.content_hash.commits_the_whole_revision",
        snapshot,
      ),
    `served=${snapshot.content_hash}`,
  );
  ok(
    "A3 admission coordinates come from the chain, not the record",
    !!admitted.j?.admission?.agentgres_operation_ref && !!admitted.j?.receipt_ref,
    `op=${admitted.j?.admission?.agentgres_operation_ref}`,
  );
  const replay = await req("POST", SNAPS, baseSnapshot("m059-snap-1", "acme.desk"));
  ok(
    "A4 an exact retry replays the revision it already minted rather than minting a second one",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.media_snapshot?.revision_ref === snapshot.revision_ref,
    `status=${replay.status} replayed=${replay.j?.replayed}`,
  );
  await refusesWithoutAppending(SNAPS, "acme.desk", "A5 a caller-authored identity or tenancy is refused by name (INV-37)", "", () =>
    req("POST", SNAPS, baseSnapshot("m059-snap-authored", "acme.desk", { tenant_ref: "tenant://someone-else" })),
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk",
    "A6 a stale expected head is refused and appends nothing",
    "",
    () => req("POST", SNAPS, baseSnapshot("m059-snap-stale", "acme.desk", { expected_head: sha256("not-the-head") })),
  );

  // ============================================================ B · rights and policy binding
  ok(
    "B1 permits_learned_use is DERIVED from the resolved claims, never taken from the caller",
    snapshot.source_rights?.permits_learned_use === false,
    `derived=${snapshot.source_rights?.permits_learned_use} (no policy-bound view bound, so the learned claim is inadmissible)`,
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "B2 missing capture rights refuses EVERY profile, procedural included",
    "",
    () => req("POST", SNAPS, baseSnapshot("m059-snap-norights", "acme.desk-neg", { capture_rights_revision_ref: "" })),
  );
  const lapsed = await req(
    "POST",
    SNAPS,
    baseSnapshot("m059-snap-lapsed", "acme.desk-lapsed", {
      capture_rights_revision_ref: seeds.lapsedClaim.revision_ref,
    }),
  );
  ok(
    "B3 a capture-rights claim whose window closed at the admission instant refuses the snapshot",
    lapsed.status >= 400 && code(lapsed.j).includes("capture_rights_not_live"),
    `status=${lapsed.status} code=${code(lapsed.j)}`,
  );
  const learnedLapsed = await req(
    "POST",
    SNAPS,
    baseSnapshot("m059-snap-learned-lapsed", "acme.desk-partial", {
      learning_source_rights_claim_revision_refs: [seeds.lapsedClaim.revision_ref],
    }),
  );
  ok(
    "B4 a lapsed TRAINING claim refuses only the learned claim and leaves the procedural path open",
    learnedLapsed.status === 201 &&
      learnedLapsed.j?.media_snapshot?.source_rights?.permits_learned_use === false,
    `status=${learnedLapsed.status} learned=${learnedLapsed.j?.media_snapshot?.source_rights?.permits_learned_use}`,
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "B5 a policy-bound view ref that no owner can resolve refuses before any byte is bound",
    "",
    () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot("m059-snap-badview", "acme.desk-neg", {
          policy_bound_data_view_revision_refs: ["view://acme.never-admitted/revision/9"],
        }),
      ),
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "B6 a view named as a FAMILY HEAD rather than an exact revision is refused",
    "",
    () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot("m059-snap-headview", "acme.desk-neg", {
          policy_bound_data_view_revision_refs: ["view://acme.desk-intake"],
        }),
      ),
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "B7 redaction that claims to create permission is refused BY NAME, not corrected underneath the caller",
    "media_snapshot_redaction_as_permission_refused",
    () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot("m059-snap-redperm", "acme.desk-neg", {
          redaction: {
            recipe_revision_ref: seeds.recipe.revision_ref,
            creates_permission: true,
            severs_lineage: false,
            source_privacy_class: "confidential",
            output_privacy_class: "confidential",
          },
        }),
      ),
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "B8 redaction that lowers the output privacy class below its source is refused as a declassification",
    "media_snapshot_redaction_declassifies_refused",
    () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot("m059-snap-declass", "acme.desk-neg", {
          redaction: {
            recipe_revision_ref: seeds.recipe.revision_ref,
            creates_permission: false,
            severs_lineage: false,
            source_privacy_class: "confidential",
            output_privacy_class: "internal",
          },
        }),
      ),
  );

  // ============================================================ C · the timebase
  ok(
    "C1 gap, reorder, clock-regression and rate-change discontinuities are RETAINED, never normalized",
    (snapshot.timebase?.discontinuities ?? []).length === 4 &&
      new Set((snapshot.timebase?.discontinuities ?? []).map((d) => d.kind)).size === 4,
    `retained=${(snapshot.timebase?.discontinuities ?? []).map((d) => d.kind).join(",")}`,
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "C2 a caller asking for discontinuities to be normalized away is refused",
    "media_snapshot_discontinuity_normalization_refused",
    () => req("POST", SNAPS, baseSnapshot("m059-snap-norm", "acme.desk-neg", { normalize_discontinuities: true })),
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "C3 a timebase declared non-monotonic is refused rather than repaired",
    "media_snapshot_timebase_not_declared_monotonic",
    () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot("m059-snap-nonmono", "acme.desk-neg", {
          timebase: { ...snapshotBody("x", "y").timebase, declared_monotonic: false },
        }),
      ),
  );

  // ============================================================ G · bounded ingest, refused by name
  for (const [cls, label] of [
    ["corrupt_chunk", "G1 a corrupt chunk retained instead of refused is refused BY NAME"],
    ["truncated_file", "G2 a truncated file retained instead of refused is refused BY NAME"],
    ["variable_rate_segment", "G3 a variable-rate segment retained instead of refused is refused BY NAME"],
  ]) {
    await refusesWithoutAppending(SNAPS, "acme.desk-neg", label, "media_snapshot_degraded_input_retained_instead_of_refused", () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot(`m059-snap-${cls}`, "acme.desk-neg", {
          quality_findings: [{ finding_class: cls, severity: "retained_with_finding", evidence_ref: "artifact://acme/x" }],
        }),
      ),
    );
  }
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "G4 a repeated artifact digest inside one snapshot is refused as a degenerate corpus",
    "media_snapshot_repeated_artifact_digest_refused",
    () => {
      const body = baseSnapshot("m059-snap-dupart", "acme.desk-neg");
      body.artifact_bindings[1].sha256 = body.artifact_bindings[0].sha256;
      return req("POST", SNAPS, body);
    },
  );
  await refusesWithoutAppending(
    SNAPS,
    "acme.desk-neg",
    "G5 an accepted census larger than the raw census it came from is refused",
    "media_snapshot_accepted_exceeds_raw",
    () =>
      req(
        "POST",
        SNAPS,
        baseSnapshot("m059-snap-pad", "acme.desk-neg", {
          accepted_census: { source_seconds: 9600, file_count: 2, byte_count: 51440000, frame_or_sample_count: 243000, chunk_count: 810 },
        }),
      ),
  );

  // ============================================================ D · label provenance
  const episode = await req(
    "POST",
    EPISODES,
    episodeBody("m059-ep-1", "acme.desk-tasks", snapshot.revision_ref, snapshot.content_hash),
  );
  const ep = episode.j?.observation_action_episode ?? {};
  ok(
    "D1 an episode is admitted and inherits its snapshot's session and timebase",
    episode.status === 201 && ep.session_ref === "session://acme.desk-a" && ep.bounds?.timebase_id === "acme-desk-tb-1",
    `status=${episode.status} session=${ep.session_ref}`,
  );
  ok(
    "D2 the ground-truth-eligible set is DERIVED from the controller-recorded subset, not authored",
    JSON.stringify(ep.ground_truth_eligible_label_refs) === JSON.stringify([CONTROLLER_LABEL]) &&
      JSON.stringify(ep.controller_recorded_label_refs) === JSON.stringify([CONTROLLER_LABEL]),
    `eligible=${JSON.stringify(ep.ground_truth_eligible_label_refs)}`,
  );
  ok(
    "D3 the video-inferred label survives as an UNCERTAIN ATTRIBUTED LABEL rather than being dropped",
    (ep.labels ?? []).some(
      (l) => l.label_provenance_class === "video_inferred" && l.epistemic_status === "uncertain_attributed_label",
    ),
    `labels=${(ep.labels ?? []).map((l) => `${l.label_provenance_class}:${l.epistemic_status}`).join(",")}`,
  );
  await refusesWithoutAppending(
    EPISODES,
    "acme.desk-neg-ep",
    "D4 a video-inferred label claiming controller ground truth is REFUSED BY NAME",
    "observation_action_episode_inferred_label_claims_controller_ground_truth",
    () => {
      const body = episodeBody("m059-ep-gt", "acme.desk-neg-ep", snapshot.revision_ref, snapshot.content_hash);
      body.labels[1].is_controller_ground_truth = true;
      return req("POST", EPISODES, body);
    },
  );
  await refusesWithoutAppending(
    EPISODES,
    "acme.desk-neg-ep",
    "D5 a video-inferred label claiming a certain epistemic status is refused rather than defaulted",
    "observation_action_episode_inferred_label_claims_certain_status",
    () => {
      const body = episodeBody("m059-ep-certain", "acme.desk-neg-ep", snapshot.revision_ref, snapshot.content_hash);
      body.labels[1].epistemic_status = "controller_ground_truth";
      return req("POST", EPISODES, body);
    },
  );
  await refusesWithoutAppending(
    EPISODES,
    "acme.desk-neg-ep",
    "D6 ground truth claimed from an operator annotation is refused — only a controller stream supports it",
    "observation_action_episode_ground_truth_claimed_without_a_controller_stream",
    () => {
      const body = episodeBody("m059-ep-op", "acme.desk-neg-ep", snapshot.revision_ref, snapshot.content_hash);
      body.labels[0].label_provenance_class = "operator_annotated";
      return req("POST", EPISODES, body);
    },
  );

  // ============================================================ C4/C5 · cross-family timebase
  await refusesWithoutAppending(
    EPISODES,
    "acme.desk-neg-ep",
    "C4 an episode whose timebase differs from its snapshot's is refused",
    "observation_action_episode_episode_timebase_differs_from_its_snapshot",
    () => {
      const body = episodeBody("m059-ep-tb", "acme.desk-neg-ep", snapshot.revision_ref, snapshot.content_hash);
      body.bounds.timebase_id = "some-other-clock";
      return req("POST", EPISODES, body);
    },
  );
  await refusesWithoutAppending(
    EPISODES,
    "acme.desk-neg-ep",
    "C5 observed frame/action skew beyond the declared envelope is refused, never absorbed",
    "observation_action_episode_observed_skew_exceeds_declared_envelope",
    () => {
      const body = episodeBody("m059-ep-skew", "acme.desk-neg-ep", snapshot.revision_ref, snapshot.content_hash);
      body.synchronization.max_observed_skew_ticks = 96;
      return req("POST", EPISODES, body);
    },
  );
  await refusesWithoutAppending(
    EPISODES,
    "acme.desk-neg-ep",
    "C6 a snapshot content hash that drifted from what its owner serves is refused",
    "observation_action_episode_snapshot_content_hash_drifted",
    () =>
      req(
        "POST",
        EPISODES,
        episodeBody("m059-ep-drift", "acme.desk-neg-ep", snapshot.revision_ref, sha256("not-the-snapshot")),
      ),
  );

  // ============================================================ E · splits and leakage
  const episodeRefs = [];
  const episodeHashes = [];
  let memberHead = "";
  for (let index = 0; index < 6; index += 1) {
    const body = episodeBody(`m059-ep-m${index}`, "acme.desk-members", snapshot.revision_ref, snapshot.content_hash);
    body.bounds.start_tick = 1000 + index * 1000;
    body.bounds.end_tick = 400000 + index * 1000;
    body.labels[0].label_ref = `${CONTROLLER_LABEL}-${index}`;
    body.labels[1].label_ref = `${INFERRED_LABEL}-${index}`;
    if (memberHead) body.expected_head = memberHead;
    const created = await req("POST", EPISODES, body);
    memberHead = created.j?.expected_head_for_successor ?? memberHead;
    episodeRefs.push(created.j?.observation_action_episode?.revision_ref ?? "");
    episodeHashes.push(created.j?.observation_action_episode?.content_hash ?? "");
  }
  const SPLIT_CLASSES = ["train", "validation", "temporal_holdout", "actor_holdout", "world_holdout", "adversarial"];
  const splitMembers = () =>
    episodeRefs.map((ref, index) => ({
      episode_revision_ref: ref,
      episode_content_hash: episodeHashes[index],
      split_class: SPLIT_CLASSES[index],
      actor_partition_key: index < 3 ? "actor-a" : `actor-${index}`,
      world_partition_key: index < 3 ? "world-a" : `world-${index}`,
      max_tick: 400000 + index * 1000,
    }));
  const splitBody = (key, over = {}) => ({
    owner_ref: OWNER,
    idempotency_key: key,
    family: over.family ?? "acme.desk-split",
    effective_at: T_ADMIT,
    members: splitMembers(),
    leakage_controls: {
      near_duplicate_exclusion_method: "perceptual-frame-hash-hamming-8",
      near_duplicate_excluded_count: 11,
      temporal_cut_tick: 500000,
      max_train_tick: 460000,
      min_temporal_holdout_tick: 520000,
    },
    registry_status: "active",
    ...over,
  });
  const split = await req("POST", SPLITS, splitBody("m059-split-1"));
  const manifest = split.j?.dataset_split_manifest ?? {};
  ok(
    "E1 a split manifest is admitted and its membership is DERIVED from the rows, not authored",
    split.status === 201 &&
      manifest.member_count === 6 &&
      (manifest.all_member_episode_revision_refs ?? []).length === 6 &&
      manifest.membership_is_immutable === true,
    `status=${split.status} count=${manifest.member_count}`,
  );
  await refusesWithoutAppending(
    SPLITS,
    "acme.desk-neg-split",
    "E2 an episode assigned to two splits is refused as double membership",
    "dataset_split_manifest_episode_is_a_member_twice",
    () => {
      const body = splitBody("m059-split-dup", { family: "acme.desk-neg-split" });
      body.members[1].episode_revision_ref = body.members[0].episode_revision_ref;
      return req("POST", SPLITS, body);
    },
  );
  await refusesWithoutAppending(
    SPLITS,
    "acme.desk-neg-split",
    "E3 training that crosses the temporal cut is refused as future-frame leakage",
    "dataset_split_manifest_training_crosses_the_temporal_cut",
    () => {
      const body = splitBody("m059-split-cut", { family: "acme.desk-neg-split" });
      body.leakage_controls.max_train_tick = 540000;
      return req("POST", SPLITS, body);
    },
  );
  await refusesWithoutAppending(
    SPLITS,
    "acme.desk-neg-split",
    "E4 a temporal holdout that begins before the cut is refused",
    "dataset_split_manifest_temporal_holdout_begins_before_the_cut",
    () => {
      const body = splitBody("m059-split-holdout", { family: "acme.desk-neg-split" });
      body.leakage_controls.min_temporal_holdout_tick = 480000;
      return req("POST", SPLITS, body);
    },
  );
  await refusesWithoutAppending(
    SPLITS,
    "acme.desk-neg-split",
    "E5 an actor holdout sharing an actor with training is refused",
    "dataset_split_manifest_actor_holdout_overlaps_training",
    () => {
      const body = splitBody("m059-split-actor", { family: "acme.desk-neg-split" });
      body.members[3].actor_partition_key = "actor-a";
      return req("POST", SPLITS, body);
    },
  );
  await refusesWithoutAppending(
    SPLITS,
    "acme.desk-neg-split",
    "E6 a world holdout sharing a world with training is refused",
    "dataset_split_manifest_world_holdout_overlaps_training",
    () => {
      const body = splitBody("m059-split-world", { family: "acme.desk-neg-split" });
      body.members[4].world_partition_key = "world-a";
      return req("POST", SPLITS, body);
    },
  );
  await refusesWithoutAppending(
    SPLITS,
    "acme.desk-neg-split",
    "E7 a member episode whose bytes drifted since membership was computed is refused",
    "dataset_split_manifest_member_content_hash_drifted",
    () => {
      const body = splitBody("m059-split-drift", { family: "acme.desk-neg-split" });
      body.members[2].episode_content_hash = sha256("not-the-episode");
      return req("POST", SPLITS, body);
    },
  );

  // ============================================================ H · census honesty
  // A real bounded lease over a real stream, admitted before any census reports against it.
  const streamDeclaration = {
    event_class_declaration: {
      admitted_truth_classes: [{ class_id: "ioi.media.chunk", payload_schema_ref: "schema://ioi/media-chunk/v1" }],
      ephemeral_delivery_classes: [],
    },
  };
  await req("POST", `/v1/event-streams/${LEASE_NS}/ingest`, {
    ...streamDeclaration,
    owner_ref: OWNER,
    idempotency_key: "m059-gate-stream",
  });
  const leaseCreated = await req("POST", "/v1/subscriptions", {
    owner_namespace: LEASE_NS,
    stream_tail: "ingest",
    subscriber_ref: "subscriber://ioi/m059-gate",
    lease_tail: LEASE_TAIL,
    permitted_event_class_ids: ["ioi.media.chunk"],
    max_undelivered_events: LEASE.window,
    recorded_at_ms: 1,
    idempotency_key: "m059-gate-lease",
  });
  ok(
    "H0 the census's backpressure evidence names a lease that was really admitted on the subscription plane",
    leaseCreated.status === 200 &&
      leaseCreated.j?.lease_state === "active" &&
      // ProjectionSubscriptionLease v1 returns an UNQUALIFIED display id by design. M05.9's evidence
      // ref is owner-qualified, so it is derived from the admitted route coordinates and the
      // response is checked to bind them — v1's own shape is recorded, never reinterpreted.
      leaseCreated.j?.lease_id === `subscription-lease://${LEASE_TAIL}` &&
      leaseCreated.j?.stream_id === `event-stream://${LEASE_NS}/ingest` &&
      LEASE.ref === `subscription-lease://${LEASE_NS}/${LEASE_TAIL}`,
    `status=${leaseCreated.status} state=${leaseCreated.j?.lease_state} display=${leaseCreated.j?.lease_id} stream=${leaseCreated.j?.stream_id} code=${code(leaseCreated.j)}`,
  );
  const census = await req("POST", CENSUSES, censusBody("m059-census-1", "acme.desk-corpus"));
  const cen = census.j?.media_corpus_census ?? {};
  ok(
    "H1 the compact lane's census is admitted and pins its own hours-scale NONCLAIM",
    census.status === 201 &&
      cen.claimed_scale === "compact_deterministic_fixture" &&
      cen.does_not_claim_hours_scale_qualification === true,
    `status=${census.status} nonclaim=${cen.does_not_claim_hours_scale_qualification} code=${code(census.j)} ${census.j?.error?.message ?? ""}`,
  );
  ok(
    "H2 the floors are pinned SERVER-SIDE at 7200s / 8 episodes / 2 Sessions, not taken from the caller",
    cen.floors?.accepted_seconds_after_deduplication === 7200 &&
      cen.floors?.bounded_episode_count === 8 &&
      cen.floors?.source_session_count === 2,
    `floors=${JSON.stringify(cen.floors)}`,
  );
  ok(
    "H3 no throughput or latency number is claimed by this contract",
    cen.does_not_claim_throughput_or_latency === true,
    `nonclaim=${cen.does_not_claim_throughput_or_latency}`,
  );
  ok(
    "H4 the census identity IS its corpus digest, so two runs over one corpus collide by construction",
    (cen.corpus_census_id ?? "").endsWith(cen.corpus_content_root?.replace("sha256:", "") ?? "x"),
    `id=${cen.corpus_census_id}`,
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "H5 a raw file with no disposition row is refused — the partition must close",
    "media_corpus_census_raw_file_without_a_disposition",
    () => {
      const body = censusBody("m059-census-short", "acme.desk-neg-corpus");
      body.raw.file_count += 1;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "H6 one source instance counted twice is refused as a padded or degenerate corpus",
    "media_corpus_census_repeated_source_identity_in_the_corpus",
    () => {
      const body = censusBody("m059-census-dup", "acme.desk-neg-corpus");
      body.file_dispositions[5].source_file_ref = body.file_dispositions[0].source_file_ref;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "H7 a required label class that was never observed is refused",
    "media_corpus_census_required_label_class_not_observed",
    () => {
      const body = censusBody("m059-census-label", "acme.desk-neg-corpus");
      body.observed_label_classes = [LABEL_CLICK, LABEL_SCROLL, LABEL_FIELD];
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "H8 deduplication that INCREASED accepted time is refused",
    "media_corpus_census_deduplication_increased_accepted_time",
    () => {
      const body = censusBody("m059-census-dedup", "acme.desk-neg-corpus");
      body.accepted.seconds_after_deduplication = body.accepted.seconds_before_deduplication + 120;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "H9 an hours-scale claim below the 7200-second floor is refused",
    "media_corpus_census_below_the_accepted_duration_floor",
    () => {
      const body = censusBody("m059-census-floor", "acme.desk-neg-corpus", { claimed_scale: "hours_scale_qualification" });
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "G6 an ingest queue that exceeded its declared bound is refused, never silently dropped",
    "media_corpus_census_queue_exceeded_its_declared_bound",
    () => {
      const body = censusBody("m059-census-queue", "acme.desk-neg-corpus");
      body.runtime_evidence.queue_high_water = 9999;
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "F1 a census whose pre- and post-restart roots differ is refused",
    "media_corpus_census_restart_equivalence_not_established",
    () => {
      const body = censusBody("m059-census-restart", "acme.desk-neg-corpus");
      body.runtime_evidence.restart_equivalence.post_restart_root = sha256("other-root");
      return req("POST", CENSUSES, body);
    },
  );

  // ================================= K · content addressing, deduplication and payload custody
  // THE CORRECTION THIS SECTION EXISTS FOR. The first version of this contract keyed distinctness on
  // `content_sha256`, which made two distinct source files with identical bytes REFUSABLE — so an
  // exact duplicate was unrepresentable and `exact_duplicate` was a label no corpus could earn. It
  // also let every payload fact be caller-supplied, so digest, byte count and fingerprint could only
  // ever be checked against each other. Both are closed below, against a live daemon.
  ok(
    "K1 an EXACT duplicate is admitted: two distinct source refs, one payload, one accepted instance",
    (() => {
      const rows = cen.file_dispositions ?? [];
      const counts = new Map();
      for (const row of rows) counts.set(row.content_sha256, (counts.get(row.content_sha256) ?? 0) + 1);
      const repeated = [...counts.entries()].filter(([, n]) => n > 1);
      if (repeated.length === 0) return false;
      return repeated.every(([digest]) => {
        const instances = rows.filter((row) => row.content_sha256 === digest);
        const accepted = instances.filter((row) => row.disposition === "accepted");
        const refs = new Set(instances.map((row) => row.source_file_ref));
        return accepted.length === 1 && refs.size === instances.length &&
          instances.every((row) => row.disposition === "accepted" ||
            (row.disposition === "deduplicated" && row.reason_class === "exact_duplicate"));
      });
    })(),
    `rows=${(cen.file_dispositions ?? []).length} payloads=${cen.distinct_content_hash_count}`,
  );
  ok(
    "K2 the distinct-payload count falls BELOW the raw file count, which is what deduplication looks like",
    typeof cen.distinct_content_hash_count === "number" &&
      cen.distinct_content_hash_count === (cen.distinct_payloads ?? []).length &&
      cen.distinct_content_hash_count < (cen.raw?.file_count ?? 0),
    `distinct=${cen.distinct_content_hash_count} raw_files=${cen.raw?.file_count}`,
  );
  ok(
    "K3 every declared payload digest and length is the digest and length of the bytes its recipe produces",
    (cen.distinct_payloads ?? []).length > 0 &&
      (cen.distinct_payloads ?? []).every((payload) => {
        const recipe = payload.payload_recipe ?? {};
        const bytes = payloadBytes(recipe.seed_tag, recipe.flipped_blocks ?? []);
        return sha256(bytes) === payload.content_sha256 &&
          bytes.length === payload.byte_count &&
          similarityFingerprint(bytes) === payload.similarity_fingerprint;
      }),
    `payloads=${(cen.distinct_payloads ?? []).length}`,
  );
  ok(
    "K4 the near-duplicate closure holds END TO END: refs resolve, bytes regenerate, distances recompute",
    (() => {
      const corpus = {
        file_dispositions: cen.file_dispositions ?? [],
        distinct_payloads: cen.distinct_payloads ?? [],
        near_duplicate_exclusions: cen.near_duplicate_exclusions ?? [],
        deduplication_policy: cen.deduplication_policy ?? {},
      };
      if (corpus.near_duplicate_exclusions.length === 0) return false;
      return nearDuplicateClosureFailures(corpus, corpusBytesResolver(corpus)).length === 0;
    })(),
    (() => {
      const corpus = {
        file_dispositions: cen.file_dispositions ?? [],
        distinct_payloads: cen.distinct_payloads ?? [],
        near_duplicate_exclusions: cen.near_duplicate_exclusions ?? [],
        deduplication_policy: cen.deduplication_policy ?? {},
      };
      const failures = nearDuplicateClosureFailures(corpus, corpusBytesResolver(corpus));
      return `exclusions=${corpus.near_duplicate_exclusions.length} failures=${failures.length}${failures.length ? ` first=${failures[0]}` : ""}`;
    })(),
  );
  ok(
    "K5 the census pins recipe-borne custody and claims NO custody of imported media bytes",
    cen.payload_custody === "deterministic_recipe" &&
      cen.does_not_claim_custody_of_imported_media_bytes === true,
    `custody=${cen.payload_custody} nonclaim=${cen.does_not_claim_custody_of_imported_media_bytes}`,
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K6 a payload digest that is not the digest of its own regenerated bytes is refused",
    "media_corpus_census_payload_digest_is_not_of_its_bytes",
    () => {
      const body = censusBody("m059-census-digest", "acme.desk-neg-corpus");
      body.distinct_payloads[0].content_sha256 = sha256("bytes-nobody-produced");
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K7 a payload byte count that is not the length of its own regenerated bytes is refused",
    "media_corpus_census_payload_byte_count_is_not_of_its_bytes",
    () => {
      const body = censusBody("m059-census-bytes", "acme.desk-neg-corpus");
      body.distinct_payloads[0].byte_count += 4096;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K8 a payload fingerprint that is not the fingerprint of its own regenerated bytes is refused",
    "media_corpus_census_payload_fingerprint_is_not_of_its_bytes",
    () => {
      const body = censusBody("m059-census-fp", "acme.desk-neg-corpus");
      body.distinct_payloads[0].similarity_fingerprint = "0123456789abcdef";
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K9 one payload accepted twice under two source refs is refused as padding",
    "media_corpus_census_repeated_payload_passes_as_distinct",
    () => {
      const body = censusBody("m059-census-twice", "acme.desk-neg-corpus");
      const repeat = body.file_dispositions.find((row) => row.reason_class === "exact_duplicate");
      repeat.disposition = "accepted";
      repeat.reason_class = null;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K10 a near-duplicate exclusion whose declared distance is not the recomputed one is refused",
    "media_corpus_census_near_duplicate_distance_was_not_recomputed",
    () => {
      const body = censusBody("m059-census-dist", "acme.desk-neg-corpus");
      body.near_duplicate_exclusions[0].distance += 1;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K11 a substituted SOURCE fingerprint is refused — the row does not choose the number it is judged on",
    "media_corpus_census_near_duplicate_source_fingerprint_substituted",
    () => {
      const body = censusBody("m059-census-srcfp", "acme.desk-neg-corpus");
      body.near_duplicate_exclusions[0].similarity_fingerprint = "fedcba9876543210";
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K12 a substituted RETAINED fingerprint is refused, independently of the source one",
    "media_corpus_census_near_duplicate_retained_fingerprint_substituted",
    () => {
      const body = censusBody("m059-census-retfp", "acme.desk-neg-corpus");
      body.near_duplicate_exclusions[0].retained_similarity_fingerprint = "fedcba9876543210";
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K13 a retained sibling this corpus never accepted is refused",
    "media_corpus_census_near_duplicate_retains_no_accepted_sibling",
    () => {
      const body = censusBody("m059-census-sibling", "acme.desk-neg-corpus");
      const rejectedRow = body.file_dispositions.find((row) => row.disposition === "rejected");
      body.near_duplicate_exclusions[0].retained_source_file_ref = rejectedRow.source_file_ref;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K14 an exclusion over a row not filed as a near duplicate is refused",
    "media_corpus_census_near_duplicate_source_is_not_filed_as_one",
    () => {
      const body = censusBody("m059-census-disp", "acme.desk-neg-corpus");
      const target = body.near_duplicate_exclusions[0].source_file_ref;
      const row = body.file_dispositions.find((r) => r.source_file_ref === target);
      row.reason_class = "exact_duplicate";
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K15 a corpus root that does not commit its own rows is refused",
    "media_corpus_census_corpus_content_root_does_not_commit_the_rows",
    () => {
      const body = censusBody("m059-census-root", "acme.desk-neg-corpus");
      body.file_dispositions[3].source_seconds += 30;
      // DELIBERATELY NOT re-rooted: the rows moved and the root stayed behind.
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K16 a raw byte count that does not sum its own rows is refused",
    "media_corpus_census_raw_bytes_do_not_close_over_the_rows",
    () => {
      const body = censusBody("m059-census-rawbytes", "acme.desk-neg-corpus");
      body.raw.byte_count += 1;
      return reroot(body) && req("POST", CENSUSES, body);
    },
  );
  // The other half of "pinned server-side": the pin is DERIVED correctly (H2), and a caller that
  // tries to author it is refused by name before the derivation is even reached (H10). Each half
  // needs its own assertion, or a mutation on either is unkillable because the other covers it.
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "H10 a caller-authored floor or hours-scale nonclaim is refused by name (INV-37)",
    "media_corpus_census_caller_authored_evidence_refused",
    () => {
      const body = censusBody("m059-census-authored", "acme.desk-neg-corpus");
      body.floors = { accepted_seconds_after_deduplication: 60, bounded_episode_count: 1, source_session_count: 1 };
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K17 backpressure evidence for a lease nobody admitted is refused",
    "media_corpus_census_subscription_lease_not_admitted",
    () => {
      const body = censusBody("m059-census-fakelease", "acme.desk-neg-corpus");
      body.runtime_evidence.projection_subscription_lease_ref = `subscription-lease://${LEASE_NS}/sub_never_created`;
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K18 a declared window that is not the LEASE'S OWN admitted bound is refused",
    "media_corpus_census_backpressure_window_is_not_the_leases_own",
    () => {
      const body = censusBody("m059-census-window", "acme.desk-neg-corpus");
      body.runtime_evidence.max_undelivered_events_declared = LEASE.window * 2;
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K19 a lease ref this route cannot resolve at all is refused by name",
    "media_corpus_census_subscription_lease_ref_not_canonical",
    () => {
      const body = censusBody("m059-census-leaseshape", "acme.desk-neg-corpus");
      body.runtime_evidence.projection_subscription_lease_ref = "projection-subscription-lease://acme/1";
      return req("POST", CENSUSES, body);
    },
  );
  await refusesWithoutAppending(
    CENSUSES,
    "acme.desk-neg-corpus",
    "K20 a census that reports no durability class is refused rather than defaulted",
    "media_corpus_census_durability_class_not_reported",
    () => {
      const body = censusBody("m059-census-durability", "acme.desk-neg-corpus");
      delete body.runtime_evidence.durability_class_achieved;
      return req("POST", CENSUSES, body);
    },
  );

  // ============================================================ I · retention and erasure impact
  const impact = await req(
    "GET",
    `${IMPACT}?snapshot_revision_ref=${encodeURIComponent(snapshot.revision_ref)}&episode_family=acme.desk-members&split_family=acme.desk-split`,
  );
  ok(
    "I1 erasure produces an IMPACT GRAPH over dependents without rewriting historical evidence",
    impact.status === 200 &&
      (impact.j?.affected_episode_revision_refs ?? []).length === 6 &&
      (impact.j?.affected_split_manifest_revision_refs ?? []).length === 1 &&
      impact.j?.historical_evidence_rewritten === false,
    `episodes=${(impact.j?.affected_episode_revision_refs ?? []).length} splits=${(impact.j?.affected_split_manifest_revision_refs ?? []).length}`,
  );
  ok(
    "I2 the impact is a governed rebuild/withdrawal DECISION, not a deletion this module performs",
    impact.j?.decision_class === "governed_rebuild_or_withdrawal_required" &&
      impact.j?.impact_is_a_decision_not_a_deletion === true,
    `decision=${impact.j?.decision_class}`,
  );
  const retention = await req("POST", "/v1/hypervisor/retention-dispositions", {
    owner_ref: OWNER,
    idempotency_key: "m059-retention",
    subject_kind: "policy_bound_media_snapshot",
    subject_ref: snapshot.revision_ref,
  });
  ok(
    "I3 a media corpus is a THIRD retention subject kind on the existing plane, not a second plane",
    retention.status !== 400 || !code(retention.j).includes("subject_kind_unsupported"),
    `status=${retention.status} code=${code(retention.j)}`,
  );

  // ============================================================ F · restart, rebuild, replay
  const beforeRestart = {
    snapshot: (await req("GET", `${SNAPS}?family=acme.desk`)).j,
    episodes: (await req("GET", `${EPISODES}?family=acme.desk-members`)).j,
    splits: (await req("GET", `${SPLITS}?family=acme.desk-split`)).j,
    censuses: (await req("GET", `${CENSUSES}?family=acme.desk-corpus`)).j,
  };
  await stopDaemon();
  // DELETE THE READ INDEX so the rebuild is POSITIVELY DETECTED. If no per-family directory exists,
  // that is itself the finding: the chain is the only copy, which is what this unit claims.
  const familyDirs = [
    "media-snapshot-revisions",
    "observation-action-episode-revisions",
    "dataset-split-manifest-revisions",
    "media-corpus-censuses",
  ];
  const present = familyDirs.filter((kind) => fs.existsSync(path.join(lane.dataDir, kind)));
  for (const kind of present) fs.rmSync(path.join(lane.dataDir, kind), { recursive: true, force: true });
  await startDaemon();
  await lane.login(boot.email, OWNER_PASSWORD);
  const afterRestart = {
    snapshot: (await req("GET", `${SNAPS}?family=acme.desk`)).j,
    episodes: (await req("GET", `${EPISODES}?family=acme.desk-members`)).j,
    splits: (await req("GET", `${SPLITS}?family=acme.desk-split`)).j,
    censuses: (await req("GET", `${CENSUSES}?family=acme.desk-corpus`)).j,
  };
  ok(
    "F2 every family replays BYTE-IDENTICALLY across a real process restart",
    canonicalJson(beforeRestart.snapshot?.revisions) ===
      canonicalJson(afterRestart.snapshot?.revisions) &&
      canonicalJson(beforeRestart.episodes?.revisions) ===
        canonicalJson(afterRestart.episodes?.revisions) &&
      canonicalJson(beforeRestart.splits?.revisions) ===
        canonicalJson(afterRestart.splits?.revisions) &&
      canonicalJson(beforeRestart.censuses?.revisions) ===
        canonicalJson(afterRestart.censuses?.revisions) &&
      (afterRestart.snapshot?.revisions ?? []).length > 0 &&
      (afterRestart.episodes?.revisions ?? []).length > 0,
    `families=4 index_dirs_deleted=${present.length} snapshots=${(afterRestart.snapshot?.revisions ?? []).length} episodes=${(afterRestart.episodes?.revisions ?? []).length}`,
  );
  ok(
    "F3 the answer after restart is rebuilt from the chain rather than served from a surviving index",
    (afterRestart.snapshot?.revisions ?? []).length > 0,
    `index_state=${afterRestart.snapshot?.index_state ?? "n/a"} deleted=${present.join(",") || "none existed — the chain is the only copy"}`,
  );

  // ============================================================ J · nonclaims, checked
  const served = (afterRestart.snapshot?.revisions ?? [])[0] ?? {};
  ok(
    "J1 the snapshot carries its authority and ArtifactRef-passivity nonclaims",
    served.authority_nonclaim === "policy_bound_media_snapshot_grants_no_authority" &&
      (served.artifact_authority ?? "").startsWith("none —"),
    `authority=${served.authority_nonclaim}`,
  );
  ok(
    "J2 capture authority does not travel into replay, and a demonstration is not consent",
    served.capture_authority_does_not_travel_into_replay === true &&
      served.demonstration_is_not_consent === true &&
      served.snapshot_is_not_a_skill_or_workflow === true,
    "three nonclaims present",
  );
  const moduleSource = fs.readFileSync(
    path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/media_trajectory_dataset_routes.rs"),
    "utf8",
  );
  ok(
    "J3 this module mints no agentgres://, receipt:// or commitment:// string at a call site",
    !/format!\(\s*"(agentgres|receipt|commitment):\/\//u.test(moduleSource),
    "no format!-minted Agentgres scheme in the module source",
  );
  ok(
    "J4 this module admits no work-lifecycle, frontier, claim, attempt or contribution state (INV-35/INV-31)",
    !/work_frontier|work_claim|attempt_finding|work_result|contribution/u.test(
      moduleSource
        .split("\n")
        .filter((line) => !line.trimStart().startsWith("//"))
        .join("\n"),
    ),
    "no work-plane writer in the module source (comments excluded — prose naming a ref is not behaviour)",
  );
  const surfaceRoots = [
    "packages/wallet-protocol/openapi",
    "packages/agent-sdk/src",
    "packages/wallet-sdk/src",
    "crates/cli/src",
    "crates/services/src/agentic/runtime/tools",
    "crates/drivers/src/mcp",
  ];
  const claimers = [];
  for (const rel of surfaceRoots) {
    const base = path.join(ROOT, rel);
    if (!fs.existsSync(base)) continue;
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (/\.(ts|rs|json|yaml|yml)$/u.test(entry.name)) {
          const text = fs.readFileSync(full, "utf8");
          if (/media-snapshot:\/\/|episode:\/\/|split-manifest:\/\/|corpus-census:\/\//u.test(text)) {
            claimers.push(path.relative(ROOT, full));
          }
        }
      }
    };
    walk(base);
  }
  ok(
    "J5 zero OpenAPI/SDK/CLI/MCP surface claims these four families, so no representation is owed (G-4)",
    claimers.length === 0,
    claimers.length ? `claimed by ${claimers.join(", ")}` : "no surface claims the families",
  );
}

// ================================================================================= mutation battery

const MODULE = "crates/node/src/bin/hypervisor_daemon_routes/media_trajectory_dataset_routes.rs";

const MUTANTS = [
  {
    id: "video-inferred-label-becomes-ground-truth",
    source: MODULE,
    from: `        if INFERRED_LABEL_PROVENANCE.contains(&provenance.as_str()) {
            if claims_ground_truth {`,
    to: `        if INFERRED_LABEL_PROVENANCE.contains(&provenance.as_str()) {
            if false {`,
    reddens: "D4 a video-inferred label claiming controller ground truth is REFUSED BY NAME",
  },
  {
    id: "epistemic-status-defaults-instead-of-refusing",
    source: MODULE,
    from: `            if status != "uncertain_attributed_label" {`,
    to: `            if false && status != "uncertain_attributed_label" {`,
    reddens: "D5 a video-inferred label claiming a certain epistemic status is refused rather than defaulted",
  },
  {
    id: "ground-truth-set-is-accepted-from-the-caller",
    source: MODULE,
    from: `        "ground_truth_eligible_label_refs": controller_recorded,`,
    to: `        "ground_truth_eligible_label_refs": string_list(&body, "ground_truth_eligible_label_refs"),`,
    reddens: "D2 the ground-truth-eligible set is DERIVED from the controller-recorded subset, not authored",
  },
  {
    id: "operator-annotation-may-claim-ground-truth",
    source: MODULE,
    from: `            if provenance != CONTROLLER_RECORDED {`,
    to: `            if false && provenance != CONTROLLER_RECORDED {`,
    reddens: "D6 ground truth claimed from an operator annotation is refused — only a controller stream supports it",
  },
  {
    id: "episode-inherits-a-different-timebase",
    source: MODULE,
    from: `    if episode_timebase != snapshot.timebase_id() {`,
    to: `    if false && episode_timebase != snapshot.timebase_id() {`,
    reddens: "C4 an episode whose timebase differs from its snapshot's is refused",
  },
  {
    id: "timebase-discontinuity-is-normalized-away",
    source: MODULE,
    from: `        == Some(true)
    {
        return refuse(
            &spec.code("discontinuity_normalization_refused"),`,
    to: `        == Some(false)
    {
        return refuse(
            &spec.code("discontinuity_normalization_refused"),`,
    reddens: "C2 a caller asking for discontinuities to be normalized away is refused",
  },
  {
    id: "non-monotonic-timebase-is-accepted",
    source: MODULE,
    from: `    if timebase.get("declared_monotonic").and_then(Value::as_bool) != Some(true) {`,
    to: `    if false {`,
    reddens: "C3 a timebase declared non-monotonic is refused rather than repaired",
  },
  {
    id: "observed-skew-envelope-is-not-compared",
    source: MODULE,
    from: `    if observed > envelope {`,
    to: `    if false && observed > envelope {`,
    reddens: "C5 observed frame/action skew beyond the declared envelope is refused, never absorbed",
  },
  {
    id: "snapshot-content-hash-drift-is-tolerated",
    source: MODULE,
    from: `    if !asserted_hash.is_empty() && asserted_hash != snapshot.content_hash {`,
    to: `    if false {`,
    reddens: "C6 a snapshot content hash that drifted from what its owner serves is refused",
  },
  {
    id: "corrupt-input-is-absorbed-instead-of-refused",
    source: MODULE,
    from: `        if NEVER_RETAINED_FINDINGS.contains(&class.as_str())
            && !REFUSING_SEVERITIES.contains(&severity.as_str())
        {`,
    to: `        if false {`,
    reddens: "G1 a corrupt chunk retained instead of refused is refused BY NAME",
  },
  {
    id: "repeated-artifact-digest-passes-the-distinctness-check",
    source: MODULE,
    // The insert is KEPT and its answer discarded. Replacing the whole condition with `false` would
    // leave `BTreeSet::new()` with no insert to infer its element type from, and the mutant would
    // fail to compile — scoring a MISS that proves nothing about the gate.
    from: `        if !seen_digests.insert(digest.clone()) {`,
    to: `        if { seen_digests.insert(digest.clone()); false } {`,
    reddens: "G4 a repeated artifact digest inside one snapshot is refused as a degenerate corpus",
  },
  {
    id: "accepted-census-may-exceed-raw",
    source: MODULE,
    from: `        if accepted > raw {`,
    to: `        if false && accepted > raw {`,
    reddens: "G5 an accepted census larger than the raw census it came from is refused",
  },
  {
    id: "capture-rights-liveness-is-not-checked",
    source: MODULE,
    from: `    if !capture_claim.is_live() || capture_claim.expires_before(recorded_at_ms) {`,
    to: `    if false {`,
    reddens: "B3 a capture-rights claim whose window closed at the admission instant refuses the snapshot",
  },
  {
    id: "permits-learned-use-is-not-derived-from-the-resolved-claims",
    source: MODULE,
    // The value is FORCED, not made caller-overridable. An override mutant reading `body` is
    // unobservable here: `permits_learned_use` is on the server-resolved list, so `reject_authored`
    // refuses any request that supplies it long before this line runs — the mutant would be
    // unkillable by construction, and an unkillable mutant is not evidence about the gate.
    from: `            "permits_learned_use": permits_learned_use,`,
    to: `            "permits_learned_use": true,`,
    reddens: "B1 permits_learned_use is DERIVED from the resolved claims, never taken from the caller",
  },
  {
    id: "the-view-ref-is-shape-checked-instead-of-owner-resolved",
    source: MODULE,
    // The resolution loop is skipped entirely, so a `view://` string is accepted as a well-formed
    // ref rather than resolved through M05.8's owner seam. This mutation COMPILES, which is the
    // point: a mutant that fails to build scores as a MISS and proves nothing about the gate.
    from: `    for view_ref in &view_refs {`,
    to: `    for view_ref in &Vec::<String>::new() {`,
    reddens: "B5 a policy-bound view ref that no owner can resolve refuses before any byte is bound",
  },
  {
    id: "redaction-may-create-permission",
    source: MODULE,
    from: `    if redaction.get("creates_permission").and_then(Value::as_bool) == Some(true) {`,
    to: `    if false {`,
    reddens: "B7 redaction that claims to create permission is refused BY NAME, not corrected underneath the caller",
  },
  {
    id: "redaction-output-class-may-fall-below-the-source-class",
    source: MODULE,
    from: `    if item_str(&redaction, "source_privacy_class") != item_str(&redaction, "output_privacy_class")
    {`,
    to: `    if false
    {`,
    reddens: "B8 redaction that lowers the output privacy class below its source is refused as a declassification",
  },
  {
    id: "split-membership-drops-the-double-membership-check",
    source: MODULE,
    from: `        if !seen_members.insert(episode_ref.clone()) {`,
    to: `        if { seen_members.insert(episode_ref.clone()); false } {`,
    reddens: "E2 an episode assigned to two splits is refused as double membership",
  },
  {
    id: "temporal-cut-comparison-is-inverted",
    source: MODULE,
    from: `    if max_train >= cut {`,
    to: `    if max_train < cut {`,
    reddens: "E3 training that crosses the temporal cut is refused as future-frame leakage",
  },
  {
    id: "temporal-holdout-fence-is-dropped",
    source: MODULE,
    from: `    if cut > min_holdout {`,
    to: `    if false && cut > min_holdout {`,
    reddens: "E4 a temporal holdout that begins before the cut is refused",
  },
  {
    id: "actor-holdout-overlap-is-tolerated",
    source: MODULE,
    from: `    if let Some(shared) = train_actors.intersection(&holdout_actors).next() {`,
    to: `    if let Some(shared) = train_actors.intersection(&BTreeSet::new()).next() {`,
    reddens: "E5 an actor holdout sharing an actor with training is refused",
  },
  {
    id: "world-holdout-overlap-is-tolerated",
    source: MODULE,
    from: `    if let Some(shared) = train_worlds.intersection(&holdout_worlds).next() {`,
    to: `    if let Some(shared) = train_worlds.intersection(&BTreeSet::new()).next() {`,
    reddens: "E6 a world holdout sharing a world with training is refused",
  },
  {
    id: "member-content-hash-drift-is-tolerated",
    source: MODULE,
    from: `        if !asserted.is_empty() && asserted != episode.content_hash {`,
    to: `        if false {`,
    reddens: "E7 a member episode whose bytes drifted since membership was computed is refused",
  },
  {
    id: "the-disposition-partition-check-is-suppressed",
    source: MODULE,
    from: `    if item_u64(&raw, "file_count") != Some(file_dispositions.len() as u64) {`,
    to: `    if false {`,
    reddens: "H5 a raw file with no disposition row is refused — the partition must close",
  },
  {
    id: "a-repeated-source-identity-passes-the-distinctness-check",
    source: MODULE,
    from: `        if !seen_sources.insert(source_ref.clone()) {`,
    to: `        if { seen_sources.insert(source_ref.clone()); false } {`,
    reddens: "H6 one source instance counted twice is refused as a padded or degenerate corpus",
  },
  {
    id: "the-payload-digest-is-believed-instead-of-derived",
    source: MODULE,
    from: `        if derived_digest != digest {`,
    to: `        if false && derived_digest != digest {`,
    reddens: "K6 a payload digest that is not the digest of its own regenerated bytes is refused",
  },
  {
    id: "the-payload-byte-count-is-believed-instead-of-measured",
    source: MODULE,
    from: `        if item_u64(payload, "byte_count") != Some(bytes.len() as u64) {`,
    to: `        if false {`,
    reddens: "K7 a payload byte count that is not the length of its own regenerated bytes is refused",
  },
  {
    id: "the-payload-fingerprint-is-believed-instead-of-recomputed",
    source: MODULE,
    from: `        if item_str(payload, "similarity_fingerprint") != derived_fingerprint {`,
    to: `        if false {`,
    reddens: "K8 a payload fingerprint that is not the fingerprint of its own regenerated bytes is refused",
  },
  {
    id: "a-repeat-of-an-accepted-payload-need-not-be-an-exact-duplicate",
    source: MODULE,
    // This is now the ONLY place a second accepted copy of one payload is refused. It used to sit
    // behind a redundant `accepted_here.len() > 1` guard that refused the same inputs under the same
    // code, which made each of the two unkillable: disabling either left the other to keep the gate
    // green. The guard was removed rather than the mutant weakened.
    from: `                if item_str(row, "disposition") != "deduplicated"
                    || item_str(row, "reason_class") != "exact_duplicate"
                {`,
    to: `                if false {`,
    reddens: "K9 one payload accepted twice under two source refs is refused as padding",
  },
  {
    id: "the-near-duplicate-distance-is-read-instead-of-recomputed",
    source: MODULE,
    from: `        if item_u64(exclusion, "distance") != Some(distance) {`,
    to: `        if false {`,
    reddens: "K10 a near-duplicate exclusion whose declared distance is not the recomputed one is refused",
  },
  {
    id: "the-source-fingerprint-may-be-substituted",
    source: MODULE,
    from: `        if item_str(exclusion, "similarity_fingerprint") != source_fingerprint {`,
    to: `        if false {`,
    reddens: "K11 a substituted SOURCE fingerprint is refused — the row does not choose the number it is judged on",
  },
  {
    id: "the-retained-fingerprint-may-be-substituted",
    source: MODULE,
    from: `        if item_str(exclusion, "retained_similarity_fingerprint") != retained_fingerprint {`,
    to: `        if false {`,
    reddens: "K12 a substituted RETAINED fingerprint is refused, independently of the source one",
  },
  {
    id: "the-retained-sibling-is-not-resolved-to-an-accepted-row",
    source: MODULE,
    from: `        if item_str(retained_row, "disposition") != "accepted" {`,
    to: `        if false {`,
    reddens: "K13 a retained sibling this corpus never accepted is refused",
  },
  {
    id: "the-excluded-row-need-not-be-filed-as-a-near-duplicate",
    source: MODULE,
    from: `        if item_str(source_row, "disposition") != "deduplicated"
            || item_str(source_row, "reason_class") != "near_duplicate"
        {`,
    to: `        if false {`,
    reddens: "K14 an exclusion over a row not filed as a near duplicate is refused",
  },
  {
    id: "the-corpus-root-is-accepted-instead-of-recomputed",
    source: MODULE,
    from: `    if corpus_content_root != recomputed_root {`,
    to: `    if false {`,
    reddens: "K15 a corpus root that does not commit its own rows is refused",
  },
  {
    id: "the-raw-byte-count-is-not-summed-over-the-rows",
    source: MODULE,
    from: `    if item_u64(&raw, "byte_count") != Some(row_bytes) {`,
    to: `    if false {`,
    reddens: "K16 a raw byte count that does not sum its own rows is refused",
  },
  {
    id: "the-subscription-lease-is-named-instead-of-resolved",
    source: MODULE,
    // An absent lease stops refusing and simply adopts whatever window the caller declared, which
    // is exactly the defect the resolution exists to close: evidence for a lease nobody created.
    from: `        Ok(None) => {
            return refuse(
                &spec.code("subscription_lease_not_admitted"),
                format!("{lease_ref} names no admitted subscription lease; BACKPRESSURE EVIDENCE FOR A LEASE NOBODY CREATED IS A NARRATION OF A SOAK, NOT THE RECORD OF ONE"),
            );
        }`,
    to: `        Ok(None) => declared_bound,`,
    reddens: "K17 backpressure evidence for a lease nobody admitted is refused",
  },
  {
    id: "the-lease-ref-shape-is-not-pinned-to-the-subscription-plane",
    source: MODULE,
    from: `        .strip_prefix("subscription-lease://")`,
    to: `        .strip_prefix("projection-subscription-lease://")`,
    reddens: "K19 a lease ref this route cannot resolve at all is refused by name",
  },
  {
    id: "the-backpressure-window-may-differ-from-the-leases-own",
    source: MODULE,
    from: `    if declared_bound != leased_window {`,
    to: `    if false {`,
    reddens: "K18 a declared window that is not the LEASE'S OWN admitted bound is refused",
  },
  {
    id: "the-durability-class-may-go-unreported",
    source: MODULE,
    from: `        .is_none()
    {
        return refuse(
            &spec.code("durability_class_not_reported"),`,
    to: `        .is_none()
        && false
    {
        return refuse(
            &spec.code("durability_class_not_reported"),`,
    reddens: "K20 a census that reports no durability class is refused rather than defaulted",
  },
  {
    id: "required-label-coverage-is-skipped",
    source: MODULE,
    from: `    if let Some(missing) = required_classes.difference(&observed_classes).next() {`,
    to: `    if let Some(missing) = required_classes.difference(&required_classes).next() {`,
    reddens: "H7 a required label class that was never observed is refused",
  },
  {
    id: "deduplication-may-increase-accepted-time",
    source: MODULE,
    from: `    if after > before {`,
    to: `    if false && after > before {`,
    reddens: "H8 deduplication that INCREASED accepted time is refused",
  },
  {
    id: "the-hours-scale-duration-floor-is-lowered",
    source: MODULE,
    from: `        if after < 7200 {`,
    to: `        if after < 60 {`,
    reddens: "H9 an hours-scale claim below the 7200-second floor is refused",
  },
  {
    id: "the-compact-lane-drops-its-hours-scale-nonclaim",
    source: MODULE,
    // The derivation is INVERTED rather than made caller-overridable: `reject_authored` already
    // refuses a body that supplies this field, so an override mutant could never be observed.
    from: `        "does_not_claim_hours_scale_qualification": !hours_scale,`,
    to: `        "does_not_claim_hours_scale_qualification": hours_scale,`,
    reddens: "H1 the compact lane's census is admitted and pins its own hours-scale NONCLAIM",
  },
  {
    id: "a-caller-may-author-the-censuss-server-resolved-evidence",
    source: MODULE,
    from: `    if let Err(response) = reject_authored(&body, spec, CENSUS_SERVER_RESOLVED) {`,
    to: `    if let Err(response) = reject_authored(&body, spec, &[]) {`,
    reddens: "H10 a caller-authored floor or hours-scale nonclaim is refused by name (INV-37)",
  },
  {
    id: "the-recorded-floor-is-not-the-pinned-one",
    source: MODULE,
    // The RECORDED pin is lowered. Reading it from `body` instead would be unobservable: `floors` is
    // server-resolved, so `reject_authored` refuses any request carrying it before this line runs.
    from: `        "floors": {
            "accepted_seconds_after_deduplication": 7200,`,
    to: `        "floors": {
            "accepted_seconds_after_deduplication": 3600,`,
    reddens: "H2 the floors are pinned SERVER-SIDE at 7200s / 8 episodes / 2 Sessions, not taken from the caller",
  },
  {
    id: "backpressure-bound-is-not-enforced",
    source: MODULE,
    from: `    if high_water > declared_bound {`,
    to: `    if false && high_water > declared_bound {`,
    reddens: "G6 an ingest queue that exceeded its declared bound is refused, never silently dropped",
  },
  {
    id: "restart-equivalence-compares-nothing",
    source: MODULE,
    from: `    if pre.is_empty() || pre != post {`,
    to: `    if false {`,
    reddens: "F1 a census whose pre- and post-restart roots differ is refused",
  },
  {
    id: "erasure-rewrites-history-instead-of-emitting-an-impact-graph",
    source: MODULE,
    from: `            "historical_evidence_rewritten": false,`,
    to: `            "historical_evidence_rewritten": true,`,
    reddens: "I1 erasure produces an IMPACT GRAPH over dependents without rewriting historical evidence",
  },
  {
    id: "artifact-passivity-nonclaim-is-dropped",
    source: MODULE,
    from: `        "artifact_authority": "none — an active ArtifactRef names bytes and grants no read, no replay, no current authority",`,
    to: `        "artifact_authority": "active — the ArtifactRef is current and readable",`,
    reddens: "J1 the snapshot carries its authority and ArtifactRef-passivity nonclaims",
  },
  {
    id: "capture-authority-travels-into-replay",
    source: MODULE,
    from: `        "capture_authority_does_not_travel_into_replay": true,`,
    to: `        "capture_authority_does_not_travel_into_replay": false,`,
    reddens: "J2 capture authority does not travel into replay, and a demonstration is not consent",
  },
  {
    id: "the-episode-session-is-taken-from-the-caller",
    source: MODULE,
    from: `        "session_ref": session_ref,`,
    to: `        "session_ref": body_str(&body, "session_ref"),`,
    reddens: "D1 an episode is admitted and inherits its snapshot's session and timebase",
  },
];

function mutantPath(mutant) {
  return path.join(ROOT, mutant.source);
}

function anchorReport() {
  const rows = [];
  for (const mutant of MUTANTS) {
    const file = mutantPath(mutant);
    if (!fs.existsSync(file)) {
      rows.push({ id: mutant.id, state: "SOURCE_MISSING", occurrences: 0 });
      continue;
    }
    const text = fs.readFileSync(file, "utf8");
    const occurrences = text.split(mutant.from).length - 1;
    rows.push({ id: mutant.id, state: occurrences === 1 ? "OK" : occurrences === 0 ? "ANCHOR_LOST" : "AMBIGUOUS", occurrences });
  }
  return rows;
}

/** Byte-restore every mutant anchor, whether or not this process planted it. */
function restoreAll() {
  let restored = 0;
  for (const mutant of MUTANTS) {
    const file = mutantPath(mutant);
    if (!fs.existsSync(file)) continue;
    const text = fs.readFileSync(file, "utf8");
    if (text.includes(mutant.to) && !text.includes(mutant.from)) {
      fs.writeFileSync(file, text.split(mutant.to).join(mutant.from));
      restored += 1;
    }
  }
  return restored;
}

async function runMutationBattery(selected) {
  // RESTORE HANDLERS FIRST. A killed battery otherwise leaves planted defects in the tree, and a
  // deletion mutant makes its own `from` block STALE so grep will never find it — only --anchors will.
  const restoreHandler = () => {
    restoreAll();
    process.exit(130);
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, restoreHandler);

  let onTarget = 0;
  const rows = [];
  for (const mutant of selected) {
    const file = mutantPath(mutant);
    const original = fs.readFileSync(file, "utf8");
    const occurrences = original.split(mutant.from).length - 1;
    if (occurrences !== 1) {
      rows.push({ id: mutant.id, verdict: "ANCHOR_LOST", detail: `${occurrences} occurrences` });
      continue;
    }
    fs.writeFileSync(file, original.replace(mutant.from, mutant.to));
    let verdict = "MISS";
    let detail = "";
    try {
      // A BUILD FAILURE IS A MISS, NEVER A PASS.
      rebuildDaemon();
      const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url)], {
        cwd: ROOT,
        encoding: "utf8",
        env: { ...process.env },
        maxBuffer: 64 * 1024 * 1024,
      });
      const output = `${child.stdout ?? ""}${child.stderr ?? ""}`;
      if (output.includes(`FAIL  ${mutant.reddens}`)) {
        verdict = "ON_TARGET";
        onTarget += 1;
      } else if (child.status !== 0) {
        verdict = "RED_ELSEWHERE";
        detail = "gate failed, but not on the named assertion";
      }
    } catch (error) {
      detail = String(error).slice(0, 200);
    } finally {
      fs.writeFileSync(file, original);
    }
    rows.push({ id: mutant.id, verdict, detail });
    console.log(`${verdict === "ON_TARGET" ? "ok  " : "FAIL"}  ${mutant.id} — ${verdict}${detail ? ` (${detail})` : ""}`);
  }
  rebuildDaemon();
  console.log(`\nmutation battery ${onTarget}/${selected.length} on target`);
  return onTarget === selected.length ? 0 : 1;
}

// ================================================================================= dispatch

// THE ZERO-BUILD MODES DISPATCH FIRST, before anything needs a binary.
if (ANCHORS) {
  const rows = anchorReport();
  for (const row of rows) console.log(`${row.state === "OK" ? "ok  " : "FAIL"}  ${row.id} — ${row.state} (${row.occurrences})`);
  const bad = rows.filter((row) => row.state !== "OK").length;
  console.log(`\nanchors ${rows.length - bad}/${rows.length} resolvable`);
  process.exit(bad === 0 ? 0 : 1);
}
if (SUMMARIZE) {
  console.log(`M05.9 mutation battery — ${MUTANTS.length} planted defects across 1 module`);
  for (const mutant of MUTANTS) console.log(`  ${mutant.id}\n      reddens: ${mutant.reddens}`);
  process.exit(0);
}
if (RESTORE) {
  const restored = restoreAll();
  console.log(`restored ${restored} planted mutant(s)`);
  process.exit(0);
}

// Resolved through the shared lane, which REFUSES a binary outside this worktree rather than
// silently verifying another checkout's daemon.
const DAEMON_BINARY = resolveDaemonBinary(ROOT);
if (!fs.existsSync(DAEMON_BINARY)) {
  console.error(`daemon binary not found at ${DAEMON_BINARY} — run: cargo build -p ioi-node --bin hypervisor-daemon`);
  process.exit(2);
}

if (MUTATE) {
  const selected = ONLY.length ? MUTANTS.filter((m) => ONLY.includes(m.id)) : MUTANTS;
  if (!selected.length) {
    console.error(`--only matched no mutant id`);
    process.exit(2);
  }
  process.exit(await runMutationBattery(selected));
}

try {
  await run();
} catch (error) {
  ok("the gate ran to completion", false, String(error).slice(0, 500));
} finally {
  await stopDaemon();
}

for (const result of results) {
  console.log(`${result.pass ? "ok  " : "FAIL"}  ${result.name}${result.detail ? `  (${result.detail})` : ""}`);
}
const passed = results.filter((r) => r.pass).length;
console.log(`\n${passed}/${results.length} passed`);
emitVerifierCensus({ verifierId: "policy-bound-media-datasets", sourceUrl: import.meta.url, results });
process.exit(passed === results.length && results.length > 0 ? 0 : 1);
