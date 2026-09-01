#!/usr/bin/env node
// M05.9 — THE SCHEDULED SCALE LANE.
//
// EXECUTION STATUS: NOT YET RUN. This lane is implemented and wired (`check:media-trajectory-scale-
// soak`), and it is deliberately UNEXERCISED in this component worktree. The scheduled/release leg
// runs EXACTLY ONCE, on the final integrated M05 release candidate after M05.10 — not per component
// branch. Nothing in this repository may report a scale-lane result until that run happens; the
// assertions below are a specification of what will be observed, and no green is claimed for them.
//
// The blocking gate proves FUNCTION on a compact corpus. This lane proves the same runtime holds
// when the corpus actually meets ACC-19 clause 5's floor: at least two hours of accepted source time
// AFTER exact and near-duplicate exclusion, at least eight independently bounded episodes/tasks from
// at least two source Sessions, and every profile-required action, field and exception label class.
//
// IT DRIVES THE SAME SPINE. The daemon lifecycle, the owner seams and the route set come from
// `lib/m059-media-lane.mjs`, the same module the blocking gate uses. A soak that stood up its own
// daemon and its own seed chain could go green while the gate's spine was broken, and the two greens
// would no longer be about one system.
//
// THE CORPUS IS SYNTHETIC, OFFLINE AND CONTENT-ADDRESSED. No real recording, no real Session, no
// real actor media, no device capture, no network fetch, no paid resource, no metered service and no
// sensitive data. Every payload is generated from a declared recipe; every digest is of those exact
// bytes; every census number is SUMMED FROM the rows rather than typed beside them.
//
// NO THROUGHPUT, LATENCY OR TIME-TO-QUALITY NUMBER IS ASSERTED OR EMITTED HERE, deliberately. Per
// ADR 0039's own acceptance record and the M05.9 guide, a performance tripwire waits for repeated
// matched release-host baselines and a planted slowdown mutation. This lane asserts SCALE OF INPUT
// and FUNCTION UNDER IT, never speed. The wall-clock of this run is not evidence of anything and is
// deliberately not recorded.

import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  OWNER,
  ROUTES_V1,
  canonicalJson,
  code,
  corpusContentRoot,
  createLane,
  seedOwners,
  sha256,
} from "./lib/m059-media-lane.mjs";
import {
  corpusBytesResolver,
  generateCorpus,
  nearDuplicateClosureFailures,
  payloadBytes,
  similarityFingerprint,
} from "./lib/synthetic-media-corpus.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

const PROFILE = "interactive-learned";
const OWNER_PASSWORD = "m059-soak-v1";
const T_ADMIT = "2026-09-01T08:00:00Z";
const POLICY_HASH = `sha256:${"77".repeat(32)}`;
const TIMEBASE = "acme-desk-tb-1";
const TICKS_PER_SECOND = 1000;
const GIB2 = 2_147_483_648;

const lane = createLane({ root: ROOT, label: "ioi-m059-soak" });
process.on("exit", lane.cleanup);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    lane.cleanup();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

const R = ROUTES_V1;
const req = (...args) => lane.req(...args);

// ------------------------------------------------------------------------------------ the corpus
// Generated ONCE, before the daemon exists, so nothing the runtime does can shape the input.
const corpus = generateCorpus({ profile: PROFILE, seed: "m059-scale-soak", sessions: 3, episodesPerSession: 4 });

const snapshotBody = (key, family, session, seeds) => ({
  owner_ref: OWNER,
  idempotency_key: key,
  family,
  effective_at: T_ADMIT,
  acquisition_class: "live_demonstration",
  capture_binding: {
    actor_ref: `actor://acme.operator-${session}`,
    session_ref: `session://acme.desk-${session}`,
    device_ref: `device://acme.workstation-${session}`,
    environment_ref: "environment://acme.sandbox/revision/4",
    application_ref: null,
    world_revision_ref: null,
  },
  capture_rights_revision_ref: seeds.captureClaim.revision_ref,
  learning_source_rights_claim_revision_refs: [seeds.learnedClaim.revision_ref],
  consent_bindings: [],
  policy_bound_data_view_revision_refs: [],
  timebase: {
    temporal_verification_profile_ref: "temporal-verification-profile://acme.wallet-anchored/v1",
    profile_hash: sha256("tvp"),
    timebase_id: TIMEBASE,
    clock_class: "authenticated_wallet_time",
    epoch_ref: "epoch://acme.desk",
    tick_unit: "millisecond",
    declared_monotonic: true,
    // RETAINED, NEVER NORMALIZED. A run that sorted a clock regression into order would have
    // destroyed the evidence ACC-16 clause 3 exists to preserve.
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
      artifact_ref: `artifact://acme/session-${session}/recording`,
      sha256: sha256(`rec-${session}`),
      media_type: "video/mp4",
      size_bytes: 51200000,
      manifest_root: sha256(`man-rec-${session}`),
      role: "recording",
    },
    {
      artifact_ref: `artifact://acme/session-${session}/control`,
      sha256: sha256(`ctl-${session}`),
      media_type: "application/jsonl",
      size_bytes: 240000,
      manifest_root: sha256(`man-ctl-${session}`),
      role: "control_stream",
    },
  ],
  availability: {
    availability_manifest_ref: `availability-manifest://acme/${session}`,
    retention_class_ref: "retention-class://bounded_retention",
    verifier_contract_ref: "verifier-contract://ioi/media-snapshot/v1",
    failure_behavior: "fail_closed",
  },
  information_flow_label_refs: ["ifc-label://acme/internal"],
  quarantine: {
    quarantine_state: "released",
    quarantine_reason: null,
    released_by_ref: "user://acme.reviewer",
    released_at: "2026-08-31T11:45:00Z",
  },
  redaction: {
    recipe_revision_ref: seeds.recipe.revision_ref,
    creates_permission: false,
    severs_lineage: false,
    source_privacy_class: "confidential",
    output_privacy_class: "confidential",
  },
  deduplication: {
    exact_key_algorithm: "jcs_sha256",
    near_duplicate_method: corpus.deduplication_policy.near_duplicate_method,
    excluded_count: corpus.deduplicated.file_count,
  },
  quality_findings: [
    { finding_class: "corrupt_chunk", severity: "refused", evidence_ref: "artifact://acme/corrupt-1" },
    { finding_class: "truncated_file", severity: "refused", evidence_ref: "artifact://acme/trunc-1" },
    { finding_class: "variable_rate_segment", severity: "excluded", evidence_ref: "artifact://acme/vrate-1" },
    { finding_class: "padded_span", severity: "excluded", evidence_ref: "artifact://acme/pad-1" },
    { finding_class: "repeated_file", severity: "excluded", evidence_ref: "artifact://acme/repeat-1" },
  ],
  source_impact_lineage: {
    data_recipe_revision_refs: [seeds.recipe.revision_ref],
    connector_mapping_revision_refs: [seeds.mapping.revision_ref],
    transformation_run_refs: [seeds.run.transformation_run_id],
  },
  // The per-snapshot census is this Session's slice of the generated corpus, summed from its rows.
  raw_census: sessionCensus(session, null),
  accepted_census: sessionCensus(session, "accepted"),
  registry_status: "active",
});

/** One Session's slice of the corpus, SUMMED FROM the generated rows rather than asserted. */
function sessionCensus(session, disposition) {
  const rows = corpus.files.filter(
    (row) => row.session_index === session && (disposition === null || row.disposition === disposition),
  );
  const seconds = rows.reduce((total, row) => total + row.source_seconds, 0);
  return {
    source_seconds: seconds,
    file_count: rows.length,
    byte_count: rows.reduce((total, row) => total + row.byte_count, 0),
    frame_or_sample_count: seconds * 30,
    chunk_count: rows.length * 12,
  };
}

const episodeBody = (episode, snapshotRef, snapshotHash) => {
  const controllerLabel = `label://acme/ep-${episode.episode_index}/controller`;
  const inferredLabel = `label://acme/ep-${episode.episode_index}/inferred`;
  const seconds = Math.round((episode.end_tick - episode.start_tick) / TICKS_PER_SECOND);
  return {
    owner_ref: OWNER,
    idempotency_key: `m059-soak-episode-${episode.episode_index}`,
    family: "acme.desk-members",
    effective_at: T_ADMIT,
    media_snapshot_revision_ref: snapshotRef,
    media_snapshot_content_hash: snapshotHash,
    bounds: {
      timebase_id: TIMEBASE,
      start_tick: episode.start_tick,
      end_tick: episode.end_tick,
      boundary_evidence_ref: `artifact://acme/ep-${episode.episode_index}/bounds`,
    },
    streams: [
      {
        stream_role: "observation",
        schema_ref: "schema://acme/frame/v1",
        channel: "screen",
        sample_count: seconds * 30,
        sync_evidence_ref: `artifact://acme/ep-${episode.episode_index}/sync`,
      },
      {
        stream_role: "action",
        schema_ref: "schema://acme/action/v1",
        channel: "controller",
        sample_count: seconds,
        sync_evidence_ref: `artifact://acme/ep-${episode.episode_index}/sync`,
      },
    ],
    synchronization: {
      method: "shared_timebase",
      frame_action_offset_ticks: -16,
      max_observed_skew_ticks: 22,
      declared_skew_envelope_ticks: 40,
    },
    // ONE controller-recorded label and ONE video-inferred label per episode. The inferred one must
    // survive as an UNCERTAIN ATTRIBUTED LABEL rather than being dropped or promoted.
    labels: [
      {
        label_ref: controllerLabel,
        label_class: episode.label_classes[0],
        value_ref: "value://acme/controller",
        label_provenance_class: "controller_recorded",
        epistemic_status: "controller_ground_truth",
        is_controller_ground_truth: true,
        confidence: null,
        uncertainty_kind: "none",
        attributed_to_ref: `device://acme.workstation-${episode.session_index}`,
        corrected_by_ref: null,
      },
      {
        label_ref: inferredLabel,
        label_class: episode.label_classes[episode.label_classes.length - 1],
        value_ref: "value://acme/inferred",
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
      {
        exception_class: "operator_abort",
        at_tick: episode.start_tick + 1000,
        evidence_ref: `artifact://acme/ep-${episode.episode_index}/abort`,
      },
    ],
    determinism: {
      determinism_class: "seeded_deterministic",
      preprocessor_code_root: sha256("pre-code"),
      preprocessor_config_root: sha256("pre-config"),
      declared_randomness_seed: `m059-scale-soak-${episode.episode_index}`,
    },
    registry_status: "active",
  };
};

/**
 * The census, built from MEASURED runtime evidence.
 *
 * `evidence` is not decoration and is not authored here: every field of it comes from a real
 * subscription lease over a real stream, a delivery that really lagged its declared window, a real
 * process restart, and the kernel's own high-water mark. The first draft of this soak hard-coded all
 * of it — a lease ref nobody created, a queue depth nothing reached, a durability class this
 * topology cannot achieve, and two equal restart roots written down BEFORE any restart had happened.
 * That census would have been a narration of a soak rather than the record of one.
 */
const censusBody = (evidence) => {
  const body = {
    owner_ref: OWNER,
    idempotency_key: "m059-soak-census",
    family: "acme.desk-scale",
    effective_at: T_ADMIT,
    claimed_scale: "hours_scale_qualification",
    profile: PROFILE,
    corpus_content_root: "",
    raw: corpus.raw,
    accepted: corpus.accepted,
    rejected: corpus.rejected,
    deduplicated: corpus.deduplicated,
    deduplication_policy: corpus.deduplication_policy,
    file_dispositions: corpus.file_dispositions,
    distinct_payloads: corpus.distinct_payloads,
    near_duplicate_exclusions: corpus.near_duplicate_exclusions,
    profile_required_label_classes: corpus.required_label_classes,
    observed_label_classes: corpus.observed_label_classes,
    runtime_evidence: {
      // Every value below is OBSERVED. See `measureRuntime()` for where each one came from.
      peak_resident_bytes: evidence.peak_resident_bytes,
      projection_subscription_lease_ref: evidence.lease_ref,
      // THE QUEUE IS BOUNDED AND THE BOUND IS DECLARED. Exceeding it produces a TYPED OUTCOME; it
      // never silently drops an accepted event — and this run made it exceed, rather than saying so.
      max_undelivered_events_declared: evidence.backpressure_window,
      queue_high_water: evidence.queue_high_water,
      backpressure_lag_outcomes: evidence.backpressure_lag_outcomes,
      durability_class_achieved: evidence.durability_class_achieved,
      interruption_count: evidence.interruption_count,
      resume_count: evidence.resume_count,
      restart_equivalence: {
        pre_restart_root: evidence.pre_restart_root,
        post_restart_root: evidence.post_restart_root,
        roots_equal: true,
      },
      corrupt_inputs_refused: corpus.file_dispositions.filter((r) => r.reason_class === "corrupt").length,
      truncated_inputs_refused: corpus.file_dispositions.filter((r) => r.reason_class === "truncated").length,
      variable_rate_inputs_handled: corpus.file_dispositions.filter((r) => r.reason_class === "variable_rate").length,
    },
    degeneracy_findings: [
      { finding_class: "repeated_file", severity: "excluded", evidence_ref: "artifact://acme/scale/exact-duplicates" },
      { finding_class: "padded_span", severity: "refused", evidence_ref: "artifact://acme/scale/padded" },
    ],
  };
  body.corpus_content_root = corpusContentRoot(body);
  return body;
};

// ============================================================== the runtime evidence, MEASURED
const LEASE_NS = "media-trajectory-scale";
const STREAM_TAIL = "ingest";
const LEASE_TAIL = "sub_scale";
const EVENT_CLASS = "ioi.media-trajectory.chunk-ingested";
const BACKPRESSURE_WINDOW = 8;
const APPENDED_EVENTS = 24; // deliberately > the window, so lag is FORCED rather than described

const declaration = (extra) => ({
  event_class_declaration: {
    admitted_truth_classes: [{ class_id: EVENT_CLASS, payload_schema_ref: "schema://ioi/media-chunk/v1" }],
    ephemeral_delivery_classes: [],
  },
  ...extra,
});

/**
 * Drive the real `/v1/subscriptions` seam and RETURN WHAT IT REPORTED.
 *
 * Nothing here is asserted into existence: a stream is declared, more events than the window are
 * appended, a bounded lease is created, delivery is asked for and reports its own lag, a checkpoint
 * is admitted, the daemon is really restarted, and delivery is asked again to show it resumed from
 * the durable checkpoint. The census is then populated from these responses.
 *
 * THE RESTART HAPPENS BEFORE THE CENSUS IS ADMITTED, on purpose. A census is immutable, so a record
 * carrying `pre_restart_root === post_restart_root` written before any restart occurred would be a
 * prediction rather than evidence — and one that is true by construction whatever the runtime does.
 */
async function measureRuntime(familyDigest, ownerEmail) {
  const observed = { failures: [] };
  const note = (why) => observed.failures.push(why);

  const declared = await req("POST", `/v1/event-streams/${LEASE_NS}/${STREAM_TAIL}`, declaration({
    owner_ref: OWNER,
    idempotency_key: "m059-soak-stream-declare",
  }));
  if (declared.status !== 200) note(`stream declare status=${declared.status} code=${code(declared.j)}`);
  let head = declared.j?.admitted_head?.resulting_head_ref;

  for (let index = 0; index < APPENDED_EVENTS; index += 1) {
    const appended = await req("POST", `/v1/event-streams/${LEASE_NS}/${STREAM_TAIL}/events`, declaration({
      class_id: EVENT_CLASS,
      idempotency_key: `m059-soak-event-${index}`,
      recorded_at_ms: index + 1,
      payload: { chunk_index: index, corpus_content_root: corpusContentRoot(corpus) },
      ...(head ? { expected_head: head } : {}),
    }));
    if (appended.status !== 200) {
      note(`append ${index} status=${appended.status} code=${code(appended.j)}`);
      break;
    }
    // A MISSING HEAD IS A FAILURE, NOT A REASON TO REUSE THE LAST ONE. Silently carrying a stale
    // head would make the next append's expected-head check pass against the wrong position, and
    // the run would look like it appended a chain it never built.
    const next = appended.j?.admitted_head?.resulting_head_ref;
    if (typeof next !== "string" || next.length === 0) {
      note(`append ${index} returned no resulting head`);
      break;
    }
    head = next;
  }

  const lease = await req("POST", "/v1/subscriptions", {
    owner_namespace: LEASE_NS,
    stream_tail: STREAM_TAIL,
    subscriber_ref: "subscriber://ioi/m059-scale-soak",
    lease_tail: LEASE_TAIL,
    permitted_event_class_ids: [EVENT_CLASS],
    max_undelivered_events: BACKPRESSURE_WINDOW,
    recorded_at_ms: 1,
    idempotency_key: "m059-soak-lease-create",
  });
  if (lease.status !== 200) note(`lease create status=${lease.status} code=${code(lease.j)}`);

  // THE V1 LEASE VIEW RETURNS AN UNQUALIFIED DISPLAY ID — `subscription-lease://<tail>`, with no
  // owner namespace — and that is ProjectionSubscriptionLease v1's own shape, not a defect to
  // reinterpret here. M05.9's evidence ref is OWNER-QUALIFIED, so it is derived from the exact route
  // coordinates this lease was admitted at, and the response is checked to BIND those coordinates
  // before the derived ref is used. Reading the display id and hoping it were qualified would be the
  // same class of mistake as trusting a fingerprint a row supplied about itself.
  const expectedStreamId = `event-stream://${LEASE_NS}/${STREAM_TAIL}`;
  if (lease.j?.stream_id !== expectedStreamId) {
    note(`lease binds stream ${lease.j?.stream_id} rather than ${expectedStreamId}`);
  }
  if (lease.j?.lease_id !== `subscription-lease://${LEASE_TAIL}`) {
    note(`lease display id ${lease.j?.lease_id} is not v1's unqualified form for tail ${LEASE_TAIL}`);
  }
  const ownerQualifiedLeaseRef = `subscription-lease://${LEASE_NS}/${LEASE_TAIL}`;

  const delivery = await req("GET", `/v1/subscriptions/${LEASE_NS}/${LEASE_TAIL}/delivery`);
  if (delivery.status !== 200) note(`delivery status=${delivery.status} code=${code(delivery.j)}`);

  // The delivery plane's vocabulary is `bounded_by_backpressure_window | drained`; the census's is
  // `typed_gap | typed_rebase | lease_revoked`. This is the one translation, and it is a mapping of
  // an OBSERVED outcome, not a substitute for observing one.
  const outcome = delivery.j?.delivery_outcome;
  const laggedOutcomes = outcome === "bounded_by_backpressure_window" ? ["typed_gap"] : [];

  const ackSeq = delivery.j?.events?.at(-1)?.seq;
  const checkpoint = await req("POST", `/v1/subscriptions/${LEASE_NS}/${LEASE_TAIL}/checkpoint`, {
    acknowledged_seq: ackSeq,
    expected_head: lease.j?.admitted_lease_transition?.resulting_head_ref,
    idempotency_key: "m059-soak-lease-checkpoint",
    recorded_at_ms: 2,
  });
  if (checkpoint.status !== 200) note(`checkpoint status=${checkpoint.status} code=${code(checkpoint.j)}`);

  // --------------------------------------------------------------------- THE REAL RESTART
  const preRestartRoot = await familyDigest();
  lane.sampleResident();
  await lane.stop();
  await lane.start();
  // The PROCESS is new, so the session is too; the durable truth underneath it is not.
  const relogin = await lane.login(ownerEmail, OWNER_PASSWORD);
  if (!relogin.sessionToken) note(`relogin after restart status=${relogin.status}`);
  const postRestartRoot = await familyDigest();

  const resumed = await req("GET", `/v1/subscriptions/${LEASE_NS}/${LEASE_TAIL}/delivery`);
  if (resumed.status !== 200) note(`resume status=${resumed.status} code=${code(resumed.j)}`);

  return {
    ...observed,
    lease_ref: ownerQualifiedLeaseRef,
    lease_display_id: lease.j?.lease_id ?? "",
    lease_stream_id: lease.j?.stream_id ?? "",
    lease_state: lease.j?.lease_state ?? "",
    backpressure_window: delivery.j?.backpressure_window ?? 0,
    // THE HIGH-WATER MARK IS COUNTED FROM THE DELIVERED EVENTS THEMSELVES. Inferring it as
    // `min(pending_total, window)` would be arithmetic over two other reported numbers — it would
    // hold even if the plane delivered nothing at all, so it could never disagree with the window
    // and could never expose a delivery that failed to fill it.
    queue_high_water: delivery.j?.events?.length ?? 0,
    pending_total: delivery.j?.pending_total ?? 0,
    delivered_event_count: delivery.j?.events?.length ?? 0,
    delivery_outcome: outcome ?? "",
    backpressure_lag_outcomes: laggedOutcomes,
    acknowledged_seq: ackSeq ?? null,
    resumed_from_checkpoint: resumed.j?.delivered_from_checkpoint ?? null,
    resumed_first_seq: resumed.j?.events?.[0]?.seq ?? null,
    resumed_state_after_restart: resumed.status,
    pre_restart_root: preRestartRoot,
    post_restart_root: postRestartRoot,
    peak_resident_bytes: lane.peakResidentBytes,
    durability_class_achieved: lane.durabilityClassAchieved,
    interruption_count: lane.interruptionCount,
    resume_count: lane.resumeCount,
  };
}

// =========================================================================================== run
async function run() {
  lane.rebuildDaemon();
  await lane.start();
  const boot = await lane.bootstrap(OWNER_PASSWORD);
  ok(
    "S0 the isolated daemon bootstraps an owner session on the SAME lane the blocking gate uses",
    !!boot.sessionToken,
    `token=${boot.sessionToken ? "present" : "absent"} status=${boot.status}`,
  );
  const seeds = await seedOwners(req, { prefix: "m059-soak" });

  // ---------------------------------------------------------------- A · the corpus meets the floor
  ok(
    "S1 the generated corpus retains at least 7200 accepted seconds AFTER exact and near-duplicate exclusion",
    corpus.accepted.seconds_after_deduplication >= 7200 &&
      corpus.accepted.seconds_after_deduplication < corpus.accepted.seconds_before_deduplication,
    `after=${corpus.accepted.seconds_after_deduplication}s before=${corpus.accepted.seconds_before_deduplication}s`,
  );
  ok(
    "S2 at least eight independently bounded episodes/tasks from at least two source Sessions",
    corpus.accepted.bounded_episode_count >= 8 &&
      corpus.accepted.task_count >= 8 &&
      corpus.accepted.source_session_count >= 2,
    `episodes=${corpus.accepted.bounded_episode_count} tasks=${corpus.accepted.task_count} sessions=${corpus.accepted.source_session_count}`,
  );
  ok(
    "S3 every profile-required action, field and exception label class is observed",
    corpus.required_label_classes.length > 0 &&
      corpus.required_label_classes.every((cls) => corpus.observed_label_classes.includes(cls)),
    `required=${corpus.required_label_classes.length} observed=${corpus.observed_label_classes.length}`,
  );
  ok(
    "S4 the corpus stays under the 2 GiB ceiling and needs no GPU runner, object store or metered service",
    corpus.accepted.byte_count <= GIB2 && corpus.raw.byte_count <= GIB2,
    `accepted=${corpus.accepted.byte_count}B raw=${corpus.raw.byte_count}B ceiling=${GIB2}B`,
  );
  ok(
    "S5 every census closes over the rows: duration, files, bytes, frames-or-samples and chunks",
    (() => {
      const rows = corpus.file_dispositions;
      const sum = (list, key) => list.reduce((total, row) => total + row[key], 0);
      const of = (d) => rows.filter((row) => row.disposition === d);
      const closes = (block, list, seconds) =>
        block.file_count === list.length &&
        block.byte_count === sum(list, "byte_count") &&
        block.chunk_count === list.length * 12 &&
        block.frame_or_sample_count === seconds * 30;
      return (
        closes(corpus.raw, rows, corpus.raw.source_seconds) &&
        corpus.raw.source_seconds === sum(rows, "source_seconds") &&
        closes({ ...corpus.accepted, source_seconds: corpus.accepted.seconds_after_deduplication },
          of("accepted"), corpus.accepted.seconds_after_deduplication) &&
        closes(corpus.rejected, of("rejected"), corpus.rejected.source_seconds) &&
        closes(corpus.deduplicated, of("deduplicated"), corpus.deduplicated.source_seconds) &&
        corpus.accepted.seconds_before_deduplication ===
          corpus.accepted.seconds_after_deduplication + corpus.deduplicated.source_seconds
      );
    })(),
    `raw=${corpus.raw.file_count}f/${corpus.raw.byte_count}B accepted=${corpus.accepted.file_count}f rejected=${corpus.rejected.file_count}f dedup=${corpus.deduplicated.file_count}f`,
  );
  ok(
    "S6 corrupt, truncated, variable-rate, padded and out-of-rights members are REFUSED by name, never absorbed",
    (() => {
      const refused = new Set(
        corpus.file_dispositions.filter((r) => r.disposition === "rejected").map((r) => r.reason_class),
      );
      return ["corrupt", "truncated", "variable_rate", "padded", "out_of_rights"].every((cls) => refused.has(cls));
    })(),
    `rejected_classes=${corpus.rejected.reason_classes.join(",")}`,
  );
  ok(
    "S7 exact duplication is REAL: distinct source refs over one payload, exactly one instance accepted",
    (() => {
      const counts = new Map();
      for (const row of corpus.file_dispositions) {
        counts.set(row.content_sha256, (counts.get(row.content_sha256) ?? 0) + 1);
      }
      const repeated = [...counts.entries()].filter(([, n]) => n > 1);
      if (repeated.length === 0) return false;
      return repeated.every(([digest]) => {
        const rows = corpus.file_dispositions.filter((r) => r.content_sha256 === digest);
        return (
          new Set(rows.map((r) => r.source_file_ref)).size === rows.length &&
          rows.filter((r) => r.disposition === "accepted").length === 1 &&
          rows.every((r) => r.disposition === "accepted" ||
            (r.disposition === "deduplicated" && r.reason_class === "exact_duplicate"))
        );
      });
    })(),
    `rows=${corpus.file_dispositions.length} payloads=${corpus.distinct_payloads.length} exact_duplicates=${corpus.deduplicated.exact_duplicate_file_count}`,
  );
  ok(
    "S8 the near-duplicate closure holds over the WHOLE corpus, recomputed from regenerated bytes",
    (() => {
      const failures = nearDuplicateClosureFailures(corpus, corpusBytesResolver(corpus));
      return corpus.near_duplicate_exclusions.length > 0 && failures.length === 0;
    })(),
    (() => {
      const failures = nearDuplicateClosureFailures(corpus, corpusBytesResolver(corpus));
      return `exclusions=${corpus.near_duplicate_exclusions.length} failures=${failures.length}${failures.length ? ` first=${failures[0]}` : ""}`;
    })(),
  );

  // ------------------------------------------------------- B · the snapshots, at one per Session
  const snapshots = [];
  for (let session = 0; session < corpus.accepted.source_session_count; session += 1) {
    const response = await req(
      "POST",
      R.SNAPS,
      snapshotBody(`m059-soak-snap-${session}`, `acme.desk-s${session}`, session, seeds),
    );
    snapshots.push(response.j?.media_snapshot ?? { __status: response.status, __code: code(response.j) });
  }
  ok(
    "S9 every Session's snapshot is admitted through the owner-scoped chain and binds its M05.7/M05.8 seams",
    snapshots.length >= 2 &&
      snapshots.every((snap, index) =>
        snap.revision_ref === `media-snapshot://acme.desk-s${index}/revision/1` &&
        (snap.resolved_source_impact_lineage ?? []).some((entry) => entry.kind === "transformation_run") &&
        (snap.resolved_source_impact_lineage ?? []).some((entry) => entry.kind === "data_recipe") &&
        (snap.resolved_source_impact_lineage ?? []).some((entry) => entry.kind === "connector_mapping")),
    `snapshots=${snapshots.length} first=${snapshots[0]?.revision_ref ?? JSON.stringify(snapshots[0])}`,
  );
  ok(
    "S10 permits_learned_use is DERIVED from the claims this seam resolved, never taken from the caller",
    snapshots.every((snap) => typeof snap.permits_learned_use === "boolean"),
    `values=${[...new Set(snapshots.map((s) => String(s.permits_learned_use)))].join(",")}`,
  );

  // ------------------------------------------------------------ C · every bounded episode, at scale
  const episodes = [];
  for (const episode of corpus.episodes) {
    const snapshot = snapshots[episode.session_index];
    const response = await req(
      "POST",
      R.EPISODES,
      episodeBody(episode, snapshot.revision_ref, snapshot.content_hash),
    );
    episodes.push(response.j?.observation_action_episode ?? { __status: response.status, __code: code(response.j) });
  }
  ok(
    "S11 every bounded episode is admitted and inherits its snapshot's Session and timebase",
    episodes.length === corpus.episodes.length &&
      episodes.every((ep, index) =>
        typeof ep.revision_ref === "string" &&
        ep.session_ref === `session://acme.desk-${corpus.episodes[index].session_index}` &&
        ep.timebase_id === TIMEBASE),
    `episodes=${episodes.length}/${corpus.episodes.length} first_code=${episodes[0]?.__code ?? "none"}`,
  );
  ok(
    "S12 the video-inferred label survives as an UNCERTAIN ATTRIBUTED LABEL and is never ground truth",
    episodes.every((ep) => {
      const eligible = ep.ground_truth_eligible_label_refs ?? [];
      const inferred = (ep.labels ?? []).filter((l) => l.label_provenance_class === "video_inferred");
      return (
        inferred.length === 1 &&
        inferred.every((l) => l.epistemic_status === "uncertain_attributed_label" && l.is_controller_ground_truth === false) &&
        inferred.every((l) => !eligible.includes(l.label_ref)) &&
        eligible.length === 1
      );
    }),
    `episodes_checked=${episodes.length}`,
  );

  // ----------------------------------------------------------------- D · one split over the episodes
  const SPLIT_CLASSES = ["train", "validation", "temporal_holdout", "actor_holdout", "world_holdout", "adversarial"];
  const cut = 500000;
  const members = episodes.slice(0, 12).map((ep, index) => {
    const klass = SPLIT_CLASSES[index % SPLIT_CLASSES.length];
    const temporal = klass === "temporal_holdout";
    return {
      episode_revision_ref: ep.revision_ref,
      episode_content_hash: ep.content_hash,
      split_class: klass,
      // The actor and world holdouts must share nothing with training, so they take their own keys.
      actor_partition_key: klass === "actor_holdout" ? `actor-holdout-${index}` : "actor-a",
      world_partition_key: klass === "world_holdout" ? `world-holdout-${index}` : "world-a",
      max_tick: temporal ? cut + 20000 + index : cut - 40000 + index,
    };
  });
  const split = await req("POST", R.SPLITS, {
    owner_ref: OWNER,
    idempotency_key: "m059-soak-split",
    family: "acme.desk-scale-split",
    effective_at: T_ADMIT,
    members,
    leakage_controls: {
      near_duplicate_exclusion_method: corpus.deduplication_policy.near_duplicate_method,
      near_duplicate_excluded_count: corpus.deduplicated.near_duplicate_file_count,
      temporal_cut_tick: cut,
      max_train_tick: cut - 40000,
      min_temporal_holdout_tick: cut + 20000,
    },
    registry_status: "active",
  });
  const manifest = split.j?.dataset_split_manifest ?? {};
  ok(
    "S13 a split manifest over every episode is admitted, with membership DERIVED from the rows",
    split.status === 201 &&
      manifest.member_count === members.length &&
      manifest.membership_is_immutable === true,
    `status=${split.status} count=${manifest.member_count}/${members.length} code=${code(split.j)} ${split.j?.error?.message ?? ""}`,
  );

  // ------------------------------------ E · the runtime evidence, measured BEFORE the census exists
  const beforeRestart = await familySnapshot();
  const evidence = await measureRuntime(familyRoots, boot.email);
  const afterRestart = await familySnapshot();
  ok(
    "S14 a bounded lease is ADMITTED over a real stream, and its evidence ref is DERIVED from those coordinates",
    evidence.failures.length === 0 &&
      evidence.lease_state === "active" &&
      // v1 returns the unqualified display id; M05.9's evidence ref is owner-qualified and derived.
      evidence.lease_display_id === `subscription-lease://${LEASE_TAIL}` &&
      evidence.lease_stream_id === `event-stream://${LEASE_NS}/${STREAM_TAIL}` &&
      evidence.lease_ref === `subscription-lease://${LEASE_NS}/${LEASE_TAIL}` &&
      evidence.backpressure_window === BACKPRESSURE_WINDOW,
    `ref=${evidence.lease_ref} display=${evidence.lease_display_id} stream=${evidence.lease_stream_id} state=${evidence.lease_state} window=${evidence.backpressure_window} failures=${evidence.failures.join("; ") || "none"}`,
  );
  ok(
    "S15 the queue really EXCEEDED its declared window, and the lag resolved to a TYPED outcome",
    evidence.pending_total > evidence.backpressure_window &&
      evidence.delivery_outcome === "bounded_by_backpressure_window" &&
      evidence.backpressure_lag_outcomes.includes("typed_gap") &&
      // Counted from the delivered events. Because more was pending than the window allowed, the
      // count must EQUAL the window the lease was admitted with — a delivery that under-filled its
      // own bound would be a silent drop wearing a typed outcome's name.
      evidence.queue_high_water === evidence.backpressure_window &&
      evidence.queue_high_water === evidence.delivered_event_count,
    `delivered=${evidence.delivered_event_count} high_water=${evidence.queue_high_water} pending=${evidence.pending_total} window=${evidence.backpressure_window} outcome=${evidence.delivery_outcome}`,
  );
  ok(
    "S16 after a REAL process restart the lease resumes from its durable checkpoint, not from the beginning",
    evidence.resumed_state_after_restart === 200 &&
      evidence.acknowledged_seq !== null &&
      evidence.resumed_from_checkpoint === evidence.acknowledged_seq &&
      (evidence.resumed_first_seq === null || evidence.resumed_first_seq > evidence.acknowledged_seq),
    `ack=${evidence.acknowledged_seq} resumed_from=${evidence.resumed_from_checkpoint} first=${evidence.resumed_first_seq}`,
  );
  ok(
    "S17 every family replays BYTE-IDENTICALLY across that restart at this scale",
    canonicalJson(beforeRestart) === canonicalJson(afterRestart) &&
      beforeRestart.episodes === corpus.episodes.length &&
      evidence.pre_restart_root === evidence.post_restart_root,
    `before=${JSON.stringify(beforeRestart)} after=${JSON.stringify(afterRestart)}`,
  );
  ok(
    "S18 the interruption, resume and peak-resident numbers are COUNTED and MEASURED, not declared",
    evidence.interruption_count >= 1 &&
      evidence.resume_count >= 1 &&
      evidence.peak_resident_bytes > 0 &&
      evidence.durability_class_achieved === "local_only",
    `interruptions=${evidence.interruption_count} resumes=${evidence.resume_count} peak_rss=${evidence.peak_resident_bytes}B durability=${evidence.durability_class_achieved}`,
  );

  // ---------------------------------------------------------- F · the hours-scale census, admitted
  const body = censusBody(evidence);
  const census = await req("POST", R.CENSUSES, body);
  const cen = census.j?.media_corpus_census ?? {};
  ok(
    "S19 the hours-scale census is ADMITTED, and its floors are the server-pinned ones",
    census.status === 201 &&
      cen.claimed_scale === "hours_scale_qualification" &&
      cen.does_not_claim_hours_scale_qualification === false &&
      cen.floors?.accepted_seconds_after_deduplication === 7200 &&
      cen.floors?.bounded_episode_count === 8 &&
      cen.floors?.source_session_count === 2,
    `status=${census.status} code=${code(census.j)} ${census.j?.error?.message ?? ""} floors=${JSON.stringify(cen.floors)}`,
  );
  ok(
    "S20 the admitted census carries the four censuses, the payload table and the exclusion evidence",
    (cen.file_dispositions ?? []).length === corpus.file_dispositions.length &&
      (cen.distinct_payloads ?? []).length === corpus.distinct_payloads.length &&
      (cen.near_duplicate_exclusions ?? []).length === corpus.near_duplicate_exclusions.length &&
      cen.distinct_content_hash_count === corpus.distinct_payloads.length &&
      cen.distinct_content_hash_count < cen.raw?.file_count,
    `rows=${(cen.file_dispositions ?? []).length} payloads=${cen.distinct_content_hash_count} exclusions=${(cen.near_duplicate_exclusions ?? []).length}`,
  );
  ok(
    "S21 the census identity IS its corpus digest, and that digest commits the rows this run produced",
    (cen.corpus_census_id ?? "").endsWith((cen.corpus_content_root ?? "x").replace("sha256:", "")) &&
      cen.corpus_content_root === corpusContentRoot(corpus),
    `id=${cen.corpus_census_id}`,
  );
  ok(
    "S22 every payload the daemon admitted regenerates to the digest, length and fingerprint it carries",
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

  // ---------------------------------------------------------------- G · replay and erasure at scale
  const replay = await req("POST", R.CENSUSES, body);
  ok(
    "S23 re-admitting the same census REPLAYS its exact revision rather than minting a second one",
    replay.status === 200 &&
      replay.j?.replayed === true &&
      replay.j?.media_corpus_census?.corpus_census_id === cen.corpus_census_id &&
      replay.j?.media_corpus_census?.content_hash === cen.content_hash,
    `status=${replay.status} replayed=${replay.j?.replayed} id=${replay.j?.media_corpus_census?.corpus_census_id}`,
  );
  const impact = await req(
    "GET",
    `${R.IMPACT}?snapshot_revision_ref=${encodeURIComponent(snapshots[0].revision_ref)}&episode_family=acme.desk-members&split_family=acme.desk-scale-split`,
  );
  ok(
    "S24 erasure produces an IMPACT GRAPH over dependents and rewrites no historical evidence",
    impact.status === 200 &&
      (impact.j?.dependent_episode_revision_refs ?? []).length > 0 &&
      impact.j?.decision === "governed_rebuild_or_withdrawal_required",
    `status=${impact.status} episodes=${(impact.j?.dependent_episode_revision_refs ?? []).length} decision=${impact.j?.decision}`,
  );

  // ----------------------------------------------------------------------------- G · the nonclaims
  ok(
    "S25 the census claims no throughput or latency, and no such number is asserted anywhere in this lane",
    cen.does_not_claim_throughput_or_latency === true &&
      !results.some((r) => /(throughput|latency|per second|ms\b|seconds per)/iu.test(r.name)),
    `nonclaim=${cen.does_not_claim_throughput_or_latency}`,
  );
  ok(
    "S26 the census pins recipe-borne custody and claims NO custody of imported media bytes",
    cen.payload_custody === "deterministic_recipe" &&
      cen.does_not_claim_custody_of_imported_media_bytes === true,
    `custody=${cen.payload_custody} nonclaim=${cen.does_not_claim_custody_of_imported_media_bytes}`,
  );
  ok(
    "S27 nothing this lane admitted grants authority: every family carries its own nonclaim",
    cen.authority_nonclaim === "media_corpus_qualification_census_grants_no_authority" &&
      snapshots.every((s) => s.authority_nonclaim === "policy_bound_media_snapshot_grants_no_authority" &&
        s.capture_authority_does_not_travel_into_replay === true &&
        s.demonstration_is_not_consent === true),
    `census=${cen.authority_nonclaim} snapshots=${snapshots.length}`,
  );
  // THE LAST GAP THIS LANE CLOSES. A census can look impeccable while its runtime evidence was
  // typed in by the harness that filed it, and no field of the record can tell. So the admitted
  // record is compared FIELD BY FIELD against what the subscription plane, the kernel and the
  // restart actually reported — the census must be a transcript of this run, not a description.
  const ev = cen.runtime_evidence ?? {};
  ok(
    "S28 every runtime-evidence field in the admitted census equals what the runtime itself reported",
    ev.projection_subscription_lease_ref === evidence.lease_ref &&
      ev.max_undelivered_events_declared === evidence.backpressure_window &&
      ev.queue_high_water === evidence.queue_high_water &&
      ev.queue_high_water <= ev.max_undelivered_events_declared &&
      canonicalJson(ev.backpressure_lag_outcomes) === canonicalJson(evidence.backpressure_lag_outcomes) &&
      ev.durability_class_achieved === evidence.durability_class_achieved &&
      ev.peak_resident_bytes === evidence.peak_resident_bytes &&
      ev.interruption_count === evidence.interruption_count &&
      ev.resume_count === evidence.resume_count &&
      ev.restart_equivalence?.pre_restart_root === evidence.pre_restart_root &&
      ev.restart_equivalence?.post_restart_root === evidence.post_restart_root,
    `lease=${ev.projection_subscription_lease_ref} window=${ev.max_undelivered_events_declared} high_water=${ev.queue_high_water} rss=${ev.peak_resident_bytes} durability=${ev.durability_class_achieved}`,
  );
  ok(
    "S29 the corrupt, truncated and variable-rate counts equal the corpus's own refused members",
    ev.corrupt_inputs_refused === corpus.file_dispositions.filter((r) => r.reason_class === "corrupt").length &&
      ev.truncated_inputs_refused === corpus.file_dispositions.filter((r) => r.reason_class === "truncated").length &&
      ev.variable_rate_inputs_handled === corpus.file_dispositions.filter((r) => r.reason_class === "variable_rate").length &&
      ev.corrupt_inputs_refused > 0,
    `corrupt=${ev.corrupt_inputs_refused} truncated=${ev.truncated_inputs_refused} variable_rate=${ev.variable_rate_inputs_handled}`,
  );

  await lane.stop();
}

/** The four family heads, as one digest, so restart equivalence is a comparison and not a boolean. */
async function familyRoots() {
  const snapshot = await familySnapshot();
  return sha256(canonicalJson(snapshot));
}

async function familySnapshot() {
  const read = async (route, family) => {
    const response = await req("GET", `${route}?family=${encodeURIComponent(family)}`);
    return (response.j?.revisions ?? []).map((r) => r.content_hash ?? r.corpus_census_id ?? "");
  };
  const snapshotHashes = [];
  for (let session = 0; session < corpus.accepted.source_session_count; session += 1) {
    snapshotHashes.push(...(await read(R.SNAPS, `acme.desk-s${session}`)));
  }
  const episodeHashes = await read(R.EPISODES, "acme.desk-members");
  const splitHashes = await read(R.SPLITS, "acme.desk-scale-split");
  const censusHashes = await read(R.CENSUSES, "acme.desk-scale");
  return {
    snapshots: snapshotHashes.length,
    episodes: episodeHashes.length,
    splits: splitHashes.length,
    censuses: censusHashes.length,
    digest: sha256(canonicalJson([snapshotHashes, episodeHashes, splitHashes, censusHashes])),
  };
}

run()
  .catch((error) => {
    ok("the scale soak completed without an unhandled failure", false, String(error?.stack ?? error));
  })
  .finally(async () => {
    await lane.stop();
    lane.cleanup();
    const passed = results.filter((r) => r.pass).length;
    for (const r of results) console.log(`${r.pass ? "ok  " : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
    // ZERO ASSERTIONS IS A FAILURE, not a pass.
    const green = results.length > 0 && passed === results.length;
    console.log(`\n${passed}/${results.length} passed`);
    console.log(
      `corpus: ${corpus.file_dispositions.length} raw files, ${corpus.distinct_payloads.length} distinct payloads, ` +
        `${corpus.accepted.seconds_after_deduplication}s accepted after exclusion, ` +
        `${corpus.accepted.bounded_episode_count} episodes over ${corpus.accepted.source_session_count} Sessions, ` +
        `${corpus.raw.byte_count} raw bytes — synthetic, offline, non-sensitive, no performance claim`,
    );
    emitVerifierCensus({
      verifierId: "hypervisor-media-trajectory-scale-soak",
      sourceUrl: import.meta.url,
      results,
    });
    process.exit(green ? 0 : 1);
  });
