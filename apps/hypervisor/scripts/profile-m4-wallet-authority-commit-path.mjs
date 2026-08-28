#!/usr/bin/env node

// profile-m4-wallet-authority-commit-path — per-approval attribution for the
// M04.8 wallet-authority commit path.
//
// WHAT THIS IS. A wrapper that runs the EXISTING full M04.8 wallet-authority
// soak — the same verifier, the same approval count, the same restart/replay
// ending — with the estate's existing IOI_AFT_BENCH_TRACE seam enabled, and
// then joins what that seam emitted into one structured artifact attributing
// each approval's wall time to a named commit-path phase.
//
// WHAT IT IS NOT.
//   * It is not a second tracer. Every timing here comes from the existing
//     IOI_AFT_BENCH_TRACE gate that crates/execution, crates/validator, and
//     crates/cli already read.
//   * It is not a budget, a tripwire, or a threshold. This file enforces NO
//     numeric latency bound anywhere. ADR 0038 requires a reproducible baseline
//     and a mutation that proves a tripwire can fail before any number becomes
//     a gate; an aspirational number is not evidence.
//   * It is not a faster soak. Nothing is reduced, skipped, or reordered.
//
// WHY THE READINESS PIN EXISTS. IOI_AFT_BENCH_TRACE is not observation-only:
// crates/cli/src/testing/cluster.rs treats it as benchmark-harness mode and
// RAISES the default ready-height lag from 1 to 16. Left alone, a profiled run
// would measure a chain admitted under a different readiness bar than the soak
// it claims to profile. IOI_TEST_READY_HEIGHT_LAG_MAX=1 pins the soak's bar
// back. (`sanitizedVerifierBaseEnv` strips IOI_TEST_* names, so the wallet
// fixture re-asserts this pin explicitly and refuses a profiled run without
// it.)
//
// FAIL-CLOSED. A phase or dimension that was not observed is never defaulted,
// interpolated, or replaced by a neighbouring fact. A missing required phase
// fails the build of the artifact.
//
// M04.9 ORDERING/FINALITY PARITY. The same wrapper now profiles either
// ordering profile — the preserved one-validator AFT control, or the immediate
// single-authority Solo engine — through the SAME admission, execution, IAVL
// commitment, Redb durability, restart and status/receipt path. The artifact
// records which engine actually produced each height (read back from the
// trace, not assumed from the request), the proposal cadence the scheduler
// actually resolved along with the provenance of each of its values, and the
// client poll interval.
//
// ONE ARTIFACT IS NOT A COMPARISON. This produces a single-profile artifact.
// Comparing two profiles means running it twice and reading both; no
// cross-profile arithmetic is performed here, and none should be inferred from
// a single run.
//
// Usage:
//   node scripts/profile-m4-wallet-authority-commit-path.mjs [--out DIR] [--durable-store NAME]
//                                                            [--ordering-profile Aft|Solo]
//                                                            [--poll-interval-ms N]
//                                                            [--proposal-cadence-ms N]
//                                                            [--consensus-min-tick-ms N]
//
// The three numeric flags are independent knobs on different sides of the
// boundary: `--poll-interval-ms` sets how often the CLIENT asks whether a tx
// committed, while `--proposal-cadence-ms` and `--consensus-min-tick-ms` set
// how often the SERVER's scheduler may produce a block. Each is passed through
// separately and each is reported separately; none is derived from another.
//
// Exit: 0 when the soak passed AND a complete profile was built · 1 otherwise.

import { spawn } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
export const SOAK_VERIFIER = "verify-m4-room-participation-contribution-plane.mjs";
// BUMPED, because the change is incompatible and a version is the only honest
// place to say so. `aft_inclusion_finalization` is now `ordering_finalization`
// (Solo produces that phase too, so the AFT-specific name mislabelled every
// Solo row), `proposal_cadence` is now `scheduler_and_block_cadence`, and
// several phase-vocabulary labels changed meaning. A reader holding a v1
// artifact and a v2 artifact must be able to tell them apart by identifier
// alone -- reusing v1 for a breaking rename asks the reader to notice a
// disclosure they may never read.
export const ARTIFACT_SCHEMA_VERSION = "ioi.m049.ordering-finality-parity-profile.v1";

// The predecessor identifier, carried as a literal.
//
// Two jobs. It tells a reader of a v2 artifact exactly which schema it
// supersedes, and it keeps the tracked M04.8 work-item code anchor
// (docs/architecture/_meta/work-items/m04-8-wallet-authority-commit-latency.v1.json)
// satisfied -- that anchor requires this file to CONTAIN the string, which a
// declared lineage does honestly, rather than requiring this file to still
// EMIT it, which after a breaking change it cannot.
export const PREDECESSOR_ARTIFACT_SCHEMA_VERSION = "ioi.m048.commit-path-profile.v1";

// Carried into every artifact so a reader resolves the lineage from the
// artifact rather than from this file.
export const SCHEMA_COMPATIBILITY = {
  version: ARTIFACT_SCHEMA_VERSION,
  predecessor: PREDECESSOR_ARTIFACT_SCHEMA_VERSION,
  compatible_with_predecessor: false,
  extended_by: "M04.9 ordering/finality parity",
  additive:
    "ordering_parity, value_kinds, phase_semantics, summation_rule, parser_contract and the unmeasured-phase rows are new; a predecessor reader ignores them.",
  breaking: {
    renamed_phases: { aft_inclusion_finalization: "ordering_finalization" },
    renamed_fields: { proposal_cadence: "scheduler_and_block_cadence" },
    changed_semantics:
      "`exclusive` now means a leaf disjoint from other exclusive leaves, not disjoint from every phase; execution_prepare is relabelled from inclusive to exclusive and joins safe_partition.",
  },
};

// The readiness bar the unprofiled soak runs under, and which a profiled run
// must therefore keep. See the header note: the trace seam would otherwise
// silently raise it to 16.
export const READY_HEIGHT_LAG_MAX = "1";

// ---------------------------------------------------------------------------
// Parser contract
// ---------------------------------------------------------------------------

// THE ONE PLACE [BENCH-IAVL] FIELD NAMES ARE ENCODED.
//
// The IAVL commitment instrumentation is an EXCLUSIVE writer other than this
// one; this file only consumes its line. If that writer lands different
// spellings, change them here and nowhere else — every consumer below reads
// these names, and the emitted artifact republishes this constant so a reader
// can see exactly which contract a given profile was parsed under.
//
// Accepted line shape (a bare operation token after the tag is optional):
//   [BENCH-IAVL] <op?> height=<u64> version_count=<u64> tree_depth=<u64>
//                unique_nodes=<u64> new_nodes=<u64> new_node_bytes=<u64>
//                block_bytes=<u64> commitment_ms=<nonnegative-decimal>
//                durable_store_ms=<nonnegative-decimal>
//                atomic_state_block=true
export const BENCH_IAVL_CONTRACT = {
  tag: "[BENCH-IAVL]",
  correlation_field: "height",
  required_fields: [
    "height",
    "version_count",
    "tree_depth",
    "unique_nodes",
    "new_nodes",
    "new_node_bytes",
    "block_bytes",
    "commitment_ms",
    "durable_store_ms",
    "atomic_state_block",
  ],
  // A refinement this parser accepts but does not require. When the IAVL writer
  // carries it, the artifact records the durable store as OBSERVED; otherwise
  // the store name is recorded as DECLARED from `--durable-store`.
  optional_fields: ["durable_store"],
  atomic_state_block_expected: "true",
  notes:
    "Consumed only. This file never emits [BENCH-IAVL]; crates/state IAVL is owned by another writer.",
};

// THE ONE PLACE [BENCH-ORDERING] FIELD NAMES ARE ENCODED.
//
// Emitted by crates/validator consensus production under the existing
// IOI_AFT_BENCH_TRACE gate. It states which ordering/finality engine produced
// a height and the cadence that engine was CONFIGURED with.
//
// This is configuration, not timing. It exists so a measurement can be
// attributed to the engine that produced it rather than the engine being
// guessed from the measurement -- the inference that the Solo-reports-Aft
// defect made impossible.
//
// EFFECTIVE, NOT CONFIGURED-AS-WRITTEN. The cadence fields report what the
// scheduler resolved, with the provenance of each value, because the ticker is
// overridable by environment: `config.block_production_interval_secs` is stale
// for exactly the cadence-varying runs these fields exist to describe. The
// emitter mirrors `lifecycle.rs::run_consensus_ticker` and is unit-tested
// against its edge cases.
//
// TWO DIFFERENT MECHANISMS, BOTH REQUIRED.
//   * `ticker_interval_ms` is how often consensus is POLLED.
//   * `genesis_block_interval_ms` is when a block is DUE -- the on-chain
//     interval from BlockTimingParams/BlockTimingRuntime. Block production
//     defers while `expected_timestamp_ms > now_ms`, so THIS is what spaces
//     blocks. A ticker faster than this floor buys nothing, which is why
//     reporting the ticker alone once let a cadence sweep look live while
//     every run sat at the same 1000ms floor.
//
// `ticker_interval_ms=0` is a real value, and it does NOT mean kick-driven
// only: `run_consensus_ticker` returns before the `select!` that owns the kick
// receiver, so consensus halts outright. Reported as 0, interpreted here.
//
// `block_timestamp_ms` is the one OBSERVED field on the line: the on-chain
// timestamp the height actually carries. Differencing it across consecutive
// heights yields the realized block spacing, which is the only value here able
// to contradict the configured floor beside it.
//
// Accepted line shape:
//   [BENCH-ORDERING] proposal height=<u64> view=<u64> ordering_profile=<name>
//                    ticker_interval_ms=<u64>
//                    ticker_interval_provenance=<token>
//                    min_tick_ms=<u64> min_tick_provenance=<token>
//                    genesis_block_interval_ms=<u64>
//                    genesis_block_interval_provenance=<token>
//                    block_timestamp_ms=<u64>
//                    view_timeout_secs=<u64>
export const BENCH_ORDERING_CONTRACT = {
  tag: "[BENCH-ORDERING]",
  op: "proposal",
  correlation_field: "height",
  required_fields: [
    "height",
    "view",
    "ordering_profile",
    "ticker_interval_ms",
    "ticker_interval_provenance",
    "min_tick_ms",
    "min_tick_provenance",
    "genesis_block_interval_ms",
    "genesis_block_interval_provenance",
    "block_timestamp_ms",
    "view_timeout_secs",
  ],
  known_profiles: ["aft", "solo", "proof_of_authority", "proof_of_stake"],
  // Every provenance the emitter can report. An unknown one is refused rather
  // than recorded, so a value whose origin this parser cannot explain never
  // reaches the artifact looking explained.
  known_ticker_provenances: [
    "env:ORCH_BLOCK_INTERVAL_MS",
    "env:ORCH_BLOCK_INTERVAL_SECS",
    "config:block_production_interval_secs",
  ],
  known_min_tick_provenances: ["env:ORCH_CONSENSUS_MIN_TICK_MS", "default"],
  // `unresolved` means the emitter saw a value the genesis builder would have
  // rejected, so no chain with that floor exists. It is accepted as a token and
  // then refused as a cadence, rather than silently echoed.
  known_block_interval_provenances: [
    "env:IOI_BENCH_BLOCK_INTERVAL_MS",
    "default:test-genesis",
    "unresolved",
  ],
  notes:
    "Cadence fields are CONFIGURATION resolved as the scheduler and genesis builder resolve it. block_timestamp_ms is the only observation. No duration is carried here; the wait before a proposal picks up a queued tx is not measured by any seam.",
};

export const BENCH_TAGS = {
  approval: "[BENCH-APPROVAL]",
  consensus: "[BENCH-CONSENSUS]",
  exec: "[BENCH-EXEC]",
  iavl: BENCH_IAVL_CONTRACT.tag,
  ordering: BENCH_ORDERING_CONTRACT.tag,
};

// A measurement the emitter could not take is spelled this way rather than
// being rendered as 0, which a parser would misread as "this cost nothing".
export const UNAVAILABLE = "unavailable";

// ---------------------------------------------------------------------------
// Phase semantics
// ---------------------------------------------------------------------------

// The kinds a value in this artifact can have. Every phase declares one, so a
// reader never has to infer what a number means from its name.
export const VALUE_KINDS = {
  inclusive:
    "A CONTAINER: contains the phases named in `contains`. NEVER sum an inclusive phase with what it contains.",
  nested: "Contained by every phase named in `nested_in`; already counted inside each of them.",
  // The previous wording -- "disjoint from every other phase" -- contradicted
  // the rows that carry it: state_commitment_materialization IS nested inside
  // execution_commit and says so. Disjointness is a property among LEAVES, not
  // between a leaf and the container that holds it.
  exclusive:
    "A LEAF: contains nothing, and is disjoint from every OTHER exclusive leaf. It is still nested inside the containers named in `nested_in` -- being a leaf is not being top-level. Exclusive leaves are the only phases that may be summed with each other.",
  derived: "Computed from other values in this artifact rather than read from a trace line.",
  polling_quantized:
    "Rounded up to the client status-poll interval. An upper bound on the underlying latency, not the latency.",
  unmeasured:
    "No seam measures this. Recorded as absent with a reason; never defaulted, interpolated, or inferred.",
};

// The ten M04.9 ordering/finality slots, in path order.
//
// A slot with no evidence is present and marked `unmeasured` rather than
// omitted: a phase that silently disappears reads as a phase that costs
// nothing, which is the failure this whole artifact exists to prevent.
export const ORDERING_PARITY_SLOTS = [
  "submission",
  "admission_queueing",
  "proposal_cadence_wait",
  "ordering_finalization",
  "execution",
  "state_commitment",
  "durable_persistence",
  "receipt_creation_durable_ack",
  "completion_notification_client_observation",
  "proof_exact_state_resolution",
];

// EXPLICIT NESTING. `process_block_ms` measured by consensus CONTAINS the
// execution prepare and commit it dispatched, and execution's `persist_ms`
// CONTAINS state commitment and durable store time. Summing every phase would
// therefore count finality time two or three times. Each phase below declares
// whether it is `inclusive` (contains the phases it names), `exclusive`
// (disjoint from every other phase), or `unmeasured`, plus what it is nested
// inside, so a reader can only add up a set that actually partitions the path.
export const PHASES = {
  client_submission_admission: {
    slot: "submission",
    ordinal: 1,
    measured: true,
    semantics: "inclusive",
    source: "[BENCH-APPROVAL].admission_ms",
    describes:
      "wall time of the submit_transaction RPC that admitted the approval tx; contains transport and whatever server-side admission and mempool enqueue that call performed",
    contains: ["admission_queueing"],
    nested_in: [],
    quantized_by: null,
  },
  admission_queueing: {
    slot: "admission_queueing",
    ordinal: 2,
    measured: false,
    semantics: "unmeasured",
    source: null,
    describes: "server-side admission and mempool enqueue, separated from the submitting RPC",
    contains: [],
    nested_in: ["client_submission_admission"],
    quantized_by: null,
    unmeasured_reason:
      "No seam times admission or mempool enqueue apart from the submit_transaction RPC that performs them. The cost is real and is contained in client_submission_admission, but it is not separable from it, so it is not reported as its own number.",
  },
  proposal_cadence_wait: {
    slot: "proposal_cadence_wait",
    ordinal: 3,
    measured: false,
    semantics: "unmeasured",
    source: null,
    describes:
      "wait from the tx sitting in the mempool until a proposal picks it up -- gated by the ON-CHAIN block interval, not by the scheduler ticker",
    contains: [],
    nested_in: ["client_commit_wait"],
    quantized_by: null,
    unmeasured_reason:
      "This wait elapses partly between consensus ticks and partly inside the block-production deferral that returns early while expected_timestamp_ms > now_ms; no seam brackets either part. The CONFIGURED floor (genesis_block_interval_ms) and the REALIZED block spacing (observed_block_interval_ms) are both recorded, but neither is this phase's duration: they describe when blocks were due and how far apart they landed, not how long any particular tx waited for one.",
  },
  ordering_finalization: {
    slot: "ordering_finalization",
    ordinal: 4,
    measured: true,
    semantics: "inclusive",
    source:
      "[BENCH-CONSENSUS] proposal_select(select_ms+verify_ms) + proposal_process(process_block_ms) + proposal_finalize(finalize_ms)",
    // Renamed from `aft_inclusion_finalization`. Solo produces this phase too,
    // so an AFT-specific name would have mislabelled every Solo row.
    describes:
      "ordering-engine selection, block processing, and finalization at the committed height, whichever engine produced it",
    contains: [
      "execution_prepare",
      "execution_commit",
      "state_commitment_materialization",
      "durable_persistence",
      "receipt_creation_durable_ack",
    ],
    nested_in: ["client_commit_wait"],
    quantized_by: null,
  },
  execution_prepare: {
    slot: "execution",
    ordinal: 5,
    measured: true,
    // A LEAF, not a container: it declares `contains: []`, and speculative
    // execution runs before commitment rather than around it, so it overlaps
    // no other exclusive leaf. Labelling it `inclusive` said it contained
    // phases it does not, and kept a genuinely summable leaf out of
    // `safe_partition` -- so a reader following the artifact's own rule dropped
    // real execution time from every partition.
    semantics: "exclusive",
    source: "[BENCH-EXEC] prepare_block.total_ms",
    describes: "speculative execution of the block's transactions before commitment",
    contains: [],
    nested_in: ["client_commit_wait", "ordering_finalization"],
    quantized_by: null,
  },
  execution_commit: {
    slot: "execution",
    ordinal: 5,
    measured: true,
    semantics: "inclusive",
    source: "[BENCH-EXEC] commit_block.total_ms",
    describes: "proof verification, state application, end-block, and durable commit",
    contains: [
      "state_commitment_materialization",
      "durable_persistence",
      "receipt_creation_durable_ack",
    ],
    nested_in: ["client_commit_wait", "ordering_finalization"],
    quantized_by: null,
  },
  state_commitment_materialization: {
    slot: "state_commitment",
    ordinal: 6,
    measured: true,
    semantics: "exclusive",
    source: "[BENCH-IAVL].commitment_ms",
    describes: "materializing the new commitment version over the state tree",
    contains: [],
    nested_in: ["client_commit_wait", "ordering_finalization", "execution_commit"],
    quantized_by: null,
  },
  durable_persistence: {
    slot: "durable_persistence",
    ordinal: 7,
    measured: true,
    semantics: "exclusive",
    source: "[BENCH-IAVL].durable_store_ms",
    describes:
      "building the persistence adapter input, then writing the committed version and block through the durable store",
    contains: [],
    nested_in: ["client_commit_wait", "ordering_finalization", "execution_commit"],
    quantized_by: null,
  },
  receipt_creation_durable_ack: {
    slot: "receipt_creation_durable_ack",
    ordinal: 8,
    measured: false,
    semantics: "unmeasured",
    source: null,
    describes: "creating the individual authority receipts and durably acknowledging them",
    contains: [],
    nested_in: ["client_commit_wait", "ordering_finalization", "execution_commit"],
    quantized_by: null,
    unmeasured_reason:
      "No seam times receipt creation or its durable acknowledgement apart from the commit that writes them. Root batching and individual authority receipts are unchanged by this profiler; their cost is contained in execution_commit and durable_persistence and is not separable there.",
  },
  client_commit_wait: {
    slot: "completion_notification_client_observation",
    ordinal: 9,
    measured: true,
    semantics: "inclusive",
    source: "[BENCH-APPROVAL].commit_wait_ms",
    describes:
      "client-observed wait until the tx reported COMMITTED, by polling; an UPPER BOUND rounded up to the poll interval, not the commit latency",
    contains: [
      "proposal_cadence_wait",
      "ordering_finalization",
      "execution_prepare",
      "execution_commit",
      "state_commitment_materialization",
      "durable_persistence",
      "receipt_creation_durable_ack",
    ],
    nested_in: [],
    quantized_by: "poll_interval_ms",
  },
  proof_exact_state_resolution: {
    slot: "proof_exact_state_resolution",
    ordinal: 10,
    measured: true,
    semantics: "exclusive",
    source: "[BENCH-APPROVAL].approval_query_ms + [BENCH-APPROVAL].approval_verify_ms",
    describes:
      "post-commit exact approval-state read proving this request hash names this decision, and its resolution",
    // DELIBERATELY NOT the daemon's authority-resolution time. That response
    // wraps a whole second governed effect — including its own submission,
    // inclusion, and commit — so folding it in here would count the commit path
    // twice. It is carried per approval under `correlation`, as a route-level
    // fact, not as a slice of this approval's own commit path.
    contains: [],
    nested_in: [],
    quantized_by: null,
  },
};

// Phases carrying a number on every approval row.
export const REQUIRED_PHASES = Object.keys(PHASES).filter((name) => PHASES[name].measured);

// Phases present in the contract but carrying no number, ever.
export const UNMEASURED_PHASES = Object.keys(PHASES).filter((name) => !PHASES[name].measured);

// Completion notification is POLLED, not pushed.
//
// The public API does expose a SubscribeEvents stream, but its BlockCommitted
// event carries only height and state_root -- `tx_count` is hardcoded to zero
// and no transaction hash is carried -- so it cannot say WHICH transaction
// completed. Correlating a specific approval would require a second RPC and a
// block scan per event, which is an architectural expansion and would measure
// block observation rather than status publication. So event-driven completion
// is recorded here as unimplemented rather than estimated.
export const EVENT_DRIVEN_COMPLETION = {
  status: "unimplemented",
  measured: false,
  reason:
    "No existing notification abstraction carries per-transaction completion. SubscribeEvents' BlockCommitted carries height and state_root only, with tx_count hardcoded to 0 and no tx hash, so it cannot identify the completing transaction without a second RPC and a block scan.",
  consequence:
    "completion_notification_client_observation is polling-quantized and is an upper bound; the push-notification latency it would otherwise be compared against is not measured by this artifact.",
};

// Dimensions that must be present for an approval row to be complete. A row
// missing any of these is not downgraded to a partial observation; it fails.
export const REQUIRED_DIMENSIONS = [
  "build_profile",
  "state_commitment_backend",
  "durable_store_backend",
  "committed_height",
  "version_count",
  "tree_depth",
  "block_bytes",
  "new_node_bytes",
  "cpu_user_ms",
  "cpu_system_ms",
  "poll_interval_ms",
  "poll_count",
];

// ---------------------------------------------------------------------------
// Line parsing
// ---------------------------------------------------------------------------

// Parse one `[TAG] <op?> k=v k=v ...` benchmark line.
//
// Returns `null` for any line that does not carry `tag`. Log drains prefix
// these lines with their own framing, so the tag is located rather than
// anchored to column zero.
export function parseBenchLine(line, tag) {
  const text = String(line ?? "");
  const at = text.indexOf(tag);
  if (at < 0) return null;
  const tokens = text.slice(at + tag.length).trim().split(/\s+/u).filter(Boolean);
  const fields = {};
  const op = [];
  for (const token of tokens) {
    const split = token.indexOf("=");
    if (split <= 0) {
      // A bare token before the first key=value is the operation name.
      if (Object.keys(fields).length === 0) op.push(token);
      continue;
    }
    fields[token.slice(0, split)] = token.slice(split + 1);
  }
  return { tag, op: op.join(" "), fields };
}

// Read a field that must be a non-negative integer.
//
// `undefined` (absent) and `UNAVAILABLE` (emitter could not measure) are
// distinct outcomes and are both returned as `null`; callers that require the
// value fail closed on it rather than substituting a number.
export function integerField(fields, name) {
  const raw = fields?.[name];
  if (raw === undefined || raw === UNAVAILABLE) return null;
  return /^[0-9]+$/u.test(raw) ? Number(raw) : null;
}

// Commitment and persistence routinely complete below one millisecond. Their
// emitter therefore retains three decimal places instead of rounding real work
// to zero; all count/height/byte fields continue to use integerField.
export function decimalMillisecondField(fields, name) {
  const raw = fields?.[name];
  if (raw === undefined || raw === UNAVAILABLE) return null;
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/u.test(raw)) return null;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

// Read a JSON-sourced millisecond value that must be a real finite number.
//
// `Number(undefined)` is `NaN`, and `NaN` is neither `null` nor `undefined` —
// so a plain conversion would slip an absent field past a null check and into
// the artifact as an unattributable value.
export function millisecondValue(record, name) {
  const raw = record?.[name];
  return typeof raw === "number" && Number.isFinite(raw) ? raw : null;
}

function readTextIfFile(path) {
  try {
    if (!statSync(path).isFile()) return "";
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

// Concatenate every regular file in `dir`, plus any extra paths.
//
// The trace directory holds one drained log per validator component, so which
// file a given line landed in is not meaningful; which height it names is.
export function collectTraceText(dir, extraPaths = []) {
  const parts = [];
  let entries = [];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    entries = [];
  }
  for (const entry of entries) {
    if (entry.isFile()) parts.push(readTextIfFile(join(dir, entry.name)));
  }
  for (const path of extraPaths) parts.push(readTextIfFile(path));
  return parts.join("\n");
}

// Index `[TAG] <op>` lines by the height they name.
//
// The last observation for a height wins, and the number of observations is
// carried so a reader can see when a height was emitted more than once (a
// replayed or re-proposed height) instead of that fact disappearing.
export function indexByHeight(text, tag, op = null) {
  const index = new Map();
  for (const line of String(text ?? "").split("\n")) {
    const parsed = parseBenchLine(line, tag);
    if (!parsed) continue;
    if (op !== null && parsed.op !== op) continue;
    const height = integerField(parsed.fields, "height");
    if (height === null) continue;
    const prior = index.get(height);
    index.set(height, {
      fields: parsed.fields,
      observations: (prior?.observations ?? 0) + 1,
    });
  }
  return index;
}

export function parseApprovalLines(text) {
  const approvals = [];
  for (const line of String(text ?? "").split("\n")) {
    const parsed = parseBenchLine(line, BENCH_TAGS.approval);
    if (!parsed) continue;
    if (!/^[0-9a-f]{64}$/u.test(parsed.fields.request_hash ?? "")) continue;
    approvals.push(parsed.fields);
  }
  return approvals;
}

export function parseObservationRecords(text) {
  const records = [];
  for (const line of String(text ?? "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed.kind === "string") records.push(parsed);
    } catch {
      /* a partially flushed diagnostic line is not evidence */
    }
  }
  return records;
}

// ---------------------------------------------------------------------------
// Profile assembly
// ---------------------------------------------------------------------------

class ProfileIncomplete extends Error {}

function requireField(value, what, requestHash) {
  if (value === null || value === undefined) {
    throw new ProfileIncomplete(
      `approval ${requestHash}: ${what} was not observed; the profile refuses to substitute a value`,
    );
  }
  return value;
}

// Build the per-approval commit-path profile.
//
// Pure over its inputs so the attribution can be mutation-proved: planting a
// delay in one source field must move exactly one phase.
export function buildCommitPathProfile({
  approvalFields = [],
  observationRecords = [],
  traceText = "",
  run = {},
}) {
  const consensusSelect = indexByHeight(traceText, BENCH_TAGS.consensus, "proposal_select");
  const consensusProcess = indexByHeight(traceText, BENCH_TAGS.consensus, "proposal_process");
  const consensusFinalize = indexByHeight(traceText, BENCH_TAGS.consensus, "proposal_finalize");
  const execPrepare = indexByHeight(traceText, BENCH_TAGS.exec, "prepare_block");
  const execCommit = indexByHeight(traceText, BENCH_TAGS.exec, "commit_block");
  const iavl = indexByHeight(traceText, BENCH_TAGS.iavl);
  const ordering = indexByHeight(traceText, BENCH_TAGS.ordering, BENCH_ORDERING_CONTRACT.op);

  const approvalRecords = new Map();
  const routeRecords = new Map();
  for (const record of observationRecords) {
    if (record.kind === "approval_record" && record.request_hash) {
      approvalRecords.set(record.request_hash, record);
    }
    if (record.kind === "governed_route" && record.request_hash) {
      routeRecords.set(record.request_hash, record);
    }
  }

  const approvals = [];
  for (const fields of approvalFields) {
    const requestHash = fields.request_hash;
    const height = requireField(
      integerField(fields, "committed_height"),
      "exact committed block height",
      requestHash,
    );
    const commit = requireField(
      execCommit.get(height),
      `[BENCH-EXEC] commit_block at height ${height}`,
      requestHash,
    );
    const prepare = requireField(
      execPrepare.get(height),
      `[BENCH-EXEC] prepare_block at height ${height}`,
      requestHash,
    );
    const tree = requireField(
      iavl.get(height),
      `${BENCH_IAVL_CONTRACT.tag} at height ${height}`,
      requestHash,
    );
    const select = requireField(
      consensusSelect.get(height),
      `[BENCH-CONSENSUS] proposal_select at height ${height}`,
      requestHash,
    );
    const processed = requireField(
      consensusProcess.get(height),
      `[BENCH-CONSENSUS] proposal_process at height ${height}`,
      requestHash,
    );
    const finalize = requireField(
      consensusFinalize.get(height),
      `[BENCH-CONSENSUS] proposal_finalize at height ${height}`,
      requestHash,
    );
    // A parity artifact that cannot name the engine that produced a height is
    // not parity evidence, so this fails closed rather than defaulting.
    const orderingLine = requireField(
      ordering.get(height),
      `${BENCH_ORDERING_CONTRACT.tag} ${BENCH_ORDERING_CONTRACT.op} at height ${height}`,
      requestHash,
    );
    for (const name of BENCH_ORDERING_CONTRACT.required_fields) {
      if (orderingLine.fields[name] === undefined) {
        throw new ProfileIncomplete(
          `approval ${requestHash}: ${BENCH_ORDERING_CONTRACT.tag} at height ${height} omits required field '${name}'`,
        );
      }
    }
    const orderingProfile = orderingLine.fields.ordering_profile;
    if (!BENCH_ORDERING_CONTRACT.known_profiles.includes(orderingProfile)) {
      throw new ProfileIncomplete(
        `approval ${requestHash}: ${BENCH_ORDERING_CONTRACT.tag} at height ${height} reports ` +
          `ordering_profile=${orderingProfile}, which this parser does not know; refusing to attribute ` +
          `measurements to an unrecognized ordering engine`,
      );
    }
    // A cadence whose origin this parser cannot name is not evidence of the
    // cadence: `500` means one thing if it came from the flag under test and
    // another if the override was ignored and config answered instead.
    for (const [field, known] of [
      ["ticker_interval_provenance", BENCH_ORDERING_CONTRACT.known_ticker_provenances],
      ["min_tick_provenance", BENCH_ORDERING_CONTRACT.known_min_tick_provenances],
      [
        "genesis_block_interval_provenance",
        BENCH_ORDERING_CONTRACT.known_block_interval_provenances,
      ],
    ]) {
      const reported = orderingLine.fields[field];
      if (!known.includes(reported)) {
        throw new ProfileIncomplete(
          `approval ${requestHash}: ${BENCH_ORDERING_CONTRACT.tag} at height ${height} reports ` +
            `${field}=${reported}, which this parser does not know; a cadence whose provenance ` +
            `cannot be named is not attributable`,
        );
      }
    }

    for (const name of BENCH_IAVL_CONTRACT.required_fields) {
      if (tree.fields[name] === undefined) {
        throw new ProfileIncomplete(
          `approval ${requestHash}: ${BENCH_IAVL_CONTRACT.tag} at height ${height} omits required field '${name}'`,
        );
      }
    }
    if (tree.fields.atomic_state_block !== BENCH_IAVL_CONTRACT.atomic_state_block_expected) {
      throw new ProfileIncomplete(
        `approval ${requestHash}: ${BENCH_IAVL_CONTRACT.tag} at height ${height} reports ` +
          `atomic_state_block=${tree.fields.atomic_state_block}; state and block were not committed atomically`,
      );
    }

    const route = routeRecords.get(requestHash) ?? null;
    const recorded = approvalRecords.get(requestHash) ?? null;

    const commitmentMs = requireField(
      decimalMillisecondField(tree.fields, "commitment_ms"),
      "state commitment materialization time",
      requestHash,
    );
    const durableStoreMs = requireField(
      decimalMillisecondField(tree.fields, "durable_store_ms"),
      "durable store time",
      requestHash,
    );
    // Route correlation is per-ROUTE, not per-approval: approvals recorded by
    // the System bootstrap never traverse the governed helpers, so requiring one
    // here would refuse an otherwise complete profile. Its absence is recorded
    // as absence on the row, and the run-level coverage check below still fails
    // closed if NO approval was route-correlated.
    const authorityResolutionMs = millisecondValue(route, "authority_resolution_ms");
    const proofResolutionMs =
      requireField(integerField(fields, "approval_query_ms"), "approval-state query time", requestHash) +
      requireField(
        integerField(fields, "approval_verify_ms"),
        "approval-state resolution time",
        requestHash,
      );

    const consensusMs =
      requireField(integerField(select.fields, "select_ms"), "consensus select time", requestHash) +
      requireField(integerField(select.fields, "verify_ms"), "consensus verify time", requestHash) +
      requireField(
        integerField(processed.fields, "process_block_ms"),
        "consensus process_block time",
        requestHash,
      ) +
      requireField(integerField(finalize.fields, "finalize_ms"), "consensus finalize time", requestHash);

    const phases = {
      client_submission_admission: requireField(
        integerField(fields, "admission_ms"),
        "RPC admission time",
        requestHash,
      ),
      client_commit_wait: requireField(
        integerField(fields, "commit_wait_ms"),
        "committed-status wait time",
        requestHash,
      ),
      ordering_finalization: consensusMs,
      execution_prepare: requireField(
        integerField(prepare.fields, "total_ms"),
        "execution prepare_block time",
        requestHash,
      ),
      execution_commit: requireField(
        integerField(commit.fields, "total_ms"),
        "execution commit_block time",
        requestHash,
      ),
      state_commitment_materialization: commitmentMs,
      durable_persistence: durableStoreMs,
      proof_exact_state_resolution: proofResolutionMs,
    };
    for (const name of REQUIRED_PHASES) {
      requireField(phases[name] ?? null, `phase '${name}'`, requestHash);
    }

    const dimensions = {
      build_profile: requireField(run.build_profile ?? null, "build profile", requestHash),
      state_commitment_backend: requireField(
        run.state_commitment_backend ?? null,
        "state commitment backend",
        requestHash,
      ),
      durable_store_backend: requireField(
        tree.fields.durable_store ?? run.durable_store_backend ?? null,
        "durable store backend",
        requestHash,
      ),
      committed_height: height,
      version_count: requireField(
        integerField(tree.fields, "version_count"),
        "version count",
        requestHash,
      ),
      tree_depth: requireField(integerField(tree.fields, "tree_depth"), "tree depth", requestHash),
      unique_nodes: integerField(tree.fields, "unique_nodes"),
      new_nodes: integerField(tree.fields, "new_nodes"),
      new_node_bytes: requireField(
        integerField(tree.fields, "new_node_bytes"),
        "new node bytes",
        requestHash,
      ),
      block_bytes: requireField(
        integerField(commit.fields, "block_bytes") ?? integerField(tree.fields, "block_bytes"),
        "committed block bytes",
        requestHash,
      ),
      cpu_user_ms: requireField(
        integerField(commit.fields, "proc_cpu_user_ms"),
        "process CPU user time across the commit window",
        requestHash,
      ),
      cpu_system_ms: requireField(
        integerField(commit.fields, "proc_cpu_sys_ms"),
        "process CPU system time across the commit window",
        requestHash,
      ),
      poll_interval_ms: requireField(
        integerField(fields, "commit_poll_interval_ms"),
        "commit status poll interval",
        requestHash,
      ),
      poll_count: requireField(
        integerField(fields, "commit_poll_count"),
        "commit status poll count",
        requestHash,
      ),
      snapshot_clone_ms: integerField(commit.fields, "snapshot_clone_ms"),
      commit_persist_ms: integerField(commit.fields, "persist_ms"),
      tx_count: integerField(commit.fields, "tx_count"),
    };
    for (const name of REQUIRED_DIMENSIONS) {
      requireField(dimensions[name] ?? null, `dimension '${name}'`, requestHash);
    }

    // Residuals subtract the nested phases from their containers so a reader
    // can partition the path without double counting. A NEGATIVE residual means
    // the declared nesting does not hold for that observation; it is surfaced
    // as an anomaly rather than clamped away.
    const consensusExclusiveMs =
      phases.ordering_finalization - (phases.execution_prepare + phases.execution_commit);
    const commitExclusiveMs =
      phases.execution_commit - (phases.state_commitment_materialization + phases.durable_persistence);
    const anomalies = [];
    if (consensusExclusiveMs < 0) {
      anomalies.push("consensus_exclusive_ms_negative: consensus time is below the execution it contains");
    }
    if (commitExclusiveMs < 0) {
      anomalies.push("commit_exclusive_ms_negative: commit time is below the commitment/store it contains");
    }
    for (const [label, entry] of [
      ["exec_commit", commit],
      ["exec_prepare", prepare],
      ["iavl", tree],
    ]) {
      if (entry.observations > 1) {
        anomalies.push(`${label}_height_observed_${entry.observations}_times`);
      }
    }

    approvals.push({
      request_hash: requestHash,
      policy_hash: fields.policy_hash ?? null,
      principal_ref: fields.principal_ref ?? null,
      target_scope: fields.target_scope ?? null,
      route: route?.route ?? null,
      tx_hash: fields.tx_hash ?? null,
      // Which engine ordered this height, and the cadence it was configured
      // with. Configuration, never a duration.
      ordering: {
        profile: orderingProfile,
        // Renamed from `proposal_cadence`: the container held only the SCHEDULER
        // period while its name promised the cadence at which proposals happen.
        // Those are different mechanisms, and the on-chain block interval is the
        // one that actually governs. The name now says which it carries: both.
        scheduler_and_block_cadence: {
          // How often consensus is POLLED, as the scheduler resolved it. 0 means
          // the ticker loop returns before servicing anything, halting consensus.
          ticker_interval_ms: requireField(
            integerField(orderingLine.fields, "ticker_interval_ms"),
            "effective proposal ticker interval",
            requestHash,
          ),
          ticker_interval_provenance: orderingLine.fields.ticker_interval_provenance,
          // The scheduler's minimum spacing between consensus ticks, from any
          // prior tick rather than only a kick-driven one.
          min_tick_ms: requireField(
            integerField(orderingLine.fields, "min_tick_ms"),
            "effective consensus minimum tick interval",
            requestHash,
          ),
          min_tick_provenance: orderingLine.fields.min_tick_provenance,
          // When a block is DUE. This is the floor that actually spaces blocks.
          genesis_block_interval_ms: requireField(
            integerField(orderingLine.fields, "genesis_block_interval_ms"),
            "on-chain genesis block interval",
            requestHash,
          ),
          genesis_block_interval_provenance:
            orderingLine.fields.genesis_block_interval_provenance,
          view_timeout_secs: requireField(
            integerField(orderingLine.fields, "view_timeout_secs"),
            "configured view timeout",
            requestHash,
          ),
          measured: false,
        },
        // OBSERVED, unlike everything above it: the on-chain timestamp this
        // height carries.
        block_timestamp_ms: requireField(
          integerField(orderingLine.fields, "block_timestamp_ms"),
          "on-chain block timestamp",
          requestHash,
        ),
        view: integerField(orderingLine.fields, "view"),
      },
      phases,
      // Present-and-absent, with the reason, so a missing phase reads as
      // "not measured" rather than "cost nothing".
      unmeasured_phases: Object.fromEntries(
        UNMEASURED_PHASES.map((name) => [
          name,
          { value: null, kind: "unmeasured", reason: PHASES[name].unmeasured_reason },
        ]),
      ),
      derived_exclusive_ms: {
        consensus_excluding_execution: consensusExclusiveMs,
        commit_excluding_commitment_and_store: commitExclusiveMs,
      },
      dimensions,
      correlation: {
        route_correlated: route !== null,
        record_approval_ms: millisecondValue(recorded, "record_approval_ms"),
        record_approval_attempts: millisecondValue(recorded, "record_approval_attempts"),
        authority_resolution_ms: authorityResolutionMs,
        route_response_status: route?.response_status ?? null,
      },
      anomalies,
    });
  }

  if (approvals.length === 0) {
    throw new ProfileIncomplete(
      "no approval observations were parsed; a profile with no attributed approval is not evidence",
    );
  }
  const routeCorrelated = approvals.filter((entry) => entry.correlation.route_correlated).length;
  if (routeCorrelated === 0) {
    throw new ProfileIncomplete(
      "no approval was correlated to a governed route; the governed-helper instrumentation produced nothing",
    );
  }

  // A parity artifact must be attributable to ONE ordering profile. A mixed
  // set would silently average two engines into a single figure, which is
  // exactly the comparison this artifact exists to make impossible to fake.
  const observedProfiles = [...new Set(approvals.map((entry) => entry.ordering.profile))].sort();
  if (observedProfiles.length !== 1) {
    throw new ProfileIncomplete(
      `approvals span more than one ordering profile (${observedProfiles.join(", ")}); ` +
        "a parity profile must attribute every measurement to a single ordering engine",
    );
  }
  const observedCadences = [
    ...new Set(
      approvals.map((entry) =>
        JSON.stringify([
          entry.ordering.scheduler_and_block_cadence.ticker_interval_ms,
          entry.ordering.scheduler_and_block_cadence.ticker_interval_provenance,
          entry.ordering.scheduler_and_block_cadence.min_tick_ms,
          entry.ordering.scheduler_and_block_cadence.min_tick_provenance,
          entry.ordering.scheduler_and_block_cadence.genesis_block_interval_ms,
          entry.ordering.scheduler_and_block_cadence.genesis_block_interval_provenance,
          entry.ordering.scheduler_and_block_cadence.view_timeout_secs,
        ]),
      ),
    ),
  ];

  // The realized block spacing, DERIVED FROM OBSERVATION rather than from the
  // configured floor: consecutive attributed heights differenced by their
  // on-chain timestamps. This is what can contradict the configured floor -- a
  // sweep whose flag never reached block production shows the same spacing at
  // every requested cadence, and this is the field that shows it.
  //
  // Only adjacent heights are differenced; a gap means intervening blocks were
  // not attributed to an approval, and their spacing is not this profile's to
  // claim.
  const timestampByHeight = new Map(
    approvals.map((entry) => [entry.dimensions.committed_height, entry.ordering.block_timestamp_ms]),
  );
  const observedBlockIntervalsMs = [
    ...new Set(
      [...timestampByHeight.keys()]
        .sort((a, b) => a - b)
        .flatMap((height, index, heights) => {
          if (index === 0) return [];
          const previous = heights[index - 1];
          if (height - previous !== 1) return [];
          return [timestampByHeight.get(height) - timestampByHeight.get(previous)];
        }),
    ),
  ].sort((a, b) => a - b);
  const pollIntervals = [...new Set(approvals.map((entry) => entry.dimensions.poll_interval_ms))];

  return {
    schema_version: ARTIFACT_SCHEMA_VERSION,
    schema_compatibility: SCHEMA_COMPATIBILITY,
    generated_at_ms: Date.now(),
    run,
    // The dimensions an ordering/finality comparison is read against.
    ordering_parity: {
      ordering_profile: observedProfiles[0],
      ordering_profile_provenance: `observed:${BENCH_ORDERING_CONTRACT.tag}`,
      // WHAT ELSE MOVES WHEN THE ORDERING PROFILE MOVES.
      //
      // A comparison is only attributable to the ordering profile if nothing
      // else varies with it. That claim was previously made and was false:
      // Solo derived block timestamps from a whole-second wall clock while AFT
      // derived them from ms-granular on-chain timing state, so a Solo-vs-AFT
      // delta was co-produced by two mechanisms with nothing separating them.
      //
      // That co-variable is now removed at the source rather than disclosed:
      // both engines call `compute_next_timestamp_ms` over the same
      // BlockTimingParams/BlockTimingRuntime with the same inputs, and both
      // fail closed on missing timing state. What remains unmeasured is listed
      // so a reader is not left to assume the list is empty.
      dimension_control: {
        varied: ["ordering_profile"],
        held_identical: [
          "block-timestamp derivation (both engines use compute_next_timestamp_ms over the same on-chain BlockTimingParams/BlockTimingRuntime)",
          "genesis block timing (base == min == max == effective, retarget disabled, same value for both profiles)",
          "scheduler ticker and minimum tick spacing",
          "client status-poll interval",
          "admission, execution, IAVL commitment, Redb durability and status/receipt path",
        ],
        // Named rather than implied absent. These are real and unquantified.
        unmeasured_timing_dimensions: [
          "The wait between a tx entering the mempool and the next proposal picking it up is not bracketed by any seam; only the configured floor and the realized block spacing are reported.",
          "Host scheduling noise, and any variation in when the deferral wake-up fires relative to the due timestamp, are not measured.",
          "Wall-clock alignment of the first block: the initial tip is pinned through IOI_TESTING_INITIAL_TIP_TIMESTAMP_MS for both engines, but the phase of the chain clock relative to the host clock is not recorded.",
        ],
        residual_risk:
          "A single-validator fixture exercises no cross-node ordering, so this profile says nothing about how either engine behaves with peers.",
      },
      scheduler_and_block_cadence: {
        values: observedCadences.map((entry) => {
          const [
            ticker_interval_ms,
            ticker_interval_provenance,
            min_tick_ms,
            min_tick_provenance,
            genesis_block_interval_ms,
            genesis_block_interval_provenance,
            view_timeout_secs,
          ] = JSON.parse(entry);
          return {
            ticker_interval_ms,
            ticker_interval_provenance,
            min_tick_ms,
            min_tick_provenance,
            genesis_block_interval_ms,
            genesis_block_interval_provenance,
            view_timeout_secs,
          };
        }),
        // Each value carries its own provenance above; the cadence is the one
        // the scheduler and genesis builder resolved, which is not always the
        // one config declares.
        provenance: `observed:${BENCH_ORDERING_CONTRACT.tag}`,
        measured: false,
        governs:
          "genesis_block_interval_ms is the floor that spaces blocks. ticker_interval_ms only decides how often consensus is polled and cannot produce a block earlier than that floor.",
      },
      // The realized spacing, differenced from on-chain block timestamps. Put
      // beside the configured floor precisely so the two can be compared: if a
      // cadence flag did not reach block production, these stay put while the
      // configured value moves.
      observed_block_interval_ms: {
        values: observedBlockIntervalsMs,
        provenance: `derived:${BENCH_ORDERING_CONTRACT.tag}.block_timestamp_ms`,
        measured: true,
        note: "Differences between on-chain timestamps of CONSECUTIVE attributed heights. Non-adjacent heights are not differenced. This is the block spacing the chain actually ran at, not a latency.",
      },
      // Reported because it sets the resolution of the client-observed phase:
      // a commit faster than one interval is indistinguishable from any other
      // commit faster than one interval.
      poll_interval_ms: { values: pollIntervals, quantizes: "client_commit_wait" },
      event_driven_completion: EVENT_DRIVEN_COMPLETION,
      slots: ORDERING_PARITY_SLOTS,
    },
    value_kinds: VALUE_KINDS,
    phase_semantics: PHASES,
    // Stated in the artifact so a reader does not have to rederive it from the
    // nesting graph before adding anything up.
    summation_rule: {
      never_sum:
        "Inclusive phases are containers: each contains the phases listed in its `contains`. Summing a container with anything it contains double- or triple-counts the same time.",
      // Every exclusive leaf, derived from PHASES rather than hand-listed, so
      // the rule and the labels cannot drift apart. `execution_prepare` belongs
      // here: it is disjoint from the other leaves and omitting it dropped real
      // execution time from every partition a reader built.
      safe_partition: Object.entries(PHASES)
        .filter(([, phase]) => phase.semantics === "exclusive")
        .map(([name]) => name),
      // Stated precisely rather than loosely: these leaves do NOT sum to any
      // container. They are pairwise disjoint, so summing them is meaningful;
      // they are not exhaustive, so the sum is a lower bound on the container,
      // and the difference is the container's unattributed residual.
      partition_is_exhaustive: false,
      note: "The exclusive leaves are pairwise disjoint but do not cover their containers. Their sum is a LOWER BOUND on the enclosing container, never equal to it. Use derived_exclusive_ms for the residual a container holds beyond the leaves named here.",
    },
    parser_contract: {
      bench_iavl: BENCH_IAVL_CONTRACT,
      bench_ordering: BENCH_ORDERING_CONTRACT,
      tags: BENCH_TAGS,
    },
    coverage: {
      approvals_attributed: approvals.length,
      heights_attributed: new Set(approvals.map((a) => a.dimensions.committed_height)).size,
      approvals_with_anomalies: approvals.filter((a) => a.anomalies.length > 0).length,
      // Approvals recorded outside the governed helpers (System bootstrap) are
      // attributed but carry no route; the split is stated rather than blurred.
      approvals_route_correlated: routeCorrelated,
      approvals_without_route: approvals.length - routeCorrelated,
    },
    nonclaims: [
      "No numeric approval latency budget is established or enforced here.",
      "CPU figures are process-wide deltas across the commit window, not commit-exclusive CPU.",
      "client_commit_wait is quantized by poll_interval_ms and is not an exact commit latency.",
      "Approvals recorded outside the governed helpers carry no route correlation; see coverage.",
      "This profile proves only the exact build profile, backend, and host it ran on.",
      "scheduler_and_block_cadence is CONFIGURATION, reported as the scheduler and genesis builder resolved it. The actual wait before a proposal picked up a queued tx is not measured by any seam, so no cadence-wait duration is claimed.",
      // CORRECTED. The previous wording said the ticker and min-tick BOUND when
      // a queued tx can be picked up. They do not: block production defers
      // until the on-chain timestamp is due, so a ticker faster than the
      // genesis block interval changes nothing about pickup. Stating the false
      // direction invited exactly the wrong reading of a cadence sweep.
      "ticker_interval_ms and min_tick_ms bound only how often consensus is POLLED. They do not bound when a queued tx is picked up: production defers while expected_timestamp_ms > now_ms, so the on-chain genesis_block_interval_ms is the binding floor and a faster ticker buys nothing below it.",
      "genesis_block_interval_ms is read from the same benchmark override the genesis builder reads, not from the running chain. A resumed chain keeps the genesis it was built with, so on a resumed run this field can name a floor the chain does not have; observed_block_interval_ms is the value that would show it.",
      "No proof generation, proof size, or cryptographic proof verification is measured anywhere in this artifact.",
      "proof_exact_state_resolution is a post-commit READ of committed state (approval_query_ms + approval_verify_ms). It is not a portable proof, does not produce one, and its cost implies nothing about what producing or verifying one would cost.",
      "receipt_creation_durable_ack is unmeasured: no receipt-creation or receipt-durability timing is claimed by any number here.",
      "admission_queueing and receipt_creation_durable_ack are unmeasured; their cost is real and contained in neighbouring phases, not zero.",
      "Completion notification is polled, not pushed; no event-driven completion latency is measured.",
      "A single-profile artifact is not a comparison. Comparing two profiles requires two artifacts and is not performed here.",
    ],
    approvals,
  };
}

export { ProfileIncomplete };

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export function profileEnv(baseEnv, traceDir, teeLogPath, options = {}) {
  const env = {
    ...baseEnv,
    // The soak's own release-profile gate, unchanged.
    IOI_WALLET_FIXTURE_RELEASE: "1",
    // The estate's existing trace seam, and where its drained logs land.
    IOI_AFT_BENCH_TRACE: "1",
    IOI_AFT_BENCH_TRACE_DIR: traceDir,
    // Fixture stdout carries [BENCH-APPROVAL]; retain it.
    IOI_WALLET_FIXTURE_TEE_LOG: teeLogPath,
    // See the header: without this the trace seam changes readiness semantics.
    IOI_TEST_READY_HEIGHT_LAG_MAX: READY_HEIGHT_LAG_MAX,
  };
  // Only set when explicitly asked for. Unset means the fixture and the node
  // run their own defaults (the AFT control, the 500ms poll interval, the
  // scheduler's own cadence), so an unflagged profiling run is byte-identical
  // to the M04.8 behaviour.
  if (options.orderingProfile) env.IOI_M049_ORDERING_PROFILE = options.orderingProfile;
  if (options.pollIntervalMs !== null && options.pollIntervalMs !== undefined) {
    env.IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS = String(options.pollIntervalMs);
  }
  // The two SERVER-side cadence knobs, distinct from the CLIENT-side poll
  // interval above. They reach the node by inheritance: this env is handed to
  // the verifier, which hands it to the wallet fixture guardian, which hands it
  // to the cargo test that spawns `orchestration` -- and `sanitizedVerifierBaseEnv`
  // strips only IOI_TEST_*/IOI_HYPERVISOR_WALLET_*/IOI_WALLET_NETWORK_*, so
  // ORCH_* names survive that boundary intact.
  // ONE FLAG, BOTH MECHANISMS. Setting only the ticker was the defect: block
  // production defers until the on-chain timestamp is due, so with the
  // historical 1000ms genesis floor a ticker of 50ms produced 1000ms blocks
  // while the artifact reported 50. The cadence is only real when the genesis
  // floor moves with it, so a single flag drives both and they are reported
  // separately so a reader can see they agreed.
  if (options.proposalCadenceMs !== null && options.proposalCadenceMs !== undefined) {
    env.ORCH_BLOCK_INTERVAL_MS = String(options.proposalCadenceMs);
    env.IOI_BENCH_BLOCK_INTERVAL_MS = String(options.proposalCadenceMs);
  }
  if (options.consensusMinTickMs !== null && options.consensusMinTickMs !== undefined) {
    env.ORCH_CONSENSUS_MIN_TICK_MS = String(options.consensusMinTickMs);
  }
  return env;
}

// The ordering profiles this wrapper may request, matching the fixture's own
// bounded selector exactly. Anything else is refused rather than passed
// through, so a typo cannot silently run the control and be labelled otherwise.
export const SELECTABLE_ORDERING_PROFILES = ["Aft", "Solo"];

// The bounded numeric wrapper flags.
//
// Each is INDEPENDENT: `--poll-interval-ms` is a CLIENT-side status-poll period
// enforced by crates/cli, while `--proposal-cadence-ms` and
// `--consensus-min-tick-ms` are SERVER-side scheduler knobs. Setting one must
// never imply another, or a run that varied a single dimension would silently
// have varied two and the comparison would answer a question nobody asked.
//
// `min` is chosen from what the receiving code actually honours, not from
// taste. `--proposal-cadence-ms` refuses 0 because the scheduler filters
// ORCH_BLOCK_INTERVAL_MS on `> 0`: a 0 would be discarded and the node would
// silently run its config cadence while the flag read as "cadence 0".
// `--consensus-min-tick-ms` accepts 0 because the scheduler genuinely honours
// 0 there (no kick throttle).
export const NUMERIC_FLAGS = {
  "--poll-interval-ms": {
    field: "pollIntervalMs",
    min: 1,
    max: 5000,
    why: "the bound crates/cli enforces on IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS",
  },
  // Drives BOTH the scheduler ticker and the on-chain genesis block interval.
  // The upper bound is the tighter of the two receivers' bounds: the genesis
  // builder rejects anything above 60_000ms, so accepting more here would let
  // the wrapper pass a value that aborts the fixture at genesis construction.
  "--proposal-cadence-ms": {
    field: "proposalCadenceMs",
    min: 1,
    max: 60_000,
    why: "ORCH_BLOCK_INTERVAL_MS is honoured by the scheduler only when > 0, and the genesis builder accepts 1..=60000ms for IOI_BENCH_BLOCK_INTERVAL_MS; this flag sets both, so it takes the tighter bound",
  },
  "--consensus-min-tick-ms": {
    field: "consensusMinTickMs",
    min: 0,
    max: 600_000,
    why: "ORCH_CONSENSUS_MIN_TICK_MS is honoured at 0 (no kick throttle); the ceiling keeps a typo from stalling a run past any plausible cadence",
  },
};

export function parseArgs(argv) {
  const args = {
    out: null,
    durableStore: "redb",
    orderingProfile: null,
    pollIntervalMs: null,
    proposalCadenceMs: null,
    consensusMinTickMs: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    // Split on the FIRST `=` only: a path may legitimately contain one.
    const at = argv[index].indexOf("=");
    const flag = at < 0 ? argv[index] : argv[index].slice(0, at);
    const inline = at < 0 ? undefined : argv[index].slice(at + 1);
    const value = inline ?? argv[index + 1];
    if (flag === "--out") {
      args.out = value;
      if (inline === undefined) index += 1;
    } else if (flag === "--durable-store") {
      args.durableStore = value;
      if (inline === undefined) index += 1;
    } else if (flag === "--ordering-profile") {
      if (!SELECTABLE_ORDERING_PROFILES.includes(value)) {
        throw new Error(
          `--ordering-profile must be one of ${SELECTABLE_ORDERING_PROFILES.join(", ")}; got ${JSON.stringify(value)}`,
        );
      }
      args.orderingProfile = value;
      if (inline === undefined) index += 1;
    } else if (Object.hasOwn(NUMERIC_FLAGS, flag)) {
      // `hasOwn`, not a truthiness test: `NUMERIC_FLAGS["constructor"]` would
      // otherwise resolve up the prototype chain and turn an unrecognized
      // argument into a confusing bounds error instead of being ignored.
      const { field, min, max, why } = NUMERIC_FLAGS[flag];
      // `Number("")` is 0 and `Number(" 5 ")` is 5, so an explicit reject of a
      // blank value keeps an empty flag from reading as a deliberate bound.
      const parsed = value === "" || value === undefined ? NaN : Number(value);
      if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
        throw new Error(
          `${flag} must be an integer in ${min}..=${max} (${why}); got ${JSON.stringify(value)}`,
        );
      }
      args[field] = parsed;
      if (inline === undefined) index += 1;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outDir = resolve(args.out ?? mkdtempSync(join(tmpdir(), "ioi-m048-profile-")));
  mkdirSync(outDir, { recursive: true });
  const traceDir = join(outDir, "trace");
  mkdirSync(traceDir, { recursive: true });
  const teeLogPath = join(outDir, "wallet-fixture.log");
  writeFileSync(teeLogPath, "");

  console.log(`M04.8 commit-path profile — artifacts under ${outDir}`);
  console.log(
    "Running the COMPLETE wallet-authority soak: no approval is reduced, skipped, or reordered.",
  );

  const soak = spawn(process.execPath, [join(HERE, SOAK_VERIFIER)], {
    // Match `npm --prefix apps/hypervisor run soak:...`, whose script cwd is
    // the package directory. The wrapper changes observation only, not cwd.
    cwd: join(HERE, ".."),
    env: profileEnv(process.env, traceDir, teeLogPath, {
      orderingProfile: args.orderingProfile,
      pollIntervalMs: args.pollIntervalMs,
      proposalCadenceMs: args.proposalCadenceMs,
      consensusMinTickMs: args.consensusMinTickMs,
    }),
    stdio: ["ignore", "inherit", "inherit"],
  });
  const soakExit = await new Promise((resolveExit) => {
    soak.once("exit", (code, signal) => resolveExit({ code, signal }));
    soak.once("error", (error) => resolveExit({ code: null, signal: `spawn-error:${error.message}` }));
  });

  const traceText = collectTraceText(traceDir, [teeLogPath]);
  const observationText = readTextIfFile(join(traceDir, "commit-path-observations.jsonl"));

  let profile;
  let profileError = null;
  try {
    profile = buildCommitPathProfile({
      approvalFields: parseApprovalLines(traceText),
      observationRecords: parseObservationRecords(observationText),
      traceText,
      run: {
        verifier: `apps/hypervisor/scripts/${SOAK_VERIFIER}`,
        soak_exit_code: soakExit.code,
        soak_exit_signal: soakExit.signal ?? null,
        build_profile: "release",
        // Entailed by the line itself: only the IAVL commitment writer emits
        // [BENCH-IAVL], so its presence at a height identifies that backend.
        state_commitment_backend: "iavl",
        // DECLARED, not observed — unless the IAVL line carries `durable_store`,
        // in which case the observed value wins.
        durable_store_backend: args.durableStore,
        durable_store_backend_provenance: "declared:--durable-store",
        // What was REQUESTED. What actually ran is read back from the trace
        // into `ordering_parity.ordering_profile`; the two are kept separate so
        // a request that did not take effect cannot masquerade as an outcome.
        requested_ordering_profile: args.orderingProfile,
        requested_poll_interval_ms: args.pollIntervalMs,
        // Likewise REQUESTED. What the scheduler resolved is read back from
        // [BENCH-ORDERING] into `ordering_parity.scheduler_and_block_cadence`,
        // each value with its own provenance, so a request the node discarded
        // cannot masquerade as the cadence that ran.
        requested_proposal_cadence_ms: args.proposalCadenceMs,
        requested_consensus_min_tick_ms: args.consensusMinTickMs,
        readiness_lag_pin: {
          IOI_TEST_READY_HEIGHT_LAG_MAX: READY_HEIGHT_LAG_MAX,
          why: "IOI_AFT_BENCH_TRACE otherwise raises the cluster ready-height lag from 1 to 16",
        },
      },
    });
  } catch (error) {
    profileError = error;
  }

  if (profile) {
    const artifactPath = join(outDir, "commit-path-profile.json");
    writeFileSync(artifactPath, `${JSON.stringify(profile, null, 2)}\n`);
    console.log(
      `PROFILE: ${profile.coverage.approvals_attributed} approvals across ` +
        `${profile.coverage.heights_attributed} heights -> ${artifactPath}`,
    );
  } else {
    console.error(`PROFILE INCOMPLETE: ${profileError?.message ?? profileError}`);
  }

  if (soakExit.code !== 0) {
    console.error(`SOAK FAILED: exit ${soakExit.code}${soakExit.signal ? `/${soakExit.signal}` : ""}`);
  }
  process.exitCode = soakExit.code === 0 && profile ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error("PROFILE CRASH:", error);
    process.exitCode = 1;
  });
}
