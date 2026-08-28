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
// trace, not assumed from the request), the configured proposal cadence, and
// the client poll interval.
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
// Bumped from ioi.m048.commit-path-profile.v1: the phase set is now the ten
// M04.9 ordering/finality slots, one phase was renamed off its AFT-specific
// name, and every value carries an explicit kind. A reader that understood v1
// would mis-read this, so it does not reuse v1's identifier.
export const ARTIFACT_SCHEMA_VERSION = "ioi.m049.ordering-parity-profile.v1";

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
// Accepted line shape:
//   [BENCH-ORDERING] proposal height=<u64> view=<u64> ordering_profile=<name>
//                    block_interval_secs=<u64> view_timeout_secs=<u64>
export const BENCH_ORDERING_CONTRACT = {
  tag: "[BENCH-ORDERING]",
  op: "proposal",
  correlation_field: "height",
  required_fields: [
    "height",
    "view",
    "ordering_profile",
    "block_interval_secs",
    "view_timeout_secs",
  ],
  known_profiles: ["aft", "solo", "proof_of_authority", "proof_of_stake"],
  notes:
    "Configuration only. No duration is carried here; the inter-tick cadence wait is not measured by any seam.",
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
    "Contains the phases named in `contains`. NEVER sum inclusive phases with what they contain.",
  nested: "Contained by every phase named in `nested_in`; already counted inside each of them.",
  exclusive: "Disjoint from every other phase. Only exclusive phases may be summed.",
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
      "wait from the tx sitting in the mempool until the next proposal tick picks it up -- the phase where an immediate single authority and a cadenced quorum engine differ most",
    contains: [],
    nested_in: ["client_commit_wait"],
    quantized_by: null,
    unmeasured_reason:
      "The inter-tick wait elapses in the scheduler between consensus ticks, outside every instrumented span; no existing seam brackets it. The CONFIGURED cadence is recorded per approval under `ordering` and at run level, but configuration is not a measurement and is never presented as this phase's duration.",
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
    semantics: "inclusive",
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
        proposal_cadence: {
          block_interval_secs: requireField(
            integerField(orderingLine.fields, "block_interval_secs"),
            "configured block production interval",
            requestHash,
          ),
          view_timeout_secs: requireField(
            integerField(orderingLine.fields, "view_timeout_secs"),
            "configured view timeout",
            requestHash,
          ),
          provenance: "configured",
          measured: false,
        },
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
          entry.ordering.proposal_cadence.block_interval_secs,
          entry.ordering.proposal_cadence.view_timeout_secs,
        ]),
      ),
    ),
  ];
  const pollIntervals = [...new Set(approvals.map((entry) => entry.dimensions.poll_interval_ms))];

  return {
    schema_version: ARTIFACT_SCHEMA_VERSION,
    generated_at_ms: Date.now(),
    run,
    // The three dimensions an ordering/finality comparison is read against.
    ordering_parity: {
      ordering_profile: observedProfiles[0],
      ordering_profile_provenance: `observed:${BENCH_ORDERING_CONTRACT.tag}`,
      proposal_cadence: {
        values: observedCadences.map((entry) => {
          const [block_interval_secs, view_timeout_secs] = JSON.parse(entry);
          return { block_interval_secs, view_timeout_secs };
        }),
        provenance: "configured",
        measured: false,
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
        "Inclusive phases contain the phases listed in their `contains`. Summing them double- or triple-counts finality time.",
      safe_partition: [
        "state_commitment_materialization",
        "durable_persistence",
        "proof_exact_state_resolution",
      ],
      note: "Use derived_exclusive_ms to partition a container without double counting.",
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
      "proposal_cadence is CONFIGURATION. The actual wait before a proposal picked up a queued tx is not measured by any seam, so no cadence-wait duration is claimed.",
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
  // Only set when explicitly asked for. Unset means the fixture runs its own
  // default (the AFT control, at the 500ms poll interval), so an unflagged
  // profiling run is byte-identical to the M04.8 behaviour.
  if (options.orderingProfile) env.IOI_M049_ORDERING_PROFILE = options.orderingProfile;
  if (options.pollIntervalMs) {
    env.IOI_TESTING_RPC_COMMIT_POLL_INTERVAL_MS = String(options.pollIntervalMs);
  }
  return env;
}

// The ordering profiles this wrapper may request, matching the fixture's own
// bounded selector exactly. Anything else is refused rather than passed
// through, so a typo cannot silently run the control and be labelled otherwise.
export const SELECTABLE_ORDERING_PROFILES = ["Aft", "Solo"];

export function parseArgs(argv) {
  const args = { out: null, durableStore: "redb", orderingProfile: null, pollIntervalMs: null };
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
    } else if (flag === "--poll-interval-ms") {
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 5000) {
        throw new Error(
          `--poll-interval-ms must be an integer in 1..=5000 (the bound crates/cli enforces); got ${JSON.stringify(value)}`,
        );
      }
      args.pollIntervalMs = parsed;
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
