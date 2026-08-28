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
// Usage:
//   node scripts/profile-m4-wallet-authority-commit-path.mjs [--out DIR] [--durable-store NAME]
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
export const ARTIFACT_SCHEMA_VERSION = "ioi.m048.commit-path-profile.v1";

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

export const BENCH_TAGS = {
  approval: "[BENCH-APPROVAL]",
  consensus: "[BENCH-CONSENSUS]",
  exec: "[BENCH-EXEC]",
  iavl: BENCH_IAVL_CONTRACT.tag,
};

// A measurement the emitter could not take is spelled this way rather than
// being rendered as 0, which a parser would misread as "this cost nothing".
export const UNAVAILABLE = "unavailable";

// ---------------------------------------------------------------------------
// Phase semantics
// ---------------------------------------------------------------------------

// EXPLICIT NESTING. `process_block_ms` measured by consensus CONTAINS the
// execution prepare and commit it dispatched, and execution's `persist_ms`
// CONTAINS state commitment and durable store time. Summing every phase would
// therefore count finality time two or three times. Each phase below declares
// whether it is `inclusive` (contains the phases it names) or `exclusive`
// (disjoint from every other phase), so a reader can only add up a set that
// actually partitions the path.
export const PHASES = {
  client_submission_admission: {
    semantics: "exclusive",
    source: "[BENCH-APPROVAL].admission_ms",
    describes: "wall time of the submit_transaction RPC call that admitted the approval tx",
    contains: [],
  },
  client_commit_wait: {
    semantics: "inclusive",
    source: "[BENCH-APPROVAL].commit_wait_ms",
    describes:
      "client-observed wait until the tx reported COMMITTED; quantized by the status poll interval",
    contains: [
      "aft_inclusion_finalization",
      "execution_prepare",
      "execution_commit",
      "state_commitment_materialization",
      "durable_persistence",
    ],
  },
  aft_inclusion_finalization: {
    semantics: "inclusive",
    source:
      "[BENCH-CONSENSUS] proposal_select(select_ms+verify_ms) + proposal_process(process_block_ms) + proposal_finalize(finalize_ms)",
    describes: "consensus selection, block processing, and finalization at the committed height",
    contains: [
      "execution_prepare",
      "execution_commit",
      "state_commitment_materialization",
      "durable_persistence",
    ],
  },
  execution_prepare: {
    semantics: "inclusive",
    source: "[BENCH-EXEC] prepare_block.total_ms",
    describes: "speculative execution of the block's transactions before commitment",
    contains: [],
  },
  execution_commit: {
    semantics: "inclusive",
    source: "[BENCH-EXEC] commit_block.total_ms",
    describes: "proof verification, state application, end-block, and durable commit",
    contains: ["state_commitment_materialization", "durable_persistence"],
  },
  state_commitment_materialization: {
    semantics: "exclusive",
    source: "[BENCH-IAVL].commitment_ms",
    describes: "materializing the new commitment version over the state tree",
    contains: [],
  },
  durable_persistence: {
    semantics: "exclusive",
    source: "[BENCH-IAVL].durable_store_ms",
    describes:
      "building the persistence adapter input, then writing the committed version and block through the durable store",
    contains: [],
  },
  wallet_proof_resolution: {
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
  },
};

export const REQUIRED_PHASES = Object.keys(PHASES);

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
      aft_inclusion_finalization: consensusMs,
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
      wallet_proof_resolution: proofResolutionMs,
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
      phases.aft_inclusion_finalization - (phases.execution_prepare + phases.execution_commit);
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
      phases,
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

  return {
    schema_version: ARTIFACT_SCHEMA_VERSION,
    generated_at_ms: Date.now(),
    run,
    phase_semantics: PHASES,
    parser_contract: { bench_iavl: BENCH_IAVL_CONTRACT, tags: BENCH_TAGS },
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
    ],
    approvals,
  };
}

export { ProfileIncomplete };

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export function profileEnv(baseEnv, traceDir, teeLogPath) {
  return {
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
}

function parseArgs(argv) {
  const args = { out: null, durableStore: "redb" };
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
    env: profileEnv(process.env, traceDir, teeLogPath),
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
