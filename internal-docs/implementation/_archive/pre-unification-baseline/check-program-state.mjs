#!/usr/bin/env node
// Read-only validator for the machine-local program-state projection.
//
// This checker validates projection freshness and owner consistency. It does
// not treat a successful process exit as a stage-exit proof and closes no
// stage. Run from the repository root after regeneration:
//   node scripts/generate-program-state.mjs
//   node internal-docs/implementation/check-program-state.mjs
import fs from "node:fs";
import path from "node:path";
import {
  GUIDE_FILE,
  M0_EVIDENCE_FILES,
  M0_EXIT_FILE,
  M0_LITERAL_EXIT_FILE,
  P0_OWNER_WORK_ITEM_ID,
  REPO_ROOT,
  STATE_FILE,
  buildProgramState,
  discoverWorkItems,
  readM0LiteralExit,
  readGuideStages,
  stableJson,
} from "../../scripts/generate-program-state.mjs";

const errors = [];
const fail = (condition, message) => {
  if (!condition) {
    errors.push(message);
  }
};

const readJson = (relativePath) =>
  JSON.parse(fs.readFileSync(path.join(REPO_ROOT, relativePath), "utf8"));

let state;
try {
  state = readJson(STATE_FILE);
} catch (error) {
  process.stderr.write(`program-state check failed: cannot read ${STATE_FILE}: ${error.message}\n`);
  process.exit(1);
}

fail(
  state.evidence_format === "ioi.program.live_state.v1",
  "program state has an unknown evidence_format",
);
fail(
  state.authority === GUIDE_FILE,
  "program state must name the master guide as authority",
);
fail(
  typeof state.rule === "string"
    && state.rule.includes("not a second sequencer")
    && state.rule.includes("grants nothing and closes nothing")
    && state.rule.includes("unsigned hash chain")
    && state.rule.includes("wallet-network grants, sealed intents, and receipts"),
  "program-state rule must preserve projection, claim, workflow-evidence, and product-authority boundaries",
);
fail(
  /^\d{4}-\d{2}-\d{2}$/u.test(state.as_of?.date ?? ""),
  "program state as_of.date must be an ISO date",
);
fail(
  state.as_of?.master_ref === "origin/master"
    || state.as_of?.master_ref === "master",
  "program state must name its resolved master ref",
);
fail(
  /^[0-9a-f]{40}$/u.test(state.as_of?.master_commit ?? ""),
  "program state as_of.master_commit must be a full commit hash",
);

// The generator parses these headings, but validate the guide's stateless
// contract directly as well: no M-stage may carry a live `Status:` line.
try {
  const guide = fs.readFileSync(path.join(REPO_ROOT, GUIDE_FILE), "utf8");
  readGuideStages(REPO_ROOT);
  fail(
    /Status truth rule:/u.test(guide),
    "master guide must declare the Status truth rule",
  );
  const stageSections = guide.split(/^### (M(?:[0-9]|1[0-4])) — .+$/mu);
  for (let index = 1; index < stageSections.length; index += 2) {
    const stageId = stageSections[index];
    const body = stageSections[index + 1] ?? "";
    fail(
      !/^Status:\s*/mu.test(body),
      `master guide ${stageId} section contains a live Status: line`,
    );
  }
} catch (error) {
  errors.push(`cannot validate stateless master guide: ${error.message}`);
}

const expectedStageIds = Array.from({ length: 15 }, (_, index) => `M${index}`);
const stageIds = (state.stages ?? []).map((stage) => stage.stage_id);
fail(
  JSON.stringify(stageIds) === JSON.stringify(expectedStageIds),
  `stages must list exactly M0-M14 in order (got ${stageIds.join(", ")})`,
);
const stageById = new Map(
  (state.stages ?? []).map((stage) => [stage.stage_id, stage]),
);
const verifiedStages = (state.stages ?? [])
  .filter((stage) => stage.state === "verified")
  .map((stage) => stage.stage_id);
fail(
  JSON.stringify(verifiedStages) === JSON.stringify(["M0"]),
  `only M0 has a committed stage-exit proof in this projection (got ${verifiedStages.join(", ") || "none"})`,
);
const ongoingStages = (state.stages ?? [])
  .filter((stage) => ["active", "evidence_ready"].includes(stage.state))
  .map((stage) => stage.stage_id);
for (let index = 1; index < expectedStageIds.length; index += 1) {
  const stage = stageById.get(expectedStageIds[index]);
  const predecessor = stageById.get(expectedStageIds[index - 1]);
  fail(
    !["active", "evidence_ready", "verified"].includes(stage?.state)
      || predecessor?.state === "verified",
    `${stage?.stage_id} is ${stage?.state} without verified predecessor ${predecessor?.stage_id}`,
  );
}

// M0 is the only stage-verification derivation in this projection. Validate
// the committed artifact and every evidence pointer; do not use work-item
// completion as a substitute for the stage-exit report.
try {
  const m0Exit = readJson(M0_EXIT_FILE);
  const m0LiteralExit = readM0LiteralExit(REPO_ROOT);
  const m0 = stageById.get("M0");
  fail(
    m0Exit.evidence_format === "ioi.m0.exit_report.v1",
    `${M0_EXIT_FILE} has an unknown evidence_format`,
  );
  fail(
    m0Exit.m0_exit_state === "verified"
      && m0?.state === "verified"
      && m0?.status_basis?.kind === "stage_exit_proof"
      && m0?.status_basis?.ref === M0_EXIT_FILE,
    "M0 projection does not match its committed stage-exit proof",
  );
  fail(
    m0?.status_basis?.literal_exit?.ref === M0_LITERAL_EXIT_FILE
      && m0?.status_basis?.literal_exit?.literal === "M0_EXIT=0"
      && m0?.status_basis?.literal_exit?.artifact_ref === M0_EXIT_FILE
      && m0?.status_basis?.literal_exit?.artifact_sha256
        === m0LiteralExit.artifact_sha256,
    "M0 projection is not gated by the content-bound literal M0_EXIT=0 log",
  );
  fail(
    m0Exit.architecture_or_production_capability_closure === false,
    "M0 exit report must retain its no-architecture/production-closure boundary",
  );
  fail(
    m0?.cross_check?.m0_exit_state === m0Exit.m0_exit_state
      && m0?.cross_check?.as_of === m0Exit.as_of_date
      && m0?.cross_check?.literal_exit === "M0_EXIT=0"
      && m0?.cross_check?.literal_exit_artifact_sha256
        === m0LiteralExit.artifact_sha256
      && m0?.cross_check?.architecture_or_production_capability_closure
        === m0Exit.architecture_or_production_capability_closure,
    "M0 cross_check does not match the exit report",
  );
  fail(
    JSON.stringify(m0?.evidence) === JSON.stringify(M0_EVIDENCE_FILES),
    "M0 evidence pointers differ from the generator's committed evidence set",
  );
  for (const evidencePath of M0_EVIDENCE_FILES) {
    fail(
      fs.existsSync(path.join(REPO_ROOT, evidencePath)),
      `M0 evidence path does not exist: ${evidencePath}`,
    );
  }
} catch (error) {
  errors.push(`cannot cross-check M0 exit evidence: ${error.message}`);
}

// Re-discover current records from the ignored private estate. Cuts are
// current while active or evidence_ready; zero or multiple concurrent cuts
// are valid. No tracked or remote-ref record is treated as a status owner.
let discovery;
try {
  discovery = discoverWorkItems(REPO_ROOT);
  const discoveredCuts = discovery.current_cuts;
  fail(
    !Object.hasOwn(state, "active_cut"),
    "program state must not retain the retired active_cut field",
  );
  fail(
    !Object.hasOwn(state, "current_cut"),
    "program state must use current_cuts rather than the retired singular current_cut field",
  );
  fail(
    Array.isArray(state.current_cuts),
    "program state current_cuts must be an array",
  );
  fail(
    state.current_cuts?.length === discoveredCuts.length,
    "current_cuts length does not match deduplicated ongoing work-item discovery",
  );
  for (const [index, discovered] of discoveredCuts.entries()) {
    const currentRecord = discovered.record;
    fail(
      ["active", "evidence_ready"].includes(currentRecord.status),
      `discovered current work item has non-ongoing status ${currentRecord.status}`,
    );
    const projected = state.current_cuts?.[index];
    fail(
      projected?.work_item_id === currentRecord.work_item_id
        && projected?.stage_id === currentRecord.stage_id
        && projected?.status === currentRecord.status
        && projected?.objective === currentRecord.objective
        && projected?.pr === (currentRecord.pr ?? null)
        && projected?.branch === discovered.branch
        && projected?.record_sha256 === discovered.record_sha256
        && stableJson(projected?.source_refs)
          === stableJson(discovered.source_refs)
        && stableJson(projected?.source_commits)
          === stableJson(discovered.source_commits),
      `current_cuts[${index}] does not match private ongoing work item ${currentRecord.work_item_id}`,
    );
  }

  const recordsByStage = new Map();
  for (const { record } of discoveredCuts) {
    const records = recordsByStage.get(record.stage_id) ?? [];
    records.push(record);
    recordsByStage.set(record.stage_id, records);
  }
  const expectedOngoingStages = [...recordsByStage.keys()].sort(
    (left, right) => Number(left.slice(1)) - Number(right.slice(1)),
  );
  fail(
    stableJson(ongoingStages) === stableJson(expectedOngoingStages),
    "active/evidence_ready stages do not match the stages owning current cuts",
  );
  for (const [stageId, records] of recordsByStage.entries()) {
    const expectedState = records.some((record) => record.status === "active")
      ? "active"
      : "evidence_ready";
    const expectedWorkItems = records.map((record) => ({
      work_item_id: record.work_item_id,
      status: record.status,
    }));
    const stage = stageById.get(stageId);
    fail(
      stage?.state === expectedState
        && stage?.status_basis?.kind === "current_work_items"
        && stableJson(stage?.status_basis?.work_items)
          === stableJson(expectedWorkItems),
      `${stageId} does not aggregate its exact current work-item IDs/statuses`,
    );
  }
} catch (error) {
  errors.push(`cannot cross-check current work-item refs: ${error.message}`);
}

// P0 is a future readiness-verifier slice, not estate-branch evidence and not
// an activated cohort. Its pointer must resolve to the planned M5 owner.
fail(
  state.p0_protocol?.state === "planned_not_activated",
  "P0 must remain planned_not_activated",
);
fail(
  state.p0_protocol?.owner_work_item_id === P0_OWNER_WORK_ITEM_ID,
  `P0 must point to work item ${P0_OWNER_WORK_ITEM_ID}`,
);
fail(
  state.p0_protocol?.direct_path_preservation_required === true,
  "P0 must retain the direct-path-preservation prerequisite",
);
fail(
  state.p0_protocol?.claim_gate_stage_id === "M9",
  "claim-bearing P0 qualification must remain gated at M9",
);
for (const forbiddenKey of ["files", "evidence", "manifest", "checker"]) {
  fail(
    !Object.hasOwn(state.p0_protocol ?? {}, forbiddenKey),
    `P0 projection must not claim unavailable master evidence through key ${forbiddenKey}`,
  );
}
if (discovery !== undefined) {
  const p0Owner = discovery.projected.find(
    ({ record }) => record.work_item_id === P0_OWNER_WORK_ITEM_ID,
  )?.record;
  fail(p0Owner !== undefined, `P0 owner record ${P0_OWNER_WORK_ITEM_ID} is missing`);
  if (p0Owner !== undefined) {
    const p0Text = stableJson(p0Owner).toLowerCase();
    fail(p0Owner.stage_id === "M5", "P0 readiness-verifier owner must be M5");
    fail(
      ["proposed", "scoped"].includes(p0Owner.status),
      `P0 readiness-verifier owner must remain planned (got ${p0Owner.status})`,
    );
    fail(
      p0Text.includes("readiness")
        && p0Text.includes("verifier")
        && (p0Text.includes("direct-path") || p0Text.includes("direct path")),
      "P0 owner must name both the readiness verifier and direct-path preservation",
    );
  }
}

// Projection freshness: rebuild in memory using the recorded explicit as-of
// date. Any work-item, guide-heading, M0-evidence, ref, or master change must
// be followed by regeneration in the same status transaction.
try {
  const expected = buildProgramState({
    repoRoot: REPO_ROOT,
    asOf: state.as_of?.date,
  });
  fail(
    stableJson(state) === stableJson(expected),
    `program state is stale; run node scripts/generate-program-state.mjs --as-of ${state.as_of?.date ?? "YYYY-MM-DD"}`,
  );
} catch (error) {
  errors.push(`cannot regenerate expected program state in memory: ${error.message}`);
}

const serializedState = JSON.stringify(state);
for (const stalePhrase of [
  "PR #102",
  "estate-camera-pipeline",
  "frozen_not_activated",
  "RUNTIME PROVEN LIVE",
  "parked_lanes",
  "note_worktree_ahead",
]) {
  fail(
    !serializedState.includes(stalePhrase),
    `program state retains stale estate/status prose: ${stalePhrase}`,
  );
}

if (errors.length > 0) {
  process.stderr.write(
    `program-state check failed with ${errors.length} error(s):\n${errors
      .map((message) => `- ${message}`)
      .join("\n")}\n`,
  );
  process.exit(1);
}

const currentSummary =
  state.current_cuts.length === 0
    ? "no ongoing work items"
    : `${state.current_cuts.length} current work item(s): ${state.current_cuts
        .map((cut) => `${cut.work_item_id} (${cut.status}) on ${cut.branch}`)
        .join(", ")}`;
process.stdout.write(
  `program-state check passed: ${state.stages.length} stages; ${currentSummary}; P0 ${state.p0_protocol.state}; as of ${state.as_of.date} (${state.as_of.master_commit.slice(0, 10)}). No stage was closed by this check.\n`,
);
