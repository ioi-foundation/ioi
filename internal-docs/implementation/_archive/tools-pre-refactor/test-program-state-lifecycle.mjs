#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  currentAggregateExit,
  deriveP0Protocol,
  evidenceBindingForEntry,
  proofGateClosureForStage,
  readWorkItems,
  verifyStatusPreservation,
} from "./generate-program-state.mjs";
import { contentBoundLiteralEvidence } from "./content-bound-literal.mjs";
import { implementationRoot, repoRoot, sha256, sha256File, stableJson } from "./lib.mjs";

function recordEntry(record) {
  return {
    record,
    record_ref: `internal-docs/implementation/work-items/${record.work_item_id}.v1.json`,
    record_sha256: sha256(stableJson(record)),
  };
}

function leaf(id, status = "verified") {
  return {
    evidence_format: "ioi.program.work_item.v1",
    work_item_id: id,
    stage_id: "M0",
    record_role: "implementation_cut",
    status,
    dependency_work_item_ids: [],
    aggregate_child_ids: [],
    aggregate_child_dispositions: [],
    aggregate_verification_binding: null,
    applicable_pg_ids: [],
    pg_gate_states: [],
    evidence_index: {
      literal_exit: `${id.toUpperCase().replaceAll("-", "_")}_EXIT=0`,
      expected_output_paths: [`private-test/${id}.exit.v1.txt`],
    },
    evidence_refs: [`private-test/${id}.exit.v1.txt`],
  };
}

function aggregateFixture() {
  const required = recordEntry(leaf("required-child"));
  const optional = recordEntry(leaf("optional-child", "proposed"));
  const dispositions = [
    {
      child_work_item_id: required.record.work_item_id,
      selection_state: "unconditional_active",
      activation_gate_id: null,
      selection_authority: "sole-sequencer stage membership",
      selection_evidence_refs: [],
      disposition_basis: "The selected stage requires this child and its retained proof before aggregate verification.",
    },
    {
      child_work_item_id: optional.record.work_item_id,
      selection_state: "conditional_not_selected",
      activation_gate_id: "test-optional-gate",
      selection_authority: "ioi-target-end-state-master-implementation-guide.md",
      selection_evidence_refs: [],
      disposition_basis: "The sole sequencer has not selected this optional child, so nonselection creates no closure claim.",
    },
  ];
  const aggregateRecord = {
    evidence_format: "ioi.program.work_item.v1",
    work_item_id: "m0-program-control-selected-profile-exit-proof",
    stage_id: "M0",
    record_role: "aggregate_exit",
    status: "verified",
    dependency_work_item_ids: [],
    aggregate_child_ids: [required.record.work_item_id, optional.record.work_item_id],
    aggregate_child_dispositions: dispositions,
    aggregate_verification_binding: null,
    applicable_pg_ids: [],
    pg_gate_states: [],
    evidence_index: {
      literal_exit: "M0_EXIT=0",
      expected_output_paths: ["private-test/m0.exit.v1.txt"],
    },
    evidence_refs: ["private-test/m0.exit.v1.txt"],
  };
  const aggregate = recordEntry(aggregateRecord);
  const childBindings = [required, optional].map((entry, index) => ({
    work_item_id: entry.record.work_item_id,
    relation: "aggregate_child",
    selection_state: dispositions[index].selection_state,
    record_sha256: entry.record_sha256,
    status_at_binding: entry.record.status,
    evidence_binding: evidenceBindingForEntry(entry),
  }));
  const aggregateEvidenceBinding = evidenceBindingForEntry(aggregate);
  const payload = {
    child_dispositions: dispositions,
    child_bindings: childBindings,
    dependency_bindings: [],
    aggregate_evidence_binding: aggregateEvidenceBinding,
  };
  aggregate.record.aggregate_verification_binding = {
    schema_version: "ioi.program.aggregate-verification-binding.v1",
    ...payload,
    binding_payload_sha256: sha256(stableJson(payload)),
    nonclaim: "This binding does not promote a child, dependency, aggregate, work item, or stage.",
  };
  return {
    aggregate,
    required,
    optional,
    recordsById: new Map([
      [aggregate.record.work_item_id, aggregate],
      [required.record.work_item_id, required],
      [optional.record.work_item_id, optional],
    ]),
  };
}

const literalEvidence = () => true;

{
  const temporaryRoot = fs.mkdtempSync(path.join(implementationRoot, ".literal-inspector-test-"));
  try {
    const artifactPath = path.join(temporaryRoot, "artifact.json");
    const evidencePath = path.join(temporaryRoot, "exit.v1.txt");
    fs.writeFileSync(artifactPath, "{\"result\":\"PASS\"}\n");
    const artifactRef = path.relative(repoRoot, artifactPath).split(path.sep).join("/");
    const evidenceRef = path.relative(repoRoot, evidencePath).split(path.sep).join("/");
    fs.writeFileSync(evidencePath, "BARE_EXIT=0\n");
    assert.equal(contentBoundLiteralEvidence(evidenceRef, "BARE_EXIT=0"), false);
    fs.writeFileSync(
      evidencePath,
      [
        "IOI_LITERAL_EXIT_LOG_FORMAT=ioi.program.literal_exit.v1",
        "BAR=BOUND",
        `ARTIFACT=${artifactRef}`,
        `ARTIFACT_SHA256=${sha256File(artifactPath)}`,
        "BOUND_EXIT=0",
        "",
      ].join("\n"),
    );
    assert.equal(contentBoundLiteralEvidence(evidenceRef, "BOUND_EXIT=0"), true);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

{
  const fixture = aggregateFixture();
  const result = currentAggregateExit("M0", fixture.recordsById, [], { literalEvidence });
  assert.equal(result.aggregate_closure_satisfied, true);
  assert.deepEqual(result.record_closure.non_verified_record_ids, []);
  assert.deepEqual(result.record_closure.literal_invalid_record_ids, []);
  assert.deepEqual(result.record_closure.inactive_conditional_child_ids, ["optional-child"]);
  assert(!result.record_closure.required_record_ids.includes("optional-child"));
}

{
  const fixture = aggregateFixture();
  fixture.required.record.status = "active";
  const result = currentAggregateExit("M0", fixture.recordsById, [], { literalEvidence });
  assert.equal(result.aggregate_closure_satisfied, false);
  assert(result.record_closure.non_verified_record_ids.includes("required-child"));
}

{
  const fixture = aggregateFixture();
  fixture.aggregate.record.aggregate_verification_binding.binding_payload_sha256 = "0".repeat(64);
  const result = currentAggregateExit("M0", fixture.recordsById, [], { literalEvidence });
  assert.equal(result.aggregate_closure_satisfied, false);
  assert(result.record_closure.stale_aggregate_binding_ids.includes(
    "m0-program-control-selected-profile-exit-proof",
  ));
}

{
  const gate = {
    pg_id: "PG-TEST",
    closure_owner_work_item_id: "gate-owner",
    closure_stage_id: "M5",
    applicability: "required_now",
    profile_selection: "selected",
    closure_status: "open",
    literal_exit: null,
    evidence_refs: [],
  };
  assert.equal(proofGateClosureForStage("M5", [gate], { literalEvidence }).satisfied, false);
  const closed = {
    ...gate,
    closure_status: "closed",
    literal_exit: "PG_TEST_EXIT=0",
    evidence_refs: ["private-test/pg-test.exit.v1.txt"],
  };
  assert.equal(proofGateClosureForStage("M5", [closed], { literalEvidence }).satisfied, true);
  assert.equal(proofGateClosureForStage("M4", [closed], { literalEvidence }).required_gate_count, 0);
}

{
  const records = readWorkItems().map((entry) => ({
    ...entry,
    record: { ...entry.record },
  }));
  const historical = records.find(({ record }) => (
    record.work_item_id === "m0-literal-exit-evidence-contract"
  ));
  historical.record.status = "scoped";
  const introduced = records.find(({ record }) => (
    record.work_item_id === "m0-program-control-selected-profile-exit-proof"
  ));
  introduced.record.status = "active";
  const audit = verifyStatusPreservation(records);
  assert.equal(audit.result, "PASS");
  assert.equal(audit.current_comparison.status_transition_count, 1);
  assert.equal(audit.current_comparison.introduced_records_all_proposed_now, false);
}

{
  const owner = recordEntry({
    ...leaf("m5-p0-readiness-verifier", "active"),
    stage_id: "M5",
  });
  const recordsById = new Map([[owner.record.work_item_id, owner]]);
  const incompleteStages = ["M3", "M4", "M5"].map((stageId) => ({
    stage_id: stageId,
    current_sequencer_exit: {
      aggregate_work_item_id: stageId === "M3" ? "m3-direct-path-and-exit-proof" : `aggregate-${stageId}`,
      retained_successful_literal_refs: [],
      satisfied: false,
    },
  }));
  const active = deriveP0Protocol({
    ownerEntry: owner,
    stages: incompleteStages,
    recordsById,
    proofGateRows: [],
    literalEvidence,
  });
  assert.equal(active.state, "owner_active_readiness_not_verified");

  owner.record.status = "verified";
  const completeStages = incompleteStages.map((stage) => ({
    ...stage,
    current_sequencer_exit: {
      ...stage.current_sequencer_exit,
      retained_successful_literal_refs: ["private-test/stage.exit.v1.txt"],
      satisfied: true,
    },
  }));
  const verified = deriveP0Protocol({
    ownerEntry: owner,
    stages: completeStages,
    recordsById,
    proofGateRows: [],
    literalEvidence,
  });
  assert.equal(verified.readiness_verified, true);
  assert.equal(verified.state, "readiness_verified");
}

process.stdout.write(
  "program-state lifecycle tests passed: historical audit is non-freezing; aggregate/status/literal/binding/gate and P0 chains fail closed.\n",
);
