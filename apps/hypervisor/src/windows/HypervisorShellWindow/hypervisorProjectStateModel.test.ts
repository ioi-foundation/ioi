import assert from "node:assert/strict";
import test from "node:test";

import { PROJECT_SCOPES } from "./hypervisorShellModel.ts";
import { HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE } from "./hypervisorProjectStateModel.ts";

test("project state projection binds each project to Agentgres restore truth", () => {
  const projection = HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.project_state_projection.v1",
  );
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.records.length, PROJECT_SCOPES.length);
  assert.match(projection.project_boundary_invariant, /Agentgres admits project truth/);
  assert.match(projection.project_boundary_invariant, /storage backends only hold bytes/);

  for (const project of projection.records) {
    assert.ok(project.workspace_ref.startsWith("workspace://"));
    assert.ok(project.agentgres_object_head_ref.startsWith("agentgres://object-head/"));
    assert.ok(project.state_root_ref.startsWith("agentgres://state-root/"));
    assert.ok(project.archive_ref.startsWith("artifact://agentgres/archive/"));
    assert.ok(project.restore_ref.startsWith("agentgres://restore/"));
    assert.ok(project.artifact_refs.length >= 2);
    assert.ok(project.latest_receipt_refs.length >= 1);
    assert.equal(project.adapter_preference_ref, "workbench-adapter:embedded_workbench");
  }
});

test("selected project exposes session, environment, provider, receipts, and local custody", () => {
  const projection = HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE;
  const selected = projection.records.find(
    (record) => record.project_id === projection.selected_project_id,
  );

  assert.equal(selected?.project_id, "hypervisor-core");
  assert.equal(selected?.custody_posture, "local_private");
  assert.equal(selected?.restore_state, "active");
  assert.match(selected?.current_session_ref ?? "", /^session:/);
  assert.match(selected?.environment_ref ?? "", /^environment:/);
  assert.match(selected?.provider_candidate_ref ?? "", /^provider-candidate:/);
  assert.ok(
    selected?.latest_receipt_refs.some((receiptRef) =>
      receiptRef.startsWith("receipt://authority/"),
    ),
  );

  const restoreReady = projection.records.find(
    (record) => record.restore_state === "restore_ready",
  );
  assert.equal(restoreReady?.custody_posture, "encrypted_archive");
  assert.equal(restoreReady?.current_session_ref, null);
});
