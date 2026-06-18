import assert from "node:assert/strict";
import test from "node:test";

import { PROJECT_SCOPES } from "./hypervisorShellModel.ts";
import {
  HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE,
  HYPERVISOR_PROJECT_STATE_PROJECTION_PATH,
  loadHypervisorProjectStateProjection,
  normalizeHypervisorProjectStateProjection,
} from "./hypervisorProjectStateModel.ts";

test("project state projection binds each project to Agentgres restore truth", () => {
  const projection = HYPERVISOR_PROJECT_STATE_PROJECTION_FIXTURE;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.project_state_projection.v1",
  );
  assert.equal(projection.source, "fixture");
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
    assert.equal(project.adapter_preference_ref, "code-editor-adapter:embedded_workbench");
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

test("project state normalization preserves Agentgres truth refs from daemon projections", () => {
  const projection = normalizeHypervisorProjectStateProjection(
    {
      projection_id: "project-state:daemon/normalized",
      selected_project_id: "project:normalized",
      records: [
        {
          project_id: "project:normalized",
          name: "Normalized",
          description: "Daemon projected project",
          environment: "Remote VM",
          root_path: "/workspace/normalized",
          workspace_ref: "workspace://normalized",
          current_session_ref: "session:normalized",
          environment_ref: "environment:normalized",
          provider_candidate_ref: "provider-candidate:normalized",
          adapter_preference_ref: "code-editor-adapter:normalized",
          custody_posture: "encrypted_archive",
          restore_state: "restore_ready",
          agentgres_object_head_ref: "agentgres://object-head/project:normalized",
          state_root_ref: "agentgres://state-root/project:normalized",
          artifact_refs: ["artifact://project/normalized/workspace-summary"],
          archive_ref: "artifact://agentgres/archive/normalized/latest",
          restore_ref: "agentgres://restore/normalized/latest",
          latest_receipt_refs: ["receipt://project/normalized/state"],
        },
      ],
      project_boundary_invariant: "Agentgres admits project truth.",
    },
    { source: "daemon-project-state-projection" },
  );

  assert.equal(projection.source, "daemon-project-state-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "project-state:daemon/normalized");
  assert.equal(projection.selected_project_id, "project:normalized");
  assert.equal(projection.records[0]?.project_id, "project:normalized");
  assert.equal(projection.records[0]?.restore_state, "restore_ready");
  assert.equal(projection.records[0]?.custody_posture, "encrypted_archive");
  assert.equal(
    projection.records[0]?.agentgres_object_head_ref,
    "agentgres://object-head/project:normalized",
  );
  assert.equal(
    projection.records[0]?.state_root_ref,
    "agentgres://state-root/project:normalized",
  );
  assert.deepEqual(projection.records[0]?.latest_receipt_refs, [
    "receipt://project/normalized/state",
  ]);
});

test("project state loader calls the daemon projection route with selected project ref", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorProjectStateProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "project-state:daemon/loaded",
            selected_project_id: "project:ioi",
            records: [
              {
                project_id: "project:ioi",
                name: "IOI",
                latest_receipt_refs: ["receipt://project/ioi/state"],
              },
            ],
          });
        },
      };
    },
  });

  assert.deepEqual(calls, [
    {
      input:
        `http://daemon.test${HYPERVISOR_PROJECT_STATE_PROJECTION_PATH}?project_id=project%3Aioi`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-project-state-projection");
  assert.equal(projection.projection_id, "project-state:daemon/loaded");
  assert.equal(projection.selected_project_id, "project:ioi");
  assert.equal(projection.records[0]?.project_id, "project:ioi");
  assert.deepEqual(projection.records[0]?.latest_receipt_refs, [
    "receipt://project/ioi/state",
  ]);
});
