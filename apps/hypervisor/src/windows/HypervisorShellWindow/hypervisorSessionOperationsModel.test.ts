import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
  HYPERVISOR_RIGHT_INSPECTOR_PANELS,
  HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL,
  HYPERVISOR_SESSION_DETAIL_TABS,
} from "./hypervisorShellNavigationModel.ts";
import {
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH,
  loadHypervisorSessionOperationsProjection,
  normalizeHypervisorSessionOperationsProjection,
} from "./hypervisorSessionOperationsModel.ts";

test("session operations fixture mirrors the canonical shell tab and inspector contract", () => {
  const projection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.session_operations_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(
    projection.session_rail.map((item) => item.state),
    [...HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL],
  );
  assert.deepEqual(
    projection.detail_tabs.map((tab) => tab.tab_id),
    HYPERVISOR_SESSION_DETAIL_TABS,
  );
  assert.deepEqual(
    projection.right_inspector_panels.map((panel) => panel.panel_id),
    HYPERVISOR_RIGHT_INSPECTOR_PANELS,
  );
  assert.deepEqual(
    projection.bottom_inspector_panels.map((panel) => panel.panel_id),
    HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
  );
});

test("session operations normalization keeps daemon projections behind runtime truth markers", () => {
  const projection = normalizeHypervisorSessionOperationsProjection(
    {
      projection_id: "hypervisor-session-operations:daemon/normalized",
      selected_session_ref: "session:normalized",
      lifecycle_state: "waiting_for_approval",
      session_rail: [{ state: "waiting_for_approval", count: 3, selected: true }],
      detail_tabs: [{ tab_id: "agent", label: "Agent", summary: "Ready" }],
      right_inspector_panels: [
        {
          panel_id: "authority",
          label: "Authority",
          summary: "Step-up required",
          status: "attention",
          evidence_refs: ["receipt://authority/step-up"],
        },
      ],
      ports_services: [
        {
          service_ref: "service:test",
          label: "Test service",
          port: 17777,
          protocol: "http",
          lease_ref: "lease:access/test",
          status: "lease_required",
        },
      ],
      latest_receipt_refs: ["receipt://session/normalized"],
    },
    { source: "daemon-session-operations-projection" },
  );

  assert.equal(projection.source, "daemon-session-operations-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "hypervisor-session-operations:daemon/normalized");
  assert.equal(projection.selected_session_ref, "session:normalized");
  assert.equal(projection.lifecycle_state, "waiting_for_approval");
  assert.equal(projection.session_rail[0]?.state, "waiting_for_approval");
  assert.equal(projection.detail_tabs[0]?.tab_id, "agent");
  assert.equal(projection.right_inspector_panels[0]?.panel_id, "authority");
  assert.equal(projection.ports_services[0]?.lease_ref, "lease:access/test");
  assert.deepEqual(projection.latest_receipt_refs, ["receipt://session/normalized"]);
});

test("session operations loader calls the daemon projection route with project and session refs", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorSessionOperationsProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    sessionRef: "session:ioi",
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "hypervisor-session-operations:daemon/loaded",
            selected_session_ref: "session:ioi",
            latest_receipt_refs: ["receipt://session/loaded"],
          });
        },
      };
    },
  });

  assert.deepEqual(calls, [
    {
      input:
        `http://daemon.test${HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH}?project_id=project%3Aioi&session_ref=session%3Aioi`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-session-operations-projection");
  assert.equal(projection.projection_id, "hypervisor-session-operations:daemon/loaded");
  assert.equal(projection.selected_session_ref, "session:ioi");
  assert.deepEqual(projection.latest_receipt_refs, ["receipt://session/loaded"]);
});

test("session operations fixture exposes provider, lease, restore, and receipt evidence", () => {
  const projection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  assert.match(projection.provider_candidate_ref, /^provider:/);
  assert.match(projection.environment_ref, /^environment:/);
  assert.match(projection.access_lease_ref, /^lease:access/);
  assert.match(projection.log_lease_ref, /^lease:logs/);
  assert.match(projection.archive_ref, /^artifact:\/\//);
  assert.match(projection.restore_ref, /^agentgres:\/\/restore/);
  assert.ok(projection.authority_scope_refs.includes("scope:workspace.patch"));
  assert.ok(projection.ports_services.length >= 2);
  assert.ok(projection.tasks.length >= 2);
  assert.ok(projection.terminal_events.length >= 2);
  assert.ok(
    projection.latest_receipt_refs.every((receiptRef) =>
      receiptRef.startsWith("receipt://"),
    ),
  );
});
