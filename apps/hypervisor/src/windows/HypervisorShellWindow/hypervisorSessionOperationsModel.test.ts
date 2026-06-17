import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
  HYPERVISOR_RIGHT_INSPECTOR_PANELS,
  HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL,
  HYPERVISOR_SESSION_DETAIL_TABS,
} from "./hypervisorShellNavigationModel";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel";

test("session operations fixture mirrors the canonical shell tab and inspector contract", () => {
  const projection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.session_operations_projection.v1",
  );
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
