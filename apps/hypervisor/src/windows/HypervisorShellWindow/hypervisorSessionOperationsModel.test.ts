import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_BOTTOM_INSPECTOR_PANELS,
  HYPERVISOR_RIGHT_INSPECTOR_PANELS,
  HYPERVISOR_SECONDARY_SESSION_RAIL_MODEL,
  HYPERVISOR_SESSION_DETAIL_TABS,
} from "./hypervisorShellNavigationModel.ts";
import {
  buildHypervisorSessionOperationProposal,
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE,
  HYPERVISOR_SESSION_OPERATION_KINDS,
  HYPERVISOR_SESSION_OPERATION_PROPOSAL_PATH,
  HYPERVISOR_SESSION_OPERATIONS_PROJECTION_PATH,
  loadHypervisorSessionOperationsProjection,
  normalizeHypervisorSessionOperationProposal,
  normalizeHypervisorSessionOperationsProjection,
  proposeHypervisorSessionOperation,
} from "./hypervisorSessionOperationsModel.ts";

test("session operations fixture mirrors the canonical shell tab and inspector contract", () => {
  const projection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.session_operations_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.display_title, "Hypervisor architecture refinement");
  assert.equal(projection.branch_label, "main");
  assert.equal(projection.resource_health_state, "healthy");
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
  assert.ok(projection.activity_signals.length >= 4);
  assert.ok(
    projection.activity_signals.every((signal) =>
      signal.receipt_ref.startsWith("receipt://"),
    ),
  );
  assert.ok(projection.access_log_leases.length >= 2);
  assert.ok(
    projection.access_log_leases.every((lease) =>
      lease.lease_ref.startsWith("lease:") &&
      lease.scope_ref.startsWith("scope:") &&
      lease.receipt_ref.startsWith("receipt://"),
    ),
  );
  assert.ok(projection.environment_lifecycle_steps.length >= 5);
  assert.ok(
    projection.environment_lifecycle_steps.every((step) =>
      step.evidence_ref.startsWith("receipt://") ||
      step.evidence_ref.startsWith("agentgres://"),
    ),
  );
  assert.ok(projection.changed_file_groups.length >= 2);
  assert.ok(
    projection.changed_file_groups.every((group) =>
      group.files.every((file) => file.receipt_ref.startsWith("receipt://")),
    ),
  );
});

test("session operations normalization keeps daemon projections behind runtime truth markers", () => {
  const projection = normalizeHypervisorSessionOperationsProjection(
    {
      projection_id: "hypervisor-session-operations:daemon/normalized",
      selected_session_ref: "session:normalized",
      display_title: "Normalized session",
      branch_label: "feature/session-cockpit",
      lifecycle_state: "waiting_for_approval",
      auto_stop_label: "15m",
      created_label: "2h ago",
      last_started_label: "5m ago",
      resource_health_label: "Attention",
      resource_health_state: "attention",
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
      activity_signals: [
        {
          signal_ref: "signal:normalized/approval",
          kind: "approval",
          label: "Step-up pending",
          detail: "Policy requires an approval before command execution.",
          status: "attention",
          receipt_ref: "receipt://normalized/activity/approval",
        },
      ],
      access_log_leases: [
        {
          lease_ref: "lease:normalized/access",
          label: "Access",
          scope_ref: "scope:session.access",
          status: "active",
          expires_label: "10m",
          receipt_ref: "receipt://normalized/lease/access",
        },
      ],
      environment_lifecycle_steps: [
        {
          step_ref: "session-step:normalized",
          label: "Normalized step",
          detail: "Hydrated from Core",
          status: "running",
          evidence_ref: "receipt://normalized/step",
        },
      ],
      changed_file_groups: [
        {
          group_ref: "changed-group:normalized",
          folder: "src/",
          files: [
            {
              file_ref: "changed-file:normalized",
              name: "index.ts",
              delta: "+7",
              status: "modified",
              receipt_ref: "receipt://normalized/change",
            },
          ],
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
  assert.equal(projection.display_title, "Normalized session");
  assert.equal(projection.branch_label, "feature/session-cockpit");
  assert.equal(projection.lifecycle_state, "waiting_for_approval");
  assert.equal(projection.resource_health_state, "attention");
  assert.equal(projection.session_rail[0]?.state, "waiting_for_approval");
  assert.equal(projection.detail_tabs[0]?.tab_id, "agent");
  assert.equal(projection.right_inspector_panels[0]?.panel_id, "authority");
  assert.equal(projection.ports_services[0]?.lease_ref, "lease:access/test");
  assert.equal(projection.activity_signals[0]?.signal_ref, "signal:normalized/approval");
  assert.equal(projection.access_log_leases[0]?.lease_ref, "lease:normalized/access");
  assert.equal(projection.environment_lifecycle_steps[0]?.step_ref, "session-step:normalized");
  assert.equal(projection.changed_file_groups[0]?.files[0]?.receipt_ref, "receipt://normalized/change");
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
  assert.equal(projection.ports_services[0]?.label, "Workspace control service");
  assert.ok(projection.tasks.length >= 2);
  assert.ok(projection.terminal_events.length >= 2);
  assert.ok(projection.activity_signals.length >= 4);
  assert.ok(
    projection.activity_signals.every((signal) =>
      signal.receipt_ref.startsWith("receipt://"),
    ),
  );
  assert.ok(
    projection.activity_signals.some((signal) => signal.kind === "approval"),
  );
  assert.ok(projection.access_log_leases.length >= 2);
  assert.ok(
    projection.access_log_leases.every((lease) =>
      lease.lease_ref.startsWith("lease:") &&
      lease.scope_ref.startsWith("scope:") &&
      lease.receipt_ref.startsWith("receipt://"),
    ),
  );
  assert.ok(projection.environment_lifecycle_steps.length >= 5);
  assert.ok(projection.changed_file_groups.length >= 2);
  assert.ok(
    projection.latest_receipt_refs.every((receiptRef) =>
      receiptRef.startsWith("receipt://"),
    ),
  );
});

test("session operation proposals bind wallet leases, Agentgres refs, receipts, and restore refs", () => {
  const projection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  const proposal = buildHypervisorSessionOperationProposal(
    projection,
    "propose_terminal_command",
    {
      targetRef: projection.terminal_events[0]?.event_ref,
    },
  );

  assert.equal(
    proposal.schema_version,
    "ioi.hypervisor.session_operation_proposal.v1",
  );
  assert.equal(proposal.source, "fixture");
  assert.equal(proposal.project_ref, projection.project_ref);
  assert.equal(proposal.session_ref, projection.selected_session_ref);
  assert.equal(proposal.operation_kind, "propose_terminal_command");
  assert.equal(proposal.admission_state, "requires_wallet_lease");
  assert.match(proposal.wallet_lease_ref, /^lease:wallet\/session\//);
  assert.ok(proposal.required_scope_refs.includes("scope:shell.exec"));
  assert.match(proposal.agentgres_operation_ref, /^agentgres:\/\/operation\/session\//);
  assert.match(proposal.receipt_ref, /^receipt:\/\/session\//);
  assert.equal(proposal.archive_ref, projection.archive_ref);
  assert.equal(proposal.restore_ref, projection.restore_ref);
  assert.match(proposal.custody_invariant, /wallet\.network grants/);
  assert.deepEqual(
    HYPERVISOR_SESSION_OPERATION_KINDS,
    [
      "request_access_lease",
      "request_log_lease",
      "open_port",
      "run_task",
      "propose_terminal_command",
      "archive_session",
      "restore_session",
    ],
  );
});

test("session operation proposal normalization and loader use daemon admission route", async () => {
  const projection = HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE;
  const normalized = normalizeHypervisorSessionOperationProposal(
    {
      proposal_ref: "session-operation:daemon/open-port",
      source: "daemon-session-operation-proposal",
      operation_kind: "open_port",
      target_ref: "service:daemon",
      admission_state: "requires_wallet_lease",
      required_scope_refs: ["scope:port.expose"],
    },
    {
      projection,
      operationKind: "open_port",
      targetRef: "service:daemon",
    },
  );
  assert.equal(normalized.source, "daemon-session-operation-proposal");
  assert.equal(normalized.operation_kind, "open_port");
  assert.equal(normalized.target_ref, "service:daemon");
  assert.deepEqual(normalized.required_scope_refs, ["scope:port.expose"]);

  const calls: Array<{ input: string; method?: string; body?: unknown }> = [];
  const proposal = await proposeHypervisorSessionOperation({
    endpoint: "http://daemon.test/",
    projection,
    operationKind: "restore_session",
    targetRef: projection.restore_ref,
    fetchImpl: async (input, init) => {
      calls.push({
        input,
        method: init?.method,
        body: init?.body ? JSON.parse(String(init.body)) : null,
      });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            proposal_ref: "session-operation:daemon/restore",
            source: "daemon-session-operation-proposal",
            operation_kind: "restore_session",
            target_ref: projection.restore_ref,
            admission_state: "requires_wallet_lease",
            wallet_lease_ref: "lease:wallet/session/restore",
          });
        },
      };
    },
  });

  assert.deepEqual(calls, [
    {
      input:
        `http://daemon.test${HYPERVISOR_SESSION_OPERATION_PROPOSAL_PATH}`,
      method: "POST",
      body: {
        project_ref: projection.project_ref,
        session_ref: projection.selected_session_ref,
        environment_ref: projection.environment_ref,
        provider_candidate_ref: projection.provider_candidate_ref,
        operation_kind: "restore_session",
        target_ref: projection.restore_ref,
        authority_scope_refs: [
          ...projection.authority_scope_refs,
          "scope:restore.apply",
        ],
        access_lease_ref: projection.access_lease_ref,
        log_lease_ref: projection.log_lease_ref,
        archive_ref: projection.archive_ref,
        restore_ref: projection.restore_ref,
      },
    },
  ]);
  assert.equal(proposal.source, "daemon-session-operation-proposal");
  assert.equal(proposal.operation_kind, "restore_session");
  assert.equal(proposal.wallet_lease_ref, "lease:wallet/session/restore");
});
