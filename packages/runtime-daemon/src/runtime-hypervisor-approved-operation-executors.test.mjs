import assert from "node:assert/strict";
import test from "node:test";

import {
  admitHypervisorApprovedOperation,
} from "./runtime-hypervisor-approved-operation-admission.mjs";
import {
  createHypervisorApprovedOperationExecutorRegistry,
  expectedExecutorRefForPlan,
} from "./runtime-hypervisor-approved-operation-executors.mjs";
import {
  dispatchHypervisorApprovedOperationPlan,
} from "./runtime-hypervisor-approved-operation-dispatch.mjs";

const sessionRequest = {
  operation_family: "session",
  proposal_ref: "session-operation:daemon/restore",
  proposal_schema_version: "ioi.hypervisor.session_operation_proposal.v1",
  proposal_source: "daemon-session-operation-proposal",
  project_ref: "project:ioi",
  session_ref: "session:ioi",
  environment_ref: "environment:ioi",
  provider_candidate_ref: "provider:local-workstation",
  operation_kind: "restore_session",
  target_ref: "agentgres://restore/ioi/latest",
  wallet_approval_ref: "approval://wallet/session/restore",
  wallet_lease_ref: "lease:wallet/session/restore",
  required_scope_refs: ["scope:restore.apply"],
  authority_receipt_refs: ["receipt://wallet/session/restore"],
  agentgres_operation_ref: "agentgres://operation/session/ioi/restore",
  receipt_ref: "receipt://session/ioi/restore",
  state_root_ref: "agentgres://state-root/session/ioi",
  archive_ref: "artifact://agentgres/archive/ioi/latest",
  restore_ref: "agentgres://restore/ioi/latest",
};

const providerRequest = {
  operation_family: "provider",
  proposal_ref: "provider-operation:daemon/zero-to-idle",
  proposal_schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
  proposal_source: "daemon-provider-operation-proposal",
  project_ref: "project:ioi",
  candidate_ref: "provider-candidate:akash-gpu",
  direct_provider_ref: "provider:akash/gpu-market",
  operation_kind: "zero_to_idle",
  wallet_approval_ref: "approval://wallet/provider/akash",
  wallet_lease_ref: "lease:wallet/provider/akash/zero-to-idle",
  required_scope_refs: ["scope:provider.spend", "scope:receipt.write"],
  agentgres_operation_ref:
    "agentgres://operation/provider/akash/zero-to-idle",
  receipt_ref: "receipt://provider/akash/zero-to-idle",
  state_root_ref: "agentgres://state-root/provider/akash",
  archive_ref: "artifact://agentgres/archive/provider/akash/latest",
  restore_ref: "agentgres://restore/akash/latest",
};

const projectRequest = {
  operation_family: "project",
  proposal_ref: "project-operation:daemon/restore",
  proposal_schema_version: "ioi.hypervisor.project_operation_proposal.v1",
  proposal_source: "daemon-project-operation-proposal",
  project_ref: "project:ioi",
  workspace_ref: "workspace://ioi",
  operation_kind: "restore",
  wallet_approval_ref: "approval://wallet/project/restore",
  wallet_lease_ref: "lease:wallet/project/restore",
  required_scope_refs: ["scope:agentgres.restore", "scope:artifact.decrypt"],
  authority_receipt_refs: ["receipt://wallet/project/restore"],
  agentgres_operation_ref: "agentgres://operation/project/ioi/restore",
  receipt_ref: "receipt://project/ioi/restore",
  state_root_ref: "agentgres://state-root/project/ioi",
  archive_ref: "artifact://agentgres/archive/ioi/latest",
  restore_ref: "agentgres://restore/ioi/latest",
};

const automationRequest = {
  operation_family: "automation",
  proposal_ref: "automation-run:daemon/mission",
  proposal_schema_version: "ioi.hypervisor.automation_run_proposal.v1",
  proposal_source: "daemon-automation-run-proposal",
  project_ref: "project:ioi",
  template_ref: "workflow-template:mission-to-workbench",
  run_recipe_ref: "run-recipe:mission-to-workbench/manual",
  graph_ref: "workflow://graph/mission-to-workbench",
  launch_action_ref: "action://workflow/mission-to-workbench/launch",
  operation_kind: "run_now",
  wallet_approval_ref: "approval://wallet/automation/mission",
  wallet_lease_ref: "lease:wallet/automation/mission",
  required_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
  authority_receipt_refs: ["receipt://wallet/automation/mission"],
  agentgres_operation_ref: "agentgres://operation/automation/mission/run",
  receipt_ref: "receipt://automation/mission/run",
  state_root_ref: "agentgres://state-root/automation/mission",
  artifact_refs: ["artifact://workflow/mission-to-workbench/graph"],
};

function planFor(request) {
  return admitHypervisorApprovedOperation(request, {
    nowIso: () => "2026-06-18T00:00:00.000Z",
  }).execution_plan;
}

test("default executor registry dispatches admitted session lifecycle plans", async () => {
  const plan = planFor(sessionRequest);
  const registry = createHypervisorApprovedOperationExecutorRegistry({
    nowIso: () => "2026-06-18T00:01:00.000Z",
  });
  const result = await dispatchHypervisorApprovedOperationPlan(
    {
      execution_plan: plan,
      executor_ref: expectedExecutorRefForPlan(plan),
    },
    {
      nowIso: () => "2026-06-18T00:01:00.000Z",
      executeApprovedOperationPlan: registry.executeApprovedOperationPlan,
    },
  );

  assert.equal(result.dispatch_status, "executed");
  assert.equal(result.executor_ref, "executor://hypervisor/session/lifecycle-adapter");
  assert.equal(result.operation_family, "session");
  assert.match(
    result.execution_result_ref,
    /^result:\/\/hypervisor\/session-lifecycle\//,
  );
  assert.ok(
    result.receipt_refs.includes("receipt://session/ioi/restore"),
  );
  assert.ok(
    result.receipt_refs.some((ref) =>
      ref.startsWith("receipt://hypervisor/session-lifecycle/"),
    ),
  );
  assert.ok(
    result.next_state_root_ref.startsWith(
      "agentgres://state-root/hypervisor/session-lifecycle/",
    ),
  );
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
});

test("default executor registry dispatches provider, project, and automation families", async () => {
  const registry = createHypervisorApprovedOperationExecutorRegistry({
    nowIso: () => "2026-06-18T00:02:00.000Z",
  });
  const cases = [
    [providerRequest, "provider", "provider-lifecycle"],
    [projectRequest, "project", "project-lifecycle"],
    [automationRequest, "automation", "workflow-compositor"],
  ];

  for (const [request, family, receiptKind] of cases) {
    const plan = planFor(request);
    const result = await dispatchHypervisorApprovedOperationPlan(
      {
        execution_plan: plan,
        executor_ref: expectedExecutorRefForPlan(plan),
      },
      {
        executeApprovedOperationPlan: registry.executeApprovedOperationPlan,
      },
    );
    assert.equal(result.operation_family, family);
    assert.equal(result.dispatch_status, "executed");
    assert.ok(
      result.receipt_refs.some((ref) =>
        ref.startsWith(`receipt://hypervisor/${receiptKind}/`),
      ),
    );
    assert.ok(
      result.agentgres_operation_refs.some((ref) =>
        ref.startsWith(`agentgres://operation/hypervisor/${receiptKind}/`),
      ),
    );
    assert.ok(
      result.trace_refs.some((ref) =>
        ref.startsWith(`trace://hypervisor/${receiptKind}/`),
      ),
    );
  }
});

test("default executor registry rejects unmounted executor refs and unknown executor kinds", async () => {
  const plan = planFor(sessionRequest);
  const registry = createHypervisorApprovedOperationExecutorRegistry();

  await assert.rejects(
    () =>
      dispatchHypervisorApprovedOperationPlan(
        {
          execution_plan: plan,
          executor_ref: "executor://hypervisor/session/local-workstation",
        },
        {
          executeApprovedOperationPlan: registry.executeApprovedOperationPlan,
        },
      ),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_approved_operation_executor_ref_not_mounted",
      );
      assert.equal(error.status, 403);
      return true;
    },
  );

  assert.throws(
    () =>
      expectedExecutorRefForPlan({
        ...plan,
        executor_kind: "retired_fixture_executor",
      }),
    /not registered/,
  );
});
