import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION,
  admitHypervisorApprovedOperation,
} from "./runtime-hypervisor-approved-operation-admission.mjs";

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
  state_root_ref: "agentgres://state-root/project:ioi",
  archive_ref: "artifact://agentgres/archive/ioi/latest",
  restore_ref: "agentgres://restore/ioi/latest",
};

test("admits daemon session operation after wallet approval and Agentgres truth refs", () => {
  const result = admitHypervisorApprovedOperation(sessionRequest, {
    nowIso: () => "2026-06-18T00:00:00.000Z",
  });

  assert.equal(
    result.schema_version,
    HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION,
  );
  assert.equal(result.operation_family, "session");
  assert.equal(result.decision, "admitted");
  assert.equal(result.execution_status, "admitted_for_execution");
  assert.equal(result.wallet_approval_ref, "approval://wallet/session/restore");
  assert.deepEqual(result.agentgres_operation_refs, [
    "agentgres://operation/session/ioi/restore",
  ]);
  assert.deepEqual(result.receipt_refs, ["receipt://session/ioi/restore"]);
  assert.equal(result.state_root_ref, "agentgres://state-root/session/ioi");
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
  assert.equal(result.admitted_at, "2026-06-18T00:00:00.000Z");
});

test("admits daemon provider operation after wallet approval and Agentgres truth refs", () => {
  const result = admitHypervisorApprovedOperation(providerRequest);

  assert.equal(result.operation_family, "provider");
  assert.equal(result.candidate_ref, "provider-candidate:akash-gpu");
  assert.equal(result.direct_provider_ref, "provider:akash/gpu-market");
  assert.equal(result.provider_candidate_ref, "provider-candidate:akash-gpu");
  assert.equal(result.archive_ref, "artifact://agentgres/archive/provider/akash/latest");
  assert.equal(result.restore_ref, "agentgres://restore/akash/latest");
});

test("admits daemon project operation after wallet approval and Agentgres archive refs", () => {
  const result = admitHypervisorApprovedOperation(projectRequest);

  assert.equal(result.operation_family, "project");
  assert.equal(result.workspace_ref, "workspace://ioi");
  assert.equal(result.target_ref, "workspace://ioi");
  assert.equal(result.archive_ref, "artifact://agentgres/archive/ioi/latest");
  assert.equal(result.restore_ref, "agentgres://restore/ioi/latest");
  assert.deepEqual(result.agentgres_operation_refs, [
    "agentgres://operation/project/ioi/restore",
  ]);
  assert.deepEqual(result.receipt_refs, ["receipt://project/ioi/restore"]);
});

test("rejects project operations from non-daemon proposal sources", () => {
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...projectRequest,
        proposal_source: "fixture",
      }),
    /daemon-authored proposals/,
  );
});

test("rejects fixture or unverified proposals as execution admission sources", () => {
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        proposal_source: "fixture",
      }),
    /daemon-authored proposals/,
  );
});

test("rejects approved operations without wallet approval or wallet lease", () => {
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        wallet_approval_ref: null,
      }),
    /wallet_approval_ref/,
  );
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        wallet_lease_ref: null,
      }),
    /wallet_lease_ref/,
  );
});

test("rejects approved operations without Agentgres operation, receipt, or state root", () => {
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        agentgres_operation_ref: null,
        agentgres_operation_refs: [],
      }),
    /agentgres_operation_refs/,
  );
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        receipt_ref: null,
        receipt_refs: [],
      }),
    /receipt_refs/,
  );
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        state_root_ref: null,
      }),
    /state_root_ref/,
  );
});

test("rejects restore admission without restore refs and camelCase aliases", () => {
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        restore_ref: null,
      }),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_approved_operation_restore_ref_required",
      );
      return true;
    },
  );
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        walletApprovalRef: "approval://wallet/session/restore",
    }),
    /snake_case/,
  );
});

test("rejects archive and restore refs outside Agentgres artifact ownership", () => {
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        archive_ref: "s3://workspace/archive",
      }),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_approved_operation_archive_ref_prefix_invalid",
      );
      return true;
    },
  );
  assert.throws(
    () =>
      admitHypervisorApprovedOperation({
        ...sessionRequest,
        restore_ref: "file:///tmp/restore",
      }),
    (error) => {
      assert.equal(
        error.code,
        "hypervisor_approved_operation_restore_ref_prefix_invalid",
      );
      return true;
    },
  );
});
