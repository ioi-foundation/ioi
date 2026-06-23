import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHypervisorProviderOperationProposal,
  HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH,
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE,
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH,
  loadHypervisorProviderPlacementProjection,
  normalizeHypervisorProviderOperationProposal,
  normalizeHypervisorProviderPlacementProjection,
  proposeHypervisorProviderOperation,
} from "./hypervisorProviderPlacementModel.ts";

test("provider placement fixture keeps direct providers as candidates, not authority", () => {
  const projection = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.provider_placement_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.anti_gateway_invariant, /wallet\.network authorizes/);
  assert.match(projection.anti_gateway_invariant, /Agentgres records/);
  assert.doesNotMatch(projection.anti_gateway_invariant, /Fleet/);
  assert.ok(projection.candidates.length >= 6);
  assert.ok(
    projection.candidates.every((candidate) =>
      candidate.direct_provider_ref.startsWith("provider:"),
    ),
  );
});

test("provider placement normalization preserves direct-provider candidate boundaries", () => {
  const projection = normalizeHypervisorProviderPlacementProjection(
    {
      projection_id: "provider-placement:daemon/normalized",
      selected_project_ref: "project:normalized",
      anti_gateway_invariant:
        "Providers perform; wallet.network authorizes; Agentgres records admitted truth.",
      candidates: [
        {
          candidate_ref: "provider-candidate:normalized-akash",
          label: "Normalized Akash GPU",
          integration_kind: "depin_compute",
          direct_provider_ref: "provider:akash/gpu-market",
          workload_fit: "Redacted compute",
          privacy_posture: "ctee_split_required",
          wallet_authority_scope_refs: ["scope:provider.spend"],
          agentgres_receipt_ref: "receipt://provider/akash/placement",
          storage_policy_ref: "storage-policy:agentgres-encrypted-refs-only",
          restore_policy_ref: "agentgres://restore/akash/latest",
          risk_labels: ["Provider root expected", "No plaintext custody"],
        },
      ],
    },
    { source: "daemon-provider-placement-projection" },
  );

  assert.equal(projection.source, "daemon-provider-placement-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "provider-placement:daemon/normalized");
  assert.equal(projection.selected_project_ref, "project:normalized");
  assert.equal(projection.candidates[0]?.candidate_ref, "provider-candidate:normalized-akash");
  assert.equal(projection.candidates[0]?.integration_kind, "depin_compute");
  assert.equal(projection.candidates[0]?.privacy_posture, "ctee_split_required");
  assert.deepEqual(projection.candidates[0]?.wallet_authority_scope_refs, [
    "scope:provider.spend",
  ]);
  assert.deepEqual(projection.candidates[0]?.risk_labels, [
    "Provider root expected",
    "No plaintext custody",
  ]);
});

test("provider placement loader calls the daemon projection route with selected project ref", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorProviderPlacementProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "provider-placement:daemon/loaded",
            selected_project_ref: "project:ioi",
            candidates: [
              {
                candidate_ref: "provider-candidate:local-workstation",
                label: "Local workstation",
                direct_provider_ref: "provider:local-workstation",
                wallet_authority_scope_refs: ["scope:workspace.read"],
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
        `http://daemon.test${HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH}?project_id=project%3Aioi`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-provider-placement-projection");
  assert.equal(projection.projection_id, "provider-placement:daemon/loaded");
  assert.equal(projection.selected_project_ref, "project:ioi");
  assert.equal(projection.candidates[0]?.candidate_ref, "provider-candidate:local-workstation");
  assert.deepEqual(projection.candidates[0]?.wallet_authority_scope_refs, [
    "scope:workspace.read",
  ]);
});

test("provider candidates expose privacy, authority, storage, and restore boundaries", () => {
  const candidates = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates;
  const labels = candidates.map((candidate) => candidate.label);
  assert.ok(labels.includes("Local workstation"));
  assert.ok(labels.includes("Akash GPU provider"));
  assert.ok(labels.includes("Filecoin encrypted archive"));
  assert.ok(
    candidates.some(
      (candidate) => candidate.privacy_posture === "confidential_compute",
    ),
  );
  assert.ok(
    candidates.some(
      (candidate) => candidate.privacy_posture === "ctee_split_required",
    ),
  );
  assert.ok(
    candidates.some(
      (candidate) => candidate.privacy_posture === "encrypted_storage_only",
    ),
  );
  assert.ok(
    candidates.every((candidate) =>
      candidate.wallet_authority_scope_refs.every((scopeRef) =>
        scopeRef.startsWith("scope:"),
      ),
    ),
  );
  assert.ok(
    candidates.every((candidate) =>
      candidate.agentgres_receipt_ref.startsWith("receipt://provider/"),
    ),
  );
  assert.ok(
    candidates.every((candidate) =>
      candidate.restore_policy_ref.startsWith("agentgres://restore/"),
    ),
  );
});

test("provider operation proposal binds wallet lease and Agentgres refs before provider mutation", () => {
  const candidate = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates.find(
    (item) => item.candidate_ref === "provider-candidate:akash-gpu",
  );
  assert.ok(candidate);

  const proposal = buildHypervisorProviderOperationProposal(
    candidate,
    "zero_to_idle",
    { projectRef: "project:ioi" },
  );

  assert.equal(
    proposal.schema_version,
    "ioi.hypervisor.provider_operation_proposal.v1",
  );
  assert.equal(proposal.operation_kind, "zero_to_idle");
  assert.equal(proposal.project_ref, "project:ioi");
  assert.equal(proposal.candidate_ref, "provider-candidate:akash-gpu");
  assert.equal(proposal.admission_state, "ready_for_daemon_admission");
  assert.match(proposal.wallet_lease_ref, /^lease:wallet\/provider\//);
  assert.match(proposal.agentgres_operation_ref, /^agentgres:\/\/operation\/provider\//);
  assert.match(proposal.receipt_ref, /^receipt:\/\/provider\//);
  assert.match(proposal.state_root_ref, /^agentgres:\/\/state-root\/provider\//);
  assert.match(proposal.restore_ref, /^agentgres:\/\/restore\//);
  assert.match(proposal.custody_invariant, /wallet\.network grants/);
  assert.match(proposal.custody_invariant, /Agentgres admits/);
});

test("provider operation normalization preserves daemon admission state", () => {
  const candidate = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[0]!;
  const proposal = normalizeHypervisorProviderOperationProposal(
    {
      proposal_ref: "provider-operation:daemon/restore",
      source: "daemon-provider-operation-proposal",
      project_ref: "project:daemon",
      candidate_ref: candidate.candidate_ref,
      direct_provider_ref: candidate.direct_provider_ref,
      operation_kind: "restore",
      admission_state: "requires_wallet_lease",
      wallet_lease_ref: "lease:wallet/provider/local/restore",
      required_scope_refs: ["scope:archive.restore"],
      agentgres_operation_ref: "agentgres://operation/provider/local/restore",
      receipt_ref: "receipt://provider/local/restore",
      state_root_ref: "agentgres://state-root/provider/local",
      archive_ref: "artifact://agentgres/archive/local/latest",
      restore_ref: "agentgres://restore/local/latest",
      custody_invariant:
        "wallet.network grants; Agentgres admits restore truth.",
    },
    { candidate, operationKind: "restore" },
  );

  assert.equal(proposal.source, "daemon-provider-operation-proposal");
  assert.equal(proposal.operation_kind, "restore");
  assert.equal(proposal.admission_state, "requires_wallet_lease");
  assert.deepEqual(proposal.required_scope_refs, ["scope:archive.restore"]);
  assert.equal(proposal.archive_ref, "artifact://agentgres/archive/local/latest");
  assert.equal(proposal.restore_ref, "agentgres://restore/local/latest");
});

test("provider operation proposal posts to daemon with scoped candidate evidence", async () => {
  const candidate = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[0]!;
  const calls: Array<{ input: string; method?: string; body?: string }> = [];

  const proposal = await proposeHypervisorProviderOperation({
    endpoint: "http://daemon.test",
    projectRef: "project:ioi",
    candidate,
    operationKind: "archive",
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method, body: init?.body });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            proposal_ref: "provider-operation:daemon/archive",
            source: "daemon-provider-operation-proposal",
            project_ref: "project:ioi",
            candidate_ref: candidate.candidate_ref,
            direct_provider_ref: candidate.direct_provider_ref,
            operation_kind: "archive",
            admission_state: "requires_wallet_lease",
            wallet_lease_ref: "lease:wallet/provider/local/archive",
            required_scope_refs: candidate.wallet_authority_scope_refs,
            agentgres_operation_ref:
              "agentgres://operation/provider/local/archive",
            receipt_ref: "receipt://provider/local/archive",
            state_root_ref: "agentgres://state-root/provider/local",
            archive_ref: candidate.storage_policy_ref,
            restore_ref: candidate.restore_policy_ref,
            custody_invariant:
              "wallet.network grants; Agentgres admits archive truth.",
          });
        },
      };
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0]?.input,
    `http://daemon.test${HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH}`,
  );
  assert.equal(calls[0]?.method, "POST");
  assert.deepEqual(JSON.parse(calls[0]?.body ?? "{}"), {
    project_ref: "project:ioi",
    candidate_ref: candidate.candidate_ref,
    direct_provider_ref: candidate.direct_provider_ref,
    operation_kind: "archive",
    wallet_authority_scope_refs: candidate.wallet_authority_scope_refs,
    storage_policy_ref: candidate.storage_policy_ref,
    restore_policy_ref: candidate.restore_policy_ref,
  });
  assert.equal(proposal.source, "daemon-provider-operation-proposal");
  assert.equal(proposal.operation_kind, "archive");
  assert.equal(proposal.admission_state, "requires_wallet_lease");
  assert.equal(proposal.wallet_lease_ref, "lease:wallet/provider/local/archive");
});
