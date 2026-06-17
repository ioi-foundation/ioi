import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE,
  HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH,
  loadHypervisorProviderPlacementProjection,
  normalizeHypervisorProviderPlacementProjection,
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
