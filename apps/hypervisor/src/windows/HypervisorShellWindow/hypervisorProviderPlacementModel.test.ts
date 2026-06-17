import assert from "node:assert/strict";
import test from "node:test";

import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "./hypervisorProviderPlacementModel";

test("provider placement fixture keeps direct providers as candidates, not authority", () => {
  const projection = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.provider_placement_projection.v1",
  );
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
