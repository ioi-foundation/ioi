import assert from "node:assert/strict";
import test from "node:test";

import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "./hypervisorReceiptEvidenceModel";

test("receipt evidence projection binds receipts to Agentgres, artifacts, traces, state roots, and replay", () => {
  const projection = HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.receipt_evidence_projection.v1",
  );
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.receipt_boundary_invariant, /Agentgres admits operational truth/);
  assert.match(projection.receipt_boundary_invariant, /Hypervisor client only renders/);
  assert.ok(projection.records.length >= 8);
  assert.ok(
    projection.records.every((record) =>
      record.agentgres_operation_refs.every((ref) =>
        ref.startsWith("agentgres://operation/"),
      ),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.artifact_refs.every((ref) => ref.startsWith("artifact://")),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.trace_refs.every((ref) => ref.startsWith("trace://")),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.state_root_ref.startsWith("agentgres://state-root/"),
    ),
  );
  assert.ok(
    projection.records.every((record) =>
      record.replay_ref.startsWith("agentgres://replay/"),
    ),
  );
});

test("receipt evidence projection covers session, provider, harness, lease, and restore evidence", () => {
  const kinds = new Set(
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.map(
      (record) => record.kind,
    ),
  );
  assert.ok(kinds.has("session_lifecycle"));
  assert.ok(kinds.has("authority"));
  assert.ok(kinds.has("environment_lease"));
  assert.ok(kinds.has("provider_placement"));
  assert.ok(kinds.has("artifact_restore"));
  assert.ok(kinds.has("harness_comparison"));
  assert.ok(
    HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records.some(
      (record) => record.status === "draft",
    ),
  );
});
