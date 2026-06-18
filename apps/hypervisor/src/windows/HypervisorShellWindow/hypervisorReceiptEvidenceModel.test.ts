import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE,
  HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH,
  loadHypervisorReceiptEvidenceProjection,
  normalizeHypervisorReceiptEvidenceProjection,
} from "./hypervisorReceiptEvidenceModel.ts";

test("receipt evidence projection binds receipts to Agentgres, artifacts, traces, state roots, and replay", () => {
  const projection = HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE;
  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.receipt_evidence_projection.v1",
  );
  assert.equal(projection.source, "fixture");
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

test("receipt evidence normalization preserves daemon evidence boundaries", () => {
  const projection = normalizeHypervisorReceiptEvidenceProjection(
    {
      projection_id: "receipt-evidence:daemon/normalized",
      receipt_boundary_invariant:
        "Agentgres admits receipt truth; clients render evidence.",
      records: [
        {
          receipt_ref: "receipt://daemon/session/normalized",
          kind: "session_lifecycle",
          summary: "Normalized session lifecycle receipt.",
          source_projection_ref: "session-operations:daemon/normalized",
          agentgres_operation_refs: [
            "agentgres://operation/session/normalized",
          ],
          artifact_refs: ["artifact://receipt-evidence/session/normalized"],
          trace_refs: ["trace://hypervisor/session/normalized"],
          state_root_ref: "agentgres://state-root/session/normalized",
          replay_ref: "agentgres://replay/session/normalized",
          status: "admitted",
        },
      ],
    },
    { source: "daemon-receipt-evidence-projection" },
  );

  assert.equal(projection.source, "daemon-receipt-evidence-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "receipt-evidence:daemon/normalized");
  assert.equal(projection.records[0]?.receipt_ref, "receipt://daemon/session/normalized");
  assert.equal(projection.records[0]?.kind, "session_lifecycle");
  assert.deepEqual(projection.records[0]?.agentgres_operation_refs, [
    "agentgres://operation/session/normalized",
  ]);
});

test("receipt evidence loader calls the daemon projection route with project and session refs", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorReceiptEvidenceProjection({
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
            projection_id: "receipt-evidence:daemon/loaded",
            records: [
              {
                receipt_ref: "receipt://loaded/session",
                kind: "session_lifecycle",
                summary: "Loaded receipt evidence.",
                source_projection_ref: "session-operations:daemon/loaded",
                agentgres_operation_refs: ["agentgres://operation/loaded/session"],
                artifact_refs: ["artifact://receipt-evidence/loaded/session"],
                trace_refs: ["trace://hypervisor/loaded/session"],
                state_root_ref: "agentgres://state-root/loaded/session",
                replay_ref: "agentgres://replay/loaded/session",
                status: "admitted",
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
        `http://daemon.test${HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_PATH}?project_id=project%3Aioi&session_ref=session%3Aioi`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-receipt-evidence-projection");
  assert.equal(projection.projection_id, "receipt-evidence:daemon/loaded");
  assert.equal(projection.records[0]?.receipt_ref, "receipt://loaded/session");
});
