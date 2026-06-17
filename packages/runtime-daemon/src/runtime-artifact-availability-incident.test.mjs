import assert from "node:assert/strict";
import test from "node:test";

import {
  ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION,
  admitArtifactAvailabilityIncident,
} from "./runtime-artifact-availability-incident.mjs";

function baseIncident(overrides = {}) {
  return {
    artifact_ref: "artifact://evidence/report",
    payload_ref: "payload://evidence/report/bytes",
    backend_ref: "storage://filecoin/mainnet",
    incident_kind: "missing",
    lifecycle_state: "opened",
    agentgres_operation_refs: ["agentgres://operation/artifact-incident/open"],
    incident_receipt_refs: ["receipt://artifact-incident/open"],
    affected_object_refs: ["agentgres://object/delivery/report"],
    ...overrides,
  };
}

test("admits artifact availability incident through Agentgres-backed daemon truth", () => {
  const incident = admitArtifactAvailabilityIncident(baseIncident(), {
    nowIso: () => "2026-06-17T19:00:00.000Z",
  });

  assert.equal(
    incident.schema_version,
    ARTIFACT_AVAILABILITY_INCIDENT_SCHEMA_VERSION,
  );
  assert.equal(incident.incident_id, "artifact-availability-incident:artifact_evidence_report:missing");
  assert.equal(incident.lifecycle_state, "opened");
  assert.equal(incident.runtimeTruthSource, "daemon-runtime");
});

test("artifact availability incidents require integrity evidence for invalid hash or CID", () => {
  assert.throws(
    () =>
      admitArtifactAvailabilityIncident(
        baseIncident({
          incident_kind: "invalid_hash",
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "artifact_availability_hash_evidence_required");
      return true;
    },
  );

  const invalidHash = admitArtifactAvailabilityIncident(
    baseIncident({
      incident_kind: "invalid_hash",
      expected_hash: "sha256:expected",
      observed_hash: "sha256:observed",
    }),
  );
  assert.equal(invalidHash.incident_kind, "invalid_hash");

  assert.throws(
    () =>
      admitArtifactAvailabilityIncident(
        baseIncident({
          incident_kind: "invalid_cid",
          expected_cid: "bafyexpected",
        }),
      ),
    (error) => {
      assert.equal(error.code, "artifact_availability_cid_evidence_required");
      return true;
    },
  );
});

test("fallback, quarantine, and repair states require the relevant refs and receipts", () => {
  assert.throws(
    () =>
      admitArtifactAvailabilityIncident(
        baseIncident({
          lifecycle_state: "fallback_attempted",
        }),
      ),
    (error) => {
      assert.equal(error.code, "artifact_availability_fallback_backend_refs_required");
      return true;
    },
  );

  const fallback = admitArtifactAvailabilityIncident(
    baseIncident({
      lifecycle_state: "fallback_attempted",
      fallback_backend_refs: ["storage://s3/replica"],
    }),
  );
  assert.deepEqual(fallback.fallback_backend_refs, ["storage://s3/replica"]);

  assert.throws(
    () =>
      admitArtifactAvailabilityIncident(
        baseIncident({
          lifecycle_state: "quarantined",
        }),
      ),
    (error) => {
      assert.equal(error.code, "artifact_availability_quarantine_refs_required");
      return true;
    },
  );

  const repaired = admitArtifactAvailabilityIncident(
    baseIncident({
      lifecycle_state: "repaired",
      repair_receipt_refs: ["receipt://artifact-repair/verified"],
      verification_refs: ["verification://artifact/hash"],
      restore_import_refs: ["restore://artifact/import"],
      payload_bytes_mutated: true,
    }),
  );
  assert.equal(repaired.lifecycle_state, "repaired");
});

test("artifact availability admission blocks silent payload mutation", () => {
  assert.throws(
    () =>
      admitArtifactAvailabilityIncident(
        baseIncident({
          payload_bytes_mutated: true,
        }),
      ),
    (error) => {
      assert.equal(error.code, "artifact_availability_silent_payload_mutation_blocked");
      return true;
    },
  );
});

test("artifact availability admission rejects retired camelCase aliases", () => {
  assert.throws(
    () =>
      admitArtifactAvailabilityIncident({
        ...baseIncident(),
        artifactRef: "legacy",
        payloadRef: "legacy",
        repairReceiptRefs: [],
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "artifact_availability_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "artifactRef",
        "payloadRef",
        "repairReceiptRefs",
      ]);
      return true;
    },
  );
});
