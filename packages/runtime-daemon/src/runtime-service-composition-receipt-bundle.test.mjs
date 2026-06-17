import assert from "node:assert/strict";
import test from "node:test";

import {
  SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION,
  admitServiceCompositionReceiptBundle,
} from "./runtime-service-composition-receipt-bundle.mjs";

function baseBundle(overrides = {}) {
  return {
    service_ref: "service://sas/reporting",
    delivery_ref: "delivery://sas/reporting/123",
    composition_graph_ref: "workflow://service-composition/reporting",
    delivery_status: "delivered",
    private_data_posture: "ctee_private_workspace",
    contribution_receipt_refs: ["receipt://contribution/worker-1"],
    verifier_receipt_refs: ["receipt://verifier/quality-1"],
    policy_receipt_refs: ["receipt://policy/service-1"],
    routing_receipt_refs: ["receipt://routing/service-1"],
    dispute_evidence_refs: ["evidence://dispute/service-1"],
    provider_log_refs: ["log://provider/supporting"],
    agentgres_operation_refs: ["agentgres://operation/service-composition/123"],
    artifact_refs: ["artifact://delivery/report"],
    payload_refs: [],
    receipt_refs: ["receipt://service-composition/bundle-123"],
    state_root: "state_root:service-composition:123",
    settlement_requested: true,
    ...overrides,
  };
}

test("admits service composition receipt bundle with contribution, verifier, policy, routing, dispute, and Agentgres refs", () => {
  const bundle = admitServiceCompositionReceiptBundle(baseBundle(), {
    nowIso: () => "2026-06-17T18:00:00.000Z",
  });

  assert.equal(
    bundle.schema_version,
    SERVICE_COMPOSITION_RECEIPT_BUNDLE_SCHEMA_VERSION,
  );
  assert.equal(bundle.bundle_ref, "service-composition-bundle:delivery_sas_reporting_123:state_root_service-composition_123");
  assert.equal(bundle.private_data_posture, "ctee_private_workspace");
  assert.equal(bundle.settlement_ready, true);
  assert.equal(bundle.runtimeTruthSource, "daemon-runtime");
});

test("service composition bundle rejects raw delivery blobs or provider logs as dispute truth", () => {
  assert.throws(
    () =>
      admitServiceCompositionReceiptBundle(
        baseBundle({
          contribution_receipt_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "service_composition_contribution_receipt_refs_required");
      return true;
    },
  );

  assert.throws(
    () =>
      admitServiceCompositionReceiptBundle(
        baseBundle({
          artifact_refs: [],
          payload_refs: [],
        }),
      ),
    (error) => {
      assert.equal(error.code, "service_composition_delivery_payload_or_artifact_required");
      return true;
    },
  );

  assert.throws(
    () =>
      admitServiceCompositionReceiptBundle(
        baseBundle({
          dispute_evidence_refs: [],
          provider_log_refs: ["log://provider/not-truth"],
        }),
      ),
    (error) => {
      assert.equal(error.code, "service_composition_dispute_evidence_refs_required");
      return true;
    },
  );
});

test("unsafe plaintext service delivery exceptions require explicit approval and cannot settle by default", () => {
  assert.throws(
    () =>
      admitServiceCompositionReceiptBundle(
        baseBundle({
          private_data_posture: "unsafe_plaintext_exception",
          wallet_approval_ref: null,
          unsafe_plaintext_exception_ref: null,
          settlement_requested: false,
        }),
      ),
    (error) => {
      assert.equal(error.code, "service_composition_unsafe_plaintext_exception_unapproved");
      return true;
    },
  );

  assert.throws(
    () =>
      admitServiceCompositionReceiptBundle(
        baseBundle({
          private_data_posture: "unsafe_plaintext_exception",
          wallet_approval_ref: "approval://wallet/unsafe-service",
          unsafe_plaintext_exception_ref: "receipt://unsafe-plaintext/service",
          settlement_requested: true,
        }),
      ),
    (error) => {
      assert.equal(error.code, "service_composition_unsafe_plaintext_settlement_blocked");
      return true;
    },
  );

  const bundle = admitServiceCompositionReceiptBundle(
    baseBundle({
      private_data_posture: "unsafe_plaintext_exception",
      wallet_approval_ref: "approval://wallet/unsafe-service",
      unsafe_plaintext_exception_ref: "receipt://unsafe-plaintext/service",
      settlement_requested: false,
    }),
  );
  assert.equal(bundle.settlement_ready, false);
});

test("service composition bundle rejects retired camelCase aliases", () => {
  assert.throws(
    () =>
      admitServiceCompositionReceiptBundle({
        ...baseBundle(),
        compositionGraphRef: "legacy",
        contributionReceipts: [],
        verifierReceipts: [],
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "service_composition_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "compositionGraphRef",
        "contributionReceipts",
        "verifierReceipts",
      ]);
      return true;
    },
  );
});
