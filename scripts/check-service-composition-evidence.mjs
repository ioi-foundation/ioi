#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));

function read(relativePath) {
  return readFileSync(join(repoRoot, relativePath), "utf8");
}

function requireAll(file, values) {
  const source = read(file);
  for (const value of values) {
    if (!source.includes(value)) {
      throw new Error(`${file} must include ${value}`);
    }
  }
  return source;
}

const serviceCompositionTerms = [
  "ServiceCompositionReceiptBundle",
  "composition_graph_ref",
  "routing_receipt_refs",
  "contribution_receipt_refs",
  "verifier_receipt_refs",
  "policy_receipt_refs",
  "private_data_posture",
  "ctee_private_workspace",
  "unsafe_plaintext_exception",
  "dispute_evidence_refs",
  "agentgres_operation_refs",
  "state_root",
];

requireAll("docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md", [
  ...serviceCompositionTerms,
  "ContributionReceipt",
  "DeliveryBundle",
  "provider logs as dispute truth",
  "token usage as contribution truth",
]);

requireAll("docs/architecture/domains/sas/service-marketplace.md", [
  "ServiceCompositionReceiptBundle",
  "worker/service/provider contribution receipts",
  "verifier and quality receipts",
  "private-data posture",
  "dispute evidence refs",
  "Agentgres operation refs and state root",
]);

requireAll("docs/architecture/domains/sas/service-endpoints.md", [
  "service_composition",
  "service_composition_receipt_bundle_ref",
  "contribution_receipts",
  "verifier_receipts",
  "private_data_posture",
  "ctee_private_workspace",
  "unsafe_plaintext_exception",
  "dispute_evidence",
  "agentgres_operation_refs",
  "state_root",
]);

requireAll("docs/architecture/_meta/implementation-matrix.md", [
  "`ServiceCompositionReceiptBundle`",
  "`npm run check:service-composition-evidence`",
  "composed deliveries cannot settle or dispute from raw blobs/provider logs alone",
]);

requireAll("docs/architecture/_meta/source-of-truth-map.md", [
  "`ServiceCompositionReceiptBundle`",
  "private-data posture",
  "dispute evidence refs",
  "cannot settle, accept, or dispute from raw delivery blobs",
]);

requireAll("docs/architecture/_meta/vocabulary.md", [
  "`ServiceCompositionReceiptBundle`",
  "contribution receipts",
  "verifier refs",
  "private-data posture",
  "dispute evidence refs",
]);

console.log("service composition evidence conformance passed");
