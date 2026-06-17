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

requireAll("docs/architecture/components/agentgres/artifact-ref-plane.md", [
  "ArtifactAvailabilityIncident",
  "missing | unavailable | invalid_hash | invalid_cid",
  "repair receipts",
  "replace missing or corrupt payload bytes without an Agentgres operation",
]);

requireAll("docs/architecture/components/storage-backends/doctrine.md", [
  "ArtifactAvailabilityIncident",
  "repair receipt",
  "Missing, invalid, stale, or unavailable payloads",
  "Storage backends hold payload bytes",
]);

requireAll("docs/architecture/_meta/source-of-truth-map.md", [
  "`ArtifactAvailabilityIncident`",
  "repair",
  "storage backends authority layers",
]);

requireAll("docs/architecture/_meta/vocabulary.md", [
  "`ArtifactAvailabilityIncident`",
  "missing, unavailable, corrupt, stale, undecryptable",
  "`ArtifactRepairReceipt`",
]);

requireAll("packages/runtime-daemon/src/runtime-artifact-availability-incident.mjs", [
  "ioi.runtime.artifact_availability_incident.v1",
  "admitArtifactAvailabilityIncident",
  "invalid_hash",
  "invalid_cid",
  "fallback_attempted",
  "quarantined",
  "repaired",
  "repair_receipt_refs",
  "verification_refs",
  "restore_import_refs",
  "artifact_availability_silent_payload_mutation_blocked",
]);

requireAll("packages/runtime-daemon/src/runtime-artifact-availability-incident.test.mjs", [
  "require integrity evidence for invalid hash or CID",
  "fallback, quarantine, and repair states require the relevant refs and receipts",
  "blocks silent payload mutation",
]);

console.log("artifact availability incident conformance passed");
