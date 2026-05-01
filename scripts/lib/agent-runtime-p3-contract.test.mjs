import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  BETTER_AGENT_VALIDATIONS,
  EXHAUSTIVE_WORKFLOW_SUITES,
  P3_PRODUCT_POLISH_ITEMS,
  RUNTIME_SCORECARD_DIMENSIONS,
  buildRedactedDiagnosticBundle,
  evaluateAgentRuntimeP3Readiness,
  scanImportBoundaries,
  validateAgentRuntimeP3Readiness,
} from "./agent-runtime-p3-contract.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);

test("P3 contract mirrors the master-guide checklist cardinality", () => {
  assert.equal(P3_PRODUCT_POLISH_ITEMS.length, 10);
  assert.equal(EXHAUSTIVE_WORKFLOW_SUITES.length, 15);
  assert.equal(BETTER_AGENT_VALIDATIONS.length, 31);
  assert.ok(RUNTIME_SCORECARD_DIMENSIONS.length >= 30);
});

test("runtime scorecard preserves GUI, cognitive, learning, substrate, and dogfooding dimensions", () => {
  const dimensions = new Set(RUNTIME_SCORECARD_DIMENSIONS.map(([dimension]) => dimension));
  for (const dimension of [
    "Task state",
    "Uncertainty",
    "Probe",
    "Semantic impact",
    "Verifier independence",
    "Budget",
    "Drift",
    "Dry-run",
    "Stop",
    "Handoff",
    "Autopilot GUI",
    "Chat UX",
    "GUI/runtime consistency",
    "Learning",
    "Substrate",
    "Dogfooding",
  ]) {
    assert.ok(dimensions.has(dimension), `missing scorecard dimension ${dimension}`);
  }
});

test("current repository satisfies P3 source and validation anchors without requiring live GUI evidence", () => {
  const readiness = evaluateAgentRuntimeP3Readiness(repoRoot, {
    requireGuiEvidence: false,
  });
  const validation = validateAgentRuntimeP3Readiness(readiness);
  assert.equal(validation.ok, true, validation.failures.join("\n"));
});

test("redacted diagnostic bundle strips secret-shaped fields and values", () => {
  const bundle = buildRedactedDiagnosticBundle({
    generatedAt: "2026-05-01T00:00:00.000Z",
    status: "Complete",
    counts: { incomplete: 0 },
    masterGuide: { path: "guide", token: "sk-test-secret" },
    guiEvidence: null,
    importBoundary: { status: "Complete", findings: [] },
    failures: ["contains ghp_testtoken"],
  });
  assert.equal(bundle.masterGuide.token, "<redacted>");
  assert.equal(bundle.failures[0], "<redacted>");
});

test("import-boundary scanner catches script fixture leaks in production paths", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-p3-boundary-"));
  const leakPath = path.join(
    tmp,
    "crates/services/src/agentic/runtime/leak.rs",
  );
  fs.mkdirSync(path.dirname(leakPath), { recursive: true });
  fs.writeFileSync(
    leakPath,
    "const BAD: &str = \"scripts/lib/autopilot-gui-harness-contract.mjs\";\n",
    "utf8",
  );
  const cleanPath = path.join(tmp, "crates/types/src/app/runtime_contracts.rs");
  fs.mkdirSync(path.dirname(cleanPath), { recursive: true });
  fs.writeFileSync(cleanPath, "pub struct RuntimeExecutionEnvelope;\n", "utf8");
  const scan = scanImportBoundaries(tmp);
  assert.equal(scan.status, "Divergent");
  assert.equal(scan.findings.length, 1);
  assert.equal(scan.findings[0].path, "crates/services/src/agentic/runtime/leak.rs");
});
