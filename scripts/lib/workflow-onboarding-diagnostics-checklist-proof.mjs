#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-onboarding-diagnostics-checklist-proof.mjs <output-path>");
}

const { buildWorkflowOnboardingDiagnosticsChecklist } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-onboarding-diagnostics-checklist.ts"
);

const observedChecks = [
  observedCommandCheck({
    id: "git",
    label: "Git",
    category: "local_binary",
    requirement: "required",
    command: "git --version",
  }),
  observedCommandCheck({
    id: "node",
    label: "Node.js",
    category: "local_binary",
    requirement: "required",
    command: "node --version",
  }),
  observedCommandCheck({
    id: "npm",
    label: "npm",
    category: "local_binary",
    requirement: "required",
    command: "npm --version",
  }),
  observedCommandCheck({
    id: "cargo",
    label: "Rust/Cargo",
    category: "local_binary",
    requirement: "recommended",
    command: "cargo --version",
  }),
  observedCommandCheck({
    id: "docker",
    label: "Docker",
    category: "container",
    requirement: "recommended",
    command: "docker --version",
  }),
];

const fixturePanel = buildWorkflowOnboardingDiagnosticsChecklist({
  checks: [
    {
      id: "git",
      label: "Git",
      category: "local_binary",
      requirement: "required",
      command: "git --version",
      detected: true,
      version: "git version 2.45.0",
    },
    {
      id: "node",
      label: "Node.js",
      category: "local_binary",
      requirement: "required",
      command: "node --version",
      detected: true,
      version: "v22.0.0",
    },
    {
      id: "npm",
      label: "npm",
      category: "local_binary",
      requirement: "required",
      command: "npm --version",
      detected: true,
      version: "10.9.0",
    },
    {
      id: "runtime-daemon",
      label: "IOI runtime daemon",
      category: "runtime_daemon",
      requirement: "required",
      command: "node packages/runtime-daemon/src/index.mjs --version",
      detected: false,
      remediation: "Start the daemon from Agent Studio or npm run dev:hypervisor-app.",
      policyRef: "policy:onboarding.runtime_daemon.required",
    },
    {
      id: "docker",
      label: "Docker",
      category: "container",
      requirement: "recommended",
      command: "docker --version",
      detected: false,
      remediation: "Install Docker to unlock container-backed browser and Linux sandbox drills.",
    },
    {
      id: "lm-studio",
      label: "LM Studio local provider",
      category: "model_provider",
      requirement: "optional",
      command: "curl http://127.0.0.1:1234/v1/models",
      detected: false,
      remediation: "Open LM Studio and start the local OpenAI-compatible server.",
    },
    {
      id: "secret-redaction",
      label: "Secret redaction canary",
      category: "policy",
      requirement: "optional",
      detected: false,
      detail: "Provider token sk-stage42-secret-value must not appear in onboarding evidence.",
    },
  ],
});

const observedPanel = buildWorkflowOnboardingDiagnosticsChecklist({ checks: observedChecks });
const rows = new Map(fixturePanel.rows.map((row) => [row.id, row]));
const serialized = JSON.stringify(fixturePanel);

assert.equal(fixturePanel.schemaVersion, "ioi.workflow.onboarding-diagnostics-checklist.v1");
assert.equal(fixturePanel.status, "blocked");
assert.equal(fixturePanel.requiredMissingCount, 1);
assert.equal(fixturePanel.recommendedMissingCount, 1);
assert.equal(fixturePanel.localBinaryCount, 3);
assert.equal(fixturePanel.modelProviderCount, 1);
assert.equal(fixturePanel.containerCheckCount, 1);
assert.equal(rows.get("git")?.state, "ready");
assert.equal(rows.get("runtime-daemon")?.state, "blocked");
assert.ok(rows.get("runtime-daemon")?.policyRefs.includes("policy:onboarding.required_prerequisite_missing"));
assert.equal(rows.get("docker")?.state, "needs_setup");
assert.equal(rows.get("lm-studio")?.state, "needs_setup");
assert.ok(rows.get("lm-studio")?.policyRefs.includes("policy:onboarding.model_provider.not_runtime_truth"));
assert.equal(serialized.includes("sk-stage42-secret-value"), false);
assert.equal(serialized.includes("[REDACTED]"), true);
assert.ok(observedPanel.rowCount >= 5);

const proof = {
  schemaVersion: "ioi.autopilot.stage42.onboarding-diagnostics-checklist-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    requiredMissingBlocks: fixturePanel.requiredMissingCount === 1 && fixturePanel.status === "blocked",
    recommendedMissingNeedsSetup: rows.get("docker")?.state === "needs_setup",
    modelProvidersNotRuntimeTruth: rows.get("lm-studio")?.policyRefs.includes("policy:onboarding.model_provider.not_runtime_truth") === true,
    gitNodeNpmRepresented: ["git", "node", "npm"].every((id) => rows.get(id)?.state === "ready"),
    secretsRedacted: serialized.includes("[REDACTED]") && !serialized.includes("sk-stage42-secret-value"),
    observedLocalEnvironmentCaptured: observedPanel.rowCount >= 5,
  },
  fixturePanel,
  observedPanel,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);

function observedCommandCheck({ id, label, category, requirement, command }) {
  const result = spawnSync("bash", ["-lc", command], {
    encoding: "utf8",
    timeout: 3_000,
  });
  const output = `${result.stdout || ""}${result.stderr || ""}`.trim().split(/\r?\n/)[0] || null;
  return {
    id,
    label,
    category,
    requirement,
    command,
    detected: result.status === 0,
    version: result.status === 0 ? output : null,
    detail: result.status === 0 ? `${label} detected for this proof run.` : `${label} was not detected in this proof run.`,
  };
}
