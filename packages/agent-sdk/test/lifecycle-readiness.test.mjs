import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION,
  inspectAutonomousSystemLifecycleReadiness,
} from "../dist/index.js";

const manifest = {
  schemaVersion: "ioi.autonomous-system-manifest.v1",
  systemId: "system://repo-maintenance",
  manifestId: "ai://autonomous-system/repo-maintenance",
  displayName: "Repo Maintenance Autonomous System",
  worker: {
    workerRef: "worker://repo-maintenance",
    responsibility: "Propose docs-only repo maintenance patches.",
  },
  workflow: {
    workflowManifestRef: "internal-docs/samples/repo-maintenance-autonomous-system-package/workflow.json",
    harnessRef: "harness://repo-maintenance/proposal-first",
  },
  capabilities: {
    modelCapabilityRefs: ["model-capability:autopilot.mounted.local-coder"],
    toolCapabilityRefs: ["tool-capability:file.read", "tool-capability:file.apply_patch"],
    connectorRefs: [],
    primitiveCapabilitiesRequired: ["prim:model.invoke", "prim:fs.read", "prim:fs.write"],
  },
  authority: {
    authorityScopeRequirements: [
      "scope:model.invoke.local",
      "scope:workspace.read",
      "scope:workspace.write",
    ],
    grantRequirements: ["grant://scope-workspace-write"],
    approvalProfileRef: "policy://approval/repo-maintenance",
    policyProfileRef: "policy://authority/repo-maintenance",
    revocationPosture: "fail_closed",
  },
  runtimeProfiles: [
    {
      profileId: "profile://runtime/repo-maintenance",
      kind: "local_daemon",
      readiness: "ready",
    },
  ],
  evaluation: {
    evalProfileRefs: ["eval://repo-maintenance/propose-safe-doc-fix"],
    qualityGateRefs: ["gate://quality/repo-maintenance"],
  },
  promotion: {
    promotionProfileRef: "profile://promotion/repo-maintenance",
    marketplaceExposureEligibility: "internal",
  },
  receipts: {
    latestEvalReceiptRefs: ["receipt://eval/repo-maintenance/propose-safe-doc-fix"],
  },
};

test("SDK projects Autonomous System Package lifecycle readiness", () => {
  const readiness = inspectAutonomousSystemLifecycleReadiness({ manifest });

  assert.equal(
    readiness.schemaVersion,
    WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION,
  );
  assert.equal(readiness.packageArtifact, "Autonomous System Package");
  assert.equal(readiness.systemId, "system://repo-maintenance");
  assert.deepEqual(
    readiness.categories.map((category) => category.kind),
    ["run", "authority", "package", "evaluation", "deployment", "promotion"],
  );
  assert.equal(readiness.status, "ready");
  assert.equal(readiness.promotionGate.status, "ready");
  assert.ok(
    readiness.promotionGate.evidenceRefs.includes(
      "receipt://eval/repo-maintenance/propose-safe-doc-fix",
    ),
  );
});

test("SDK promotion gate blocks without eval evidence", () => {
  const readiness = inspectAutonomousSystemLifecycleReadiness({
    manifest: {
      ...manifest,
      receipts: { latestEvalReceiptRefs: [] },
    },
  });

  assert.equal(readiness.status, "blocked");
  assert.equal(readiness.promotionGate.status, "blocked");
  assert.deepEqual(readiness.promotionGate.blockers, [
    "eval receipt evidence missing",
  ]);
});
