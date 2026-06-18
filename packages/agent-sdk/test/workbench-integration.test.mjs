import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";

import {
  WORKBENCH_INTEGRATION_CONTRACT_SCHEMA_VERSION,
  assertWorkbenchProjectionContract,
  isWorkbenchProjectionContract,
  workbenchProjectionBase,
} from "../dist/index.js";

test("workbench projection base names daemon runtime as source of truth", () => {
  const base = workbenchProjectionBase({
    runId: "run://workspace-codegen",
    receiptRefs: ["receipt://workbench/context-attached"],
    authorityRefs: ["authority://workspace/write"],
    manifestRefs: ["manifest://autonomous-system/repo-maintenance"],
    capabilityRefs: ["model-capability:hypervisor.mounted.local-coder"],
  });

  assert.equal(base.schemaVersion, WORKBENCH_INTEGRATION_CONTRACT_SCHEMA_VERSION);
  assert.equal(base.runtimeTruthSource, "daemon-runtime");
  assert.equal(base.projectionOwner, "code-editor-adapter:openvscode");
  assert.equal(base.ownsRuntimeState, false);
  assert.equal(base.runtimeRefs.runId, "run://workspace-codegen");
  assert.ok(isWorkbenchProjectionContract(base));
  assert.doesNotThrow(() => assertWorkbenchProjectionContract(base));
});

test("workbench context snapshots carry editor state without editor-owned runtime state", () => {
  const snapshot = {
    ...workbenchProjectionBase({
      receiptRefs: ["receipt://context/active-selection"],
      manifestRefs: ["manifest://workflow/repo-agent"],
    }),
    snapshotId: "snapshot://workbench/1",
    generatedAtMs: 1_779_209_600_000,
    workspaceRoot: "/workspace/example",
    workspaceRef: "workspace://example",
    packageRef: "package://repo-agent",
    activeEditor: {
      filePath: "src/index.ts",
      languageId: "typescript",
      selection: {
        startLineNumber: 12,
        startColumn: 3,
        endLineNumber: 18,
        endColumn: 1,
      },
      selectedTextHash: "sha256:selection",
    },
    openEditors: [{ filePath: "src/index.ts" }],
    diagnostics: [
      {
        filePath: "src/index.ts",
        range: {
          startLineNumber: 14,
          startColumn: 5,
          endLineNumber: 14,
          endColumn: 12,
        },
        severity: "warning",
        message: "Unused local.",
        source: "typescript",
      },
    ],
    scmState: {
      provider: "git",
      branch: "main",
      dirty: true,
      changedFiles: ["src/index.ts"],
    },
    taskState: {
      activeTaskLabels: [],
      recentTaskLabels: ["npm test"],
      checkRefs: ["check://npm-test"],
    },
    terminalState: {
      activeTerminalName: "npm test",
      terminalCount: 1,
      taskBacked: true,
    },
    visibleView: {
      activityId: "workbench.view.explorer",
      activeIoiViewId: "ioi.chat",
    },
    inspectionTargetIndexRef: "target-index://workbench/1",
  };

  assertWorkbenchProjectionContract(snapshot);
  assert.equal(snapshot.ownsRuntimeState, false);
  assert.equal(snapshot.activeEditor.filePath, "src/index.ts");
  assert.equal(snapshot.scmState.dirty, true);
});

test("workflow code generation contracts stay proposal-first and capability-shaped", () => {
  const request = {
    ...workbenchProjectionBase({
      authorityRefs: ["authority://workspace/proposal-first-write"],
      capabilityRefs: [
        "model-capability:hypervisor.mounted.local-coder",
        "tool-capability:workspace.apply-patch",
      ],
      manifestRefs: ["manifest://autonomous-system/repo-agent"],
    }),
    requestId: "request://workflow-codegen/1",
    requestedAtMs: 1_779_209_601_000,
    workflowRef: "workflow://repo-agent",
    packageRef: "package://repo-agent",
    goal: "Add a focused unit test.",
    boundModelCapabilityRef: "model-capability:hypervisor.mounted.local-coder",
    boundToolCapabilityRefs: ["tool-capability:workspace.apply-patch"],
    targetWorkspace: "workspace://example",
    authorityScope: "scope:workspace.write.proposal",
    evalProfileRef: "eval://repo-agent/unit",
    proposalOnly: true,
  };
  const receipt = {
    ...workbenchProjectionBase({
      runId: "run://workflow-codegen/1",
      receiptRefs: ["receipt://proposal/generated"],
      artifactRefs: ["artifact://diff/1"],
      manifestRefs: ["manifest://autonomous-system/repo-agent"],
    }),
    receiptId: "receipt://workflow-codegen/1",
    requestRef: request.requestId,
    status: "proposed",
    createdFiles: [],
    changedFiles: ["test/example.test.ts"],
    diffRefs: ["artifact://diff/1"],
    runRefs: ["run://workflow-codegen/1"],
    verificationRefs: [],
    evalReceiptRefs: [],
    promotionBlockers: ["eval receipt evidence missing"],
  };

  assertWorkbenchProjectionContract(request);
  assertWorkbenchProjectionContract(receipt);
  assert.equal(request.proposalOnly, true);
  assert.equal(receipt.status, "proposed");
  assert.ok(request.boundModelCapabilityRef.startsWith("model-capability:"));
  assert.ok(request.boundToolCapabilityRefs[0].startsWith("tool-capability:"));
  assert.doesNotMatch(JSON.stringify(request), /provider|openai|anthropic|ollama/i);
});

test("workbench integration source does not create a runtime or React shadow store", () => {
  const dirname = path.dirname(fileURLToPath(import.meta.url));
  const sourcePath = path.resolve(dirname, "../src/workbench-integration.ts");
  const source = readFileSync(sourcePath, "utf8");

  assert.match(source, /runtimeTruthSource: WorkbenchRuntimeTruthSource/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /WorkflowCodeGenerationRequest/);
  assert.match(source, /WorkbenchInspectionTargetIndex/);
  assert.doesNotMatch(source, /new Runtime|createRuntime|React\.useState|useReducer|React Flow shadow/i);
});
