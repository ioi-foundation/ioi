import assert from "node:assert/strict";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

test("daemon store thread turn and control pass-through delegates are retired", () => {
  const prototype = AgentgresRuntimeStateStore.prototype;
  for (const method of [
    "resumeThread",
    "createTurn",
    "interruptTurn",
    "steerTurn",
    "updateThreadRuntimeControls",
    "appendThreadRuntimeControlEvent",
    "inspectManagedSessionsForThread",
    "inspectWorkspaceChangeReviewsForThread",
    "controlWorkspaceChangeForThread",
    "controlManagedSessionForThread",
    "forkThread",
    "cancelRun",
    "applyThreadMcpServerMutation",
    "mcpStatusWithLiveDiscovery",
    "appendThreadMcpControlEvent",
    "mcpServersForContext",
    "appendCodingToolCommandStreamEvents",
    "codingToolApprovalSatisfaction",
    "blockCodingToolForApproval",
    "blockCodingToolForBudget",
    "prepareWorkspaceSnapshotForPatch",
    "materializeWorkspaceSnapshotArtifact",
    "appendWorkspaceSnapshotEvent",
    "workspaceSnapshotContentPackage",
    "materializeWorkspaceRestorePreviewArtifact",
    "materializeWorkspaceRestoreApplyArtifact",
    "appendWorkspaceRestorePreviewEvent",
    "appendWorkspaceRestoreApplyEvent",
    "maybeRunPostEditDiagnostics",
    "pendingDiagnosticsFeedbackForNextTurn",
    "materializeCodingToolArtifactDrafts",
    "materializeVisualGuiObservationArtifacts",
    "readCodingToolArtifact",
    "retrieveCodingToolResult",
    "executeDiagnosticsOperatorOverride",
    "turnForOperatorOverrideEvent",
    "appendDiagnosticsOperatorOverrideEvent",
    "createDiagnosticsRepairRetryTurn",
    "turnForRepairRetryEvent",
    "appendDiagnosticsRepairRetryTurnEvent",
    "resolveDiagnosticsRepairDecision",
    "appendDiagnosticsRepairDecisionExecutedEvent",
    "createConversationArtifact",
    "listConversationArtifacts",
    "getConversationArtifact",
    "listConversationArtifactRevisions",
    "performConversationArtifactAction",
    "exportConversationArtifact",
    "promoteConversationArtifact",
  ]) {
    assert.equal(Object.hasOwn(prototype, method), false, `${method} must not be a store delegate`);
    assert.equal(typeof prototype[method], "undefined", `${method} must be absent from the store`);
  }
});
