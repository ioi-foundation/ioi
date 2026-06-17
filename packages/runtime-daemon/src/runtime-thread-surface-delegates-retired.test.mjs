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
    "appendWorkspaceTrustWarningEvent",
    "updateThreadRuntimeControls",
    "appendThreadRuntimeControlEvent",
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
  ]) {
    assert.equal(Object.hasOwn(prototype, method), false, `${method} must not be a store delegate`);
    assert.equal(typeof prototype[method], "undefined", `${method} must be absent from the store`);
  }
});

test("daemon store thread auxiliary methods are positive API owners, not surface delegates", () => {
  const prototype = AgentgresRuntimeStateStore.prototype;
  for (const [method, expectedCall] of [
    ["inspectManagedSessionsForThread", "this.threadAuxiliaryApi.inspectManagedSessionsForThread"],
    ["inspectWorkspaceChangeReviewsForThread", "this.threadAuxiliaryApi.inspectWorkspaceChangeReviewsForThread"],
    ["controlWorkspaceChangeForThread", "this.threadAuxiliaryApi.controlWorkspaceChangeForThread"],
    ["controlManagedSessionForThread", "this.threadAuxiliaryApi.controlManagedSessionForThread"],
    ["forkThread", "this.threadAuxiliaryApi.forkThread"],
    ["cancelRun", "this.threadAuxiliaryApi.cancelRun"],
  ]) {
    assert.equal(Object.hasOwn(prototype, method), true, `${method} must be a store-owned auxiliary API method`);
    assert.match(prototype[method].toString(), new RegExp(expectedCall.replaceAll(".", "\\.")));
  }
});

test("daemon store conversation artifact methods are positive API owners, not surface delegates", () => {
  const prototype = AgentgresRuntimeStateStore.prototype;
  for (const [method, expectedCall] of [
    ["createConversationArtifact", "this.conversationArtifactApi.createConversationArtifact"],
    ["listConversationArtifacts", "this.conversationArtifactApi.listConversationArtifacts"],
    ["getConversationArtifact", "this.conversationArtifactApi.getConversationArtifact"],
    ["listConversationArtifactRevisions", "this.conversationArtifactApi.listConversationArtifactRevisions"],
    ["performConversationArtifactAction", "this.conversationArtifactApi.performConversationArtifactAction"],
    ["exportConversationArtifact", "this.conversationArtifactApi.exportConversationArtifact"],
    ["promoteConversationArtifact", "this.conversationArtifactApi.promoteConversationArtifact"],
  ]) {
    assert.equal(Object.hasOwn(prototype, method), true, `${method} must be a store-owned artifact API method`);
    assert.match(prototype[method].toString(), new RegExp(expectedCall.replaceAll(".", "\\.")));
  }
});

test("daemon store subagent methods are positive API owners, not surface delegates", () => {
  const prototype = AgentgresRuntimeStateStore.prototype;
  for (const [method, expectedCall] of [
    ["listSubagents", "this.subagentApi.listSubagents"],
    ["getSubagent", "this.subagentApi.getSubagent"],
    ["spawnSubagent", "this.subagentApi.spawnSubagent"],
    ["propagateSubagentCancellation", "this.subagentApi.propagateSubagentCancellation"],
    ["waitSubagent", "this.subagentApi.waitSubagent"],
    ["sendSubagentInput", "this.subagentApi.sendSubagentInput"],
    ["cancelSubagent", "this.subagentApi.cancelSubagent"],
    ["resumeSubagent", "this.subagentApi.resumeSubagent"],
    ["assignSubagent", "this.subagentApi.assignSubagent"],
    ["getSubagentResult", "this.subagentApi.getSubagentResult"],
    ["subagentProjection", "this.subagentApi.subagentProjection"],
    ["appendThreadSubagentControlEvent", "this.subagentApi.appendThreadSubagentControlEvent"],
  ]) {
    assert.equal(Object.hasOwn(prototype, method), true, `${method} must be a store-owned subagent API method`);
    assert.match(prototype[method].toString(), new RegExp(expectedCall.replaceAll(".", "\\.")));
  }
});
