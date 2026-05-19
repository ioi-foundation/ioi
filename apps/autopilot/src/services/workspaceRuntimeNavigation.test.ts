import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workspaceRuntimeNavigation = readFileSync(
  "apps/autopilot/src/services/workspaceRuntimeNavigation.ts",
  "utf8",
);
const runtimeChatNavigation = readFileSync(
  "apps/autopilot/src/services/runtimeChatNavigation.ts",
  "utf8",
);
const codeAwareActionContext = readFileSync(
  "apps/autopilot/src/services/codeAwareActionContext.ts",
  "utf8",
);
const workspaceBridgeState = readFileSync(
  "apps/autopilot/src/services/workspaceBridgeState.ts",
  "utf8",
);

test("native workbench projection requests are routed deliberately", () => {
  assert.match(workspaceRuntimeNavigation, /case "workbench\.contextSnapshot"/);
  assert.match(workspaceRuntimeNavigation, /case "workbench\.inspectionTargetIndex"/);
  assert.match(workspaceRuntimeNavigation, /case "workbench\.commandRouteReceipt"/);
  assert.match(workspaceRuntimeNavigation, /routedTo: "workbench\.command-route-receipt"/);
});

test("native chat submit routes into the runtime chat intent path", () => {
  assert.match(workspaceRuntimeNavigation, /case "chat\.submit"/);
  assert.match(workspaceRuntimeNavigation, /case "chat\.generateAgentInstructions"/);
  assert.match(workspaceRuntimeNavigation, /case "chat\.showConfig"/);
  assert.match(workspaceRuntimeNavigation, /case "chat\.addContext"/);
  assert.match(workspaceRuntimeNavigation, /case "chat\.attachEditorContext"/);
  assert.match(workspaceRuntimeNavigation, /case "chat\.contextOptions"/);
  assert.match(workspaceRuntimeNavigation, /case "chat\.toolControls"/);
  assert.match(workspaceRuntimeNavigation, /case "settings\.open"/);
  assert.match(workspaceRuntimeNavigation, /submitNativeWorkbenchChatPrompt\(runtime, prompt\)/);
  assert.match(workspaceRuntimeNavigation, /runtime\.startSessionTask<AgentTask>\(prompt\)/);
  assert.match(workspaceRuntimeNavigation, /runtime\.continueSessionTask\(sessionId, prompt\)/);
  assert.match(workspaceRuntimeNavigation, /routedTo: "native-chat\.inline-runtime-submit"/);
  assert.match(
    workspaceRuntimeNavigation,
    /routedTo: "native-chat\.inline-generate-agent-instructions"/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /routedTo: "native-chat\.inline-native-workbench-config"/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /routedTo: "native-chat\.inline-attach-native-context"/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /routedTo: "native-chat\.inline-context-options"/,
  );
  assert.match(workspaceRuntimeNavigation, /openRuntimeConnectionsOverview\(runtime/);
  assert.match(workspaceRuntimeNavigation, /runtime\.openChatView\("settings"\)/);
  assert.match(runtimeChatNavigation, /export async function openRuntimeChatPrompt/);
});

test("native workflow code-generation requests become proposal-first runtime intents", () => {
  assert.match(workspaceRuntimeNavigation, /case "workflow\.codeGenerationRequest"/);
  assert.match(
    workspaceRuntimeNavigation,
    /materializeWorkflowCodeGenerationProposal\(\{[\s\S]*targetWorkspace:/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /bridge_request_artifact_materialized/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /bridge_request_artifact_materialization_failed/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /openRuntimeWorkflowCodeGeneration\(runtime,\s*\{[\s\S]*proposalOnly:/,
  );
  assert.match(runtimeChatNavigation, /export async function openRuntimeWorkflowCodeGeneration/);
  assert.match(codeAwareActionContext, /export function buildWorkflowCodeGenerationIntent/);
  assert.match(codeAwareActionContext, /Mutation posture: \$\{mutationPosture\}/);
  assert.match(
    codeAwareActionContext,
    /Produce a bounded proposal, diff artifact, approval\/check plan, and receipt trail/,
  );
});

test("workspace bridge state projects active chat turns for the native sidebar", () => {
  assert.match(workspaceBridgeState, /runtime\.getSessionProjection<AgentTask, SessionSummary>\(\)/);
  assert.match(workspaceBridgeState, /projectWorkspaceChatState\(sessionProjection\)/);
  assert.match(workspaceBridgeState, /hasActiveConversation/);
  assert.match(workspaceBridgeState, /turns/);
  assert.match(workspaceBridgeState, /recentSessions/);
});
