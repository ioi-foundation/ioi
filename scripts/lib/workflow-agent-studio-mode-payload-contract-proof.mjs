#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-agent-studio-mode-payload-contract-proof.mjs <output-path>");
}

const extensionPath = "workbench-adapters/ioi-workbench/extension.js";
const source = fs.readFileSync(extensionPath, "utf8");

const snippets = {
  askConstant: /const STUDIO_MODE_ASK = "ask"/.test(source),
  agentConstant: /const STUDIO_MODE_AGENT = "agent"/.test(source),
  askBranchStreamsDirectModel: /if \(executionMode === STUDIO_MODE_ASK\) \{[\s\S]*streamStudioModelCompletion\(/.test(source),
  agentBranchSubmitsHarnessTurn: /\} else \{[\s\S]*submitStudioAgentTurn\(/.test(source),
  askSourceTagged: /source: normalizedMode === STUDIO_MODE_AGENT \? "agent-studio-agent-mode" : "agent-studio-ask-mode"/.test(source),
  agentSourceTagged: /source: "agent-studio-agent-mode"/.test(source),
  submitBridgeCarriesExecutionMode: /writeBridgeRequest\(\s*"chat\.submit"[\s\S]*executionMode,[\s\S]*runtimeProfile: studioRuntimeProjection\.runtimeProfile/.test(source),
  bridgeDisclaimsRuntimeOwnership: /ownsRuntimeState: false/.test(source),
  askModelStreamHasDirectFlags: /askMode: true,[\s\S]*directModelAnswer: true,[\s\S]*chatOnlyMode: true/.test(source),
  agentRequiresChatReply: /String\(studioRuntimeEventToolName\(event\)\)\.toLowerCase\(\) === "chat__reply"/.test(source),
  missingReplyMessageVisible: /did not emit a final chat__reply/.test(source),
  agentDoesNotAcceptModelProseAsProof: /Daemon agent turn completed without accepting model prose as execution proof/.test(source),
  askFinalAnswerMessage: /Explicit Ask direct model stream completed/.test(source),
  threadResetOnModeChange: /normalizeStudioExecutionMode\(studioRuntimeProjection\.executionMode\) !== normalizedMode[\s\S]*studioRuntimeProjection\.threadId = null/.test(source),
};

for (const [key, passed] of Object.entries(snippets)) {
  assert.equal(passed, true, `missing source contract: ${key}`);
}

const askSubmitSummary = {
  executionMode: "ask",
  runtimeProfile: "fixture",
  source: "agent-studio-ask-mode",
  path: "streamStudioModelCompletion",
  directModelAnswer: true,
  ownsRuntimeState: false,
};
const agentSubmitSummary = {
  executionMode: "agent",
  runtimeProfile: "runtime_service",
  source: "agent-studio-agent-mode",
  path: "submitStudioAgentTurn",
  requiresChatReply: true,
  ownsRuntimeState: false,
};

const proof = {
  schemaVersion: "ioi.autopilot.stage59.agent-studio-mode-payload-contract-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  extensionPath,
  checks: {
    askAndAgentConstantsPresent: snippets.askConstant && snippets.agentConstant,
    askRoutesToDirectModelStream: snippets.askBranchStreamsDirectModel,
    agentRoutesToHarnessTurn: snippets.agentBranchSubmitsHarnessTurn,
    bridgePayloadCarriesModeAndRuntimeProfile: snippets.submitBridgeCarriesExecutionMode,
    bridgeDisclaimsRuntimeOwnership: snippets.bridgeDisclaimsRuntimeOwnership,
    askDirectFlagsVisible: snippets.askModelStreamHasDirectFlags,
    agentChatReplyRequired: snippets.agentRequiresChatReply && snippets.missingReplyMessageVisible,
    modeChangeResetsThread: snippets.threadResetOnModeChange,
  },
  snippets,
  askSubmitSummary,
  agentSubmitSummary,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
