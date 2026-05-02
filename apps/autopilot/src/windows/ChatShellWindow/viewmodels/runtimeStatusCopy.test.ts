import assert from "node:assert/strict";
import {
  defaultRunActivityDetail,
  defaultRunActivityTitle,
  isInfrastructureCurrentStep,
  operatorFacingCurrentStep,
  runtimeExecutionFailureDetail,
  operatorFacingRunTitle,
} from "./runtimeStatusCopy.ts";

const researchSummary = {
  routeFamily: "research",
  progressSummary: null,
  pauseSummary: null,
  routeDecision: {
    currentnessOverride: true,
    connectorFirstPreference: false,
    selectedProviderFamily: null,
    artifactOutputIntent: false,
    fileOutputIntent: false,
    inlineVisualIntent: false,
    directAnswerAllowed: false,
    outputIntent: "tool_execution",
    effectiveToolSurface: {
      projectedTools: ["web_search", "web_fetch"],
      primaryTools: ["web_search"],
      broadFallbackTools: ["browser__open"],
      diagnosticTools: [],
    },
  },
} as const;

const directInlineSummary = {
  routeFamily: "general",
  progressSummary: null,
  pauseSummary: null,
  routeDecision: {
    currentnessOverride: false,
    connectorFirstPreference: false,
    selectedProviderFamily: null,
    artifactOutputIntent: false,
    fileOutputIntent: false,
    inlineVisualIntent: false,
    directAnswerAllowed: true,
    outputIntent: "direct_inline",
    effectiveToolSurface: {
      projectedTools: [],
      primaryTools: [],
      broadFallbackTools: [],
      diagnosticTools: [],
    },
  },
} as const;

const installSummary = {
  routeFamily: "command_execution",
  progressSummary: null,
  pauseSummary: null,
  routeDecision: {
    currentnessOverride: false,
    connectorFirstPreference: false,
    selectedProviderFamily: null,
    artifactOutputIntent: false,
    fileOutputIntent: false,
    inlineVisualIntent: false,
    directAnswerAllowed: false,
    outputIntent: "tool_execution",
    effectiveToolSurface: {
      projectedTools: [
        "host_discovery",
        "software_install_resolver",
        "software_install__execute_plan",
      ],
      primaryTools: [
        "host_discovery",
        "software_install_resolver",
        "software_install__execute_plan",
      ],
      broadFallbackTools: [],
      diagnosticTools: [],
    },
  },
} as const;

assert.equal(
  isInfrastructureCurrentStep(
    "Session state is reconciling, but the first step was queued using the committed bootstrap nonce.",
  ),
  true,
);

assert.equal(
  isInfrastructureCurrentStep(
    "Chat verified candidate-1 after clearing 4/4 required obligations across 1 candidate(s).",
  ),
  true,
);

assert.equal(
  defaultRunActivityTitle(researchSummary as any),
  "Checking current sources",
);

assert.equal(
  defaultRunActivityDetail(researchSummary as any),
  "Checking fresh public information before answering.",
);

assert.equal(
  defaultRunActivityTitle(directInlineSummary as any),
  "Preparing answer",
);

assert.equal(
  defaultRunActivityDetail(directInlineSummary as any),
  "Drafting the answer inline.",
);

assert.equal(
  operatorFacingCurrentStep(
    {
      current_step:
        "Session state is reconciling, but the first step was queued using the committed bootstrap nonce.",
    } as any,
    researchSummary as any,
  ),
  "Checking fresh public information before answering.",
);

assert.equal(
  operatorFacingCurrentStep(
    {
      current_step:
        "Chat verified candidate-1 after clearing 4/4 required obligations across 1 candidate(s).",
    } as any,
    directInlineSummary as any,
  ),
  "Drafting the answer inline.",
);

assert.equal(
  operatorFacingRunTitle(installSummary as any, {
    chat_outcome: {
      decisionEvidence: [
        "local_install_requested",
        "software_install_target_text:example app",
      ],
    },
  } as any),
  "Install example app",
);

assert.equal(
  operatorFacingCurrentStep(
    {
      chat_outcome: {
        decisionEvidence: [
          "local_install_requested",
          "software_install_target_text:example app",
        ],
      },
      current_step:
        "Session start commit is delayed, but bootstrap is continuing in the background: Tx abc did not commit within 15000ms (last tx status: InMempool).",
    } as any,
    installSummary as any,
  ),
  "Resolving example app install route before host mutation.",
);

assert.equal(
  operatorFacingCurrentStep(
    {
      current_step: "Reading Reuters coverage for confirmation.",
    } as any,
    researchSummary as any,
  ),
  "Reading Reuters coverage for confirmation.",
);

assert.equal(
  runtimeExecutionFailureDetail({
    current_step:
      "Executed system::invalid_tool_call: ERROR_CLASS=UnexpectedState Failed to parse tool call",
  } as any),
  "Executed system::invalid_tool_call: ERROR_CLASS=UnexpectedState Failed to parse tool call",
);

console.log("runtimeStatusCopy.test.ts: ok");
