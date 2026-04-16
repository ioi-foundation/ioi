import assert from "node:assert/strict";
import {
  defaultRunActivityDetail,
  defaultRunActivityTitle,
  isInfrastructureCurrentStep,
  operatorFacingCurrentStep,
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

assert.equal(
  isInfrastructureCurrentStep(
    "Session state is reconciling, but the first step was queued using the committed bootstrap nonce.",
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
  "Drafting the direct answer",
);

assert.equal(
  defaultRunActivityDetail(directInlineSummary as any),
  "Answering inline and only widening the route if outside data becomes necessary.",
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
      current_step: "Reading Reuters coverage for confirmation.",
    } as any,
    researchSummary as any,
  ),
  "Reading Reuters coverage for confirmation.",
);

console.log("runtimeStatusCopy.test.ts: ok");
