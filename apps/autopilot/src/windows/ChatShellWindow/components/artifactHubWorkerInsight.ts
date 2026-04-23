import type { PlanSummary, ThoughtAgentSummary } from "../../../types";

function humanizeStatus(value: string | null | undefined): string {
  const text = (value || "").trim().replace(/[_-]+/g, " ");
  if (!text) return "Unknown";
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

export function workerInsightForPlanSummary(
  agent: ThoughtAgentSummary,
  planSummary: PlanSummary | null,
): { label: string; text: string } | null {
  if (!planSummary) {
    return null;
  }

  if (agent.agentKind === "verifier") {
    if (planSummary.researchVerification) {
      return {
        label: "Verifier finding",
        text:
          planSummary.researchVerification.notes ||
          `${planSummary.researchVerification.sourceCount} sources across ${planSummary.researchVerification.distinctDomainCount} domains. Quote grounding ${humanizeStatus(planSummary.researchVerification.quoteGroundingStatus)}.`,
      };
    }
    if (planSummary.codingVerification) {
      return {
        label: "Verifier finding",
        text:
          planSummary.codingVerification.notes ||
          `${planSummary.codingVerification.targetedPassCount}/${planSummary.codingVerification.targetedCommandCount} targeted commands passed. Regression ${humanizeStatus(planSummary.codingVerification.regressionStatus)}.`,
      };
    }
    if (planSummary.computerUseVerification) {
      return {
        label: "Verifier finding",
        text:
          planSummary.computerUseVerification.notes ||
          `Postcondition ${humanizeStatus(planSummary.computerUseVerification.postconditionStatus)}. Recovery ${humanizeStatus(planSummary.computerUseVerification.recoveryStatus)}.`,
      };
    }
    if (planSummary.artifactQuality) {
      return {
        label: "Verifier finding",
        text:
          planSummary.artifactQuality.notes ||
          `Fidelity ${humanizeStatus(planSummary.artifactQuality.fidelityStatus)}. Presentation ${humanizeStatus(planSummary.artifactQuality.presentationStatus)}.`,
      };
    }
  }

  if (agent.agentKind === "patch_synthesizer" && planSummary.patchSynthesis) {
    return {
      label: "Output",
      text:
        planSummary.patchSynthesis.notes ||
        `${planSummary.patchSynthesis.touchedFileCount} touched files ready for final handoff.`,
    };
  }

  if (agent.agentKind === "artifact_generator" && planSummary.artifactGeneration) {
    return {
      label: "Output",
      text:
        planSummary.artifactGeneration.notes ||
        `${planSummary.artifactGeneration.producedFileCount} files produced with presentation ${humanizeStatus(planSummary.artifactGeneration.presentationStatus)}.`,
    };
  }

  if (
    agent.agentKind === "computer_use_operator" &&
    planSummary.computerUsePerception?.nextAction
  ) {
    return {
      label: "Next action",
      text: planSummary.computerUsePerception.nextAction,
    };
  }

  if (planSummary.activeWorkerLabel === agent.agentLabel && planSummary.progressSummary) {
    return {
      label: "Route progress",
      text: planSummary.progressSummary,
    };
  }

  return null;
}
