import type {
  AgentTask,
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
  PlanSummary,
} from "../../../types";

export function humanizeStatus(value: string | null | undefined): string {
  const text = (value || "").trim().replace(/[_-]+/g, " ");
  if (!text) return "Unknown";
  return text.replace(/\b\w/g, (char) => char.toUpperCase());
}

export function formatTaskTimestamp(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "Unknown";
  }

  return new Date(value).toLocaleTimeString([], {
    hour: "numeric",
    minute: "2-digit",
  });
}

export function latestTaskOutputs(task: AgentTask, maxEntries: number = 5) {
  return task.history
    .filter(
      (message) =>
        message.text.trim().length > 0 &&
        message.role.trim().toLowerCase() !== "user",
    )
    .slice(-maxEntries)
    .reverse();
}

export function taskBlockerSummary(
  task: AgentTask | null,
  overrides?: {
    clarificationRequest?: ClarificationRequest;
    credentialRequest?: CredentialRequest;
    gateInfo?: GateInfo;
    isGated?: boolean;
  },
): {
  title: string;
  detail: string;
} | null {
  if (!task && !overrides?.clarificationRequest && !overrides?.credentialRequest) {
    if (!(overrides?.isGated || overrides?.gateInfo)) {
      return null;
    }
  }

  const clarificationRequest =
    overrides?.clarificationRequest ?? task?.clarification_request;
  const credentialRequest =
    overrides?.credentialRequest ?? task?.credential_request;
  const gateInfo = overrides?.gateInfo ?? task?.gate_info;
  const isGated =
    overrides?.isGated ??
    Boolean(
      task?.pending_request_hash || task?.gate_info || task?.phase === "Gate",
    );

  if (clarificationRequest) {
    const optionLabels = clarificationRequest.options
      .map((option) => option.label)
      .filter(Boolean)
      .join(" · ");
    const detail = [
      clarificationRequest.question,
      clarificationRequest.context_hint,
      optionLabels ? `Options: ${optionLabels}` : null,
    ]
      .filter(Boolean)
      .join(" ");
    return {
      title: "Clarification required",
      detail,
    };
  }

  if (credentialRequest) {
    return {
      title: "Credential required",
      detail: credentialRequest.prompt || humanizeStatus(credentialRequest.kind),
    };
  }

  if (isGated) {
    return {
      title: gateInfo?.title || "Approval required",
      detail:
        gateInfo?.description ||
        gateInfo?.operator_note ||
        task?.current_step ||
        "The task is waiting on an operator decision before it can continue.",
    };
  }

  return null;
}

export function buildVerificationNotes(planSummary: PlanSummary | null): string[] {
  if (!planSummary) return [];

  const verifierHeadline = [
    `Verifier state: ${humanizeStatus(planSummary.verifierState)}`,
    planSummary.verifierOutcome
      ? `Outcome: ${humanizeStatus(planSummary.verifierOutcome)}`
      : null,
    `Approval: ${humanizeStatus(planSummary.approvalState)}`,
  ]
    .filter(Boolean)
    .join(" · ");

  const notes: string[] = [verifierHeadline];

  if (planSummary.researchVerification) {
    notes.push(
      `Research scorecard: ${humanizeStatus(planSummary.researchVerification.verdict)} · ${planSummary.researchVerification.sourceCount} sources across ${planSummary.researchVerification.distinctDomainCount} domains.`,
    );
  }

  if (planSummary.codingVerification) {
    notes.push(
      `Coding scorecard: ${humanizeStatus(planSummary.codingVerification.verdict)} · ${planSummary.codingVerification.targetedPassCount}/${planSummary.codingVerification.targetedCommandCount} targeted commands passed.`,
    );
  }

  if (planSummary.computerUseVerification) {
    notes.push(
      `Computer-use verifier: ${humanizeStatus(planSummary.computerUseVerification.verdict)} · postcondition ${humanizeStatus(planSummary.computerUseVerification.postconditionStatus)} · recovery ${humanizeStatus(planSummary.computerUseVerification.recoveryStatus)}.`,
    );
  }

  if (planSummary.artifactQuality) {
    notes.push(
      `Artifact validation: ${humanizeStatus(planSummary.artifactQuality.verdict)} · fidelity ${humanizeStatus(planSummary.artifactQuality.fidelityStatus)} · presentation ${humanizeStatus(planSummary.artifactQuality.presentationStatus)}.`,
    );
  }

  if (planSummary.pauseSummary) {
    notes.push(`Pause: ${planSummary.pauseSummary}`);
  }

  return notes;
}
