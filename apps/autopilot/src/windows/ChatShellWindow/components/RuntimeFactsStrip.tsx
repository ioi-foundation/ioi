import type {
  AgentTask,
  EvidenceTier,
  LocalEngineSnapshot,
  PlanSummary,
} from "../../../types";

type RuntimeFactsStripProps = {
  task: AgentTask | null;
  planSummary: PlanSummary | null;
  runtimeModelLabel?: string | null;
  localEngineSnapshot?: LocalEngineSnapshot | null;
  compact?: boolean;
  onOpenEvidence?: () => void;
};

type RuntimeFact = {
  key: string;
  label: string;
  value: string;
  tone?: "normal" | "warn" | "good";
};

function compactLabel(value: string | null | undefined, fallback: string): string {
  const trimmed = (value || "").trim();
  return trimmed || fallback;
}

function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function hasSettlementRefs(task: AgentTask | null): boolean {
  const materialization = task?.chat_session?.materialization as
    | Record<string, unknown>
    | undefined;
  const executionEnvelope = materialization?.executionEnvelope as
    | Record<string, unknown>
    | undefined;
  if (!executionEnvelope) {
    return false;
  }

  return [
    "settlementRefs",
    "settlement_refs",
    "settlementReceipts",
    "settlement_receipts",
  ].some((key) => Array.isArray(executionEnvelope[key]));
}

function runtimeEvidenceTier(task: AgentTask | null): EvidenceTier {
  if (!task) {
    return "Projection";
  }
  if (hasSettlementRefs(task)) {
    return "Settlement receipt";
  }
  if ((task.events?.length ?? 0) > 0) {
    return "Runtime event receipt";
  }
  if ((task.artifacts?.length ?? 0) > 0) {
    return "Artifact promotion";
  }
  return "Projection";
}

function approvalLabel(task: AgentTask | null, planSummary: PlanSummary | null): string {
  if (task?.pending_request_hash || task?.gate_info) {
    return "Pending grant";
  }
  return titleCase(planSummary?.approvalState || "clear");
}

function capabilityLabel(
  planSummary: PlanSummary | null,
  localEngineSnapshot: LocalEngineSnapshot | null | undefined,
): string {
  const projectedTools =
    planSummary?.routeDecision?.effectiveToolSurface.projectedTools || [];
  if (projectedTools.length > 0) {
    return projectedTools.slice(0, 3).join(", ");
  }
  if (planSummary?.selectedSkills.length) {
    return planSummary.selectedSkills
      .slice(0, 3)
      .map((skill) => skill.label)
      .join(", ");
  }
  const capabilityCount = localEngineSnapshot?.capabilities.length ?? 0;
  if (capabilityCount > 0) {
    return `${capabilityCount} runtime categories`;
  }
  return "Envelope pending";
}

export function RuntimeFactsStrip({
  task,
  planSummary,
  runtimeModelLabel,
  localEngineSnapshot,
  compact = false,
  onOpenEvidence,
}: RuntimeFactsStripProps) {
  const evidenceTier = runtimeEvidenceTier(task);
  const settlementState = hasSettlementRefs(task)
    ? "Settlement-backed"
    : evidenceTier === "Projection"
      ? "Projection-only"
      : "Receipt projection";
  const stage =
    planSummary?.currentStage ||
    task?.current_step ||
    (task?.phase ? titleCase(task.phase) : null);
  const facts: RuntimeFact[] = [
    {
      key: "route",
      label: "Route",
      value: compactLabel(planSummary?.selectedRoute, "Resolving"),
    },
    {
      key: "model",
      label: "Model",
      value: compactLabel(runtimeModelLabel, "Kernel-selected"),
    },
    {
      key: "stage",
      label: "Stage",
      value: compactLabel(stage, "Ready"),
    },
    {
      key: "policy",
      label: "Policy",
      value: planSummary?.policyBindings.length
        ? `${planSummary.policyBindings.length} binding${
            planSummary.policyBindings.length === 1 ? "" : "s"
          }`
        : "Projection",
    },
    {
      key: "approval",
      label: "Approval",
      value: approvalLabel(task, planSummary),
      tone: task?.pending_request_hash || task?.gate_info ? "warn" : "normal",
    },
    {
      key: "capabilities",
      label: "Capabilities",
      value: capabilityLabel(planSummary, localEngineSnapshot),
    },
    {
      key: "evidence",
      label: "Evidence",
      value: evidenceTier,
      tone: evidenceTier === "Missing settlement" ? "warn" : "good",
    },
    {
      key: "settlement",
      label: "State",
      value: settlementState,
      tone: settlementState === "Projection-only" ? "warn" : "normal",
    },
  ];

  return (
    <div
      className={`runtime-facts-strip ${compact ? "is-compact" : ""}`}
      aria-label="Runtime facts"
    >
      <div className="runtime-facts-strip__head">
        <span>Runtime Facts</span>
        <small>kernel records, not model claims</small>
      </div>
      <dl className="runtime-facts-strip__grid">
        {facts.map((fact) => {
          const className = `runtime-facts-strip__item ${
            fact.tone ? `is-${fact.tone}` : ""
          }`;
          if (fact.key === "evidence" && onOpenEvidence) {
            return (
              <button
                className={`${className} is-action`}
                key={fact.key}
                type="button"
                onClick={onOpenEvidence}
                title="Open runtime workbench evidence"
              >
                <span className="runtime-facts-strip__term">{fact.label}</span>
                <span className="runtime-facts-strip__value">{fact.value}</span>
              </button>
            );
          }
          return (
            <div className={className} key={fact.key}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}
