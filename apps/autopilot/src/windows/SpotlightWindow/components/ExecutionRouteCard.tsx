import type { PlanSummary } from "../../../types";

type ExecutionRouteCardProps = {
  summary: PlanSummary;
  currentStep?: string;
  traceDetail?: string | null;
  onOpenArtifacts?: () => void;
};

function familyLabel(family: PlanSummary["routeFamily"]): string {
  switch (family) {
    case "research":
      return "Research";
    case "coding":
      return "Coding";
    case "computer_use":
      return "Computer use";
    case "artifacts":
      return "Artifacts";
    default:
      return "General";
  }
}

function topologyLabel(topology: PlanSummary["topology"]): string {
  switch (topology) {
    case "planner_specialist_verifier":
      return "Planner -> specialist -> verifier";
    case "planner_specialist":
      return "Planner -> specialist";
    default:
      return "Single agent";
  }
}

function plannerAuthorityLabel(
  authority: PlanSummary["plannerAuthority"],
): string {
  switch (authority) {
    case "kernel":
      return "Kernel";
    default:
      return "Primary agent";
  }
}

function verifierStateLabel(state: PlanSummary["verifierState"]): string {
  switch (state) {
    case "passed":
      return "Completed";
    case "blocked":
      return "Blocked";
    case "active":
      return "Running";
    case "queued":
      return "Queued";
    default:
      return "Not engaged";
  }
}

function verifierOutcomeLabel(
  outcome: PlanSummary["verifierOutcome"],
): string {
  switch (outcome) {
    case "pass":
      return "Pass";
    case "warning":
      return "Warning";
    case "blocked":
      return "Blocked";
    default:
      return "Unknown";
  }
}

function verifierRoleLabel(role: PlanSummary["verifierRole"]): string {
  switch (role) {
    case "citation_verifier":
      return "Citation verifier";
    case "test_verifier":
      return "Test verifier";
    case "postcondition_verifier":
      return "Postcondition verifier";
    case "artifact_quality_verifier":
      return "Artifact quality verifier";
    default:
      return "Verifier";
  }
}

function verifierHeadline(summary: PlanSummary): string {
  return summary.verifierOutcome
    ? verifierOutcomeLabel(summary.verifierOutcome)
    : verifierStateLabel(summary.verifierState);
}

function verifierSubLabel(summary: PlanSummary): string | null {
  if (!summary.verifierOutcome) return null;
  if (summary.verifierOutcome === "blocked" && summary.verifierState === "blocked") {
    return null;
  }
  return verifierStateLabel(summary.verifierState);
}

function approvalLabel(state: PlanSummary["approvalState"]): string {
  switch (state) {
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
    case "denied":
      return "Denied";
    default:
      return "Clear";
  }
}

function statusLabel(status: string): string {
  const normalized = status.trim().replace(/[_-]+/g, " ");
  if (!normalized) return "Captured";
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function researchStatusLabel(value: string): string {
  const normalized = value.trim().replace(/[_-]+/g, " ");
  if (!normalized) return "Unknown";
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

export function ExecutionRouteCard({
  summary,
  currentStep,
  traceDetail,
  onOpenArtifacts,
}: ExecutionRouteCardProps) {
  const currentStage = currentStep?.trim() || summary.currentStage;

  return (
    <section
      className={`spot-execution-card ${
        summary.approvalState === "pending" ? "is-gated" : ""
      }`}
      aria-label="Execution route summary"
    >
      <div className="spot-execution-card-header">
        <div className="spot-execution-card-copy">
          <span className="spot-execution-card-kicker">
            {familyLabel(summary.routeFamily)} route
          </span>
          <strong>{summary.selectedRoute}</strong>
          <p>{topologyLabel(summary.topology)}</p>
        </div>
        <span className="spot-execution-card-status">
          {statusLabel(summary.status)}
        </span>
      </div>

      {(currentStage || summary.progressSummary || summary.pauseSummary) && (
        <div className="spot-execution-card-story">
          {currentStage && (
            <div className="spot-execution-card-story-block">
              <span>Current stage</span>
              <p>{currentStage}</p>
            </div>
          )}
          {summary.progressSummary && (
            <div className="spot-execution-card-story-block">
              <span>Progress</span>
              <p>{summary.progressSummary}</p>
            </div>
          )}
          {summary.pauseSummary && (
            <div className="spot-execution-card-story-block is-emphasis">
              <span>Pause</span>
              <p>{summary.pauseSummary}</p>
            </div>
          )}
        </div>
      )}

      <div className="spot-execution-card-grid">
        <div className="spot-execution-card-metric">
          <span>Active worker</span>
          <strong>{summary.activeWorkerLabel || "Waiting on planner"}</strong>
          {summary.activeWorkerRole && (
            <small>{summary.activeWorkerRole.replace(/[_-]+/g, " ")}</small>
          )}
        </div>
        <div className="spot-execution-card-metric">
          <span>Planner of record</span>
          <strong>{plannerAuthorityLabel(summary.plannerAuthority)}</strong>
        </div>
        <div className="spot-execution-card-metric">
          <span>
            {summary.verifierRole
              ? verifierRoleLabel(summary.verifierRole)
              : "Verifier"}
          </span>
          <strong>{verifierHeadline(summary)}</strong>
          {verifierSubLabel(summary) && (
            <small>{verifierSubLabel(summary)}</small>
          )}
        </div>
        <div className="spot-execution-card-metric">
          <span>Approval</span>
          <strong>{approvalLabel(summary.approvalState)}</strong>
        </div>
        <div className="spot-execution-card-metric">
          <span>Evidence</span>
          <strong>{summary.evidenceCount}</strong>
          <small>
            {summary.workerCount} workers · {summary.branchCount} branches
          </small>
        </div>
      </div>

      {onOpenArtifacts && (
        <div className="spot-execution-card-actions">
          <div className="spot-execution-card-actions-copy">
            <span>Evidence and raw trace</span>
            <p>
              {traceDetail ||
                "Open the execution drawer for full evidence and logs."}
            </p>
          </div>
          <button
            className="spot-execution-card-action"
            type="button"
            onClick={() => void onOpenArtifacts()}
          >
            Open execution drawer
          </button>
        </div>
      )}

      {summary.policyBindings.length > 0 && (
        <div className="spot-execution-card-policy">
          {summary.policyBindings.slice(0, 3).map((binding) => (
            <span key={binding} className="spot-execution-card-policy-chip">
              {binding}
            </span>
          ))}
        </div>
      )}

      {(summary.selectedSkills.length > 0 || summary.prepSummary) && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Prepared context</span>
            {summary.prepSummary && <p>{summary.prepSummary}</p>}
          </div>
          {summary.selectedSkills.length > 0 && (
            <div className="spot-execution-card-policy">
              {summary.selectedSkills.slice(0, 4).map((skill) => (
                <span key={skill} className="spot-execution-card-policy-chip">
                  {skill}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {summary.artifactGeneration && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Artifact generation</span>
            <p>
              Status: {researchStatusLabel(summary.artifactGeneration.status)}.{" "}
              {summary.artifactGeneration.producedFileCount} produced files.
            </p>
            <p>
              Verification signals:{" "}
              {researchStatusLabel(
                summary.artifactGeneration.verificationSignalStatus,
              )}
              {" · "}Presentation:{" "}
              {researchStatusLabel(
                summary.artifactGeneration.presentationStatus,
              )}
            </p>
            {summary.artifactGeneration.notes && (
              <p>{summary.artifactGeneration.notes}</p>
            )}
          </div>
        </div>
      )}

      {summary.computerUsePerception && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>UI perception</span>
            <p>
              Surface:{" "}
              {researchStatusLabel(summary.computerUsePerception.surfaceStatus)}
              . {summary.computerUsePerception.uiState}
            </p>
            <p>
              Approval risk:{" "}
              {researchStatusLabel(summary.computerUsePerception.approvalRisk)}
              {summary.computerUsePerception.target
                ? `. Target: ${summary.computerUsePerception.target}.`
                : "."}
            </p>
            {summary.computerUsePerception.nextAction && (
              <p>
                Next safe action: {summary.computerUsePerception.nextAction}
              </p>
            )}
            {summary.computerUsePerception.notes && (
              <p>{summary.computerUsePerception.notes}</p>
            )}
          </div>
        </div>
      )}

      {summary.researchVerification && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Research verification</span>
            <p>
              Verdict:{" "}
              {researchStatusLabel(summary.researchVerification.verdict)}.{" "}
              {summary.researchVerification.sourceCount} sources across{" "}
              {summary.researchVerification.distinctDomainCount} domains.
            </p>
            <p>
              Freshness:{" "}
              {researchStatusLabel(
                summary.researchVerification.freshnessStatus,
              )}{" "}
              · Quote grounding:{" "}
              {researchStatusLabel(
                summary.researchVerification.quoteGroundingStatus,
              )}
            </p>
            {summary.researchVerification.notes && (
              <p>{summary.researchVerification.notes}</p>
            )}
          </div>
          <div className="spot-execution-card-policy">
            <span className="spot-execution-card-policy-chip">
              Source floor{" "}
              {summary.researchVerification.sourceCountFloorMet
                ? "met"
                : "open"}
            </span>
            <span className="spot-execution-card-policy-chip">
              Independence{" "}
              {summary.researchVerification.sourceIndependenceFloorMet
                ? "met"
                : "open"}
            </span>
          </div>
        </div>
      )}

      {summary.computerUseVerification && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Computer-use verification</span>
            <p>
              Verdict:{" "}
              {researchStatusLabel(summary.computerUseVerification.verdict)}.
              Postcondition:{" "}
              {researchStatusLabel(
                summary.computerUseVerification.postconditionStatus,
              )}
              .
            </p>
            <p>
              Approval:{" "}
              {researchStatusLabel(
                summary.computerUseVerification.approvalState,
              )}
              {" · "}Recovery:{" "}
              {researchStatusLabel(
                summary.computerUseVerification.recoveryStatus,
              )}
            </p>
            {summary.computerUseVerification.observedPostcondition && (
              <p>
                Observed postcondition:{" "}
                {summary.computerUseVerification.observedPostcondition}
              </p>
            )}
            {summary.computerUseVerification.notes && (
              <p>{summary.computerUseVerification.notes}</p>
            )}
          </div>
        </div>
      )}

      {summary.codingVerification && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Coding verification</span>
            <p>
              Verdict: {researchStatusLabel(summary.codingVerification.verdict)}
              . {summary.codingVerification.targetedPassCount}/
              {summary.codingVerification.targetedCommandCount} targeted
              commands passed.
            </p>
            <p>
              Widening:{" "}
              {researchStatusLabel(summary.codingVerification.wideningStatus)} ·
              Regression risk:{" "}
              {researchStatusLabel(summary.codingVerification.regressionStatus)}
            </p>
            {summary.codingVerification.notes && (
              <p>{summary.codingVerification.notes}</p>
            )}
          </div>
        </div>
      )}

      {summary.artifactQuality && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Artifact quality</span>
            <p>
              Verdict: {researchStatusLabel(summary.artifactQuality.verdict)}.
              Fidelity:{" "}
              {researchStatusLabel(summary.artifactQuality.fidelityStatus)}
              {" · "}Presentation:{" "}
              {researchStatusLabel(summary.artifactQuality.presentationStatus)}
            </p>
            <p>
              Repair:{" "}
              {researchStatusLabel(summary.artifactQuality.repairStatus)}
            </p>
            {summary.artifactQuality.notes && (
              <p>{summary.artifactQuality.notes}</p>
            )}
          </div>
        </div>
      )}

      {summary.computerUseRecovery && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Recovery</span>
            <p>
              Status: {researchStatusLabel(summary.computerUseRecovery.status)}.
            </p>
            {summary.computerUseRecovery.reason && (
              <p>{summary.computerUseRecovery.reason}</p>
            )}
            {summary.computerUseRecovery.nextStep && (
              <p>Next step: {summary.computerUseRecovery.nextStep}</p>
            )}
          </div>
        </div>
      )}

      {summary.artifactRepair && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Artifact repair</span>
            <p>Status: {researchStatusLabel(summary.artifactRepair.status)}.</p>
            {summary.artifactRepair.reason && (
              <p>{summary.artifactRepair.reason}</p>
            )}
            {summary.artifactRepair.nextStep && (
              <p>Next step: {summary.artifactRepair.nextStep}</p>
            )}
          </div>
        </div>
      )}

      {summary.patchSynthesis && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Patch synthesis</span>
            <p>
              Status: {researchStatusLabel(summary.patchSynthesis.status)}.{" "}
              {summary.patchSynthesis.touchedFileCount} touched files.
            </p>
            <p>
              Verification{" "}
              {summary.patchSynthesis.verificationReady ? "accepted" : "open"}.
            </p>
            {summary.patchSynthesis.notes && (
              <p>{summary.patchSynthesis.notes}</p>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
