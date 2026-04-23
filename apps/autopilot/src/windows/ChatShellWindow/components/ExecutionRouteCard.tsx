import { useMemo } from "react";
import type {
  CapabilityRegistryEntry,
  PlanSelectedSkill,
  PlanSummary,
} from "../../../types";
import { useChatCapabilityRegistry } from "../hooks/useChatCapabilityRegistry";

type ExecutionRouteCardProps = {
  summary: PlanSummary;
  currentStep?: string;
  traceDetail?: string | null;
  onOpenArtifacts?: () => void;
  preferCompactDirectInline?: boolean;
};

function familyLabel(family: PlanSummary["routeFamily"]): string {
  switch (family) {
    case "research":
      return "Research";
    case "coding":
      return "Coding";
    case "integrations":
      return "Integrations";
    case "communication":
      return "Communication";
    case "user_input":
      return "Decision";
    case "tool_widget":
      return "Tool widget";
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
    case "artifact_validation_verifier":
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

function outputIntentLabel(
  outputIntent: NonNullable<PlanSummary["routeDecision"]>["outputIntent"],
): string {
  switch (outputIntent) {
    case "direct_inline":
      return "Direct inline";
    case "inline_visual":
      return "Inline visual";
    case "tool_execution":
      return "Tool execution";
    default:
      return outputIntent.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
  }
}

function routeBlockerLabel(blocker: string): string {
  switch (blocker.trim().toLowerCase()) {
    case "currentness_override":
      return "Fresh/current data required";
    case "connector_preferred":
      return "Connector/provider path preferred";
    case "file_output_intent":
      return "File output required";
    case "artifact_output_intent":
      return "Artifact output required";
    case "inline_visual_intent":
      return "Visual interaction required";
    case "skill_prep_required":
      return "Guidance prep required";
    default:
      return blocker.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
  }
}

function providerLabel(value: string): string {
  return value.replace(/[._]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function laneLabel(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function sourceFamilyLabel(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function researchStatusLabel(value: string): string {
  const normalized = value.trim().replace(/[_-]+/g, " ");
  if (!normalized) return "Unknown";
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function requestFrameLabel(
  frame: NonNullable<PlanSummary["routeDecision"]>["requestFrame"],
): string | null {
  if (!frame) return null;
  switch (frame.kind) {
    case "weather":
      return "Weather";
    case "sports":
      return "Sports";
    case "places":
      return "Places";
    case "recipe":
      return "Recipe";
    case "message_compose":
      return "Message compose";
    case "user_input":
      return "User input";
    default:
      return null;
  }
}

function requestFrameSummary(
  frame: NonNullable<PlanSummary["routeDecision"]>["requestFrame"],
): string | null {
  if (!frame) return null;
  switch (frame.kind) {
    case "weather":
      return [
        frame.inferredLocations[0],
        frame.assumedLocation,
        frame.temporalScope,
      ]
        .filter(Boolean)
        .join(" · ") || null;
    case "sports":
      return [frame.league, frame.teamOrTarget, frame.dataScope]
        .filter(Boolean)
        .join(" · ") || null;
    case "places":
      return [frame.category, frame.locationScope || frame.searchAnchor]
        .filter(Boolean)
        .join(" · ") || null;
    case "recipe":
      return [frame.dish, frame.servings ? `${frame.servings} servings` : null]
        .filter(Boolean)
        .join(" · ") || null;
    case "message_compose":
      return [frame.channel, frame.purpose, frame.recipientContext]
        .filter(Boolean)
        .join(" · ") || null;
    case "user_input":
      return [
        frame.interactionKind,
        frame.explicitOptionsPresent ? "explicit options" : null,
      ]
        .filter(Boolean)
        .join(" · ") || null;
    default:
      return null;
  }
}

function transitionLabel(
  transition: NonNullable<PlanSummary["routeDecision"]>["laneTransitions"][number],
): string {
  const from = transition.fromLane ? laneLabel(transition.fromLane) : "Entry";
  return `${from} -> ${laneLabel(transition.toLane)}`;
}

function fallbackSkillLabel(skill: PlanSelectedSkill): string {
  const label = skill.label.trim();
  if (label) {
    return label;
  }

  const id = skill.id.trim();
  if (!id) {
    return "Prepared skill";
  }

  return id.replace(/[_-]+/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function capabilitySkillSummary(
  entry: CapabilityRegistryEntry | null,
  skill: PlanSelectedSkill,
): string {
  if (entry) {
    return entry.whySelectable;
  }

  return `Capability registry details are not attached yet for ${fallbackSkillLabel(skill)}.`;
}

function capabilitySkillMeta(
  entry: CapabilityRegistryEntry | null,
  skill: PlanSelectedSkill,
): string[] {
  if (entry) {
    return [
      entry.authority.tierLabel,
      entry.lease.modeLabel ?? entry.lease.availabilityLabel,
      entry.sourceLabel,
    ].filter(Boolean);
  }

  return [skill.id];
}

export function ExecutionRouteCard({
  summary,
  currentStep,
  traceDetail,
  onOpenArtifacts,
  preferCompactDirectInline = false,
}: ExecutionRouteCardProps) {
  const currentStage = currentStep?.trim() || summary.currentStage;
  const { entryLookup } = useChatCapabilityRegistry(
    summary.selectedSkills.length > 0,
  );
  const preparedSkills = useMemo(
    () =>
      summary.selectedSkills.map((skill) => ({
        skill,
        registryEntry:
          entryLookup.get(skill.entryId) ??
          entryLookup.get(`skill:${skill.id}`) ??
          null,
      })),
    [entryLookup, summary.selectedSkills],
  );
  const compactDirectInline =
    preferCompactDirectInline &&
    summary.routeFamily === "general" &&
    summary.routeDecision?.outputIntent === "direct_inline" &&
    summary.selectedSkills.length === 0 &&
    !summary.artifactGeneration &&
    !summary.computerUsePerception;

  if (compactDirectInline) {
    return (
      <section
        className="spot-execution-card"
        aria-label="Execution route summary"
      >
        <div className="spot-execution-card-header">
          <div className="spot-execution-card-copy">
            <span className="spot-execution-card-kicker">Direct inline route</span>
            <strong>{summary.selectedRoute}</strong>
            <p>
              {summary.routeDecision?.directAnswerAllowed
                ? "Direct answer stayed in the main lane."
                : "The runtime kept this answer inline."}
            </p>
          </div>
          <span className="spot-execution-card-status">
            {statusLabel(summary.status)}
          </span>
        </div>

        {onOpenArtifacts && (
          <div className="spot-execution-card-actions">
            <div className="spot-execution-card-actions-copy">
              <span>Evidence and raw trace</span>
              <p>
                {traceDetail ||
                  `${summary.evidenceCount} ${
                    summary.evidenceCount === 1 ? "step" : "steps"
                  } captured.`}
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
      </section>
    );
  }

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

      {summary.routeDecision && (
        <div className="spot-execution-card-prep">
          <div className="spot-execution-card-prep-copy">
            <span>Runtime route</span>
            <p>
              Output: {outputIntentLabel(summary.routeDecision.outputIntent)}.
              {" "}
              Direct answer:{" "}
              {summary.routeDecision.directAnswerAllowed ? "Allowed" : "Blocked"}.
            </p>
            {(summary.routeDecision.selectedProviderFamily ||
              summary.routeDecision.currentnessOverride ||
              summary.routeDecision.skillPrepRequired) && (
              <p>
                {summary.routeDecision.selectedProviderFamily
                  ? `Preferred provider: ${providerLabel(
                      summary.routeDecision.selectedProviderFamily,
                    )}. `
                  : ""}
                {summary.routeDecision.currentnessOverride
                  ? "Fresh/current data was required. "
                  : ""}
                {summary.routeDecision.skillPrepRequired
                  ? "Conditional guidance prep was part of the route."
                  : ""}
              </p>
            )}
          </div>
          {(summary.routeDecision.directAnswerBlockers.length > 0 ||
            summary.routeDecision.effectiveToolSurface.projectedTools.length > 0) && (
            <>
              {summary.routeDecision.directAnswerBlockers.length > 0 && (
                <div className="spot-execution-card-policy">
                  {summary.routeDecision.directAnswerBlockers.map((blocker) => (
                    <span
                      key={`route-blocker-${blocker}`}
                      className="spot-execution-card-policy-chip"
                    >
                      {routeBlockerLabel(blocker)}
                    </span>
                  ))}
                </div>
              )}
              {summary.routeDecision.effectiveToolSurface.projectedTools.length > 0 && (
                <div className="spot-execution-card-capability-list">
                  <article className="spot-execution-card-capability">
                    <div className="spot-execution-card-capability-head">
                      <div className="spot-execution-card-capability-copy">
                        <strong>Projected tool surface</strong>
                        <span>
                          {summary.routeDecision.effectiveToolSurface.primaryTools.length} primary
                          {" · "}
                          {summary.routeDecision.effectiveToolSurface.broadFallbackTools.length} fallback
                        </span>
                      </div>
                      <span className="spot-execution-card-capability-badge">
                        {summary.routeDecision.connectorFirstPreference
                          ? "Connector-first"
                          : summary.routeDecision.narrowToolPreference
                            ? "Narrow-tool"
                            : "General"}
                      </span>
                    </div>
                    <div className="spot-execution-card-policy">
                      {summary.routeDecision.effectiveToolSurface.projectedTools
                        .slice(0, 6)
                        .map((tool) => (
                          <span
                            key={`projected-tool-${tool}`}
                            className="spot-execution-card-policy-chip"
                          >
                            {tool}
                          </span>
                        ))}
                    </div>
                  </article>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {summary.routeDecision &&
        (summary.routeDecision.laneFrame ||
          summary.routeDecision.requestFrame ||
          summary.routeDecision.sourceSelection ||
          summary.routeDecision.retainedLaneState ||
          summary.routeDecision.laneTransitions.length > 0 ||
          summary.routeDecision.orchestrationState ||
          summary.routeDecision.domainPolicyBundle) && (
          <div className="spot-execution-card-prep">
            <div className="spot-execution-card-prep-copy">
              <span>Domain topology</span>
              {summary.routeDecision.laneFrame && (
                <>
                  <p>
                    Primary lane:{" "}
                    {laneLabel(summary.routeDecision.laneFrame.primaryLane)}.
                    {" "}
                    {summary.routeDecision.laneFrame.primaryGoal}
                  </p>
                  {(summary.routeDecision.laneFrame.toolWidgetFamily ||
                    summary.routeDecision.laneFrame.currentnessPressure ||
                    summary.routeDecision.laneFrame.workspaceGroundingRequired) && (
                    <p>
                      {summary.routeDecision.laneFrame.toolWidgetFamily
                        ? `Tool family: ${providerLabel(
                            summary.routeDecision.laneFrame.toolWidgetFamily,
                          )}. `
                        : ""}
                      {summary.routeDecision.laneFrame.currentnessPressure
                        ? "Fresh/current context shaped the lane. "
                        : ""}
                      {summary.routeDecision.laneFrame.workspaceGroundingRequired
                        ? "Workspace grounding stayed in scope."
                        : ""}
                    </p>
                  )}
                </>
              )}
              {summary.routeDecision.requestFrame && (
                <p>
                  Request frame:{" "}
                  {requestFrameLabel(summary.routeDecision.requestFrame)}
                  {requestFrameSummary(summary.routeDecision.requestFrame)
                    ? ` · ${requestFrameSummary(summary.routeDecision.requestFrame)}.`
                    : "."}
                </p>
              )}
              {summary.routeDecision.sourceSelection && (
                <p>
                  Selected source:{" "}
                  {sourceFamilyLabel(
                    summary.routeDecision.sourceSelection.selectedSource,
                  )}
                  {summary.routeDecision.sourceSelection.fallbackReason
                    ? `. ${summary.routeDecision.sourceSelection.fallbackReason}`
                    : "."}
                </p>
              )}
            </div>

            {(summary.routeDecision.laneFrame?.secondaryLanes.length ||
              summary.routeDecision.sourceSelection?.candidateSources.length ||
              summary.routeDecision.requestFrame?.missingSlots.length) && (
              <div className="spot-execution-card-policy">
                {summary.routeDecision.laneFrame?.secondaryLanes
                  .slice(0, 3)
                  .map((lane) => (
                    <span
                      key={`secondary-lane-${lane}`}
                      className="spot-execution-card-policy-chip"
                    >
                      {laneLabel(lane)} assist
                    </span>
                  ))}
                {summary.routeDecision.sourceSelection?.candidateSources
                  .slice(0, 3)
                  .map((source) => (
                    <span
                      key={`candidate-source-${source}`}
                      className="spot-execution-card-policy-chip"
                    >
                      {sourceFamilyLabel(source)}
                    </span>
                  ))}
                {summary.routeDecision.requestFrame?.missingSlots
                  .slice(0, 2)
                  .map((slot) => (
                    <span
                      key={`missing-slot-${slot}`}
                      className="spot-execution-card-policy-chip"
                    >
                      Missing: {providerLabel(slot)}
                    </span>
                  ))}
              </div>
            )}

            {(summary.routeDecision.retainedLaneState ||
              summary.routeDecision.laneTransitions.length > 0 ||
              summary.routeDecision.orchestrationState ||
              summary.routeDecision.domainPolicyBundle) && (
              <div className="spot-execution-card-capability-list">
                {summary.routeDecision.retainedLaneState && (
                  <article className="spot-execution-card-capability">
                    <div className="spot-execution-card-capability-head">
                      <div className="spot-execution-card-capability-copy">
                        <strong>Retained lane state</strong>
                        <span>
                          Active lane:{" "}
                          {laneLabel(
                            summary.routeDecision.retainedLaneState.activeLane,
                          )}
                        </span>
                      </div>
                      <span className="spot-execution-card-capability-badge">
                        {summary.routeDecision.retainedLaneState
                          .selectedProviderFamily
                          ? providerLabel(
                              summary.routeDecision.retainedLaneState
                                .selectedProviderFamily,
                            )
                          : "Stateful"}
                      </span>
                    </div>
                    <div className="spot-execution-card-policy">
                      {summary.routeDecision.retainedLaneState
                        .selectedSourceFamily && (
                        <span className="spot-execution-card-policy-chip">
                          {sourceFamilyLabel(
                            summary.routeDecision.retainedLaneState
                              .selectedSourceFamily,
                          )}
                        </span>
                      )}
                      {summary.routeDecision.retainedLaneState
                        .activeToolWidgetFamily && (
                        <span className="spot-execution-card-policy-chip">
                          {providerLabel(
                            summary.routeDecision.retainedLaneState
                              .activeToolWidgetFamily,
                          )}
                        </span>
                      )}
                      {summary.routeDecision.retainedLaneState
                        .unresolvedClarificationQuestion && (
                        <span className="spot-execution-card-policy-chip">
                          Clarification open
                        </span>
                      )}
                    </div>
                  </article>
                )}
                {summary.routeDecision.laneTransitions.length > 0 && (
                  <article className="spot-execution-card-capability">
                    <div className="spot-execution-card-capability-head">
                      <div className="spot-execution-card-capability-copy">
                        <strong>Lane transitions</strong>
                        <span>
                          {summary.routeDecision.laneTransitions.length} retained
                        </span>
                      </div>
                      <span className="spot-execution-card-capability-badge">
                        Transition map
                      </span>
                    </div>
                    <div className="spot-execution-card-policy">
                      {summary.routeDecision.laneTransitions
                        .slice(0, 3)
                        .map((transition) => (
                          <span
                            key={`${transition.transitionKind}-${transition.toLane}-${transition.reason}`}
                            className="spot-execution-card-policy-chip"
                          >
                            {transitionLabel(transition)}
                          </span>
                        ))}
                    </div>
                  </article>
                )}
                {summary.routeDecision.orchestrationState && (
                  <article className="spot-execution-card-capability">
                    <div className="spot-execution-card-capability-head">
                      <div className="spot-execution-card-capability-copy">
                        <strong>
                          {summary.routeDecision.orchestrationState.objective
                            ?.title || "Orchestration state"}
                        </strong>
                        <span>
                          {summary.routeDecision.orchestrationState.tasks.length} tasks
                          {" · "}
                          {summary.routeDecision.orchestrationState.checkpoints.length} checkpoints
                        </span>
                      </div>
                      <span className="spot-execution-card-capability-badge">
                        {summary.routeDecision.orchestrationState
                          .completionInvariant?.satisfied
                          ? "Invariant met"
                          : "Active"}
                      </span>
                    </div>
                    <div className="spot-execution-card-policy">
                      {summary.routeDecision.orchestrationState.tasks
                        .slice(0, 3)
                        .map((task) => (
                          <span
                            key={`orchestration-task-${task.taskId}`}
                            className="spot-execution-card-policy-chip"
                          >
                            {providerLabel(task.status)}: {task.label}
                          </span>
                        ))}
                    </div>
                  </article>
                )}
                {summary.routeDecision.domainPolicyBundle && (
                  <article className="spot-execution-card-capability">
                    <div className="spot-execution-card-capability-head">
                      <div className="spot-execution-card-capability-copy">
                        <strong>Domain policy bundle</strong>
                        <span>
                          {summary.routeDecision.domainPolicyBundle.sourceRanking.length} ranked sources
                          {" · "}
                          {summary.routeDecision.domainPolicyBundle.verificationContract
                            ?.strategy || "policy receipts"}
                        </span>
                      </div>
                      <span className="spot-execution-card-capability-badge">
                        {summary.routeDecision.domainPolicyBundle.presentationPolicy
                          ?.primarySurface
                          ? providerLabel(
                              summary.routeDecision.domainPolicyBundle.presentationPolicy
                                .primarySurface,
                            )
                          : "Typed policy"}
                      </span>
                    </div>
                    <div className="spot-execution-card-policy">
                      {summary.routeDecision.domainPolicyBundle.clarificationPolicy && (
                        <span className="spot-execution-card-policy-chip">
                          Clarify: {providerLabel(
                            summary.routeDecision.domainPolicyBundle.clarificationPolicy.mode,
                          )}
                        </span>
                      )}
                      {summary.routeDecision.domainPolicyBundle.fallbackPolicy && (
                        <span className="spot-execution-card-policy-chip">
                          Fallback: {providerLabel(
                            summary.routeDecision.domainPolicyBundle.fallbackPolicy.mode,
                          )}
                        </span>
                      )}
                      {summary.routeDecision.domainPolicyBundle.riskProfile && (
                        <span className="spot-execution-card-policy-chip">
                          Risk: {providerLabel(
                            summary.routeDecision.domainPolicyBundle.riskProfile.sensitivity,
                          )}
                        </span>
                      )}
                      {summary.routeDecision.domainPolicyBundle.retainedWidgetState
                        ?.widgetFamily && (
                        <span className="spot-execution-card-policy-chip">
                          Retained widget: {providerLabel(
                            summary.routeDecision.domainPolicyBundle.retainedWidgetState
                              .widgetFamily,
                          )}
                        </span>
                      )}
                    </div>
                    <div className="spot-execution-card-prep-copy">
                      {summary.routeDecision.domainPolicyBundle.presentationPolicy && (
                        <p>
                          Presentation:{" "}
                          {providerLabel(
                            summary.routeDecision.domainPolicyBundle.presentationPolicy
                              .primarySurface,
                          )}
                          {summary.routeDecision.domainPolicyBundle.presentationPolicy
                            .renderer
                            ? ` via ${providerLabel(
                                summary.routeDecision.domainPolicyBundle.presentationPolicy
                                  .renderer,
                              )}.`
                            : "."}
                        </p>
                      )}
                      {summary.routeDecision.domainPolicyBundle.transformationPolicy && (
                        <p>
                          Transformation:{" "}
                          {
                            summary.routeDecision.domainPolicyBundle.transformationPolicy
                              .outputShape
                          }
                          .
                        </p>
                      )}
                      {summary.routeDecision.domainPolicyBundle.policyContract && (
                        <p>
                          Policy contract:{" "}
                          {summary.routeDecision.domainPolicyBundle.policyContract
                            .hiddenInstructionDependency
                            ? "still depends on hidden instructions."
                            : "retained in typed bindings."}
                        </p>
                      )}
                    </div>
                  </article>
                )}
              </div>
            )}
          </div>
        )}

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
            <span>
              {summary.selectedSkills.length > 0 ? "Skill guidance" : "Prepared context"}
            </span>
            {summary.prepSummary && <p>{summary.prepSummary}</p>}
          </div>
          {summary.selectedSkills.length > 0 && (
            <>
              <div className="spot-execution-card-policy">
                {preparedSkills.slice(0, 4).map(({ skill, registryEntry }) => (
                  <span
                    key={skill.entryId}
                    className="spot-execution-card-policy-chip"
                  >
                    {registryEntry?.label ?? fallbackSkillLabel(skill)}
                  </span>
                ))}
              </div>
              <div className="spot-execution-card-capability-list">
                {preparedSkills.slice(0, 2).map(({ skill, registryEntry }) => (
                  <article
                    key={`${skill.entryId}-detail`}
                    className="spot-execution-card-capability"
                  >
                    <div className="spot-execution-card-capability-head">
                      <div className="spot-execution-card-capability-copy">
                        <strong>
                          {registryEntry?.label ?? fallbackSkillLabel(skill)}
                        </strong>
                        <span>{capabilitySkillSummary(registryEntry, skill)}</span>
                      </div>
                      <span className="spot-execution-card-capability-badge">
                        {registryEntry?.authority.tierLabel ?? "Registry pending"}
                      </span>
                    </div>
                    <div className="spot-execution-card-policy">
                      {capabilitySkillMeta(registryEntry, skill).map((item) => (
                        <span
                          key={`${skill.entryId}-${item}`}
                          className="spot-execution-card-policy-chip"
                        >
                          {item}
                        </span>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            </>
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
