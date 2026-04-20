import React from "react";
import type {
  ArtifactHubViewKey,
  RunPresentation,
  SourceSummary,
} from "../../../types";
import type { ConversationTurn, TurnContext } from "../hooks/useTurnContexts";
import { normalizeVisualHash } from "../utils/visualHash";
import { AnswerCard } from "./AnswerCard";
import { ExecutionMomentList } from "./ExecutionMomentList";
import { ExecutionRouteCard } from "./ExecutionRouteCard";
import { MarkdownMessage } from "./MarkdownMessage";
import { ReasoningDisclosure } from "./ReasoningDisclosure";
import { SourceChipRow } from "./SourceChipRow";
import { ToolActivityGroup } from "./ToolActivityGroup";
import { VisualEvidenceCard } from "./VisualEvidenceCard";

function formatLifecycleLabel(value: string | null | undefined): string {
  if (!value) {
    return "Pending";
  }

  return value
    .split(/[-_]+/g)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

type ConversationTimelineProps = {
  conversationTurns: ConversationTurn[];
  latestAnsweredTurnIndex: number;
  turnContexts: TurnContext[];
  runPresentation: RunPresentation;
  isRunning: boolean;
  currentStep?: string;
  visualHash?: string | null;
  sourceDurationLabel?: string;
  showInitialLoader: boolean;
  suppressPendingIndicators?: boolean;
  icons: {
    artifacts: React.ReactNode;
    sparkles: React.ReactNode;
  };
  onExportTraceBundle: () => Promise<void> | void;
  onOpenArtifactHub: (
    preferredView?: ArtifactHubViewKey,
    preferredTurnId?: string | null,
  ) => void;
  onOpenSourceSummary: (summary: SourceSummary) => void;
  activeStudioArtifactSessionId?: string | null;
  onOpenStudioArtifact?: (studioSessionId: string) => void;
  inlineStatusCard?: React.ReactNode;
};

function compactArtifactClassLabel(value: string): string {
  switch (value) {
    case "workspace_project":
    case "interactive_single_file":
    case "code_patch":
      return "Code";
    case "document":
      return "Document";
    case "visual":
      return "Visual";
    case "downloadable_file":
      return "File";
    case "compound_bundle":
    case "report_bundle":
      return "Bundle";
    default:
      return "Artifact";
  }
}

function compactRendererLabel(value: string): string {
  switch (value) {
    case "html_iframe":
      return "HTML";
    case "jsx_sandbox":
      return "JSX";
    case "workspace_surface":
      return "Workspace";
    case "bundle_manifest":
      return "Bundle";
    case "download_card":
      return "Download";
    case "pdf_embed":
      return "PDF";
    default:
      return value
        .replace(/[_-]+/g, " ")
        .replace(/\b\w/g, (character) => character.toUpperCase());
  }
}

function preferredSourceLabels(sourceSummary: SourceSummary | null): string[] {
  if (!sourceSummary) {
    return [];
  }

  const seen = new Set<string>();
  const labels: string[] = [];
  const push = (value: string | null | undefined) => {
    const compact = String(value || "").replace(/\s+/g, " ").trim();
    if (!compact) {
      return;
    }
    const key = compact.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    labels.push(compact);
  };

  for (const browse of sourceSummary.browses) {
    const title = browse.title?.trim() || "";
    const titleSuffix = title.split(" - ").at(-1)?.trim() || "";
    push(titleSuffix && titleSuffix.length <= 48 ? titleSuffix : null);
    push(
      browse.domain
        .replace(/^www\./i, "")
        .replace(/^science\./i, "")
        .replace(/^news\./i, ""),
    );
    if (labels.length >= 3) {
      break;
    }
  }

  if (labels.length < 3) {
    for (const domain of sourceSummary.domains) {
      push(
        domain.domain
          .replace(/^www\./i, "")
          .replace(/^science\./i, "")
          .replace(/^news\./i, ""),
      );
      if (labels.length >= 3) {
        break;
      }
    }
  }

  return labels.slice(0, 3);
}

function joinLabels(labels: string[]): string | null {
  if (labels.length === 0) {
    return null;
  }
  if (labels.length === 1) {
    return labels[0] || null;
  }
  if (labels.length === 2) {
    return `${labels[0]} and ${labels[1]}`;
  }
  return `${labels[0]}, ${labels[1]}, and ${labels[2]}`;
}

function artifactSummaryLooksOperational(summary: string): boolean {
  const normalized = summary.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  return (
    normalized.includes("studio materialized")
    || normalized.includes("final acceptance validation")
    || normalized.includes("primary artifact view")
    || normalized.includes("lifecycle")
    || normalized.includes("verification cleared")
    || normalized.includes("candidate-")
    || normalized.includes("artifact view")
  );
}

export function artifactReplyText(turnContext: TurnContext | null): string | null {
  if (
    !turnContext ||
    turnContext.hasPendingStudioArtifact ||
    turnContext.artifacts.length === 0
  ) {
    return null;
  }

  if (turnContext.artifacts.length === 1) {
    const artifact = turnContext.artifacts[0];
    if (!artifact) {
      return null;
    }
    const rawSummary =
      artifact.studioSession.verifiedReply.summary.trim() ||
      artifact.summary.trim();
    const summary = artifactSummaryLooksOperational(rawSummary) ? "" : rawSummary;
    const lifecycleState = String(artifact.lifecycleState || "")
      .trim()
      .toLowerCase();
    const failedLifecycle =
      lifecycleState === "blocked" || lifecycleState === "failed";

    if (failedLifecycle) {
      return summary.length > 0
        ? `I wasn’t able to land **${artifact.title}**. ${summary}`
        : `I wasn’t able to land **${artifact.title}**. Inspect the blocked artifact card below for details.`;
    }

    const sourceAttribution = joinLabels(preferredSourceLabels(turnContext.sourceSummary));
    if (summary.length > 0 && sourceAttribution) {
      return `I put together **${artifact.title}**. ${summary} It’s grounded in ${sourceAttribution}.`;
    }
    if (summary.length > 0) {
      return `I put together **${artifact.title}**. ${summary}`;
    }
    if (sourceAttribution) {
      return `I put together **${artifact.title}** and grounded it in ${sourceAttribution}.`;
    }
    return `I put together **${artifact.title}**. It’s ready in the artifact card below.`;
  }

  const failedArtifacts = turnContext.artifacts.filter((artifact) => {
    const lifecycleState = String(artifact.lifecycleState || "")
      .trim()
      .toLowerCase();
    return lifecycleState === "blocked" || lifecycleState === "failed";
  });
  if (failedArtifacts.length === turnContext.artifacts.length) {
    const previewTitles = failedArtifacts
      .slice(0, 3)
      .map((artifact) => `**${artifact.title}**`)
      .join(", ");
    const overflowCount =
      failedArtifacts.length - Math.min(failedArtifacts.length, 3);
    const overflowSuffix =
      overflowCount > 0 ? `, and ${overflowCount} more` : "";
    return `I wasn’t able to finish the requested artifacts: ${previewTitles}${overflowSuffix}. Inspect the artifact cards below for failure details.`;
  }

  const previewTitles = turnContext.artifacts
    .slice(0, 3)
    .map((artifact) => `**${artifact.title}**`)
    .join(", ");
  const overflowCount =
    turnContext.artifacts.length - Math.min(turnContext.artifacts.length, 3);
  const overflowSuffix = overflowCount > 0 ? `, and ${overflowCount} more` : "";

  return `I created ${turnContext.artifacts.length} artifacts for this request: ${previewTitles}${overflowSuffix}. Open one from the cards below.`;
}

function operatorRunIsPending(turnContext: TurnContext | null): boolean {
  const status = turnContext?.studioSession?.activeOperatorRun?.status;
  const normalized = String(status || "")
    .trim()
    .toLowerCase();
  return (
    normalized === "active"
    || normalized === "pending"
    || normalized === "other"
  );
}

function artifactTurnMetaLabel(
  artifact: NonNullable<TurnContext>["artifacts"][number],
): string {
  const lifecycleLabel = formatLifecycleLabel(
    artifact.lifecycleState || artifact.status,
  );
  const fileCountLabel = `${artifact.fileCount} ${
    artifact.fileCount === 1 ? "file" : "files"
  }`;
  const lifecycleState = String(artifact.lifecycleState || "")
    .trim()
    .toLowerCase();

  if (lifecycleState === "blocked" || lifecycleState === "failed") {
    return `${lifecycleLabel} · ${fileCountLabel}`;
  }

  return fileCountLabel;
}

function inlineAnswerText(
  answer: NonNullable<RunPresentation["finalAnswer"]>,
): string {
  const display = answer.displayText.trim();
  if (display.length > 0) {
    return display;
  }
  return answer.message.text;
}

export function ConversationTimeline({
  conversationTurns,
  latestAnsweredTurnIndex,
  turnContexts,
  runPresentation,
  isRunning,
  currentStep,
  visualHash,
  sourceDurationLabel,
  showInitialLoader,
  suppressPendingIndicators = false,
  icons,
  onExportTraceBundle,
  onOpenArtifactHub,
  onOpenSourceSummary,
  activeStudioArtifactSessionId = null,
  onOpenStudioArtifact,
  inlineStatusCard,
}: ConversationTimelineProps) {
  const normalizePendingReplyDetail = (
    detail: string | undefined,
    running: boolean,
  ) => {
    const fallback = running
      ? "Thinking through the request."
      : "Preparing a conversational reply.";

    if (!detail) {
      return fallback;
    }

    const trimmed = detail.trim();
    const normalized = trimmed.toLowerCase();
    if (
      normalized.includes("routed this request to") ||
      normalized.includes("shared execution lane") ||
      normalized.includes("artifact renderer was invoked") ||
      normalized.includes("route ready")
    ) {
      return fallback;
    }

    return trimmed;
  };

  return (
    <>
      {conversationTurns.map((turn, index) => {
        const isLatestTurn = index === conversationTurns.length - 1;
        const isLatestAnsweredTurn = index === latestAnsweredTurnIndex;
        const turnContext = turnContexts[index] || null;
        const turnPlanSummary =
          turnContext?.planSummary ||
          (isLatestTurn ? runPresentation.planSummary : null);
        const hasPendingStudioArtifact =
          turnContext?.hasPendingStudioArtifact || false;
        const hasPendingOperatorRun = operatorRunIsPending(turnContext);
        const latestAnswerMatches =
          isLatestAnsweredTurn &&
          !!turn.answer &&
          !!runPresentation.finalAnswer;
        const showPendingRunAnswer =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          !hasPendingStudioArtifact &&
          !hasPendingOperatorRun &&
          !!runPresentation.finalAnswer &&
          runPresentation.finalAnswer.message.timestamp >=
            turn.prompt.timestamp;
        const hasThoughtSummary = !!runPresentation.thoughtSummary;
        const hasPlanSummary = !!turnPlanSummary;
        const toolActivityGroup = turnContext?.toolActivityGroup || null;
        const turnSourceSummary =
          turnContext?.sourceSummary ||
          (latestAnswerMatches ? runPresentation.sourceSummary : null);
        const inlineTranscriptRoute =
          toolActivityGroup?.presentation === "inline_transcript";
        const showInlineTranscript = !!turn.prompt && inlineTranscriptRoute;
        const showLiveThinking =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          isRunning &&
          !suppressPendingIndicators;
        const showInlineStatusCard =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          !!inlineStatusCard &&
          !showInlineTranscript;
        const compactDirectInlineRoute =
          !!turnPlanSummary &&
          turnPlanSummary.routeFamily === "general" &&
          turnPlanSummary.routeDecision?.outputIntent === "direct_inline" &&
          turnPlanSummary.selectedSkills.length === 0 &&
          !turnPlanSummary.artifactGeneration &&
          !turnPlanSummary.computerUsePerception;
        const showExecutionRouteCard =
          !!turn.prompt &&
          hasPlanSummary &&
          !showLiveThinking &&
          !showInlineStatusCard &&
          !showInlineTranscript;
        const showAssistantPendingBubble =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          !showPendingRunAnswer &&
          !runPresentation.finalAnswer &&
          !showInlineTranscript &&
          !showExecutionRouteCard &&
          !showInlineStatusCard &&
          !suppressPendingIndicators;
        const showThoughtTrigger =
          !showExecutionRouteCard &&
          !showInlineStatusCard &&
          !showInlineTranscript &&
          !!turn.prompt &&
          (showLiveThinking || !!turn.answer);
        const thoughtCount = turnContext?.thoughtCount || 0;
        const visualReceiptCount = turnContext?.visualReceiptCount || 0;
        const liveVisualHash =
          isLatestTurn && showLiveThinking
            ? normalizeVisualHash(visualHash ?? "") || null
            : null;
        const inlineVisualHash =
          liveVisualHash || turnContext?.latestVisualHash || null;
        const showInlineVisualReceipt =
          !!inlineVisualHash ||
          (!!turnContext && turnContext.visualReceiptCount > 0);
        const hasTurnTrace =
          (turnContext?.kernelEventCount || 0) > 0 ||
          thoughtCount > 0 ||
          visualReceiptCount > 0;
        const traceDetail = showLiveThinking
          ? currentStep || "Reasoning across tools"
          : !hasTurnTrace
            ? "No trace captured"
            : thoughtCount > 0
              ? `${thoughtCount} ${thoughtCount === 1 ? "step" : "steps"} captured`
              : visualReceiptCount > 0
                ? `${visualReceiptCount} visual ${
                    visualReceiptCount === 1 ? "receipt" : "receipts"
                  } captured`
                : `${turnContext?.kernelEventCount || 0} events captured`;
        const worklogLabel = showLiveThinking ? "Working..." : "Worklog";
        const pendingReplyDetail = normalizePendingReplyDetail(
          currentStep,
          showLiveThinking,
        );
        const inlineArtifactReply = artifactReplyText(turnContext);
        const effectiveInlineAnswer =
          showInlineTranscript && inlineArtifactReply
            ? inlineArtifactReply
            : latestAnswerMatches && runPresentation.finalAnswer
              ? inlineAnswerText(runPresentation.finalAnswer)
              : turn.answer?.text || null;
        const showArtifactReplyBubble =
          !turn.answer &&
          !!inlineArtifactReply &&
          !hasPendingStudioArtifact &&
          !hasPendingOperatorRun &&
          !showPendingRunAnswer &&
          !showAssistantPendingBubble &&
          !showLiveThinking;

        return (
          <React.Fragment key={turn.key}>
            {turn.prompt && (
              <div className="spot-message user spot-message--prompt">
                <div className="message-content-text">{turn.prompt.text}</div>
              </div>
            )}

            {showInlineStatusCard && (
              <div className="spot-message agent spot-message--studio-status">
                {inlineStatusCard}
              </div>
            )}

            {showInlineTranscript && toolActivityGroup ? (
              <ToolActivityGroup group={toolActivityGroup} />
            ) : null}

            {showInlineTranscript &&
            turnContext?.reasoningDurationLabel &&
            turnContext.thoughtSummary &&
            !hasPendingOperatorRun &&
            !hasPendingStudioArtifact ? (
              <ReasoningDisclosure
                label={turnContext.reasoningDurationLabel}
                thoughtSummary={turnContext.thoughtSummary}
              />
            ) : null}

            {showExecutionRouteCard && turnPlanSummary && (
              <>
                <ExecutionRouteCard
                  summary={turnPlanSummary}
                  currentStep={showLiveThinking ? currentStep : undefined}
                  traceDetail={traceDetail}
                  preferCompactDirectInline
                  onOpenArtifacts={() =>
                    onOpenArtifactHub(
                      "active_context",
                      turnContext?.turnId || null,
                    )
                  }
                />
                {!compactDirectInlineRoute && (
                  <ExecutionMomentList
                    moments={turnContext?.executionMoments || []}
                  />
                )}
              </>
            )}

            {showAssistantPendingBubble && (
              <div
                className="spot-message agent spot-message--pending"
                aria-live="polite"
              >
                <div className="spot-message--pending-shell">
                  <span className="spot-message--pending-kicker">
                    <span className="spot-message--pending-dot" />
                    {showLiveThinking ? "Thinking" : "Preparing reply"}
                  </span>
                  <p>{pendingReplyDetail}</p>
                </div>
              </div>
            )}

            {showThoughtTrigger && (
              <button
                className={`spot-thinking-pill ${
                  showLiveThinking ? "spot-thinking-pill--active" : ""
                }`}
                type="button"
                onClick={() =>
                  onOpenArtifactHub(
                    turnContext?.defaultView ||
                      (hasThoughtSummary ? "thoughts" : "kernel_logs"),
                    turnContext?.turnId || null,
                  )
                }
                title="Open thinking artifacts"
              >
                <span className="spot-thinking-pill-icon">
                  {icons.sparkles}
                </span>
                <span className="spot-thinking-pill-text">{worklogLabel}</span>
                <span className="spot-thinking-pill-detail">{traceDetail}</span>
              </button>
            )}

            {showLiveThinking &&
              !showExecutionRouteCard &&
              !!turnContext?.streamPreview && (
                <div className="thought-stream-panel spot-inline-stream-panel">
                  <div className="thought-stream-header">
                    <span>{turnContext.streamLabel || "Terminal output"}</span>
                    <span>{turnContext.streamIsFinal ? "final" : "live"}</span>
                  </div>
                  <pre className="thought-stream-output">
                    {turnContext.streamPreview}
                  </pre>
                </div>
              )}

            {showInlineVisualReceipt && (
              <VisualEvidenceCard
                hash={inlineVisualHash || ""}
                timestamp={turnContext?.latestVisualTimestamp || null}
                stepIndex={turnContext?.latestVisualStepIndex || null}
                title={
                  showLiveThinking
                    ? "Live visual context"
                    : turnContext?.latestVisualHasBlob
                      ? "Captured visual context"
                      : "Captured screenshot receipt (metadata-only)"
                }
                compact={true}
                className="spot-inline-visual-evidence"
              />
            )}
            {showInlineVisualReceipt &&
              !inlineVisualHash &&
              !!turnContext?.latestVisualSummary && (
                <p className="spot-inline-visual-summary">
                  {turnContext.latestVisualSummary}
                </p>
              )}

            {turn.answer &&
              (latestAnswerMatches && runPresentation.finalAnswer ? (
                showInlineTranscript ? (
                  <>
                    <div className="spot-message agent spot-message--inline-answer">
                      <MarkdownMessage text={effectiveInlineAnswer || ""} />
                    </div>
                    <SourceChipRow
                      sourceSummary={turnSourceSummary}
                      onOpenSummary={onOpenSourceSummary}
                    />
                  </>
                ) : (
                  <AnswerCard
                    answer={runPresentation.finalAnswer}
                    sourceSummary={runPresentation.sourceSummary}
                    sourceDurationLabel={sourceDurationLabel}
                    onExportTraceBundle={onExportTraceBundle}
                    onOpenArtifacts={() =>
                      onOpenArtifactHub(
                        turnContext?.defaultView ||
                          (runPresentation.thoughtSummary
                            ? "thoughts"
                            : runPresentation.sourceSummary
                              ? "sources"
                              : "kernel_logs"),
                        turnContext?.turnId || null,
                      )
                    }
                    onOpenSources={onOpenSourceSummary}
                  />
                )
              ) : (
                <>
                  <div className="spot-message agent spot-message--inline-answer">
                    <MarkdownMessage text={effectiveInlineAnswer || turn.answer.text} />
                  </div>
                  {showInlineTranscript ? (
                    <SourceChipRow
                      sourceSummary={turnSourceSummary}
                      onOpenSummary={onOpenSourceSummary}
                    />
                  ) : null}
                </>
              ))}

            {showArtifactReplyBubble && inlineArtifactReply ? (
              <>
                <div className="spot-message agent spot-message--inline-answer">
                  <MarkdownMessage text={inlineArtifactReply} />
                </div>
                {showInlineTranscript ? (
                  <SourceChipRow
                    sourceSummary={turnSourceSummary}
                    onOpenSummary={onOpenSourceSummary}
                  />
                ) : null}
              </>
            ) : null}

            {!turn.answer &&
              showPendingRunAnswer &&
              runPresentation.finalAnswer &&
              (showInlineTranscript ? (
                <>
                  <div className="spot-message agent spot-message--inline-answer">
                    <MarkdownMessage text={inlineArtifactReply || inlineAnswerText(runPresentation.finalAnswer)} />
                  </div>
                  <SourceChipRow
                    sourceSummary={
                      turnSourceSummary || runPresentation.sourceSummary
                    }
                    onOpenSummary={onOpenSourceSummary}
                  />
                </>
              ) : (
                <AnswerCard
                  answer={runPresentation.finalAnswer}
                  sourceSummary={runPresentation.sourceSummary}
                  sourceDurationLabel={sourceDurationLabel}
                  onExportTraceBundle={onExportTraceBundle}
                  onOpenArtifacts={() =>
                    onOpenArtifactHub(
                      turnContext?.defaultView ||
                        (runPresentation.thoughtSummary
                          ? "thoughts"
                          : runPresentation.sourceSummary
                            ? "sources"
                            : "kernel_logs"),
                      turnContext?.turnId || null,
                    )
                  }
                  onOpenSources={onOpenSourceSummary}
                />
              ))}

            {turnContext &&
            turnContext.artifacts.length > 0 &&
            onOpenStudioArtifact ? (
              showInlineTranscript ? (
                <div
                  className="spot-inline-artifact-actions"
                  aria-label="Artifact actions"
                >
                  {turnContext.artifacts.map((artifact) => {
                    const active =
                      artifact.sessionId === activeStudioArtifactSessionId;
                    return (
                      <button
                        key={artifact.key}
                        type="button"
                        className={`spot-inline-artifact-chip ${
                          active ? "is-active" : ""
                        }`}
                        onClick={() => onOpenStudioArtifact(artifact.sessionId)}
                        aria-pressed={active}
                      >
                        <span aria-hidden="true">{icons.artifacts}</span>
                        <span>{artifact.title}</span>
                      </button>
                    );
                  })}
                </div>
              ) : (
                <section
                  className="spot-conversation-artifacts"
                  aria-label="Turn artifacts"
                >
                  <div className="spot-conversation-artifacts-head">
                    <span>Artifacts</span>
                    <small>
                      {turnContext.artifacts.length}{" "}
                      {turnContext.artifacts.length === 1
                        ? "artifact"
                        : "artifacts"}
                    </small>
                  </div>
                  <div className="spot-conversation-artifact-list">
                    {turnContext.artifacts.map((artifact) => {
                      const active =
                        artifact.sessionId === activeStudioArtifactSessionId;
                      return (
                        <button
                          key={artifact.key}
                          type="button"
                          className={`spot-conversation-artifact-card ${
                            active ? "is-active" : ""
                          }`}
                          onClick={() =>
                            onOpenStudioArtifact(artifact.sessionId)
                          }
                          aria-pressed={active}
                        >
                          <span
                            className="spot-conversation-artifact-icon"
                            aria-hidden="true"
                          >
                            {icons.artifacts}
                          </span>
                          <span className="spot-conversation-artifact-copy">
                            <strong>{artifact.title}</strong>
                            <span>
                              {compactArtifactClassLabel(
                                artifact.artifactClass,
                              )}{" "}
                              · {compactRendererLabel(artifact.renderer)}
                            </span>
                          </span>
                          <span className="spot-conversation-artifact-meta">
                            {artifactTurnMetaLabel(artifact)}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </section>
              )
            ) : null}
          </React.Fragment>
        );
      })}

      {conversationTurns.length === 0 && runPresentation.finalAnswer && (
        <AnswerCard
          answer={runPresentation.finalAnswer}
          sourceSummary={runPresentation.sourceSummary}
          sourceDurationLabel={sourceDurationLabel}
          onExportTraceBundle={onExportTraceBundle}
          onOpenArtifacts={() =>
            onOpenArtifactHub(
              runPresentation.thoughtSummary
                ? "thoughts"
                : runPresentation.sourceSummary
                  ? "sources"
                  : "kernel_logs",
            )
          }
          onOpenSources={onOpenSourceSummary}
        />
      )}

      {showInitialLoader && !suppressPendingIndicators && (
        <button
          className="spot-thinking-pill spot-thinking-pill--active"
          type="button"
          onClick={() =>
            onOpenArtifactHub(
              runPresentation.thoughtSummary ? "thoughts" : "kernel_logs",
            )
          }
          title="Open thinking artifacts"
        >
          <span className="spot-thinking-pill-icon">{icons.sparkles}</span>
          <span className="spot-thinking-pill-text">Working...</span>
          <span className="spot-thinking-pill-detail">
            {currentStep || "Initializing..."}
          </span>
        </button>
      )}
    </>
  );
}
