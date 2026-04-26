import React from "react";
import type {
  AgentTask,
  ArtifactHubViewKey,
  LocalEngineSnapshot,
  RunPresentation,
  SourceSummary,
} from "../../../types";
import type { ConversationTurn, TurnContext } from "../hooks/useTurnContexts";
import { normalizeVisualHash } from "../utils/visualHash";
import { AnswerCard } from "./AnswerCard";
import {
  artifactReplyText,
  artifactTurnMetaLabel,
  compactArtifactClassLabel,
  compactRendererLabel,
  inlineAnswerText,
  operatorRunIsPending,
} from "./ConversationTimeline.helpers";
import { ExecutionMomentList } from "./ExecutionMomentList";
import { ExecutionRouteCard } from "./ExecutionRouteCard";
import { MarkdownMessage } from "./MarkdownMessage";
import { ReasoningDisclosure } from "./ReasoningDisclosure";
import { RuntimeFactsStrip } from "./RuntimeFactsStrip";
import { SourceChipRow } from "./SourceChipRow";
import { ToolActivityGroup } from "./ToolActivityGroup";
import { VisualEvidenceCard } from "./VisualEvidenceCard";

type ConversationTimelineProps = {
  conversationTurns: ConversationTurn[];
  latestAnsweredTurnIndex: number;
  turnContexts: TurnContext[];
  runPresentation: RunPresentation;
  task?: AgentTask | null;
  runtimeModelLabel?: string | null;
  localEngineSnapshot?: LocalEngineSnapshot | null;
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
  activeChatArtifactSessionId?: string | null;
  onOpenChatArtifact?: (chatSessionId: string) => void;
  inlineStatusCard?: React.ReactNode;
};

export function ConversationTimeline({
  conversationTurns,
  latestAnsweredTurnIndex,
  turnContexts,
  runPresentation,
  task = null,
  runtimeModelLabel = null,
  localEngineSnapshot = null,
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
  activeChatArtifactSessionId = null,
  onOpenChatArtifact,
  inlineStatusCard,
}: ConversationTimelineProps) {
  const normalizePendingReplyDetail = (
    detail: string | undefined,
    running: boolean,
  ) => {
    const fallback = running
      ? "Thinking through the request."
      : "Runtime timeline is initializing.";

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
        const hasPendingArtifact =
          turnContext?.hasPendingArtifact || false;
        const hasPendingOperatorRun = operatorRunIsPending(turnContext);
        const latestAnswerMatches =
          isLatestAnsweredTurn &&
          !!turn.answer &&
          !!runPresentation.finalAnswer;
        const showPendingRunAnswer =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          !hasPendingArtifact &&
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
        const runtimeFacts = (
          <RuntimeFactsStrip
            task={task}
            planSummary={turnPlanSummary}
            runtimeModelLabel={runtimeModelLabel}
            localEngineSnapshot={localEngineSnapshot}
            onOpenEvidence={() =>
              onOpenArtifactHub(
                turnContext?.defaultView || "active_context",
                turnContext?.turnId || null,
              )
            }
            compact
          />
        );
        const effectiveInlineAnswer =
          showInlineTranscript && inlineArtifactReply
            ? inlineArtifactReply
            : latestAnswerMatches && runPresentation.finalAnswer
              ? inlineAnswerText(runPresentation.finalAnswer)
              : turn.answer?.text || null;
        const showArtifactReplyBubble =
          !turn.answer &&
          !!inlineArtifactReply &&
          !hasPendingArtifact &&
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
              <div className="spot-message agent spot-message--chat-status">
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
            !hasPendingArtifact ? (
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
                    {showLiveThinking ? "Thinking" : "Runtime timeline"}
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
                    runtimeFacts={runtimeFacts}
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
                  runtimeFacts={runtimeFacts}
                />
              ))}

            {turnContext &&
            turnContext.artifacts.length > 0 &&
            onOpenChatArtifact ? (
              showInlineTranscript ? (
                <div
                  className="spot-inline-artifact-actions"
                  aria-label="Artifact actions"
                >
                  {turnContext.artifacts.map((artifact) => {
                    const active =
                      artifact.sessionId === activeChatArtifactSessionId;
                    return (
                      <button
                        key={artifact.key}
                        type="button"
                        className={`spot-inline-artifact-chip ${
                          active ? "is-active" : ""
                        }`}
                        onClick={() => onOpenChatArtifact(artifact.sessionId)}
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
                        artifact.sessionId === activeChatArtifactSessionId;
                      return (
                        <button
                          key={artifact.key}
                          type="button"
                          className={`spot-conversation-artifact-card ${
                            active ? "is-active" : ""
                          }`}
                          onClick={() =>
                            onOpenChatArtifact(artifact.sessionId)
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
          runtimeFacts={
            <RuntimeFactsStrip
              task={task}
              planSummary={runPresentation.planSummary}
              runtimeModelLabel={runtimeModelLabel}
              localEngineSnapshot={localEngineSnapshot}
              onOpenEvidence={() => onOpenArtifactHub("active_context")}
              compact
            />
          }
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
