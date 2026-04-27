import React from "react";
import type {
  AgentTask,
  ArtifactHubViewKey,
  RunPresentation,
  SourceSummary,
} from "../../../types";
import type { ConversationTurn, TurnContext } from "../hooks/useTurnContexts";
import { normalizeVisualHash } from "../utils/visualHash";
import { buildAssistantTurnProcess } from "../utils/assistantTurnProcessModel";
import { extractUserRequestFromContextualIntent } from "../utils/contextualIntent";
import { operatorFacingCurrentStep } from "../viewmodels/runtimeStatusCopy";
import { AnswerCard } from "./AnswerCard";
import { AssistantTurn } from "./AssistantTurn";
import {
  artifactReplyText,
  artifactTurnMetaLabel,
  compactArtifactClassLabel,
  compactRendererLabel,
  inlineAnswerText,
  operatorRunIsPending,
} from "./ConversationTimeline.helpers";
import { MarkdownMessage } from "./MarkdownMessage";
import { ReasoningDisclosure } from "./ReasoningDisclosure";
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
  isRunning,
  visualHash,
  sourceDurationLabel,
  showInitialLoader,
  suppressPendingIndicators = false,
  icons,
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
      : "Getting the response ready.";

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
        const hasCompletedArtifact =
          !!turnContext &&
          turnContext.artifacts.length > 0 &&
          !hasPendingArtifact &&
          !hasPendingOperatorRun;
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
        const toolActivityGroup = turnContext?.toolActivityGroup || null;
        const turnSourceSummary =
          turnContext?.sourceSummary ||
          (latestAnswerMatches ? runPresentation.sourceSummary : null);
        const inlineTranscriptRoute =
          toolActivityGroup?.presentation === "inline_transcript";
        const showLiveThinking =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          isRunning &&
          !suppressPendingIndicators;
        const showInlineTranscript =
          !!turn.prompt && inlineTranscriptRoute && showLiveThinking;
        const showInlineStatusCard =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          !!inlineStatusCard &&
          !showInlineTranscript;
        const turnCurrentStep = operatorFacingCurrentStep(task, turnPlanSummary);
        const showAssistantPendingBubble =
          isLatestTurn &&
          !!turn.prompt &&
          !turn.answer &&
          !showPendingRunAnswer &&
          !runPresentation.finalAnswer &&
          !showInlineTranscript &&
          !showInlineStatusCard &&
          !hasCompletedArtifact &&
          !suppressPendingIndicators;
        const liveVisualHash =
          isLatestTurn && showLiveThinking
            ? normalizeVisualHash(visualHash ?? "") || null
            : null;
        const inlineVisualHash =
          liveVisualHash || turnContext?.latestVisualHash || null;
        const showInlineVisualReceipt =
          !!inlineVisualHash ||
          (!!turnContext && turnContext.visualReceiptCount > 0);
        const pendingReplyDetail = normalizePendingReplyDetail(
          turnCurrentStep || undefined,
          showLiveThinking,
        );
        const inlineArtifactReply = artifactReplyText(turnContext);
        const openTurnDetails = () =>
          onOpenArtifactHub(
            turnContext?.thoughtSummary
              ? "thoughts"
              : turnContext?.sourceSummary
                ? "sources"
                : "kernel_logs",
            turnContext?.turnId || null,
          );
        const assistantProcess = buildAssistantTurnProcess({
          task,
          planSummary: turnPlanSummary,
          runtimeModelLabel,
          sourceSummary: turnSourceSummary,
          thoughtSummary: turnContext?.thoughtSummary || null,
          toolActivityGroup,
          finalAnswer:
            latestAnswerMatches && runPresentation.finalAnswer
              ? runPresentation.finalAnswer
              : showPendingRunAnswer
                ? runPresentation.finalAnswer
                : null,
          isRunning: showLiveThinking,
          currentStep: turnCurrentStep,
        });
        const assistantTurnShell = (children: React.ReactNode) => (
          <AssistantTurn process={assistantProcess}>
            {children}
          </AssistantTurn>
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
                <div className="message-content-text">
                  {extractUserRequestFromContextualIntent(turn.prompt.text)}
                </div>
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

            {showAssistantPendingBubble && (
              <div
                className="spot-message agent spot-message--pending"
                aria-live="polite"
              >
                <div className="spot-message--pending-shell">
                  <span className="spot-message--pending-kicker">
                    <span className="spot-message--pending-dot" />
                    {showLiveThinking ? "Thinking" : "Working"}
                  </span>
                  <p>{pendingReplyDetail}</p>
                </div>
              </div>
            )}

            {showLiveThinking &&
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
                  assistantTurnShell(
                    <AnswerCard
                      answer={runPresentation.finalAnswer}
                      sourceSummary={null}
                      sourceDurationLabel={sourceDurationLabel}
                      onOpenArtifacts={openTurnDetails}
                      onOpenSources={onOpenSourceSummary}
                    />,
                  )
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
                assistantTurnShell(
                  <AnswerCard
                    answer={runPresentation.finalAnswer}
                    sourceSummary={null}
                    sourceDurationLabel={sourceDurationLabel}
                    onOpenArtifacts={openTurnDetails}
                    onOpenSources={onOpenSourceSummary}
                  />,
                )
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
        <AssistantTurn
          process={buildAssistantTurnProcess({
            task,
            planSummary: runPresentation.planSummary,
            runtimeModelLabel,
            sourceSummary: runPresentation.sourceSummary,
            thoughtSummary: runPresentation.thoughtSummary,
            finalAnswer: runPresentation.finalAnswer,
            isRunning,
            currentStep: operatorFacingCurrentStep(
              task,
              runPresentation.planSummary,
            ),
          })}
        >
          <AnswerCard
            answer={runPresentation.finalAnswer}
            sourceSummary={null}
            sourceDurationLabel={sourceDurationLabel}
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
        </AssistantTurn>
      )}

      {showInitialLoader && !suppressPendingIndicators && (
        <div
          className="spot-thinking-pill spot-thinking-pill--active"
          aria-live="polite"
        >
          <span className="spot-thinking-pill-icon">{icons.sparkles}</span>
          <span className="spot-thinking-pill-text">Working...</span>
          <span className="spot-thinking-pill-detail">
            {operatorFacingCurrentStep(task, runPresentation.planSummary) ||
              "Initializing..."}
          </span>
        </div>
      )}
    </>
  );
}
