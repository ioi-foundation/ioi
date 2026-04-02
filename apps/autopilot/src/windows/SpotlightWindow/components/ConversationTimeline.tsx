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
import { VisualEvidenceCard } from "./VisualEvidenceCard";

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
  icons: {
    sparkles: React.ReactNode;
  };
  onDownloadContext: () => Promise<void> | void;
  onOpenArtifactHub: (
    preferredView?: ArtifactHubViewKey,
    preferredTurnId?: string | null,
  ) => void;
  onOpenSourceSummary: (summary: SourceSummary) => void;
};

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
  icons,
  onDownloadContext,
  onOpenArtifactHub,
  onOpenSourceSummary,
}: ConversationTimelineProps) {
  return (
    <>
      {conversationTurns.map((turn, index) => {
        const isLatestTurn = index === conversationTurns.length - 1;
        const isLatestAnsweredTurn = index === latestAnsweredTurnIndex;
        const turnContext = turnContexts[index] || null;
        const turnPlanSummary =
          turnContext?.planSummary ||
          (isLatestTurn ? runPresentation.planSummary : null);
        const latestAnswerMatches =
          isLatestAnsweredTurn &&
          !!turn.answer &&
          !!runPresentation.finalAnswer;
        const hasThoughtSummary = !!runPresentation.thoughtSummary;
        const hasPlanSummary = !!turnPlanSummary;
        const showLiveThinking =
          isLatestTurn && !!turn.prompt && !turn.answer && isRunning;
        const showExecutionRouteCard = !!turn.prompt && hasPlanSummary;
        const showThoughtTrigger =
          !showExecutionRouteCard &&
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

        return (
          <React.Fragment key={turn.key}>
            {turn.prompt && (
              <div className="spot-message user spot-message--prompt">
                <div className="message-content-text">{turn.prompt.text}</div>
              </div>
            )}

            {showExecutionRouteCard && turnPlanSummary && (
              <>
                <ExecutionRouteCard
                  summary={turnPlanSummary}
                  currentStep={showLiveThinking ? currentStep : undefined}
                  traceDetail={traceDetail}
                  onOpenArtifacts={() =>
                    onOpenArtifactHub(
                      "active_context",
                      turnContext?.turnId || null,
                    )
                  }
                />
                <ExecutionMomentList
                  moments={turnContext?.executionMoments || []}
                />
              </>
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
                <AnswerCard
                  answer={runPresentation.finalAnswer}
                  sourceSummary={runPresentation.sourceSummary}
                  sourceDurationLabel={sourceDurationLabel}
                  onDownloadContext={onDownloadContext}
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
              ) : (
                <div className="spot-message agent">
                  <MarkdownMessage text={turn.answer.text} />
                </div>
              ))}
          </React.Fragment>
        );
      })}

      {conversationTurns.length === 0 && runPresentation.finalAnswer && (
        <AnswerCard
          answer={runPresentation.finalAnswer}
          sourceSummary={runPresentation.sourceSummary}
          sourceDurationLabel={sourceDurationLabel}
          onDownloadContext={onDownloadContext}
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

      {showInitialLoader && (
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
