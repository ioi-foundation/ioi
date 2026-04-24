import {
  formatSessionTimeAgo,
  type AssistantWorkbenchActivity,
  type AssistantWorkbenchSession,
} from "@ioi/agent-ide";
import type {
  WorkspaceCommitResult,
  WorkspaceSourceControlState,
} from "@ioi/workspace-substrate";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  openAssistantWorkbenchReview,
  openEvidenceReviewSession,
} from "../../../services/reviewNavigation";
import type {
  AgentEvent,
  AgentTask,
  Artifact,
  ArtifactHubViewKey,
  CanonicalTraceBundle,
  LocalEngineSnapshot,
  PlanSummary,
  SessionBranchSnapshot,
  SessionRemoteEnvSnapshot,
  SessionServerSnapshot,
} from "../../../types";
import type { AssistantWorkbenchSummary } from "../../../lib/assistantWorkbenchSummary";
import { useChatVoiceInput } from "../hooks/useChatVoiceInput";
import type { ScreenshotReceiptEvidence } from "../utils/screenshotEvidence";
import { RemoteContinuityPolicyCard } from "./ArtifactHubRemoteContinuityPolicyCard";
import type { SubstrateReceiptRow } from "./ArtifactHubViewModels";
import {
  buildVerificationNotes,
  humanizeStatus,
  taskBlockerSummary,
} from "./ArtifactHubViewHelpers";
import { buildCommitOverview } from "./artifactHubCommitModel";
import type { MobileOverview } from "./artifactHubMobileModel";
import {
  buildMobileEvidenceContinuityAction,
  type ChatRemoteContinuityLaunchRequest,
} from "./artifactHubRemoteContinuityModel";
import { buildMobileRemoteContinuityPolicyOverview } from "./artifactHubRemoteContinuityPolicyModel";
import { buildVoiceOverview } from "./artifactHubVoiceModel";
import { buildPrCommentsOverview } from "./artifactHubPrCommentsModel";

function clipText(value: string, maxChars: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function workbenchSurfaceLabel(
  surface: AssistantWorkbenchActivity["surface"],
): string {
  return surface === "reply-composer" ? "Reply composer" : "Meeting prep";
}

function workbenchActivityActionLabel(
  action: AssistantWorkbenchActivity["action"],
): string {
  return humanizeStatus(action);
}

export function PrCommentsView({
  currentTask,
  planSummary,
  branchSnapshot,
  sourceControlState,
  sourceControlLastCommitReceipt,
  replayBundle,
  visibleSourceCount,
  screenshotReceipts,
  substrateReceipts,
  onOpenView,
}: {
  currentTask: AgentTask | null;
  planSummary: PlanSummary | null;
  branchSnapshot: SessionBranchSnapshot | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlLastCommitReceipt: WorkspaceCommitResult | null;
  replayBundle: CanonicalTraceBundle | null;
  visibleSourceCount: number;
  screenshotReceipts: ScreenshotReceiptEvidence[];
  substrateReceipts: SubstrateReceiptRow[];
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = useMemo(() => {
    const blocker = taskBlockerSummary(currentTask);
    const commitOverview = buildCommitOverview(
      sourceControlState,
      branchSnapshot,
      sourceControlLastCommitReceipt,
    );
    return buildPrCommentsOverview({
      sessionTitle:
        replayBundle?.sessionSummary?.title ||
        currentTask?.intent ||
        currentTask?.current_step ||
        null,
      branchLabel:
        branchSnapshot?.currentBranch || branchSnapshot?.repoLabel || null,
      lastCommitLabel:
        sourceControlLastCommitReceipt?.commitSummary ||
        branchSnapshot?.lastCommit ||
        null,
      progressSummary:
        planSummary?.progressSummary || currentTask?.current_step || null,
      currentStage: planSummary?.currentStage || currentTask?.phase || null,
      selectedRoute: planSummary?.selectedRoute || null,
      changedPathCount: commitOverview.changedCount,
      stagedPathCount: commitOverview.stagedCount,
      unstagedPathCount: commitOverview.unstagedCount,
      evidenceEventCount: replayBundle?.stats.eventCount ?? 0,
      evidenceArtifactCount: replayBundle?.stats.artifactCount ?? 0,
      visibleSourceCount,
      screenshotCount: screenshotReceipts.length,
      substrateReceiptCount: substrateReceipts.length,
      verifierState: planSummary?.verifierState || null,
      verifierOutcome: planSummary?.verifierOutcome || null,
      approvalState: planSummary?.approvalState || null,
      blockerTitle: blocker?.title || null,
      blockerDetail: blocker?.detail || null,
      verificationNotes: buildVerificationNotes(planSummary),
    });
  }, [
    branchSnapshot,
    currentTask,
    planSummary,
    replayBundle,
    screenshotReceipts.length,
    sourceControlLastCommitReceipt,
    sourceControlState,
    substrateReceipts.length,
    visibleSourceCount,
  ]);
  const [copiedDraftId, setCopiedDraftId] = useState<string | null>(null);

  useEffect(() => {
    if (!copiedDraftId) {
      return;
    }
    const timeout = window.setTimeout(() => {
      setCopiedDraftId(null);
    }, 1500);
    return () => window.clearTimeout(timeout);
  }, [copiedDraftId]);

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          overview.readiness === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">PR Comments</span>
        <strong>{overview.readinessLabel}</strong>
        <p>{overview.readinessDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{overview.draftCount} comment drafts</span>
          <span>{overview.evidenceLabel}</span>
          <span>{visibleSourceCount} evidence sources</span>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Reviewer handoff</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Draft reviewer-facing PR comments from the same plan, source-control,
          and evidence state that already backs Commit, Share, Replay, and the
          retained route summary.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("commit")}
            >
              Open Commit
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("share")}
            >
              Share Evidence
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("active_context")}
            >
              Review Plan
            </button>
          ) : null}
        </div>
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Comment drafts</span>
          <span>{overview.drafts.length}</span>
        </div>
        <div className="artifact-hub-generic-list">
          {overview.drafts.map((draft) => (
            <article className="artifact-hub-generic-row" key={draft.id}>
              <div className="artifact-hub-generic-meta">
                <span>{draft.label}</span>
                <span>{draft.description}</span>
              </div>
              <textarea
                className="artifact-hub-commit-textarea"
                value={draft.markdown}
                readOnly
                rows={9}
              />
              <div className="artifact-hub-generic-actions">
                <button
                  type="button"
                  className="artifact-hub-open-btn"
                  onClick={() => {
                    void navigator.clipboard
                      .writeText(draft.markdown)
                      .then(() => {
                        setCopiedDraftId(draft.id);
                      });
                  }}
                >
                  {copiedDraftId === draft.id ? "Copied" : "Copy markdown"}
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

export function MobileView({
  assistantWorkbench,
  activeWorkbenchSummary,
  retainedWorkbenchActivities,
  retainedWorkbenchEvidenceThreadId,
  retainedWorkbenchTraceLoading,
  retainedWorkbenchTraceError,
  retainedWorkbenchEventCount,
  retainedWorkbenchArtifactCount,
  latestRetainedWorkbenchEvent,
  latestRetainedWorkbenchArtifact,
  retainedWorkbenchEvidenceAttachable,
  mobileOverview,
  serverSnapshot,
  remoteEnvSnapshot,
  managedSettings,
  onRequestReplLaunch,
  onOpenView,
}: {
  assistantWorkbench: AssistantWorkbenchSession | null;
  activeWorkbenchSummary: AssistantWorkbenchSummary | null;
  retainedWorkbenchActivities: AssistantWorkbenchActivity[];
  retainedWorkbenchEvidenceThreadId: string | null;
  retainedWorkbenchTraceLoading: boolean;
  retainedWorkbenchTraceError: string | null;
  retainedWorkbenchEventCount: number;
  retainedWorkbenchArtifactCount: number;
  latestRetainedWorkbenchEvent: AgentEvent | null;
  latestRetainedWorkbenchArtifact: Artifact | null;
  retainedWorkbenchEvidenceAttachable: boolean;
  mobileOverview: MobileOverview;
  serverSnapshot: SessionServerSnapshot | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineSnapshot["managedSettings"] | null;
  onRequestReplLaunch?: (request: ChatRemoteContinuityLaunchRequest) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const activityRows = retainedWorkbenchActivities.slice(0, 6);
  const evidenceAction = buildMobileEvidenceContinuityAction({
    evidenceThreadId: retainedWorkbenchEvidenceThreadId,
    hasActiveWorkbench: Boolean(assistantWorkbench),
    hasAttachableSessionTarget: retainedWorkbenchEvidenceAttachable,
  });
  const policyOverview = useMemo(
    () =>
      buildMobileRemoteContinuityPolicyOverview({
        mobileOverview,
        mobileAction: evidenceAction,
        serverSnapshot,
        remoteEnvSnapshot,
        managedSettings,
      }),
    [
      evidenceAction,
      managedSettings,
      mobileOverview,
      remoteEnvSnapshot,
      serverSnapshot,
    ],
  );

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          mobileOverview.status === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Mobile</span>
        <strong>{mobileOverview.statusLabel}</strong>
        <p>{mobileOverview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{mobileOverview.activityCount} retained activities</span>
          <span>{mobileOverview.evidenceLabel}</span>
          <span>{mobileOverview.sessionHistoryCount} retained sessions</span>
          <span>
            {evidenceAction.attachable ? "REPL ready" : "Evidence only"}
          </span>
        </div>
      </section>

      {retainedWorkbenchTraceError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {retainedWorkbenchTraceError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Active handoff</strong>
            <span className="artifact-hub-policy-pill">
              {assistantWorkbench ? "Live" : "Retained only"}
            </span>
          </div>
          <p>
            {activeWorkbenchSummary?.summary ||
              "No native reply or meeting-prep handoff is active right now."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              {assistantWorkbench
                ? workbenchSurfaceLabel(
                    assistantWorkbench.kind === "gmail_reply"
                      ? "reply-composer"
                      : "meeting-prep",
                  )
                : "Awaiting inbox-driven handoff"}
            </span>
            <span>
              {retainedWorkbenchEvidenceThreadId
                ? clipText(retainedWorkbenchEvidenceThreadId, 72)
                : "No retained evidence thread"}
            </span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {assistantWorkbench ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void openAssistantWorkbenchReview(assistantWorkbench);
                }}
              >
                {activeWorkbenchSummary?.resumeLabel || "Resume in Chat"}
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("tasks")}
              >
                Review Tasks
              </button>
            ) : null}
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Retained evidence</strong>
            <span className="artifact-hub-policy-pill">
              {mobileOverview.evidenceReady ? "Replay ready" : "Pending"}
            </span>
          </div>
          <p>
            Handoff activity stays tied to a retained evidence thread so replay,
            sharing, and later promotion can use the same runtime truth.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{retainedWorkbenchEventCount} events</span>
            <span>{retainedWorkbenchArtifactCount} artifacts</span>
            <span>
              {retainedWorkbenchTraceLoading
                ? "Loading retained evidence"
                : mobileOverview.evidenceReady
                  ? "Evidence retained"
                  : "Evidence not ready yet"}
            </span>
            <span>
              {evidenceAction.attachable
                ? "Attachable session"
                : "Evidence-only continuity"}
            </span>
          </div>
          {!retainedWorkbenchTraceLoading ? (
            <div className="artifact-hub-generic-list">
              <article className="artifact-hub-generic-row">
                <div className="artifact-hub-generic-meta">
                  <span>
                    {latestRetainedWorkbenchEvent?.title || "Awaiting event"}
                  </span>
                  <span>
                    {latestRetainedWorkbenchArtifact?.title ||
                      "No artifact yet"}
                  </span>
                </div>
                <p className="artifact-hub-generic-summary">
                  {retainedWorkbenchEvidenceThreadId
                    ? clipText(retainedWorkbenchEvidenceThreadId, 132)
                    : "A retained evidence thread will appear once a reply/prep surface records activity."}
                </p>
              </article>
            </div>
          ) : null}
          <p className="artifact-hub-generic-summary">
            {evidenceAction.detail}
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {(() => {
              const launchRequest = evidenceAction.launchRequest;
              if (!launchRequest || !onRequestReplLaunch) {
                return null;
              }
              return (
                <button
                  type="button"
                  className="artifact-hub-open-btn"
                  onClick={() => {
                    onRequestReplLaunch(launchRequest);
                  }}
                >
                  {evidenceAction.chatShellLabel}
                </button>
              );
            })()}
            {retainedWorkbenchEvidenceThreadId ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => {
                  void openEvidenceReviewSession(
                    retainedWorkbenchEvidenceThreadId,
                  );
                }}
              >
                {evidenceAction.studioLabel}
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("share")}
              >
                Share Evidence
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("replay")}
              >
                Review Replay
              </button>
            ) : null}
          </div>
        </section>
      </div>

      {activityRows.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Recent handoff activity</span>
            <span>{activityRows.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {activityRows.map((activity) => (
              <article
                className="artifact-hub-generic-row"
                key={activity.activityId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{workbenchSurfaceLabel(activity.surface)}</span>
                  <span>{workbenchActivityActionLabel(activity.action)}</span>
                  <span>{humanizeStatus(activity.status)}</span>
                  <span>{formatSessionTimeAgo(activity.timestampMs)}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {activity.message}
                </div>
                {activity.detail ? (
                  <p className="artifact-hub-generic-summary">
                    {activity.detail}
                  </p>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No native reply or meeting-prep handoffs have been retained yet. Once
          one starts, this drawer will keep its activity trail, evidence thread,
          and continuity shortcuts together.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Cross-shell continuity</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Chat, replay/export, and retained session history all stay aligned
          because the handoff state comes from the same runtime-owned session
          and evidence records.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{mobileOverview.sessionHistoryCount} retained sessions</span>
          <span>
            {mobileOverview.activityCount} retained handoff activities
          </span>
          <span>
            {evidenceAction.attachable
              ? "REPL ready"
              : mobileOverview.evidenceReady
                ? "Evidence-preserving"
                : "Awaiting evidence"}
          </span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("repl")}
            >
              Open REPL
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("export")}
            >
              Export Evidence
            </button>
          ) : null}
        </div>
      </section>

      <RemoteContinuityPolicyCard
        title={policyOverview.statusLabel}
        overview={policyOverview}
        onRequestReplLaunch={onRequestReplLaunch}
        onOpenView={onOpenView}
      />
    </div>
  );
}

export function VoiceView({
  onSeedIntent,
  onOpenView,
}: {
  onSeedIntent?: (intent: string) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [language, setLanguage] = useState("");
  const { status, error, result, fileName, reset, transcribeFile } =
    useChatVoiceInput();
  const overview = buildVoiceOverview({
    status,
    fileName,
    error,
    result,
  });
  const busy = status === "reading" || status === "transcribing";
  const transcript = result?.text.trim() ?? "";
  const selectedFileLabel = result?.fileName || fileName || "No clip selected";
  const languageHint = language.trim();

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          overview.tone === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Voice</span>
        <strong>{overview.statusLabel}</strong>
        <p>{overview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Tone: {humanizeStatus(overview.tone)}</span>
          <span>Projection: {humanizeStatus(status)}</span>
          <span>{selectedFileLabel}</span>
          <span>{result?.modelId || "Shared runtime transcription"}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Transcribe clip</strong>
            <span className="artifact-hub-policy-pill">
              {busy ? "In progress" : "Runtime-backed"}
            </span>
          </div>
          <p>
            Choose an audio clip and transcribe it through the shared inference
            runtime instead of relying on shell-local speech handling.
          </p>
          <div className="artifact-hub-commit-form">
            <label className="artifact-hub-commit-field">
              <span>Language hint</span>
              <input
                className="artifact-hub-commit-input"
                type="text"
                value={language}
                onChange={(event) => setLanguage(event.target.value)}
                placeholder="Optional, for example en or en-US"
                maxLength={16}
              />
            </label>
          </div>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Selected: {selectedFileLabel}</span>
            <span>
              {languageHint ? `Hint: ${languageHint}` : "Language: auto-detect"}
            </span>
            <span>{busy ? "Preparing transcript" : "Ready for audio"}</span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            <input
              ref={fileInputRef}
              type="file"
              accept="audio/*,.mp3,.wav,.m4a,.webm,.ogg,.aac,.flac"
              style={{ display: "none" }}
              onChange={(event) => {
                const nextFile = event.currentTarget.files?.[0];
                event.currentTarget.value = "";
                if (!nextFile) {
                  return;
                }
                void transcribeFile(nextFile, languageHint || null).catch(
                  () => {
                    // The error state is already captured by the hook.
                  },
                );
              }}
            />
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={busy}
              onClick={() => fileInputRef.current?.click()}
            >
              {busy
                ? "Transcribing..."
                : result
                  ? "Choose another clip"
                  : "Choose audio clip"}
            </button>
            {result || fileName || error ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                disabled={busy}
                onClick={reset}
              >
                Reset
              </button>
            ) : null}
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Latest transcript</strong>
            <span className="artifact-hub-policy-pill">
              {transcript ? "Ready" : "Awaiting audio"}
            </span>
          </div>
          <p>
            Seed the transcribed text directly back into the composer once it is
            ready so the next plan or execution request stays tied to the same
            shared runtime truth.
          </p>
          {transcript ? (
            <div className="artifact-hub-commit-form">
              <label className="artifact-hub-commit-field">
                <span>Transcript</span>
                <textarea
                  className="artifact-hub-commit-textarea"
                  value={transcript}
                  readOnly
                  rows={6}
                />
              </label>
            </div>
          ) : (
            <p>
              No transcript is retained yet. Choose an audio clip to preview its
              text here before sending it back to the composer.
            </p>
          )}
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{result?.mimeType || "Pending mime type"}</span>
            <span>{result?.language || languageHint || "Auto language"}</span>
            <span>{result?.modelId || "Awaiting runtime result"}</span>
          </div>
          <div className="artifact-hub-permissions-card__actions">
            {onSeedIntent && transcript ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => onSeedIntent(transcript)}
              >
                Use in composer
              </button>
            ) : null}
            {onOpenView ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => onOpenView("active_context")}
              >
                Review Plan
              </button>
            ) : null}
          </div>
        </section>
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Cross-shell continuity</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Voice transcription stays inside the same runtime plane as Server,
          Mobile, REPL, and Chat plan execution, so the result can move across
          shells without inventing a separate speech subsystem.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>
            {transcript ? "Transcript retained locally" : "Awaiting transcript"}
          </span>
          <span>{result?.fileName || fileName || "No audio clip yet"}</span>
          <span>{result?.modelId || "Shared runtime"}</span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("server")}
            >
              Inspect Server Mode
            </button>
          ) : null}
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("mobile")}
            >
              Open Mobile
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}
