import { useMemo } from "react";
import type {
  AgentTask,
  ArtifactHubViewKey,
  CanonicalTraceBundle,
  PlanSummary,
  SessionBranchSnapshot,
  SessionCompactionSnapshot,
} from "../../../../types";
import type {
  WorkspaceCommitResult,
  WorkspaceSourceControlState,
} from "@ioi/workspace-substrate";
import type { ScreenshotReceiptEvidence } from "../../utils/screenshotEvidence";
import type { SubstrateReceiptRow } from "../ArtifactHubViewModels";
import type { DurabilityEvidenceOverview } from "../../utils/durabilityEvidenceModel";
import type { PrivacyEvidenceOverview } from "../../utils/privacyEvidenceModel";
import type { TraceBundleExportVariant } from "../../utils/traceBundleExportModel";
import { buildCommitOverview } from "../artifactHubCommitModel";
import { buildPrCommentsOverview } from "../artifactHubPrCommentsModel";
import { buildReviewOverview } from "../artifactHubReviewModel";
import { buildRetainedPortfolioDossier } from "../../utils/retainedPortfolioDossierModel";
import { buildSavedBundleProofOverview } from "../../utils/savedBundleProofModel";

function reviewActionLabel(view: ArtifactHubViewKey): string {
  switch (view) {
    case "tasks":
      return "Review Tasks";
    case "replay":
      return "Review Replay";
    case "pr_comments":
      return "Draft PR Comments";
    case "privacy":
      return "Review Privacy";
    case "share":
      return "Share Evidence";
    case "export":
      return "Export Evidence";
    default:
      return "Review drawer";
  }
}

function RetainedPortfolioDossierCard({
  dossier,
  onExportRecommendedPack,
  onOpenView,
  secondaryView = "share",
}: {
  dossier: ReturnType<typeof buildRetainedPortfolioDossier>;
  onExportRecommendedPack?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  secondaryView?: ArtifactHubViewKey;
}) {
  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>{dossier.title}</strong>
        <span className="artifact-hub-policy-pill">{dossier.readinessLabel}</span>
      </div>
      <p>{dossier.summary}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>Recommended pack: {dossier.recommendedVariantLabel}</span>
        {dossier.latestExportLabel ? (
          <span>Latest export: {dossier.latestExportLabel}</span>
        ) : (
          <span>No packaged review pack yet</span>
        )}
        <span>{dossier.portfolioSummary}</span>
      </div>
      <p className="artifact-hub-generic-summary">
        {dossier.checklist.join(" · ")}
      </p>
      <div className="artifact-hub-permissions-card__actions">
        {onExportRecommendedPack ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void onExportRecommendedPack();
            }}
          >
            {dossier.latestExportMatchesRecommendation
              ? "Refresh recommended pack"
              : "Export recommended pack"}
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView(secondaryView)}
          >
            {secondaryView === "export" ? "Export Evidence" : "Share Evidence"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function SavedBundleProofCard({
  overview,
  onExportRecommendedPack,
  onOpenView,
  secondaryView = "share",
}: {
  overview: ReturnType<typeof buildSavedBundleProofOverview>;
  onExportRecommendedPack?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
  secondaryView?: ArtifactHubViewKey;
}) {
  return (
    <section
      className={`artifact-hub-permissions-card ${
        overview.tone === "review"
          ? "artifact-hub-permissions-card--alert"
          : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">{overview.tone}</span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        {overview.meta.map((item) => (
          <span key={item}>{item}</span>
        ))}
      </div>
      <p className="artifact-hub-generic-summary">
        {overview.checklist.join(" · ")}
      </p>
      <div className="artifact-hub-permissions-card__actions">
        {onExportRecommendedPack ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void onExportRecommendedPack();
            }}
          >
            Refresh saved bundle proof
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView(secondaryView)}
          >
            {secondaryView === "export" ? "Export Evidence" : "Share Evidence"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

export function ReviewView({
  currentTask,
  planSummary,
  branchSnapshot,
  compactionSnapshot,
  sourceControlState,
  sourceControlLastCommitReceipt,
  replayBundle,
  visibleSourceCount,
  screenshotReceipts,
  substrateReceipts,
  durabilityOverview,
  privacyOverview,
  exportPath,
  exportTimestampMs,
  exportStatus,
  exportVariant,
  verificationNotes,
  blockerSummary,
  onOpenView,
}: {
  currentTask: AgentTask | null;
  planSummary: PlanSummary | null;
  branchSnapshot: SessionBranchSnapshot | null;
  compactionSnapshot: SessionCompactionSnapshot | null;
  sourceControlState: WorkspaceSourceControlState | null;
  sourceControlLastCommitReceipt: WorkspaceCommitResult | null;
  replayBundle: CanonicalTraceBundle | null;
  visibleSourceCount: number;
  screenshotReceipts: ScreenshotReceiptEvidence[];
  substrateReceipts: SubstrateReceiptRow[];
  durabilityOverview: DurabilityEvidenceOverview;
  privacyOverview: PrivacyEvidenceOverview;
  exportPath: string | null;
  exportTimestampMs: number | null;
  exportStatus: string;
  exportVariant: TraceBundleExportVariant | null;
  verificationNotes: string[];
  blockerSummary: { title: string; detail: string } | null;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = useMemo(() => {
    const commitOverview = buildCommitOverview(
      sourceControlState,
      branchSnapshot,
      sourceControlLastCommitReceipt,
    );
    const prCommentsOverview = buildPrCommentsOverview({
      sessionTitle:
        replayBundle?.sessionSummary?.title ||
        currentTask?.intent ||
        currentTask?.current_step ||
        null,
      branchLabel: branchSnapshot?.currentBranch || branchSnapshot?.repoLabel || null,
      lastCommitLabel:
        sourceControlLastCommitReceipt?.commitSummary ||
        branchSnapshot?.lastCommit ||
        null,
      progressSummary: planSummary?.progressSummary || currentTask?.current_step || null,
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
      blockerTitle: blockerSummary?.title || null,
      blockerDetail: blockerSummary?.detail || null,
      verificationNotes,
    });

    return buildReviewOverview({
      sessionTitle:
        replayBundle?.sessionSummary?.title ||
        currentTask?.intent ||
        currentTask?.current_step ||
        null,
      branchLabel: branchSnapshot?.currentBranch || branchSnapshot?.repoLabel || null,
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
      blockerTitle: blockerSummary?.title || null,
      blockerDetail: blockerSummary?.detail || null,
      prReadiness: prCommentsOverview.readiness,
      prReadinessLabel: prCommentsOverview.readinessLabel,
      prReadinessDetail: prCommentsOverview.readinessDetail,
      privacyStatusLabel: privacyOverview.statusLabel,
      privacyDetail: privacyOverview.detail,
      privacyRecommendationLabel: privacyOverview.recommendationLabel,
      durabilityStatusLabel: durabilityOverview.statusLabel,
      durabilityDetail: durabilityOverview.detail,
      exportStatus,
      exportVariant,
      replayReady: Boolean(replayBundle),
    });
  }, [
    blockerSummary,
    branchSnapshot,
    currentTask,
    durabilityOverview.detail,
    durabilityOverview.statusLabel,
    exportStatus,
    exportVariant,
    planSummary,
    privacyOverview.detail,
    privacyOverview.recommendationLabel,
    privacyOverview.statusLabel,
    replayBundle,
    screenshotReceipts.length,
    sourceControlLastCommitReceipt,
    sourceControlState,
    substrateReceipts.length,
    verificationNotes,
    visibleSourceCount,
  ]);

  const dossier = useMemo(
    () =>
      buildRetainedPortfolioDossier({
        sessionTitle:
          replayBundle?.sessionSummary?.title ||
          currentTask?.intent ||
          currentTask?.current_step ||
          null,
        bundle: replayBundle,
        portfolio: compactionSnapshot?.durabilityPortfolio ?? null,
        exportVariant,
        privacyStatusLabel: privacyOverview.statusLabel,
        privacyRecommendationLabel: privacyOverview.recommendationLabel,
        durabilityStatusLabel: durabilityOverview.statusLabel,
      }),
    [
      compactionSnapshot?.durabilityPortfolio,
      currentTask,
      durabilityOverview.statusLabel,
      exportVariant,
      privacyOverview.recommendationLabel,
      privacyOverview.statusLabel,
      replayBundle,
    ],
  );

  const savedBundleProof = useMemo(
    () =>
      buildSavedBundleProofOverview({
        dossier,
        exportPath,
        exportTimestampMs,
        exportVariant,
        bundle: replayBundle,
      }),
    [dossier, exportPath, exportTimestampMs, exportVariant, replayBundle],
  );

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          overview.tone === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Review</span>
        <strong>{overview.headline}</strong>
        <p>{overview.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{overview.cards.length} workflow lanes</span>
          <span>{overview.reviewCount} need review</span>
          <span>{overview.watchCount} still assembling</span>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Workflow hub</strong>
          <span className="artifact-hub-policy-pill">Shared runtime truth</span>
        </div>
        <p>
          Review the live run, reviewer handoff, privacy posture, and promotion
          readiness from one runtime-backed surface instead of reconstructing it
          across separate drawers.
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
              onClick={() => onOpenView("pr_comments")}
            >
              Draft PR Comments
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
        </div>
      </section>

      <RetainedPortfolioDossierCard
        dossier={dossier}
        onOpenView={onOpenView}
        secondaryView="share"
      />

      <SavedBundleProofCard
        overview={savedBundleProof}
        onOpenView={onOpenView}
        secondaryView="share"
      />

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>Review lanes</span>
          <span>{overview.cards.length}</span>
        </div>
        <div className="artifact-hub-generic-list">
          {overview.cards.map((card) => (
            <article className="artifact-hub-generic-row" key={card.id}>
              <div className="artifact-hub-generic-meta">
                <span>{card.label}</span>
                <span>{card.value}</span>
              </div>
              <div className="artifact-hub-generic-title">{card.value}</div>
              <p className="artifact-hub-generic-summary">{card.detail}</p>
              <p className="artifact-hub-generic-summary">
                {card.meta.join(" · ")}
              </p>
              {card.actionView && onOpenView ? (
                <div className="artifact-hub-generic-actions">
                  <button
                    type="button"
                    className="artifact-hub-open-btn secondary"
                    onClick={() => onOpenView(card.actionView!)}
                  >
                    {reviewActionLabel(card.actionView)}
                  </button>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      </section>
    </div>
  );
}

