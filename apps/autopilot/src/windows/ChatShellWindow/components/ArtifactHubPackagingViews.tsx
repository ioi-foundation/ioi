import { useMemo, useState } from "react";
import type {
  ArtifactHubViewKey,
  CanonicalTraceBundle,
  LocalEngineStagedOperation,
  SessionCompactionSnapshot,
} from "../../../types";
import {
  buildArtifactPipelineAutomationPlan,
  type ArtifactPipelineAutomationQueuedAction,
} from "../utils/artifactPipelineAutomationModel";
import type { DurabilityEvidenceOverview } from "../utils/durabilityEvidenceModel";
import type { PrivacyEvidenceOverview } from "../utils/privacyEvidenceModel";
import type { PromotionTarget } from "../utils/promotionStageModel";
import { buildRetainedPortfolioDossier } from "../utils/retainedPortfolioDossierModel";
import { buildSavedBundleProofOverview } from "../utils/savedBundleProofModel";
import {
  traceBundleExportVariantLabel,
  type TraceBundleExportVariant,
} from "../utils/traceBundleExportModel";
import { formatTaskTimestamp, humanizeStatus } from "./ArtifactHubViewHelpers";

export interface ArtifactHubPackagingViewProps {
  exportSessionId?: string | null;
  exportStatus: string;
  exportError: string | null;
  exportPath: string | null;
  exportTimestampMs: number | null;
  exportVariant: TraceBundleExportVariant | null;
  durabilityOverview: DurabilityEvidenceOverview;
  privacyOverview: PrivacyEvidenceOverview;
  compactionSnapshot: SessionCompactionSnapshot | null;
  stagedOperations: LocalEngineStagedOperation[];
  replayBundle: CanonicalTraceBundle | null;
  replayLoading: boolean;
  replayError: string | null;
  promotionStageBusyTarget: PromotionTarget | null;
  promotionStageMessage: string | null;
  promotionStageError: string | null;
  onExportBundle?: (variant?: TraceBundleExportVariant) => Promise<unknown>;
  onStagePromotionCandidate?: (target: PromotionTarget) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}

function clipText(value: string, maxChars: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= maxChars) return compact;
  return `${compact.slice(0, maxChars - 1).trim()}…`;
}

function useArtifactPackagingAutomation({
  sessionTitle,
  exportPath,
  exportTimestampMs,
  exportVariant,
  durabilityOverview,
  privacyOverview,
  compactionSnapshot,
  stagedOperations,
  replayBundle,
  onExportBundle,
  onStagePromotionCandidate,
  onOpenView,
}: ArtifactHubPackagingViewProps & { sessionTitle: string }) {
  const dossier = useMemo(
    () =>
      buildRetainedPortfolioDossier({
        sessionTitle,
        bundle: replayBundle,
        portfolio: compactionSnapshot?.durabilityPortfolio ?? null,
        exportVariant,
        privacyStatusLabel: privacyOverview.statusLabel,
        privacyRecommendationLabel: privacyOverview.recommendationLabel,
        durabilityStatusLabel: durabilityOverview.statusLabel,
      }),
    [
      compactionSnapshot?.durabilityPortfolio,
      durabilityOverview.statusLabel,
      exportVariant,
      privacyOverview.recommendationLabel,
      privacyOverview.statusLabel,
      replayBundle,
      sessionTitle,
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
  const artifactAutomationPlan = useMemo(
    () =>
      buildArtifactPipelineAutomationPlan({
        dossier,
        savedBundleProof,
        privacyOverview,
        durabilityOverview,
        stagedOperations,
      }),
    [
      dossier,
      durabilityOverview,
      privacyOverview,
      savedBundleProof,
      stagedOperations,
    ],
  );
  const [artifactAutomationBusy, setArtifactAutomationBusy] = useState(false);
  const [artifactAutomationMessage, setArtifactAutomationMessage] = useState<
    string | null
  >(null);
  const [artifactAutomationError, setArtifactAutomationError] = useState<
    string | null
  >(null);

  const runArtifactAutomationPlan = async (
    action:
      | ArtifactPipelineAutomationQueuedAction
      | undefined = artifactAutomationPlan.queuedActions[0],
  ) => {
    if (!action && artifactAutomationPlan.actionKind === "none") {
      setArtifactAutomationMessage(
        "Artifact automation does not have a pending action right now.",
      );
      return;
    }
    setArtifactAutomationBusy(true);
    setArtifactAutomationMessage(null);
    setArtifactAutomationError(null);
    try {
      const nextAction = action ??
        artifactAutomationPlan.queuedActions[0] ?? {
          kind: artifactAutomationPlan.actionKind,
          label:
            artifactAutomationPlan.primaryActionLabel ||
            "Run artifact automation",
          recommendedView: artifactAutomationPlan.recommendedView,
          promotionTarget: artifactAutomationPlan.promotionTarget,
          detail: artifactAutomationPlan.detail,
        };
      switch (nextAction.kind) {
        case "export_recommended_pack":
          if (!onExportBundle) {
            throw new Error("Recommended pack export is unavailable.");
          }
          await onExportBundle(dossier.recommendedVariant);
          setArtifactAutomationMessage(
            `Exported the ${dossier.recommendedVariantLabel.toLowerCase()} from the shared artifact automation plan.`,
          );
          break;
        case "review_privacy":
          if (!onOpenView) {
            throw new Error("Privacy review is unavailable.");
          }
          onOpenView(nextAction.recommendedView || "privacy");
          setArtifactAutomationMessage(
            "Opened Privacy so the artifact path can review the current sharing posture.",
          );
          break;
        case "review_durability":
          if (!onOpenView) {
            throw new Error("Durability review is unavailable.");
          }
          onOpenView(nextAction.recommendedView || "compact");
          setArtifactAutomationMessage(
            "Opened Compact so the artifact path can review long-session durability.",
          );
          break;
        case "stage_promotion":
          if (!nextAction.promotionTarget || !onStagePromotionCandidate) {
            throw new Error("Promotion staging is unavailable.");
          }
          await onStagePromotionCandidate(nextAction.promotionTarget);
          setArtifactAutomationMessage(
            `Staged ${nextAction.promotionTarget} from the shared artifact automation plan.`,
          );
          break;
        default:
          setArtifactAutomationMessage(
            "Artifact automation does not have a pending action right now.",
          );
          break;
      }
    } catch (automationError) {
      setArtifactAutomationError(
        automationError instanceof Error
          ? automationError.message
          : String(automationError),
      );
    } finally {
      setArtifactAutomationBusy(false);
    }
  };

  return {
    artifactAutomationBusy,
    artifactAutomationError,
    artifactAutomationMessage,
    artifactAutomationPlan,
    dossier,
    runArtifactAutomationPlan,
    savedBundleProof,
  };
}

function PromotionStageCard({
  dossier,
  exportPath,
  exportVariant,
  busyTarget,
  message,
  error,
  onStagePromotionCandidate,
  onOpenView,
}: {
  dossier?: ReturnType<typeof buildRetainedPortfolioDossier> | null;
  exportPath: string | null;
  exportVariant: TraceBundleExportVariant | null;
  busyTarget: PromotionTarget | null;
  message: string | null;
  error: string | null;
  onStagePromotionCandidate?: (target: PromotionTarget) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const latestPackLabel = traceBundleExportVariantLabel(exportVariant);
  const stageDisabled = !onStagePromotionCandidate || busyTarget !== null;

  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>Promotion queue</strong>
        <span className="artifact-hub-policy-pill">Evidence-preserving</span>
      </div>
      <p>
        Stage this run into the governed Local Engine queue so `sas.xyz` service
        candidate review and `Forge` productionization can continue from the
        same replay-safe trace bundle truth.
      </p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>Source: canonical trace bundle</span>
        {dossier ? <span>Dossier: {dossier.title}</span> : null}
        {dossier ? (
          <span>Recommended pack: {dossier.recommendedVariantLabel}</span>
        ) : null}
        {latestPackLabel ? <span>Latest pack: {latestPackLabel}</span> : null}
        {exportPath ? (
          <span title={exportPath}>
            Export path: {clipText(exportPath, 40)}
          </span>
        ) : null}
      </div>
      {dossier ? (
        <p className="artifact-hub-generic-summary">
          {dossier.summary} {dossier.portfolioSummary}
        </p>
      ) : null}
      {message ? <p className="artifact-hub-note">{message}</p> : null}
      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}
      <div className="artifact-hub-permissions-card__actions">
        <button
          type="button"
          className="artifact-hub-open-btn"
          onClick={() => {
            void onStagePromotionCandidate?.("sas.xyz");
          }}
          disabled={stageDisabled}
        >
          {busyTarget === "sas.xyz" ? "Staging..." : "Stage for sas.xyz"}
        </button>
        <button
          type="button"
          className="artifact-hub-open-btn"
          onClick={() => {
            void onStagePromotionCandidate?.("Forge");
          }}
          disabled={stageDisabled}
        >
          {busyTarget === "Forge" ? "Staging..." : "Stage for Forge"}
        </button>
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView("thoughts")}
          >
            Open staged queue
          </button>
        ) : null}
      </div>
    </section>
  );
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
        <span className="artifact-hub-policy-pill">
          {dossier.readinessLabel}
        </span>
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
        overview.tone === "review" ? "artifact-hub-permissions-card--alert" : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">
          {humanizeStatus(overview.tone)}
        </span>
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

function ArtifactPipelineAutomationCard({
  plan,
  busy,
  message,
  error,
  onRun,
  onOpenView,
}: {
  plan: ReturnType<typeof buildArtifactPipelineAutomationPlan>;
  busy: boolean;
  message: string | null;
  error: string | null;
  onRun?: (action?: ArtifactPipelineAutomationQueuedAction) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  return (
    <section
      className={`artifact-hub-permissions-card ${
        plan.tone === "review" ? "artifact-hub-permissions-card--alert" : ""
      }`}
    >
      <div className="artifact-hub-permissions-card__head">
        <strong>{plan.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">
          {humanizeStatus(plan.tone)}
        </span>
      </div>
      <p>{plan.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        {plan.checklist.map((item) => (
          <span key={item}>{item}</span>
        ))}
        {plan.queuedActions.length > 1 ? (
          <span>{plan.queuedActions.length} queued promotion steps</span>
        ) : null}
      </div>
      {message ? <p className="artifact-hub-note">{message}</p> : null}
      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}
      {plan.queuedActions.length > 1 ? (
        <div className="artifact-hub-generic-list">
          {plan.queuedActions.map((action, index) => (
            <article
              className="artifact-hub-generic-row"
              key={`${action.kind}:${action.promotionTarget ?? action.label}`}
            >
              <div className="artifact-hub-generic-meta">
                <span>Step {index + 1}</span>
                <span>
                  {action.promotionTarget ?? humanizeStatus(action.kind)}
                </span>
              </div>
              <div className="artifact-hub-generic-title">{action.label}</div>
              <p className="artifact-hub-generic-summary">{action.detail}</p>
              <div className="artifact-hub-generic-actions">
                {onRun ? (
                  <button
                    type="button"
                    className="artifact-hub-open-btn secondary"
                    disabled={busy}
                    onClick={() => onRun(action)}
                  >
                    {busy && index === 0 ? "Running..." : "Run step"}
                  </button>
                ) : null}
              </div>
            </article>
          ))}
        </div>
      ) : null}
      <div className="artifact-hub-permissions-card__actions">
        {plan.primaryActionLabel && onRun ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            disabled={busy}
            onClick={() => onRun(plan.queuedActions[0])}
          >
            {busy ? "Running..." : plan.primaryActionLabel}
          </button>
        ) : null}
        {plan.recommendedView && onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView(plan.recommendedView!)}
          >
            {plan.recommendedView === "compact"
              ? "Compact Session"
              : plan.recommendedView === "privacy"
                ? "Review Privacy"
                : "Open Review"}
          </button>
        ) : null}
      </div>
    </section>
  );
}

function DurabilityEvidenceCard({
  overview,
  onOpenView,
}: {
  overview: DurabilityEvidenceOverview;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">Long-session truth</span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>{overview.compactionSummary}</span>
        <span>{overview.teamMemorySummary}</span>
      </div>
      <div className="artifact-hub-permissions-card__actions">
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => onOpenView("compact")}
          >
            Compact Session
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
  );
}

function PrivacyEvidenceCard({
  overview,
  onOpenView,
}: {
  overview: PrivacyEvidenceOverview;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  return (
    <section className="artifact-hub-permissions-card">
      <div className="artifact-hub-permissions-card__head">
        <strong>{overview.statusLabel}</strong>
        <span className="artifact-hub-policy-pill">Privacy posture</span>
      </div>
      <p>{overview.detail}</p>
      <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
        <span>{overview.exportSummary}</span>
        <span>{overview.recommendationLabel}</span>
      </div>
      <div className="artifact-hub-permissions-card__actions">
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => onOpenView("privacy")}
          >
            Review Privacy
          </button>
        ) : null}
        {onOpenView ? (
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => onOpenView("permissions")}
          >
            Review Permissions
          </button>
        ) : null}
      </div>
    </section>
  );
}

export function ExportView(props: ArtifactHubPackagingViewProps) {
  const {
    exportSessionId,
    exportStatus,
    exportError,
    exportPath,
    exportTimestampMs,
    exportVariant,
    durabilityOverview,
    privacyOverview,
    replayBundle,
    replayLoading,
    replayError,
    promotionStageBusyTarget,
    promotionStageMessage,
    promotionStageError,
    onExportBundle,
    onStagePromotionCandidate,
    onOpenView,
  } = props;
  const sessionTitle =
    replayBundle?.sessionSummary?.title?.trim() || "Active session export";
  const sessionId = replayBundle?.sessionId || exportSessionId || "No session";
  const threadId = replayBundle?.threadId || exportSessionId || "Unavailable";
  const bundleGeneratedAt = replayBundle?.exportedAtUtc
    ? new Date(replayBundle.exportedAtUtc).toLocaleString()
    : null;
  const latestExportLabel =
    typeof exportTimestampMs === "number" && Number.isFinite(exportTimestampMs)
      ? formatTaskTimestamp(exportTimestampMs)
      : null;
  const artifactPayloadCount = replayBundle?.artifactPayloads.length ?? 0;
  const replayEventCount = replayBundle?.stats.eventCount ?? 0;
  const replayReceiptCount = replayBundle?.stats.receiptCount ?? 0;
  const replayArtifactCount = replayBundle?.stats.artifactCount ?? 0;
  const isExporting = exportStatus === "exporting";
  const lastExportVariantLabel = traceBundleExportVariantLabel(exportVariant);
  const {
    artifactAutomationBusy,
    artifactAutomationError,
    artifactAutomationMessage,
    artifactAutomationPlan,
    dossier,
    runArtifactAutomationPlan,
    savedBundleProof,
  } = useArtifactPackagingAutomation({ ...props, sessionTitle });

  if (!exportSessionId && !replayBundle) {
    return (
      <p className="artifact-hub-empty">
        No retained session is available to export yet.
      </p>
    );
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Export</span>
        <strong>{sessionTitle}</strong>
        <p>
          Export the canonical trace bundle for the active session, including
          retained receipts, replay history, and artifact payloads.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(exportStatus)}</span>
          <span>Thread: {clipText(threadId, 24)}</span>
          <span>Session: {clipText(sessionId, 24)}</span>
          <span>Payloads: {artifactPayloadCount}</span>
          <span>Events: {replayEventCount}</span>
          <span>Receipts: {replayReceiptCount}</span>
          <span>Artifacts: {replayArtifactCount}</span>
        </div>
      </section>

      {exportError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {exportError}
        </p>
      ) : null}
      {replayError && !replayBundle ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          Replay snapshot unavailable: {replayError}
        </p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Bundle scope</strong>
          <span className="artifact-hub-policy-pill">Canonical trace</span>
        </div>
        <p>
          This export uses the same canonical trace-bundle path as the answer
          card export action. Artifact payloads are included in the saved zip.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Share posture: local operator export</span>
          <span>Artifact payloads: included</span>
          {bundleGeneratedAt ? (
            <span>Snapshot: {bundleGeneratedAt}</span>
          ) : null}
          {latestExportLabel ? (
            <span>Last export: {latestExportLabel}</span>
          ) : null}
          {lastExportVariantLabel ? (
            <span>Variant: {lastExportVariantLabel}</span>
          ) : null}
        </div>
        {exportPath ? (
          <p className="artifact-hub-generic-summary" title={exportPath}>
            Latest exported bundle: {exportPath}
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onExportBundle ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onExportBundle("trace_bundle");
              }}
              disabled={isExporting}
            >
              {isExporting ? "Exporting..." : "Export Trace Bundle"}
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

      <SavedBundleProofCard
        overview={savedBundleProof}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="share"
      />

      <ArtifactPipelineAutomationCard
        plan={artifactAutomationPlan}
        busy={artifactAutomationBusy}
        message={artifactAutomationMessage}
        error={artifactAutomationError}
        onRun={(action) => {
          void runArtifactAutomationPlan(action);
        }}
        onOpenView={onOpenView}
      />

      <RetainedPortfolioDossierCard
        dossier={dossier}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="share"
      />

      <PromotionStageCard
        dossier={dossier}
        exportPath={exportPath}
        exportVariant={exportVariant}
        busyTarget={promotionStageBusyTarget}
        message={promotionStageMessage}
        error={promotionStageError}
        onStagePromotionCandidate={onStagePromotionCandidate}
        onOpenView={onOpenView}
      />

      <DurabilityEvidenceCard
        overview={durabilityOverview}
        onOpenView={onOpenView}
      />
      <PrivacyEvidenceCard overview={privacyOverview} onOpenView={onOpenView} />

      {replayLoading && !replayBundle ? (
        <p className="artifact-hub-empty">
          Loading the retained replay snapshot for export preview.
        </p>
      ) : null}
    </div>
  );
}

export function ShareView(props: ArtifactHubPackagingViewProps) {
  const {
    exportSessionId,
    exportStatus,
    exportError,
    exportPath,
    exportTimestampMs,
    exportVariant,
    durabilityOverview,
    privacyOverview,
    replayBundle,
    replayLoading,
    replayError,
    promotionStageBusyTarget,
    promotionStageMessage,
    promotionStageError,
    onExportBundle,
    onStagePromotionCandidate,
    onOpenView,
  } = props;
  const sessionTitle =
    replayBundle?.sessionSummary?.title?.trim() || "Active session share pack";
  const latestExportLabel =
    typeof exportTimestampMs === "number" && Number.isFinite(exportTimestampMs)
      ? formatTaskTimestamp(exportTimestampMs)
      : null;
  const lastExportVariantLabel = traceBundleExportVariantLabel(exportVariant);
  const replayStats = replayBundle?.stats ?? null;
  const isExporting = exportStatus === "exporting";
  const {
    artifactAutomationBusy,
    artifactAutomationError,
    artifactAutomationMessage,
    artifactAutomationPlan,
    dossier,
    runArtifactAutomationPlan,
    savedBundleProof,
  } = useArtifactPackagingAutomation({ ...props, sessionTitle });

  if (!exportSessionId && !replayBundle) {
    return (
      <p className="artifact-hub-empty">
        No retained session is available to package for sharing yet.
      </p>
    );
  }

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Share</span>
        <strong>{sessionTitle}</strong>
        <p>
          Package the current session into a first-class local share artifact
          without leaving the runtime-owned canonical trace bundle path.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(exportStatus)}</span>
          <span>
            {replayStats?.eventCount ?? 0} events ·{" "}
            {replayStats?.receiptCount ?? 0} receipts
          </span>
          <span>
            {replayStats?.artifactCount ?? 0} artifacts ·{" "}
            {replayStats?.includedArtifactPayloadCount ?? 0} payloads
          </span>
          {latestExportLabel ? (
            <span>Last export: {latestExportLabel}</span>
          ) : null}
          {lastExportVariantLabel ? (
            <span>Variant: {lastExportVariantLabel}</span>
          ) : null}
        </div>
      </section>

      {exportError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          {exportError}
        </p>
      ) : null}
      {replayError && !replayBundle ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          Replay snapshot unavailable: {replayError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Operator evidence pack</strong>
            <span className="artifact-hub-policy-pill">Full payloads</span>
          </div>
          <p>
            Export the canonical trace bundle with artifact payloads intact so a
            local reviewer can inspect receipts, replay history, and retained
            artifacts together.
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {onExportBundle ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onExportBundle("operator_share");
                }}
                disabled={isExporting}
              >
                {isExporting ? "Packaging..." : "Export Evidence Pack"}
              </button>
            ) : null}
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Redacted review pack</strong>
            <span className="artifact-hub-policy-pill">No payloads</span>
          </div>
          <p>
            Export a lighter review-oriented pack that keeps the trace,
            receipts, and bundle manifest while omitting artifact payload
            bodies.
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {onExportBundle ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onExportBundle("redacted_share");
                }}
                disabled={isExporting}
              >
                {isExporting ? "Packaging..." : "Export Redacted Pack"}
              </button>
            ) : null}
          </div>
        </section>
      </div>

      {exportPath ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Latest packaged artifact</strong>
            <span className="artifact-hub-policy-pill">Local path</span>
          </div>
          <p className="artifact-hub-generic-summary" title={exportPath}>
            {exportPath}
          </p>
        </section>
      ) : null}

      <SavedBundleProofCard
        overview={savedBundleProof}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="export"
      />

      <ArtifactPipelineAutomationCard
        plan={artifactAutomationPlan}
        busy={artifactAutomationBusy}
        message={artifactAutomationMessage}
        error={artifactAutomationError}
        onRun={(action) => {
          void runArtifactAutomationPlan(action);
        }}
        onOpenView={onOpenView}
      />

      <RetainedPortfolioDossierCard
        dossier={dossier}
        onExportRecommendedPack={
          onExportBundle
            ? async () => {
                await onExportBundle(dossier.recommendedVariant);
              }
            : undefined
        }
        onOpenView={onOpenView}
        secondaryView="export"
      />

      <PromotionStageCard
        dossier={dossier}
        exportPath={exportPath}
        exportVariant={exportVariant}
        busyTarget={promotionStageBusyTarget}
        message={promotionStageMessage}
        error={promotionStageError}
        onStagePromotionCandidate={onStagePromotionCandidate}
        onOpenView={onOpenView}
      />

      <DurabilityEvidenceCard
        overview={durabilityOverview}
        onOpenView={onOpenView}
      />
      <PrivacyEvidenceCard overview={privacyOverview} onOpenView={onOpenView} />

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Related surfaces</strong>
          <span className="artifact-hub-policy-pill">Same runtime truth</span>
        </div>
        <p>
          Share stays a projection over the canonical export and replay flow so
          evidence packaging does not fork away from the underlying session
          truth.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("export")}
            >
              Export Evidence
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

      {replayLoading && !replayBundle ? (
        <p className="artifact-hub-empty">
          Loading the retained replay snapshot for share preview.
        </p>
      ) : null}
    </div>
  );
}
