import { formatSessionTimeAgo } from "@ioi/agent-ide";
import { useMemo, useState } from "react";
import type {
  ArtifactHubViewKey,
  LocalEngineSnapshot,
  SessionHookSnapshot,
  SessionPluginSnapshot,
  SessionRemoteEnvSnapshot,
  SessionServerSnapshot,
} from "../../../../types";
import type { ChatLocalEngineStatus } from "../../hooks/useChatLocalEngine";
import type { ChatPluginsStatus } from "../../hooks/useChatPlugins";
import type { ChatServerModeStatus } from "../../hooks/useChatServerMode";
import type { ChatRemoteContinuityLaunchRequest } from "../artifactHubRemoteContinuityModel";
import type { SessionPermissionProfileId, ShieldRememberedApprovalSnapshot, CapabilityGovernanceRequest } from "../../../../surfaces/Policy/policyCenter";
import {
  openEvidenceReviewSession,
  openReviewCapabilities,
  openReviewPolicyCenter,
} from "../../../../services/reviewNavigation";
import { buildPluginRolloutAutomationPlan } from "../../utils/pluginRolloutAutomationModel";
import { buildAuthorityAutomationPlan } from "../../utils/authorityAutomationModel";
import {
  buildPluginRolloutDossier,
  buildPluginRolloutStageDraft,
} from "../../utils/pluginRolloutModel";
import { RemoteContinuityPolicyCard } from "../ArtifactHubRemoteContinuityPolicyCard";
import {
  formatTaskTimestamp,
  humanizeStatus,
} from "../ArtifactHubViewHelpers";
import { buildHookControlOverview } from "../artifactHubHookControlModel";
import { buildServerOverview } from "../artifactHubServerModel";
import { buildRemoteContinuityGovernanceOverview } from "../artifactHubRemoteContinuityGovernanceModel";
import { buildServerRemoteContinuityPolicyOverview } from "../artifactHubRemoteContinuityPolicyModel";
import { buildRemoteSessionContinuityAction } from "../artifactHubRemoteContinuityModel";
import { getSessionOperatorRuntime } from "../../../../services/sessionRuntime";

export function ServerView({
  snapshot,
  status,
  error,
  remoteEnvSnapshot,
  managedSettings,
  onRefreshServer,
  onRequestReplLaunch,
  onOpenView,
}: {
  snapshot: SessionServerSnapshot | null;
  status: ChatServerModeStatus;
  error: string | null;
  remoteEnvSnapshot: SessionRemoteEnvSnapshot | null;
  managedSettings: LocalEngineSnapshot["managedSettings"] | null;
  onRefreshServer?: () => Promise<unknown>;
  onRequestReplLaunch?: (request: ChatRemoteContinuityLaunchRequest) => void;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = buildServerOverview(snapshot);
  const governance = useMemo(
    () => buildRemoteContinuityGovernanceOverview(snapshot),
    [snapshot],
  );
  const policyOverview = useMemo(
    () =>
      buildServerRemoteContinuityPolicyOverview({
        serverSnapshot: snapshot,
        remoteEnvSnapshot,
        managedSettings,
      }),
    [managedSettings, remoteEnvSnapshot, snapshot],
  );
  const recentSessions = snapshot?.recentRemoteSessions ?? [];
  const notes = snapshot?.notes ?? [];

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Server</span>
        <strong>{snapshot?.continuityModeLabel || "Server continuity"}</strong>
        <p>{overview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Tone: {humanizeStatus(overview.tone)}</span>
          <span>Projection: {humanizeStatus(status)}</span>
          <span>{snapshot?.kernelConnectionLabel || "Unknown"}</span>
          <span>{snapshot?.rpcSourceLabel || "No RPC target"}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{overview.statusLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.kernelConnectionLabel || "Unknown"}
            </span>
          </div>
          <p>
            {snapshot?.kernelConnectionDetail ||
              "Open a retained session to inspect the kernel RPC target and continuity posture."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {overview.continuityMeta.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {overview.historyMeta.map((item) => (
              <span key={item}>{item}</span>
            ))}
            <span>
              {snapshot?.currentSessionVisibleRemotely
                ? "Current session visible remotely"
                : "Current session local only"}
            </span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Continuity notes</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.rpcUrl || "No RPC target"}
            </span>
          </div>
          {notes.length > 0 ? (
            <div className="artifact-hub-permissions-list">
              {notes.map((note, index) => (
                <div
                  key={`${note}-${index}`}
                  className="artifact-hub-permissions-list__row"
                >
                  <div>
                    <strong>Retained signal</strong>
                    <p>{note}</p>
                  </div>
                  <span>Runtime</span>
                </div>
              ))}
            </div>
          ) : (
            <p>No continuity notes are retained for this shell yet.</p>
          )}
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Current session continuity</strong>
            <span className="artifact-hub-policy-pill">
              {overview.currentSessionLabel}
            </span>
          </div>
          <p>{overview.currentSessionDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>
              {snapshot?.remoteAttachableSessionCount ?? 0} remote attachable
            </span>
            <span>
              {snapshot?.remoteHistoryOnlySessionCount ?? 0} remote history-only
            </span>
            <span>
              {snapshot?.currentSessionVisibleRemotely
                ? "Current session mirrored"
                : "Current session local only"}
            </span>
          </div>
        </section>

        <section
          className={`artifact-hub-permissions-card ${
            governance.tone === "review" || governance.tone === "attention"
              ? "artifact-hub-permissions-card--alert"
              : ""
          }`}
        >
          <div className="artifact-hub-permissions-card__head">
            <strong>{governance.statusLabel}</strong>
            <span className="artifact-hub-policy-pill">
              {humanizeStatus(governance.tone)}
            </span>
          </div>
          <p>{governance.detail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {governance.checklist.map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
          {governance.primaryAction ? (
            <p className="artifact-hub-generic-summary">
              {governance.primaryAction.detail}
            </p>
          ) : null}
          <div className="artifact-hub-permissions-card__actions">
            {governance.primaryAction && onRequestReplLaunch ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  onRequestReplLaunch(governance.primaryAction!.launchRequest);
                }}
              >
                {governance.primaryAction.label}
              </button>
            ) : null}
            {governance.secondaryAction && onRequestReplLaunch ? (
              <button
                type="button"
                className="artifact-hub-open-btn secondary"
                onClick={() => {
                  onRequestReplLaunch(
                    governance.secondaryAction!.launchRequest,
                  );
                }}
              >
                {governance.secondaryAction.label}
              </button>
            ) : null}
            {!governance.primaryAction && onRefreshServer ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                onClick={() => {
                  void onRefreshServer();
                }}
              >
                Refresh server snapshot
              </button>
            ) : null}
          </div>
        </section>

        <RemoteContinuityPolicyCard
          title={policyOverview.statusLabel}
          overview={policyOverview}
          onRequestReplLaunch={onRequestReplLaunch}
          onOpenView={onOpenView}
          onRefreshServer={onRefreshServer}
        />
      </div>

      {recentSessions.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Recent remote sessions</span>
            <span>{recentSessions.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {recentSessions.map((session) => (
              <article
                className="artifact-hub-generic-row"
                key={session.sessionId}
              >
                {(() => {
                  const continuityAction =
                    buildRemoteSessionContinuityAction(session);
                  return (
                    <>
                      <div className="artifact-hub-generic-meta">
                        <span>{session.sourceLabel}</span>
                        <span>{formatSessionTimeAgo(session.timestamp)}</span>
                        <span>{session.presenceLabel}</span>
                      </div>
                      <div className="artifact-hub-generic-title">
                        {session.title}
                      </div>
                      <p className="artifact-hub-generic-summary">
                        {session.resumeHint ||
                          session.workspaceRoot ||
                          "Retained remote history merged into the shared session projection."}
                      </p>
                      <p className="artifact-hub-generic-summary">
                        {continuityAction.detail}
                      </p>
                      <div className="artifact-hub-generic-actions">
                        {onRequestReplLaunch ? (
                          <button
                            type="button"
                            className="artifact-hub-open-btn"
                            onClick={() => {
                              onRequestReplLaunch(
                                continuityAction.launchRequest,
                              );
                            }}
                          >
                            {continuityAction.chatShellLabel}
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="artifact-hub-open-btn secondary"
                          onClick={() => {
                            void openEvidenceReviewSession(session.sessionId);
                          }}
                        >
                          {continuityAction.studioLabel}
                        </button>
                      </div>
                    </>
                  );
                })()}
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No remote-retained sessions are visible yet. Once the kernel publishes
          retained history, this surface will show which sessions arrived
          remotely and whether they merge cleanly with local evidence.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Related controls</strong>
          <span className="artifact-hub-policy-pill">Next steps</span>
        </div>
        <p>
          Server continuity stays grounded in the same runtime-owned session
          projection as Chat, retained sessions, and the standalone REPL.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onRefreshServer ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onRefreshServer();
              }}
            >
              Refresh server
            </button>
          ) : null}
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
              onClick={() => onOpenView("remote_env")}
            >
              Inspect Runtime Env
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

export function PluginsView({
  snapshot,
  status,
  error,
  onRefreshPlugins,
  onTrustPlugin,
  onSetPluginEnabled,
  onReloadPlugin,
  onRefreshPluginCatalog,
  onRevokePluginTrust,
  onInstallPluginPackage,
  onUpdatePluginPackage,
  onRemovePluginPackage,
  onOpenView,
}: {
  snapshot: SessionPluginSnapshot | null;
  status: ChatPluginsStatus;
  error: string | null;
  onRefreshPlugins?: () => Promise<unknown>;
  onTrustPlugin?: (
    pluginId: string,
    enableAfterTrust?: boolean,
  ) => Promise<unknown>;
  onSetPluginEnabled?: (pluginId: string, enabled: boolean) => Promise<unknown>;
  onReloadPlugin?: (pluginId: string) => Promise<unknown>;
  onRefreshPluginCatalog?: (pluginId: string) => Promise<unknown>;
  onRevokePluginTrust?: (pluginId: string) => Promise<unknown>;
  onInstallPluginPackage?: (pluginId: string) => Promise<unknown>;
  onUpdatePluginPackage?: (pluginId: string) => Promise<unknown>;
  onRemovePluginPackage?: (pluginId: string) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const plugins = snapshot?.plugins ?? [];
  const receipts = snapshot?.recentReceipts ?? [];
  const workspaceLabel =
    snapshot?.workspaceRoot?.trim() || "No active workspace";
  const busy = status === "loading";
  const rolloutDossier = useMemo(
    () => buildPluginRolloutDossier(snapshot),
    [snapshot],
  );
  const rolloutAutomationPlan = useMemo(
    () => buildPluginRolloutAutomationPlan(snapshot),
    [snapshot],
  );
  const [rolloutStageBusy, setRolloutStageBusy] = useState(false);
  const [rolloutStageMessage, setRolloutStageMessage] = useState<string | null>(
    null,
  );
  const [rolloutStageError, setRolloutStageError] = useState<string | null>(
    null,
  );
  const [rolloutAutomationBusy, setRolloutAutomationBusy] = useState(false);
  const [rolloutAutomationMessage, setRolloutAutomationMessage] = useState<
    string | null
  >(null);
  const [rolloutAutomationError, setRolloutAutomationError] = useState<
    string | null
  >(null);

  const stageRolloutReview = async () => {
    setRolloutStageBusy(true);
    setRolloutStageMessage(null);
    setRolloutStageError(null);
    try {
      const draft = buildPluginRolloutStageDraft({
        dossier: rolloutDossier,
        snapshot,
      });
      await getSessionOperatorRuntime().stageLocalEngineOperation(draft);
      setRolloutStageMessage(
        `Staged '${rolloutDossier.title}' in the Local Engine queue with remote catalog context attached.`,
      );
    } catch (stageError) {
      setRolloutStageError(
        stageError instanceof Error ? stageError.message : String(stageError),
      );
    } finally {
      setRolloutStageBusy(false);
    }
  };

  const runRolloutAutomationPlan = async (
    action = rolloutAutomationPlan.queuedActions[0] ?? {
      kind: rolloutAutomationPlan.primaryActionKind,
      label: rolloutAutomationPlan.primaryActionLabel ?? "Run rollout action",
      pluginId: rolloutAutomationPlan.pluginId,
      detail: rolloutAutomationPlan.detail,
    },
  ) => {
    setRolloutAutomationBusy(true);
    setRolloutAutomationMessage(null);
    setRolloutAutomationError(null);
    try {
      switch (action.kind) {
        case "refresh_inventory":
          if (!onRefreshPlugins) {
            throw new Error("Plugin inventory refresh is unavailable.");
          }
          await onRefreshPlugins();
          setRolloutAutomationMessage(
            "Refreshed the plugin inventory for rollout automation review.",
          );
          break;
        case "refresh_catalog":
          if (!action.pluginId || !onRefreshPluginCatalog) {
            throw new Error("Catalog refresh automation is unavailable.");
          }
          await onRefreshPluginCatalog(action.pluginId);
          setRolloutAutomationMessage(
            `Triggered catalog refresh for ${action.pluginId}.`,
          );
          break;
        case "install_package":
          if (!action.pluginId || !onInstallPluginPackage) {
            throw new Error(
              "Managed package install automation is unavailable.",
            );
          }
          await onInstallPluginPackage(action.pluginId);
          setRolloutAutomationMessage(
            `Installed the managed package copy for ${action.pluginId}.`,
          );
          break;
        case "apply_update":
          if (!action.pluginId || !onUpdatePluginPackage) {
            throw new Error(
              "Managed package update automation is unavailable.",
            );
          }
          await onUpdatePluginPackage(action.pluginId);
          setRolloutAutomationMessage(
            `Applied the managed package update for ${action.pluginId}.`,
          );
          break;
        case "trust_and_enable":
          if (!action.pluginId || !onTrustPlugin) {
            throw new Error("Trust automation is unavailable.");
          }
          await onTrustPlugin(action.pluginId, true);
          setRolloutAutomationMessage(
            `Trusted and enabled ${action.pluginId} for runtime load.`,
          );
          break;
        case "stage_review":
          await stageRolloutReview();
          setRolloutAutomationMessage(
            "Staged the rollout review dossier from the automation plan.",
          );
          break;
        case "none":
        default:
          setRolloutAutomationMessage(
            "Rollout automation does not have a pending action right now.",
          );
          break;
      }
    } catch (automationError) {
      setRolloutAutomationError(
        automationError instanceof Error
          ? automationError.message
          : String(automationError),
      );
    } finally {
      setRolloutAutomationBusy(false);
    }
  };

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Plugins</span>
        <strong>Plugin trust and lifecycle posture</strong>
        <p>
          Review tracked plugins and catalog-backed packages as runtime
          subjects: authenticity signals, requested capabilities, remembered
          trust, package install posture, update posture, and the latest
          lifecycle receipts.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          <span>Workspace: {workspaceLabel}</span>
          <span>{snapshot?.pluginCount ?? 0} plugins</span>
          <span>{snapshot?.recommendedPluginCount ?? 0} recommended</span>
          <span>
            {snapshot?.reviewRequiredPluginCount ?? 0} review required
          </span>
          <span>{snapshot?.criticalUpdateCount ?? 0} critical updates</span>
          <span>{snapshot?.refreshAvailableCount ?? 0} refresh available</span>
          <span>{snapshot?.refreshFailedCount ?? 0} refresh failed</span>
          <span>{snapshot?.catalogSourceCount ?? 0} catalog sources</span>
          <span>{snapshot?.remoteCatalogSourceCount ?? 0} remote sources</span>
          <span>{snapshot?.localCatalogSourceCount ?? 0} local sources</span>
          <span>{snapshot?.failedCatalogSourceCount ?? 0} failed sources</span>
          <span>{snapshot?.catalogChannelCount ?? 0} catalog channels</span>
          <span>{snapshot?.nonconformantChannelCount ?? 0} nonconformant</span>
          <span>
            {snapshot?.nonconformantSourceCount ?? 0} nonconformant sources
          </span>
          <span>{snapshot?.staleCatalogCount ?? 0} stale catalogs</span>
          <span>{snapshot?.expiredCatalogCount ?? 0} expired catalogs</span>
          <span>{snapshot?.verifiedPluginCount ?? 0} verified</span>
          <span>
            {snapshot?.unverifiedPluginCount ?? 0} unsigned/unverified
          </span>
          <span>{snapshot?.signatureMismatchPluginCount ?? 0} mismatch</span>
          <span>{snapshot?.trustedPluginCount ?? 0} trusted</span>
          <span>{snapshot?.enabledPluginCount ?? 0} runtime enabled</span>
          <span>{snapshot?.managedPackageCount ?? 0} managed packages</span>
          <span>{snapshot?.updateAvailableCount ?? 0} updates ready</span>
          <span>{snapshot?.blockedPluginCount ?? 0} blocked</span>
          <span>{snapshot?.reloadablePluginCount ?? 0} reloadable</span>
          <span>{snapshot?.recentReceiptCount ?? 0} recent receipts</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>{rolloutDossier.title}</strong>
          <span className="artifact-hub-policy-pill">
            {rolloutDossier.readinessLabel}
          </span>
        </div>
        <p>{rolloutDossier.summary}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{rolloutDossier.sourceSummary}</span>
          <span>{snapshot?.pluginCount ?? 0} tracked plugins</span>
          <span>{snapshot?.remoteCatalogSourceCount ?? 0} remote sources</span>
        </div>
        <p className="artifact-hub-generic-summary">
          {rolloutDossier.checklist.join(" · ")}
        </p>
        {rolloutStageMessage ? (
          <p className="artifact-hub-note">{rolloutStageMessage}</p>
        ) : null}
        {rolloutStageError ? (
          <p className="artifact-hub-note artifact-hub-note--error">
            {rolloutStageError}
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => {
              void stageRolloutReview();
            }}
            disabled={rolloutStageBusy || !snapshot}
          >
            {rolloutStageBusy ? "Staging..." : "Stage rollout review"}
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

      <section
        className={`artifact-hub-permissions-card ${
          rolloutAutomationPlan.tone === "review"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <div className="artifact-hub-permissions-card__head">
          <strong>{rolloutAutomationPlan.statusLabel}</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(rolloutAutomationPlan.tone)}
          </span>
        </div>
        <p>{rolloutAutomationPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {rolloutAutomationPlan.checklist.map((item) => (
            <span key={item}>{item}</span>
          ))}
          {rolloutAutomationPlan.queuedActions.length > 1 ? (
            <span>
              {rolloutAutomationPlan.queuedActions.length} queued rollout steps
            </span>
          ) : null}
          {rolloutAutomationPlan.governanceNotes.length > 0 ? (
            <span>
              {rolloutAutomationPlan.governanceNotes.length} governed review{" "}
              {rolloutAutomationPlan.governanceNotes.length === 1
                ? "gate"
                : "gates"}
            </span>
          ) : null}
        </div>
        {rolloutAutomationPlan.governanceNotes.length > 0 ? (
          <div className="artifact-hub-permissions-list">
            {rolloutAutomationPlan.governanceNotes.map((note, index) => (
              <div
                key={`${note.pluginId ?? "session"}:${note.label}:${index}`}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{note.label}</strong>
                  <p>{note.detail}</p>
                </div>
                <span className="artifact-hub-policy-pill">
                  {humanizeStatus(note.severity)}
                </span>
              </div>
            ))}
          </div>
        ) : null}
        {rolloutAutomationPlan.queuedActions.length > 1 ? (
          <div className="artifact-hub-permissions-list">
            {rolloutAutomationPlan.queuedActions.map((action, index) => (
              <div
                key={`${action.kind}:${action.pluginId ?? index}`}
                className="artifact-hub-permissions-list__row"
              >
                <div>
                  <strong>{action.label}</strong>
                  <p>{action.detail}</p>
                </div>
                <button
                  type="button"
                  className="artifact-hub-open-btn secondary"
                  disabled={rolloutAutomationBusy}
                  onClick={() => {
                    void runRolloutAutomationPlan(action);
                  }}
                >
                  Run step
                </button>
              </div>
            ))}
          </div>
        ) : null}
        {rolloutAutomationMessage ? (
          <p className="artifact-hub-note">{rolloutAutomationMessage}</p>
        ) : null}
        {rolloutAutomationError ? (
          <p className="artifact-hub-note artifact-hub-note--error">
            {rolloutAutomationError}
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {rolloutAutomationPlan.primaryActionLabel ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={rolloutAutomationBusy}
              onClick={() => {
                void runRolloutAutomationPlan();
              }}
            >
              {rolloutAutomationBusy
                ? "Running..."
                : rolloutAutomationPlan.primaryActionLabel}
            </button>
          ) : null}
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

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>
              {snapshot?.verifiedPluginCount ?? 0} verified packages
            </strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.signatureMismatchPluginCount ?? 0} mismatch
            </span>
          </div>
          <p>
            Authenticity and runtime trust are separate. A plugin can be
            signature-verified but still require operator trust before runtime
            load, or it can remain visible from a local or catalog source while
            authenticity stays unresolved.
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>{snapshot?.managedPackageCount ?? 0} managed packages</span>
            <span>
              {snapshot?.installablePackageCount ?? 0} ready to install
            </span>
            <span>{snapshot?.recommendedPluginCount ?? 0} recommended</span>
            <span>
              {snapshot?.reviewRequiredPluginCount ?? 0} review required
            </span>
            <span>{snapshot?.criticalUpdateCount ?? 0} critical updates</span>
            <span>
              {snapshot?.refreshAvailableCount ?? 0} refresh available
            </span>
            <span>{snapshot?.refreshFailedCount ?? 0} refresh failed</span>
            <span>{snapshot?.catalogSourceCount ?? 0} catalog sources</span>
            <span>
              {snapshot?.remoteCatalogSourceCount ?? 0} remote sources
            </span>
            <span>{snapshot?.staleCatalogCount ?? 0} stale catalogs</span>
            <span>{snapshot?.filesystemSkillCount ?? 0} filesystem skills</span>
            <span>
              {snapshot?.hookContributionCount ?? 0} hook contributions
            </span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Plugin actions</strong>
            <span className="artifact-hub-policy-pill">Lifecycle controls</span>
          </div>
          <p>
            Trust once, manage a profile-local package copy, enable or disable
            runtime load, reload with remembered trust, or revoke trust to force
            the next load back through a gate.
          </p>
          <div className="artifact-hub-permissions-card__actions">
            {onRefreshPlugins ? (
              <button
                type="button"
                className="artifact-hub-open-btn"
                disabled={busy}
                onClick={() => {
                  void onRefreshPlugins();
                }}
              >
                Refresh plugin inventory
              </button>
            ) : null}
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => void openReviewCapabilities()}
            >
              Open Chat Capabilities
            </button>
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => void openReviewPolicyCenter()}
            >
              Open Governing Policy
            </button>
          </div>
        </section>
      </div>

      {(snapshot?.catalogSources.length ?? 0) > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Catalog sources</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.catalogSourceCount ?? 0} visible
            </span>
          </div>
          <p>
            External marketplace sources are tracked separately from channel and
            plugin state so refresh failures, stale mirrors, and source-level
            conformance problems stay attributable to the right distribution
            origin.
          </p>
          <div className="artifact-hub-generic-list">
            {snapshot?.catalogSources.map((source) => (
              <article
                className="artifact-hub-generic-row"
                key={source.sourceId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{source.label}</span>
                  {source.channel ? <span>{source.channel}</span> : null}
                  <span>
                    {source.transportKind === "remote_url"
                      ? "Remote URL"
                      : "Local path"}
                  </span>
                  <span>{source.statusLabel}</span>
                  <span>{source.conformanceLabel}</span>
                  <span>{source.validCatalogCount} valid catalogs</span>
                  {source.invalidCatalogCount > 0 ? (
                    <span>{source.invalidCatalogCount} invalid catalogs</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">
                  {source.sourceId}
                </div>
                <p className="artifact-hub-generic-summary">
                  {source.statusDetail}
                </p>
                {source.conformanceError ? (
                  <p className="artifact-hub-generic-summary">
                    {source.conformanceError}
                  </p>
                ) : null}
                {source.refreshError ? (
                  <p className="artifact-hub-generic-summary">
                    {source.refreshError}
                  </p>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{source.catalogCount} channel catalogs</span>
                  <span>Source URI: {source.sourceUri}</span>
                  {source.authorityBundleLabel ? (
                    <span>Authority bundle: {source.authorityBundleLabel}</span>
                  ) : null}
                  {source.authorityBundleId ? (
                    <span>Bundle ID: {source.authorityBundleId}</span>
                  ) : null}
                  {source.lastSuccessfulRefreshAtMs ? (
                    <span>
                      Last success{" "}
                      {formatTaskTimestamp(source.lastSuccessfulRefreshAtMs)}
                    </span>
                  ) : null}
                  {source.lastFailedRefreshAtMs ? (
                    <span>
                      Last failure{" "}
                      {formatTaskTimestamp(source.lastFailedRefreshAtMs)}
                    </span>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {(snapshot?.catalogChannels.length ?? 0) > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Catalog channels</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.catalogChannelCount ?? 0} visible
            </span>
          </div>
          <p>
            Signed marketplace channels are tracked separately from individual
            plugins so refresh failures, stale feeds, and nonconformant channel
            entries surface before they are mistaken for plugin-specific risk.
          </p>
          <div className="artifact-hub-generic-list">
            {snapshot?.catalogChannels.map((channel) => (
              <article
                className="artifact-hub-generic-row"
                key={`${channel.catalogId}:${channel.channel ?? "default"}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{channel.label}</span>
                  {channel.channel ? <span>{channel.channel}</span> : null}
                  <span>{channel.statusLabel}</span>
                  <span>{channel.conformanceLabel}</span>
                  <span>{channel.validPluginCount} valid</span>
                  {channel.invalidPluginCount > 0 ? (
                    <span>{channel.invalidPluginCount} invalid</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">
                  {channel.catalogId}
                </div>
                <p className="artifact-hub-generic-summary">
                  {channel.statusDetail}
                </p>
                {channel.conformanceError ? (
                  <p className="artifact-hub-generic-summary">
                    {channel.conformanceError}
                  </p>
                ) : null}
                {channel.refreshError ? (
                  <p className="artifact-hub-generic-summary">
                    {channel.refreshError}
                  </p>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{channel.pluginCount} published entries</span>
                  <span>{channel.refreshBundleCount} refresh bundles</span>
                  {channel.issuedAtMs ? (
                    <span>
                      Issued {formatTaskTimestamp(channel.issuedAtMs)}
                    </span>
                  ) : null}
                  {channel.refreshedAtMs ? (
                    <span>
                      Refreshed {formatTaskTimestamp(channel.refreshedAtMs)}
                    </span>
                  ) : null}
                  {channel.expiresAtMs ? (
                    <span>
                      Expires {formatTaskTimestamp(channel.expiresAtMs)}
                    </span>
                  ) : null}
                  {channel.refreshSource ? (
                    <span>Source: {humanizeStatus(channel.refreshSource)}</span>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {receipts.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent plugin lifecycle receipts</strong>
            <span className="artifact-hub-policy-pill">
              {receipts.length} retained
            </span>
          </div>
          <p>
            Latest remembered-trust, enable, reload, and revoke outcomes for the
            runtime plugin roster.
          </p>
          <div className="artifact-hub-generic-list">
            {receipts.slice(0, 4).map((receipt) => (
              <article
                className="artifact-hub-generic-row"
                key={receipt.receiptId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{receipt.pluginLabel}</span>
                  <span>{humanizeStatus(receipt.action)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                  <span>{formatTaskTimestamp(receipt.timestampMs)}</span>
                </div>
                <p className="artifact-hub-generic-summary">
                  {receipt.summary}
                </p>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {plugins.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Visible plugins</span>
            <span>{plugins.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {plugins.map((plugin) => (
              <article
                className="artifact-hub-generic-row"
                key={plugin.pluginId}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{plugin.sourceLabel}</span>
                  <span>{plugin.statusLabel}</span>
                  <span>{plugin.sessionScopeLabel}</span>
                  <span>{plugin.operatorReviewLabel}</span>
                  <span>{plugin.catalogStatusLabel}</span>
                  {plugin.updateSeverityLabel ? (
                    <span>{plugin.updateSeverityLabel}</span>
                  ) : null}
                </div>
                <div className="artifact-hub-generic-title">{plugin.label}</div>
                <p className="artifact-hub-generic-summary">
                  {plugin.whyAvailable}
                </p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{plugin.authorityTierLabel}</span>
                  <span>{humanizeStatus(plugin.trustPosture)}</span>
                  <span>{humanizeStatus(plugin.governedProfile)}</span>
                  <span>{plugin.authenticityLabel}</span>
                  <span>{plugin.runtimeTrustLabel}</span>
                  <span>{plugin.runtimeLoadLabel}</span>
                  <span>{plugin.packageInstallLabel}</span>
                  <span>Review: {plugin.operatorReviewLabel}</span>
                  <span>Catalog: {plugin.catalogStatusLabel}</span>
                  {plugin.catalogSourceLabel ? (
                    <span>Winning source: {plugin.catalogSourceLabel}</span>
                  ) : null}
                  {plugin.updateSeverityLabel ? (
                    <span>Update: {plugin.updateSeverityLabel}</span>
                  ) : null}
                  <span>{plugin.reloadabilityLabel}</span>
                  <span>{plugin.contributionCount} contributions</span>
                  <span>{plugin.filesystemSkillCount} filesystem skills</span>
                </div>
                <p className="artifact-hub-generic-summary">
                  {plugin.authenticityDetail}
                </p>
                <p className="artifact-hub-generic-summary">
                  {plugin.operatorReviewReason}
                </p>
                <p className="artifact-hub-generic-summary">
                  {plugin.catalogStatusDetail}
                </p>
                {plugin.updateDetail ? (
                  <p className="artifact-hub-generic-summary">
                    {plugin.updateDetail}
                  </p>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  {plugin.publisherLabel ? (
                    <span>Publisher: {plugin.publisherLabel}</span>
                  ) : null}
                  {plugin.catalogSourceUri ? (
                    <span>Catalog source URI: {plugin.catalogSourceUri}</span>
                  ) : null}
                  {plugin.publisherId ? (
                    <span>Publisher ID: {plugin.publisherId}</span>
                  ) : null}
                  {plugin.signerIdentity ? (
                    <span>Signer: {plugin.signerIdentity}</span>
                  ) : null}
                  {plugin.signingKeyId ? (
                    <span>Signing key: {plugin.signingKeyId}</span>
                  ) : null}
                  {plugin.verificationAlgorithm ? (
                    <span>
                      Algorithm: {plugin.verificationAlgorithm.toUpperCase()}
                    </span>
                  ) : null}
                  {plugin.verificationTimestampMs ? (
                    <span>
                      Verified{" "}
                      {formatTaskTimestamp(plugin.verificationTimestampMs)}
                    </span>
                  ) : null}
                  {plugin.verificationSource ? (
                    <span>
                      Source: {humanizeStatus(plugin.verificationSource)}
                    </span>
                  ) : null}
                  {plugin.verifiedDigestSha256 ? (
                    <span>
                      Digest sha256:{plugin.verifiedDigestSha256.slice(0, 16)}
                      ...
                    </span>
                  ) : null}
                  {plugin.trustScoreLabel ? (
                    <span>Trust score: {plugin.trustScoreLabel}</span>
                  ) : null}
                  {plugin.trustScoreSource ? (
                    <span>Score source: {plugin.trustScoreSource}</span>
                  ) : null}
                  {plugin.publisherTrustLabel ? (
                    <span>Publisher trust: {plugin.publisherTrustLabel}</span>
                  ) : null}
                  {plugin.publisherTrustSource ? (
                    <span>
                      Publisher source:{" "}
                      {humanizeStatus(plugin.publisherTrustSource)}
                    </span>
                  ) : null}
                  {plugin.publisherRootLabel ? (
                    <span>Trust root: {plugin.publisherRootLabel}</span>
                  ) : null}
                  {plugin.publisherRootId ? (
                    <span>Root ID: {plugin.publisherRootId}</span>
                  ) : null}
                  {plugin.authorityBundleLabel ? (
                    <span>Authority bundle: {plugin.authorityBundleLabel}</span>
                  ) : null}
                  {plugin.authorityBundleId ? (
                    <span>Bundle ID: {plugin.authorityBundleId}</span>
                  ) : null}
                  {plugin.authorityBundleIssuedAtMs ? (
                    <span>
                      Bundle issued{" "}
                      {formatTaskTimestamp(plugin.authorityBundleIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleLabel ? (
                    <span>
                      Trust bundle: {plugin.authorityTrustBundleLabel}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleStatus ? (
                    <span>
                      Trust bundle status:{" "}
                      {humanizeStatus(plugin.authorityTrustBundleStatus)}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleIssuedAtMs ? (
                    <span>
                      Trust bundle issued{" "}
                      {formatTaskTimestamp(
                        plugin.authorityTrustBundleIssuedAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.authorityTrustBundleExpiresAtMs ? (
                    <span>
                      Trust bundle expires{" "}
                      {formatTaskTimestamp(
                        plugin.authorityTrustBundleExpiresAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.authorityTrustIssuerLabel ? (
                    <span>
                      Trust issuer: {plugin.authorityTrustIssuerLabel}
                    </span>
                  ) : null}
                  {plugin.authorityTrustIssuerId ? (
                    <span>
                      Trust issuer ID: {plugin.authorityTrustIssuerId}
                    </span>
                  ) : null}
                  {plugin.authorityLabel ? (
                    <span>Authority: {plugin.authorityLabel}</span>
                  ) : null}
                  {plugin.authorityId ? (
                    <span>Authority ID: {plugin.authorityId}</span>
                  ) : null}
                  {plugin.publisherStatementIssuedAtMs ? (
                    <span>
                      Statement issued{" "}
                      {formatTaskTimestamp(plugin.publisherStatementIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.publisherRevokedAtMs ? (
                    <span>
                      Revoked {formatTaskTimestamp(plugin.publisherRevokedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogIssuedAtMs ? (
                    <span>
                      Catalog issued{" "}
                      {formatTaskTimestamp(plugin.catalogIssuedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshedAtMs ? (
                    <span>
                      Catalog refreshed{" "}
                      {formatTaskTimestamp(plugin.catalogRefreshedAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogExpiresAtMs ? (
                    <span>
                      Catalog expires{" "}
                      {formatTaskTimestamp(plugin.catalogExpiresAtMs)}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshSource ? (
                    <span>
                      Catalog source:{" "}
                      {humanizeStatus(plugin.catalogRefreshSource)}
                    </span>
                  ) : null}
                  {plugin.catalogChannel ? (
                    <span>Catalog channel: {plugin.catalogChannel}</span>
                  ) : null}
                  {plugin.catalogRefreshBundleLabel ? (
                    <span>
                      Refresh bundle: {plugin.catalogRefreshBundleLabel}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleId ? (
                    <span>
                      Refresh bundle ID: {plugin.catalogRefreshBundleId}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleIssuedAtMs ? (
                    <span>
                      Refresh bundle issued{" "}
                      {formatTaskTimestamp(
                        plugin.catalogRefreshBundleIssuedAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshBundleExpiresAtMs ? (
                    <span>
                      Refresh bundle expires{" "}
                      {formatTaskTimestamp(
                        plugin.catalogRefreshBundleExpiresAtMs,
                      )}
                    </span>
                  ) : null}
                  {plugin.catalogRefreshAvailableVersion ? (
                    <span>
                      Refresh advertises {plugin.catalogRefreshAvailableVersion}
                    </span>
                  ) : null}
                  {plugin.lastCatalogRefreshAtMs ? (
                    <span>
                      Last refresh{" "}
                      {formatTaskTimestamp(plugin.lastCatalogRefreshAtMs)}
                    </span>
                  ) : null}
                </div>
                {plugin.publisherTrustDetail ? (
                  <p className="artifact-hub-generic-summary">
                    {plugin.publisherTrustDetail}
                  </p>
                ) : null}
                {plugin.trustRecommendation ? (
                  <p className="artifact-hub-generic-summary">
                    {plugin.trustRecommendation}
                  </p>
                ) : null}
                <p className="artifact-hub-generic-summary">
                  {plugin.runtimeStatusDetail}
                </p>
                <p className="artifact-hub-generic-summary">
                  {plugin.packageInstallDetail}
                </p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Managed package: {plugin.packageManaged ? "yes" : "no"}
                  </span>
                  <span>
                    Install state: {humanizeStatus(plugin.packageInstallState)}
                  </span>
                  {plugin.packageInstallSourceLabel ? (
                    <span>
                      Install source: {plugin.packageInstallSourceLabel}
                    </span>
                  ) : null}
                  {plugin.marketplacePackageUrl ? (
                    <span>Package URI: {plugin.marketplacePackageUrl}</span>
                  ) : null}
                  {plugin.installedVersion ? (
                    <span>Installed {plugin.installedVersion}</span>
                  ) : null}
                  {plugin.availableVersion ? (
                    <span>Available {plugin.availableVersion}</span>
                  ) : null}
                </div>
                {plugin.marketplaceInstallationPolicy ||
                plugin.marketplaceAuthenticationPolicy ||
                plugin.marketplaceProducts.length > 0 ? (
                  <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                    {plugin.marketplaceDisplayName ? (
                      <span>{plugin.marketplaceDisplayName}</span>
                    ) : null}
                    {plugin.marketplaceInstallationPolicy ? (
                      <span>
                        Install policy:{" "}
                        {humanizeStatus(plugin.marketplaceInstallationPolicy)}
                      </span>
                    ) : null}
                    {plugin.marketplaceAuthenticationPolicy ? (
                      <span>
                        Auth:{" "}
                        {humanizeStatus(plugin.marketplaceAuthenticationPolicy)}
                      </span>
                    ) : null}
                    {plugin.marketplaceProducts.map((product) => (
                      <span key={`${plugin.pluginId}-${product}`}>
                        {product}
                      </span>
                    ))}
                  </div>
                ) : null}
                {plugin.requestedCapabilities.length > 0 ? (
                  <details className="artifact-hub-plugin-inspect">
                    <summary>
                      Inspect requested capabilities (
                      {plugin.requestedCapabilities.length})
                    </summary>
                    <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                      {plugin.requestedCapabilities.map((capability) => (
                        <span key={`${plugin.pluginId}-${capability}`}>
                          {capability}
                        </span>
                      ))}
                    </div>
                  </details>
                ) : null}
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>
                    Source tracked: {plugin.sourceEnabled ? "yes" : "no"}
                  </span>
                  <span>
                    Trust remembered: {plugin.trustRemembered ? "yes" : "no"}
                  </span>
                  {plugin.lastTrustedAtMs ? (
                    <span>
                      Trusted {formatTaskTimestamp(plugin.lastTrustedAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastReloadedAtMs ? (
                    <span>
                      Reloaded {formatTaskTimestamp(plugin.lastReloadedAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastInstalledAtMs ? (
                    <span>
                      Installed {formatTaskTimestamp(plugin.lastInstalledAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastUpdatedAtMs ? (
                    <span>
                      Updated {formatTaskTimestamp(plugin.lastUpdatedAtMs)}
                    </span>
                  ) : null}
                  {plugin.lastRemovedAtMs ? (
                    <span>
                      Removed {formatTaskTimestamp(plugin.lastRemovedAtMs)}
                    </span>
                  ) : null}
                </div>
                {plugin.loadError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.loadError}
                  </p>
                ) : null}
                {plugin.verificationError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.verificationError}
                  </p>
                ) : null}
                {plugin.packageError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.packageError}
                  </p>
                ) : null}
                {plugin.catalogRefreshError ? (
                  <p className="artifact-hub-note artifact-hub-note--error">
                    {plugin.catalogRefreshError}
                  </p>
                ) : null}
                <div className="artifact-hub-permissions-card__actions">
                  {(plugin.sourceKind === "marketplace_catalog" ||
                    plugin.marketplaceDisplayName) &&
                  onRefreshPluginCatalog ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onRefreshPluginCatalog(plugin.pluginId);
                      }}
                    >
                      {plugin.catalogStatus === "refresh_available"
                        ? "Apply catalog refresh"
                        : plugin.catalogStatus === "refresh_failed"
                          ? "Retry catalog refresh"
                          : "Refresh catalog"}
                    </button>
                  ) : null}
                  {!plugin.packageManaged && onInstallPluginPackage ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onInstallPluginPackage(plugin.pluginId);
                      }}
                    >
                      Install managed package
                    </button>
                  ) : null}
                  {plugin.packageManaged &&
                  plugin.updateAvailable &&
                  onUpdatePluginPackage ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onUpdatePluginPackage(plugin.pluginId);
                      }}
                    >
                      Apply package update
                    </button>
                  ) : null}
                  {plugin.packageManaged && onRemovePluginPackage ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={busy}
                      onClick={() => {
                        void onRemovePluginPackage(plugin.pluginId);
                      }}
                    >
                      Remove managed package
                    </button>
                  ) : null}
                  {plugin.runtimeTrustState !== "trusted" && onTrustPlugin ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onTrustPlugin(plugin.pluginId, true);
                      }}
                    >
                      Trust and enable
                    </button>
                  ) : null}
                  {plugin.runtimeTrustState === "trusted" &&
                  !plugin.enabled &&
                  onSetPluginEnabled ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onSetPluginEnabled(plugin.pluginId, true);
                      }}
                    >
                      Enable runtime load
                    </button>
                  ) : null}
                  {plugin.enabled && onReloadPlugin ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      disabled={busy}
                      onClick={() => {
                        void onReloadPlugin(plugin.pluginId);
                      }}
                    >
                      Reload plugin
                    </button>
                  ) : null}
                  {plugin.enabled && onSetPluginEnabled ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={busy}
                      onClick={() => {
                        void onSetPluginEnabled(plugin.pluginId, false);
                      }}
                    >
                      Disable runtime load
                    </button>
                  ) : null}
                  {plugin.runtimeTrustState === "trusted" &&
                  onRevokePluginTrust ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      disabled={busy}
                      onClick={() => {
                        void onRevokePluginTrust(plugin.pluginId);
                      }}
                    >
                      Revoke trust
                    </button>
                  ) : null}
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openReviewCapabilities()}
                  >
                    Open Chat Capabilities
                  </button>
                  <button
                    type="button"
                    className="artifact-hub-open-btn secondary"
                    onClick={() => void openReviewPolicyCenter()}
                  >
                    Open Governing Policy
                  </button>
                  {onOpenView ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => onOpenView("hooks")}
                    >
                      Review Hooks
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No tracked or catalog-backed plugins are visible yet. Add a plugin
          source or refresh the active catalog, then reopen Plugins.
        </p>
      )}
    </div>
  );
}

export function HooksView({
  snapshot,
  status,
  error,
  permissionCurrentProfileId,
  permissionApplyingProfileId,
  permissionRememberedApprovals,
  permissionGovernanceRequest,
  permissionActiveOverrideCount,
  onRefreshHooks,
  onApplyPermissionProfile,
  onOpenView,
}: {
  snapshot: SessionHookSnapshot | null;
  status: string;
  error: string | null;
  permissionCurrentProfileId: SessionPermissionProfileId | null;
  permissionApplyingProfileId: SessionPermissionProfileId | null;
  permissionRememberedApprovals: ShieldRememberedApprovalSnapshot | null;
  permissionGovernanceRequest: CapabilityGovernanceRequest | null;
  permissionActiveOverrideCount: number;
  onRefreshHooks?: () => Promise<unknown>;
  onApplyPermissionProfile?: (
    profileId: SessionPermissionProfileId,
  ) => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const hooks = snapshot?.hooks ?? [];
  const receipts = snapshot?.recentReceipts ?? [];
  const workspaceLabel =
    snapshot?.workspaceRoot?.trim() || "No active workspace";
  const controlOverview = buildHookControlOverview(snapshot);
  const authorityAutomationPlan = buildAuthorityAutomationPlan({
    currentProfileId: permissionCurrentProfileId,
    hookSnapshot: snapshot,
    rememberedApprovals: permissionRememberedApprovals,
    governanceRequest: permissionGovernanceRequest,
    activeOverrideCount: permissionActiveOverrideCount,
  });

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          controlOverview.tone === "attention"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">Hooks</span>
        <strong>{controlOverview.statusLabel}</strong>
        <p>{controlOverview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          {controlOverview.meta.map((item) => (
            <span key={item}>{item}</span>
          ))}
          <span>Workspace: {workspaceLabel}</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <section
        className={`artifact-hub-permissions-card ${
          authorityAutomationPlan.tone === "review"
            ? "artifact-hub-permissions-card--alert"
            : ""
        }`}
      >
        <div className="artifact-hub-permissions-card__head">
          <strong>{authorityAutomationPlan.statusLabel}</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(authorityAutomationPlan.tone)}
          </span>
        </div>
        <p>{authorityAutomationPlan.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {authorityAutomationPlan.checklist.map((item) => (
            <span key={item}>{item}</span>
          ))}
          <span>
            Current profile:{" "}
            {permissionCurrentProfileId
              ? humanizeStatus(permissionCurrentProfileId)
              : "Custom posture"}
          </span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {authorityAutomationPlan.recommendedProfileId &&
          onApplyPermissionProfile ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              disabled={
                permissionApplyingProfileId ===
                authorityAutomationPlan.recommendedProfileId
              }
              onClick={() => {
                void onApplyPermissionProfile(
                  authorityAutomationPlan.recommendedProfileId!,
                );
              }}
            >
              {permissionApplyingProfileId ===
              authorityAutomationPlan.recommendedProfileId
                ? `Applying ${humanizeStatus(
                    authorityAutomationPlan.recommendedProfileId,
                  )}...`
                : authorityAutomationPlan.primaryActionLabel}
            </button>
          ) : null}
          {authorityAutomationPlan.recommendedView && onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() =>
                onOpenView(authorityAutomationPlan.recommendedView!)
              }
            >
              {authorityAutomationPlan.recommendedView === "permissions"
                ? "Review Permissions"
                : "Review hooks"}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewPolicyCenter()}
          >
            Open Chat Policy
          </button>
        </div>
      </section>

      {receipts.length > 0 ? (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent runtime hook receipts</strong>
            <span className="artifact-hub-policy-pill">
              {receipts.length} retained
            </span>
          </div>
          <p>
            Latest runtime activity and approval-memory rows that look hook- or
            automation-adjacent for the active session context.
          </p>
          <div className="artifact-hub-generic-list">
            {receipts.slice(0, 4).map((receipt) => (
              <article
                className="artifact-hub-generic-row"
                key={`${receipt.timestampMs}-${receipt.toolName}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{receipt.title}</span>
                  <span>{formatTaskTimestamp(receipt.timestampMs)}</span>
                  <span>{humanizeStatus(receipt.status)}</span>
                </div>
                <div className="artifact-hub-generic-title">
                  {receipt.toolName}
                </div>
                <p className="artifact-hub-generic-summary">
                  {receipt.summary}
                </p>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Recent runtime hook receipts</strong>
            <span className="artifact-hub-policy-pill">None retained</span>
          </div>
          <p>
            No hook-adjacent runtime receipts have been retained yet for this
            session context.
          </p>
        </section>
      )}

      {hooks.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Runtime-visible hooks</span>
            <span>{hooks.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {hooks.map((hook) => (
              <article className="artifact-hub-generic-row" key={hook.hookId}>
                <div className="artifact-hub-generic-meta">
                  <span>{hook.ownerLabel}</span>
                  <span>{hook.statusLabel}</span>
                  <span>{hook.sessionScopeLabel}</span>
                </div>
                <div className="artifact-hub-generic-title">{hook.label}</div>
                <p className="artifact-hub-generic-summary">{hook.whyActive}</p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{hook.triggerLabel}</span>
                  <span>{humanizeStatus(hook.trustPosture)}</span>
                  <span>{humanizeStatus(hook.governedProfile)}</span>
                  <span>{hook.authorityTierLabel}</span>
                  <span>{hook.availabilityLabel}</span>
                </div>
                <div className="artifact-hub-permissions-card__actions">
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openReviewCapabilities()}
                  >
                    Open Chat Capabilities
                  </button>
                  <button
                    type="button"
                    className="artifact-hub-open-btn"
                    onClick={() => void openReviewPolicyCenter()}
                  >
                    Open Governing Policy
                  </button>
                  {onOpenView ? (
                    <button
                      type="button"
                      className="artifact-hub-open-btn secondary"
                      onClick={() => onOpenView("permissions")}
                    >
                      Review session permissions
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No runtime-visible hook contributions are retained for this session
          yet. Track or enable an extension with a `hooks` contribution, then
          reopen this drawer.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Hook control plane</strong>
          <span className="artifact-hub-policy-pill">
            {humanizeStatus(controlOverview.tone)}
          </span>
        </div>
        <p>{controlOverview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          {controlOverview.meta.map((item) => (
            <span key={item}>{item}</span>
          ))}
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onRefreshHooks ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onRefreshHooks();
              }}
            >
              Refresh hooks
            </button>
          ) : null}
          {controlOverview.recommendedView && onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => onOpenView(controlOverview.recommendedView!)}
            >
              {controlOverview.recommendedActionLabel}
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openReviewCapabilities()}
          >
            Open Chat Capabilities
          </button>
          <button
            type="button"
            className="artifact-hub-open-btn"
            onClick={() => void openReviewPolicyCenter()}
          >
            Open Governing Policy
          </button>
        </div>
      </section>
    </div>
  );
}

export function CapabilityInventoryView({
  localEngineSnapshot,
  localEngineStatus,
  localEngineError,
}: {
  localEngineSnapshot: LocalEngineSnapshot | null;
  localEngineStatus: ChatLocalEngineStatus;
  localEngineError: string | null;
}) {
  const capabilities = localEngineSnapshot?.capabilities ?? [];
  const availableCount = capabilities.filter(
    (capability) => capability.status.toLowerCase() === "available",
  ).length;

  return (
    <div className="artifact-hub-stack" data-testid="capability-inventory-view">
      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <div>
            <strong>Authoritative Runtime Capability Inventory</strong>
            <p>
              Kernel-owned categories, status, and evidence expectations. This
              is runtime state, not a model-generated capability claim.
            </p>
          </div>
          <span>{localEngineStatus}</span>
        </div>
        {localEngineError ? <p>{localEngineError}</p> : null}
        <p>
          {availableCount}/{capabilities.length} categories available from{" "}
          {localEngineSnapshot?.controlPlaneProfileId || "the active runtime profile"}.
        </p>
      </section>

      {capabilities.length === 0 ? (
        <section className="artifact-hub-permissions-card artifact-hub-permissions-card--alert">
          <div className="artifact-hub-permissions-card__head">
            <strong>No capability registry projected</strong>
            <span>Projection missing</span>
          </div>
          <p>
            The chat surface could not load an authoritative capability
            inventory for this profile.
          </p>
        </section>
      ) : (
        <div className="artifact-hub-capability-grid">
          {capabilities.map((capability) => (
            <section
              className="artifact-hub-permissions-card artifact-hub-capability-card"
              key={capability.id}
            >
              <div className="artifact-hub-permissions-card__head">
                <div>
                  <strong>{capability.label}</strong>
                  <p>{capability.operatorSummary || capability.description}</p>
                </div>
                <span>{capability.status}</span>
              </div>
              <p>{capability.description}</p>
              <dl className="artifact-hub-capability-facts">
                <div>
                  <dt>Tools</dt>
                  <dd>{capability.availableCount}</dd>
                </div>
                <div>
                  <dt>Authority</dt>
                  <dd>Runtime registry</dd>
                </div>
                <div>
                  <dt>Evidence if used</dt>
                  <dd>Tool transcript, observation, validation refs</dd>
                </div>
              </dl>
              {capability.toolNames.length > 0 ? (
                <div className="artifact-hub-capability-tools">
                  {capability.toolNames.slice(0, 8).map((toolName) => (
                    <span key={toolName}>{toolName}</span>
                  ))}
                  {capability.toolNames.length > 8 ? (
                    <span>+{capability.toolNames.length - 8} more</span>
                  ) : null}
                </div>
              ) : null}
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
