import { useMemo } from "react";
import { openReviewSettings } from "../../../services/reviewNavigation";
import type {
  ArtifactHubViewKey,
  CapabilityRegistrySnapshot,
  LocalEngineSnapshot,
  SessionRemoteEnvSnapshot,
} from "../../../types";
import type { ChatCapabilityRegistryStatus } from "../hooks/useChatCapabilityRegistry";
import type { ChatLocalEngineStatus } from "../hooks/useChatLocalEngine";
import type { ChatRemoteEnvStatus } from "../hooks/useChatRemoteEnv";
import { buildMcpOverview } from "./artifactHubMcpModel";
import type { DoctorOverview } from "./artifactHubDoctorModel";
import { buildRemoteEnvDiffOverview } from "./artifactHubRemoteEnvModel";
import {
  formatTaskTimestamp,
  humanizeStatus,
} from "./ArtifactHubViewHelpers";

function doctorActionLabel(view: ArtifactHubViewKey): string {
  switch (view) {
    case "branch":
      return "Manage Branches";
    case "compact":
      return "Compact Session";
    case "hooks":
      return "Review Hooks";
    case "permissions":
      return "Review Permissions";
    case "plugins":
      return "Manage Plugins";
    case "privacy":
      return "Review Privacy";
    case "server":
      return "Inspect Server Mode";
    case "remote_env":
      return "Inspect Runtime Env";
    default:
      return "Review drawer";
  }
}

export function DoctorView({
  overview,
  localEngineSnapshot,
  localEngineStatus,
  localEngineError,
  onRefreshDoctor,
  onOpenView,
}: {
  overview: DoctorOverview;
  localEngineSnapshot: LocalEngineSnapshot | null;
  localEngineStatus: ChatLocalEngineStatus;
  localEngineError: string | null;
  onRefreshDoctor?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const generatedAtLabel =
    localEngineSnapshot?.generatedAtMs != null
      ? formatTaskTimestamp(localEngineSnapshot.generatedAtMs)
      : "Snapshot pending";
  const escalatedCards = overview.cards.filter((card) => card.tone !== "ready");

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Doctor</span>
        <strong>{overview.headline}</strong>
        <p>{overview.detail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(localEngineStatus)}</span>
          <span>Overall: {humanizeStatus(overview.tone)}</span>
          <span>{overview.reviewCount} review items</span>
          <span>{overview.watchCount} watch items</span>
          <span>Snapshot: {generatedAtLabel}</span>
        </div>
      </section>

      {localEngineError ? (
        <p className="artifact-hub-note artifact-hub-note--error">
          Runtime snapshot unavailable: {localEngineError}
        </p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        {overview.cards.map((card) => (
          <section
            key={card.id}
            className={`artifact-hub-permissions-card${
              card.tone === "attention"
                ? " artifact-hub-permissions-card--alert"
                : ""
            }`}
          >
            <div className="artifact-hub-permissions-card__head">
              <strong>{card.label}</strong>
              <span className="artifact-hub-policy-pill">{card.value}</span>
            </div>
            <p>{card.detail}</p>
            <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
              <span>Tone: {humanizeStatus(card.tone)}</span>
              {card.meta.map((item) => (
                <span key={`${card.id}-${item}`}>{item}</span>
              ))}
            </div>
            <div className="artifact-hub-permissions-card__actions">
              {card.actionView && onOpenView ? (
                <button
                  type="button"
                  className="artifact-hub-open-btn"
                  onClick={() => onOpenView(card.actionView!)}
                >
                  {doctorActionLabel(card.actionView)}
                </button>
              ) : null}
              {card.id === "runtime" ? (
                <button
                  type="button"
                  className="artifact-hub-open-btn secondary"
                  onClick={() => void openReviewSettings()}
                >
                  Open Chat Settings
                </button>
              ) : null}
            </div>
          </section>
        ))}
      </div>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Runtime summary</strong>
          <span className="artifact-hub-policy-pill">Shared truth</span>
        </div>
        <p>
          Chat Doctor is a projection over the same kernel snapshots that
          power Branches, Compact, Permissions, Plugins, Server, Hooks, Remote
          Env, and Chat diagnostics.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{localEngineSnapshot?.capabilities.length ?? 0} capability families</span>
          <span>
            {localEngineSnapshot?.compatibilityRoutes.length ?? 0} compatibility routes
          </span>
          <span>{localEngineSnapshot?.stagedOperations.length ?? 0} staged operations</span>
          <span>{localEngineSnapshot?.parentPlaybookRuns.length ?? 0} playbook runs</span>
        </div>
        <div className="artifact-hub-permissions-card__actions">
          {onRefreshDoctor ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onRefreshDoctor();
              }}
            >
              Refresh diagnostics
            </button>
          ) : null}
          <button
            type="button"
            className="artifact-hub-open-btn secondary"
            onClick={() => void openReviewSettings()}
          >
            Open Chat Diagnostics
          </button>
        </div>
      </section>

      {escalatedCards.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Suggested follow-up</span>
            <span>{escalatedCards.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {escalatedCards.map((card) => (
              <article className="artifact-hub-generic-row" key={`follow-up-${card.id}`}>
                <div className="artifact-hub-generic-meta">
                  <span>{humanizeStatus(card.tone)}</span>
                  <span>{card.value}</span>
                </div>
                <div className="artifact-hub-generic-title">{card.label}</div>
                <p className="artifact-hub-generic-summary">{card.detail}</p>
                {card.actionView && onOpenView ? (
                  <div className="artifact-hub-generic-actions">
                    <button
                      type="button"
                      className="artifact-hub-open-btn"
                      onClick={() => onOpenView(card.actionView!)}
                    >
                      {doctorActionLabel(card.actionView)}
                    </button>
                  </div>
                ) : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

export function RemoteEnvView({
  snapshot,
  status,
  error,
  onRefreshRemoteEnv,
  onOpenView,
}: {
  snapshot: SessionRemoteEnvSnapshot | null;
  status: ChatRemoteEnvStatus;
  error: string | null;
  onRefreshRemoteEnv?: () => Promise<unknown>;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const bindings = snapshot?.bindings ?? [];
  const notes = snapshot?.notes ?? [];
  const workspaceLabel = snapshot?.workspaceRoot?.trim() || "No active workspace";
  const diffOverview = useMemo(() => buildRemoteEnvDiffOverview(snapshot), [snapshot]);

  return (
    <div className="artifact-hub-permissions">
      <section className="artifact-hub-files-identity artifact-hub-permissions__identity">
        <span className="artifact-hub-files-kicker">Remote Env</span>
        <strong>{snapshot?.focusedScopeLabel || "Session remote environment"}</strong>
        <p>
          Review the effective runtime and shell environment posture that shapes
          provider lanes, local runtime wiring, and remote execution context.
        </p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>Projection: {humanizeStatus(status)}</span>
          <span>Workspace: {workspaceLabel}</span>
          <span>{snapshot?.bindingCount ?? 0} visible bindings</span>
          <span>{snapshot?.overlappingBindingCount ?? 0} overlapping keys</span>
          <span>{snapshot?.redactedBindingCount ?? 0} redacted</span>
        </div>
      </section>

      {error ? (
        <p className="artifact-hub-note artifact-hub-note--error">{error}</p>
      ) : null}

      <div className="artifact-hub-permissions-grid">
        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>{snapshot?.postureLabel || "Read-only environment projection"}</strong>
            <span className="artifact-hub-policy-pill">
              {snapshot?.governingSourceLabel || "Runtime"}
            </span>
          </div>
          <p>
            {snapshot?.postureDetail ||
              "Open a session to inspect the effective runtime and shell environment posture."}
          </p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            <span>Control plane: {snapshot?.controlPlaneBindingCount ?? 0}</span>
            <span>Process: {snapshot?.processBindingCount ?? 0}</span>
            <span>Secrets: {snapshot?.secretBindingCount ?? 0}</span>
          </div>
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Binding diff</strong>
            <span className="artifact-hub-policy-pill">{diffOverview.statusLabel}</span>
          </div>
          <p>{diffOverview.statusDetail}</p>
          <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
            {diffOverview.meta.map((label) => (
              <span key={label}>{label}</span>
            ))}
          </div>
          {diffOverview.overlappingBindings.length > 0 ? (
            <div className="artifact-hub-permissions-list">
              {diffOverview.overlappingBindings.map((binding) => (
                <div key={binding.key} className="artifact-hub-permissions-list__row">
                  <div>
                    <strong>{binding.key}</strong>
                    <p>{binding.sourceLabels.join(" vs ")}</p>
                    <p>{binding.valuePreviews.join(" / ")}</p>
                  </div>
                  <span>Diff</span>
                </div>
              ))}
            </div>
          ) : null}
        </section>

        <section className="artifact-hub-permissions-card">
          <div className="artifact-hub-permissions-card__head">
            <strong>Projection notes</strong>
            <span className="artifact-hub-policy-pill">Read-only</span>
          </div>
          {notes.length > 0 ? (
            <div className="artifact-hub-permissions-list">
              {notes.map((note, index) => (
                <div key={`${note}-${index}`} className="artifact-hub-permissions-list__row">
                  <div>
                    <strong>Runtime note</strong>
                    <p>{note}</p>
                  </div>
                  <span>Context</span>
                </div>
              ))}
            </div>
          ) : (
            <p>No additional environment notes are retained for this session yet.</p>
          )}
        </section>
      </div>

      {bindings.length > 0 ? (
        <section className="artifact-hub-task-section">
          <div className="artifact-hub-task-section-head">
            <span>Visible bindings</span>
            <span>{bindings.length}</span>
          </div>
          <div className="artifact-hub-generic-list">
            {bindings.map((binding) => (
              <article
                className="artifact-hub-generic-row"
                key={`${binding.key}:${binding.sourceLabel}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{binding.scopeLabel}</span>
                  <span>{binding.sourceLabel}</span>
                  <span>{binding.redacted ? "Redacted" : binding.secret ? "Secret" : "Visible"}</span>
                </div>
                <div className="artifact-hub-generic-title">{binding.key}</div>
                <p className="artifact-hub-generic-summary">{binding.valuePreview}</p>
                <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
                  <span>{binding.provenanceLabel}</span>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : (
        <p className="artifact-hub-empty">
          No runtime environment bindings are currently visible for this shell.
        </p>
      )}

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Related controls</strong>
          <span className="artifact-hub-policy-pill">Next steps</span>
        </div>
        <p>
          This slice remains read-only, but it now highlights control-plane
          versus process drift so environment review can happen before
          authority, privacy, or continuity decisions widen the session posture.
        </p>
        <div className="artifact-hub-permissions-card__actions">
          {onRefreshRemoteEnv ? (
            <button
              type="button"
              className="artifact-hub-open-btn"
              onClick={() => {
                void onRefreshRemoteEnv();
              }}
            >
              Refresh remote env
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
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("privacy")}
            >
              Review Privacy
            </button>
          ) : null}
        </div>
      </section>
    </div>
  );
}

export function McpView({
  capabilityRegistrySnapshot,
  capabilityRegistryStatus,
  capabilityRegistryError,
  onOpenView,
}: {
  capabilityRegistrySnapshot: CapabilityRegistrySnapshot | null;
  capabilityRegistryStatus: ChatCapabilityRegistryStatus;
  capabilityRegistryError: string | null;
  onOpenView?: (view: ArtifactHubViewKey) => void;
}) {
  const overview = useMemo(
    () => buildMcpOverview(capabilityRegistrySnapshot?.extensionManifests ?? []),
    [capabilityRegistrySnapshot],
  );

  return (
    <div className="artifact-hub-permissions">
      <section
        className={`artifact-hub-files-identity artifact-hub-permissions__identity ${
          overview.tone === "attention" ? "artifact-hub-permissions-card--alert" : ""
        }`}
      >
        <span className="artifact-hub-files-kicker">MCP</span>
        <strong>{overview.statusLabel}</strong>
        <p>{overview.statusDetail}</p>
        <div className="artifact-hub-files-meta artifact-hub-permissions__meta">
          <span>{overview.bridgeCount} bridge package(s)</span>
          <span>{overview.serverCount} server contribution(s)</span>
          <span>{overview.reviewCount} require review</span>
        </div>
      </section>

      <section className="artifact-hub-permissions-card">
        <div className="artifact-hub-permissions-card__head">
          <strong>Governed MCP bridge</strong>
          <span className="artifact-hub-policy-pill">Capability registry</span>
        </div>
        <p>
          Treat MCP servers as governed extension-backed bridge surfaces instead
          of shell-local setup hidden behind raw config files.
        </p>
        {capabilityRegistryError ? (
          <p className="artifact-hub-error">{capabilityRegistryError}</p>
        ) : capabilityRegistryStatus === "loading" ? (
          <p className="artifact-hub-generic-summary">
            Loading the shared capability registry snapshot.
          </p>
        ) : null}
        <div className="artifact-hub-permissions-card__actions">
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("plugins")}
            >
              Manage Plugins
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
          {onOpenView ? (
            <button
              type="button"
              className="artifact-hub-open-btn secondary"
              onClick={() => onOpenView("doctor")}
            >
              Run Diagnostics
            </button>
          ) : null}
        </div>
      </section>

      <section className="artifact-hub-task-section">
        <div className="artifact-hub-task-section-head">
          <span>MCP bridge packages</span>
          <span>{overview.servers.length}</span>
        </div>
        {overview.servers.length > 0 ? (
          <div className="artifact-hub-generic-list">
            {overview.servers.map((server) => (
              <article
                className="artifact-hub-generic-row"
                key={`${server.extensionId}:${server.contributionPath || server.label}`}
              >
                <div className="artifact-hub-generic-meta">
                  <span>{server.label}</span>
                  <span>{server.serverCount} server(s)</span>
                </div>
                <div className="artifact-hub-generic-title">{server.sourceLabel}</div>
                <p className="artifact-hub-generic-summary">
                  {server.contributionDetail ||
                    "This extension publishes MCP bridge surfaces into the governed runtime lane."}
                </p>
                <p className="artifact-hub-generic-summary">
                  {humanizeStatus(server.trustPosture)} trust ·{" "}
                  {humanizeStatus(server.governedProfile)} profile
                  {server.contributionPath ? ` · ${server.contributionPath}` : ""}
                </p>
              </article>
            ))}
          </div>
        ) : (
          <p className="artifact-hub-empty">
            No extension manifest is currently contributing MCP servers into the
            shared capability registry.
          </p>
        )}
      </section>
    </div>
  );
}
