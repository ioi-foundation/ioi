import { useState } from "react";
import { humanize } from "./model";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { DetailDocument } from "./ui";

function formatEngineTimestamp(timestampMs: number): string {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

function formatEngineBytes(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value >= 10 || unitIndex === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unitIndex]}`;
}

function formatEngineIdentifier(value?: string | null): string {
  if (!value) return "n/a";
  if (value.length <= 14) return value;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

export function EngineDetailPane({
  controller,
  onOpenSessionTarget,
  onOpenArtifact,
  onOpenInbox,
  onOpenSettings,
}: {
  controller: CapabilitiesController;
  onOpenSessionTarget?: (sessionId: string) => void;
  onOpenArtifact?: (artifactId: string) => void;
  onOpenInbox?: () => void;
  onOpenSettings?: () => void;
}) {
  const [stageSubjectKind, setStageSubjectKind] = useState<
    "model" | "backend" | "gallery"
  >("model");
  const [stageOperation, setStageOperation] = useState("install");
  const [stageSourceUri, setStageSourceUri] = useState("");
  const [stageSubjectId, setStageSubjectId] = useState("");
  const [stageNotes, setStageNotes] = useState("");
  const snapshot = controller.engine.snapshot;

  if (controller.engine.loading) {
    return (
      <div className="capabilities-empty-detail">
        Loading local engine posture from the kernel…
      </div>
    );
  }

  if (controller.engine.error || !snapshot) {
    return (
      <div className="capabilities-empty-detail">
        {controller.engine.error ??
          "The runtime has not published a local engine snapshot yet."}
      </div>
    );
  }

  const controlPlane = controller.engine.configDraft ?? snapshot.controlPlane;
  const enabledGalleryCount = controlPlane.galleries.filter(
    (source) => source.enabled,
  ).length;
  const enabledGallerySources = controlPlane.galleries.filter(
    (source) => source.enabled,
  );
  const defaultModelId = controlPlane.runtime.defaultModel?.trim() ?? "";
  const stagedCount = snapshot.stagedOperations.length;
  const liveJobCount = snapshot.jobs.filter(
    (job) => !["completed", "failed", "cancelled"].includes(job.status),
  ).length;
  const completedJobCount = snapshot.jobs.filter(
    (job) => job.status === "completed",
  ).length;
  const activeParentPlaybookRunCount = snapshot.parentPlaybookRuns.filter(
    (run) => !["completed", "failed"].includes(run.status),
  ).length;
  const blockedParentPlaybookRunCount = snapshot.parentPlaybookRuns.filter(
    (run) => run.status === "blocked",
  ).length;
  const failedRegistryCount =
    snapshot.registryModels.filter((record) => record.status === "failed")
      .length +
    snapshot.managedBackends.filter(
      (record) => record.status === "failed" || record.health === "degraded",
    ).length +
    snapshot.galleryCatalogs.filter((record) => record.syncStatus === "failed")
      .length;
  const latestConfigMigration =
    snapshot.controlPlaneMigrations
      .slice()
      .sort((left, right) => right.appliedAtMs - left.appliedAtMs)[0] ?? null;
  const studioSurfaceCount = snapshot.capabilities.filter((family) =>
    [
      "transcription",
      "speech",
      "vision",
      "image",
      "video",
      "knowledge",
      "workers",
    ].includes(family.id),
  ).length;
  const stageCanSubmit =
    stageSubjectKind === "gallery" ||
    stageSourceUri.trim().length > 0 ||
    stageSubjectId.trim().length > 0;
  const quickStageActions = [
    ...enabledGallerySources.map((source) => ({
      key: `gallery:${source.id}`,
      eyebrow: `${humanize(source.kind)} source`,
      title: `Sync ${source.label}`,
      description: source.uri,
      onClick: () =>
        controller.engine.stageOperation({
          subjectKind: "gallery",
          operation: "sync",
          subjectId: source.id,
          sourceUri: source.uri,
          notes: `Sync the live ${source.label} ${humanize(source.kind).toLowerCase()} source into the kernel catalog.`,
        }),
    })),
    ...(defaultModelId
      ? [
          {
            key: `model:${defaultModelId}`,
            eyebrow: "Residency",
            title: `Warm ${defaultModelId}`,
            description:
              "Queue the current runtime default model for managed residency and receipts.",
            onClick: () =>
              controller.engine.stageOperation({
                subjectKind: "model",
                operation: "load",
                subjectId: defaultModelId,
                notes:
                  "Warm the current runtime default model under kernel-native registry control.",
              }),
          },
        ]
      : []),
  ];

  const sectionTitle =
    controller.engine.detailSection === "families"
      ? controller.engine.selectedFamily?.label || "Capability family"
      : controller.engine.detailSection === "runtime"
        ? "Runtime posture"
        : controller.engine.detailSection === "configuration"
          ? "Settings bridge"
          : controller.engine.detailSection === "catalogs"
            ? "Catalogs and staging"
      : controller.engine.detailSection === "registry"
        ? "Registry queue"
        : controller.engine.detailSection === "activity"
          ? "Recent activity"
          : "Overview";
  const sectionSummary =
    controller.engine.detailSection === "families"
      ? controller.engine.selectedFamily?.description ||
        "Kernel-native tools grouped by capability family."
      : controller.engine.detailSection === "runtime"
        ? "Execution mode, filesystem layout, and the compatibility posture that keeps the kernel in charge."
        : controller.engine.detailSection === "configuration"
          ? "Inspect runtime posture here, then edit the authoritative control documents in System Settings."
          : controller.engine.detailSection === "catalogs"
            ? "Gallery sources plus staged install and sync intents that can be promoted into native execution."
      : controller.engine.detailSection === "registry"
        ? "Managed models, backends, galleries, and queued lifecycle work now share one kernel-owned registry surface."
        : controller.engine.detailSection === "activity"
          ? "Latest typed receipts emitted by absorbed model, media, registry, and parent-playbook workloads."
          : "Local inference, media, and registry semantics now routed through the kernel.";
  const sectionMeta =
    controller.engine.detailSection === "families"
      ? controller.engine.selectedFamily
        ? `${controller.engine.selectedFamily.availableCount} tools`
        : "No family selected"
      : controller.engine.detailSection === "runtime"
        ? controlPlane.runtime.mode
      : controller.engine.detailSection === "configuration"
        ? controller.engine.configDirty
          ? "Draft differs"
          : "Synced"
      : controller.engine.detailSection === "catalogs"
        ? `${enabledGalleryCount}/${controlPlane.galleries.length} live`
      : controller.engine.detailSection === "registry"
        ? `${snapshot.registryModels.length + snapshot.managedBackends.length + snapshot.galleryCatalogs.length} tracked`
        : controller.engine.detailSection === "activity"
          ? `${snapshot.recentActivity.length} receipts`
          : `${snapshot.totalNativeTools} native tools`;
  const selectedRegistryEntry = controller.engine.selectedRegistryEntry;

  return (
    <div className="capabilities-detail-scroll capabilities-detail-scroll-engine">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">Kernel-native control plane</span>
          <h2>Runtime Deck</h2>
        </div>
        <div className="capabilities-action-row">
          <button
            type="button"
            className="capabilities-secondary-button"
            onClick={onOpenSettings}
            disabled={!onOpenSettings}
          >
            Open settings
          </button>
          <button
            type="button"
            className="capabilities-secondary-button"
            onClick={() => void controller.engine.refreshSnapshot()}
          >
            Refresh
          </button>
        </div>
      </header>

      <div className="capabilities-detail-inline-meta">
        <span>
          Native tools <strong>{snapshot.totalNativeTools}</strong>
        </span>
        <span>
          Live jobs <strong>{liveJobCount}</strong>
        </span>
        <span>
          Playbook runs <strong>{activeParentPlaybookRunCount}</strong>
        </span>
        <span>
          Pending controls <strong>{snapshot.pendingControlCount}</strong>
        </span>
        <span>
          Active issues <strong>{snapshot.activeIssueCount}</strong>
        </span>
        <span>
          Registry drift <strong>{failedRegistryCount}</strong>
        </span>
        <span>
          Updated <strong>{formatEngineTimestamp(snapshot.generatedAtMs)}</strong>
        </span>
      </div>

      <p className="capabilities-detail-summary">
        This deck stays focused on runtime visibility: inference, media, model
        residency, queue state, and lifecycle receipts are rendered as
        first-class kernel capabilities rather than provider adapters. Settings
        owns the editable control documents.
      </p>

      {controller.engine.configMessage ? (
        <section className="capabilities-detail-card capabilities-engine-message-card">
          <div className="capabilities-detail-card-head">
            <h3>Control-plane status</h3>
            <span>
              {controller.engine.configSaving || controller.engine.stagingBusy
                ? "Working"
                : "Ready"}
            </span>
          </div>
          <p>{controller.engine.configMessage}</p>
        </section>
      ) : null}

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.engine.detailSection === "overview" ? (
          <section className="capabilities-engine-layout">
            <article className="capabilities-engine-hero">
              <span className="capabilities-engine-hero-kicker">
                Agentic chat
              </span>
              <h3>Operator visibility for the local runtime.</h3>
              <p>
                The kernel is now the source of truth for local model, media,
                knowledge, and worker actions. Chat stays on top as the
                operator shell without reviving a second runtime control plane.
              </p>
              <div className="capabilities-engine-hero-actions">
                <button
                  type="button"
                  className="capabilities-primary-button"
                  onClick={onOpenInbox}
                  disabled={!onOpenInbox}
                >
                  Review queue
                </button>
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={onOpenSettings}
                  disabled={!onOpenSettings}
                >
                  Open settings
                </button>
              </div>
            </article>

            <div className="capabilities-engine-metrics">
              <article>
                <span>Pending approvals</span>
                <strong>{snapshot.pendingApprovalCount}</strong>
              </article>
              <article>
                <span>Capability families</span>
                <strong>{snapshot.capabilities.length}</strong>
              </article>
              <article>
                <span>Recent receipts</span>
                <strong>{snapshot.recentActivity.length}</strong>
              </article>
              <article>
                <span>Staged plans</span>
                <strong>{stagedCount}</strong>
              </article>
              <article>
                <span>Live jobs</span>
                <strong>{liveJobCount}</strong>
              </article>
            </div>

            <div className="capabilities-engine-plane-grid">
              <article className="capabilities-detail-card capabilities-engine-plane-card">
                <div className="capabilities-detail-card-head">
                  <h3>Runtime</h3>
                  <span>{humanize(controlPlane.runtime.mode)}</span>
                </div>
                <p>{controlPlane.runtime.baselineRole}</p>
                <div className="capabilities-chip-row">
                  <span className="capabilities-chip">
                    {controlPlane.runtime.defaultModel}
                  </span>
                  <span className="capabilities-chip">
                    {controlPlane.api.bindAddress}
                  </span>
                </div>
              </article>
              <article className="capabilities-detail-card capabilities-engine-plane-card">
                <div className="capabilities-detail-card-head">
                  <h3>Kernel API</h3>
                  <span>Native only</span>
                </div>
                <p>
                  Local Engine exposes the current kernel-owned API surface;
                  compatibility facades are no longer advertised as runtime
                  control-plane contracts.
                </p>
                <div className="capabilities-chip-row">
                  <span className="capabilities-chip">{controlPlane.api.authMode}</span>
                  <span className="capabilities-chip">{controlPlane.api.corsMode}</span>
                </div>
              </article>
              <article className="capabilities-detail-card capabilities-engine-plane-card">
                <div className="capabilities-detail-card-head">
                  <h3>Job monitor</h3>
                  <span>{liveJobCount} live</span>
                </div>
                <p>
                  Promoted plans, running installs, and registry actions all
                  land in one visible queue instead of hiding in backend
                  processes.
                </p>
                <div className="capabilities-chip-row">
                  <span className="capabilities-chip">{stagedCount} staged</span>
                  <span className="capabilities-chip">{completedJobCount} done</span>
                </div>
              </article>
              <article className="capabilities-detail-card capabilities-engine-plane-card">
                <div className="capabilities-detail-card-head">
                  <h3>Launcher parity</h3>
                  <span>
                    {controlPlane.launcher.autoStartOnBoot ? "Boot armed" : "Manual"}
                  </span>
                </div>
                <p>
                  Startup, updates, and shell posture now live in Chat rather
                  than a detached launcher window.
                </p>
                <div className="capabilities-chip-row">
                  <span className="capabilities-chip">
                    {controlPlane.launcher.releaseChannel}
                  </span>
                  <span className="capabilities-chip">
                    {controlPlane.launcher.autoCheckUpdates ? "Update watch" : "Manual updates"}
                  </span>
                  <span className="capabilities-chip">{studioSurfaceCount} studios</span>
                </div>
              </article>
            </div>

            <div className="capabilities-engine-family-grid">
              {snapshot.capabilities.map((family) => (
                <button
                  key={family.id}
                  type="button"
                  className="capabilities-engine-family-card"
                  onClick={() => {
                    controller.engine.setDetailSection("families");
                    controller.engine.setSelectedFamilyId(family.id);
                  }}
                >
                  <span>{family.status}</span>
                  <strong>{family.label}</strong>
                  <p>{family.operatorSummary}</p>
                </button>
              ))}
            </div>
          </section>
        ) : null}

        {controller.engine.detailSection === "runtime" ? (
          <section className="capabilities-engine-stack">
            <article className="capabilities-detail-card capabilities-engine-runtime-card">
              <div className="capabilities-detail-card-head">
                <h3>Execution mode</h3>
                <span>{humanize(controlPlane.runtime.mode)}</span>
              </div>
              <p>{controlPlane.runtime.kernelAuthority}</p>
              <div className="capabilities-detail-meta-grid capabilities-detail-meta-grid-compact">
                <article>
                  <span>Endpoint</span>
                  <strong>{controlPlane.runtime.endpoint}</strong>
                </article>
                <article>
                  <span>Default model</span>
                  <strong>{controlPlane.runtime.defaultModel}</strong>
                </article>
                <article>
                  <span>API surface</span>
                  <strong>Kernel only</strong>
                </article>
              </div>
            </article>

            <article className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Filesystem residency</h3>
                <span>Local only</span>
              </div>
              <div className="capabilities-engine-path-list">
                <div>
                  <strong>Models</strong>
                  <span>{controlPlane.storage.modelsPath}</span>
                </div>
                <div>
                  <strong>Backends</strong>
                  <span>{controlPlane.storage.backendsPath}</span>
                </div>
                <div>
                  <strong>Artifacts</strong>
                  <span>{controlPlane.storage.artifactsPath}</span>
                </div>
                <div>
                  <strong>Cache</strong>
                  <span>{controlPlane.storage.cachePath}</span>
                </div>
              </div>
            </article>

            <article className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Launcher parity</h3>
                <span>{controlPlane.launcher.releaseChannel}</span>
              </div>
              <div className="capabilities-engine-meta-grid">
                <article>
                  <span>Start on boot</span>
                  <strong>
                    {controlPlane.launcher.autoStartOnBoot ? "Enabled" : "Disabled"}
                  </strong>
                </article>
                <article>
                  <span>Reopen Chat</span>
                  <strong>
                    {controlPlane.launcher.reopenChatOnLaunch ? "Yes" : "No"}
                  </strong>
                </article>
                <article>
                  <span>Update watch</span>
                  <strong>
                    {controlPlane.launcher.autoCheckUpdates ? "Auto" : "Manual"}
                  </strong>
                </article>
                <article>
                  <span>Kernel console</span>
                  <strong>
                    {controlPlane.launcher.showKernelConsole ? "Visible" : "Hidden"}
                  </strong>
                </article>
              </div>
            </article>

            <article className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Operator notes</h3>
                <span>{controlPlane.notes.length}</span>
              </div>
              <div className="capabilities-note-stack">
                {controlPlane.notes.map((note) => (
                  <p key={note} className="capabilities-inline-note">
                    {note}
                  </p>
                ))}
              </div>
            </article>
          </section>
        ) : null}

        {controller.engine.detailSection === "configuration" ? (
          <section className="capabilities-engine-stack">
            <article className="capabilities-detail-card capabilities-engine-message-card">
              <div className="capabilities-detail-card-head">
                <h3>Settings authority</h3>
                <span>{controller.engine.configDirty ? "Draft differs" : "Synced"}</span>
              </div>
              <p>
                Runtime, storage, API, gallery, launcher, and environment
                documents are editable in System Settings now so the shell
                matches operator expectations and stays aligned with future CLI
                control.
              </p>
              <div className="capabilities-detail-inline-meta">
                <span>
                  Runtime <strong>{humanize(controlPlane.runtime.mode)}</strong>
                </span>
                <span>
                  Profile <strong>{snapshot.controlPlaneProfileId}</strong>
                </span>
                <span>
                  Schema <strong>v{snapshot.controlPlaneSchemaVersion}</strong>
                </span>
                <span>
                  Galleries <strong>{enabledGalleryCount}</strong>
                </span>
                <span>
                  Bindings <strong>{controlPlane.environment.length}</strong>
                </span>
              </div>
              {latestConfigMigration ? (
                <p className="capabilities-inline-note">
                  Latest config upgrade: {latestConfigMigration.summary} at{" "}
                  {formatEngineTimestamp(latestConfigMigration.appliedAtMs)}.
                </p>
              ) : null}
              <div className="capabilities-action-row">
                <button
                  type="button"
                  className="capabilities-primary-button"
                  onClick={onOpenSettings}
                  disabled={!onOpenSettings}
                >
                  Open system settings
                </button>
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={() => void controller.engine.refreshSnapshot()}
                >
                  Refresh deck
                </button>
              </div>
            </article>

            <div className="capabilities-engine-meta-grid">
              <article>
                <span>Watchdog</span>
                <strong>{controlPlane.watchdog.enabled ? "Armed" : "Manual"}</strong>
              </article>
              <article>
                <span>Memory</span>
                <strong>
                  {controlPlane.memory.reclaimerEnabled
                    ? `${controlPlane.memory.thresholdPercent}%`
                    : "Unmanaged"}
                </strong>
              </article>
              <article>
                <span>API surface</span>
                <strong>Kernel only</strong>
              </article>
              <article>
                <span>Launcher</span>
                <strong>
                  {controlPlane.launcher.autoStartOnBoot ? "Boot armed" : "Manual"}
                </strong>
              </article>
              <article>
                <span>Storage</span>
                <strong>{controlPlane.storage.modelsPath}</strong>
              </article>
              <article>
                <span>Environment</span>
                <strong>{controlPlane.environment.length} bindings</strong>
              </article>
            </div>
          </section>
        ) : null}

        {controller.engine.detailSection === "catalogs" ? (
          <section className="capabilities-engine-stack">
            <article className="capabilities-detail-card capabilities-engine-form-card">
              <div className="capabilities-detail-card-head">
                <h3>Gallery sources</h3>
                <span>{controlPlane.galleries.length}</span>
              </div>
              <p>
                Gallery source editing now lives in System Settings. This deck
                keeps the current catalog visible so operators can supervise
                migration state without juggling two runtime UIs.
              </p>
              <div className="capabilities-engine-gallery-list">
                {controlPlane.galleries.map((source) => (
                  <div key={source.id} className="capabilities-engine-gallery-card">
                    <div className="capabilities-detail-card-head">
                      <h3>{source.label}</h3>
                      <span>{humanize(source.compatibilityTier)}</span>
                    </div>
                    <div className="capabilities-chip-row">
                      <span className="capabilities-chip">{humanize(source.kind)}</span>
                      <span className="capabilities-chip">{humanize(source.syncStatus)}</span>
                      <span className="capabilities-chip">
                        {source.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </div>
                    <div className="capabilities-engine-field">
                      <span>URI</span>
                      <input value={source.uri} readOnly />
                    </div>
                  </div>
                ))}
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={onOpenSettings}
                  disabled={!onOpenSettings}
                >
                  Manage gallery sources in settings
                </button>
              </div>
            </article>

            <article className="capabilities-detail-card capabilities-engine-form-card">
              <div className="capabilities-detail-card-head">
                <h3>Runtime quick actions</h3>
                <span>Live snapshot</span>
              </div>
              <p>
                Stage sync and residency work directly from the current control
                plane without relying on vendored preset identifiers.
              </p>
              {quickStageActions.length > 0 ? (
                <div className="capabilities-engine-preset-grid">
                  {quickStageActions.map((action) => (
                    <button
                      key={action.key}
                      type="button"
                      className="capabilities-engine-preset-card"
                      disabled={controller.engine.stagingBusy}
                      onClick={() => {
                        void action.onClick();
                      }}
                    >
                      <span>{action.eyebrow}</span>
                      <strong>{action.title}</strong>
                      <p>{action.description}</p>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="capabilities-empty-inline">
                  No live gallery sources or default model are configured for
                  quick staging yet.
                </div>
              )}
            </article>

            <article className="capabilities-detail-card capabilities-engine-form-card">
              <div className="capabilities-detail-card-head">
                <h3>Stage an operation</h3>
                <span>{controller.engine.stagingBusy ? "Working" : "Queue"}</span>
              </div>
              <p>
                Stage model installs, backend imports, or gallery sync intents
                now. These persist as operator plans until native executors
                consume them.
              </p>
              <div className="capabilities-engine-form-grid">
                <label className="capabilities-engine-field">
                  <span>Subject kind</span>
                  <select
                    value={stageSubjectKind}
                    onChange={(event) =>
                      setStageSubjectKind(
                        event.target.value as "model" | "backend" | "gallery",
                      )
                    }
                  >
                    <option value="model">Model</option>
                    <option value="backend">Backend</option>
                    <option value="gallery">Gallery</option>
                  </select>
                </label>
                <label className="capabilities-engine-field">
                  <span>Operation</span>
                  <select
                    value={stageOperation}
                    onChange={(event) => setStageOperation(event.target.value)}
                  >
                    <option value="install">Install</option>
                    <option value="import">Import</option>
                    <option value="sync">Sync</option>
                    <option value="load">Load</option>
                  </select>
                </label>
                <label className="capabilities-engine-field">
                  <span>Source URI</span>
                  <input
                    value={stageSourceUri}
                    onChange={(event) => setStageSourceUri(event.target.value)}
                    placeholder="oci://, https://, file://, or gallery source"
                  />
                </label>
                <label className="capabilities-engine-field">
                  <span>Subject id</span>
                  <input
                    value={stageSubjectId}
                    onChange={(event) => setStageSubjectId(event.target.value)}
                    placeholder="model id, backend id, or gallery id"
                  />
                </label>
                <label className="capabilities-engine-field is-wide">
                  <span>Notes</span>
                  <textarea
                    value={stageNotes}
                    onChange={(event) => setStageNotes(event.target.value)}
                    placeholder="Why this should be promoted, what it should replace, or how it maps from a legacy local setup."
                  />
                </label>
              </div>
              <div className="capabilities-action-row">
                <button
                  type="button"
                  className="capabilities-primary-button"
                  disabled={!stageCanSubmit || controller.engine.stagingBusy}
                  onClick={() => {
                    void controller.engine
                      .stageOperation({
                        subjectKind: stageSubjectKind,
                        operation: stageOperation,
                        sourceUri: stageSourceUri || null,
                        subjectId: stageSubjectId || null,
                        notes: stageNotes || null,
                      })
                      .then(() => {
                        setStageSourceUri("");
                        setStageSubjectId("");
                        setStageNotes("");
                      })
                      .catch(() => undefined);
                  }}
                >
                  {controller.engine.stagingBusy ? "Staging…" : "Stage plan"}
                </button>
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={() => {
                    setStageSourceUri("");
                    setStageSubjectId("");
                    setStageNotes("");
                  }}
                >
                  Clear
                </button>
              </div>
            </article>

            <article className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Staged operations</h3>
                <span>{stagedCount}</span>
              </div>
              {snapshot.stagedOperations.length > 0 ? (
                <div className="capabilities-engine-stage-list">
                  {snapshot.stagedOperations.map((operation) => (
                    <div
                      key={operation.operationId}
                      className="capabilities-engine-stage-card"
                    >
                      <div className="capabilities-detail-card-head">
                        <h3>{operation.title}</h3>
                        <span>{humanize(operation.status)}</span>
                      </div>
                      <div className="capabilities-chip-row">
                        <span className="capabilities-chip">
                          {humanize(operation.subjectKind)}
                        </span>
                        <span className="capabilities-chip">
                          {humanize(operation.operation)}
                        </span>
                        <span className="capabilities-chip">
                          {formatEngineTimestamp(operation.createdAtMs)}
                        </span>
                      </div>
                      {operation.sourceUri ? (
                        <p className="capabilities-inline-note">
                          Source: {operation.sourceUri}
                        </p>
                      ) : null}
                      {operation.notes ? (
                        <p className="capabilities-inline-note">{operation.notes}</p>
                      ) : null}
                      <div className="capabilities-action-row">
                        <button
                          type="button"
                          className="capabilities-primary-button"
                          onClick={() =>
                            void controller.engine.promoteOperation(
                              operation.operationId,
                            )
                          }
                          disabled={controller.engine.stagingBusy}
                        >
                          Promote
                        </button>
                        <button
                          type="button"
                          className="capabilities-inline-button"
                          onClick={() =>
                            void controller.engine.removeOperation(
                              operation.operationId,
                            )
                          }
                          disabled={controller.engine.stagingBusy}
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No staged Local Engine plans yet.</p>
              )}
            </article>
          </section>
        ) : null}

        {controller.engine.detailSection === "registry" ? (
          <section className="capabilities-engine-stack">
            {selectedRegistryEntry ? (
              <article className="capabilities-detail-card capabilities-engine-target-card">
                <div className="capabilities-detail-card-head">
                  <h3>Focused runtime member</h3>
                  <span>{humanize(selectedRegistryEntry.kind)}</span>
                </div>
                <div className="capabilities-engine-target-identity">
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Focused runtime member:</strong>{" "}
                    {selectedRegistryEntry.label}
                  </p>
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Registry entry:</strong>{" "}
                    {selectedRegistryEntry.entryId}
                  </p>
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Kind:</strong> {humanize(selectedRegistryEntry.kind)}
                  </p>
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Authority tier:</strong>{" "}
                    {selectedRegistryEntry.authority.tierLabel}
                  </p>
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Source:</strong> {selectedRegistryEntry.sourceLabel}
                  </p>
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Status:</strong> {selectedRegistryEntry.statusLabel}
                  </p>
                  <p className="capabilities-engine-target-identity-line">
                    <strong>Lease posture:</strong>{" "}
                    {selectedRegistryEntry.lease.modeLabel ??
                      selectedRegistryEntry.lease.availabilityLabel}
                  </p>
                  {selectedRegistryEntry.lease.runtimeTargetLabel ? (
                    <p className="capabilities-engine-target-identity-line">
                      <strong>Runtime target:</strong>{" "}
                      {selectedRegistryEntry.lease.runtimeTargetLabel}
                    </p>
                  ) : null}
                  <p className="capabilities-engine-target-summary">
                    {selectedRegistryEntry.summary}
                  </p>
                </div>
                <div className="capabilities-trust-tier-line">
                  <div className="capabilities-trust-tier-copy">
                    <strong>{selectedRegistryEntry.label}</strong>
                    <span>{selectedRegistryEntry.summary}</span>
                  </div>
                  <span className="capabilities-trust-tier-badge">
                    {selectedRegistryEntry.authority.tierLabel}
                  </span>
                </div>
                <p className="capabilities-inline-note">
                  Routed here from the governing-family graph so the owning
                  runtime member stays inspectable even when it came from sparse
                  fallback registry state.
                </p>
                <div className="capabilities-detail-inline-meta">
                  <span>
                    Source <strong>{selectedRegistryEntry.sourceLabel}</strong>
                  </span>
                  <span>
                    Status <strong>{selectedRegistryEntry.statusLabel}</strong>
                  </span>
                  <span>
                    Lease <strong>{selectedRegistryEntry.lease.modeLabel ?? selectedRegistryEntry.lease.availabilityLabel}</strong>
                  </span>
                  {selectedRegistryEntry.lease.runtimeTargetLabel ? (
                    <span>
                      Runtime target{" "}
                      <strong>{selectedRegistryEntry.lease.runtimeTargetLabel}</strong>
                    </span>
                  ) : null}
                </div>
              </article>
            ) : null}

            <section className="capabilities-engine-state-grid">
              <article className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Registry models</h3>
                  <span>{snapshot.registryModels.length}</span>
                </div>
                {snapshot.registryModels.length > 0 ? (
                  <div className="capabilities-engine-state-list">
                    {snapshot.registryModels.map((record) => (
                      <div
                        key={record.modelId}
                        className={`capabilities-engine-state-card status-${record.status} ${
                          selectedRegistryEntry?.entryId === `model:${record.modelId}`
                            ? "is-targeted"
                            : ""
                        }`.trim()}
                      >
                        <div className="capabilities-detail-card-head">
                          <h3>{record.modelId}</h3>
                          <span>{humanize(record.status)}</span>
                        </div>
                        <div className="capabilities-detail-inline-meta">
                          <span>
                            Residency <strong>{humanize(record.residency)}</strong>
                          </span>
                          <span>
                            Updated{" "}
                            <strong>{formatEngineTimestamp(record.updatedAtMs)}</strong>
                          </span>
                          {record.bytesTransferred ? (
                            <span>
                              Transfer{" "}
                              <strong>{formatEngineBytes(record.bytesTransferred)}</strong>
                            </span>
                          ) : null}
                        </div>
                        <div className="capabilities-chip-row">
                          {record.backendId ? (
                            <span className="capabilities-chip">{record.backendId}</span>
                          ) : null}
                          {record.hardwareProfile ? (
                            <span className="capabilities-chip">
                              {record.hardwareProfile}
                            </span>
                          ) : null}
                          {record.jobId ? (
                            <span className="capabilities-chip">
                              Job {record.jobId.slice(0, 12)}
                            </span>
                          ) : null}
                        </div>
                        {record.sourceUri ? (
                          <p className="capabilities-inline-note">
                            Source: {record.sourceUri}
                          </p>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p>No models are tracked in the registry yet.</p>
                )}
              </article>

              <article className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Managed backends</h3>
                  <span>{snapshot.managedBackends.length}</span>
                </div>
                {snapshot.managedBackends.length > 0 ? (
                  <div className="capabilities-engine-state-list">
                    {snapshot.managedBackends.map((record) => (
                      <div
                        key={record.backendId}
                        className={`capabilities-engine-state-card status-${record.status} ${
                          selectedRegistryEntry?.entryId === `backend:${record.backendId}`
                            ? "is-targeted"
                            : ""
                        }`.trim()}
                      >
                        <div className="capabilities-detail-card-head">
                          <h3>{record.backendId}</h3>
                          <span>{humanize(record.status)}</span>
                        </div>
                        <div className="capabilities-detail-inline-meta">
                          <span>
                            Health <strong>{humanize(record.health)}</strong>
                          </span>
                          <span>
                            Updated{" "}
                            <strong>{formatEngineTimestamp(record.updatedAtMs)}</strong>
                          </span>
                          {record.pid ? (
                            <span>
                              PID <strong>{record.pid}</strong>
                            </span>
                          ) : null}
                        </div>
                        <div className="capabilities-chip-row">
                          {record.alias ? (
                            <span className="capabilities-chip">{record.alias}</span>
                          ) : null}
                          {record.hardwareProfile ? (
                            <span className="capabilities-chip">
                              {record.hardwareProfile}
                            </span>
                          ) : null}
                          {record.jobId ? (
                            <span className="capabilities-chip">
                              Job {record.jobId.slice(0, 12)}
                            </span>
                          ) : null}
                          {record.healthEndpoint ? (
                            <span className="capabilities-chip">Health endpoint</span>
                          ) : null}
                        </div>
                        {record.entrypoint ? (
                          <p className="capabilities-inline-note">
                            Entrypoint: {record.entrypoint}
                          </p>
                        ) : null}
                        {record.installPath ? (
                          <p className="capabilities-inline-note">
                            Install root: {record.installPath}
                          </p>
                        ) : null}
                        {record.healthEndpoint ? (
                          <p className="capabilities-inline-note">
                            Health probe: {record.healthEndpoint}
                          </p>
                        ) : null}
                        {record.sourceUri ? (
                          <p className="capabilities-inline-note">
                            Source: {record.sourceUri}
                          </p>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p>No backend runtimes are tracked yet.</p>
                )}
              </article>
            </section>

            <article className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Gallery catalogs</h3>
                <span>{snapshot.galleryCatalogs.length}</span>
              </div>
              {snapshot.galleryCatalogs.length > 0 ? (
                <div className="capabilities-engine-state-list">
                  {snapshot.galleryCatalogs.map((record) => (
                    <div
                      key={record.galleryId}
                      className={`capabilities-engine-state-card status-${record.syncStatus}`}
                    >
                      <div className="capabilities-detail-card-head">
                        <h3>{record.label}</h3>
                        <span>{humanize(record.syncStatus)}</span>
                      </div>
                      <div className="capabilities-detail-inline-meta">
                        <span>
                          Kind <strong>{humanize(record.kind)}</strong>
                        </span>
                        <span>
                          Entries <strong>{record.entryCount}</strong>
                        </span>
                        <span>
                          Tier <strong>{humanize(record.compatibilityTier)}</strong>
                        </span>
                      </div>
                      <div className="capabilities-chip-row">
                        <span className="capabilities-chip">{record.galleryId}</span>
                        <span className="capabilities-chip">
                          {record.enabled ? "Enabled" : "Disabled"}
                        </span>
                        {record.lastSyncedAtMs ? (
                          <span className="capabilities-chip">
                            Synced {formatEngineTimestamp(record.lastSyncedAtMs)}
                          </span>
                        ) : null}
                        {record.lastJobId ? (
                          <span className="capabilities-chip">
                            Job {record.lastJobId.slice(0, 12)}
                          </span>
                        ) : null}
                      </div>
                      {record.sampleEntries.length > 0 ? (
                        <div className="capabilities-engine-preview-list">
                          {record.sampleEntries.map((entry) => (
                            <div
                              key={`${record.galleryId}:${entry.entryId}`}
                              className="capabilities-engine-preview-item"
                            >
                              <strong>{entry.label}</strong>
                              <span>{entry.summary}</span>
                              {entry.sourceUri ? (
                                <span className="capabilities-engine-preview-source">
                                  Source {entry.sourceUri}
                                </span>
                              ) : null}
                              {(record.kind === "model" || record.kind === "backend") &&
                              entry.sourceUri ? (
                                <div className="capabilities-inline-actions">
                                  <button
                                    type="button"
                                    className="capabilities-inline-button"
                                    disabled={controller.engine.stagingBusy}
                                    onClick={() =>
                                      void controller.engine.stageOperation({
                                        subjectKind: record.kind,
                                        operation: "install",
                                        subjectId: entry.entryId,
                                        sourceUri: entry.sourceUri ?? null,
                                        notes: `Install ${entry.label} ${record.kind} payload from synced gallery ${record.label}.`,
                                      })
                                    }
                                  >
                                    {record.kind === "backend"
                                      ? "Stage backend"
                                      : "Stage install"}
                                  </button>
                                </div>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      ) : null}
                      <p className="capabilities-inline-note">
                        Source: {record.sourceUri}
                      </p>
                      {record.catalogPath ? (
                        <p className="capabilities-inline-note">
                          Catalog: {record.catalogPath}
                        </p>
                      ) : null}
                      {record.lastError ? (
                        <p className="capabilities-inline-note">
                          Last error: {record.lastError}
                        </p>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : (
                <p>No gallery catalogs have been reconciled yet.</p>
              )}
            </article>

            <article className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Control-plane jobs</h3>
                <span>{snapshot.jobs.length}</span>
              </div>
              {snapshot.jobs.length > 0 ? (
                <div className="capabilities-engine-job-list">
                  {snapshot.jobs.map((job) => (
                    <div
                      key={job.jobId}
                      className={`capabilities-engine-job-card status-${job.status}`}
                    >
                      <div className="capabilities-detail-card-head">
                        <h3>{job.title}</h3>
                        <span>{humanize(job.status)}</span>
                      </div>
                      <p>{job.summary}</p>
                      <div className="capabilities-engine-job-progress">
                        <span style={{ width: `${job.progressPercent}%` }} />
                      </div>
                      <div className="capabilities-detail-inline-meta">
                        <span>
                          Origin <strong>{humanize(job.origin)}</strong>
                        </span>
                        <span>
                          Updated{" "}
                          <strong>{formatEngineTimestamp(job.updatedAtMs)}</strong>
                        </span>
                        <span>
                          Progress <strong>{job.progressPercent}%</strong>
                        </span>
                      </div>
                      <div className="capabilities-chip-row">
                        <span className="capabilities-chip">
                          {humanize(job.subjectKind)}
                        </span>
                        <span className="capabilities-chip">
                          {humanize(job.operation)}
                        </span>
                        {job.subjectId ? (
                          <span className="capabilities-chip">{job.subjectId}</span>
                        ) : null}
                        {job.backendId ? (
                          <span className="capabilities-chip">{job.backendId}</span>
                        ) : null}
                      </div>
                      {job.sourceUri ? (
                        <p className="capabilities-inline-note">
                          Source: {job.sourceUri}
                        </p>
                      ) : null}
                      <div className="capabilities-action-row">
                        {!["running", "completed", "failed", "cancelled"].includes(
                          job.status,
                        ) ? (
                          <button
                            type="button"
                            className="capabilities-primary-button"
                            onClick={() =>
                              void controller.engine.updateJobStatus(
                                job.jobId,
                                "running",
                              )
                            }
                            disabled={controller.engine.stagingBusy}
                          >
                            Run
                          </button>
                        ) : null}
                        {job.status === "running" ? (
                          <>
                            <button
                              type="button"
                              className="capabilities-secondary-button"
                              onClick={() =>
                                void controller.engine.updateJobStatus(
                                  job.jobId,
                                  "completed",
                                )
                              }
                              disabled={controller.engine.stagingBusy}
                            >
                              Mark complete
                            </button>
                            <button
                              type="button"
                              className="capabilities-inline-button"
                              onClick={() =>
                                void controller.engine.updateJobStatus(
                                  job.jobId,
                                  "failed",
                                )
                              }
                              disabled={controller.engine.stagingBusy}
                            >
                              Mark failed
                            </button>
                          </>
                        ) : null}
                        {!["completed", "failed", "cancelled"].includes(job.status) ? (
                          <button
                            type="button"
                            className="capabilities-inline-button"
                            onClick={() =>
                              void controller.engine.updateJobStatus(
                                job.jobId,
                                "cancelled",
                              )
                            }
                            disabled={controller.engine.stagingBusy}
                          >
                            Cancel
                          </button>
                        ) : null}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p>No promoted Local Engine jobs yet.</p>
              )}
            </article>

            {snapshot.pendingControls.length > 0 ? (
              snapshot.pendingControls.map((action) => (
                <article
                  key={action.itemId}
                  className={`capabilities-detail-card capabilities-engine-queue-card severity-${action.severity}`}
                >
                  <div className="capabilities-detail-card-head">
                    <h3>{action.title}</h3>
                    <span>{action.severity}</span>
                  </div>
                  <p>{action.summary}</p>
                  <div className="capabilities-detail-inline-meta">
                    <span>
                      Status <strong>{humanize(action.status)}</strong>
                    </span>
                    <span>
                      Requested{" "}
                      <strong>{formatEngineTimestamp(action.requestedAtMs)}</strong>
                    </span>
                    {action.dueAtMs ? (
                      <span>
                        Due <strong>{formatEngineTimestamp(action.dueAtMs)}</strong>
                      </span>
                    ) : null}
                  </div>
                  <div className="capabilities-chip-row">
                    {action.approvalScope ? (
                      <span className="capabilities-chip">{action.approvalScope}</span>
                    ) : null}
                    {action.sensitiveActionType ? (
                      <span className="capabilities-chip">
                        {humanize(action.sensitiveActionType)}
                      </span>
                    ) : null}
                    {action.requestHash ? (
                      <span className="capabilities-chip">
                        Request {action.requestHash.slice(0, 12)}
                      </span>
                    ) : null}
                    {action.recommendedAction ? (
                      <span className="capabilities-chip">
                        {action.recommendedAction}
                      </span>
                    ) : null}
                  </div>
                  {action.recoveryHint ? (
                    <p className="capabilities-inline-note">{action.recoveryHint}</p>
                  ) : null}
                </article>
              ))
            ) : (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Registry queue</h3>
                  <span>Clear</span>
                </div>
                <p>
                  No model, backend, or gallery control actions are waiting on
                  the operator right now.
                </p>
              </section>
            )}
          </section>
        ) : null}

        {controller.engine.detailSection === "activity" ? (
          <section className="capabilities-engine-stack">
            {snapshot.recentActivity.length > 0 ? (
              snapshot.recentActivity.map((activity) => (
                <article
                  key={activity.eventId}
                  className={`capabilities-detail-card capabilities-engine-activity-card ${activity.success ? "is-success" : "is-failure"}`}
                >
                  <div className="capabilities-detail-card-head">
                    <h3>{activity.title}</h3>
                    <span>{activity.success ? "Success" : "Failure"}</span>
                  </div>
                  <div className="capabilities-detail-inline-meta">
                    <span>
                      Session{" "}
                      {onOpenSessionTarget ? (
                        <button
                          type="button"
                          className="capabilities-inline-button"
                          onClick={() => onOpenSessionTarget(activity.sessionId)}
                        >
                          {activity.sessionId.slice(0, 12)}
                        </button>
                      ) : (
                        <strong>{activity.sessionId.slice(0, 12)}</strong>
                      )}
                    </span>
                    <span>
                      Tool <strong>{activity.toolName}</strong>
                    </span>
                    <span>
                      Captured{" "}
                      <strong>{formatEngineTimestamp(activity.timestampMs)}</strong>
                    </span>
                  </div>
                  <div className="capabilities-chip-row">
                    <span className="capabilities-chip">{humanize(activity.family)}</span>
                    {activity.operation ? (
                      <span className="capabilities-chip">
                        {humanize(activity.operation)}
                      </span>
                    ) : null}
                    {activity.subjectKind ? (
                      <span className="capabilities-chip">
                        {humanize(activity.subjectKind)}
                      </span>
                    ) : null}
                    {activity.subjectId ? (
                      <span className="capabilities-chip">{activity.subjectId}</span>
                    ) : null}
                  </div>
                  {activity.errorClass ? (
                    <p className="capabilities-inline-note">
                      Error class: {activity.errorClass}
                    </p>
                  ) : null}
                </article>
              ))
            ) : (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Recent activity</h3>
                </div>
                <p>No absorbed local engine receipts have been observed yet.</p>
              </section>
            )}
          </section>
        ) : null}

        {controller.engine.detailSection === "families" ? (
          controller.engine.selectedFamily ? (
            <section className="capabilities-engine-stack">
              <article className="capabilities-detail-card capabilities-engine-family-focus">
                <div className="capabilities-detail-card-head">
                  <h3>{controller.engine.selectedFamily.label}</h3>
                  <span>{controller.engine.selectedFamily.status}</span>
                </div>
                <p>{controller.engine.selectedFamily.description}</p>
                <p className="capabilities-inline-note">
                  {controller.engine.selectedFamily.operatorSummary}
                </p>
                <div className="capabilities-chip-row">
                  {controller.engine.selectedFamily.toolNames.length > 0 ? (
                    controller.engine.selectedFamily.toolNames.map((toolName) => (
                      <span key={toolName} className="capabilities-chip">
                        {toolName}
                      </span>
                    ))
                  ) : (
                    <span className="capabilities-chip">No runtime tools yet</span>
                  )}
                </div>
              </article>
              {controller.engine.selectedFamily.id === "workers" ? (
                <>
                  <article className="capabilities-detail-card">
                    <div className="capabilities-detail-card-head">
                      <h3>Live playbook runs</h3>
                      <span>{snapshot.parentPlaybookRuns.length}</span>
                    </div>
                    <div className="capabilities-detail-inline-meta">
                      <span>
                        Active <strong>{activeParentPlaybookRunCount}</strong>
                      </span>
                      <span>
                        Blocked <strong>{blockedParentPlaybookRunCount}</strong>
                      </span>
                      <span>
                        Completed{" "}
                        <strong>
                          {
                            snapshot.parentPlaybookRuns.filter(
                              (run) => run.status === "completed",
                            ).length
                          }
                        </strong>
                      </span>
                    </div>
                    {snapshot.parentPlaybookRuns.length > 0 ? (
                      <div className="capabilities-engine-state-list">
                        {snapshot.parentPlaybookRuns.map((run) => {
                          const currentStep =
                            run.steps.find((step) => step.stepId === run.currentStepId) ??
                            null;
                          const canDismissRun = ["blocked", "completed", "failed"].includes(
                            run.status,
                          );

                          return (
                            <div
                              key={run.runId}
                              className={`capabilities-engine-state-card status-${run.status}`}
                            >
                              <div className="capabilities-detail-card-head">
                                <h3>{run.playbookLabel}</h3>
                                <span>{humanize(run.status)}</span>
                              </div>
                              <p>{run.summary}</p>
                              <div className="capabilities-detail-inline-meta">
                                <span>
                                  Phase <strong>{humanize(run.latestPhase)}</strong>
                                </span>
                                <span>
                                  Session{" "}
                                  {onOpenSessionTarget ? (
                                    <button
                                      type="button"
                                      className="capabilities-inline-button"
                                      onClick={() =>
                                        onOpenSessionTarget(run.parentSessionId)
                                      }
                                    >
                                      {formatEngineIdentifier(run.parentSessionId)}
                                    </button>
                                  ) : (
                                    <strong>
                                      {formatEngineIdentifier(run.parentSessionId)}
                                    </strong>
                                  )}
                                </span>
                                <span>
                                  Current step{" "}
                                  <strong>
                                    {run.currentStepLabel ?? "Awaiting next step"}
                                  </strong>
                                </span>
                                <span>
                                  Updated{" "}
                                  <strong>
                                    {formatEngineTimestamp(run.updatedAtMs)}
                                  </strong>
                                </span>
                                {run.completedAtMs ? (
                                  <span>
                                    Completed{" "}
                                    <strong>
                                      {formatEngineTimestamp(run.completedAtMs)}
                                    </strong>
                                  </span>
                                ) : null}
                                {run.activeChildSessionId ? (
                                  <span>
                                    Child{" "}
                                    {onOpenSessionTarget ? (
                                      <button
                                        type="button"
                                        className="capabilities-inline-button"
                                        onClick={() =>
                                          onOpenSessionTarget(run.activeChildSessionId!)
                                        }
                                      >
                                        {formatEngineIdentifier(
                                          run.activeChildSessionId,
                                        )}
                                      </button>
                                    ) : (
                                      <strong>
                                        {formatEngineIdentifier(
                                          run.activeChildSessionId,
                                        )}
                                      </strong>
                                    )}
                                  </span>
                                ) : null}
                              </div>
                              {run.errorClass ? (
                                <p className="capabilities-inline-note">
                                  Issue: {run.errorClass}
                                </p>
                              ) : null}
                              {currentStep || canDismissRun ? (
                                <div className="capabilities-inline-actions">
                                  {run.status === "blocked" && currentStep ? (
                                    <button
                                      type="button"
                                      className="capabilities-primary-button"
                                      disabled={controller.engine.stagingBusy}
                                      onClick={() =>
                                        void controller.engine.retryParentPlaybookRun(
                                          run.runId,
                                        )
                                      }
                                    >
                                      Retry step
                                    </button>
                                  ) : null}
                                  {currentStep ? (
                                    <button
                                      type="button"
                                      className="capabilities-secondary-button"
                                      disabled={controller.engine.stagingBusy}
                                      onClick={() =>
                                        void controller.engine.resumeParentPlaybookRun(
                                          run.runId,
                                          currentStep.stepId,
                                        )
                                      }
                                    >
                                      Resume current step
                                    </button>
                                  ) : null}
                                  {canDismissRun ? (
                                    <button
                                      type="button"
                                      className="capabilities-secondary-button"
                                      disabled={controller.engine.stagingBusy}
                                      onClick={() =>
                                        void controller.engine.dismissParentPlaybookRun(
                                          run.runId,
                                        )
                                      }
                                    >
                                      Dismiss run
                                    </button>
                                  ) : null}
                                </div>
                              ) : null}
                              <div className="capabilities-playbook-step-grid">
                                {run.steps.map((step) => (
                                  <div
                                    key={`${run.runId}:${step.stepId}`}
                                    className={`capabilities-engine-state-card capabilities-playbook-step-card status-${step.status}`}
                                  >
                                    <div className="capabilities-detail-card-head">
                                      <h3>{step.label}</h3>
                                      <span>{humanize(step.status)}</span>
                                    </div>
                                    <p>{step.summary}</p>
                                    <div className="capabilities-detail-inline-meta">
                                      {step.templateId ? (
                                        <span>
                                          Worker <strong>{step.templateId}</strong>
                                        </span>
                                      ) : null}
                                      {step.workflowId ? (
                                        <span>
                                          Workflow{" "}
                                          <strong>{step.workflowId}</strong>
                                        </span>
                                      ) : null}
                                      {step.childSessionId ? (
                                        <span>
                                          Child{" "}
                                          {onOpenSessionTarget ? (
                                            <button
                                              type="button"
                                              className="capabilities-inline-button"
                                              onClick={() =>
                                                onOpenSessionTarget(step.childSessionId!)
                                              }
                                            >
                                              {formatEngineIdentifier(
                                                step.childSessionId,
                                              )}
                                            </button>
                                          ) : (
                                            <strong>
                                              {formatEngineIdentifier(
                                                step.childSessionId,
                                              )}
                                            </strong>
                                          )}
                                        </span>
                                      ) : null}
                                      {step.updatedAtMs ? (
                                        <span>
                                          Updated{" "}
                                          <strong>
                                            {formatEngineTimestamp(step.updatedAtMs)}
                                          </strong>
                                        </span>
                                      ) : null}
                                    </div>
                                    {step.errorClass ? (
                                      <p className="capabilities-inline-note">
                                        Issue: {step.errorClass}
                                      </p>
                                    ) : null}
                                    {step.status !== "pending" ? (
                                      <div className="capabilities-inline-actions">
                                        <button
                                          type="button"
                                          className="capabilities-inline-button"
                                          disabled={controller.engine.stagingBusy}
                                          onClick={() =>
                                            void controller.engine.resumeParentPlaybookRun(
                                              run.runId,
                                              step.stepId,
                                            )
                                          }
                                        >
                                          Resume here
                                        </button>
                                      </div>
                                    ) : null}
                                    {step.receipts.length > 0 ? (
                                      <div className="capabilities-playbook-receipt-list">
                                        {step.receipts.map((receipt) => (
                                          <div
                                            key={receipt.eventId}
                                            className={`capabilities-playbook-receipt ${receipt.success ? "is-success" : "is-failure"}`}
                                          >
                                            <div className="capabilities-detail-inline-meta">
                                              <span>
                                                Phase{" "}
                                                <strong>
                                                  {humanize(receipt.phase)}
                                                </strong>
                                              </span>
                                              <span>
                                                Status{" "}
                                                <strong>
                                                  {humanize(receipt.status)}
                                                </strong>
                                              </span>
                                              <span>
                                                At{" "}
                                                <strong>
                                                  {formatEngineTimestamp(
                                                    receipt.timestampMs,
                                                  )}
                                                </strong>
                                              </span>
                                              {receipt.receiptRef ? (
                                                <span>
                                                  Receipt{" "}
                                                  <strong>
                                                    {formatEngineIdentifier(
                                                      receipt.receiptRef,
                                                    )}
                                                  </strong>
                                                </span>
                                              ) : null}
                                            </div>
                                            <p className="capabilities-inline-note">
                                              {receipt.summary}
                                            </p>
                                            {receipt.artifactIds.length > 0 ? (
                                              <div className="capabilities-chip-row">
                                                {receipt.artifactIds.map(
                                                  (artifactId) => (
                                                    <button
                                                      type="button"
                                                      key={`${receipt.eventId}:${artifactId}`}
                                                      className="capabilities-chip capabilities-inline-button"
                                                      onClick={() =>
                                                        onOpenArtifact?.(artifactId)
                                                      }
                                                    >
                                                      Artifact{" "}
                                                      {formatEngineIdentifier(
                                                        artifactId,
                                                      )}
                                                    </button>
                                                  ),
                                                )}
                                              </div>
                                            ) : null}
                                          </div>
                                        ))}
                                      </div>
                                    ) : (
                                      <p className="capabilities-inline-note">
                                        No typed receipts recorded for this step yet.
                                      </p>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <p>
                        No parent playbook runs have been observed yet. Trigger a
                        parity or evidence-audited patch task to watch the
                        research, implementation, and audit phases materialize
                        here.
                      </p>
                    )}
                  </article>

                  <article className="capabilities-detail-card">
                    <div className="capabilities-detail-card-head">
                      <h3>Parent playbooks</h3>
                      <span>{snapshot.agentPlaybooks.length}</span>
                    </div>
                    {snapshot.agentPlaybooks.length > 0 ? (
                      <div className="capabilities-engine-state-list">
                        {snapshot.agentPlaybooks.map((playbook) => (
                          <div
                            key={playbook.playbookId}
                            className="capabilities-engine-state-card status-ready"
                          >
                            <div className="capabilities-detail-card-head">
                              <h3>{playbook.label}</h3>
                              <span>{playbook.playbookId}</span>
                            </div>
                            <p>{playbook.summary}</p>
                            <div className="capabilities-detail-inline-meta">
                              <span>
                                Budget <strong>{playbook.defaultBudget}</strong>
                              </span>
                              <span>
                                Merge{" "}
                                <strong>
                                  {humanize(playbook.completionContract.mergeMode)}
                                </strong>
                              </span>
                              <span>
                                Steps <strong>{playbook.steps.length}</strong>
                              </span>
                            </div>
                            <p className="capabilities-inline-note">
                              Goal template: {playbook.goalTemplate}
                            </p>
                            <p className="capabilities-inline-note">
                              Final success contract:{" "}
                              {playbook.completionContract.successCriteria}
                            </p>
                            <p className="capabilities-inline-note">
                              Final expected output:{" "}
                              {playbook.completionContract.expectedOutput}
                            </p>
                            {playbook.completionContract.verificationHint ? (
                              <p className="capabilities-inline-note">
                                Verification:{" "}
                                {playbook.completionContract.verificationHint}
                              </p>
                            ) : null}
                            <div className="capabilities-chip-row">
                              {playbook.triggerIntents.map((intentId) => (
                                <span
                                  key={`${playbook.playbookId}:${intentId}`}
                                  className="capabilities-chip"
                                >
                                  {intentId}
                                </span>
                              ))}
                              {playbook.recommendedFor.map((hint) => (
                                <span
                                  key={`${playbook.playbookId}:${hint}`}
                                  className="capabilities-chip"
                                >
                                  {hint}
                                </span>
                              ))}
                            </div>
                            <div className="capabilities-engine-state-list">
                              {playbook.steps.map((step) => (
                                <div
                                  key={`${playbook.playbookId}:${step.stepId}`}
                                  className="capabilities-engine-state-card status-ready"
                                >
                                  <div className="capabilities-detail-card-head">
                                    <h3>{step.label}</h3>
                                    <span>{step.stepId}</span>
                                  </div>
                                  <p>{step.summary}</p>
                                  <p className="capabilities-inline-note">
                                    Worker contract: {step.workerTemplateId}/
                                    {step.workerWorkflowId}
                                  </p>
                                  <p className="capabilities-inline-note">
                                    Goal template: {step.goalTemplate}
                                  </p>
                                  {step.dependsOn.length > 0 ? (
                                    <div className="capabilities-chip-row">
                                      {step.dependsOn.map((dependency) => (
                                        <span
                                          key={`${step.stepId}:${dependency}`}
                                          className="capabilities-chip"
                                        >
                                          depends on {dependency}
                                        </span>
                                      ))}
                                    </div>
                                  ) : null}
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p>No parent playbooks are registered yet.</p>
                    )}
                  </article>

                  <article className="capabilities-detail-card">
                    <div className="capabilities-detail-card-head">
                      <h3>Worker templates</h3>
                      <span>{snapshot.workerTemplates.length}</span>
                    </div>
                    {snapshot.workerTemplates.length > 0 ? (
                      <div className="capabilities-engine-state-list">
                        {snapshot.workerTemplates.map((template) => (
                          <div
                            key={template.templateId}
                            className="capabilities-engine-state-card status-ready"
                          >
                            <div className="capabilities-detail-card-head">
                              <h3>{template.label}</h3>
                              <span>{template.role}</span>
                            </div>
                            <p>{template.summary}</p>
                            <div className="capabilities-detail-inline-meta">
                              <span>
                                Budget <strong>{template.defaultBudget}</strong>
                              </span>
                              <span>
                                Retries <strong>{template.maxRetries}</strong>
                              </span>
                              <span>
                                Merge{" "}
                                <strong>
                                  {humanize(template.completionContract.mergeMode)}
                                </strong>
                              </span>
                            </div>
                            <div className="capabilities-chip-row">
                              <span className="capabilities-chip">
                                {template.templateId}
                              </span>
                              {template.allowedTools.map((toolName) => (
                                <span
                                  key={`${template.templateId}:${toolName}`}
                                  className="capabilities-chip"
                                >
                                  {toolName}
                                </span>
                              ))}
                            </div>
                            <p className="capabilities-inline-note">
                              Success criteria:{" "}
                              {template.completionContract.successCriteria}
                            </p>
                            <p className="capabilities-inline-note">
                              Expected output:{" "}
                              {template.completionContract.expectedOutput}
                            </p>
                            {template.completionContract.verificationHint ? (
                              <p className="capabilities-inline-note">
                                Verification:{" "}
                                {template.completionContract.verificationHint}
                              </p>
                            ) : null}
                            {template.workflows.length > 0 ? (
                              <div className="capabilities-engine-state-list">
                                {template.workflows.map((workflow) => (
                                  <div
                                    key={`${template.templateId}:${workflow.workflowId}`}
                                    className="capabilities-engine-state-card status-ready"
                                  >
                                    <div className="capabilities-detail-card-head">
                                      <h3>{workflow.label}</h3>
                                      <span>{workflow.workflowId}</span>
                                    </div>
                                    <p>{workflow.summary}</p>
                                    <p className="capabilities-inline-note">
                                      Goal template: {workflow.goalTemplate}
                                    </p>
                                    <div className="capabilities-detail-inline-meta">
                                      {workflow.defaultBudget != null ? (
                                        <span>
                                          Budget <strong>{workflow.defaultBudget}</strong>
                                        </span>
                                      ) : null}
                                      {workflow.maxRetries != null ? (
                                        <span>
                                          Retries <strong>{workflow.maxRetries}</strong>
                                        </span>
                                      ) : null}
                                    </div>
                                    {workflow.completionContract ? (
                                      <>
                                        <p className="capabilities-inline-note">
                                          Success criteria:{" "}
                                          {workflow.completionContract.successCriteria}
                                        </p>
                                        <p className="capabilities-inline-note">
                                          Expected output:{" "}
                                          {workflow.completionContract.expectedOutput}
                                        </p>
                                        {workflow.completionContract.verificationHint ? (
                                          <p className="capabilities-inline-note">
                                            Verification:{" "}
                                            {workflow.completionContract.verificationHint}
                                          </p>
                                        ) : null}
                                      </>
                                    ) : null}
                                    <div className="capabilities-chip-row">
                                      {workflow.allowedTools.map((toolName) => (
                                        <span
                                          key={`${workflow.workflowId}:${toolName}`}
                                          className="capabilities-chip"
                                        >
                                          {toolName}
                                        </span>
                                      ))}
                                      {workflow.triggerIntents.map((intentId) => (
                                        <span
                                          key={`${workflow.workflowId}:${intentId}`}
                                          className="capabilities-chip"
                                        >
                                          {intentId}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            ) : null}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p>No worker templates are registered yet.</p>
                    )}
                  </article>
                </>
              ) : null}
            </section>
          ) : (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Capability family</h3>
              </div>
              <p>Select a family from the left to inspect its runtime surface.</p>
            </section>
          )
        ) : null}
      </DetailDocument>
    </div>
  );
}
