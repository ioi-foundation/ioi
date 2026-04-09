import type { ConnectorSummary } from "@ioi/agent-ide";
import {
  buildExtensionTrustProfile,
  connectorStatusLabel,
  formatSuccessRate,
  groupLabelForConnection,
  humanize,
  providerAccent,
  templateLabelForConnection,
  type CapabilityTrustProfile,
  type CapabilityTreeEntry,
  type WorkspaceSkill,
} from "./model";
import { type CapabilitiesController } from "./useCapabilitiesController";
import {
  ArrowLeftIcon,
  BlocksIcon,
  CableIcon,
  CheckCircleIcon,
  ChevronRightIcon,
  CpuIcon,
  MenuButton,
  SearchIcon,
  SparklesIcon,
  XIcon,
} from "./ui";
import { StudioLeftSidebarShell } from "../StudioLeftSidebarShell";

function renderTreeEntries(entries: CapabilityTreeEntry[]) {
  return (
    <div className="capabilities-tree-children">
      {entries.map((entry) => (
        <button
          key={entry.id}
          type="button"
          className={`capabilities-tree-child ${entry.active ? "is-active" : ""}`}
          onClick={entry.onSelect}
          aria-current={entry.active ? "page" : undefined}
        >
          <span className="capabilities-tree-rail" aria-hidden="true" />
          <span className="capabilities-tree-copy">
            <strong>{entry.label}</strong>
            <small>{entry.note}</small>
          </span>
          {entry.meta ? (
            <span className="capabilities-tree-meta">{entry.meta}</span>
          ) : null}
        </button>
      ))}
    </div>
  );
}

function renderSkillList(
  controller: CapabilitiesController,
  onOpenSkillSources?: () => void,
) {
  const runtimeObserved = controller.skills.filteredItems.filter(
    (skill) => skill.origin === "runtime",
  );
  const filesystemBacked = controller.skills.filteredItems.filter(
    (skill) => skill.origin === "filesystem",
  );

  if (controller.skills.loading) {
    return (
      <div className="capabilities-empty-state">
        Loading runtime and filesystem skill inventory...
      </div>
    );
  }

  if (controller.skills.error) {
    if (controller.skills.filteredItems.length === 0) {
      return (
        <div className="capabilities-empty-state">
          Skill inventory unavailable: {controller.skills.error}
        </div>
      );
    }
  }

  const skillEntriesFor = (skill: WorkspaceSkill): CapabilityTreeEntry[] => [
    {
      id: "guide",
      label: "SKILL.md",
      note:
        skill.origin === "runtime"
          ? "Primary markdown instructions for the reusable behavior"
          : "Filesystem-backed instructions discovered on disk",
      meta:
        skill.origin === "filesystem"
          ? skill.relativePath ?? "Filesystem"
          : skill.detailStatus === "error"
          ? "Unavailable"
          : skill.detailStatus === "ready"
            ? "Markdown"
            : "Loading",
      active: controller.skills.detailSection === "guide",
      onSelect: () => controller.skills.setDetailSection("guide"),
    },
    {
      id: "overview",
      label: "Overview",
      note:
        skill.origin === "runtime"
          ? "Benchmarks, tool bundle, and operating posture"
          : "Source root, sync posture, and runtime readiness",
      meta:
        skill.origin === "filesystem"
          ? skill.sourceLabel ?? "Filesystem"
          : skill.detailStatus === "ready" && skill.detail
          ? formatSuccessRate(skill.detail.benchmark.success_rate_bps)
          : skill.detailStatus === "error"
            ? "Unavailable"
            : "Loading",
      active: controller.skills.detailSection === "overview",
      onSelect: () => controller.skills.setDetailSection("overview"),
    },
    {
      id: "procedure",
      label: skill.origin === "runtime" ? "Procedure" : "Selection",
      note:
        skill.origin === "runtime"
          ? "Observed execution outline and tool sequence"
          : "Why this filesystem skill is available for future runtime selection",
      meta:
        skill.origin === "filesystem"
          ? skill.syncStatus ? humanize(skill.syncStatus) : "Filesystem"
          : skill.detailStatus === "ready" && skill.detail
          ? skill.detail.steps.length > 0
            ? `${skill.detail.steps.length} steps`
            : "Macro"
          : skill.detailStatus === "error"
            ? "Unavailable"
            : "Loading",
      active: controller.skills.detailSection === "procedure",
      onSelect: () => controller.skills.setDetailSection("procedure"),
    },
  ];

  const renderSkillGroup = (title: string, items: WorkspaceSkill[]) => {
    if (items.length === 0) return null;
    return (
      <section className="capabilities-list-group">
        <div className="capabilities-list-group-head">
          <h3>{title}</h3>
          <span>{items.length}</span>
        </div>
        <div className="capabilities-list-rows">
          {items.map((skill) => {
            const isSelected = controller.skills.selectedSkillHash === skill.hash;
            const entries = skillEntriesFor(skill);

            return (
              <div
                key={skill.hash}
                className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
              >
                <button
                  type="button"
                  className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                  onClick={() => controller.skills.setSelectedSkillHash(skill.hash)}
                >
                  <span className="capabilities-row-icon capabilities-row-icon-skill">
                    <SparklesIcon />
                  </span>
                  <span className="capabilities-row-copy">
                    <strong>{skill.catalog.name}</strong>
                    <small>{skill.catalog.description}</small>
                  </span>
                  <span className="capabilities-row-meta">
                    {skill.origin === "runtime" ? "Runtime" : "Filesystem"}
                  </span>
                  <span
                    className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                    aria-hidden="true"
                  >
                    <ChevronRightIcon />
                  </span>
                </button>

                {isSelected ? renderTreeEntries(entries) : null}
              </div>
            );
          })}
        </div>
      </section>
    );
  };

  return (
    <>
      <div className="capabilities-list-toolbar">
        {onOpenSkillSources ? (
          <button
            type="button"
            className="capabilities-secondary-button"
            onClick={onOpenSkillSources}
          >
            Open skill sources
          </button>
        ) : null}
        <span className="capabilities-list-toolbar-meta">
          {controller.sourceRegistry.count === 1
            ? "1 tracked root"
            : `${controller.sourceRegistry.count} tracked roots`}
        </span>
      </div>
      {controller.sourceRegistry.message ? (
        <div className="capabilities-inline-note">
          {controller.sourceRegistry.message}
        </div>
      ) : null}
      {controller.sourceRegistry.error ? (
        <div className="capabilities-inline-note">
          {controller.sourceRegistry.error}
        </div>
      ) : null}
      {controller.skills.error && controller.skills.filteredItems.length > 0 ? (
        <div className="capabilities-inline-note">
          Inventory partially unavailable: {controller.skills.error}
        </div>
      ) : null}
      {renderSkillGroup("Observed in runtime", runtimeObserved)}
      {renderSkillGroup("Filesystem-backed", filesystemBacked)}
      {controller.skills.filteredItems.length === 0 ? (
        <div className="capabilities-empty-state">
          {controller.skills.items.length === 0
            ? "No runtime or filesystem-backed skills are visible yet."
            : "No skills match the current search."}
        </div>
      ) : null}
    </>
  );
}

function renderConnectionList(
  controller: CapabilitiesController,
  getConnectorTrustProfile?: (
    connector: ConnectorSummary,
    options?: { template?: boolean },
  ) => CapabilityTrustProfile | null,
) {
  const hasTemplates = controller.connections.filteredTemplates.length > 0;

  if (
    controller.connections.loading &&
    controller.connections.items.length === 0 &&
    !hasTemplates
  ) {
    return (
      <div className="capabilities-empty-state">
        Loading live connector catalog...
      </div>
    );
  }

  if (
    controller.connections.error &&
    controller.connections.items.length === 0 &&
    !hasTemplates
  ) {
    return (
      <div className="capabilities-empty-state">
        Live connector catalog unavailable: {controller.connections.error}
      </div>
    );
  }

  const groups = [
    "Not connected",
    "Connected",
    "Needs attention",
  ];

  return (
    <>
      {controller.connections.error && hasTemplates ? (
        <div className="capabilities-inline-note">
          Live connector catalog unavailable: {controller.connections.error}
        </div>
      ) : null}
      {groups.map((group) => {
        const groupItems = controller.connections.filteredItems.filter(
          ({ connector }) => groupLabelForConnection(connector) === group,
        );
        if (groupItems.length === 0) return null;
        return (
          <section key={group} className="capabilities-list-group">
            <div className="capabilities-list-group-head">
              <h3>{group}</h3>
              <span>{groupItems.length}</span>
            </div>
            <div className="capabilities-list-rows">
              {groupItems.map(({ connector }) => {
                const isSelected =
                  controller.connections.selectedConnectionId === connector.id;
                const trustProfile =
                  getConnectorTrustProfile?.(connector) ?? null;
                const actionState = controller.connections.getActionState(
                  connector.id,
                );
                const entries: CapabilityTreeEntry[] = [
                  {
                    id: "overview",
                    label: "Overview",
                    note: "Scopes, notes, and capability reach",
                    meta: `${connector.scopes.length} scopes`,
                    active: controller.connections.detailSection === "overview",
                    onSelect: () =>
                      controller.connections.setDetailSection("overview"),
                  },
                  {
                    id: "setup",
                    label: "Setup",
                    note:
                      "Attach auth and unlock callable actions",
                    meta: "Live",
                    active: controller.connections.detailSection === "setup",
                    onSelect: () =>
                      controller.connections.setDetailSection("setup"),
                  },
                  {
                    id: "actions",
                    label: "Actions",
                    note:
                      "Inspect live tools, field requirements, and confirm-before-run posture",
                    meta:
                      actionState.status === "ready"
                        ? `${actionState.actions.length} tools`
                        : actionState.status === "error"
                          ? "Retry"
                          : actionState.status === "loading"
                            ? "Loading"
                            : "Live tools",
                    active: controller.connections.detailSection === "actions",
                    onSelect: () =>
                      controller.connections.setDetailSection("actions"),
                  },
                  {
                    id: "policy",
                    label: "Policy",
                    note:
                      "Governance, approvals, and connector-specific controls",
                    meta: trustProfile?.tierLabel ?? "Guardrails",
                    active: controller.connections.detailSection === "policy",
                    onSelect: () =>
                      controller.connections.setDetailSection("policy"),
                  },
                ];

                return (
                  <div
                    key={connector.id}
                    className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
                  >
                    <button
                      type="button"
                      className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                      onClick={() =>
                        controller.connections.setSelectedConnectionId(
                          connector.id,
                        )
                      }
                    >
                      <span
                        className="capabilities-provider-badge"
                        style={{ color: providerAccent(connector.provider) }}
                      >
                        {connector.name.slice(0, 1)}
                      </span>
                      <span className="capabilities-row-copy">
                        <strong>{connector.name}</strong>
                        <small>{connector.description}</small>
                      </span>
                      <span
                        className={`capabilities-row-status status-${connector.status}`}
                      >
                        {connectorStatusLabel(connector.status)}
                      </span>
                      <span
                        className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                        aria-hidden="true"
                      >
                        <ChevronRightIcon />
                      </span>
                    </button>

                    {isSelected ? renderTreeEntries(entries) : null}
                  </div>
                );
              })}
            </div>
          </section>
        );
      })}
      {controller.connections.filteredTemplates.length > 0 ? (
        <section className="capabilities-list-group">
          <div className="capabilities-list-group-head">
            <h3>Workspace planning templates</h3>
            <span>{controller.connections.filteredTemplates.length}</span>
          </div>
          <div className="capabilities-list-rows">
            {controller.connections.filteredTemplates.map((template) => {
              const { connector } = template;
              const isSelected =
                controller.connections.selectedTemplateId === connector.id;
              const trustProfile =
                getConnectorTrustProfile?.(connector, { template: true }) ??
                null;
              const entries: CapabilityTreeEntry[] = [
                {
                  id: "overview",
                  label: "Overview",
                  note: "Planned scopes, notes, and intended capability reach",
                  meta: `${connector.scopes.length} scopes`,
                  active: controller.connections.detailSection === "overview",
                  onSelect: () =>
                    controller.connections.setDetailSection("overview"),
                },
                {
                  id: "setup",
                  label: "Planning notes",
                  note:
                    "Track adapter intent, ownership, and runtime prerequisites outside the live catalog",
                  meta: templateLabelForConnection(template),
                  active: controller.connections.detailSection === "setup",
                  onSelect: () =>
                    controller.connections.setDetailSection("setup"),
                },
                {
                  id: "policy",
                  label: "Policy",
                  note:
                    "Review guardrails teams expect once this template becomes a live connector",
                  meta: trustProfile?.tierLabel ?? "Guardrails",
                  active: controller.connections.detailSection === "policy",
                  onSelect: () =>
                    controller.connections.setDetailSection("policy"),
                },
              ];

              return (
                <div
                  key={connector.id}
                  className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
                >
                  <button
                    type="button"
                    className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                    onClick={() =>
                      controller.connections.setSelectedTemplateId(connector.id)
                    }
                  >
                    <span
                      className="capabilities-provider-badge"
                      style={{ color: providerAccent(connector.provider) }}
                    >
                      {connector.name.slice(0, 1)}
                    </span>
                    <span className="capabilities-row-copy">
                      <strong>{connector.name}</strong>
                      <small>{connector.description}</small>
                    </span>
                    <span className="capabilities-row-meta">
                      {templateLabelForConnection(template)}
                    </span>
                    <span
                      className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                      aria-hidden="true"
                    >
                      <ChevronRightIcon />
                    </span>
                  </button>

                  {isSelected ? renderTreeEntries(entries) : null}
                </div>
              );
            })}
          </div>
        </section>
      ) : null}
      {controller.connections.filteredItems.length === 0 &&
      controller.connections.filteredTemplates.length === 0 ? (
        <div className="capabilities-empty-state">
          No live connectors or workspace planning templates match the current search.
        </div>
      ) : null}
    </>
  );
}

function renderExtensionList(
  controller: CapabilitiesController,
  onOpenSkillSources?: () => void,
) {
  if (controller.extensions.loading) {
    return (
      <div className="capabilities-empty-state">
        Loading extension manifests...
      </div>
    );
  }

  if (controller.extensions.error && controller.extensions.filteredItems.length === 0) {
    return (
      <div className="capabilities-empty-state">
        Extension inventory unavailable: {controller.extensions.error}
      </div>
    );
  }

  return (
    <>
      <div className="capabilities-list-toolbar">
        {onOpenSkillSources ? (
          <button
            type="button"
            className="capabilities-secondary-button"
            onClick={onOpenSkillSources}
          >
            Open skill sources
          </button>
        ) : null}
        <span className="capabilities-list-toolbar-meta">
          {controller.sourceRegistry.count === 1
            ? "1 tracked root"
            : `${controller.sourceRegistry.count} tracked roots`}
        </span>
      </div>
      {controller.sourceRegistry.message ? (
        <div className="capabilities-inline-note">
          {controller.sourceRegistry.message}
        </div>
      ) : null}
      {controller.sourceRegistry.error ? (
        <div className="capabilities-inline-note">
          {controller.sourceRegistry.error}
        </div>
      ) : null}
      {controller.extensions.error && controller.extensions.filteredItems.length > 0 ? (
        <div className="capabilities-inline-note">
          Extension inventory partially unavailable: {controller.extensions.error}
        </div>
      ) : null}
      <section className="capabilities-list-group">
        <div className="capabilities-list-group-head">
          <h3>Manifest-backed extensions</h3>
          <span>{controller.extensions.filteredItems.length}</span>
        </div>
        <div className="capabilities-list-rows">
          {controller.extensions.filteredItems.map((extension) => {
            const isSelected =
              controller.extensions.selectedExtensionId === extension.id;
            const trustProfile = buildExtensionTrustProfile(extension);
            const entries: CapabilityTreeEntry[] = [
              {
                id: "overview",
                label: "Overview",
                note: "Manifest provenance, policy posture, and source visibility",
                meta: trustProfile.governedProfileLabel,
                active: controller.extensions.detailSection === "overview",
                onSelect: () =>
                  controller.extensions.setDetailSection("overview"),
              },
              {
                id: "manifest",
                label: "Manifest",
                note: "Display metadata, prompts, and declared package identity",
                meta: extension.version ? `v${extension.version}` : extension.manifestKind,
                active: controller.extensions.detailSection === "manifest",
                onSelect: () =>
                  controller.extensions.setDetailSection("manifest"),
              },
              {
                id: "contributions",
                label: "Contributions",
                note: "Filesystem skills, MCP servers, hooks, apps, and capabilities",
                meta: `${extension.contributionCount} items`,
                active: controller.extensions.detailSection === "contributions",
                onSelect: () =>
                  controller.extensions.setDetailSection("contributions"),
              },
            ];

            return (
              <div
                key={extension.id}
                className={`capabilities-tree-item ${isSelected ? "is-open" : ""}`}
              >
                <button
                  type="button"
                  className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                  onClick={() =>
                    controller.extensions.setSelectedExtensionId(extension.id)
                  }
                >
                  <span className="capabilities-row-icon capabilities-row-icon-extension">
                    <BlocksIcon />
                  </span>
                  <span className="capabilities-row-copy">
                    <strong>{extension.name}</strong>
                    <small>{extension.description}</small>
                  </span>
                  <span className="capabilities-row-meta">
                    {trustProfile.tierLabel}
                  </span>
                  <span
                    className={`capabilities-row-caret ${isSelected ? "is-open" : ""}`}
                    aria-hidden="true"
                  >
                    <ChevronRightIcon />
                  </span>
                </button>

                {isSelected ? renderTreeEntries(entries) : null}
              </div>
            );
          })}
        </div>
      </section>
      {controller.extensions.filteredItems.length === 0 ? (
        <div className="capabilities-empty-state">
          {controller.extensions.items.length === 0
            ? "No extension manifests are visible from the workspace, registered skill roots, or home plugin directory."
            : "No extension manifests match the current search."}
        </div>
      ) : null}
    </>
  );
}

function renderEngineList(controller: CapabilitiesController) {
  const snapshot = controller.engine.snapshot;

  if (controller.engine.loading) {
    return (
      <div className="capabilities-empty-state">
        Loading kernel-native engine posture…
      </div>
    );
  }

  if (controller.engine.error) {
    return (
      <div className="capabilities-empty-state">
        {controller.engine.error}
      </div>
    );
  }

  const overviewEntries: CapabilityTreeEntry[] = [
    {
      id: "overview",
      label: "Overview",
      note: "Operator-facing posture for the absorbed local engine",
      meta: snapshot ? `${snapshot.totalNativeTools} tools` : "Unavailable",
      active: controller.engine.detailSection === "overview",
      onSelect: () => controller.engine.setDetailSection("overview"),
    },
    {
      id: "runtime",
      label: "Runtime",
      note: "Execution mode, compatibility facades, launcher parity, and residency",
      meta: snapshot ? humanize(snapshot.controlPlane.runtime.mode) : "Runtime",
      active: controller.engine.detailSection === "runtime",
      onSelect: () => controller.engine.setDetailSection("runtime"),
    },
    {
      id: "configuration",
      label: "Settings bridge",
      note: "Review runtime config posture here, then edit authoritative values in System Settings",
      meta: controller.engine.configDirty ? "Draft differs" : "Synced",
      active: controller.engine.detailSection === "configuration",
      onSelect: () => controller.engine.setDetailSection("configuration"),
    },
    {
      id: "catalogs",
      label: "Catalogs",
      note: "Gallery parity, migration lanes, and staged plans waiting for promotion",
      meta: snapshot
        ? `${snapshot.stagedOperations.length} staged`
        : "0 staged",
      active: controller.engine.detailSection === "catalogs",
      onSelect: () => controller.engine.setDetailSection("catalogs"),
    },
    {
      id: "registry",
      label: "Registry Queue",
      note: "Promoted jobs plus pending model, backend, and gallery control actions",
      meta: snapshot ? `${snapshot.jobs.length} jobs` : "0 jobs",
      active: controller.engine.detailSection === "registry",
      onSelect: () => controller.engine.setDetailSection("registry"),
    },
    {
      id: "activity",
      label: "Recent Activity",
      note: "Latest lifecycle and workload receipts emitted by the kernel",
      meta: snapshot ? `${snapshot.recentActivity.length} receipts` : "0 receipts",
      active: controller.engine.detailSection === "activity",
      onSelect: () => controller.engine.setDetailSection("activity"),
    },
  ];

  return (
    <>
      <section className="capabilities-list-group">
        <div className="capabilities-list-group-head">
          <h3>Operator deck</h3>
          <span>{overviewEntries.length}</span>
        </div>
        <div className="capabilities-list-rows">
          {overviewEntries.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={`capabilities-list-row ${entry.active ? "is-selected" : ""}`}
              onClick={entry.onSelect}
            >
              <span className="capabilities-row-icon capabilities-row-icon-engine">
                <CpuIcon />
              </span>
              <span className="capabilities-row-copy">
                <strong>{entry.label}</strong>
                <small>{entry.note}</small>
              </span>
              <span className="capabilities-row-meta">{entry.meta}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="capabilities-list-group">
        <div className="capabilities-list-group-head">
          <h3>Kernel-native families</h3>
          <span>{controller.engine.filteredFamilies.length}</span>
        </div>
        <div className="capabilities-list-rows">
          {controller.engine.filteredFamilies.map((family) => {
            const isSelected =
              controller.engine.detailSection === "families" &&
              controller.engine.selectedFamilyId === family.id;
            return (
              <button
                key={family.id}
                type="button"
                className={`capabilities-list-row ${isSelected ? "is-selected" : ""}`}
                onClick={() => {
                  controller.engine.setDetailSection("families");
                  controller.engine.setSelectedFamilyId(family.id);
                }}
              >
                <span className="capabilities-row-icon capabilities-row-icon-engine">
                  <CpuIcon />
                </span>
                <span className="capabilities-row-copy">
                  <strong>{family.label}</strong>
                  <small>{family.description}</small>
                </span>
                <span className="capabilities-row-meta">
                  {family.availableCount > 0
                    ? `${family.availableCount} tools`
                    : family.status}
                </span>
              </button>
            );
          })}
        </div>
      </section>
    </>
  );
}

function CapabilitiesHomePane({
  pendingEngineControls,
  skillCount,
  connectedCount,
  connectionCount,
  extensionCount,
  registrySummary,
  registryLoading,
  registryError,
  onOpenSurface,
}: {
  pendingEngineControls: number;
  skillCount: number;
  connectedCount: number;
  connectionCount: number;
  extensionCount: number;
  registrySummary: CapabilitiesController["registry"]["summary"];
  registryLoading: boolean;
  registryError: string | null;
  onOpenSurface: (surface: "engine" | "skills" | "connections" | "extensions") => void;
}) {
  const registryGeneratedLabel = registrySummary
    ? new Date(registrySummary.generatedAtMs).toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit",
      })
    : null;

  return (
    <section className="capabilities-home-pane">
      <div className="capabilities-home-shell">
        <div className="capabilities-home-hero">
          <div className="capabilities-home-icon capabilities-home-icon-engine">
            <CpuIcon />
          </div>
          <h2>Equip workers without fragmenting the runtime.</h2>
          <p>
            Capabilities is for what the workspace can use: reusable skills,
            governed connections, extension manifests, and the runtime deck for
            monitoring absorbed local-engine behavior. Authoritative runtime
            configuration now lives in System Settings.
          </p>
          <div className="capabilities-home-meta" aria-label="Capability summary">
            <span>{pendingEngineControls} pending engine controls</span>
            <span>{skillCount} skills available</span>
            <span>
              {connectedCount}/{connectionCount} connections active
            </span>
            <span>{extensionCount} extensions visible</span>
          </div>
        </div>
        <div className="capabilities-home-registry">
          <div className="capabilities-home-registry-head">
            <span className="capabilities-home-surface-kicker">Canonical registry</span>
            <strong>One runtime-owned capability snapshot</strong>
            <p>
              Skills, connections, extensions, and kernel-native runtime families
              now land from the same backend registry instead of stitched-together
              shell fetches.
            </p>
            <span className="capabilities-home-registry-meta">
              {registryLoading
                ? "Refreshing registry snapshot..."
                : registryError
                  ? "Registry snapshot unavailable"
                  : registryGeneratedLabel
                    ? `Last refreshed ${registryGeneratedLabel}`
                    : "Live snapshot ready"}
            </span>
          </div>
          {registryLoading ? (
            <div className="capabilities-home-registry-empty">
              Loading the authoritative capability registry...
            </div>
          ) : registryError ? (
            <div className="capabilities-home-registry-empty">
              Capability registry unavailable: {registryError}
            </div>
          ) : registrySummary ? (
            <div className="capabilities-home-registry-grid">
              <article className="capabilities-home-registry-card">
                <span>Total entries</span>
                <strong>{registrySummary.totalEntries}</strong>
                <p>
                  {registrySummary.connectorCount} connectors, {registrySummary.runtimeSkillCount} runtime skills, and {registrySummary.extensionCount} manifest-backed extensions.
                </p>
              </article>
              <article className="capabilities-home-registry-card">
                <span>Authority roots</span>
                <strong>{registrySummary.authoritativeSourceCount}</strong>
                <p>
                  {registrySummary.trackedSourceCount} tracked source roots feeding {registrySummary.filesystemSkillCount} filesystem skills into the catalog lane.
                </p>
              </article>
              <article className="capabilities-home-registry-card">
                <span>Governed runtime</span>
                <strong>
                  {registrySummary.connectedConnectorCount}/{registrySummary.connectorCount}
                </strong>
                <p>
                  Live governed connectors plus {registrySummary.pendingEngineControlCount} pending engine controls visible in the same deck.
                </p>
              </article>
              <article className="capabilities-home-registry-card">
                <span>Kernel-native</span>
                <strong>
                  {registrySummary.modelCount + registrySummary.backendCount}
                </strong>
                <p>
                  {registrySummary.modelCount} models, {registrySummary.backendCount} backends, and {registrySummary.nativeFamilyCount} native families under one absorbed runtime view.
                </p>
              </article>
            </div>
          ) : null}
        </div>
        <div className="capabilities-home-grid">
          <button
            type="button"
            className="capabilities-home-surface capabilities-home-surface-engine"
            onClick={() => onOpenSurface("engine")}
          >
            <span className="capabilities-home-surface-kicker">Monitor</span>
            <strong>Runtime deck</strong>
            <p>Inspect queue state, capability families, lifecycle receipts, and control actions without burying skills or connections.</p>
          </button>
          <button
            type="button"
            className="capabilities-home-surface"
            onClick={() => onOpenSurface("skills")}
          >
            <span className="capabilities-home-surface-kicker">Reusable</span>
            <strong>Skills</strong>
            <p>Review benchmark posture, worker procedures, and attached tool bundles.</p>
          </button>
          <button
            type="button"
            className="capabilities-home-surface"
            onClick={() => onOpenSurface("connections")}
          >
            <span className="capabilities-home-surface-kicker">Governed</span>
            <strong>Connections</strong>
            <p>Bind live auth surfaces and keep connector policy within the same control plane.</p>
          </button>
          <button
            type="button"
            className="capabilities-home-surface"
            onClick={() => onOpenSurface("extensions")}
          >
            <span className="capabilities-home-surface-kicker">Packaged</span>
            <strong>Extensions</strong>
            <p>
              Inspect real manifest-backed plugins, filesystem skills, and policy posture from one runtime-backed view.
            </p>
          </button>
        </div>
      </div>
    </section>
  );
}

interface CapabilitiesNavigationPaneProps {
  controller: CapabilitiesController;
  getConnectorTrustProfile?: (
    connector: ConnectorSummary,
    options?: { template?: boolean },
  ) => CapabilityTrustProfile | null;
  onOpenSkillSources?: () => void;
}

export function CapabilitiesNavigationPane({
  controller,
  getConnectorTrustProfile,
  onOpenSkillSources,
}: CapabilitiesNavigationPaneProps) {
  return (
    <>
      <StudioLeftSidebarShell
        ariaLabel="Capabilities navigation"
        title="Capabilities"
        className="capabilities-sidebar"
        bodyClassName="capabilities-sidebar-body"
        actions={
          controller.surface !== null ? (
            <button
              type="button"
              className="studio-chat-pane-control capabilities-sidebar-backdrop"
              onClick={controller.returnToHome}
              aria-label="Back to capabilities home"
              title="Back to capabilities home"
            >
              <ArrowLeftIcon />
            </button>
          ) : null
        }
      >
        <div className="capabilities-nav-shell">
          <nav className="capabilities-nav">
            <MenuButton
              active={controller.surface === "engine"}
              icon={<CpuIcon />}
              label="Runtime Deck"
              onClick={() => controller.openSurface("engine")}
            />
            <MenuButton
              active={controller.surface === "skills"}
              icon={<SparklesIcon />}
              label="Skills"
              onClick={() => controller.openSurface("skills")}
            />
            <MenuButton
              active={controller.surface === "connections"}
              icon={<CableIcon />}
              label="Connections"
              onClick={() => controller.openSurface("connections")}
            />
            <MenuButton
              active={controller.surface === "extensions"}
              icon={<BlocksIcon />}
              label="Extensions"
              onClick={() => controller.openSurface("extensions")}
            />
          </nav>
        </div>
      </StudioLeftSidebarShell>

      {controller.surface === null ? (
        <CapabilitiesHomePane
          pendingEngineControls={controller.engine.snapshot?.pendingControlCount ?? 0}
          skillCount={controller.skills.items.length}
          connectedCount={controller.connectedConnectionCount}
          connectionCount={controller.connections.items.length}
          extensionCount={controller.extensions.items.length}
          registrySummary={controller.registry.summary}
          registryLoading={controller.registry.loading}
          registryError={controller.registry.error}
          onOpenSurface={controller.openSurface}
        />
      ) : (
        <section className="capabilities-list-pane">
          <header className="capabilities-pane-header">
            <div className="capabilities-pane-title">
              <span className="capabilities-pane-kicker">Workspace</span>
              <h2>
                {controller.surface === "engine"
                  ? "Runtime Deck"
                  : controller.surface === "extensions"
                    ? "Extensions"
                  : humanize(controller.surface)}
              </h2>
              <span className="capabilities-pane-count">
                {controller.surface === "engine"
                  ? controller.engine.loading
                    ? "Loading posture"
                    : `${controller.engine.snapshot?.totalNativeTools ?? 0} native tools`
                  : controller.surface === "skills"
                  ? controller.skills.loading
                    ? "Loading catalog"
                    : controller.skills.error
                      ? "Catalog unavailable"
                      : `${controller.skills.items.length} visible`
                  : controller.surface === "connections"
                    ? controller.connections.loading &&
                      controller.connections.liveCount === 0 &&
                      controller.connections.templateCount === 0
                      ? "Loading catalog"
                      : controller.connections.error &&
                          controller.connections.liveCount === 0 &&
                          controller.connections.templateCount === 0
                        ? "Catalog unavailable"
                        : controller.connections.filteredTemplateCount > 0
                          ? `${controller.connections.filteredLiveCount} live · ${controller.connections.filteredTemplateCount} planning`
                          : `${controller.connections.filteredLiveCount} live`
                    : `${controller.extensions.items.length} visible`}
              </span>
            </div>
            <div className="capabilities-pane-controls">
              <label className="capabilities-search">
                <SearchIcon />
                <input
                  value={controller.query}
                  onChange={(event) => controller.setQuery(event.target.value)}
                  placeholder={`Search ${controller.surface}...`}
                  aria-label={`Search ${controller.surface}`}
                />
              </label>
              {controller.surface === "connections" ? (
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={() => controller.connections.setCustomModalOpen(true)}
                >
                  Add planning template
                </button>
              ) : null}
            </div>
          </header>

          {controller.connections.customNotice ? (
            <div className="capabilities-pane-flash">
              <CheckCircleIcon />
              <span>{controller.connections.customNotice}</span>
              <button
                type="button"
                aria-label="Dismiss notice"
                onClick={() => controller.connections.setCustomNotice(null)}
              >
                <XIcon />
              </button>
            </div>
          ) : null}

          <div className="capabilities-list-scroll">
            {controller.surface === "engine" ? renderEngineList(controller) : null}
            {controller.surface === "skills"
              ? renderSkillList(controller, onOpenSkillSources)
              : null}
            {controller.surface === "connections"
              ? renderConnectionList(controller, getConnectorTrustProfile)
              : null}
            {controller.surface === "extensions"
              ? renderExtensionList(controller, onOpenSkillSources)
              : null}
          </div>
        </section>
      )}
    </>
  );
}
