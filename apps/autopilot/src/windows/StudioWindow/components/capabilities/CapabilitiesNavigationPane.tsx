import {
  connectorStatusLabel,
  formatSuccessRate,
  groupLabelForConnection,
  humanize,
  providerAccent,
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
  PlusIcon,
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

function renderSkillList(controller: CapabilitiesController) {
  const starter = controller.skills.filteredItems.filter(
    (skill) => skill.origin === "starter",
  );
  const runtimeObserved = controller.skills.filteredItems.filter(
    (skill) => skill.origin === "runtime",
  );

  const skillEntriesFor = (skill: WorkspaceSkill): CapabilityTreeEntry[] => [
    {
      id: "guide",
      label: "SKILL.md",
      note: "Primary markdown instructions for the reusable behavior",
      meta: "Markdown",
      active: controller.skills.detailSection === "guide",
      onSelect: () => controller.skills.setDetailSection("guide"),
    },
    {
      id: "overview",
      label: "Overview",
      note: "Benchmarks, tool bundle, and operating posture",
      meta: formatSuccessRate(skill.detail.benchmark.success_rate_bps),
      active: controller.skills.detailSection === "overview",
      onSelect: () => controller.skills.setDetailSection("overview"),
    },
    {
      id: "procedure",
      label: "Procedure",
      note: "Observed execution outline and tool sequence",
      meta:
        skill.detail.steps.length > 0
          ? `${skill.detail.steps.length} steps`
          : "Macro",
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
                    {skill.origin === "starter" ? "Starter" : "Runtime"}
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
      {renderSkillGroup("Starter library", starter)}
      {renderSkillGroup("Observed in runtime", runtimeObserved)}
      {controller.skills.filteredItems.length === 0 ? (
        <div className="capabilities-empty-state">
          No skills match the current search.
        </div>
      ) : null}
    </>
  );
}

function renderConnectionList(controller: CapabilitiesController) {
  const groups = [
    "Not connected",
    "Connected",
    "Needs attention",
    "Workspace planned",
  ];

  return (
    <>
      {groups.map((group) => {
        const groupItems = controller.connections.filteredItems.filter(
          ({ connector, origin }) =>
            groupLabelForConnection(connector, origin) === group,
        );
        if (groupItems.length === 0) return null;
        return (
          <section key={group} className="capabilities-list-group">
            <div className="capabilities-list-group-head">
              <h3>{group}</h3>
              <span>{groupItems.length}</span>
            </div>
            <div className="capabilities-list-rows">
              {groupItems.map(({ connector, origin }) => {
                const isSelected =
                  controller.connections.selectedConnectionId === connector.id;
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
                      origin === "workspace"
                        ? "Stage the adapter before runtime execution is available"
                        : "Attach auth and unlock callable actions",
                    meta: origin === "workspace" ? "Planned" : "Live",
                    active: controller.connections.detailSection === "setup",
                    onSelect: () =>
                      controller.connections.setDetailSection("setup"),
                  },
                  {
                    id: "policy",
                    label: "Policy",
                    note:
                      "Governance, approvals, and connector-specific controls",
                    meta: "Guardrails",
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
                        {origin === "workspace"
                          ? "Staged"
                          : connectorStatusLabel(connector.status)}
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
      {controller.connections.filteredItems.length === 0 ? (
        <div className="capabilities-empty-state">
          No connections match the current search.
        </div>
      ) : null}
    </>
  );
}

function renderExtensionList(controller: CapabilitiesController) {
  return (
    <>
      <section className="capabilities-list-group">
        <div className="capabilities-list-group-head">
          <h3>Installed surfaces</h3>
          <span>{controller.extensions.filteredItems.length}</span>
        </div>
        <div className="capabilities-list-rows">
          {controller.extensions.filteredItems.map((extension) => {
            const isSelected =
              controller.extensions.selectedExtensionId === extension.id;
            const entries: CapabilityTreeEntry[] = [
              {
                id: "overview",
                label: "Overview",
                note: "Why this package exists in the capability model",
                meta: extension.status,
                active: controller.extensions.detailSection === "overview",
                onSelect: () =>
                  controller.extensions.setDetailSection("overview"),
              },
              {
                id: "surface",
                label: "Surfaces",
                note: "Callable capability surfaces contributed by the package",
                meta: `${extension.surfaces.length} items`,
                active: controller.extensions.detailSection === "surface",
                onSelect: () =>
                  controller.extensions.setDetailSection("surface"),
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
                    {extension.status}
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
          No extensions match the current search.
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
  onOpenSurface,
}: {
  pendingEngineControls: number;
  skillCount: number;
  connectedCount: number;
  connectionCount: number;
  extensionCount: number;
  onOpenSurface: (surface: "engine" | "skills" | "connections" | "extensions") => void;
}) {
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
            governed connections, packaged extensions, and the runtime deck for
            monitoring absorbed local-engine behavior. Authoritative runtime
            configuration now lives in System Settings.
          </p>
          <div className="capabilities-home-meta" aria-label="Capability summary">
            <span>{pendingEngineControls} pending engine controls</span>
            <span>{skillCount} skills available</span>
            <span>
              {connectedCount}/{connectionCount} connections active
            </span>
            <span>{extensionCount} extensions installed</span>
          </div>
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
            <p>See which packages widen the workspace surface without fragmenting the operator model.</p>
          </button>
        </div>
      </div>
    </section>
  );
}

export function CapabilitiesNavigationPane({
  controller,
}: {
  controller: CapabilitiesController;
}) {
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
                  : humanize(controller.surface)}
              </h2>
              <span className="capabilities-pane-count">
                {controller.surface === "engine"
                  ? controller.engine.loading
                    ? "Loading posture"
                    : `${controller.engine.snapshot?.totalNativeTools ?? 0} native tools`
                  : controller.surface === "skills"
                  ? `${controller.skills.items.length} available`
                  : controller.surface === "connections"
                    ? `${controller.connections.items.length} total`
                    : `${controller.extensions.items.length} installed`}
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
                <div
                  ref={controller.connectionsMenuRef}
                  className="capabilities-popover"
                >
                  <button
                    type="button"
                    className="capabilities-icon-button"
                    onClick={() =>
                      controller.connections.setMenuOpen(
                        !controller.connections.menuOpen,
                      )
                    }
                    aria-label="Browse connections"
                    aria-expanded={controller.connections.menuOpen}
                    aria-haspopup="menu"
                  >
                    <PlusIcon />
                  </button>
                  {controller.connections.menuOpen ? (
                    <div className="capabilities-popover-menu" role="menu">
                      <button
                        type="button"
                        className="capabilities-popover-item"
                        role="menuitem"
                        onClick={() => {
                          controller.connections.setMenuOpen(false);
                          controller.connections.setCatalogModalOpen(true);
                        }}
                      >
                        <strong>Browse connections</strong>
                        <span>Choose from the starter catalog</span>
                      </button>
                      <button
                        type="button"
                        className="capabilities-popover-item"
                        role="menuitem"
                        onClick={() => {
                          controller.connections.setMenuOpen(false);
                          controller.connections.setCustomModalOpen(true);
                        }}
                      >
                        <strong>Add custom connection</strong>
                        <span>Register a remote MCP surface</span>
                      </button>
                    </div>
                  ) : null}
                </div>
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
            {controller.surface === "skills" ? renderSkillList(controller) : null}
            {controller.surface === "connections"
              ? renderConnectionList(controller)
              : null}
            {controller.surface === "extensions"
              ? renderExtensionList(controller)
              : null}
          </div>
        </section>
      )}
    </>
  );
}
