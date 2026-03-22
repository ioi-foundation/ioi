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
  MenuButton,
  PlusIcon,
  SearchIcon,
  SparklesIcon,
  XIcon,
} from "./ui";

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

function CapabilitiesHomePane({
  skillCount,
  connectedCount,
  connectionCount,
  extensionCount,
}: {
  skillCount: number;
  connectedCount: number;
  connectionCount: number;
  extensionCount: number;
}) {
  return (
    <section className="capabilities-home-pane">
      <div className="capabilities-home-shell">
        <div className="capabilities-home-hero">
          <div className="capabilities-home-icon">
            <BlocksIcon />
          </div>
          <h2>Manage capabilities</h2>
          <p>
            Choose one top-level surface from the left, then drill into the
            nested browser only when you need the deeper controls.
          </p>
          <div className="capabilities-home-meta" aria-label="Capability summary">
            <span>{skillCount} skills available</span>
            <span>
              {connectedCount}/{connectionCount} connections active
            </span>
            <span>{extensionCount} extensions installed</span>
          </div>
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
      <aside className="capabilities-sidebar">
        <div className="capabilities-sidebar-head">
          <div className="capabilities-sidebar-titlebar">
            <button
              type="button"
              className="capabilities-sidebar-backdrop"
              onClick={controller.returnToHome}
              disabled={controller.surface === null}
              aria-label="Back to capabilities home"
              title="Back to capabilities home"
            >
              <ArrowLeftIcon />
            </button>
            <span>Capabilities</span>
          </div>
        </div>

        <nav className="capabilities-nav">
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
      </aside>

      {controller.surface === null ? (
        <CapabilitiesHomePane
          skillCount={controller.skills.items.length}
          connectedCount={controller.connectedConnectionCount}
          connectionCount={controller.connections.items.length}
          extensionCount={controller.extensions.items.length}
        />
      ) : (
        <section className="capabilities-list-pane">
          <header className="capabilities-pane-header">
            <div className="capabilities-pane-title">
              <span className="capabilities-pane-kicker">Workspace</span>
              <h2>{humanize(controller.surface)}</h2>
              <span className="capabilities-pane-count">
                {controller.surface === "skills"
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
