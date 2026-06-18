import {
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES,
  getWorkbenchAdapterPreferenceByRef,
  getWorkbenchAdapterPreferenceRef,
} from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import { SettingsAuthoritySection } from "./SettingsAuthoritySection";
import { SettingsEnvironmentSection } from "./SettingsEnvironmentSection";
import { SettingsKnowledgeSection } from "./SettingsKnowledgeSection";
import { SettingsMaintenanceSection } from "./SettingsMaintenanceSection";
import { SettingsManagedSection } from "./SettingsManagedSection";
import { SettingsRuntimeSection } from "./SettingsRuntimeSection";
import { SettingsSkillSourcesSection } from "./SettingsSkillSourcesSection";
import { SettingsSourcesSection } from "./SettingsSourcesSection";
import { SettingsStorageApiSection } from "./SettingsStorageApiSection";
import { SettingsWorkbenchAdapterSection } from "./SettingsWorkbenchAdapterSection";
import { isEngineSection, type SettingsSection } from "./settingsViewShared";
import type { SettingsViewBodyView } from "./settingsViewTypes";

const PRIMARY_SETTINGS_NAV: Array<{
  id: SettingsSection;
  label: string;
}> = [
  { id: "identity", label: "Account" },
  { id: "secrets", label: "Secrets" },
  { id: "git_auth", label: "Git authentications" },
  { id: "personal_access_tokens", label: "Personal access tokens" },
  { id: "integrations", label: "Integrations" },
];

const ADVANCED_SETTINGS_NAV: Array<{
  id: SettingsSection;
  label: string;
}> = [
  { id: "authority", label: "Authority" },
  { id: "knowledge", label: "Knowledge" },
  { id: "skill_sources", label: "Skill sources" },
  { id: "managed_settings", label: "Managed settings" },
  { id: "workbench_adapter", label: "Workbench adapter" },
  { id: "runtime", label: "Runtime" },
  { id: "storage_api", label: "Storage / API" },
  { id: "sources", label: "Sources" },
  { id: "environment", label: "Environment" },
  { id: "local_data", label: "Local data" },
  { id: "repair_reset", label: "Repair / reset" },
  { id: "diagnostics", label: "Diagnostics" },
];

function SettingsNavButton({
  section,
  label,
  selectedSection,
  setSelectedSection,
}: {
  section: SettingsSection;
  label: string;
  selectedSection: SettingsSection;
  setSelectedSection: (section: SettingsSection) => void;
}) {
  return (
    <button
      type="button"
      className={`chat-settings-reference-nav-item ${
        selectedSection === section ? "active" : ""
      }`}
      onClick={() => setSelectedSection(section)}
      aria-current={selectedSection === section ? "page" : undefined}
    >
      {label}
    </button>
  );
}

function SettingsSwitch({
  checked,
  label,
  description,
}: {
  checked?: boolean;
  label: string;
  description: string;
}) {
  return (
    <label className="chat-settings-reference-switch">
      <input type="checkbox" defaultChecked={checked} />
      <span aria-hidden="true" />
      <strong>{label}</strong>
      <em>{description}</em>
    </label>
  );
}

function SettingsEditorTargetList({ view }: { view: SettingsViewBodyView }) {
  const visibleTargets = HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.filter(
    (preference) => preference.settings_visible !== false,
  );
  const selectedPreference =
    getWorkbenchAdapterPreferenceByRef(view.workbenchAdapterPreferenceRef) ??
    visibleTargets[0];

  return (
    <label
      className="chat-settings-reference-editor-select"
      aria-label="Default editor adapter targets"
      data-settings-editor-picker="workbench-adapter-targets"
    >
      <span className="chat-settings-reference-editor-icon" aria-hidden="true">
        {selectedPreference.icon_label ?? selectedPreference.label.slice(0, 2)}
      </span>
      <select
        value={view.workbenchAdapterPreferenceRef}
        onChange={(event) =>
          view.setWorkbenchAdapterPreferenceRef(event.currentTarget.value)
        }
      >
        {visibleTargets.map((preference) => {
          const preferenceRef = getWorkbenchAdapterPreferenceRef(preference);
          return (
            <option
              key={preference.adapter_id}
              value={preferenceRef}
              data-settings-editor-target={preference.adapter_id}
              data-workbench-adapter-preference={preferenceRef}
            >
              {preference.label}
            </option>
          );
        })}
      </select>
    </label>
  );
}

function SettingsAccountPanel({ view }: { view: SettingsViewBodyView }) {
  const selectedPreference = getWorkbenchAdapterPreferenceByRef(
    view.workbenchAdapterPreferenceRef,
  );

  return (
    <section
      className="chat-settings-reference-panel"
      aria-label="Account settings"
    >
      <div className="chat-settings-reference-section">
        <h2>Account details</h2>
        <div className="chat-settings-reference-account-row">
          <span className="chat-settings-reference-avatar" aria-hidden="true">
            IO
          </span>
          <div>
            <strong>IOI Workspace</strong>
            <em>operator@ioi.local</em>
          </div>
        </div>
        <label className="chat-settings-reference-field">
          <span>Account ID</span>
          <span className="chat-settings-reference-copy-field">
            <input
              readOnly
              value="019ed02a-f5e1-701e-af22-57676d837f9c"
            />
            <button type="button" aria-label="Copy account ID">
              Copy
            </button>
          </span>
        </label>
      </div>

      <div className="chat-settings-reference-section">
        <h2>Preferences</h2>

        <div className="chat-settings-reference-preference">
          <span>Appearance</span>
          <div className="chat-settings-reference-segmented" role="group">
            <button type="button">System</button>
            <button type="button" className="active">
              Light
            </button>
            <button type="button">Dark</button>
          </div>
        </div>

        <div className="chat-settings-reference-field">
          <span>Default Editor</span>
          <SettingsEditorTargetList view={view} />
          <em>
            This will be your default selected editor for environments.
            {" "}
            <a href="#learn-default-editor">Learn more.</a>
          </em>
        </div>

        <SettingsSwitch
          checked={selectedPreference.adapter_id === "embedded_workbench"}
          label="Embedded Workbench"
          description="Show the packaged editor adapter inside Workbench sessions. Disabling this reduces resource usage."
        />
        <SettingsSwitch
          label="Agent done notification"
          description="Play sound when an agent is done."
        />
        <SettingsSwitch
          label="Session number shortcuts"
          description="Use Cmd/Ctrl + 1-9 to switch between sidebar sessions."
        />

        <label className="chat-settings-reference-field">
          <span>Dotfiles repository</span>
          <input placeholder="https://github.com/your-username/dotfiles" />
          <em>
            URL of a dotfiles Git repository.{" "}
            <a href="#learn-dotfiles">Learn more.</a>
          </em>
        </label>
      </div>
    </section>
  );
}

function SettingsSimplePanel({
  title,
  body,
  rows,
}: {
  title: string;
  body: string;
  rows: Array<{ label: string; value: string; action: string }>;
}) {
  return (
    <section
      className="chat-settings-reference-panel"
      aria-label={`${title} settings`}
    >
      <div className="chat-settings-reference-section">
        <h2>{title}</h2>
        <p>{body}</p>
        <div className="chat-settings-reference-list">
          {rows.map((row) => (
            <article key={row.label}>
              <div>
                <strong>{row.label}</strong>
                <span>{row.value}</span>
              </div>
              <button type="button">{row.action}</button>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function SettingsReferencePrimaryPanel({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  switch (view.selectedSection) {
    case "identity":
      return <SettingsAccountPanel view={view} />;
    case "secrets":
      return (
        <SettingsSimplePanel
          title="Secrets"
          body="Store credentials for controlled use without exposing raw secrets to agents, editors, or remote workspaces."
          rows={[
            {
              label: "Brokered secret store",
              value: "Local vault and connected authority providers.",
              action: "Manage",
            },
            {
              label: "Declassification policy",
              value: "Step-up is required before sensitive release.",
              action: "Review",
            },
            {
              label: "Capability leases",
              value: "2 active, 1 expiring soon.",
              action: "Open",
            },
          ]}
        />
      );
    case "git_auth":
      return (
        <SettingsSimplePanel
          title="Git authentications"
          body="Connect source control accounts and choose how sessions may read, clone, and push changes."
          rows={[
            {
              label: "Primary source control",
              value: "Read/write access available for the current workspace.",
              action: "Configure",
            },
            {
              label: "Session git identity",
              value: "Used for commits created from approved sessions.",
              action: "Inspect",
            },
          ]}
        />
      );
    case "personal_access_tokens":
      return (
        <SettingsSimplePanel
          title="Personal access tokens"
          body="Add tokens for integrations that cannot use OAuth or app-based login."
          rows={[
            {
              label: "Token vault",
              value: "Raw tokens are hidden after creation.",
              action: "Add token",
            },
            {
              label: "Recent use",
              value: "Usage history is available in receipts.",
              action: "Receipts",
            },
          ]}
        />
      );
    case "integrations":
      return (
        <SettingsSimplePanel
          title="Integrations"
          body="Connect editors, terminals, browsers, cloud accounts, model providers, and storage services."
          rows={[
            {
              label: "Workbench adapters",
              value: "Embedded, external editor, browser workspace, terminal, VM, node.",
              action: "Open",
            },
            {
              label: "Provider integrations",
              value: "Local, cloud, DePIN, confidential compute, storage.",
              action: "Configure",
            },
            {
              label: "Model routes",
              value: "Local, API, mounted, or provider-backed model calls.",
              action: "Routes",
            },
          ]}
        />
      );
    default:
      return null;
  }
}

function SettingsAdvancedPanel({ view }: { view: SettingsViewBodyView }) {
  const { selectedSection, renderEngineControls } = view;

  return (
    <section className="chat-settings-panel">
      {isEngineSection(selectedSection) ? renderEngineControls() : null}

      {selectedSection === "authority" ? (
        <SettingsAuthoritySection view={view} />
      ) : null}
      {selectedSection === "managed_settings" ? (
        <SettingsManagedSection view={view} />
      ) : null}
      {selectedSection === "workbench_adapter" ? (
        <SettingsWorkbenchAdapterSection view={view} />
      ) : null}
      {selectedSection === "runtime" ? (
        <SettingsRuntimeSection view={view} />
      ) : null}
      {selectedSection === "storage_api" ? (
        <SettingsStorageApiSection view={view} />
      ) : null}
      {selectedSection === "sources" ? (
        <SettingsSourcesSection view={view} />
      ) : null}
      {selectedSection === "environment" ? (
        <SettingsEnvironmentSection view={view} />
      ) : null}
      {selectedSection === "knowledge" ? (
        <SettingsKnowledgeSection view={view} />
      ) : null}
      {selectedSection === "skill_sources" ? (
        <SettingsSkillSourcesSection view={view} />
      ) : null}
      {selectedSection === "local_data" ||
      selectedSection === "repair_reset" ||
      selectedSection === "diagnostics" ? (
        <SettingsMaintenanceSection view={view} />
      ) : null}
    </section>
  );
}

export function SettingsViewBody({ view }: { view: SettingsViewBodyView }) {
  const { selectedSection, setSelectedSection } = view;
  const primarySelected = PRIMARY_SETTINGS_NAV.some(
    (item) => item.id === selectedSection,
  );

  return (
    <div
      className="chat-settings-reference-shell"
      data-settings-reference-shell="ioi-settings"
    >
      <header className="chat-settings-reference-header">
        <h1>User settings</h1>
        <button type="button" aria-label="Close settings">
          ×
        </button>
      </header>

      <div className="chat-settings-reference-layout">
        <aside className="chat-settings-reference-nav">
          <div className="chat-settings-reference-nav-primary">
            {PRIMARY_SETTINGS_NAV.map((item) => (
              <SettingsNavButton
                key={item.id}
                section={item.id}
                label={item.label}
                selectedSection={selectedSection}
                setSelectedSection={setSelectedSection}
              />
            ))}
          </div>

          <details className="chat-settings-reference-advanced">
            <summary>Advanced</summary>
            {ADVANCED_SETTINGS_NAV.map((item) => (
              <SettingsNavButton
                key={item.id}
                section={item.id}
                label={item.label}
                selectedSection={selectedSection}
                setSelectedSection={setSelectedSection}
              />
            ))}
          </details>

          <button
            type="button"
            className="chat-settings-reference-org"
            onClick={() => setSelectedSection("authority")}
          >
            <span aria-hidden="true">&larr;</span>
            Go to Organization settings
          </button>
        </aside>

        <main className="chat-settings-reference-main">
          {primarySelected ? (
            <SettingsReferencePrimaryPanel view={view} />
          ) : (
            <SettingsAdvancedPanel view={view} />
          )}
        </main>
      </div>
    </div>
  );
}
