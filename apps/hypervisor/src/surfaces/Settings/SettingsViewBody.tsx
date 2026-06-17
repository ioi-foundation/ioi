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

function SettingsAccountPanel({ view }: { view: SettingsViewBodyView }) {
  const selectedPreference = getWorkbenchAdapterPreferenceByRef(
    view.workbenchAdapterPreferenceRef,
  );
  const profile = view.profileDraft;
  const profileEmail = profile.primaryEmail || "operator@local.hypervisor";
  const accountId = `account:${(profile.avatarSeed || "operator").toLowerCase()}`;

  return (
    <section
      className="chat-settings-reference-panel"
      aria-label="Account settings"
    >
      <div className="chat-settings-reference-section">
        <h2>Account details</h2>
        <div className="chat-settings-reference-account-row">
          <span className="chat-settings-reference-avatar" aria-hidden="true">
            {(profile.avatarSeed || "OP").slice(0, 2).toUpperCase()}
          </span>
          <div>
            <strong>{profile.displayName || "Operator"}</strong>
            <em>{profileEmail}</em>
          </div>
        </div>

        <label className="chat-settings-reference-field">
          <span>Account ID</span>
          <div className="chat-settings-reference-copy-field">
            <input value={accountId} readOnly />
            <button type="button" aria-label="Copy account ID">
              Copy
            </button>
          </div>
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

        <label className="chat-settings-reference-field">
          <span>Default Editor</span>
          <select
            value={view.workbenchAdapterPreferenceRef}
            onChange={(event) =>
              view.setWorkbenchAdapterPreferenceRef(event.target.value)
            }
          >
            {HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.map((preference) => {
              const preferenceRef = getWorkbenchAdapterPreferenceRef(preference);
              return (
                <option key={preferenceRef} value={preferenceRef}>
                  {preference.label}
                </option>
              );
            })}
          </select>
          <em>
            This will be your default selected editor or workspace target for
            environments.
          </em>
        </label>

        <SettingsSwitch
          checked={selectedPreference.adapter_id === "embedded_workbench"}
          label="Embedded Workbench"
          description="Show the embedded code editor in the Workbench tab."
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
          <em>URL of a dotfiles Git repository.</em>
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
          body="Brokered credentials stay behind wallet and vault policy. Agents receive scoped use leases, not durable plaintext secrets."
          rows={[
            {
              label: "Brokered secret store",
              value: "wallet.network / local vault",
              action: "Manage",
            },
            {
              label: "Declassification policy",
              value: "Step-up required for sensitive release.",
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
          body="Git credentials are attached as scoped session capabilities and receipted whenever a session requests source access."
          rows={[
            {
              label: "Primary source control",
              value: "Read/write lease available for local workspace.",
              action: "Configure",
            },
            {
              label: "Session git identity",
              value: "Bound to project policy and restore refs.",
              action: "Inspect",
            },
          ]}
        />
      );
    case "personal_access_tokens":
      return (
        <SettingsSimplePanel
          title="Personal access tokens"
          body="Tokens are treated as brokered secrets. Hypervisor can use them through capability exits without making the UI or node a plaintext custody domain."
          rows={[
            {
              label: "Token vault",
              value: "No raw tokens displayed in client memory.",
              action: "Add token",
            },
            {
              label: "Recent use",
              value: "Every token exercise emits a capability-use receipt.",
              action: "Receipts",
            },
          ]}
        />
      );
    case "integrations":
      return (
        <SettingsSimplePanel
          title="Integrations"
          body="Editor, terminal, browser, cloud, model, and provider integrations attach as adapters over Hypervisor Core."
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
          x
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
