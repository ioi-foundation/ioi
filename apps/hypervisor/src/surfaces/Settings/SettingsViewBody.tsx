import {
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  getCodeEditorAdapterPreferenceByRef,
  getCodeEditorAdapterPreferenceRef,
} from "../../windows/HypervisorShellWindow/hypervisorShellNavigationModel";
import { type SettingsSection } from "./settingsViewShared";
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
  const visibleTargets = HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.filter(
    (preference) => preference.settings_visible !== false,
  );
  const selectedPreference =
    getCodeEditorAdapterPreferenceByRef(view.codeEditorAdapterPreferenceRef) ??
    visibleTargets[0];

  return (
    <label
      className="chat-settings-reference-editor-select"
      aria-label="Default editor adapter targets"
      data-settings-editor-picker="code-editor-adapter-targets"
    >
      <span className="chat-settings-reference-editor-icon" aria-hidden="true">
        {selectedPreference.icon_label ?? selectedPreference.label.slice(0, 2)}
      </span>
      <select
        value={view.codeEditorAdapterPreferenceRef}
        onChange={(event) =>
          view.setCodeEditorAdapterPreferenceRef(event.currentTarget.value)
        }
      >
        {visibleTargets.map((preference) => {
          const preferenceRef = getCodeEditorAdapterPreferenceRef(preference);
          return (
            <option
              key={preference.adapter_id}
              value={preferenceRef}
              data-settings-editor-target={preference.adapter_id}
              data-code-editor-adapter-preference={preferenceRef}
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
  const selectedPreference = getCodeEditorAdapterPreferenceByRef(
    view.codeEditorAdapterPreferenceRef,
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
          <span>Default code editor target</span>
          <SettingsEditorTargetList view={view} />
          <em>
            This will be your default code editor for workspace sessions.
            {" "}
            <a href="#learn-default-code-editor-target">Learn more.</a>
          </em>
        </div>

        <SettingsSwitch
          checked={selectedPreference.adapter_id === "embedded_code_editor"}
          label="Embedded code editor"
          description="Show the packaged editor adapter inside workspace sessions. Disabling this reduces resource usage."
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
          body="Connect editor adapters, terminals, browsers, cloud accounts, model providers, and storage services."
          rows={[
            {
              label: "code editor adapters",
              value: "Embedded, desktop, and browser-based code editors.",
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

export function SettingsViewBody({ view }: { view: SettingsViewBodyView }) {
  const { selectedSection, setSelectedSection } = view;
  const selectedPrimarySection = PRIMARY_SETTINGS_NAV.some(
    (item) => item.id === selectedSection,
  )
    ? selectedSection
    : "identity";

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
                selectedSection={selectedPrimarySection}
                setSelectedSection={setSelectedSection}
              />
            ))}
          </div>

          <button
            type="button"
            className="chat-settings-reference-org"
            data-settings-reference-organization-link="true"
          >
            <span aria-hidden="true">&larr;</span>
            Go to Organization settings
          </button>
        </aside>

        <main className="chat-settings-reference-main">
          <SettingsReferencePrimaryPanel
            view={{ ...view, selectedSection: selectedPrimarySection }}
          />
        </main>
      </div>
    </div>
  );
}
