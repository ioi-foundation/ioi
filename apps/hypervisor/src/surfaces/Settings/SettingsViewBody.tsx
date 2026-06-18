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
      className={`hypervisor-settings-reference-nav-item ${
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
    <label className="hypervisor-settings-reference-switch">
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
      className="hypervisor-settings-reference-editor-select"
      aria-label="Default editor adapter targets"
      data-settings-editor-picker="code-editor-adapter-targets"
    >
      <span className="hypervisor-settings-reference-editor-icon" aria-hidden="true">
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
      className="hypervisor-settings-reference-panel"
      aria-label="Account settings"
    >
      <div className="hypervisor-settings-reference-section">
        <h2>Account details</h2>
        <div className="hypervisor-settings-reference-account-row">
          <span className="hypervisor-settings-reference-avatar" aria-hidden="true">
            IO
          </span>
          <div>
            <strong>IOI Workspace</strong>
            <em>operator@ioi.local</em>
          </div>
        </div>
        <label className="hypervisor-settings-reference-field">
          <span>Account ID</span>
          <span className="hypervisor-settings-reference-copy-field">
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

      <div className="hypervisor-settings-reference-section">
        <h2>Preferences</h2>

        <div className="hypervisor-settings-reference-preference">
          <span>Appearance</span>
          <div className="hypervisor-settings-reference-segmented" role="group">
            <button type="button">System</button>
            <button type="button" className="active">
              Light
            </button>
            <button type="button">Dark</button>
          </div>
        </div>

        <div className="hypervisor-settings-reference-field">
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

        <label className="hypervisor-settings-reference-field">
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

function SettingsCapabilityPanel({
  section,
  title,
  body,
  authorityOwner,
  custodyMode,
  rows,
}: {
  section: Exclude<SettingsSection, "identity">;
  title: string;
  body: string;
  authorityOwner: "wallet.network" | "Hypervisor Core";
  custodyMode: string;
  rows: Array<{
    label: string;
    value: string;
    action: string;
    capability: string;
    receipt: string;
  }>;
}) {
  return (
    <section
      className="hypervisor-settings-reference-panel"
      aria-label={`${title} settings`}
      data-settings-credential-panel={section}
      data-settings-authority-owner={authorityOwner}
      data-settings-credential-custody={custodyMode}
    >
      <div className="hypervisor-settings-reference-section">
        <h2>{title}</h2>
        <p>{body}</p>
        <dl className="hypervisor-settings-reference-boundary">
          <div>
            <dt>Authority owner</dt>
            <dd>{authorityOwner}</dd>
          </div>
          <div>
            <dt>Credential custody</dt>
            <dd>{custodyMode}</dd>
          </div>
        </dl>
        <div className="hypervisor-settings-reference-list">
          {rows.map((row) => (
            <article
              key={row.label}
              data-settings-capability-row={row.capability}
              data-settings-receipt-ref={row.receipt}
            >
              <div>
                <strong>{row.label}</strong>
                <span>{row.value}</span>
                <em>{row.capability}</em>
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
        <SettingsCapabilityPanel
          section="secrets"
          title="Secrets"
          body="Configure brokered secrets for controlled use. wallet.network authorizes use and viewing separately; sessions receive short-lived capability leases, never durable plaintext."
          authorityOwner="wallet.network"
          custodyMode="brokered use-only leases; no plaintext session custody"
          rows={[
            {
              label: "Brokered secret store",
              value: "Local vault and connected authority providers hold encrypted credential material.",
              action: "Manage",
              capability: "scope:secret.use",
              receipt: "receipt://wallet.secret-broker/config",
            },
            {
              label: "Declassification policy",
              value: "Step-up is required before viewing or releasing sensitive values.",
              action: "Review",
              capability: "scope:secret.declassify",
              receipt: "receipt://wallet.declassification-policy/current",
            },
            {
              label: "Capability leases",
              value: "Session and agent leases auto-expire and can be revoked from Authority.",
              action: "Open",
              capability: "scope:capability.lease",
              receipt: "receipt://wallet.capability-lease/index",
            },
          ]}
        />
      );
    case "git_auth":
      return (
        <SettingsCapabilityPanel
          section="git_auth"
          title="Git authentications"
          body="Connect source control accounts and choose how sessions may read, clone, commit, push, and open review artifacts through scoped SCM leases."
          authorityOwner="wallet.network"
          custodyMode="SCM auth leases; editors and harnesses receive scoped actions"
          rows={[
            {
              label: "Primary source control",
              value: "Repository read/write is available only through project-bound scopes.",
              action: "Configure",
              capability: "scope:scm.repo.read_write",
              receipt: "receipt://wallet.git-auth/primary",
            },
            {
              label: "Session git identity",
              value: "Used for commits created from approved sessions.",
              action: "Inspect",
              capability: "scope:scm.commit.sign",
              receipt: "receipt://wallet.git-identity/current",
            },
            {
              label: "Pull request authority",
              value: "Opening or updating pull requests requires a lease and receipt.",
              action: "Review",
              capability: "scope:scm.pull_request.write",
              receipt: "receipt://wallet.git-pr-policy/current",
            },
          ]}
        />
      );
    case "personal_access_tokens":
      return (
        <SettingsCapabilityPanel
          section="personal_access_tokens"
          title="Personal access tokens"
          body="Add tokens for integrations that cannot use OAuth or app-based login. Tokens are stored as brokered credentials and are not exposed to agents as reusable strings."
          authorityOwner="wallet.network"
          custodyMode="vaulted token refs; use-only invocation by lease"
          rows={[
            {
              label: "Token vault",
              value: "Raw tokens are hidden after creation and bound to explicit scopes.",
              action: "Add token",
              capability: "scope:token.create",
              receipt: "receipt://wallet.token-vault/config",
            },
            {
              label: "Recent use",
              value: "Usage history is available in receipts.",
              action: "Receipts",
              capability: "scope:token.audit",
              receipt: "receipt://wallet.token-use/index",
            },
            {
              label: "Rotation policy",
              value: "Expiring tokens trigger renewal or revocation reviews.",
              action: "Policy",
              capability: "scope:token.rotate",
              receipt: "receipt://wallet.token-rotation/current",
            },
          ]}
        />
      );
    case "integrations":
      return (
        <SettingsCapabilityPanel
          section="integrations"
          title="Integrations"
          body="Connect adapter targets and provider accounts. Integrations propose actions; Hypervisor Core gates execution and wallet.network authorizes credentials."
          authorityOwner="Hypervisor Core"
          custodyMode="adapter capability refs; provider secrets stay wallet-brokered"
          rows={[
            {
              label: "code editor adapters",
              value: "Embedded, desktop, and browser-based code editors.",
              action: "Open",
              capability: "scope:adapter.code_editor.use",
              receipt: "receipt://hypervisor.adapter/code-editor",
            },
            {
              label: "Provider integrations",
              value: "Local, cloud, DePIN, confidential compute, storage.",
              action: "Configure",
              capability: "scope:provider.route.configure",
              receipt: "receipt://hypervisor.provider-integrations/index",
            },
            {
              label: "Model routes",
              value: "Local, API, mounted, or provider-backed model calls.",
              action: "Routes",
              capability: "scope:model.route.configure",
              receipt: "receipt://hypervisor.model-routes/index",
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
      className="hypervisor-settings-reference-shell"
      data-settings-reference-shell="ioi-settings"
    >
      <header className="hypervisor-settings-reference-header">
        <h1>User settings</h1>
        <button type="button" aria-label="Close settings">
          ×
        </button>
      </header>

      <div className="hypervisor-settings-reference-layout">
        <aside className="hypervisor-settings-reference-nav">
          <div className="hypervisor-settings-reference-nav-primary">
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
            className="hypervisor-settings-reference-org"
            data-settings-reference-organization-link="true"
          >
            <span aria-hidden="true">&larr;</span>
            Go to Organization settings
          </button>
        </aside>

        <main className="hypervisor-settings-reference-main">
          <SettingsReferencePrimaryPanel
            view={{ ...view, selectedSection: selectedPrimarySection }}
          />
        </main>
      </div>
    </div>
  );
}
