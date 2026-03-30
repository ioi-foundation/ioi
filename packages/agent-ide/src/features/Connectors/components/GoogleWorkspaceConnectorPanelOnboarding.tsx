import { formatTimestamp } from "./googleWorkspaceConnectorPanelParts";
import type { GoogleWorkspaceConnectorPanelView } from "./googleWorkspaceConnectorPanelView";

export function GoogleWorkspaceConnectorPanelOnboarding({
  view,
}: {
  view: GoogleWorkspaceConnectorPanelView;
}) {
  const {
    workspace,
    onboardingStep,
    missingOauthClient,
    oauthClientIdInput,
    setOauthClientIdInput,
    oauthClientSecretInput,
    setOauthClientSecretInput,
    selectedBundles,
    requestedScopes,
    canBeginAuth,
    tokenStoragePath,
    clientStoragePath,
    setScopeModalOpen,
    setConsentModalOpen,
    setSetupHelpModalOpen,
    openAuthLink,
    copyAuthLink,
    resetGoogleSetup,
    reopenScopeSelection,
    retryConsent,
  } = view;

  return (
    <div className="workspace-tab-panel">
      {onboardingStep === "credentials" ? (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Step 1</span>
              <h4>Set up Google access</h4>
              <p>
                Create a Desktop OAuth client in your own Google Cloud project,
                then save it locally in Autopilot. This assistant does not use
                platform-managed Google credentials.
              </p>
            </div>
            <span className="workspace-health-pill tone-setup">
              Credentials required
            </span>
          </div>

          <div className="workspace-auth-stage-grid">
            <article className="workspace-auth-step">
              <strong>1. Create a Desktop OAuth client</strong>
              <p>
                Use Google Cloud Console credentials for your own project. If
                you plan to sign in with personal Gmail or any account outside a
                Workspace org, the app must be set to External.
              </p>
            </article>
            <article className="workspace-auth-step">
              <strong>2. Save it locally</strong>
              <p>
                Autopilot validates the client ID format before it enables
                Google consent.
              </p>
            </article>
            <article className="workspace-auth-step">
              <strong>3. Keep ownership local</strong>
              <p>
                Client config and tokens stay on this machine, under your
                control.
              </p>
            </article>
          </div>

          <div className="workspace-auth-stage-actions">
            <a
              className="btn-secondary"
              href="https://console.cloud.google.com/apis/credentials"
              target="_blank"
              rel="noreferrer"
            >
              Open Google Cloud Console
            </a>
            <a
              className="btn-secondary"
              href="https://developers.google.com/workspace/guides/create-credentials"
              target="_blank"
              rel="noreferrer"
            >
              Credential setup guide
            </a>
          </div>

          {missingOauthClient ? (
            <div className="workspace-warning-panel">
              <strong>Google client setup is the first gate</strong>
              <div className="workspace-warning-list">
                <span>
                  Create a Desktop OAuth client in your own Google Cloud
                  project.
                </span>
                <span>Paste the client ID below and save it locally.</span>
                <span>
                  Google sign-in is only enabled after local validation
                  succeeds.
                </span>
              </div>
            </div>
          ) : null}

          <div className="workspace-warning-panel">
            <strong>Common Google setup failures</strong>
            <div className="workspace-warning-list">
              <span>
                `org_internal` means the OAuth app is restricted to an internal
                Workspace organization.
              </span>
              <span>
                Personal Gmail accounts need an External audience, or they must
                be listed as test users while the app is still in testing mode.
              </span>
              <span>
                Use a Desktop app OAuth client, not a Web app client, for the
                native Autopilot redirect flow.
              </span>
            </div>
          </div>

          <section className="workspace-byok-panel">
            <div className="workspace-byok-head">
              <div>
                <strong>Google Cloud Desktop OAuth client</strong>
                <p>
                  This is the required setup path for private Autopilot
                  installs. The client belongs to you and is stored locally on
                  disk.
                </p>
              </div>
              <span className="workspace-health-pill tone-setup">
                Local setup
              </span>
            </div>
            <div className="workspace-action-grid">
              <label className="workspace-field">
                Google OAuth client ID
                <input
                  type="text"
                  value={oauthClientIdInput}
                  onChange={(event) => setOauthClientIdInput(event.target.value)}
                  placeholder="1234567890-abcdef.apps.googleusercontent.com"
                />
                <span>
                  Use the Desktop app client ID from your own Google Cloud
                  project.
                </span>
              </label>
              <label className="workspace-field">
                Client secret
                <input
                  type="password"
                  value={oauthClientSecretInput}
                  onChange={(event) =>
                    setOauthClientSecretInput(event.target.value)
                  }
                  placeholder="Optional"
                />
                <span>
                  Optional for this native flow. Leave blank unless your client
                  needs it.
                </span>
              </label>
            </div>
            <div className="workspace-storage-list">
              <span>
                Client config path:{" "}
                <code>{clientStoragePath ?? "Unavailable until runtime is ready."}</code>
              </span>
              <span>
                Token storage path:{" "}
                <code>{tokenStoragePath ?? "Unavailable until runtime is ready."}</code>
              </span>
            </div>
            <div className="workspace-byok-meta">
              <span>
                Nothing is sent to a platform relay. Your Google project issues
                the consent screen, and Autopilot stores the result locally.
              </span>
            </div>
            <div className="workspace-auth-stage-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() =>
                  void workspace.saveOauthClient(
                    oauthClientIdInput,
                    oauthClientSecretInput,
                  )
                }
                disabled={
                  workspace.busy ||
                  !workspace.runtimeReady ||
                  !oauthClientIdInput.trim()
                }
              >
                Save locally
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => setSetupHelpModalOpen(true)}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                Troubleshoot setup
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.checkConnection}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                Refresh status
              </button>
            </div>
          </section>
        </section>
      ) : null}

      {onboardingStep === "scopes" ? (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Step 2</span>
              <h4>Choose what this local agent can access</h4>
              <p>
                Select the Google capabilities you want to grant before
                Autopilot sends you to Google consent. Nothing beyond these
                bundles will be requested.
              </p>
            </div>
            <span className="workspace-health-pill tone-setup">
              {selectedBundles.length > 0
                ? `${selectedBundles.length} selected`
                : "Select scopes"}
            </span>
          </div>
          <div className="workspace-onboarding-summary">
            <strong>
              {selectedBundles.length > 0
                ? `${selectedBundles.length} capability bundles selected`
                : "No bundles selected yet"}
            </strong>
            <p>
              Keep the column focused on the next action. Use the bundle picker
              to review and change the detailed scope map.
            </p>
            <div className="workspace-bundle-strip">
              {selectedBundles.length > 0 ? (
                selectedBundles.map((bundle) => (
                  <span key={bundle.id} className="workspace-bundle-chip">
                    {bundle.title}
                  </span>
                ))
              ) : (
                <span className="workspace-bundle-chip">
                  Choose bundles to continue
                </span>
              )}
            </div>
          </div>

          <div className="workspace-storage-list">
            <span>
              OAuth client:{" "}
              <code>
                {workspace.oauthClient.clientIdPreview
                  ? `${workspace.oauthClient.source} ${workspace.oauthClient.clientIdPreview}`
                  : "Not configured"}
              </code>
            </span>
            <span>
              Tokens stay on disk at <code>{tokenStoragePath ?? "Unavailable"}</code>
            </span>
          </div>

          <div className="workspace-auth-stage-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={() => setScopeModalOpen(true)}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              Choose bundles
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={() => void workspace.beginAuth(requestedScopes)}
              disabled={workspace.busy || !canBeginAuth}
            >
              {workspace.busy ? "Starting..." : "Continue to Google consent"}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                setOauthClientIdInput("");
                setOauthClientSecretInput("");
                void workspace.clearOauthClient();
              }}
              disabled={
                workspace.busy ||
                !workspace.runtimeReady ||
                workspace.oauthClient.source !== "local"
              }
            >
              Remove local client
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void resetGoogleSetup()}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              Reset Google setup
            </button>
          </div>
        </section>
      ) : null}

      {onboardingStep === "consent" ? (
        <section className="workspace-auth-stage">
          <div className="workspace-auth-stage-head">
            <div>
              <span className="workspace-hero-kicker">Step 3</span>
              <h4>Finish consent in Google</h4>
              <p>
                Autopilot has started native Google OAuth with the exact bundles
                you selected. Complete consent in your browser, then return here
                while the connector refreshes automatically.
              </p>
            </div>
            <span className="workspace-health-pill tone-setup">
              Awaiting approval
            </span>
          </div>
          <div className="workspace-onboarding-summary">
            <strong>
              {selectedBundles.length > 0
                ? `Google will prompt for ${selectedBundles.length} selected bundle${selectedBundles.length === 1 ? "" : "s"}`
                : "Consent is in progress"}
            </strong>
            <p>
              The OAuth link now forces the Google account chooser. If Google
              opens the wrong cached account or shows an authorization error,
              restart from here without retyping your client credentials.
              Google-side errors like `org_internal` happen before the local
              callback, so fix the Cloud Console settings and retry from this
              step.
            </p>
            <div className="workspace-bundle-strip">
              {selectedBundles.map((bundle) => (
                <span key={bundle.id} className="workspace-bundle-chip">
                  {bundle.title}
                </span>
              ))}
            </div>
          </div>
          <div className="workspace-auth-stage-actions">
            <button
              type="button"
              className="btn-primary"
              onClick={openAuthLink}
              disabled={!workspace.authUrl}
            >
              Open sign-in page
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void copyAuthLink()}
              disabled={!workspace.authUrl}
            >
              Copy sign-in link
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={workspace.checkConnection}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              I finished sign-in
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void retryConsent()}
              disabled={
                workspace.busy ||
                !workspace.runtimeReady ||
                requestedScopes.length === 0
              }
            >
              Retry sign-in
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => void reopenScopeSelection()}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              Change bundles
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => setConsentModalOpen(true)}
              disabled={!workspace.authUrl}
            >
              View details
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => setSetupHelpModalOpen(true)}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              I hit a Google error
            </button>
          </div>
          {workspace.authExpiresAtUtc ? (
            <p className="workspace-inline-note">
              Link expires around {formatTimestamp(workspace.authExpiresAtUtc)}.
            </p>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
