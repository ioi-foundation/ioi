import { useEffect, useMemo, useState } from "react";
import type {
  ConnectorActionDefinition,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";
import { useGoogleWorkspaceConnector } from "../hooks/useGoogleWorkspaceConnector";
import {
  GOOGLE_OAUTH_TROUBLESHOOTING,
  GOOGLE_SCOPE_BUNDLES,
  SERVICE_META,
  type GoogleWorkspaceConnectorPanelProps,
  type WorkspaceOnboardingStepId,
  type WorkspaceServiceGroup,
  type WorkspaceTabId,
} from "./googleWorkspaceConnectorPanelConfig";
import { GoogleWorkspaceConnectorPanelBody } from "./GoogleWorkspaceConnectorPanelBody";
import {
  WorkspaceModal,
  actionKindLabel,
  availabilityLabel,
  availabilityTone,
  googleScopeUri,
  inferBundleSelectionFromScopes,
  isMissingOauthClientError,
  orderIndex,
} from "./googleWorkspaceConnectorPanelParts";

export function GoogleWorkspaceConnectorPanel({
  runtime,
  connector,
  onConfigured,
  onOpenPolicyCenter,
  policySummary,
}: GoogleWorkspaceConnectorPanelProps) {
  const [activeTab, setActiveTab] = useState<WorkspaceTabId>("overview");
  const [oauthClientIdInput, setOauthClientIdInput] = useState("");
  const [oauthClientSecretInput, setOauthClientSecretInput] = useState("");
  const [selectedBundleIds, setSelectedBundleIds] = useState<string[]>([]);
  const [scopeModalOpen, setScopeModalOpen] = useState(false);
  const [consentModalOpen, setConsentModalOpen] = useState(false);
  const [setupHelpModalOpen, setSetupHelpModalOpen] = useState(false);
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);
  const workspace = useGoogleWorkspaceConnector(runtime, connector, {
    onConfigured,
  });

  const actionsById = useMemo(() => {
    return new Map(
      workspace.actions.map((action) => [action.id, action] as const),
    );
  }, [workspace.actions]);

  const groupedActions = useMemo<WorkspaceServiceGroup[]>(() => {
    const groups = new Map<
      string,
      { serviceLabel: string; actions: ConnectorActionDefinition[] }
    >();
    for (const action of workspace.actions) {
      const key = action.service ?? "workspace";
      const current = groups.get(key);
      if (current) {
        current.actions.push(action);
      } else {
        groups.set(key, {
          serviceLabel: action.serviceLabel ?? key,
          actions: [action],
        });
      }
    }

    return Array.from(groups.entries())
      .map(([service, value]) => {
        const meta = SERVICE_META[service] ?? {
          title: value.serviceLabel,
          summary: `${value.serviceLabel} actions`,
          detail: "Curated Google action bundle.",
          featuredActionIds: [],
        };
        const featuredIds = new Set(meta.featuredActionIds);
        const featuredActions = meta.featuredActionIds
          .map(
            (actionId) =>
              value.actions.find((action) => action.id === actionId) ?? null,
          )
          .filter((action): action is ConnectorActionDefinition =>
            Boolean(action),
          );
        const supportingActions = value.actions.filter(
          (action) => !featuredIds.has(action.id),
        );
        const kinds = Array.from(
          new Set(value.actions.map((action) => actionKindLabel(action.kind))),
        );

        return {
          service,
          serviceLabel: value.serviceLabel,
          title: meta.title,
          summary: meta.summary,
          detail: meta.detail,
          actions: value.actions,
          featuredActions:
            featuredActions.length > 0
              ? featuredActions
              : value.actions.slice(0, 3),
          supportingActions,
          kinds,
        };
      })
      .sort(
        (left, right) => orderIndex(left.service) - orderIndex(right.service),
      );
  }, [workspace.actions]);

  const capabilityGroups = groupedActions.filter(
    (group) => group.service !== "expert" && group.service !== "events",
  );
  const automationGroups = groupedActions.filter(
    (group) =>
      group.service === "events" ||
      group.actions.some(
        (action) =>
          action.id === "gmail.watch_emails" || action.kind === "admin",
      ),
  );
  const advancedGroups = groupedActions;
  const activeSubscriptions = workspace.subscriptions.filter(
    (subscription) =>
      subscription.status === "active" || subscription.status === "renewing",
  );
  const attentionSubscriptions = workspace.subscriptions.filter(
    (subscription) =>
      subscription.status === "degraded" ||
      subscription.status === "reauth_required",
  );

  const connectorStatus =
    (workspace.connectionStatus as ConnectorSummary["status"] | null) ??
    connector.status;
  const availability = availabilityLabel(connectorStatus);
  const availabilityStyle = availabilityTone(connectorStatus);
  const isConnected =
    connectorStatus === "connected" || connectorStatus === "degraded";
  const missingOauthClient = isMissingOauthClientError(workspace.error);
  const onboardingStep: WorkspaceOnboardingStepId = isConnected
    ? "connected"
    : workspace.authPending
      ? "consent"
      : workspace.oauthClient.configured
        ? "scopes"
        : "credentials";

  useEffect(() => {
    if (workspace.authPending && workspace.requestedScopes.length > 0) {
      setSelectedBundleIds(
        inferBundleSelectionFromScopes(workspace.requestedScopes),
      );
    }
  }, [workspace.authPending, workspace.requestedScopes]);

  const selectedBundles = GOOGLE_SCOPE_BUNDLES.filter((bundle) =>
    selectedBundleIds.includes(bundle.id),
  );
  const requestedScopes = Array.from(
    new Set(selectedBundles.flatMap((bundle) => bundle.scopes)),
  );
  const canBeginAuth = workspace.runtimeReady && requestedScopes.length > 0;
  const reconnectScopes =
    requestedScopes.length > 0 ? requestedScopes : workspace.grantedScopes;
  const tokenStoragePath = workspace.tokenStorage.storagePath;
  const clientStoragePath = workspace.oauthClient.storagePath;
  const troubleshootingScopes = Array.from(
    new Set(["openid", "email", ...requestedScopes].map(googleScopeUri)),
  );
  const troubleshootingApis = Array.from(
    new Set(selectedBundles.flatMap((bundle) => bundle.apiLabels)),
  );
  const oauthClientPreview =
    workspace.oauthClient.clientIdPreview ||
    oauthClientIdInput.trim() ||
    "your saved Desktop OAuth client";

  const presetForAction = (
    action: ConnectorActionDefinition,
    extraPreset?: Record<string, string>,
  ) => {
    const fieldProfilePreset = action.fields.reduce<Record<string, string>>(
      (next, field) => {
        const defaultValue = workspace.fieldProfiles[field.id]?.defaultValue;
        if (defaultValue !== undefined) {
          next[field.id] = defaultValue;
        }
        return next;
      },
      {},
    );
    return {
      ...fieldProfilePreset,
      ...extraPreset,
    };
  };

  const openAction = (
    tab: WorkspaceTabId,
    actionId: string,
    presetInput?: Record<string, string>,
  ) => {
    const action = actionsById.get(actionId);
    if (!action) return;
    workspace.selectAction(actionId, presetForAction(action, presetInput));
    setActiveTab(tab);
  };

  const openAuthLink = () => {
    if (!workspace.authUrl || typeof window === "undefined") return;
    window.open(workspace.authUrl, "_blank", "noopener,noreferrer");
  };

  const copyAuthLink = async () => {
    if (!workspace.authUrl || !navigator.clipboard?.writeText) return;
    try {
      await navigator.clipboard.writeText(workspace.authUrl);
    } catch (_error) {
      // Leave the manual link visible as a fallback.
    }
  };

  const toggleBundle = (bundleId: string) => {
    setSelectedBundleIds((current) =>
      current.includes(bundleId)
        ? current.filter((value) => value !== bundleId)
        : [...current, bundleId],
    );
  };

  const resetGoogleSetup = async () => {
    const confirmed = window.confirm(
      "Reset Google setup? This will remove local OAuth tokens and the saved local client configuration.",
    );
    if (!confirmed) return;
    setScopeModalOpen(false);
    setConsentModalOpen(false);
    await workspace.resetLocalSetup();
    setSelectedBundleIds([]);
    setOauthClientIdInput("");
    setOauthClientSecretInput("");
  };

  const reopenScopeSelection = async () => {
    await workspace.cancelPendingAuth();
    setConsentModalOpen(false);
    setScopeModalOpen(true);
  };

  const retryConsent = async () => {
    await workspace.cancelPendingAuth();
    await workspace.beginAuth(requestedScopes);
  };

  const view = { connector, workspace, onOpenPolicyCenter, policySummary, activeTab, setActiveTab, oauthClientIdInput, setOauthClientIdInput, oauthClientSecretInput, setOauthClientSecretInput, selectedBundleIds, setSelectedBundleIds, scopeModalOpen, setScopeModalOpen, consentModalOpen, setConsentModalOpen, setupHelpModalOpen, setSetupHelpModalOpen, settingsModalOpen, setSettingsModalOpen, actionsById, groupedActions, capabilityGroups, automationGroups, advancedGroups, activeSubscriptions, attentionSubscriptions, connectorStatus, availability, availabilityStyle, isConnected, missingOauthClient, onboardingStep, selectedBundles, requestedScopes, canBeginAuth, reconnectScopes, tokenStoragePath, clientStoragePath, troubleshootingScopes, troubleshootingApis, oauthClientPreview, presetForAction, openAction, openAuthLink, copyAuthLink, toggleBundle, resetGoogleSetup, reopenScopeSelection, retryConsent };

  return (
    <div className="connector-test-panel workspace-connector-panel workspace-product-panel">
      <GoogleWorkspaceConnectorPanelBody view={view} />

      <WorkspaceModal
        open={settingsModalOpen}
        title="Google connection settings"
        description="Connection-local operational settings live here. Governance and approval posture live in Policy."
        onClose={() => setSettingsModalOpen(false)}
      >
        <div className="workspace-settings-grid">
          <article className="workspace-settings-card">
            <strong>Trust model</strong>
            <p>
              Google access is owned by the local user. Client configuration and
              refresh tokens stay on disk unless you explicitly remove them.
            </p>
            <div className="workspace-storage-list">
              <span>
                Connected account:{" "}
                <code>
                  {workspace.connectedAccountEmail ?? "Not connected"}
                </code>
              </span>
              <span>
                OAuth client source:{" "}
                <code>
                  {workspace.oauthClient.source}
                  {workspace.oauthClient.clientIdPreview
                    ? ` ${workspace.oauthClient.clientIdPreview}`
                    : ""}
                </code>
              </span>
              <span>
                Token source: <code>{workspace.tokenStorage.source}</code>
              </span>
            </div>
          </article>

          <article className="workspace-settings-card">
            <strong>Local storage</strong>
            <p>
              These paths are local to this machine. They are not shared with a
              hosted platform service.
            </p>
            <div className="workspace-storage-list">
              <span>
                Client config path:{" "}
                <code>{clientStoragePath ?? "Unavailable"}</code>
              </span>
              <span>
                Token storage path:{" "}
                <code>{tokenStoragePath ?? "Unavailable"}</code>
              </span>
            </div>
          </article>

          <article className="workspace-settings-card">
            <strong>Account maintenance</strong>
            <p>
              Use reconnect to refresh scopes or swap accounts. Review grants in
              Google when you want to inspect or revoke permissions directly.
            </p>
            <div className="workspace-auth-stage-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() => void workspace.beginAuth(reconnectScopes)}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                {workspace.busy ? "Working..." : "Reconnect"}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.checkConnection}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                Refresh status
              </button>
              <a
                className="btn-secondary"
                href="https://myaccount.google.com/permissions"
                target="_blank"
                rel="noreferrer"
              >
                Review Google grants
              </a>
            </div>
          </article>

          <article className="workspace-settings-card workspace-settings-card-danger">
            <strong>Danger zone</strong>
            <p>
              Use these only when rotating credentials, intentionally
              disconnecting, or fully resetting the local Google setup.
            </p>
            <div className="workspace-auth-stage-actions">
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.disconnect}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                {workspace.tokenStorage.source === "local"
                  ? "Wipe local tokens"
                  : "Disconnect"}
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
          </article>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={scopeModalOpen}
        title="Choose Google capability bundles"
        description="Select the Google services this local assistant should request before browser consent."
        onClose={() => setScopeModalOpen(false)}
      >
        <div className="workspace-scope-grid">
          {GOOGLE_SCOPE_BUNDLES.map((bundle) => {
            const selected = selectedBundleIds.includes(bundle.id);
            return (
              <label
                key={bundle.id}
                className={`workspace-scope-card ${selected ? "selected" : ""}`}
              >
                <div className="workspace-scope-card-head">
                  <input
                    type="checkbox"
                    checked={selected}
                    onChange={() => toggleBundle(bundle.id)}
                  />
                  <div>
                    <strong>{bundle.title}</strong>
                    <p>{bundle.summary}</p>
                  </div>
                </div>
                <span className="workspace-state-detail">{bundle.detail}</span>
                <div className="workspace-bundle-strip">
                  {bundle.scopes.map((scope) => (
                    <span
                      key={`${bundle.id}-${scope}`}
                      className="workspace-bundle-chip"
                    >
                      {scope}
                    </span>
                  ))}
                </div>
              </label>
            );
          })}
        </div>
        <div className="workspace-auth-stage-actions">
          <button
            type="button"
            className="btn-primary"
            onClick={() => {
              setScopeModalOpen(false);
              void workspace.beginAuth(requestedScopes);
            }}
            disabled={workspace.busy || !canBeginAuth}
          >
            {workspace.busy ? "Starting..." : "Continue to Google consent"}
          </button>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={consentModalOpen}
        title="Google consent details"
        description="Use this when you need to inspect the selected bundles, restart sign-in, or recover from the wrong cached Google account."
        onClose={() => setConsentModalOpen(false)}
      >
        <div className="workspace-onboarding-summary">
          <strong>Selected bundles</strong>
          <div className="workspace-bundle-strip">
            {selectedBundles.map((bundle) => (
              <span key={bundle.id} className="workspace-bundle-chip">
                {bundle.title}
              </span>
            ))}
          </div>
        </div>
        {workspace.authUrl ? (
          <a
            className="workspace-auth-link"
            href={workspace.authUrl}
            target="_blank"
            rel="noreferrer"
          >
            {workspace.authUrl}
          </a>
        ) : null}
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
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={setupHelpModalOpen}
        title="Google OAuth troubleshooting"
        description="Use this when Google shows an error page instead of returning to Autopilot."
        onClose={() => setSetupHelpModalOpen(false)}
      >
        <div className="workspace-warning-panel">
          <strong>What to do next</strong>
          <div className="workspace-warning-list">
            <span>
              Fix the Google Cloud Console setting that caused the browser
              error.
            </span>
            <span>
              Keep the saved local client unless you are replacing credentials
              entirely.
            </span>
            <span>
              Return here and use Retry sign-in. That restarts OAuth without
              forcing you to re-enter your client configuration.
            </span>
          </div>
        </div>
        <div className="workspace-troubleshooting-steps">
          <article className="workspace-troubleshooting-card">
            <strong>Enable necessary APIs</strong>
            <p>
              In Google Cloud Console, open the project associated with{" "}
              <code>{oauthClientPreview}</code>, then go to{" "}
              <code>APIs &amp; Services</code>, then <code>Library</code>, and
              confirm the APIs below are enabled.
            </p>
            <div className="workspace-bundle-strip">
              {troubleshootingApis.length > 0 ? (
                troubleshootingApis.map((api) => (
                  <span key={api} className="workspace-bundle-chip">
                    {api}
                  </span>
                ))
              ) : (
                <span className="workspace-bundle-chip">
                  Select capability bundles first
                </span>
              )}
            </div>
          </article>
          <article className="workspace-troubleshooting-card">
            <strong>Verify OAuth consent screen</strong>
            <p>
              In <code>Google Auth Platform</code>, then <code>Audience</code>,
              switch the app to <code>External</code> if this local assistant
              should work with personal Gmail or any account outside a Workspace
              org. <code>Internal</code> is only appropriate if every user
              belongs to that Workspace organization and you intentionally want
              org-only access. If the app stays in testing mode, add the exact
              Google account as a test user before retrying.
            </p>
            <p>
              In <code>Google Auth Platform</code>, then{" "}
              <code>Data Access</code>, review the exact scopes that will be
              requested for the bundles selected in Autopilot.
            </p>
            <p>
              When switching to <code>External</code>, Google may require extra
              app metadata such as privacy policy, terms of service, and
              authorized domains, especially if you later move beyond personal
              testing or request sensitive scopes.
            </p>
            <div className="workspace-bundle-strip">
              {troubleshootingScopes.map((scope) => (
                <span key={scope} className="workspace-bundle-chip">
                  {scope}
                </span>
              ))}
            </div>
          </article>
        </div>
        <div className="workspace-troubleshooting-grid">
          {GOOGLE_OAUTH_TROUBLESHOOTING.map((item) => (
            <article key={item.id} className="workspace-troubleshooting-card">
              <strong>{item.title}</strong>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>
        <div className="workspace-auth-stage-actions">
          <a
            className="btn-secondary"
            href="https://console.cloud.google.com/auth/overview"
            target="_blank"
            rel="noreferrer"
          >
            Open Google Auth Platform
          </a>
          <a
            className="btn-secondary"
            href="https://console.cloud.google.com/apis/credentials"
            target="_blank"
            rel="noreferrer"
          >
            Open OAuth credentials
          </a>
          <button
            type="button"
            className="btn-primary"
            onClick={() => void retryConsent()}
            disabled={
              workspace.busy ||
              !workspace.runtimeReady ||
              requestedScopes.length === 0
            }
          >
            Retry sign-in
          </button>
        </div>
      </WorkspaceModal>
    </div>
  );
}
