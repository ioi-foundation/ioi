import { useCallback, useMemo, useRef, useState } from "react";
import {
  ConnectorActionPreviewStage,
  ConnectorActionUnlockModal,
} from "./ConnectorUnlockSurface";
import { GOOGLE_SCOPE_BUNDLES } from "./googleWorkspaceConnectorPanelConfig";
import {
  formatTimestamp,
  normalizeGoogleScope,
} from "./googleWorkspaceConnectorPanelParts";
import type {
  GoogleWorkspaceConnectorPanelView,
  UnlockBundleRecommendation,
} from "./googleWorkspaceConnectorPanelView";

function buildBundleRecommendationReason({
  actionLabel,
  actionKind,
  bundleTitle,
}: {
  actionLabel: string;
  actionKind: string;
  bundleTitle: string;
}) {
  const bundleTarget = bundleTitle.toLowerCase();
  if (actionKind === "read") {
    return `Needed so ${actionLabel} can read ${bundleTarget} data.`;
  }
  if (actionKind === "write") {
    return `Needed so ${actionLabel} can create or update ${bundleTarget} data.`;
  }
  if (actionKind === "admin") {
    return `Needed so ${actionLabel} can manage ${bundleTarget} configuration safely.`;
  }
  return `Needed so ${actionLabel} can run its ${bundleTarget} workflow end to end.`;
}

export function GoogleWorkspaceConnectorPanelOnboarding({
  view,
}: {
  view: GoogleWorkspaceConnectorPanelView;
}) {
  const {
    activeTab,
    capabilityGroups,
    automationGroups,
    advancedGroups,
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
    saveOauthClientAndContinue,
    unlockBundleContext,
    rememberUnlockBundleContext,
    openAuthLink,
    copyAuthLink,
    resetGoogleSetup,
    reopenScopeSelection,
    retryConsent,
  } = view;
  const setupStageRef = useRef<HTMLElement | null>(null);
  const credentialsInputRef = useRef<HTMLInputElement | null>(null);
  const chooseBundlesButtonRef = useRef<HTMLButtonElement | null>(null);
  const openAuthButtonRef = useRef<HTMLButtonElement | null>(null);
  const [selectedPreviewActionId, setSelectedPreviewActionId] = useState<
    string | null
  >(null);

  const previewGroups =
    activeTab === "automations"
      ? automationGroups
      : activeTab === "advanced"
        ? advancedGroups
        : capabilityGroups;
  const previewTitle =
    activeTab === "automations"
      ? "Connect to unlock durable Google automations"
      : activeTab === "advanced"
        ? "Connect to unlock the full Google tool catalog"
        : "Connect to unlock Google actions";
  const previewSummary =
    activeTab === "automations"
      ? "Browse the recipes and subscriptions you’ll be able to configure once Google auth is attached locally."
      : activeTab === "advanced"
        ? "The full catalog stays available after connect, but it should still feel like a guided action surface."
        : "You opened the action surface. These task-first flows become runnable as soon as local Google auth is configured.";
  const previewActions = previewGroups
    .flatMap((group) =>
      group.featuredActions.map((action) => ({
        serviceTitle: group.title,
        action,
      })),
    )
    .slice(0, 8);
  const setupDrilldownLabel =
    onboardingStep === "scopes"
      ? "bundle selection"
      : onboardingStep === "consent"
        ? "Google sign-in"
        : "local client setup";
  const setupDrilldownTitle =
    onboardingStep === "scopes"
      ? "Review bundle selection"
      : onboardingStep === "consent"
        ? "Continue to Google sign-in"
        : "Continue to local client setup";
  const focusCurrentSetupTarget = useCallback(() => {
    const preferredTarget =
      onboardingStep === "scopes"
        ? chooseBundlesButtonRef.current
        : onboardingStep === "consent"
          ? openAuthButtonRef.current
          : credentialsInputRef.current;
    const target = preferredTarget ?? setupStageRef.current;
    if (!target) {
      return;
    }
    requestAnimationFrame(() => {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
      target.focus({ preventScroll: true });
    });
  }, [onboardingStep]);
  const selectedPreviewAction = useMemo(
    () =>
      previewActions.find(
        ({ action }) => action.id === selectedPreviewActionId,
      ) ?? null,
    [previewActions, selectedPreviewActionId],
  );
  const previewCards = useMemo(
    () =>
      previewActions.map(({ serviceTitle, action }) => ({
        id: action.id,
        categoryLabel: serviceTitle,
        title: action.label,
        description: action.description,
        hint: `Unlock this action: jump to ${setupDrilldownLabel}`,
        ariaLabel: `Unlock ${action.label}. Open action setup details.`,
      })),
    [previewActions, setupDrilldownLabel],
  );
  const unlockDetail = useMemo(() => {
    if (!selectedPreviewAction) {
      return null;
    }
    const requiredScopes = Array.from(
      new Set(
        (selectedPreviewAction.action.requiredScopes ?? []).map(
          normalizeGoogleScope,
        ),
      ),
    );
    const requiredBundles = GOOGLE_SCOPE_BUNDLES.filter((bundle) =>
      bundle.scopes.some((scope) =>
        requiredScopes.includes(normalizeGoogleScope(scope)),
      ),
    );
    const selectedBundleIds = new Set(selectedBundles.map((bundle) => bundle.id));
    const activeRequiredBundles = requiredBundles.filter((bundle) =>
      selectedBundleIds.has(bundle.id),
    );
    const missingRequiredBundles = requiredBundles.filter(
      (bundle) => !selectedBundleIds.has(bundle.id),
    );
    const blockerHeadline =
      onboardingStep === "credentials"
        ? "Local Google client setup is still blocking this action."
        : onboardingStep === "consent"
          ? "Google consent is still pending for this action."
          : missingRequiredBundles.length > 0
            ? `This action still needs ${missingRequiredBundles.length === 1 ? "a capability bundle" : "capability bundles"} selected before sign-in.`
            : "This action is ready for consent once you continue to Google sign-in.";
    const blockerDetail =
      onboardingStep === "credentials"
        ? "Save a Desktop OAuth client locally first, then you can choose the exact Google bundles for this action."
        : onboardingStep === "consent"
          ? "The local setup is ready. Finish the Google account approval flow to unlock this action."
          : missingRequiredBundles.length > 0
            ? `Select ${missingRequiredBundles.map((bundle) => bundle.title).join(", ")} during scope selection so this action has the right access.`
            : "The required bundle is already selected. The next step is Google consent.";
    const bundleRecommendations: UnlockBundleRecommendation[] =
      requiredBundles.map((bundle) => ({
        bundleId: bundle.id,
        reason: buildBundleRecommendationReason({
          actionLabel: selectedPreviewAction.action.label,
          actionKind: selectedPreviewAction.action.kind,
          bundleTitle: bundle.title,
        }),
      }));
    return {
      requiredScopes,
      requiredBundles,
      activeRequiredBundles,
      missingRequiredBundles,
      blockerHeadline,
      blockerDetail,
      bundleRecommendations,
    };
  }, [onboardingStep, selectedBundles, selectedPreviewAction]);
  const openUnlockDrilldown = useCallback((actionId: string) => {
    setSelectedPreviewActionId(actionId);
  }, []);
  const closeUnlockDrilldown = useCallback(() => {
    setSelectedPreviewActionId(null);
  }, []);
  const continueSetupFromUnlockDrilldown = useCallback(() => {
    if (selectedPreviewAction && unlockDetail) {
      rememberUnlockBundleContext(
        selectedPreviewAction.action.label,
        unlockDetail.bundleRecommendations,
      );
    }
    closeUnlockDrilldown();
    if (onboardingStep === "scopes") {
      setScopeModalOpen(true);
      return;
    }
    focusCurrentSetupTarget();
  }, [
    closeUnlockDrilldown,
    focusCurrentSetupTarget,
    onboardingStep,
    rememberUnlockBundleContext,
    selectedPreviewAction,
    setScopeModalOpen,
    unlockDetail,
  ]);
  const saveAndContinueLabel = unlockBundleContext
    ? "Save client and continue"
    : "Save locally";
  const saveAndContinueAriaLabel = unlockBundleContext
    ? `${saveAndContinueLabel}. Unlocking ${unlockBundleContext.actionLabel}.`
    : saveAndContinueLabel;

  return (
    <div className="workspace-tab-panel">
      {activeTab !== "overview" ? (
        <ConnectorActionPreviewStage
          title={previewTitle}
          summary={previewSummary}
          actions={previewCards}
          onSelectAction={openUnlockDrilldown}
        />
      ) : null}

      {onboardingStep === "credentials" ? (
        <section
          ref={setupStageRef}
          className="workspace-auth-stage"
          tabIndex={-1}
        >
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

          {unlockBundleContext ? (
            <div className="workspace-onboarding-summary workspace-onboarding-summary-recommended">
              <strong>Continue unlocking {unlockBundleContext.actionLabel}</strong>
              <p>
                Save your local Google client once, then Autopilot will open
                bundle selection already centered on the access this action
                needs.
              </p>
              <div className="workspace-bundle-strip">
                {unlockBundleContext.recommendations.length > 0 ? (
                  unlockBundleContext.recommendations.map(({ bundleId }) => {
                    const bundle = GOOGLE_SCOPE_BUNDLES.find(
                      (item) => item.id === bundleId,
                    );
                    return (
                      <span key={bundleId} className="workspace-bundle-chip">
                        {bundle?.title ?? bundleId}
                      </span>
                    );
                  })
                ) : (
                  <span className="workspace-bundle-chip">
                    Recommended bundles will appear after save
                  </span>
                )}
              </div>
              <p className="workspace-inline-note">
                Next: save your client, then review the recommended bundles for{" "}
                {unlockBundleContext.actionLabel}.
              </p>
            </div>
          ) : null}

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
                  ref={credentialsInputRef}
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
            {unlockBundleContext ? (
              <div
                className="workspace-auth-pending-action"
                role="status"
                aria-live="polite"
                aria-label={`Unlocking ${unlockBundleContext.actionLabel}`}
              >
                <strong>Unlocking:</strong>
                <span>{unlockBundleContext.actionLabel}</span>
              </div>
            ) : null}
            <div className="workspace-auth-stage-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() =>
                  void (unlockBundleContext
                    ? saveOauthClientAndContinue()
                    : workspace.saveOauthClient(
                        oauthClientIdInput,
                        oauthClientSecretInput,
                      ))
                }
                disabled={
                  workspace.busy ||
                  !workspace.runtimeReady ||
                  !oauthClientIdInput.trim()
                }
                aria-label={saveAndContinueAriaLabel}
              >
                {saveAndContinueLabel}
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
        <section
          ref={setupStageRef}
          className="workspace-auth-stage"
          tabIndex={-1}
        >
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
              ref={chooseBundlesButtonRef}
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
        <section
          ref={setupStageRef}
          className="workspace-auth-stage"
          tabIndex={-1}
        >
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
              ref={openAuthButtonRef}
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

      <ConnectorActionUnlockModal
        open={Boolean(selectedPreviewAction && unlockDetail)}
        title={
          selectedPreviewAction
            ? `Unlock ${selectedPreviewAction.action.label}`
            : "Unlock Google action"
        }
        description={
          selectedPreviewAction
            ? `See what ${selectedPreviewAction.serviceTitle} access this action needs before you continue setup.`
            : undefined
        }
        summaryCategory={selectedPreviewAction?.serviceTitle ?? "Google"}
        summaryTitle={selectedPreviewAction?.action.label ?? "Google action"}
        summaryDescription={selectedPreviewAction?.action.description ?? ""}
        onClose={closeUnlockDrilldown}
      >
        {selectedPreviewAction && unlockDetail ? (
          <>
            <div className="workspace-unlock-grid">
              <article className="workspace-stat-card workspace-summary-card">
                <span>Current blocker</span>
                <strong>{unlockDetail.blockerHeadline}</strong>
                <p>{unlockDetail.blockerDetail}</p>
              </article>

              <article className="workspace-stat-card workspace-summary-card">
                <span>Setup target</span>
                <strong>{setupDrilldownTitle}</strong>
                <p>
                  The primary action below jumps straight to the current setup
                  control for this action.
                </p>
              </article>
            </div>

            {unlockDetail.requiredBundles.length > 0 ? (
              <div className="workspace-panel-heading">
                <strong>Required capability bundles</strong>
                <div className="workspace-bundle-strip">
                  {unlockDetail.requiredBundles.map((bundle) => (
                    <span key={bundle.id} className="workspace-bundle-chip">
                      {bundle.title}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            {unlockDetail.missingRequiredBundles.length > 0 ? (
              <div className="workspace-warning-panel">
                <strong>Still missing before this action can run</strong>
                <div className="workspace-warning-list">
                  {unlockDetail.missingRequiredBundles.map((bundle) => (
                    <span key={bundle.id}>
                      {bundle.title}: {bundle.summary}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}

            {unlockDetail.activeRequiredBundles.length > 0 ? (
              <div className="workspace-storage-list">
                {unlockDetail.activeRequiredBundles.map((bundle) => (
                  <span key={bundle.id}>
                    Already selected: <code>{bundle.title}</code>
                  </span>
                ))}
              </div>
            ) : null}

            {unlockDetail.requiredScopes.length > 0 ? (
              <div className="workspace-panel-heading">
                <strong>Exact Google scopes</strong>
                <div className="workspace-required-scopes">
                  {unlockDetail.requiredScopes.map((scope) => (
                    <code key={scope}>{scope}</code>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="workspace-modal-actions workspace-unlock-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={continueSetupFromUnlockDrilldown}
              >
                {setupDrilldownTitle}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={closeUnlockDrilldown}
              >
                Keep browsing
              </button>
            </div>
          </>
        ) : null}
      </ConnectorActionUnlockModal>
    </div>
  );
}
