import { Icons } from "../../../ui/icons";
import {
  ONBOARDING_STEPS,
  TAB_DEFINITIONS,
} from "./googleWorkspaceConnectorPanelConfig";
import { onboardingStepIndex } from "./googleWorkspaceConnectorPanelParts";
import { GoogleWorkspaceConnectorPanelConnected } from "./GoogleWorkspaceConnectorPanelConnected";
import { GoogleWorkspaceConnectorPanelOnboarding } from "./GoogleWorkspaceConnectorPanelOnboarding";
import type { GoogleWorkspaceConnectorPanelView } from "./googleWorkspaceConnectorPanelView";

export function GoogleWorkspaceConnectorPanelBody({
  view,
}: {
  view: GoogleWorkspaceConnectorPanelView;
}) {
  const {
    connector,
    workspace,
    onOpenPolicyCenter,
    activeTab,
    setActiveTab,
    setSettingsModalOpen,
    availability,
    availabilityStyle,
    isConnected,
    onboardingStep,
    reconnectScopes,
  } = view;

  return (
    <>
      <div className="workspace-overview-hero">
        <div className="workspace-hero-copy">
          <span className="workspace-hero-kicker">Kernel-backed Google connector</span>
          <h3>Google Workspace</h3>
          <p>
            Local-first Google access for Gmail, Calendar, Docs, Sheets,
            BigQuery, Drive, Tasks, Chat, and durable Workspace automations
            inside Autopilot.
          </p>
          {workspace.connectedAccountEmail ? (
            <p className="workspace-hero-account">
              Connected account: <strong>{workspace.connectedAccountEmail}</strong>
            </p>
          ) : null}
        </div>
        <div className="workspace-hero-meta">
          <div className={`workspace-health-pill tone-${availabilityStyle}`}>
            {availability}
          </div>
          <div className="workspace-hero-actions">
            <button
              type="button"
              className="btn-secondary workspace-utility-button"
              onClick={() => setSettingsModalOpen(true)}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              <Icons.Settings width="14" height="14" />
              <span>Local settings</span>
            </button>
            {onOpenPolicyCenter ? (
              <button
                type="button"
                className="btn-secondary workspace-utility-button"
                onClick={() => onOpenPolicyCenter(connector)}
              >
                <Icons.Gate width="14" height="14" />
                <span>Open policy</span>
              </button>
            ) : null}
            {isConnected ? (
              <>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => void workspace.beginAuth(reconnectScopes)}
                  disabled={
                    workspace.busy ||
                    !workspace.runtimeReady ||
                    reconnectScopes.length === 0
                  }
                >
                  {workspace.busy ? "Working..." : "Reconnect"}
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={workspace.checkConnection}
                  disabled={workspace.busy || !workspace.runtimeReady}
                >
                  Refresh
                </button>
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
              </>
            ) : null}
          </div>
        </div>
      </div>

      <div className="workspace-onboarding-rail">
        {ONBOARDING_STEPS.map((step) => {
          const stepIndex = onboardingStepIndex(step.id);
          const currentIndex = onboardingStepIndex(onboardingStep);
          const state =
            stepIndex < currentIndex
              ? "complete"
              : step.id === onboardingStep
                ? "active"
                : "upcoming";
          return (
            <div
              key={step.id}
              className={`workspace-onboarding-step state-${state}`}
              aria-current={step.id === onboardingStep ? "step" : undefined}
            >
              <span>{stepIndex + 1}</span>
              <strong>{step.label}</strong>
            </div>
          );
        })}
      </div>

      {!workspace.runtimeReady ? (
        <p className="connector-test-error">
          Runtime is missing the generic Google connector commands.
        </p>
      ) : null}
      {workspace.notice ? (
        <p className="connector-test-success">{workspace.notice}</p>
      ) : null}
      {workspace.error ? (
        <p className="connector-test-error">{workspace.error}</p>
      ) : null}

      <div
        className="workspace-tab-nav"
        role="tablist"
        aria-label="Google Workspace sections"
      >
        {TAB_DEFINITIONS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            className={`workspace-tab-button ${
              activeTab === tab.id ? "active" : ""
            }`}
            onClick={() => setActiveTab(tab.id)}
          >
            <strong>{tab.label}</strong>
            <span>{tab.blurb}</span>
          </button>
        ))}
      </div>

      {!isConnected ? (
        <GoogleWorkspaceConnectorPanelOnboarding view={view} />
      ) : (
        <GoogleWorkspaceConnectorPanelConnected view={view} />
      )}
    </>
  );
}
