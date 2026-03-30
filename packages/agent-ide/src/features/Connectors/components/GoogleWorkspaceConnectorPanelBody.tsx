import { Icons } from "../../../ui/icons";
import { ONBOARDING_STEPS } from "./googleWorkspaceConnectorPanelConfig";
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
          <span className="workspace-hero-kicker">Built-in Google Connector</span>
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

      {!isConnected ? (
        <GoogleWorkspaceConnectorPanelOnboarding view={view} />
      ) : (
        <GoogleWorkspaceConnectorPanelConnected view={view} />
      )}
    </>
  );
}
