import { summarizeSettingsAuthorityCenter } from "./settingsAuthorityCenter";
import type { SettingsViewBodyView } from "./settingsViewTypes";

function authorityPillClass(tone: string): string {
  if (tone === "blocked")
    return "chat-settings-pill chat-settings-pill-blocked";
  if (tone === "warning")
    return "chat-settings-pill chat-settings-pill-warning";
  if (tone === "ready") return "chat-settings-pill chat-settings-pill-ready";
  return "chat-settings-pill";
}

export function SettingsAuthoritySection({
  view,
}: {
  view: SettingsViewBodyView;
}) {
  const {
    authorityCenterProjection,
    authorityCenterLoading,
    authorityCenterError,
    refreshAuthorityCenterProjection,
    onOpenPolicySurface,
    onOpenConnections,
  } = view;
  const summary = summarizeSettingsAuthorityCenter(authorityCenterProjection);

  return (
    <div
      className="chat-settings-stack"
      data-testid="settings-authority-center"
    >
      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Authority Center</span>
            <h2>Capability control plane</h2>
          </div>
          <span className={authorityPillClass(summary.tone)}>
            {authorityCenterLoading ? "Refreshing" : summary.label}
          </span>
        </div>
        <p className="chat-settings-body">
          {authorityCenterError ?? summary.detail}
        </p>
        <div className="chat-settings-summary-grid">
          {summary.checklist.map((item) => (
            <article key={item} className="chat-settings-subcard">
              <strong>{item.split(" ").slice(1).join(" ")}</strong>
              <span>{item.split(" ")[0]}</span>
            </article>
          ))}
        </div>
        <div className="chat-settings-actions">
          <button
            type="button"
            className="chat-settings-secondary"
            onClick={() => void refreshAuthorityCenterProjection(true)}
            disabled={authorityCenterLoading}
          >
            {authorityCenterLoading ? "Refreshing..." : "Refresh projection"}
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            onClick={onOpenPolicySurface}
          >
            Open full Authority Center
          </button>
          <button
            type="button"
            className="chat-settings-secondary"
            onClick={onOpenConnections}
          >
            Open connections
          </button>
        </div>
      </article>

      {summary.failClosedReasons.length > 0 ? (
        <article
          className="chat-settings-card"
          data-testid="settings-authority-fail-closed"
        >
          <div className="chat-settings-card-head">
            <div>
              <span className="chat-settings-card-eyebrow">Run safety</span>
              <h2>Fail-closed reasons</h2>
            </div>
            <span className="chat-settings-pill chat-settings-pill-warning">
              {summary.failClosedReasons.length} item
              {summary.failClosedReasons.length === 1 ? "" : "s"}
            </span>
          </div>
          <div className="chat-settings-stack chat-settings-stack--compact">
            {summary.failClosedReasons.slice(0, 8).map((reason) => (
              <article key={reason} className="chat-settings-subcard">
                <strong>Readiness blocker</strong>
                <span>{reason}</span>
              </article>
            ))}
          </div>
        </article>
      ) : null}

      <article className="chat-settings-card">
        <div className="chat-settings-card-head">
          <div>
            <span className="chat-settings-card-eyebrow">Registry</span>
            <h2>Capabilities used by workflows and runs</h2>
          </div>
          <span className="chat-settings-pill">
            {authorityCenterProjection.capabilities.length} projected
          </span>
        </div>
        <div className="chat-settings-stack chat-settings-stack--compact">
          {summary.topCapabilities.length === 0 ? (
            <p className="chat-settings-body">
              The runtime has not projected model, tool, or connector
              capabilities yet.
            </p>
          ) : (
            summary.topCapabilities.map((capability) => (
              <article
                key={`${capability.kind}-${capability.id}`}
                className="chat-settings-subcard"
                data-testid="settings-authority-capability-row"
              >
                <div className="chat-settings-subcard-head">
                  <strong>{capability.label}</strong>
                  <span>{capability.status}</span>
                </div>
                <div className="chat-settings-chip-row">
                  <span className="chat-settings-chip">{capability.kind}</span>
                  <span className="chat-settings-chip">
                    {capability.receiptTypes.length} receipt type
                    {capability.receiptTypes.length === 1 ? "" : "s"}
                  </span>
                  <span className="chat-settings-chip">
                    {capability.requiredScopes.length} scope
                    {capability.requiredScopes.length === 1 ? "" : "s"}
                  </span>
                </div>
                <p>{capability.detail}</p>
                <small>{capability.policyTarget ?? capability.id}</small>
              </article>
            ))
          )}
        </div>
      </article>
    </div>
  );
}
