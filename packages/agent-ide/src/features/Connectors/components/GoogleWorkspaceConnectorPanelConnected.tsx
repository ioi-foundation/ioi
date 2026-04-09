import { AUTOMATION_RECIPES, OVERVIEW_QUICKSTARTS } from "./googleWorkspaceConnectorPanelConfig";
import {
  ConnectorActionWorkbench,
  ConnectorFocusedFormCard,
} from "./ConnectorExecutionWorkbench";
import {
  WorkspaceActionComposer,
  WorkspaceSubscriptionCard,
  formatTimestamp,
  serviceStateLabel,
  serviceStateTone,
} from "./googleWorkspaceConnectorPanelParts";
import type { GoogleWorkspaceConnectorPanelView } from "./googleWorkspaceConnectorPanelView";

export function GoogleWorkspaceConnectorPanelConnected({
  view,
}: {
  view: GoogleWorkspaceConnectorPanelView;
}) {
  const {
    connector,
    workspace,
    onOpenPolicyCenter,
    policySummary,
    activeTab,
    setSettingsModalOpen,
    actionsById,
    capabilityGroups,
    automationGroups,
    advancedGroups,
    activeSubscriptions,
    attentionSubscriptions,
    availability,
    openAction,
    focusedActionModalOpen,
    openFocusedActionModal,
    closeFocusedActionModal,
  } = view;

  return (
    <>
      {activeTab === "overview" ? (
        <div className="workspace-tab-panel">
          <div className="workspace-overview-grid">
            <article className="workspace-stat-card">
              <span>Account</span>
              <strong>{workspace.connectedAccountEmail ?? "Not connected"}</strong>
              <p>
                {workspace.lastConfiguredAtUtc
                  ? `Last checked ${formatTimestamp(workspace.lastConfiguredAtUtc)}`
                  : connector.lastSyncAtUtc
                    ? `Last sync ${formatTimestamp(connector.lastSyncAtUtc)}`
                    : "Run Connect to start native Google OAuth in Autopilot."}
              </p>
            </article>
            <article className="workspace-stat-card">
              <span>Availability</span>
              <strong>{availability}</strong>
              <p>
                {workspace.grantedScopes.length > 0
                  ? `${workspace.grantedScopes.length} Google scopes granted for this connection.`
                  : "No Google scopes are available until the connector is connected."}
              </p>
            </article>
            <article className="workspace-stat-card">
              <span>Background Automations</span>
              <strong>{activeSubscriptions.length}</strong>
              <p>
                {attentionSubscriptions.length > 0
                  ? `${attentionSubscriptions.length} subscriptions need attention.`
                  : "No automation incidents are currently visible."}
              </p>
            </article>
            <article className="workspace-stat-card">
              <span>Capability Bundles</span>
              <strong>{capabilityGroups.length}</strong>
              <p>{capabilityGroups.map((group) => group.title).join(", ")}</p>
            </article>
          </div>

          <div className="workspace-overview-grid">
            <article className="workspace-stat-card workspace-summary-card">
              <span>Local settings</span>
              <strong>
                {workspace.tokenStorage.source === "local"
                  ? "Stored locally"
                  : "Managed by runtime"}
              </strong>
              <p>
                Client configuration and tokens stay on this machine. Open local
                settings to review storage paths, grants, reconnect flow, and
                destructive reset actions.
              </p>
              <div className="workspace-card-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setSettingsModalOpen(true)}
                >
                  Open local settings
                </button>
              </div>
            </article>
            {policySummary ? (
              <article className="workspace-stat-card workspace-summary-card">
                <span>Policy</span>
                <strong>{policySummary.headline}</strong>
                <p>{policySummary.detail}</p>
                <div className="workspace-card-actions">
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => onOpenPolicyCenter?.(connector)}
                  >
                    Open policy
                  </button>
                </div>
              </article>
            ) : null}
          </div>

          <div className="workspace-state-grid">
            {capabilityGroups.map((group) => {
              const serviceState = workspace.serviceStates[group.service];
              const readinessLabel = serviceStateLabel(serviceState?.status);
              const readinessTone = serviceStateTone(serviceState?.status);

              return (
                <article key={group.service} className="workspace-state-card">
                  <div className="workspace-state-head">
                    <strong>{group.title}</strong>
                    <span
                      className={`workspace-health-pill tone-${readinessTone}`}
                    >
                      {readinessLabel}
                    </span>
                  </div>
                  <p>{serviceState?.summary ?? group.summary}</p>
                  {serviceState?.missingScopes?.length ? (
                    <span className="workspace-state-detail">
                      Missing scopes: {serviceState.missingScopes.join(", ")}
                    </span>
                  ) : (
                    <span className="workspace-state-detail">{group.detail}</span>
                  )}
                </article>
              );
            })}
          </div>

          <div className="workspace-section-header">
            <div>
              <h4>Recommended next moves</h4>
              <p>
                Guide users toward a first win, then into durable background
                automation.
              </p>
            </div>
          </div>
          <div className="workspace-quickstart-grid">
            {OVERVIEW_QUICKSTARTS.map((item) => {
              const enabled = item.actionId ? actionsById.has(item.actionId) : true;
              return (
                <article key={item.id} className="workspace-quickstart-card">
                  <strong>{item.title}</strong>
                  <p>{item.summary}</p>
                  {item.actionId && item.tab ? (
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() =>
                        openAction(item.tab!, item.actionId!, item.presetInput)
                      }
                      disabled={
                        !enabled ||
                        (item.requiresRuntime && !workspace.runtimeReady)
                      }
                    >
                      Open flow
                    </button>
                  ) : null}
                </article>
              );
            })}
          </div>

          <div className="workspace-section-header">
            <div>
              <h4>Scope bundles</h4>
              <p>Expose capabilities as service bundles first, not raw OAuth jargon.</p>
            </div>
          </div>
          <div className="workspace-bundle-strip">
            {capabilityGroups.map((group) => (
              <span key={group.service} className="workspace-bundle-chip">
                {group.title}
              </span>
            ))}
          </div>
          {workspace.bootstrapWarnings.length > 0 ? (
            <div className="workspace-warning-panel">
              <strong>Discovery notes</strong>
              <div className="workspace-warning-list">
                {workspace.bootstrapWarnings.map((warning) => (
                  <span key={`${warning.service}-${warning.message}`}>
                    {warning.service}: {warning.message}
                  </span>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {activeTab === "capabilities" ? (
        <div className="workspace-tab-panel">
          <ConnectorActionWorkbench
            title="Capability workspace"
            summary="Select a common Google task from the catalog or the quick picks below. The runnable form stays pinned here while you browse."
            actionLabel={workspace.selectedAction?.label ?? null}
            shortcuts={OVERVIEW_QUICKSTARTS.filter(
              (item) =>
                item.actionId &&
                item.tab === "capabilities" &&
                actionsById.has(item.actionId),
            ).map((item) => (
              <button
                key={item.id}
                type="button"
                className={`workspace-featured-action ${
                  workspace.selectedActionId === item.actionId ? "active" : ""
                }`}
                onClick={() =>
                  openAction("capabilities", item.actionId!, item.presetInput)
                }
              >
                {item.title}
              </button>
            ))}
            composer={
              focusedActionModalOpen ? (
                <ConnectorFocusedFormCard
                  actionLabel={workspace.selectedAction?.label ?? null}
                  description="The full form is open in a modal so the fields and primary action stay in view while you work."
                  onReturn={closeFocusedActionModal}
                />
              ) : (
                <WorkspaceActionComposer
                  action={workspace.selectedAction}
                  workspace={workspace}
                  eyebrow="Capability workspace"
                  showFocusedFormButton
                  onOpenFocusedForm={openFocusedActionModal}
                />
              )
            }
          >
            <div className="workspace-section-header">
              <div>
                <h4>Capability catalog</h4>
                <p>
                  Lead with common jobs to be done, then open the full action
                  composer only when needed.
                </p>
              </div>
            </div>
            <div className="workspace-capability-grid">
              {capabilityGroups.map((group) => {
                const serviceState = workspace.serviceStates[group.service];
                return (
                  <article key={group.service} className="workspace-service-card">
                    <div className="workspace-service-card-head">
                      <div>
                        <h4>{group.title}</h4>
                        <p>{serviceState?.summary ?? group.summary}</p>
                      </div>
                      <div className="workspace-service-card-meta">
                        <span
                          className={`workspace-health-pill tone-${serviceStateTone(serviceState?.status)}`}
                        >
                          {serviceStateLabel(serviceState?.status)}
                        </span>
                        <span className="workspace-service-count">
                          {group.actions.length} tools
                        </span>
                      </div>
                    </div>
                    {serviceState?.missingScopes?.length ? (
                      <span className="workspace-state-detail">
                        Missing scopes: {serviceState.missingScopes.join(", ")}
                      </span>
                    ) : null}
                    <div className="workspace-kind-list">
                      {group.kinds.map((kind) => (
                        <span
                          key={`${group.service}-${kind}`}
                          className="workspace-kind-chip"
                        >
                          {kind}
                        </span>
                      ))}
                    </div>
                    <div className="workspace-featured-actions">
                      {group.featuredActions.map((action) => (
                        <button
                          key={action.id}
                          type="button"
                          className={`workspace-featured-action ${
                            workspace.selectedActionId === action.id
                              ? "active"
                              : ""
                          }`}
                          onClick={() => openAction("capabilities", action.id)}
                        >
                          {action.label}
                        </button>
                      ))}
                    </div>
                    {group.supportingActions.length > 0 ? (
                      <div className="workspace-supporting-actions">
                        {group.supportingActions.map((action) => (
                          <button
                            key={action.id}
                            type="button"
                            className={`workspace-tool-chip ${
                              workspace.selectedActionId === action.id
                                ? "active"
                                : ""
                            }`}
                            onClick={() => openAction("capabilities", action.id)}
                          >
                            {action.label}
                          </button>
                        ))}
                      </div>
                    ) : null}
                  </article>
                );
              })}
            </div>
          </ConnectorActionWorkbench>
        </div>
      ) : null}

      {activeTab === "automations" ? (
        <div className="workspace-tab-panel">
          <ConnectorActionWorkbench
            title="Automation setup"
            summary="Keep the long-lived recipe form in view while you compare watches, event streams, and subscription health."
            actionLabel={workspace.selectedAction?.label ?? null}
            shortcuts={AUTOMATION_RECIPES.filter((recipe) =>
              actionsById.has(recipe.actionId),
            ).map((recipe) => (
              <button
                key={recipe.id}
                type="button"
                className={`workspace-featured-action ${
                  workspace.selectedActionId === recipe.actionId ? "active" : ""
                }`}
                onClick={() =>
                  openAction("automations", recipe.actionId, recipe.presetInput)
                }
              >
                {recipe.title}
              </button>
            ))}
            composer={
              focusedActionModalOpen ? (
                <ConnectorFocusedFormCard
                  actionLabel={workspace.selectedAction?.label ?? null}
                  description="The automation form is open in a modal so the longer recipe fields stay visible."
                  onReturn={closeFocusedActionModal}
                />
              ) : (
                <WorkspaceActionComposer
                  action={workspace.selectedAction}
                  workspace={workspace}
                  eyebrow="Automation setup"
                  showFocusedFormButton
                  onOpenFocusedForm={openFocusedActionModal}
                />
              )
            }
          >
            <div className="workspace-section-header">
              <div>
                <h4>Automation center</h4>
                <p>
                  Manage durable Gmail watches and Workspace event ingestion as
                  long-lived product state.
                </p>
              </div>
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.refreshSubscriptions}
                disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
              >
                Refresh automations
              </button>
            </div>

            <div className="workspace-overview-grid">
              <article className="workspace-stat-card">
                <span>Running</span>
                <strong>{activeSubscriptions.length}</strong>
                <p>
                  Watches and event streams currently kept alive by the desktop
                  runtime.
                </p>
              </article>
              <article className="workspace-stat-card">
                <span>Attention</span>
                <strong>{attentionSubscriptions.length}</strong>
                <p>
                  Subscriptions needing reauth or repair before they can keep
                  consuming.
                </p>
              </article>
              <article className="workspace-stat-card">
                <span>Total subscriptions</span>
                <strong>{workspace.subscriptions.length}</strong>
                <p>Pause, renew, and inspect them directly from this surface.</p>
              </article>
              <article className="workspace-stat-card">
                <span>Automation entry points</span>
                <strong>{automationGroups.length}</strong>
                <p>
                  Admin-grade actions are packaged separately from the day-to-day
                  capability grid.
                </p>
              </article>
            </div>

            <div className="workspace-automation-grid">
              {AUTOMATION_RECIPES.map((recipe) => (
                <article key={recipe.id} className="workspace-automation-card">
                  <strong>{recipe.title}</strong>
                  <p>{recipe.summary}</p>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() =>
                      openAction("automations", recipe.actionId, recipe.presetInput)
                    }
                    disabled={!actionsById.has(recipe.actionId)}
                  >
                    Configure recipe
                  </button>
                </article>
              ))}
            </div>

            {workspace.subscriptions.length > 0 ? (
              <div className="workspace-subscription-list">
                {workspace.subscriptions.map((subscription) => (
                  <WorkspaceSubscriptionCard
                    key={subscription.subscriptionId}
                    subscription={subscription}
                    workspace={workspace}
                  />
                ))}
              </div>
            ) : (
              <div className="workspace-empty-state">
                <strong>No automations running yet</strong>
                <p>
                  Configure Gmail Watch Emails or Workspace Events Subscribe to
                  create the first durable job.
                </p>
              </div>
            )}
          </ConnectorActionWorkbench>
        </div>
      ) : null}

      {activeTab === "advanced" ? (
        <div className="workspace-tab-panel">
          <ConnectorActionWorkbench
            title="Advanced execution"
            summary="Browse the full tool catalog without losing the live action form or the current result pane."
            actionLabel={workspace.selectedAction?.label ?? null}
            shortcuts={advancedGroups
              .flatMap((group) => group.featuredActions)
              .slice(0, 6)
              .map((action) => (
                <button
                  key={action.id}
                  type="button"
                  className={`workspace-featured-action ${
                    workspace.selectedActionId === action.id ? "active" : ""
                  }`}
                  onClick={() => openAction("advanced", action.id)}
                >
                  {action.label}
                </button>
              ))}
            composer={
              focusedActionModalOpen ? (
                <ConnectorFocusedFormCard
                  actionLabel={workspace.selectedAction?.label ?? null}
                  description="The full execution form is open in a modal so the advanced tool fields do not compete with the catalog."
                  onReturn={closeFocusedActionModal}
                />
              ) : (
                <>
                  <WorkspaceActionComposer
                    action={workspace.selectedAction}
                    workspace={workspace}
                    eyebrow="Advanced execution"
                    showFocusedFormButton
                    onOpenFocusedForm={openFocusedActionModal}
                  />
                  {workspace.formattedResult ? (
                    <pre className="connector-test-result workspace-result-panel">
                      {workspace.formattedResult}
                    </pre>
                  ) : null}
                </>
              )
            }
          >
            <div className="workspace-section-header">
              <div>
                <h4>Advanced tool catalog</h4>
                <p>
                  Keep the full connector catalog available for power users,
                  debugging, and edge cases.
                </p>
              </div>
            </div>
            <div className="workspace-service-panel">
              {advancedGroups.map((group) => (
                <section key={group.service} className="workspace-service-group">
                  <div className="workspace-service-head">
                    <div>
                      <h4>{group.title}</h4>
                      <p>{group.detail}</p>
                    </div>
                    <div className="workspace-service-tools">
                      {group.actions.map((action) => (
                        <button
                          key={action.id}
                          type="button"
                          className={`workspace-tool-chip ${
                            workspace.selectedActionId === action.id ? "active" : ""
                          }`}
                          onClick={() => openAction("advanced", action.id)}
                        >
                          {action.label}
                        </button>
                      ))}
                    </div>
                  </div>
                </section>
              ))}
            </div>

            {connector.notes ? (
              <p className="workspace-inline-note">{connector.notes}</p>
            ) : null}
          </ConnectorActionWorkbench>
        </div>
      ) : null}
    </>
  );
}
