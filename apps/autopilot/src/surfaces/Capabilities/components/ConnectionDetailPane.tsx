import {
  GenericConnectorPanel,
  GoogleWorkspaceConnectorPanel,
  MailConnectorPanel,
} from "@ioi/agent-ide";
import {
  connectorStatusLabel,
  formatAuthMode,
  humanize,
  templateLabelForConnection,
} from "./model";
import { CapabilityAuthoritySection } from "./CapabilityAuthoritySection";
import { DetailDocument } from "./ui";
import type { CapabilitiesDetailPaneProps } from "./detailPaneTypes";

export function ConnectionDetailPane({
  controller,
  getConnectorPolicySummary,
  getConnectorTrustProfile,
  onOpenPolicyCenter,
}: CapabilitiesDetailPaneProps) {
  const selectedConnectionRecord = controller.connections.selectedRecord;
  if (!selectedConnectionRecord) {
    return (
      <div className="capabilities-empty-detail">
        {controller.connections.loading
          ? "Loading live connector catalog..."
          : controller.connections.error
            ? `Live connector catalog unavailable: ${controller.connections.error}`
            : "Select a live connector or workspace planning template to inspect setup posture and guardrails."}
      </div>
    );
  }

  const { connector, origin } = selectedConnectionRecord;
  const isTemplate = origin === "workspace_template";
  const policySummary = getConnectorPolicySummary?.(connector) ?? null;
  const trustProfile =
    getConnectorTrustProfile?.(connector, { template: isTemplate }) ?? null;
  const registryEntry = controller.connections.selectedRegistryEntry;
  const actionState = controller.connections.selectedActionState;
  const liveActions = actionState?.actions ?? [];
  const actionScopeCount = new Set(
    liveActions.flatMap((action) => action.requiredScopes ?? []),
  ).size;
  const confirmBeforeRunCount = liveActions.filter(
    (action) => action.confirmBeforeRun,
  ).length;
  const sectionTitle = humanize(controller.connections.detailSection);
  const sectionSummary =
    controller.connections.detailSection === "overview"
      ? isTemplate
        ? "Planned scopes, ownership notes, and adapter intent for this workspace planning template."
        : "Reach, scopes, and current notes for this authenticated surface."
      : controller.connections.detailSection === "setup"
        ? isTemplate
          ? "Capture adapter intent, ownership, and runtime prerequisites while this stays outside the live connector catalog."
          : "Attach auth and finish adapter wiring for runtime use."
        : controller.connections.detailSection === "actions"
          ? isTemplate
            ? "Live tools are only inspectable after this planning template becomes a real runtime connector."
            : "Inspect live callable actions, required fields, and confirm-before-run posture for this connector."
        : "Governance and approval controls applied to this connection.";
  const sectionMeta =
    controller.connections.detailSection === "overview"
      ? `${connector.scopes.length} scopes`
      : controller.connections.detailSection === "setup"
        ? isTemplate
          ? "Template"
          : "Live"
        : controller.connections.detailSection === "actions"
          ? isTemplate
            ? "Template"
            : actionState?.status === "ready"
              ? `${liveActions.length} tools`
              : actionState?.status === "error"
                ? "Retry"
                : "Loading"
        : trustProfile?.tierLabel ?? "Guardrails";

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">{humanize(connector.category)}</span>
          <h2>{connector.name}</h2>
        </div>
        <span className={`capabilities-pill status-${connector.status}`}>
          {isTemplate
            ? templateLabelForConnection(selectedConnectionRecord)
            : connectorStatusLabel(connector.status)}
        </span>
      </header>

      <div className="capabilities-detail-inline-meta">
        <span>
          Provider <strong>{connector.provider}</strong>
        </span>
        <span>
          Category <strong>{humanize(connector.category)}</strong>
        </span>
        <span>
          Auth <strong>{formatAuthMode(connector.authMode)}</strong>
        </span>
        <span>
          Authority <strong>{trustProfile?.tierLabel ?? "Pending"}</strong>
        </span>
        <span>
          Scopes <strong>{connector.scopes.length}</strong>
        </span>
      </div>

      <p className="capabilities-detail-summary">{connector.description}</p>

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.connections.detailSection === "overview" ? (
          registryEntry ? (
            <CapabilityAuthoritySection
              currentEntry={registryEntry}
              authority={registryEntry.authority}
              lease={registryEntry.lease}
              comparisonPool={controller.registry.snapshot?.entries}
              relatedGoverningEntries={controller.registry.getRelatedGoverningEntries(
                registryEntry.entryId,
              )}
              onPlanWiderLeaseProposal={(comparisonEntryId) =>
                controller.connections.planSelectedConnectionGovernanceProposal(
                  comparisonEntryId,
                )
              }
              onRequestWiderLease={(request) =>
                controller.connections.requestSelectedConnectionPolicyIntent(
                  "widen",
                  request,
                )
              }
              onReturnToBaseline={() =>
                controller.connections.requestSelectedConnectionPolicyIntent("baseline")
              }
              onOpenPolicyCenter={() => onOpenPolicyCenter?.(connector)}
              onOpenRelatedEntry={(entryId) =>
                controller.registry.openEntry(entryId)
              }
              onOpenRelatedPolicy={(entryId) =>
                controller.registry.openEntry(entryId, {
                  openPolicyCenter: true,
                })
              }
              sourceNote={`This runtime connector is resolved from ${registryEntry.sourceLabel}.`}
            />
          ) : trustProfile ? (
            <section className="capabilities-detail-card capabilities-trust-card">
              <div className="capabilities-detail-card-head">
                <h3>Authority tier</h3>
                <span>{trustProfile.governedProfileLabel}</span>
              </div>
              <div className="capabilities-trust-tier-line">
                <div className="capabilities-trust-tier-copy">
                  <strong>{trustProfile.tierLabel}</strong>
                  <span>{trustProfile.summary}</span>
                </div>
                <span className="capabilities-trust-tier-badge">
                  {trustProfile.governedProfileLabel}
                </span>
              </div>
              <p className="capabilities-trust-detail">{trustProfile.detail}</p>
              <div className="capabilities-trust-signal-list">
                {trustProfile.signals.map((signal) => (
                  <span key={signal} className="capabilities-trust-signal">
                    {signal}
                  </span>
                ))}
              </div>
            </section>
          ) : null
        ) : null}

        {controller.connections.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
              <span>{connector.scopes.length} scopes</span>
            </div>
            <div className="capabilities-chip-row">
              {connector.scopes.map((scope: string) => (
                <span key={scope} className="capabilities-chip">
                  {humanize(scope)}
                </span>
              ))}
            </div>
            {connector.notes ? (
              <p className="capabilities-inline-note">{connector.notes}</p>
            ) : null}
          </section>
        ) : null}

        {controller.connections.detailSection === "policy" ? (
          policySummary ? (
            <section className="capabilities-detail-card capabilities-policy-card">
              <div className="capabilities-detail-card-head">
                <h3>Policy</h3>
                <button
                  type="button"
                  className="capabilities-inline-button"
                  onClick={() => onOpenPolicyCenter?.(connector)}
                >
                  Open policy
                </button>
              </div>
              <strong>{policySummary.headline}</strong>
              <p>{policySummary.detail}</p>
            </section>
          ) : (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Policy</h3>
              </div>
              <p>
                No connection-specific policy summary is available yet for this
                surface.
              </p>
            </section>
          )
        ) : null}

        {controller.connections.detailSection === "setup" ? (
          !isTemplate && connector.pluginId === "google_workspace" ? (
            <GoogleWorkspaceConnectorPanel
              runtime={controller.runtime}
              connector={connector}
              initialTab="overview"
              onConfigured={controller.connections.applyConfiguredConnectorResult}
              onOpenPolicyCenter={onOpenPolicyCenter}
              policySummary={policySummary ?? undefined}
            />
          ) : !isTemplate && connector.id === "mail.primary" ? (
            <MailConnectorPanel mail={controller.mail} />
          ) : (
            isTemplate ? (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Setup</h3>
                  <span>Template</span>
                </div>
                <p>
                  This workspace planning template stays outside the live connector
                  catalog. Use it to capture adapter intent, ownership, and policy
                  posture before a real runtime connector exists.
                </p>
                <div className="capabilities-action-row">
                  <button
                    type="button"
                    className="capabilities-secondary-button"
                    onClick={() => onOpenPolicyCenter?.(connector)}
                  >
                    Open policy
                  </button>
                </div>
              </section>
            ) : (
              <GenericConnectorPanel
                runtime={controller.runtime}
                connector={connector}
                section="setup"
                onConfigured={controller.connections.applyConfiguredConnectorResult}
                onOpenPolicyCenter={onOpenPolicyCenter}
              />
            )
          )
        ) : null}

        {controller.connections.detailSection === "actions" ? (
          !isTemplate && connector.pluginId === "google_workspace" ? (
            <GoogleWorkspaceConnectorPanel
              runtime={controller.runtime}
              connector={connector}
              initialTab="capabilities"
              onConfigured={controller.connections.applyConfiguredConnectorResult}
              onOpenPolicyCenter={onOpenPolicyCenter}
              policySummary={policySummary ?? undefined}
            />
          ) : isTemplate ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Live tools</h3>
                <span>Template</span>
              </div>
              <p>
                This workspace planning template does not expose callable runtime
                actions yet. Promote it to a real connector before expecting live
                tool inspection here.
              </p>
            </section>
          ) : !isTemplate && connector.id === "mail.primary" ? (
            <MailConnectorPanel mail={controller.mail} />
          ) : !isTemplate && connector.pluginId !== "google_workspace" ? (
            <GenericConnectorPanel
              runtime={controller.runtime}
              connector={connector}
              section="actions"
              onConfigured={controller.connections.applyConfiguredConnectorResult}
              onOpenPolicyCenter={onOpenPolicyCenter}
            />
          ) : actionState?.status === "error" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Live tools</h3>
                <button
                  type="button"
                  className="capabilities-inline-button"
                  onClick={() =>
                    controller.connections.retrySelectedConnectorActions()
                  }
                >
                  Retry
                </button>
              </div>
              <p>
                {actionState.error ??
                  "The runtime could not load connector actions for this surface."}
              </p>
            </section>
          ) : actionState?.status === "loading" || actionState?.status === "idle" ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Live tools</h3>
                <span>Loading</span>
              </div>
              <p>Inspecting connector-backed actions from the live runtime...</p>
            </section>
          ) : liveActions.length === 0 ? (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Live tools</h3>
                <span>0 tools</span>
              </div>
              <p>
                This connector is live, but it does not currently publish any
                callable actions through the runtime.
              </p>
            </section>
          ) : (
            <>
              <section className="capabilities-detail-meta-grid capabilities-detail-meta-grid-compact">
                <article>
                  <span>Live tools</span>
                  <strong>{liveActions.length}</strong>
                </article>
                <article>
                  <span>Confirm before run</span>
                  <strong>{confirmBeforeRunCount}</strong>
                </article>
                <article>
                  <span>Required scopes</span>
                  <strong>{actionScopeCount}</strong>
                </article>
              </section>

              <section className="capabilities-connector-actions">
                {liveActions.map((action) => (
                  <article
                    key={action.id}
                    className="capabilities-detail-card capabilities-connector-action-card"
                  >
                    <div className="capabilities-connector-action-head">
                      <div className="capabilities-connector-action-copy">
                        <div className="capabilities-connector-action-title">
                          <h3>{action.label}</h3>
                          <span className="capabilities-pill">
                            {humanize(action.kind)}
                          </span>
                        </div>
                        <p>
                          {action.description ||
                            "Live runtime action exposed by this connector."}
                        </p>
                      </div>
                      <div className="capabilities-connector-action-meta">
                        {action.toolName ? (
                          <span className="capabilities-chip">
                            Tool {action.toolName}
                          </span>
                        ) : null}
                        {action.serviceLabel || action.service ? (
                          <span className="capabilities-chip">
                            Service {action.serviceLabel ?? humanize(action.service ?? "")}
                          </span>
                        ) : null}
                        {action.confirmBeforeRun ? (
                          <span className="capabilities-chip">
                            Confirm before run
                          </span>
                        ) : null}
                      </div>
                    </div>

                    {action.requiredScopes && action.requiredScopes.length > 0 ? (
                      <div className="capabilities-connector-action-block">
                        <strong>Required scopes</strong>
                        <div className="capabilities-chip-row">
                          {action.requiredScopes.map((scope) => (
                            <span key={scope} className="capabilities-chip">
                              {humanize(scope)}
                            </span>
                          ))}
                        </div>
                      </div>
                    ) : null}

                    <div className="capabilities-connector-action-block">
                      <strong>Input fields</strong>
                      {action.fields.length > 0 ? (
                        <div className="capabilities-connector-field-list">
                          {action.fields.map((field) => (
                            <div
                              key={field.id}
                              className="capabilities-connector-field"
                            >
                              <div className="capabilities-connector-field-head">
                                <strong>{field.label}</strong>
                                <div className="capabilities-connector-field-flags">
                                  <span className="capabilities-chip">
                                    {humanize(field.type)}
                                  </span>
                                  <span className="capabilities-chip">
                                    {field.required ? "Required" : "Optional"}
                                  </span>
                                </div>
                              </div>
                              <p>
                                {field.description ||
                                  field.placeholder ||
                                  "No additional field guidance is available yet."}
                              </p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="capabilities-inline-note">
                          This action does not currently require structured input
                          fields.
                        </p>
                      )}
                    </div>
                  </article>
                ))}
              </section>
            </>
          )
        ) : null}
      </DetailDocument>
    </div>
  );
}
