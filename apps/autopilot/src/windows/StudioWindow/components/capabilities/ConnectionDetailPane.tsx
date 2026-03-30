import {
  GoogleWorkspaceConnectorPanel,
  MailConnectorPanel,
} from "@ioi/agent-ide";
import { connectorStatusLabel, formatAuthMode, humanize } from "./model";
import { DetailDocument } from "./ui";
import type { CapabilitiesDetailPaneProps } from "./detailPaneTypes";

export function ConnectionDetailPane({
  controller,
  getConnectorPolicySummary,
  onOpenPolicyCenter,
}: CapabilitiesDetailPaneProps) {
  const selectedConnectionRecord = controller.connections.selectedRecord;
  if (!selectedConnectionRecord) {
    return (
      <div className="capabilities-empty-detail">
        Select a connection to inspect auth state, policy posture, and setup
        flows.
      </div>
    );
  }

  const { connector, origin } = selectedConnectionRecord;
  const policySummary = getConnectorPolicySummary?.(connector) ?? null;
  const sectionTitle = humanize(controller.connections.detailSection);
  const sectionSummary =
    controller.connections.detailSection === "overview"
      ? "Reach, scopes, and current notes for this authenticated surface."
      : controller.connections.detailSection === "setup"
        ? "Attach auth, finish adapter wiring, or stage the connector for runtime use."
        : "Governance and approval controls applied to this connection.";
  const sectionMeta =
    controller.connections.detailSection === "overview"
      ? `${connector.scopes.length} scopes`
      : controller.connections.detailSection === "setup"
        ? origin === "workspace"
          ? "Planned"
          : "Live"
        : "Guardrails";

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">{humanize(connector.category)}</span>
          <h2>{connector.name}</h2>
        </div>
        <span className={`capabilities-pill status-${connector.status}`}>
          {origin === "workspace"
            ? "Staged"
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
          origin === "runtime" && connector.pluginId === "google_workspace" ? (
            <GoogleWorkspaceConnectorPanel
              runtime={controller.runtime}
              connector={connector}
              onConfigured={controller.connections.applyConfiguredConnectorResult}
              onOpenPolicyCenter={onOpenPolicyCenter}
              policySummary={policySummary ?? undefined}
            />
          ) : origin === "runtime" && connector.id === "mail.primary" ? (
            <MailConnectorPanel mail={controller.mail} />
          ) : (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Setup</h3>
                <span>{origin === "workspace" ? "Planned" : "Available"}</span>
              </div>
              <p>
                {origin === "workspace"
                  ? "This connection is staged in the workspace shell so teams can design around it before the adapter ships."
                  : "This connection exposes a generic runtime surface. Configure it to attach auth and unlock its callable actions."}
              </p>
              <div className="capabilities-action-row">
                {origin === "runtime" ? (
                  <button
                    type="button"
                    className="capabilities-primary-button"
                    disabled={controller.connections.genericConnectorBusy}
                    onClick={() =>
                      void controller.connections.runGenericConnectorSetup(
                        connector,
                      )
                    }
                  >
                    {controller.connections.genericConnectorBusy
                      ? "Connecting..."
                      : "Connect"}
                  </button>
                ) : null}
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={() => onOpenPolicyCenter?.(connector)}
                >
                  Open policy
                </button>
              </div>
              {controller.connections.genericConnectorMessage ? (
                <p className="capabilities-inline-note">
                  {controller.connections.genericConnectorMessage}
                </p>
              ) : null}
            </section>
          )
        ) : null}
      </DetailDocument>
    </div>
  );
}
