import type {
  AuthorityCenterCapabilityRow,
  AuthorityCenterGrantRow,
  AuthorityCenterProjection,
  AuthorityCenterRepairAction,
} from "./authorityCenter";

export interface AuthorityCenterReceiptPreview {
  id: string;
  kind: string;
  summary: string;
  createdAt: string;
  redaction: string;
  evidenceRefs: string[];
}

export function AuthorityCenterPanel({
  projection,
  loading,
  error,
  actionStatus,
  busyAction,
  selectedReceipt,
  onRefresh,
  onRequestGrant,
  onCapabilityRepairAction,
  onRevokeGrant,
  onOpenReceipt,
}: {
  projection: AuthorityCenterProjection;
  loading: boolean;
  error: string | null;
  actionStatus: string | null;
  busyAction: string | null;
  selectedReceipt: AuthorityCenterReceiptPreview | null;
  onRefresh: () => void;
  onRequestGrant: (capability: AuthorityCenterCapabilityRow) => void;
  onCapabilityRepairAction: (
    capability: AuthorityCenterCapabilityRow,
    action: AuthorityCenterRepairAction,
  ) => void;
  onRevokeGrant: (grant: AuthorityCenterGrantRow) => void;
  onOpenReceipt: (receiptId: string) => void;
}) {
  const topCapabilities = projection.capabilities.slice(0, 5);
  const topGrants = projection.grants.slice(0, 3);
  const topVaultRefs = projection.vaultRefs.slice(0, 3);
  const statusTone =
    projection.status === "ready"
      ? "ready"
      : projection.status === "blocked"
        ? "blocked"
        : projection.status === "degraded"
          ? "warning"
          : "idle";

  return (
    <article
      className="shield-policy-card shield-authority-center"
      aria-labelledby="shield-authority-center-title"
    >
      <div className="shield-policy-card-head">
        <div>
          <span className="shield-kicker">Authority Center</span>
          <strong id="shield-authority-center-title">
            {projection.headline}
          </strong>
        </div>
        <div className="shield-detail-actions">
          <span className={`shield-status status-${statusTone}`}>
            {loading ? "refreshing" : projection.status}
          </span>
          <button
            type="button"
            className="shield-button shield-button-secondary"
            onClick={onRefresh}
            disabled={loading}
          >
            Refresh authority
          </button>
        </div>
      </div>
      <p className="shield-authority-copy">{error ?? projection.detail}</p>
      {actionStatus ? (
        <div className="shield-authority-action-status" role="status">
          {actionStatus}
        </div>
      ) : null}

      <div
        className="shield-summary-row"
        role="list"
        aria-label="Authority readiness summary"
      >
        <article className="shield-summary-chip" role="listitem">
          <span>Ready capabilities</span>
          <strong>{projection.summary.readyCapabilities}</strong>
        </article>
        <article className="shield-summary-chip" role="listitem">
          <span>Blocked</span>
          <strong>{projection.summary.blockedCapabilities}</strong>
        </article>
        <article className="shield-summary-chip" role="listitem">
          <span>Active grants</span>
          <strong>{projection.summary.activeGrants}</strong>
        </article>
        <article className="shield-summary-chip" role="listitem">
          <span>Vault refs</span>
          <strong>{projection.summary.vaultRefs}</strong>
        </article>
        <article className="shield-summary-chip" role="listitem">
          <span>Policy overrides</span>
          <strong>{projection.summary.policyOverrides}</strong>
        </article>
      </div>

      {projection.blockers.length > 0 ? (
        <div className="shield-authority-blockers" role="status">
          {projection.blockers.map((blocker) => (
            <span key={blocker}>{blocker}</span>
          ))}
        </div>
      ) : null}

      <div className="shield-authority-lanes">
        <section aria-labelledby="shield-authority-capabilities-title">
          <h3 id="shield-authority-capabilities-title">Capability readiness</h3>
          <div className="shield-authority-list">
            {topCapabilities.length === 0 ? (
              <p className="shield-inline-empty">
                No model, tool, or connector capabilities are projected yet.
              </p>
            ) : (
              topCapabilities.map((capability) => (
                <div
                  key={`${capability.kind}-${capability.id}`}
                  className="shield-authority-row"
                >
                  <div>
                    <strong>{capability.label}</strong>
                    <span>
                      {capability.kind} / {capability.detail}
                    </span>
                    <small>
                      {capability.requiredScopes.slice(0, 2).join(", ") ||
                        "no authority scopes projected"}
                    </small>
                  </div>
                  <span className={`shield-status status-${capability.tone}`}>
                    {capability.status}
                  </span>
                  <div className="shield-authority-row-actions">
                    {capability.repairActions.length === 0 ? (
                      <button
                        type="button"
                        className="shield-button shield-button-secondary shield-authority-row-action"
                        onClick={() => onRequestGrant(capability)}
                        disabled={Boolean(busyAction)}
                      >
                        {busyAction === `grant:${capability.id}`
                          ? "Requesting"
                          : "Request grant"}
                      </button>
                    ) : (
                      capability.repairActions.map((action) => (
                        <button
                          key={action.id}
                          type="button"
                          className="shield-button shield-button-secondary shield-authority-row-action"
                          onClick={() =>
                            action.kind === "requestGrant"
                              ? onRequestGrant(capability)
                              : onCapabilityRepairAction(capability, action)
                          }
                          disabled={Boolean(busyAction)}
                          title={action.detail}
                          data-repair-action-kind={action.kind}
                          data-repair-action-target={action.targetRef}
                        >
                          {busyAction === `grant:${capability.id}` &&
                          action.kind === "requestGrant"
                            ? "Requesting"
                            : action.label}
                        </button>
                      ))
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        <section aria-labelledby="shield-authority-grants-title">
          <h3 id="shield-authority-grants-title">Grants</h3>
          <div className="shield-authority-list">
            {topGrants.length === 0 ? (
              <p className="shield-inline-empty">
                No scoped runtime grants are currently projected.
              </p>
            ) : (
              topGrants.map((grant) => (
                <div key={grant.id} className="shield-authority-row">
                  <div>
                    <strong>{grant.grantId}</strong>
                    <span>
                      {grant.allowedCount} allowed / {grant.deniedCount} denied
                      / expires {grant.expiresAt}
                    </span>
                    <small>
                      receipt {grant.receiptRef} / last scope {grant.lastScope}
                    </small>
                  </div>
                  <span className={`shield-status status-${grant.tone}`}>
                    {grant.state}
                  </span>
                  <div className="shield-authority-row-actions">
                    {grant.receiptRefs[0] ? (
                      <button
                        type="button"
                        className="shield-button shield-button-secondary shield-authority-row-action"
                        onClick={() => onOpenReceipt(grant.receiptRefs[0])}
                        disabled={Boolean(busyAction)}
                      >
                        Open receipt
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="shield-button shield-button-secondary shield-authority-row-action"
                      onClick={() => onRevokeGrant(grant)}
                      disabled={Boolean(busyAction) || !grant.canRevoke}
                    >
                      {busyAction === `revoke:${grant.id}`
                        ? "Revoking"
                        : grant.canRevoke
                          ? "Revoke"
                          : "Revoked"}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        <section aria-labelledby="shield-authority-vault-title">
          <h3 id="shield-authority-vault-title">Vault refs</h3>
          <div className="shield-authority-list">
            {topVaultRefs.length === 0 ? (
              <p className="shield-inline-empty">
                No vault ref metadata returned by the runtime.
              </p>
            ) : (
              topVaultRefs.map((vaultRef) => (
                <div key={vaultRef.id} className="shield-authority-row">
                  <div>
                    <strong>{vaultRef.label}</strong>
                    <span>{vaultRef.purpose}</span>
                    <small>last resolved {vaultRef.lastResolved}</small>
                  </div>
                  <span className={`shield-status status-${vaultRef.tone}`}>
                    {vaultRef.state}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      {selectedReceipt ? (
        <section
          className="shield-authority-receipt"
          aria-labelledby="shield-authority-receipt-title"
        >
          <div>
            <span className="shield-kicker">Receipt</span>
            <h3 id="shield-authority-receipt-title">{selectedReceipt.id}</h3>
            <p>{selectedReceipt.summary}</p>
          </div>
          <div className="shield-authority-receipt-facts">
            <span>{selectedReceipt.kind}</span>
            <span>{selectedReceipt.redaction}</span>
            <span>{selectedReceipt.createdAt}</span>
            <span>
              {selectedReceipt.evidenceRefs.length} evidence ref
              {selectedReceipt.evidenceRefs.length === 1 ? "" : "s"}
            </span>
          </div>
        </section>
      ) : null}
    </article>
  );
}
