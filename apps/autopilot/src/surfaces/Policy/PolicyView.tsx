import { useEffect, useMemo, useState } from "react";
import type { AgentWorkbenchRuntime, ConnectorSummary } from "@ioi/agent-ide";
import type {
  AutomationPolicyMode,
  CapabilityGovernanceRequest,
  ConnectorPolicyOverride,
  DataHandlingMode,
  GlobalPolicyDefaults,
  PolicyDecisionMode,
  ShieldPolicyState,
} from "./policyCenter";
import {
  buildPolicyIntentDeltaDeck,
  buildPolicyDeltaDeck,
  buildPolicySimulationDeck,
  buildConnectorPolicySummary,
  countActiveOverrides,
  dataHandlingLabel,
  resetConnectorOverride,
  resolveConnectorPolicy,
  updateConnectorOverride,
} from "./policyCenter";
import { buildConnectorTrustProfile } from "../Capabilities/components/model";

interface PolicyViewProps {
  runtime: AgentWorkbenchRuntime;
  policyState: ShieldPolicyState;
  onChange: (next: ShieldPolicyState) => void;
  governanceRequest?: CapabilityGovernanceRequest | null;
  focusedConnectorId?: string | null;
  onFocusConnector?: (connectorId: string | null) => void;
  onApplyGovernanceRequest?: (next: ShieldPolicyState) => void;
  onDismissGovernanceRequest?: () => void;
  onOpenIntegrations?: () => void;
}

const DECISION_OPTIONS: Array<{ value: PolicyDecisionMode; label: string }> = [
  { value: "auto", label: "Auto-run" },
  { value: "confirm", label: "Confirm" },
  { value: "block", label: "Block" },
];

const AUTOMATION_OPTIONS: Array<{
  value: AutomationPolicyMode;
  label: string;
}> = [
  { value: "confirm_on_create", label: "Confirm on create" },
  { value: "confirm_on_run", label: "Confirm on first run" },
  { value: "manual_only", label: "Manual only" },
];

const DATA_OPTIONS: Array<{ value: DataHandlingMode; label: string }> = [
  { value: "local_only", label: "Local only" },
  { value: "local_redacted", label: "Local with redacted artifacts" },
];

function connectorStatusLabel(status: ConnectorSummary["status"]): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "degraded":
      return "Degraded";
    case "disabled":
      return "Disabled";
    default:
      return "Needs auth";
  }
}

function decisionSummary(value: PolicyDecisionMode): string {
  switch (value) {
    case "auto":
      return "Auto";
    case "confirm":
      return "Confirm";
    case "block":
      return "Block";
    default:
      return value;
  }
}

function automationSummary(value: AutomationPolicyMode): string {
  switch (value) {
    case "confirm_on_create":
      return "Confirm create";
    case "confirm_on_run":
      return "Confirm run";
    case "manual_only":
      return "Manual only";
    default:
      return value;
  }
}

function simulationOutcomeLabel(value: "auto" | "gate" | "deny"): string {
  switch (value) {
    case "auto":
      return "Auto-approved";
    case "gate":
      return "Approval gate";
    case "deny":
      return "Denied";
    default:
      return value;
  }
}

function simulationSummaryLabel(value: "auto" | "gate" | "deny"): string {
  switch (value) {
    case "auto":
      return "Auto";
    case "gate":
      return "Gates";
    case "deny":
      return "Denied";
    default:
      return value;
  }
}

function deltaLabel(value: "wider" | "tighter"): string {
  return value === "wider" ? "Wider authority" : "Tighter authority";
}

function PolicySelect<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled = false,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (next: T) => void;
  disabled?: boolean;
}) {
  return (
    <label className="shield-field">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
        disabled={disabled}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

export function PolicyView({
  runtime,
  policyState,
  onChange,
  governanceRequest,
  focusedConnectorId,
  onFocusConnector,
  onApplyGovernanceRequest,
  onDismissGovernanceRequest,
  onOpenIntegrations,
}: PolicyViewProps) {
  const [connectors, setConnectors] = useState<ConnectorSummary[]>([]);
  const [connectorsLoading, setConnectorsLoading] = useState(true);
  const [connectorsError, setConnectorsError] = useState<string | null>(null);
  const [connectorsUnavailable, setConnectorsUnavailable] = useState(false);
  const [selectedTarget, setSelectedTarget] = useState<string>("global");
  const effectivePolicyState = governanceRequest?.requestedState ?? policyState;

  useEffect(() => {
    let cancelled = false;
    if (!runtime.getConnectors) {
      setConnectors([]);
      setConnectorsLoading(false);
      setConnectorsError(null);
      setConnectorsUnavailable(true);
      return () => {
        cancelled = true;
      };
    }

    setConnectorsLoading(true);
    setConnectorsError(null);
    setConnectorsUnavailable(false);

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled) {
          setConnectors(Array.isArray(items) ? items : []);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setConnectors([]);
          setConnectorsError(String(error));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setConnectorsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  useEffect(() => {
    const requestConnectorId = governanceRequest?.connectorId ?? null;

    if (focusedConnectorId) {
      setSelectedTarget(focusedConnectorId);
      return;
    }
    if (requestConnectorId) {
      setSelectedTarget(requestConnectorId);
      return;
    }
    setSelectedTarget((current) => current || "global");
  }, [focusedConnectorId, governanceRequest]);

  const selectedConnector = useMemo(
    () =>
      connectors.find((connector) => connector.id === selectedTarget) ?? null,
    [connectors, selectedTarget],
  );
  const selectedConnectorMissing =
    selectedTarget !== "global" && selectedConnector === null;

  const selectedPolicy = useMemo(() => {
    if (!selectedConnector) {
      return {
        effective: effectivePolicyState.global,
        override: null,
        summary: {
          headline: "Global runtime defaults",
          detail: `Reads ${decisionSummary(effectivePolicyState.global.reads)} · Writes ${decisionSummary(
            effectivePolicyState.global.writes,
          )} · Automations ${automationSummary(effectivePolicyState.global.automations)}`,
        },
      };
    }

    const resolved = resolveConnectorPolicy(effectivePolicyState, selectedConnector.id);
    return {
      ...resolved,
      summary: buildConnectorPolicySummary(effectivePolicyState, selectedConnector.id),
    };
  }, [effectivePolicyState, selectedConnector]);
  const trustProfile = useMemo(
    () =>
      selectedConnector
        ? buildConnectorTrustProfile(selectedConnector, effectivePolicyState)
        : null,
    [effectivePolicyState, selectedConnector],
  );

  const openTarget = (target: string) => {
    if (governanceRequest && target !== selectedTarget) {
      onDismissGovernanceRequest?.();
    }
    setSelectedTarget(target);
    onFocusConnector?.(target === "global" ? null : target);
  };

  const updateGlobal = <K extends keyof GlobalPolicyDefaults>(
    key: K,
    value: GlobalPolicyDefaults[K],
  ) => {
    onChange({
      ...policyState,
      global: {
        ...policyState.global,
        [key]: value,
      },
    });
  };

  const updateOverride = <K extends keyof ConnectorPolicyOverride>(
    key: K,
    value: ConnectorPolicyOverride[K],
  ) => {
    if (!selectedConnector) return;
    onChange(
      updateConnectorOverride(policyState, selectedConnector.id, {
        [key]: value,
      }),
    );
  };

  const activeOverrides = countActiveOverrides(effectivePolicyState);
  const connectorInheritsGlobal =
    selectedConnector &&
    effectivePolicyState.overrides[selectedConnector.id]?.inheritGlobal !== false;
  const simulation = useMemo(
    () =>
      buildPolicySimulationDeck(
        effectivePolicyState,
        selectedConnectorMissing ? null : selectedConnector?.id ?? null,
      ),
    [effectivePolicyState, selectedConnector, selectedConnectorMissing],
  );
  const deltaDeck = useMemo(
    () => {
      if (!governanceRequest) {
        return buildPolicyDeltaDeck(
          policyState,
          selectedConnectorMissing ? null : selectedConnector?.id ?? null,
        );
      }
      return buildPolicyIntentDeltaDeck(
        policyState,
        governanceRequest.requestedState,
        selectedConnectorMissing ? null : selectedConnector?.id ?? null,
        {
          baselineLabel: "Current effective posture",
          nextLabel:
            governanceRequest.action === "widen"
              ? "Requested wider posture"
              : "Requested baseline posture",
        },
      );
    },
    [governanceRequest, policyState, selectedConnector, selectedConnectorMissing],
  );
  const scopeLabel = selectedConnector
    ? "Connector override"
    : "Global baseline";
  const inheritanceLabel = selectedConnector
    ? connectorInheritsGlobal
      ? "Inherited"
      : "Custom"
    : "Source of truth";
  const preflightHasChanges = useMemo(
    () =>
      governanceRequest
        ? JSON.stringify(governanceRequest.requestedState) !==
          JSON.stringify(policyState)
        : false,
    [governanceRequest, policyState],
  );
  const policyMatrixLocked = Boolean(governanceRequest);

  return (
    <div className="shield-policy-view">
      <div className="shield-layout">
        <aside className="shield-sidebar">
          <div className="shield-sidebar-section">
            <div className="shield-sidebar-head">
              <strong>Policy objects</strong>
              <span>Governance</span>
            </div>
            <button
              type="button"
              className={`shield-target-card ${selectedTarget === "global" ? "active" : ""}`}
              onClick={() => openTarget("global")}
            >
              <strong>Global runtime policy</strong>
              <span>
                Reads {decisionSummary(policyState.global.reads)} · Writes{" "}
                {decisionSummary(policyState.global.writes)}
              </span>
              <small>
                Applies everywhere unless a connection override is active.
              </small>
            </button>
          </div>

          <div className="shield-sidebar-section">
            <div className="shield-sidebar-head">
              <strong>Connection overrides</strong>
              <span>{connectors.length} connections</span>
            </div>
            {connectorsLoading ? (
              <div className="shield-target-card">
                <strong>Loading live connectors</strong>
                <small>Fetching connector policy objects from the runtime.</small>
              </div>
            ) : connectorsError ? (
              <div className="shield-target-card">
                <strong>Live connector catalog unavailable</strong>
                <small>{connectorsError}</small>
              </div>
            ) : connectorsUnavailable ? (
              <div className="shield-target-card">
                <strong>Connector catalog not exposed</strong>
                <small>This runtime does not expose live connector policy objects yet.</small>
              </div>
            ) : connectors.length === 0 ? (
              <div className="shield-target-card">
                <strong>No live connectors</strong>
                <small>No connector-specific policy overrides are available yet.</small>
              </div>
            ) : (
              connectors.map((connector) => {
                const summary = buildConnectorPolicySummary(
                  policyState,
                  connector.id,
                );
                const override = policyState.overrides[connector.id];
                return (
                  <button
                    key={connector.id}
                    type="button"
                    className={`shield-target-card ${selectedTarget === connector.id ? "active" : ""}`}
                    onClick={() => openTarget(connector.id)}
                  >
                    <div className="shield-target-head">
                      <strong>{connector.name}</strong>
                      <span
                        className={`shield-status status-${connector.status}`}
                      >
                        {connectorStatusLabel(connector.status)}
                      </span>
                    </div>
                    <span>{summary.headline}</span>
                    <small>{summary.detail}</small>
                    {override && !override.inheritGlobal ? (
                      <em>Custom override</em>
                    ) : (
                      <em>Inheriting global</em>
                    )}
                  </button>
                );
              })
            )}
          </div>
        </aside>

        <section className="shield-detail-panel">
          <div className="shield-detail-head">
            <div>
              <span className="shield-kicker">
                {selectedConnectorMissing
                  ? "Connection unavailable"
                  : selectedConnector
                    ? "Connection policy"
                    : "Global defaults"}
              </span>
              <h2>
                {selectedConnectorMissing
                  ? "Live connector override unavailable"
                  : selectedConnector
                  ? `${selectedConnector.name} policy`
                  : "Global policy baseline"}
              </h2>
              <p>
                {selectedConnectorMissing
                  ? connectorsError
                    ? `Live connector catalog unavailable: ${connectorsError}`
                    : connectorsUnavailable
                      ? "This runtime does not expose live connector policy objects yet."
                      : "The requested connector is not currently exposed by the runtime, so policy editing is showing the global baseline."
                    : selectedPolicy.summary.detail}
              </p>
            </div>
            <div className="shield-detail-actions">
              {selectedConnector && !governanceRequest ? (
                <label className="shield-toggle">
                  <input
                    type="checkbox"
                    checked={
                      policyState.overrides[selectedConnector.id]
                        ?.inheritGlobal !== false
                    }
                    onChange={(event) =>
                      updateOverride("inheritGlobal", event.target.checked)
                    }
                  />
                  <span>Inherit global defaults</span>
                </label>
              ) : null}
              {selectedConnector && !governanceRequest ? (
                <button
                  type="button"
                  className="shield-button shield-button-secondary"
                  onClick={() =>
                    onChange(
                      resetConnectorOverride(policyState, selectedConnector.id),
                    )
                  }
                >
                  Reset override
                </button>
              ) : null}
              {selectedConnector ? (
                <button
                  type="button"
                  className="shield-button shield-button-secondary"
                  onClick={onOpenIntegrations}
                >
                  Open capabilities
                </button>
              ) : null}
            </div>
          </div>

          {governanceRequest ? (
            <article className="shield-policy-card shield-request-card">
              <div className="shield-policy-card-head">
                <strong>{governanceRequest.headline}</strong>
                <span>
                  {governanceRequest.action === "widen"
                    ? "Lease widening request"
                    : "Return-to-baseline request"}
                </span>
              </div>
              <p>{governanceRequest.detail}</p>
              <div className="shield-request-meta">
                <span>
                  Policy target <strong>{governanceRequest.connectorLabel}</strong>
                </span>
                <span>
                  Capability <strong>{governanceRequest.capabilityLabel}</strong>
                </span>
                {governanceRequest.governingLabel &&
                governanceRequest.governingEntryId &&
                governanceRequest.governingEntryId !==
                  governanceRequest.capabilityEntryId ? (
                  <span>
                    Governing target{" "}
                    <strong>{governanceRequest.governingLabel}</strong>
                  </span>
                ) : null}
                <span>
                  Authority <strong>{governanceRequest.authorityTierLabel}</strong>
                </span>
                <span>
                  Lease <strong>{governanceRequest.leaseModeLabel ?? "Availability bound"}</strong>
                </span>
                <span>
                  Source <strong>{governanceRequest.sourceLabel}</strong>
                </span>
              </div>
              <small>{governanceRequest.whySelectable}</small>
              <div className="shield-request-actions">
                <button
                  type="button"
                  className="shield-button"
                  disabled={!preflightHasChanges}
                  onClick={() =>
                    governanceRequest &&
                    onApplyGovernanceRequest?.(governanceRequest.requestedState)
                  }
                >
                  {preflightHasChanges ? "Apply request" : "Already at requested posture"}
                </button>
                <button
                  type="button"
                  className="shield-button shield-button-secondary"
                  onClick={onDismissGovernanceRequest}
                >
                  Dismiss request
                </button>
              </div>
            </article>
          ) : null}

          <div
            className="shield-summary-row"
            role="list"
            aria-label="Policy summary"
          >
            <article className="shield-summary-chip" role="listitem">
              <span>Scope</span>
              <strong>{scopeLabel}</strong>
            </article>
            {trustProfile ? (
              <article className="shield-summary-chip" role="listitem">
                <span>Authority tier</span>
                <strong>{trustProfile.tierLabel}</strong>
              </article>
            ) : null}
            <article className="shield-summary-chip" role="listitem">
              <span>Inheritance</span>
              <strong>{inheritanceLabel}</strong>
            </article>
            <article className="shield-summary-chip" role="listitem">
              <span>Reads</span>
              <strong>{decisionSummary(selectedPolicy.effective.reads)}</strong>
            </article>
            <article className="shield-summary-chip" role="listitem">
              <span>Writes</span>
              <strong>
                {decisionSummary(selectedPolicy.effective.writes)}
              </strong>
            </article>
            <article className="shield-summary-chip" role="listitem">
              <span>Automations</span>
              <strong>
                {automationSummary(selectedPolicy.effective.automations)}
              </strong>
            </article>
            <article className="shield-summary-chip" role="listitem">
              <span>Overrides</span>
              <strong>{activeOverrides}</strong>
            </article>
          </div>

          <div className="shield-callout">
            <strong>{selectedPolicy.summary.headline}</strong>
            <p>
              Precedence resolves in this order: hard runtime stop, global
              baseline, connector override, graph tightening, then explicit
              approval at execution time.
            </p>
          </div>

          {trustProfile ? (
            <article className="shield-policy-card shield-trust-card">
              <div className="shield-policy-card-head">
                <strong>Authority tier</strong>
                <span>{trustProfile.governedProfileLabel}</span>
              </div>
              <div className="shield-trust-summary">
                <strong>{trustProfile.tierLabel}</strong>
                <p>{trustProfile.summary}</p>
                <small>{trustProfile.detail}</small>
              </div>
              <div className="shield-trust-signals">
                {trustProfile.signals.map((signal) => (
                  <span key={signal} className="shield-trust-signal">
                    {signal}
                  </span>
                ))}
              </div>
            </article>
          ) : null}

          <article className="shield-policy-card">
              <div className="shield-policy-card-head">
                <strong>Policy matrix</strong>
                <span>
                  {policyMatrixLocked
                    ? "Previewing the requested posture before it is persisted"
                    : selectedConnector && connectorInheritsGlobal
                      ? "Inherited from the global baseline"
                    : "Editing the selected governance object"}
                </span>
              </div>
              <div className="shield-form-grid">
                <PolicySelect
                  label="Read actions"
                  value={selectedPolicy.effective.reads}
                  options={DECISION_OPTIONS}
                  disabled={policyMatrixLocked || Boolean(connectorInheritsGlobal)}
                  onChange={(value) =>
                    selectedConnector
                      ? updateOverride("reads", value)
                    : updateGlobal("reads", value)
                }
              />
              <PolicySelect
                  label="Write actions"
                  value={selectedPolicy.effective.writes}
                  options={DECISION_OPTIONS}
                  disabled={policyMatrixLocked || Boolean(connectorInheritsGlobal)}
                  onChange={(value) =>
                    selectedConnector
                      ? updateOverride("writes", value)
                    : updateGlobal("writes", value)
                }
              />
              <PolicySelect
                  label="Admin actions"
                  value={selectedPolicy.effective.admin}
                  options={DECISION_OPTIONS}
                  disabled={policyMatrixLocked || Boolean(connectorInheritsGlobal)}
                  onChange={(value) =>
                    selectedConnector
                      ? updateOverride("admin", value)
                    : updateGlobal("admin", value)
                }
              />
              <PolicySelect
                  label="Expert / raw actions"
                  value={selectedPolicy.effective.expert}
                  options={DECISION_OPTIONS}
                  disabled={policyMatrixLocked || Boolean(connectorInheritsGlobal)}
                  onChange={(value) =>
                    selectedConnector
                      ? updateOverride("expert", value)
                    : updateGlobal("expert", value)
                }
              />
              <PolicySelect
                  label="Automations"
                  value={selectedPolicy.effective.automations}
                  options={AUTOMATION_OPTIONS}
                  disabled={policyMatrixLocked || Boolean(connectorInheritsGlobal)}
                  onChange={(value) =>
                    selectedConnector
                      ? updateOverride("automations", value)
                    : updateGlobal("automations", value)
                }
              />
              <PolicySelect
                  label="Artifact handling"
                  value={selectedPolicy.effective.dataHandling}
                  options={DATA_OPTIONS}
                  disabled={policyMatrixLocked || Boolean(connectorInheritsGlobal)}
                  onChange={(value) =>
                    selectedConnector
                      ? updateOverride("dataHandling", value)
                    : updateGlobal("dataHandling", value)
                }
              />
            </div>
          </article>

          <div className="shield-inspector-grid">
            <article className="shield-policy-card">
              <div className="shield-policy-card-head">
                <strong>Preflight simulation</strong>
                <span>
                  {governanceRequest
                    ? "Truthful preview from the requested governance object"
                    : "Truthful preview from the current runtime policy object"}
                </span>
              </div>

              <div className="shield-preflight-summary">
                {(["auto", "gate", "deny"] as const).map((outcome) => (
                  <article
                    key={outcome}
                    className="shield-summary-chip"
                    role="listitem"
                  >
                    <span>{simulationSummaryLabel(outcome)}</span>
                    <strong>{simulation.summary[outcome]}</strong>
                  </article>
                ))}
                <article className="shield-summary-chip" role="listitem">
                  <span>Artifacts</span>
                  <strong>
                    {dataHandlingLabel(simulation.artifactHandling.mode)}
                  </strong>
                </article>
              </div>

              <div className="shield-preflight-list">
                {simulation.scenarios.map((scenario) => (
                  <article
                    key={scenario.id}
                    className={`shield-preflight-card outcome-${scenario.outcome}`}
                  >
                    <div className="shield-preflight-card-head">
                      <strong>{scenario.label}</strong>
                      <span className={`shield-outcome-badge outcome-${scenario.outcome}`}>
                        {simulationOutcomeLabel(scenario.outcome)}
                      </span>
                    </div>
                    <p>{scenario.detail}</p>
                    <small>{scenario.rationale}</small>
                  </article>
                ))}
                <article className="shield-preflight-card outcome-artifact">
                  <div className="shield-preflight-card-head">
                    <strong>Artifact handling</strong>
                    <span className="shield-outcome-badge outcome-artifact">
                      {simulation.artifactHandling.label}
                    </span>
                  </div>
                  <p>{simulation.artifactHandling.detail}</p>
                  <small>
                    This posture is part of the persisted policy object, even
                    though it is not an approval gate by itself.
                  </small>
                </article>
              </div>
            </article>

            <article className="shield-policy-card">
              <div className="shield-policy-card-head">
                <strong>Policy delta</strong>
                <span>
                  {deltaDeck.baselineLabel} to {deltaDeck.nextLabel}
                </span>
              </div>

              {deltaDeck.items.length === 0 ? (
                <div className="shield-inline-empty">
                  <strong>No delta from the baseline.</strong>
                  <p>
                    This scope is currently aligned with{" "}
                    {deltaDeck.baselineLabel.toLowerCase()}.
                  </p>
                </div>
              ) : (
                <div className="shield-delta-list">
                  {deltaDeck.items.map((item) => (
                    <article
                      key={item.id}
                      className={`shield-delta-card delta-${item.change}`}
                    >
                      <div className="shield-preflight-card-head">
                        <strong>{item.label}</strong>
                        <span className={`shield-delta-badge delta-${item.change}`}>
                          {deltaLabel(item.change)}
                        </span>
                      </div>
                      <p>
                        {item.baseline} to {item.next}
                      </p>
                      <small>{item.detail}</small>
                    </article>
                  ))}
                </div>
              )}
            </article>
          </div>

          <details className="shield-help-panel">
            <summary>Policy notes</summary>
            <div className="shield-help-content">
              <article className="shield-guidance-card">
                <strong>Use the global baseline for broad posture</strong>
                <p>
                  Keep global settings conservative, then override only when a
                  connection has a clear operational need to behave differently.
                </p>
              </article>
              <article className="shield-guidance-card">
                <strong>Policy is separate from connection auth</strong>
                <p>
                  Wallet-backed connection auth stores durable credentials and
                  consent state, while policy defines whether reads, writes,
                  admin actions, and automations should run automatically.
                </p>
              </article>
              <article className="shield-guidance-card">
                <strong>Automations deserve their own gate</strong>
                <p>
                  Durable background work is different from one-shot actions.
                  Keep creation and first execution approvals explicit unless a
                  connection truly needs autonomy.
                </p>
              </article>
            </div>
          </details>
        </section>
      </div>
    </div>
  );
}

export const ShieldPolicyView = PolicyView;
