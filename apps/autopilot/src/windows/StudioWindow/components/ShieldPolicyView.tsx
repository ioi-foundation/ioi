import { useEffect, useMemo, useState } from "react";
import type { AgentRuntime, ConnectorSummary } from "@ioi/agent-ide";
import type {
  AutomationPolicyMode,
  ConnectorPolicyOverride,
  DataHandlingMode,
  GlobalPolicyDefaults,
  PolicyDecisionMode,
  ShieldPolicyState,
} from "../policyCenter";
import {
  buildConnectorPolicySummary,
  countActiveOverrides,
  resetConnectorOverride,
  resolveConnectorPolicy,
  updateConnectorOverride,
} from "../policyCenter";

interface ShieldPolicyViewProps {
  runtime: AgentRuntime;
  policyState: ShieldPolicyState;
  onChange: (next: ShieldPolicyState) => void;
  focusedConnectorId?: string | null;
  onFocusConnector?: (connectorId: string | null) => void;
  onOpenIntegrations?: () => void;
}

const FALLBACK_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    pluginId: "wallet_mail",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description: "Delegated inbox reads and safe outbound mail actions.",
    status: "needs_auth",
    authMode: "wallet_capability",
    scopes: ["mail.read.latest", "mail.list.recent", "mail.reply"],
  },
  {
    id: "google.workspace",
    pluginId: "google_workspace",
    name: "Google",
    provider: "google",
    category: "productivity",
    description: "Gmail, Calendar, Docs, Sheets, BigQuery, and durable Google automations.",
    status: "connected",
    authMode: "wallet_capability",
    scopes: ["gmail", "calendar", "docs", "sheets", "bigquery", "automations"],
  },
];

const DECISION_OPTIONS: Array<{ value: PolicyDecisionMode; label: string }> = [
  { value: "auto", label: "Auto-run" },
  { value: "confirm", label: "Confirm" },
  { value: "block", label: "Block" },
];

const AUTOMATION_OPTIONS: Array<{ value: AutomationPolicyMode; label: string }> = [
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

export function ShieldPolicyView({
  runtime,
  policyState,
  onChange,
  focusedConnectorId,
  onFocusConnector,
  onOpenIntegrations,
}: ShieldPolicyViewProps) {
  const [connectors, setConnectors] = useState<ConnectorSummary[]>(FALLBACK_CONNECTORS);
  const [selectedTarget, setSelectedTarget] = useState<string>("global");

  useEffect(() => {
    let cancelled = false;
    if (!runtime.getConnectors) return () => {};

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled && Array.isArray(items) && items.length > 0) {
          setConnectors(items);
        }
      })
      .catch(() => {
        // Keep fallback connector list when runtime state is unavailable.
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  useEffect(() => {
    if (focusedConnectorId) {
      setSelectedTarget(focusedConnectorId);
      return;
    }
    setSelectedTarget((current) => current || "global");
  }, [focusedConnectorId]);

  const selectedConnector = useMemo(
    () => connectors.find((connector) => connector.id === selectedTarget) ?? null,
    [connectors, selectedTarget],
  );

  const selectedPolicy = useMemo(() => {
    if (!selectedConnector) {
      return {
        effective: policyState.global,
        override: null,
        summary: {
          headline: "Global runtime defaults",
          detail: `Reads ${decisionSummary(policyState.global.reads)} · Writes ${decisionSummary(
            policyState.global.writes,
          )} · Automations ${automationSummary(policyState.global.automations)}`,
        },
      };
    }

    const resolved = resolveConnectorPolicy(policyState, selectedConnector.id);
    return {
      ...resolved,
      summary: buildConnectorPolicySummary(policyState, selectedConnector.id),
    };
  }, [policyState, selectedConnector]);

  const openTarget = (target: string) => {
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
    onChange(updateConnectorOverride(policyState, selectedConnector.id, { [key]: value }));
  };

  const activeOverrides = countActiveOverrides(policyState);
  const connectorInheritsGlobal =
    selectedConnector && policyState.overrides[selectedConnector.id]?.inheritGlobal !== false;

  return (
    <div className="shield-policy-view">
      <header className="shield-header">
        <div>
          <span className="shield-kicker">Shield</span>
          <h1>Policy Center</h1>
          <p>
            Global runtime defaults live here. Connectors inherit by default, then opt into explicit
            overrides only when a specific integration needs a tighter or looser posture.
          </p>
        </div>
        <div className="shield-header-actions">
          <button type="button" className="shield-button shield-button-secondary" onClick={() => openTarget("global")}>
            Global defaults
          </button>
          {selectedConnector ? (
            <button
              type="button"
              className="shield-button shield-button-secondary"
              onClick={onOpenIntegrations}
            >
              Open connector
            </button>
          ) : null}
        </div>
      </header>

      <section className="shield-stat-grid">
        <article className="shield-stat-card">
          <span>Reads</span>
          <strong>{decisionSummary(policyState.global.reads)}</strong>
          <p>Default posture for read-only connector actions.</p>
        </article>
        <article className="shield-stat-card">
          <span>Writes</span>
          <strong>{decisionSummary(policyState.global.writes)}</strong>
          <p>Default approval bar for state-changing connector actions.</p>
        </article>
        <article className="shield-stat-card">
          <span>Automations</span>
          <strong>{automationSummary(policyState.global.automations)}</strong>
          <p>How durable subscriptions and triggers enter runtime execution.</p>
        </article>
        <article className="shield-stat-card">
          <span>Overrides</span>
          <strong>{activeOverrides}</strong>
          <p>Connector-specific exceptions to the global baseline.</p>
        </article>
      </section>

      <div className="shield-layout">
        <aside className="shield-sidebar">
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
            <small>Applies everywhere unless a connector override is active.</small>
          </button>

          <div className="shield-sidebar-section">
            <div className="shield-sidebar-head">
              <strong>Connector overrides</strong>
              <span>{connectors.length} connectors</span>
            </div>
            {connectors.map((connector) => {
              const summary = buildConnectorPolicySummary(policyState, connector.id);
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
                    <span className={`shield-status status-${connector.status}`}>
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
            })}
          </div>
        </aside>

        <section className="shield-detail-panel">
          <div className="shield-detail-head">
            <div>
              <span className="shield-kicker">
                {selectedConnector ? "Connector policy" : "Global defaults"}
              </span>
              <h2>{selectedConnector ? `${selectedConnector.name} policy` : "Global policy baseline"}</h2>
              <p>{selectedPolicy.summary.detail}</p>
            </div>
            {selectedConnector ? (
              <div className="shield-detail-actions">
                <label className="shield-toggle">
                  <input
                    type="checkbox"
                    checked={policyState.overrides[selectedConnector.id]?.inheritGlobal !== false}
                    onChange={(event) =>
                      updateOverride("inheritGlobal", event.target.checked)
                    }
                  />
                  <span>Inherit global defaults</span>
                </label>
                <button
                  type="button"
                  className="shield-button shield-button-secondary"
                  onClick={() => onChange(resetConnectorOverride(policyState, selectedConnector.id))}
                >
                  Reset override
                </button>
              </div>
            ) : null}
          </div>

          <div className="shield-callout">
            <strong>{selectedPolicy.summary.headline}</strong>
            <p>
              Precedence is: hard runtime stop, global policy, connector override, graph-level
              tightening, then explicit approval at execution time.
            </p>
          </div>

          <div className="shield-form-grid">
            <PolicySelect
              label="Read actions"
              value={selectedPolicy.effective.reads}
              options={DECISION_OPTIONS}
              disabled={Boolean(connectorInheritsGlobal)}
              onChange={(value) =>
                selectedConnector ? updateOverride("reads", value) : updateGlobal("reads", value)
              }
            />
            <PolicySelect
              label="Write actions"
              value={selectedPolicy.effective.writes}
              options={DECISION_OPTIONS}
              disabled={Boolean(connectorInheritsGlobal)}
              onChange={(value) =>
                selectedConnector ? updateOverride("writes", value) : updateGlobal("writes", value)
              }
            />
            <PolicySelect
              label="Admin actions"
              value={selectedPolicy.effective.admin}
              options={DECISION_OPTIONS}
              disabled={Boolean(connectorInheritsGlobal)}
              onChange={(value) =>
                selectedConnector ? updateOverride("admin", value) : updateGlobal("admin", value)
              }
            />
            <PolicySelect
              label="Expert / raw actions"
              value={selectedPolicy.effective.expert}
              options={DECISION_OPTIONS}
              disabled={Boolean(connectorInheritsGlobal)}
              onChange={(value) =>
                selectedConnector ? updateOverride("expert", value) : updateGlobal("expert", value)
              }
            />
            <PolicySelect
              label="Automations"
              value={selectedPolicy.effective.automations}
              options={AUTOMATION_OPTIONS}
              disabled={Boolean(connectorInheritsGlobal)}
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
              disabled={Boolean(connectorInheritsGlobal)}
              onChange={(value) =>
                selectedConnector
                  ? updateOverride("dataHandling", value)
                  : updateGlobal("dataHandling", value)
              }
            />
          </div>

          <div className="shield-guidance-grid">
            <article className="shield-guidance-card">
              <strong>Use the global baseline for broad posture</strong>
              <p>
                Keep global settings conservative, then override only when a connector has a clear
                operational need to behave differently.
              </p>
            </article>
            <article className="shield-guidance-card">
              <strong>Policy is separate from connector auth</strong>
              <p>
                Wallet-backed connector auth stores durable credentials and consent state, while
                Shield policy defines whether reads, writes, admin actions, and automations should
                run automatically.
              </p>
            </article>
            <article className="shield-guidance-card">
              <strong>Automations deserve their own gate</strong>
              <p>
                Durable background work is different from one-shot actions. Keep creation and first
                execution approvals explicit unless a connector truly needs autonomy.
              </p>
            </article>
          </div>
        </section>
      </div>
    </div>
  );
}
