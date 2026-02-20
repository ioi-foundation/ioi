import { useEffect, useMemo, useState } from "react";
import type { AgentRuntime, ConnectorSummary, ConnectorStatus } from "../../runtime/agent-runtime";
import { Icons } from "../../ui/icons";
import "./ConnectorsView.css";

interface ConnectorsViewProps {
  runtime: AgentRuntime;
}

const FALLBACK_CONNECTORS: ConnectorSummary[] = [
  {
    id: "mail.primary",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Agent-safe mail access via delegated session authority. Planned first wallet_network integration: check inbox and read latest email.",
    status: "needs_auth",
    authMode: "wallet_network_session",
    scopes: ["mail.read.latest", "mail.read.thread"],
    notes:
      "Planned path: open session channel -> approve bounded read lease -> execute inbox/list and latest message read.",
  },
  {
    id: "calendar.primary",
    name: "Calendar",
    provider: "wallet.network",
    category: "productivity",
    description: "Scaffold for delegated calendar read/write operations.",
    status: "disabled",
    authMode: "wallet_network_session",
    scopes: ["calendar.read.events"],
  },
];

function statusLabel(status: ConnectorStatus): string {
  switch (status) {
    case "connected":
      return "Connected";
    case "needs_auth":
      return "Needs auth";
    case "degraded":
      return "Degraded";
    case "disabled":
      return "Disabled";
    default:
      return "Unknown";
  }
}

export function ConnectorsView({ runtime }: ConnectorsViewProps) {
  const [connectors, setConnectors] = useState<ConnectorSummary[]>(FALLBACK_CONNECTORS);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<ConnectorStatus | "all">("all");

  useEffect(() => {
    let cancelled = false;
    if (!runtime.getConnectors) return;

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled && Array.isArray(items) && items.length > 0) {
          setConnectors(items);
        }
      })
      .catch(() => {
        // Keep fallback scaffold when runtime connector api is not active yet.
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  const filtered = useMemo(() => {
    return connectors.filter((connector) => {
      if (statusFilter !== "all" && connector.status !== statusFilter) {
        return false;
      }
      if (!query.trim()) return true;
      const q = query.trim().toLowerCase();
      const haystack = [
        connector.name,
        connector.provider,
        connector.description,
        connector.scopes.join(" "),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [connectors, query, statusFilter]);

  return (
    <div className="connectors-view">
      <header className="connectors-header">
        <div className="connectors-title-wrap">
          <h1>Integrations</h1>
          <p>
            Connector-first surface for external apps. Secrets stay in Vault; agents receive bounded
            execution rights.
          </p>
        </div>
        <div className="connectors-filters">
          <input
            className="connectors-search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search connectors..."
            aria-label="Search connectors"
          />
          <div className="connectors-status-row">
            {(["all", "connected", "needs_auth", "degraded", "disabled"] as const).map((value) => (
              <button
                key={value}
                type="button"
                className={`status-chip ${statusFilter === value ? "active" : ""}`}
                onClick={() => setStatusFilter(value)}
              >
                {value === "all" ? "All" : statusLabel(value)}
              </button>
            ))}
          </div>
        </div>
      </header>

      <section className="connectors-grid">
        {filtered.map((connector) => (
          <article key={connector.id} className="connector-card">
            <div className="connector-card-head">
              <div className="connector-name-wrap">
                <span className="connector-icon">
                  {connector.name.toLowerCase().includes("mail") ? (
                    <Icons.Mail width="16" height="16" />
                  ) : (
                    <Icons.Plug width="16" height="16" />
                  )}
                </span>
                <div>
                  <h2>{connector.name}</h2>
                  <p>{connector.provider}</p>
                </div>
              </div>
              <span className={`connector-status status-${connector.status}`}>
                {statusLabel(connector.status)}
              </span>
            </div>

            <p className="connector-description">{connector.description}</p>

            <div className="connector-meta">
              <span>Auth: {connector.authMode}</span>
              {connector.lastSyncAtUtc ? <span>Last sync: {connector.lastSyncAtUtc}</span> : null}
            </div>

            <div className="connector-scopes">
              {connector.scopes.map((scope) => (
                <code key={scope}>{scope}</code>
              ))}
            </div>

            {connector.notes ? <p className="connector-notes">{connector.notes}</p> : null}

            <div className="connector-actions">
              <button type="button" className="btn-secondary">
                Configure
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={connector.status === "disabled"}
              >
                {connector.status === "connected" ? "Manage Session" : "Connect"}
              </button>
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}
