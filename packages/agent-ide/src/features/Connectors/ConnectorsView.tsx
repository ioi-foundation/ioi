import { useEffect, useMemo, useState } from "react";
import type {
  AgentRuntime,
  ConnectorSummary,
  ConnectorStatus,
} from "../../runtime/agent-runtime";
import { Icons } from "../../ui/icons";
import { ConnectorsHeader } from "./components/ConnectorsHeader";
import { MailConnectorPanel } from "./components/MailConnectorPanel";
import { useMailConnectorActions } from "./hooks/useMailConnectorActions";
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
    scopes: ["mail.read.latest", "mail.list.recent", "mail.delete.spam", "mail.reply"],
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

  const mail = useMailConnectorActions(runtime);

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
        // Keep fallback scaffold when runtime connector API is not active yet.
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
      <ConnectorsHeader
        query={query}
        onQueryChange={setQuery}
        statusFilter={statusFilter}
        onStatusFilterChange={setStatusFilter}
        statusLabel={statusLabel}
      />

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

            {connector.id === "mail.primary" ? <MailConnectorPanel mail={mail} /> : null}

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
