import type { ConnectorStatus } from "../../../runtime/agent-runtime";

interface ConnectorsHeaderProps {
  query: string;
  onQueryChange: (value: string) => void;
  statusFilter: ConnectorStatus | "all";
  onStatusFilterChange: (value: ConnectorStatus | "all") => void;
  statusLabel: (status: ConnectorStatus) => string;
}

export function ConnectorsHeader({
  query,
  onQueryChange,
  statusFilter,
  onStatusFilterChange,
  statusLabel,
}: ConnectorsHeaderProps) {
  return (
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
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder="Search connectors..."
          aria-label="Search connectors"
        />
        <div className="connectors-status-row">
          {(["all", "connected", "needs_auth", "degraded", "disabled"] as const).map(
            (value) => (
              <button
                key={value}
                type="button"
                className={`status-chip ${statusFilter === value ? "active" : ""}`}
                onClick={() => onStatusFilterChange(value)}
              >
                {value === "all" ? "All" : statusLabel(value)}
              </button>
            )
          )}
        </div>
      </div>
    </header>
  );
}
