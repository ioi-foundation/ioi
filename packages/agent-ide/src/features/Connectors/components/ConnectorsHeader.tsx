import type { ConnectorStatus } from "../../../runtime/agent-runtime";

interface ConnectorsHeaderProps {
  title?: string;
  description?: string;
  query: string;
  onQueryChange: (value: string) => void;
  statusFilter: ConnectorStatus | "all";
  onStatusFilterChange: (value: ConnectorStatus | "all") => void;
  statusLabel: (status: ConnectorStatus) => string;
  searchPlaceholder?: string;
  searchLabel?: string;
}

export function ConnectorsHeader({
  title = "Connections",
  description = "Authenticated systems workers can reach. Secrets stay in Vault; workers receive bounded execution rights.",
  query,
  onQueryChange,
  statusFilter,
  onStatusFilterChange,
  statusLabel,
  searchPlaceholder = "Search connections...",
  searchLabel = "Search connections",
}: ConnectorsHeaderProps) {
  return (
    <header className="connectors-header">
      <div className="connectors-title-wrap">
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="connectors-filters">
        <input
          className="connectors-search"
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          placeholder={searchPlaceholder}
          aria-label={searchLabel}
        />
        <div className="connectors-status-row">
          {(
            ["all", "connected", "needs_auth", "degraded", "disabled"] as const
          ).map((value) => (
            <button
              key={value}
              type="button"
              className={`status-chip ${statusFilter === value ? "active" : ""}`}
              onClick={() => onStatusFilterChange(value)}
            >
              {value === "all" ? "All" : statusLabel(value)}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
}
