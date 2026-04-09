// packages/agent-ide/src/features/Fleet/FleetView.tsx
import { useState, useEffect, useMemo } from "react";
import { AgentRuntime, Zone, Container } from "../../runtime/agent-runtime";
import { Icons } from "../../ui/icons";
import "./FleetView.css";

interface FleetViewProps {
  runtime: AgentRuntime;
}

function detailRowsForContainer(
  container: Container,
  zoneName: string,
): Array<{ label: string; value: string }> {
  const rows = [
    { label: "Runtime ID", value: container.id },
    { label: "Zone", value: zoneName },
    { label: "Status", value: container.status },
    { label: "Image", value: container.image },
    { label: "Uptime", value: container.uptime },
    { label: "CPU", value: `${container.metrics.cpu.toFixed(0)}%` },
    { label: "RAM", value: `${container.metrics.ram.toFixed(0)}%` },
  ];

  if (typeof container.metrics.vram === "number") {
    rows.push({ label: "GPU", value: `${container.metrics.vram.toFixed(0)}%` });
  }

  if (container.id.startsWith("run:")) {
    rows.push({
      label: "Run state",
      value:
        container.status === "running"
          ? "Parent playbook still advancing."
          : "Run waiting for operator review or completion.",
    });
    rows.push({
      label: "Progress",
      value: `${container.metrics.cpu.toFixed(0)}% of completed steps surfaced`,
    });
  } else if (container.id.startsWith("backend:")) {
    rows.push({
      label: "Backend state",
      value:
        container.status === "running"
          ? "Kernel-backed Local Engine service is healthy."
          : "Backend is stopped or degraded in the live runtime.",
    });
  }

  return rows;
}

export function FleetView({ runtime }: FleetViewProps) {
  const [selectedZone, setSelectedZone] = useState<string>("all");
  const [zones, setZones] = useState<Zone[]>([]);
  const [containers, setContainers] = useState<Container[]>([]);
  const [selectedContainerId, setSelectedContainerId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Poll for updates
  useEffect(() => {
    const fetchState = async () => {
        try {
          const state = await runtime.getFleetState();
          setZones(state.zones);
          setContainers(state.containers);
          setError(null);
        } catch (nextError) {
          setError(String(nextError));
          setZones([]);
          setContainers([]);
        } finally {
          setLoading(false);
        }
    };
    
    fetchState();
    const interval = setInterval(fetchState, 2000);
    return () => clearInterval(interval);
  }, [runtime]);

  const filteredContainers = selectedZone === "all" 
    ? containers 
    : containers.filter(c => c.zoneId === selectedZone);

  useEffect(() => {
    if (filteredContainers.length === 0) {
      if (selectedContainerId !== null) {
        setSelectedContainerId(null);
      }
      return;
    }

    const selectionStillVisible = filteredContainers.some(
      (container) => container.id === selectedContainerId,
    );

    if (!selectionStillVisible) {
      setSelectedContainerId(filteredContainers[0].id);
    }
  }, [filteredContainers, selectedContainerId]);

  const activeContainer = filteredContainers.find(c => c.id === selectedContainerId) ?? null;
  const activeZoneName = useMemo(
    () =>
      zones.find((zone) => zone.id === activeContainer?.zoneId)?.name ??
      activeContainer?.zoneId ??
      "Unknown zone",
    [activeContainer?.zoneId, zones],
  );
  const activeContainerDetails = useMemo(
    () =>
      activeContainer
        ? detailRowsForContainer(activeContainer, activeZoneName)
        : [],
    [activeContainer, activeZoneName],
  );

  return (
    <div className="fleet-view">
      {/* SIDEBAR: ZONES */}
      <div className="fleet-sidebar">
        <div className="zone-header">Infrastructure Zones</div>
        <div className="zone-list">
          <div 
            className={`zone-item ${selectedZone === "all" ? "active" : ""}`}
            onClick={() => setSelectedZone("all")}
          >
            <div className="zone-name-row">
              <span className="zone-icon"><Icons.Trigger width="14" height="14" /></span>
              <span>All Zones</span>
            </div>
          </div>
          
          {zones.map(zone => (
            <div 
              key={zone.id} 
              className={`zone-item ${selectedZone === zone.id ? "active" : ""}`}
              onClick={() => setSelectedZone(zone.id)}
            >
              <div className="zone-name-row">
                <span className="zone-icon">
                  {zone.type === "local" ? <Icons.Trigger width="14" height="14" /> : <Icons.Folder width="14" height="14" />}
                </span>
                <span>{zone.name}</span>
              </div>
              <div className="zone-stats">
                <span>{zone.capacity.used}/{zone.capacity.total} {zone.capacity.unit}</span>
                <span>${zone.costPerHour.toFixed(2)}/hr</span>
              </div>
              <div className="zone-capacity-bar">
                <div 
                  className="zone-capacity-fill" 
                  style={{ width: `${(zone.capacity.used / zone.capacity.total) * 100}%` }} 
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* MAIN: CONTAINER GRID */}
      <div className="fleet-main">
        <div className="fleet-toolbar">
          <span className="toolbar-title">Active Containers ({filteredContainers.length})</span>
          <div className="fleet-toolbar-meta">
            <span className="fleet-toolbar-chip">
              {zones.length} live zone{zones.length === 1 ? "" : "s"}
            </span>
            <span className="fleet-toolbar-chip">Polled every 2s</span>
          </div>
        </div>

        {loading ? (
          <div className="fleet-terminal" style={{ marginBottom: 16 }}>
            <div className="terminal-content">Loading live fleet state…</div>
          </div>
        ) : null}

        {error ? (
          <div className="fleet-terminal" style={{ marginBottom: 16 }}>
            <div className="terminal-content">{error}</div>
          </div>
        ) : null}

        <div className="fleet-grid">
          {filteredContainers.map(c => (
            <div 
              key={c.id} 
              className={`container-card ${selectedContainerId === c.id ? "selected" : ""}`}
              onClick={() => setSelectedContainerId(c.id)}
            >
              <div className="card-header">
                <div>
                  <span className="container-name">{c.name}</span>
                  <span className="container-image">{c.image}</span>
                </div>
                <div className={`container-status status-${c.status}`} title={c.status} />
              </div>

              <div className="card-metrics">
                <MetricBar label="CPU" value={c.metrics.cpu} color="#60A5FA" />
                <MetricBar label="RAM" value={c.metrics.ram} color="#34D399" />
                {c.metrics.vram !== undefined && (
                  <MetricBar label="GPU" value={c.metrics.vram} color="#A78BFA" />
                )}
              </div>

              <div className="card-footer">
                <span>Uptime: {c.uptime}</span>
                {c.zoneId !== "local" && <span className="cost-ticker">Running Cost</span>}
              </div>
            </div>
          ))}
        </div>

        {/* BOTTOM: LIVE DETAIL */}
        <div className="fleet-terminal">
          <div className="terminal-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Icons.Action width="12" /> Live detail</span>
            <div className="divider-vertical" style={{ height: 16, width: 1, background: '#2E333D' }} />
            <div className={`terminal-tab ${activeContainer ? "active" : ""}`}>
              {activeContainer ? activeContainer.name : "Select a container..."}
            </div>
          </div>
          <div className="terminal-content">
            {activeContainer ? (
              <div className="fleet-detail-list">
                {activeContainerDetails.map((row) => (
                  <div key={`${activeContainer.id}:${row.label}`} className="fleet-detail-row">
                    <span className="fleet-detail-label">{row.label}</span>
                    <span className="fleet-detail-value">{row.value}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ color: '#4B5563', fontStyle: 'italic' }}>
                {error
                  ? "Fleet state unavailable. Resolve the runtime error above to inspect live containers."
                  : "No container selected. Click a card above to inspect the live runtime detail we have for it."}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetricBar({ label, value, color }: { label: string, value: number, color: string }) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <div className="metric-track">
        <div 
          className="metric-fill" 
          style={{ width: `${value}%`, background: color }} 
        />
      </div>
      <span style={{ width: 28, textAlign: 'right' }}>{value.toFixed(0)}%</span>
    </div>
  );
}
