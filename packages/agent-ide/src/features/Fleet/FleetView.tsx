// packages/agent-ide/src/features/Fleet/FleetView.tsx
import { useState, useEffect } from "react"; // React removed
import { AgentRuntime, Zone, Container } from "../../runtime/agent-runtime";
import { Icons } from "../../ui/icons";
import "./FleetView.css";

interface FleetViewProps {
  runtime: AgentRuntime;
}

export function FleetView({ runtime }: FleetViewProps) {
  const [selectedZone, setSelectedZone] = useState<string>("all");
  const [zones, setZones] = useState<Zone[]>([]);
  const [containers, setContainers] = useState<Container[]>([]);
  const [selectedContainerId, setSelectedContainerId] = useState<string | null>(null);
  
  // Poll for updates
  useEffect(() => {
    const fetchState = async () => {
        const state = await runtime.getFleetState();
        setZones(state.zones);
        setContainers(state.containers);
    };
    
    fetchState();
    const interval = setInterval(fetchState, 2000);
    return () => clearInterval(interval);
  }, [runtime]);

  const filteredContainers = selectedZone === "all" 
    ? containers 
    : containers.filter(c => c.zoneId === selectedZone);

  const activeContainer = containers.find(c => c.id === selectedContainerId);

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
          <div style={{ display: 'flex', gap: 8 }}>
             <button className="btn-secondary">New Container</button>
             <button className="btn-secondary">Prune Stopped</button>
          </div>
        </div>

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

        {/* BOTTOM: LOGS TERMINAL */}
        <div className="fleet-terminal">
          <div className="terminal-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Icons.Action width="12" /> Terminal</span>
            <div className="divider-vertical" style={{ height: 16, width: 1, background: '#2E333D' }} />
            <div className={`terminal-tab ${activeContainer ? "active" : ""}`}>
              {activeContainer ? activeContainer.name : "Select a container..."}
            </div>
          </div>
          <div className="terminal-content">
            {activeContainer ? (
              <>
                <div><span className="log-ts">[14:02:11]</span><span className="log-info">INFO</span>  Container started successfully. ID: {activeContainer.id}</div>
                <div><span className="log-ts">[14:02:12]</span><span className="log-info">INFO</span>  Listening on port 8080</div>
                <div><span className="log-ts">[14:02:15]</span><span className="log-info">INFO</span>  Model weights loaded to VRAM (12.4GB)</div>
                {activeContainer.metrics.vram && activeContainer.metrics.vram > 90 && (
                   <div><span className="log-ts">[14:05:01]</span><span className="log-err">WARN</span>  VRAM usage critical (92%). Throttling...</div>
                )}
                <div style={{ marginTop: 4 }}>_</div>
              </>
            ) : (
              <div style={{ color: '#4B5563', fontStyle: 'italic' }}>No container selected. Click a card above to view logs.</div>
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