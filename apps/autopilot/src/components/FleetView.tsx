import { useState, useEffect } from "react";
import "./FleetView.css";

// --- Icons ---
const ServerIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>;
const CloudIcon = () => <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>;
const LockIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>;
const TerminalIcon = () => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>;

interface Zone {
  id: string;
  name: string;
  type: "local" | "cloud" | "enclave";
  capacity: { used: number; total: number; unit: string };
  costPerHour: number;
}

interface Container {
  id: string;
  name: string;
  image: string;
  zoneId: string;
  status: "running" | "stopped" | "error";
  metrics: {
    cpu: number; // 0-100%
    ram: number; // 0-100%
    vram?: number; // 0-100%
  };
  uptime: string;
}

const INITIAL_ZONES: Zone[] = [
  { id: "local", name: "Local (Mac Studio)", type: "local", capacity: { used: 14, total: 64, unit: "GB" }, costPerHour: 0.00 },
  { id: "akash", name: "Akash Network (gpu-1)", type: "cloud", capacity: { used: 22, total: 48, unit: "VRAM" }, costPerHour: 0.45 },
  { id: "aws", name: "AWS Nitro Enclave", type: "enclave", capacity: { used: 2, total: 16, unit: "GB" }, costPerHour: 2.80 },
];

const INITIAL_CONTAINERS: Container[] = [
  { id: "c1", name: "research-worker-a", image: "ioi/researcher:v1.2", zoneId: "local", status: "running", metrics: { cpu: 12, ram: 24 }, uptime: "2h 14m" },
  { id: "c2", name: "llama-3-8b-local", image: "ollama/llama3", zoneId: "local", status: "running", metrics: { cpu: 5, ram: 45 }, uptime: "4d 1h" },
  { id: "c3", name: "video-gen-worker", image: "ioi/creative:v0.9", zoneId: "akash", status: "running", metrics: { cpu: 88, ram: 60, vram: 92 }, uptime: "15m" },
  { id: "c4", name: "payment-signer", image: "ioi/vault:secure", zoneId: "aws", status: "running", metrics: { cpu: 1, ram: 5 }, uptime: "12d" },
];

export function FleetView() {
  const [selectedZone, setSelectedZone] = useState<string>("all");
  const [containers, setContainers] = useState<Container[]>(INITIAL_CONTAINERS);
  const [selectedContainerId, setSelectedContainerId] = useState<string | null>(null);
  
  // Simulate live metrics
  useEffect(() => {
    const interval = setInterval(() => {
      setContainers(prev => prev.map(c => {
        if (c.status !== "running") return c;
        return {
          ...c,
          metrics: {
            cpu: Math.min(100, Math.max(0, c.metrics.cpu + (Math.random() * 10 - 5))),
            ram: Math.min(100, Math.max(0, c.metrics.ram + (Math.random() * 4 - 2))),
            vram: c.metrics.vram ? Math.min(100, Math.max(0, c.metrics.vram + (Math.random() * 6 - 3))) : undefined
          }
        };
      }));
    }, 1000);
    return () => clearInterval(interval);
  }, []);

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
              <span className="zone-icon"><ServerIcon /></span>
              <span>All Zones</span>
            </div>
          </div>
          
          {INITIAL_ZONES.map(zone => (
            <div 
              key={zone.id} 
              className={`zone-item ${selectedZone === zone.id ? "active" : ""}`}
              onClick={() => setSelectedZone(zone.id)}
            >
              <div className="zone-name-row">
                <span className="zone-icon">
                  {zone.type === "local" ? <ServerIcon /> : zone.type === "enclave" ? <LockIcon /> : <CloudIcon />}
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
             <button className="btn btn-secondary">New Container</button>
             <button className="btn btn-secondary">Prune Stopped</button>
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
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}><TerminalIcon /> Terminal</span>
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
                <div><span className="log-ts">[14:05:00]</span><span className="log-info">INFO</span>  Processing request batch #492...</div>
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