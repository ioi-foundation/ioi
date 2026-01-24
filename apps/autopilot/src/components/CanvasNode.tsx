// src/components/CanvasNode.tsx
import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Node as IOINode, NodeLaw } from '../types'; 
import "./CanvasNode.css";

type CanvasNodeData = IOINode & Record<string, unknown>;

const typeIcons: Record<string, string> = {
  trigger: "⚡",
  action: "⚙️",
  gate: "🔒",
  model: "🧠",
  receipt: "🧾",
  tool: "🔧",
  code: "💻", // [NEW] Icon for Code Block
  router: "🔀", // [NEW] Icon for Router Block
  wait: "⏳", // [NEW] Icon for Wait Block
  context: "📦", // [NEW] Icon for Variables Block
};

export const CanvasNode = memo(({ data, selected }: NodeProps) => {
  const nodeData = data as CanvasNodeData;
  const { type, name, status, ioTypes, metrics, isGhost, config } = nodeData;

  const icon = typeIcons[type] || "📦";
  const statusClass = status || "idle";
  const ghostClass = isGhost ? "ghost" : "";
  const activeClass = status === "running" ? "active" : "";

  // Determine if Governance ports are needed based on configuration
  const law = config?.law as NodeLaw | undefined;
  const hasGovernance = law && (
    (law.budgetCap !== undefined && law.budgetCap > 0) ||
    (law.networkAllowlist !== undefined && law.networkAllowlist.length > 0) ||
    (law.requireHumanGate === true)
  );

  // [NEW] Determine dynamic ports for Router nodes
  const isRouter = type === "router";
  // For Router: Use the 'routes' array from config, fallback to default if missing
  // For others: Use standard single output unless specific logic requires more
  const outputHandles = isRouter ? (config?.logic?.routes || ["out"]) : ["out"];

  return (
    <div className={`canvas-node ${selected ? "selected" : ""} ${ghostClass} ${activeClass}`}>
      
      {/* INPUT PORT */}
      {/* Most nodes accept input, except specific triggers maybe? Assuming yes for parity */}
      <Handle 
        type="target" 
        position={Position.Left} 
        className="node-port port-in" 
        id="in"
      />

      {/* STATUS DOT */}
      {!isGhost && <div className={`status-dot status-${statusClass}`} />}

      {/* HEADER */}
      <div className="node-header">
        <span className="node-icon">{icon}</span>
        <span className="node-title">
          {isGhost ? "Inferred Action..." : name}
        </span>
      </div>

      {/* IO STRIP */}
      <div className="node-io">
        <span className="io-pill">{ioTypes?.in || "Any"}</span>
        <span>→</span>
        <span className="io-pill">{ioTypes?.out || "Any"}</span>
      </div>

      {/* BODY */}
      <div className="node-body">
        {status === "running" && <div className="activity-bar" />}
        <div className="node-stat">
          <span>Records</span>
          <span className="node-stat-val">{metrics?.records || "—"}</span>
        </div>
        <div className="node-stat" style={{ marginTop: 4 }}>
          <span>Latency</span>
          <span className="node-stat-val">{metrics?.time || "—"}</span>
        </div>
      </div>

      {/* OUTPUT PORTS (SEMANTIC) */}
      <div className="node-ports-stack">
        
        {/* 1. Success Paths (Dynamic for Router) */}
        {outputHandles.map((handleId: string, index: number) => (
          <div key={handleId} className="port-wrapper success" title={isRouter ? `Route: ${handleId}` : "Success Path"} style={{ marginTop: index * 20 }}>
            {/* Show label for Router paths so user knows which is which */}
            {isRouter && <span className="port-label" style={{ right: 14, top: 0, fontSize: 9, color: '#3D85C6' }}>{handleId}</span>}
            
            <Handle 
              type="source" 
              position={Position.Right} 
              id={handleId} // Critical: ID matches route name
              className="node-port port-out success"
              style={{ top: 12 }} // Adjust based on stacking if needed, simplistic here
            />
          </div>
        ))}

        {/* 2. Governance Blocked (Conditional) */}
        {hasGovernance && (
          <div className="port-wrapper blocked" title="Policy Blocked (Firewall/Budget)" style={{ marginTop: outputHandles.length * 20 }}>
            <Handle 
              type="source" 
              position={Position.Right} 
              id="blocked" 
              className="node-port port-out blocked"
              style={{ top: 12 }}
            />
            <span className="port-label gov">🛡️</span>
          </div>
        )}

        {/* 3. Error (Always available for robustness) */}
        <div className="port-wrapper error" title="Runtime Error / Failure" style={{ marginTop: (outputHandles.length + (hasGovernance ? 1 : 0)) * 20 }}>
          <Handle 
            type="source" 
            position={Position.Right} 
            id="error" 
            className="node-port port-out error"
            style={{ top: 12 }}
          />
          <span className="port-label err">!</span>
        </div>

      </div>

      {/* FOOTER */}
      <div className="node-footer">
        <span>{isGhost ? "PROPOSED" : `ID: ${nodeData.id?.slice(0,4)}`}</span>
      </div>
    </div>
  );
});