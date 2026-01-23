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

  return (
    <div className={`canvas-node ${selected ? "selected" : ""} ${ghostClass} ${activeClass}`}>
      
      {/* INPUT PORT */}
      {nodeData.inputs && (
        <Handle 
          type="target" 
          position={Position.Left} 
          className="node-port port-in" 
          id="in"
        />
      )}

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
      {nodeData.outputs && (
        <div className="node-ports-stack">
          
          {/* 1. Success (Standard) */}
          <div className="port-wrapper success" title="Success Path">
            <Handle 
              type="source" 
              position={Position.Right} 
              id="out" 
              className="node-port port-out success"
              style={{ top: 12 }}
            />
          </div>

          {/* 2. Governance Blocked (Conditional) */}
          {hasGovernance && (
            <div className="port-wrapper blocked" title="Policy Blocked (Firewall/Budget)">
              <Handle 
                type="source" 
                position={Position.Right} 
                id="blocked" 
                className="node-port port-out blocked"
                style={{ top: 32 }}
              />
              <span className="port-label gov">🛡️</span>
            </div>
          )}

          {/* 3. Error (Always available for robustness) */}
          <div className="port-wrapper error" title="Runtime Error / Failure">
            <Handle 
              type="source" 
              position={Position.Right} 
              id="error" 
              className="node-port port-out error"
              style={{ top: hasGovernance ? 52 : 32 }}
            />
            <span className="port-label err">!</span>
          </div>

        </div>
      )}

      {/* FOOTER */}
      <div className="node-footer">
        <span>{isGhost ? "PROPOSED" : `ID: ${nodeData.id?.slice(0,4)}`}</span>
      </div>
    </div>
  );
});