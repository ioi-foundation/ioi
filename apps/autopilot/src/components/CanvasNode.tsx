import { useState, useCallback } from "react";
import { Node } from "../types";
import "./CanvasNode.css";

interface CanvasNodeProps {
  node: Node;
  isSelected: boolean;
  onSelect: () => void;
  onMove: (x: number, y: number) => void;
  scale: number;
}

const typeIcons: Record<string, string> = {
  trigger: "⚡",
  action: "⚙️",
  gate: "🔒",
  model: "🧠",
  receipt: "🧾",
};

export function CanvasNode({
  node,
  isSelected,
  onSelect,
  onMove,
  scale,
}: CanvasNodeProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (e.button !== 0) return; // Only left click
      e.stopPropagation();
      onSelect();
      setIsDragging(true);

      const startX = e.clientX;
      const startY = e.clientY;
      const startNodeX = node.x;
      const startNodeY = node.y;

      const handleMouseMove = (ev: MouseEvent) => {
        // Calculate delta and apply canvas scale
        const dx = (ev.clientX - startX) / scale;
        const dy = (ev.clientY - startY) / scale;
        onMove(startNodeX + dx, startNodeY + dy);
      };

      const handleMouseUp = () => {
        setIsDragging(false);
        document.removeEventListener("mousemove", handleMouseMove);
        document.removeEventListener("mouseup", handleMouseUp);
      };

      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    },
    [node.x, node.y, scale, onSelect, onMove]
  );

  const icon = typeIcons[node.type] || "📦";
  const inType = node.ioTypes?.in || "Any";
  const outType = node.ioTypes?.out || "Any";
  const records = node.metrics?.records?.toLocaleString() || "—";
  const time = node.metrics?.time || "—";
  
  // Visual classes
  const statusClass = node.status || "idle";
  const ghostClass = node.isGhost ? "ghost" : "";
  const activeClass = node.status === "running" ? "active" : "";

  return (
    <div
      className={`canvas-node ${isSelected ? "selected" : ""} ${ghostClass} ${activeClass} ${isDragging ? "dragging" : ""}`}
      style={{ left: node.x, top: node.y }}
      onMouseDown={handleMouseDown}
    >
      {/* Status Dot (HIDDEN for Ghost/Inferred nodes) */}
      {!node.isGhost && <div className={`status-dot status-${statusClass}`} />}

      {/* Connection Ports */}
      {node.inputs && <div className="node-port port-in" title={`In: ${inType}`} />}
      {node.outputs && <div className="node-port port-out" title={`Out: ${outType}`} />}

      {/* Header Section */}
      <div className="node-header">
        <span className="node-icon">{icon}</span>
        <span className="node-title">
          {node.isGhost ? "Inferred Action..." : node.name}
        </span>
      </div>

      {/* IO Types Data Strip */}
      <div className="node-io">
        <span className="io-pill">{inType}</span>
        <span>→</span>
        <span className="io-pill">{outType}</span>
      </div>

      {/* Main Body - Metrics & Progress */}
      <div className="node-body">
        {node.status === "running" && <div className="activity-bar" />}
        
        <div className="node-stat">
          <span>Records</span>
          <span className="node-stat-val">{records}</span>
        </div>
        <div className="node-stat" style={{ marginTop: 4 }}>
          <span>Latency</span>
          <span className="node-stat-val">{time}</span>
        </div>
      </div>

      {/* Footer / ID Section */}
      <div className="node-footer">
        <span>{node.isGhost ? "PROPOSED" : `ID: ${node.id}`}</span>
        {!node.isGhost && (
          <button 
            className="footer-btn" 
            onClick={(e) => {
              e.stopPropagation();
              console.log("Previewing node:", node.id);
            }}
          >
            PREVIEW ▶
          </button>
        )}
      </div>
    </div>
  );
}