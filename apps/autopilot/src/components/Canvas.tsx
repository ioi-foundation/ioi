import { useRef, useState } from "react";
import { CanvasNode } from "./CanvasNode";
import { CanvasEdge } from "./CanvasEdge";
import { Node, Edge } from "../types";
import "./Canvas.css";

interface Transform {
  x: number;
  y: number;
  scale: number;
}

interface CanvasProps {
  nodes: Node[];
  edges: Edge[];
  selectedNodeId: string | null;
  onNodeSelect: (nodeId: string | null) => void;
  onNodeMove: (nodeId: string, x: number, y: number) => void;
  transform: Transform;
  onTransformChange: (t: Transform) => void;
}

export function Canvas({
  nodes,
  edges,
  selectedNodeId,
  onNodeSelect,
  onNodeMove,
  transform,
  onTransformChange,
}: CanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isPanning, setIsPanning] = useState(false);
  const [showGrid, setShowGrid] = useState(true);

  // Pan Logic
  const handleMouseDown = (e: React.MouseEvent) => {
    // Only pan if clicking on the background, not on a node or control
    if (e.button === 0 && (e.target as HTMLElement).classList.contains("canvas")) {
      setIsPanning(true);
      onNodeSelect(null);
    }
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (isPanning) {
      onTransformChange({
        ...transform,
        x: transform.x + e.movementX,
        y: transform.y + e.movementY,
      });
    }
  };

  const handleMouseUp = () => setIsPanning(false);

  // Zoom Logic
  const handleWheel = (e: React.WheelEvent) => {
    if (e.ctrlKey || e.metaKey) {
      e.preventDefault();
      const zoom = e.deltaY < 0 ? 1.1 : 0.9;
      onTransformChange({ 
        ...transform, 
        scale: Math.max(0.2, Math.min(2, transform.scale * zoom)) 
      });
    } else {
      // Normal wheel scrolls/pans
      onTransformChange({ 
        ...transform, 
        x: transform.x - e.deltaX, 
        y: transform.y - e.deltaY 
      });
    }
  };

  const zoomIn = () => onTransformChange({ ...transform, scale: Math.min(2, transform.scale * 1.2) });
  const zoomOut = () => onTransformChange({ ...transform, scale: Math.max(0.2, transform.scale / 1.2) });
  const fitView = () => onTransformChange({ x: 50, y: 50, scale: 1 });

  const getNodePos = (id: string) => nodes.find((n) => n.id === id) || { x: 0, y: 0 };

  return (
    <div
      ref={containerRef}
      className={`canvas ${isPanning ? "panning" : ""}`}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onWheel={handleWheel}
    >
      {/* Map Controls Overlay */}
      <div className="canvas-map-controls">
        <div className="control-group">
          <button className="control-btn" onClick={zoomIn} title="Zoom In">+</button>
          <button className="control-btn" onClick={zoomOut} title="Zoom Out">−</button>
        </div>
        <div className="control-group">
          <button className="control-btn" onClick={fitView} title="Fit View">⤢</button>
          <button 
            className={`control-btn ${showGrid ? 'active' : ''}`} 
            onClick={() => setShowGrid(!showGrid)} 
            title="Toggle Grid"
          >
            #
          </button>
        </div>
      </div>

      <div
        className="canvas-transform"
        style={{
          transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.scale})`,
        }}
      >
        {/* Background Grid */}
        {showGrid && <div className="canvas-grid" />}

        {/* Governance Zones (Sandbox vs Production) */}
        <div className="canvas-zones">
          <div className="zone zone-sandbox">
            <div className="zone-label">Sandbox</div>
          </div>
          <div className="zone zone-production">
            <div className="zone-label">Production</div>
            <div className="zone-lock">🔒</div>
          </div>
        </div>

        {/* Edges Layer (Lines connecting nodes) */}
        <svg className="canvas-edges">
          {edges.map((edge) => {
            const fromNode = getNodePos(edge.from);
            const toNode = getNodePos(edge.to);
            return (
              <CanvasEdge
                key={edge.id}
                edge={edge}
                fromX={fromNode.x + 220} // Account for node width
                fromY={fromNode.y + 40}  // Account for port vertical alignment
                toX={toNode.x}
                toY={toNode.y + 40}
              />
            );
          })}
        </svg>

        {/* Nodes Layer */}
        {nodes.map((node) => (
          <CanvasNode
            key={node.id}
            node={node}
            isSelected={node.id === selectedNodeId}
            onSelect={() => onNodeSelect(node.id)}
            onMove={(x, y) => onNodeMove(node.id, x, y)}
            scale={transform.scale}
          />
        ))}
      </div>
    </div>
  );
}