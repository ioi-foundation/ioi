import "./CanvasEdge.css";

interface Edge {
  id: string;
  from: string;
  to: string;
  type: "data" | "control";
  active?: boolean;
  volume?: number; // 1-10 scale representing data throughput
}

interface CanvasEdgeProps {
  edge: Edge;
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
}

export function CanvasEdge({ edge, fromX, fromY, toX, toY }: CanvasEdgeProps) {
  // Bezier curve
  const dx = Math.abs(toX - fromX);
  const controlOffset = Math.max(dx * 0.5, 60);
  
  const path = `
    M ${fromX} ${fromY}
    C ${fromX + controlOffset} ${fromY},
      ${toX - controlOffset} ${toY},
      ${toX} ${toY}
  `;

  // Scale stroke width based on volume (logarithmic visualization)
  const volume = edge.volume || 1;
  const strokeWidth = Math.min(2 + Math.log(volume) * 2, 8);

  return (
    <g>
      {/* Invisible hitbox */}
      <path
        d={path}
        fill="none"
        stroke="transparent"
        strokeWidth="16"
      />
      {/* Visible Pipe */}
      <path
        className={`canvas-edge ${edge.active ? "active" : ""}`}
        d={path}
        style={{ "--edge-width": `${strokeWidth}px` } as React.CSSProperties}
      />
      <circle cx={toX} cy={toY} r={3} fill={edge.active ? "#3D85C6" : "#2E333D"} />
    </g>
  );
}