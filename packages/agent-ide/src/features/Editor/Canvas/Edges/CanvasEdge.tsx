// packages/agent-ide/src/features/Editor/Canvas/Edges/CanvasEdge.tsx
import { BaseEdge, EdgeProps, getBezierPath } from '@xyflow/react';
import "./CanvasEdge.css";

const CONNECTION_LABELS: Record<string, string> = {
  approval: "approval",
  control: "flow",
  data: "data",
  delivery: "delivery",
  error: "error",
  memory: "memory",
  model: "model",
  parser: "parser",
  retry: "retry",
  state: "state",
  subgraph: "subflow",
  tool: "tool",
};

const SEMANTIC_HANDLE_LABELS: Record<string, string> = {
  approval: "approval",
  context: "context",
  error: "error",
  left: "left",
  memory: "memory",
  model: "model",
  parser: "parser",
  retry: "retry",
  right: "right",
  tool: "tool",
};

function edgeSemanticLabel(
  connectionClass: string,
  sourceHandleId?: string | null,
  targetHandleId?: string | null,
  data?: EdgeProps["data"],
): string | null {
  const explicitLabel = data?.label;
  if (typeof explicitLabel === "string" && explicitLabel.trim().length > 0) {
    return explicitLabel.trim();
  }

  const classLabel = CONNECTION_LABELS[connectionClass] ?? connectionClass;
  if (connectionClass !== "data" && connectionClass !== "control") {
    return classLabel;
  }

  const semanticHandle = sourceHandleId ?? targetHandleId ?? "";
  return SEMANTIC_HANDLE_LABELS[semanticHandle] ?? null;
}

export function CanvasEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
  sourceHandleId,
  targetHandleId,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const isActive = data?.active === true;
  const status = (data?.status as string) || 'idle';
  const volume = (data?.volume as number) || 1;
  const connectionClass = String(data?.connectionClass || 'data');
  const issueCount = Number(data?.issueCount ?? 0);
  const issueStatus = String(data?.issueStatus ?? "");
  const issueTitle = typeof data?.issueTitle === "string" ? data.issueTitle : "Connection needs attention";
  const issueMessage = typeof data?.issueMessage === "string" ? data.issueMessage : "";
  const edgeLabel = edgeSemanticLabel(connectionClass, sourceHandleId, targetHandleId, data);
  const edgeLabelWidth = edgeLabel ? Math.max(34, edgeLabel.length * 7 + 14) : 0;
  const macroClass = data?.createdBy === "agent_loop_macro" ? " canvas-edge--macro" : "";

  // Build semantic class names
  let className = `canvas-edge canvas-edge--${connectionClass}${macroClass}`;
  if (isActive) {
    className += " active";
    if (status === 'blocked') className += " blocked";
    else if (status === 'error' || status === 'failed') className += " error";
  }
  if (issueCount > 0) {
    className += " has-issues";
  }

  // Dynamic stroke width based on data volume (logarithmic scale)
  const strokeWidth = isActive ? Math.min(2 + Math.log(volume + 1), 6) : 2;
  
  // Animation speed inverse to duration (higher volume = faster flow visually)
  const animationDuration = Math.max(0.5, 2.0 - Math.log(volume + 1) * 0.2);

  return (
    <>
      {/* Invisible wide path for easier clicking/hover detection */}
      <BaseEdge 
        path={edgePath} 
        style={{ strokeWidth: 20, stroke: 'transparent', cursor: 'pointer' }} 
      />
      
      {/* Visible semantic path */}
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{ 
            ...style, 
            strokeWidth,
            animationDuration: isActive ? `${animationDuration}s` : undefined
        }}
        className={className}
      />

      {/* Data Packet Particle (Visual indicator of flow) */}
      {isActive && (
        <circle r="4" fill={status === 'blocked' ? 'var(--status-warning)' : status === 'error' ? 'var(--status-error)' : 'var(--accent-blue)'}>
          <animateMotion 
            dur={`${animationDuration * 1.5}s`} 
            repeatCount="indefinite"
            path={edgePath}
            rotate="auto"
          />
        </circle>
      )}

      {edgeLabel ? (
        <g
          className={`canvas-edge-label canvas-edge-label--${connectionClass}`}
          data-testid="workflow-canvas-edge-label"
          data-connection-class={connectionClass}
          transform={`translate(${labelX}, ${labelY})`}
          pointerEvents="none"
        >
          <rect
            className="canvas-edge-label-background"
            x={-edgeLabelWidth / 2}
            y={-9}
            width={edgeLabelWidth}
            height={18}
            rx={9}
          />
          <text className="canvas-edge-label-text" textAnchor="middle" dominantBaseline="middle">
            {edgeLabel}
          </text>
        </g>
      ) : null}
      {issueCount > 0 ? (
        <g
          className={`canvas-edge-warning is-${issueStatus || "warning"}`}
          data-testid="workflow-canvas-edge-warning"
          data-issue-status={issueStatus || "warning"}
          transform={`translate(${labelX}, ${labelY + (edgeLabel ? 22 : 0)})`}
          pointerEvents="none"
        >
          <title>{`${issueTitle}${issueMessage ? `: ${issueMessage}` : ""}`}</title>
          <circle r="10" className="canvas-edge-warning-background" />
          <text className="canvas-edge-warning-text" textAnchor="middle" dominantBaseline="middle">
            !
          </text>
        </g>
      ) : null}
    </>
  );
}
