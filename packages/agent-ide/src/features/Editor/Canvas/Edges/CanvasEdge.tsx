// packages/agent-ide/src/features/Editor/Canvas/Edges/CanvasEdge.tsx
import { BaseEdge, EdgeProps, getBezierPath } from '@xyflow/react';
import "./CanvasEdge.css";

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
}: EdgeProps) {
  const [edgePath] = getBezierPath({
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

  // Build semantic class names
  let className = "canvas-edge";
  if (isActive) {
    className += " active";
    if (status === 'blocked') className += " blocked";
    else if (status === 'error' || status === 'failed') className += " error";
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
    </>
  );
}