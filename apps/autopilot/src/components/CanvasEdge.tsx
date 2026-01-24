// src/components/CanvasEdge.tsx
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

  // Build semantic class names
  let className = "canvas-edge";
  if (isActive) {
    className += " active";
    if (status === 'blocked') className += " blocked";
    else if (status === 'error' || status === 'failed') className += " error";
    // Default 'active' is blue (success)
  }

  // Dynamic stroke width simulation based on volume
  const volume = (data?.volume as number) || 1;
  // Base width 2, max 6 based on volume log
  const strokeWidth = isActive ? 3 : Math.min(2 + Math.log(volume), 5);

  return (
    <>
      {/* Invisible wide path for easier clicking */}
      <BaseEdge 
        path={edgePath} 
        style={{ strokeWidth: 20, stroke: 'transparent', cursor: 'pointer' }} 
      />
      
      {/* Visible semantic path */}
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{ ...style, strokeWidth }}
        className={className}
      />
    </>
  );
}