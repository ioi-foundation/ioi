// packages/agent-ide/src/features/Editor/Canvas/Canvas.tsx
import React, { useMemo } from 'react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css'; 

import { WORKFLOW_CANVAS_NODE_TYPE_IDS } from '../../../runtime/workflow-canvas-node-types';
import { CanvasNode } from './Nodes/CanvasNode';
import { CanvasEdge } from './Edges/CanvasEdge';

interface CanvasProps {
  nodes: any[];
  edges: any[];
  onNodesChange: any;
  onEdgesChange: any;
  onConnect: any;
  onNodeSelect: (id: string | null) => void;
  onNodeActivate?: (id: string) => void;
  onDrop: (e: React.DragEvent) => void;
  readOnly?: boolean;
  workflowChromeLocale?: string | null;
}

export const WORKFLOW_CANVAS_NODE_TYPES = Object.fromEntries(
  WORKFLOW_CANVAS_NODE_TYPE_IDS.map((type) => [type, CanvasNode]),
) as Record<string, typeof CanvasNode>;

export function Canvas({
  nodes, edges, onNodesChange, onEdgesChange, onConnect, onNodeSelect, onNodeActivate, onDrop, readOnly = false, workflowChromeLocale = null
}: CanvasProps) {

  const keyboardNodes = useMemo(
    () =>
      nodes.map((node) => ({
        ...node,
        data: {
          ...(node.data ?? {}),
          onKeyboardSelect: (nodeId: string) => onNodeSelect(nodeId),
          workflowChromeLocale,
        },
      })),
    [nodes, onNodeSelect, workflowChromeLocale],
  );

  const nodeTypes = useMemo(() => WORKFLOW_CANVAS_NODE_TYPES, []);

  const edgeTypes = useMemo(() => ({
    semantic: CanvasEdge
  }), []);

  return (
    <div className="agent-ide-react-flow-surface" style={{ width: '100%', height: '100%', background: 'var(--bg-dark)' }}
         onDragOver={e => e.preventDefault()}
         onDrop={readOnly ? undefined : onDrop}
         aria-label="Workflow canvas"
         data-workflow-chrome-locale={workflowChromeLocale ?? "default"}
         data-keyboard-navigation="node-enter-space-selects-inspector"
         data-read-only={readOnly ? "true" : "false"}>
      <ReactFlow
        nodes={keyboardNodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodesDraggable={!readOnly}
        nodesConnectable={!readOnly}
        nodesFocusable
        edgesFocusable={!readOnly}
        elementsSelectable
        onNodeClick={(_, node) => onNodeSelect(node.id)}
        onNodeDoubleClick={(_, node) => onNodeActivate?.(node.id)}
        onPaneClick={() => onNodeSelect(null)}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
      >
        {/* @ts-ignore */}
        <Background color="rgba(123, 143, 164, 0.22)" gap={20} />
        {/* @ts-ignore */}
        <Controls />
        <MiniMap style={{background: 'var(--bg-panel)'}} />
      </ReactFlow>
    </div>
  );
}
