// packages/agent-ide/src/features/Editor/Canvas/Canvas.tsx
import React, { useMemo } from 'react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css'; 

import { CanvasNode } from './Nodes/CanvasNode';
import { CanvasEdge } from './Edges/CanvasEdge';

interface CanvasProps {
  nodes: any[];
  edges: any[];
  onNodesChange: any;
  onEdgesChange: any;
  onConnect: any;
  onNodeSelect: (id: string | null) => void;
  onDrop: (e: React.DragEvent) => void;
}

export function Canvas({ 
  nodes, edges, onNodesChange, onEdgesChange, onConnect, onNodeSelect, onDrop 
}: CanvasProps) {
  
  const nodeTypes = useMemo(() => ({
    action: CanvasNode,
    trigger: CanvasNode,
    model: CanvasNode,
    gate: CanvasNode,
    tool: CanvasNode,
    receipt: CanvasNode,
    code: CanvasNode,
    router: CanvasNode,
    wait: CanvasNode,
    context: CanvasNode,
    retrieval: CanvasNode
  }), []);

  const edgeTypes = useMemo(() => ({
    semantic: CanvasEdge
  }), []);

  return (
    <div style={{ width: '100%', height: '100%', background: 'var(--bg-dark)' }} 
         onDragOver={e => e.preventDefault()} 
         onDrop={onDrop}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={(_, node) => onNodeSelect(node.id)}
        onPaneClick={() => onNodeSelect(null)}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
      >
        {/* @ts-ignore */}
        <Background color="#2E333D" gap={20} />
        {/* @ts-ignore */}
        <Controls />
        <MiniMap style={{background: 'var(--bg-panel)'}} />
      </ReactFlow>
    </div>
  );
}