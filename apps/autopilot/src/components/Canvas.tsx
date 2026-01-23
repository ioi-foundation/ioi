import { useCallback, useMemo } from 'react';
import { 
  ReactFlow, 
  Background, 
  Controls, 
  MiniMap,
  addEdge,
  Connection,
  Edge as FlowEdge,
  Node as FlowNode,
  BackgroundVariant,
  NodeTypes,
  OnNodesChange,
  OnEdgesChange,
  OnConnect
} from '@xyflow/react';
import '@xyflow/react/dist/style.css'; 

import { CanvasNode } from './CanvasNode';
import "./Canvas.css";

interface CanvasProps {
  nodes: FlowNode[];
  edges: FlowEdge[];
  onNodesChange: OnNodesChange;
  onEdgesChange: OnEdgesChange;
  onConnect: OnConnect;
  onNodeSelect: (nodeId: string | null) => void;
}

export function Canvas({ 
  nodes, 
  edges, 
  onNodesChange, 
  onEdgesChange, 
  onConnect,
  onNodeSelect 
}: CanvasProps) {

  const handleSelectionChange = useCallback(({ nodes }: { nodes: FlowNode[] }) => {
    if (nodes.length > 0) {
      onNodeSelect(nodes[0].id);
    } else {
      onNodeSelect(null);
    }
  }, [onNodeSelect]);

  // Memoize nodeTypes to prevent re-creation
  const nodeTypes: NodeTypes = useMemo(() => ({
    trigger: CanvasNode,
    action: CanvasNode,
    gate: CanvasNode,
    model: CanvasNode,
    tool: CanvasNode,
    receipt: CanvasNode
  }), []);

  return (
    <div style={{ width: '100%', height: '100%' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onSelectionChange={handleSelectionChange}
        nodeTypes={nodeTypes}
        fitView
        snapToGrid
        snapGrid={[15, 15]}
        defaultEdgeOptions={{ type: 'smoothstep', animated: false }}
        minZoom={0.2}
      >
        <Background 
          color="#2E333D" 
          variant={BackgroundVariant.Dots} 
          gap={24} 
          size={1} 
        />
        <Controls style={{ fill: '#8A9BA8' }} />
        <MiniMap 
          nodeColor="#1F2329" 
          maskColor="rgba(10, 12, 16, 0.8)"
          style={{ background: '#0D0F12', border: '1px solid #2E333D' }} 
        />
      </ReactFlow>
    </div>
  );
}