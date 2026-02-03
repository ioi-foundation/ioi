// packages/agent-ide/src/hooks/useGraphState.ts
import { useState, useCallback } from "react";
import { 
  useNodesState, 
  useEdgesState, 
  addEdge, 
  Connection, 
  useReactFlow,
  Node as FlowNode,
  Edge as FlowEdge
} from "@xyflow/react";
import { Node, Edge, NodeLogic, FirewallPolicy } from "../types/graph";

export function useGraphState(initialNodes: Node[] = [], initialEdges: Edge[] = []) {
  // Convert domain types to ReactFlow types
  const flowNodes = initialNodes.map(n => ({
      id: n.id, type: n.type, position: {x: n.x, y: n.y}, data: {...n}
  }));
  const flowEdges = initialEdges.map(e => ({
      id: e.id, source: e.from, target: e.to, sourceHandle: e.fromPort, targetHandle: e.toPort,
      data: { ...e.data }
  }));

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(flowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>(flowEdges);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  
  const { screenToFlowPosition, fitView, zoomIn, zoomOut } = useReactFlow();

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ 
      ...params, 
      type: 'semantic', 
      animated: false,
      data: { status: 'idle', active: false } 
    }, eds)),
    [setEdges],
  );

  const handleNodeSelect = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId);
  }, []);

  const handleNodeUpdate = useCallback((nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<FirewallPolicy>) => {
    setNodes((nds) => nds.map((node) => {
      if (node.id === nodeId) {
        // Explicitly cast to Node type to access config structure
        const currentData = node.data as unknown as Node;
        const currentConfig = currentData.config || { logic: {}, law: {} };
        
        // Use type assertion to access dynamic property safely
        const sectionData = (currentConfig as any)[section] || {};
        const newSectionData = { ...sectionData, ...updates };
        
        return {
          ...node,
          data: {
            ...node.data,
            config: { ...currentConfig, [section]: newSectionData }
          },
        };
      }
      return node;
    }));
  }, [setNodes]);

  const handleCanvasDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const type = e.dataTransfer.getData("nodeType");
    const pos = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    
    const newNode: FlowNode = {
        id: `node-${Date.now()}`,
        type: type || 'action',
        position: pos,
        data: { 
            id: `node-${Date.now()}`, 
            type: type || 'action', 
            name: "New Node",
            config: { logic: {}, law: {} }
        }
    };
    setNodes(prev => [...prev, newNode]);
  }, [screenToFlowPosition, setNodes]);

  return {
    nodes, edges, setNodes, setEdges, onNodesChange, onEdgesChange,
    onConnect, selectedNodeId, handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    fitView, zoomIn, zoomOut
  };
}