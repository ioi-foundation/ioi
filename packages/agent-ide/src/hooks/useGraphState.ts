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
import { Node, Edge, NodeLogic, FirewallPolicy, ProjectFile } from "../types/graph";

function toFlowNodes(nodes: Node[]): FlowNode[] {
  return nodes.map((node) => ({
    id: node.id,
    type: node.type,
    position: { x: node.x, y: node.y },
    data: { ...node },
  }));
}

function toFlowEdges(edges: Edge[]): FlowEdge[] {
  return edges.map((edge) => ({
    id: edge.id,
    source: edge.from,
    target: edge.to,
    sourceHandle: edge.fromPort,
    targetHandle: edge.toPort,
    data: { ...(edge.data ?? {}) },
  }));
}

export function useGraphState(initialNodes: Node[] = [], initialEdges: Edge[] = []) {
  // Convert domain types to ReactFlow types
  const flowNodes = toFlowNodes(initialNodes);
  const flowEdges = toFlowEdges(initialEdges);

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

  const replaceGraph = useCallback((project: ProjectFile) => {
    setNodes(toFlowNodes((project.nodes ?? []) as Node[]));
    setEdges(toFlowEdges((project.edges ?? []) as Edge[]));
    setSelectedNodeId(null);
  }, [setEdges, setNodes]);

  return {
    nodes, edges, setNodes, setEdges, onNodesChange, onEdgesChange,
    onConnect, selectedNodeId, handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    fitView, zoomIn, zoomOut, replaceGraph
  };
}
