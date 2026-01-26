// src/windows/StudioWindow/hooks/useGraphState.ts
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
import { Node as IOINode, Edge as IOIEdge, NodeLogic, FirewallPolicy, AgentConfiguration } from "../../../types.ts";
import { NODE_TEMPLATES } from "../templates";
import { compileAgentToGraph } from "../utils/agentCompiler";

// --- Initial Data Helpers ---
const toFlowNode = (n: IOINode): FlowNode<IOINode> => ({
  id: n.id,
  type: n.type,
  position: { x: n.x, y: n.y },
  data: { ...n }
});

const toFlowEdge = (e: IOIEdge): FlowEdge => ({
  id: e.id,
  source: e.from,
  target: e.to,
  sourceHandle: e.fromPort,
  targetHandle: e.toPort,
  type: 'semantic', 
  data: { 
    active: e.active, 
    volume: e.volume,
    status: 'idle' 
  },
  animated: e.active,
});

// Initial mock data
const initialIOINodes: IOINode[] = [
  { 
    id: "n-1", type: "trigger", name: "Cron Trigger", x: 100, y: 150, status: "idle", 
    outputs: ["out"], ioTypes: {in: "—", out: "Signal"},
    config: { logic: { cronSchedule: "*/5 * * * *" }, law: {} } 
  },
  { 
    id: "n-2", type: "action", name: "Read Invoices", x: 400, y: 150, status: "idle", 
    inputs: ["in"], outputs: ["out"], ioTypes: {in: "Signal", out: "PDF[]"},
    config: { logic: { method: "GET", endpoint: "https://api.invoicing.com/v1/list" }, law: { privacyLevel: "masked" } }
  },
  { 
    id: "n-3", type: "model", name: "Parse + Classify", x: 700, y: 150, status: "idle", 
    inputs: ["in"], outputs: ["out"], ioTypes: {in: "PDF[]", out: "Invoice[]"}, 
    metrics: { records: 300, time: "1.2s" },
    config: { logic: { model: "local-llm", temperature: 0.2, systemPrompt: "Extract vendor and total." }, law: { budgetCap: 0.50 } }
  },
  { 
    id: "n-4", type: "gate", name: "Policy Gate", x: 1000, y: 150, status: "idle", 
    inputs: ["in"], outputs: ["out"], ioTypes: {in: "Invoice[]", out: "Invoice[]"},
    config: { logic: { conditionScript: "risk < 0.5" }, law: { requireHumanGate: true } }
  },
  { 
    id: "n-5", type: "receipt", name: "Receipt Logger", x: 1300, y: 150, status: "idle", 
    inputs: ["in"], ioTypes: {in: "Invoice[]", out: "Log"},
    config: { logic: {}, law: {} }
  },
];

const initialIOIEdges: IOIEdge[] = [
  { id: "e-1", from: "n-1", to: "n-2", fromPort: "out", toPort: "in", type: "control", active: false },
  { id: "e-2", from: "n-2", to: "n-3", fromPort: "out", toPort: "in", type: "data", active: false, volume: 5 },
  { id: "e-3", from: "n-3", to: "n-4", fromPort: "out", toPort: "in", type: "data", active: false, volume: 5 },
  { id: "e-4", from: "n-4", to: "n-5", fromPort: "out", toPort: "in", type: "control", active: false },
];

export function useGraphState() {
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode<IOINode>>(initialIOINodes.map(toFlowNode));
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialIOIEdges.map(toFlowEdge));
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  
  const { screenToFlowPosition, fitView, zoomIn, zoomOut } = useReactFlow();

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ 
      ...params, 
      type: 'semantic', // Enforce custom type on new connections
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
        const currentData = node.data as unknown as IOINode;
        const currentConfig = currentData.config || { logic: {}, law: {} };
        
        let newSectionData = { ...(currentConfig[section] || {}), ...updates };
        
        if (section === 'logic' && 'arguments' in updates) {
            const currentArgs = (currentConfig.logic as NodeLogic)?.arguments || {};
            // @ts-ignore
            const newArgs = updates.arguments || {};
            newSectionData = {
                ...newSectionData,
                arguments: { ...currentArgs, ...newArgs }
            };
        }

        return {
          ...node,
          data: {
            ...currentData,
            config: {
              ...currentConfig,
              [section]: newSectionData
            }
          },
        };
      }
      return node;
    }));
  }, [setNodes]);

  const handleCanvasDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    try {
      const nodeId = e.dataTransfer.getData("nodeId"); 
      const nodeName = e.dataTransfer.getData("nodeName");
      const nodeType = e.dataTransfer.getData("nodeType");
      const schemaStr = e.dataTransfer.getData("nodeSchema");
      
      const position = screenToFlowPosition({ x: e.clientX, y: e.clientY });
      
      const template = NODE_TEMPLATES[nodeId];
      let newNodeData: IOINode;

      if (template) {
        newNodeData = {
          id: `${nodeId}-${Date.now()}`,
          type: template.type,
          name: template.name,
          x: position.x, 
          y: position.y,
          status: "idle",
          ioTypes: template.ioTypes,
          inputs: ["in"], 
          outputs: ["out"],
          config: JSON.parse(JSON.stringify(template.defaultConfig))
        };
      } else if (nodeType === "agent") {
        newNodeData = {
          id: `agent-${Date.now()}`,
          type: "model", 
          name: nodeName || "Nested Agent",
          x: position.x,
          y: position.y,
          status: "idle",
          ioTypes: { in: "Task", out: "Result" },
          inputs: ["in"],
          outputs: ["out"],
          config: {
            logic: {
              model: "nested-agent", 
              systemPrompt: `Execute the agent: ${nodeName}`,
            },
            law: { 
                budgetCap: 5.0 
            }
          }
        };
      } else if (nodeId.includes("__")) {
        // Dynamic MCP Tool Scaffolding
        newNodeData = {
          id: `tool-${Date.now()}`,
          type: "tool",
          name: nodeName || "MCP Tool",
          x: position.x,
          y: position.y,
          status: "idle",
          ioTypes: { in: "Args", out: "Data" },
          inputs: ["in"],
          outputs: ["out"],
          // Store schema for UI generation
          schema: schemaStr,
          config: {
            logic: {
              tool_name: nodeId, // "filesystem__read_file"
              // Arguments will be populated via UI
              arguments: {}
            },
            law: {
              requireHumanGate: true // Default safe
            }
          }
        };
      } else {
        newNodeData = {
          id: `node-${Date.now()}`,
          type: "action",
          name: nodeName || "Generic Node",
          x: position.x, 
          y: position.y,
          status: "idle", 
          ioTypes: { in: "Any", out: "Any" }, 
          inputs: ["in"], outputs: ["out"],
          config: { logic: {}, law: {} }
        };
      }

      const flowNode = toFlowNode(newNodeData);
      setNodes(prev => [...prev, flowNode]);
      setSelectedNodeId(flowNode.id);
    } catch (err) {
      console.error("Drop failed", err);
    }
  }, [screenToFlowPosition, setNodes]);

  // [UPDATED] Adds the agent as a comprehensive subgraph via Compiler
  const addAgentToGraph = useCallback((config: AgentConfiguration) => {
    // 1. Compile the config into a subgraph
    const { nodes: newIOINodes, edges: newIOIEdges } = compileAgentToGraph(config);

    // 2. Convert to ReactFlow format
    const newFlowNodes = newIOINodes.map(toFlowNode);
    const newFlowEdges = newIOIEdges.map(toFlowEdge);

    // 3. Replace existing graph (Builder Handoff implies new workspace context)
    setNodes(newFlowNodes);
    setEdges(newFlowEdges);
    
    // 4. Select the core model node for immediate inspection
    const coreNode = newFlowNodes.find(n => n.data.type === "model");
    if (coreNode) {
        setSelectedNodeId(coreNode.id);
    }
    
    // 5. Fit view after render cycle
    setTimeout(() => fitView({ duration: 800 }), 100);

  }, [setNodes, setEdges, setSelectedNodeId, fitView]);

  // Handle Ghost Mode inference (Mock)
  const injectGhostNode = useCallback(() => {
    const ghostNode: IOINode = {
      id: "n-ghost", type: "action", name: "Verify Stripe", x: 1000, y: 350,
      status: "idle", ioTypes: { in: "Invoice", out: "Bool" }, isGhost: true
    };
    setNodes(prev => { 
      if (prev.find(n => n.id === "n-ghost")) return prev; 
      return [...prev, toFlowNode(ghostNode)]; 
    });
    
    const ghostEdge: IOIEdge = {
      id: "e-ghost", from: "n-3", to: "n-ghost", fromPort: "out", toPort: "in", type: "data", active: true
    };
    setEdges(prev => { 
      if (prev.find(e => e.id === "e-ghost")) return prev; 
      return [...prev, toFlowEdge(ghostEdge)]; 
    });
  }, [setNodes, setEdges]);

  const clearGhostNodes = useCallback(() => {
    setNodes(prev => prev.filter(n => n.id !== "n-ghost"));
    setEdges(prev => prev.filter(e => e.id !== "e-ghost"));
  }, [setNodes, setEdges]);

  return {
    nodes, edges, selectedNodeId, setSelectedNodeId,
    setNodes, setEdges, onNodesChange, onEdgesChange, onConnect,
    handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    addAgentToGraph, // Handles Builder -> Graph compilation
    injectGhostNode, clearGhostNodes,
    fitView, zoomIn, zoomOut
  };
}