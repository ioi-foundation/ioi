import { useState, useEffect, useCallback } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
// Go up 3 levels: hooks -> StudioWindow -> windows -> src
import { Node as IOINode } from "../../../types";
// Go up 1 level: hooks -> StudioWindow (where types.ts resides)
import { NodeArtifacts, ExecutionLog, ExecutionStep, GraphGlobalConfig } from "../types.ts";

export function useGraphExecution(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  nodes: any[], 
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  edges: any[], 
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setNodes: React.Dispatch<React.SetStateAction<any[]>>,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  setEdges: React.Dispatch<React.SetStateAction<any[]>>
) {
  const [nodeArtifacts, setNodeArtifacts] = useState<NodeArtifacts>({});
  const [executionLogs, setExecutionLogs] = useState<ExecutionLog[]>([]);
  const [executionSteps, setExecutionSteps] = useState<ExecutionStep[]>([]);

  // Listen for Rust backend events
  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const unlisten = listen<any>("graph-event", (event) => {
      const { node_id, status, result } = event.payload;
      const timestamp = new Date().toISOString();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const nodeName = nodes.find((n: any) => n.id === node_id)?.data?.name || node_id;
      
      // 1. Visual Status Update
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      setNodes((nds: any[]) => nds.map((n) => {
        if (n.id === node_id) return { ...n, data: { ...n.data, status } };
        return n;
      }));

      // 2. Logs
      const logLevel = status === "error" || status === "failed" ? "error" : status === "blocked" ? "warn" : "info";
      
      // EXPLICIT TYPE ANNOTATION HERE
      setExecutionLogs((prev: ExecutionLog[]) => [...prev, {
        id: `log-${Date.now()}-${Math.random()}`,
        timestamp,
        level: logLevel,
        source: nodeName,
        message: result?.output || `Status update: ${status}`
      }]);

      // 3. Timeline
      // EXPLICIT TYPE ANNOTATION HERE
      setExecutionSteps((prev: ExecutionStep[]) => {
        const existing = prev.findIndex(s => s.id === node_id);
        const step: ExecutionStep = {
            id: node_id,
            name: nodeName,
            status,
            timestamp,
            duration: result?.metrics?.latency_ms ? `${result.metrics.latency_ms}ms` : undefined,
            dataCount: result?.output?.length
        };
        
        if (existing >= 0) {
            const newSteps = [...prev];
            newSteps[existing] = step;
            return newSteps;
        }
        return [...prev, step];
      });

      // 4. Artifacts
      if (result) {
        setNodeArtifacts((prev: NodeArtifacts) => ({
          ...prev,
          [node_id]: { output: result.output, metrics: result.metrics, timestamp: Date.now() }
        }));
      }

      // 5. Edge Animation
      if (status === "success") {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        setEdges((eds: any[]) => eds.map((e) => {
          if (e.source === node_id) {
            return { ...e, animated: true, style: { stroke: '#3D85C6', strokeWidth: 3 } };
          }
          return e;
        }));
      }
    });

    return () => { unlisten.then(f => f()); };
  }, [nodes, setNodes, setEdges]);

  // Run the Graph
  const runGraph = useCallback(async (graphConfig: GraphGlobalConfig) => {
    // Reset state
    setNodeArtifacts({});
    setExecutionLogs([]);
    setExecutionSteps([]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setNodes((nds: any[]) => nds.map(n => ({ ...n, data: { ...n.data, status: "idle" } })));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setEdges((eds: any[]) => eds.map(e => ({ ...e, animated: false, style: { stroke: '#2E333D', strokeWidth: 2 } })));

    const payload = {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      nodes: nodes.map((n: any) => ({
        id: n.id,
        type: n.type || "action",
        config: (n.data as IOINode).config || { logic: {}, law: {} }
      })),
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      edges: edges.map((e: any) => ({
        source: e.source,
        target: e.target,
        sourceHandle: e.sourceHandle 
      })),
      global_config: {
        env: graphConfig.env,
        policy: graphConfig.policy,
        meta: graphConfig.meta
      }
    };

    try {
      await invoke("run_studio_graph", { payload });
    } catch (e) {
      console.error("Execution failed:", e);
      // EXPLICIT TYPE ANNOTATION HERE
      setExecutionLogs((prev: ExecutionLog[]) => [...prev, {
          id: `err-${Date.now()}`,
          timestamp: new Date().toISOString(),
          level: "error",
          source: "Orchestrator",
          message: `Failed to start: ${e}`
      }]);
    }
  }, [nodes, edges, setNodes, setEdges]);

  // Single Node Run (Debug)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeRunComplete = useCallback((nodeId: string, result: any) => {
    setNodeArtifacts((prev: NodeArtifacts) => ({
      ...prev,
      [nodeId]: { output: result.output, metrics: result.metrics, timestamp: Date.now() }
    }));
    // EXPLICIT TYPE ANNOTATION HERE
    setExecutionLogs((prev: ExecutionLog[]) => [...prev, {
        id: `unit-${Date.now()}`,
        timestamp: new Date().toISOString(),
        level: "info",
        source: "Unit Test",
        message: `Manually executed node ${nodeId}`
    }]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setNodes((nds: any[]) => nds.map((n) => n.id === nodeId ? { ...n, data: { ...n.data, status: "success" } } : n));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setEdges((eds: any[]) => eds.map((e) => e.source === nodeId ? { ...e, animated: true, style: { stroke: '#3D85C6', strokeWidth: 3 } } : e));
  }, [setNodes, setEdges]);

  const getUpstreamContext = useCallback((targetNodeId: string): string => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const incomingEdges = edges.filter((e: any) => e.target === targetNodeId);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const inputs = incomingEdges.map((edge: any) => nodeArtifacts[edge.source]?.output || "").filter(Boolean);
    return inputs.join("\n---\n");
  }, [edges, nodeArtifacts]);

  return {
    nodeArtifacts, executionLogs, executionSteps,
    runGraph, handleNodeRunComplete, getUpstreamContext
  };
}
