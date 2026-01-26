// src/windows/StudioWindow/hooks/useGraphExecution.ts
import { useState, useEffect, useCallback, useMemo } from "react";
import { listen } from "@tauri-apps/api/event";
import { invoke } from "@tauri-apps/api/core";
import { Node as IOINode } from "../../../types";
import { NodeArtifacts, ExecutionLog, ExecutionStep, GraphGlobalConfig } from "../types.ts";
import { TraceSpan } from "../../../components/TraceViewer";

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
  const [isExecuting, setIsExecuting] = useState(false);

  // [NEW] Cache Rehydration Effect
  // Checks if backend has cached results for current node configs to show "ready" state immediately
  useEffect(() => {
    // Debounce to avoid flooding IPC on every keystroke
    const timer = setTimeout(() => {
      nodes.forEach(async (node) => {
        // Skip if we already have data
        if (nodeArtifacts[node.id]) return;

        try {
          // Construct the same context input string the Orchestrator would use
          // (Simplified for MVP: Empty context or default)
          const inputStr = "{}"; // In full version, this needs to calculate upstream inputs
          
          const result = await invoke("check_node_cache", {
             nodeId: node.id,
             config: node.data.config.logic,
             input: inputStr
          });
          
          if (result) {
             // @ts-ignore
             const res = result as any;
             console.log(`[Cache] Rehydrated ${node.id}`);
             setNodeArtifacts(prev => ({
                 ...prev,
                 [node.id]: {
                     output: res.output,
                     metrics: res.metrics,
                     timestamp: Date.now(),
                     input_snapshot: res.input_snapshot
                 }
             }));
             
             // Visual indication
             // eslint-disable-next-line @typescript-eslint/no-explicit-any
             setNodes((nds: any[]) => nds.map((n) => {
                if (n.id === node.id) {
                    return { 
                        ...n, 
                        data: { 
                            ...n.data, 
                            status: 'success',
                            metrics: res.metrics // Hydrate metrics from cache
                        } 
                    };
                }
                return n;
             }));
          }
        } catch (e) {
           // Ignore cache check errors
        }
      });
    }, 500);
    return () => clearTimeout(timer);
  }, [nodes.length]); // Re-run when node count changes (add/remove)

  // Listen for Rust backend events
  useEffect(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const unlisten = listen<any>("graph-event", (event) => {
      const { node_id, status, result, fitness_score, generation } = event.payload;
      const timestamp = new Date().toISOString();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const nodeName = nodes.find((n: any) => n.id === node_id)?.data?.name || node_id;
      
      // 1. Visual Status & Metrics Update
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      setNodes((nds: any[]) => nds.map((n) => {
        if (n.id === node_id) {
            const currentMetrics = n.data.metrics || {};
            // Merge new metrics if available (including evolutionary data)
            const newMetrics = {
              ...currentMetrics,
              ...(result?.metrics || {}),
              ...(fitness_score !== undefined ? { fitness_score } : {}),
              ...(generation !== undefined ? { generation } : {})
            };

            return { 
                ...n, 
                data: { 
                    ...n.data, 
                    status,
                    metrics: newMetrics
                } 
            };
        }
        return n;
      }));

      // 2. Logs
      const logLevel = status === "error" || status === "failed" ? "error" : status === "blocked" ? "warn" : "info";
      
      setExecutionLogs((prev: ExecutionLog[]) => [...prev, {
        id: `log-${Date.now()}-${Math.random()}`,
        timestamp,
        level: logLevel,
        source: nodeName,
        message: result?.output || `Status update: ${status}`
      }]);

      // 3. Timeline Step
      setExecutionSteps((prev: ExecutionStep[]) => {
        const existingIdx = prev.findIndex(s => s.id === node_id);
        const step: ExecutionStep = {
            id: node_id,
            name: nodeName,
            status,
            timestamp,
            duration: result?.metrics?.latency_ms ? `${result.metrics.latency_ms}ms` : undefined,
            dataCount: result?.output?.length
        };
        
        if (existingIdx >= 0) {
            const newSteps = [...prev];
            newSteps[existingIdx] = { ...newSteps[existingIdx], ...step };
            return newSteps;
        }
        return [...prev, step];
      });

      // 4. Artifacts
      if (result) {
        setNodeArtifacts((prev: NodeArtifacts) => ({
          ...prev,
          [node_id]: { 
              output: result.output, 
              metrics: result.metrics, 
              timestamp: Date.now(),
              // [NEW] Capture the input snapshot for observability
              input_snapshot: result.input_snapshot 
          }
        }));
      }

      // 5. Semantic Edge Routing (Visual Traffic Control)
      if (status === "success" || status === "blocked" || status === "error" || status === "failed") {
        // Map execution status to the corresponding source handle ID
        let targetHandleId = "out"; // Default success path
        
        if (status === "blocked") {
            targetHandleId = "blocked"; // Governance/Policy path
        } else if (status === "error" || status === "failed") {
            targetHandleId = "error"; // Runtime Failure path
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        setEdges((eds: any[]) => eds.map((e) => {
          // Only affect edges originating from this node
          if (e.source === node_id) {
            // Check if this edge is connected to the active handle
            if (e.sourceHandle === targetHandleId) {
              return { 
                ...e, 
                data: { ...e.data, active: true, status: status },
                animated: true // Optional: ReactFlow marker
              };
            } else {
              // Deactivate other paths (e.g., success path if blocked)
              return { 
                ...e, 
                data: { ...e.data, active: false, status: 'idle' },
                animated: false 
              };
            }
          }
          return e;
        }));
      }
    });

    return () => { unlisten.then(f => f()); };
  }, [nodes, setNodes, setEdges]);

  // Transform flat steps into hierarchical TraceSpans for the TraceViewer
  const traceData = useMemo(() => {
    return buildTraceTree(executionSteps);
  }, [executionSteps]);

  // Run the Graph
  const runGraph = useCallback(async (graphConfig: GraphGlobalConfig) => {
    setIsExecuting(true);
    // Reset state
    setNodeArtifacts({});
    setExecutionLogs([]);
    setExecutionSteps([]);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setNodes((nds: any[]) => nds.map(n => ({ ...n, data: { ...n.data, status: "idle" } })));
    
    // Reset Edges to idle
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setEdges((eds: any[]) => eds.map(e => ({ 
      ...e, 
      animated: false, 
      data: { ...e.data, active: false, status: 'idle' }
    })));

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
      setExecutionLogs((prev: ExecutionLog[]) => [...prev, {
          id: `err-${Date.now()}`,
          timestamp: new Date().toISOString(),
          level: "error",
          source: "Orchestrator",
          message: `Failed to start: ${e}`
      }]);
    } finally {
      // Small delay to allow final events to settle
      setTimeout(() => setIsExecuting(false), 500);
    }
  }, [nodes, edges, setNodes, setEdges]);

  // Single Node Run (Debug)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleNodeRunComplete = useCallback((nodeId: string, result: any) => {
    setNodeArtifacts((prev: NodeArtifacts) => ({
      ...prev,
      [nodeId]: { 
          output: result.output, 
          metrics: result.metrics, 
          timestamp: Date.now(),
          // [NEW] Capture input snapshot from unit tests too
          input_snapshot: result.input_snapshot 
      }
    }));
    
    setExecutionLogs((prev: ExecutionLog[]) => [...prev, {
        id: `unit-${Date.now()}`,
        timestamp: new Date().toISOString(),
        level: "info",
        source: "Unit Test",
        message: `Manually executed node ${nodeId}`
    }]);
    
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setNodes((nds: any[]) => nds.map((n) => n.id === nodeId ? { 
        ...n, 
        data: { 
            ...n.data, 
            status: "success",
            // Merge metrics from unit test result
            metrics: { ...n.data.metrics, ...(result.metrics || {}) }
        } 
    } : n));
    
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setEdges((eds: any[]) => eds.map((e) => {
        if (e.source === nodeId) {
             // For unit tests, we default to success path unless result implies otherwise
             if (e.sourceHandle === 'out') {
                return { 
                    ...e, 
                    data: { ...e.data, active: true, status: 'success' },
                    animated: true 
                };
             }
        }
        return e;
    }));
  }, [setNodes, setEdges]);

  // Context-Aware Data Hydration
  // Transforms upstream artifacts into a JSON object that matches the Rust Orchestrator's behavior.
  const getUpstreamContext = useCallback((targetNodeId: string): string => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const incomingEdges = edges.filter((e: any) => e.target === targetNodeId);
    
    const mergedContext: Record<string, any> = {};
    
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    incomingEdges.forEach((edge: any) => {
      const artifact = nodeArtifacts[edge.source];
      if (artifact?.output) {
        try {
          // 1. Try to treat upstream output as structured data (JSON)
          const parsed = JSON.parse(artifact.output);
          
          if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
            // Flatten objects into the root context (simulating environment injection)
            Object.assign(mergedContext, parsed);
          } else {
            // Arrays or Primitives get keyed by source ID to avoid root pollution
            mergedContext[edge.source] = parsed;
          }
        } catch (e) {
          // 2. Fallback: Raw text output (e.g. LLM prose)
          // Key it by source ID so it can be referenced like {{n-123}}
          mergedContext[edge.source] = artifact.output;
        }
      }
    });

    // Return empty string if no context, allowing the UI to fallback to variable scaffolding
    if (Object.keys(mergedContext).length === 0) {
      return "";
    }

    return JSON.stringify(mergedContext, null, 2);
  }, [edges, nodeArtifacts]);

  return {
    nodeArtifacts, 
    executionLogs, 
    executionSteps,
    traceData, // Export the transformed tree
    isExecuting,
    runGraph, 
    handleNodeRunComplete, 
    getUpstreamContext
  };
}

// --- Helper: Trace Transformer ---
function buildTraceTree(steps: ExecutionStep[]): TraceSpan[] {
  if (steps.length === 0) return [];

  // Sort by timestamp to ensure chronological order
  const sortedSteps = [...steps].sort((a, b) => 
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const startSpan = sortedSteps[0];
  const startTime = new Date(startSpan.timestamp).getTime();
  
  // Calculate end time based on the last step
  const lastStep = sortedSteps[sortedSteps.length - 1];
  const lastDuration = parseDuration(lastStep.duration);
  const endTime = new Date(lastStep.timestamp).getTime() + lastDuration;

  // Determine global status
  const hasError = steps.some(s => s.status === "error");
  const isRunning = steps.some(s => s.status === "running");
  const status = hasError ? "error" : isRunning ? "running" : "success";

  const rootSpan: TraceSpan = {
    id: "run-root",
    name: "Graph Execution",
    type: "chain",
    status,
    startTime,
    endTime,
    metadata: {
      model: "Orchestrator",
      inputs: { nodeCount: steps.length }
    },
    children: sortedSteps.map(step => mapStepToSpan(step))
  };

  return [rootSpan];
}

function mapStepToSpan(step: ExecutionStep): TraceSpan {
  const start = new Date(step.timestamp).getTime();
  const duration = parseDuration(step.duration);
  
  // Map our internal status to TraceSpan status
  let status: "running" | "success" | "error" = "success";
  if (step.status === "running") status = "running";
  if (step.status === "error") status = "error";
  // Map "blocked" (Governance) to "error" for visual attention
  if (step.status === "blocked") status = "error"; 

  // Guess type based on name or ID if not explicitly provided
  const type = step.name.toLowerCase().includes("gate") ? "tool" : "agent";

  return {
    id: step.id,
    name: step.name,
    type,
    status,
    startTime: start,
    endTime: start + duration,
    metadata: {
      outputs: { dataCount: step.dataCount }
    }
  };
}

function parseDuration(dur?: string): number {
  if (!dur) return 100; // Default visual width
  if (dur.endsWith("ms")) return parseInt(dur);
  if (dur.endsWith("s")) return parseFloat(dur) * 1000;
  return 100;
}