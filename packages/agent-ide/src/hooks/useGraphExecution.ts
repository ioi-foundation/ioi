import { useState, useEffect, useCallback } from "react";
import { AgentRuntime, GraphPayload } from "../runtime/agent-runtime";
import { GraphGlobalConfig } from "../types/graph";

// Internal state for visual feedback
interface ExecutionState {
    logs: any[];
    nodeStatus: Record<string, string>;
    artifacts: Record<string, any>;
    isRunning: boolean;
}

export function useGraphExecution(
    runtime: AgentRuntime,
    nodes: any[],
    edges: any[],
    setNodes: any,
    setEdges: any
) {
    const [state, setState] = useState<ExecutionState>({
        logs: [],
        nodeStatus: {},
        artifacts: {},
        isRunning: false
    });

    // 1. Listen for Runtime Events
    useEffect(() => {
        const unsubscribe = runtime.onEvent((event) => {
            const { node_id, status, result } = event;
            
            // Update local state
            setState(prev => ({
                ...prev,
                nodeStatus: { ...prev.nodeStatus, [node_id]: status },
                artifacts: result ? { ...prev.artifacts, [node_id]: result } : prev.artifacts,
                logs: [...prev.logs, {
                    id: Date.now(),
                    source: node_id,
                    message: result?.output || `Status: ${status}`,
                    level: status === 'error' ? 'error' : 'info'
                }]
            }));

            // Update ReactFlow Nodes (Visuals)
            setNodes((nds: any[]) => nds.map((n) => {
                if (n.id === node_id) {
                    return { ...n, data: { ...n.data, status, metrics: result?.metrics } };
                }
                return n;
            }));

            // Update Edges (Traffic)
            if (status === 'success' || status === 'error') {
                setEdges((eds: any[]) => eds.map((e: any) => {
                    if (e.source === node_id) {
                        return { ...e, animated: true, style: { stroke: status === 'error' ? 'red' : '#3D85C6' } };
                    }
                    return e;
                }));
            }
        });

        return () => unsubscribe();
    }, [runtime, setNodes, setEdges]);

    // 2. Run Graph
    const runGraph = useCallback(async (globalConfig: GraphGlobalConfig) => {
        setState(prev => ({ ...prev, isRunning: true, logs: [], nodeStatus: {} }));
        
        // Reset Visuals
        setNodes((nds: any[]) => nds.map((n) => ({ ...n, data: { ...n.data, status: 'idle' } })));
        setEdges((eds: any[]) => eds.map((e: any) => ({ ...e, animated: false })));

        const payload: GraphPayload = {
            nodes: nodes.map(n => ({
                id: n.id,
                type: n.type,
                config: n.data.config
            })),
            edges: edges.map(e => ({
                source: e.source,
                target: e.target,
                sourceHandle: e.sourceHandle
            })),
            global_config: globalConfig
        };

        try {
            await runtime.runGraph(payload);
        } catch (e) {
            console.error("Execution failed", e);
            setState(prev => ({ ...prev, isRunning: false }));
        }
    }, [runtime, nodes, edges, setNodes, setEdges]);

    // 3. Run Single Node
    const runNode = useCallback(async (nodeId: string) => {
        const node = nodes.find(n => n.id === nodeId);
        if (!node) return;
        
        const result = await runtime.runNode(node.type!, node.data.config, "{}");
        
        setState(prev => ({
            ...prev,
            artifacts: { ...prev.artifacts, [nodeId]: result }
        }));
    }, [runtime, nodes]);

    // [NEW] 4. Context Hydration Logic
    const getUpstreamContext = useCallback((targetNodeId: string): any => {
        const incomingEdges = edges.filter((e: any) => e.target === targetNodeId);
        const mergedContext: Record<string, any> = {};
        
        incomingEdges.forEach((edge: any) => {
            const artifact = state.artifacts[edge.source];
            if (artifact?.output) {
                try {
                    const parsed = JSON.parse(artifact.output);
                    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
                        Object.assign(mergedContext, parsed);
                    } else {
                        mergedContext[edge.source] = parsed;
                    }
                } catch {
                    mergedContext[edge.source] = artifact.output;
                }
            }
        });
        
        return Object.keys(mergedContext).length > 0 ? mergedContext : null;
    }, [edges, state.artifacts]);

    return {
        ...state,
        runGraph,
        runNode,
        getUpstreamContext // [FIX] Exported
    };
}