import { useState, useEffect, useCallback } from "react";
import {
    AgentWorkbenchRuntime,
    GraphCapabilityCatalog,
    GraphModelBindingCatalog,
    GraphPayload,
} from "../runtime/agent-runtime";
import { GraphGlobalConfig } from "../types/graph";

// Internal state for visual feedback
interface ExecutionState {
    logs: any[];
    nodeStatus: Record<string, string>;
    artifacts: Record<string, any>;
    isRunning: boolean;
}

const UNRUNNABLE_MODEL_STATUSES = new Set([
    "failed",
    "cancelled",
    "queued",
    "installing",
    "loading",
    "unloading",
]);

function modelStatusIsRunnable(status?: string): boolean {
    if (!status) return false;
    return !UNRUNNABLE_MODEL_STATUSES.has(status.trim().toLowerCase());
}

const NODE_TYPES_BY_CAPABILITY: Record<string, string[]> = {
    reasoning: ["responses", "model"],
    vision: ["vision_read"],
    embedding: ["embeddings"],
    image: ["generate_image", "edit_image"],
    speech: ["synthesize_speech"],
    video: ["generate_video"],
};

const MODEL_BOUND_CAPABILITY_KEYS = new Set(["reasoning", "vision", "embedding", "image"]);

export function useGraphExecution(
    runtime: AgentWorkbenchRuntime,
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

    const runBindingPreflight = useCallback(
        async (globalConfig: GraphGlobalConfig): Promise<boolean> => {
            const [bindingCatalog, capabilityCatalog]: [
                GraphModelBindingCatalog | null,
                GraphCapabilityCatalog | null,
            ] = await Promise.all([
                runtime.getGraphModelBindingCatalog
                    ? runtime.getGraphModelBindingCatalog().catch(() => null)
                    : Promise.resolve(null),
                runtime.getGraphCapabilityCatalog
                    ? runtime.getGraphCapabilityCatalog().catch(() => null)
                    : Promise.resolve(null),
            ]);

            const catalogById = new Map(
                (bindingCatalog?.models ?? []).map((model) => [model.modelId, model] as const)
            );
            const capabilityCatalogById = new Map(
                (capabilityCatalog?.capabilities ?? []).map((capability) => [
                    capability.capabilityId,
                    capability,
                ] as const)
            );
            const preflightErrors: Array<{ nodeId?: string; message: string }> = [];

            Object.entries(globalConfig.modelBindings || {}).forEach(([bindingKey, binding]) => {
                const modelId = binding?.modelId?.trim();
                if (binding?.required && !modelId) {
                    preflightErrors.push({
                        message: `Required graph model binding '${bindingKey}' does not have a model id yet.`,
                    });
                }
            });

            Object.entries(globalConfig.requiredCapabilities || {}).forEach(
                ([capabilityKey, requirement]: [string, any]) => {
                    if (!requirement?.required) return;

                    const impactedNodeIds = new Set(
                        nodes
                            .filter((node: any) =>
                                (NODE_TYPES_BY_CAPABILITY[capabilityKey] ?? []).includes(node.type)
                            )
                            .map((node: any) => node.id)
                    );

                    const pushCapabilityError = (message: string) => {
                        if (impactedNodeIds.size === 0) {
                            preflightErrors.push({ message });
                            return;
                        }

                        impactedNodeIds.forEach((nodeId) => {
                            preflightErrors.push({ nodeId, message });
                        });
                    };

                    const runtimeCapability = capabilityCatalogById.get(capabilityKey);
                    if (!runtimeCapability || runtimeCapability.availableCount === 0) {
                        pushCapabilityError(
                            `Graph capability '${capabilityKey}' is marked required, but Local Engine does not currently surface that family. Resolve it in Settings -> Local Engine before running this workflow.`
                        );
                        return;
                    }

                    if (MODEL_BOUND_CAPABILITY_KEYS.has(capabilityKey)) {
                        const bindingKey = String(
                            requirement.bindingKey || capabilityKey
                        ).trim();
                        const binding = globalConfig.modelBindings?.[bindingKey];
                        const modelId = String(binding?.modelId || "").trim();
                        if (!modelId) {
                            pushCapabilityError(
                                `Graph capability '${capabilityKey}' requires model binding '${bindingKey}', but that slot is not configured. Resolve it in graph settings or Local Engine before running this workflow.`
                            );
                            return;
                        }

                        if (bindingCatalog) {
                            const record = catalogById.get(modelId);
                            if (!record) {
                                pushCapabilityError(
                                    `Graph capability '${capabilityKey}' expects model '${modelId}', but Local Engine does not currently expose that model.`
                                );
                                return;
                            }

                            if (!modelStatusIsRunnable(record.status)) {
                                pushCapabilityError(
                                    `Graph capability '${capabilityKey}' expects model '${modelId}', but Local Engine reports status '${record.status}'.`
                                );
                            }
                        }
                    }
                }
            );

            nodes.forEach((node: any) => {
                const logic = node?.data?.config?.logic || {};
                const modelRef = String(logic.modelRef || "").trim();
                if (!modelRef) return;

                const binding = globalConfig.modelBindings?.[modelRef];
                const modelId = binding?.modelId?.trim();
                if (!binding || !modelId) {
                    preflightErrors.push({
                        nodeId: node.id,
                        message: `Node '${node.data?.name || node.id}' requires graph model binding '${modelRef}', but that slot is not configured.`,
                    });
                    return;
                }

                if (bindingCatalog) {
                    const record = catalogById.get(modelId);
                    if (!record) {
                        preflightErrors.push({
                            nodeId: node.id,
                            message: `Node '${node.data?.name || node.id}' resolves '${modelRef}' to '${modelId}', but Local Engine does not currently expose that model.`,
                        });
                        return;
                    }

                    if (!modelStatusIsRunnable(record.status)) {
                        preflightErrors.push({
                            nodeId: node.id,
                            message: `Node '${node.data?.name || node.id}' resolves '${modelRef}' to '${modelId}', but Local Engine reports status '${record.status}'.`,
                        });
                    }
                }
            });

            if (preflightErrors.length === 0) {
                return true;
            }

            const blockedNodeIds = new Set(
                preflightErrors
                    .map((entry) => entry.nodeId)
                    .filter((entry): entry is string => Boolean(entry))
            );

            setState((prev) => ({
                ...prev,
                isRunning: false,
                nodeStatus: {
                    ...prev.nodeStatus,
                    ...Array.from(blockedNodeIds).reduce<Record<string, string>>((acc, nodeId) => {
                        acc[nodeId] = "blocked";
                        return acc;
                    }, {}),
                },
                logs: preflightErrors.map((entry, index) => ({
                    id: Date.now() + index,
                    source: entry.nodeId || "graph",
                    message: entry.message,
                    level: "error",
                })),
            }));

            setNodes((nds: any[]) =>
                nds.map((node) =>
                    blockedNodeIds.has(node.id)
                        ? { ...node, data: { ...node.data, status: "blocked" } }
                        : node
                )
            );

            return false;
        },
        [nodes, runtime, setNodes]
    );

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

        const preflightPassed = await runBindingPreflight(globalConfig);
        if (!preflightPassed) {
            return;
        }

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
    }, [runtime, nodes, edges, setNodes, setEdges, runBindingPreflight]);

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
