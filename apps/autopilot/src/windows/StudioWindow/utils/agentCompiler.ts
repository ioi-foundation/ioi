import { Node as IOINode, Edge as IOIEdge, AgentConfiguration } from "../../../types";

const createId = () => {
  if (globalThis.crypto?.randomUUID) {
    return globalThis.crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
};

// Helper to calculate positions for a vertical layout
const BASE_X = 600;
const START_Y = 150;
const GAP_Y = 200;

export function compileAgentToGraph(config: AgentConfiguration): { nodes: IOINode[], edges: IOIEdge[] } {
  const nodes: IOINode[] = [];
  const edges: IOIEdge[] = [];
  let currentY = START_Y;
  let previousNodeId: string | null = null;

  // 1. Entry Point (Trigger)
  const triggerId = `trigger-${createId().slice(0, 8)}`;
  nodes.push({
    id: triggerId,
    type: "trigger",
    name: "Manual Input",
    x: BASE_X,
    y: currentY,
    status: "idle",
    ioTypes: { in: "—", out: "User Request" },
    inputs: [],
    outputs: ["out"],
    config: {
      logic: { cronSchedule: "" }, // Manual trigger
      law: {}
    }
  });
  previousNodeId = triggerId;
  currentY += GAP_Y;

  // 2. Memory / Retrieval (if implied by instructions or standard pattern)
  // For this compiler, we assume most agents benefit from context
  const retrievalId = `retr-${createId().slice(0, 8)}`;
  nodes.push({
    id: retrievalId,
    type: "retrieval",
    name: "Knowledge Recall",
    x: BASE_X,
    y: currentY,
    status: "idle",
    ioTypes: { in: "Query", out: "Context" },
    inputs: ["in"],
    outputs: ["out"],
    config: {
      logic: {
        query: "{{input}}", // Default to using the whole input as query
        limit: 5
      },
      law: { privacyLevel: "zero-knowledge" }
    }
  });
  
  edges.push({
    id: `e-${createId().slice(0, 6)}`,
    from: previousNodeId,
    to: retrievalId,
    fromPort: "out",
    toPort: "in",
    type: "data",
    active: false
  });
  
  previousNodeId = retrievalId;
  currentY += GAP_Y;

  // 3. The Core Agent (LLM)
  const modelId = `core-${createId().slice(0, 8)}`;
  nodes.push({
    id: modelId,
    type: "model",
    name: config.name || "Core Agent",
    x: BASE_X,
    y: currentY,
    status: "idle",
    ioTypes: { in: "Context", out: "Decision" },
    inputs: ["in"],
    outputs: ["out"],
    config: {
      logic: {
        model: config.model || "gpt-4o",
        temperature: config.temperature,
        // We inject the prompt from the builder
        systemPrompt: config.instructions
      },
      law: {
        budgetCap: 2.0 // Default budget for main agent
      }
    }
  });

  edges.push({
    id: `e-${createId().slice(0, 6)}`,
    from: previousNodeId,
    to: modelId,
    fromPort: "out",
    toPort: "in",
    type: "data",
    active: false
  });

  previousNodeId = modelId;
  currentY += GAP_Y;

  // 4. Tools (Branching)
  // If tools are defined, we create a specialized tool node or a router
  // For the MVP, we'll append a "Tools Executor" node if any tools are enabled
  if (config.tools && config.tools.length > 0) {
    const toolId = `tools-${createId().slice(0, 8)}`;
    nodes.push({
      id: toolId,
      type: "tool",
      name: "Tool Executor",
      x: BASE_X,
      y: currentY,
      status: "idle",
      ioTypes: { in: "Call", out: "Result" },
      inputs: ["in"],
      outputs: ["out"],
      config: {
        logic: {
          // In a real scenario, this would be a dynamic tool router
          // Here we represent it as a generic capability
          endpoint: "local://mcp-router", 
          method: "POST"
        },
        law: {
          requireHumanGate: true // Safety first for tools
        }
      }
    });

    edges.push({
        id: `e-${createId().slice(0, 6)}`,
        from: previousNodeId,
        to: toolId,
        fromPort: "out",
        toPort: "in",
        type: "control", // Logic control flow
        active: false
    });
  }

  return { nodes, edges };
}
