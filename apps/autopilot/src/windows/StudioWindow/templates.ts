// apps/autopilot/src/windows/StudioWindow/templates.ts
import { NodeLaw, NodeLogic } from "../../types";

export interface NodeTemplate {
  type: string;
  name: string;
  ioTypes: { in: string; out: string };
  defaultConfig: {
    logic: NodeLogic;
    law: NodeLaw;
  };
}

export const NODE_TEMPLATES: Record<string, NodeTemplate> = {
  // === COMPETITOR PARITY: CORE BLOCKS ===

  // 1. Function Block (Code Execution)
  "code-python": {
    type: "code",
    name: "Python Worker",
    ioTypes: { in: "JSON", out: "JSON" },
    defaultConfig: {
      logic: {
        language: "python",
        code: "def main(input):\n    # Transform data here\n    return {\"processed\": True, \"data\": input}",
      },
      law: {
        // Governance: Code execution is dangerous, default to sandboxed + budget
        budgetCap: 0.10, 
        privacyLevel: "masked",
      },
    },
  },

  // 2. Condition/Router Block (Branching)
  "semantic-router": {
    type: "router",
    name: "Semantic Router",
    ioTypes: { in: "Text", out: "Dynamic" }, // 'Dynamic' signals the CanvasNode to render multiple ports
    defaultConfig: {
      logic: {
        model: "local-embeddings",
        routerInstruction: "Classify the intent of the input text.",
        routes: ["Route A", "Route B"],
      },
      law: {},
    },
  },

  // 3. Wait Block (Control Flow)
  "wait-timer": {
    type: "wait",
    name: "Delay / Sleep",
    ioTypes: { in: "Any", out: "Any" },
    defaultConfig: {
      logic: {
        durationMs: 5000,
      },
      law: {},
    },
  },

  // 4. Variables Block (Context State)
  "set-variables": {
    type: "context",
    name: "Set Variables",
    ioTypes: { in: "Any", out: "Context" },
    defaultConfig: {
      logic: {
        variables: {
          "user_status": "active",
          "last_step": "{{input.step}}"
        },
      },
      law: {},
    },
  },

  // 5. RSS Feed (Trigger)
  "rss-monitor": {
    type: "trigger",
    name: "RSS Monitor",
    ioTypes: { in: "—", out: "Article" },
    defaultConfig: {
      logic: {
        rssUrl: "https://news.ycombinator.com/rss",
        cronSchedule: "*/15 * * * *", // Poll every 15m
      },
      law: {
        networkAllowlist: ["news.ycombinator.com"],
      },
    },
  },

  // [NEW] Semantic Retrieval (RAG)
  "retrieval-rag": {
    type: "retrieval",
    name: "Knowledge Search",
    ioTypes: { in: "Query", out: "Context" },
    defaultConfig: {
      logic: {
        // Default to passing the raw input as the search query
        // User can change this to "{{input.question}}" etc.
        query: "{{input}}", 
        limit: 3,
      },
      law: {
        // Safe by default: Read-only access to local memory
        privacyLevel: "zero-knowledge", 
      },
    },
  },

  // === IOI UNIQUE VALUE: GOVERNANCE BLOCKS ===

  "agency-firewall": {
    type: "gate",
    name: "Agency Firewall",
    ioTypes: { in: "Any", out: "Any" },
    defaultConfig: {
      logic: {
        conditionScript: "input.risk_score < 0.7",
      },
      law: {
        requireHumanGate: true,
        retryPolicy: { maxAttempts: 0, backoffMs: 0 },
      },
    },
  },
  "approval-gate": {
    type: "gate",
    name: "Manager Approval",
    ioTypes: { in: "Proposal", out: "Signal" },
    defaultConfig: {
      logic: { conditionScript: "true" }, // Logic passes, Law stops it
      law: { requireHumanGate: true },
    },
  },

  // === TOOLS ===
  "stripe": {
    type: "tool",
    name: "Stripe API",
    ioTypes: { in: "PaymentIntent", out: "Receipt" },
    defaultConfig: {
      logic: {
        method: "POST",
        endpoint: "https://api.stripe.com/v1/charges",
        bodyTemplate: '{\n  "amount": {{amount}},\n  "currency": "usd"\n}',
      },
      law: {
        networkAllowlist: ["api.stripe.com"],
        budgetCap: 50.0, // Hard limit for financial nodes
        privacyLevel: "masked",
      },
    },
  },
  "slack": {
    type: "tool",
    name: "Slack Notify",
    ioTypes: { in: "Message", out: "Ack" },
    defaultConfig: {
      logic: {
        method: "POST",
        endpoint: "https://hooks.slack.com/services/...",
        bodyTemplate: '{"text": "{{message}}"}',
      },
      law: {
        networkAllowlist: ["hooks.slack.com"],
      },
    },
  },

  // === MODELS ===
  "local-llm": {
    type: "model",
    name: "Llama 3 (Local)",
    ioTypes: { in: "Context", out: "Text" },
    defaultConfig: {
      logic: {
        model: "llama3",
        temperature: 0.7,
        systemPrompt: "You are a helpful assistant running locally.",
      },
      law: {
        privacyLevel: "zero-knowledge", // No data leaves device
      },
    },
  },
};