// FILE: src/windows/StudioWindow/templates.ts
import { NodeLaw, NodeLogic } from "../../types";

export interface NodeTemplate {
  type: string;
  name: string; // Display name
  ioTypes: { in: string; out: string };
  defaultConfig: {
    logic: NodeLogic;
    law: NodeLaw;
  };
}

export const NODE_TEMPLATES: Record<string, NodeTemplate> = {
  // --- GOVERNANCE PRIMITIVES ---
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

  // --- TOOLS ---
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

  // --- MODELS ---
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