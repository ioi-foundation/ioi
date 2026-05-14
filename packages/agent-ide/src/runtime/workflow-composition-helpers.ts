import type {
  WorkflowCanonicalPrimitive,
  WorkflowPaletteVisibility,
} from "./workflow-node-taxonomy";

export type WorkflowCompositionHelperId =
  | "agent_loop"
  | "coding_budget_recovery"
  | "telemetry_budget_chain"
  | "terminal_coding_loop";

export interface WorkflowCompositionHelperDefinition {
  helperId: WorkflowCompositionHelperId;
  label: string;
  description: string;
  canonicalPrimitive: WorkflowCanonicalPrimitive;
  paletteVisibility: WorkflowPaletteVisibility;
  searchAliases: string[];
}

export const WORKFLOW_COMPOSITION_HELPERS: WorkflowCompositionHelperDefinition[] =
  [
    {
      helperId: "agent_loop",
      label: "Agent loop",
      description:
        "Expands into typed source, agent step, memory, tool, decision, and output primitives.",
      canonicalPrimitive: "agent_step",
      paletteVisibility: "template",
      searchAliases: [
        "agent",
        "agent loop",
        "worker loop",
        "model loop",
        "tool use",
        "reasoning",
        "memory",
        "output",
      ],
    },
    {
      helperId: "coding_budget_recovery",
      label: "Coding budget recovery",
      description:
        "Prewires daemon-backed coding budget request, approval, rejection, and retry primitives.",
      canonicalPrimitive: "recovery",
      paletteVisibility: "template",
      searchAliases: [
        "coding",
        "budget",
        "recovery",
        "approval",
        "retry",
        "coding tool budget",
        "blocked run",
      ],
    },
    {
      helperId: "telemetry_budget_chain",
      label: "Telemetry budget chain",
      description:
        "Prewires usage, context budget, compaction, and coding-tool budget gate primitives.",
      canonicalPrimitive: "policy_gate",
      paletteVisibility: "template",
      searchAliases: [
        "telemetry",
        "usage",
        "budget",
        "context budget",
        "compaction",
        "policy",
        "gate",
      ],
    },
    {
      helperId: "terminal_coding_loop",
      label: "Terminal coding loop",
      description:
        "Prewires daemon-backed coding tools that mirror the TUI slash loop and run-inspector evidence.",
      canonicalPrimitive: "tool_pack",
      paletteVisibility: "template",
      searchAliases: [
        "terminal",
        "terminal coding",
        "terminal coding loop",
        "tui",
        "slash loop",
        "shell",
        "coding tool",
        "deepseek",
        "tool pack",
        "run inspector",
      ],
    },
  ];
