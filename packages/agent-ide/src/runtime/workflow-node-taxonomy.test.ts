import assert from "node:assert/strict";
import test from "node:test";
import {
  WORKFLOW_NODE_DEFINITIONS,
  workflowNodeCreatorDefinitions,
  workflowNodeDefinition,
} from "./workflow-node-registry";
import type {
  WorkflowCanonicalPrimitive,
  WorkflowPaletteVisibility,
} from "./workflow-node-taxonomy";

const REQUIRED_PRIMITIVES = new Set<WorkflowCanonicalPrimitive>([
  "trigger",
  "input",
  "context",
  "agent_step",
  "tool_pack",
  "connector",
  "memory",
  "skills",
  "hook",
  "policy_gate",
  "worker",
  "state",
  "control_flow",
  "verification",
  "recovery",
  "pull_request",
  "output",
  "harness_runtime",
]);

const REQUIRED_VISIBILITY = new Set<WorkflowPaletteVisibility>([
  "default",
  "template",
  "advanced",
  "hidden",
]);

function assertTaxonomyMetadata(item: {
  label: string;
  canonicalPrimitive: WorkflowCanonicalPrimitive;
  paletteVisibility: WorkflowPaletteVisibility;
  collapseTarget: string;
  displayLabel: string;
  advancedLabel: string;
  searchAliases: string[];
  configSections: string[];
  runtimeMapping: { executorId: string; contract: string; eventKinds: string[] };
  shapeProfile: { executionBoundary: WorkflowCanonicalPrimitive; statusTextEquivalent: string };
}) {
  assert.ok(
    REQUIRED_PRIMITIVES.has(item.canonicalPrimitive),
    `${item.label} has a known canonical primitive`,
  );
  assert.ok(
    REQUIRED_VISIBILITY.has(item.paletteVisibility),
    `${item.label} has a known palette visibility`,
  );
  assert.ok(item.collapseTarget, `${item.label} has a collapse target`);
  assert.ok(item.displayLabel, `${item.label} has a display label`);
  assert.ok(item.advancedLabel, `${item.label} has an advanced label`);
  assert.ok(item.searchAliases.length > 0, `${item.label} has search aliases`);
  assert.ok(item.configSections.length > 0, `${item.label} has config sections`);
  assert.ok(item.runtimeMapping.executorId, `${item.label} has executor mapping`);
  assert.ok(item.runtimeMapping.contract, `${item.label} has runtime contract`);
  assert.ok(
    item.runtimeMapping.eventKinds.includes("workflow_activation"),
    `${item.label} maps to workflow activation events`,
  );
  assert.equal(
    item.shapeProfile.executionBoundary,
    item.canonicalPrimitive,
    `${item.label} shape boundary matches primitive`,
  );
  assert.ok(
    item.shapeProfile.statusTextEquivalent,
    `${item.label} has color-independent status text`,
  );
}

test("all base node definitions carry executable taxonomy metadata", () => {
  assert.ok(WORKFLOW_NODE_DEFINITIONS.length > 0);
  for (const definition of WORKFLOW_NODE_DEFINITIONS) {
    assertTaxonomyMetadata(definition);
  }
});

test("all creator presets carry executable taxonomy metadata", () => {
  const creators = workflowNodeCreatorDefinitions();
  assert.ok(creators.length > WORKFLOW_NODE_DEFINITIONS.length);
  for (const creator of creators) {
    assertTaxonomyMetadata(creator);
  }
});

test("taxonomy projects over-expanded subsystem facets to canonical primitives", () => {
  assert.equal(workflowNodeDefinition("model_call").canonicalPrimitive, "agent_step");
  assert.equal(workflowNodeDefinition("model_call").displayLabel, "Agent Step");
  assert.equal(workflowNodeDefinition("model_binding").collapseTarget, "agent_step.model_route");
  assert.equal(workflowNodeDefinition("skill_context").canonicalPrimitive, "skills");
  assert.equal(workflowNodeDefinition("skill_pack").collapseTarget, "skills.pack");
  assert.equal(workflowNodeDefinition("hook_policy").collapseTarget, "hook.policy");
  assert.equal(workflowNodeDefinition("runtime_task").paletteVisibility, "advanced");
});

test("creator taxonomy covers memory, worker, mcp, skill, and computer-use authoring words", () => {
  const creators = new Map(
    workflowNodeCreatorDefinitions().map((creator) => [creator.creatorId, creator]),
  );

  assert.equal(creators.get("memory.search")?.canonicalPrimitive, "memory");
  assert.equal(creators.get("subagent.spawn")?.canonicalPrimitive, "worker");
  assert.equal(creators.get("mcp.tool.invoke")?.canonicalPrimitive, "tool_pack");
  assert.equal(creators.get("mcp.status")?.canonicalPrimitive, "connector");
  assert.equal(creators.get("skill_context.discover")?.canonicalPrimitive, "skills");
  assert.equal(creators.get("plugin_tool.coding_pack")?.canonicalPrimitive, "tool_pack");
  assert.equal(creators.get("plugin_tool.browser_use")?.canonicalPrimitive, "tool_pack");
  assert.equal(
    creators.get("plugin_tool.computer_use.visual_gui")?.canonicalPrimitive,
    "tool_pack",
  );
  assert.equal(
    creators.get("plugin_tool.computer_use.sandboxed")?.canonicalPrimitive,
    "tool_pack",
  );
  assert.equal(
    creators.get("computer_use.browser_discovery")?.canonicalPrimitive,
    "harness_runtime",
  );
  assert.equal(
    creators.get("computer_use.browser_discovery")?.paletteVisibility,
    "advanced",
  );
  assert.equal(
    creators.get("computer_use.browser_discovery")?.defaultLogic.toolBinding
      ?.arguments?.["computerUseBrowserDiscovery"],
    true,
  );
  const browserUseArguments =
    creators.get("plugin_tool.browser_use")?.defaultLogic.toolBinding?.arguments ?? {};
  assert.equal(browserUseArguments["computerUse"], true);
  assert.equal(browserUseArguments["computerUseLane"], "native_browser");
  assert.equal(browserUseArguments["computerUseSessionMode"], "owned_hermetic_browser");
  assert.equal(browserUseArguments["computerUseActionKind"], "inspect");
  assert.equal(browserUseArguments["observationRetentionMode"], "local_redacted_artifacts");
  assert.equal(browserUseArguments["failClosedWhenUnavailable"], true);
  assert.equal(
    creators.get("plugin_tool.computer_use.visual_gui")?.defaultLaw.requireHumanGate,
    true,
  );
  assert.equal(
    creators.get("plugin_tool.computer_use.sandboxed")?.defaultLogic.toolBinding
      ?.arguments?.["computerUseLane"],
    "sandboxed_hosted",
  );
});
