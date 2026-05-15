import assert from "node:assert/strict";
import test from "node:test";
import { workflowPrimitiveConfigProjection } from "./workflow-primitive-config-projection";
import {
  workflowNodeCreatorDefinitions,
  workflowNodeDefinition,
} from "./workflow-node-registry";

test("subsystem state operations project to canonical primitive config modes", () => {
  assert.deepEqual(
    {
      primitive: workflowPrimitiveConfigProjection("state", {
        stateOperation: "memory_search",
      }).canonicalPrimitive,
      label: workflowPrimitiveConfigProjection("state", {
        stateOperation: "memory_search",
      }).primitiveLabel,
    },
    { primitive: "memory", label: "Memory" },
  );

  assert.equal(
    workflowPrimitiveConfigProjection("state", {
      stateOperation: "subagent_spawn",
    }).canonicalPrimitive,
    "worker",
  );
  assert.equal(
    workflowPrimitiveConfigProjection("state", {
      stateOperation: "mcp_tool_invoke",
    }).canonicalPrimitive,
    "tool_pack",
  );
  assert.equal(
    workflowPrimitiveConfigProjection("state", {
      stateOperation: "mcp_status",
    }).canonicalPrimitive,
    "connector",
  );
});

test("dedicated subsystem nodes expose canonical primitive labels and sections", () => {
  const skills = workflowPrimitiveConfigProjection("skill_context", {
    skillContext: { mode: "pinned" } as any,
  });
  assert.equal(skills.primitiveLabel, "Skills");
  assert.equal(skills.modeLabel, "Skill pinned");
  assert.ok(skills.configSections.includes("discovery"));
  assert.ok(skills.configSections.includes("audit"));

  const agentStep = workflowPrimitiveConfigProjection("model_call", {
    toolUseMode: "auto",
  });
  assert.equal(agentStep.primitiveLabel, "Agent Step");
  assert.equal(agentStep.modeLabel, "auto");
  assert.ok(agentStep.configSections.includes("model"));

  const hookPolicy = workflowPrimitiveConfigProjection("hook_policy");
  assert.equal(hookPolicy.primitiveLabel, "Hook");
  assert.equal(hookPolicy.modeLabel, "Hook policy");
});

test("creator display labels collapse operation variants into primitive names", () => {
  const creators = new Map(
    workflowNodeCreatorDefinitions().map((creator) => [creator.creatorId, creator]),
  );

  assert.equal(creators.get("memory.search")?.displayLabel, "Memory");
  assert.equal(creators.get("subagent.spawn")?.displayLabel, "Worker");
  assert.equal(creators.get("plugin_tool.coding_pack")?.displayLabel, "Tool Pack");
  assert.equal(creators.get("plugin_tool.browser_use")?.displayLabel, "Tool Pack");
  assert.equal(
    creators.get("plugin_tool.computer_use.visual_gui")?.displayLabel,
    "Tool Pack",
  );
  assert.equal(
    creators.get("computer_use.browser_discovery")?.displayLabel,
    "Browser Discovery",
  );
  assert.equal(
    creators.get("computer_use.visual_gui_observe")?.displayLabel,
    "Visual Observation",
  );
  assert.equal(creators.get("skill_context.discover")?.displayLabel, "Skills");
  assert.equal(creators.get("github_pr_create")?.displayLabel, "Pull Request");
  assert.equal(workflowNodeDefinition("model_call").displayLabel, "Agent Step");
});
