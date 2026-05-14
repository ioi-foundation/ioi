import assert from "node:assert/strict";
import test from "node:test";
import { WORKFLOW_COMPOSITION_HELPERS } from "./workflow-composition-helpers";
import {
  workflowNodeActionDefinitions,
  workflowNodeCreatorDefinitions,
  workflowScaffoldDefinitions,
  type WorkflowNodeCreatorDefinition,
} from "./workflow-node-registry";
import {
  rankWorkflowCompositionHelpers,
  rankWorkflowNodeLibrary,
} from "./workflow-node-library-search";
import type { WorkflowCanonicalPrimitive } from "./workflow-node-taxonomy";

const NODE_LIBRARY = workflowNodeCreatorDefinitions();
const SCAFFOLDS = workflowScaffoldDefinitions();
const ACTIONS = workflowNodeActionDefinitions();

function rankNodes(query: string) {
  return rankWorkflowNodeLibrary(NODE_LIBRARY, query, (item) => {
    const scaffold = SCAFFOLDS.find((entry) => entry.nodeType === item.type);
    const action = ACTIONS.find((entry) => entry.nodeType === item.type);
    return {
      scaffoldKeywords: scaffold?.keywords,
      scaffoldConnectionClasses: scaffold?.connectionClasses,
      actionDescription: action?.description,
      actionRequiredBinding: action?.requiredBinding,
      actionSideEffectClass: action?.sideEffectClass,
      actionKeywords: action?.keywords,
      actionConnectionClasses: action?.connectionClasses,
      actionRequiresApproval: action?.requiresApproval,
      actionSupportsMockBinding: action?.supportsMockBinding,
      actionSchemaRequired: action?.schemaRequired,
    };
  });
}

function topNode(query: string): WorkflowNodeCreatorDefinition {
  const [result] = rankNodes(query);
  assert.ok(result, `${query} should return at least one node`);
  return result.item;
}

function assertTopPrimitive(
  query: string,
  primitive: WorkflowCanonicalPrimitive,
) {
  assert.equal(
    topNode(query).canonicalPrimitive,
    primitive,
    `${query} should prioritize ${primitive}`,
  );
}

test("authoring synonyms prioritize canonical primitives", () => {
  assertTopPrimitive("worker", "worker");
  assertTopPrimitive("agent", "agent_step");
  assertTopPrimitive("pull request", "pull_request");
  assertTopPrimitive("repo", "context");
  assertTopPrimitive("skills", "skills");
  assertTopPrimitive("memory", "memory");
  assertTopPrimitive("tool", "tool_pack");
  assertTopPrimitive("policy", "policy_gate");
  assertTopPrimitive("approval", "policy_gate");
  assertTopPrimitive("output", "output");
});

test("short pr query does not act like broad substring search", () => {
  const results = rankNodes("pr");
  assert.ok(results.length > 0);
  assert.equal(results[0]?.item.canonicalPrimitive, "pull_request");
  assert.ok(
    results.length < 20,
    `expected focused pr results, received ${results.length}`,
  );
  assert.ok(
    results.every((result) =>
      result.matchedTerms.some((term) =>
        ["pr", "pull request", "github pr", "review gate"].includes(term),
      ),
    ),
    "pr matches should come from explicit PR synonyms",
  );
});

test("advanced debug nodes rank below default authoring primitives", () => {
  const results = rankNodes("run");
  const firstAdvanced = results.findIndex(
    (result) => result.item.paletteVisibility === "advanced",
  );
  const firstDefault = results.findIndex(
    (result) => result.item.paletteVisibility === "default",
  );
  assert.notEqual(firstDefault, -1, "query should include default matches");
  assert.notEqual(firstAdvanced, -1, "query should include advanced matches");
  assert.ok(
    firstDefault < firstAdvanced,
    "default primitives should appear before advanced runtime matches",
  );
});

test("palette visibility separates default authoring from advanced runtime contracts", () => {
  const defaultAuthoring = NODE_LIBRARY.filter(
    (item) =>
      item.paletteVisibility === "default" ||
      item.paletteVisibility === "template",
  ).map((item) => item.creatorId);
  const advanced = NODE_LIBRARY.filter(
    (item) => item.paletteVisibility === "advanced",
  ).map((item) => item.creatorId);

  assert.ok(defaultAuthoring.includes("model_call"));
  assert.ok(defaultAuthoring.includes("plugin_tool.coding_pack"));
  assert.ok(defaultAuthoring.includes("skill_context.discover"));
  assert.ok(!defaultAuthoring.includes("runtime_task"));
  assert.ok(advanced.includes("runtime_task"));
  assert.ok(advanced.includes("workflow_package_import"));
});

test("composition helpers are searchable by authoring vocabulary", () => {
  const terminal = rankWorkflowCompositionHelpers(
    WORKFLOW_COMPOSITION_HELPERS,
    "terminal",
  );
  assert.equal(terminal[0]?.item.helperId, "terminal_coding_loop");

  const agent = rankWorkflowCompositionHelpers(
    WORKFLOW_COMPOSITION_HELPERS,
    "agent",
  );
  assert.equal(agent[0]?.item.helperId, "agent_loop");
});
