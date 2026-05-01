import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  REQUIRED_DECISION_CATEGORY_IDS,
} from "./benchmark-matrix-contracts.mjs";
import {
  AGENT_RUNTIME_SUPERIORITY_SCHEMA_VERSION,
  SMARTER_AGENT_SUPERIORITY_SCENARIOS,
  evaluateAgentRuntimeSuperiority,
  validateAgentRuntimeSuperiority,
} from "./agent-runtime-superiority-contract.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);

test("superiority scenario pack covers every required surface and smarter dimension", () => {
  assert.equal(
    AGENT_RUNTIME_SUPERIORITY_SCHEMA_VERSION,
    "ioi.agent-runtime.smarter-superiority-validation.v1",
  );
  assert.ok(SMARTER_AGENT_SUPERIORITY_SCENARIOS.length >= 12);

  const surfaces = new Set(SMARTER_AGENT_SUPERIORITY_SCENARIOS.flatMap((scenario) => scenario.surfaces));
  for (const surface of ["cli", "api", "ui", "harness", "benchmark", "workflow_compositor"]) {
    assert.ok(surfaces.has(surface), `missing surface ${surface}`);
  }

  const dimensions = new Set(
    SMARTER_AGENT_SUPERIORITY_SCENARIOS.flatMap((scenario) => scenario.smarterDimensions),
  );
  for (const dimension of [
    "task_state",
    "uncertainty",
    "probe",
    "postcondition_synthesis",
    "semantic_impact",
    "strategy_routing",
    "tool_model_selection",
    "memory_learning",
    "verifier_independence",
    "cognitive_budget",
    "drift",
    "dry_run",
    "stop_condition",
    "handoff_quality",
    "operator_collaboration",
    "bounded_self_improvement",
    "clean_chat_ux",
    "unified_substrate",
  ]) {
    assert.ok(dimensions.has(dimension), `missing smarter dimension ${dimension}`);
  }
});

test("current repository proves smarter-agent superiority with existing GUI evidence", () => {
  const superiority = evaluateAgentRuntimeSuperiority(repoRoot, {
    requireGuiEvidence: true,
  });
  const validation = validateAgentRuntimeSuperiority(superiority);
  assert.equal(validation.ok, true, validation.failures.join("\n"));
  assert.equal(superiority.status, "CompletePlus");
  assert.equal(superiority.counts.completePlusScenarios, superiority.counts.scenarios);
  assert.equal(superiority.coverage.missingSurfaces.length, 0);
  assert.equal(superiority.coverage.missingDimensions.length, 0);
  assert.ok(superiority.guiEvidence?.resultPath);
  assert.ok(superiority.p3Evidence?.resultPath);
});

test("all required benchmark decision categories remain covered by the superiority proof", () => {
  const superiority = evaluateAgentRuntimeSuperiority(repoRoot, {
    requireGuiEvidence: false,
  });
  assert.equal(superiority.scorecardSchema.requiredScorecardCategoriesCovered, true);
  assert.deepEqual(
    superiority.scorecardSchema.requiredDecisionCategoryIds,
    REQUIRED_DECISION_CATEGORY_IDS,
  );
});

test("superiority validation fails when a decisive IOI runtime anchor is absent", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-superiority-missing-anchor-"));
  fs.mkdirSync(path.join(tmp, "examples/claude-code-main/claude-code-main"), {
    recursive: true,
  });
  fs.writeFileSync(
    path.join(tmp, "examples/claude-code-main/claude-code-main/README.md"),
    [
      "Permission System",
      "BashTool",
      "FileWriteTool",
      "WebSearchTool",
      "WebFetchTool",
      "cost tracking",
      "EnterPlanModeTool",
      "TaskCreateTool",
      "TaskUpdateTool",
      "FileEditTool",
      "GrepTool",
      "/diff",
      "/review",
      "/memory",
      "Skill System",
      "memdir",
      "ToolSearchTool",
      "tools/",
      "plugins/",
      "AgentTool",
      "TeamCreateTool",
      "SendMessageTool",
      "/compact",
      "/resume",
      "context compression",
      "Anthropic SDK",
      "token count",
      "Terminal UI",
      "React + Ink",
      "screens/",
      "server mode",
      "remote sessions",
    ].join("\n"),
  );
  fs.mkdirSync(path.join(tmp, "docs/specs/runtime"), { recursive: true });
  fs.writeFileSync(
    path.join(tmp, "docs/specs/runtime/agent-runtime-parity-plus-master-guide.md"),
    "# Guide\n",
  );
  fs.writeFileSync(
    path.join(tmp, "package.json"),
    JSON.stringify(
      {
        scripts: {
          "test:autopilot-gui-harness": "node test",
          "validate:autopilot-gui-harness": "node test",
          "validate:autopilot-gui-harness:run": "node test",
          "test:agent-runtime-p3": "node test",
          "validate:agent-runtime-p3": "node test",
        },
      },
      null,
      2,
    ),
  );
  fs.mkdirSync(path.join(tmp, "crates/types/src/app"), { recursive: true });
  fs.writeFileSync(
    path.join(tmp, "crates/types/src/app/runtime_contracts.rs"),
    "pub struct RuntimeExecutionEnvelope;\n",
  );
  const superiority = evaluateAgentRuntimeSuperiority(tmp, {
    requireGuiEvidence: false,
  });
  const validation = validateAgentRuntimeSuperiority(superiority);
  assert.equal(validation.ok, false);
  assert.ok(
    validation.failures.some((failure) =>
      failure.includes("destructive_action_governed_stop"),
    ),
  );
});
