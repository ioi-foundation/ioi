import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";

import {
  discoverSkillHookCatalog,
  hookRecordFromDefinition,
  parseMarkdownSkillMetadata,
  skillHookSources,
} from "./skill-hook-catalog.mjs";

const tempRoots = [];

afterEach(() => {
  for (const root of tempRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

function tempDir() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-skill-hook-catalog-"));
  tempRoots.push(root);
  return root;
}

function writeFile(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

test("skill hook sources include workspace and global compatibility locations", () => {
  const sources = skillHookSources({ workspaceRoot: "/workspace", globalHome: "/home/user" });

  assert.equal(sources.length, 16);
  assert.ok(sources.some((source) => source.id === "workspace.ioi.skills" && source.kind === "skill_dir"));
  assert.ok(sources.some((source) => source.id === "workspace.cursor.hooks_file" && source.kind === "hook_file"));
  assert.ok(sources.some((source) => source.id === "global.agents.hooks_file" && source.scope === "global"));
  assert.ok(sources.every((source) => typeof source.pathHash === "string" && source.pathHash.length === 64));
});

test("skill hook catalog discovers skills and redacted hook definitions", () => {
  const workspace = tempDir();
  const home = tempDir();
  writeFile(
    path.join(workspace, ".ioi/skills/planner/SKILL.md"),
    [
      "---",
      "name: Planner",
      "description: Keeps plans tidy",
      "activationMode: automatic",
      "capabilityScopes: workspace, memory",
      "---",
      "# Planner Skill",
      "",
    ].join("\n"),
  );
  writeFile(
    path.join(workspace, ".agents/hooks.json"),
    JSON.stringify({
      hooks: [
        {
          name: "pre_tool_guard",
          command: "secret-token=do-not-leak",
          authorityScopes: ["workspace.write"],
          toolContracts: ["coding.apply_patch"],
          sideEffectClass: "local_write",
          failurePolicy: "block",
        },
      ],
    }),
  );
  writeFile(
    path.join(home, ".agents/hooks.json"),
    JSON.stringify({
      global_subscriber: {
        events: "post_model",
        failure_policy: "ignore",
      },
    }),
  );

  const catalog = discoverSkillHookCatalog({ cwd: workspace, homeDir: home });

  assert.equal(catalog.object, "ioi.agent_skill_hook_catalog");
  assert.equal(catalog.skillCount, 1);
  assert.equal(catalog.hookCount, 2);
  assert.equal(catalog.status, "pass");
  assert.equal(catalog.redaction.hookCommandsIncluded, false);
  assert.equal(catalog.skills[0].name, "Planner");
  assert.deepEqual(catalog.skills[0].capabilityScopes, ["workspace", "memory"]);

  const commandHook = catalog.hooks.find((hook) => hook.name === "pre_tool_guard");
  assert.ok(commandHook);
  assert.equal(commandHook.commandConfigured, true);
  assert.equal(commandHook.commandRedacted, true);
  assert.equal(commandHook.commandHash.length, 64);
  assert.equal(JSON.stringify(commandHook).includes("secret-token"), false);
  assert.deepEqual(commandHook.eventKinds, ["pre_tool"]);
  assert.equal(commandHook.validation.status, "pass");

  const globalHook = catalog.hooks.find((hook) => hook.name === "global_subscriber");
  assert.ok(globalHook);
  assert.equal(globalHook.trustLevel, "global_user");
  assert.deepEqual(globalHook.eventKinds, ["post_model"]);
});

test("skill hook catalog marks missing canonical skill files and hook capability gaps", () => {
  const workspace = tempDir();
  const home = tempDir();
  writeFile(path.join(workspace, ".cursor/skills/readme-only/README.md"), "# Legacy Skill\n");
  writeFile(
    path.join(workspace, ".cursor/hooks/blocking.json"),
    JSON.stringify({
      risky_hook: {
        command: "npm run mutate",
        side_effect_class: "local_write",
      },
    }),
  );

  const catalog = discoverSkillHookCatalog({ cwd: workspace, homeDir: home });

  assert.equal(catalog.status, "degraded");
  assert.equal(catalog.skillStatus, "degraded");
  assert.equal(catalog.hookStatus, "degraded");
  assert.equal(catalog.validationIssueCount, 3);
  assert.deepEqual(catalog.skills[0].validation.issues, ["missing_canonical_SKILL_md"]);
  assert.deepEqual(catalog.hooks[0].validation.issues, [
    "missing_authority_scope",
    "missing_tool_contract",
  ]);
});

test("skill metadata and hook definitions normalize compatibility aliases", () => {
  assert.deepEqual(parseMarkdownSkillMetadata("---\nname: Ops\ncapability_scopes: repo, shell\n---\n# Ignored\n"), {
    name: "Ops",
    title: "Ignored",
    description: null,
    activationMode: null,
    capabilityScopes: ["repo", "shell"],
    frontmatterKeys: ["capability_scopes", "name"],
  });

  const hook = hookRecordFromDefinition({
    source: {
      id: "workspace.ioi.hooks_file",
      compatibility: "ioi",
      trustLevel: "workspace",
    },
    name: "approval-check",
    definition: {
      subscribe: "approval",
      onFailure: "retry",
      capabilities: "wallet.approval",
      tools: "policy.receipt",
      script: "approve --token hidden",
    },
    definitionPath: "/workspace/.ioi/hooks.json",
    workspaceRoot: "/workspace",
  });

  assert.deepEqual(hook.eventKinds, ["approval"]);
  assert.equal(hook.failurePolicy, "retry");
  assert.deepEqual(hook.authorityScopes, ["wallet.approval"]);
  assert.deepEqual(hook.toolContracts, ["policy.receipt"]);
  assert.equal(JSON.stringify(hook).includes("approve --token hidden"), false);
});
