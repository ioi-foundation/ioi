import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeSkillHookSurface } from "./runtime-skill-hook-surface.mjs";

function catalog({ cwd, homeDir }) {
  return {
    generatedAt: "2026-06-04T00:00:00.000Z",
    workspace: { root: cwd, homeDir },
    skillStatus: "pass",
    hookStatus: "degraded",
    skillCount: 1,
    hookCount: 2,
    activeSkillSetHash: "skill-hash",
    activeHookSetHash: "hook-hash",
    sources: [
      { id: "workspace.skills", kind: "skill_dir" },
      { id: "workspace.hooks.file", kind: "hook_file" },
      { id: "workspace.hooks.dir", kind: "hook_dir" },
      { id: "ignored", kind: "other" },
    ],
    skills: [{ id: "skill.one" }],
    hooks: [{ id: "hook.one" }, { id: "hook.two" }],
    redaction: {
      hookCommandsIncluded: false,
      secretValuesIncluded: false,
    },
  };
}

test("runtime skill hook surface projects catalog, skills, and hooks from default cwd", () => {
  const calls = [];
  const surface = createRuntimeSkillHookSurface({
    defaultCwd: "/workspace/project",
    homeDir: "/home/operator",
    discoverSkillHookCatalog(input) {
      calls.push(input);
      return catalog(input);
    },
  });

  assert.equal(surface.skillHookCatalog().workspace.root, "/workspace/project");
  assert.deepEqual(surface.listSkills(), {
    schemaVersion: "ioi.agent-runtime.skills.v1",
    object: "ioi.agent_skill_registry_projection",
    generatedAt: "2026-06-04T00:00:00.000Z",
    workspace: { root: "/workspace/project", homeDir: "/home/operator" },
    status: "pass",
    skillCount: 1,
    activeSkillSetHash: "skill-hash",
    sources: [{ id: "workspace.skills", kind: "skill_dir" }],
    skills: [{ id: "skill.one" }],
    redaction: {
      hookCommandsIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: ["runtime_skill_discovery", "SkillNode", "SkillPackNode"],
  });
  assert.deepEqual(surface.listHooks({ cwd: "/other/workspace" }), {
    schemaVersion: "ioi.agent-runtime.hooks.v1",
    object: "ioi.agent_hook_registry_projection",
    generatedAt: "2026-06-04T00:00:00.000Z",
    workspace: { root: "/other/workspace", homeDir: "/home/operator" },
    status: "degraded",
    hookCount: 2,
    activeHookSetHash: "hook-hash",
    sources: [
      { id: "workspace.hooks.file", kind: "hook_file" },
      { id: "workspace.hooks.dir", kind: "hook_dir" },
    ],
    hooks: [{ id: "hook.one" }, { id: "hook.two" }],
    redaction: {
      hookCommandsIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: ["runtime_hook_discovery", "HookNode", "HookPolicyNode"],
  });
  assert.deepEqual(calls, [
    { cwd: "/workspace/project", homeDir: "/home/operator" },
    { cwd: "/workspace/project", homeDir: "/home/operator" },
    { cwd: "/other/workspace", homeDir: "/home/operator" },
  ]);
});
