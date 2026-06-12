import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeSkillHookSurface } from "./runtime-skill-hook-surface.mjs";

test("runtime skill hook surface returns Rust-owned catalog skills and hooks", () => {
  const calls = [];
  const surface = createRuntimeSkillHookSurface({
    defaultCwd: "/workspace/project",
    env: { HOME: "/home/operator" },
    skillHookRunner: {
      projectSkillHookRegistry(request) {
        calls.push(request);
        if (request.registry_kind === "catalog") {
          return {
            registry_kind: "catalog",
            operation_kind: request.operation_kind,
            projection: {
              schemaVersion: "ioi.agent-runtime.skill-hook-catalog.v1",
              status: "pass",
              skillCount: 1,
              hookCount: 1,
              skills: [{ id: "skill.repo", name: "Repo Cartographer" }],
              hooks: [{ id: "hook.pre_model", name: "pre-model-redaction" }],
              sources: [],
            },
          };
        }
        if (request.registry_kind === "skills") {
          return {
            registry_kind: "skills",
            operation_kind: request.operation_kind,
            projection: {
              schemaVersion: "ioi.agent-runtime.skills.v1",
              status: "pass",
              skillCount: 1,
              skills: [{ id: "skill.repo", name: "Repo Cartographer" }],
            },
          };
        }
        return {
          registry_kind: "hooks",
          operation_kind: request.operation_kind,
          projection: {
            schemaVersion: "ioi.agent-runtime.hooks.v1",
            status: "pass",
            hookCount: 1,
            hooks: [{ id: "hook.pre_model", name: "pre-model-redaction" }],
          },
        };
      },
    },
  });

  const catalog = surface.skillHookCatalog();
  const skills = surface.listSkills();
  const hooks = surface.listHooks({ cwd: "/workspace/other" });

  assert.equal(catalog.skillCount, 1);
  assert.equal(skills.skills[0].name, "Repo Cartographer");
  assert.equal(hooks.hooks[0].name, "pre-model-redaction");
  assert.deepEqual(calls.map((call) => call.registry_kind), ["catalog", "skills", "hooks"]);
  assert.equal(calls[0].workspace_root, "/workspace/project");
  assert.equal(calls[0].home_dir, "/home/operator");
  assert.equal(calls[2].workspace_root, "/workspace/other");
  assert.equal(Object.hasOwn(calls[0], "workspaceRoot"), false);
  assert.equal(Object.hasOwn(calls[0], "registryKind"), false);
});

test("runtime skill hook surface fails closed when Rust projection is missing", () => {
  const surface = createRuntimeSkillHookSurface({ defaultCwd: "/workspace/project" });

  assert.throws(
    () => surface.listSkills(),
    (error) =>
      error.status === 501 &&
      error.code === "runtime_skill_hook_registry_rust_core_required" &&
      error.details.registry_kind === "skills" &&
      error.details.workspace_root === "/workspace/project" &&
      error.details.evidence_refs.includes("runtime_skill_hook_registry_js_projection_retired") &&
      !Object.hasOwn(error.details, "registryKind"),
  );
});

test("runtime skill hook surface rejects Rust projection mismatches", () => {
  const surface = createRuntimeSkillHookSurface({
    defaultCwd: "/workspace/project",
    skillHookRunner: {
      projectSkillHookRegistry() {
        return {
          registry_kind: "hooks",
          operation_kind: "skill_hook.registry.hooks",
          projection: { hooks: [] },
        };
      },
    },
  });

  assert.throws(
    () => surface.listSkills(),
    (error) =>
      error.code === "runtime_skill_hook_registry_rust_projection_invalid" &&
      error.details.expected_registry_kind === "skills" &&
      error.details.registry_kind === "hooks",
  );
});
