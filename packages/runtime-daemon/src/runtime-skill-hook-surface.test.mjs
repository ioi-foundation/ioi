import assert from "node:assert/strict";
import test from "node:test";

import { createRuntimeSkillHookSurface } from "./runtime-skill-hook-surface.mjs";

test("runtime skill hook surface fails closed before JS catalog discovery", () => {
  const surface = createRuntimeSkillHookSurface({
    defaultCwd: "/workspace/project",
    discoverSkillHookCatalog() {
      throw new Error("JS skill hook discovery must not author public registry projection");
    },
  });

  assert.throws(
    () => surface.listSkills(),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(
        error.code,
        "runtime_skill_hook_registry_rust_core_required",
      );
      assert.equal(
        error.details.rust_core_boundary,
        "runtime.skill_hook_registry",
      );
      assert.equal(error.details.operation, "skill_hook_registry_skills");
      assert.equal(error.details.operation_kind, "skill_hook.registry.skills");
      assert.equal(error.details.registry_kind, "skills");
      assert.equal(error.details.workspace_root, "/workspace/project");
      assert.equal(Object.hasOwn(error.details, "registryKind"), false);
      assert.equal(Object.hasOwn(error.details, "workspaceRoot"), false);
      return true;
    },
  );
});

test("runtime skill hook surface translates mounted Rust projection-required record", () => {
  let captured = null;
  const surface = createRuntimeSkillHookSurface({
    defaultCwd: "/workspace/project",
    skillHookRunner: {
      planSkillHookRegistryProjectionRequired(request) {
        captured = request;
        return {
          record: {
            status_code: 501,
            code: "runtime_skill_hook_registry_rust_core_required",
            message:
              "Skill and hook registry projection requires direct Rust daemon-core projection over admitted governance/catalog truth.",
            details: {
              rust_core_boundary: "runtime.skill_hook_registry",
              operation: request.operation,
              operation_kind: request.operation_kind,
              registry_kind: request.registry_kind,
              workspace_root: request.workspace_root,
              source: request.source,
              evidence_refs: request.evidence_refs,
            },
          },
        };
      },
    },
  });

  assert.throws(
    () => surface.listHooks({ cwd: "/other/workspace" }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(
        error.code,
        "runtime_skill_hook_registry_rust_core_required",
      );
      assert.equal(error.details.operation, "skill_hook_registry_hooks");
      assert.equal(error.details.operation_kind, "skill_hook.registry.hooks");
      assert.equal(error.details.registry_kind, "hooks");
      assert.equal(error.details.workspace_root, "/other/workspace");
      assert.equal(error.details.source, "runtime.skill_hook_surface");
      assert.deepEqual(error.details.evidence_refs, [
        "runtime_skill_hook_registry_js_projection_retired",
        "rust_daemon_core_skill_hook_registry_required",
        "agentgres_skill_hook_registry_truth_required",
      ]);
      return true;
    },
  );

  assert.deepEqual(captured, {
    operation: "skill_hook_registry_hooks",
    operation_kind: "skill_hook.registry.hooks",
    registry_kind: "hooks",
    workspace_root: "/other/workspace",
    source: "runtime.skill_hook_surface",
    evidence_refs: [
      "runtime_skill_hook_registry_js_projection_retired",
      "rust_daemon_core_skill_hook_registry_required",
      "agentgres_skill_hook_registry_truth_required",
    ],
  });
});
