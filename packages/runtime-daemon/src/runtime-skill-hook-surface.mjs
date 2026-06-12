import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeSkillHookSurface({
  defaultCwd,
  env = process.env,
  skillHookRunner = null,
} = {}) {
  const cwdForRequest = (request = {}) => request.cwd ?? defaultCwd;
  const project = (projection) => {
    if (!skillHookRunner?.projectSkillHookRegistry) {
      throwSkillHookRegistryRustCoreRequired({
        ...projection,
        source: "runtime.skill_hook_surface",
      });
    }
    const result = skillHookRunner.projectSkillHookRegistry({
      ...projection,
      source: "runtime.skill_hook_surface",
      home_dir: optionalString(env.HOME),
    });
    if (result.registry_kind !== projection.registry_kind) {
      throwSkillHookRegistryProjectionInvalid(result, projection);
    }
    const record = objectRecord(result.projection);
    if (!record) {
      throwSkillHookRegistryProjectionInvalid(result, projection);
    }
    return record;
  };

  return {
    skillHookCatalog(request = {}) {
      return project({
        operation: "skill_hook_registry_catalog",
        operation_kind: "skill_hook.registry.catalog",
        registry_kind: "catalog",
        workspace_root: cwdForRequest(request),
      });
    },
    listSkills(request = {}) {
      return project({
        operation: "skill_hook_registry_skills",
        operation_kind: "skill_hook.registry.skills",
        registry_kind: "skills",
        workspace_root: cwdForRequest(request),
      });
    },
    listHooks(request = {}) {
      return project({
        operation: "skill_hook_registry_hooks",
        operation_kind: "skill_hook.registry.hooks",
        registry_kind: "hooks",
        workspace_root: cwdForRequest(request),
      });
    },
  };
}

function throwSkillHookRegistryRustCoreRequired(details = {}) {
  throw createSkillHookRegistryProjectionError(null, {
    ...details,
    evidence_refs: [
      "runtime_skill_hook_registry_js_projection_retired",
      "rust_daemon_core_skill_hook_registry_projection_required",
      "agentgres_skill_hook_registry_truth_required",
    ],
  });
}

function throwSkillHookRegistryProjectionInvalid(record, expected) {
  const error = new Error("Rust skill/hook registry projection did not match the requested public registry projection.");
  error.status = 502;
  error.code = "runtime_skill_hook_registry_rust_projection_invalid";
  error.details = {
    rust_core_boundary: "runtime.skill_hook_registry",
    expected_registry_kind: expected.registry_kind,
    registry_kind: record?.registry_kind ?? null,
    operation_kind: record?.operation_kind ?? null,
  };
  throw error;
}

function createSkillHookRegistryProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Skill and hook registry projection requires Rust daemon-core projection over admitted governance/catalog truth.",
  );
  error.status = Number(record?.status_code ?? 501);
  error.code =
    optionalString(record?.code) ??
    "runtime_skill_hook_registry_rust_core_required";
  error.details = record?.details ?? {
    rust_core_boundary: "runtime.skill_hook_registry",
    ...fallbackDetails,
  };
  return error;
}
