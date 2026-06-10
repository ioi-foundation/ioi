import { optionalString } from "./runtime-value-helpers.mjs";

export function createRuntimeSkillHookSurface({
  defaultCwd,
  skillHookRunner = null,
} = {}) {
  const cwdForRequest = (request = {}) => request.cwd ?? defaultCwd;

  return {
    skillHookCatalog(request = {}) {
      throwSkillHookRegistryRustCoreRequired({
        skillHookRunner,
        operation: "skill_hook_registry_catalog",
        operation_kind: "skill_hook.registry.catalog",
        registry_kind: "catalog",
        workspace_root: cwdForRequest(request),
      });
    },
    listSkills(request = {}) {
      throwSkillHookRegistryRustCoreRequired({
        skillHookRunner,
        operation: "skill_hook_registry_skills",
        operation_kind: "skill_hook.registry.skills",
        registry_kind: "skills",
        workspace_root: cwdForRequest(request),
      });
    },
    listHooks(request = {}) {
      throwSkillHookRegistryRustCoreRequired({
        skillHookRunner,
        operation: "skill_hook_registry_hooks",
        operation_kind: "skill_hook.registry.hooks",
        registry_kind: "hooks",
        workspace_root: cwdForRequest(request),
      });
    },
  };
}

function throwSkillHookRegistryRustCoreRequired(details = {}) {
  const { skillHookRunner = null, ...errorDetails } = details;
  const evidence_refs = [
    "runtime_skill_hook_registry_js_projection_retired",
    "rust_daemon_core_skill_hook_registry_required",
    "agentgres_skill_hook_registry_truth_required",
  ];

  if (skillHookRunner?.planSkillHookRegistryProjectionRequired) {
    const record = skillHookRunner.planSkillHookRegistryProjectionRequired({
      ...errorDetails,
      source: "runtime.skill_hook_surface",
      evidence_refs,
    });
    const planned = record?.record ?? record;
    throw createSkillHookRegistryProjectionError(planned ?? record, {
      ...errorDetails,
      source: "runtime.skill_hook_surface",
      evidence_refs,
    });
  }

  throw createSkillHookRegistryProjectionError(null, {
    ...errorDetails,
    source: "runtime.skill_hook_surface",
    evidence_refs,
  });
}

function createSkillHookRegistryProjectionError(record, fallbackDetails) {
  const error = new Error(
    optionalString(record?.message) ??
      "Skill and hook registry projection requires direct Rust daemon-core projection over admitted governance/catalog truth.",
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
