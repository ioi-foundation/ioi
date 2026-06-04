import { discoverSkillHookCatalog } from "./skill-hook-catalog.mjs";

export function createRuntimeSkillHookSurface({
  discoverSkillHookCatalog: discoverSkillHookCatalogDep = discoverSkillHookCatalog,
  defaultCwd,
  homeDir,
} = {}) {
  const cwdForRequest = (request = {}) => request.cwd ?? defaultCwd;
  const skillHookCatalog = ({ cwd = defaultCwd } = {}) =>
    discoverSkillHookCatalogDep({ cwd, homeDir });

  return {
    skillHookCatalog(request = {}) {
      return skillHookCatalog({ cwd: cwdForRequest(request) });
    },
    listSkills(request = {}) {
      const catalog = skillHookCatalog({ cwd: cwdForRequest(request) });
      return {
        schemaVersion: "ioi.agent-runtime.skills.v1",
        object: "ioi.agent_skill_registry_projection",
        generatedAt: catalog.generatedAt,
        workspace: catalog.workspace,
        status: catalog.skillStatus,
        skillCount: catalog.skillCount,
        activeSkillSetHash: catalog.activeSkillSetHash,
        sources: catalog.sources.filter((source) => source.kind === "skill_dir"),
        skills: catalog.skills,
        redaction: catalog.redaction,
        evidenceRefs: ["runtime_skill_discovery", "SkillNode", "SkillPackNode"],
      };
    },
    listHooks(request = {}) {
      const catalog = skillHookCatalog({ cwd: cwdForRequest(request) });
      return {
        schemaVersion: "ioi.agent-runtime.hooks.v1",
        object: "ioi.agent_hook_registry_projection",
        generatedAt: catalog.generatedAt,
        workspace: catalog.workspace,
        status: catalog.hookStatus,
        hookCount: catalog.hookCount,
        activeHookSetHash: catalog.activeHookSetHash,
        sources: catalog.sources.filter((source) => source.kind === "hook_file" || source.kind === "hook_dir"),
        hooks: catalog.hooks,
        redaction: catalog.redaction,
        evidenceRefs: ["runtime_hook_discovery", "HookNode", "HookPolicyNode"],
      };
    },
  };
}
