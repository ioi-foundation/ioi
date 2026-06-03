import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function discoverSkillHookCatalog({ cwd, homeDir } = {}) {
  const workspaceRoot = path.resolve(cwd ?? process.cwd());
  const globalHome = path.resolve(homeDir ?? process.env.HOME ?? os.homedir());
  const generatedAt = new Date().toISOString();
  const sources = skillHookSources({ workspaceRoot, globalHome });
  const skills = sources.flatMap((source) => discoverSkillsFromSource(source, workspaceRoot));
  const hooks = sources.flatMap((source) => discoverHooksFromSource(source, workspaceRoot));
  const validationIssueCount =
    skills.reduce((count, skill) => count + normalizeArray(skill.validation?.issues).length, 0) +
    hooks.reduce((count, hook) => count + normalizeArray(hook.validation?.issues).length, 0) +
    sources.filter((source) => source.status === "error").length;
  const skillStatus = skills.some((skill) => skill.validation?.status !== "pass") ? "degraded" : "pass";
  const hookStatus = hooks.some((hook) => hook.validation?.status !== "pass") ? "degraded" : "pass";
  const status =
    validationIssueCount > 0 || skillStatus !== "pass" || hookStatus !== "pass" ? "degraded" : "pass";
  const skillHashes = skills.map((skill) => skill.skillHash).filter(Boolean).sort();
  const hookHashes = hooks.map((hook) => hook.definitionHash).filter(Boolean).sort();
  return {
    schemaVersion: "ioi.agent-runtime.skill-hook-catalog.v1",
    object: "ioi.agent_skill_hook_catalog",
    generatedAt,
    status,
    skillStatus,
    hookStatus,
    workspace: {
      root: workspaceRoot,
      exists: fs.existsSync(workspaceRoot),
    },
    sources,
    skillCount: skills.length,
    hookCount: hooks.length,
    skills,
    hooks,
    activeSkillSetHash: doctorHash(skillHashes.join("\n")),
    activeHookSetHash: doctorHash(hookHashes.join("\n")),
    validationIssueCount,
    redaction: {
      profile: "skill_hook_registry_safe",
      hookCommandsIncluded: false,
      hookCommandsHashed: true,
      secretValuesIncluded: false,
    },
    evidenceRefs: ["runtime_skill_hook_discovery", "governed_skill_hook_catalog"],
  };
}

export function skillHookSources({ workspaceRoot, globalHome }) {
  const skillSources = [
    ["workspace.ioi.skills", ".ioi/skills", "ioi", "workspace"],
    ["workspace.agents.skills", ".agents/skills", "agents", "workspace"],
    ["workspace.cursor.skills", ".cursor/skills", "cursor", "workspace"],
    ["workspace.claude.skills", ".claude/skills", "claude", "workspace"],
    ["global.ioi.skills", ".ioi/skills", "ioi", "global"],
    ["global.agents.skills", ".agents/skills", "agents", "global"],
  ];
  const hookSources = [
    ["workspace.ioi.hooks_file", ".ioi/hooks.json", "ioi", "workspace", "hook_file"],
    ["workspace.agents.hooks_file", ".agents/hooks.json", "agents", "workspace", "hook_file"],
    ["workspace.cursor.hooks_file", ".cursor/hooks.json", "cursor", "workspace", "hook_file"],
    ["workspace.claude.hooks_file", ".claude/hooks.json", "claude", "workspace", "hook_file"],
    ["workspace.ioi.hooks_dir", ".ioi/hooks", "ioi", "workspace", "hook_dir"],
    ["workspace.agents.hooks_dir", ".agents/hooks", "agents", "workspace", "hook_dir"],
    ["workspace.cursor.hooks_dir", ".cursor/hooks", "cursor", "workspace", "hook_dir"],
    ["workspace.claude.hooks_dir", ".claude/hooks", "claude", "workspace", "hook_dir"],
    ["global.ioi.hooks_file", ".ioi/hooks.json", "ioi", "global", "hook_file"],
    ["global.agents.hooks_file", ".agents/hooks.json", "agents", "global", "hook_file"],
  ];
  const rootForScope = (scope) => (scope === "global" ? globalHome : workspaceRoot);
  return [
    ...skillSources.map(([id, relativePath, compatibility, scope]) =>
      skillHookSource({
        id,
        relativePath,
        compatibility,
        scope,
        kind: "skill_dir",
        root: rootForScope(scope),
      }),
    ),
    ...hookSources.map(([id, relativePath, compatibility, scope, kind]) =>
      skillHookSource({
        id,
        relativePath,
        compatibility,
        scope,
        kind,
        root: rootForScope(scope),
      }),
    ),
  ];
}

export function skillHookSource({ id, relativePath, compatibility, scope, kind, root }) {
  const sourcePath = path.join(root, relativePath);
  const exists = fs.existsSync(sourcePath);
  return {
    id,
    kind,
    compatibility,
    scope,
    trustLevel: scope === "global" ? "global_user" : "workspace",
    path: sourcePath,
    pathHash: doctorHash(sourcePath),
    exists,
    status: exists ? "available" : "missing",
    evidenceRefs: ["skill_hook_source", id],
  };
}

export function discoverSkillsFromSource(source, workspaceRoot) {
  if (source.kind !== "skill_dir" || !source.exists) return [];
  return safeDirectoryEntries(source.path).flatMap((entry) => {
    if (entry.name.startsWith(".")) return [];
    const entryPath = path.join(source.path, entry.name);
    const stat = safeStat(entryPath);
    if (!stat) return [];
    if (stat.isDirectory()) {
      return [skillRecordFromPath({ source, skillPath: entryPath, workspaceRoot })];
    }
    if (stat.isFile() && entry.name.toLowerCase().endsWith(".md")) {
      return [skillRecordFromPath({ source, skillPath: entryPath, workspaceRoot, markdownFile: entryPath })];
    }
    return [];
  });
}

export function skillRecordFromPath({ source, skillPath, workspaceRoot, markdownFile = null }) {
  const stat = safeStat(skillPath);
  const candidateFiles = markdownFile
    ? [markdownFile]
    : ["SKILL.md", "skill.md", "README.md"].map((name) => path.join(skillPath, name));
  const skillFile = candidateFiles.find((filePath) => fs.existsSync(filePath)) ?? null;
  const content = skillFile ? readTextQuiet(skillFile) ?? "" : "";
  const metadata = parseMarkdownSkillMetadata(content);
  const hasSkillMd = Boolean(skillFile && path.basename(skillFile).toLowerCase() === "skill.md");
  const issues = [];
  if (!skillFile) issues.push("missing_skill_markdown");
  if (skillFile && !hasSkillMd && stat?.isDirectory()) issues.push("missing_canonical_SKILL_md");
  if (skillFile && !content.trim()) issues.push("empty_skill_markdown");
  const name = metadata.name ?? metadata.title ?? path.basename(skillPath, path.extname(skillPath));
  const skillHash = doctorHash(`${source.id}:${skillFile ?? skillPath}:${content}`);
  return {
    schemaVersion: "ioi.agent-runtime.skill.v1",
    id: `skill.${safeId(source.id)}.${safeId(name)}.${skillHash.slice(0, 10)}`,
    name,
    description: metadata.description ?? null,
    sourceId: source.id,
    compatibility: source.compatibility,
    trustLevel: source.trustLevel,
    activationMode: metadata.activationMode ?? "discoverable",
    skillHash,
    path: skillPath,
    pathHash: doctorHash(skillPath),
    relativePath: relativePathForWorkspace(skillPath, workspaceRoot),
    skillFile,
    skillFileHash: skillFile ? doctorHash(skillFile) : null,
    hasSkillMd,
    frontmatterKeys: metadata.frontmatterKeys,
    capabilityScopes: metadata.capabilityScopes,
    validation: {
      status: issues.length > 0 ? "degraded" : "pass",
      issues,
    },
    provenance: {
      importedFrom: source.compatibility,
      governed: true,
      readOnlyDiscovery: true,
    },
    evidenceRefs: ["runtime_skill_discovery", source.id, skillFile ? "SKILL.md" : "missing_SKILL.md"],
  };
}

export function discoverHooksFromSource(source, workspaceRoot) {
  if (!source.exists) return [];
  if (source.kind === "hook_file") {
    const parsed = readJsonQuiet(source.path);
    return hooksFromDefinition({ source, definition: parsed, definitionPath: source.path, workspaceRoot });
  }
  if (source.kind === "hook_dir") {
    return safeDirectoryEntries(source.path).flatMap((entry) => {
      if (entry.name.startsWith(".")) return [];
      const entryPath = path.join(source.path, entry.name);
      const stat = safeStat(entryPath);
      if (!stat) return [];
      if (stat.isFile() && entry.name.toLowerCase().endsWith(".json")) {
        return hooksFromDefinition({
          source,
          definition: readJsonQuiet(entryPath),
          definitionPath: entryPath,
          workspaceRoot,
        });
      }
      if (stat.isDirectory()) {
        const hookJson = path.join(entryPath, "hook.json");
        if (!fs.existsSync(hookJson)) return [];
        return hooksFromDefinition({
          source,
          definition: readJsonQuiet(hookJson),
          definitionPath: hookJson,
          workspaceRoot,
          fallbackName: entry.name,
        });
      }
      return [];
    });
  }
  return [];
}

export function hooksFromDefinition({ source, definition, definitionPath, workspaceRoot, fallbackName = null }) {
  if (!definition || typeof definition !== "object") {
    return [
      hookRecordFromDefinition({
        source,
        name: fallbackName ?? path.basename(definitionPath, path.extname(definitionPath)),
        definition: {},
        definitionPath,
        workspaceRoot,
        issues: ["invalid_hook_definition"],
      }),
    ];
  }
  if (Array.isArray(definition)) {
    return definition.map((item, index) =>
      hookRecordFromDefinition({
        source,
        name: item?.name ?? fallbackName ?? `hook_${index + 1}`,
        definition: item,
        definitionPath,
        workspaceRoot,
      }),
    );
  }
  const entries = Object.entries(definition);
  if (entries.length === 1 && entries[0][0] === "hooks" && Array.isArray(entries[0][1])) {
    return entries[0][1].map((item, index) =>
      hookRecordFromDefinition({
        source,
        name: item?.name ?? fallbackName ?? `hook_${index + 1}`,
        definition: item,
        definitionPath,
        workspaceRoot,
      }),
    );
  }
  return entries.map(([name, item]) =>
    hookRecordFromDefinition({
      source,
      name,
      definition: item,
      definitionPath,
      workspaceRoot,
    }),
  );
}

export function hookRecordFromDefinition({ source, name, definition, definitionPath, workspaceRoot, issues = [] }) {
  const record = definition && typeof definition === "object" && !Array.isArray(definition) ? definition : {};
  const eventKinds = normalizeStringList(record.eventKinds ?? record.events ?? record.subscribe ?? record.subscriptions);
  const inferredEventKinds = eventKinds.length > 0 ? eventKinds : inferHookEventKinds(name);
  const authorityScopes = normalizeStringList(record.authorityScopes ?? record.authority_scopes ?? record.capabilities);
  const toolContracts = normalizeStringList(record.toolContracts ?? record.tool_contracts ?? record.tools);
  const commandInput = record.command ?? record.script ?? record.path ?? (typeof definition === "string" ? definition : null);
  const failurePolicy = normalizeHookFailurePolicy(record.failurePolicy ?? record.failure_policy ?? record.onFailure);
  const sideEffectClass = optionalString(record.sideEffectClass ?? record.side_effect_class) ?? "none";
  const nextIssues = [...issues];
  if (commandInput && authorityScopes.length === 0) nextIssues.push("missing_authority_scope");
  if (sideEffectClass !== "none" && toolContracts.length === 0) nextIssues.push("missing_tool_contract");
  const definitionHash = doctorHash(JSON.stringify(redactedHookDefinition(record)));
  return {
    schemaVersion: "ioi.agent-runtime.hook.v1",
    id: `hook.${safeId(source.id)}.${safeId(name)}.${definitionHash.slice(0, 10)}`,
    name,
    sourceId: source.id,
    compatibility: source.compatibility,
    trustLevel: source.trustLevel,
    enabled: record.enabled !== false,
    eventKinds: inferredEventKinds,
    failurePolicy,
    sideEffectClass,
    authorityScopes,
    toolContracts,
    commandConfigured: Boolean(commandInput),
    commandHash: commandInput ? doctorHash(commandInput) : null,
    commandRedacted: Boolean(commandInput),
    definitionPath,
    definitionPathHash: doctorHash(definitionPath),
    relativePath: relativePathForWorkspace(definitionPath, workspaceRoot),
    definitionHash,
    mutationPolicy: {
      outsideDeclaredCapabilitiesBlocked: true,
      mutationRequiresAuthorityScope: true,
      mutationRequiresToolContract: true,
    },
    validation: {
      status: nextIssues.length > 0 ? "degraded" : "pass",
      issues: [...new Set(nextIssues)],
    },
    evidenceRefs: ["runtime_hook_discovery", source.id, "hook_failure_policy"],
  };
}

export function redactedHookDefinition(record = {}) {
  const clone = { ...record };
  for (const key of ["command", "script", "env", "secrets", "headers"]) {
    if (clone[key] !== undefined) clone[key] = "[redacted]";
  }
  return clone;
}

export function parseMarkdownSkillMetadata(content = "") {
  const frontmatter = {};
  const text = String(content ?? "");
  if (text.startsWith("---")) {
    const end = text.indexOf("\n---", 3);
    if (end > 0) {
      for (const line of text.slice(3, end).split(/\r?\n/)) {
        const match = line.match(/^([A-Za-z0-9_.-]+):\s*(.*)$/);
        if (match) frontmatter[match[1]] = match[2].trim().replace(/^["']|["']$/g, "");
      }
    }
  }
  const title = text.match(/^#\s+(.+)$/m)?.[1]?.trim();
  return {
    name: optionalString(frontmatter.name),
    title: optionalString(title),
    description: optionalString(frontmatter.description),
    activationMode: optionalString(frontmatter.activationMode ?? frontmatter.activation_mode),
    capabilityScopes: normalizeStringList(frontmatter.capabilityScopes ?? frontmatter.capability_scopes),
    frontmatterKeys: Object.keys(frontmatter).sort(),
  };
}

export function inferHookEventKinds(name) {
  const text = String(name ?? "").toLowerCase();
  if (text.includes("pre-model") || text.includes("pre_model")) return ["pre_model"];
  if (text.includes("post-model") || text.includes("post_model")) return ["post_model"];
  if (text.includes("pre-tool") || text.includes("pre_tool")) return ["pre_tool"];
  if (text.includes("post-tool") || text.includes("post_tool")) return ["post_tool"];
  if (text.includes("approval")) return ["approval"];
  if (text.includes("activation")) return ["workflow_activation"];
  return ["event_subscriber"];
}

export function normalizeHookFailurePolicy(value) {
  const text = optionalString(value)?.toLowerCase();
  if (["block", "warn", "ignore", "retry"].includes(text)) return text;
  return "warn";
}

function normalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function normalizeStringList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => optionalString(item)).filter(Boolean);
  }
  const text = optionalString(value);
  return text ? text.split(",").map((item) => item.trim()).filter(Boolean) : [];
}

function doctorHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function safeId(value) {
  return String(value ?? "item")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "") || "item";
}

function safeDirectoryEntries(directory) {
  try {
    return fs.readdirSync(directory, { withFileTypes: true });
  } catch {
    return [];
  }
}

function safeStat(filePath) {
  try {
    return fs.statSync(filePath);
  } catch {
    return null;
  }
}

function readTextQuiet(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function readJsonQuiet(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function relativePathForWorkspace(filePath, workspaceRoot) {
  const relative = path.relative(workspaceRoot, filePath);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative) ? relative : null;
}
