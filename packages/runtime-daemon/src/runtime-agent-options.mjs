import fs from "node:fs";
import path from "node:path";

export function createRuntimeAgentOptionsHelpers({
  doctorHash,
  externalBlocker,
  readJson,
  env = process.env,
}) {
  function summarizeAgentOptions(cwd, options = {}) {
    const cursorConfig = loadCursorCompatibilityConfig(cwd);
    return {
      localCwd: options.local?.cwd,
      cloudConfigured: Boolean(options.cloud ?? options.hosted),
      selfHostedConfigured: Boolean(options.selfHosted),
      mcpServerNames: [
        ...new Set([
          ...Object.keys(options.mcp_servers ?? {}),
          ...Object.keys(cursorConfig.mcpServers),
        ]),
      ],
      skillNames: cursorConfig.skillNames,
      hookNames: cursorConfig.hookNames,
      subagentNames: Object.keys(options.agents ?? {}),
      sandboxProfile: options.sandboxOptions?.profile ?? "development",
    };
  }

  function loadCursorCompatibilityConfig(cwd) {
    const cursorDir = path.join(cwd, ".cursor");
    const mcpPath = path.join(cursorDir, "mcp.json");
    const hooksPath = path.join(cursorDir, "hooks.json");
    const skillsDir = path.join(cursorDir, "skills");
    return {
      mcpServers: fs.existsSync(mcpPath) ? readJson(mcpPath).mcpServers ?? {} : {},
      hookNames: fs.existsSync(hooksPath) ? Object.keys(readJson(hooksPath)) : [],
      skillNames: fs.existsSync(skillsDir)
        ? fs.readdirSync(skillsDir).filter((entry) => !entry.startsWith("."))
        : [],
    };
  }

  function runtimeModeForOptions(options = {}) {
    if (options.cloud) return "cloud";
    if (options.hosted) return "hosted";
    if (options.selfHosted) return "selfHosted";
    return "local";
  }

  function ensureProviderAvailable(runtime, options = {}) {
    if (runtime === "local") return;
    const endpoint =
      options.hosted?.endpoint ??
      options.hosted?.provider?.endpoint ??
      options.cloud?.endpoint ??
      options.selfHosted?.endpoint ??
      env.IOI_AGENT_SDK_HOSTED_ENDPOINT ??
      env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
    if (!endpoint) {
      throw externalBlocker(`${runtime} runtime requested, but no IOI worker provider endpoint is configured.`, {
        runtime,
        requiredEnvironment: [
          "IOI_AGENT_SDK_HOSTED_ENDPOINT",
          "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
        ],
      });
    }
  }

  function memoryOptionsForRequest(request = {}) {
    return {
      ...(request.memory ?? {}),
      ...(request.options?.memory ?? {}),
    };
  }

  function doctorProviderKeyReport() {
    return [
      "OPENAI_API_KEY",
      "ANTHROPIC_API_KEY",
      "DEEPSEEK_API_KEY",
      "OPENROUTER_API_KEY",
      "IOI_AGENT_SDK_HOSTED_ENDPOINT",
      "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
    ].map((name) => ({
      name,
      source: "env",
      configured: Boolean(env[name]),
      valueRedacted: true,
      valueHash: env[name] ? doctorHash(env[name]) : null,
    }));
  }

  return {
    doctorProviderKeyReport,
    ensureProviderAvailable,
    loadCursorCompatibilityConfig,
    memoryOptionsForRequest,
    runtimeModeForOptions,
    summarizeAgentOptions,
  };
}
