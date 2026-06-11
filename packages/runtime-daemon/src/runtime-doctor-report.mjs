export function createRuntimeDoctorReport({
  doctorCheck,
  doctorHash,
  doctorProviderKeyReport,
  fs,
  normalizeArray,
  path,
  processEnv = process.env,
  redactRuntimeNodeForDoctor,
} = {}) {
  function doctorReport(store, { baseUrl = null } = {}) {
    const generatedAt = new Date().toISOString();
    const modelProjection = store.modelMounting.projection();
    const skillHookCatalog = skillHookCatalogForDoctor(store);
    const runtimeToolCatalog = runtimeToolCatalogForDoctor(store);
    const runtimeNodes = runtimeNodesForDoctor(store);
    const memoryPaths = store.memory.pathProjection({
      threadId: null,
      workspace: store.defaultCwd,
    });
    const providerKeys = doctorProviderKeyReport();
    const optionalWarnings = [];
    const checks = [
      doctorCheck("daemon.public_api", "pass", true, "Public runtime daemon routes are reachable.", [
        "/v1/doctor",
      ]),
      doctorCheck(
        "workspace.root",
        fs.existsSync(store.defaultCwd) ? "pass" : "blocked",
        true,
        fs.existsSync(store.defaultCwd)
          ? "Workspace root exists."
          : "Workspace root is missing.",
        [store.defaultCwd],
      ),
      doctorCheck(
        "agentgres.store",
        fs.existsSync(store.stateDir) ? "pass" : "blocked",
        true,
        "Agentgres v0 state directory is present.",
        [store.stateDir, "agentgres_canonical_state_projection"],
      ),
      doctorCheck(
        "model.routes",
        modelProjection.routes.length > 0 ? "pass" : "blocked",
        true,
        `${modelProjection.routes.length} model route(s) are registered.`,
        modelProjection.routes.map((route) => route.id),
      ),
      doctorCheck(
        "memory.store",
        fs.existsSync(memoryPaths.recordsPath) && fs.existsSync(memoryPaths.policiesPath)
          ? "pass"
          : "blocked",
        true,
        "Memory records and policies are backed by durable state paths.",
        [memoryPaths.recordsPath, memoryPaths.policiesPath],
      ),
      doctorCheck(
        "tool.catalog",
        runtimeToolCatalog.status,
        false,
        runtimeToolCatalog.message,
        runtimeToolCatalog.toolIds,
      ),
      doctorCheck(
        "workflow.react_flow_registry",
        "pass",
        true,
        "React Flow registry exposes runtime doctor and readiness nodes.",
        ["RuntimeDoctorNode", "packages/agent-ide/src/runtime/workflow-node-registry.ts"],
      ),
      doctorCheck(
        "mcp.registry",
        modelProjection.mcpServers.length > 0 ? "pass" : "degraded",
        false,
        modelProjection.mcpServers.length > 0
          ? `${modelProjection.mcpServers.length} MCP server(s) are registered.`
          : "No MCP servers are registered; MCP remains optional.",
        modelProjection.mcpServers.map((server) => server.id),
      ),
      doctorCheck(
        "skills.hooks",
        skillHookCatalog.status,
        false,
        `${skillHookCatalog.skillCount} governed skill(s) and ${skillHookCatalog.hookCount} hook(s) discovered across ${skillHookCatalog.sources.length} source(s).`,
        ["runtime_skill_hook_discovery", "/v1/skills", "/v1/hooks"],
      ),
      doctorCheck(
        "wallet.network",
        processEnv.IOI_WALLET_NETWORK_URL ? "pass" : "degraded",
        false,
        processEnv.IOI_WALLET_NETWORK_URL
          ? "Wallet/network approval endpoint is configured."
          : "Wallet/network approval endpoint is optional and not configured.",
        ["IOI_WALLET_NETWORK_URL"],
      ),
      doctorCheck(
        "remote.agentgres",
        processEnv.IOI_AGENTGRES_URL ? "pass" : "degraded",
        false,
        processEnv.IOI_AGENTGRES_URL
          ? "Remote Agentgres adapter is configured."
          : "Remote Agentgres adapter is optional and not configured.",
        ["IOI_AGENTGRES_URL"],
      ),
      doctorCheck(
        "lsp.status",
        "degraded",
        false,
        "LSP health is not daemon-owned yet; workflow activation should treat it as optional.",
        ["lsp.status.next_slice"],
      ),
    ];
    for (const check of checks) {
      if (!check.required && check.status !== "pass") optionalWarnings.push(check.id);
    }
    const requiredFailures = checks.filter((check) => check.required && check.status !== "pass");
    const status = requiredFailures.length > 0
      ? "blocked"
      : optionalWarnings.length > 0
        ? "degraded"
        : "pass";
    return {
      schemaVersion: "ioi.agent-runtime.doctor.v1",
      object: "ioi.agent_runtime_doctor_report",
      generatedAt,
      status,
      readiness: requiredFailures.length > 0 ? "blocked" : "ready",
      version: {
        runtime: "ioi-runtime-daemon",
        schema: store.schemaVersion,
      },
      daemon: {
        endpoint: baseUrl,
        publicApi: "/v1",
        nativeApi: "/api/v1",
        requestScoped: true,
      },
      workspace: {
        root: store.defaultCwd,
        exists: fs.existsSync(store.defaultCwd),
      },
      configPaths: {
        stateDir: store.stateDir,
        projections: path.join(store.stateDir, "projections"),
        memoryRecords: memoryPaths.recordsPath,
        memoryPolicies: memoryPaths.policiesPath,
        modelMountingProjection: path.join(store.stateDir, "projections", "model-mounting-canonical.json"),
      },
      providerKeys,
      modelRoutes: {
        modelCount: modelProjection.artifacts.length,
        routeCount: modelProjection.routes.length,
        routeIds: modelProjection.routes.map((route) => route.id),
        selectedDefaultRoute: modelProjection.routes.find((route) => route.id === "route.local-first")?.id ?? null,
      },
      mcp: {
        serverCount: modelProjection.mcpServers.length,
        servers: modelProjection.mcpServers.map((server) => ({
          id: server.id,
          transport: server.transport,
          status: server.status,
          secretRefCount: normalizeArray(server.secretRefs).length,
          secretsRedacted: true,
        })),
      },
      skillsHooks: {
        status: skillHookCatalog.status,
        skillCount: skillHookCatalog.skillCount,
        hookCount: skillHookCatalog.hookCount,
        sourceCount: skillHookCatalog.sources.length,
        activeSkillSetHash: skillHookCatalog.activeSkillSetHash,
        activeHookSetHash: skillHookCatalog.activeHookSetHash,
        validationIssueCount: skillHookCatalog.validationIssueCount,
        rustCoreRequired: skillHookCatalog.rustCoreRequired === true,
        rustCoreDetails: skillHookCatalog.rustCoreDetails ?? null,
        discoveryEndpoints: ["/v1/skills", "/v1/hooks"],
      },
      memory: {
        recordCount: store.memory.records.size,
        policyCount: store.memory.policies.size,
        defaultPolicy: store.memory.effectivePolicy({
          threadId: null,
          workspace: store.defaultCwd,
        }),
        paths: memoryPaths,
      },
      sandbox: {
        status: "pass",
        profile: "local_private",
        approvalMode: "suggest",
        networkDefault: "local_only",
      },
      workflow: {
        reactFlowRegistryVersion: "ioi.reactflow.workflow-node-registry.v1",
        doctorNodeType: "runtime_doctor",
        activationConsumesDoctorReport: true,
        readinessBlockerField: "checks",
      },
      agentgres: {
        schemaVersion: store.schemaVersion,
        source: "agentgres_canonical_state_projection",
        runStateWatermark: store.runs instanceof Map ? store.runs.size : 0,
        localStateDirPresent: fs.existsSync(store.stateDir),
        remoteAdapterConfigured: Boolean(processEnv.IOI_AGENTGRES_URL),
        remoteAdapterHash: processEnv.IOI_AGENTGRES_URL ? doctorHash(processEnv.IOI_AGENTGRES_URL) : null,
      },
      wallet: {
        approvalStatus: processEnv.IOI_WALLET_NETWORK_URL ? "configured" : "not_configured",
        networkConfigured: Boolean(processEnv.IOI_WALLET_NETWORK_URL),
        networkUrlHash: processEnv.IOI_WALLET_NETWORK_URL ? doctorHash(processEnv.IOI_WALLET_NETWORK_URL) : null,
      },
      runtimeNodes: runtimeNodes.nodes.map((node) => redactRuntimeNodeForDoctor(node, { doctorHash })),
      checks,
      blockers: requiredFailures.map((check) => check.id),
      optionalWarnings,
      redaction: {
        profile: "doctor_safe",
        secretValuesIncluded: false,
        endpointValuesHashed: true,
      },
      evidenceRefs: ["ioi_agent_runtime_doctor", "runtime_preflight", "RuntimeDoctorNode"],
    };
  }

  return {
    doctorReport,
  };
}

function runtimeToolCatalogForDoctor(store) {
  try {
    const tools = store.toolSurface.listTools();
    return {
      status: tools.length > 0 ? "pass" : "blocked",
      message: `${tools.length} governed runtime tool(s) are registered.`,
      toolIds: tools.map((tool) => tool.stable_tool_id),
      rustCoreRequired: false,
      rustCoreDetails: null,
    };
  } catch (error) {
    if (error?.code !== "runtime_tool_catalog_rust_core_required") {
      throw error;
    }
    return {
      status: "degraded",
      message: "Runtime tool catalog projection is retired in JS and requires direct Rust daemon-core projection.",
      toolIds: [
        "runtime_tool_catalog_js_projection_retired",
        "rust_daemon_core_runtime_tool_catalog_required",
      ],
      rustCoreRequired: true,
      rustCoreDetails: error.details,
    };
  }
}

function runtimeNodesForDoctor(store) {
  try {
    return {
      nodes: store.toolSurface.listRuntimeNodes(),
      rustCoreRequired: false,
      rustCoreDetails: null,
    };
  } catch (error) {
    if (error?.code !== "runtime_tool_catalog_rust_core_required") {
      throw error;
    }
    return {
      nodes: [],
      rustCoreRequired: true,
      rustCoreDetails: error.details,
    };
  }
}

function skillHookCatalogForDoctor(store) {
  try {
    return store.skillHookSurface.skillHookCatalog({ cwd: store.defaultCwd });
  } catch (error) {
    if (error?.code !== "runtime_skill_hook_registry_rust_core_required") {
      throw error;
    }
    return {
      status: "degraded",
      skillCount: 0,
      hookCount: 0,
      sources: [],
      activeSkillSetHash: null,
      activeHookSetHash: null,
      validationIssueCount: 1,
      rustCoreRequired: true,
      rustCoreDetails: error.details,
    };
  }
}
