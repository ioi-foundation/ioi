import {
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { listen } from "@tauri-apps/api/event";
import {
  type ConnectorConfigureResult,
  type ConnectorSummary,
  useMailConnectorActions,
} from "@ioi/agent-ide";
import { type TauriRuntime } from "../../../../services/TauriRuntime";
import type { SkillCatalogEntry, SkillDetailView } from "../../../../types";
import {
  CONNECTION_CATALOG,
  STARTER_SKILL_BUNDLES,
} from "../capabilitiesCatalog";
import {
  cloneLocalEngineControlPlane,
  CUSTOM_CONNECTIONS_STORAGE_KEY,
  SKILL_SWITCH_STORAGE_KEY,
  connectionDraftFromCatalog,
  connectorFromDraft,
  type EngineDetailSection,
  extensionStatusFromConnectors,
  humanize,
  loadStoredConnectionDrafts,
  loadStoredSkillSwitches,
  patchConnectorFromConfigurationResult,
  patchMailConnectorFromConfiguredAccount,
  skillDetailFromCatalog,
  type CapabilitySurface,
  type LocalEnginePanel,
  type StoredConnectionDraft,
  type WorkspaceExtension,
  type WorkspaceSkill,
} from "./model";

interface UseCapabilitiesControllerOptions {
  runtime: TauriRuntime;
}

export function useCapabilitiesController({
  runtime,
}: UseCapabilitiesControllerOptions) {
  const connectionsMenuRef = useRef<HTMLDivElement | null>(null);
  const [surface, setSurface] = useState<CapabilitySurface | null>(null);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [runtimeConnectors, setRuntimeConnectors] = useState<
    ConnectorSummary[]
  >([]);
  const [runtimeSkills, setRuntimeSkills] = useState<SkillCatalogEntry[]>([]);
  const [runtimeSkillDetails, setRuntimeSkillDetails] = useState<
    Record<string, SkillDetailView>
  >({});
  const [toolCount, setToolCount] = useState<number | null>(null);
  const [localEnginePanel, setLocalEnginePanel] = useState<LocalEnginePanel>({
    snapshot: null,
    loading: true,
    error: null,
    configDraft: null,
    configSaving: false,
    configMessage: null,
    stagingBusy: false,
  });
  const [storedConnections, setStoredConnections] = useState<
    StoredConnectionDraft[]
  >(() => loadStoredConnectionDrafts());
  const [enabledSkills, setEnabledSkills] = useState<Record<string, boolean>>(
    () => loadStoredSkillSwitches(),
  );
  const [selectedSkillHash, setSelectedSkillHash] = useState<string | null>(
    null,
  );
  const [selectedConnectionId, setSelectedConnectionId] = useState<
    string | null
  >(null);
  const [selectedExtensionId, setSelectedExtensionId] = useState<string | null>(
    null,
  );
  const [engineDetailSection, setEngineDetailSection] =
    useState<EngineDetailSection>("overview");
  const [selectedEngineFamilyId, setSelectedEngineFamilyId] = useState<
    string | null
  >(null);
  const [skillDetailSection, setSkillDetailSection] = useState<
    "overview" | "guide" | "procedure"
  >("guide");
  const [connectionDetailSection, setConnectionDetailSection] = useState<
    "overview" | "setup" | "policy"
  >("overview");
  const [extensionDetailSection, setExtensionDetailSection] = useState<
    "overview" | "surface"
  >("overview");
  const [catalogModalOpen, setCatalogModalOpen] = useState(false);
  const [customModalOpen, setCustomModalOpen] = useState(false);
  const [connectionsMenuOpen, setConnectionsMenuOpen] = useState(false);
  const [catalogCategoryFilter, setCatalogCategoryFilter] = useState<
    ConnectorSummary["category"] | "all"
  >("all");
  const [catalogQuery, setCatalogQuery] = useState("");
  const [customName, setCustomName] = useState("");
  const [customUrl, setCustomUrl] = useState("");
  const [customCategory, setCustomCategory] =
    useState<ConnectorSummary["category"]>("developer");
  const [customDescription, setCustomDescription] = useState(
    "Remote MCP surface exposed through a capability adapter.",
  );
  const [customScopes, setCustomScopes] = useState(
    "tools.invoke, resources.read",
  );
  const [customNotice, setCustomNotice] = useState<string | null>(null);
  const [genericConnectorMessage, setGenericConnectorMessage] = useState<
    string | null
  >(null);
  const [genericConnectorBusy, setGenericConnectorBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;

    runtime
      .getConnectors()
      .then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setRuntimeConnectors(items);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRuntimeConnectors([]);
        }
      });

    void runtime
      .getSkillCatalog()
      .then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setRuntimeSkills(items);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setRuntimeSkills([]);
        }
      });

    void runtime
      .getLocalEngineSnapshot()
      .then((snapshot) => {
        if (!cancelled) {
          setLocalEnginePanel({
            snapshot,
            loading: false,
            error: null,
            configDraft: cloneLocalEngineControlPlane(snapshot.controlPlane),
            configSaving: false,
            configMessage: null,
            stagingBusy: false,
          });
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setLocalEnginePanel({
            snapshot: null,
            loading: false,
            error: String(error),
            configDraft: null,
            configSaving: false,
            configMessage: null,
            stagingBusy: false,
          });
        }
      });

    void runtime
      .getAvailableTools()
      .then((items) => {
        if (!cancelled && Array.isArray(items)) {
          setToolCount(items.length);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setToolCount(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [runtime]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      CUSTOM_CONNECTIONS_STORAGE_KEY,
      JSON.stringify(storedConnections),
    );
  }, [storedConnections]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      SKILL_SWITCH_STORAGE_KEY,
      JSON.stringify(enabledSkills),
    );
  }, [enabledSkills]);

  useEffect(() => {
    setQuery("");
    setConnectionsMenuOpen(false);
  }, [surface]);

  useEffect(() => {
    if (surface === "engine") {
      setEngineDetailSection("overview");
    }
  }, [surface]);

  useEffect(() => {
    setSkillDetailSection("guide");
  }, [selectedSkillHash]);

  useEffect(() => {
    setConnectionDetailSection("overview");
    setGenericConnectorMessage(null);
  }, [selectedConnectionId]);

  useEffect(() => {
    setExtensionDetailSection("overview");
  }, [selectedExtensionId]);

  const filteredEngineFamilies = useMemo(() => {
    const families = localEnginePanel.snapshot?.capabilities ?? [];
    if (!deferredQuery.trim()) return families;
    const lowered = deferredQuery.trim().toLowerCase();
    return families.filter((family) =>
      [
        family.label,
        family.description,
        family.operatorSummary,
        family.toolNames.join(" "),
      ]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, localEnginePanel.snapshot]);

  useEffect(() => {
    if (!connectionsMenuOpen) return;

    const handlePointerDown = (event: PointerEvent) => {
      if (
        connectionsMenuRef.current &&
        !connectionsMenuRef.current.contains(event.target as Node)
      ) {
        setConnectionsMenuOpen(false);
      }
    };

    window.addEventListener("pointerdown", handlePointerDown);
    return () => {
      window.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [connectionsMenuOpen]);

  const mail = useMailConnectorActions(runtime, {
    onAccountConfigured(result) {
      setRuntimeConnectors((current) =>
        patchMailConnectorFromConfiguredAccount(current, result),
      );
    },
  });

  const workspaceSkills = useMemo<WorkspaceSkill[]>(() => {
    const runtimeByName = new Map(
      runtimeSkills.map((entry) => [entry.name.toLowerCase(), entry] as const),
    );

    const merged: WorkspaceSkill[] = runtimeSkills.map((entry) => ({
      hash: entry.skill_hash,
      catalog: entry,
      detail:
        runtimeSkillDetails[entry.skill_hash] ?? skillDetailFromCatalog(entry),
      origin: "runtime",
      addedBy:
        runtimeSkillDetails[entry.skill_hash]?.source_registry_label ??
        "Observed runtime",
      invokedBy: "Worker or workflow",
    }));

    for (const starter of STARTER_SKILL_BUNDLES) {
      if (runtimeByName.has(starter.catalog.name.toLowerCase())) {
        continue;
      }
      merged.push({
        hash: starter.catalog.skill_hash,
        catalog: starter.catalog,
        detail: starter.detail,
        origin: "starter",
        addedBy: starter.addedBy,
        invokedBy: starter.invokedBy,
      });
    }

    return merged.sort((left, right) => {
      if (left.origin !== right.origin) {
        return left.origin === "starter" ? -1 : 1;
      }
      if (left.catalog.stale !== right.catalog.stale) {
        return left.catalog.stale ? 1 : -1;
      }
      if (left.catalog.sample_size !== right.catalog.sample_size) {
        return right.catalog.sample_size - left.catalog.sample_size;
      }
      return left.catalog.name.localeCompare(right.catalog.name);
    });
  }, [runtimeSkillDetails, runtimeSkills]);

  const workspaceConnections = useMemo(() => {
    const runtimeIds = new Set(
      runtimeConnectors.map((connector) => connector.id),
    );
    const runtimePluginIds = new Set(
      runtimeConnectors.map((connector) => connector.pluginId),
    );
    const staged = storedConnections
      .filter(
        (draft) =>
          !runtimeIds.has(draft.id) && !runtimePluginIds.has(draft.pluginId),
      )
      .map((draft) => ({
        connector: connectorFromDraft(draft),
        origin: "workspace" as const,
      }));

    return [
      ...runtimeConnectors.map((connector) => ({
        connector,
        origin: "runtime" as const,
      })),
      ...staged,
    ];
  }, [runtimeConnectors, storedConnections]);

  const extensions = useMemo<WorkspaceExtension[]>(() => {
    const pluginMap = new Map<string, WorkspaceExtension>();

    pluginMap.set("core.operator", {
      id: "core.operator",
      name: "Core operator surface",
      description:
        "Built-in browser, file, and shell primitives available inside the local trust boundary.",
      status: "Built-in",
      meta:
        toolCount === null
          ? "Loading tool inventory from runtime"
          : `${toolCount} low-level tools available`,
      surfaces: ["Browser", "Files", "Shell", "Execution"],
    });

    for (const { connector } of workspaceConnections) {
      if (pluginMap.has(connector.pluginId)) continue;
      pluginMap.set(connector.pluginId, {
        id: connector.pluginId,
        name: humanize(connector.pluginId),
        description: connector.description,
        status: extensionStatusFromConnectors(
          workspaceConnections.map((item) => item.connector),
          connector.pluginId,
        ),
        meta: `${connector.provider} · ${connector.scopes.length} scopes`,
        surfaces: connector.scopes.slice(0, 6).map(humanize),
      });
    }

    return [...pluginMap.values()].sort((left, right) =>
      left.name.localeCompare(right.name),
    );
  }, [toolCount, workspaceConnections]);

  const filteredSkills = useMemo(() => {
    if (!deferredQuery.trim()) return workspaceSkills;
    const lowered = deferredQuery.trim().toLowerCase();
    return workspaceSkills.filter((skill) =>
      [
        skill.catalog.name,
        skill.catalog.description,
        skill.catalog.source_type,
        skill.detail.used_tools.join(" "),
      ]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, workspaceSkills]);

  const filteredConnections = useMemo(() => {
    if (!deferredQuery.trim()) return workspaceConnections;
    const lowered = deferredQuery.trim().toLowerCase();
    return workspaceConnections.filter(({ connector }) =>
      [
        connector.name,
        connector.provider,
        connector.description,
        connector.scopes.join(" "),
      ]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, workspaceConnections]);

  const filteredExtensions = useMemo(() => {
    if (!deferredQuery.trim()) return extensions;
    const lowered = deferredQuery.trim().toLowerCase();
    return extensions.filter((extension) =>
      [extension.name, extension.description, extension.surfaces.join(" ")]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, extensions]);

  const connectedConnectionCount = workspaceConnections.filter(
    ({ connector }) => connector.status === "connected",
  ).length;

  useEffect(() => {
    if (surface !== "engine") return;
    const next = filteredEngineFamilies[0]?.id ?? null;
    if (
      !selectedEngineFamilyId ||
      !filteredEngineFamilies.some((family) => family.id === selectedEngineFamilyId)
    ) {
      setSelectedEngineFamilyId(next);
    }
  }, [filteredEngineFamilies, selectedEngineFamilyId, surface]);

  const openSurface = (nextSurface: CapabilitySurface) => {
    setSurface(nextSurface);
  };

  const returnToHome = () => {
    setSurface(null);
    setQuery("");
    setConnectionsMenuOpen(false);
  };

  useEffect(() => {
    if (surface !== "skills") return;
    const next = filteredSkills[0]?.hash ?? null;
    if (
      !selectedSkillHash ||
      !filteredSkills.some((skill) => skill.hash === selectedSkillHash)
    ) {
      setSelectedSkillHash(next);
    }
  }, [filteredSkills, selectedSkillHash, surface]);

  useEffect(() => {
    if (surface !== "connections") return;
    const next = filteredConnections[0]?.connector.id ?? null;
    if (
      !selectedConnectionId ||
      !filteredConnections.some(
        ({ connector }) => connector.id === selectedConnectionId,
      )
    ) {
      setSelectedConnectionId(next);
    }
  }, [filteredConnections, selectedConnectionId, surface]);

  useEffect(() => {
    if (surface !== "extensions") return;
    const next = filteredExtensions[0]?.id ?? null;
    if (
      !selectedExtensionId ||
      !filteredExtensions.some((item) => item.id === selectedExtensionId)
    ) {
      setSelectedExtensionId(next);
    }
  }, [filteredExtensions, selectedExtensionId, surface]);

  const selectedSkill =
    workspaceSkills.find((skill) => skill.hash === selectedSkillHash) ?? null;
  const selectedConnectionRecord =
    workspaceConnections.find(
      ({ connector }) => connector.id === selectedConnectionId,
    ) ?? null;
  const selectedExtension =
    extensions.find((extension) => extension.id === selectedExtensionId) ??
    null;
  const selectedEngineFamily =
    localEnginePanel.snapshot?.capabilities.find(
      (family) => family.id === selectedEngineFamilyId,
    ) ?? filteredEngineFamilies[0] ?? null;

  useEffect(() => {
    if (!selectedSkill || selectedSkill.origin !== "runtime") return;
    if (runtimeSkillDetails[selectedSkill.hash]) return;

    let cancelled = false;

    runtime
      .getSkillDetail(selectedSkill.hash)
      .then((detail) => {
        if (cancelled) return;
        setRuntimeSkillDetails((current) => ({
          ...current,
          [selectedSkill.hash]: detail,
        }));
      })
      .catch(() => {
        if (cancelled) return;
        setRuntimeSkillDetails((current) => ({
          ...current,
          [selectedSkill.hash]: skillDetailFromCatalog(selectedSkill.catalog),
        }));
      });

    return () => {
      cancelled = true;
    };
  }, [runtime, runtimeSkillDetails, selectedSkill]);

  const availableCatalogItems = useMemo(() => {
    const existingIds = new Set([
      ...workspaceConnections.map(({ connector }) => connector.pluginId),
      ...workspaceConnections.map(({ connector }) => connector.id),
    ]);
    const lowered = catalogQuery.trim().toLowerCase();

    return CONNECTION_CATALOG.filter((item) => {
      if (
        catalogCategoryFilter !== "all" &&
        item.category !== catalogCategoryFilter
      ) {
        return false;
      }
      if (
        lowered &&
        ![item.name, item.provider, item.description, item.scopes.join(" ")]
          .join(" ")
          .toLowerCase()
          .includes(lowered)
      ) {
        return false;
      }
      return true;
    }).map((item) => ({
      item,
      alreadyAdded:
        existingIds.has(item.id) ||
        existingIds.has(
          item.id === "google_workspace" ? "google.workspace" : item.id,
        ) ||
        existingIds.has(item.id === "wallet_mail" ? "mail.primary" : item.id),
    }));
  }, [catalogCategoryFilter, catalogQuery, workspaceConnections]);

  const addCatalogConnection = (item: (typeof CONNECTION_CATALOG)[number]) => {
    const draft = connectionDraftFromCatalog(item);

    setStoredConnections((current) => {
      if (
        current.some(
          (existing) =>
            existing.id === draft.id || existing.pluginId === draft.pluginId,
        )
      ) {
        return current;
      }
      return [...current, draft];
    });

    setSelectedConnectionId(draft.id);
    setSurface("connections");
    setCatalogModalOpen(false);
    setConnectionsMenuOpen(false);
    setCustomNotice(`${item.name} added to the workspace shell.`);
  };

  const createCustomConnection = () => {
    const trimmedName = customName.trim();
    const trimmedUrl = customUrl.trim();
    if (!trimmedName || !trimmedUrl) {
      setCustomNotice(
        "Add a name and remote endpoint to register a custom connection.",
      );
      return;
    }

    const slug = trimmedName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
    const draft: StoredConnectionDraft = {
      id: `custom.${slug || "connection"}`,
      pluginId: `custom.mcp.${slug || "connection"}`,
      name: trimmedName,
      provider: "mcp",
      category: customCategory,
      description: customDescription.trim(),
      authMode: "api_key",
      scopes: customScopes
        .split(",")
        .map((scope) => scope.trim())
        .filter(Boolean),
      notes:
        "Custom connection staged locally. Install or bind the remote MCP adapter to activate tool execution.",
      endpoint: trimmedUrl,
    };

    setStoredConnections((current) => {
      const next = current.filter((item) => item.id !== draft.id);
      next.push(draft);
      return next;
    });
    setSelectedConnectionId(draft.id);
    setSurface("connections");
    setCustomModalOpen(false);
    setConnectionsMenuOpen(false);
    setCustomName("");
    setCustomUrl("");
    setCustomDescription(
      "Remote MCP surface exposed through a capability adapter.",
    );
    setCustomScopes("tools.invoke, resources.read");
    setCustomNotice(`${trimmedName} added as a custom connection.`);
  };

  const runGenericConnectorSetup = async (connector: ConnectorSummary) => {
    if (!runtime.configureConnector) {
      setGenericConnectorMessage(
        "This connection is staged in the workspace, but the runtime does not expose a generic configure flow yet.",
      );
      return;
    }

    setGenericConnectorBusy(true);
    setGenericConnectorMessage(null);
    try {
      const result = await runtime.configureConnector({
        connectorId: connector.id,
        input: {},
      });
      setRuntimeConnectors((current) =>
        patchConnectorFromConfigurationResult(current, result),
      );
      setGenericConnectorMessage(result.summary);
    } catch (error) {
      setGenericConnectorMessage(String(error));
    } finally {
      setGenericConnectorBusy(false);
    }
  };

  const applyConfiguredConnectorResult = (result: ConnectorConfigureResult) => {
    setRuntimeConnectors((current) =>
      patchConnectorFromConfigurationResult(current, result),
    );
  };

  const refreshLocalEngineSnapshot = async () => {
    setLocalEnginePanel((current) => ({
      ...current,
      loading: true,
      error: null,
      configMessage: null,
    }));
    try {
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft &&
          current.snapshot &&
          JSON.stringify(current.configDraft) !==
            JSON.stringify(current.snapshot.controlPlane)
            ? current.configDraft
            : cloneLocalEngineControlPlane(snapshot.controlPlane),
        configSaving: false,
        stagingBusy: false,
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        loading: false,
        error: String(error),
      }));
    }
  };

  useEffect(() => {
    let active = true;
    const unlistenPromise = listen("local-engine-updated", () => {
      if (!active) return;
      void runtime
        .getLocalEngineSnapshot()
        .then((snapshot) => {
          if (!active) return;
          setLocalEnginePanel((current) => ({
            ...current,
            snapshot,
            loading: false,
            error: null,
            configDraft:
              current.configDraft &&
              current.snapshot &&
              JSON.stringify(current.configDraft) !==
                JSON.stringify(current.snapshot.controlPlane)
                ? current.configDraft
                : cloneLocalEngineControlPlane(snapshot.controlPlane),
          }));
        })
        .catch(() => undefined);
    });

    return () => {
      active = false;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [runtime]);

  const setEngineConfigDraft = (
    next:
      | LocalEnginePanel["configDraft"]
      | ((current: NonNullable<LocalEnginePanel["configDraft"]>) => NonNullable<LocalEnginePanel["configDraft"]>),
  ) => {
    setLocalEnginePanel((current) => {
      if (!current.configDraft) return current;
      const resolved =
        typeof next === "function"
          ? next(current.configDraft)
          : next;
      return {
        ...current,
        configDraft: resolved
          ? cloneLocalEngineControlPlane(resolved)
          : current.configDraft,
        configMessage: null,
      };
    });
  };

  const resetEngineConfigDraft = () => {
    setLocalEnginePanel((current) =>
      current.snapshot
        ? {
            ...current,
            configDraft: cloneLocalEngineControlPlane(current.snapshot.controlPlane),
            configMessage: null,
          }
        : current,
    );
  };

  const saveEngineConfigDraft = async () => {
    const draft = localEnginePanel.configDraft;
    if (!draft) return;
    setLocalEnginePanel((current) => ({
      ...current,
      configSaving: true,
      configMessage: null,
      error: null,
    }));
    try {
      const saved = await runtime.saveLocalEngineControlPlane(draft);
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot: current.snapshot
          ? { ...current.snapshot, controlPlane: saved }
          : current.snapshot,
        configDraft: cloneLocalEngineControlPlane(saved),
        configSaving: false,
        configMessage: "Local engine settings saved to the kernel control plane.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        configSaving: false,
        configMessage: String(error),
      }));
    }
  };

  const stageEngineOperation = async (input: {
    subjectKind: string;
    operation: string;
    sourceUri?: string | null;
    subjectId?: string | null;
    notes?: string | null;
  }) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.stageLocalEngineOperation(input);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage:
          "Staged operation added to the Local Engine queue for later native execution.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const removeEngineOperation = async (operationId: string) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.removeLocalEngineOperation(operationId);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage: "Staged operation removed from the Local Engine queue.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const promoteEngineOperation = async (operationId: string) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.promoteLocalEngineOperation(operationId);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage:
          "Staged plan promoted into the live Local Engine job queue.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const updateEngineJobStatus = async (jobId: string, status: string) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.updateLocalEngineJobStatus({ jobId, status });
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage:
          "Local Engine job state updated in the kernel control plane.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const retryParentPlaybookRun = async (runId: string) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.retryLocalEngineParentPlaybookRun(runId);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage:
          "Retry request sent to the active parent playbook step.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const resumeParentPlaybookRun = async (
    runId: string,
    stepId?: string | null,
  ) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.resumeLocalEngineParentPlaybookRun(runId, stepId);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage: stepId
          ? "Resume request sent for the selected parent playbook step."
          : "Resume request sent for the current parent playbook step.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const dismissParentPlaybookRun = async (runId: string) => {
    setLocalEnginePanel((current) => ({
      ...current,
      stagingBusy: true,
      configMessage: null,
      error: null,
    }));
    try {
      await runtime.dismissLocalEngineParentPlaybookRun(runId);
      const snapshot = await runtime.getLocalEngineSnapshot();
      setLocalEnginePanel((current) => ({
        ...current,
        snapshot,
        loading: false,
        error: null,
        configDraft:
          current.configDraft ??
          cloneLocalEngineControlPlane(snapshot.controlPlane),
        stagingBusy: false,
        configMessage:
          "Parent playbook run dismissed from the Runtime Deck.",
      }));
    } catch (error) {
      setLocalEnginePanel((current) => ({
        ...current,
        stagingBusy: false,
        configMessage: String(error),
      }));
    }
  };

  const engineConfigDirty =
    !!localEnginePanel.snapshot &&
    JSON.stringify(localEnginePanel.snapshot.controlPlane) !==
      JSON.stringify(localEnginePanel.configDraft);

  return {
    runtime,
    connectionsMenuRef,
    surface,
    query,
    setQuery,
    openSurface,
    returnToHome,
    toolCount,
    connectedConnectionCount,
    mail,
    engine: {
      ...localEnginePanel,
      detailSection: engineDetailSection,
      setDetailSection: setEngineDetailSection,
      selectedFamily: selectedEngineFamily,
      selectedFamilyId: selectedEngineFamilyId,
      setSelectedFamilyId: setSelectedEngineFamilyId,
      filteredFamilies: filteredEngineFamilies,
      refreshSnapshot: refreshLocalEngineSnapshot,
      configDirty: engineConfigDirty,
      setConfigDraft: setEngineConfigDraft,
      resetConfigDraft: resetEngineConfigDraft,
      saveConfigDraft: saveEngineConfigDraft,
      stageOperation: stageEngineOperation,
      removeOperation: removeEngineOperation,
      promoteOperation: promoteEngineOperation,
      updateJobStatus: updateEngineJobStatus,
      retryParentPlaybookRun,
      resumeParentPlaybookRun,
      dismissParentPlaybookRun,
    },
    skills: {
      items: workspaceSkills,
      filteredItems: filteredSkills,
      selectedSkill,
      selectedSkillHash,
      setSelectedSkillHash,
      detailSection: skillDetailSection,
      setDetailSection: setSkillDetailSection,
      enabledSkills,
      setEnabledSkills,
    },
    connections: {
      items: workspaceConnections,
      filteredItems: filteredConnections,
      selectedRecord: selectedConnectionRecord,
      selectedConnectionId,
      setSelectedConnectionId,
      detailSection: connectionDetailSection,
      setDetailSection: setConnectionDetailSection,
      menuOpen: connectionsMenuOpen,
      setMenuOpen: setConnectionsMenuOpen,
      customNotice,
      setCustomNotice,
      genericConnectorMessage,
      genericConnectorBusy,
      runGenericConnectorSetup,
      applyConfiguredConnectorResult,
      catalogModalOpen,
      setCatalogModalOpen,
      catalogCategoryFilter,
      setCatalogCategoryFilter,
      catalogQuery,
      setCatalogQuery,
      availableCatalogItems,
      addCatalogConnection,
      customModalOpen,
      setCustomModalOpen,
      customName,
      setCustomName,
      customUrl,
      setCustomUrl,
      customCategory,
      setCustomCategory,
      customDescription,
      setCustomDescription,
      customScopes,
      setCustomScopes,
      createCustomConnection,
    },
    extensions: {
      items: extensions,
      filteredItems: filteredExtensions,
      selectedExtension,
      selectedExtensionId,
      setSelectedExtensionId,
      detailSection: extensionDetailSection,
      setDetailSection: setExtensionDetailSection,
    },
  };
}

export type CapabilitiesController = ReturnType<
  typeof useCapabilitiesController
>;
