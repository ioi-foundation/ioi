import {
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useState,
} from "react";
import { listen } from "@tauri-apps/api/event";
import {
  type ConnectorActionDefinition,
  type ConnectorConfigureResult,
  type ConnectorSummary,
  useMailConnectorActions,
} from "@ioi/agent-ide";
import { safelyDisposeTauriListener } from "../../../services/tauriListeners";
import { type TauriRuntime } from "../../../services/TauriRuntime";
import type {
  CapabilityRegistryEntry,
  CapabilityRegistrySnapshot,
  ExtensionManifestRecord,
  SkillCatalogEntry,
  SkillSourceRecord,
} from "../../../types";
import {
  cloneLocalEngineControlPlane,
  type CapabilitySurface,
  type ConnectionDetailSection,
  CUSTOM_CONNECTIONS_STORAGE_KEY,
  type EngineDetailSection,
  type ExtensionDetailSection,
  extensionStatusLabel,
  humanize,
  loadStoredConnectionDrafts,
  patchConnectorFromConfigurationResult,
  patchMailConnectorFromConfiguredAccount,
  type RuntimeConnectorActionState,
  templateRecordFromDraft,
  type LocalEnginePanel,
  type RuntimeSkillDetailState,
  type StoredConnectionDraft,
  type WorkspaceConnectionRecord,
  type WorkspaceConnectionTemplateRecord,
  type WorkspaceExtension,
  type WorkspaceSkill,
  workspaceSkillFromExtensionManifest,
  workspaceSkillFromSkillSource,
} from "./model";
import {
  type CapabilityGovernanceProposal,
  type CapabilityGovernanceRequest,
  type CapabilityPolicyIntentAction,
} from "../../Policy/policyCenter";

interface UseCapabilitiesControllerOptions {
  runtime: TauriRuntime;
  onOpenPolicyCenter?: (connector?: ConnectorSummary | null) => void;
}

export interface RelatedGoverningEntry {
  entry: CapabilityRegistryEntry;
  sharedHints: string[];
}

function sourceRegistryKey(kind: string | null | undefined, uri: string | null | undefined) {
  const normalizedKind = (kind ?? "").trim().toLowerCase();
  const normalizedUri = (uri ?? "").trim().replace(/\\/g, "/");
  return `${normalizedKind}:${normalizedUri}`;
}

export function useCapabilitiesController({
  runtime,
  onOpenPolicyCenter,
}: UseCapabilitiesControllerOptions) {
  const [surface, setSurface] = useState<CapabilitySurface | null>(null);
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [capabilityRegistrySnapshot, setCapabilityRegistrySnapshot] =
    useState<CapabilityRegistrySnapshot | null>(null);
  const [capabilityRegistryLoading, setCapabilityRegistryLoading] =
    useState(true);
  const [capabilityRegistryError, setCapabilityRegistryError] = useState<
    string | null
  >(null);
  const [runtimeConnectors, setRuntimeConnectors] = useState<
    ConnectorSummary[]
  >([]);
  const [runtimeConnectorsLoading, setRuntimeConnectorsLoading] = useState(true);
  const [runtimeConnectorsError, setRuntimeConnectorsError] = useState<string | null>(
    null,
  );
  const [runtimeSkills, setRuntimeSkills] = useState<SkillCatalogEntry[]>([]);
  const [runtimeSkillsLoading, setRuntimeSkillsLoading] = useState(true);
  const [runtimeSkillsError, setRuntimeSkillsError] = useState<string | null>(null);
  const [skillSources, setSkillSources] = useState<SkillSourceRecord[]>([]);
  const [skillSourcesLoading, setSkillSourcesLoading] = useState(true);
  const [skillSourcesError, setSkillSourcesError] = useState<string | null>(null);
  const [extensionManifests, setExtensionManifests] = useState<
    ExtensionManifestRecord[]
  >([]);
  const [extensionManifestsLoading, setExtensionManifestsLoading] = useState(true);
  const [extensionManifestsError, setExtensionManifestsError] = useState<string | null>(
    null,
  );
  const [runtimeSkillDetails, setRuntimeSkillDetails] = useState<
    Record<string, RuntimeSkillDetailState>
  >({});
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
  const [selectedSkillHash, setSelectedSkillHash] = useState<string | null>(
    null,
  );
  const [selectedConnectionId, setSelectedConnectionId] = useState<
    string | null
  >(null);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(
    null,
  );
  const [selectedExtensionId, setSelectedExtensionId] = useState<string | null>(
    null,
  );
  const [engineDetailSection, setEngineDetailSection] =
    useState<EngineDetailSection>("overview");
  const [selectedEngineFamilyId, setSelectedEngineFamilyId] = useState<
    string | null
  >(null);
  const [selectedEngineRegistryEntryId, setSelectedEngineRegistryEntryId] =
    useState<string | null>(null);
  const [skillDetailSection, setSkillDetailSection] = useState<
    "overview" | "guide" | "procedure"
  >("guide");
  const [connectionDetailSection, setConnectionDetailSection] =
    useState<ConnectionDetailSection>("overview");
  const [extensionDetailSection, setExtensionDetailSection] =
    useState<ExtensionDetailSection>("overview");
  const [runtimeConnectorActions, setRuntimeConnectorActions] = useState<
    Record<string, RuntimeConnectorActionState>
  >({});
  const [customModalOpen, setCustomModalOpen] = useState(false);
  const [customName, setCustomName] = useState("");
  const [customUrl, setCustomUrl] = useState("");
  const [customCategory, setCustomCategory] =
    useState<ConnectorSummary["category"]>("developer");
  const [customDescription, setCustomDescription] = useState(
    "Workspace planning template for a remote MCP surface or adapter.",
  );
  const [customScopes, setCustomScopes] = useState(
    "tools.invoke, resources.read",
  );
  const [customNotice, setCustomNotice] = useState<string | null>(null);
  const [genericConnectorMessage, setGenericConnectorMessage] = useState<
    string | null
  >(null);
  const [genericConnectorBusy, setGenericConnectorBusy] = useState(false);
  const [sourceRegistryBusy, setSourceRegistryBusy] = useState(false);
  const [sourceRegistryMessage, setSourceRegistryMessage] = useState<string | null>(
    null,
  );
  const [sourceRegistryError, setSourceRegistryError] = useState<string | null>(
    null,
  );
  const [sourceRegistryModalOpen, setSourceRegistryModalOpen] =
    useState(false);
  const [sourceRegistryLabel, setSourceRegistryLabel] = useState("");
  const [sourceRegistryUri, setSourceRegistryUri] = useState("");

  const applyCapabilityRegistrySnapshot = useCallback(
    (
      snapshot: CapabilityRegistrySnapshot,
      options?: {
        preserveDraft?: boolean;
        preserveConfigSaving?: boolean;
        preserveStagingBusy?: boolean;
        configMessage?: string | null;
      },
    ) => {
      setCapabilityRegistrySnapshot(snapshot);
      setCapabilityRegistryError(null);
      setCapabilityRegistryLoading(false);

      setRuntimeConnectors(snapshot.connectors);
      setRuntimeConnectorsLoading(false);
      setRuntimeConnectorsError(null);

      setRuntimeSkills(snapshot.skillCatalog);
      setRuntimeSkillsLoading(false);
      setRuntimeSkillsError(null);

      setSkillSources(snapshot.skillSources);
      setSkillSourcesLoading(false);
      setSkillSourcesError(null);

      setExtensionManifests(snapshot.extensionManifests);
      setExtensionManifestsLoading(false);
      setExtensionManifestsError(null);

      setLocalEnginePanel((current) => {
        const preserveDraft =
          options?.preserveDraft !== false &&
          current.configDraft &&
          current.snapshot &&
          JSON.stringify(current.configDraft) !==
            JSON.stringify(current.snapshot.controlPlane);

        return {
          snapshot: snapshot.localEngine,
          loading: false,
          error: null,
          configDraft: preserveDraft
            ? current.configDraft
            : cloneLocalEngineControlPlane(snapshot.localEngine.controlPlane),
          configSaving: options?.preserveConfigSaving
            ? current.configSaving
            : false,
          configMessage: options?.configMessage ?? null,
          stagingBusy: options?.preserveStagingBusy
            ? current.stagingBusy
            : false,
        };
      });
    },
    [],
  );

  const clearCapabilityRegistryState = useCallback((message: string) => {
    setCapabilityRegistrySnapshot(null);
    setCapabilityRegistryError(message);
    setCapabilityRegistryLoading(false);

    setRuntimeConnectors([]);
    setRuntimeConnectorsLoading(false);
    setRuntimeConnectorsError(message);

    setRuntimeSkills([]);
    setRuntimeSkillsLoading(false);
    setRuntimeSkillsError(message);

    setSkillSources([]);
    setSkillSourcesLoading(false);
    setSkillSourcesError(message);

    setExtensionManifests([]);
    setExtensionManifestsLoading(false);
    setExtensionManifestsError(message);

    setLocalEnginePanel({
      snapshot: null,
      loading: false,
      error: message,
      configDraft: null,
      configSaving: false,
      configMessage: null,
      stagingBusy: false,
    });
  }, []);

  const refreshCapabilityRegistrySnapshot = useCallback(
    async (options?: {
      preserveDraft?: boolean;
      preserveConfigSaving?: boolean;
      preserveStagingBusy?: boolean;
      configMessage?: string | null;
    }) => {
      setCapabilityRegistryLoading(true);
      setCapabilityRegistryError(null);
      setRuntimeConnectorsLoading(true);
      setRuntimeConnectorsError(null);
      setRuntimeSkillsLoading(true);
      setRuntimeSkillsError(null);
      setSkillSourcesLoading(true);
      setSkillSourcesError(null);
      setExtensionManifestsLoading(true);
      setExtensionManifestsError(null);
      setLocalEnginePanel((current) => ({
        ...current,
        loading: true,
        error: null,
        configMessage:
          options?.configMessage === undefined
            ? current.configMessage
            : options.configMessage,
      }));

      try {
        const snapshot = await runtime.getCapabilityRegistrySnapshot();
        applyCapabilityRegistrySnapshot(snapshot, options);
        return snapshot;
      } catch (error) {
        const message = String(error);
        clearCapabilityRegistryState(message);
        throw error;
      }
    },
    [applyCapabilityRegistrySnapshot, clearCapabilityRegistryState, runtime],
  );

  useEffect(() => {
    let cancelled = false;

    void runtime
      .getCapabilityRegistrySnapshot()
      .then((snapshot) => {
        if (!cancelled) {
          applyCapabilityRegistrySnapshot(snapshot);
        }
      })
      .catch((error) => {
        if (!cancelled) {
          clearCapabilityRegistryState(String(error));
        }
      });

    return () => {
      cancelled = true;
    };
  }, [applyCapabilityRegistrySnapshot, clearCapabilityRegistryState, runtime]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(
      CUSTOM_CONNECTIONS_STORAGE_KEY,
      JSON.stringify(storedConnections),
    );
  }, [storedConnections]);

  useEffect(() => {
    setQuery("");
  }, [surface]);

  useEffect(() => {
    if (
      surface === "engine" &&
      !selectedEngineFamilyId &&
      !selectedEngineRegistryEntryId
    ) {
      setEngineDetailSection("overview");
    }
  }, [selectedEngineFamilyId, selectedEngineRegistryEntryId, surface]);

  useEffect(() => {
    if (
      surface === "engine" &&
      selectedEngineRegistryEntryId &&
      engineDetailSection !== "registry"
    ) {
      setEngineDetailSection("registry");
    }
  }, [engineDetailSection, selectedEngineRegistryEntryId, surface]);

  useEffect(() => {
    setSkillDetailSection("guide");
  }, [selectedSkillHash]);

  useEffect(() => {
    setConnectionDetailSection("overview");
    setGenericConnectorMessage(null);
  }, [selectedConnectionId]);

  useEffect(() => {
    setConnectionDetailSection("overview");
    setGenericConnectorMessage(null);
  }, [selectedTemplateId]);

  useEffect(() => {
    setExtensionDetailSection("overview");
  }, [selectedExtensionId]);

  const refreshSourceInventory = useCallback(
    async () => refreshCapabilityRegistrySnapshot({ preserveDraft: true }),
    [refreshCapabilityRegistrySnapshot],
  );

  useEffect(() => {
    if (surface !== "skills" && surface !== "extensions") {
      return;
    }

    void refreshSourceInventory();
  }, [refreshSourceInventory, surface]);

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

  const mail = useMailConnectorActions(runtime, {
    onAccountConfigured(result) {
      setRuntimeConnectors((current) =>
        patchMailConnectorFromConfiguredAccount(current, result),
      );
    },
  });

  const skillSourceLookup = useMemo(() => {
    const lookup = new Map<string, SkillSourceRecord>();
    skillSources.forEach((source) => {
      lookup.set(sourceRegistryKey("skill_source", source.uri), source);
    });
    return lookup;
  }, [skillSources]);

  const capabilityRegistryEntryLookup = useMemo(() => {
    const lookup = new Map<string, CapabilityRegistryEntry>();
    capabilityRegistrySnapshot?.entries.forEach((entry) => {
      lookup.set(entry.entryId, entry);
    });
    return lookup;
  }, [capabilityRegistrySnapshot]);

  const getRelatedGoverningEntries = useCallback(
    (entryId: string): RelatedGoverningEntry[] => {
      const currentEntry = capabilityRegistryEntryLookup.get(entryId);
      if (!currentEntry) {
        return [];
      }

      const relatedEntries = currentEntry.relatedGoverningEntryIds
        .map((relatedEntryId) => capabilityRegistryEntryLookup.get(relatedEntryId) ?? null)
        .filter((entry): entry is CapabilityRegistryEntry => Boolean(entry))
        .map((entry) => {
          const sharedHints = currentEntry.governingFamilyHints.filter((hint) =>
            entry.governingFamilyHints.includes(hint),
          );
          return {
            entry,
            sharedHints:
              sharedHints.length > 0
                ? sharedHints
                : currentEntry.governingFamilyId &&
                    currentEntry.governingFamilyId === entry.governingFamilyId
                  ? [currentEntry.governingFamilyId]
                  : [],
          };
        })
        .sort((left, right) => {
          if (left.sharedHints.length !== right.sharedHints.length) {
            return right.sharedHints.length - left.sharedHints.length;
          }
          if (left.entry.kind !== right.entry.kind) {
            return left.entry.kind.localeCompare(right.entry.kind);
          }
          return left.entry.label.localeCompare(right.entry.label);
        });

      return relatedEntries;
    },
    [capabilityRegistryEntryLookup],
  );

  const workspaceSkills = useMemo<WorkspaceSkill[]>(() => {
    const runtimeObserved: WorkspaceSkill[] = runtimeSkills.map((entry) => {
      const detailState = runtimeSkillDetails[entry.skill_hash];
      return {
        hash: entry.skill_hash,
        catalog: entry,
        detail: detailState?.detail ?? null,
        detailStatus: detailState?.status ?? "idle",
        detailError: detailState?.error ?? null,
        origin: "runtime",
        addedBy:
          detailState?.detail?.source_registry_label ?? "Observed runtime",
        invokedBy: "Worker or workflow",
      };
    });

    const sourceBacked = skillSources.flatMap((source) =>
      source.discoveredSkills.map((skill) =>
        workspaceSkillFromSkillSource(source, skill),
      ),
    );

    const extensionBacked = extensionManifests.flatMap((manifest) =>
      manifest.filesystemSkills.map((skill) => {
        const linkedSource =
          manifest.sourceKind === "skill_source"
            ? skillSourceLookup.get(
                sourceRegistryKey(manifest.sourceKind, manifest.sourceUri),
              ) ?? null
            : null;
        return workspaceSkillFromExtensionManifest(
          manifest,
          skill,
          linkedSource?.sourceId ?? null,
        );
      }),
    );

    const merged: WorkspaceSkill[] = [
      ...runtimeObserved,
      ...sourceBacked,
      ...extensionBacked,
    ];

    return merged.sort((left, right) => {
      if (left.origin !== right.origin) {
        return left.origin === "runtime" ? -1 : 1;
      }
      if (left.catalog.stale !== right.catalog.stale) {
        return left.catalog.stale ? 1 : -1;
      }
      if (left.catalog.sample_size !== right.catalog.sample_size) {
        return right.catalog.sample_size - left.catalog.sample_size;
      }
      return left.catalog.name.localeCompare(right.catalog.name);
    });
  }, [
    extensionManifests,
    runtimeSkillDetails,
    runtimeSkills,
    skillSourceLookup,
    skillSources,
  ]);

  const workspaceConnections = useMemo<WorkspaceConnectionRecord[]>(
    () =>
      runtimeConnectors.map((connector) => ({
        connector,
        origin: "runtime" as const,
      })),
    [runtimeConnectors],
  );

  const workspaceConnectionTemplates = useMemo<
    WorkspaceConnectionTemplateRecord[]
  >(() => {
    const runtimeIds = new Set(runtimeConnectors.map((connector) => connector.id));
    const runtimePluginIds = new Set(
      runtimeConnectors.map((connector) => connector.pluginId),
    );

    return storedConnections
      .filter(
        (draft) =>
          !runtimeIds.has(draft.id) && !runtimePluginIds.has(draft.pluginId),
      )
      .map(templateRecordFromDraft)
      .sort((left, right) => left.connector.name.localeCompare(right.connector.name));
  }, [runtimeConnectors, storedConnections]);

  const extensions = useMemo<WorkspaceExtension[]>(() => {
    return extensionManifests
      .map((manifest) => {
        const linkedSource =
          manifest.sourceKind === "skill_source"
            ? skillSourceLookup.get(
                sourceRegistryKey(manifest.sourceKind, manifest.sourceUri),
              ) ?? null
            : null;

        return {
          id: manifest.extensionId,
          name: manifest.displayName ?? humanize(manifest.name),
          displayName: manifest.displayName,
          version: manifest.version,
          description:
            manifest.description ??
            `${manifest.displayName ?? humanize(manifest.name)} manifest discovered from ${manifest.sourceLabel}.`,
          statusLabel: extensionStatusLabel(manifest),
          meta: [
            manifest.sourceLabel,
            manifest.category ?? manifest.marketplaceCategory,
            manifest.version ? `v${manifest.version}` : null,
          ]
            .filter(Boolean)
            .join(" · "),
          surfaces:
            manifest.capabilities.length > 0
              ? manifest.capabilities.map(humanize)
              : manifest.contributions.map((contribution) => contribution.label),
          sourceId: linkedSource?.sourceId ?? null,
          sourceLabel: manifest.sourceLabel,
          sourceUri: manifest.sourceUri,
          sourceKind: manifest.sourceKind,
          manifestKind: manifest.manifestKind,
          manifestPath: manifest.manifestPath,
          rootPath: manifest.rootPath,
          enabled: manifest.enabled,
          trustPosture: manifest.trustPosture,
          governedProfile: manifest.governedProfile,
          developerName: manifest.developerName,
          authorName: manifest.authorName,
          authorEmail: manifest.authorEmail,
          authorUrl: manifest.authorUrl,
          category: manifest.category ?? manifest.marketplaceCategory,
          homepage: manifest.homepage,
          repository: manifest.repository,
          license: manifest.license,
          keywords: manifest.keywords,
          defaultPrompts: manifest.defaultPrompts,
          contributionCount: manifest.contributions.length,
          filesystemSkillCount: manifest.filesystemSkills.length,
          contributions: manifest.contributions,
          marketplaceName: manifest.marketplaceName,
          marketplaceDisplayName: manifest.marketplaceDisplayName,
          marketplaceCategory: manifest.marketplaceCategory,
          marketplaceInstallationPolicy: manifest.marketplaceInstallationPolicy,
          marketplaceAuthenticationPolicy:
            manifest.marketplaceAuthenticationPolicy,
          marketplaceProducts: manifest.marketplaceProducts,
        };
      })
      .sort((left, right) => left.name.localeCompare(right.name));
  }, [extensionManifests, skillSourceLookup]);

  const filteredSkills = useMemo(() => {
    if (!deferredQuery.trim()) return workspaceSkills;
    const lowered = deferredQuery.trim().toLowerCase();
    return workspaceSkills.filter((skill) =>
      [
        skill.catalog.name,
        skill.catalog.description,
        skill.catalog.source_type,
        skill.addedBy,
        skill.invokedBy,
        skill.sourceLabel ?? "",
        skill.sourceUri ?? "",
        skill.relativePath ?? "",
        skill.extensionDisplayName ?? "",
        skill.detail?.used_tools.join(" ") ?? skill.catalog.definition.name,
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

  const filteredConnectionTemplates = useMemo(() => {
    if (!deferredQuery.trim()) return workspaceConnectionTemplates;
    const lowered = deferredQuery.trim().toLowerCase();
    return workspaceConnectionTemplates.filter(({ connector, draft, source }) =>
      [
        connector.name,
        connector.provider,
        connector.description,
        connector.scopes.join(" "),
        draft.notes ?? "",
        source,
      ]
        .join(" ")
        .toLowerCase()
        .includes(lowered),
    );
  }, [deferredQuery, workspaceConnectionTemplates]);

  const filteredExtensions = useMemo(() => {
    if (!deferredQuery.trim()) return extensions;
    const lowered = deferredQuery.trim().toLowerCase();
    return extensions.filter((extension) =>
      [
        extension.name,
        extension.description,
        extension.meta,
        extension.statusLabel,
        extension.governedProfile,
        extension.sourceLabel,
        extension.sourceUri,
        extension.manifestPath,
        extension.surfaces.join(" "),
        extension.keywords.join(" "),
        extension.defaultPrompts.join(" "),
        extension.trustPosture,
      ]
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
    if (selectedEngineRegistryEntryId) return;
    const next = filteredEngineFamilies[0]?.id ?? null;
    if (
      !selectedEngineFamilyId ||
      !filteredEngineFamilies.some((family) => family.id === selectedEngineFamilyId)
    ) {
      setSelectedEngineFamilyId(next);
    }
  }, [
    filteredEngineFamilies,
    selectedEngineFamilyId,
    selectedEngineRegistryEntryId,
    surface,
  ]);

  const openSurface = (nextSurface: CapabilitySurface) => {
    setSurface(nextSurface);
  };

  const returnToHome = () => {
    setSurface(null);
    setQuery("");
  };

  const selectConnection = (connectionId: string | null) => {
    setSelectedConnectionId(connectionId);
    if (connectionId) {
      setSelectedTemplateId(null);
    }
  };

  const selectConnectionTemplate = (templateId: string | null) => {
    setSelectedTemplateId(templateId);
    if (templateId) {
      setSelectedConnectionId(null);
    }
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
    const hasSelectedConnection = filteredConnections.some(
      ({ connector }) => connector.id === selectedConnectionId,
    );
    const hasSelectedTemplate = filteredConnectionTemplates.some(
      ({ connector }) => connector.id === selectedTemplateId,
    );

    if (hasSelectedConnection || hasSelectedTemplate) {
      return;
    }

    const nextConnectionId = filteredConnections[0]?.connector.id ?? null;
    if (nextConnectionId) {
      selectConnection(nextConnectionId);
      return;
    }

    const nextTemplateId = filteredConnectionTemplates[0]?.connector.id ?? null;
    selectConnectionTemplate(nextTemplateId);
  }, [
    filteredConnectionTemplates,
    filteredConnections,
    selectedConnectionId,
    selectedTemplateId,
    surface,
  ]);

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
  const selectedTemplateRecord =
    workspaceConnectionTemplates.find(
      ({ connector }) => connector.id === selectedTemplateId,
    ) ?? null;
  const selectedExtension =
    extensions.find((extension) => extension.id === selectedExtensionId) ??
    null;
  const selectedSkillSourceRecord =
    selectedSkill?.sourceId
      ? skillSources.find((source) => source.sourceId === selectedSkill.sourceId) ??
        null
      : null;
  const selectedExtensionSourceRecord =
    selectedExtension?.sourceId
      ? skillSources.find((source) => source.sourceId === selectedExtension.sourceId) ??
        null
      : null;
  const selectedSkillRegistryEntry =
    selectedSkill?.origin === "runtime"
      ? capabilityRegistryEntryLookup.get(`skill:${selectedSkill.hash}`) ?? null
      : selectedSkill?.registryEntryId
        ? capabilityRegistryEntryLookup.get(selectedSkill.registryEntryId) ?? null
      : selectedSkill?.extensionId
        ? capabilityRegistryEntryLookup.get(`extension:${selectedSkill.extensionId}`) ??
          null
        : selectedSkill?.sourceId
          ? capabilityRegistryEntryLookup.get(
              `skill_source:${selectedSkill.sourceId}`,
            ) ?? null
          : null;
  const selectedConnectionRegistryEntry =
    selectedConnectionRecord?.origin === "runtime"
      ? capabilityRegistryEntryLookup.get(
          `connector:${selectedConnectionRecord.connector.id}`,
        ) ?? null
      : null;
  const selectedExtensionRegistryEntry = selectedExtension
    ? capabilityRegistryEntryLookup.get(`extension:${selectedExtension.id}`) ?? null
    : null;
  const selectedEngineFamily =
    localEnginePanel.snapshot?.capabilities.find(
      (family) => family.id === selectedEngineFamilyId,
    ) ?? filteredEngineFamilies[0] ?? null;
  const selectedEngineRegistryEntry =
    selectedEngineRegistryEntryId
      ? capabilityRegistryEntryLookup.get(selectedEngineRegistryEntryId) ?? null
      : null;

  const openCapabilityRegistryEntry = useCallback(
    (
      entryId: string,
      options?: {
        openPolicyCenter?: boolean;
      },
    ) => {
      const entry = capabilityRegistryEntryLookup.get(entryId);
      if (!entry) {
        return;
      }

      const openPolicyCenter = options?.openPolicyCenter === true;
      let connectorForPolicy: ConnectorSummary | null = null;

      switch (entry.kind) {
        case "connector": {
          const connectorId = entry.entryId.replace(/^connector:/, "");
          const matchingRecord =
            workspaceConnections.find(
              ({ connector }) => connector.id === connectorId,
            ) ?? null;
          if (matchingRecord) {
            setSelectedTemplateId(null);
            setSelectedConnectionId(matchingRecord.connector.id);
            setConnectionDetailSection("overview");
            setSurface("connections");
            connectorForPolicy = matchingRecord.connector;
          }
          break;
        }
        case "extension": {
          const extensionId = entry.entryId.replace(/^extension:/, "");
          if (extensions.some((item) => item.id === extensionId)) {
            setSelectedExtensionId(extensionId);
            setExtensionDetailSection("overview");
            setSurface("extensions");
          }
          break;
        }
        case "skill": {
          const skillHash = entry.entryId.replace(/^skill:/, "");
          if (workspaceSkills.some((skill) => skill.hash === skillHash)) {
            setSelectedSkillHash(skillHash);
            setSkillDetailSection("overview");
            setSurface("skills");
          }
          break;
        }
        case "filesystem_skill": {
          const matchingSkill =
            workspaceSkills.find((skill) => skill.registryEntryId === entry.entryId) ??
            null;
          if (matchingSkill) {
            setSelectedSkillHash(matchingSkill.hash);
            setSkillDetailSection("overview");
            setSurface("skills");
          }
          break;
        }
        case "skill_source": {
          const sourceId = entry.entryId.replace(/^skill_source:/, "");
          const matchingSkill =
            workspaceSkills.find((skill) => skill.sourceId === sourceId) ?? null;
          setSkillDetailSection("overview");
          if (matchingSkill) {
            setSelectedSkillHash(matchingSkill.hash);
          }
          setSurface("skills");
          break;
        }
        case "backend":
        case "model": {
          setSelectedEngineFamilyId(null);
          setSelectedEngineRegistryEntryId(entry.entryId);
          setEngineDetailSection("registry");
          setSurface("engine");
          break;
        }
        case "native_family": {
          const familyId = entry.entryId.replace(/^native_family:/, "");
          setSelectedEngineRegistryEntryId(null);
          setSelectedEngineFamilyId(familyId);
          setEngineDetailSection("families");
          setSurface("engine");
          break;
        }
        default: {
          setSelectedEngineFamilyId(null);
          setSelectedEngineRegistryEntryId(entry.entryId);
          setEngineDetailSection("registry");
          setSurface("engine");
          break;
        }
      }

      if (openPolicyCenter) {
        onOpenPolicyCenter?.(connectorForPolicy);
      }
    },
    [
      capabilityRegistryEntryLookup,
      extensions,
      onOpenPolicyCenter,
      workspaceConnections,
      workspaceSkills,
    ],
  );

  const stageCapabilityGovernanceRequest = useCallback(
    async (input: {
      action: CapabilityPolicyIntentAction;
      entry: CapabilityRegistryEntry;
      request?: CapabilityGovernanceRequest | null;
      governingEntryId?: string | null;
      connectorId?: string | null;
      connectorLabel?: string | null;
    }) => {
      if (input.request) {
        return runtime.setCapabilityGovernanceRequest(input.request);
      }

      const request = await runtime.planCapabilityGovernanceRequest<CapabilityGovernanceRequest>(
        {
          capabilityEntryId: input.entry.entryId,
          action: input.action,
          governingEntryId: input.governingEntryId ?? null,
          connectorId: input.connectorId ?? null,
          connectorLabel: input.connectorLabel ?? null,
        },
      );
      return runtime.setCapabilityGovernanceRequest(request);
    },
    [runtime],
  );

  const planCapabilityGovernanceProposal = useCallback(
    async (input: {
      action: CapabilityPolicyIntentAction;
      entry: CapabilityRegistryEntry;
      comparisonEntryId?: string | null;
    }) => {
      return runtime.planCapabilityGovernanceProposal<CapabilityGovernanceProposal>({
        capabilityEntryId: input.entry.entryId,
        action: input.action,
        comparisonEntryId: input.comparisonEntryId ?? null,
      });
    },
    [runtime],
  );

  const queueSelectedConnectionPolicyIntent = useCallback(
    (
      action: CapabilityPolicyIntentAction,
      request?: CapabilityGovernanceRequest | null,
    ) => {
      if (!selectedConnectionRecord || selectedConnectionRecord.origin !== "runtime") {
        return;
      }
      if (!selectedConnectionRegistryEntry) {
        return;
      }

      void (async () => {
        setGenericConnectorMessage(null);

        try {
          await stageCapabilityGovernanceRequest({
            action,
            entry: selectedConnectionRegistryEntry,
            request,
            connectorId: selectedConnectionRecord.connector.id,
            connectorLabel: selectedConnectionRecord.connector.name,
          });
          onOpenPolicyCenter?.(selectedConnectionRecord.connector);
        } catch (error) {
          setGenericConnectorMessage(
            `Could not stage the governance request: ${String(error)}`,
          );
        }
      })();
    },
    [
      onOpenPolicyCenter,
      selectedConnectionRecord,
      selectedConnectionRegistryEntry,
      stageCapabilityGovernanceRequest,
    ],
  );

  const planSelectedConnectionGovernanceProposal = useCallback(
    async (comparisonEntryId?: string | null) => {
      if (!selectedConnectionRecord || selectedConnectionRecord.origin !== "runtime") {
        return null;
      }
      if (!selectedConnectionRegistryEntry) {
        return null;
      }
      return planCapabilityGovernanceProposal({
        action: "widen",
        entry: selectedConnectionRegistryEntry,
        comparisonEntryId,
      });
    },
    [
      planCapabilityGovernanceProposal,
      selectedConnectionRecord,
      selectedConnectionRegistryEntry,
    ],
  );

  const queueSelectedSkillPolicyIntent = useCallback(
    (
      action: CapabilityPolicyIntentAction,
      request?: CapabilityGovernanceRequest | null,
    ) => {
      if (!selectedSkill || selectedSkill.origin !== "filesystem") {
        return;
      }
      if (!selectedSkillRegistryEntry) {
        return;
      }

      void (async () => {
        setSourceRegistryMessage(null);
        setSourceRegistryError(null);

        try {
          await stageCapabilityGovernanceRequest({
            action,
            entry: selectedSkillRegistryEntry,
            request,
          });
          onOpenPolicyCenter?.(null);
        } catch (error) {
          setSourceRegistryError(
            `Could not stage the governance request: ${String(error)}`,
          );
        }
      })();
    },
    [
      onOpenPolicyCenter,
      selectedSkill,
      selectedSkillRegistryEntry,
      stageCapabilityGovernanceRequest,
    ],
  );

  const planSelectedSkillGovernanceProposal = useCallback(
    async (comparisonEntryId?: string | null) => {
      if (!selectedSkill || selectedSkill.origin !== "filesystem") {
        return null;
      }
      if (!selectedSkillRegistryEntry) {
        return null;
      }
      return planCapabilityGovernanceProposal({
        action: "widen",
        entry: selectedSkillRegistryEntry,
        comparisonEntryId,
      });
    },
    [planCapabilityGovernanceProposal, selectedSkill, selectedSkillRegistryEntry],
  );

  const queueSelectedExtensionPolicyIntent = useCallback(
    (
      action: CapabilityPolicyIntentAction,
      request?: CapabilityGovernanceRequest | null,
    ) => {
      if (!selectedExtension || !selectedExtensionRegistryEntry) {
        return;
      }

      void (async () => {
        setSourceRegistryMessage(null);
        setSourceRegistryError(null);

        try {
          await stageCapabilityGovernanceRequest({
            action,
            entry: selectedExtensionRegistryEntry,
            request,
          });
          onOpenPolicyCenter?.(null);
        } catch (error) {
          setSourceRegistryError(
            `Could not stage the governance request: ${String(error)}`,
          );
        }
      })();
    },
    [
      onOpenPolicyCenter,
      selectedExtension,
      selectedExtensionRegistryEntry,
      stageCapabilityGovernanceRequest,
    ],
  );

  const planSelectedExtensionGovernanceProposal = useCallback(
    async (comparisonEntryId?: string | null) => {
      if (!selectedExtension || !selectedExtensionRegistryEntry) {
        return null;
      }
      return planCapabilityGovernanceProposal({
        action: "widen",
        entry: selectedExtensionRegistryEntry,
        comparisonEntryId,
      });
    },
    [planCapabilityGovernanceProposal, selectedExtension, selectedExtensionRegistryEntry],
  );

  const requestSkillDetail = useCallback(
    async (skillHash: string) => {
      setRuntimeSkillDetails((current) => ({
        ...current,
        [skillHash]: {
          status: "loading",
          detail: current[skillHash]?.detail ?? null,
          error: null,
        },
      }));

      try {
        const detail = await runtime.getSkillDetail(skillHash);
        setRuntimeSkillDetails((current) => ({
          ...current,
          [skillHash]: {
            status: "ready",
            detail,
            error: null,
          },
        }));
      } catch (error) {
        setRuntimeSkillDetails((current) => ({
          ...current,
          [skillHash]: {
            status: "error",
            detail: null,
            error: String(error),
          },
        }));
      }
    },
    [runtime],
  );

  const requestConnectorActions = useCallback(
    async (connectorId: string) => {
      if (!runtime.getConnectorActions) {
        setRuntimeConnectorActions((current) => ({
          ...current,
          [connectorId]: {
            status: "error",
            actions: current[connectorId]?.actions ?? [],
            error:
              "This runtime does not expose live connector-action inspection yet.",
          },
        }));
        return;
      }

      setRuntimeConnectorActions((current) => ({
        ...current,
        [connectorId]: {
          status: "loading",
          actions: current[connectorId]?.actions ?? [],
          error: null,
        },
      }));

      try {
        const actions = await runtime.getConnectorActions(connectorId);
        setRuntimeConnectorActions((current) => ({
          ...current,
          [connectorId]: {
            status: "ready",
            actions,
            error: null,
          },
        }));
      } catch (error) {
        setRuntimeConnectorActions((current) => ({
          ...current,
          [connectorId]: {
            status: "error",
            actions: current[connectorId]?.actions ?? [],
            error: String(error),
          },
        }));
      }
    },
    [runtime],
  );

  useEffect(() => {
    if (!selectedSkill || selectedSkill.origin !== "runtime") return;
    const detailState = runtimeSkillDetails[selectedSkill.hash];
    if (
      detailState?.status === "loading" ||
      detailState?.status === "ready" ||
      detailState?.status === "error"
    ) {
      return;
    }

    void requestSkillDetail(selectedSkill.hash);
  }, [requestSkillDetail, runtimeSkillDetails, selectedSkill]);

  useEffect(() => {
    if (surface !== "connections") return;
    if (!selectedConnectionRecord || selectedConnectionRecord.origin !== "runtime") {
      return;
    }

    const connectorId = selectedConnectionRecord.connector.id;
    const actionState = runtimeConnectorActions[connectorId];
    if (actionState?.status === "loading" || actionState?.status === "ready") {
      return;
    }

    void requestConnectorActions(connectorId);
  }, [
    requestConnectorActions,
    runtimeConnectorActions,
    selectedConnectionRecord,
    surface,
  ]);

  const runSourceRegistryAction = useCallback(
    async (action: () => Promise<unknown>, successMessage: string) => {
      setSourceRegistryBusy(true);
      setSourceRegistryMessage(null);
      setSourceRegistryError(null);
      try {
        await action();
        await refreshSourceInventory();
        setSourceRegistryMessage(successMessage);
        return true;
      } catch (error) {
        setSourceRegistryError(String(error));
        return false;
      } finally {
        setSourceRegistryBusy(false);
      }
    },
    [refreshSourceInventory],
  );

  const createSourceRegistryEntry = useCallback(async () => {
    const trimmedUri = sourceRegistryUri.trim();
    const trimmedLabel = sourceRegistryLabel.trim();
    if (!trimmedUri) {
      setSourceRegistryError("A directory or checked-out repo path is required.");
      return;
    }

    const created = await runSourceRegistryAction(
      () => runtime.addSkillSource(trimmedUri, trimmedLabel || null),
      "Source added and synced.",
    );
    if (!created) {
      return;
    }

    setSourceRegistryModalOpen(false);
    setSourceRegistryLabel("");
    setSourceRegistryUri("");
    setSurface((current) => current ?? "extensions");
  }, [
    runSourceRegistryAction,
    runtime,
    sourceRegistryLabel,
    sourceRegistryUri,
  ]);

  const addSourceRegistrySource = useCallback(
    async (
      uri: string,
      label?: string | null,
      successMessage = "Source added and synced.",
    ) => {
      const trimmedUri = uri.trim();
      const trimmedLabel = label?.trim() ?? "";
      if (!trimmedUri) {
        setSourceRegistryError("A directory or checked-out repo path is required.");
        return false;
      }

      return runSourceRegistryAction(
        () => runtime.addSkillSource(trimmedUri, trimmedLabel || null),
        successMessage,
      );
    },
    [runSourceRegistryAction, runtime],
  );

  const syncSourceRegistrySource = useCallback(
    async (sourceId: string) =>
      runSourceRegistryAction(
        () => runtime.syncSkillSource(sourceId),
        "Source synced.",
      ),
    [runSourceRegistryAction, runtime],
  );

  const toggleSourceRegistrySource = useCallback(
    async (sourceId: string, enabled: boolean) =>
      runSourceRegistryAction(
        () => runtime.setSkillSourceEnabled(sourceId, enabled),
        enabled ? "Source enabled." : "Source disabled.",
      ),
    [runSourceRegistryAction, runtime],
  );

  const removeSourceRegistrySource = useCallback(
    async (sourceId: string) =>
      runSourceRegistryAction(
        () => runtime.removeSkillSource(sourceId),
        "Source removed from the registry.",
      ),
    [runSourceRegistryAction, runtime],
  );

  const createCustomConnection = () => {
    const trimmedName = customName.trim();
    const trimmedUrl = customUrl.trim();
    if (!trimmedName || !trimmedUrl) {
      setCustomNotice(
        "Add a name and remote endpoint to save a workspace planning template.",
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
      availabilityLabel: "Planning template",
      notes:
        "Workspace planning template staged locally. It remains outside the live connector catalog until a real adapter is added to the kernel-backed runtime.",
      endpoint: trimmedUrl,
    };

    setStoredConnections((current) => {
      const next = current.filter((item) => item.id !== draft.id);
      next.push(draft);
      return next;
    });
    selectConnectionTemplate(draft.id);
    setSurface("connections");
    setCustomModalOpen(false);
    setCustomName("");
    setCustomUrl("");
    setCustomDescription(
      "Workspace planning template for a remote MCP surface or adapter.",
    );
    setCustomScopes("tools.invoke, resources.read");
    setCustomNotice(`${trimmedName} added to the workspace planning lane.`);
  };

  const runGenericConnectorSetup = async (connector: ConnectorSummary) => {
    if (!runtime.configureConnector) {
      setGenericConnectorMessage(
        "This live runtime connector does not expose a generic configure flow yet.",
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
    try {
      await refreshCapabilityRegistrySnapshot({ preserveDraft: true });
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
      void refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        preserveConfigSaving: true,
        preserveStagingBusy: true,
      }).catch(() => undefined);
    });

    return () => {
      active = false;
      safelyDisposeTauriListener(unlistenPromise);
    };
  }, [refreshCapabilityRegistrySnapshot]);

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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage:
          "Staged operation added to the Local Engine queue for later native execution.",
      });
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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage: "Staged operation removed from the Local Engine queue.",
      });
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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage:
          "Staged plan promoted into the live Local Engine job queue.",
      });
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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage:
          "Local Engine job state updated in the kernel control plane.",
      });
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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage:
          "Retry request sent to the active parent playbook step.",
      });
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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage: stepId
          ? "Resume request sent for the selected parent playbook step."
          : "Resume request sent for the current parent playbook step.",
      });
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
      await refreshCapabilityRegistrySnapshot({
        preserveDraft: true,
        configMessage:
          "Parent playbook run dismissed from the Runtime Deck.",
      });
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
  const selectedConnectorActionState =
    selectedConnectionRecord?.origin === "runtime"
      ? runtimeConnectorActions[selectedConnectionRecord.connector.id] ?? {
          status: "idle",
          actions: [] as ConnectorActionDefinition[],
          error: null,
        }
      : null;
  const skillInventoryLoading =
    runtimeSkillsLoading || skillSourcesLoading || extensionManifestsLoading;
  const skillInventoryError = [
    runtimeSkillsError,
    skillSourcesError,
    extensionManifestsError,
  ]
    .filter((value): value is string => Boolean(value))
    .join(" | ");

  return {
    runtime,
    surface,
    query,
    setQuery,
    openSurface,
    returnToHome,
    connectedConnectionCount,
    registry: {
      snapshot: capabilityRegistrySnapshot,
      summary: capabilityRegistrySnapshot?.summary ?? null,
      loading: capabilityRegistryLoading,
      error: capabilityRegistryError,
      refresh: refreshCapabilityRegistrySnapshot,
      getRelatedGoverningEntries,
      openEntry: openCapabilityRegistryEntry,
    },
    mail,
    engine: {
      ...localEnginePanel,
      detailSection: engineDetailSection,
      setDetailSection: setEngineDetailSection,
      selectedFamily: selectedEngineFamily,
      selectedFamilyId: selectedEngineFamilyId,
      setSelectedFamilyId: setSelectedEngineFamilyId,
      selectedRegistryEntry: selectedEngineRegistryEntry,
      selectedRegistryEntryId: selectedEngineRegistryEntryId,
      setSelectedRegistryEntryId: setSelectedEngineRegistryEntryId,
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
      loading: skillInventoryLoading,
      error: skillInventoryError || null,
      selectedSkill,
      selectedSourceRecord: selectedSkillSourceRecord,
      selectedRegistryEntry: selectedSkillRegistryEntry,
      selectedSkillHash,
      setSelectedSkillHash,
      retrySelectedSkillDetail: () => {
        if (!selectedSkill || selectedSkill.origin !== "runtime") return;
        void requestSkillDetail(selectedSkill.hash);
      },
      detailSection: skillDetailSection,
      setDetailSection: setSkillDetailSection,
      sourceBusy: sourceRegistryBusy,
      sourceMessage: sourceRegistryMessage,
      sourceError: sourceRegistryError,
      syncSelectedSource: () => {
        if (!selectedSkillSourceRecord) return;
        void syncSourceRegistrySource(selectedSkillSourceRecord.sourceId);
      },
      toggleSelectedSourceEnabled: () => {
        if (!selectedSkillSourceRecord) return;
        void toggleSourceRegistrySource(
          selectedSkillSourceRecord.sourceId,
          !selectedSkillSourceRecord.enabled,
        );
      },
      removeSelectedSource: () => {
        if (!selectedSkillSourceRecord) return;
        void removeSourceRegistrySource(selectedSkillSourceRecord.sourceId);
      },
      planSelectedSkillGovernanceProposal,
      requestSelectedSkillPolicyIntent: queueSelectedSkillPolicyIntent,
    },
    connections: {
      items: workspaceConnections,
      filteredItems: filteredConnections,
      liveCount: workspaceConnections.length,
      filteredLiveCount: filteredConnections.length,
      templates: workspaceConnectionTemplates,
      filteredTemplates: filteredConnectionTemplates,
      templateCount: workspaceConnectionTemplates.length,
      filteredTemplateCount: filteredConnectionTemplates.length,
      loading: runtimeConnectorsLoading,
      error: runtimeConnectorsError,
      selectedRecord: selectedConnectionRecord ?? selectedTemplateRecord,
      selectedTemplateRecord,
      selectedRegistryEntry: selectedConnectionRegistryEntry,
      selectedConnectionId,
      setSelectedConnectionId: selectConnection,
      selectedTemplateId,
      setSelectedTemplateId: selectConnectionTemplate,
      detailSection: connectionDetailSection,
      setDetailSection: setConnectionDetailSection,
      getActionState: (connectorId: string): RuntimeConnectorActionState =>
        runtimeConnectorActions[connectorId] ?? {
          status: "idle",
          actions: [],
          error: null,
        },
      selectedActionState: selectedConnectorActionState,
      retrySelectedConnectorActions: () => {
        if (!selectedConnectionRecord || selectedConnectionRecord.origin !== "runtime") {
          return;
        }
        void requestConnectorActions(selectedConnectionRecord.connector.id);
      },
      customNotice,
      setCustomNotice,
      genericConnectorMessage,
      genericConnectorBusy,
      runGenericConnectorSetup,
      applyConfiguredConnectorResult,
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
      planSelectedConnectionGovernanceProposal,
      requestSelectedConnectionPolicyIntent: queueSelectedConnectionPolicyIntent,
    },
    extensions: {
      items: extensions,
      filteredItems: filteredExtensions,
      loading: extensionManifestsLoading,
      error: extensionManifestsError,
      selectedExtension,
      selectedSourceRecord: selectedExtensionSourceRecord,
      selectedRegistryEntry: selectedExtensionRegistryEntry,
      selectedExtensionId,
      setSelectedExtensionId,
      detailSection: extensionDetailSection,
      setDetailSection: setExtensionDetailSection,
      sourceBusy: sourceRegistryBusy,
      sourceMessage: sourceRegistryMessage,
      sourceError: sourceRegistryError,
      syncSelectedSource: () => {
        if (!selectedExtensionSourceRecord) return;
        void syncSourceRegistrySource(selectedExtensionSourceRecord.sourceId);
      },
      toggleSelectedSourceEnabled: () => {
        if (!selectedExtensionSourceRecord) return;
        void toggleSourceRegistrySource(
          selectedExtensionSourceRecord.sourceId,
          !selectedExtensionSourceRecord.enabled,
        );
      },
      removeSelectedSource: () => {
        if (!selectedExtensionSourceRecord) return;
        void removeSourceRegistrySource(selectedExtensionSourceRecord.sourceId);
      },
      trackSelectedExtensionRoot: () => {
        if (!selectedExtension || selectedExtensionSourceRecord) return;
        void addSourceRegistrySource(
          selectedExtension.rootPath,
          selectedExtension.displayName ?? selectedExtension.name,
          "Extension root added as a tracked source.",
        );
      },
      planSelectedExtensionGovernanceProposal,
      requestSelectedExtensionPolicyIntent: queueSelectedExtensionPolicyIntent,
    },
    sourceRegistry: {
      count: skillSources.length,
      busy: sourceRegistryBusy,
      message: sourceRegistryMessage,
      error: sourceRegistryError,
      modalOpen: sourceRegistryModalOpen,
      setModalOpen: (next: boolean) => {
        setSourceRegistryModalOpen(next);
        if (next) {
          setSourceRegistryMessage(null);
          setSourceRegistryError(null);
        }
      },
      label: sourceRegistryLabel,
      setLabel: setSourceRegistryLabel,
      uri: sourceRegistryUri,
      setUri: setSourceRegistryUri,
      addSource: createSourceRegistryEntry,
    },
  };
}

export type CapabilitiesController = ReturnType<
  typeof useCapabilitiesController
>;
