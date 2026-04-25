import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  applySessionPermissionProfileToRuntime,
  buildConnectorPolicySummary,
  countActiveOverrides,
  fetchShieldRememberedApprovalSnapshotFromRuntime,
  fetchShieldPolicyStateFromRuntime,
  forgetShieldApprovalInRuntime,
  listSessionPermissionProfiles,
  loadShieldPolicyState,
  onShieldPolicyStateUpdated,
  persistShieldPolicyStateToRuntime,
  rememberShieldApprovalInRuntime,
  resetConnectorOverrideInRuntime,
  resolveSessionPermissionProfileId,
  setConnectorOverrideInRuntime,
  setShieldApprovalExpiryInRuntime,
  setShieldApprovalScopeModeInRuntime,
  type CapabilityGovernanceRequest,
  type ConnectorPolicyOverride,
  type SessionPermissionProfile,
  type SessionPermissionProfileId,
  type ShieldRememberApprovalInput,
  type ShieldApprovalScopeMode,
  type ShieldRememberedApprovalSnapshot,
  type ShieldPolicyState,
} from "../../../surfaces/Policy/policyCenter";
import { useChatCapabilityRegistry } from "./useChatCapabilityRegistry";

export type ChatPermissionsStatus =
  | "idle"
  | "loading"
  | "ready"
  | "error";

export interface ChatPermissionConnectorOverrideSummary {
  connectorId: string;
  entryId: string | null;
  label: string;
  headline: string;
  detail: string;
}

export interface ChatPermissionProfileSummary {
  id: SessionPermissionProfileId;
  label: string;
  summary: string;
  detail: string;
  profile: SessionPermissionProfile;
}

function humanizeConnectorId(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (match) => match.toUpperCase());
}

export function useChatPermissions(enabled = true) {
  const [policyState, setPolicyState] = useState<ShieldPolicyState>(() =>
    loadShieldPolicyState(),
  );
  const [policyStatus, setPolicyStatus] =
    useState<ChatPermissionsStatus>("idle");
  const [policyError, setPolicyError] = useState<string | null>(null);
  const [governanceRequest, setGovernanceRequest] =
    useState<CapabilityGovernanceRequest | null>(null);
  const [governanceStatus, setGovernanceStatus] =
    useState<ChatPermissionsStatus>("idle");
  const [governanceError, setGovernanceError] = useState<string | null>(null);
  const [applyingProfileId, setApplyingProfileId] =
    useState<SessionPermissionProfileId | null>(null);
  const [editingConnectorId, setEditingConnectorId] = useState<string | null>(
    null,
  );
  const [applyingGovernanceRequest, setApplyingGovernanceRequest] =
    useState(false);
  const [rememberedApprovals, setRememberedApprovals] =
    useState<ShieldRememberedApprovalSnapshot | null>(null);
  const {
    snapshot: capabilitySnapshot,
    error: capabilityRegistryError,
  } = useChatCapabilityRegistry(enabled);
  const availableProfiles = useMemo<ChatPermissionProfileSummary[]>(
    () =>
      listSessionPermissionProfiles().map((profile) => ({
        id: profile.id,
        label: profile.label,
        summary: profile.summary,
        detail: profile.detail,
        profile,
      })),
    [],
  );

  const refresh = useCallback(async () => {
    setPolicyStatus("loading");
    setPolicyError(null);
    try {
      const [nextPolicyState, nextRemembered] = await Promise.all([
        fetchShieldPolicyStateFromRuntime(),
        fetchShieldRememberedApprovalSnapshotFromRuntime().catch(() => null),
      ]);
      setPolicyState(nextPolicyState);
      setRememberedApprovals(nextRemembered);
      setPolicyStatus("ready");
      return nextPolicyState;
    } catch (error) {
      setPolicyStatus("error");
      setPolicyError(error instanceof Error ? error.message : String(error));
      throw error;
    }
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setPolicyStatus("loading");
    setPolicyError(null);

    void fetchShieldPolicyStateFromRuntime()
      .then(async (nextPolicyState) => {
        if (cancelled) {
          return;
        }
        const nextRemembered =
          await fetchShieldRememberedApprovalSnapshotFromRuntime().catch(
            () => null,
          );
        setPolicyState(nextPolicyState);
        setRememberedApprovals(nextRemembered);
        setPolicyStatus("ready");
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setPolicyStatus("error");
        setPolicyError(error instanceof Error ? error.message : String(error));
      });

    return () => {
      cancelled = true;
    };
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    setGovernanceStatus("loading");
    setGovernanceError(null);

    void invoke<CapabilityGovernanceRequest | null>(
      "get_capability_governance_request",
    )
      .then((request) => {
        if (cancelled) {
          return;
        }
        setGovernanceRequest(request);
        setGovernanceStatus("ready");
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setGovernanceRequest(null);
        setGovernanceStatus("error");
        setGovernanceError(
          error instanceof Error ? error.message : String(error),
        );
      });

    const unlistenPromise = listen<CapabilityGovernanceRequest | null>(
      "capability-governance-request-updated",
      (event) => {
        if (cancelled) {
          return;
        }
        setGovernanceRequest(event.payload);
        setGovernanceStatus("ready");
      },
    );

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    return onShieldPolicyStateUpdated((nextPolicyState) => {
      setPolicyState(nextPolicyState);
      setPolicyStatus("ready");
      setPolicyError(null);
    });
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    const unlistenPromise = listen<ShieldRememberedApprovalSnapshot>(
      "shield-approval-memory-updated",
      (event) => {
        if (cancelled) {
          return;
        }
        setRememberedApprovals(event.payload);
      },
    );

    return () => {
      cancelled = true;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [enabled]);

  const connectorEntryLookup = useMemo(() => {
    const lookup = new Map<string, { entryId: string; label: string }>();
    capabilitySnapshot?.entries.forEach((entry) => {
      if (entry.kind !== "connector") {
        return;
      }
      const connectorId = entry.entryId.replace(/^connector:/, "");
      lookup.set(connectorId, {
        entryId: entry.entryId,
        label: entry.label,
      });
    });
    return lookup;
  }, [capabilitySnapshot]);

  const connectorOverrides = useMemo<
    ChatPermissionConnectorOverrideSummary[]
  >(() => {
    return Object.entries(policyState.overrides)
      .filter(([, override]) => !override.inheritGlobal)
      .map(([connectorId]) => {
        const connectorEntry = connectorEntryLookup.get(connectorId);
        const summary = buildConnectorPolicySummary(policyState, connectorId);
        return {
          connectorId,
          entryId: connectorEntry?.entryId ?? null,
          label:
            connectorEntry?.label ??
            (governanceRequest?.connectorId === connectorId
              ? governanceRequest.connectorLabel
              : humanizeConnectorId(connectorId)),
          headline: summary.headline,
          detail: summary.detail,
        };
      });
  }, [connectorEntryLookup, governanceRequest, policyState]);

  const status = useMemo<ChatPermissionsStatus>(() => {
    if (policyStatus === "loading" || governanceStatus === "loading") {
      return "loading";
    }
    if (
      policyStatus === "error" ||
      governanceStatus === "error" ||
      capabilityRegistryError
    ) {
      return "error";
    }
    if (policyStatus === "ready" || governanceStatus === "ready") {
      return "ready";
    }
    return "idle";
  }, [capabilityRegistryError, governanceStatus, policyStatus]);

  const error = useMemo(() => {
    return (
      policyError || governanceError || capabilityRegistryError || null
    );
  }, [capabilityRegistryError, governanceError, policyError]);

  const currentProfileId = useMemo(
    () => resolveSessionPermissionProfileId(policyState),
    [policyState],
  );

  const applyProfile = useCallback(
    async (profileId: SessionPermissionProfileId) => {
      setApplyingProfileId(profileId);
      setPolicyStatus("loading");
      setPolicyError(null);
      try {
        const nextPolicyState = await applySessionPermissionProfileToRuntime(
          profileId,
          policyState,
        );
        setPolicyState(nextPolicyState);
        setPolicyStatus("ready");
        return nextPolicyState;
      } catch (error) {
        setPolicyStatus("error");
        const message = error instanceof Error ? error.message : String(error);
        setPolicyError(message);
        throw error;
      } finally {
        setApplyingProfileId(null);
      }
    },
    [policyState],
  );

  const rememberApproval = useCallback(
    async (input: ShieldRememberApprovalInput) => {
      const snapshot = await rememberShieldApprovalInRuntime(input);
      setRememberedApprovals(snapshot);
      return snapshot;
    },
    [],
  );

  const forgetApproval = useCallback(async (decisionId: string) => {
    const snapshot = await forgetShieldApprovalInRuntime(decisionId);
    setRememberedApprovals(snapshot);
    return snapshot;
  }, []);

  const setApprovalScopeMode = useCallback(
    async (decisionId: string, scopeMode: ShieldApprovalScopeMode) => {
      const snapshot = await setShieldApprovalScopeModeInRuntime({
        decisionId,
        scopeMode,
      });
      setRememberedApprovals(snapshot);
      return snapshot;
    },
    [],
  );

  const setApprovalExpiry = useCallback(
    async (decisionId: string, expiresAtMs: number | null) => {
      const snapshot = await setShieldApprovalExpiryInRuntime({
        decisionId,
        expiresAtMs,
      });
      setRememberedApprovals(snapshot);
      return snapshot;
    },
    [],
  );

  const updateConnectorOverride = useCallback(
    async (
      connectorId: string,
      nextOverride: Partial<ConnectorPolicyOverride>,
    ) => {
      setEditingConnectorId(connectorId);
      setPolicyStatus("loading");
      setPolicyError(null);
      try {
        const nextPolicyState = await setConnectorOverrideInRuntime(
          connectorId,
          nextOverride,
          policyState,
        );
        setPolicyState(nextPolicyState);
        setPolicyStatus("ready");
        return nextPolicyState;
      } catch (error) {
        setPolicyStatus("error");
        const message = error instanceof Error ? error.message : String(error);
        setPolicyError(message);
        throw error;
      } finally {
        setEditingConnectorId(null);
      }
    },
    [policyState],
  );

  const resetConnectorOverride = useCallback(
    async (connectorId: string) => {
      setEditingConnectorId(connectorId);
      setPolicyStatus("loading");
      setPolicyError(null);
      try {
        const nextPolicyState = await resetConnectorOverrideInRuntime(
          connectorId,
          policyState,
        );
        setPolicyState(nextPolicyState);
        setPolicyStatus("ready");
        return nextPolicyState;
      } catch (error) {
        setPolicyStatus("error");
        const message = error instanceof Error ? error.message : String(error);
        setPolicyError(message);
        throw error;
      } finally {
        setEditingConnectorId(null);
      }
    },
    [policyState],
  );

  const applyGovernanceRequest = useCallback(async () => {
    if (!governanceRequest) {
      return null;
    }

    setApplyingGovernanceRequest(true);
    setPolicyStatus("loading");
    setPolicyError(null);
    try {
      const nextPolicyState = await persistShieldPolicyStateToRuntime(
        governanceRequest.requestedState,
      );
      await invoke("clear_capability_governance_request");
      setPolicyState(nextPolicyState);
      setGovernanceRequest(null);
      setGovernanceStatus("ready");
      setPolicyStatus("ready");
      return nextPolicyState;
    } catch (error) {
      setPolicyStatus("error");
      const message = error instanceof Error ? error.message : String(error);
      setPolicyError(message);
      throw error;
    } finally {
      setApplyingGovernanceRequest(false);
    }
  }, [governanceRequest]);

  const dismissGovernanceRequest = useCallback(async () => {
    await invoke("clear_capability_governance_request");
    setGovernanceRequest(null);
    setGovernanceStatus("ready");
  }, []);

  return {
    status,
    error,
    policyState,
    governanceRequest,
    connectorOverrides,
    activeOverrideCount: countActiveOverrides(policyState),
    availableProfiles,
    currentProfileId,
    applyingProfileId,
    editingConnectorId,
    applyingGovernanceRequest,
    rememberedApprovals,
    applyProfile,
    applyGovernanceRequest,
    dismissGovernanceRequest,
    rememberApproval,
    forgetApproval,
    updateConnectorOverride,
    resetConnectorOverride,
    setApprovalScopeMode,
    setApprovalExpiry,
    refresh,
  };
}
