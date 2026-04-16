import { useEffect, useMemo, useRef, useState } from "react";
import type {
  AgentWorkbenchRuntime,
  ConnectorActionDefinition,
  ConnectorActionResult,
  ConnectorConfigureResult,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";
import {
  buildDefaultInput,
  coerceInput,
  defaultOauthClientState,
  defaultTokenStorageState,
  formatJsonBlock,
  isRecord,
  readBootstrapWarnings,
  readFieldProfiles,
  readOauthClientState,
  readServiceStates,
  readString,
  readStringArray,
  readTokenStorageState,
  type GoogleWorkspaceBootstrapWarning,
  type GoogleWorkspaceConnectorState,
  type GoogleWorkspaceFieldProfile,
  type GoogleWorkspacePendingRunApproval,
  type GoogleWorkspaceOauthClientState,
  type GoogleWorkspaceServiceState,
  type GoogleWorkspaceTokenStorageState,
  type UseGoogleWorkspaceConnectorOptions,
} from "./googleWorkspaceConnectorState";
import {
  buildConnectorApprovalMemoryRequest,
  parseShieldApprovalRequest,
} from "../../../runtime/shield-approval";

export type {
  GoogleWorkspaceBootstrapWarning,
  GoogleWorkspaceConnectorState,
  GoogleWorkspaceFieldProfile,
  GoogleWorkspaceOauthClientState,
  GoogleWorkspaceServiceState,
  GoogleWorkspaceTokenStorageState,
} from "./googleWorkspaceConnectorState";

export function useGoogleWorkspaceConnector(
  runtime: AgentWorkbenchRuntime,
  connector: ConnectorSummary,
  options?: UseGoogleWorkspaceConnectorOptions
): GoogleWorkspaceConnectorState {
  const runtimeReady = Boolean(
    runtime.getConnectorActions && runtime.runConnectorAction && runtime.configureConnector
  );
  const subscriptionRuntimeReady = Boolean(
    runtime.listConnectorSubscriptions &&
      runtime.stopConnectorSubscription &&
      runtime.resumeConnectorSubscription &&
      runtime.renewConnectorSubscription
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [authPending, setAuthPending] = useState(false);
  const [authUrl, setAuthUrl] = useState<string | null>(null);
  const [authStartedAtUtc, setAuthStartedAtUtc] = useState<string | null>(null);
  const [authExpiresAtUtc, setAuthExpiresAtUtc] = useState<string | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<string | null>(null);
  const [oauthClient, setOauthClient] = useState<GoogleWorkspaceOauthClientState>(
    defaultOauthClientState()
  );
  const [requestedScopes, setRequestedScopes] = useState<string[]>([]);
  const [tokenStorage, setTokenStorage] = useState<GoogleWorkspaceTokenStorageState>(
    defaultTokenStorageState()
  );
  const [connectedAccountEmail, setConnectedAccountEmail] = useState<string | null>(null);
  const [grantedScopes, setGrantedScopes] = useState<string[]>([]);
  const [fieldProfiles, setFieldProfiles] = useState<Record<string, GoogleWorkspaceFieldProfile>>(
    {}
  );
  const [serviceStates, setServiceStates] = useState<Record<string, GoogleWorkspaceServiceState>>(
    {}
  );
  const [bootstrapWarnings, setBootstrapWarnings] = useState<GoogleWorkspaceBootstrapWarning[]>(
    []
  );
  const [lastConfiguredAtUtc, setLastConfiguredAtUtc] = useState<string | null>(null);
  const [actions, setActions] = useState<ConnectorActionDefinition[]>([]);
  const [subscriptions, setSubscriptions] = useState<ConnectorSubscriptionSummary[]>([]);
  const [selectedActionId, setSelectedActionId] = useState("");
  const [input, setInput] = useState<Record<string, string>>({});
  const [pendingRunApproval, setPendingRunApproval] =
    useState<GoogleWorkspacePendingRunApproval | null>(null);
  const [formattedResult, setFormattedResult] = useState("");
  const pendingPresetInputRef = useRef<Record<string, string> | null>(null);

  const rememberShieldApproval = async (
    approvalRequest?: GoogleWorkspacePendingRunApproval["request"],
  ) => {
    if (!approvalRequest || !runtime.rememberConnectorApproval) {
      return;
    }
    const input = buildConnectorApprovalMemoryRequest(
      approvalRequest,
      "Google Workspace connector panel",
    );
    if (!input) {
      return;
    }
    try {
      await runtime.rememberConnectorApproval(input);
    } catch (error) {
      console.warn("Failed to remember Shield approval:", error);
    }
  };

  useEffect(() => {
    let cancelled = false;
    if (!runtime.getConnectorActions) return () => {};

    runtime
      .getConnectorActions(connector.id)
      .then((nextActions) => {
        if (cancelled) return;
        setActions(nextActions);
        if (nextActions.length > 0) {
          setSelectedActionId((current) => current || nextActions[0].id);
        }
      })
      .catch((loadError) => {
        if (cancelled) return;
        setError(loadError instanceof Error ? loadError.message : String(loadError));
      });

    return () => {
      cancelled = true;
    };
  }, [connector.id, runtime]);

  useEffect(() => {
    let cancelled = false;
    if (!runtime.listConnectorSubscriptions) return () => {};

    const loadSubscriptions = async () => {
      try {
        const nextSubscriptions = await runtime.listConnectorSubscriptions!(connector.id);
        if (!cancelled) {
          setSubscriptions(nextSubscriptions);
        }
      } catch (loadError) {
        if (!cancelled) {
          setError(loadError instanceof Error ? loadError.message : String(loadError));
        }
      }
    };

    void loadSubscriptions();
    const interval = window.setInterval(() => {
      void loadSubscriptions();
    }, 5000);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [connector.id, runtime]);

  useEffect(() => {
    void refreshConnectionProfile(false);
  }, [connector.id, runtime]);

  const selectedAction = useMemo(() => {
    return actions.find((action) => action.id === selectedActionId) ?? null;
  }, [actions, selectedActionId]);

  useEffect(() => {
    const nextInput = buildDefaultInput(selectedAction);
    if (pendingPresetInputRef.current) {
      setInput({
        ...nextInput,
        ...pendingPresetInputRef.current,
      });
      pendingPresetInputRef.current = null;
      return;
    }
    setInput(nextInput);
  }, [selectedAction]);

  useEffect(() => {
    if (!selectedAction) return;
    setInput((current) => {
      let changed = false;
      const next = { ...current };
      for (const field of selectedAction.fields) {
        const defaultValue = fieldProfiles[field.id]?.defaultValue;
        if (!defaultValue) continue;
        const existingValue = next[field.id] ?? "";
        if (existingValue.trim()) continue;
        next[field.id] = defaultValue;
        changed = true;
      }
      return changed ? next : current;
    });
  }, [fieldProfiles, selectedAction]);

  const setInputValue = (fieldId: string, value: string) => {
    setInput((current) => ({
      ...current,
      [fieldId]: value,
    }));
  };

  const selectAction = (actionId: string, presetInput?: Record<string, string>) => {
    pendingPresetInputRef.current = presetInput ?? null;
    setPendingRunApproval(null);
    setSelectedActionId(actionId);
  };

  const applyConfigureResult = (
    result: ConnectorConfigureResult,
    surfaceFeedback: boolean
  ) => {
    const data = isRecord(result.data) ? result.data : null;
    const bootstrap = isRecord(data?.bootstrap) ? data.bootstrap : null;

    setAuthPending(Boolean(data?.authPending));
    setAuthUrl(readString(data?.authUrl));
    setAuthStartedAtUtc(readString(data?.startedAtUtc));
    setAuthExpiresAtUtc(readString(data?.expiresAtUtc));
    setConnectionStatus(result.status);
    setOauthClient(readOauthClientState(data?.oauthClient));
    setRequestedScopes(readStringArray(data?.requestedScopes));
    setTokenStorage(readTokenStorageState(data?.tokenStorage));
    setLastConfiguredAtUtc(result.executedAtUtc);
    setConnectedAccountEmail(
      readString(bootstrap?.accountEmail) ?? readString(data?.account) ?? null
    );
    setGrantedScopes(
      readStringArray(bootstrap?.grantedScopes).length > 0
        ? readStringArray(bootstrap?.grantedScopes)
        : readStringArray(data?.scopes)
    );
    setFieldProfiles(readFieldProfiles(bootstrap?.fieldProfiles));
    setServiceStates(readServiceStates(bootstrap?.serviceStates));
    setBootstrapWarnings(readBootstrapWarnings(bootstrap?.warnings));

    if (!bootstrap && result.status !== "connected") {
      setFieldProfiles({});
      setServiceStates({});
      setBootstrapWarnings([]);
      if (result.status === "needs_auth") {
        setGrantedScopes([]);
        setConnectedAccountEmail(null);
      }
    }

    if (result.status === "connected" || result.status === "degraded") {
      setAuthPending(false);
      setAuthUrl(null);
      setAuthStartedAtUtc(null);
      setAuthExpiresAtUtc(null);
    }

    if (surfaceFeedback) {
      setNotice(result.summary);
      setFormattedResult(formatJsonBlock(result.data ?? result));
    }
    options?.onConfigured?.(result);
  };

  const refreshConnectionProfile = async (surfaceFeedback: boolean) => {
    if (!runtime.configureConnector) return;

    if (surfaceFeedback) {
      setBusy(true);
      setError(null);
    }

    try {
      const result: ConnectorConfigureResult = await runtime.configureConnector({
        connectorId: connector.id,
        input: { mode: "status" },
      });
      applyConfigureResult(result, surfaceFeedback);
    } catch (configureError) {
      if (surfaceFeedback) {
        setNotice(null);
        setError(
          configureError instanceof Error ? configureError.message : String(configureError)
        );
      }
    } finally {
      if (surfaceFeedback) {
        setBusy(false);
      }
    }
  };

  const checkConnection = async () => {
    await refreshConnectionProfile(true);
  };

  const saveOauthClient = async (clientId: string, clientSecret?: string) => {
    if (!runtime.configureConnector) {
      setError("Runtime is missing generic connector configuration support.");
      return false;
    }

    setBusy(true);
    setError(null);
    try {
      const result: ConnectorConfigureResult = await runtime.configureConnector({
        connectorId: connector.id,
        input: {
          mode: "save_oauth_client",
          clientId,
          clientSecret: clientSecret ?? "",
        },
      });
      applyConfigureResult(result, true);
      await refreshSubscriptions();
      return true;
    } catch (configureError) {
      setNotice(null);
      setError(configureError instanceof Error ? configureError.message : String(configureError));
      return false;
    } finally {
      setBusy(false);
    }
  };

  const clearOauthClient = async () => {
    if (!runtime.configureConnector) {
      setError("Runtime is missing generic connector configuration support.");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      const result: ConnectorConfigureResult = await runtime.configureConnector({
        connectorId: connector.id,
        input: { mode: "clear_oauth_client" },
      });
      applyConfigureResult(result, true);
      await refreshSubscriptions();
    } catch (configureError) {
      setNotice(null);
      setError(configureError instanceof Error ? configureError.message : String(configureError));
    } finally {
      setBusy(false);
    }
  };

  const beginAuth = async (nextRequestedScopes?: string[]) => {
    const authUrl = await runConfigureMode("login", {
      requestedScopes: nextRequestedScopes ?? requestedScopes,
    });
    if (authUrl && typeof window !== "undefined") {
      window.open(authUrl, "_blank", "noopener,noreferrer");
    }
    void pollForConnectedState();
  };

  const disconnect = async () => {
    await runConfigureMode("logout");
  };

  const cancelPendingAuth = async () => {
    await runConfigureMode("cancel_login");
  };

  const resetLocalSetup = async () => {
    await runConfigureMode("cancel_login");
    await runConfigureMode("logout");
    await clearOauthClient();
  };

  const runConfigureMode = async (
    mode: "status" | "login" | "logout" | "cancel_login",
    extraInput?: Record<string, unknown>
  ): Promise<string | null> => {
    if (!runtime.configureConnector) {
      setError("Runtime is missing generic connector configuration support.");
      return null;
    }

    setBusy(true);
    setError(null);
    try {
      const result: ConnectorConfigureResult = await runtime.configureConnector({
        connectorId: connector.id,
        input: { mode, ...(extraInput ?? {}) },
      });
      applyConfigureResult(result, true);
      await refreshSubscriptions();
      const data = isRecord(result.data) ? result.data : null;
      return readString(data?.authUrl);
    } catch (configureError) {
      setNotice(null);
      setError(configureError instanceof Error ? configureError.message : String(configureError));
      return null;
    } finally {
      setBusy(false);
    }
  };

  const pollForConnectedState = async () => {
    if (!runtime.configureConnector) return;

    for (let attempt = 0; attempt < 60; attempt += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, 2000));
      try {
        const result: ConnectorConfigureResult = await runtime.configureConnector({
          connectorId: connector.id,
          input: { mode: "status" },
        });
        applyConfigureResult(result, true);
        await refreshSubscriptions();
        if (result.status === "connected" || result.status === "degraded") {
          return;
        }
      } catch (pollError) {
        setError(pollError instanceof Error ? pollError.message : String(pollError));
        return;
      }
    }
  };

  const runSelectedAction = async ({
    skipLocalConfirmation = false,
    shieldApproved = false,
  }: {
    skipLocalConfirmation?: boolean;
    shieldApproved?: boolean;
  } = {}) => {
    if (!runtime.runConnectorAction) {
      setError("Runtime is missing generic connector action support.");
      return;
    }
    if (!selectedAction) {
      setError("Select a Google Workspace action first.");
      return;
    }

    for (const field of selectedAction.fields) {
      if (field.required && !(input[field.id] ?? "").trim()) {
        setError(`${field.label} is required.`);
        return;
      }
    }

    if (selectedAction.confirmBeforeRun && !skipLocalConfirmation) {
      setNotice(null);
      setError(null);
      setPendingRunApproval({
        kind: "confirm_before_run",
        actionId: selectedAction.id,
        actionLabel: selectedAction.label,
        message: `${selectedAction.label} will make changes in Google Workspace.`,
      });
      return;
    }

    setBusy(true);
    setError(null);
    setPendingRunApproval(null);
    try {
      const result: ConnectorActionResult = await runtime.runConnectorAction({
        connectorId: connector.id,
        actionId: selectedAction.id,
        input: {
          ...coerceInput(selectedAction, input),
          ...(shieldApproved ? { _shieldApproved: true } : {}),
        },
      });
      setNotice(result.summary);
      setFormattedResult(formatJsonBlock(result.data ?? result));
      await refreshSubscriptions();
      await refreshConnectionProfile(false);
    } catch (actionError) {
      const approvalRequest = parseShieldApprovalRequest(actionError);
      if (approvalRequest && !shieldApproved) {
        setNotice(null);
        setError(null);
        setPendingRunApproval({
          kind: "shield_policy",
          actionId: selectedAction.id,
          actionLabel: approvalRequest.actionLabel,
          message: approvalRequest.message,
          request: approvalRequest,
        });
        return;
      }
      setNotice(null);
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setBusy(false);
    }
  };

  const approvePendingRun = async () => {
    if (!pendingRunApproval) return;
    if (pendingRunApproval.kind === "shield_policy") {
      await rememberShieldApproval(pendingRunApproval.request);
    }
    await runSelectedAction({
      skipLocalConfirmation: true,
      shieldApproved: pendingRunApproval.kind === "shield_policy",
    });
  };

  const cancelPendingRun = () => {
    setPendingRunApproval(null);
    setError(null);
  };

  const refreshSubscriptions = async () => {
    if (!runtime.listConnectorSubscriptions) return;
    const nextSubscriptions = await runtime.listConnectorSubscriptions(connector.id);
    setSubscriptions(nextSubscriptions);
  };

  const stopSubscription = async (subscriptionId: string) => {
    if (!runtime.stopConnectorSubscription) return;
    setBusy(true);
    setError(null);
    try {
      await runtime.stopConnectorSubscription(connector.id, subscriptionId);
      await refreshSubscriptions();
    } catch (subscriptionError) {
      setError(
        subscriptionError instanceof Error
          ? subscriptionError.message
          : String(subscriptionError)
      );
    } finally {
      setBusy(false);
    }
  };

  const resumeSubscription = async (subscriptionId: string) => {
    if (!runtime.resumeConnectorSubscription) return;
    setBusy(true);
    setError(null);
    try {
      await runtime.resumeConnectorSubscription(connector.id, subscriptionId);
      await refreshSubscriptions();
    } catch (subscriptionError) {
      setError(
        subscriptionError instanceof Error
          ? subscriptionError.message
          : String(subscriptionError)
      );
    } finally {
      setBusy(false);
    }
  };

  const renewSubscription = async (subscriptionId: string) => {
    if (!runtime.renewConnectorSubscription) return;
    setBusy(true);
    setError(null);
    try {
      await runtime.renewConnectorSubscription(connector.id, subscriptionId);
      await refreshSubscriptions();
    } catch (subscriptionError) {
      setError(
        subscriptionError instanceof Error
          ? subscriptionError.message
          : String(subscriptionError)
      );
    } finally {
      setBusy(false);
    }
  };

  return {
    runtimeReady,
    subscriptionRuntimeReady,
    busy,
    error,
    notice,
    authPending,
    authUrl,
    authStartedAtUtc,
    authExpiresAtUtc,
    connectionStatus,
    oauthClient,
    requestedScopes,
    tokenStorage,
    connectedAccountEmail,
    grantedScopes,
    fieldProfiles,
    serviceStates,
    bootstrapWarnings,
    lastConfiguredAtUtc,
    actions,
    subscriptions,
    selectedActionId,
    setSelectedActionId,
    selectAction,
    selectedAction,
    input,
    setInputValue,
    pendingRunApproval,
    approvePendingRun,
    cancelPendingRun,
    formattedResult,
    checkConnection,
    saveOauthClient,
    clearOauthClient,
    beginAuth,
    cancelPendingAuth,
    disconnect,
    resetLocalSetup,
    runSelectedAction: () => runSelectedAction(),
    refreshSubscriptions,
    stopSubscription,
    resumeSubscription,
    renewSubscription,
  };
}
