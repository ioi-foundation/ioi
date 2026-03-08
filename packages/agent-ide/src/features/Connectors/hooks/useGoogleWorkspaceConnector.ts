import { useEffect, useMemo, useRef, useState } from "react";
import type {
  AgentRuntime,
  ConnectorActionDefinition,
  ConnectorActionResult,
  ConnectorConfigureResult,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";

function buildDefaultInput(action: ConnectorActionDefinition | null): Record<string, string> {
  if (!action) return {};
  return action.fields.reduce<Record<string, string>>((next, field) => {
    if (field.defaultValue !== undefined) {
      next[field.id] = String(field.defaultValue);
    } else {
      next[field.id] = "";
    }
    return next;
  }, {});
}

function formatJsonBlock(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function coerceInput(action: ConnectorActionDefinition, input: Record<string, string>) {
  return action.fields.reduce<Record<string, unknown>>((next, field) => {
    const rawValue = input[field.id] ?? "";
    if (!rawValue.trim()) {
      return next;
    }

    if (field.type === "number") {
      const parsed = Number(rawValue);
      if (!Number.isNaN(parsed)) {
        next[field.id] = parsed;
      }
      return next;
    }

    next[field.id] = rawValue;
    return next;
  }, {});
}

interface UseGoogleWorkspaceConnectorOptions {
  onConfigured?: (result: ConnectorConfigureResult) => void;
}

export interface GoogleWorkspaceFieldProfileOption {
  label: string;
  value: string;
}

export interface GoogleWorkspaceFieldProfile {
  defaultValue?: string;
  options: GoogleWorkspaceFieldProfileOption[];
  suggestions: GoogleWorkspaceFieldProfileOption[];
  description?: string;
  inputMode?: string;
}

export interface GoogleWorkspaceServiceState {
  status: string;
  summary: string;
  missingScopes: string[];
  details?: Record<string, unknown>;
}

export interface GoogleWorkspaceBootstrapWarning {
  service: string;
  message: string;
}

export interface GoogleWorkspaceOauthClientState {
  configured: boolean;
  source: string;
  clientIdPreview?: string;
  hasClientSecret: boolean;
  storagePath?: string;
}

export interface GoogleWorkspaceTokenStorageState {
  source: string;
  storagePath?: string;
  present: boolean;
}

export interface GoogleWorkspaceConnectorState {
  runtimeReady: boolean;
  subscriptionRuntimeReady: boolean;
  busy: boolean;
  error: string | null;
  notice: string | null;
  authPending: boolean;
  authUrl: string | null;
  authStartedAtUtc: string | null;
  authExpiresAtUtc: string | null;
  connectionStatus: string | null;
  oauthClient: GoogleWorkspaceOauthClientState;
  requestedScopes: string[];
  tokenStorage: GoogleWorkspaceTokenStorageState;
  connectedAccountEmail: string | null;
  grantedScopes: string[];
  fieldProfiles: Record<string, GoogleWorkspaceFieldProfile>;
  serviceStates: Record<string, GoogleWorkspaceServiceState>;
  bootstrapWarnings: GoogleWorkspaceBootstrapWarning[];
  lastConfiguredAtUtc: string | null;
  actions: ConnectorActionDefinition[];
  subscriptions: ConnectorSubscriptionSummary[];
  selectedActionId: string;
  setSelectedActionId: (actionId: string) => void;
  selectAction: (actionId: string, presetInput?: Record<string, string>) => void;
  selectedAction: ConnectorActionDefinition | null;
  input: Record<string, string>;
  setInputValue: (fieldId: string, value: string) => void;
  formattedResult: string;
  checkConnection: () => Promise<void>;
  saveOauthClient: (clientId: string, clientSecret?: string) => Promise<void>;
  clearOauthClient: () => Promise<void>;
  beginAuth: (requestedScopes?: string[]) => Promise<void>;
  cancelPendingAuth: () => Promise<void>;
  disconnect: () => Promise<void>;
  resetLocalSetup: () => Promise<void>;
  runSelectedAction: () => Promise<void>;
  refreshSubscriptions: () => Promise<void>;
  stopSubscription: (subscriptionId: string) => Promise<void>;
  resumeSubscription: (subscriptionId: string) => Promise<void>;
  renewSubscription: (subscriptionId: string) => Promise<void>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];
}

function readFieldOptions(value: unknown): GoogleWorkspaceFieldProfileOption[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => {
      if (!isRecord(item)) return null;
      const label = readString(item.label);
      const optionValue = readString(item.value);
      if (!label || !optionValue) return null;
      return { label, value: optionValue };
    })
    .filter((item): item is GoogleWorkspaceFieldProfileOption => Boolean(item));
}

function readFieldProfiles(
  value: unknown
): Record<string, GoogleWorkspaceFieldProfile> {
  if (!isRecord(value)) return {};
  return Object.entries(value).reduce<Record<string, GoogleWorkspaceFieldProfile>>(
    (next, [fieldId, profile]) => {
      if (!isRecord(profile)) return next;
      next[fieldId] = {
        defaultValue: readString(profile.defaultValue) ?? undefined,
        options: readFieldOptions(profile.options),
        suggestions: readFieldOptions(profile.suggestions),
        description: readString(profile.description) ?? undefined,
        inputMode: readString(profile.inputMode) ?? undefined,
      };
      return next;
    },
    {}
  );
}

function readServiceStates(
  value: unknown
): Record<string, GoogleWorkspaceServiceState> {
  if (!isRecord(value)) return {};
  return Object.entries(value).reduce<Record<string, GoogleWorkspaceServiceState>>(
    (next, [serviceId, state]) => {
      if (!isRecord(state)) return next;
      const summary = readString(state.summary);
      const status = readString(state.status);
      if (!summary || !status) return next;
      next[serviceId] = {
        status,
        summary,
        missingScopes: readStringArray(state.missingScopes),
        details: isRecord(state.details) ? state.details : undefined,
      };
      return next;
    },
    {}
  );
}

function readBootstrapWarnings(value: unknown): GoogleWorkspaceBootstrapWarning[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => {
      if (!isRecord(item)) return null;
      const service = readString(item.service);
      const message = readString(item.message);
      if (!service || !message) return null;
      return { service, message };
    })
    .filter((item): item is GoogleWorkspaceBootstrapWarning => Boolean(item));
}

function readOauthClientState(value: unknown): GoogleWorkspaceOauthClientState {
  if (!isRecord(value)) {
    return {
      configured: false,
      source: "none",
      hasClientSecret: false,
      storagePath: undefined,
    };
  }
  return {
    configured: Boolean(value.configured),
    source: readString(value.source) ?? "none",
    clientIdPreview: readString(value.clientIdPreview) ?? undefined,
    hasClientSecret: Boolean(value.hasClientSecret),
    storagePath: readString(value.storagePath) ?? undefined,
  };
}

function readTokenStorageState(value: unknown): GoogleWorkspaceTokenStorageState {
  if (!isRecord(value)) {
    return {
      source: "none",
      storagePath: undefined,
      present: false,
    };
  }
  return {
    source: readString(value.source) ?? "none",
    storagePath: readString(value.storagePath) ?? undefined,
    present: Boolean(value.present),
  };
}

export function useGoogleWorkspaceConnector(
  runtime: AgentRuntime,
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
  const [oauthClient, setOauthClient] = useState<GoogleWorkspaceOauthClientState>({
    configured: false,
    source: "none",
    hasClientSecret: false,
  });
  const [requestedScopes, setRequestedScopes] = useState<string[]>([]);
  const [tokenStorage, setTokenStorage] = useState<GoogleWorkspaceTokenStorageState>({
    source: "none",
    storagePath: undefined,
    present: false,
  });
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
  const [formattedResult, setFormattedResult] = useState("");
  const pendingPresetInputRef = useRef<Record<string, string> | null>(null);

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
      return;
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
    } catch (configureError) {
      setNotice(null);
      setError(configureError instanceof Error ? configureError.message : String(configureError));
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

  const runSelectedAction = async () => {
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

    if (selectedAction.confirmBeforeRun) {
      const confirmed = window.confirm(
        `${selectedAction.label} will make changes in Google Workspace. Continue?`
      );
      if (!confirmed) return;
    }

    setBusy(true);
    setError(null);
    try {
      const result: ConnectorActionResult = await runtime.runConnectorAction({
        connectorId: connector.id,
        actionId: selectedAction.id,
        input: coerceInput(selectedAction, input),
      });
      setNotice(result.summary);
      setFormattedResult(formatJsonBlock(result.data ?? result));
      await refreshSubscriptions();
      await refreshConnectionProfile(false);
    } catch (actionError) {
      setNotice(null);
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setBusy(false);
    }
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
    formattedResult,
    checkConnection,
    saveOauthClient,
    clearOauthClient,
    beginAuth,
    cancelPendingAuth,
    disconnect,
    resetLocalSetup,
    runSelectedAction,
    refreshSubscriptions,
    stopSubscription,
    resumeSubscription,
    renewSubscription,
  };
}
