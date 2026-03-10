import type {
  ConnectorActionDefinition,
  ConnectorConfigureResult,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";

export function buildDefaultInput(
  action: ConnectorActionDefinition | null
): Record<string, string> {
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

export function formatJsonBlock(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

export function coerceInput(
  action: ConnectorActionDefinition,
  input: Record<string, string>
) {
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

export interface UseGoogleWorkspaceConnectorOptions {
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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function readString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function readStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];
}

export function readFieldOptions(value: unknown): GoogleWorkspaceFieldProfileOption[] {
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

export function readFieldProfiles(
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

export function readServiceStates(
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

export function readBootstrapWarnings(value: unknown): GoogleWorkspaceBootstrapWarning[] {
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

export function readOauthClientState(value: unknown): GoogleWorkspaceOauthClientState {
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

export function readTokenStorageState(value: unknown): GoogleWorkspaceTokenStorageState {
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

export function defaultOauthClientState(): GoogleWorkspaceOauthClientState {
  return {
    configured: false,
    source: "none",
    hasClientSecret: false,
  };
}

export function defaultTokenStorageState(): GoogleWorkspaceTokenStorageState {
  return {
    source: "none",
    storagePath: undefined,
    present: false,
  };
}

export function defaultConnectorState(
  connector: ConnectorSummary
): Pick<
  GoogleWorkspaceConnectorState,
  | "error"
  | "notice"
  | "authPending"
  | "authUrl"
  | "authStartedAtUtc"
  | "authExpiresAtUtc"
  | "connectionStatus"
  | "oauthClient"
  | "requestedScopes"
  | "tokenStorage"
  | "connectedAccountEmail"
  | "grantedScopes"
  | "fieldProfiles"
  | "serviceStates"
  | "bootstrapWarnings"
  | "lastConfiguredAtUtc"
  | "actions"
  | "subscriptions"
  | "selectedActionId"
  | "input"
  | "formattedResult"
> {
  return {
    error: null,
    notice: null,
    authPending: false,
    authUrl: null,
    authStartedAtUtc: null,
    authExpiresAtUtc: null,
    connectionStatus: connector.status,
    oauthClient: defaultOauthClientState(),
    requestedScopes: [],
    tokenStorage: defaultTokenStorageState(),
    connectedAccountEmail: null,
    grantedScopes: [],
    fieldProfiles: {},
    serviceStates: {},
    bootstrapWarnings: [],
    lastConfiguredAtUtc: null,
    actions: [],
    subscriptions: [],
    selectedActionId: "",
    input: {},
    formattedResult: "",
  };
}
