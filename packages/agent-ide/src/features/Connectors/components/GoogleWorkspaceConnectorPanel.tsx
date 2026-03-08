import { useEffect, useMemo, useState, type ReactNode } from "react";
import type {
  AgentRuntime,
  ConnectorActionDefinition,
  ConnectorConfigureResult,
  ConnectorSubscriptionStatus,
  ConnectorSubscriptionSummary,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";
import { Icons } from "../../../ui/icons";
import {
  useGoogleWorkspaceConnector,
  type GoogleWorkspaceConnectorState,
} from "../hooks/useGoogleWorkspaceConnector";

interface GoogleWorkspaceConnectorPanelProps {
  runtime: AgentRuntime;
  connector: ConnectorSummary;
  onConfigured?: (result: ConnectorConfigureResult) => void;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
  policySummary?: {
    headline: string;
    detail: string;
  };
}

type WorkspaceTabId = "overview" | "capabilities" | "automations" | "advanced";
type WorkspaceOnboardingStepId = "credentials" | "scopes" | "consent" | "connected";

interface WorkspaceServiceMeta {
  title: string;
  summary: string;
  detail: string;
  featuredActionIds: string[];
}

interface WorkspaceServiceGroup {
  service: string;
  serviceLabel: string;
  title: string;
  summary: string;
  detail: string;
  actions: ConnectorActionDefinition[];
  featuredActions: ConnectorActionDefinition[];
  supportingActions: ConnectorActionDefinition[];
  kinds: string[];
}

interface AutomationRecipe {
  id: string;
  title: string;
  summary: string;
  actionId: string;
  presetInput?: Record<string, string>;
}

interface GoogleScopeBundle {
  id: string;
  title: string;
  summary: string;
  detail: string;
  scopes: string[];
  apiLabels: string[];
}

interface GoogleOauthTroubleshootingItem {
  id: string;
  title: string;
  detail: string;
}

const TAB_DEFINITIONS: Array<{ id: WorkspaceTabId; label: string; blurb: string }> = [
  {
    id: "overview",
    label: "Overview",
    blurb: "Connection health, capability bundles, and next steps.",
  },
  {
    id: "capabilities",
    label: "Capabilities",
    blurb: "Task-first entry points across Gmail, Calendar, Docs, Sheets, and more.",
  },
  {
    id: "automations",
    label: "Automations",
    blurb: "Durable watches, event subscriptions, and trigger recipes.",
  },
  {
    id: "advanced",
    label: "Advanced",
    blurb: "Full tool catalog, required scopes, and raw execution details.",
  },
];

const SERVICE_ORDER = [
  "gmail",
  "calendar",
  "docs",
  "sheets",
  "bigquery",
  "drive",
  "tasks",
  "chat",
  "workflow",
  "events",
  "expert",
] as const;

const SERVICE_META: Record<string, WorkspaceServiceMeta> = {
  gmail: {
    title: "Gmail",
    summary: "Triaging inboxes, drafting replies, and shaping labels.",
    detail: "Lead with inbox reads and thread work, then escalate into label or watch setup.",
    featuredActionIds: [
      "gmail.read_emails",
      "gmail.send_email",
      "gmail.draft_email",
      "gmail.get_thread",
    ],
  },
  calendar: {
    title: "Calendar",
    summary: "Plan meetings, adjust schedules, and fetch event context.",
    detail: "Creation and maintenance flows should feel like scheduling tasks, not API operations.",
    featuredActionIds: [
      "calendar.list_events_for_date",
      "calendar.create_event",
      "calendar.update_event",
    ],
  },
  docs: {
    title: "Docs",
    summary: "Create notes, read documents, and push updates into living docs.",
    detail: "Keep common writing operations close to the surface; full text transforms stay one click deeper.",
    featuredActionIds: ["docs.create_document", "docs.read_document", "docs.append_text"],
  },
  sheets: {
    title: "Sheets",
    summary: "Read ranges, append rows, and maintain operational spreadsheets.",
    detail: "Expose spreadsheet work as structured actions rather than raw ranges whenever possible.",
    featuredActionIds: ["sheets.read_range", "sheets.append_rows", "sheets.write_range"],
  },
  bigquery: {
    title: "BigQuery",
    summary: "Run SQL against project data with clear query controls.",
    detail: "This stays high leverage, but the UI should still frame it as a data task instead of a hidden expert path.",
    featuredActionIds: ["bigquery.execute_query"],
  },
  drive: {
    title: "Drive",
    summary: "Upload files and publish them into working loops.",
    detail: "Drive works best as a bridge service between content creation and collaboration.",
    featuredActionIds: ["drive.upload_file", "drive.share_file"],
  },
  tasks: {
    title: "Tasks",
    summary: "Pull task lists and create follow-ups from captured work.",
    detail: "Position Tasks as the operational sink for inbox and meeting follow-up.",
    featuredActionIds: ["tasks.list_tasks", "tasks.create_task"],
  },
  chat: {
    title: "Chat",
    summary: "Deliver announcements and event reactions into Google Chat spaces.",
    detail: "Chat is usually the output surface for automations, not where users should begin.",
    featuredActionIds: ["chat.send_message"],
  },
  workflow: {
    title: "Workflows",
    summary: "Cross-service recipes for rituals like standups, meeting prep, and digesting work.",
    detail: "These are the highest signal paths to parity with the old example workflows.",
    featuredActionIds: [
      "workflow.meeting_prep",
      "workflow.email_to_task",
      "workflow.weekly_digest",
    ],
  },
  events: {
    title: "Workspace Events",
    summary: "Subscribe to durable Google Workspace event streams.",
    detail: "Treat this as background automation infrastructure, not a one-shot action.",
    featuredActionIds: ["events.subscribe", "events.renew"],
  },
  expert: {
    title: "Expert Mode",
    summary: "Raw request escape hatch for unsupported Google operations.",
    detail: "Keep this available, but hide it behind an explicit advanced boundary.",
    featuredActionIds: ["expert.raw_request"],
  },
};

const OVERVIEW_QUICKSTARTS: Array<{
  id: string;
  title: string;
  summary: string;
  actionId?: string;
  tab?: WorkspaceTabId;
  presetInput?: Record<string, string>;
  requiresRuntime?: boolean;
}> = [
  {
    id: "read-inbox",
    title: "Review unread mail",
    summary: "Start with Gmail triage so the connector immediately proves value.",
    actionId: "gmail.read_emails",
    tab: "capabilities",
    requiresRuntime: true,
  },
  {
    id: "create-event",
    title: "Create a calendar event",
    summary: "Validate write approval and OAuth scope health with a common scheduling flow.",
    actionId: "calendar.create_event",
    tab: "capabilities",
    requiresRuntime: true,
  },
  {
    id: "start-automation",
    title: "Stand up a durable inbox automation",
    summary: "Provision Gmail watch flow and hand off to the background runtime.",
    actionId: "gmail.watch_emails",
    tab: "automations",
    presetInput: {
      labelIds: "INBOX",
      automationActionId: "workflow.email_to_task",
      automationInputTemplate: "{\"messageId\":\"{{message.messageId}}\",\"tasklist\":\"@default\"}",
    },
    requiresRuntime: true,
  },
];

const AUTOMATION_RECIPES: AutomationRecipe[] = [
  {
    id: "gmail-watch",
    title: "Inbox watch",
    summary: "Maintain a durable Gmail watch and inspect normalized deliveries in Autopilot.",
    actionId: "gmail.watch_emails",
    presetInput: {
      labelIds: "INBOX",
      maxMessages: "10",
      pollInterval: "5",
    },
  },
  {
    id: "gmail-to-task",
    title: "Inbox to task",
    summary: "Convert new Gmail deliveries into Google Tasks using the built-in workflow.",
    actionId: "gmail.watch_emails",
    presetInput: {
      labelIds: "INBOX",
      automationActionId: "workflow.email_to_task",
      automationInputTemplate: "{\"messageId\":\"{{message.messageId}}\",\"tasklist\":\"@default\"}",
    },
  },
  {
    id: "workspace-events",
    title: "Workspace event stream",
    summary: "Subscribe to durable Workspace events and keep them visible in the runtime.",
    actionId: "events.subscribe",
    presetInput: {
      eventTypes: "google.workspace.chat.message.v1.created",
      pollInterval: "5",
      maxMessages: "10",
    },
  },
  {
    id: "workspace-to-chat",
    title: "Workspace events to Chat",
    summary: "Route normalized Workspace events into a Chat space after you fill in the target space.",
    actionId: "events.subscribe",
    presetInput: {
      eventTypes: "google.workspace.chat.message.v1.created",
      automationActionId: "chat.send_message",
      automationInputTemplate:
        "{\"space\":\"spaces/AAAA...\",\"text\":\"Workspace event {{event.eventType}} on {{event.subject}}\"}",
    },
  },
];

const GOOGLE_SCOPE_BUNDLES: GoogleScopeBundle[] = [
  {
    id: "gmail",
    title: "Gmail",
    summary: "Read inboxes, draft replies, and manage Gmail labels and threads.",
    detail: "Includes inbox reads plus write access for drafts, labels, archive, and mark-as-read flows.",
    scopes: ["gmail.readonly", "gmail.modify"],
    apiLabels: ["Gmail API"],
  },
  {
    id: "calendar",
    title: "Calendar",
    summary: "List, create, update, and delete Google Calendar events.",
    detail: "Covers read and write access for scheduling workflows and meeting prep.",
    scopes: ["calendar.readonly", "calendar"],
    apiLabels: ["Google Calendar API"],
  },
  {
    id: "docs",
    title: "Docs",
    summary: "Create, read, append, and replace content in Google Docs.",
    detail: "Best for notes, briefs, and collaborative document updates.",
    scopes: ["documents.readonly", "documents"],
    apiLabels: ["Google Docs API"],
  },
  {
    id: "sheets",
    title: "Sheets",
    summary: "Read ranges, write values, append rows, and inspect spreadsheets.",
    detail: "Covers operational spreadsheet reads and writes.",
    scopes: ["spreadsheets.readonly", "spreadsheets"],
    apiLabels: ["Google Sheets API"],
  },
  {
    id: "drive",
    title: "Drive",
    summary: "Upload and share files from the local assistant.",
    detail: "Use when the assistant needs to publish or hand off files.",
    scopes: ["drive.readonly", "drive"],
    apiLabels: ["Google Drive API"],
  },
  {
    id: "tasks",
    title: "Tasks",
    summary: "Read task lists and create follow-up tasks.",
    detail: "Useful for inbox-to-task and meeting follow-up loops.",
    scopes: ["tasks"],
    apiLabels: ["Google Tasks API"],
  },
  {
    id: "chat",
    title: "Chat",
    summary: "Send messages into Google Chat spaces.",
    detail: "Primarily used as an automation output surface.",
    scopes: ["chat.messages.create"],
    apiLabels: ["Google Chat API"],
  },
  {
    id: "bigquery",
    title: "BigQuery",
    summary: "Execute queries against Google Cloud project data.",
    detail: "Requires cloud data access and is typically only needed for analytics workflows.",
    scopes: ["bigquery", "cloud-platform"],
    apiLabels: ["BigQuery API"],
  },
  {
    id: "automations",
    title: "Automations",
    summary: "Enable Gmail watch and Workspace Events background subscriptions.",
    detail: "Adds Pub/Sub, Cloud project, and chat event read scopes needed for the default durable event flows.",
    scopes: ["pubsub", "cloud-platform", "chat.messages.readonly"],
    apiLabels: ["Cloud Pub/Sub API", "Google Workspace Events API", "Google Chat API"],
  },
];

const ONBOARDING_STEPS: Array<{ id: WorkspaceOnboardingStepId; label: string }> = [
  { id: "credentials", label: "Credentials" },
  { id: "scopes", label: "Scope selection" },
  { id: "consent", label: "Consent" },
  { id: "connected", label: "Connected dashboard" },
];

const GOOGLE_OAUTH_TROUBLESHOOTING: GoogleOauthTroubleshootingItem[] = [
  {
    id: "org-internal",
    title: "org_internal or 'only be used within its organization'",
    detail:
      "Your Google Auth Platform audience is set to Internal. In Google Cloud Console, open the project, go to APIs & Services, then OAuth consent screen or Google Auth Platform Audience, edit the app, and change User Type from Internal to External. Internal can still work, but only for accounts inside that Workspace organization and usually requires more controlled setup.",
  },
  {
    id: "test-user",
    title: "Access blocked for a personal Gmail or tester",
    detail:
      "If the consent screen is External but still in testing mode, add the exact Google account as a test user before retrying sign-in.",
  },
  {
    id: "redirect-uri",
    title: "redirect_uri_mismatch",
    detail:
      "Use a Desktop app OAuth client. Web application credentials often expect a different redirect URI and will fail with the local native callback flow.",
  },
  {
    id: "wrong-account",
    title: "Wrong cached Google account",
    detail:
      "Use Retry sign-in to force the account chooser again. You do not need to re-enter the saved local client just to switch accounts.",
  },
];

function actionKindLabel(kind: string): string {
  switch (kind) {
    case "read":
      return "Read";
    case "write":
      return "Write";
    case "workflow":
      return "Workflow";
    case "admin":
      return "Admin";
    case "expert":
      return "Expert";
    default:
      return kind;
  }
}

function subscriptionStatusLabel(status: ConnectorSubscriptionStatus): string {
  switch (status) {
    case "active":
      return "Active";
    case "paused":
      return "Paused";
    case "renewing":
      return "Renewing";
    case "reauth_required":
      return "Reauth required";
    case "degraded":
      return "Degraded";
    case "stopped":
      return "Stopped";
    default:
      return status;
  }
}

function formatTimestamp(value?: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function orderIndex(service: string): number {
  const index = SERVICE_ORDER.indexOf(service as (typeof SERVICE_ORDER)[number]);
  return index === -1 ? SERVICE_ORDER.length : index;
}

function availabilityLabel(status: ConnectorSummary["status"]): string {
  switch (status) {
    case "connected":
      return "Ready";
    case "degraded":
      return "Attention";
    case "disabled":
      return "Disabled";
    default:
      return "Connect required";
  }
}

function availabilityTone(status: ConnectorSummary["status"]): "ready" | "attention" | "setup" {
  switch (status) {
    case "connected":
      return "ready";
    case "degraded":
      return "attention";
    default:
      return "setup";
  }
}

function isMissingOauthClientError(message: string | null): boolean {
  if (!message) return false;
  return message.includes("Missing Google OAuth client ID");
}

function serviceStateLabel(status?: string): string {
  switch (status) {
    case "ready":
      return "Ready";
    case "manual_input":
      return "Needs input";
    case "needs_scope":
      return "Needs scope";
    case "degraded":
      return "Attention";
    default:
      return "Setup";
  }
}

function serviceStateTone(status?: string): "ready" | "attention" | "setup" {
  switch (status) {
    case "ready":
      return "ready";
    case "degraded":
    case "needs_scope":
      return "attention";
    default:
      return "setup";
  }
}

function normalizeGoogleScope(scope: string): string {
  const trimmed = scope.trim();
  const prefix = "https://www.googleapis.com/auth/";
  if (trimmed.startsWith(prefix)) {
    return trimmed.slice(prefix.length);
  }
  if (trimmed === "https://www.googleapis.com/auth/userinfo.email") {
    return "email";
  }
  return trimmed;
}

function googleScopeUri(scope: string): string {
  const normalized = normalizeGoogleScope(scope);
  if (normalized === "openid") {
    return "openid";
  }
  if (normalized === "email") {
    return "https://www.googleapis.com/auth/userinfo.email";
  }
  return `https://www.googleapis.com/auth/${normalized}`;
}

function inferBundleSelectionFromScopes(scopes: string[]): string[] {
  const normalized = new Set(scopes.map(normalizeGoogleScope));
  return GOOGLE_SCOPE_BUNDLES.filter((bundle) =>
    bundle.scopes.some((scope) => normalized.has(normalizeGoogleScope(scope)))
  ).map((bundle) => bundle.id);
}

function onboardingStepIndex(step: WorkspaceOnboardingStepId): number {
  return ONBOARDING_STEPS.findIndex((item) => item.id === step);
}

function mergedFieldDescription(
  fieldDescription?: string,
  profileDescription?: string
): string | undefined {
  if (fieldDescription && profileDescription && fieldDescription !== profileDescription) {
    return `${profileDescription} ${fieldDescription}`;
  }
  return profileDescription ?? fieldDescription;
}

function renderActionField(
  action: ConnectorActionDefinition,
  workspace: GoogleWorkspaceConnectorState
) {
  return action.fields.map((field) => {
    const value = workspace.input[field.id] ?? "";
    const fieldProfile = workspace.fieldProfiles[field.id];
    const fieldDescription = mergedFieldDescription(field.description, fieldProfile?.description);
    const profileOptions = fieldProfile?.options ?? [];
    const profileSuggestions = fieldProfile?.suggestions ?? [];
    const useProfileSelect =
      field.type !== "select" &&
      fieldProfile?.inputMode === "select" &&
      profileOptions.length > 0;

    if (field.type === "textarea") {
      return (
        <label key={field.id} className="workspace-field textarea">
          {field.label}
          <textarea
            value={value}
            onChange={(event) => workspace.setInputValue(field.id, event.target.value)}
            placeholder={field.placeholder}
            rows={5}
          />
          {fieldDescription ? <span>{fieldDescription}</span> : null}
          {profileSuggestions.length > 0 ? (
            <div className="workspace-suggestion-row">
              {profileSuggestions.map((suggestion) => (
                <button
                  key={`${field.id}-${suggestion.value}`}
                  type="button"
                  className="workspace-suggestion-chip"
                  onClick={() => workspace.setInputValue(field.id, suggestion.value)}
                >
                  {suggestion.label}
                </button>
              ))}
            </div>
          ) : null}
        </label>
      );
    }

    if (field.type === "select" || useProfileSelect) {
      const options = field.type === "select" ? field.options ?? [] : profileOptions;
      return (
        <label key={field.id} className="workspace-field">
          {field.label}
          <select
            value={value}
            onChange={(event) => workspace.setInputValue(field.id, event.target.value)}
          >
            {options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
          {fieldDescription ? <span>{fieldDescription}</span> : null}
        </label>
      );
    }

    return (
      <label key={field.id} className="workspace-field">
        {field.label}
        <input
          type={field.type === "number" ? "number" : field.type === "email" ? "email" : "text"}
          value={value}
          onChange={(event) => workspace.setInputValue(field.id, event.target.value)}
          placeholder={field.placeholder}
        />
        {fieldDescription ? <span>{fieldDescription}</span> : null}
        {profileSuggestions.length > 0 ? (
          <div className="workspace-suggestion-row">
            {profileSuggestions.map((suggestion) => (
              <button
                key={`${field.id}-${suggestion.value}`}
                type="button"
                className="workspace-suggestion-chip"
                onClick={() => workspace.setInputValue(field.id, suggestion.value)}
              >
                {suggestion.label}
              </button>
            ))}
          </div>
        ) : null}
      </label>
    );
  });
}

function WorkspaceActionComposer({
  action,
  workspace,
  eyebrow,
}: {
  action: ConnectorActionDefinition | null;
  workspace: GoogleWorkspaceConnectorState;
  eyebrow: string;
}) {
  if (!action) {
    return (
      <div className="workspace-empty-state">
        <strong>Select an action</strong>
        <p>Pick a capability or automation recipe to configure it here.</p>
      </div>
    );
  }

  return (
    <div className="workspace-action-panel workspace-composer-card">
      <div className="workspace-panel-heading">
        <span>{eyebrow}</span>
        <strong>{action.label}</strong>
      </div>
      <div className="workspace-action-summary">
        <span className={`workspace-action-kind kind-${action.kind}`}>
          {actionKindLabel(action.kind)}
        </span>
        <p>{action.description}</p>
        {action.confirmBeforeRun ? (
          <p className="workspace-inline-note">
            This action requests confirmation before making changes in Google Workspace.
          </p>
        ) : null}
        {action.requiredScopes?.length ? (
          <div className="workspace-required-scopes">
            {action.requiredScopes.map((scope) => (
              <code key={scope}>{scope}</code>
            ))}
          </div>
        ) : null}
      </div>

      {action.fields.length > 0 ? (
        <div className="workspace-action-grid">{renderActionField(action, workspace)}</div>
      ) : (
        <p className="workspace-auth-note">No additional input is required for this action.</p>
      )}

      <div className="workspace-action-actions">
        <button
          type="button"
          className="btn-primary"
          onClick={workspace.runSelectedAction}
          disabled={workspace.busy || !workspace.runtimeReady}
        >
          {workspace.busy ? "Running..." : `Run ${action.label}`}
        </button>
      </div>
    </div>
  );
}

function WorkspaceSubscriptionCard({
  subscription,
  workspace,
}: {
  subscription: ConnectorSubscriptionSummary;
  workspace: GoogleWorkspaceConnectorState;
}) {
  return (
    <article className="workspace-subscription-card">
      <div className="workspace-subscription-card-head">
        <div>
          <strong>{subscription.kind}</strong>
          <p>{subscription.pubsubSubscription}</p>
        </div>
        <span
          className={`workspace-action-kind workspace-subscription-status status-${subscription.status}`}
        >
          {subscriptionStatusLabel(subscription.status)}
        </span>
      </div>
      <div className="workspace-subscription-meta">
        <span>Topic: {subscription.pubsubTopic}</span>
        {subscription.accountEmail ? <span>Account: {subscription.accountEmail}</span> : null}
        {subscription.automationActionId ? (
          <span>Trigger: {subscription.automationActionId}</span>
        ) : (
          <span>Trigger: none</span>
        )}
        {subscription.renewAtUtc ? (
          <span>Renew at: {formatTimestamp(subscription.renewAtUtc)}</span>
        ) : null}
        {subscription.lastDeliveryAtUtc ? (
          <span>Last delivery: {formatTimestamp(subscription.lastDeliveryAtUtc)}</span>
        ) : null}
        {subscription.lastError ? <span>Error: {subscription.lastError}</span> : null}
      </div>
      <div className="workspace-subscription-actions">
        <button
          type="button"
          className="btn-secondary"
          onClick={() => workspace.renewSubscription(subscription.subscriptionId)}
          disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
        >
          Renew
        </button>
        {subscription.status === "paused" ? (
          <button
            type="button"
            className="btn-secondary"
            onClick={() => workspace.resumeSubscription(subscription.subscriptionId)}
            disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
          >
            Resume
          </button>
        ) : (
          <button
            type="button"
            className="btn-secondary"
            onClick={() => workspace.stopSubscription(subscription.subscriptionId)}
            disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
          >
            Pause
          </button>
        )}
      </div>
    </article>
  );
}

function WorkspaceModal({
  open,
  title,
  description,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
}) {
  if (!open) return null;

  return (
    <div className="workspace-modal-backdrop" role="presentation" onClick={onClose}>
      <div
        className="workspace-modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="workspace-modal-head">
          <div>
            <h4>{title}</h4>
            {description ? <p>{description}</p> : null}
          </div>
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
        <div className="workspace-modal-body">{children}</div>
      </div>
    </div>
  );
}

export function GoogleWorkspaceConnectorPanel({
  runtime,
  connector,
  onConfigured,
  onOpenPolicyCenter,
  policySummary,
}: GoogleWorkspaceConnectorPanelProps) {
  const [activeTab, setActiveTab] = useState<WorkspaceTabId>("overview");
  const [oauthClientIdInput, setOauthClientIdInput] = useState("");
  const [oauthClientSecretInput, setOauthClientSecretInput] = useState("");
  const [selectedBundleIds, setSelectedBundleIds] = useState<string[]>([]);
  const [scopeModalOpen, setScopeModalOpen] = useState(false);
  const [consentModalOpen, setConsentModalOpen] = useState(false);
  const [setupHelpModalOpen, setSetupHelpModalOpen] = useState(false);
  const [settingsModalOpen, setSettingsModalOpen] = useState(false);
  const workspace = useGoogleWorkspaceConnector(runtime, connector, {
    onConfigured,
  });

  const actionsById = useMemo(() => {
    return new Map(workspace.actions.map((action) => [action.id, action] as const));
  }, [workspace.actions]);

  const groupedActions = useMemo<WorkspaceServiceGroup[]>(() => {
    const groups = new Map<string, { serviceLabel: string; actions: ConnectorActionDefinition[] }>();
    for (const action of workspace.actions) {
      const key = action.service ?? "workspace";
      const current = groups.get(key);
      if (current) {
        current.actions.push(action);
      } else {
        groups.set(key, {
          serviceLabel: action.serviceLabel ?? key,
          actions: [action],
        });
      }
    }

    return Array.from(groups.entries())
      .map(([service, value]) => {
        const meta = SERVICE_META[service] ?? {
          title: value.serviceLabel,
          summary: `${value.serviceLabel} actions`,
          detail: "Curated Google action bundle.",
          featuredActionIds: [],
        };
        const featuredIds = new Set(meta.featuredActionIds);
        const featuredActions = meta.featuredActionIds
          .map((actionId) => value.actions.find((action) => action.id === actionId) ?? null)
          .filter((action): action is ConnectorActionDefinition => Boolean(action));
        const supportingActions = value.actions.filter((action) => !featuredIds.has(action.id));
        const kinds = Array.from(new Set(value.actions.map((action) => actionKindLabel(action.kind))));

        return {
          service,
          serviceLabel: value.serviceLabel,
          title: meta.title,
          summary: meta.summary,
          detail: meta.detail,
          actions: value.actions,
          featuredActions: featuredActions.length > 0 ? featuredActions : value.actions.slice(0, 3),
          supportingActions,
          kinds,
        };
      })
      .sort((left, right) => orderIndex(left.service) - orderIndex(right.service));
  }, [workspace.actions]);

  const capabilityGroups = groupedActions.filter(
    (group) => group.service !== "expert" && group.service !== "events"
  );
  const automationGroups = groupedActions.filter(
    (group) =>
      group.service === "events" ||
      group.actions.some((action) => action.id === "gmail.watch_emails" || action.kind === "admin")
  );
  const advancedGroups = groupedActions;
  const activeSubscriptions = workspace.subscriptions.filter(
    (subscription) => subscription.status === "active" || subscription.status === "renewing"
  );
  const attentionSubscriptions = workspace.subscriptions.filter(
    (subscription) =>
      subscription.status === "degraded" || subscription.status === "reauth_required"
  );

  const connectorStatus =
    (workspace.connectionStatus as ConnectorSummary["status"] | null) ?? connector.status;
  const availability = availabilityLabel(connectorStatus);
  const availabilityStyle = availabilityTone(connectorStatus);
  const isConnected = connectorStatus === "connected" || connectorStatus === "degraded";
  const missingOauthClient = isMissingOauthClientError(workspace.error);
  const onboardingStep: WorkspaceOnboardingStepId = isConnected
    ? "connected"
    : workspace.authPending
      ? "consent"
      : workspace.oauthClient.configured
        ? "scopes"
        : "credentials";

  useEffect(() => {
    if (workspace.authPending && workspace.requestedScopes.length > 0) {
      setSelectedBundleIds(inferBundleSelectionFromScopes(workspace.requestedScopes));
    }
  }, [workspace.authPending, workspace.requestedScopes]);

  const selectedBundles = GOOGLE_SCOPE_BUNDLES.filter((bundle) =>
    selectedBundleIds.includes(bundle.id)
  );
  const requestedScopes = Array.from(
    new Set(selectedBundles.flatMap((bundle) => bundle.scopes))
  );
  const canBeginAuth = workspace.runtimeReady && requestedScopes.length > 0;
  const reconnectScopes =
    requestedScopes.length > 0 ? requestedScopes : workspace.grantedScopes;
  const tokenStoragePath = workspace.tokenStorage.storagePath;
  const clientStoragePath = workspace.oauthClient.storagePath;
  const troubleshootingScopes = Array.from(
    new Set(["openid", "email", ...requestedScopes].map(googleScopeUri))
  );
  const troubleshootingApis = Array.from(
    new Set(selectedBundles.flatMap((bundle) => bundle.apiLabels))
  );
  const oauthClientPreview =
    workspace.oauthClient.clientIdPreview ||
    oauthClientIdInput.trim() ||
    "your saved Desktop OAuth client";

  const presetForAction = (
    action: ConnectorActionDefinition,
    extraPreset?: Record<string, string>
  ) => {
    const fieldProfilePreset = action.fields.reduce<Record<string, string>>((next, field) => {
      const defaultValue = workspace.fieldProfiles[field.id]?.defaultValue;
      if (defaultValue !== undefined) {
        next[field.id] = defaultValue;
      }
      return next;
    }, {});
    return {
      ...fieldProfilePreset,
      ...extraPreset,
    };
  };

  const openAction = (
    tab: WorkspaceTabId,
    actionId: string,
    presetInput?: Record<string, string>
  ) => {
    const action = actionsById.get(actionId);
    if (!action) return;
    workspace.selectAction(actionId, presetForAction(action, presetInput));
    setActiveTab(tab);
  };

  const openAuthLink = () => {
    if (!workspace.authUrl || typeof window === "undefined") return;
    window.open(workspace.authUrl, "_blank", "noopener,noreferrer");
  };

  const copyAuthLink = async () => {
    if (!workspace.authUrl || !navigator.clipboard?.writeText) return;
    try {
      await navigator.clipboard.writeText(workspace.authUrl);
    } catch (_error) {
      // Leave the manual link visible as a fallback.
    }
  };

  const toggleBundle = (bundleId: string) => {
    setSelectedBundleIds((current) =>
      current.includes(bundleId)
        ? current.filter((value) => value !== bundleId)
        : [...current, bundleId]
    );
  };

  const resetGoogleSetup = async () => {
    const confirmed = window.confirm(
      "Reset Google setup? This will remove local OAuth tokens and the saved local client configuration."
    );
    if (!confirmed) return;
    setScopeModalOpen(false);
    setConsentModalOpen(false);
    await workspace.resetLocalSetup();
    setSelectedBundleIds([]);
    setOauthClientIdInput("");
    setOauthClientSecretInput("");
  };

  const reopenScopeSelection = async () => {
    await workspace.cancelPendingAuth();
    setConsentModalOpen(false);
    setScopeModalOpen(true);
  };

  const retryConsent = async () => {
    await workspace.cancelPendingAuth();
    await workspace.beginAuth(requestedScopes);
  };

  return (
    <div className="connector-test-panel workspace-connector-panel workspace-product-panel">
      <div className="workspace-overview-hero">
        <div className="workspace-hero-copy">
          <span className="workspace-hero-kicker">Built-in Google Connector</span>
          <h3>Google Workspace</h3>
          <p>
            Local-first Google access for Gmail, Calendar, Docs, Sheets, BigQuery, Drive, Tasks,
            Chat, and durable Workspace automations inside Autopilot.
          </p>
          {workspace.connectedAccountEmail ? (
            <p className="workspace-hero-account">
              Connected account: <strong>{workspace.connectedAccountEmail}</strong>
            </p>
          ) : null}
        </div>
        <div className="workspace-hero-meta">
          <div className={`workspace-health-pill tone-${availabilityStyle}`}>{availability}</div>
          <div className="workspace-hero-actions">
            <button
              type="button"
              className="btn-secondary workspace-utility-button"
              onClick={() => setSettingsModalOpen(true)}
              disabled={workspace.busy || !workspace.runtimeReady}
            >
              <Icons.Settings width="14" height="14" />
              <span>Local settings</span>
            </button>
            {onOpenPolicyCenter ? (
              <button
                type="button"
                className="btn-secondary workspace-utility-button"
                onClick={() => onOpenPolicyCenter(connector)}
              >
                <Icons.Gate width="14" height="14" />
                <span>Open policy</span>
              </button>
            ) : null}
            {isConnected ? (
              <>
              <button
                type="button"
                className="btn-primary"
                onClick={() => void workspace.beginAuth(reconnectScopes)}
                disabled={workspace.busy || !workspace.runtimeReady || reconnectScopes.length === 0}
              >
                {workspace.busy ? "Working..." : isConnected ? "Reconnect" : "Start sign-in"}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.checkConnection}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                Refresh
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.disconnect}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                {workspace.tokenStorage.source === "local" ? "Wipe local tokens" : "Disconnect"}
              </button>
              </>
            ) : null}
          </div>
        </div>
      </div>

      <div className="workspace-onboarding-rail">
        {ONBOARDING_STEPS.map((step) => {
          const stepIndex = onboardingStepIndex(step.id);
          const currentIndex = onboardingStepIndex(onboardingStep);
          const state =
            stepIndex < currentIndex
              ? "complete"
              : step.id === onboardingStep
                ? "active"
                : "upcoming";
          return (
            <div
              key={step.id}
              className={`workspace-onboarding-step state-${state}`}
              aria-current={step.id === onboardingStep ? "step" : undefined}
            >
              <span>{stepIndex + 1}</span>
              <strong>{step.label}</strong>
            </div>
          );
        })}
      </div>

      {!workspace.runtimeReady ? (
        <p className="connector-test-error">
          Runtime is missing the generic Google connector commands.
        </p>
      ) : null}
      {workspace.notice ? <p className="connector-test-success">{workspace.notice}</p> : null}
      {workspace.error ? <p className="connector-test-error">{workspace.error}</p> : null}

      {!isConnected ? (
        <div className="workspace-tab-panel">
          {onboardingStep === "credentials" ? (
            <section className="workspace-auth-stage">
              <div className="workspace-auth-stage-head">
                <div>
                  <span className="workspace-hero-kicker">Step 1</span>
                  <h4>Set up Google access</h4>
                  <p>
                    Create a Desktop OAuth client in your own Google Cloud project, then save it
                    locally in Autopilot. This assistant does not use platform-managed Google
                    credentials.
                  </p>
                </div>
                <span className="workspace-health-pill tone-setup">Credentials required</span>
              </div>

              <div className="workspace-auth-stage-grid">
                <article className="workspace-auth-step">
                  <strong>1. Create a Desktop OAuth client</strong>
                  <p>
                    Use Google Cloud Console credentials for your own project. If you plan to sign
                    in with personal Gmail or any account outside a Workspace org, the app must be
                    set to External.
                  </p>
                </article>
                <article className="workspace-auth-step">
                  <strong>2. Save it locally</strong>
                  <p>Autopilot validates the client ID format before it enables Google consent.</p>
                </article>
                <article className="workspace-auth-step">
                  <strong>3. Keep ownership local</strong>
                  <p>Client config and tokens stay on this machine, under your control.</p>
                </article>
              </div>

              <div className="workspace-auth-stage-actions">
                <a
                  className="btn-secondary"
                  href="https://console.cloud.google.com/apis/credentials"
                  target="_blank"
                  rel="noreferrer"
                >
                  Open Google Cloud Console
                </a>
                <a
                  className="btn-secondary"
                  href="https://developers.google.com/workspace/guides/create-credentials"
                  target="_blank"
                  rel="noreferrer"
                >
                  Credential setup guide
                </a>
              </div>

              {missingOauthClient ? (
                <div className="workspace-warning-panel">
                  <strong>Google client setup is the first gate</strong>
                  <div className="workspace-warning-list">
                    <span>Create a Desktop OAuth client in your own Google Cloud project.</span>
                    <span>Paste the client ID below and save it locally.</span>
                    <span>Google sign-in is only enabled after local validation succeeds.</span>
                  </div>
                </div>
              ) : null}

              <div className="workspace-warning-panel">
                <strong>Common Google setup failures</strong>
                <div className="workspace-warning-list">
                  <span>
                    `org_internal` means the OAuth app is restricted to an internal Workspace
                    organization.
                  </span>
                  <span>
                    Personal Gmail accounts need an External audience, or they must be listed as
                    test users while the app is still in testing mode.
                  </span>
                  <span>
                    Use a Desktop app OAuth client, not a Web app client, for the native Autopilot
                    redirect flow.
                  </span>
                </div>
              </div>

              <section className="workspace-byok-panel">
                <div className="workspace-byok-head">
                  <div>
                    <strong>Google Cloud Desktop OAuth client</strong>
                    <p>
                      This is the required setup path for private Autopilot installs. The client
                      belongs to you and is stored locally on disk.
                    </p>
                  </div>
                  <span className="workspace-health-pill tone-setup">Local setup</span>
                </div>
                <div className="workspace-action-grid">
                  <label className="workspace-field">
                    Google OAuth client ID
                    <input
                      type="text"
                      value={oauthClientIdInput}
                      onChange={(event) => setOauthClientIdInput(event.target.value)}
                      placeholder="1234567890-abcdef.apps.googleusercontent.com"
                    />
                    <span>Use the Desktop app client ID from your own Google Cloud project.</span>
                  </label>
                  <label className="workspace-field">
                    Client secret
                    <input
                      type="password"
                      value={oauthClientSecretInput}
                      onChange={(event) => setOauthClientSecretInput(event.target.value)}
                      placeholder="Optional"
                    />
                    <span>Optional for this native flow. Leave blank unless your client needs it.</span>
                  </label>
                </div>
                <div className="workspace-storage-list">
                  <span>
                    Client config path:{" "}
                    <code>{clientStoragePath ?? "Unavailable until runtime is ready."}</code>
                  </span>
                  <span>
                    Token storage path:{" "}
                    <code>{tokenStoragePath ?? "Unavailable until runtime is ready."}</code>
                  </span>
                </div>
                <div className="workspace-byok-meta">
                  <span>
                    Nothing is sent to a platform relay. Your Google project issues the consent
                    screen, and Autopilot stores the result locally.
                  </span>
                </div>
                <div className="workspace-auth-stage-actions">
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={() =>
                      void workspace.saveOauthClient(oauthClientIdInput, oauthClientSecretInput)
                    }
                    disabled={workspace.busy || !workspace.runtimeReady || !oauthClientIdInput.trim()}
                  >
                    Save locally
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => setSetupHelpModalOpen(true)}
                    disabled={workspace.busy || !workspace.runtimeReady}
                  >
                    Troubleshoot setup
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={workspace.checkConnection}
                    disabled={workspace.busy || !workspace.runtimeReady}
                  >
                    Refresh status
                  </button>
                </div>
              </section>
            </section>
          ) : null}

          {onboardingStep === "scopes" ? (
            <section className="workspace-auth-stage">
              <div className="workspace-auth-stage-head">
                <div>
                  <span className="workspace-hero-kicker">Step 2</span>
                  <h4>Choose what this local agent can access</h4>
                  <p>
                    Select the Google capabilities you want to grant before Autopilot sends you to
                    Google consent. Nothing beyond these bundles will be requested.
                  </p>
                </div>
                <span className="workspace-health-pill tone-setup">
                  {selectedBundles.length > 0 ? `${selectedBundles.length} selected` : "Select scopes"}
                </span>
              </div>
              <div className="workspace-onboarding-summary">
                <strong>
                  {selectedBundles.length > 0
                    ? `${selectedBundles.length} capability bundles selected`
                    : "No bundles selected yet"}
                </strong>
                <p>
                  Keep the column focused on the next action. Use the bundle picker to review and
                  change the detailed scope map.
                </p>
                <div className="workspace-bundle-strip">
                  {selectedBundles.length > 0 ? (
                    selectedBundles.map((bundle) => (
                      <span key={bundle.id} className="workspace-bundle-chip">
                        {bundle.title}
                      </span>
                    ))
                  ) : (
                    <span className="workspace-bundle-chip">Choose bundles to continue</span>
                  )}
                </div>
              </div>

              <div className="workspace-storage-list">
                <span>
                  OAuth client:{" "}
                  <code>
                    {workspace.oauthClient.clientIdPreview
                      ? `${workspace.oauthClient.source} ${workspace.oauthClient.clientIdPreview}`
                      : "Not configured"}
                  </code>
                </span>
                <span>
                  Tokens stay on disk at <code>{tokenStoragePath ?? "Unavailable"}</code>
                </span>
              </div>

              <div className="workspace-auth-stage-actions">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setScopeModalOpen(true)}
                  disabled={workspace.busy || !workspace.runtimeReady}
                >
                  Choose bundles
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => void workspace.beginAuth(requestedScopes)}
                  disabled={workspace.busy || !canBeginAuth}
                >
                  {workspace.busy ? "Starting..." : "Continue to Google consent"}
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => {
                    setOauthClientIdInput("");
                    setOauthClientSecretInput("");
                    void workspace.clearOauthClient();
                  }}
                  disabled={
                    workspace.busy ||
                    !workspace.runtimeReady ||
                    workspace.oauthClient.source !== "local"
                  }
                >
                  Remove local client
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => void resetGoogleSetup()}
                  disabled={workspace.busy || !workspace.runtimeReady}
                >
                  Reset Google setup
                </button>
              </div>
            </section>
          ) : null}

          {onboardingStep === "consent" ? (
            <section className="workspace-auth-stage">
              <div className="workspace-auth-stage-head">
                <div>
                  <span className="workspace-hero-kicker">Step 3</span>
                  <h4>Finish consent in Google</h4>
                  <p>
                    Autopilot has started native Google OAuth with the exact bundles you selected.
                    Complete consent in your browser, then return here while the connector refreshes
                    automatically.
                  </p>
                </div>
                <span className="workspace-health-pill tone-setup">Awaiting approval</span>
              </div>
              <div className="workspace-onboarding-summary">
                <strong>
                  {selectedBundles.length > 0
                    ? `Google will prompt for ${selectedBundles.length} selected bundle${selectedBundles.length === 1 ? "" : "s"}`
                    : "Consent is in progress"}
                </strong>
                <p>
                  The OAuth link now forces the Google account chooser. If Google opens the wrong
                  cached account or shows an authorization error, restart from here without retyping
                  your client credentials. Google-side errors like `org_internal` happen before the
                  local callback, so fix the Cloud Console settings and retry from this step.
                </p>
                <div className="workspace-bundle-strip">
                  {selectedBundles.map((bundle) => (
                    <span key={bundle.id} className="workspace-bundle-chip">
                      {bundle.title}
                    </span>
                  ))}
                </div>
              </div>
              <div className="workspace-auth-stage-actions">
                <button
                  type="button"
                  className="btn-primary"
                  onClick={openAuthLink}
                  disabled={!workspace.authUrl}
                >
                  Open sign-in page
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => void copyAuthLink()}
                  disabled={!workspace.authUrl}
                >
                  Copy sign-in link
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={workspace.checkConnection}
                  disabled={workspace.busy || !workspace.runtimeReady}
                >
                  I finished sign-in
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => void retryConsent()}
                  disabled={workspace.busy || !workspace.runtimeReady || requestedScopes.length === 0}
                >
                  Retry sign-in
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => void reopenScopeSelection()}
                  disabled={workspace.busy || !workspace.runtimeReady}
                >
                  Change bundles
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setConsentModalOpen(true)}
                  disabled={!workspace.authUrl}
                >
                  View details
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setSetupHelpModalOpen(true)}
                  disabled={workspace.busy || !workspace.runtimeReady}
                >
                  I hit a Google error
                </button>
              </div>
              {workspace.authExpiresAtUtc ? (
                <p className="workspace-inline-note">
                  Link expires around {formatTimestamp(workspace.authExpiresAtUtc)}.
                </p>
              ) : null}
            </section>
          ) : null}
        </div>
      ) : (
        <>
          <div className="workspace-tab-nav" role="tablist" aria-label="Google Workspace sections">
            {TAB_DEFINITIONS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={activeTab === tab.id}
                className={`workspace-tab-button ${activeTab === tab.id ? "active" : ""}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <strong>{tab.label}</strong>
                <span>{tab.blurb}</span>
              </button>
            ))}
          </div>

          {activeTab === "overview" ? (
            <div className="workspace-tab-panel">
              <div className="workspace-overview-grid">
                <article className="workspace-stat-card">
                  <span>Account</span>
                  <strong>{workspace.connectedAccountEmail ?? "Not connected"}</strong>
                  <p>
                    {workspace.lastConfiguredAtUtc
                      ? `Last checked ${formatTimestamp(workspace.lastConfiguredAtUtc)}`
                      : connector.lastSyncAtUtc
                        ? `Last sync ${formatTimestamp(connector.lastSyncAtUtc)}`
                        : "Run Connect to start native Google OAuth in Autopilot."}
                  </p>
                </article>
                <article className="workspace-stat-card">
                  <span>Availability</span>
                  <strong>{availability}</strong>
                  <p>
                    {workspace.grantedScopes.length > 0
                      ? `${workspace.grantedScopes.length} Google scopes granted for this connection.`
                      : "No Google scopes are available until the connector is connected."}
                  </p>
                </article>
                <article className="workspace-stat-card">
                  <span>Background Automations</span>
                  <strong>{activeSubscriptions.length}</strong>
                  <p>
                    {attentionSubscriptions.length > 0
                      ? `${attentionSubscriptions.length} subscriptions need attention.`
                      : "No automation incidents are currently visible."}
                  </p>
                </article>
                <article className="workspace-stat-card">
                  <span>Capability Bundles</span>
                  <strong>{capabilityGroups.length}</strong>
                  <p>{capabilityGroups.map((group) => group.title).join(", ")}</p>
                </article>
              </div>

              <div className="workspace-overview-grid">
                <article className="workspace-stat-card workspace-summary-card">
                  <span>Local settings</span>
                  <strong>{workspace.tokenStorage.source === "local" ? "Stored locally" : "Managed by runtime"}</strong>
                  <p>
                    Client configuration and tokens stay on this machine. Open local settings to
                    review storage paths, grants, reconnect flow, and destructive reset actions.
                  </p>
                  <div className="workspace-card-actions">
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => setSettingsModalOpen(true)}
                    >
                      Open local settings
                    </button>
                  </div>
                </article>
                {policySummary ? (
                  <article className="workspace-stat-card workspace-summary-card">
                    <span>Policy</span>
                    <strong>{policySummary.headline}</strong>
                    <p>{policySummary.detail}</p>
                    <div className="workspace-card-actions">
                      <button
                        type="button"
                        className="btn-secondary"
                        onClick={() => onOpenPolicyCenter?.(connector)}
                      >
                        Open Shield policy
                      </button>
                    </div>
                  </article>
                ) : null}
              </div>

              <div className="workspace-state-grid">
                {capabilityGroups.map((group) => {
                  const serviceState = workspace.serviceStates[group.service];
                  const readinessLabel = serviceStateLabel(serviceState?.status);
                  const readinessTone = serviceStateTone(serviceState?.status);

                  return (
                    <article key={group.service} className="workspace-state-card">
                      <div className="workspace-state-head">
                        <strong>{group.title}</strong>
                        <span className={`workspace-health-pill tone-${readinessTone}`}>
                          {readinessLabel}
                        </span>
                      </div>
                      <p>{serviceState?.summary ?? group.summary}</p>
                      {serviceState?.missingScopes?.length ? (
                        <span className="workspace-state-detail">
                          Missing scopes: {serviceState.missingScopes.join(", ")}
                        </span>
                      ) : (
                        <span className="workspace-state-detail">{group.detail}</span>
                      )}
                    </article>
                  );
                })}
              </div>

              <div className="workspace-section-header">
                <div>
                  <h4>Recommended next moves</h4>
                  <p>Guide users toward a first win, then into durable background automation.</p>
                </div>
              </div>
              <div className="workspace-quickstart-grid">
                {OVERVIEW_QUICKSTARTS.map((item) => {
                  const enabled = item.actionId ? actionsById.has(item.actionId) : true;
                  return (
                    <article key={item.id} className="workspace-quickstart-card">
                      <strong>{item.title}</strong>
                      <p>{item.summary}</p>
                      {item.actionId && item.tab ? (
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => openAction(item.tab!, item.actionId!, item.presetInput)}
                          disabled={!enabled || (item.requiresRuntime && !workspace.runtimeReady)}
                        >
                          Open flow
                        </button>
                      ) : null}
                    </article>
                  );
                })}
              </div>

              <div className="workspace-section-header">
                <div>
                  <h4>Scope bundles</h4>
                  <p>Expose capabilities as service bundles first, not raw OAuth jargon.</p>
                </div>
              </div>
              <div className="workspace-bundle-strip">
                {capabilityGroups.map((group) => (
                  <span key={group.service} className="workspace-bundle-chip">
                    {group.title}
                  </span>
                ))}
              </div>
              {workspace.bootstrapWarnings.length > 0 ? (
                <div className="workspace-warning-panel">
                  <strong>Discovery notes</strong>
                  <div className="workspace-warning-list">
                    {workspace.bootstrapWarnings.map((warning) => (
                      <span key={`${warning.service}-${warning.message}`}>
                        {warning.service}: {warning.message}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}

          {activeTab === "capabilities" ? (
        <div className="workspace-tab-panel">
          <div className="workspace-section-header">
            <div>
              <h4>Capability catalog</h4>
              <p>Lead with common jobs to be done, then open the full action composer only when needed.</p>
            </div>
          </div>
          <div className="workspace-capability-grid">
            {capabilityGroups.map((group) => (
              <article key={group.service} className="workspace-service-card">
                {(() => {
                  const serviceState = workspace.serviceStates[group.service];
                  return (
                    <>
                <div className="workspace-service-card-head">
                  <div>
                    <h4>{group.title}</h4>
                    <p>{serviceState?.summary ?? group.summary}</p>
                  </div>
                  <div className="workspace-service-card-meta">
                    <span className={`workspace-health-pill tone-${serviceStateTone(serviceState?.status)}`}>
                      {serviceStateLabel(serviceState?.status)}
                    </span>
                    <span className="workspace-service-count">{group.actions.length} tools</span>
                  </div>
                </div>
                {serviceState?.missingScopes?.length ? (
                  <span className="workspace-state-detail">
                    Missing scopes: {serviceState.missingScopes.join(", ")}
                  </span>
                ) : null}
                <div className="workspace-kind-list">
                  {group.kinds.map((kind) => (
                    <span key={`${group.service}-${kind}`} className="workspace-kind-chip">
                      {kind}
                    </span>
                  ))}
                </div>
                <div className="workspace-featured-actions">
                  {group.featuredActions.map((action) => (
                    <button
                      key={action.id}
                      type="button"
                      className={`workspace-featured-action ${
                        workspace.selectedActionId === action.id ? "active" : ""
                      }`}
                      onClick={() => openAction("capabilities", action.id)}
                    >
                      {action.label}
                    </button>
                  ))}
                </div>
                {group.supportingActions.length > 0 ? (
                  <div className="workspace-supporting-actions">
                    {group.supportingActions.map((action) => (
                      <button
                        key={action.id}
                        type="button"
                        className={`workspace-tool-chip ${
                          workspace.selectedActionId === action.id ? "active" : ""
                        }`}
                        onClick={() => openAction("capabilities", action.id)}
                      >
                        {action.label}
                      </button>
                    ))}
                  </div>
                ) : null}
                    </>
                  );
                })()}
              </article>
            ))}
          </div>

          <WorkspaceActionComposer
            action={workspace.selectedAction}
            workspace={workspace}
            eyebrow="Capability workspace"
          />
        </div>
          ) : null}

          {activeTab === "automations" ? (
        <div className="workspace-tab-panel">
          <div className="workspace-section-header">
            <div>
              <h4>Automation center</h4>
              <p>Manage durable Gmail watches and Workspace event ingestion as long-lived product state.</p>
            </div>
            <button
              type="button"
              className="btn-secondary"
              onClick={workspace.refreshSubscriptions}
              disabled={workspace.busy || !workspace.subscriptionRuntimeReady}
            >
              Refresh automations
            </button>
          </div>

          <div className="workspace-overview-grid">
            <article className="workspace-stat-card">
              <span>Running</span>
              <strong>{activeSubscriptions.length}</strong>
              <p>Watches and event streams currently kept alive by the desktop runtime.</p>
            </article>
            <article className="workspace-stat-card">
              <span>Attention</span>
              <strong>{attentionSubscriptions.length}</strong>
              <p>Subscriptions needing reauth or repair before they can keep consuming.</p>
            </article>
            <article className="workspace-stat-card">
              <span>Total subscriptions</span>
              <strong>{workspace.subscriptions.length}</strong>
              <p>Pause, renew, and inspect them directly from this surface.</p>
            </article>
            <article className="workspace-stat-card">
              <span>Automation entry points</span>
              <strong>{automationGroups.length}</strong>
              <p>Admin-grade actions are packaged separately from the day-to-day capability grid.</p>
            </article>
          </div>

          <div className="workspace-automation-grid">
            {AUTOMATION_RECIPES.map((recipe) => (
              <article key={recipe.id} className="workspace-automation-card">
                <strong>{recipe.title}</strong>
                <p>{recipe.summary}</p>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => openAction("automations", recipe.actionId, recipe.presetInput)}
                  disabled={!actionsById.has(recipe.actionId)}
                >
                  Configure recipe
                </button>
              </article>
            ))}
          </div>

          {workspace.subscriptions.length > 0 ? (
            <div className="workspace-subscription-list">
              {workspace.subscriptions.map((subscription) => (
                <WorkspaceSubscriptionCard
                  key={subscription.subscriptionId}
                  subscription={subscription}
                  workspace={workspace}
                />
              ))}
            </div>
          ) : (
            <div className="workspace-empty-state">
              <strong>No automations running yet</strong>
              <p>Configure Gmail Watch Emails or Workspace Events Subscribe to create the first durable job.</p>
            </div>
          )}

          <WorkspaceActionComposer
            action={workspace.selectedAction}
            workspace={workspace}
            eyebrow="Automation setup"
          />
        </div>
          ) : null}

          {activeTab === "advanced" ? (
            <div className="workspace-tab-panel">
              <div className="workspace-section-header">
                <div>
                  <h4>Advanced tool catalog</h4>
                  <p>
                    Keep the full connector catalog available for power users, debugging, and edge
                    cases.
                  </p>
                </div>
              </div>
              <div className="workspace-service-panel">
                {advancedGroups.map((group) => (
                  <section key={group.service} className="workspace-service-group">
                    <div className="workspace-service-head">
                      <div>
                        <h4>{group.title}</h4>
                        <p>{group.detail}</p>
                      </div>
                      <div className="workspace-service-tools">
                        {group.actions.map((action) => (
                          <button
                            key={action.id}
                            type="button"
                            className={`workspace-tool-chip ${
                              workspace.selectedActionId === action.id ? "active" : ""
                            }`}
                            onClick={() => openAction("advanced", action.id)}
                          >
                            {action.label}
                          </button>
                        ))}
                      </div>
                    </div>
                  </section>
                ))}
              </div>

              <WorkspaceActionComposer
                action={workspace.selectedAction}
                workspace={workspace}
                eyebrow="Advanced execution"
              />
              {connector.notes ? <p className="workspace-inline-note">{connector.notes}</p> : null}
              {workspace.formattedResult ? (
                <pre className="connector-test-result workspace-result-panel">
                  {workspace.formattedResult}
                </pre>
              ) : null}
            </div>
          ) : null}
        </>
      )}

      <WorkspaceModal
        open={settingsModalOpen}
        title="Google connector settings"
        description="Connector-local operational settings live here. Governance and approval posture live in Shield."
        onClose={() => setSettingsModalOpen(false)}
      >
        <div className="workspace-settings-grid">
          <article className="workspace-settings-card">
            <strong>Trust model</strong>
            <p>
              Google access is owned by the local user. Client configuration and refresh tokens stay
              on disk unless you explicitly remove them.
            </p>
            <div className="workspace-storage-list">
              <span>
                Connected account: <code>{workspace.connectedAccountEmail ?? "Not connected"}</code>
              </span>
              <span>
                OAuth client source:{" "}
                <code>
                  {workspace.oauthClient.source}
                  {workspace.oauthClient.clientIdPreview
                    ? ` ${workspace.oauthClient.clientIdPreview}`
                    : ""}
                </code>
              </span>
              <span>
                Token source: <code>{workspace.tokenStorage.source}</code>
              </span>
            </div>
          </article>

          <article className="workspace-settings-card">
            <strong>Local storage</strong>
            <p>
              These paths are local to this machine. They are not shared with a hosted platform
              service.
            </p>
            <div className="workspace-storage-list">
              <span>
                Client config path: <code>{clientStoragePath ?? "Unavailable"}</code>
              </span>
              <span>
                Token storage path: <code>{tokenStoragePath ?? "Unavailable"}</code>
              </span>
            </div>
          </article>

          <article className="workspace-settings-card">
            <strong>Account maintenance</strong>
            <p>
              Use reconnect to refresh scopes or swap accounts. Review grants in Google when you want
              to inspect or revoke permissions directly.
            </p>
            <div className="workspace-auth-stage-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={() => void workspace.beginAuth(reconnectScopes)}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                {workspace.busy ? "Working..." : "Reconnect"}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.checkConnection}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                Refresh status
              </button>
              <a
                className="btn-secondary"
                href="https://myaccount.google.com/permissions"
                target="_blank"
                rel="noreferrer"
              >
                Review Google grants
              </a>
            </div>
          </article>

          <article className="workspace-settings-card workspace-settings-card-danger">
            <strong>Danger zone</strong>
            <p>
              Use these only when rotating credentials, intentionally disconnecting, or fully
              resetting the local Google setup.
            </p>
            <div className="workspace-auth-stage-actions">
              <button
                type="button"
                className="btn-secondary"
                onClick={workspace.disconnect}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                {workspace.tokenStorage.source === "local" ? "Wipe local tokens" : "Disconnect"}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  setOauthClientIdInput("");
                  setOauthClientSecretInput("");
                  void workspace.clearOauthClient();
                }}
                disabled={
                  workspace.busy ||
                  !workspace.runtimeReady ||
                  workspace.oauthClient.source !== "local"
                }
              >
                Remove local client
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => void resetGoogleSetup()}
                disabled={workspace.busy || !workspace.runtimeReady}
              >
                Reset Google setup
              </button>
            </div>
          </article>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={scopeModalOpen}
        title="Choose Google capability bundles"
        description="Select the Google services this local assistant should request before browser consent."
        onClose={() => setScopeModalOpen(false)}
      >
        <div className="workspace-scope-grid">
          {GOOGLE_SCOPE_BUNDLES.map((bundle) => {
            const selected = selectedBundleIds.includes(bundle.id);
            return (
              <label key={bundle.id} className={`workspace-scope-card ${selected ? "selected" : ""}`}>
                <div className="workspace-scope-card-head">
                  <input
                    type="checkbox"
                    checked={selected}
                    onChange={() => toggleBundle(bundle.id)}
                  />
                  <div>
                    <strong>{bundle.title}</strong>
                    <p>{bundle.summary}</p>
                  </div>
                </div>
                <span className="workspace-state-detail">{bundle.detail}</span>
                <div className="workspace-bundle-strip">
                  {bundle.scopes.map((scope) => (
                    <span key={`${bundle.id}-${scope}`} className="workspace-bundle-chip">
                      {scope}
                    </span>
                  ))}
                </div>
              </label>
            );
          })}
        </div>
        <div className="workspace-auth-stage-actions">
          <button
            type="button"
            className="btn-primary"
            onClick={() => {
              setScopeModalOpen(false);
              void workspace.beginAuth(requestedScopes);
            }}
            disabled={workspace.busy || !canBeginAuth}
          >
            {workspace.busy ? "Starting..." : "Continue to Google consent"}
          </button>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={consentModalOpen}
        title="Google consent details"
        description="Use this when you need to inspect the selected bundles, restart sign-in, or recover from the wrong cached Google account."
        onClose={() => setConsentModalOpen(false)}
      >
        <div className="workspace-onboarding-summary">
          <strong>Selected bundles</strong>
          <div className="workspace-bundle-strip">
            {selectedBundles.map((bundle) => (
              <span key={bundle.id} className="workspace-bundle-chip">
                {bundle.title}
              </span>
            ))}
          </div>
        </div>
        {workspace.authUrl ? (
          <a className="workspace-auth-link" href={workspace.authUrl} target="_blank" rel="noreferrer">
            {workspace.authUrl}
          </a>
        ) : null}
        <div className="workspace-auth-stage-actions">
          <button
            type="button"
            className="btn-primary"
            onClick={openAuthLink}
            disabled={!workspace.authUrl}
          >
            Open sign-in page
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => void retryConsent()}
            disabled={workspace.busy || !workspace.runtimeReady || requestedScopes.length === 0}
          >
            Retry sign-in
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => void reopenScopeSelection()}
            disabled={workspace.busy || !workspace.runtimeReady}
          >
            Change bundles
          </button>
        </div>
      </WorkspaceModal>

      <WorkspaceModal
        open={setupHelpModalOpen}
        title="Google OAuth troubleshooting"
        description="Use this when Google shows an error page instead of returning to Autopilot."
        onClose={() => setSetupHelpModalOpen(false)}
      >
        <div className="workspace-warning-panel">
          <strong>What to do next</strong>
          <div className="workspace-warning-list">
            <span>Fix the Google Cloud Console setting that caused the browser error.</span>
            <span>
              Keep the saved local client unless you are replacing credentials entirely.
            </span>
            <span>
              Return here and use Retry sign-in. That restarts OAuth without forcing you to re-enter
              your client configuration.
            </span>
          </div>
        </div>
        <div className="workspace-troubleshooting-steps">
          <article className="workspace-troubleshooting-card">
            <strong>Enable necessary APIs</strong>
            <p>
              In Google Cloud Console, open the project associated with{" "}
              <code>{oauthClientPreview}</code>, then go to <code>APIs &amp; Services</code>, then{" "}
              <code>Library</code>, and confirm the APIs below are enabled.
            </p>
            <div className="workspace-bundle-strip">
              {troubleshootingApis.length > 0 ? (
                troubleshootingApis.map((api) => (
                  <span key={api} className="workspace-bundle-chip">
                    {api}
                  </span>
                ))
              ) : (
                <span className="workspace-bundle-chip">Select capability bundles first</span>
              )}
            </div>
          </article>
          <article className="workspace-troubleshooting-card">
            <strong>Verify OAuth consent screen</strong>
            <p>
              In <code>Google Auth Platform</code>, then <code>Audience</code>, switch the app to{" "}
              <code>External</code> if this local assistant should work with personal Gmail or any
              account outside a Workspace org. <code>Internal</code> is only appropriate if every
              user belongs to that Workspace organization and you intentionally want org-only access.
              If the app stays in testing mode, add the exact Google account as a test user before
              retrying.
            </p>
            <p>
              In <code>Google Auth Platform</code>, then <code>Data Access</code>, review the
              exact scopes that will be requested for the bundles selected in Autopilot.
            </p>
            <p>
              When switching to <code>External</code>, Google may require extra app metadata such as
              privacy policy, terms of service, and authorized domains, especially if you later move
              beyond personal testing or request sensitive scopes.
            </p>
            <div className="workspace-bundle-strip">
              {troubleshootingScopes.map((scope) => (
                <span key={scope} className="workspace-bundle-chip">
                  {scope}
                </span>
              ))}
            </div>
          </article>
        </div>
        <div className="workspace-troubleshooting-grid">
          {GOOGLE_OAUTH_TROUBLESHOOTING.map((item) => (
            <article key={item.id} className="workspace-troubleshooting-card">
              <strong>{item.title}</strong>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>
        <div className="workspace-auth-stage-actions">
          <a
            className="btn-secondary"
            href="https://console.cloud.google.com/auth/overview"
            target="_blank"
            rel="noreferrer"
          >
            Open Google Auth Platform
          </a>
          <a
            className="btn-secondary"
            href="https://console.cloud.google.com/apis/credentials"
            target="_blank"
            rel="noreferrer"
          >
            Open OAuth credentials
          </a>
          <button
            type="button"
            className="btn-primary"
            onClick={() => void retryConsent()}
            disabled={workspace.busy || !workspace.runtimeReady || requestedScopes.length === 0}
          >
            Retry sign-in
          </button>
        </div>
      </WorkspaceModal>
    </div>
  );
}
