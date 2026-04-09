import type {
  AgentRuntime,
  ConnectorActionDefinition,
  ConnectorConfigureResult,
  ConnectorSummary,
} from "../../../runtime/agent-runtime";

export interface GoogleWorkspaceConnectorPanelProps {
  runtime: AgentRuntime;
  connector: ConnectorSummary;
  initialTab?: WorkspaceTabId;
  onConfigured?: (result: ConnectorConfigureResult) => void;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
  policySummary?: {
    headline: string;
    detail: string;
  };
}

export type WorkspaceTabId = "overview" | "capabilities" | "automations" | "advanced";
export type WorkspaceOnboardingStepId = "credentials" | "scopes" | "consent" | "connected";

export interface WorkspaceServiceMeta {
  title: string;
  summary: string;
  detail: string;
  featuredActionIds: string[];
}

export interface WorkspaceServiceGroup {
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

export interface AutomationRecipe {
  id: string;
  title: string;
  summary: string;
  actionId: string;
  presetInput?: Record<string, string>;
}

export interface GoogleScopeBundle {
  id: string;
  title: string;
  summary: string;
  detail: string;
  scopes: string[];
  apiLabels: string[];
}

export interface GoogleOauthTroubleshootingItem {
  id: string;
  title: string;
  detail: string;
}

export const TAB_DEFINITIONS: Array<{ id: WorkspaceTabId; label: string; blurb: string }> = [
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

export const SERVICE_ORDER = [
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

export const SERVICE_META: Record<string, WorkspaceServiceMeta> = {
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

export const OVERVIEW_QUICKSTARTS: Array<{
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

export const AUTOMATION_RECIPES: AutomationRecipe[] = [
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
    summary:
      "Convert new Gmail deliveries into Google Tasks using the first-party workflow.",
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

export const GOOGLE_SCOPE_BUNDLES: GoogleScopeBundle[] = [
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

export const ONBOARDING_STEPS: Array<{ id: WorkspaceOnboardingStepId; label: string }> = [
  { id: "credentials", label: "Credentials" },
  { id: "scopes", label: "Scope selection" },
  { id: "consent", label: "Consent" },
  { id: "connected", label: "Connected dashboard" },
];

export const GOOGLE_OAUTH_TROUBLESHOOTING: GoogleOauthTroubleshootingItem[] = [
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
