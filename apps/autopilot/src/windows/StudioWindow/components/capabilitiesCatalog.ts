import type { ConnectorSummary } from "@ioi/agent-ide";
import type { SkillCatalogEntry, SkillDetailView } from "../../../types";

export interface StarterSkillBundle {
  catalog: SkillCatalogEntry;
  detail: SkillDetailView;
  addedBy: string;
  invokedBy: string;
  defaultEnabled: boolean;
}

export interface ConnectionCatalogItem {
  id: string;
  name: string;
  provider: string;
  category: ConnectorSummary["category"];
  description: string;
  authMode: ConnectorSummary["authMode"];
  scopes: string[];
  popularityLabel: string;
  featured?: boolean;
}

function buildStarterSkillBundle(input: {
  hash: string;
  name: string;
  description: string;
  successRateBps: number;
  sampleSize: number;
  usedTools: string[];
  steps: Array<{
    tool: string;
    target: string;
    params: Record<string, unknown>;
  }>;
  markdown: string;
  addedBy: string;
  invokedBy: string;
  defaultEnabled?: boolean;
}): StarterSkillBundle {
  const detail: SkillDetailView = {
    skill_hash: input.hash,
    name: input.name,
    description: input.description,
    lifecycle_state: "Published",
    source_type: "StarterLibrary",
    archival_record_id: 0,
    success_rate_bps: input.successRateBps,
    sample_size: input.sampleSize,
    stale: false,
    used_tools: input.usedTools,
    steps: input.steps.map((step, index) => ({
      index,
      tool_name: step.tool,
      target: step.target,
      params_json: step.params,
    })),
    benchmark: {
      sample_size: input.sampleSize,
      success_rate_bps: input.successRateBps,
      intervention_rate_bps: 720,
      policy_incident_rate_bps: 35,
      avg_cost: 7,
      avg_latency_ms: 1830,
      passed: true,
      last_evaluated_height: 0,
    },
    markdown: input.markdown,
    neighborhood: {
      lens: "skills",
      title: input.name,
      summary: input.description,
      focus_id: `skill:${input.hash}`,
      nodes: [],
      edges: [],
    },
  };

  return {
    catalog: {
      skill_hash: input.hash,
      name: input.name,
      description: input.description,
      lifecycle_state: detail.lifecycle_state,
      source_type: detail.source_type,
      success_rate_bps: input.successRateBps,
      sample_size: input.sampleSize,
      archival_record_id: 0,
      source_session_id: null,
      source_evidence_hash: null,
      relative_path: null,
      stale: false,
      definition: {
        name: input.name,
        description: input.description,
        parameters: JSON.stringify(
          input.steps.reduce<Record<string, unknown>>((params, step) => {
            Object.assign(params, step.params);
            return params;
          }, {}),
          null,
          2,
        ),
      },
    },
    detail,
    addedBy: input.addedBy,
    invokedBy: input.invokedBy,
    defaultEnabled: input.defaultEnabled ?? true,
  };
}

export const STARTER_SKILL_BUNDLES: StarterSkillBundle[] = [
  buildStarterSkillBundle({
    hash: "1111111111111111111111111111111111111111111111111111111111111111",
    name: "inbox-triage",
    description:
      "Review high-signal inbox traffic, cluster follow-ups, and tee up reply work without leaving the trust boundary.",
    successRateBps: 9720,
    sampleSize: 48,
    usedTools: [
      "gmail.read_emails",
      "gmail.get_thread",
      "workflow.email_to_task",
      "tasks.create_task",
    ],
    steps: [
      {
        tool: "gmail.read_emails",
        target: "recent unread threads",
        params: { labelIds: ["INBOX", "UNREAD"], maxResults: 12 },
      },
      {
        tool: "gmail.get_thread",
        target: "high-priority thread detail",
        params: { includeBodies: false },
      },
      {
        tool: "workflow.email_to_task",
        target: "follow-up extraction",
        params: { tasklist: "@default" },
      },
      {
        tool: "tasks.create_task",
        target: "capture outstanding follow-ups",
        params: { dueMode: "next_available_slot" },
      },
    ],
    markdown: `# Inbox Triage

Use this skill when a worker needs to turn inbox noise into an actionable operating queue.

## What it does

- Pulls recent unread or high-risk threads
- Expands only the threads worth deeper review
- Extracts follow-ups, owners, and deadlines
- Pushes unresolved actions into Tasks or a downstream workflow

## Good triggers

- "What in my inbox needs attention?"
- "Turn new mail into a morning action list."
- "Summarize outstanding follow-ups from Gmail."

## Guardrails

- Keep reads scoped to recent or explicitly requested threads
- Prefer task capture over silent reply generation
- Escalate to a reply workflow when the user wants draft text`,
    addedBy: "Autopilot",
    invokedBy: "Worker or workflow",
  }),
  buildStarterSkillBundle({
    hash: "2222222222222222222222222222222222222222222222222222222222222222",
    name: "meeting-brief",
    description:
      "Assemble a compact pre-read for an upcoming meeting using calendar context, thread history, and relevant working docs.",
    successRateBps: 9530,
    sampleSize: 32,
    usedTools: [
      "calendar.list_events_for_date",
      "gmail.get_thread",
      "docs.read_document",
      "drive.share_file",
    ],
    steps: [
      {
        tool: "calendar.list_events_for_date",
        target: "upcoming meeting context",
        params: { timeWindowMinutes: 90 },
      },
      {
        tool: "gmail.get_thread",
        target: "latest coordination threads",
        params: { participantMatch: true },
      },
      {
        tool: "docs.read_document",
        target: "linked working doc",
        params: { mode: "summary" },
      },
      {
        tool: "drive.share_file",
        target: "brief handoff",
        params: { access: "internal_view" },
      },
    ],
    markdown: `# Meeting Brief

Create a tight pre-read before a calendar event starts.

## What it composes

- Event metadata and attendees
- Recent coordination threads
- Linked docs or planning notes
- Recommended talking points and open risks

## Best uses

- Executive or customer meetings
- Staff syncs that need context compression
- Last-minute prep when the worker has calendar and doc access

## Output shape

1. Purpose and meeting objective
2. Who is attending
3. Decisions already made
4. Questions to resolve
5. Materials worth opening during the meeting`,
    addedBy: "Autopilot",
    invokedBy: "Calendar agents",
  }),
  buildStarterSkillBundle({
    hash: "3333333333333333333333333333333333333333333333333333333333333333",
    name: "research-brief",
    description:
      "Turn open-ended research into a concise working brief with sources, synthesis, and next steps.",
    successRateBps: 9410,
    sampleSize: 41,
    usedTools: [
      "web.search",
      "browser.open",
      "browser.extract",
      "docs.create_document",
    ],
    steps: [
      {
        tool: "web.search",
        target: "source discovery",
        params: { diversityFloor: 4 },
      },
      {
        tool: "browser.open",
        target: "primary sources",
        params: { readMode: "focused" },
      },
      {
        tool: "browser.extract",
        target: "facts and supporting evidence",
        params: { citationMode: "required" },
      },
      {
        tool: "docs.create_document",
        target: "publishable brief",
        params: { template: "briefing" },
      },
    ],
    markdown: `# Research Brief

Use this skill when a worker needs to investigate a topic and leave behind a reusable brief.

## Behavior

- Starts with source discovery instead of drafting
- Prefers primary sources and recent material when time-sensitive
- Extracts evidence before synthesis
- Produces a brief with citations and a clear recommendation

## Typical prompts

- "Research this market and summarize the important shifts."
- "Build a decision memo from current sources."
- "Give me a sourced brief I can share with the team."`,
    addedBy: "Autopilot",
    invokedBy: "User or workflow",
  }),
  buildStarterSkillBundle({
    hash: "4444444444444444444444444444444444444444444444444444444444444444",
    name: "repo-audit",
    description:
      "Inspect a repository, surface implementation risks, and leave a high-signal engineering review trail.",
    successRateBps: 9350,
    sampleSize: 27,
    usedTools: ["shell.exec", "files.read", "git.diff", "docs.create_document"],
    steps: [
      {
        tool: "shell.exec",
        target: "project inventory",
        params: { command: "rg --files" },
      },
      {
        tool: "files.read",
        target: "relevant modules",
        params: { strategy: "focused" },
      },
      {
        tool: "git.diff",
        target: "behavioral changes",
        params: { mode: "review" },
      },
      {
        tool: "docs.create_document",
        target: "audit output",
        params: { template: "engineering_review" },
      },
    ],
    markdown: `# Repo Audit

This skill packages a practical engineering review loop.

## Core moves

- Map the codebase slice first
- Read the changed files with surrounding context
- Prioritize regressions, correctness risks, and missing tests
- Summarize findings in a way that a teammate can act on quickly

## Output contract

- Findings first
- Line or file references when possible
- Short risk summary
- Residual test gaps called out explicitly`,
    addedBy: "Autopilot",
    invokedBy: "Engineering workers",
  }),
  buildStarterSkillBundle({
    hash: "5555555555555555555555555555555555555555555555555555555555555555",
    name: "ops-digest",
    description:
      "Bundle inbox signals, calendar commitments, and workflow drift into a single daily operating digest.",
    successRateBps: 9650,
    sampleSize: 36,
    usedTools: [
      "gmail.read_emails",
      "calendar.list_events_for_date",
      "workflow.weekly_digest",
      "chat.send_message",
    ],
    steps: [
      {
        tool: "gmail.read_emails",
        target: "overnight changes",
        params: { labelIds: ["INBOX"], maxResults: 8 },
      },
      {
        tool: "calendar.list_events_for_date",
        target: "today's commitments",
        params: { includeDeclined: false },
      },
      {
        tool: "workflow.weekly_digest",
        target: "execution summary",
        params: { horizon: "day" },
      },
      {
        tool: "chat.send_message",
        target: "team digest delivery",
        params: { channel: "#ops" },
      },
    ],
    markdown: `# Ops Digest

Use this skill for recurring operational rollups.

## Included inputs

- Inbox changes worth attention
- Calendar pressure for the day
- Workflow or automation drift
- Suggested actions and owners

## Why it matters

This is the fastest way to turn scattered capability signals into one operating view a worker can act on immediately.`,
    addedBy: "Autopilot",
    invokedBy: "Scheduled workflows",
  }),
];

export const STARTER_SKILL_MAP = new Map(
  STARTER_SKILL_BUNDLES.map((bundle) => [bundle.catalog.skill_hash, bundle]),
);

export const CONNECTION_CATALOG: ConnectionCatalogItem[] = [
  {
    id: "google_workspace",
    name: "Google Workspace",
    provider: "google",
    category: "productivity",
    description:
      "Mail, calendar, docs, sheets, drive, chat, and event automation through one connection.",
    authMode: "wallet_capability",
    scopes: ["gmail", "calendar", "docs", "sheets", "drive", "chat"],
    popularityLabel: "#1 standard",
    featured: true,
  },
  {
    id: "wallet_mail",
    name: "Mail",
    provider: "wallet.network",
    category: "communication",
    description:
      "Attach mailbox accounts for delegated inbox reads, reply workflows, and spam cleanup.",
    authMode: "wallet_capability",
    scopes: ["mail.read.latest", "mail.reply", "mail.delete.spam"],
    popularityLabel: "#2 standard",
    featured: true,
  },
  {
    id: "github",
    name: "GitHub",
    provider: "github",
    category: "developer",
    description:
      "Read repos, inspect pull requests, and ground engineering workflows in live repository state.",
    authMode: "oauth",
    scopes: ["repo.read", "pull_requests.read", "issues.read"],
    popularityLabel: "#3 planned",
  },
  {
    id: "notion",
    name: "Notion",
    provider: "notion",
    category: "productivity",
    description:
      "Search team docs, update planning pages, and attach living knowledge to worker flows.",
    authMode: "oauth",
    scopes: ["pages.read", "pages.write", "search"],
    popularityLabel: "#4 planned",
  },
  {
    id: "slack",
    name: "Slack",
    provider: "slack",
    category: "communication",
    description:
      "Send channel updates, watch for escalations, and feed digest output back into team conversation.",
    authMode: "oauth",
    scopes: ["chat.write", "channels.read", "messages.read"],
    popularityLabel: "#5 planned",
  },
  {
    id: "linear",
    name: "Linear",
    provider: "linear",
    category: "developer",
    description:
      "Read issue queues, write triage updates, and connect product work to engineering execution.",
    authMode: "oauth",
    scopes: ["issues.read", "issues.write", "projects.read"],
    popularityLabel: "#6 planned",
  },
  {
    id: "figma",
    name: "Figma",
    provider: "figma",
    category: "productivity",
    description:
      "Pull design context into briefs and implementation reviews without flattening visuals into screenshots.",
    authMode: "oauth",
    scopes: ["files.read", "comments.read"],
    popularityLabel: "#7 planned",
  },
  {
    id: "mcp_remote",
    name: "Remote MCP",
    provider: "mcp",
    category: "developer",
    description:
      "Register a remote MCP surface and expose its tools through the capability layer.",
    authMode: "api_key",
    scopes: ["tools.invoke", "resources.read"],
    popularityLabel: "#8 custom",
  },
];
