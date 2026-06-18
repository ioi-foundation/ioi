import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF,
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  getHarnessSelectionRef,
} from "./harnessAdapterModel.ts";

export type HypervisorAgentsProjectionSource =
  | "daemon-agents-projection"
  | "fixture"
  | "unverified";

export type HypervisorAgentStatus =
  | "running"
  | "idle"
  | "blocked"
  | "paused"
  | "archived";

export type HypervisorAgentTruthBoundary =
  | "daemon_owned"
  | "proposal_source_only";

export interface HypervisorAgentRuntimeBinding {
  harness_selection_ref: string;
  harness_label: string;
  truth_boundary: HypervisorAgentTruthBoundary;
  model_route_ref: string;
  adapter_target_ref: string;
  privacy_posture_ref: string;
}

export interface HypervisorAgentSkillBinding {
  skill_ref: string;
  label: string;
  source: "workspace" | "aiagent_package" | "private_package";
  version_ref: string;
  promotion_state: "draft" | "active" | "candidate";
  receipt_ref: string;
}

export interface HypervisorAgentMemoryBinding {
  memory_ref: string;
  label: string;
  scope: "workspace_bound" | "agent_bound" | "org_bound";
  owner: "agent_wiki_ioi_memory" | "agentgres_projection" | "workspace_state";
  persistence: "persistent" | "ephemeral";
  receipt_ref: string;
}

export interface HypervisorAgentCapabilityLease {
  lease_ref: string;
  capability_ref: string;
  status: "active" | "requires_step_up" | "expiring" | "revoked";
  expires_at: string;
  wallet_authority_scope_refs: string[];
  receipt_ref: string;
}

export interface HypervisorAgentRecord {
  agent_ref: string;
  label: string;
  objective: string;
  status: HypervisorAgentStatus;
  workspace_ref: string;
  session_ref: string;
  runtime: HypervisorAgentRuntimeBinding;
  skill_bindings: HypervisorAgentSkillBinding[];
  memory_bindings: HypervisorAgentMemoryBinding[];
  capability_leases: HypervisorAgentCapabilityLease[];
  agentgres_operation_refs: string[];
  state_root_ref: string;
  latest_receipt_refs: string[];
  updated_at: string;
}

export interface HypervisorAgentsProjection {
  schema_version: "ioi.hypervisor.agents_projection.v1";
  projection_id: string;
  source: HypervisorAgentsProjectionSource;
  selected_project_ref: string;
  records: HypervisorAgentRecord[];
  boundary_invariant: string;
  memory_invariant: string;
  capability_invariant: string;
  runtimeTruthSource: "daemon-runtime";
}

export const HYPERVISOR_AGENTS_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_AGENTS_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_AGENTS_PROJECTION_PATH = "/v1/hypervisor/agents";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeAgentsProjectionOptions {
  source?: HypervisorAgentsProjectionSource;
  selectedProjectRef?: string;
}

interface LoadAgentsProjectionOptions extends NormalizeAgentsProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
}

const defaultHarnessRef = getHarnessSelectionRef(DEFAULT_HARNESS_PROFILE_OPTION);

export const HYPERVISOR_AGENTS_PROJECTION_FIXTURE: HypervisorAgentsProjection =
  {
    schema_version: "ioi.hypervisor.agents_projection.v1",
    projection_id: "agents:hypervisor/default",
    source: "fixture",
    selected_project_ref: "project:hypervisor",
    boundary_invariant:
      "Agents are configured workers for governed sessions. Connector UIs, external harnesses, and model providers may propose work; Hypervisor admits sessions, gates, receipts, and replay.",
    memory_invariant:
      "Skills and memory may persist with the workspace or agent, but Agent Wiki / ioi-memory owns semantic memory while Agentgres records admitted operational refs.",
    capability_invariant:
      "Agents exercise wallet.network capability leases, not durable plaintext credentials or unrestricted authority.",
    records: [
      {
        agent_ref: "agent:quant-research-private",
        label: "Quant research agent",
        objective:
          "Backtest market hypotheses against public tensors while keeping AlphaSeal private-head scoring behind cTEE policy.",
        status: "running",
        workspace_ref: "workspace://ioi/quant-alpha",
        session_ref: "session:agent/quant-research-private",
        runtime: {
          harness_selection_ref: defaultHarnessRef,
          harness_label: DEFAULT_HARNESS_PROFILE_OPTION.label,
          truth_boundary: "daemon_owned",
          model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
          adapter_target_ref: "adapter-target:vscode-embedded",
          privacy_posture_ref: HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF,
        },
        skill_bindings: [
          {
            skill_ref: "skill:backtest.kernel.public",
            label: "Public backtest kernel",
            source: "workspace",
            version_ref: "skill-version:backtest.kernel.public/v3",
            promotion_state: "active",
            receipt_ref: "receipt://agent/quant/skill/backtest-kernel",
          },
          {
            skill_ref: "skill:alpha.seal.private-head",
            label: "AlphaSeal private head",
            source: "private_package",
            version_ref: "skill-version:alpha.seal.private-head/v1",
            promotion_state: "candidate",
            receipt_ref: "receipt://agent/quant/skill/alpha-seal",
          },
        ],
        memory_bindings: [
          {
            memory_ref: "memory://workspace/quant-alpha/research-notes",
            label: "Workspace research memory",
            scope: "workspace_bound",
            owner: "agent_wiki_ioi_memory",
            persistence: "persistent",
            receipt_ref: "receipt://memory/quant-alpha/research-notes",
          },
        ],
        capability_leases: [
          {
            lease_ref: "lease://wallet/agent/quant/read-market-data",
            capability_ref: "scope:market_data.read",
            status: "active",
            expires_at: "2026-06-18T00:00:00Z",
            wallet_authority_scope_refs: ["scope:market_data.read"],
            receipt_ref: "receipt://wallet/lease/quant/read-market-data",
          },
          {
            lease_ref: "lease://wallet/agent/quant/broker-paper-order",
            capability_ref: "scope:broker.paper_order",
            status: "requires_step_up",
            expires_at: "2026-06-17T20:00:00Z",
            wallet_authority_scope_refs: ["scope:broker.paper_order"],
            receipt_ref: "receipt://wallet/lease/quant/broker-paper-order",
          },
        ],
        agentgres_operation_refs: [
          "agentgres://operation/agent/quant-research-private/latest",
        ],
        state_root_ref: "agentgres://state-root/agent/quant-research-private",
        latest_receipt_refs: [
          "receipt://agent/quant/latest-loop",
          "receipt://privacy/ctee/quant/private-head",
        ],
        updated_at: "2026-06-17T12:00:00Z",
      },
      {
        agent_ref: "agent:discord-community-steward",
        label: "Community steward",
        objective:
          "Draft moderation responses and escalation summaries without posting until a wallet-scoped capability lease is granted.",
        status: "idle",
        workspace_ref: "workspace://ioi/community",
        session_ref: "session:agent/discord-community-steward",
        runtime: {
          harness_selection_ref: "agent-harness-adapter:generic_cli",
          harness_label: "Generic CLI Harness",
          truth_boundary: "proposal_source_only",
          model_route_ref: "model-route:adapter-native",
          adapter_target_ref: "adapter-target:terminal-workspace",
          privacy_posture_ref: "privacy:redacted-projection",
        },
        skill_bindings: [
          {
            skill_ref: "skill:moderation.reply-draft",
            label: "Moderation reply draft",
            source: "aiagent_package",
            version_ref: "skill-version:moderation.reply-draft/v2",
            promotion_state: "active",
            receipt_ref: "receipt://agent/community/skill/reply-draft",
          },
        ],
        memory_bindings: [
          {
            memory_ref: "memory://agent/community/steward-context",
            label: "Community policy context",
            scope: "agent_bound",
            owner: "agent_wiki_ioi_memory",
            persistence: "persistent",
            receipt_ref: "receipt://memory/community/steward-context",
          },
        ],
        capability_leases: [
          {
            lease_ref: "lease://wallet/agent/community/discord-draft",
            capability_ref: "scope:discord.message.draft",
            status: "active",
            expires_at: "2026-06-17T23:00:00Z",
            wallet_authority_scope_refs: ["scope:discord.message.draft"],
            receipt_ref: "receipt://wallet/lease/community/discord-draft",
          },
        ],
        agentgres_operation_refs: [
          "agentgres://operation/agent/discord-community-steward/latest",
        ],
        state_root_ref: "agentgres://state-root/agent/discord-community-steward",
        latest_receipt_refs: ["receipt://agent/community/latest-draft"],
        updated_at: "2026-06-17T11:30:00Z",
      },
      {
        agent_ref: "agent:workbench-repair",
        label: "Workbench repair agent",
        objective:
          "Investigate failing app checks, propose patches, and route accepted edits through governed workspace receipts.",
        status: "blocked",
        workspace_ref: "workspace://ioi/hypervisor",
        session_ref: "session:agent/workbench-repair",
        runtime: {
          harness_selection_ref: "agent-harness-adapter:codex_cli",
          harness_label: "Codex CLI",
          truth_boundary: "proposal_source_only",
          model_route_ref: "model-route:provider/codex",
          adapter_target_ref: "adapter-target:cursor",
          privacy_posture_ref: "privacy:redacted-projection",
        },
        skill_bindings: [
          {
            skill_ref: "skill:react.ui-repair",
            label: "React UI repair",
            source: "workspace",
            version_ref: "skill-version:react.ui-repair/v4",
            promotion_state: "active",
            receipt_ref: "receipt://agent/workbench/skill/react-ui-repair",
          },
          {
            skill_ref: "skill:playwright.visual-check",
            label: "Playwright visual check",
            source: "workspace",
            version_ref: "skill-version:playwright.visual-check/v2",
            promotion_state: "active",
            receipt_ref: "receipt://agent/workbench/skill/playwright-check",
          },
        ],
        memory_bindings: [
          {
            memory_ref: "memory://workspace/hypervisor/ux-parity",
            label: "UX parity notes",
            scope: "workspace_bound",
            owner: "workspace_state",
            persistence: "persistent",
            receipt_ref: "receipt://memory/hypervisor/ux-parity",
          },
        ],
        capability_leases: [
          {
            lease_ref: "lease://wallet/agent/workbench/workspace-patch",
            capability_ref: "scope:workspace.patch",
            status: "expiring",
            expires_at: "2026-06-17T18:00:00Z",
            wallet_authority_scope_refs: [
              "scope:workspace.read",
              "scope:workspace.patch",
            ],
            receipt_ref: "receipt://wallet/lease/workbench/workspace-patch",
          },
        ],
        agentgres_operation_refs: [
          "agentgres://operation/agent/workbench-repair/latest",
        ],
        state_root_ref: "agentgres://state-root/agent/workbench-repair",
        latest_receipt_refs: [
          "receipt://agent/workbench/blocker",
          "receipt://workspace/patch/proposal/latest",
        ],
        updated_at: "2026-06-17T10:45:00Z",
      },
    ],
    runtimeTruthSource: "daemon-runtime",
  };

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const values = value
    .filter((item): item is string => typeof item === "string" && !!item.trim())
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
}

function statusValue(value: unknown): HypervisorAgentStatus {
  const normalized = stringValue(value, "idle").toLowerCase();
  if (normalized === "running" || normalized === "active") return "running";
  if (normalized === "blocked" || normalized === "failed") return "blocked";
  if (normalized === "paused" || normalized === "waiting_for_approval") {
    return "paused";
  }
  if (normalized === "archived") return "archived";
  return "idle";
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function firstString(record: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return null;
}

function normalizeRuntimeBinding(
  value: unknown,
  record: Record<string, unknown>,
): HypervisorAgentRuntimeBinding {
  const runtime = objectRecord(value);
  const harnessRef = stringValue(
    runtime.harness_selection_ref,
    stringValue(record.harness_selection_ref, defaultHarnessRef),
  );
  const truthBoundary =
    harnessRef === defaultHarnessRef ? "daemon_owned" : "proposal_source_only";
  return {
    harness_selection_ref: harnessRef,
    harness_label: stringValue(
      runtime.harness_label,
      stringValue(record.runtime_profile, DEFAULT_HARNESS_PROFILE_OPTION.label),
    ),
    truth_boundary: truthBoundary,
    model_route_ref: stringValue(
      runtime.model_route_ref,
      firstString(record, [
        "model_route_ref",
        "model_route_id",
        "modelRouteId",
        "model_route",
        "model_id",
        "modelId",
      ]) ?? HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    ),
    adapter_target_ref: stringValue(
      runtime.adapter_target_ref,
      stringValue(record.adapter_target_ref, "adapter-target:vscode-embedded"),
    ),
    privacy_posture_ref: stringValue(
      runtime.privacy_posture_ref,
      stringValue(
        record.privacy_posture_ref,
        HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF,
      ),
    ),
  };
}

function normalizeSkillBindings(
  value: unknown,
  agentRef: string,
): HypervisorAgentSkillBinding[] {
  const skills = arrayOf(value).map((skill, index) => ({
    skill_ref: stringValue(skill.skill_ref, `${agentRef}/skill/${index + 1}`),
    label: stringValue(skill.label, `Agent skill ${index + 1}`),
    source: stringValue(skill.source, "workspace") as HypervisorAgentSkillBinding["source"],
    version_ref: stringValue(skill.version_ref, `${agentRef}/skill-version/${index + 1}`),
    promotion_state: stringValue(skill.promotion_state, "active") as HypervisorAgentSkillBinding["promotion_state"],
    receipt_ref: stringValue(skill.receipt_ref, `receipt://${agentRef}/skill/${index + 1}`),
  }));
  return skills.length > 0
    ? skills
    : [
        {
          skill_ref: `${agentRef}/skill/default`,
          label: "Default workspace skill",
          source: "workspace",
          version_ref: `${agentRef}/skill-version/default`,
          promotion_state: "active",
          receipt_ref: `receipt://${agentRef}/skill/default`,
        },
      ];
}

function normalizeMemoryBindings(
  value: unknown,
  agentRef: string,
  record: Record<string, unknown>,
): HypervisorAgentMemoryBinding[] {
  const memory = arrayOf(value).map((binding, index) => ({
    memory_ref: stringValue(binding.memory_ref, `${agentRef}/memory/${index + 1}`),
    label: stringValue(binding.label, `Agent memory ${index + 1}`),
    scope: stringValue(binding.scope, "workspace_bound") as HypervisorAgentMemoryBinding["scope"],
    owner: stringValue(
      binding.owner,
      "agent_wiki_ioi_memory",
    ) as HypervisorAgentMemoryBinding["owner"],
    persistence: stringValue(binding.persistence, "persistent") as HypervisorAgentMemoryBinding["persistence"],
    receipt_ref: stringValue(binding.receipt_ref, `receipt://${agentRef}/memory/${index + 1}`),
  }));
  if (memory.length > 0) {
    return memory;
  }
  const memoryCount = numberValue(record.memory_count, 0);
  return memoryCount > 0
    ? [
        {
          memory_ref: `${agentRef}/memory/daemon`,
          label: `${memoryCount} memory records`,
          scope: "agent_bound",
          owner: "agent_wiki_ioi_memory",
          persistence: "persistent",
          receipt_ref: `receipt://${agentRef}/memory/daemon`,
        },
      ]
    : [
        {
          memory_ref: `${agentRef}/memory/workspace`,
          label: "Workspace-bound memory",
          scope: "workspace_bound",
          owner: "agent_wiki_ioi_memory",
          persistence: "persistent",
          receipt_ref: `receipt://${agentRef}/memory/workspace`,
        },
      ];
}

function normalizeCapabilityLeases(
  value: unknown,
  agentRef: string,
): HypervisorAgentCapabilityLease[] {
  const leases = arrayOf(value).map((lease, index) => ({
    lease_ref: stringValue(lease.lease_ref, `lease://wallet/${agentRef}/${index + 1}`),
    capability_ref: stringValue(lease.capability_ref, "scope:workspace.read"),
    status: stringValue(lease.status, "active") as HypervisorAgentCapabilityLease["status"],
    expires_at: stringValue(lease.expires_at, "2026-06-18T00:00:00Z"),
    wallet_authority_scope_refs: stringList(
      lease.wallet_authority_scope_refs,
      [stringValue(lease.capability_ref, "scope:workspace.read")],
    ),
    receipt_ref: stringValue(lease.receipt_ref, `receipt://wallet/${agentRef}/${index + 1}`),
  }));
  return leases.length > 0
    ? leases
    : [
        {
          lease_ref: `lease://wallet/${agentRef}/workspace-read`,
          capability_ref: "scope:workspace.read",
          status: "active",
          expires_at: "2026-06-18T00:00:00Z",
          wallet_authority_scope_refs: ["scope:workspace.read"],
          receipt_ref: `receipt://wallet/${agentRef}/workspace-read`,
        },
      ];
}

function normalizeAgentRecord(
  value: unknown,
  index = 0,
): HypervisorAgentRecord {
  const record = objectRecord(value);
  const agentRef =
    firstString(record, ["agent_ref", "agent_id", "agentId", "id"]) ??
    `agent:daemon/${index + 1}`;
  const sessionRef =
    firstString(record, ["session_ref", "thread_id", "session_id"]) ??
    `${agentRef}/session`;
  const workspaceRef =
    firstString(record, ["workspace_ref", "workspace", "workspace_root"]) ??
    "workspace://unknown";
  const evidenceRefs = stringList(record.evidence_refs, []);
  const receiptRefs = stringList(record.latest_receipt_refs, evidenceRefs);
  return {
    agent_ref: agentRef,
    label: stringValue(
      record.label,
      firstString(record, ["title", "name"]) ?? agentRef.replace(/^agent:/, ""),
    ),
    objective: stringValue(
      record.objective,
      firstString(record, ["goal", "title"]) ??
        "Configured Hypervisor agent runtime.",
    ),
    status: statusValue(record.status),
    workspace_ref: workspaceRef,
    session_ref: sessionRef,
    runtime: normalizeRuntimeBinding(record.runtime, record),
    skill_bindings: normalizeSkillBindings(record.skill_bindings, agentRef),
    memory_bindings: normalizeMemoryBindings(
      record.memory_bindings,
      agentRef,
      record,
    ),
    capability_leases: normalizeCapabilityLeases(
      record.capability_leases,
      agentRef,
    ),
    agentgres_operation_refs: stringList(record.agentgres_operation_refs, [
      `agentgres://operation/${agentRef}/latest`,
    ]),
    state_root_ref: stringValue(
      record.state_root_ref,
      `agentgres://state-root/${agentRef}`,
    ),
    latest_receipt_refs:
      receiptRefs.length > 0 ? receiptRefs : [`receipt://${agentRef}/latest`],
    updated_at: stringValue(
      record.updated_at,
      firstString(record, ["updatedAt", "created_at", "createdAt"]) ??
        "2026-06-17T00:00:00Z",
    ),
  };
}

function rawAgentRecords(snapshot: unknown): Record<string, unknown>[] {
  if (Array.isArray(snapshot)) {
    return snapshot.map(objectRecord);
  }
  const value = objectRecord(snapshot);
  if (Array.isArray(value.records)) {
    return arrayOf(value.records);
  }
  if (Array.isArray(value.agents)) {
    return arrayOf(value.agents);
  }
  if (Array.isArray(value.projection)) {
    return arrayOf(value.projection);
  }
  return [];
}

export function normalizeHypervisorAgentsProjection(
  snapshot: unknown,
  options: NormalizeAgentsProjectionOptions = {},
): HypervisorAgentsProjection {
  const value = objectRecord(snapshot);
  const fallback = HYPERVISOR_AGENTS_PROJECTION_FIXTURE;
  const records = rawAgentRecords(snapshot).map(normalizeAgentRecord);
  return {
    schema_version: "ioi.hypervisor.agents_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-agents-projection",
    selected_project_ref: stringValue(
      value.selected_project_ref,
      options.selectedProjectRef ?? fallback.selected_project_ref,
    ),
    records: records.length > 0 ? records : fallback.records,
    boundary_invariant: stringValue(
      value.boundary_invariant,
      fallback.boundary_invariant,
    ),
    memory_invariant: stringValue(
      value.memory_invariant,
      fallback.memory_invariant,
    ),
    capability_invariant: stringValue(
      value.capability_invariant,
      fallback.capability_invariant,
    ),
    runtimeTruthSource: "daemon-runtime",
  };
}

export function readHypervisorAgentsDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_AGENTS_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(HYPERVISOR_AGENTS_DAEMON_ENDPOINT_STORAGE_KEY) ||
      HYPERVISOR_AGENTS_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_AGENTS_DEFAULT_DAEMON_ENDPOINT;
  }
}

export async function loadHypervisorAgentsProjection(
  options: LoadAgentsProjectionOptions = {},
): Promise<HypervisorAgentsProjection> {
  const endpoint = options.endpoint ?? readHypervisorAgentsDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor agents projection");
  }
  const query = new URLSearchParams();
  if (options.projectId) {
    query.set("project_id", options.projectId);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_AGENTS_PROJECTION_PATH}${suffix}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(`Agents projection request failed with ${response.status}`);
  }
  return normalizeHypervisorAgentsProjection(value, {
    source: options.source ?? "daemon-agents-projection",
    selectedProjectRef: options.projectId ?? undefined,
  });
}
