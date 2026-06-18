import { PROJECT_SCOPES } from "./hypervisorShellModel.ts";
import { HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE } from "./hypervisorReceiptEvidenceModel.ts";

export type HypervisorAutomationRunStatus =
  | "draft"
  | "ready"
  | "scheduled"
  | "running"
  | "blocked"
  | "completed";

export interface HypervisorAutomationTemplate {
  template_ref: string;
  label: string;
  description: string;
  graph_ref: string;
  recipe_ref: string;
  required_scope_refs: string[];
  model_route_policy_ref: string;
  receipt_policy_ref: string;
  latest_receipt_refs: string[];
}

export interface HypervisorAutomationRunRecipe {
  run_recipe_ref: string;
  template_ref: string;
  label: string;
  schedule_ref: string;
  launch_action_ref: string;
  authority_scope_refs: string[];
  receipt_refs: string[];
}

export interface HypervisorAutomationGraph {
  graph_ref: string;
  label: string;
  node_count: number;
  edge_count: number;
  context_chamber_refs: string[];
  artifact_refs: string[];
  receipt_refs: string[];
}

export interface HypervisorAutomationRun {
  run_ref: string;
  template_ref: string;
  status: HypervisorAutomationRunStatus;
  action_proposal_ref: string;
  agentgres_operation_ref: string;
  state_root_ref: string;
  latest_receipt_ref: string;
}

export interface HypervisorAutomationCompositorProjection {
  schema_version: "ioi.hypervisor.automation_compositor_projection.v1";
  projection_id: string;
  source:
    | "daemon-automation-compositor-projection"
    | "fixture"
    | "unverified";
  selected_project_id: string;
  runtimeTruthSource: "daemon-runtime";
  compositor_boundary_invariant: string;
  workflow_template_refs: string[];
  run_recipe_refs: string[];
  graph_refs: string[];
  templates: HypervisorAutomationTemplate[];
  run_recipes: HypervisorAutomationRunRecipe[];
  graphs: HypervisorAutomationGraph[];
  runs: HypervisorAutomationRun[];
  latest_receipt_refs: string[];
  agentgres_operation_refs: string[];
  state_root_ref: string;
}

export const HYPERVISOR_AUTOMATION_COMPOSITOR_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_AUTOMATION_COMPOSITOR_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH =
  "/v1/hypervisor/automation-compositor";

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeAutomationCompositorProjectionOptions {
  source?: HypervisorAutomationCompositorProjection["source"];
}

interface LoadAutomationCompositorProjectionOptions
  extends NormalizeAutomationCompositorProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
}

const selectedProject =
  PROJECT_SCOPES.find((project) => project.id === "hypervisor-core") ??
  PROJECT_SCOPES[0]!;

const receiptRefs = HYPERVISOR_RECEIPT_EVIDENCE_PROJECTION_FIXTURE.records
  .slice(0, 4)
  .map((record) => record.receipt_ref);

export const HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE: HypervisorAutomationCompositorProjection =
  {
    schema_version: "ioi.hypervisor.automation_compositor_projection.v1",
    projection_id: "automation-compositor:hypervisor-core/default",
    source: "fixture",
    selected_project_id: selectedProject.id,
    runtimeTruthSource: "daemon-runtime",
    compositor_boundary_invariant:
      "Automations renders workflow templates, compositor graphs, run recipes, action proposals, Agentgres operation refs, state roots, and receipts. The Workflow Compositor edits and proposes; Hypervisor Core admits execution; Agentgres records operational truth.",
    workflow_template_refs: [
      "workflow-template:mission-to-workbench",
      "workflow-template:private-workspace-backtest",
      "workflow-template:provider-zero-to-idle",
    ],
    run_recipe_refs: [
      "run-recipe:mission-to-workbench/manual",
      "run-recipe:private-workspace-backtest/nightly",
      "run-recipe:provider-zero-to-idle/on-idle",
    ],
    graph_refs: [
      "workflow://graph/mission-to-workbench",
      "workflow://graph/private-workspace-backtest",
      "workflow://graph/provider-zero-to-idle",
    ],
    templates: [
      {
        template_ref: "workflow-template:mission-to-workbench",
        label: "Mission to Workbench",
        description:
          "Turn accepted mission evidence into a governed Workbench session with adapter, model route, and receipt policy already bound.",
        graph_ref: "workflow://graph/mission-to-workbench",
        recipe_ref: "run-recipe:mission-to-workbench/manual",
        required_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
        model_route_policy_ref: "model-route-policy:inherit-session",
        receipt_policy_ref: "receipt-policy:workflow/compositor",
        latest_receipt_refs: receiptRefs.slice(0, 2),
      },
      {
        template_ref: "workflow-template:private-workspace-backtest",
        label: "Private Workspace Backtest",
        description:
          "Run public market transforms remotely while private strategy state remains behind cTEE and wallet-governed declassification.",
        graph_ref: "workflow://graph/private-workspace-backtest",
        recipe_ref: "run-recipe:private-workspace-backtest/nightly",
        required_scope_refs: [
          "scope:workspace.redacted.read",
          "scope:ctee.private-head.evaluate",
        ],
        model_route_policy_ref: "model-route-policy:local-or-redacted",
        receipt_policy_ref: "receipt-policy:workflow/private-workspace",
        latest_receipt_refs: receiptRefs.slice(1, 3),
      },
      {
        template_ref: "workflow-template:provider-zero-to-idle",
        label: "Provider Zero to Idle",
        description:
          "Archive session state, write restore refs, revoke access leases, and idle provider resources through governed admission.",
        graph_ref: "workflow://graph/provider-zero-to-idle",
        recipe_ref: "run-recipe:provider-zero-to-idle/on-idle",
        required_scope_refs: ["scope:provider.stop", "scope:archive.write"],
        model_route_policy_ref: "model-route-policy:none",
        receipt_policy_ref: "receipt-policy:provider/zero-to-idle",
        latest_receipt_refs: receiptRefs.slice(2, 4),
      },
    ],
    run_recipes: [
      {
        run_recipe_ref: "run-recipe:mission-to-workbench/manual",
        template_ref: "workflow-template:mission-to-workbench",
        label: "Manual mission handoff",
        schedule_ref: "schedule:manual",
        launch_action_ref: "action://workflow/mission-to-workbench/launch",
        authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
        receipt_refs: receiptRefs.slice(0, 1),
      },
      {
        run_recipe_ref: "run-recipe:private-workspace-backtest/nightly",
        template_ref: "workflow-template:private-workspace-backtest",
        label: "Nightly redacted backtest",
        schedule_ref: "schedule:nightly",
        launch_action_ref: "action://workflow/private-backtest/launch",
        authority_scope_refs: [
          "scope:workspace.redacted.read",
          "scope:provider.spend",
        ],
        receipt_refs: receiptRefs.slice(1, 2),
      },
      {
        run_recipe_ref: "run-recipe:provider-zero-to-idle/on-idle",
        template_ref: "workflow-template:provider-zero-to-idle",
        label: "Idle provider cleanup",
        schedule_ref: "schedule:on-session-idle",
        launch_action_ref: "action://workflow/provider-zero-to-idle/launch",
        authority_scope_refs: ["scope:archive.write", "scope:provider.stop"],
        receipt_refs: receiptRefs.slice(2, 3),
      },
    ],
    graphs: [
      {
        graph_ref: "workflow://graph/mission-to-workbench",
        label: "Mission acceptance graph",
        node_count: 6,
        edge_count: 7,
        context_chamber_refs: [
          "chamber://mission/evidence",
          "chamber://workbench/setup",
        ],
        artifact_refs: ["artifact://workflow/mission-to-workbench/graph"],
        receipt_refs: receiptRefs.slice(0, 2),
      },
      {
        graph_ref: "workflow://graph/private-workspace-backtest",
        label: "cTEE backtest graph",
        node_count: 8,
        edge_count: 11,
        context_chamber_refs: [
          "chamber://public-market-data",
          "chamber://private-alpha-head",
        ],
        artifact_refs: ["artifact://workflow/private-backtest/graph"],
        receipt_refs: receiptRefs.slice(1, 3),
      },
      {
        graph_ref: "workflow://graph/provider-zero-to-idle",
        label: "Provider idle graph",
        node_count: 5,
        edge_count: 5,
        context_chamber_refs: [
          "chamber://session/archive",
          "chamber://provider/lifecycle",
        ],
        artifact_refs: ["artifact://workflow/provider-zero-to-idle/graph"],
        receipt_refs: receiptRefs.slice(2, 4),
      },
    ],
    runs: [
      {
        run_ref: "workflow-run:mission-to-workbench/latest",
        template_ref: "workflow-template:mission-to-workbench",
        status: "ready",
        action_proposal_ref: "action://workflow/mission-to-workbench/launch",
        agentgres_operation_ref:
          "agentgres://operation/workflow/mission-to-workbench/ready",
        state_root_ref: "agentgres://state-root/workflow/mission-to-workbench",
        latest_receipt_ref: receiptRefs[0] ?? "receipt://workflow/ready",
      },
      {
        run_ref: "workflow-run:private-backtest/nightly",
        template_ref: "workflow-template:private-workspace-backtest",
        status: "scheduled",
        action_proposal_ref: "action://workflow/private-backtest/launch",
        agentgres_operation_ref:
          "agentgres://operation/workflow/private-backtest/scheduled",
        state_root_ref: "agentgres://state-root/workflow/private-backtest",
        latest_receipt_ref: receiptRefs[1] ?? "receipt://workflow/scheduled",
      },
      {
        run_ref: "workflow-run:provider-zero-to-idle/latest",
        template_ref: "workflow-template:provider-zero-to-idle",
        status: "blocked",
        action_proposal_ref: "action://workflow/provider-zero-to-idle/launch",
        agentgres_operation_ref:
          "agentgres://operation/workflow/provider-zero-to-idle/blocked",
        state_root_ref: "agentgres://state-root/workflow/provider-zero-to-idle",
        latest_receipt_ref: receiptRefs[2] ?? "receipt://workflow/blocked",
      },
    ],
    latest_receipt_refs: receiptRefs,
    agentgres_operation_refs: [
      "agentgres://operation/workflow/mission-to-workbench/ready",
      "agentgres://operation/workflow/private-backtest/scheduled",
      "agentgres://operation/workflow/provider-zero-to-idle/blocked",
    ],
    state_root_ref: "agentgres://state-root/workflow-compositor/hypervisor-core",
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

function numberValue(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
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

function enumValue<T extends string>(
  value: unknown,
  fallback: T,
  allowed: readonly T[],
): T {
  return typeof value === "string" && allowed.includes(value as T)
    ? (value as T)
    : fallback;
}

function normalizeTemplate(
  item: Record<string, unknown>,
  index: number,
): HypervisorAutomationTemplate {
  const fallback =
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.templates[index] ??
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.templates[0]!;
  return {
    template_ref: stringValue(item.template_ref, fallback.template_ref),
    label: stringValue(item.label, fallback.label),
    description: stringValue(item.description, fallback.description),
    graph_ref: stringValue(item.graph_ref, fallback.graph_ref),
    recipe_ref: stringValue(item.recipe_ref, fallback.recipe_ref),
    required_scope_refs: stringList(
      item.required_scope_refs,
      fallback.required_scope_refs,
    ),
    model_route_policy_ref: stringValue(
      item.model_route_policy_ref,
      fallback.model_route_policy_ref,
    ),
    receipt_policy_ref: stringValue(
      item.receipt_policy_ref,
      fallback.receipt_policy_ref,
    ),
    latest_receipt_refs: stringList(
      item.latest_receipt_refs,
      fallback.latest_receipt_refs,
    ),
  };
}

function normalizeRunRecipe(
  item: Record<string, unknown>,
  index: number,
): HypervisorAutomationRunRecipe {
  const fallback =
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.run_recipes[index] ??
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.run_recipes[0]!;
  return {
    run_recipe_ref: stringValue(item.run_recipe_ref, fallback.run_recipe_ref),
    template_ref: stringValue(item.template_ref, fallback.template_ref),
    label: stringValue(item.label, fallback.label),
    schedule_ref: stringValue(item.schedule_ref, fallback.schedule_ref),
    launch_action_ref: stringValue(
      item.launch_action_ref,
      fallback.launch_action_ref,
    ),
    authority_scope_refs: stringList(
      item.authority_scope_refs,
      fallback.authority_scope_refs,
    ),
    receipt_refs: stringList(item.receipt_refs, fallback.receipt_refs),
  };
}

function normalizeGraph(
  item: Record<string, unknown>,
  index: number,
): HypervisorAutomationGraph {
  const fallback =
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.graphs[index] ??
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.graphs[0]!;
  return {
    graph_ref: stringValue(item.graph_ref, fallback.graph_ref),
    label: stringValue(item.label, fallback.label),
    node_count: numberValue(item.node_count, fallback.node_count),
    edge_count: numberValue(item.edge_count, fallback.edge_count),
    context_chamber_refs: stringList(
      item.context_chamber_refs,
      fallback.context_chamber_refs,
    ),
    artifact_refs: stringList(item.artifact_refs, fallback.artifact_refs),
    receipt_refs: stringList(item.receipt_refs, fallback.receipt_refs),
  };
}

function normalizeRun(
  item: Record<string, unknown>,
  index: number,
): HypervisorAutomationRun {
  const fallback =
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.runs[index] ??
    HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.runs[0]!;
  return {
    run_ref: stringValue(item.run_ref, fallback.run_ref),
    template_ref: stringValue(item.template_ref, fallback.template_ref),
    status: enumValue(item.status, fallback.status, [
      "draft",
      "ready",
      "scheduled",
      "running",
      "blocked",
      "completed",
    ]),
    action_proposal_ref: stringValue(
      item.action_proposal_ref,
      fallback.action_proposal_ref,
    ),
    agentgres_operation_ref: stringValue(
      item.agentgres_operation_ref,
      fallback.agentgres_operation_ref,
    ),
    state_root_ref: stringValue(item.state_root_ref, fallback.state_root_ref),
    latest_receipt_ref: stringValue(
      item.latest_receipt_ref,
      fallback.latest_receipt_ref,
    ),
  };
}

export function readHypervisorAutomationCompositorDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_AUTOMATION_COMPOSITOR_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_AUTOMATION_COMPOSITOR_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_AUTOMATION_COMPOSITOR_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_AUTOMATION_COMPOSITOR_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorAutomationCompositorProjection(
  snapshot: unknown,
  options: NormalizeAutomationCompositorProjectionOptions = {},
): HypervisorAutomationCompositorProjection {
  const value = objectRecord(snapshot);
  const templates = arrayOf(value.templates).map(normalizeTemplate);
  const runRecipes = arrayOf(value.run_recipes).map(normalizeRunRecipe);
  const graphs = arrayOf(value.graphs).map(normalizeGraph);
  const runs = arrayOf(value.runs).map(normalizeRun);
  return {
    schema_version: "ioi.hypervisor.automation_compositor_projection.v1",
    projection_id: stringValue(
      value.projection_id,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.projection_id,
    ),
    source: options.source ?? "daemon-automation-compositor-projection",
    selected_project_id: stringValue(
      value.selected_project_id,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.selected_project_id,
    ),
    runtimeTruthSource: "daemon-runtime",
    compositor_boundary_invariant: stringValue(
      value.compositor_boundary_invariant,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.compositor_boundary_invariant,
    ),
    workflow_template_refs: stringList(
      value.workflow_template_refs,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.workflow_template_refs,
    ),
    run_recipe_refs: stringList(
      value.run_recipe_refs,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.run_recipe_refs,
    ),
    graph_refs: stringList(
      value.graph_refs,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.graph_refs,
    ),
    templates:
      templates.length > 0
        ? templates
        : HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.templates,
    run_recipes:
      runRecipes.length > 0
        ? runRecipes
        : HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.run_recipes,
    graphs:
      graphs.length > 0
        ? graphs
        : HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.graphs,
    runs:
      runs.length > 0
        ? runs
        : HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.runs,
    latest_receipt_refs: stringList(
      value.latest_receipt_refs,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.latest_receipt_refs,
    ),
    agentgres_operation_refs: stringList(
      value.agentgres_operation_refs,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.agentgres_operation_refs,
    ),
    state_root_ref: stringValue(
      value.state_root_ref,
      HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE.state_root_ref,
    ),
  };
}

export async function loadHypervisorAutomationCompositorProjection(
  options: LoadAutomationCompositorProjectionOptions = {},
): Promise<HypervisorAutomationCompositorProjection> {
  const endpoint =
    options.endpoint ?? readHypervisorAutomationCompositorDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error(
      "fetch unavailable for Hypervisor automation compositor projection",
    );
  }
  const url = new URL(
    `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH}`,
  );
  if (options.projectId) {
    url.searchParams.set("project_id", options.projectId);
  }
  const response = await fetchImpl(url.toString(), {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Automation compositor projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorAutomationCompositorProjection(value, {
    source: options.source ?? "daemon-automation-compositor-projection",
  });
}
