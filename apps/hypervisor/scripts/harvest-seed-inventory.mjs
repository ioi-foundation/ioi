// Harvested UX parity inventory — the canonical map of Hypervisor application seeds.
//
// Phase doctrine: capture completeness → bit-for-bit UX seed → classify unbound lanes → later
// daemon rebind → later IOI-owned surface. This module is the SINGLE SOURCE OF TRUTH the parity
// verifier iterates; it is also the follow-up map for truth-binding cuts.
//
// Each entry:
//   owner       — the canonical Hypervisor suite surface that owns this UX
//   slug        — the /__apps/<slug> route inside Hypervisor
//   captureBase — the capture workspace route (…/public/workspace/<dir>/)
//   grammar     — the intended interaction grammar (editor_canvas | graph | wizard | table_list |
//                 document | catalog | landing)
//   tier        — "high_value" seeds MUST boot past shell into their grammar; "aux" may land/shell
//   reboundLane — a daemon lane already rebound on the owner surface, or null (unbound seed)
//   note        — unbound-lane classification / named gaps
//
// `tier` marks a high-value surface; whether a seed boots is decided EMPIRICALLY by the parity
// verifier against the LOCAL CAPTURE ONLY, and recorded in its JSON artifact as one of:
// boots_{editor_canvas,graph,wizard,table_list,document,landing} | shell_only |
// blocked_missing_capture. There is no "live re-harvest" in this phase — a seed the static capture
// cannot boot past shell is classified honestly (shell_only / blocked_missing_capture), never faked
// and never described as needing a live tenant.

export const SEED_INVENTORY = [
  // ── Studio — system/process composition ────────────────────────────────────────────────
  { owner: "Studio", ownerUrl: "/__ioi/agent-studio", slug: "designer", captureBase: "/workspace/solution-design/", grammar: "editor_canvas", tier: "high_value", reboundLane: "odk composition patterns + surface descriptors", note: "typed concept/component/resource canvas; in-canvas open/save/reference/load-lineage = named gaps" },
  { owner: "Studio", ownerUrl: "/__ioi/agent-studio", slug: "machinery", captureBase: "/workspace/machinery-app/", grammar: "graph", tier: "high_value", reboundLane: null, note: "process/state-machine graph; data lanes unbound" },
  { owner: "Studio", ownerUrl: "/__ioi/agent-studio", slug: "workshop", captureBase: "/workspace/workshop/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "application/module builder; unbound" },
  { owner: "Studio", ownerUrl: "/__ioi/agent-studio", slug: "module", captureBase: "/workspace/module/", grammar: "editor_canvas", tier: "aux", reboundLane: null, note: "compute-module builder; unbound" },

  // ── Automations ────────────────────────────────────────────────────────────────────────
  { owner: "Automations", ownerUrl: "/__ioi/automations", slug: "monitors", captureBase: "/workspace/object-monitoring/", grammar: "wizard", tier: "high_value", reboundLane: null, note: "condition→effect monitor wizard; unbound" },
  { owner: "Automations", ownerUrl: "/__ioi/operations", slug: "scheduler", captureBase: "/workspace/scheduler/", grammar: "table_list", tier: "aux", reboundLane: null, note: "schedule table; unbound" },

  // ── Provenance ─────────────────────────────────────────────────────────────────────────
  { owner: "Provenance", ownerUrl: "/__ioi/work-ledger", slug: "lineage", captureBase: "/workspace/monocle/", grammar: "graph", tier: "high_value", reboundLane: "Work Ledger cross-object lineage edges", note: "lineage graph editor; in-canvas resource-search lanes = named gaps" },

  // ── Data ───────────────────────────────────────────────────────────────────────────────
  { owner: "Data", ownerUrl: "/__ioi/ontology", slug: "ingest", captureBase: "/workspace/hyperauto/", grammar: "wizard", tier: "high_value", reboundLane: null, note: "source-first pipeline wizard; unbound" },
  { owner: "Data", ownerUrl: "/__ioi/ontology", slug: "sources", captureBase: "/workspace/data-ingestion-app/", grammar: "table_list", tier: "high_value", reboundLane: null, note: "Sources/Syncs/Listeners IA; unbound" },
  { owner: "Data", ownerUrl: "/__ioi/ontology", slug: "pipeline", captureBase: "/workspace/builder/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "Pipeline Builder canvas; boots as classified from the local capture" },
  { owner: "Data", ownerUrl: "/__ioi/ontology", slug: "dataset", captureBase: "/workspace/dataset/", grammar: "table_list", tier: "aux", reboundLane: null, note: "dataset preview/table; unbound" },

  // ── Ontology ───────────────────────────────────────────────────────────────────────────
  { owner: "Ontology", ownerUrl: "/__ioi/ontology", slug: "schema", captureBase: "/workspace/ontology/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "schema workbench (types/functions/health/history); unbound" },
  { owner: "Ontology", ownerUrl: "/__ioi/ontology", slug: "explorer", captureBase: "/workspace/hubble/", grammar: "table_list", tier: "high_value", reboundLane: null, note: "object explorer + saved sets; unbound" },
  { owner: "Ontology", ownerUrl: "/__ioi/ontology", slug: "objectview", captureBase: "/workspace/object-view/", grammar: "document", tier: "aux", reboundLane: null, note: "object view; unbound" },
  { owner: "Ontology", ownerUrl: "/__ioi/ontology", slug: "objecteditor", captureBase: "/workspace/object-view-editor/", grammar: "editor_canvas", tier: "aux", reboundLane: null, note: "object-view editor; unbound" },

  // ── Evaluations ────────────────────────────────────────────────────────────────────────
  { owner: "Evaluations", ownerUrl: "/__ioi/evaluations", slug: "evalsuites", captureBase: "/workspace/evals/", grammar: "table_list", tier: "high_value", reboundLane: null, note: "eval-suite library; unbound" },
  { owner: "Evaluations", ownerUrl: "/__ioi/evaluations", slug: "analysis", captureBase: "/workspace/insight/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "object-set-first analysis canvas; unbound" },
  { owner: "Evaluations", ownerUrl: "/__ioi/evaluations", slug: "quiver", captureBase: "/workspace/quiver/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "time-series analysis canvas; unbound" },

  // ── Foundry ────────────────────────────────────────────────────────────────────────────
  { owner: "Foundry", ownerUrl: "/__ioi/foundry", slug: "models", captureBase: "/workspace/model-catalog/", grammar: "catalog", tier: "high_value", reboundLane: null, note: "model registry home; unbound" },
  { owner: "Foundry", ownerUrl: "/__ioi/foundry", slug: "modelstudio", captureBase: "/workspace/model-studio/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "model studio; unbound" },
  { owner: "Foundry", ownerUrl: "/__ioi/foundry", slug: "inference", captureBase: "/workspace/foundry-inference-app/", grammar: "wizard", tier: "aux", reboundLane: null, note: "inference app; unbound" },

  // ── Marketplace ────────────────────────────────────────────────────────────────────────
  { owner: "Marketplace", ownerUrl: "/__ioi/marketplace", slug: "listings", captureBase: "/workspace/marketplace/", grammar: "catalog", tier: "high_value", reboundLane: "daemon marketplace listing plane", note: "store browse + install wizard; drill-down = named gap" },
  { owner: "Marketplace", ownerUrl: "/__ioi/marketplace", slug: "registry", captureBase: "/workspace/artifacts/", grammar: "table_list", tier: "high_value", reboundLane: null, note: "versioned artifact registry; unbound" },

  // ── Developer Console ──────────────────────────────────────────────────────────────────
  { owner: "Developer Console", ownerUrl: "/__ioi/connections", slug: "devconsole", captureBase: "/workspace/developer-console/", grammar: "wizard", tier: "high_value", reboundLane: null, note: "OAuth app registration + SDK on-ramps (self-bootstrapped)" },
  { owner: "Developer Console", ownerUrl: "/__ioi/connections", slug: "widgets", captureBase: "/workspace/custom-widgets/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "widget-set authoring (self-bootstrapped)" },
  { owner: "Developer Console", ownerUrl: "/__ioi/connections", slug: "developer", captureBase: "/workspace/developer/", grammar: "table_list", tier: "aux", reboundLane: null, note: "developer home; unbound" },

  // ── Workbench ──────────────────────────────────────────────────────────────────────────
  { owner: "Workbench", ownerUrl: "/__ioi/workbench", slug: "workspaces", captureBase: "/workspace/code-workspaces/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "code workspace IDE; unbound" },
  { owner: "Workbench", ownerUrl: "/__ioi/workbench", slug: "repositories", captureBase: "/workspace/code-repositories/", grammar: "table_list", tier: "aux", reboundLane: null, note: "code repositories; unbound" },
  { owner: "Workbench", ownerUrl: "/__ioi/workbench", slug: "notepad", captureBase: "/workspace/notepad/", grammar: "document", tier: "aux", reboundLane: null, note: "notepad document; unbound" },

  // ── Geospatial / graph ─────────────────────────────────────────────────────────────────
  { owner: "Provenance", ownerUrl: "/__ioi/work-ledger", slug: "vertex", captureBase: "/workspace/vertex/", grammar: "graph", tier: "high_value", reboundLane: null, note: "Vertex graph exploration canvas; boots as classified from the local capture" },
  { owner: "Environments", ownerUrl: "/__ioi/environments", slug: "map", captureBase: "/workspace/map/", grammar: "editor_canvas", tier: "aux", reboundLane: null, note: "geospatial map canvas; unbound" },

  // ── Domain-app composition ─────────────────────────────────────────────────────────────
  { owner: "Domain Apps", ownerUrl: "/__ioi/domain-apps", slug: "slate", captureBase: "/workspace/slate/", grammar: "editor_canvas", tier: "high_value", reboundLane: null, note: "Slate app builder; unbound" },
  { owner: "Domain Apps", ownerUrl: "/__ioi/domain-apps", slug: "logic", captureBase: "/workspace/logic-app/", grammar: "editor_canvas", tier: "aux", reboundLane: null, note: "Logic builder; unbound" },
  { owner: "Domain Apps", ownerUrl: "/__ioi/domain-apps", slug: "contour", captureBase: "/workspace/contour-app/", grammar: "editor_canvas", tier: "aux", reboundLane: null, note: "Contour analysis; unbound" },
  { owner: "Domain Apps", ownerUrl: "/__ioi/domain-apps", slug: "fusion", captureBase: "/workspace/fusion/", grammar: "editor_canvas", tier: "aux", reboundLane: null, note: "Fusion spreadsheet; unbound" },

  // ── Missions / Improvement / Governance (already rebound, kept in inventory for coverage) ─
  { owner: "Missions", ownerUrl: "/__ioi/missions", slug: "jobs", captureBase: "/workspace/job-tracker/", grammar: "table_list", tier: "high_value", reboundLane: "daemon jobs queue", note: "run/job status table" },
  { owner: "Missions", ownerUrl: "/__ioi/missions", slug: "incidents", captureBase: "/workspace/issues-app/", grammar: "table_list", tier: "high_value", reboundLane: "daemon incident inbox", note: "status-lane remediation inbox" },
  { owner: "Governance", ownerUrl: "/__ioi/governance", slug: "approvals", captureBase: "/workspace/approvals-app/", grammar: "table_list", tier: "high_value", reboundLane: "daemon approval-requests", note: "approvals inbox; per-row drilldown = named gap" },
  { owner: "Improvement", ownerUrl: "/__ioi/agent-studio", slug: "changes", captureBase: "/workspace/upgrade-assistant/", grammar: "table_list", tier: "high_value", reboundLane: "daemon improvement-proposals", note: "change inbox" },
];

