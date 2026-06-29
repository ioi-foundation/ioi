// Applications surface model — source-owned, source-derived from the product-ui serve
// augmentation (the "Applications" sidebar section + applications catalog modal). The route
// anatomy is ported verbatim: a favorites strip (empty by default) plus a categorized catalog
// browser (category rail → grouped rows → detail). The data boundary differs:
//
// The Hypervisor daemon owns NO applications/favorites plane yet (GET /v1/applications,
// /v1/hypervisor/applications etc. all 404). So the catalog is a static, IOI-owned snapshot of the
// surface's app inventory, and "favorites" is honest client-only state persisted to localStorage —
// no rows are fabricated against a daemon that doesn't serve them. When a daemon applications plane
// lands, swap CATALOG/loadFavorites for typed daemon clients (see src/data/daemon.ts), exactly as
// Connections/Home already do.

export type AppEntry = {
  id: string;
  name: string;
  category: string;
  description: string;
  color: string;
  glyph: string;
};

// Category ordering — the surface's own taxonomy.
export const CATEGORIES = [
  "Administration",
  "Analytics & Operations",
  "Application development",
  "Data integration",
  "Developer toolchain",
  "Models",
  "Ontology",
  "Security & governance",
  "Support",
] as const;

// Static catalog — the application inventory the workspace can launch. IOI-owned snapshot of the
// surface's app set; not fetched from a daemon plane (none exists yet).
export const CATALOG: AppEntry[] = [
  { id: "control-panel", name: "Control Panel", category: "Administration", description: "Manage critical platform operations for an enrollment or organization.", color: "#48607d", glyph: "C" },
  { id: "resource-management", name: "Resource Management", category: "Administration", description: "Track and manage costs, budgets, resource queues, and usage limits.", color: "#125f6b", glyph: "R" },
  { id: "upgrade-assistant", name: "Upgrade Assistant", category: "Administration", description: "Track important platform updates and changes affecting the platform.", color: "#265e9b", glyph: "U" },
  { id: "aip-analyst", name: "AIP Analyst", category: "Analytics & Operations", description: "Agentic ad-hoc analysis.", color: "#8b4d1f", glyph: "A" },
  { id: "contour", name: "Contour", category: "Analytics & Operations", description: "Analyze large datasets with filters, joins, and visualizations.", color: "#8a5c27", glyph: "C" },
  { id: "fusion", name: "Fusion", category: "Analytics & Operations", description: "Interact with live data in a familiar spreadsheet interface.", color: "#126441", glyph: "F" },
  { id: "insight", name: "Insight", category: "Analytics & Operations", description: "Search, analyze, and view data in your ontology.", color: "#3e6c2d", glyph: "I" },
  { id: "map", name: "Map", category: "Analytics & Operations", description: "Analyze geospatial and geotemporal data.", color: "#16703f", glyph: "M" },
  { id: "notepad", name: "Notepad", category: "Analytics & Operations", description: "Create, share, and export object-aware documents and reports.", color: "#285b8f", glyph: "N" },
  { id: "quiver", name: "Quiver", category: "Analytics & Operations", description: "Visualize, analyze, and build interactive dashboards.", color: "#514184", glyph: "Q" },
  { id: "vertex", name: "Vertex", category: "Analytics & Operations", description: "Visualize and analyze complex relationships between objects and systems.", color: "#195d86", glyph: "V" },
  { id: "pipeline-builder", name: "Pipeline Builder", category: "Application development", description: "Build, inspect, and publish data pipelines.", color: "#0e7f79", glyph: "P" },
  { id: "code-repositories", name: "Code Repositories", category: "Application development", description: "Browse and manage repository-backed development work.", color: "#44546f", glyph: "<>" },
  { id: "workshop", name: "Workshop", category: "Application development", description: "Create operational applications and workflows.", color: "#5d4f9c", glyph: "W" },
  { id: "slate", name: "Slate", category: "Application development", description: "Compose operational interfaces and dashboards.", color: "#7750a6", glyph: "S" },
  { id: "automate", name: "Automate", category: "Application development", description: "Create event-driven application automation.", color: "#265b9a", glyph: "A" },
  { id: "developer-console", name: "Developer Console", category: "Application development", description: "Inspect developer resources, clients, and integrations.", color: "#455469", glyph: "D" },
  { id: "workflow-builder", name: "Workflow Builder", category: "Application development", description: "Draft and manage process workflows.", color: "#546078", glyph: "W" },
  { id: "ontology-manager", name: "Ontology Manager", category: "Data integration", description: "Design object types, links, and action contracts.", color: "#294a7b", glyph: "O" },
  { id: "object-explorer", name: "Object Explorer", category: "Data integration", description: "Inspect object data and relationships.", color: "#2c6770", glyph: "O" },
  { id: "data-lineage", name: "Data Lineage", category: "Data integration", description: "Trace datasets, transforms, and downstream consumers.", color: "#735f25", glyph: "L" },
  { id: "file-imports", name: "File Imports", category: "Data integration", description: "Stage and validate uploaded source files.", color: "#555d69", glyph: "F" },
  { id: "data-connector", name: "Data Connector", category: "Data integration", description: "Configure external source connections.", color: "#226c52", glyph: "D" },
  { id: "transform", name: "Transform", category: "Data integration", description: "Author transform logic and pipeline steps.", color: "#7a4b2d", glyph: "T" },
  { id: "time-series-catalog", name: "Time Series Catalog", category: "Data integration", description: "Manage time series signals and telemetry.", color: "#3c5d86", glyph: "T" },
  { id: "media-sets", name: "Media Sets", category: "Data integration", description: "Catalog media artifacts and annotations.", color: "#5b526f", glyph: "M" },
  { id: "data-health", name: "Data Health", category: "Data integration", description: "Monitor pipeline freshness and quality.", color: "#266843", glyph: "H" },
  { id: "tables", name: "Tables", category: "Data integration", description: "Browse structured datasets and table schemas.", color: "#394f7a", glyph: "T" },
  { id: "jobs", name: "Jobs", category: "Data integration", description: "Inspect scheduled and ad-hoc execution jobs.", color: "#6b5035", glyph: "J" },
  { id: "schedules", name: "Schedules", category: "Data integration", description: "Coordinate recurring pipeline execution.", color: "#5d6231", glyph: "S" },
  { id: "syncs", name: "Syncs", category: "Data integration", description: "Observe replication and sync activity.", color: "#2a6362", glyph: "S" },
  { id: "sources", name: "Sources", category: "Data integration", description: "Manage source-system inventory.", color: "#4b5c72", glyph: "S" },
  { id: "monitoring", name: "Monitoring", category: "Data integration", description: "Track operational health and incidents.", color: "#395f7d", glyph: "M" },
  { id: "models", name: "Models", category: "Developer toolchain", description: "Manage model artifacts and serving endpoints.", color: "#4b5f89", glyph: "M" },
  { id: "foundry-sdk", name: "Foundry SDK", category: "Developer toolchain", description: "Explore SDK clients and generated bindings.", color: "#4e5365", glyph: "S" },
  { id: "api-explorer", name: "API Explorer", category: "Developer toolchain", description: "Inspect and test API contracts.", color: "#59647a", glyph: "A" },
  { id: "checkpoints", name: "Checkpoints", category: "Developer toolchain", description: "Review saved execution and development checkpoints.", color: "#66624a", glyph: "C" },
  { id: "model-garden", name: "Model Garden", category: "Models", description: "Discover model options and local configuration targets.", color: "#4b5aa3", glyph: "G" },
  { id: "model-studio", name: "Model Studio", category: "Models", description: "Evaluate and package model behavior.", color: "#384f8c", glyph: "S" },
  { id: "model-evaluation", name: "Model Evaluation", category: "Models", description: "Compare runs, prompts, and quality metrics.", color: "#5d4f83", glyph: "E" },
  { id: "prompt-studio", name: "Prompt Studio", category: "Models", description: "Draft and test reusable prompt templates.", color: "#6a4e7f", glyph: "P" },
  { id: "agent-studio", name: "Agent Studio", category: "Models", description: "Configure agent skills and tool bindings.", color: "#365f8d", glyph: "A" },
  { id: "notepad-template", name: "Notepad Template", category: "Models", description: "Author reusable report and analysis templates.", color: "#3a6178", glyph: "N" },
  { id: "vector-index", name: "Vector Index", category: "Models", description: "Manage embeddings and retrieval indexes.", color: "#45617a", glyph: "V" },
  { id: "ontology", name: "Ontology", category: "Ontology", description: "Browse object models and semantic resources.", color: "#4f5c69", glyph: "O" },
  { id: "actions", name: "Actions", category: "Ontology", description: "Manage admitted user and agent actions.", color: "#69577a", glyph: "A" },
  { id: "approvals", name: "Approvals", category: "Ontology", description: "Review approvals and pending requests.", color: "#71613f", glyph: "A" },
  { id: "object-types", name: "Object Types", category: "Ontology", description: "Inspect object schemas and constraints.", color: "#38646c", glyph: "O" },
  { id: "functions", name: "Functions", category: "Ontology", description: "Register and test ontology functions.", color: "#5c5270", glyph: "F" },
  { id: "scenario", name: "Scenario", category: "Ontology", description: "Explore planning and what-if scenarios.", color: "#51633e", glyph: "S" },
  { id: "cipher", name: "Cipher", category: "Security & governance", description: "Manage governed secrets and sensitive policy posture.", color: "#44586d", glyph: "C" },
  { id: "policies", name: "Policies", category: "Security & governance", description: "Review policy controls and enforcement.", color: "#615a3d", glyph: "P" },
  { id: "audit", name: "Audit", category: "Security & governance", description: "Inspect audit trails and access events.", color: "#6a4b4b", glyph: "A" },
  { id: "markings", name: "Markings", category: "Security & governance", description: "Configure data markings and access labels.", color: "#4d5d76", glyph: "M" },
  { id: "marketplace", name: "Marketplace", category: "Security & governance", description: "Browse governed extensions and packaged capabilities.", color: "#536165", glyph: "M" },
  { id: "help-center", name: "Help Center", category: "Support", description: "Find documentation and operational support.", color: "#4b6070", glyph: "H" },
  { id: "support", name: "Support", category: "Support", description: "Open support resources and diagnostics.", color: "#59606b", glyph: "S" },
  { id: "status", name: "Status", category: "Support", description: "Review service status and incidents.", color: "#576f50", glyph: "S" },
  { id: "releases", name: "Releases", category: "Support", description: "Track product release notes and changes.", color: "#6d5d42", glyph: "R" },
  { id: "admin-docs", name: "Admin Docs", category: "Support", description: "Open administration documentation.", color: "#4c5f78", glyph: "D" },
];

const FAVORITES_KEY = "ioi.hypervisor.favoriteApplicationIds";

// Favorites are honest client-only state (no daemon plane to own them yet). Persisted to
// localStorage exactly as the surface persists its selected/pinned app id.
export function loadFavorites(): string[] {
  try {
    const raw = localStorage.getItem(FAVORITES_KEY);
    const ids = raw ? (JSON.parse(raw) as unknown) : [];
    if (!Array.isArray(ids)) return [];
    return ids.filter((id): id is string => typeof id === "string" && CATALOG.some((a) => a.id === id));
  } catch {
    return [];
  }
}

export function saveFavorites(ids: string[]): void {
  try {
    localStorage.setItem(FAVORITES_KEY, JSON.stringify(ids));
  } catch {
    /* storage unavailable */
  }
}

export function toggleFavorite(ids: string[], id: string): string[] {
  return ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id];
}

export function getApp(id: string | null): AppEntry | null {
  return id ? CATALOG.find((a) => a.id === id) || null : null;
}

export function categoryCount(category: string): number {
  return CATALOG.filter((a) => a.category === category).length;
}

// Filter the catalog by an active category ("All apps" = no filter) and a free-text query over
// name / description / category.
export function filterCatalog(category: string, query: string): AppEntry[] {
  const q = query.trim().toLowerCase();
  return CATALOG.filter((app) => {
    const categoryMatch = category === ALL_CATEGORY || app.category === category;
    const queryMatch = !q || `${app.name} ${app.description} ${app.category}`.toLowerCase().includes(q);
    return categoryMatch && queryMatch;
  });
}

export const ALL_CATEGORY = "All apps";

// Group an already-filtered list back into the category taxonomy (ordered, non-empty only).
export function groupByCategory(apps: AppEntry[]): { category: string; apps: AppEntry[] }[] {
  return CATEGORIES.map((category) => ({ category, apps: apps.filter((a) => a.category === category) })).filter(
    (g) => g.apps.length > 0,
  );
}
