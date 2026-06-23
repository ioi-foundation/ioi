import type { PrimaryView } from "../../windows/HypervisorShellWindow/hypervisorShellModel";

// Shared Applications-catalog mapping used by the activity-rail launcher (to
// resolve the singular Open Application label) and the Applications catalog
// surface (to launch an entry). Canon: Applications is a query-first catalog
// launcher and `Open Application` is the singular active surface slot — these
// specialized surfaces are catalog entries, NOT a permanent pinned rail.
export interface ApplicationSurfaceCatalogEntry {
  id: string;
  label: string;
  view: PrimaryView;
  description: string;
}

export const APPLICATION_SURFACE_CATALOG: readonly ApplicationSurfaceCatalogEntry[] =
  [
    {
      id: "foundry",
      label: "Foundry",
      view: "foundry",
      description: "Foundry jobs, evals, packages, and harness comparisons.",
    },
    {
      id: "models",
      label: "Models",
      view: "models",
      description: "Model routes, mounts, local engines, and model custody.",
    },
    {
      id: "workers",
      label: "Workers",
      view: "agents",
      description: "Agent and worker package projections.",
    },
    {
      id: "connectors",
      label: "Connectors",
      view: "applications",
      description: "Connector catalog entries inside Applications.",
    },
    {
      id: "policies",
      label: "Policies",
      view: "authority",
      description: "wallet.network policy and approval projections.",
    },
    {
      id: "receipts",
      label: "Receipts",
      view: "receipts",
      description: "Agentgres receipt and replay evidence.",
    },
    {
      id: "monitoring",
      label: "Monitoring",
      view: "insights",
      description: "Monitoring and runtime insight projections.",
    },
  ];

// Resolve the primary view for a catalog application id (used to launch an
// Applications catalog entry as the singular Open Application).
export function applicationViewForId(id: string): PrimaryView | null {
  return APPLICATION_SURFACE_CATALOG.find((entry) => entry.id === id)?.view ?? null;
}

// The catalog entry whose surface is currently active, if any. Excludes the
// Applications catalog surface itself (`applications`), which is the launcher,
// not a singular Open Application.
export function openApplicationForView(
  view: PrimaryView,
): ApplicationSurfaceCatalogEntry | null {
  if (view === "applications") return null;
  return APPLICATION_SURFACE_CATALOG.find((entry) => entry.view === view) ?? null;
}
