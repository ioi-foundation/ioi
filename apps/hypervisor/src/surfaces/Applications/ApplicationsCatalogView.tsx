import { useEffect, useMemo, useState } from "react";

import {
  HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY,
  HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT,
} from "../../domain/harnessAdapterModel";

interface HypervisorApplicationCatalogRecord {
  application_id: string;
  label: string;
  category: string;
  pinned: boolean;
  route_ref: string;
  status: string;
}

interface HypervisorApplicationsCatalog {
  schema_version?: string;
  applications: HypervisorApplicationCatalogRecord[];
}

function readHypervisorApplicationsDaemonEndpoint(): string {
  if (typeof window === "undefined") {
    return HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT;
  }

  const stored = window.localStorage
    .getItem(HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DAEMON_ENDPOINT_STORAGE_KEY)
    ?.trim();
  return stored || HYPERVISOR_HARNESS_PUBLIC_FIXTURE_DEFAULT_DAEMON_ENDPOINT;
}

function normalizeApplicationsCatalog(value: unknown): HypervisorApplicationsCatalog {
  const record =
    value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  const applications = Array.isArray(record.applications)
    ? record.applications.map((item, index): HypervisorApplicationCatalogRecord => {
        const candidate =
          item && typeof item === "object" ? (item as Record<string, unknown>) : {};
        const fallbackId = `application:${index + 1}`;
        return {
          application_id:
            typeof candidate.application_id === "string"
              ? candidate.application_id
              : fallbackId,
          label:
            typeof candidate.label === "string" ? candidate.label : fallbackId,
          category:
            typeof candidate.category === "string"
              ? candidate.category
              : "platform",
          pinned: candidate.pinned === true,
          route_ref:
            typeof candidate.route_ref === "string"
              ? candidate.route_ref
              : `surface:${fallbackId}`,
          status:
            typeof candidate.status === "string" ? candidate.status : "available",
        };
      })
    : [];

  return {
    schema_version:
      typeof record.schema_version === "string" ? record.schema_version : undefined,
    applications,
  };
}

interface HypervisorApplicationsCatalogSurfaceProps {
  // Launch a catalog entry as the singular Open Application. Optional so the
  // catalog still renders read-only where no launch path is wired.
  onLaunchApplication?: (applicationId: string) => void;
}

export function HypervisorApplicationsCatalogSurface({
  onLaunchApplication,
}: HypervisorApplicationsCatalogSurfaceProps = {}) {
  const [catalog, setCatalog] = useState<HypervisorApplicationsCatalog>({
    applications: [],
  });
  const [loadState, setLoadState] = useState<
    "loading" | "ready" | "unavailable"
  >("loading");
  const [message, setMessage] = useState("Loading applications from replay route.");
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadCatalog() {
      try {
        const endpoint = readHypervisorApplicationsDaemonEndpoint();
        const response = await fetch(
          `${endpoint.replace(/\/+$/, "")}/v1/hypervisor/applications`,
          { headers: { accept: "application/json" } },
        );
        if (!response.ok) {
          throw new Error(`Applications catalog request failed with ${response.status}`);
        }
        const nextCatalog = normalizeApplicationsCatalog(await response.json());
        if (cancelled) return;
        setCatalog(nextCatalog);
        setLoadState("ready");
        setMessage(
          `Loaded ${nextCatalog.applications.length} pinned application surfaces from the daemon-shaped replay route.`,
        );
      } catch (error) {
        if (cancelled) return;
        setLoadState("unavailable");
        setMessage(error instanceof Error ? error.message : String(error));
      }
    }

    void loadCatalog();

    return () => {
      cancelled = true;
    };
  }, []);

  const pinnedApplications = catalog.applications.filter(
    (application) => application.pinned,
  );
  const availableApplications = catalog.applications.filter(
    (application) => application.status === "available",
  );

  // Query-first catalog: filter by label/category/id. Favorites/recent are
  // catalog metadata surfaced here, not a permanent pinned shell rail.
  const normalizedQuery = query.trim().toLowerCase();
  const visibleApplications = useMemo(() => {
    if (!normalizedQuery) return catalog.applications;
    return catalog.applications.filter((application) =>
      [application.label, application.category, application.application_id]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery),
    );
  }, [catalog.applications, normalizedQuery]);

  return (
    <section
      className="hypervisor-applications-catalog"
      aria-label="Applications catalog"
      data-applications-launcher="true"
      data-hypervisor-applications-state={loadState}
      data-hypervisor-applications-count={catalog.applications.length}
      data-hypervisor-applications-visible-count={visibleApplications.length}
    >
      <div className="hypervisor-applications-catalog__header">
        <div>
          <span>Applications</span>
          <h2>Hypervisor application catalog</h2>
          <p>
            Operational applications hydrate from the local daemon-shaped
            replay route. Foundry, Models, Workers, Connectors, Policies,
            Receipts, and Monitoring stay app surfaces over Core instead of
            becoming separate runtimes.
          </p>
        </div>
        <p data-hypervisor-applications-load-state={loadState}>{message}</p>
      </div>

      <div className="hypervisor-applications-catalog__search">
        <input
          type="search"
          className="hypervisor-applications-catalog__search-input"
          data-applications-catalog-query="true"
          placeholder="Search applications…"
          aria-label="Search applications"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      <div className="hypervisor-applications-catalog__summary" aria-label="Application summary">
        <div>
          <span>Favorites</span>
          <strong>{pinnedApplications.length}</strong>
        </div>
        <div>
          <span>Available</span>
          <strong>{availableApplications.length}</strong>
        </div>
        <div>
          <span>Route source</span>
          <strong>/v1/hypervisor/applications</strong>
        </div>
      </div>

      <div className="hypervisor-applications-catalog__grid">
        {visibleApplications.map((application) => (
          <article
            key={application.application_id}
            className="hypervisor-applications-catalog__item"
            data-hypervisor-application-id={application.application_id}
            data-hypervisor-application-route={application.route_ref}
          >
            <div>
              <span>{application.category}</span>
              <h3>{application.label}</h3>
            </div>
            <p>{application.route_ref}</p>
            <footer>
              <strong>{application.status}</strong>
              {application.pinned ? <span>Favorite</span> : <span>Catalog</span>}
              {onLaunchApplication ? (
                <button
                  type="button"
                  className="hypervisor-applications-catalog__launch"
                  data-application-launch-id={application.application_id}
                  onClick={() => onLaunchApplication(application.application_id)}
                  title={`Open ${application.label}`}
                >
                  Open
                </button>
              ) : null}
            </footer>
          </article>
        ))}
        {visibleApplications.length === 0 ? (
          <p
            className="hypervisor-applications-catalog__empty"
            data-applications-catalog-empty="true"
          >
            No applications match “{query}”.
          </p>
        ) : null}
      </div>
    </section>
  );
}
