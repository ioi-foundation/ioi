import { useEffect, useState } from "react";

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

export function HypervisorApplicationsCatalogSurface() {
  const [catalog, setCatalog] = useState<HypervisorApplicationsCatalog>({
    applications: [],
  });
  const [loadState, setLoadState] = useState<
    "loading" | "ready" | "unavailable"
  >("loading");
  const [message, setMessage] = useState("Loading applications from replay route.");

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

  return (
    <section
      className="hypervisor-applications-catalog"
      aria-label="Applications catalog"
      data-hypervisor-applications-state={loadState}
      data-hypervisor-applications-count={catalog.applications.length}
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
        {catalog.applications.map((application) => (
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
            </footer>
          </article>
        ))}
      </div>
    </section>
  );
}
