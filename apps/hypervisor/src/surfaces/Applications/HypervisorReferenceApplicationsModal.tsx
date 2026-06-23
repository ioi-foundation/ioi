// Parity Phase C — Applications launcher modal, ported from the reference's
// server-injected catalog dialog (server.js buildHypervisorApplicationsModal). Emits
// the exact hypervisor-applications-* DOM (CSS already vendored in hypervisor-brand.css)
// and reproduces the behavior: search filter, category rail with counts, app grid
// grouped by category, selectable rows, and the detail aside. Opened from the shell's
// Applications nav item; closes on the x button, backdrop click, or Escape.
import { useEffect, useState } from "react";
import { APPLICATION_CATALOG, APPLICATION_CATEGORIES, type CatalogApp } from "./applicationsCatalog";

const PROMOTED_ID = "pipeline-builder";

function AppIcon({ app, className = "" }: { app: CatalogApp; className?: string }) {
  return (
    <span
      className={`hypervisor-application-icon ${className}`}
      aria-hidden="true"
      style={{ background: app.color, color: "#f5f7fb", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: "11px", fontWeight: 750 }}
    >
      {app.glyph}
    </span>
  );
}

export function HypervisorReferenceApplicationsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All apps");
  const [activeId, setActiveId] = useState(PROMOTED_ID);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const promoted = APPLICATION_CATALOG.find((a) => a.id === PROMOTED_ID) ?? APPLICATION_CATALOG[0];
  const q = query.trim().toLowerCase();
  const filtered = APPLICATION_CATALOG.filter(
    (a) => (category === "All apps" || a.category === category) && (!q || a.name.toLowerCase().includes(q) || a.description.toLowerCase().includes(q)),
  );
  const active = APPLICATION_CATALOG.find((a) => a.id === activeId) ?? filtered[0];
  const grouped = APPLICATION_CATEGORIES.map((cat) => ({ cat, apps: filtered.filter((a) => a.category === cat) })).filter((g) => g.apps.length);

  return (
    <div
      className="hypervisor-applications-modal-backdrop"
      data-hypervisor-applications-modal="true"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <section className="hypervisor-applications-modal" role="dialog" aria-modal="true" aria-label="Applications">
        <header className="hypervisor-applications-modal-header">
          <label className="hypervisor-applications-search">
            <span aria-hidden="true">Search</span>
            <input data-hypervisor-applications-search value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search for applications..." />
          </label>
          <button type="button" className="hypervisor-applications-modal-action" data-hypervisor-applications-filters>Filters</button>
          <button type="button" className="hypervisor-applications-modal-action" data-hypervisor-applications-close aria-label="Close applications" onClick={onClose}>x</button>
        </header>
        <div className="hypervisor-applications-modal-body">
          <nav className="hypervisor-applications-category-rail" aria-label="Application categories">
            {["All apps", ...APPLICATION_CATEGORIES].map((cat) => {
              const count = cat === "All apps" ? APPLICATION_CATALOG.length : APPLICATION_CATALOG.filter((a) => a.category === cat).length;
              return (
                <button key={cat} type="button" className="hypervisor-applications-category" data-hypervisor-application-category={cat} data-active={String(category === cat)} onClick={() => setCategory(cat)}>
                  <span>{cat}</span>
                  <span className="hypervisor-applications-category-count">{count}</span>
                </button>
              );
            })}
            <div className="hypervisor-applications-category-label">Promoted apps</div>
            <button type="button" className="hypervisor-applications-category" data-hypervisor-application-id={promoted.id} onClick={() => setActiveId(promoted.id)}>
              <span>{promoted.name}</span>
              <span className="hypervisor-applications-category-count">Selected</span>
            </button>
          </nav>
          <main className="hypervisor-applications-list">
            {grouped.length ? (
              grouped.map((g) => (
                <section key={g.cat} className="hypervisor-applications-group">
                  <h3 className="hypervisor-applications-group-title">{g.cat}</h3>
                  {g.apps.map((app) => (
                    <button key={app.id} type="button" className="hypervisor-application-row" data-hypervisor-application-id={app.id} data-selected={String(active != null && active.id === app.id)} onClick={() => setActiveId(app.id)}>
                      <AppIcon app={app} />
                      <span>
                        <span className="hypervisor-application-row-title">{app.name}</span>
                        <span className="hypervisor-application-row-description">{app.description}</span>
                      </span>
                      <span aria-hidden="true">{">"}</span>
                    </button>
                  ))}
                </section>
              ))
            ) : (
              <div className="hypervisor-applications-empty-detail">No applications match this search.</div>
            )}
          </main>
          <aside className="hypervisor-applications-detail">
            {active ? (
              <div className="hypervisor-applications-detail-card">
                <div className="hypervisor-applications-detail-top">
                  <AppIcon app={active} />
                  <button type="button" className="hypervisor-applications-open" data-hypervisor-open-application={active.id} onClick={onClose}>Open</button>
                </div>
                <h2 className="hypervisor-applications-detail-title">{active.name}</h2>
                <p className="hypervisor-applications-detail-description">{active.description}</p>
                <button type="button" className="hypervisor-applications-detail-link">Documentation</button>
              </div>
            ) : (
              <div className="hypervisor-applications-empty-detail">Click on an application to see details</div>
            )}
          </aside>
        </div>
      </section>
    </div>
  );
}

export default HypervisorReferenceApplicationsModal;
