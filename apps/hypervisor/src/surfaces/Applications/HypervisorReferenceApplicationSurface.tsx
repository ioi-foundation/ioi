// Parity Phase C — the blank application surface the reference renders when an
// application is opened (server.js renderHypervisorBlankApplicationSurface, hijacking
// /insights): a bare surface showing the selected app's icon + name. Hydration of the
// real application UI is deferred — this nails the reference's open-an-app target.
import { APPLICATION_CATALOG } from "./applicationsCatalog";
import { useSelectedApplicationId } from "./selectedApplication";

export function HypervisorReferenceApplicationSurface() {
  const selectedId = useSelectedApplicationId();
  const app = selectedId
    ? APPLICATION_CATALOG.find((candidate) => candidate.id === selectedId)
    : undefined;

  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0">
      <section className="hypervisor-blank-application-surface" data-hypervisor-blank-application-surface>
        {app ? (
          <div className="hypervisor-blank-application-title">
            <span
              className="hypervisor-application-icon"
              aria-hidden="true"
              style={{ background: app.color, color: "#f5f7fb", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: "11px", fontWeight: 750 }}
            >
              {app.glyph}
            </span>
            <span>{app.name}</span>
          </div>
        ) : (
          <div className="hypervisor-blank-application-title">
            <span>No application selected</span>
          </div>
        )}
      </section>
    </main>
  );
}

export default HypervisorReferenceApplicationSurface;
