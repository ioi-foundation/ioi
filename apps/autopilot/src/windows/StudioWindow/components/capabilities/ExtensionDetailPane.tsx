import { type CapabilitiesController } from "./useCapabilitiesController";
import { DetailDocument } from "./ui";

export function ExtensionDetailPane({
  controller,
}: {
  controller: CapabilitiesController;
}) {
  const selectedExtension = controller.extensions.selectedExtension;
  if (!selectedExtension) {
    return (
      <div className="capabilities-empty-detail">
        Select an extension to inspect the capability surface it contributes.
      </div>
    );
  }

  const sectionTitle =
    controller.extensions.detailSection === "surface" ? "Surfaces" : "Overview";
  const sectionSummary =
    controller.extensions.detailSection === "surface"
      ? "Capability surfaces currently contributed by this extension package."
      : "How this extension fits into the broader worker capability model.";
  const sectionMeta =
    controller.extensions.detailSection === "surface"
      ? `${selectedExtension.surfaces.length} items`
      : selectedExtension.status;

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">{selectedExtension.meta}</span>
          <h2>{selectedExtension.name}</h2>
        </div>
        <span className="capabilities-pill">{selectedExtension.status}</span>
      </header>

      <div className="capabilities-detail-inline-meta">
        <span>
          Status <strong>{selectedExtension.status}</strong>
        </span>
        <span>
          Package <strong>{selectedExtension.meta}</strong>
        </span>
        <span>
          Surfaces <strong>{selectedExtension.surfaces.length}</strong>
        </span>
      </div>

      <p className="capabilities-detail-summary">
        {selectedExtension.description}
      </p>

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.extensions.detailSection === "surface" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Surfaces</h3>
              <span>{selectedExtension.meta}</span>
            </div>
            <div className="capabilities-chip-row">
              {selectedExtension.surfaces.map((surfaceName) => (
                <span key={surfaceName} className="capabilities-chip">
                  {surfaceName}
                </span>
              ))}
            </div>
          </section>
        ) : null}

        {controller.extensions.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
            </div>
            <p>
              Extensions package one or more capability surfaces into something
              the worker can reliably use. They can contribute connections,
              tools, wrappers, or local adapters without fragmenting the
              top-level model.
            </p>
          </section>
        ) : null}
      </DetailDocument>
    </div>
  );
}
