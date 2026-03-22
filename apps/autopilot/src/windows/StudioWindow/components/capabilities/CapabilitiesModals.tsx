import type { ConnectorSummary } from "@ioi/agent-ide";
import { humanize, providerAccent } from "./model";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { SearchIcon, XIcon } from "./ui";

export function CapabilitiesModals({
  controller,
}: {
  controller: CapabilitiesController;
}) {
  return (
    <>
      {controller.connections.catalogModalOpen ? (
        <div className="capabilities-modal-backdrop" role="presentation">
          <div
            className="capabilities-modal capabilities-modal-wide"
            role="dialog"
            aria-modal="true"
            aria-label="Browse connections"
          >
            <div className="capabilities-modal-head">
              <div>
                <h2>Browse connections</h2>
                <p>
                  Add authenticated systems to the workspace shell before wiring
                  or expanding the underlying adapter.
                </p>
              </div>
              <button
                type="button"
                className="capabilities-icon-button"
                onClick={() => controller.connections.setCatalogModalOpen(false)}
                aria-label="Close browse connections"
              >
                <XIcon />
              </button>
            </div>

            <div className="capabilities-modal-toolbar">
              <label className="capabilities-search">
                <SearchIcon />
                <input
                  value={controller.connections.catalogQuery}
                  onChange={(event) =>
                    controller.connections.setCatalogQuery(event.target.value)
                  }
                  placeholder="Search connection catalog..."
                />
              </label>
              <label className="capabilities-select">
                <span>Category</span>
                <select
                  value={controller.connections.catalogCategoryFilter}
                  onChange={(event) =>
                    controller.connections.setCatalogCategoryFilter(
                      event.target.value as ConnectorSummary["category"] | "all",
                    )
                  }
                >
                  <option value="all">All</option>
                  <option value="communication">Communication</option>
                  <option value="productivity">Productivity</option>
                  <option value="storage">Storage</option>
                  <option value="developer">Developer</option>
                </select>
              </label>
            </div>

            <div className="capabilities-catalog-grid">
              {controller.connections.availableCatalogItems.map(
                ({ item, alreadyAdded }) => (
                  <article key={item.id} className="capabilities-catalog-card">
                    <div className="capabilities-catalog-card-head">
                      <span
                        className="capabilities-provider-badge"
                        style={{ color: providerAccent(item.provider) }}
                      >
                        {item.name.slice(0, 1)}
                      </span>
                      <div>
                        <strong>{item.name}</strong>
                        <small>{item.popularityLabel}</small>
                      </div>
                    </div>
                    <p>{item.description}</p>
                    <div className="capabilities-chip-row">
                      {item.scopes.slice(0, 3).map((scope) => (
                        <span key={scope} className="capabilities-chip">
                          {humanize(scope)}
                        </span>
                      ))}
                    </div>
                    <div className="capabilities-action-row">
                      <button
                        type="button"
                        className="capabilities-primary-button"
                        onClick={() =>
                          controller.connections.addCatalogConnection(item)
                        }
                        disabled={alreadyAdded}
                      >
                        {alreadyAdded ? "Added" : "Add to workspace"}
                      </button>
                    </div>
                  </article>
                ),
              )}
            </div>
          </div>
        </div>
      ) : null}

      {controller.connections.customModalOpen ? (
        <div className="capabilities-modal-backdrop" role="presentation">
          <div
            className="capabilities-modal"
            role="dialog"
            aria-modal="true"
            aria-label="Add custom connection"
          >
            <div className="capabilities-modal-head">
              <div>
                <h2>Add custom connection</h2>
                <p>
                  Register a remote MCP or local adapter surface so teams can
                  design around it before the runtime is fully wired.
                </p>
              </div>
              <button
                type="button"
                className="capabilities-icon-button"
                onClick={() => controller.connections.setCustomModalOpen(false)}
                aria-label="Close custom connection modal"
              >
                <XIcon />
              </button>
            </div>

            <div className="capabilities-form-grid">
              <label>
                Name
                <input
                  value={controller.connections.customName}
                  onChange={(event) =>
                    controller.connections.setCustomName(event.target.value)
                  }
                  placeholder="GitHub Enterprise"
                />
              </label>
              <label>
                Remote MCP server URL
                <input
                  value={controller.connections.customUrl}
                  onChange={(event) =>
                    controller.connections.setCustomUrl(event.target.value)
                  }
                  placeholder="https://mcp.example.com"
                />
              </label>
              <label>
                Category
                <select
                  value={controller.connections.customCategory}
                  onChange={(event) =>
                    controller.connections.setCustomCategory(
                      event.target.value as ConnectorSummary["category"],
                    )
                  }
                >
                  <option value="developer">Developer</option>
                  <option value="communication">Communication</option>
                  <option value="productivity">Productivity</option>
                  <option value="storage">Storage</option>
                </select>
              </label>
              <label className="is-wide">
                Description
                <textarea
                  value={controller.connections.customDescription}
                  onChange={(event) =>
                    controller.connections.setCustomDescription(event.target.value)
                  }
                />
              </label>
              <label className="is-wide">
                Scopes
                <input
                  value={controller.connections.customScopes}
                  onChange={(event) =>
                    controller.connections.setCustomScopes(event.target.value)
                  }
                  placeholder="tools.invoke, resources.read"
                />
              </label>
            </div>

            <div className="capabilities-inline-note">
              Only register custom connections from developers you trust. A
              staged connection does not grant runtime execution until an
              adapter is installed and policy allows it.
            </div>

            <div className="capabilities-modal-actions">
              <button
                type="button"
                className="capabilities-secondary-button"
                onClick={() => controller.connections.setCustomModalOpen(false)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="capabilities-primary-button"
                onClick={controller.connections.createCustomConnection}
              >
                Add connection
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
