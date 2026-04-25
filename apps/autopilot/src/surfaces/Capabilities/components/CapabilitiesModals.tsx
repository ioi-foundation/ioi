import type { ConnectorSummary } from "@ioi/agent-ide";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { XIcon } from "./ui";

export function CapabilitiesModals({
  controller,
}: {
  controller: CapabilitiesController;
}) {
  return (
    <>
      {controller.connections.customModalOpen ? (
        <div className="capabilities-modal-backdrop" role="presentation">
          <div
            className="capabilities-modal"
            role="dialog"
            aria-modal="true"
            aria-label="Add workspace planning template"
          >
            <div className="capabilities-modal-head">
              <div>
                <h2>Add workspace planning template</h2>
                <p>
                  Document a remote MCP or local adapter plan in the workspace
                  planning lane. This does not create a live connector or bind
                  runtime execution.
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
              Only record planning templates from developers you trust. A
              planning template stays outside the live connector catalog until a
              real adapter is added and policy allows execution.
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
                Save template
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
