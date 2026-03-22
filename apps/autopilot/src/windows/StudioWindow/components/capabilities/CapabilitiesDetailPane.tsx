import {
  GoogleWorkspaceConnectorPanel,
  MailConnectorPanel,
  type ConnectorSummary,
} from "@ioi/agent-ide";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  connectorStatusLabel,
  formatAuthMode,
  formatSuccessRate,
  humanize,
} from "./model";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { DetailDocument } from "./ui";

const MarkdownRenderer = ReactMarkdown as any;

interface CapabilitiesDetailPaneProps {
  controller: CapabilitiesController;
  getConnectorPolicySummary?: (
    connector: ConnectorSummary,
  ) => { headline: string; detail: string } | null;
  onOpenPolicyCenter?: (connector: ConnectorSummary) => void;
}

function SkillDetailPane({
  controller,
}: {
  controller: CapabilitiesController;
}) {
  const selectedSkill = controller.skills.selectedSkill;
  if (!selectedSkill) {
    return (
      <div className="capabilities-empty-detail">
        Select a skill to inspect its procedure, tools, and benchmark posture.
      </div>
    );
  }

  const enabled = controller.skills.enabledSkills[selectedSkill.hash] ?? true;
  const sectionTitle =
    controller.skills.detailSection === "guide"
      ? "SKILL.md"
      : humanize(controller.skills.detailSection);
  const sectionSummary =
    controller.skills.detailSection === "overview"
      ? "Benchmark posture, tool bundle, and readiness for worker attachment."
      : controller.skills.detailSection === "procedure"
        ? "Observed or published execution flow for this reusable behavior."
        : "Primary markdown instructions used when the worker invokes this skill.";
  const sectionMeta =
    controller.skills.detailSection === "guide"
      ? "Markdown"
      : controller.skills.detailSection === "procedure"
        ? `${selectedSkill.detail.steps.length || 1} steps`
        : `${selectedSkill.detail.used_tools.length} tools`;

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">
            {selectedSkill.origin === "starter" ? "Starter skill" : "Runtime skill"}
          </span>
          <h2>{selectedSkill.catalog.name}</h2>
        </div>
        <label className="capabilities-switch">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) =>
              controller.skills.setEnabledSkills((current) => ({
                ...current,
                [selectedSkill.hash]: event.target.checked,
              }))
            }
          />
          <span>{enabled ? "Enabled" : "Disabled"}</span>
        </label>
      </header>

      <div className="capabilities-detail-inline-meta">
        <span>
          Added by <strong>{selectedSkill.addedBy}</strong>
        </span>
        <span>
          Invoked by <strong>{selectedSkill.invokedBy}</strong>
        </span>
        <span>
          Status <strong>{humanize(selectedSkill.catalog.lifecycle_state)}</strong>
        </span>
        <span>
          Success{" "}
          <strong>
            {formatSuccessRate(selectedSkill.detail.benchmark.success_rate_bps)}
          </strong>
        </span>
      </div>

      <p className="capabilities-detail-summary">
        {selectedSkill.catalog.description}
      </p>

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.skills.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
              <span>{selectedSkill.detail.used_tools.length} tools</span>
            </div>
            <div className="capabilities-detail-meta-grid capabilities-detail-meta-grid-compact">
              <article>
                <span>Sample size</span>
                <strong>{selectedSkill.detail.benchmark.sample_size}</strong>
              </article>
              <article>
                <span>Avg latency</span>
                <strong>{selectedSkill.detail.benchmark.avg_latency_ms} ms</strong>
              </article>
              <article>
                <span>Policy incidents</span>
                <strong>
                  {selectedSkill.detail.benchmark.policy_incident_rate_bps} bps
                </strong>
              </article>
            </div>
            <div className="capabilities-chip-row">
              {selectedSkill.detail.used_tools.map((toolName) => (
                <span key={toolName} className="capabilities-chip">
                  {toolName}
                </span>
              ))}
            </div>
          </section>
        ) : null}

        {controller.skills.detailSection === "procedure" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Procedure</h3>
              <span>{selectedSkill.detail.steps.length} steps</span>
            </div>
            <ol className="capabilities-step-list">
              {selectedSkill.detail.steps.length > 0 ? (
                selectedSkill.detail.steps.map((step) => (
                  <li key={`${step.tool_name}-${step.index}`}>
                    <strong>{step.tool_name}</strong>
                    <span>{step.target}</span>
                  </li>
                ))
              ) : (
                <li>
                  <strong>Published macro</strong>
                  <span>
                    This skill ships without a step-by-step trace in the local
                    runtime.
                  </span>
                </li>
              )}
            </ol>
          </section>
        ) : null}

        {controller.skills.detailSection === "guide" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Guide</h3>
              <span>Spec-aligned reusable behavior</span>
            </div>
            <div className="capabilities-markdown">
              <MarkdownRenderer remarkPlugins={[remarkGfm]}>
                {selectedSkill.detail.markdown ||
                  `# ${selectedSkill.catalog.name}\n\n${selectedSkill.catalog.description}`}
              </MarkdownRenderer>
            </div>
          </section>
        ) : null}
      </DetailDocument>
    </div>
  );
}

function ConnectionDetailPane({
  controller,
  getConnectorPolicySummary,
  onOpenPolicyCenter,
}: CapabilitiesDetailPaneProps) {
  const selectedConnectionRecord = controller.connections.selectedRecord;
  if (!selectedConnectionRecord) {
    return (
      <div className="capabilities-empty-detail">
        Select a connection to inspect auth state, policy posture, and setup
        flows.
      </div>
    );
  }

  const { connector, origin } = selectedConnectionRecord;
  const policySummary = getConnectorPolicySummary?.(connector) ?? null;
  const sectionTitle = humanize(controller.connections.detailSection);
  const sectionSummary =
    controller.connections.detailSection === "overview"
      ? "Reach, scopes, and current notes for this authenticated surface."
      : controller.connections.detailSection === "setup"
        ? "Attach auth, finish adapter wiring, or stage the connector for runtime use."
        : "Governance and approval controls applied to this connection.";
  const sectionMeta =
    controller.connections.detailSection === "overview"
      ? `${connector.scopes.length} scopes`
      : controller.connections.detailSection === "setup"
        ? origin === "workspace"
          ? "Planned"
          : "Live"
        : "Guardrails";

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">{humanize(connector.category)}</span>
          <h2>{connector.name}</h2>
        </div>
        <span className={`capabilities-pill status-${connector.status}`}>
          {origin === "workspace"
            ? "Staged"
            : connectorStatusLabel(connector.status)}
        </span>
      </header>

      <div className="capabilities-detail-inline-meta">
        <span>
          Provider <strong>{connector.provider}</strong>
        </span>
        <span>
          Category <strong>{humanize(connector.category)}</strong>
        </span>
        <span>
          Auth <strong>{formatAuthMode(connector.authMode)}</strong>
        </span>
        <span>
          Scopes <strong>{connector.scopes.length}</strong>
        </span>
      </div>

      <p className="capabilities-detail-summary">{connector.description}</p>

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.connections.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
              <span>{connector.scopes.length} scopes</span>
            </div>
            <div className="capabilities-chip-row">
              {connector.scopes.map((scope: string) => (
                <span key={scope} className="capabilities-chip">
                  {humanize(scope)}
                </span>
              ))}
            </div>
            {connector.notes ? (
              <p className="capabilities-inline-note">{connector.notes}</p>
            ) : null}
          </section>
        ) : null}

        {controller.connections.detailSection === "policy" ? (
          policySummary ? (
            <section className="capabilities-detail-card capabilities-policy-card">
              <div className="capabilities-detail-card-head">
                <h3>Policy</h3>
                <button
                  type="button"
                  className="capabilities-inline-button"
                  onClick={() => onOpenPolicyCenter?.(connector)}
                >
                  Open policy
                </button>
              </div>
              <strong>{policySummary.headline}</strong>
              <p>{policySummary.detail}</p>
            </section>
          ) : (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Policy</h3>
              </div>
              <p>
                No connection-specific policy summary is available yet for this
                surface.
              </p>
            </section>
          )
        ) : null}

        {controller.connections.detailSection === "setup" ? (
          origin === "runtime" && connector.pluginId === "google_workspace" ? (
            <GoogleWorkspaceConnectorPanel
              runtime={controller.runtime}
              connector={connector}
              onConfigured={controller.connections.applyConfiguredConnectorResult}
              onOpenPolicyCenter={onOpenPolicyCenter}
              policySummary={policySummary ?? undefined}
            />
          ) : origin === "runtime" && connector.id === "mail.primary" ? (
            <MailConnectorPanel mail={controller.mail} />
          ) : (
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Setup</h3>
                <span>{origin === "workspace" ? "Planned" : "Available"}</span>
              </div>
              <p>
                {origin === "workspace"
                  ? "This connection is staged in the workspace shell so teams can design around it before the adapter ships."
                  : "This connection exposes a generic runtime surface. Configure it to attach auth and unlock its callable actions."}
              </p>
              <div className="capabilities-action-row">
                {origin === "runtime" ? (
                  <button
                    type="button"
                    className="capabilities-primary-button"
                    disabled={controller.connections.genericConnectorBusy}
                    onClick={() =>
                      void controller.connections.runGenericConnectorSetup(
                        connector,
                      )
                    }
                  >
                    {controller.connections.genericConnectorBusy
                      ? "Connecting..."
                      : "Connect"}
                  </button>
                ) : null}
                <button
                  type="button"
                  className="capabilities-secondary-button"
                  onClick={() => onOpenPolicyCenter?.(connector)}
                >
                  Open policy
                </button>
              </div>
              {controller.connections.genericConnectorMessage ? (
                <p className="capabilities-inline-note">
                  {controller.connections.genericConnectorMessage}
                </p>
              ) : null}
            </section>
          )
        ) : null}
      </DetailDocument>
    </div>
  );
}

function ExtensionDetailPane({
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

export function CapabilitiesDetailPane(props: CapabilitiesDetailPaneProps) {
  const { controller } = props;

  return (
    <section className="capabilities-detail-pane">
      {controller.surface === "skills" ? (
        <SkillDetailPane controller={controller} />
      ) : null}
      {controller.surface === "connections" ? (
        <ConnectionDetailPane {...props} />
      ) : null}
      {controller.surface === "extensions" ? (
        <ExtensionDetailPane controller={controller} />
      ) : null}
    </section>
  );
}
