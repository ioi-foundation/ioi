import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { formatSuccessRate, humanize } from "./model";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { DetailDocument } from "./ui";

const MarkdownRenderer = ReactMarkdown as any;

export function SkillDetailPane({
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
        {selectedSkill.detail.source_registry_kind ? (
          <span>
            Source kind{" "}
            <strong>{humanize(selectedSkill.detail.source_registry_kind)}</strong>
          </span>
        ) : null}
        {selectedSkill.detail.source_registry_sync_status ? (
          <span>
            Source sync{" "}
            <strong>
              {humanize(selectedSkill.detail.source_registry_sync_status)}
            </strong>
          </span>
        ) : null}
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
            {selectedSkill.detail.source_registry_label ? (
              <p className="capabilities-inline-note">
                Source registry:{" "}
                <strong>{selectedSkill.detail.source_registry_label}</strong>
                {selectedSkill.detail.source_registry_relative_path
                  ? ` · ${selectedSkill.detail.source_registry_relative_path}`
                  : ""}
                {selectedSkill.detail.source_registry_uri
                  ? ` · ${selectedSkill.detail.source_registry_uri}`
                  : ""}
              </p>
            ) : null}
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
