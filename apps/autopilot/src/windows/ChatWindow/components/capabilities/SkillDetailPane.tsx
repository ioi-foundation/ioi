import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { formatSuccessRate, humanize } from "./model";
import { CapabilityAuthoritySection } from "./CapabilityAuthoritySection";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { DetailDocument } from "./ui";

const MarkdownRenderer = ReactMarkdown as any;

export function SkillDetailPane({
  controller,
  onOpenPolicyCenter,
  onOpenSettings,
}: {
  controller: CapabilitiesController;
  onOpenPolicyCenter?: () => void;
  onOpenSettings?: () => void;
}) {
  const selectedSkill = controller.skills.selectedSkill;
  if (!selectedSkill) {
    return (
      <div className="capabilities-empty-detail">
        {controller.skills.loading
          ? "Loading runtime and filesystem skill inventory..."
          : controller.skills.error
            ? `Skill inventory unavailable: ${controller.skills.error}`
            : "Select a skill to inspect its procedure, provenance, and benchmark posture."}
      </div>
    );
  }

  const isFilesystem = selectedSkill.origin === "filesystem";
  const selectedSourceRecord = controller.skills.selectedSourceRecord;
  const registryEntry = controller.skills.selectedRegistryEntry;
  const detail = selectedSkill.detail;
  const detailPending =
    !isFilesystem &&
    (selectedSkill.detailStatus === "idle" ||
      selectedSkill.detailStatus === "loading");
  const detailUnavailable =
    !isFilesystem && (selectedSkill.detailStatus === "error" || detail === null);
  const readyDetail = !detailPending && !detailUnavailable ? detail : null;
  const sectionTitle =
    controller.skills.detailSection === "guide"
      ? "SKILL.md"
      : isFilesystem && controller.skills.detailSection === "procedure"
        ? "Selection"
        : humanize(controller.skills.detailSection);
  const sectionSummary =
    isFilesystem
      ? controller.skills.detailSection === "overview"
        ? "Filesystem-backed skill provenance, source sync posture, and how the runtime can discover this behavior."
        : controller.skills.detailSection === "procedure"
          ? "Why this discovered skill is available for future runtime selection even before benchmark evidence exists."
          : "Filesystem-backed instructions discovered from the local source registry or a local extension manifest."
      : detailPending
      ? "Loading live skill detail, procedure, and benchmark evidence from the runtime."
      : detailUnavailable
        ? "Live skill detail is unavailable right now. Only catalog-level metadata is currently available."
      : controller.skills.detailSection === "overview"
      ? "Benchmark posture, tool bundle, and readiness for worker attachment."
      : controller.skills.detailSection === "procedure"
        ? "Observed or published execution flow for this reusable behavior."
        : "Primary markdown instructions used when the worker invokes this skill.";
  const sectionMeta =
    isFilesystem
      ? controller.skills.detailSection === "guide"
        ? selectedSkill.relativePath ?? "Filesystem"
        : controller.skills.detailSection === "procedure"
          ? humanize(selectedSkill.syncStatus ?? "ready")
          : selectedSkill.sourceLabel ?? "Filesystem"
      : detailPending
      ? "Loading"
      : detailUnavailable
        ? "Unavailable"
        : readyDetail
          ? controller.skills.detailSection === "guide"
            ? "Markdown"
            : controller.skills.detailSection === "procedure"
              ? `${readyDetail.steps.length || 1} steps`
              : `${readyDetail.used_tools.length} tools`
          : "Unavailable";

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">
            {isFilesystem ? "Filesystem skill" : "Runtime skill"}
          </span>
          <h2>{selectedSkill.catalog.name}</h2>
        </div>
        <span className="capabilities-pill">
          {isFilesystem
            ? selectedSourceRecord
              ? selectedSourceRecord.enabled
                ? "Source enabled"
                : "Source disabled"
              : humanize(selectedSkill.syncStatus ?? "filesystem")
            : humanize(selectedSkill.catalog.lifecycle_state)}
        </span>
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
        {registryEntry ? (
          <span>
            Authority <strong>{registryEntry.authority.tierLabel}</strong>
          </span>
        ) : null}
        {selectedSkill.sourceKind ? (
          <span>
            Source kind <strong>{humanize(selectedSkill.sourceKind)}</strong>
          </span>
        ) : null}
        {selectedSkill.syncStatus ? (
          <span>
            Source sync <strong>{humanize(selectedSkill.syncStatus)}</strong>
          </span>
        ) : null}
        {selectedSkill.relativePath ? (
          <span>
            Path <strong>{selectedSkill.relativePath}</strong>
          </span>
        ) : null}
        {selectedSkill.extensionDisplayName ? (
          <span>
            Extension <strong>{selectedSkill.extensionDisplayName}</strong>
          </span>
        ) : null}
        {!isFilesystem && detail ? (
          <span>
            Success{" "}
            <strong>{formatSuccessRate(detail.benchmark.success_rate_bps)}</strong>
          </span>
        ) : null}
        {!isFilesystem && detailPending ? (
          <span>
            Live detail <strong>Loading</strong>
          </span>
        ) : null}
        {!isFilesystem && selectedSkill.detailStatus === "error" ? (
          <span>
            Live detail <strong>Unavailable</strong>
          </span>
        ) : null}
        {!isFilesystem && detail?.source_registry_kind ? (
          <span>
            Source kind <strong>{humanize(detail.source_registry_kind)}</strong>
          </span>
        ) : null}
        {!isFilesystem && detail?.source_registry_sync_status ? (
          <span>
            Source sync <strong>{humanize(detail.source_registry_sync_status)}</strong>
          </span>
        ) : null}
      </div>

      <p className="capabilities-detail-summary">
        {selectedSkill.catalog.description}
      </p>

      {isFilesystem && controller.skills.sourceMessage ? (
        <p className="capabilities-inline-note">
          {controller.skills.sourceMessage}
        </p>
      ) : null}
      {isFilesystem && controller.skills.sourceError ? (
        <p className="capabilities-inline-note">
          {controller.skills.sourceError}
        </p>
      ) : null}

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.skills.detailSection === "overview" && registryEntry ? (
          <CapabilityAuthoritySection
            currentEntry={registryEntry}
            authority={registryEntry.authority}
            lease={registryEntry.lease}
            comparisonPool={controller.registry.snapshot?.entries}
            relatedGoverningEntries={controller.registry.getRelatedGoverningEntries(
              registryEntry.entryId,
            )}
            onPlanWiderLeaseProposal={
              isFilesystem
                ? (comparisonEntryId) =>
                    controller.skills.planSelectedSkillGovernanceProposal(
                      comparisonEntryId,
                    )
                : undefined
            }
            onRequestWiderLease={
              isFilesystem
                ? (request) =>
                    controller.skills.requestSelectedSkillPolicyIntent(
                      "widen",
                      request,
                    )
                : undefined
            }
            onReturnToBaseline={
              isFilesystem
                ? () => controller.skills.requestSelectedSkillPolicyIntent("baseline")
                : undefined
            }
            onOpenPolicyCenter={onOpenPolicyCenter}
            onOpenRelatedEntry={(entryId) =>
              controller.registry.openEntry(entryId)
            }
            onOpenRelatedPolicy={(entryId) =>
              controller.registry.openEntry(entryId, {
                openPolicyCenter: true,
              })
            }
            sourceNote={
              selectedSkill.origin === "runtime"
                ? "This runtime skill stays selection-scoped; execution authority is inherited from the leased substrates it calls into."
                : selectedSkill.extensionDisplayName
                  ? `This filesystem skill inherits authority from the packaged extension ${selectedSkill.extensionDisplayName}.`
                  : selectedSkill.sourceLabel
                    ? `This filesystem skill inherits authority from the tracked source ${selectedSkill.sourceLabel}.`
                    : `This filesystem skill inherits authority from ${registryEntry.sourceLabel}.`
            }
          />
        ) : null}

        {isFilesystem ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Source management</h3>
              <span>
                {selectedSourceRecord
                  ? humanize(selectedSourceRecord.syncStatus)
                  : humanize(selectedSkill.sourceKind ?? "filesystem")}
              </span>
            </div>
            {selectedSourceRecord ? (
              <>
                <p className="capabilities-inline-note">
                  This filesystem skill is indexed from{" "}
                  <strong>{selectedSourceRecord.label}</strong> and can be
                  synced or enabled here without leaving Capabilities.
                </p>
                <div className="capabilities-detail-actions">
                  <button
                    type="button"
                    className="capabilities-secondary-button"
                    onClick={() => controller.skills.syncSelectedSource()}
                    disabled={controller.skills.sourceBusy}
                  >
                    {controller.skills.sourceBusy ? "Working..." : "Sync source"}
                  </button>
                  <button
                    type="button"
                    className="capabilities-primary-button"
                    onClick={() =>
                      controller.skills.toggleSelectedSourceEnabled()
                    }
                    disabled={controller.skills.sourceBusy}
                  >
                    {selectedSourceRecord.enabled
                      ? "Disable source"
                      : "Enable source"}
                  </button>
                  {onOpenSettings ? (
                    <button
                      type="button"
                      className="capabilities-secondary-button"
                      onClick={onOpenSettings}
                      disabled={controller.skills.sourceBusy}
                    >
                      Open Settings
                    </button>
                  ) : null}
                </div>
              </>
            ) : (
              <>
                <p className="capabilities-inline-note">
                  This skill is discoverable from an ambient filesystem root such
                  as the workspace or home plugin directory. Register that root as
                  a source if you want direct enable/disable controls.
                </p>
                {onOpenSettings ? (
                  <div className="capabilities-detail-actions">
                    <button
                      type="button"
                      className="capabilities-secondary-button"
                      onClick={onOpenSettings}
                    >
                      Open Settings
                    </button>
                  </div>
                ) : null}
              </>
            )}
          </section>
        ) : null}

        {isFilesystem && controller.skills.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
              <span>{selectedSkill.sourceLabel ?? "Filesystem source"}</span>
            </div>
            <div className="capabilities-detail-inline-meta">
              <span>
                Source <strong>{selectedSkill.sourceLabel ?? "Filesystem"}</strong>
              </span>
              <span>
                Sync <strong>{humanize(selectedSkill.syncStatus ?? "ready")}</strong>
              </span>
              <span>
                Type <strong>{humanize(selectedSkill.sourceKind ?? "filesystem")}</strong>
              </span>
            </div>
            {selectedSkill.sourceUri ? (
              <p className="capabilities-inline-note">
                Source root: <strong>{selectedSkill.sourceUri}</strong>
              </p>
            ) : null}
            {selectedSkill.relativePath ? (
              <p className="capabilities-inline-note">
                Relative path: <strong>{selectedSkill.relativePath}</strong>
              </p>
            ) : null}
          </section>
        ) : null}

        {isFilesystem && controller.skills.detailSection === "guide" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Filesystem guide</h3>
              <span>On disk</span>
            </div>
            <p className="capabilities-inline-note">
              This skill is discoverable from the filesystem inventory even though
              the runtime has not published a benchmarked detail record yet.
            </p>
            {selectedSkill.relativePath ? (
              <p className="capabilities-inline-note">
                Inspect the source `SKILL.md` at <strong>{selectedSkill.relativePath}</strong>.
              </p>
            ) : null}
          </section>
        ) : null}

        {isFilesystem && controller.skills.detailSection === "procedure" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Selection readiness</h3>
              <span>{humanize(selectedSkill.syncStatus ?? "ready")}</span>
            </div>
            <p className="capabilities-inline-note">
              Filesystem-backed skills become runtime-selectable once their source
              stays enabled and the runtime attaches or publishes the same behavior.
            </p>
            {selectedSkill.extensionDisplayName ? (
              <p className="capabilities-inline-note">
                This skill is packaged by <strong>{selectedSkill.extensionDisplayName}</strong>.
              </p>
            ) : null}
          </section>
        ) : null}

        {detailPending ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Loading live detail</h3>
              <span>Runtime</span>
            </div>
            <p className="capabilities-inline-note">
              Fetching benchmark posture, procedure trace, and markdown instructions
              from the live skill runtime.
            </p>
          </section>
        ) : null}

        {selectedSkill.detailStatus === "error" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Live detail unavailable</h3>
              <button
                type="button"
                className="capabilities-secondary-button"
                onClick={() => controller.skills.retrySelectedSkillDetail()}
              >
                Retry
              </button>
            </div>
            <p className="capabilities-inline-note">
              The live skill catalog loaded, but the runtime detail fetch failed.
            </p>
            {selectedSkill.detailError ? (
              <p className="capabilities-inline-note">
                Error: <strong>{selectedSkill.detailError}</strong>
              </p>
            ) : null}
          </section>
        ) : null}

        {readyDetail && controller.skills.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
              <span>{readyDetail.used_tools.length} tools</span>
            </div>
            <div className="capabilities-detail-meta-grid capabilities-detail-meta-grid-compact">
              <article>
                <span>Sample size</span>
                <strong>{readyDetail.benchmark.sample_size}</strong>
              </article>
              <article>
                <span>Avg latency</span>
                <strong>{readyDetail.benchmark.avg_latency_ms} ms</strong>
              </article>
              <article>
                <span>Policy incidents</span>
                <strong>{readyDetail.benchmark.policy_incident_rate_bps} bps</strong>
              </article>
            </div>
            <div className="capabilities-chip-row">
              {readyDetail.used_tools.map((toolName) => (
                <span key={toolName} className="capabilities-chip">
                  {toolName}
                </span>
              ))}
            </div>
            {readyDetail.source_registry_label ? (
              <p className="capabilities-inline-note">
                Source registry: <strong>{readyDetail.source_registry_label}</strong>
                {readyDetail.source_registry_relative_path
                  ? ` · ${readyDetail.source_registry_relative_path}`
                  : ""}
                {readyDetail.source_registry_uri
                  ? ` · ${readyDetail.source_registry_uri}`
                  : ""}
              </p>
            ) : null}
          </section>
        ) : null}

        {readyDetail && controller.skills.detailSection === "procedure" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Procedure</h3>
              <span>{readyDetail.steps.length} steps</span>
            </div>
            <ol className="capabilities-step-list">
              {readyDetail.steps.length > 0 ? (
                readyDetail.steps.map((step) => (
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

        {readyDetail && controller.skills.detailSection === "guide" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Guide</h3>
              <span>Spec-aligned reusable behavior</span>
            </div>
            <div className="capabilities-markdown">
              <MarkdownRenderer remarkPlugins={[remarkGfm]}>
                {readyDetail.markdown}
              </MarkdownRenderer>
            </div>
          </section>
        ) : null}
      </DetailDocument>
    </div>
  );
}
