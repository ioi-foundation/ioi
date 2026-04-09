import { useState } from "react";
import { openPath, revealItemInDir } from "@tauri-apps/plugin-opener";
import { buildExtensionTrustProfile, humanize } from "./model";
import { CapabilityAuthoritySection } from "./CapabilityAuthoritySection";
import { type CapabilitiesController } from "./useCapabilitiesController";
import { DetailDocument } from "./ui";

function resolveContributionPath(
  rootPath: string,
  contributionPath: string | null | undefined,
): string | null {
  const normalizedPath = contributionPath?.trim().replace(/\\/g, "/") ?? "";
  if (!normalizedPath) {
    return null;
  }
  if (normalizedPath.startsWith("/") || /^[A-Za-z]:\//.test(normalizedPath)) {
    return normalizedPath;
  }
  const normalizedRoot = rootPath.replace(/\\/g, "/").replace(/\/+$/, "");
  return `${normalizedRoot}/${normalizedPath.replace(/^\.?\//, "")}`;
}

export function ExtensionDetailPane({
  controller,
  onOpenPolicyCenter,
  onOpenSettings,
}: {
  controller: CapabilitiesController;
  onOpenPolicyCenter?: () => void;
  onOpenSettings?: () => void;
}) {
  const selectedExtension = controller.extensions.selectedExtension;
  const selectedSourceRecord = controller.extensions.selectedSourceRecord;
  const [pathActionError, setPathActionError] = useState<string | null>(null);
  if (!selectedExtension) {
    return (
      <div className="capabilities-empty-detail">
        Select an extension manifest to inspect its provenance, policy posture, and packaged contributions.
      </div>
    );
  }

  const sectionTitle =
    controller.extensions.detailSection === "manifest"
      ? "Manifest"
      : controller.extensions.detailSection === "contributions"
        ? "Contributions"
        : "Overview";
  const sectionSummary =
    controller.extensions.detailSection === "manifest"
      ? "Declared package identity, display metadata, prompts, and source files discovered on disk."
      : controller.extensions.detailSection === "contributions"
        ? "What this manifest contributes: filesystem skills, MCP servers, hooks, apps, and declared capability surfaces."
      : "How this local extension fits into the runtime-backed extensibility model.";
  const sectionMeta =
    controller.extensions.detailSection === "manifest"
      ? selectedExtension.version
        ? `v${selectedExtension.version}`
        : selectedExtension.manifestKind
      : controller.extensions.detailSection === "contributions"
        ? `${selectedExtension.contributionCount} items`
        : selectedExtension.statusLabel;

  const runPathAction = async (action: () => Promise<void>) => {
    setPathActionError(null);
    try {
      await action();
    } catch (error) {
      setPathActionError(String(error));
    }
  };
  const registryEntry = controller.extensions.selectedRegistryEntry;
  const trustProfile = buildExtensionTrustProfile(selectedExtension);

  return (
    <div className="capabilities-detail-scroll">
      <header className="capabilities-detail-header">
        <div>
          <span className="capabilities-kicker">
            {selectedExtension.sourceLabel} · {humanize(selectedExtension.sourceKind)}
          </span>
          <h2>{selectedExtension.name}</h2>
        </div>
        <span className="capabilities-pill">{selectedExtension.statusLabel}</span>
      </header>

      <div className="capabilities-detail-inline-meta">
        <span>
          Source <strong>{selectedExtension.sourceLabel}</strong>
        </span>
        <span>
          Authority{" "}
          <strong>{registryEntry?.authority.tierLabel ?? trustProfile.tierLabel}</strong>
        </span>
        <span>
          Profile{" "}
          <strong>
            {registryEntry?.authority.governedProfileLabel ??
              trustProfile.governedProfileLabel}
          </strong>
        </span>
        <span>
          Contributions <strong>{selectedExtension.contributionCount}</strong>
        </span>
        <span>
          Filesystem skills <strong>{selectedExtension.filesystemSkillCount}</strong>
        </span>
      </div>

      <p className="capabilities-detail-summary">
        {selectedExtension.description}
      </p>

      {controller.extensions.sourceMessage ? (
        <p className="capabilities-inline-note">
          {controller.extensions.sourceMessage}
        </p>
      ) : null}
      {controller.extensions.sourceError ? (
        <p className="capabilities-inline-note">
          {controller.extensions.sourceError}
        </p>
      ) : null}
      {pathActionError ? (
        <p className="capabilities-inline-note">
          Path action unavailable: <strong>{pathActionError}</strong>
        </p>
      ) : null}

      <DetailDocument
        title={sectionTitle}
        summary={sectionSummary}
        meta={<span className="capabilities-pill">{sectionMeta}</span>}
      >
        {controller.extensions.detailSection === "overview" ? (
          registryEntry ? (
            <CapabilityAuthoritySection
              currentEntry={registryEntry}
              authority={registryEntry.authority}
              lease={registryEntry.lease}
              comparisonPool={controller.registry.snapshot?.entries}
              relatedGoverningEntries={controller.registry.getRelatedGoverningEntries(
                registryEntry.entryId,
              )}
              onPlanWiderLeaseProposal={(comparisonEntryId) =>
                controller.extensions.planSelectedExtensionGovernanceProposal(
                  comparisonEntryId,
                )
              }
              onRequestWiderLease={(request) =>
                controller.extensions.requestSelectedExtensionPolicyIntent(
                  "widen",
                  request,
                )
              }
              onReturnToBaseline={() =>
                controller.extensions.requestSelectedExtensionPolicyIntent("baseline")
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
              sourceNote={`This extension authority is resolved from ${registryEntry.sourceLabel}.`}
            />
          ) : (
            <section className="capabilities-detail-card capabilities-trust-card">
              <div className="capabilities-detail-card-head">
                <h3>Authority tier</h3>
                <span>{humanize(selectedExtension.trustPosture)}</span>
              </div>
              <div className="capabilities-trust-tier-line">
                <div className="capabilities-trust-tier-copy">
                  <strong>{trustProfile.tierLabel}</strong>
                  <span>{trustProfile.summary}</span>
                </div>
                <span className="capabilities-trust-tier-badge">
                  {trustProfile.governedProfileLabel}
                </span>
              </div>
              <p className="capabilities-trust-detail">{trustProfile.detail}</p>
              <div className="capabilities-trust-signal-list">
                {trustProfile.signals.map((signal) => (
                  <span key={signal} className="capabilities-trust-signal">
                    {signal}
                  </span>
                ))}
              </div>
            </section>
          )
        ) : null}

        {controller.extensions.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Source management</h3>
              <span>
                {selectedSourceRecord
                  ? humanize(selectedSourceRecord.syncStatus)
                  : humanize(selectedExtension.sourceKind)}
              </span>
            </div>
            {selectedSourceRecord ? (
              <>
                <p className="capabilities-inline-note">
                  This manifest is indexed from{" "}
                  <strong>{selectedSourceRecord.label}</strong> and can be synced
                  or governed here without leaving the extension inventory.
                </p>
                <div className="capabilities-detail-actions">
                  <button
                    type="button"
                    className="capabilities-secondary-button"
                    onClick={() => controller.extensions.syncSelectedSource()}
                    disabled={controller.extensions.sourceBusy}
                  >
                    {controller.extensions.sourceBusy ? "Working..." : "Sync source"}
                  </button>
                  <button
                    type="button"
                    className="capabilities-primary-button"
                    onClick={() =>
                      controller.extensions.toggleSelectedSourceEnabled()
                    }
                    disabled={controller.extensions.sourceBusy}
                    >
                      {selectedSourceRecord.enabled
                      ? "Disable source"
                      : "Enable source"}
                  </button>
                  <button
                    type="button"
                    className="capabilities-secondary-button"
                    onClick={() => controller.extensions.removeSelectedSource()}
                    disabled={controller.extensions.sourceBusy}
                  >
                    Remove source
                  </button>
                  {onOpenSettings ? (
                    <button
                      type="button"
                      className="capabilities-secondary-button"
                      onClick={onOpenSettings}
                      disabled={controller.extensions.sourceBusy}
                    >
                      Open Settings
                    </button>
                  ) : null}
                </div>
              </>
            ) : (
              <>
                <p className="capabilities-inline-note">
                  This manifest comes from an ambient root such as the workspace
                  or home plugin directory. Track this extension root when you
                  want explicit sync, enable, disable, and removal controls.
                </p>
                <div className="capabilities-detail-actions">
                  <button
                    type="button"
                    className="capabilities-primary-button"
                    onClick={() =>
                      controller.extensions.trackSelectedExtensionRoot()
                    }
                    disabled={controller.extensions.sourceBusy}
                  >
                    {controller.extensions.sourceBusy
                      ? "Working..."
                      : "Track extension root"}
                  </button>
                  {onOpenSettings ? (
                    <button
                      type="button"
                      className="capabilities-secondary-button"
                      onClick={onOpenSettings}
                      disabled={controller.extensions.sourceBusy}
                    >
                      Open Settings
                    </button>
                  ) : null}
                </div>
              </>
            )}
          </section>
        ) : null}

        {controller.extensions.detailSection === "overview" ? (
          <section className="capabilities-detail-card">
            <div className="capabilities-detail-card-head">
              <h3>Overview</h3>
              <span>{selectedExtension.meta}</span>
            </div>
            <div className="capabilities-detail-inline-meta">
              <span>
                Manifest <strong>{selectedExtension.manifestKind}</strong>
              </span>
              <span>
                Source enabled <strong>{selectedExtension.enabled ? "Yes" : "No"}</strong>
              </span>
              <span>
                Category <strong>{selectedExtension.category ?? "Unspecified"}</strong>
              </span>
            </div>
            <p className="capabilities-inline-note">
              Manifest path: <strong>{selectedExtension.manifestPath}</strong>
            </p>
            <p className="capabilities-inline-note">
              Root path: <strong>{selectedExtension.rootPath}</strong>
            </p>
            <div className="capabilities-detail-actions">
              <button
                type="button"
                className="capabilities-secondary-button"
                onClick={() =>
                  void runPathAction(() => openPath(selectedExtension.manifestPath))
                }
              >
                Open manifest
              </button>
              <button
                type="button"
                className="capabilities-secondary-button"
                onClick={() =>
                  void runPathAction(() =>
                    revealItemInDir(selectedExtension.manifestPath),
                  )
                }
              >
                Reveal manifest
              </button>
              <button
                type="button"
                className="capabilities-secondary-button"
                onClick={() =>
                  void runPathAction(() => openPath(selectedExtension.rootPath))
                }
              >
                Open extension root
              </button>
            </div>
            {selectedExtension.marketplaceInstallationPolicy ? (
              <p className="capabilities-inline-note">
                Marketplace policy:{" "}
                <strong>{humanize(selectedExtension.marketplaceInstallationPolicy)}</strong>
                {selectedExtension.marketplaceAuthenticationPolicy
                  ? ` · ${humanize(selectedExtension.marketplaceAuthenticationPolicy)}`
                  : ""}
                {selectedExtension.marketplaceDisplayName
                  ? ` · ${selectedExtension.marketplaceDisplayName}`
                  : ""}
              </p>
            ) : null}
          </section>
        ) : null}

        {controller.extensions.detailSection === "manifest" ? (
          <>
            <section className="capabilities-detail-card">
              <div className="capabilities-detail-card-head">
                <h3>Manifest metadata</h3>
                <span>{selectedExtension.manifestKind}</span>
              </div>
              <div className="capabilities-detail-inline-meta">
                <span>
                  Name <strong>{selectedExtension.displayName ?? selectedExtension.name}</strong>
                </span>
                {selectedExtension.version ? (
                  <span>
                    Version <strong>{selectedExtension.version}</strong>
                  </span>
                ) : null}
                {selectedExtension.developerName ? (
                  <span>
                    Developer <strong>{selectedExtension.developerName}</strong>
                  </span>
                ) : null}
                {selectedExtension.license ? (
                  <span>
                    License <strong>{selectedExtension.license}</strong>
                  </span>
                ) : null}
              </div>
            </section>

            {selectedExtension.defaultPrompts.length > 0 ? (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Default prompts</h3>
                  <span>{selectedExtension.defaultPrompts.length} starters</span>
                </div>
                <ol className="capabilities-step-list">
                  {selectedExtension.defaultPrompts.map((prompt) => (
                    <li key={prompt}>
                      <strong>Starter prompt</strong>
                      <span>{prompt}</span>
                    </li>
                  ))}
                </ol>
              </section>
            ) : null}

            {(selectedExtension.surfaces.length > 0 ||
              selectedExtension.keywords.length > 0) ? (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Declared surfaces</h3>
                  <span>
                    {selectedExtension.surfaces.length > 0
                      ? `${selectedExtension.surfaces.length} capabilities`
                      : "Metadata"}
                  </span>
                </div>
                {selectedExtension.surfaces.length > 0 ? (
                  <div className="capabilities-chip-row">
                    {selectedExtension.surfaces.map((surfaceName) => (
                      <span key={surfaceName} className="capabilities-chip">
                        {surfaceName}
                      </span>
                    ))}
                  </div>
                ) : null}
                {selectedExtension.keywords.length > 0 ? (
                  <div className="capabilities-chip-row">
                    {selectedExtension.keywords.map((keyword) => (
                      <span key={keyword} className="capabilities-chip">
                        {keyword}
                      </span>
                    ))}
                  </div>
                ) : null}
              </section>
            ) : null}

            {(selectedExtension.homepage ||
              selectedExtension.repository ||
              selectedExtension.authorEmail ||
              selectedExtension.authorUrl ||
              selectedExtension.authorName) ? (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Links and authorship</h3>
                </div>
                <div className="capabilities-detail-inline-meta">
                  {selectedExtension.authorName ? (
                    <span>
                      Author <strong>{selectedExtension.authorName}</strong>
                    </span>
                  ) : null}
                  {selectedExtension.authorEmail ? (
                    <span>
                      Email <strong>{selectedExtension.authorEmail}</strong>
                    </span>
                  ) : null}
                  {selectedExtension.homepage ? (
                    <span>
                      Homepage <strong>{selectedExtension.homepage}</strong>
                    </span>
                  ) : null}
                  {selectedExtension.repository ? (
                    <span>
                      Repository <strong>{selectedExtension.repository}</strong>
                    </span>
                  ) : null}
                </div>
              </section>
            ) : null}
          </>
        ) : null}

        {controller.extensions.detailSection === "contributions" ? (
          <>
            {selectedExtension.contributions.length > 0 ? (
              selectedExtension.contributions.map((contribution) => {
                const resolvedContributionPath = resolveContributionPath(
                  selectedExtension.rootPath,
                  contribution.path,
                );

                return (
                  <section
                    key={`${selectedExtension.id}:${contribution.kind}:${contribution.path ?? contribution.label}`}
                    className="capabilities-detail-card"
                  >
                    <div className="capabilities-detail-card-head">
                      <h3>{contribution.label}</h3>
                      <span>
                        {contribution.itemCount !== null && contribution.itemCount !== undefined
                          ? `${contribution.itemCount} item${contribution.itemCount === 1 ? "" : "s"}`
                          : contribution.path ?? contribution.kind}
                      </span>
                    </div>
                    {contribution.path ? (
                      <p className="capabilities-inline-note">
                        Path: <strong>{contribution.path}</strong>
                      </p>
                    ) : null}
                    {contribution.detail ? (
                      <p className="capabilities-inline-note">{contribution.detail}</p>
                    ) : null}
                    {resolvedContributionPath ? (
                      <div className="capabilities-detail-actions">
                        <button
                          type="button"
                          className="capabilities-secondary-button"
                          onClick={() =>
                            void runPathAction(() =>
                              openPath(resolvedContributionPath),
                            )
                          }
                        >
                          Open contribution
                        </button>
                        <button
                          type="button"
                          className="capabilities-secondary-button"
                          onClick={() =>
                            void runPathAction(() =>
                              revealItemInDir(resolvedContributionPath),
                            )
                          }
                        >
                          Reveal
                        </button>
                      </div>
                    ) : null}
                  </section>
                );
              })
            ) : (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>No packaged contributions</h3>
                </div>
                <p className="capabilities-inline-note">
                  This manifest currently advertises identity and policy metadata without a declared skills, hooks, MCP, or apps bundle.
                </p>
              </section>
            )}

            {selectedExtension.filesystemSkillCount > 0 ? (
              <section className="capabilities-detail-card">
                <div className="capabilities-detail-card-head">
                  <h3>Filesystem skill payload</h3>
                  <span>{selectedExtension.filesystemSkillCount} skills</span>
                </div>
                <p className="capabilities-inline-note">
                  These skills are also surfaced in the shared skills inventory as filesystem-backed entries.
                </p>
              </section>
            ) : null}
          </>
        ) : null}
      </DetailDocument>
    </div>
  );
}
