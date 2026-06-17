"use strict";

function createStudioRuntimeCockpitRows({
  STUDIO_RUNTIME_VISIBILITY,
  escapeHtml,
  firstArray,
  getHunkApprovalId,
  getStudioRuntimeProjection,
  safeJsonPreview = (value) => {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value || "");
    }
  },
  studioCommandHeadline,
  stringValue,
}) {
  function projection() {
    return getStudioRuntimeProjection() || {};
  }

  function studioDiffRows() {
    return firstArray(projection().diffHunks).map((hunk, index) => {
      const changeId = stringValue(hunk.changeId || hunk.change_id);
      const hunkIndex = Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index;
      const acceptAvailable = hunk.acceptAvailable ?? hunk.accept_available ?? true;
      const rejectAvailable = hunk.rejectAvailable ?? hunk.reject_available ?? true;
      const rollbackAvailable = hunk.rollbackAvailable ?? hunk.rollback_available ?? false;
      const staleReason = stringValue(hunk.staleReason || hunk.stale_reason);
      return `
    <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
      <header>
        <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
        <code>${escapeHtml(hunk.file || "workspace")}</code>
        <mark>${escapeHtml(hunk.status || "pending")}</mark>
      </header>
      ${hunk.stale && staleReason ? `<p class="studio-diff-hunk__stale">Stale: ${escapeHtml(staleReason)}</p>` : ""}
      <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(hunk.before || "")}</span>
<span class="studio-diff-add">${escapeHtml(hunk.after || "")}</span></pre>
      <footer data-testid="studio-hunk-accept-reject">
        <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
        <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
        ${acceptAvailable ? `<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || getHunkApprovalId())}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Accept hunk</button>` : ""}
        ${rejectAvailable ? `<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || getHunkApprovalId())}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Reject hunk</button>` : ""}
        ${rollbackAvailable ? `<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="${escapeHtml(hunk.approvalId || getHunkApprovalId())}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Roll back hunk</button>` : ""}
      </footer>
    </article>
  `;
    }).join("");
  }

  function studioActionCardRows() {
    return firstArray(projection().actionCards).slice(-6).map((card) => `
    <article class="studio-cockpit-card studio-tool-proposal-card" data-testid="studio-tool-proposal-card" data-tool-id="${escapeHtml(card.toolId || "")}">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(card.status || "pending")}"></span>
        <strong>${escapeHtml(card.title || card.toolId || "Tool proposal")}</strong>
        <mark>${escapeHtml(card.status || "proposed")}</mark>
      </header>
      <p>${escapeHtml(card.detail || "Daemon-projected tool proposal.")}</p>
      ${card.receiptRefs?.length ? `<code>${escapeHtml(card.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
  }

  function studioPolicyLeaseRows() {
    return firstArray(projection().policyLeases).slice(-4).map((lease) => `
    <article
      class="studio-cockpit-card studio-policy-lease-card"
      data-testid="studio-policy-lease-dialog"
      data-lease-status="${escapeHtml(lease.status || "pending")}"
      data-lease-decision="${escapeHtml(lease.decision || "")}"
      data-lease-lifecycle="${escapeHtml(lease.lifecycle || "")}"
      data-lease-did-execute="${lease.didExecute ? "true" : "false"}"
      data-lease-executed-before-expiry="${lease.executedBeforeExpiry ? "true" : "false"}"
      data-lease-after-revoke-blocked="${lease.afterRevokeBlocked ? "true" : "false"}"
      data-lease-after-expiry-blocked="${lease.afterExpiryBlocked ? "true" : "false"}"
    >
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "waiting_for_approval")}"></span>
        <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
        <mark>${escapeHtml(lease.status || "pending")}</mark>
      </header>
      <p>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</p>
      <dl>
        <dt>Action</dt><dd>${escapeHtml(lease.action || "unknown")}</dd>
        <dt>Execution</dt><dd>${escapeHtml(lease.didExecute ? "executed" : "did not execute")}</dd>
        ${lease.decisionLabel || lease.decision ? `<dt>Decision</dt><dd>${escapeHtml(lease.decisionLabel || lease.decision)}</dd>` : ""}
        ${lease.outcome ? `<dt>Outcome</dt><dd>${escapeHtml(lease.outcome)}</dd>` : ""}
        ${lease.ttlLabel ? `<dt>Lease</dt><dd>${escapeHtml(lease.ttlLabel)}</dd>` : ""}
      </dl>
      ${lease.receiptRefs?.length ? `<code>${escapeHtml(lease.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
  }

  function studioCommandOutputRows() {
    return firstArray(projection().commandOutputs).slice(-4).map((command) => {
      const status = command.status || "completed";
      const stdout = command.stdout || command.excerptPreview || command.excerpt_preview || "";
      const resultLabel = command.exitCode === null || command.exitCode === undefined
        ? status
        : `exit ${command.exitCode}`;
      return `
      <article class="studio-cockpit-card studio-command-output-card" data-testid="studio-command-output-card">
        <header>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(status)}"></span>
          <strong>${escapeHtml(studioCommandHeadline(command))}</strong>
          <mark>${escapeHtml(resultLabel || "completed")}</mark>
        </header>
        <pre data-testid="studio-command-stdout">${escapeHtml(stdout || "No output")}</pre>
        ${command.stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(command.stderr)}</pre>` : ""}
      </article>
    `;
    }).join("");
  }

  function studioDiagnosticsRows() {
    return firstArray(projection().diagnosticGates).slice(-4).map((gate) => `
    <article class="studio-cockpit-card studio-diagnostics-gate" data-testid="studio-diagnostics-test-gate">
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(gate.status || "completed")}"></span>
        <strong>${escapeHtml(gate.title || "Diagnostics / test gate")}</strong>
        <mark>${escapeHtml(gate.status || "completed")}</mark>
      </header>
      <p>${escapeHtml(gate.detail || "Postcondition gate projected from daemon tool output.")}</p>
      ${gate.receiptRefs?.length ? `<code>${escapeHtml(gate.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
  }

  function studioBrowserWorkerRows() {
    const runtimeProjection = projection();
    const browserCards = firstArray(runtimeProjection.browserCards).slice(-2).map((card) => `
    <article class="studio-cockpit-card" data-testid="studio-browser-status-card">
      <header><strong>${escapeHtml(card.title || "Browser status")}</strong><mark>${escapeHtml(card.status || "observed")}</mark></header>
      <p>${escapeHtml(card.detail || "")}</p>
    </article>
  `).join("");
    const workerCards = firstArray(runtimeProjection.workerCards).slice(-2).map((card) => `
    <article class="studio-cockpit-card" data-testid="studio-worker-status-card">
      <header><strong>${escapeHtml(card.title || "Worker / subagent status")}</strong><mark>${escapeHtml(card.status || "observed")}</mark></header>
      <p>${escapeHtml(card.detail || "")}</p>
      ${card.receiptRefs?.length ? `<code>${escapeHtml(card.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
    return `${browserCards}${workerCards}`;
  }

  function studioCompactRuntimeStatusRows() {
    const runtimeProjection = projection();
    const rows = [];
    for (const lease of firstArray(runtimeProjection.policyLeases).slice(-2)) {
      rows.push(`
      <article class="studio-compact-runtime-card studio-compact-runtime-card--blocking" data-testid="studio-policy-prompt-actionable" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineAction}">
        <div>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "blocked")}"></span>
          <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
          <span>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</span>
        </div>
        <button type="button" data-studio-drawer-open>Review</button>
      </article>
    `);
    }
    const pendingHunks = firstArray(runtimeProjection.diffHunks).filter((hunk) =>
      /needs[_\s-]?review|pending|preview/i.test(String(hunk.status || "")) ||
      hunk.acceptAvailable ||
      hunk.rejectAvailable
    );
    if (pendingHunks.length > 0) {
      rows.push(`
      <article class="studio-compact-runtime-card studio-compact-runtime-card--blocking" data-testid="studio-native-hunk-review-inline" data-runtime-visibility="${STUDIO_RUNTIME_VISIBILITY.inlineAction}">
        <div>
          <span class="studio-status-dot studio-status-dot--pending"></span>
          <strong>Patch proposal</strong>
          <span>${escapeHtml(`${pendingHunks.length} hunk${pendingHunks.length === 1 ? "" : "s"} waiting for review`)}</span>
        </div>
        <button type="button" data-studio-drawer-open>Review hunks</button>
      </article>
    `);
    }
    if (!rows.length) {
      return "";
    }
    return `<section class="studio-compact-runtime-list" data-testid="studio-actionable-runtime-state">${rows.join("")}</section>`;
  }

  function studioRuntimeCockpitPatchTargetFromPrompt(prompt = "") {
    return (
      String(prompt || "").match(/\.tmp\/autopilot-runtime-cockpit-code\/[A-Za-z0-9_.-]+\/status-labels\.mjs/i)?.[0] ||
      "README.md"
    );
  }

  function patchPreviewHunkFromToolResponse(response, targetPath = "README.md") {
    const result = response?.result || {};
    const diff =
      result.diff ||
      result.patch ||
      result.unifiedDiff ||
      result.unified_diff ||
      result.preview ||
      safeJsonPreview(result, 1600);
    return {
      file: targetPath,
      title: "Status label helper patch",
      status: "pending",
      approvalId: projection().hunkApprovalId || getHunkApprovalId(),
      before: "- export function statusLabel(status) { return String(status); }",
      after: "+ export function normalizeRunStatusLabel(status) { return String(status).split('_').map(capitalize).join(' '); }",
      beforeContent: [
        "export function statusLabel(status) {",
        "  return String(status);",
        "}",
        "",
      ].join("\n"),
      afterContent: [
        "function capitalize(part) {",
        "  return part ? part[0].toUpperCase() + part.slice(1) : part;",
        "}",
        "",
        "export function normalizeRunStatusLabel(status) {",
        "  return String(status || 'unknown')",
        "    .split('_')",
        "    .filter(Boolean)",
        "    .map(capitalize)",
        "    .join(' ');",
        "}",
        "",
        diff,
        "",
      ].join("\n"),
    };
  }

  return {
    patchPreviewHunkFromToolResponse,
    studioActionCardRows,
    studioBrowserWorkerRows,
    studioCommandOutputRows,
    studioCompactRuntimeStatusRows,
    studioDiagnosticsRows,
    studioDiffRows,
    studioPolicyLeaseRows,
    studioRuntimeCockpitPatchTargetFromPrompt,
  };
}

module.exports = {
  createStudioRuntimeCockpitRows,
};
