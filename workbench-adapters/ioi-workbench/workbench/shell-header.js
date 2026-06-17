"use strict";

function createAutopilotShellHeader({
  AUTOPILOT_MODE_BY_ID,
  daemonEndpoint,
  escapeHtml,
  modelSnapshotFromState,
  processEnv = process.env,
  workspaceSummary,
}) {
  function shellStatusTone(value) {
    const normalized = String(value || "").toLowerCase();
    if (/ready|connected|loaded|running|active|pass/.test(normalized)) {
      return "ready";
    }
    if (/blocked|failed|error|denied|absent/.test(normalized)) {
      return "blocked";
    }
    if (/degraded|loading|pending|warning|queued/.test(normalized)) {
      return "warn";
    }
    return "muted";
  }

  function autopilotShellHeaderStyles() {
    return `
      .autopilot-shell-header {
        box-sizing: border-box;
        width: 100%;
        min-height: 50px;
        display: grid;
        grid-template-columns: minmax(190px, 260px) minmax(240px, 1fr) auto;
        gap: 12px;
        align-items: center;
        padding: 8px 12px;
        border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,.14));
        background: color-mix(in srgb, var(--vscode-editor-background, #101216) 92%, var(--vscode-foreground, #fff) 5%);
        color: var(--vscode-foreground, #f4f6f8);
      }
      .autopilot-shell-header__crumb {
        min-width: 0;
        display: flex;
        align-items: baseline;
        gap: 7px;
        overflow: hidden;
        white-space: nowrap;
      }
      .autopilot-shell-header__crumb strong {
        font-size: 13px;
        font-weight: 700;
      }
      .autopilot-shell-header__crumb span {
        color: var(--vscode-descriptionForeground, #9ca3af);
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .autopilot-shell-header__command {
        min-width: 0;
        height: 32px;
        display: flex;
        align-items: center;
        gap: 8px;
        border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
        border-radius: 6px;
        background: var(--vscode-input-background, rgba(255,255,255,.06));
        color: var(--vscode-input-foreground, var(--vscode-foreground));
        padding: 0 10px;
        font: inherit;
        text-align: left;
      }
      .autopilot-shell-header__command span {
        min-width: 0;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .autopilot-shell-header__posture {
        min-width: 0;
        display: flex;
        align-items: center;
        justify-content: end;
        gap: 6px;
        flex-wrap: wrap;
      }
      .autopilot-shell-chip,
      .autopilot-shell-action {
        min-height: 24px;
        display: inline-flex;
        align-items: center;
        gap: 4px;
        border: 1px solid var(--vscode-panel-border, rgba(255,255,255,.16));
        border-radius: 999px;
        padding: 2px 8px;
        color: var(--vscode-descriptionForeground, #9ca3af);
        background: transparent;
        font-size: 11px;
        line-height: 1.2;
        white-space: nowrap;
      }
      .autopilot-shell-chip.is-ready {
        border-color: color-mix(in srgb, #2ea043 70%, var(--vscode-panel-border, transparent));
        color: #7ee787;
      }
      .autopilot-shell-chip.is-warn {
        border-color: color-mix(in srgb, #d29922 70%, var(--vscode-panel-border, transparent));
        color: #e3b341;
      }
      .autopilot-shell-chip.is-blocked {
        border-color: color-mix(in srgb, #f85149 70%, var(--vscode-panel-border, transparent));
        color: #ff7b72;
      }
      .autopilot-shell-action {
        border-radius: 5px;
        background: var(--vscode-button-secondaryBackground, rgba(255,255,255,.08));
        color: var(--vscode-button-secondaryForeground, var(--vscode-foreground));
        cursor: pointer;
      }
      .autopilot-shell-action:hover,
      .autopilot-shell-header__command:hover {
        background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,.12));
      }
      @media (max-width: 1000px) {
        .autopilot-shell-header {
          grid-template-columns: minmax(0, 1fr);
        }
        .autopilot-shell-header__posture {
          justify-content: start;
        }
      }
  `;
  }

  function nativeWorkbenchShellEnabled() {
    return processEnv.IOI_WORKBENCH_NATIVE_SHELL === "1";
  }

  function renderAutopilotShellHeader(state, modeId, options = {}) {
    if (nativeWorkbenchShellEnabled()) {
      return "";
    }
    const mode = AUTOPILOT_MODE_BY_ID[modeId] || AUTOPILOT_MODE_BY_ID.home;
    const workspace = state.workspace || workspaceSummary();
    const snapshot = modelSnapshotFromState(state);
    const daemonStatus =
      state.modelMountingStatus?.status || (daemonEndpoint() ? "connected" : "not_configured");
    const loadedModels = snapshot.instances.filter((instance) =>
      /loaded|ready|running/i.test(String(instance.status || "")),
    );
    const activeRuns = (Array.isArray(state.runs) ? state.runs : []).filter((run) =>
      /active|running|queued|pending/i.test(String(run.status || "")),
    );
    const policyIssueCount =
      state.summary?.policyIssueCount ??
      (Array.isArray(state.policy?.issues) ? state.policy.issues.length : 0);
    const activeRoute =
      snapshot.routes.find((route) => /active|ready|default/i.test(String(route.status || ""))) ||
      snapshot.routes[0] ||
      snapshot.endpoints[0] ||
      null;
    const routeLabel =
      activeRoute?.displayName || activeRoute?.routeId || activeRoute?.id || activeRoute?.modelId || "unbound";
    const workspaceLabel = workspace.name || "No workspace";
    const shellAction =
      mode.id === "code"
        ? {
            label: "Back to Autopilot",
            command: "ioi.autopilot.back",
            testId: "back-to-autopilot-from-code",
          }
        : {
            label: "Code",
            command: "ioi.code.open",
            testId: "autopilot-shell-code-drilldown",
          };
    return `
    <header
      class="autopilot-shell-header"
      data-testid="autopilot-workbench-shell-header"
      data-autopilot-mode="${escapeHtml(mode.id)}"
      data-runtime-authority="daemon-owned"
      data-extension-host-authority="projection-only"
      data-vscode-menu-dominates="false"
      data-tauri-used="false"
    >
      <div class="autopilot-shell-header__crumb" data-testid="autopilot-shell-breadcrumb">
        <strong>Autopilot</strong>
        <span>/</span>
        <span title="${escapeHtml(workspace.path || workspaceLabel)}">${escapeHtml(workspaceLabel)}</span>
        <span>/</span>
        <strong>${escapeHtml(mode.title)}</strong>
      </div>
      <button
        class="autopilot-shell-header__command"
        type="button"
        data-command="ioi.commandCenter.open"
        data-testid="autopilot-shell-command-center"
        data-operator-command-center
      >
        <span>Search Autopilot, code, workflows, runs, and commands</span>
      </button>
      <div class="autopilot-shell-header__posture" data-testid="autopilot-shell-runtime-posture">
        <span class="autopilot-shell-chip is-${escapeHtml(shellStatusTone(daemonStatus))}" data-testid="autopilot-shell-daemon-status">Daemon ${escapeHtml(daemonStatus)}</span>
        <span class="autopilot-shell-chip is-${loadedModels.length ? "ready" : "muted"}" data-testid="autopilot-shell-model-route">Model ${escapeHtml(routeLabel)}</span>
        <span class="autopilot-shell-chip is-${activeRuns.length ? "warn" : "muted"}" data-testid="autopilot-shell-active-runs">Runs ${escapeHtml(String(activeRuns.length))}</span>
        <span class="autopilot-shell-chip is-${policyIssueCount ? "warn" : "ready"}" data-testid="autopilot-shell-policy-posture">Approvals ${escapeHtml(String(policyIssueCount))}</span>
        <span class="autopilot-shell-chip" data-testid="autopilot-shell-wallet-posture">Authority local</span>
        ${
          options.hideModeAction
            ? ""
            : `<button class="autopilot-shell-action" type="button" data-command="${escapeHtml(shellAction.command)}" data-testid="${escapeHtml(shellAction.testId)}">${escapeHtml(shellAction.label)}</button>`
        }
      </div>
    </header>
  `;
  }

  return {
    autopilotShellHeaderStyles,
    nativeWorkbenchShellEnabled,
    renderAutopilotShellHeader,
    shellStatusTone,
  };
}

module.exports = {
  createAutopilotShellHeader,
};
