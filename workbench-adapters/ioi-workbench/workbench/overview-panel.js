"use strict";

function createWorkbenchOverviewPanelRenderer({
  autopilotShellHeaderStyles,
  currentOverviewPanelNonce,
  daemonEndpoint,
  escapeHtml,
  loadedProductStudioModelInstances,
  modelSnapshotFromState,
  overviewPill,
  overviewTone,
  productStudioModelSelectionsFromSnapshot,
  renderAutopilotShellHeader,
  renderOverviewAction,
  renderOverviewRow,
  workspaceSummary,
}) {
  function overviewPanelHtml(state) {
    const pageNonce = currentOverviewPanelNonce();
    const workspace = state.workspace || workspaceSummary();
    const snapshot = modelSnapshotFromState(state);
    const workflows = Array.isArray(state.workflows) ? state.workflows : [];
    const runs = Array.isArray(state.runs) ? state.runs : [];
    const artifacts = Array.isArray(state.artifacts) ? state.artifacts : [];
    const connections = Array.isArray(state.connections) ? state.connections : [];
    const summary = state.summary || {};
    const daemonStatus =
      state.modelMountingStatus?.status || (daemonEndpoint() ? "connected" : "not_configured");
    const daemonDetail =
      daemonStatus === "connected"
        ? state.modelMountingStatus?.endpoint || "daemon endpoint connected"
        : daemonStatus === "degraded"
          ? state.modelMountingStatus?.error || "daemon endpoint degraded"
          : "daemon endpoint not configured";
    const productModelSelections = productStudioModelSelectionsFromSnapshot(snapshot);
    const loadedModels = loadedProductStudioModelInstances(snapshot, productModelSelections);
    const productModelCount = productModelSelections.length;
    const activeRuns = runs.filter((run) =>
      /active|running|queued|pending/i.test(String(run.status || "")),
    );
    const receipts = snapshot.receipts;
    const policyIssueCount =
      summary.policyIssueCount ??
      (Array.isArray(state.policy?.issues) ? state.policy.issues.length : 0);
    const connectorCount = connections.length || summary.connectorCount || 0;
    const connectorReadyCount = connections.filter((connection) =>
      /ready|available|connected|configured/i.test(String(connection.status || "")),
    ).length;
    const recentWorkflow = workflows[0];
    const recentRun = runs[0];
    const recentArtifact = artifacts[0];
    const latestReceipt = receipts[0];
    const workspaceLabel =
      workspace.path && workspace.path !== "Open a workspace folder to ground IOI context."
        ? workspace.path
        : "Open a workspace folder to ground runtime context.";

    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Autopilot Overview</title>
    <style nonce="${pageNonce}">
      :root {
        color-scheme: dark;
        --overview-bg: var(--vscode-editor-background, #101216);
        --overview-panel: color-mix(in srgb, var(--vscode-editor-background, #101216) 88%, var(--vscode-foreground, #fff) 6%);
        --overview-panel-soft: color-mix(in srgb, var(--vscode-editor-background, #101216) 94%, var(--vscode-foreground, #fff) 4%);
        --overview-border: var(--vscode-panel-border, rgba(255,255,255,.13));
        --overview-text: var(--vscode-foreground, #f4f6f8);
        --overview-muted: var(--vscode-descriptionForeground, #9ca3af);
        --overview-accent: var(--vscode-textLink-foreground, #4ea1ff);
        --overview-ready: #7ee787;
        --overview-warn: #e3b341;
        --overview-blocked: #ff7b72;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--overview-text);
        background: var(--overview-bg);
      }
      .overview-shell {
        min-height: 100vh;
        display: grid;
        grid-template-rows: auto auto minmax(0, 1fr);
      }
      .overview-header {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 20px;
        align-items: start;
        padding: 28px 32px 22px;
        border-bottom: 1px solid var(--overview-border);
        background: var(--overview-panel-soft);
      }
      .overview-kicker,
      .overview-section__kicker,
      .overview-table th {
        color: var(--overview-muted);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: .08em;
        text-transform: uppercase;
      }
      h1 {
        margin: 7px 0 8px;
        font-size: clamp(28px, 4vw, 42px);
        font-weight: 520;
        letter-spacing: 0;
      }
      .overview-header p {
        max-width: 880px;
        margin: 0;
        color: var(--overview-muted);
        font-size: 14px;
        line-height: 1.5;
      }
      .overview-status {
        min-width: 280px;
        display: grid;
        gap: 8px;
      }
      .overview-pill {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        min-height: 28px;
        border: 1px solid var(--overview-border);
        border-radius: 999px;
        padding: 4px 10px;
        color: var(--overview-muted);
        font-size: 12px;
      }
      .overview-pill strong { color: var(--overview-text); font-weight: 560; }
      .overview-pill.is-ready { border-color: color-mix(in srgb, var(--overview-ready) 70%, var(--overview-border)); }
      .overview-pill.is-warn { border-color: color-mix(in srgb, var(--overview-warn) 70%, var(--overview-border)); }
      .overview-pill.is-blocked { border-color: color-mix(in srgb, var(--overview-blocked) 70%, var(--overview-border)); }
      .overview-nav {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: 1px;
        border-bottom: 1px solid var(--overview-border);
        background: var(--overview-border);
      }
      .overview-action {
        min-height: 76px;
        display: grid;
        align-content: center;
        gap: 5px;
        border: 0;
        border-radius: 0;
        padding: 14px 18px;
        background: var(--overview-panel);
        color: var(--overview-text);
        text-align: left;
        font: inherit;
        cursor: pointer;
      }
      .overview-action span { font-weight: 650; }
      .overview-action small {
        color: var(--overview-muted);
        line-height: 1.35;
      }
      .overview-action:hover,
      .overview-action:focus-visible {
        outline: 1px solid var(--overview-accent);
        outline-offset: -1px;
        background: color-mix(in srgb, var(--overview-panel) 86%, var(--overview-accent) 14%);
      }
      .overview-action.is-primary {
        background: color-mix(in srgb, var(--overview-panel) 80%, var(--overview-accent) 14%);
      }
      .overview-main {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
        min-height: 0;
      }
      .overview-column {
        min-width: 0;
        display: grid;
        align-content: start;
        gap: 18px;
        padding: 22px 32px 34px;
      }
      .overview-column + .overview-column {
        border-left: 1px solid var(--overview-border);
        background: var(--overview-panel-soft);
      }
      .overview-section {
        min-width: 0;
        display: grid;
        gap: 10px;
      }
      .overview-section h2 {
        margin: 0;
        font-size: 16px;
        font-weight: 650;
      }
      .overview-section p {
        margin: 0;
        color: var(--overview-muted);
        line-height: 1.45;
      }
      .overview-board {
        border: 1px solid var(--overview-border);
        border-radius: 8px;
        overflow: hidden;
      }
      .overview-row {
        display: grid;
        grid-template-columns: 128px minmax(0, 1fr) minmax(150px, .8fr);
        gap: 14px;
        align-items: center;
        min-height: 48px;
        padding: 10px 12px;
        border-bottom: 1px solid var(--overview-border);
        background: var(--overview-panel);
      }
      .overview-row:last-child { border-bottom: 0; }
      .overview-row__label,
      .overview-row small {
        color: var(--overview-muted);
      }
      .overview-row strong,
      .overview-row small {
        min-width: 0;
        overflow-wrap: anywhere;
      }
      .overview-row small.is-ready { color: var(--overview-ready); }
      .overview-row small.is-warn { color: var(--overview-warn); }
      .overview-row small.is-blocked { color: var(--overview-blocked); }
      .overview-table {
        width: 100%;
        border-collapse: collapse;
        table-layout: fixed;
        border: 1px solid var(--overview-border);
        border-radius: 8px;
        overflow: hidden;
      }
      .overview-table th,
      .overview-table td {
        padding: 9px 10px;
        border-bottom: 1px solid var(--overview-border);
        text-align: left;
        vertical-align: top;
        background: var(--overview-panel);
      }
      .overview-table tr:last-child td { border-bottom: 0; }
      .overview-table td {
        color: var(--overview-muted);
        line-height: 1.38;
      }
      .overview-table td strong {
        display: block;
        margin-bottom: 3px;
        color: var(--overview-text);
      }
      .overview-side-actions {
        display: grid;
        gap: 8px;
      }
      .overview-side-actions .overview-action {
        min-height: 58px;
        border: 1px solid var(--overview-border);
        border-radius: 6px;
      }
      code {
        color: var(--vscode-textPreformat-foreground, var(--overview-text));
        background: var(--vscode-textCodeBlock-background, transparent);
        border-radius: 4px;
        padding: 2px 5px;
      }
      ${autopilotShellHeaderStyles()}
      @media (max-width: 1000px) {
        .overview-header,
        .overview-main {
          grid-template-columns: minmax(0, 1fr);
        }
        .overview-status { min-width: 0; }
        .overview-nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .overview-column + .overview-column { border-left: 0; border-top: 1px solid var(--overview-border); }
      }
      @media (max-width: 680px) {
        .overview-header,
        .overview-column { padding-left: 18px; padding-right: 18px; }
        .overview-nav,
        .overview-row { grid-template-columns: minmax(0, 1fr); }
      }
    </style>
  </head>
  <body>
    <main class="overview-shell" data-testid="autopilot-overview-home" data-runtime-authority="daemon-owned">
      ${renderAutopilotShellHeader(state, "home")}
      <header class="overview-header">
        <div>
          <div class="overview-kicker">Autopilot Workbench</div>
          <h1>Operator console for autonomous systems</h1>
          <p>
            Build, run, govern, and verify agentic work from one IDE-native surface.
            The Electron workbench projects state and sends typed requests; IOI daemon owns execution authority.
          </p>
        </div>
        <div class="overview-status" aria-label="Runtime status">
          ${overviewPill("Daemon", daemonStatus, overviewTone(daemonStatus))}
          ${overviewPill("Models", `${loadedModels.length}/${productModelCount} loaded`, loadedModels.length ? "ready" : "muted")}
          ${overviewPill("Runs", `${activeRuns.length} active`, activeRuns.length ? "warn" : "ready")}
          ${overviewPill("Policy", `${policyIssueCount} issues`, policyIssueCount ? "warn" : "ready")}
        </div>
      </header>

      <nav class="overview-nav" aria-label="Autopilot primary actions">
        ${renderOverviewAction({
          label: "Build",
          description: "Agent Studio, workflows, workers, and model-backed app intent.",
          command: "ioi.studio.open",
          tone: "primary",
        })}
        ${renderOverviewAction({
          label: "Run",
          description: "Daemon runtime, local models, executions, and connector dry runs.",
          command: "ioi.models.open",
        })}
        ${renderOverviewAction({
          label: "Govern",
          description: "Policy, approvals, secrets, authority, and connector posture.",
          command: "ioi.policy.open",
        })}
        ${renderOverviewAction({
          label: "Verify",
          description: "Receipts, replay, evidence, tests, and run history.",
          command: "ioi.runs.refresh",
        })}
      </nav>

      <section class="overview-main">
        <div class="overview-column">
          <section class="overview-section" aria-label="Current workspace">
            <div class="overview-section__kicker">Current Workspace</div>
            <h2>${escapeHtml(workspace.name || "No workspace selected")}</h2>
            <p><code>${escapeHtml(workspaceLabel)}</code></p>
            <div class="overview-board">
              ${renderOverviewRow("Daemon", daemonStatus, daemonDetail, overviewTone(daemonStatus))}
              ${renderOverviewRow("Models", `${productModelCount} product model${productModelCount === 1 ? "" : "s"}`, `${loadedModels.length} loaded instance${loadedModels.length === 1 ? "" : "s"}`, loadedModels.length ? "ready" : "muted")}
              ${renderOverviewRow("Workflows", `${workflows.length || summary.workflowCount || 0} indexed`, recentWorkflow?.name || recentWorkflow?.id || "Open composer to create one", workflows.length ? "ready" : "muted")}
              ${renderOverviewRow("Connectors", `${connectorReadyCount}/${connectorCount} ready`, "dry-run only for sprint readiness", connectorReadyCount ? "ready" : "muted")}
            </div>
          </section>

          <section class="overview-section" aria-label="Continue work">
            <div class="overview-section__kicker">Continue</div>
            <table class="overview-table">
              <thead>
                <tr><th>Surface</th><th>Current item</th><th>Status</th></tr>
              </thead>
              <tbody>
                <tr>
                  <td><strong>Workflow</strong>Composable autonomous system</td>
                  <td>${escapeHtml(recentWorkflow?.name || recentWorkflow?.id || "No saved workflow projected")}</td>
                  <td>${escapeHtml(recentWorkflow?.status || "open composer")}</td>
                </tr>
                <tr>
                  <td><strong>Run</strong>Execution timeline</td>
                  <td>${escapeHtml(recentRun?.name || recentRun?.id || "No active run projected")}</td>
                  <td>${escapeHtml(recentRun?.status || "idle")}</td>
                </tr>
                <tr>
                  <td><strong>Evidence</strong>Receipt and replay trail</td>
                  <td>${escapeHtml(latestReceipt?.receiptId || recentArtifact?.id || "No receipt projected")}</td>
                  <td>${escapeHtml(latestReceipt ? "daemon receipt" : recentArtifact?.status || "pending evidence")}</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section class="overview-section" aria-label="Readiness">
            <div class="overview-section__kicker">Connector Sprint Readiness</div>
            <div class="overview-board">
              ${renderOverviewRow("Execution", daemonStatus === "connected" ? "Daemon path available" : "Daemon path blocked", "UI must not own durable runtime", daemonStatus === "connected" ? "ready" : "blocked")}
              ${renderOverviewRow("Model route", loadedModels.length ? "Live model route ready" : "No loaded route", "Models mode is the route source", loadedModels.length ? "ready" : "warn")}
              ${renderOverviewRow("External action", "disabled", "use fixture/dry-run connector flows only", "ready")}
              ${renderOverviewRow("Audit", receipts.length ? `${receipts.length} receipts` : "Receipts pending", "receipt and replay remain daemon-owned", receipts.length ? "ready" : "warn")}
            </div>
          </section>
        </div>

        <aside class="overview-column" aria-label="Open surfaces">
          <section class="overview-section">
            <div class="overview-section__kicker">Create</div>
            <div class="overview-side-actions">
              ${renderOverviewAction({
                label: "Agent Studio",
                description: "Prompt-to-agent/workflow intent, routed through daemon-owned boundaries.",
                command: "ioi.studio.open",
                tone: "primary",
              })}
              ${renderOverviewAction({
                label: "Workflow Composer",
                description: "Open the rich graph canvas directly.",
                command: "ioi.workflow.openComposer",
              })}
              ${renderOverviewAction({
                label: "Mount Models",
                description: "Inspect local artifacts, load routes, and bind workflows.",
                command: "ioi.models.open",
              })}
              ${renderOverviewAction({
                label: "Connector Dry Run",
                description: "Exercise connector-neutral capability binding without external action.",
                command: "ioi.workflow.openComposer",
                payload: { scenarioId: "connector-fixture", phase: "connector-fixture" },
              })}
            </div>
          </section>

          <section class="overview-section">
            <div class="overview-section__kicker">Operate</div>
            <div class="overview-side-actions">
              ${renderOverviewAction({
                label: "Runs",
                description: "Open runtime state, active jobs, and latest execution history.",
                command: "ioi.runs.refresh",
              })}
              ${renderOverviewAction({
                label: "Policy",
                description: "Review approval posture and authority gates.",
                command: "ioi.policy.open",
              })}
              ${renderOverviewAction({
                label: "Connections",
                description: "Inspect available services and connector posture.",
                command: "ioi.connections.inspect",
              })}
              ${renderOverviewAction({
                label: "Command Center",
                description: "Search Autopilot commands and runtime surfaces.",
                command: "ioi.commandCenter.open",
              })}
            </div>
          </section>
        </aside>
      </section>
    </main>
    <script nonce="${pageNonce}">
      const vscode = acquireVsCodeApi();
      function parsePayload(raw) {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          console.error("[IOI Overview] Failed to parse command payload", error);
          return undefined;
        }
      }
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: parsePayload(button.dataset.payload)
          });
        });
      });
    </script>
  </body>
</html>`;
  }

  return {
    overviewPanelHtml,
  };
}

module.exports = {
  createWorkbenchOverviewPanelRenderer,
};
