"use strict";

function createWorkbenchOverviewPanelRenderer({
  hypervisorShellHeaderStyles,
  currentOverviewPanelNonce,
  daemonEndpoint,
  escapeHtml,
  loadedProductStudioModelInstances,
  modelSnapshotFromState,
  overviewTone,
  productStudioModelSelectionsFromSnapshot,
  renderHypervisorShellHeader,
  workspaceSummary,
}) {
  function commandPayloadAttr(payload) {
    return payload ? ` data-payload="${escapeHtml(JSON.stringify(payload))}"` : "";
  }

  function commandButton({ label, description, command, payload, tone = "default", meta = "" }) {
    return `
      <button
        class="ioi-home-command is-${escapeHtml(tone)}"
        type="button"
        data-command="${escapeHtml(command)}"${commandPayloadAttr(payload)}
      >
        <span>${escapeHtml(label)}</span>
        ${meta ? `<em>${escapeHtml(meta)}</em>` : ""}
        <small>${escapeHtml(description)}</small>
      </button>
    `;
  }

  function navButton({ label, icon, command, payload, active = false }) {
    return `
      <button class="${active ? "is-active" : ""}" type="button" data-command="${escapeHtml(command)}"${commandPayloadAttr(payload)}>
        <span class="ioi-home-nav-icon">${escapeHtml(icon)}</span>
        <span>${escapeHtml(label)}</span>
      </button>
    `;
  }

  function sessionButton({ title, context, dot, command, payload, index }) {
    return `
      <button class="ioi-home-session-button" type="button" data-command="${escapeHtml(command)}"${commandPayloadAttr(payload)}>
        <span class="ioi-home-dot is-${escapeHtml(dot)}"></span>
        <span class="ioi-home-session-text">
          <strong>${escapeHtml(title)}</strong>
          <span>${escapeHtml(context)}</span>
        </span>
        <span class="ioi-home-session-badge">${escapeHtml(index)}</span>
      </button>
    `;
  }

  function overviewPanelHtml(state) {
    const pageNonce = currentOverviewPanelNonce();
    const workspace = state.workspace || workspaceSummary();
    const snapshot = modelSnapshotFromState(state);
    const workflows = Array.isArray(state.workflows) ? state.workflows : [];
    const runs = Array.isArray(state.runs) ? state.runs : [];
    const artifacts = Array.isArray(state.artifacts) ? state.artifacts : [];
    const connections = Array.isArray(state.connections) ? state.connections : [];
    const summary = state.summary || {};
    const receipts = Array.isArray(snapshot.receipts) ? snapshot.receipts : [];
    const daemonStatus =
      state.modelMountingStatus?.status || (daemonEndpoint() ? "connected" : "not_configured");
    const daemonDetail =
      daemonStatus === "connected"
        ? state.modelMountingStatus?.endpoint || "Core endpoint connected"
        : daemonStatus === "degraded"
          ? state.modelMountingStatus?.error || "Core endpoint degraded"
          : "Core endpoint not configured";
    const productModelSelections = productStudioModelSelectionsFromSnapshot(snapshot);
    const loadedModels = loadedProductStudioModelInstances(snapshot, productModelSelections);
    const productModelCount = productModelSelections.length;
    const activeRuns = runs.filter((run) =>
      /active|running|queued|pending/i.test(String(run.status || "")),
    );
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
    const workspacePath =
      workspace.path && workspace.path !== "Open a workspace folder to ground IOI context."
        ? workspace.path
        : "Open a workspace folder to ground runtime context.";
    const workflowCount = workflows.length || summary.workflowCount || 0;
    const projectName = workspace.name || "Current workspace";

    const sessionRows = [
      {
        title: recentRun?.name || recentRun?.id || "Start from scratch",
        context: recentRun?.status || "No active session yet",
        dot: activeRuns.length ? "active" : "idle",
        command: "ioi.studio.open",
        payload: { source: "overview-session-row" },
      },
      {
        title: recentWorkflow?.name || recentWorkflow?.id || "Create an automation",
        context: recentWorkflow?.status || "Workflow graph not projected",
        dot: workflows.length ? "active" : "idle",
        command: "ioi.workflow.openComposer",
        payload: { source: "overview-workflow-row" },
      },
      {
        title: latestReceipt?.receiptId || recentArtifact?.id || "Review receipts",
        context: latestReceipt ? "Latest receipt ready" : "Evidence will appear after a run",
        dot: latestReceipt ? "active" : "idle",
        command: "ioi.runs.refresh",
        payload: { source: "overview-receipt-row" },
      },
    ];

    const postureRows = [
      ["Core", daemonStatus, daemonDetail, overviewTone(daemonStatus)],
      [
        "Models",
        `${loadedModels.length}/${productModelCount} loaded`,
        loadedModels.length ? "Model route available" : "Choose or mount a model",
        loadedModels.length ? "ready" : "idle",
      ],
      [
        "Authority",
        `${policyIssueCount} issue${policyIssueCount === 1 ? "" : "s"}`,
        policyIssueCount ? "Review policy before execution" : "No policy blockers projected",
        policyIssueCount ? "warn" : "ready",
      ],
      [
        "Connections",
        `${connectorReadyCount}/${connectorCount} ready`,
        connectorCount ? "Provider posture projected" : "No provider connections yet",
        connectorReadyCount ? "ready" : "idle",
      ],
    ];

    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Hypervisor Home</title>
    <style nonce="${pageNonce}">
      :root {
        color-scheme: light;
        --home-bg: #f4f5f7;
        --home-panel: #ffffff;
        --home-sidebar: #fbfbfc;
        --home-border: #dddee3;
        --home-border-soft: #eceef2;
        --home-text: #17181c;
        --home-muted: #6f7580;
        --home-faint: #8b929d;
        --home-accent: #3156c8;
        --home-ready: #116329;
        --home-warn: #9a6700;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        background: var(--home-bg);
        color: var(--home-text);
        font-family: "ABC Diatype", var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
      }
      .ioi-home-shell {
        min-height: 100vh;
        display: grid;
        grid-template-columns: 244px minmax(0, 1fr);
        background: var(--home-bg);
      }
      .ioi-home-sidebar {
        display: grid;
        grid-template-rows: auto auto minmax(0, 1fr) auto;
        gap: 18px;
        min-height: 100vh;
        padding: 18px 14px 16px;
        border-right: 1px solid var(--home-border);
        background: var(--home-sidebar);
      }
      .ioi-home-brand {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        min-height: 28px;
        padding: 0 4px;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: .06em;
      }
      .ioi-home-brand-mark {
        display: inline-grid;
        place-items: center;
        width: 24px;
        height: 24px;
        border-radius: 7px;
        background: #101216;
        color: #fff;
        font-size: 11px;
        letter-spacing: 0;
      }
      .ioi-home-new-session {
        min-height: 34px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
        border: 1px solid #d7d9df;
        border-radius: 8px;
        padding: 0 10px;
        background: var(--home-panel);
        color: var(--home-text);
        font: inherit;
        font-size: 13px;
        font-weight: 650;
        cursor: pointer;
        box-shadow: 0 1px 2px rgba(16, 18, 22, .04);
      }
      .ioi-home-new-session span:first-child {
        display: inline-flex;
        align-items: center;
        gap: 8px;
      }
      .ioi-home-kbd {
        border: 1px solid #d9dbe2;
        border-radius: 5px;
        padding: 1px 5px;
        color: var(--home-muted);
        background: #f6f7f9;
        font-size: 11px;
        font-weight: 500;
      }
      .ioi-home-stack,
      .ioi-home-nav,
      .ioi-home-session-list,
      .ioi-home-footer,
      .ioi-home-side,
      .ioi-home-side-block,
      .ioi-home-section {
        display: grid;
      }
      .ioi-home-stack { gap: 22px; }
      .ioi-home-nav,
      .ioi-home-session-list,
      .ioi-home-footer,
      .ioi-home-side-block {
        gap: 6px;
      }
      .ioi-home-nav button,
      .ioi-home-footer button {
        min-height: 32px;
        display: grid;
        grid-template-columns: 20px minmax(0, 1fr);
        align-items: center;
        gap: 9px;
        border: 0;
        border-radius: 7px;
        padding: 0 8px;
        background: transparent;
        color: #3f444d;
        font: inherit;
        font-size: 13px;
        text-align: left;
        cursor: pointer;
      }
      .ioi-home-nav button:hover,
      .ioi-home-footer button:hover,
      .ioi-home-session-button:hover {
        background: #f0f1f4;
      }
      .ioi-home-nav button.is-active {
        background: #eceef2;
        color: #111216;
        font-weight: 650;
      }
      .ioi-home-nav-icon {
        width: 18px;
        color: #68707c;
        text-align: center;
      }
      .ioi-home-sidebar-section {
        display: grid;
        gap: 7px;
        padding-top: 12px;
        border-top: 1px solid #e5e6eb;
      }
      .ioi-home-sidebar-label {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 6px;
        color: var(--home-faint);
        font-size: 11px;
      }
      .ioi-home-session-button {
        min-height: 42px;
        display: grid;
        grid-template-columns: 8px minmax(0, 1fr) auto;
        align-items: center;
        gap: 8px;
        border: 0;
        border-radius: 8px;
        padding: 6px 7px;
        background: transparent;
        color: #282c34;
        font: inherit;
        text-align: left;
        cursor: pointer;
      }
      .ioi-home-dot {
        width: 6px;
        height: 6px;
        border-radius: 999px;
        background: #9ba2ad;
      }
      .ioi-home-dot.is-active { background: #16a34a; }
      .ioi-home-session-text {
        min-width: 0;
        display: grid;
        gap: 2px;
      }
      .ioi-home-session-text strong,
      .ioi-home-session-text span {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .ioi-home-session-text strong {
        color: #1c2027;
        font-size: 12px;
        font-weight: 650;
      }
      .ioi-home-session-text span {
        color: #7b818c;
        font-size: 11px;
      }
      .ioi-home-session-badge {
        min-width: 20px;
        border-radius: 999px;
        padding: 2px 6px;
        background: #e8edff;
        color: var(--home-accent);
        font-size: 11px;
        text-align: center;
      }
      .ioi-home-footer {
        padding-top: 10px;
        border-top: 1px solid #e5e6eb;
      }
      .ioi-home-footer small {
        display: block;
        padding: 0 8px;
        color: #838995;
        font-size: 11px;
      }
      .ioi-home-main {
        min-width: 0;
        min-height: 100vh;
        display: grid;
        grid-template-rows: auto minmax(0, 1fr);
      }
      .ioi-home-topbar {
        min-height: 58px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 20px;
        padding: 0 32px;
        border-bottom: 1px solid var(--home-border);
        background: rgba(250, 250, 251, .92);
      }
      .ioi-home-topbar strong { font-size: 14px; }
      .ioi-home-search {
        width: min(520px, 45vw);
        min-height: 34px;
        display: flex;
        align-items: center;
        gap: 9px;
        border: 1px solid #d8dae1;
        border-radius: 9px;
        padding: 0 12px;
        background: var(--home-panel);
        color: #7d838e;
        font-size: 13px;
      }
      .ioi-home-content {
        min-width: 0;
        display: grid;
        grid-template-columns: minmax(0, 1fr) 340px;
        gap: 30px;
        align-content: start;
        padding: 30px 32px 44px;
      }
      .ioi-home-title h1 {
        margin: 0 0 6px;
        color: #15171c;
        font-size: clamp(28px, 4vw, 46px);
        font-weight: 600;
        letter-spacing: 0;
      }
      .ioi-home-title p {
        max-width: 740px;
        margin: 0;
        color: var(--home-muted);
        font-size: 14px;
        line-height: 1.5;
      }
      .ioi-home-composer,
      .ioi-home-table,
      .ioi-home-posture,
      .ioi-home-command {
        border: 1px solid var(--home-border);
        background: var(--home-panel);
      }
      .ioi-home-composer {
        border-radius: 14px;
        box-shadow: 0 14px 35px rgba(29, 31, 38, .06);
        overflow: hidden;
      }
      .ioi-home-composer textarea {
        width: 100%;
        min-height: 126px;
        resize: vertical;
        border: 0;
        padding: 18px 20px;
        background: transparent;
        color: var(--home-text);
        font: inherit;
        font-size: 16px;
        line-height: 1.45;
        outline: none;
      }
      .ioi-home-composer textarea::placeholder { color: #9096a1; }
      .ioi-home-composer-bar {
        min-height: 46px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
        border-top: 1px solid var(--home-border-soft);
        padding: 8px 10px 8px 14px;
      }
      .ioi-home-composer-tools {
        display: flex;
        flex-wrap: wrap;
        gap: 7px;
      }
      .ioi-home-chip {
        min-height: 26px;
        display: inline-flex;
        align-items: center;
        border: 1px solid #dde0e6;
        border-radius: 999px;
        padding: 0 9px;
        color: #59606b;
        background: #fafbfc;
        font-size: 12px;
      }
      .ioi-home-submit {
        min-height: 30px;
        border: 0;
        border-radius: 8px;
        padding: 0 12px;
        background: var(--home-text);
        color: #fff;
        font: inherit;
        font-size: 12px;
        font-weight: 650;
        cursor: pointer;
      }
      .ioi-home-section {
        min-width: 0;
        gap: 10px;
      }
      .ioi-home-section-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
      }
      .ioi-home-section h2 {
        margin: 0;
        color: #20242c;
        font-size: 15px;
        font-weight: 700;
      }
      .ioi-home-link {
        border: 0;
        background: transparent;
        color: var(--home-accent);
        font: inherit;
        font-size: 12px;
        cursor: pointer;
      }
      .ioi-home-table {
        border-radius: 12px;
        overflow: hidden;
      }
      .ioi-home-table-row {
        display: grid;
        grid-template-columns: minmax(160px, 1.15fr) minmax(0, 1.4fr) minmax(100px, .7fr);
        gap: 18px;
        align-items: center;
        min-height: 58px;
        padding: 12px 15px;
        border-bottom: 1px solid var(--home-border-soft);
      }
      .ioi-home-table-row:last-child { border-bottom: 0; }
      .ioi-home-table-row strong {
        display: block;
        margin-bottom: 3px;
        color: #20242c;
        font-size: 13px;
      }
      .ioi-home-table-row span,
      .ioi-home-table-row small {
        color: var(--home-muted);
        font-size: 12px;
        line-height: 1.35;
      }
      .ioi-home-side {
        min-width: 0;
        align-content: start;
        gap: 18px;
      }
      .ioi-home-command {
        min-height: 64px;
        align-content: center;
        gap: 3px;
        border-radius: 10px;
        padding: 12px 14px;
        color: #20242c;
        font: inherit;
        text-align: left;
        cursor: pointer;
      }
      .ioi-home-command:hover,
      .ioi-home-command:focus-visible {
        border-color: #b9bec8;
        background: #fafbfc;
        outline: none;
      }
      .ioi-home-command.is-primary {
        border-color: #cfd8ff;
        background: #f2f5ff;
      }
      .ioi-home-command span {
        font-size: 13px;
        font-weight: 700;
      }
      .ioi-home-command em {
        justify-self: start;
        border-radius: 999px;
        padding: 2px 7px;
        background: #eff2f6;
        color: #606874;
        font-size: 11px;
        font-style: normal;
      }
      .ioi-home-command small {
        color: var(--home-muted);
        font-size: 12px;
        line-height: 1.35;
      }
      .ioi-home-posture {
        border-radius: 12px;
        overflow: hidden;
      }
      .ioi-home-posture-row {
        display: grid;
        grid-template-columns: 92px minmax(0, 1fr);
        gap: 10px;
        min-height: 52px;
        padding: 11px 13px;
        border-bottom: 1px solid var(--home-border-soft);
      }
      .ioi-home-posture-row:last-child { border-bottom: 0; }
      .ioi-home-posture-row span {
        color: #7d838e;
        font-size: 12px;
      }
      .ioi-home-posture-row strong {
        display: block;
        color: #20242c;
        font-size: 13px;
      }
      .ioi-home-posture-row small {
        display: block;
        margin-top: 2px;
        color: #7d838e;
        font-size: 11px;
        line-height: 1.35;
      }
      .ioi-home-posture-row.is-warn strong { color: var(--home-warn); }
      .ioi-home-posture-row.is-ready strong { color: var(--home-ready); }
      ${hypervisorShellHeaderStyles()}
      @media (max-width: 1000px) {
        .ioi-home-shell,
        .ioi-home-content {
          grid-template-columns: minmax(0, 1fr);
        }
        .ioi-home-sidebar { min-height: auto; }
      }
      @media (max-width: 680px) {
        .ioi-home-content,
        .ioi-home-topbar {
          padding-left: 18px;
          padding-right: 18px;
        }
        .ioi-home-topbar {
          align-items: start;
          flex-direction: column;
          padding-top: 12px;
          padding-bottom: 12px;
        }
        .ioi-home-search { width: 100%; }
        .ioi-home-table-row,
        .ioi-home-posture-row {
          grid-template-columns: minmax(0, 1fr);
        }
      }
    </style>
  </head>
  <body>
    <main class="ioi-home-shell" data-testid="hypervisor-overview-home" data-runtime-authority="daemon-owned">
      ${renderHypervisorShellHeader(state, "home")}
      <aside class="ioi-home-sidebar" aria-label="Hypervisor navigation">
        <div class="ioi-home-brand">
          <span class="ioi-home-brand-mark">IOI</span>
          <span>IOI</span>
          <span aria-hidden="true">⌘</span>
        </div>
        <button class="ioi-home-new-session" type="button" data-command="ioi.studio.open"${commandPayloadAttr({ source: "overview-new-session" })}>
          <span><span aria-hidden="true">＋</span> New Session</span>
          <span class="ioi-home-kbd">Ctrl I</span>
        </button>
        <div class="ioi-home-stack">
          <nav class="ioi-home-nav" aria-label="Primary">
            ${navButton({ label: "Home", icon: "⌂", command: "ioi.commandCenter.open", payload: { surface: "home" }, active: true })}
            ${navButton({ label: "Projects", icon: "⌁", command: "ioi.commandCenter.open", payload: { surface: "projects" } })}
            ${navButton({ label: "Automations", icon: "⌘", command: "ioi.workflow.openComposer", payload: { source: "overview-automations" } })}
            ${navButton({ label: "Insights", icon: "⌗", command: "ioi.runs.refresh", payload: { source: "overview-insights" } })}
          </nav>
          <section class="ioi-home-sidebar-section" aria-label="Sessions">
            <div class="ioi-home-sidebar-label"><span>Sessions</span><span>From scratch</span></div>
            <div class="ioi-home-session-list">
              ${sessionRows
                .map((session, index) =>
                  sessionButton({ ...session, index: String(index + 1) }),
                )
                .join("")}
            </div>
          </section>
        </div>
        <div class="ioi-home-footer">
          ${navButton({ label: "Organization settings", icon: "⚙", command: "ioi.policy.open" })}
          <small>IOI Workspace · Operator</small>
        </div>
      </aside>
      <section class="ioi-home-main" aria-label="Hypervisor home">
        <header class="ioi-home-topbar">
          <strong>Home</strong>
          <div class="ioi-home-search" role="search" aria-label="Search">
            <span aria-hidden="true">⌕</span>
            <span>Search projects, sessions, receipts, models</span>
          </div>
        </header>
        <div class="ioi-home-content">
          <div class="ioi-home-stack">
            <section class="ioi-home-title" aria-label="Workspace prompt">
              <h1>What should Hypervisor do?</h1>
              <p>Start a governed session, open a project, compose an automation, or inspect the receipts behind recent work.</p>
            </section>
            <section class="ioi-home-composer" aria-label="New session composer">
              <textarea placeholder="Ask Hypervisor to build, operate, inspect, or automate this workspace..." aria-label="New session prompt"></textarea>
              <div class="ioi-home-composer-bar">
                <div class="ioi-home-composer-tools">
                  <span class="ioi-home-chip">Workspace: ${escapeHtml(projectName)}</span>
                  <span class="ioi-home-chip">Model route: ${escapeHtml(loadedModels.length ? "ready" : "choose")}</span>
                  <span class="ioi-home-chip">Receipts: ${escapeHtml(String(receipts.length || 0))}</span>
                </div>
                <button class="ioi-home-submit" type="button" data-command="ioi.studio.open"${commandPayloadAttr({ source: "overview-composer" })}>Start</button>
              </div>
            </section>
            <section class="ioi-home-section" aria-label="Projects">
              <div class="ioi-home-section-head">
                <h2>Projects</h2>
                <button class="ioi-home-link" type="button" data-command="ioi.commandCenter.open"${commandPayloadAttr({ surface: "projects" })}>See all</button>
              </div>
              <div class="ioi-home-table">
                <div class="ioi-home-table-row">
                  <div><strong>${escapeHtml(projectName)}</strong><span>${escapeHtml(workspacePath)}</span></div>
                  <span>Local workspace session target with editor, terminal, model, and browser adapters.</span>
                  <small>${escapeHtml(daemonStatus === "connected" ? "ready" : "setup needed")}</small>
                </div>
                <div class="ioi-home-table-row">
                  <div><strong>Automations</strong><span>${escapeHtml(String(workflowCount))} workflow${workflowCount === 1 ? "" : "s"}</span></div>
                  <span>Composable runs are created through the automation surface and admitted by Core.</span>
                  <small>${escapeHtml(recentWorkflow?.status || "open")}</small>
                </div>
                <div class="ioi-home-table-row">
                  <div><strong>Receipts</strong><span>${escapeHtml(latestReceipt?.receiptId || "No receipt yet")}</span></div>
                  <span>Evidence, replay, state roots, and artifact refs appear after execution.</span>
                  <small>${escapeHtml(latestReceipt ? "available" : "pending")}</small>
                </div>
              </div>
            </section>
          </div>
          <aside class="ioi-home-side" aria-label="Session controls">
            <section class="ioi-home-side-block">
              <div class="ioi-home-section-head"><h2>Create</h2></div>
              ${commandButton({
                label: "Session",
                meta: "recommended",
                description: "Start a governed Hypervisor session from this workspace.",
                command: "ioi.studio.open",
                payload: { source: "overview-create-session" },
                tone: "primary",
              })}
              ${commandButton({
                label: "Automation",
                description: "Open the workflow surface for reusable work.",
                command: "ioi.workflow.openComposer",
                payload: { source: "overview-create-automation" },
              })}
              ${commandButton({
                label: "Models",
                description: "Review mounted routes and local model availability.",
                command: "ioi.models.open",
                payload: { source: "overview-models" },
              })}
            </section>
            <section class="ioi-home-side-block">
              <div class="ioi-home-section-head"><h2>Posture</h2></div>
              <div class="ioi-home-posture">
                ${postureRows
                  .map(
                    ([label, value, detail, tone]) => `
                    <div class="ioi-home-posture-row is-${escapeHtml(tone)}">
                      <span>${escapeHtml(label)}</span>
                      <div><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small></div>
                    </div>
                  `,
                  )
                  .join("")}
              </div>
            </section>
          </aside>
        </div>
      </section>
    </main>
    <script nonce="${pageNonce}">
      const vscode = acquireVsCodeApi();
      function parsePayload(raw) {
        if (!raw) return undefined;
        try {
          return JSON.parse(raw);
        } catch (error) {
          console.error("[IOI Home] Failed to parse command payload", error);
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
