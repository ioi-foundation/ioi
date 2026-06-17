"use strict";

function createWorkbenchCodeModePanelRenderer({
  hypervisorShellHeaderStyles,
  buildWorkbenchContextSnapshot,
  escapeHtml,
  nonce,
  workspaceSummary,
}) {
  function relativeWorkspacePath(workspacePath, filePath) {
    const rawPath = typeof filePath === "string" ? filePath.trim() : "";
    if (!rawPath) {
      return "unknown";
    }
    const root = typeof workspacePath === "string" ? workspacePath.replace(/\/+$/, "") : "";
    if (root && rawPath.startsWith(`${root}/`)) {
      return rawPath.slice(root.length + 1);
    }
    return rawPath;
  }

  function shortPathLabel(path) {
    const value = typeof path === "string" && path.trim() ? path.trim() : "unknown";
    const segments = value.split("/").filter(Boolean);
    return segments.length ? segments[segments.length - 1] : value;
  }

  function codeRepositoryGateProjection(state) {
    const context = buildWorkbenchContextSnapshot("code-repositories-gate");
    const workspace = context.workspace || state.workspace || workspaceSummary();
    const workspacePath = typeof workspace.path === "string" ? workspace.path.trim() : "";
    const workspaceName = typeof workspace.name === "string" && workspace.name.trim()
      ? workspace.name.trim()
      : shortPathLabel(workspacePath);
    const currentRepository = workspacePath
      ? {
          id: "current-workspace",
          name: workspaceName || "Current workspace",
          rootPath: workspacePath,
          description: "Current Hypervisor workspace",
          favorite: false,
        }
      : null;
    return {
      context,
      workspace,
      repositories: currentRepository ? [currentRepository] : [],
    };
  }

  function repositoryGateIconSvg() {
    return `<svg class="workspace-repository-gate__icon" viewBox="0 0 30 30" role="img" aria-label="Repository">
    <defs>
      <linearGradient id="repoGateShell" x1="4" x2="26" y1="5" y2="25" gradientUnits="userSpaceOnUse">
        <stop stop-color="#ffffff" />
        <stop offset="1" stop-color="#dbe7f0" />
      </linearGradient>
    </defs>
    <rect x="4.5" y="5.5" width="21" height="19" rx="3" fill="url(#repoGateShell)" stroke="#7890a4" />
    <path d="M9 11.5h7.2M9 15h11.5M9 18.5h8.5" stroke="#4b6478" stroke-width="1.4" stroke-linecap="round" />
    <path d="M7.8 9.2 10.8 12l-3 2.8" fill="none" stroke="#283d4d" stroke-width="1.45" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
  }

  function searchIconSvg(size = 16) {
    const numericSize = Number.isFinite(size) ? size : 16;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="2" />
    <path d="m16.5 16.5 4 4" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
  </svg>`;
  }

  function plusIconSvg(size = 16) {
    const numericSize = Number.isFinite(size) ? size : 16;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
  </svg>`;
  }

  function pullRequestIconSvg(size = 46) {
    const numericSize = Number.isFinite(size) ? size : 46;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="6" cy="6" r="3" stroke="currentColor" stroke-width="1.4" />
    <circle cx="18" cy="18" r="3" stroke="currentColor" stroke-width="1.4" />
    <path d="M6 9v9M18 15V8.8A3.8 3.8 0 0 0 14.2 5H12" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
    <path d="m14 2.8-2.2 2.2L14 7.2" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
  }

  function externalLinkIconSvg(size = 16) {
    const numericSize = Number.isFinite(size) ? size : 16;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M14 5h5v5M10 14 19 5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M19 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
  </svg>`;
  }

  function folderIconSvg(size = 16) {
    const numericSize = Number.isFinite(size) ? size : 16;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="M3.5 7.5A2.5 2.5 0 0 1 6 5h4.2l2 2H18a2.5 2.5 0 0 1 2.5 2.5v7A2.5 2.5 0 0 1 18 19H6a2.5 2.5 0 0 1-2.5-2.5v-9Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" />
  </svg>`;
  }

  function chevronRightIconSvg(size = 15) {
    const numericSize = Number.isFinite(size) ? size : 15;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="m9 18 6-6-6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
  </svg>`;
  }

  function starIconSvg(size = 15) {
    const numericSize = Number.isFinite(size) ? size : 15;
    return `<svg width="${numericSize}" height="${numericSize}" viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path d="m12 3.4 2.5 5.1 5.7.8-4.1 4 1 5.7-5.1-2.7L6.9 19l1-5.7-4.1-4 5.7-.8L12 3.4Z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round" />
  </svg>`;
  }

  function renderRepositoryGateList(items, emptyLabel) {
    if (!items.length) {
      return `<div class="workspace-repository-gate__empty-small">${escapeHtml(emptyLabel)}</div>`;
    }
    return items
      .map(
        (repository) => `
        <div class="workspace-repository-gate__repo-row">
          <button
            type="button"
            class="workspace-repository-gate__repo-open"
            data-command="workbench.action.files.openFolder"
            data-testid="code-repository-open-current"
          >
            ${folderIconSvg(16)}
            <span>
              <strong>${escapeHtml(repository.name)}</strong>
              <small>${escapeHtml(relativeWorkspacePath("", repository.rootPath))}</small>
            </span>
            ${chevronRightIconSvg(15)}
          </button>
          <button
            type="button"
            class="workspace-repository-gate__favorite-button"
            aria-label="Add ${escapeHtml(repository.name)} to favorites"
            title="Add to favorites"
          >
            ${starIconSvg(15)}
          </button>
        </div>
      `,
      )
      .join("");
  }

  function codeModePanelHtml(state) {
    const pageNonce = nonce();
    const projection = codeRepositoryGateProjection(state);
    const repositories = projection.repositories;
    const recentRows = renderRepositoryGateList(repositories, "No recent activity");
    const favoriteRows = renderRepositoryGateList(
      repositories.filter((repository) => repository.favorite),
      "You have no favorites",
    );
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'nonce-${pageNonce}'; script-src 'nonce-${pageNonce}';"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Hypervisor Workbench</title>
    <style nonce="${pageNonce}">
      :root {
        color-scheme: dark;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: var(--vscode-font-family, ui-sans-serif, system-ui, sans-serif);
        color: var(--vscode-foreground);
        background: var(--vscode-editor-background);
      }
      ${hypervisorShellHeaderStyles()}
      .code-repository-shell {
        min-height: calc(100vh - 50px);
        display: grid;
        grid-template-columns: minmax(250px, 318px) minmax(0, 1fr);
        gap: 0;
      }
      .code-repository-rail {
        min-height: 0;
        padding: 18px;
        border-right: 1px solid var(--vscode-panel-border);
        background: var(--vscode-sideBar-background);
        display: grid;
        align-content: start;
        gap: 18px;
      }
      .code-repository-rail h1,
      .code-repository-main h2,
      .code-repository-main h3 {
        margin: 0;
      }
      .code-repository-rail h1 {
        font-size: 20px;
      }
      .code-repository-main h2 {
        font-size: 22px;
      }
      .code-repository-main h3 {
        font-size: 14px;
      }
      .code-repository-rail p,
      .code-repository-main p {
        margin: 6px 0 0;
        color: var(--vscode-descriptionForeground);
        line-height: 1.45;
      }
      .code-repository-actions {
        display: grid;
        gap: 8px;
      }
      .code-repository-action {
        min-height: 36px;
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 5px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        padding: 8px 10px;
        font: inherit;
        text-align: left;
      }
      .code-repository-action:hover {
        background: var(--vscode-button-secondaryHoverBackground);
      }
      .code-repository-main {
        min-width: 0;
        min-height: 0;
        display: grid;
        grid-template-rows: auto auto minmax(0, 1fr);
        background: var(--vscode-editor-background);
      }
      .code-repository-hero {
        padding: 24px 28px 20px;
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .code-repository-metrics {
        display: grid;
        grid-template-columns: repeat(5, minmax(110px, 1fr));
        border-bottom: 1px solid var(--vscode-panel-border);
      }
      .code-repository-metric {
        min-width: 0;
        padding: 13px 18px;
        border-right: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-editor-background) 92%, var(--vscode-foreground) 5%);
      }
      .code-repository-metric span,
      .code-repository-section-label,
      .code-repository-chip span,
      .code-repository-footnote {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .code-repository-metric strong {
        display: block;
        margin-top: 5px;
        font-size: 16px;
        overflow-wrap: anywhere;
      }
      .code-repository-body {
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(0, 1.1fr) minmax(320px, 0.9fr);
        overflow: hidden;
      }
      .code-repository-pane {
        min-width: 0;
        min-height: 0;
        padding: 18px 22px;
        overflow: auto;
      }
      .code-repository-pane + .code-repository-pane {
        border-left: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 88%, var(--vscode-editor-background) 12%);
      }
      .code-repository-section {
        display: grid;
        gap: 10px;
        margin-bottom: 22px;
      }
      .code-repository-section header {
        display: flex;
        align-items: end;
        justify-content: space-between;
        gap: 12px;
      }
      .code-repository-table {
        width: 100%;
        border-collapse: collapse;
        border: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-editor-background) 94%, var(--vscode-foreground) 4%);
      }
      .code-repository-table th,
      .code-repository-table td {
        padding: 9px 10px;
        border-bottom: 1px solid var(--vscode-panel-border);
        text-align: left;
        vertical-align: top;
      }
      .code-repository-table th {
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        background: color-mix(in srgb, var(--vscode-editor-background) 88%, var(--vscode-foreground) 6%);
      }
      .code-repository-table td:first-child {
        width: 72px;
      }
      .code-repository-table td:last-child {
        width: 96px;
        text-align: right;
      }
      .code-repository-table strong,
      .code-repository-table span {
        display: block;
        overflow-wrap: anywhere;
      }
      .code-repository-table span {
        margin-top: 3px;
        color: var(--vscode-descriptionForeground);
        font-size: 12px;
      }
      .code-repository-table button {
        min-height: 26px;
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 4px;
        padding: 3px 8px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font: inherit;
        cursor: pointer;
      }
      .code-repository-status {
        display: inline-flex;
        min-width: 34px;
        height: 20px;
        align-items: center;
        justify-content: center;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 999px;
        padding: 0 7px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        text-transform: uppercase;
      }
      .code-repository-status.is-clean {
        border-color: color-mix(in srgb, #3fb950 70%, var(--vscode-panel-border));
        color: #7ee787;
      }
      .code-repository-status.is-dirty,
      .code-repository-status.is-warn {
        border-color: color-mix(in srgb, #d29922 70%, var(--vscode-panel-border));
        color: #e3b341;
      }
      .code-repository-status.is-muted {
        color: var(--vscode-descriptionForeground);
      }
      .code-repository-empty {
        color: var(--vscode-descriptionForeground);
      }
      .code-repository-chip-grid {
        display: grid;
        gap: 8px;
      }
      .code-repository-chip {
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto;
        gap: 12px;
        align-items: center;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        padding: 10px 12px;
        background: color-mix(in srgb, var(--vscode-editor-background) 92%, var(--vscode-foreground) 5%);
      }
      .code-repository-chip strong {
        overflow-wrap: anywhere;
      }
      .code-repository-chip button {
        min-height: 28px;
        border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
        border-radius: 4px;
        padding: 4px 8px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        font: inherit;
        cursor: pointer;
      }
      .code-repository-footnote {
        text-transform: none;
        letter-spacing: 0;
        line-height: 1.45;
      }
      @media (max-width: 880px) {
        .code-repository-shell,
        .code-repository-body,
        .code-repository-metrics {
          grid-template-columns: minmax(0, 1fr);
        }
      }
      .workspace-repository-gate {
        height: 100vh;
        min-width: 0;
        min-height: 0;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        background: #f5f7fa;
        color: #1f2933;
      }
      .workspace-repository-gate button,
      .workspace-repository-gate input {
        font: inherit;
      }
      .workspace-repository-gate__header {
        flex: 0 0 52px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        padding: 0 18px 0 10px;
        border-bottom: 1px solid #d5dce4;
        background: #ffffff;
      }
      .workspace-repository-gate__title {
        min-width: 0;
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .workspace-repository-gate__title h1 {
        margin: 0;
        overflow: hidden;
        color: #344150;
        font-size: 15px;
        font-weight: 700;
        letter-spacing: 0;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .workspace-repository-gate__icon-shell {
        width: 34px;
        height: 30px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 1px solid #a9bac8;
        border-radius: 3px;
        background: #edf4f8;
      }
      .workspace-repository-gate__icon {
        width: 26px;
        height: 26px;
        display: block;
      }
      .workspace-repository-gate__primary-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 7px;
        min-height: 30px;
        padding: 0 12px;
        border: 1px solid #19703f;
        border-radius: 4px;
        background: #1f7f49;
        color: #ffffff;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
        transition:
          background 120ms ease,
          border-color 120ms ease;
      }
      .workspace-repository-gate__primary-button:hover {
        border-color: #155f36;
        background: #176b3d;
      }
      .workspace-repository-gate__landing {
        flex: 1;
        min-height: 0;
        display: flex;
        flex-direction: column;
        overflow: hidden;
      }
      .workspace-repository-gate__content {
        flex: 1;
        min-height: 0;
        display: grid;
        grid-template-columns: minmax(420px, 840px) minmax(280px, 322px);
        justify-content: center;
        gap: 18px;
        overflow: auto;
        padding: 24px;
      }
      .workspace-repository-gate__main,
      .workspace-repository-gate__rail {
        min-width: 0;
      }
      .workspace-repository-gate__main {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }
      .workspace-repository-gate__pr-toolbar {
        display: grid;
        grid-template-columns: auto minmax(220px, 1fr);
        align-items: center;
        gap: 20px;
      }
      .workspace-repository-gate__tabs {
        display: flex;
        align-items: center;
        gap: 8px;
        white-space: nowrap;
      }
      .workspace-repository-gate__tabs button {
        min-height: 30px;
        padding: 0 11px;
        border: 0;
        border-radius: 999px;
        background: #e7ebf0;
        color: #425466;
        font-size: 12px;
        cursor: pointer;
      }
      .workspace-repository-gate__tabs button.is-active {
        background: transparent;
        color: #1f2933;
        font-weight: 700;
      }
      .workspace-repository-gate__search-field,
      .workspace-repository-gate__repository-search {
        min-width: 0;
        display: flex;
        align-items: center;
        gap: 8px;
        border: 1px solid #b8c2cc;
        border-radius: 4px;
        background: #ffffff;
        color: #66788a;
      }
      .workspace-repository-gate__search-field,
      .workspace-repository-gate__repository-search {
        height: 30px;
        padding: 0 9px;
      }
      .workspace-repository-gate__search-field input,
      .workspace-repository-gate__repository-search input {
        width: 100%;
        min-width: 0;
        border: 0;
        outline: 0;
        background: transparent;
        color: #1f2933;
        font-size: 12px;
      }
      .workspace-repository-gate__pr-empty {
        min-height: 236px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 28px;
        border: 1px solid #d0d7df;
        border-radius: 4px;
        background: #ffffff;
        color: #637083;
        text-align: center;
      }
      .workspace-repository-gate__pr-empty svg {
        color: #c5cfda;
      }
      .workspace-repository-gate__pr-empty h2 {
        margin: 0;
        color: #637083;
        font-size: 16px;
        line-height: 1.2;
      }
      .workspace-repository-gate__pr-empty p {
        width: min(440px, 100%);
        margin: 0;
        color: #526274;
        font-size: 12px;
        line-height: 1.45;
      }
      .workspace-repository-gate__rail {
        display: flex;
        flex-direction: column;
        gap: 18px;
      }
      .workspace-repository-gate__rail-heading {
        min-height: 28px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .workspace-repository-gate__rail-heading h2 {
        margin: 0;
        color: #1f2933;
        font-size: 12px;
        font-weight: 700;
      }
      .workspace-repository-gate__rail-heading button {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        border: 0;
        background: transparent;
        color: #0f5cc0;
        font-size: 12px;
        cursor: pointer;
      }
      .workspace-repository-gate__news,
      .workspace-repository-gate__repositories {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }
      .workspace-repository-gate__news-card,
      .workspace-repository-gate__repo-card {
        border: 1px solid #d0d7df;
        border-radius: 4px;
        background: #ffffff;
      }
      .workspace-repository-gate__news-card {
        padding: 16px;
      }
      .workspace-repository-gate__news-card div {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 8px;
      }
      .workspace-repository-gate__news-card span {
        display: inline-flex;
        align-items: center;
        min-height: 20px;
        padding: 0 8px;
        border-radius: 4px;
        background: #e8f0ff;
        color: #1558c7;
        font-size: 11px;
      }
      .workspace-repository-gate__news-card time {
        color: #66788a;
        font-size: 12px;
      }
      .workspace-repository-gate__news-card p {
        margin: 0;
        color: #1f2933;
        font-size: 12px;
        line-height: 1.35;
      }
      .workspace-repository-gate__news-card button {
        margin-top: 8px;
        padding: 0;
        border: 0;
        background: transparent;
        color: #0f5cc0;
        font-size: 12px;
        cursor: pointer;
      }
      .workspace-repository-gate__repo-card h3 {
        margin: 0;
        padding: 13px 20px;
        border-bottom: 1px solid #dce2e8;
        color: #1f2933;
        font-size: 12px;
        font-weight: 700;
      }
      .workspace-repository-gate__repo-list {
        min-height: 74px;
        display: flex;
        flex-direction: column;
      }
      .workspace-repository-gate__repo-row {
        display: grid;
        grid-template-columns: minmax(0, 1fr) 34px;
        border-bottom: 1px solid #edf0f3;
      }
      .workspace-repository-gate__repo-row:last-child {
        border-bottom: 0;
      }
      .workspace-repository-gate__repo-open {
        min-width: 0;
        display: grid;
        grid-template-columns: 18px minmax(0, 1fr) 15px;
        align-items: center;
        gap: 8px;
        padding: 10px 8px 10px 16px;
        border: 0;
        background: transparent;
        color: #425466;
        text-align: left;
        cursor: pointer;
      }
      .workspace-repository-gate__repo-open:hover {
        background: #f7f9fb;
      }
      .workspace-repository-gate__repo-open span {
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 2px;
      }
      .workspace-repository-gate__repo-open strong,
      .workspace-repository-gate__repo-open small {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .workspace-repository-gate__repo-open strong {
        color: #1f2933;
        font-size: 12px;
      }
      .workspace-repository-gate__repo-open small {
        color: #66788a;
        font-size: 11px;
      }
      .workspace-repository-gate__favorite-button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border: 0;
        border-left: 1px solid #edf0f3;
        background: transparent;
        color: #8091a3;
        cursor: pointer;
      }
      .workspace-repository-gate__favorite-button:hover {
        background: #f7f9fb;
        color: #b78105;
      }
      .workspace-repository-gate__empty-small {
        min-height: 74px;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 18px;
        color: #66788a;
        font-size: 12px;
        text-align: center;
      }
      .code-repository-substrate-sentinel {
        position: absolute;
        width: 1px;
        height: 1px;
        overflow: hidden;
        clip: rect(0 0 0 0);
        clip-path: inset(50%);
        white-space: nowrap;
      }
      @media (max-width: 880px) {
        .workspace-repository-gate__content,
        .workspace-repository-gate__pr-toolbar {
          grid-template-columns: minmax(0, 1fr);
        }
        .workspace-repository-gate__tabs {
          overflow-x: auto;
        }
      }
    </style>
  </head>
  <body>
    <main
      class="workspace-repository-gate"
      data-testid="hypervisor-code-mode"
      data-runtime-authority="daemon-owned"
      data-vscode-substrate-visible="true"
    >
      <div class="code-repository-substrate-sentinel" aria-hidden="true">
        <button type="button" data-command="ioi.hypervisor.back" data-testid="code-mode-back-to-hypervisor">Back to Hypervisor</button>
        <button type="button" data-command="workbench.view.explorer" data-testid="code-mode-explorer">Explorer</button>
        <button type="button" data-command="workbench.view.search" data-testid="code-mode-search">Search</button>
        <button type="button" data-command="workbench.view.scm" data-testid="code-mode-scm">Source Control</button>
        <button type="button" data-command="workbench.view.debug" data-testid="code-mode-run-debug">Run / Debug</button>
        <button type="button" data-command="workbench.view.extensions" data-testid="code-mode-extensions">Extensions</button>
        <button type="button" data-command="workbench.action.terminal.toggleTerminal" data-testid="code-mode-terminal">Terminal</button>
        <span data-testid="code-mode-vscode-menu-tooling">local substrate controls visible</span>
      </div>
      <header class="workspace-repository-gate__header" data-testid="code-repository-surface">
        <div class="workspace-repository-gate__title">
          <span class="workspace-repository-gate__icon-shell">
            ${repositoryGateIconSvg()}
          </span>
          <h1>Code repositories</h1>
        </div>
        <button
          type="button"
          class="workspace-repository-gate__primary-button"
          data-command="ioi.commandCenter.open"
          data-payload='{"initialQuery":"new code repository"}'
          data-testid="code-repository-new"
        >
          ${plusIconSvg(16)}
          <span>New repository</span>
        </button>
      </header>
      <div class="workspace-repository-gate__landing" data-testid="code-repositories-gate">
        <div class="workspace-repository-gate__content">
          <main class="workspace-repository-gate__main">
            <div class="workspace-repository-gate__pr-toolbar">
              <div class="workspace-repository-gate__tabs" role="tablist">
                <button type="button" class="is-active">Pull requests</button>
                <button type="button">Created by you</button>
                <button type="button">Review requested</button>
              </div>
              <label class="workspace-repository-gate__search-field">
                ${searchIconSvg(16)}
                <input type="search" placeholder="Find pull requests..." />
              </label>
            </div>
            <section class="workspace-repository-gate__pr-empty">
              ${pullRequestIconSvg(46)}
              <h2>No pull requests created by you</h2>
              <p>
                There are no open pull requests created by you. Here are the
                recently visited code repositories and their pull requests.
              </p>
            </section>
          </main>

          <aside class="workspace-repository-gate__rail">
            <section class="workspace-repository-gate__news">
              <div class="workspace-repository-gate__rail-heading">
                <h2>What's new?</h2>
                <button type="button">
                  <span>See all</span>
                  ${externalLinkIconSvg(16)}
                </button>
              </div>
              <article class="workspace-repository-gate__news-card">
                <div>
                  <span>Feature</span>
                  <time datetime="2026-04-21">Apr 21, 2026</time>
                </div>
                <p>
                  Ontology Manager now displays run history directly within
                  function and action observability dashboards.
                </p>
                <button type="button">More</button>
              </article>
            </section>

            <section class="workspace-repository-gate__repositories">
              <div class="workspace-repository-gate__rail-heading">
                <h2>Repositories</h2>
                ${searchIconSvg(18)}
              </div>
              <label class="workspace-repository-gate__repository-search">
                ${searchIconSvg(15)}
                <input type="search" placeholder="Search repositories" />
              </label>
              <div class="workspace-repository-gate__repo-card">
                <h3>Recents</h3>
                <div class="workspace-repository-gate__repo-list">${recentRows}</div>
              </div>
              <div class="workspace-repository-gate__repo-card">
                <h3>Favorites</h3>
                <div class="workspace-repository-gate__repo-list">${favoriteRows}</div>
              </div>
            </section>
          </aside>
        </div>
      </div>
    </main>
    <script nonce="${pageNonce}">
      const vscode = acquireVsCodeApi();
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          vscode.postMessage({
            type: "command",
            command: button.dataset.command,
            payload: button.dataset.payload ? JSON.parse(button.dataset.payload) : undefined
          });
        });
      });
    </script>
  </body>
</html>`;
  }

  return {
    codeModePanelHtml,
    codeRepositoryGateProjection,
    relativeWorkspacePath,
    renderRepositoryGateList,
    shortPathLabel,
  };
}

module.exports = {
  createWorkbenchCodeModePanelRenderer,
};
