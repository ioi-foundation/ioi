const crypto = require("crypto");
const http = require("http");
const https = require("https");
const vscode = require("vscode");

const VIEW_DEFINITIONS = [
  {
    id: "ioi.chat",
    title: "Chat",
    eyebrow: "Outcome control plane",
    description:
      "Use Chat as a native workbench surface for code-aware prompting, patch review, and outcome shaping.",
    actions: [
      {
        label: "Review current file",
        command: "ioi.chat.reviewFile",
      },
      {
        label: "Explain selected code",
        command: "ioi.chat.explainSelection",
      },
      {
        label: "Open command palette",
        command: "workbench.action.showCommands",
      },
    ],
  },
  {
    id: "ioi.workflows",
    title: "Workflows",
    eyebrow: "Agent orchestration",
    description:
      "Launch, inspect, and sequence agent workflows without leaving the workbench shell.",
    actions: [
      {
        label: "Open workflow surface",
        command: "ioi.workflow.new",
      },
      {
        label: "Start browser validation",
        command: "ioi.automation.browser",
      },
      {
        label: "Focus explorer",
        command: "workbench.view.explorer",
      },
      {
        label: "Open search",
        command: "workbench.view.search",
      },
    ],
  },
  {
    id: "ioi.runs",
    title: "Runs",
    eyebrow: "Runtime evidence",
    description:
      "Track active runs, surface receipts, and jump back to impacted files and artifacts.",
    actions: [
      {
        label: "Open runs surface",
        command: "ioi.runs.refresh",
      },
      {
        label: "Review latest run in Chat",
        command: "ioi.runs.review",
      },
      {
        label: "Run browser remediation",
        command: "ioi.automation.browser",
      },
      {
        label: "Open terminal",
        command: "workbench.action.terminal.toggleTerminal",
      },
      {
        label: "Open output",
        command: "workbench.action.output.toggleOutput",
      },
    ],
  },
  {
    id: "ioi.artifacts",
    title: "Artifacts",
    eyebrow: "Evidence and receipts",
    description:
      "Inspect generated artifacts, provenance, and receipt-linked surfaces as a first-class workbench concern.",
    actions: [
      {
        label: "Open evidence session",
        command: "ioi.artifacts.openEvidence",
      },
      {
        label: "Review latest artifact in Chat",
        command: "ioi.artifacts.review",
      },
      {
        label: "Open connector policy",
        command: "ioi.artifacts.openPolicy",
      },
      {
        label: "Review current file",
        command: "ioi.chat.reviewFile",
      },
      {
        label: "Open explorer",
        command: "workbench.view.explorer",
      },
      {
        label: "Reveal outline",
        command: "outline.focus",
      },
    ],
  },
  {
    id: "ioi.policy",
    title: "Policy",
    eyebrow: "Governed execution",
    description:
      "Keep approvals, authority, and policy context visible while acting from the workspace.",
    actions: [
      {
        label: "Open policy context",
        command: "ioi.policy.open",
      },
      {
        label: "Show problems",
        command: "workbench.actions.view.problems",
      },
      {
        label: "Open settings",
        command: "workbench.action.openSettings",
      },
    ],
  },
  {
    id: "ioi.connections",
    title: "Connections",
    eyebrow: "Services and integrations",
    description:
      "Inspect available services, runtime bindings, and connection posture from inside the workspace.",
    actions: [
      {
        label: "Open connections surface",
        command: "ioi.connections.inspect",
      },
      {
        label: "Open connector overview",
        command: "ioi.connections.openConnector",
      },
      {
        label: "Show source control",
        command: "workbench.view.scm",
      },
      {
        label: "Open extensions",
        command: "workbench.view.extensions",
      },
    ],
  },
];

function bridgeUrl() {
  return process.env.IOI_WORKSPACE_IDE_BRIDGE_URL || null;
}

function workspaceSummary() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return {
      name: "No folder",
      path: "Open a workspace folder to ground IOI context.",
    };
  }

  return {
    name: folder.name,
    path: folder.uri.fsPath,
  };
}

function buildWorkspaceActionContext(source, uri) {
  const editor = vscode.window.activeTextEditor;
  const selection = editor?.selection;
  const selectedText =
    selection && !selection.isEmpty
      ? editor?.document.getText(selection).trim() || null
      : null;

  return {
    workspaceRoot: workspaceSummary().path,
    filePath: resolveFileContext(uri),
    selection:
      selection && !selection.isEmpty
        ? {
            startLineNumber: selection.start.line + 1,
            startColumn: selection.start.character + 1,
            endLineNumber: selection.end.line + 1,
            endColumn: selection.end.character + 1,
            selectedText,
          }
        : null,
    source,
  };
}

function defaultBridgeState() {
  return {
    schemaVersion: 1,
    generatedAtMs: Date.now(),
    authoritativeRuntime: true,
    workspace: workspaceSummary(),
    chat: {
      runtime: "ioi-runtime",
      authority: "bounded",
      helperText:
        "IOI runtime remains authoritative for policy, approvals, evidence, and settlement.",
    },
    workflows: [],
    runs: [],
    artifacts: [],
    policy: null,
    connections: [],
  };
}

function requestBridge(method, bridgePath, payload) {
  const base = bridgeUrl();
  if (!base) {
    return Promise.reject(new Error("IOI workspace bridge URL is not configured."));
  }

  const target = new URL(bridgePath, `${base}/`);
  const client = target.protocol === "https:" ? https : http;
  const body = payload ? JSON.stringify(payload) : null;

  return new Promise((resolve, reject) => {
    const request = client.request(
      target,
      {
        method,
        headers: body
          ? {
              "content-type": "application/json",
              "content-length": Buffer.byteLength(body),
            }
          : undefined,
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          if (response.statusCode >= 400) {
            reject(
              new Error(
                `[IOI Workbench] Bridge request failed (${response.statusCode}): ${raw}`,
              ),
            );
            return;
          }
          resolve(raw);
        });
      },
    );

    request.on("error", reject);
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

async function readBridgeState() {
  try {
    const raw = await requestBridge("GET", "state");
    return {
      ...defaultBridgeState(),
      ...JSON.parse(raw || "{}"),
    };
  } catch (error) {
    console.error("[IOI Workbench] Failed to read bridge state:", error);
    return defaultBridgeState();
  }
}

async function writeBridgeRequest(requestType, payload = {}, context = null) {
  const request = {
    requestId: crypto.randomUUID(),
    requestType,
    context,
    payload,
    timestampMs: Date.now(),
  };
  await requestBridge("POST", "requests", request);
  return request;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatRelativeTime(timestampMs) {
  if (!timestampMs) {
    return "now";
  }
  const elapsed = Math.max(0, Date.now() - timestampMs);
  const minutes = Math.floor(elapsed / 60_000);
  if (minutes < 1) {
    return "<1m ago";
  }
  if (minutes < 60) {
    return `${minutes}m ago`;
  }
  const hours = Math.floor(minutes / 60);
  const rem = minutes % 60;
  return rem > 0 ? `${hours}h ${rem}m ago` : `${hours}h ago`;
}

function renderItems(items, emptyLabel, renderItem) {
  if (!items.length) {
    return `<div class="empty-state">${escapeHtml(emptyLabel)}</div>`;
  }
  return `<div class="stack">${items.map(renderItem).join("")}</div>`;
}

function renderCommandButton(action) {
  const payload =
    action && "payload" in action && action.payload != null
      ? ` data-payload="${escapeHtml(JSON.stringify(action.payload))}"`
      : "";
  return `<button class="action" data-command="${escapeHtml(action.command)}"${payload}>${escapeHtml(action.label)}</button>`;
}

function renderRuntimeSummary(state) {
  const summary = state.summary || {};
  const metrics = [
    ["Workflows", summary.workflowCount ?? 0],
    ["Runs", summary.runCount ?? 0],
    ["Artifacts", summary.artifactCount ?? 0],
    ["Connectors", summary.connectorCount ?? 0],
    ["Policy issues", summary.policyIssueCount ?? 0],
  ];
  return `
    <div class="runtime-strip" aria-label="IOI runtime snapshot">
      ${metrics
        .map(
          ([label, value]) => `
            <div class="runtime-strip__item">
              <span>${escapeHtml(label)}</span>
              <strong>${escapeHtml(value)}</strong>
            </div>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderDiagnostics(state) {
  const diagnostics = state.diagnostics || [];
  if (!diagnostics.length) {
    return "";
  }
  return `
    <div class="diagnostics">
      <strong>Bridge diagnostics</strong>
      ${diagnostics
        .map(
          (item) => `
            <p><code>${escapeHtml(item.label)}</code> ${escapeHtml(item.message)}</p>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderChatView(state) {
  const helper = state.chat?.helperText || "Open Chat from the current file or selection.";
  return `
    ${renderRuntimeSummary(state)}
    <div class="card">
      <strong>Runtime</strong>
      <code>${escapeHtml(state.chat?.runtime || "ioi-runtime")}</code>
      <p>${escapeHtml(helper)}</p>
    </div>
    <div class="callout">
      Chat requests from this pane route back into the IOI runtime. This workbench view does not hold authority on its own.
    </div>
  `;
}

function renderWorkflowView(state) {
  return renderItems(
    state.workflows || [],
    "No workspace workflows were discovered for this repo.",
    (workflow) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(workflow.slashCommand)}</strong>
          <span>${escapeHtml(workflow.stepCount)} steps</span>
        </div>
        <p>${escapeHtml(workflow.description)}</p>
        <code>${escapeHtml(workflow.relativePath || workflow.workflowId)}</code>
        <div class="actions item-actions">
          ${renderCommandButton({
            label: "Open workflow surface",
            command: "ioi.workflow.new",
            payload: {
              workflowId: workflow.workflowId,
              slashCommand: workflow.slashCommand,
              relativePath: workflow.relativePath,
            },
          })}
          ${renderCommandButton({
            label: "Review workflow file",
            command: "ioi.chat.reviewFile",
            payload: {
              filePath: workflow.relativePath,
            },
          })}
        </div>
      </article>
    `,
  );
}

function renderRunsView(state) {
  return renderItems(
    state.runs || [],
    "No active runtime runs are currently attached to this workspace snapshot.",
    (run) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(run.label || run.runId)}</strong>
          <span class="status-pill">${escapeHtml(run.status)}</span>
        </div>
        <p>${escapeHtml(run.summary || "Runtime run")}</p>
        <code>${escapeHtml(run.currentStepLabel || run.runId)}</code>
        <div class="actions item-actions">
          ${renderCommandButton({
            label: "Review in Chat",
            command: "ioi.runs.review",
            payload: {
              runId: run.runId,
              evidenceThreadId: run.reviewSessionId,
              artifactId: run.artifactId,
            },
          })}
          ${
            run.reviewSessionId
              ? renderCommandButton({
                  label: "Open active session",
                  command: "ioi.artifacts.openEvidence",
                  payload: {
                    sessionId: run.reviewSessionId,
                  },
                })
              : ""
          }
          ${
            run.artifactId
              ? renderCommandButton({
                  label: "Open linked artifact",
                  command: "ioi.chatSession.openArtifact",
                  payload: {
                    artifactId: run.artifactId,
                  },
                })
              : ""
          }
          ${
            run.artifactId
              ? renderCommandButton({
                  label: "Review linked artifact in Chat",
                  command: "ioi.artifacts.review",
                  payload: {
                    artifactId: run.artifactId,
                    evidenceThreadId: run.reviewSessionId,
                  },
                })
              : ""
          }
          ${renderCommandButton({
            label: "Open runs surface",
            command: "ioi.runs.refresh",
          })}
        </div>
      </article>
    `,
  );
}

function renderArtifactsView(state) {
  return renderItems(
    state.artifacts || [],
    "No recent artifact/evidence activity is available for this workspace snapshot.",
    (artifact) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(artifact.action || artifact.sessionKind || "Artifact")}</strong>
          <span>${escapeHtml(formatRelativeTime(artifact.timestampMs))}</span>
        </div>
        <p>${escapeHtml(artifact.message || "Evidence-linked activity")}</p>
        <code>${escapeHtml(artifact.evidenceThreadId || artifact.activityId)}</code>
        ${
          artifact.activityId || artifact.evidenceThreadId || artifact.connectorId
            ? `<div class="actions item-actions">
                ${renderCommandButton({
                  label: "Open in Chat Session",
                  command: "ioi.chatSession.openArtifact",
                  payload: {
                    artifactId: artifact.activityId,
                  },
                })}
                ${renderCommandButton({
                  label: "Review in Chat",
                  command: "ioi.artifacts.review",
                  payload: {
                    artifactId: artifact.activityId,
                    evidenceThreadId: artifact.evidenceThreadId,
                    connectorId: artifact.connectorId,
                  },
                })}
                ${
                  artifact.evidenceThreadId
                    ? renderCommandButton({
                        label: "Open evidence session",
                        command: "ioi.artifacts.openEvidence",
                        payload: {
                          sessionId: artifact.evidenceThreadId,
                        },
                      })
                    : ""
                }
                ${
                  artifact.connectorId
                    ? renderCommandButton({
                        label: "Open connector policy",
                        command: "ioi.artifacts.openPolicy",
                        payload: {
                          connectorId: artifact.connectorId,
                        },
                      })
                    : ""
                }
              </div>`
            : ""
        }
      </article>
    `,
  );
}

function renderPolicyView(state) {
  const policy = state.policy;
  if (!policy) {
    return `<div class="empty-state">Policy summary is not available yet for this workspace snapshot.</div>`;
  }
  return `
    <div class="metric-grid">
      <div class="metric-card"><span>Entries</span><strong>${escapeHtml(policy.totalEntries)}</strong></div>
      <div class="metric-card"><span>Connectors</span><strong>${escapeHtml(policy.connectorCount)}</strong></div>
      <div class="metric-card"><span>Connected</span><strong>${escapeHtml(policy.connectedConnectorCount)}</strong></div>
      <div class="metric-card"><span>Runtime skills</span><strong>${escapeHtml(policy.runtimeSkillCount)}</strong></div>
      <div class="metric-card"><span>Authority sources</span><strong>${escapeHtml(policy.authoritativeSourceCount)}</strong></div>
      <div class="metric-card"><span>Active issues</span><strong>${escapeHtml(policy.activeIssueCount)}</strong></div>
    </div>
    <div class="callout">
      Policy state here is a projection of the IOI runtime and capability registry. Approval and settlement authority remain outside the workbench shell.
    </div>
  `;
}

function renderConnectionsView(state) {
  return renderItems(
    state.connections || [],
    "No connector catalog entries are available for this workspace snapshot.",
    (connection) => `
      <article class="item-card">
        <div class="item-head">
          <strong>${escapeHtml(connection.name || connection.id)}</strong>
          <span class="status-pill">${escapeHtml(connection.status || "unknown")}</span>
        </div>
        <p>${escapeHtml(connection.summary || "Connector surface")}</p>
        <code>${escapeHtml(connection.id)}</code>
        <div class="actions item-actions">
          ${renderCommandButton({
            label: "Open connector overview",
            command: "ioi.connections.openConnector",
            payload: {
              connectorId: connection.id,
            },
          })}
          ${renderCommandButton({
            label: "Open connector policy",
            command: "ioi.artifacts.openPolicy",
            payload: {
              connectorId: connection.id,
            },
          })}
        </div>
      </article>
    `,
  );
}

function renderBody(viewId, state) {
  switch (viewId) {
    case "ioi.chat":
      return renderChatView(state);
    case "ioi.workflows":
      return renderWorkflowView(state);
    case "ioi.runs":
      return renderRunsView(state);
    case "ioi.artifacts":
      return renderArtifactsView(state);
    case "ioi.policy":
      return renderPolicyView(state);
    case "ioi.connections":
      return renderConnectionsView(state);
    default:
      return `<div class="empty-state">No renderer registered for this view.</div>`;
  }
}

function renderHtml(view, state) {
  const workspace = state.workspace || workspaceSummary();
  const actions = view.actions
    .map((action) => renderCommandButton(action))
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <style>
      :root {
        color-scheme: dark;
      }
      body {
        margin: 0;
        padding: 16px;
        font-family: var(--vscode-font-family);
        color: var(--vscode-foreground);
        background: var(--vscode-sideBar-background);
      }
      .eyebrow {
        margin: 0 0 8px;
        color: var(--vscode-descriptionForeground);
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      h2 {
        margin: 0 0 10px;
        font-size: 20px;
        line-height: 1.1;
      }
      p {
        margin: 0 0 14px;
        color: var(--vscode-descriptionForeground);
        line-height: 1.45;
      }
      .card, .item-card, .metric-card, .callout, .diagnostics {
        border: 1px solid var(--vscode-panel-border);
        background: color-mix(in srgb, var(--vscode-sideBar-background) 90%, white 10%);
        border-radius: 6px;
      }
      .card, .callout, .diagnostics {
        padding: 12px;
        margin: 0 0 14px;
      }
      .item-card {
        padding: 12px;
      }
      .item-card p {
        margin: 0 0 8px;
      }
      .item-head {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: center;
        margin-bottom: 8px;
      }
      .item-head strong {
        font-size: 13px;
      }
      .status-pill {
        padding: 2px 8px;
        border-radius: 999px;
        background: color-mix(in srgb, var(--vscode-badge-background) 78%, transparent 22%);
        color: var(--vscode-badge-foreground);
        font-size: 11px;
      }
      .metric-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 10px;
      }
      .metric-card {
        padding: 10px 12px;
      }
      .metric-card span {
        display: block;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.06em;
      }
      .metric-card strong {
        font-size: 18px;
      }
      .runtime-strip {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px;
        margin: 0 0 14px;
      }
      .runtime-strip__item {
        min-width: 0;
        padding: 8px 9px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-sideBar-background) 92%, white 8%);
      }
      .runtime-strip__item span {
        display: block;
        color: var(--vscode-descriptionForeground);
        font-size: 10px;
        margin-bottom: 3px;
      }
      .runtime-strip__item strong {
        font-size: 15px;
      }
      .diagnostics {
        border-color: var(--vscode-inputValidation-warningBorder, var(--vscode-panel-border));
      }
      .diagnostics strong {
        display: block;
        margin-bottom: 8px;
      }
      .diagnostics p {
        margin: 0 0 6px;
      }
      code {
        display: block;
        white-space: normal;
        word-break: break-word;
        color: var(--vscode-textPreformat-foreground);
        font-size: 12px;
      }
      .stack {
        display: grid;
        gap: 10px;
      }
      .actions {
        display: grid;
        gap: 8px;
        margin-bottom: 14px;
      }
      .item-actions {
        margin-top: 10px;
        margin-bottom: 0;
      }
      .action {
        appearance: none;
        border: 1px solid var(--vscode-button-border, transparent);
        border-radius: 4px;
        background: var(--vscode-button-secondaryBackground);
        color: var(--vscode-button-secondaryForeground);
        text-align: left;
        padding: 10px 12px;
        font: inherit;
        cursor: pointer;
      }
      .action:hover {
        background: var(--vscode-button-secondaryHoverBackground);
      }
      .workspace-card {
        margin-bottom: 14px;
      }
      .empty-state {
        border: 1px dashed var(--vscode-panel-border);
        border-radius: 12px;
        padding: 14px 12px;
        color: var(--vscode-descriptionForeground);
      }
      .footer {
        margin-top: 14px;
        font-size: 11px;
        color: var(--vscode-descriptionForeground);
      }
    </style>
  </head>
  <body>
    <p class="eyebrow">${escapeHtml(view.eyebrow)}</p>
    <h2>${escapeHtml(view.title)}</h2>
    <p>${escapeHtml(view.description)}</p>
    <div class="card workspace-card">
      <strong>Workspace</strong>
      <code>${escapeHtml(workspace.name || "No folder")}</code>
      <code>${escapeHtml(workspace.rootPath || workspace.path || "No folder selected")}</code>
    </div>
    ${view.id === "ioi.chat" ? "" : renderRuntimeSummary(state)}
    ${renderDiagnostics(state)}
    <div class="actions">${actions}</div>
    ${renderBody(view.id, state)}
    <div class="footer">Snapshot refreshed ${escapeHtml(formatRelativeTime(state.generatedAtMs))} · IOI runtime remains authoritative.</div>
    <script>
      const vscode = acquireVsCodeApi();
      document.querySelectorAll("[data-command]").forEach((button) => {
        button.addEventListener("click", () => {
          const rawPayload = button.dataset.payload;
          let payload = undefined;
          if (rawPayload) {
            try {
              payload = JSON.parse(rawPayload);
            } catch (error) {
              console.error("[IOI Workbench] Failed to parse command payload:", error);
            }
          }
          vscode.postMessage({ type: "command", command: button.dataset.command, payload });
        });
      });
    </script>
  </body>
</html>`;
}

class IOIViewProvider {
  constructor(definition, getState) {
    this.definition = definition;
    this.getState = getState;
    this.webviewView = null;
  }

  resolveWebviewView(webviewView) {
    this.webviewView = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
    };
    void this.render();
    webviewView.webview.onDidReceiveMessage(async (message) => {
      if (message?.type !== "command" || typeof message.command !== "string") {
        return;
      }
      await vscode.commands.executeCommand(message.command, message.payload);
    });
    webviewView.onDidDispose(() => {
      this.webviewView = null;
    });
  }

  async render() {
    if (!this.webviewView) {
      return;
    }
    this.webviewView.webview.html = renderHtml(
      this.definition,
      await this.getState(),
    );
  }
}

function watchBridgeState(onChange) {
  const handle = setInterval(() => {
    void onChange();
  }, 2_000);
  return {
    dispose() {
      clearInterval(handle);
    },
  };
}

function resolveFileContext(uri) {
  if (uri?.scheme === "file") {
    return uri.fsPath;
  }

  const activeEditorPath = vscode.window.activeTextEditor?.document.uri.fsPath;
  if (activeEditorPath) {
    return activeEditorPath;
  }

  const explorerSelection = vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .find((tab) => tab.isActive)?.input?.uri?.fsPath;
  return explorerSelection || null;
}

function registerNativeCommands(context, output) {
  const status = (message) =>
    vscode.window.setStatusBarMessage(`$(symbol-keyword) ${message}`, 3000);
  const pickString = (value, key) => {
    if (typeof value === "string") {
      return value;
    }
    if (value && typeof value === "object" && typeof value[key] === "string") {
      return value[key];
    }
    return null;
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("ioi.chat.explainSelection", async (uri) => {
      const context = buildWorkspaceActionContext("editor", uri);
      const payloadFilePath = pickString(uri, "filePath");
      const payloadSelectedText = pickString(uri, "selectedText");
      if (payloadFilePath) {
        context.filePath = payloadFilePath;
      }
      await writeBridgeRequest("chat.explainSelection", {
        filePath: context.filePath,
        selectedText: payloadSelectedText ?? context.selection?.selectedText ?? null,
      }, context);
      status("Queued IOI Chat selection review.");
    }),
    vscode.commands.registerCommand("ioi.chat.reviewFile", async (uri) => {
      const payloadFilePath = pickString(uri, "filePath");
      const context = buildWorkspaceActionContext(
        uri && !payloadFilePath ? "explorer" : "editor",
        uri,
      );
      if (payloadFilePath) {
        context.filePath = payloadFilePath;
      }
      await writeBridgeRequest("chat.reviewFile", {
        filePath: context.filePath,
      }, context);
      status("Queued IOI Chat file review.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.review", async (payload) => {
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        artifactId: pickString(payload, "artifactId"),
        evidenceThreadId: pickString(payload, "evidenceThreadId"),
        connectorId: pickString(payload, "connectorId"),
      };
      await writeBridgeRequest(
        "chat.reviewArtifact",
        {
          artifactId: context.artifactId,
          evidenceThreadId: context.evidenceThreadId,
          connectorId: context.connectorId,
        },
        context,
      );
      status("Queued IOI Chat artifact review.");
    }),
    vscode.commands.registerCommand("ioi.workflow.new", async () => {
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("workflow.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI workflow surface.");
    }),
    vscode.commands.registerCommand("ioi.runs.refresh", async () => {
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("runs.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI runs surface.");
    }),
    vscode.commands.registerCommand("ioi.runs.review", async (payload) => {
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        runId: pickString(payload, "runId"),
        artifactId: pickString(payload, "artifactId"),
        evidenceThreadId: pickString(payload, "evidenceThreadId"),
      };
      await writeBridgeRequest(
        "chat.reviewRun",
        {
          runId: context.runId,
          artifactId: context.artifactId,
          evidenceThreadId: context.evidenceThreadId,
        },
        context,
      );
      status("Queued IOI Chat run review.");
    }),
    vscode.commands.registerCommand("ioi.policy.open", async () => {
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI policy surface.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.openEvidence", async (payload) => {
      const sessionId = pickString(payload, "sessionId");
      if (!sessionId) {
        vscode.window.showWarningMessage("No evidence session is available for this artifact.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        evidenceThreadId: sessionId,
      };
      await writeBridgeRequest("evidence.open", {
        sessionId,
      }, context);
      status("Queued IOI evidence session.");
    }),
    vscode.commands.registerCommand("ioi.artifacts.openPolicy", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("policy.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, context);
      status("Queued artifact policy context.");
    }),
    vscode.commands.registerCommand("ioi.chatSession.openArtifact", async (payload) => {
      const artifactId = pickString(payload, "artifactId");
      if (!artifactId) {
        vscode.window.showWarningMessage("No artifact target is available for Chat Session.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        artifactId,
      };
      await writeBridgeRequest("chatSession.openArtifact", {
        artifactId,
      }, context);
      status("Queued Chat Session artifact drill-in.");
    }),
    vscode.commands.registerCommand("ioi.connections.inspect", async () => {
      const context = buildWorkspaceActionContext("workbench-view");
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
      }, context);
      status("Queued IOI connections surface.");
    }),
    vscode.commands.registerCommand("ioi.connections.openConnector", async (payload) => {
      const connectorId = pickString(payload, "connectorId");
      if (!connectorId) {
        vscode.window.showWarningMessage("No connector target is available for this workspace item.");
        return;
      }
      const context = {
        ...buildWorkspaceActionContext("workbench-view"),
        connectorId,
      };
      await writeBridgeRequest("connections.open", {
        workspaceRoot: workspaceSummary().path,
        connectorId,
      }, context);
      status("Queued IOI connector overview.");
    }),
    vscode.commands.registerCommand("ioi.automation.browser", async (uri) => {
      const context = buildWorkspaceActionContext(uri ? "explorer" : "editor", uri);
      await writeBridgeRequest("automation.browser", {
        workspaceRoot: workspaceSummary().path,
        filePath: context.filePath,
        selectedText: context.selection?.selectedText ?? null,
      }, context);
      status("Queued governed browser/computer-use.");
    }),
  );

  output.appendLine("Registered IOI runtime bridge commands.");
}

function activate(context) {
  const output = vscode.window.createOutputChannel("IOI Workbench");
  output.appendLine("IOI Workbench extension activated.");
  context.subscriptions.push(output);

  const statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    80,
  );
  statusItem.name = "IOI Workbench";
  statusItem.text = "$(symbol-keyword) IOI";
  statusItem.tooltip = "IOI-native workbench surfaces are available.";
  statusItem.command = "workbench.view.extension.ioi";
  statusItem.show();
  context.subscriptions.push(statusItem);

  const providers = VIEW_DEFINITIONS.map(
    (definition) => new IOIViewProvider(definition, readBridgeState),
  );

  for (const provider of providers) {
    context.subscriptions.push(
      vscode.window.registerWebviewViewProvider(
        provider.definition.id,
        provider,
      ),
    );
  }

  context.subscriptions.push(
    watchBridgeState(() => {
      for (const provider of providers) {
        void provider.render();
      }
    }),
  );

  registerNativeCommands(context, output);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
};
