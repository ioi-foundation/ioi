const crypto = require("crypto");
const http = require("http");
const https = require("https");

function buildRuntimeRefs() {
  return {
    receiptRefs: [],
    artifactRefs: [],
    authorityRefs: [],
    manifestRefs: [],
    capabilityRefs: [],
  };
}

function hashRef(prefix, value) {
  const stableValue = typeof value === "string" ? value : JSON.stringify(value || {});
  return `${prefix}:${crypto.createHash("sha256").update(stableValue).digest("hex").slice(0, 16)}`;
}

function isRuntimeActionRequestType(requestType) {
  return /^(commandCenter|code)\./.test(
    requestType,
  );
}

function buildWorkbenchCommandRouteReceipt({
  commandId,
  route,
  status = "routed",
  context = null,
  reason = null,
  actionProposalRef = null,
}) {
  return {
    schemaVersion: "ioi.code-editor-adapter.v1",
    receiptId: `code-editor-command-route:${crypto.randomUUID()}`,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
    commandId,
    routedAtMs: Date.now(),
    route,
    contextRef: context ? hashRef("code-editor-context", context) : null,
    actionProposalRef,
    status,
    reason,
    runtimeRefs: buildRuntimeRefs(),
  };
}

function createWorkspaceBridge({
  bridgeUrl,
  readDaemonModelSnapshot,
  workspaceSummary,
  vscode,
  modelSnapshotTimeoutMs,
  refreshStateTimeoutMs,
}) {
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
      appearance: {
        themeId: "dark-modern",
        themeLabel: "Dark Modern",
        density: "default",
        openVsCodeColorTheme: "Default Dark Modern",
        source: "default",
        updatedAtMs: 0,
      },
      workflows: [],
      runs: [],
      artifacts: [],
      policy: null,
      connections: [],
    };
  }

  function requestBridge(method, bridgePath, payload, { timeoutMs } = {}) {
    const base = bridgeUrl();
    if (!base) {
      return Promise.reject(new Error("IOI code editor adapter bridge URL is not configured."));
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
                  `[IOI Code Adapter] Bridge request failed (${response.statusCode}): ${raw}`,
                ),
              );
              return;
            }
            resolve(raw);
          });
        },
      );

      if (timeoutMs && Number.isFinite(Number(timeoutMs))) {
        const boundedTimeoutMs = Math.max(500, Math.floor(Number(timeoutMs)));
        request.setTimeout(boundedTimeoutMs, () => {
          request.destroy(new Error(`Bridge request timed out after ${boundedTimeoutMs}ms.`));
        });
      }
      request.on("error", reject);
      if (body) {
        request.write(body);
      }
      request.end();
    });
  }

  async function writeWorkbenchCommandRouteReceipt(receipt, context = null) {
    const request = {
      requestId: crypto.randomUUID(),
      requestType: "codeEditor.commandRouteReceipt",
      context,
      payload: receipt,
      timestampMs: Date.now(),
    };
    await requestBridge("POST", "requests", request);
    return request;
  }

  async function readBridgeState() {
    const daemonModelMounting = await readDaemonModelSnapshot({
      timeoutMs: modelSnapshotTimeoutMs,
    });
    try {
      const raw = await requestBridge("GET", "state", undefined, {
        timeoutMs: refreshStateTimeoutMs,
      });
      return {
        ...defaultBridgeState(),
        ...JSON.parse(raw || "{}"),
        modelMounting: daemonModelMounting.snapshot ?? JSON.parse(raw || "{}").modelMounting ?? null,
        modelMountingStatus: daemonModelMounting,
      };
    } catch (error) {
      console.error("[IOI Code Adapter] Failed to read bridge state:", error);
      return {
        ...defaultBridgeState(),
        modelMounting: daemonModelMounting.snapshot,
        modelMountingStatus: daemonModelMounting,
      };
    }
  }

  async function readBridgeCommands() {
    try {
      const raw = await requestBridge("GET", "commands");
      const commands = JSON.parse(raw || "[]");
      return Array.isArray(commands) ? commands : [];
    } catch (error) {
      console.error("[IOI Code Adapter] Failed to read bridge commands:", error);
      return [];
    }
  }

  function startBridgeCommandPolling(context, output) {
    let running = false;
    const poll = async () => {
      if (running) {
        return;
      }
      running = true;
      try {
        const commands = await readBridgeCommands();
        for (const bridgeCommand of commands) {
          if (!bridgeCommand || typeof bridgeCommand.command !== "string") {
            continue;
          }
          const args = Array.isArray(bridgeCommand.args) ? bridgeCommand.args : [];
          output.appendLine(
            `Executing bridge command ${bridgeCommand.command} (${bridgeCommand.commandId || "no-id"}).`,
          );
          try {
            await vscode.commands.executeCommand(bridgeCommand.command, ...args);
            await writeWorkbenchCommandRouteReceipt(
              buildWorkbenchCommandRouteReceipt({
                commandId: bridgeCommand.command,
                route: bridgeCommand.command.startsWith("ioi.")
                  ? "ioi-runtime-action"
                  : "editor-local",
                status: "routed",
                context: bridgeCommand,
              }),
              {
                source: "ioi-code-editor-command-poll",
                commandId: bridgeCommand.commandId || bridgeCommand.command,
              },
            ).catch((error) => {
              output.appendLine(
                `Bridge command route receipt failed: ${error?.message || String(error)}`,
              );
            });
          } catch (error) {
            await writeWorkbenchCommandRouteReceipt(
              buildWorkbenchCommandRouteReceipt({
                commandId: bridgeCommand.command,
                route: "blocked",
                status: "failed",
                context: bridgeCommand,
                reason: error?.message || String(error),
              }),
              {
                source: "ioi-code-editor-command-poll",
                commandId: bridgeCommand.commandId || bridgeCommand.command,
              },
            ).catch(() => undefined);
            throw error;
          }
        }
      } catch (error) {
        console.error("[IOI Code Adapter] Failed to execute bridge command:", error);
        output.appendLine(`Bridge command failed: ${error?.message || String(error)}`);
      } finally {
        running = false;
      }
    };
    const timer = setInterval(poll, 750);
    context.subscriptions.push({ dispose: () => clearInterval(timer) });
    void poll();
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
    if (isRuntimeActionRequestType(requestType)) {
      const commandId =
        context?.sourceCommand ||
        payload?.sourceCommand ||
        payload?.commandId ||
        requestType;
      await writeWorkbenchCommandRouteReceipt(
        buildWorkbenchCommandRouteReceipt({
          commandId,
          route: "ioi-runtime-action",
          status: "routed",
          context: {
            requestId: request.requestId,
            requestType,
            ...(context || {}),
          },
        }),
        {
          source: "ioi-code-editor-adapter",
          originalRequestId: request.requestId,
          requestType,
        },
      ).catch((error) => {
        console.error("[IOI Code Adapter] Failed to write command route receipt:", error);
      });
    }
    return request;
  }

  return {
    buildRuntimeRefs,
    buildWorkbenchCommandRouteReceipt,
    defaultBridgeState,
    readBridgeCommands,
    readBridgeState,
    requestBridge,
    startBridgeCommandPolling,
    writeBridgeRequest,
    writeWorkbenchCommandRouteReceipt,
  };
}

module.exports = {
  buildRuntimeRefs,
  buildWorkbenchCommandRouteReceipt,
  createWorkspaceBridge,
  hashRef,
  isRuntimeActionRequestType,
};
