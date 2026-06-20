import { createServer } from "node:http";
import { readFile, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { extname, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { admitCodeEditorAdapterLaunchPlan } from "../packages/runtime-daemon/src/runtime-code-editor-adapter-launch-plan-admission.mjs";
import { admitHypervisorSessionLaunchRecipe } from "../packages/runtime-daemon/src/runtime-hypervisor-session-launch-recipe-admission.mjs";
import { admitHarnessSessionBinding } from "../packages/runtime-daemon/src/runtime-harness-session-binding-admission.mjs";
import { buildHarnessSessionLaunch } from "../packages/runtime-daemon/src/runtime-harness-session-launch.mjs";
import { buildHarnessSessionReadiness } from "../packages/runtime-daemon/src/runtime-harness-session-readiness.mjs";
import { buildHarnessSessionSpawn } from "../packages/runtime-daemon/src/runtime-harness-session-spawn.mjs";
import { admitHarnessSessionTerminalAttach } from "../packages/runtime-daemon/src/runtime-harness-session-terminal-attach.mjs";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const distRoot = resolve(repoRoot, "apps/hypervisor/dist");

const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".ttf", "font/ttf"],
  [".woff", "font/woff"],
  [".woff2", "font/woff2"],
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function assertNoInactiveWorkspaceShell(page, surfaceName) {
  const workspaceShellCount = await page.locator(".hypervisor-workspace-shell").count();
  assert(
    workspaceShellCount === 0,
    `${surfaceName} should not mount the workbench workspace shell while inactive. count=${workspaceShellCount}`,
  );
  const text = await page.locator("body").innerText();
  for (const staleWorkspaceText of [
    "Environment starting",
    "Environment needs runtime",
    "Ports & Services",
    "No open ports",
  ]) {
    assert(
      !text.includes(staleWorkspaceText),
      `${surfaceName} leaked inactive workspace copy: ${staleWorkspaceText}`,
    );
  }
}

async function assertNoSessionRightPaneOverflow(page, surfaceName) {
  const overflowingControls = await page.evaluate(() => {
    const viewportRight = window.innerWidth;
    return Array.from(
      document.querySelectorAll(
        [
          ".hypervisor-session-operations__right-pane button",
          ".hypervisor-session-operations__right-pane input",
          ".hypervisor-session-operations__right-pane .hypervisor-session-operations__search",
        ].join(", "),
      ),
    )
      .map((element) => {
        const rect = element.getBoundingClientRect();
        return {
          text: element.textContent?.replace(/\s+/g, " ").trim() ?? "",
          right: Math.round(rect.right),
          overflowRight: Math.round(rect.right - viewportRight),
        };
      })
      .filter((item) => item.overflowRight > 0);
  });
  assert(
    overflowingControls.length === 0,
    `${surfaceName} should keep right-inspector controls inside the viewport. overflow=${JSON.stringify(overflowingControls)}`,
  );
}

function contentTypeFor(pathname) {
  return contentTypes.get(extname(pathname)) ?? "application/octet-stream";
}

function pathInside(root, candidate) {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !rel.includes("..\\"));
}

async function fileForRequest(url) {
  const requestPath = decodeURIComponent(url.pathname);
  const normalizedPath = normalize(requestPath).replace(/^(\.\.[/\\])+/, "");
  const candidate = resolve(distRoot, `.${normalizedPath}`);
  if (pathInside(distRoot, candidate)) {
    try {
      const info = await stat(candidate);
      if (info.isFile()) {
        return candidate;
      }
    } catch {
      // Fall through to the SPA entry.
    }
  }
  return join(distRoot, "index.html");
}

async function createStaticServer() {
  assert(
    existsSync(join(distRoot, "index.html")),
    "apps/hypervisor/dist/index.html is missing; run npm run build --workspace=@ioi/hypervisor-app first.",
  );
  const server = createServer(async (request, response) => {
    try {
      const filePath = await fileForRequest(
        new URL(request.url ?? "/", "http://127.0.0.1"),
      );
      response.setHeader("content-type", contentTypeFor(filePath));
      response.end(await readFile(filePath));
    } catch (error) {
      response.statusCode = 500;
      response.end(error instanceof Error ? error.message : String(error));
    }
  });
  await new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return {
    server,
    url: `http://127.0.0.1:${server.address().port}/`,
  };
}

async function readJsonBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  return text ? JSON.parse(text) : {};
}

function setContractDaemonHeaders(response) {
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-methods", "GET,POST,OPTIONS");
  response.setHeader(
    "access-control-allow-headers",
    "accept,content-type,authorization",
  );
  response.setHeader("content-type", "application/json; charset=utf-8");
}

function writeContractDaemonJson(response, value, status = 200) {
  response.statusCode = status;
  setContractDaemonHeaders(response);
  response.end(JSON.stringify(value));
}

function writeContractDaemonError(response, error) {
  writeContractDaemonJson(
    response,
    {
      error: {
        code: error?.code ?? "hypervisor_app_shell_contract_daemon_error",
        message:
          error instanceof Error
            ? error.message
            : "Hypervisor app shell contract daemon request failed.",
        details: error?.details ?? {},
      },
    },
    error?.status ?? 500,
  );
}

function buildContractHarnessComparisonRun() {
  return {
    schema_version: "ioi.hypervisor.harness_comparison_run.v1",
    run_id: "harness-comparison:shell-contract/local-qwen",
    project_ref: "project:hypervisor-core",
    task_ref: "task:reference-parity/local-qwen",
    comparison_mode: "same_fixture",
    candidate_selection_refs: [
      "agent-harness-adapter:codex_cli",
      "agent-harness-adapter:deepseek_tui",
      "agent-harness-adapter:claude_code_cli",
      "agent-harness-adapter:generic_cli",
    ],
    acceptance_criteria_refs: [
      "criteria:route-backed-demo",
      "criteria:terminal-transcript-projection",
      "criteria:receipt-linked-replay",
    ],
    receipt_refs: ["receipt://foundry/harness-comparison/shell-contract"],
    runtimeTruthSource: "daemon-runtime",
    candidate_reports: [
      {
        selection_ref: "agent-harness-adapter:codex_cli",
        label: "Codex OSS / Qwen",
        execution_lane: "host_dev",
        output_summary:
          "Codex OSS adapter is ready for local Qwen session launch.",
        estimated_cost_usd: 0,
        verification_status: "passed",
        receipt_ref: "receipt://foundry/harness-comparison/codex-qwen",
        evidence_refs: [
          "receipt://foundry/harness-comparison/codex-qwen",
          "artifact://sessions/local-qwen/codex-cli-transcript",
        ],
      },
      {
        selection_ref: "agent-harness-adapter:deepseek_tui",
        label: "DeepSeek TUI / Qwen",
        execution_lane: "host_dev",
        output_summary:
          "DeepSeek TUI adapter is ready for local Qwen session launch.",
        estimated_cost_usd: 0,
        verification_status: "passed",
        receipt_ref: "receipt://foundry/harness-comparison/deepseek-qwen",
        evidence_refs: [
          "receipt://foundry/harness-comparison/deepseek-qwen",
          "artifact://sessions/local-qwen/deepseek-tui-transcript",
        ],
      },
      {
        selection_ref: "agent-harness-adapter:claude_code_cli",
        label: "Claude Code example / Qwen",
        execution_lane: "host_dev",
        output_summary:
          "Claude Code example adapter is ready for local Qwen session launch.",
        estimated_cost_usd: 0,
        verification_status: "passed",
        receipt_ref: "receipt://foundry/harness-comparison/claude-code-qwen",
        evidence_refs: [
          "receipt://foundry/harness-comparison/claude-code-qwen",
          "artifact://sessions/local-qwen/claude-code-transcript",
        ],
      },
      {
        selection_ref: "agent-harness-adapter:generic_cli",
        label: "Generic CLI / Qwen",
        execution_lane: "host_dev",
        output_summary:
          "Generic CLI adapter is ready for local Qwen session launch.",
        estimated_cost_usd: 0,
        verification_status: "passed",
        receipt_ref: "receipt://foundry/harness-comparison/generic-cli-qwen",
        evidence_refs: [
          "receipt://foundry/harness-comparison/generic-cli-qwen",
          "artifact://sessions/local-qwen/generic-cli-transcript",
        ],
      },
    ],
  };
}

function buildContractAgentsProjection() {
  return {
    schema_version: "ioi.hypervisor.agents_projection.v1",
    projection_id: "agents:shell-contract/local-qwen",
    source: "daemon-agents-projection",
    selected_project_ref: "project:hypervisor-core",
    boundary_invariant:
      "Agents are governed session workers admitted by the Hypervisor Daemon.",
    memory_invariant:
      "Agent memory refs are projections; admitted operational truth is recorded by Agentgres.",
    capability_invariant:
      "Agents exercise wallet.network capability leases instead of durable plaintext authority.",
    records: [
      {
        agent_ref: "agent:local-qwen/codex-oss",
        label: "Local Qwen coding agent",
        objective:
          "Run a Codex OSS harness session over the local Qwen model route.",
        status: "running",
        workspace_ref: "workspace://ioi/hypervisor-core",
        session_ref: "session:local-qwen/codex-oss",
        runtime: {
          harness_selection_ref: "agent-harness-adapter:codex_cli",
          harness_label: "Codex OSS / Qwen",
          truth_boundary: "proposal_source_only",
          model_route_ref: "model-route:hypervisor/default-local",
          adapter_target_ref: "adapter-target:host-dev",
          privacy_posture_ref: "privacy:local-dev-replay",
        },
        skill_bindings: [
          {
            skill_ref: "skill:hypervisor.reference-parity",
            label: "Reference parity implementation",
            source: "workspace",
            version_ref: "skill-version:hypervisor.reference-parity/v1",
            promotion_state: "active",
            receipt_ref: "receipt://agent/local-qwen/skill/reference-parity",
          },
        ],
        memory_bindings: [
          {
            memory_ref: "memory:workspace/hypervisor-reference-grade-parity",
            label: "Workspace parity notes",
            scope: "workspace_bound",
            owner: "agent_wiki_ioi_memory",
            persistence: "persistent",
            receipt_ref: "receipt://agent/local-qwen/memory/workspace",
          },
        ],
        capability_leases: [
          {
            lease_ref: "lease://wallet/local-qwen/workspace-read",
            capability_ref: "scope:workspace.read",
            status: "active",
            expires_at: "2026-06-19T13:00:00.000Z",
            wallet_authority_scope_refs: ["scope:workspace.read"],
            receipt_ref: "receipt://wallet/local-qwen/workspace-read",
          },
        ],
        agentgres_operation_refs: [
          "agentgres://operation/agent/local-qwen/codex-oss/latest",
        ],
        state_root_ref: "agentgres://state-root/agent/local-qwen/codex-oss",
        latest_receipt_refs: [
          "receipt://agent/local-qwen/session-ready",
          "receipt://foundry/harness-comparison/codex-qwen",
        ],
        updated_at: "2026-06-19T12:00:00.000Z",
      },
    ],
    runtimeTruthSource: "daemon-runtime",
  };
}

function buildContractReceiptEvidenceProjection() {
  return {
    schema_version: "ioi.hypervisor.receipt_evidence_projection.v1",
    projection_id: "receipt-evidence:shell-contract/local-qwen",
    source: "daemon-receipt-evidence-projection",
    receipt_boundary_invariant:
      "Receipts bind session transitions, artifacts, replay refs, and state roots admitted by Agentgres.",
    page_cursor: null,
    next_page_cursor: null,
    page_size: 25,
    has_more: false,
    records: [
      {
        receipt_ref: "receipt://agent/local-qwen/session-ready",
        kind: "session_lifecycle",
        summary: "Local Qwen harness session admitted and ready.",
        source_projection_ref: "session-operations:shell-contract/local-qwen",
        agentgres_operation_refs: [
          "agentgres://operation/session/local-qwen/session-ready",
        ],
        artifact_refs: ["artifact://sessions/local-qwen/session-ready"],
        trace_refs: ["agentgres://trace/session/local-qwen/session-ready"],
        state_root_ref: "agentgres://state-root/session/local-qwen/session-ready",
        replay_ref: "agentgres://replay/session/local-qwen/session-ready",
        status: "admitted",
      },
      {
        receipt_ref: "receipt://foundry/harness-comparison/codex-qwen",
        kind: "harness_comparison",
        summary: "Codex OSS / Qwen comparison candidate is ready for review.",
        source_projection_ref: "harness-comparison:shell-contract/local-qwen",
        agentgres_operation_refs: [
          "agentgres://operation/foundry/harness-comparison/codex-qwen",
        ],
        artifact_refs: ["artifact://sessions/local-qwen/codex-cli-transcript"],
        trace_refs: ["agentgres://trace/foundry/harness-comparison/codex-qwen"],
        state_root_ref:
          "agentgres://state-root/foundry/harness-comparison/codex-qwen",
        replay_ref: "agentgres://replay/foundry/harness-comparison/codex-qwen",
        status: "draft",
      },
      {
        receipt_ref: "receipt://terminal/local-qwen/codex-cli-transcript",
        kind: "terminal_transcript",
        summary: "Terminal transcript projection linked to replay evidence.",
        source_projection_ref: "terminal:local-qwen/codex-cli",
        agentgres_operation_refs: [
          "agentgres://operation/terminal/local-qwen/codex-cli-transcript",
        ],
        artifact_refs: ["artifact://sessions/local-qwen/codex-cli-transcript"],
        trace_refs: ["agentgres://trace/terminal/local-qwen/codex-cli"],
        state_root_ref: "agentgres://state-root/terminal/local-qwen/codex-cli",
        replay_ref: "agentgres://replay/terminal/local-qwen/codex-cli",
        status: "admitted",
      },
    ],
    runtimeTruthSource: "daemon-runtime",
  };
}

async function createContractDaemonServer() {
  const server = createServer(async (request, response) => {
    setContractDaemonHeaders(response);
    if (request.method === "OPTIONS") {
      response.statusCode = 204;
      response.end();
      return;
    }
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (
        request.method === "GET" &&
        url.pathname === "/v1/model-mount/snapshot"
      ) {
        writeContractDaemonJson(response, {
          routes: [
            {
              id: "model-route:hypervisor/default-local",
              role: "default-local",
              status: "active",
              privacy: "local",
            },
          ],
          endpoints: [
            {
              id: "model-endpoint:hypervisor/default-local",
              providerId: "provider:hypervisor-local",
              modelId: "model:local/codex-oss-qwen",
              status: "mounted",
              privacyClass: "local",
            },
          ],
          instances: [
            {
              id: "model-instance:hypervisor/default-local",
              endpointId: "model-endpoint:hypervisor/default-local",
              providerId: "provider:hypervisor-local",
              modelId: "model:local/codex-oss-qwen",
              status: "loaded",
            },
          ],
        });
        return;
      }
      if (request.method === "GET" && url.pathname === "/v1/hypervisor/agents") {
        writeContractDaemonJson(response, buildContractAgentsProjection());
        return;
      }
      if (
        request.method === "GET" &&
        url.pathname === "/v1/hypervisor/session-operations"
      ) {
        // Sessions cockpit hydrates this when a session launches inline; the
        // normalizer fills presentation defaults from the app fixture.
        writeContractDaemonJson(response, {
          schema_version: "ioi.hypervisor.session_operations_projection.v1",
          projection_id: "session-operations:shell-contract/local-qwen",
          source: "daemon-session-operations-projection",
          selected_session_ref: "session:shell-contract/local-qwen",
          ports_services: [],
          tasks: [],
          terminal_events: [],
          changed_file_groups: [],
        });
        return;
      }
      if (
        request.method === "GET" &&
        url.pathname.startsWith("/v1/hypervisor/sessions/") &&
        url.pathname.endsWith("/events")
      ) {
        // Canonical session-events SSE the cockpit subscription folds. Emits a
        // ready environment status so the launched-session drill-in renders.
        response.setHeader("content-type", "text/event-stream; charset=utf-8");
        response.setHeader("cache-control", "no-store");
        response.statusCode = 200;
        const componentReady = (component) => ({
          phase: "ready",
          evidence_ref: `receipt://env/${component}`,
        });
        const environmentStatus = {
          schema_version: "ioi.hypervisor.environment_status.v1",
          environment_ref: "environment:shell-contract",
          provider_placement_ref: null,
          phase: "running",
          components: {
            provisioner: componentReady("provisioner"),
            workspace_content: componentReady("workspace_content"),
            sandbox: componentReady("sandbox"),
            secrets: componentReady("secrets"),
            automations: componentReady("automations"),
            model_mount: componentReady("model_mount"),
            harness: componentReady("harness"),
          },
          ports: [],
          failure_message: null,
          warning_message: null,
          state_root_ref: "agentgres://state-root/env/shell-contract",
          workspace_artifact_ref: "agentgres://artifact/workspace/shell-contract",
          runtimeTruthSource: "daemon-runtime",
        };
        response.write(
          `event: environment_status\ndata: ${JSON.stringify(environmentStatus)}\n\n`,
        );
        response.write(
          `event: readiness\ndata: ${JSON.stringify({
            session_ref: "session:shell-contract/local-qwen",
            environment_phase: "running",
            ready: true,
          })}\n\n`,
        );
        response.end();
        return;
      }
      if (
        request.method === "GET" &&
        url.pathname === "/v1/hypervisor/receipt-evidence"
      ) {
        writeContractDaemonJson(response, buildContractReceiptEvidenceProjection());
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/code-editor-adapter-launch-plans"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          admitCodeEditorAdapterLaunchPlan({
            ...body,
            source:
              body.source ??
              "hypervisor_app_shell_contract./v1/hypervisor/code-editor-adapter-launch-plans",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/session-launch-recipe-admissions"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          admitHypervisorSessionLaunchRecipe({
            ...body,
            source:
              body.source ??
              "hypervisor_app_shell_contract./v1/hypervisor/session-launch-recipe-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-binding-admissions"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          admitHarnessSessionBinding({
            ...body,
            source:
              body.source ??
              "hypervisor_app_shell_contract./v1/hypervisor/harness-session-binding-admissions",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-launches"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          buildHarnessSessionLaunch({
            ...body,
            source:
              body.source ??
              "hypervisor_app_shell_contract./v1/hypervisor/harness-session-launches",
          }),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-spawns"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          buildHarnessSessionSpawn(
            {
              ...body,
              source:
                body.source ??
                "hypervisor_app_shell_contract./v1/hypervisor/harness-session-spawns",
            },
            {
              baseWorkspaceRoot: repoRoot,
              defaultWorkspaceRoot: repoRoot,
            },
          ),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-readiness"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          await buildHarnessSessionReadiness(
            {
              ...body,
              source:
                body.source ??
                "hypervisor_app_shell_contract./v1/hypervisor/harness-session-readiness",
            },
            {
              nowIso: () => "2026-06-18T12:40:00.000Z",
              runCommand: async (command, args) => {
                if (command === "codex" && args[0] === "--help") {
                  return {
                    status: 0,
                    stdout:
                      "Codex CLI\nOptions:\n  --oss\n  --local-provider <OSS_PROVIDER>\n  --model <MODEL>\n  --cd <DIR>\n",
                    stderr: "",
                  };
                }
                if (command === "ollama" && args[0] === "list") {
                  return {
                    status: 0,
                    stdout: "NAME ID SIZE MODIFIED\nqwen 123 4 GB now\n",
                    stderr: "",
                  };
                }
                return { status: 127, stdout: "", stderr: "not found" };
              },
            },
          ),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-session-terminal-attachments"
      ) {
        const body = await readJsonBody(request);
        writeContractDaemonJson(
          response,
          admitHarnessSessionTerminalAttach(
            {
              ...body,
              source:
                body.source ??
                "hypervisor_app_shell_contract./v1/hypervisor/harness-session-terminal-attachments",
            },
            {
              nowIso: () => "2026-06-18T12:41:00.000Z",
            },
          ),
          202,
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/harness-public-fixture-runs"
      ) {
        writeContractDaemonJson(response, buildContractHarnessComparisonRun(), 202);
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/v1/hypervisor/session-turns"
      ) {
        // The environment status reaches ready in the offline shell, so the
        // cockpit auto-answers the seed intent. The contract daemon has no live
        // model route, so it emits the honest Phase 0 "no model route" SSE — no
        // faked answer and no 404 console error.
        response.setHeader("content-type", "text/event-stream; charset=utf-8");
        response.setHeader("cache-control", "no-store");
        response.statusCode = 200;
        const turnRef = "session-turn:shell-contract/local-qwen";
        response.write(
          `event: turn_start\ndata: ${JSON.stringify({
            turn_ref: turnRef,
            source: "no_model_route",
            replay_mode: false,
          })}\n\n`,
        );
        response.write(
          `event: error\ndata: ${JSON.stringify({
            code: "no_model_route",
            turn_ref: turnRef,
            message:
              "No model route is configured for the offline shell contract.",
          })}\n\n`,
        );
        response.write(
          `event: done\ndata: ${JSON.stringify({
            turn_ref: turnRef,
            finish_reason: "no_model_route",
            source: "no_model_route",
          })}\n\n`,
        );
        response.end();
        return;
      }
      writeContractDaemonJson(
        response,
        {
          error: {
            code: "hypervisor_app_shell_contract_daemon_not_found",
            message: "Contract daemon route not found.",
            details: { path: url.pathname, method: request.method },
          },
        },
        404,
      );
    } catch (error) {
      writeContractDaemonError(response, error);
    }
  });
  await new Promise((resolveListen) => {
    server.listen(0, "127.0.0.1", resolveListen);
  });
  return {
    server,
    url: `http://127.0.0.1:${server.address().port}`,
  };
}

async function main() {
  const evidencePath = process.argv.includes("--evidence")
    ? process.argv[process.argv.indexOf("--evidence") + 1]
    : null;
  const { server, url } = await createStaticServer();
  const { server: contractDaemonServer, url: contractDaemonUrl } =
    await createContractDaemonServer();
  const browser = await chromium.launch({ headless: true });
  const consoleMessages = [];
  try {
    const page = await browser.newPage({
      viewport: { width: 1440, height: 960 },
    });
    page.setDefaultTimeout(90_000);
    page.on("console", (message) => {
      if (["error", "warning"].includes(message.type())) {
        consoleMessages.push({
          type: message.type(),
          text: message.text(),
        });
      }
    });
    page.on("pageerror", (error) => {
      consoleMessages.push({
        type: "pageerror",
        text: error.message,
      });
    });
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 90_000 });
    try {
      await page.waitForSelector(
        '[data-home-dashboard-variant="ioi-reference-home"]',
      );
    } catch (error) {
      const rootText = await page
        .locator("#root")
        .innerText({ timeout: 1_000 })
        .catch(() => "");
      throw new Error(
        [
          "Hypervisor Home reference prompt shell did not become visible.",
          `root_text=${JSON.stringify(rootText.slice(0, 600))}`,
          `console=${JSON.stringify(consoleMessages.slice(-10))}`,
          error instanceof Error ? error.message : String(error),
        ].join("\n"),
      );
    }
    const bodyText = await page.locator("body").innerText();
    await assertNoInactiveWorkspaceShell(page, "Home");
    const promptPlaceholder = await page
      .locator(".hypervisor-home-prompt__composer textarea")
      .getAttribute("placeholder");
    assert(
      bodyText.includes("What do you want to get done today?"),
      "Home does not expose the IOI-reference prompt surface.",
    );
    assert(
      promptPlaceholder === "Describe your task or type / for commands",
      "Home does not expose the reference prompt composer.",
    );
    assert(
      (await page.locator("[data-home-reference-session-list]").count()) === 0 &&
        (await page.locator("[data-home-reference-session-ref]").count()) === 0,
      "Fresh Home should match the IOI reference clean prompt viewport without seeded Recent Sessions.",
    );
    assert(
      (await page.locator("[data-home-recent-sessions]").count()) === 0,
      "Home revived the old static recent-session shortcut model.",
    );
    const initialSessionRows = page.locator(".hypervisor-activity-session-row");
    const initialSessionRowCount = await initialSessionRows.count();
    assert(
      initialSessionRowCount === 0,
      "Fresh Home should not seed fake launched-session rail rows before a launch or restore.",
    );
    assert(
      (await page.locator(".hypervisor-activity-profile-indicator").count()) === 1 &&
        bodyText.includes("IOI Workspace") &&
        bodyText.includes("Operator"),
      "Left rail does not expose the reference-style workspace/user footer.",
    );
    assert(
      (await page.locator(".hypervisor-activity-footer-profile-row").count()) === 1 &&
        (await page.locator(".hypervisor-activity-profile-secondary").count()) === 1,
      "Left rail footer must use the IOI reference split workspace/action layout.",
    );
    const profileFooterLayout = await page
      .locator(".hypervisor-activity-footer-profile-row")
      .evaluate((element) => {
        const row = element.getBoundingClientRect();
        const profile = element
          .querySelector(".hypervisor-activity-profile-indicator")
          ?.getBoundingClientRect();
        const secondary = element
          .querySelector(".hypervisor-activity-profile-secondary")
          ?.getBoundingClientRect();
        return {
          rowWidth: row.width,
          profileWidth: profile?.width ?? 0,
          secondaryWidth: secondary?.width ?? 0,
          gap:
            profile && secondary
              ? Math.round(secondary.left - profile.right)
              : null,
        };
      });
    assert(
      profileFooterLayout.rowWidth >= 280 &&
        profileFooterLayout.rowWidth <= 286 &&
        profileFooterLayout.profileWidth >= 246 &&
        profileFooterLayout.profileWidth <= 250 &&
        profileFooterLayout.secondaryWidth === 32 &&
        profileFooterLayout.gap === 4,
      `Left rail footer proportions drifted from the IOI reference split control. layout=${JSON.stringify(profileFooterLayout)}`,
    );
    const profileAvatarStyle = await page
      .locator(".hypervisor-activity-profile-avatar")
      .evaluate((element) => {
        const style = getComputedStyle(element);
        return {
          backgroundColor: style.backgroundColor,
          color: style.color,
        };
      });
    assert(
      profileAvatarStyle.backgroundColor === "rgb(21, 92, 255)" &&
        profileAvatarStyle.color === "rgb(255, 255, 255)",
      `Left rail avatar should use the filled reference blue style. style=${JSON.stringify(profileAvatarStyle)}`,
    );
    const brandMark = page.locator(".hypervisor-activity-brand svg").first();
    const brandMarkBox = await brandMark.boundingBox();
    const brandTickCount = await page.locator(".hypervisor-activity-brand-tick").count();
    assert(
      (await page.locator(".hypervisor-activity-brand svg polygon").count()) >= 10 &&
        brandMarkBox &&
        brandMarkBox.width <= 22 &&
        brandMarkBox.height <= 22 &&
        brandTickCount === 2,
      "Left rail brand mark must render as the small filled IOI reference mark.",
    );
    const deepLinkPage = await browser.newPage({
      viewport: { width: 1440, height: 960 },
    });
    try {
      await deepLinkPage.goto(new URL("workspaces", url).toString(), {
        waitUntil: "domcontentloaded",
        timeout: 90_000,
      });
      await deepLinkPage.waitForSelector(
        '[data-session-reference-page="workspace-detail"]',
      );
      await assertNoSessionRightPaneOverflow(deepLinkPage, "/workspaces");
      const workspaceText = await deepLinkPage.locator("body").innerText();
      assert(
        (await deepLinkPage.locator('[data-window-surface="sessions"].is-active').count()) ===
          1,
        "/workspaces should cold boot into the retained Sessions cockpit.",
      );
      assert(
        workspaceText.includes("Code") &&
          workspaceText.includes("Agent") &&
          workspaceText.includes("Environment") &&
          workspaceText.includes("Changes") &&
          workspaceText.includes("All Files") &&
          workspaceText.includes("Comments") &&
          workspaceText.includes("Ports & Services") &&
          workspaceText.includes("Tasks") &&
          workspaceText.includes("Terminal"),
        "/workspaces should expose the IOI-reference session tabs, right inspector modes, and bottom dock.",
      );
      await deepLinkPage.goto(
        new URL("details/019ed128-a3fd-7433-8cc3-99afed4a8ac4/logs", url)
          .toString(),
        { waitUntil: "domcontentloaded", timeout: 90_000 },
      );
      await deepLinkPage.waitForSelector(
        '[data-session-reference-page="workspace-detail"]',
      );
      await assertNoSessionRightPaneOverflow(
        deepLinkPage,
        "/details/:sessionId/logs",
      );
      const detailsText = await deepLinkPage.locator("body").innerText();
      assert(
        (await deepLinkPage.locator('[data-window-surface="sessions"].is-active').count()) ===
          1,
        "/details/:sessionId/logs should cold boot into the retained Sessions cockpit.",
      );
      assert(
        detailsText.includes("Agent") &&
          detailsText.includes("Environment") &&
          detailsText.includes("All Files") &&
          detailsText.includes("Comments"),
        "/details/:sessionId/logs should retain the visible agent, environment, and change-inspector tabs.",
      );
      await deepLinkPage.goto(new URL("ai?user-settings=profile", url).toString(), {
        waitUntil: "domcontentloaded",
        timeout: 90_000,
      });
      await deepLinkPage.waitForSelector(
        '[data-settings-reference-shell="ioi-settings"]',
      );
      const settingsText = await deepLinkPage.locator("body").innerText();
      assert(
        settingsText.includes("User settings") &&
          settingsText.includes("Account details"),
        "/ai?user-settings=profile should cold boot into the Settings account surface.",
      );
    } finally {
      await deepLinkPage.close().catch(() => undefined);
    }
    const launchedRowsBefore = await page
      .locator(".hypervisor-activity-session-row")
      .count();
    assert(
      launchedRowsBefore === 0,
      "Fresh shells should not render seeded launched-session rows before a launch or restore.",
    );
    await page.evaluate((endpoint) => {
      window.localStorage.setItem("ioi.hypervisor.daemonEndpoint", endpoint);
    }, contractDaemonUrl);
    // Reference parity: starting a session launches a governed session inline on
    // the Sessions surface instead of opening a separate New Session modal window.
    await page.locator('[data-home-start-session="true"]').click();
    assert(
      (await page.locator(".hypervisor-new-session-modal").count()) === 0,
      "Starting a session must not open a separate New Session modal window.",
    );
    await page.waitForFunction(
      (previousCount) =>
        document.querySelectorAll(".hypervisor-activity-session-row").length >
        previousCount,
      launchedRowsBefore,
    );
    const launchedSessionRows = await page
      .locator(".hypervisor-activity-session-row")
      .allInnerTexts();
    assert(
      launchedSessionRows.some((row) => row.includes("master")),
      `Launching the selected New Session recipe should create a readable launched-session rail row. rows=${JSON.stringify(launchedSessionRows)}`,
    );
    assert(
      launchedSessionRows.every(
        (row) =>
          !row.includes("Open a governed Hypervisor session for this workspace."),
      ),
      "Default Home seed text should not become the launched-session rail title.",
    );
    const launchedSessionRow = page
      .locator(".hypervisor-activity-session-row")
      .last();
    assert(
      (await launchedSessionRow.getAttribute("data-launched-session-admission")) ===
        "daemon_admitted",
      "Launching through the contract daemon should produce a daemon-admitted session.",
    );
    assert(
      ((await launchedSessionRow.getAttribute("data-launched-session-spawn")) ??
        ""
      ).startsWith("harness-session-spawn:"),
      "Daemon-admitted launched session did not expose a harness session spawn ref.",
    );
    assert(
      (await launchedSessionRow.getAttribute(
        "data-launched-session-spawn-state",
      )) === "ready_for_client_pty_attach",
      "Daemon-admitted launched session did not expose client PTY spawn readiness.",
    );
    assert(
      (await launchedSessionRow.getAttribute("data-launched-session-model-name")) ===
        "qwen",
      "Daemon-admitted launched session did not bind the local Qwen model mount.",
    );
    const spawnCommand =
      (await launchedSessionRow.getAttribute(
        "data-launched-session-spawn-command",
      )) ?? "";
    assert(
      spawnCommand.includes("codex --oss") &&
        spawnCommand.includes("--local-provider ollama") &&
        spawnCommand.includes("--model qwen") &&
        spawnCommand.includes("--cd "),
      `Daemon-admitted launched session did not expose the resolved Codex OSS command. command=${spawnCommand}`,
    );
    assert(
      (await launchedSessionRow.getAttribute(
        "data-launched-session-readiness",
      )) === "ready",
      "Daemon-admitted launched session did not expose host readiness.",
    );
    assert(
      (await launchedSessionRow.getAttribute(
        "data-launched-session-readiness-state",
      )) === "ready_for_harness_pty_attach",
      "Daemon-admitted launched session did not expose PTY attach readiness.",
    );
    assert(
      ((await launchedSessionRow.getAttribute(
        "data-launched-session-terminal-attach",
      )) ?? ""
      ).startsWith("harness-session-terminal-attach:") &&
        (await launchedSessionRow.getAttribute(
          "data-launched-session-terminal-attach-state",
        )) === "client_pty_attach_admitted" &&
        ((await launchedSessionRow.getAttribute(
          "data-launched-session-terminal-transcript",
        )) ?? ""
        ).startsWith("agentgres://trace/harness-terminal-transcript/") &&
        (await launchedSessionRow.getAttribute(
          "data-launched-session-terminal-transcript-state",
        )) === "awaiting_client_stream" &&
        (await launchedSessionRow.getAttribute(
          "data-launched-session-terminal-transcript-cursor",
        )) === "0" &&
        (await launchedSessionRow.getAttribute(
          "data-launched-session-terminal-transcript-lines",
        )) === "2",
      "Daemon-admitted launched session did not expose terminal attach and transcript refs.",
    );
    await page.evaluate(() => {
      window.localStorage.removeItem("ioi.hypervisor.daemonEndpoint");
      window.localStorage.removeItem("ioi.modelMounts.daemonEndpoint");
    });
    await page.goto(new URL("?view=sessions", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector('[data-session-reference-page="workspace-detail"]');
    const sessionsText = await page.locator("body").innerText();
    assert(
      // After an inline launch the cockpit renders the session conversation
      // (seeded with the launched task); with no active session it renders the
      // reference prompt and suggestion chips.
      sessionsText.includes(
        "Open a governed Hypervisor session for this workspace.",
      ) ||
        (sessionsText.includes("What do you want to get done today?") &&
          sessionsText.includes("Automate env setup") &&
          sessionsText.includes("Fix a bug") &&
          sessionsText.includes("Boost your test coverage")),
      "Sessions did not render the launched conversation or the reference prompt.",
    );
    const sessionHarnessDrillIn = page
      .locator("[data-session-harness-drill-in]")
      .first();
    await sessionHarnessDrillIn.waitFor({ timeout: 15_000 });
    const drillInCommand =
      (await sessionHarnessDrillIn.getAttribute(
        "data-session-harness-drill-in-command",
      )) ?? "";
    assert(
      (await sessionHarnessDrillIn.getAttribute(
        "data-session-harness-drill-in-admission",
      )) === "daemon_admitted" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-model-name",
        )) === "qwen" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-readiness",
        )) === "ready" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-readiness-state",
        )) === "ready_for_harness_pty_attach" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-pty-transport",
        )) === "hypervisor_client_terminal_adapter" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-terminal-attach-state",
        )) === "client_pty_attach_admitted" &&
        ((await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-terminal-transcript",
        )) ?? ""
        ).startsWith("agentgres://trace/harness-terminal-transcript/") &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-terminal-transcript-state",
        )) === "awaiting_client_stream" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-terminal-transcript-cursor",
        )) === "0" &&
        (await sessionHarnessDrillIn.getAttribute(
          "data-session-harness-drill-in-terminal-transcript-lines",
        )) === "2" &&
        drillInCommand.includes("codex --oss") &&
        drillInCommand.includes("--local-provider ollama") &&
        drillInCommand.includes("--model qwen"),
      `Sessions did not expose the launched Codex OSS/Qwen harness drill-in. command=${drillInCommand}`,
    );
    assert(
      (await page
        .locator(
          '.hypervisor-session-operations__composer textarea[placeholder="Describe your task or type / for commands"]',
        )
        .count()) === 1,
      "Sessions did not render the reference composer placeholder.",
    );
    assert(
      (await page.locator(".hypervisor-agent-selector__trigger").count()) >= 1,
      "Sessions composer should expose the agent/model selector toggle.",
    );
    assert(
      (await page.locator(".hypervisor-session-operations__recent-launches").count()) ===
        0 &&
        (await page.locator(".hypervisor-session-operations__environment").count()) ===
          0,
      "Sessions reintroduced the launched-session strip or environment-first workplane.",
    );
    assert(
      sessionsText.includes("No open ports"),
      "Sessions did not render the reference empty ports state.",
    );
    assert(
      sessionsText.includes(".devcontainer/") &&
        sessionsText.includes("devcontainer.json") &&
        sessionsText.includes("Dockerfile") &&
        sessionsText.includes("parent-harness-evidence-boundary.md"),
      "Sessions did not render the reference changed-file tree.",
    );
    assert(
      (await page.locator(".hypervisor-session-operations__activity-grid").count()) ===
        0,
      "Sessions reintroduced the non-reference center activity card grid.",
    );
    assert(
      (await page.locator("[data-session-port-service]").count()) === 0,
      "Sessions should render empty ports until daemon reports an opened service.",
    );

    // Configure/Advanced governed launch: an explicit, optional affordance (not an
    // auto-popup). Inline launch uses policy-safe admitted defaults; Advanced
    // exposes harness/model/privacy/recipe gating, and the step-up rule blocks a
    // posture that exceeds a safe admitted route.
    await page
      .locator('[data-session-new-session-configure="true"]')
      .first()
      .click();
    await page.waitForSelector(".hypervisor-new-session-modal");
    await page.locator('[data-new-session-start-mode="scratch"]').click();
    await page.waitForSelector(
      '[data-new-session-launch-summary="ioi.hypervisor.new_session_launch_summary.v1"]',
    );
    await page.waitForSelector(
      '[data-new-session-target-binding="ioi.hypervisor.new_session_target_binding.v1"]',
    );
    const advancedSelectCount = await page
      .locator(".hypervisor-new-session-modal__configure select")
      .count();
    assert(
      advancedSelectCount >= 3,
      `Configure/Advanced should expose harness, model route, and privacy controls. selects=${advancedSelectCount}`,
    );
    await page
      .locator(".hypervisor-new-session-modal__configure select")
      .nth(2)
      .selectOption("privacy:ctee-private-workspace");
    await page.waitForFunction(() => {
      const card = document.querySelector("[data-new-session-harness-verdict]");
      return card?.getAttribute("data-new-session-harness-verdict") === "blocked";
    });
    const blockedConfigureLaunch = await page
      .locator('[data-new-session-start-selected="true"]')
      .isDisabled();
    assert(
      blockedConfigureLaunch,
      "Configure/Advanced step-up: external harness + cTEE private workspace must block launch.",
    );
    await page
      .locator(".hypervisor-new-session-modal__configure select")
      .nth(2)
      .selectOption("privacy:redacted-projection");
    await page.waitForFunction(() =>
      ["adapter_native_only", "compatible", "provider_trust"].includes(
        document
          .querySelector("[data-new-session-harness-verdict]")
          ?.getAttribute("data-new-session-harness-verdict") ?? "",
      ),
    );
    const safeConfigureLaunch = await page
      .locator('[data-new-session-start-selected="true"]')
      .isDisabled();
    assert(
      !safeConfigureLaunch,
      "Configure/Advanced with a safe redacted-projection route should allow launch.",
    );
    await page
      .locator(".hypervisor-new-session-modal__close")
      .click()
      .catch(() => undefined);

    await page.goto(new URL("?view=automations", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(".hypervisor-automation-compositor__table");
    await assertNoInactiveWorkspaceShell(page, "Automations");
    const automationsText = await page.locator("body").innerText();
    assert(
      automationsText.includes("Total Automations") &&
        automationsText.includes("No automations yet") &&
        automationsText.includes("You haven't created any automations yet") &&
        automationsText.includes("All (4)"),
      "Automations did not render the IOI-reference clean empty state.",
    );
    assert(
      (await page.locator("[data-automation-row-ref]").count()) === 0,
      "Automations clean boot should not expose fake automation rows.",
    );
    const automationsReferenceLayout = await page.evaluate(() => {
      const main = document.querySelector(
        ".hypervisor-automation-compositor__main",
      );
      const suggested = document.querySelector(
        ".hypervisor-automation-compositor__suggested",
      );
      const mainRect = main?.getBoundingClientRect();
      const suggestedRect = suggested?.getBoundingClientRect();
      return {
        mainWidth: mainRect?.width ?? null,
        suggestedWidth: suggestedRect?.width ?? null,
        suggestedLeft: suggestedRect?.left ?? null,
        gap:
          mainRect && suggestedRect
            ? suggestedRect.left - mainRect.right
            : null,
      };
    });
    assert(
      typeof automationsReferenceLayout.mainWidth === "number" &&
        automationsReferenceLayout.mainWidth >= 720 &&
        automationsReferenceLayout.mainWidth <= 760 &&
        typeof automationsReferenceLayout.suggestedWidth === "number" &&
        automationsReferenceLayout.suggestedWidth >= 285 &&
        automationsReferenceLayout.suggestedWidth <= 305 &&
        typeof automationsReferenceLayout.gap === "number" &&
        automationsReferenceLayout.gap >= 36 &&
        automationsReferenceLayout.gap <= 48,
      `Automations should use the IOI-reference main/suggested column rhythm. layout=${JSON.stringify(automationsReferenceLayout)}`,
    );
    const suggestedTemplates = await page
      .locator("[data-workflow-template-suggestion]")
      .allInnerTexts();
    assert(
      suggestedTemplates.length >= 8 &&
        suggestedTemplates.some((template) =>
          template.includes("Scan recent commits for bugs"),
        ) &&
        suggestedTemplates.some((template) =>
          template.includes("Automated dev environment setup"),
        ) &&
        suggestedTemplates.some((template) =>
          template.includes("CVE mitigation & dependency updates"),
        ),
      `Automations did not render the full IOI-reference suggested-template rail. templates=${JSON.stringify(suggestedTemplates)}`,
    );

    await page.locator('[data-window-surface="projects"]').click();
    await page.waitForSelector("[data-hypervisor-project-state]");
    await assertNoInactiveWorkspaceShell(page, "Projects");
    const projectsText = await page.locator("body").innerText();
    assert(
      projectsText.includes("Projects") &&
        projectsText.includes("No projects") &&
        projectsText.includes("Projects bundle your repo, secrets, and other configuration") &&
        projectsText.includes("Learn more about projects in IOI."),
      "Projects page did not render the IOI-reference searchable clean empty state.",
    );
    assert(
      (await page
        .locator('.hypervisor-project-state__search input[placeholder="Search projects"]')
        .count()) === 1,
      "Projects page did not expose the IOI-reference search input.",
    );
    assert(
      projectsText.includes("New project"),
      "Projects page did not expose the New project action.",
    );
    assert(
      !projectsText.includes("Agentgres owns project truth") &&
        !projectsText.includes("workspace://hypervisor-core") &&
        !projectsText.includes("Nested Guardian") &&
        !projectsText.includes("Capability Lab"),
      "Projects clean boot leaked daemon-fixture project truth.",
    );
    assert(
      (await page.locator("[data-project-state-record]").count()) === 0,
      "Projects clean boot should not expose project records before daemon admission.",
    );
    assert(
      (await page.locator("[data-project-state-record-count='0']").count()) === 1,
      "Projects clean boot should bind a zero-record projection.",
    );
    assert(
      (await page.locator(".hypervisor-project-state__search input").count()) === 1,
      "Projects clean boot should render the reference search control.",
    );
    assert(
      (await page.locator(".hypervisor-project-state__filters").count()) === 0,
      "Projects clean boot should not render loaded-project filters until projects exist.",
    );
    const projectsEmptyLayout = await page.evaluate(() => {
      const emptyIcon = document.querySelector(
        ".hypervisor-project-state__empty-icon",
      );
      const newProjectButton = document.querySelector(
        ".hypervisor-project-state__empty .hypervisor-project-state__new",
      );
      const emptyHeadline = document.querySelector(
        ".hypervisor-project-state__empty h3",
      );
      const iconRect = emptyIcon?.getBoundingClientRect();
      const buttonRect = newProjectButton?.getBoundingClientRect();
      const headlineStyle = emptyHeadline
        ? getComputedStyle(emptyHeadline)
        : null;
      const buttonStyle = newProjectButton
        ? getComputedStyle(newProjectButton)
        : null;
      return {
        iconTop: iconRect?.top ?? null,
        buttonTop: buttonRect?.top ?? null,
        headlineFontSize: headlineStyle?.fontSize ?? null,
        buttonFontWeight: buttonStyle?.fontWeight ?? null,
      };
    });
    assert(
      typeof projectsEmptyLayout.iconTop === "number" &&
        projectsEmptyLayout.iconTop >= 210 &&
        projectsEmptyLayout.iconTop <= 265 &&
        typeof projectsEmptyLayout.buttonTop === "number" &&
        projectsEmptyLayout.buttonTop >= 425 &&
        projectsEmptyLayout.buttonTop <= 490 &&
        projectsEmptyLayout.headlineFontSize === "20px" &&
        Number(projectsEmptyLayout.buttonFontWeight) <= 600,
      `Projects clean empty state should match the IOI-reference upper-mid viewport rhythm. layout=${JSON.stringify(projectsEmptyLayout)}`,
    );

    await page.goto(new URL("?view=workbench", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(".hypervisor-workspace-shell__workbench-surface");
    const workbenchSurfaceCount = await page
      .locator(".hypervisor-workspace-shell__workbench-surface")
      .count();
    assert(
      workbenchSurfaceCount === 1,
      "Workbench did not render the code-editor workspace session surface.",
    );

    await page.evaluate((endpoint) => {
      window.localStorage.setItem("ioi.hypervisor.daemonEndpoint", endpoint);
    }, contractDaemonUrl);
    await page.goto(new URL("?view=foundry", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector("[data-hypervisor-harness-comparison-run]");
    const foundryText = await page.locator("body").innerText();
    assert(
      foundryText.includes("Compare harness adapters against one public fixture."),
      "Foundry did not render the harness comparison dashboard.",
    );
    assert(
      foundryText.includes("Codex OSS / Qwen") &&
        foundryText.includes("DeepSeek TUI / Qwen") &&
        foundryText.includes("Claude Code example / Qwen") &&
        foundryText.includes("Generic CLI / Qwen"),
      "Foundry harness comparison did not expose the local Qwen adapter candidates.",
    );
    const harnessCandidateCount = await page
      .locator("[data-harness-comparison-candidate]")
      .count();
    assert(
      harnessCandidateCount >= 4,
      "Foundry harness comparison did not render the route-backed local Qwen adapter set.",
    );
    assert(
      (await page
        .locator('[data-harness-comparison-state="admitted"]')
        .count()) === 1,
      "Foundry harness comparison did not load the governed route-backed state.",
    );
    await page.locator('[data-harness-comparison-action="request-run"]').click();
    await page.waitForFunction(() => {
      const state = document
        .querySelector("[data-harness-comparison-state]")
        ?.getAttribute("data-harness-comparison-state");
      return state === "admitted" || state === "unavailable";
    });
    const foundryRunState = await page
      .locator("[data-harness-comparison-state]")
      .getAttribute("data-harness-comparison-state");
    assert(
      foundryRunState === "admitted",
      "Foundry harness comparison did not refresh through the governed daemon route.",
    );

    await page.goto(new URL("?view=agents", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector("[data-hypervisor-agents]");
    const agentsText = await page.locator("body").innerText();
    assert(agentsText.includes("Agents"), "Agents surface did not render.");
    const agentsSearchPlaceholder = await page
      .locator(".hypervisor-agents__search input")
      .getAttribute("placeholder");
    assert(
      agentsSearchPlaceholder === "Search agents...",
      "Agents surface did not expose the reference search control.",
    );
    assert(
      agentsText.includes("Selected agent"),
      "Agents surface did not expose a selected agent detail pane.",
    );
    assert(
      agentsText.includes("Interface"),
      "Agents surface did not expose the product-facing interface column.",
    );
    assert(
      agentsText.includes("Access"),
      "Agents surface did not expose the product-facing access controls.",
    );
    assert(
      !agentsText.includes("Build with Agent"),
      "Agents surface should not expose a right-side agent chat pane.",
    );
    assert(
      !agentsText.match(
        /Configured workers|Review leases|Daemon Owned|Proposal Source Only|Default Harness Profile|Hypervisor Daemon|Agentgres|wallet\.network|Total Agents|Personal Source Only|Provider Source Only/i,
      ),
      "Agents surface leaked implementation-truth copy into the visible product surface.",
    );

    await page.goto(new URL("?view=receipts", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(
      '[data-receipt-evidence-filter-controls="true"]',
    );
    const initialReceiptCount = Number(
      await page
        .locator("[data-receipt-evidence-filtered-count]")
        .getAttribute("data-receipt-evidence-filtered-count"),
    );
    assert(
      initialReceiptCount > 1,
      "Receipts surface did not render evidence records.",
    );
    await page.selectOption('label:has-text("Status") select', "draft");
    await page.waitForFunction(() => {
      const root = document.querySelector(
        "[data-receipt-evidence-filtered-count]",
      );
      const cards = Array.from(
        document.querySelectorAll("[data-receipt-evidence-status]"),
      );
      return (
        Number(
          root?.getAttribute("data-receipt-evidence-filtered-count") ?? "0",
        ) > 0 &&
        cards.every(
          (card) =>
            card.getAttribute("data-receipt-evidence-status") === "draft",
        )
      );
    });
    await page.locator("[data-receipt-evidence-review]").first().click();
    const receiptDetailRef = await page
      .locator("[data-receipt-evidence-detail]")
      .getAttribute("data-receipt-evidence-detail");
    const receiptReplayRef = await page
      .locator("[data-receipt-evidence-detail]")
      .getAttribute("data-receipt-evidence-replay-ref");
    assert(
      receiptDetailRef?.startsWith("receipt:"),
      "Receipts surface did not expose selected receipt detail.",
    );
    assert(
      receiptReplayRef?.startsWith("agentgres://replay/"),
      "Receipts surface did not expose selected replay ref.",
    );

    await page.goto(new URL("?view=settings", url).toString(), {
      waitUntil: "domcontentloaded",
      timeout: 90_000,
    });
    await page.waitForSelector(
      '[data-settings-reference-shell="ioi-settings"]',
    );
    const settingsText = await page.locator("body").innerText();
    assert(
      settingsText.includes("User settings"),
      "Settings reference shell did not render.",
    );
    assert(
      settingsText.includes("Account"),
      "Settings did not expose Account navigation.",
    );
    assert(
      settingsText.includes("Secrets"),
      "Settings did not expose Secrets navigation.",
    );
    assert(
      settingsText.includes("Git authentications"),
      "Settings did not expose Git authentication navigation.",
    );
    assert(
      settingsText.includes("Personal access tokens"),
      "Settings did not expose personal access token navigation.",
    );
    assert(
      settingsText.includes("Integrations"),
      "Settings did not expose Integrations navigation.",
    );
    assert(
      settingsText.includes("Default code editor target"),
      "Settings did not expose default code editor target preference.",
    );
    assert(
      settingsText.includes("Embedded code editor"),
      "Settings did not expose the embedded code editor preference.",
    );
    assert(
      !settingsText.match(
        /Default Editor|default selected editor|Code tab|Show the embedded VS Code editor|adapter_preference_ref|Advanced|Runtime|Storage \/ API/i,
      ),
      "Settings leaked old Code tab, raw adapter-preference copy, or retired advanced settings copy.",
    );
    const settingsShell = page.locator(
      '[data-settings-reference-shell="ioi-settings"]',
    );
    const settingsAdapterTargets = await settingsShell
      .locator("[data-settings-editor-target]")
      .count();
    assert(
      settingsAdapterTargets >= 8,
      "Settings did not expose code editor adapter preference targets.",
    );
    const settingsAdapterText = await page.locator("body").innerText();
    assert(
      settingsAdapterText.includes("This will be your default code editor for workspace sessions.") &&
        settingsAdapterText.includes("Embedded code editor") &&
        settingsAdapterText.includes("Dotfiles repository"),
      "Settings did not render reference account preferences.",
    );
    const credentialPanels = [
      {
        label: "Secrets",
        panel: "secrets",
        owner: "wallet.network",
        scope: "scope:secret.use",
        copy: "sessions receive short-lived capability leases",
      },
      {
        label: "Git authentications",
        panel: "git_auth",
        owner: "wallet.network",
        scope: "scope:scm.pull_request.write",
        copy: "scoped SCM leases",
      },
      {
        label: "Personal access tokens",
        panel: "personal_access_tokens",
        owner: "wallet.network",
        scope: "scope:token.create",
        copy: "not exposed to agents as reusable strings",
      },
      {
        label: "Integrations",
        panel: "integrations",
        owner: "Hypervisor Core",
        scope: "scope:adapter.code_editor.use",
        copy: "provider secrets stay wallet-brokered",
      },
    ];
    for (const section of credentialPanels) {
      await page.getByRole("button", { name: section.label }).click();
      const panel = page.locator(
        `[data-settings-credential-panel="${section.panel}"]`,
      );
      await panel.waitFor({ timeout: 5_000 });
      assert(
        (await panel.getAttribute("data-settings-authority-owner")) ===
          section.owner,
        `${section.label} did not bind the expected authority owner.`,
      );
      assert(
        ((await panel.getAttribute("data-settings-credential-custody")) ?? "")
          .length > 0,
        `${section.label} did not expose credential custody mode.`,
      );
      assert(
        (await panel
          .locator(`[data-settings-capability-row="${section.scope}"]`)
          .count()) === 1,
        `${section.label} did not expose ${section.scope}.`,
      );
      const panelText = await panel.innerText();
      assert(
        panelText.includes(section.copy),
        `${section.label} did not render the expected custody copy.`,
      );
      assert(
        (await panel.locator("[data-settings-receipt-ref]").count()) >= 2,
        `${section.label} did not expose receipt-bound settings rows.`,
      );
    }
    assert(
      consoleMessages.length === 0,
      `Offline reference shell emitted console warnings/errors: ${JSON.stringify(consoleMessages)}`,
    );

    const result = {
      schema_version: "ioi.hypervisor.app_shell_contract.v1",
      ok: true,
      url,
      contractDaemonUrl,
      checks: [
        "home_reference_prompt_surface_rendered",
        "home_reference_prompt_surface_sparse",
        "home_reference_clean_boot_has_no_seeded_recent_sessions",
        "left_rail_workspace_account_footer_rendered",
        "left_rail_reference_brand_mark_rendered",
        "reference_deep_links_boot_owning_surfaces",
        "home_seed_intent_reaches_new_session",
        "home_reference_prompt_action_reaches_new_session",
        "clean_boot_has_no_seeded_session_rail_rows",
        "new_session_starts_inline_without_modal_window",
        "new_session_launch_creates_readable_session_row",
        "new_session_launch_daemon_spawn_ready_for_codex_oss_qwen",
        "new_session_launch_daemon_host_readiness_ready",
        "sessions_reference_workspace_cockpit_rendered",
        "sessions_launched_harness_drill_in_rendered",
        "sessions_composer_agent_selector_rendered",
        "sessions_configure_advanced_governed_launch",
        "sessions_configure_advanced_step_up_gate",
        "automations_reference_clean_empty_state_rendered",
        "projects_reference_clean_empty_state_rendered",
        "workbench_workspace_session_surface_rendered",
        "foundry_harness_comparison_rendered",
        "foundry_harness_route_backed_qwen_adapters",
        "agents_reference_product_surface_rendered",
        "receipts_filter_and_drill_in_rendered",
        "settings_reference_surface_rendered",
        "settings_reference_primary_nav_rendered",
        "settings_code_editor_preference_rendered",
        "settings_credential_capability_panels_rendered",
        "offline_reference_shell_console_clean",
      ],
      consoleMessages,
    };
    if (evidencePath) {
      await writeFile(evidencePath, `${JSON.stringify(result, null, 2)}\n`);
    }
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await browser.close().catch(() => undefined);
    await new Promise((resolveClose) =>
      contractDaemonServer.close(resolveClose),
    );
    await new Promise((resolveClose) => server.close(resolveClose));
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
