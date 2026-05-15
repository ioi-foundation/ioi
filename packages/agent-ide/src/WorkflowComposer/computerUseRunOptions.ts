import type { WorkflowProject } from "../types/graph";

export const WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION =
  "ioi.workflow.composer-computer-use-run-options.v1" as const;

export interface WorkflowComposerComputerUseRunMetadata {
  schemaVersion: typeof WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION;
  source: "react_flow_workflow";
  computerUse: true;
  computerUseLane: string;
  computerUseSessionMode: string;
  computerUseActionKind: string;
  computerUseApprovalRef?: string;
  computerUseTargetRef?: string;
  controlledRelaunchApprovalRef?: string;
  controlledRelaunchBrokerRef?: string;
  controlledRelaunchExecutablePath?: string;
  controlledRelaunchHeadless?: boolean;
  controlledRelaunchStartUrl?: string;
  controlledRelaunchCdpPort?: number;
  selector?: string;
  text?: string;
  key?: string;
  scrollX?: number;
  scrollY?: number;
  filePath?: string;
  cdpEndpointUrl?: string;
  cdpWebSocketUrl?: string;
  cdpTimeoutMs?: number;
  screenshotRef?: string;
  screenshotPath?: string;
  somRef?: string;
  somPath?: string;
  axRef?: string;
  axPath?: string;
  captureScreen?: boolean;
  captureAxTree?: boolean;
  captureAppName?: string;
  captureWindowTitle?: string;
  localGuiExecutor?: boolean;
  localGuiExecutorProvider?: string;
  appName?: string;
  windowTitle?: string;
  coordinateSpaceId?: string;
  viewportWidth?: number;
  viewportHeight?: number;
  sandboxProvider?: string;
  sandboxFixture?: boolean;
  sandboxImageRef?: string;
  sandboxTaskRef?: string;
  observationRetentionMode: string | null;
  failClosedWhenUnavailable: boolean;
  workflowGraphId: string | null;
  workflowNodeId: string;
  workflowNodeIds: string[];
  toolRef: string | null;
  authorityScopes: string[];
}

export interface WorkflowComposerComputerUseRunOptions {
  metadata: WorkflowComposerComputerUseRunMetadata;
}

export function workflowComposerComputerUseRunOptions(
  workflow: WorkflowProject,
): WorkflowComposerComputerUseRunOptions | null {
  const computerUseNodes = workflow.nodes
    .filter((node) => node.type === "plugin_tool")
    .map((node) => {
      const toolBinding = node.config?.logic?.toolBinding;
      const args = toolBinding?.arguments ?? {};
      return {
        node,
        toolBinding,
        args,
      };
    })
    .filter(({ args }) => args["computerUse"] === true || args["computer_use"] === true);
  const first = computerUseNodes[0];
  if (!first) return null;
  const lane =
    cleanString(first.args["computerUseLane"]) ??
    cleanString(first.args["computer_use_lane"]) ??
    "native_browser";
  const sessionMode =
    cleanString(first.args["computerUseSessionMode"]) ??
    cleanString(first.args["computer_use_session_mode"]) ??
    defaultSessionModeForLane(lane);
  const actionKind =
    cleanString(first.args["computerUseActionKind"]) ??
    cleanString(first.args["computer_use_action_kind"]) ??
    cleanString(first.args["actionKind"]) ??
    cleanString(first.args["action_kind"]) ??
    "inspect";
  const approvalRef =
    cleanString(first.args["computerUseApprovalRef"]) ??
    cleanString(first.args["computer_use_approval_ref"]) ??
    cleanString(first.args["approvalRef"]) ??
    cleanString(first.args["approval_ref"]);
  const targetRef =
    cleanString(first.args["computerUseTargetRef"]) ??
    cleanString(first.args["computer_use_target_ref"]) ??
    cleanString(first.args["targetRef"]) ??
    cleanString(first.args["target_ref"]);
  const controlledRelaunchApprovalRef =
    cleanString(first.args["controlledRelaunchApprovalRef"]) ??
    cleanString(first.args["controlled_relaunch_approval_ref"]) ??
    cleanString(first.args["hostBrowserLaunchApprovalRef"]) ??
    cleanString(first.args["host_browser_launch_approval_ref"]) ??
    cleanString(first.args["browserLaunchApprovalRef"]) ??
    cleanString(first.args["browser_launch_approval_ref"]);
  const controlledRelaunchBrokerRef =
    cleanString(first.args["controlledRelaunchBrokerRef"]) ??
    cleanString(first.args["controlled_relaunch_broker_ref"]);
  const controlledRelaunchExecutablePath =
    cleanString(first.args["controlledRelaunchExecutablePath"]) ??
    cleanString(first.args["controlled_relaunch_executable_path"]) ??
    cleanString(first.args["browserExecutablePath"]) ??
    cleanString(first.args["browser_executable_path"]);
  const controlledRelaunchHeadless =
    booleanValue(first.args["controlledRelaunchHeadless"]) ??
    booleanValue(first.args["controlled_relaunch_headless"]) ??
    booleanValue(first.args["browserLaunchHeadless"]) ??
    booleanValue(first.args["browser_launch_headless"]);
  const controlledRelaunchStartUrl =
    cleanString(first.args["controlledRelaunchStartUrl"]) ??
    cleanString(first.args["controlled_relaunch_start_url"]);
  const controlledRelaunchCdpPort = positiveNumber(
    first.args["controlledRelaunchCdpPort"] ??
      first.args["controlled_relaunch_cdp_port"] ??
      first.args["browserLaunchCdpPort"] ??
      first.args["browser_launch_cdp_port"],
  );
  const selector = cleanString(first.args["selector"]) ?? cleanString(first.args["cssSelector"]);
  const text =
    cleanString(first.args["text"]) ??
    cleanString(first.args["inputText"]) ??
    cleanString(first.args["input_text"]);
  const key =
    cleanString(first.args["key"]) ??
    cleanString(first.args["keyText"]) ??
    cleanString(first.args["key_text"]);
  const scrollX = finiteNumber(first.args["scrollX"] ?? first.args["scroll_x"]);
  const scrollY = finiteNumber(first.args["scrollY"] ?? first.args["scroll_y"]);
  const filePath =
    cleanString(first.args["filePath"]) ??
    cleanString(first.args["file_path"]) ??
    cleanString(first.args["uploadPath"]) ??
    cleanString(first.args["upload_path"]);
  const cdpEndpointUrl =
    cleanString(first.args["cdpEndpointUrl"]) ??
    cleanString(first.args["cdp_endpoint_url"]) ??
    cleanString(first.args["cdpEndpoint"]) ??
    cleanString(first.args["cdp_endpoint"]);
  const cdpWebSocketUrl =
    cleanString(first.args["cdpWebSocketUrl"]) ??
    cleanString(first.args["cdp_websocket_url"]) ??
    cleanString(first.args["webSocketDebuggerUrl"]) ??
    cleanString(first.args["websocketDebuggerUrl"]);
  const cdpTimeoutMs = positiveNumber(
    first.args["cdpTimeoutMs"] ?? first.args["cdp_timeout_ms"],
  );
  const screenshotRef =
    cleanString(first.args["screenshotRef"]) ??
    cleanString(first.args["screenshot_ref"]);
  const screenshotPath =
    cleanString(first.args["screenshotPath"]) ??
    cleanString(first.args["screenshot_path"]);
  const somRef =
    cleanString(first.args["somRef"]) ??
    cleanString(first.args["som_ref"]) ??
    cleanString(first.args["setOfMarksRef"]) ??
    cleanString(first.args["set_of_marks_ref"]);
  const somPath =
    cleanString(first.args["somPath"]) ??
    cleanString(first.args["som_path"]) ??
    cleanString(first.args["setOfMarksPath"]) ??
    cleanString(first.args["set_of_marks_path"]);
  const axRef =
    cleanString(first.args["axRef"]) ??
    cleanString(first.args["ax_ref"]) ??
    cleanString(first.args["accessibilityTreeRef"]) ??
    cleanString(first.args["accessibility_tree_ref"]);
  const axPath =
    cleanString(first.args["axPath"]) ??
    cleanString(first.args["ax_path"]) ??
    cleanString(first.args["accessibilityTreePath"]) ??
    cleanString(first.args["accessibility_tree_path"]);
  const captureScreen =
    booleanValue(first.args["captureScreen"]) ??
    booleanValue(first.args["capture_screen"]) ??
    booleanValue(first.args["localCapture"]) ??
    booleanValue(first.args["local_capture"]);
  const captureAxTree =
    booleanValue(first.args["captureAxTree"]) ??
    booleanValue(first.args["capture_ax_tree"]) ??
    booleanValue(first.args["captureAccessibilityTree"]) ??
    booleanValue(first.args["capture_accessibility_tree"]);
  const captureAppName =
    cleanString(first.args["captureAppName"]) ??
    cleanString(first.args["capture_app_name"]);
  const captureWindowTitle =
    cleanString(first.args["captureWindowTitle"]) ??
    cleanString(first.args["capture_window_title"]);
  const localGuiExecutor =
    booleanValue(first.args["localGuiExecutor"]) ??
    booleanValue(first.args["local_gui_executor"]) ??
    booleanValue(first.args["executeLocalGui"]) ??
    booleanValue(first.args["execute_local_gui"]);
  const localGuiExecutorProvider =
    cleanString(first.args["localGuiExecutorProvider"]) ??
    cleanString(first.args["local_gui_executor_provider"]);
  const appName =
    cleanString(first.args["appName"]) ??
    cleanString(first.args["app_name"]);
  const windowTitle =
    cleanString(first.args["windowTitle"]) ??
    cleanString(first.args["window_title"]);
  const coordinateSpaceId =
    cleanString(first.args["coordinateSpaceId"]) ??
    cleanString(first.args["coordinate_space_id"]);
  const viewportWidth = positiveNumber(
    first.args["viewportWidth"] ?? first.args["viewport_width"],
  );
  const viewportHeight = positiveNumber(
    first.args["viewportHeight"] ?? first.args["viewport_height"],
  );
  const sandboxProvider =
    cleanString(first.args["computerUseSandboxProvider"]) ??
    cleanString(first.args["computer_use_sandbox_provider"]) ??
    cleanString(first.args["sandboxProvider"]) ??
    cleanString(first.args["sandbox_provider"]);
  const sandboxFixture =
    booleanValue(first.args["computerUseSandboxFixture"]) ??
    booleanValue(first.args["computer_use_sandbox_fixture"]) ??
    booleanValue(first.args["sandboxFixture"]) ??
    booleanValue(first.args["sandbox_fixture"]);
  const sandboxImageRef =
    cleanString(first.args["computerUseSandboxImageRef"]) ??
    cleanString(first.args["computer_use_sandbox_image_ref"]) ??
    cleanString(first.args["sandboxImageRef"]) ??
    cleanString(first.args["sandbox_image_ref"]);
  const sandboxTaskRef =
    cleanString(first.args["computerUseSandboxTaskRef"]) ??
    cleanString(first.args["computer_use_sandbox_task_ref"]) ??
    cleanString(first.args["sandboxTaskRef"]) ??
    cleanString(first.args["sandbox_task_ref"]);
  return {
    metadata: {
      schemaVersion: WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
      source: "react_flow_workflow",
      computerUse: true,
      computerUseLane: lane,
      computerUseSessionMode: sessionMode,
      computerUseActionKind: actionKind,
      ...(approvalRef ? { computerUseApprovalRef: approvalRef } : {}),
      ...(targetRef ? { computerUseTargetRef: targetRef } : {}),
      ...(controlledRelaunchApprovalRef
        ? { controlledRelaunchApprovalRef }
        : {}),
      ...(controlledRelaunchBrokerRef ? { controlledRelaunchBrokerRef } : {}),
      ...(controlledRelaunchExecutablePath
        ? { controlledRelaunchExecutablePath }
        : {}),
      ...(controlledRelaunchHeadless === true
        ? { controlledRelaunchHeadless: true }
        : {}),
      ...(controlledRelaunchStartUrl ? { controlledRelaunchStartUrl } : {}),
      ...(controlledRelaunchCdpPort ? { controlledRelaunchCdpPort } : {}),
      ...(selector ? { selector } : {}),
      ...(text ? { text } : {}),
      ...(key ? { key } : {}),
      ...(scrollX !== null && actionKind !== "inspect" ? { scrollX } : {}),
      ...(scrollY !== null && actionKind !== "inspect" ? { scrollY } : {}),
      ...(filePath ? { filePath } : {}),
      ...(cdpEndpointUrl ? { cdpEndpointUrl } : {}),
      ...(cdpWebSocketUrl ? { cdpWebSocketUrl } : {}),
      ...(cdpTimeoutMs &&
      (cdpEndpointUrl || cdpWebSocketUrl || sessionMode === "controlled_relaunch")
        ? { cdpTimeoutMs }
        : {}),
      ...(screenshotRef ? { screenshotRef } : {}),
      ...(screenshotPath ? { screenshotPath } : {}),
      ...(somRef ? { somRef } : {}),
      ...(somPath ? { somPath } : {}),
      ...(axRef ? { axRef } : {}),
      ...(axPath ? { axPath } : {}),
      ...(captureScreen === true ? { captureScreen: true } : {}),
      ...(captureAxTree === true ? { captureAxTree: true } : {}),
      ...(captureAppName ? { captureAppName } : {}),
      ...(captureWindowTitle ? { captureWindowTitle } : {}),
      ...(localGuiExecutor === true ? { localGuiExecutor: true } : {}),
      ...(localGuiExecutor === true && localGuiExecutorProvider
        ? { localGuiExecutorProvider }
        : {}),
      ...(appName ? { appName } : {}),
      ...(windowTitle ? { windowTitle } : {}),
      ...(coordinateSpaceId ? { coordinateSpaceId } : {}),
      ...(viewportWidth ? { viewportWidth } : {}),
      ...(viewportHeight ? { viewportHeight } : {}),
      ...(sandboxProvider ? { sandboxProvider } : {}),
      ...(sandboxFixture === true ? { sandboxFixture: true } : {}),
      ...(sandboxImageRef ? { sandboxImageRef } : {}),
      ...(sandboxTaskRef ? { sandboxTaskRef } : {}),
      observationRetentionMode:
        cleanString(first.args["observationRetentionMode"]) ??
        cleanString(first.args["observation_retention_mode"]),
      failClosedWhenUnavailable:
        booleanValue(first.args["failClosedWhenUnavailable"]) ??
        booleanValue(first.args["fail_closed_when_unavailable"]) ??
        true,
      workflowGraphId: cleanString(workflow.metadata?.id),
      workflowNodeId: first.node.id,
      workflowNodeIds: computerUseNodes.map(({ node }) => node.id),
      toolRef: cleanString(first.toolBinding?.toolRef),
      authorityScopes: first.toolBinding?.capabilityScope ?? [],
    },
  };
}

export function mergeWorkflowComposerComputerUseRunOptions(
  base: Record<string, unknown>,
  computerUse: WorkflowComposerComputerUseRunOptions | null,
): Record<string, unknown> {
  if (!computerUse) return base;
  const existingMetadata = recordValue(base["metadata"]);
  return {
    ...base,
    metadata: {
      ...existingMetadata,
      ...computerUse.metadata,
    },
  };
}

function defaultSessionModeForLane(lane: string): string {
  if (lane === "visual_gui") return "visual_fallback";
  if (lane === "sandboxed_hosted") return "local_sandbox";
  return "owned_hermetic_browser";
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function booleanValue(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function positiveNumber(value: unknown): number | null {
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return numeric;
}

function finiteNumber(value: unknown): number | null {
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
