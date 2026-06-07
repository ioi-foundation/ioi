import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computerUseControlActionForInput,
  nativeBrowserActionKindForInput,
  nativeBrowserActionKindIsReadOnly,
  nativeBrowserActionKindValue,
  nativeBrowserActionShouldUseCdpExecutor,
  nativeBrowserCdpTimeoutMs,
  nativeBrowserControlledRelaunchApprovalRefForInput,
  nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch,
  nativeBrowserHasExplicitCdpEndpoint,
  nativeBrowserSessionModeForInput,
  sandboxedHostedSessionModeForInput,
  visualGuiMediaTypeForPath,
  visualGuiObservationMetadataForInput,
  visualGuiSessionModeForInput,
} from "./computer-use-inputs.mjs";

test("computer-use inputs normalize action kinds and read-only classes", () => {
  assert.equal(nativeBrowserActionKindValue("input text"), "type_text");
  assert.equal(nativeBrowserActionKindValue("keypress"), "key_press");
  assert.equal(nativeBrowserActionKindValue("mouse move"), "hover");
  assert.equal(nativeBrowserActionKindForInput({}, "click the button"), "click");
  assert.equal(nativeBrowserActionKindForInput({ action_kind: "upload" }), "upload");
  assert.equal(
    nativeBrowserActionKindForInput({
      action_kind: "upload",
      actionKind: "click",
      computerUseActionKind: "click",
    }),
    "upload",
  );
  assert.equal(nativeBrowserActionKindForInput({ actionKind: "click", computerUseActionKind: "click" }), "inspect");
  assert.equal(nativeBrowserActionKindForInput({}, "unknown"), "inspect");
  assert.equal(nativeBrowserActionKindIsReadOnly("scroll"), true);
  assert.equal(nativeBrowserActionKindIsReadOnly("click"), false);
});

test("computer-use inputs normalize browser session and approval controls", () => {
  assert.equal(nativeBrowserSessionModeForInput({ cdp_endpoint_url: "ws://localhost/devtools" }), "attached_cdp");
  assert.equal(nativeBrowserSessionModeForInput({ controlled_relaunch: true }), "controlled_relaunch");
  assert.equal(nativeBrowserSessionModeForInput({}), "owned_hermetic_browser");
  assert.equal(visualGuiSessionModeForInput({ session_mode: "foreground_desktop" }), "foreground_desktop");
  assert.equal(visualGuiSessionModeForInput({ session_mode: "native_browser" }), "visual_fallback");
  assert.equal(sandboxedHostedSessionModeForInput({ session_mode: "hosted_sandbox" }), "hosted_sandbox");
  assert.equal(sandboxedHostedSessionModeForInput({ session_mode: "native_browser" }), "local_sandbox");
  assert.equal(nativeBrowserControlledRelaunchApprovalRefForInput({ browser_launch_approval_ref: "approval-1" }), "approval-1");
  assert.equal(
    nativeBrowserSessionModeForInput({
      session_mode: "controlled_relaunch",
      sessionMode: "attached_cdp",
      computerUseSessionMode: "attached_cdp",
    }),
    "controlled_relaunch",
  );
  assert.equal(nativeBrowserSessionModeForInput({ controlledRelaunch: true }), "owned_hermetic_browser");
  assert.equal(visualGuiSessionModeForInput({ sessionMode: "foreground_desktop" }), "visual_fallback");
  assert.equal(sandboxedHostedSessionModeForInput({ computerUseSessionMode: "hosted_sandbox" }), "local_sandbox");
  assert.equal(
    nativeBrowserControlledRelaunchApprovalRefForInput({
      controlled_relaunch_approval_ref: "approval-canonical",
      controlledRelaunchApprovalRef: "approval-retired",
      hostBrowserLaunchApprovalRef: "approval-retired-host",
    }),
    "approval-canonical",
  );
  assert.equal(nativeBrowserControlledRelaunchApprovalRefForInput({ browserLaunchApprovalRef: "approval-retired" }), null);
});

test("computer-use inputs classify CDP execution and control actions", () => {
  assert.equal(nativeBrowserHasExplicitCdpEndpoint({ cdp_ws_url: "ws://localhost/devtools" }), true);
  assert.equal(nativeBrowserHasExplicitCdpEndpoint({ cdpWsUrl: "ws://localhost/devtools" }), false);
  assert.equal(nativeBrowserCdpTimeoutMs({ timeout_ms: 2500.4 }), 2500);
  assert.equal(nativeBrowserCdpTimeoutMs({ cdpTimeoutMs: 2500.4, timeoutMs: 2500.4 }), 3000);
  assert.equal(nativeBrowserCdpTimeoutMs({ timeout_ms: 10 }), 3000);
  assert.equal(nativeBrowserActionShouldUseCdpExecutor("click", "approval-1", {}), true);
  assert.equal(nativeBrowserActionShouldUseCdpExecutor("scroll", null, { cdp_endpoint: "ws://x" }), true);
  assert.equal(computerUseControlActionForInput({ command: "clean up" }), "cleanup");
  assert.equal(computerUseControlActionForInput({ command: "stop" }), "abort");
  assert.equal(computerUseControlActionForInput({ command: "continue" }), "resume");
  assert.equal(computerUseControlActionForInput({}), "pause");
});

test("computer-use inputs project visual metadata and unavailable relaunch receipts", () => {
  const metadata = visualGuiObservationMetadataForInput({
    visual_observation: {
      screenshot_ref: "shot-1",
      viewport_width: "1280",
      viewport_height: 720,
      targets: [{ id: "target-1" }],
      detected_patterns: ["auth_wall"],
    },
  });
  assert.equal(metadata.screenshot_ref, "shot-1");
  assert.equal(metadata.viewport_width, 1280);
  assert.equal(metadata.viewport_height, 720);
  assert.equal(metadata.visual_targets.length, 1);
  assert.deepEqual(metadata.detected_patterns, ["auth_wall"]);
  for (const key of [
    "screenshotRef",
    "viewportWidth",
    "viewportHeight",
    "visualTargets",
    "detectedPatterns",
    "computerUseVisualObservation",
  ]) {
    assert.equal(Object.hasOwn(metadata, key), false, `retired visual metadata alias ${key} must be absent`);
  }
  assert.equal(visualGuiMediaTypeForPath("/tmp/a.webp"), "image/webp");

  const unavailable = nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch({
    launchReceipt: {
      launch_ref: "launch-1",
      broker_ref: "broker-1",
      evidence_refs: ["extra-1"],
    },
    actionKind: "click",
    approvalRef: "approval-1",
  });
  assert.equal(unavailable.status, "unavailable");
  assert.deepEqual(unavailable.evidence_refs, ["launch-1", "broker-1", "extra-1"]);

  const injectedDedupe = nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch({
    launchReceipt: {
      launch_ref: "launch-1",
      broker_ref: "broker-1",
      evidence_refs: ["launch-1", "extra-1"],
    },
    uniqueStrings(values) {
      return [...new Set(values.filter(Boolean))].reverse();
    },
  });
  assert.deepEqual(injectedDedupe.evidence_refs, ["extra-1", "broker-1", "launch-1"]);
});
