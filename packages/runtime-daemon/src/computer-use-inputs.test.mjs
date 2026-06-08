import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computerUseAuthorityScopesForInput,
  computerUseControlActionForInput,
  computerUseObservationRetentionModeForInput,
  computerUseWorkflowNodeIdsForInput,
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

test("computer-use inputs consume canonical authority scopes only", () => {
  assert.deepEqual(
    computerUseAuthorityScopesForInput({
      authority_scopes: ["computer_use.visual_gui.read", " ", "scope.extra"],
      authorityScopes: ["scope.retired"],
    }),
    ["computer_use.visual_gui.read", "scope.extra"],
  );
  assert.deepEqual(
    computerUseAuthorityScopesForInput({
      authorityScopes: ["scope.retired"],
    }),
    [],
  );
});

test("computer-use inputs consume canonical observation retention only", () => {
  assert.equal(
    computerUseObservationRetentionModeForInput(
      {
        observation_retention_mode: "local_redacted_artifacts",
        observationRetentionMode: "local_raw_artifacts",
      },
      "prompt_visible_summary_only",
    ),
    "local_redacted_artifacts",
  );
  assert.equal(
    computerUseObservationRetentionModeForInput(
      {
        observationRetentionMode: "local_raw_artifacts",
      },
      "prompt_visible_summary_only",
    ),
    "prompt_visible_summary_only",
  );
});

test("computer-use inputs consume canonical workflow node ids only", () => {
  assert.deepEqual(
    computerUseWorkflowNodeIdsForInput({
      workflow_node_ids: ["node.canonical", " ", "node.extra"],
      workflowNodeIds: ["node.retired"],
    }),
    ["node.canonical", "node.extra"],
  );
  assert.deepEqual(
    computerUseWorkflowNodeIdsForInput({
      workflowNodeIds: ["node.retired"],
    }),
    [],
  );
});

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

  const retiredOnlyMetadata = visualGuiObservationMetadataForInput({
    computerUseVisualObservation: {
      screenshotRef: "retired-shot",
      viewportWidth: 1200,
      visualTargets: [{ targetRef: "retired-target" }],
      detectedPatterns: ["retired-pattern"],
    },
    visualObservation: {
      screenshotRef: "retired-visual-shot",
    },
    visualTargets: [{ target_ref: "retired-top-level-target" }],
    detectedPatterns: ["retired-top-level-pattern"],
    viewportWidth: 800,
    viewportHeight: 600,
  });
  assert.deepEqual(retiredOnlyMetadata, {});

  const canonicalMetadata = visualGuiObservationMetadataForInput({
    computer_use_visual_observation: {
      screenshot_ref: "canonical-shot",
      screenshotRef: "retired-shot",
      viewport_width: 640,
      viewportWidth: 1200,
      visual_targets: [{ target_ref: "canonical-target" }],
      visualTargets: [{ targetRef: "retired-target" }],
      detected_patterns: ["canonical-pattern"],
      detectedPatterns: ["retired-pattern"],
    },
    screenshotRef: "retired-top-level-shot",
    viewportWidth: 999,
    visualTargets: [{ targetRef: "retired-top-level-target" }],
  });
  assert.equal(canonicalMetadata.screenshot_ref, "canonical-shot");
  assert.equal(canonicalMetadata.viewport_width, 640);
  assert.deepEqual(canonicalMetadata.visual_targets, [{ target_ref: "canonical-target" }]);
  assert.deepEqual(canonicalMetadata.detected_patterns, ["canonical-pattern"]);
  assert.equal(Object.hasOwn(canonicalMetadata, "screenshotRef"), false);
  assert.equal(Object.hasOwn(canonicalMetadata, "viewportWidth"), false);
  assert.equal(Object.hasOwn(canonicalMetadata, "visualTargets"), false);

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
