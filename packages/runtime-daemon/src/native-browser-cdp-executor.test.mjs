import assert from "node:assert/strict";
import test from "node:test";

import { executeNativeBrowserCdpAction } from "./native-browser-cdp-executor.mjs";
import { startFakeNativeBrowserCdpServer } from "./native-browser-cdp-test-fixture.mjs";

test("native browser CDP executor completes approved navigate actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdpEndpointUrl: fixture.endpointUrl,
        url: "https://example.test/next",
      },
      actionKind: "navigate",
      approvalRef: "approval-navigate",
      prompt: "Navigate to https://example.test/next",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.adapter_id, "ioi.native_browser.cdp");
    assert.equal(result.action_kind, "navigate");
    assert.equal(result.action_result.url, "https://example.test/next");
    assert.equal(result.after.url, "https://example.test/next");
    assert.equal(fixture.state.url, "https://example.test/next");
  } finally {
    await fixture.close();
  }
});

test("native browser CDP executor completes approved click actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdpEndpointUrl: fixture.endpointUrl,
        selector: "#submit",
      },
      actionKind: "click",
      approvalRef: "approval-click",
      targetRef: "#submit",
      prompt: "Click submit",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.action_result.action, "click");
    assert.equal(result.action_result.selector, "#submit");
    assert.equal(result.after.text_preview, "Clicked");
    assert.deepEqual(fixture.state.clicks, ["#submit"]);
  } finally {
    await fixture.close();
  }
});

test("native browser CDP executor fails closed without endpoint", async () => {
  const result = await executeNativeBrowserCdpAction({
    input: {},
    actionKind: "click",
    approvalRef: "approval-click",
    targetRef: "#submit",
    prompt: "Click submit",
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error_class, "NativeBrowserCdpUnavailable");
  assert.equal(result.action_kind, "click");
  assert.equal(result.approval_ref, "approval-click");
});
