import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { executeNativeBrowserCdpAction } from "./native-browser-cdp-executor.mjs";
import { startFakeNativeBrowserCdpServer } from "./native-browser-cdp-test-fixture.mjs";

test("native browser CDP executor completes approved navigate actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdp_endpoint_url: fixture.endpointUrl,
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
        cdp_endpoint_url: fixture.endpointUrl,
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

test("native browser CDP executor completes approved type_text actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdp_endpoint_url: fixture.endpointUrl,
        selector: "#input",
        text: "hello IOI",
      },
      actionKind: "type_text",
      approvalRef: "approval-type",
      targetRef: "#input",
      prompt: "Type into input",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.action_result.action, "type_text");
    assert.equal(result.action_result.selector, "#input");
    assert.equal(result.action_result.text_length, 9);
    assert.equal(result.after.text_preview, "Typed hello IOI");
    assert.deepEqual(fixture.state.typed, [{ selector: "#input", text: "hello IOI" }]);
  } finally {
    await fixture.close();
  }
});

test("native browser CDP executor completes approved key_press actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdp_endpoint_url: fixture.endpointUrl,
        key: "Enter",
      },
      actionKind: "key_press",
      approvalRef: "approval-key",
      prompt: "Press Enter",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.action_result.action, "key_press");
    assert.equal(result.action_result.key, "Enter");
    assert.equal(result.action_result.code, "Enter");
    assert.equal(result.after.text_preview, "Pressed Enter");
    assert.deepEqual(fixture.state.keys, [{ key: "Enter", code: "Enter", text: "" }]);
  } finally {
    await fixture.close();
  }
});

test("native browser CDP executor completes explicit scroll actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdp_endpoint_url: fixture.endpointUrl,
        scroll_y: 420,
      },
      actionKind: "scroll",
      prompt: "Scroll down",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.action_result.action, "scroll");
    assert.equal(result.action_result.delta_y, 420);
    assert.equal(result.action_result.target, "window");
    assert.equal(result.after.text_preview, "Scrolled 420");
    assert.deepEqual(fixture.state.scrolls, [{ selector: null, deltaX: 0, deltaY: 420 }]);
  } finally {
    await fixture.close();
  }
});

test("native browser CDP executor completes approved upload actions", async () => {
  const fixture = await startFakeNativeBrowserCdpServer();
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-cdp-upload-"));
  const uploadPath = path.join(tempDir, "fixture.txt");
  fs.writeFileSync(uploadPath, "upload me", "utf8");
  try {
    const result = await executeNativeBrowserCdpAction({
      input: {
        cdp_endpoint_url: fixture.endpointUrl,
        selector: "#file",
        file_path: uploadPath,
      },
      actionKind: "upload",
      approvalRef: "approval-upload",
      targetRef: "#file",
      prompt: "Upload the fixture",
    });

    assert.equal(result.status, "completed");
    assert.equal(result.action_result.action, "upload");
    assert.equal(result.action_result.selector, "#file");
    assert.equal(result.action_result.file_count, 1);
    assert.equal(result.after.text_preview, "Uploaded 1");
    assert.deepEqual(fixture.state.uploads, [{ nodeId: 2, files: [uploadPath] }]);
  } finally {
    await fixture.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test("native browser CDP executor ignores retired camelCase input aliases", async () => {
  const result = await executeNativeBrowserCdpAction({
    input: {
      cdpEndpointUrl: "http://127.0.0.1:1",
      cdpEndpoint: "http://127.0.0.1:2",
      cdpWebSocketUrl: "ws://127.0.0.1/devtools/retired",
      cdpWsUrl: "ws://127.0.0.1/devtools/retired-short",
      webSocketDebuggerUrl: "ws://127.0.0.1/devtools/retired-debugger",
      websocketDebuggerUrl: "ws://127.0.0.1/devtools/retired-lower",
      targetUrl: "https://retired.example.test",
      targetSelector: "#retired",
      cssSelector: "#retired-css",
      inputText: "retired input",
      textValue: "retired text",
      keyText: "R",
      keyboardKey: "R",
      scrollX: 20,
      scrollY: 30,
      deltaX: 40,
      deltaY: 50,
      filePath: "/tmp/retired-file",
      uploadPath: "/tmp/retired-upload",
      filePaths: ["/tmp/retired-list"],
    },
    actionKind: "click",
    approvalRef: "approval-retired-aliases",
    prompt: "Click #retired",
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error_class, "NativeBrowserCdpUnavailable");
  assert.equal(result.endpoint_ref, null);
  assert.equal(result.session_ref, null);
  assert.deepEqual(
    result.evidence_refs.filter((ref) => ref.includes("retired")),
    [],
  );
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
