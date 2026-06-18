import { createServer } from "node:http";
import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const {
  buildRuntimeRefs,
  createCodeEditorAdapterBridge,
} = require("./workspace-bridge.js");

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

test("code editor adapter bridge writes only adapter request envelopes", async () => {
  const requests = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({
        method: request.method,
        url: request.url,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
      });
      response.writeHead(204);
      response.end();
    });
  });

  const base = await listen(server);
  try {
    const bridge = createCodeEditorAdapterBridge({
      bridgeUrl: () => base,
    });
    const written = await bridge.writeBridgeRequest(
      "codeEditor.contextSnapshot",
      { workspaceRoot: "/workspace/repo" },
      { source: "unit" },
    );

    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].url, "/requests");
    assert.equal(requests[0].body.schemaVersion, "ioi.code_editor_adapter_request.v1");
    assert.equal(requests[0].body.requestType, "codeEditor.contextSnapshot");
    assert.equal(requests[0].body.runtimeTruthSource, "daemon-runtime");
    assert.equal(requests[0].body.projectionOwner, "hypervisor-code-editor-adapter");
    assert.equal(requests[0].body.ownsRuntimeState, false);
    assert.deepEqual(requests[0].body.runtimeRefs, buildRuntimeRefs());
    assert.equal(written.requestId, requests[0].body.requestId);
  } finally {
    server.close();
  }
});
