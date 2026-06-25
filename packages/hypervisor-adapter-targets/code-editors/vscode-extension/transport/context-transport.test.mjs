import { createServer } from "node:http";
import { createRequire } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const {
  buildRuntimeRefs,
  createCodeEditorAdapterTransport,
} = require("./context-transport.js");

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

test("code editor adapter transport writes only adapter context envelopes", async () => {
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
    const transport = createCodeEditorAdapterTransport({
      transportUrl: () => base,
    });
    const written = await transport.writeContextEnvelope(
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

test("WS-6a: runtime refs are populated from the Session Execution Binding env when launched through Hypervisor", () => {
  const env = {
    IOI_HYPERVISOR_SESSION_REF: "session:s1",
    IOI_HYPERVISOR_ENVIRONMENT_REF: "environment:env1",
    IOI_HYPERVISOR_WORK_RUN_REF: "work_run:wr1",
    IOI_HYPERVISOR_BINDING_REF: "binding:bind1",
    IOI_HYPERVISOR_ACCESS_LEASE_REF: "enterprise.authority://grant/agr_1",
    IOI_HYPERVISOR_RECEIPT_REFS: "agentgres://r/1, agentgres://r/2",
  };
  const refs = buildRuntimeRefs(env);
  assert.equal(refs.sessionRef, "session:s1");
  assert.equal(refs.environmentRef, "environment:env1");
  assert.equal(refs.workRunRef, "work_run:wr1");
  assert.equal(refs.bindingRef, "binding:bind1");
  assert.equal(refs.accessLeaseRef, "enterprise.authority://grant/agr_1");
  assert.deepEqual(refs.receiptRefs, ["agentgres://r/1", "agentgres://r/2"]);
  assert.deepEqual(refs.capabilityRefs, ["enterprise.authority://grant/agr_1"]);
  assert.deepEqual(refs.authorityRefs, ["enterprise.authority://grant/agr_1"]);
  assert.equal(refs.boundThroughHypervisor, true);
});

test("WS-6a: runtime refs stay empty (not faked) when NOT launched through Hypervisor", () => {
  const refs = buildRuntimeRefs({});
  assert.equal(refs.sessionRef, null);
  assert.equal(refs.bindingRef, null);
  assert.equal(refs.boundThroughHypervisor, false);
  assert.deepEqual(refs.receiptRefs, []);
  assert.deepEqual(refs.capabilityRefs, []);
});
