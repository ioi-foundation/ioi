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

function createCodeEditorAdapterTransport({ transportUrl }) {
  function postEnvelope(transportPath, payload, { timeoutMs } = {}) {
    const base = transportUrl();
    if (!base) {
      return Promise.reject(
        new Error("IOI code editor adapter transport URL is not configured."),
      );
    }

    const target = new URL(transportPath, `${base}/`);
    const client = target.protocol === "https:" ? https : http;
    const body = payload ? JSON.stringify(payload) : null;

    return new Promise((resolve, reject) => {
      const request = client.request(
        target,
        {
          method: "POST",
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
                  `[IOI Code Editor Adapter] Transport request failed (${response.statusCode}): ${raw}`,
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
          request.destroy(
            new Error(`Transport request timed out after ${boundedTimeoutMs}ms.`),
          );
        });
      }
      request.on("error", reject);
      if (body) {
        request.write(body);
      }
      request.end();
    });
  }

  async function writeContextEnvelope(requestType, payload = {}, context = null) {
    const envelope = {
      schemaVersion: "ioi.code_editor_adapter_request.v1",
      requestId: crypto.randomUUID(),
      requestType,
      context,
      payload,
      runtimeTruthSource: "daemon-runtime",
      projectionOwner: "hypervisor-code-editor-adapter",
      ownsRuntimeState: false,
      runtimeRefs: buildRuntimeRefs(),
      timestampMs: Date.now(),
    };
    await postEnvelope("requests", envelope);
    return envelope;
  }

  return {
    buildRuntimeRefs,
    postEnvelope,
    writeContextEnvelope,
  };
}

module.exports = {
  buildRuntimeRefs,
  createCodeEditorAdapterTransport,
};
