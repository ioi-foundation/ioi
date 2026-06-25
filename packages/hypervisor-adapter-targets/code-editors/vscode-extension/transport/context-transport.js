const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const https = require("https");

// WS-6a — ingest the Session Execution Binding refs the daemon's host provisioner injects into the
// editor host (env vars, with a workspace-config file fallback). When launched through Hypervisor
// these are non-empty, so the context envelope carries real session/environment/work_run/binding/
// access-lease/receipt refs — the adapter publishes context but never owns runtime truth.
function buildRuntimeRefs(env = process.env) {
  const str = (k) => {
    const v = env[k];
    return v && String(v).trim() ? String(v).trim() : null;
  };
  const list = (k) => {
    const v = str(k);
    return v ? v.split(",").map((s) => s.trim()).filter(Boolean) : [];
  };
  // Optional workspace-config fallback installed into the host by the provisioner.
  let cfg = {};
  const cfgPath = str("IOI_HYPERVISOR_ADAPTER_CONTEXT_FILE");
  if (cfgPath) {
    try {
      cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    } catch {
      cfg = {};
    }
  }
  const sessionRef = str("IOI_HYPERVISOR_SESSION_REF") || cfg.sessionRef || null;
  const environmentRef = str("IOI_HYPERVISOR_ENVIRONMENT_REF") || cfg.environmentRef || null;
  const workRunRef = str("IOI_HYPERVISOR_WORK_RUN_REF") || cfg.workRunRef || null;
  const bindingRef = str("IOI_HYPERVISOR_BINDING_REF") || cfg.bindingRef || null;
  const accessLeaseRef = str("IOI_HYPERVISOR_ACCESS_LEASE_REF") || cfg.accessLeaseRef || null;
  const receiptRefs = list("IOI_HYPERVISOR_RECEIPT_REFS").length
    ? list("IOI_HYPERVISOR_RECEIPT_REFS")
    : Array.isArray(cfg.receiptRefs)
      ? cfg.receiptRefs
      : [];
  return {
    // Session Execution Binding refs (the one product binding).
    sessionRef,
    environmentRef,
    workRunRef,
    bindingRef,
    accessLeaseRef,
    // neutral ref lists (capability/authority leases reuse the access-lease ref).
    receiptRefs,
    artifactRefs: Array.isArray(cfg.artifactRefs) ? cfg.artifactRefs : [],
    authorityRefs: accessLeaseRef ? [accessLeaseRef] : [],
    manifestRefs: Array.isArray(cfg.manifestRefs) ? cfg.manifestRefs : [],
    capabilityRefs: accessLeaseRef ? [accessLeaseRef] : [],
    boundThroughHypervisor: Boolean(bindingRef || environmentRef),
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
