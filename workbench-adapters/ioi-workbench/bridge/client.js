const http = require("http");
const https = require("https");

function bridgeUrl() {
  return process.env.IOI_WORKSPACE_IDE_BRIDGE_URL || null;
}

function daemonEndpoint() {
  return process.env.IOI_DAEMON_ENDPOINT || process.env.IOI_MODEL_MOUNTING_API_URL || null;
}

function daemonToken() {
  return process.env.IOI_DAEMON_TOKEN || process.env.IOI_MODEL_MOUNTING_TOKEN || null;
}

function normalizeBaseUrl(value) {
  if (!value) {
    return null;
  }
  return String(value).replace(/\/+$/, "");
}

function requestJson(baseUrl, routePath, { method = "GET", payload, token, timeoutMs } = {}) {
  const base = normalizeBaseUrl(baseUrl);
  if (!base) {
    return Promise.reject(new Error("IOI daemon endpoint is not configured."));
  }

  const target = new URL(routePath, `${base}/`);
  const client = target.protocol === "https:" ? https : http;
  const body = payload === undefined ? null : JSON.stringify(payload);

  return new Promise((resolve, reject) => {
    const request = client.request(
      target,
      {
        method,
        headers: {
          accept: "application/json",
          ...(body
            ? {
                "content-type": "application/json",
                "content-length": Buffer.byteLength(body),
              }
            : {}),
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          let parsed = null;
          try {
            parsed = raw ? JSON.parse(raw) : null;
          } catch (error) {
            reject(error);
            return;
          }
          if (response.statusCode >= 400) {
            reject(
              new Error(
                `[IOI Workbench] Daemon request failed (${response.statusCode}): ${raw}`,
              ),
            );
            return;
          }
          resolve(parsed);
        });
      },
    );

    const boundedTimeoutMs = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
      ? Number(timeoutMs)
      : 0;
    if (boundedTimeoutMs > 0) {
      request.setTimeout(boundedTimeoutMs, () => {
        request.destroy(new Error(`Daemon request timed out after ${boundedTimeoutMs}ms.`));
      });
    }
    request.on("error", reject);
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

async function readDaemonModelSnapshot({ timeoutMs } = {}) {
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    return {
      configured: false,
      endpoint: null,
      status: "not_configured",
      error: null,
      snapshot: null,
    };
  }

  try {
    const snapshot = await requestJson(endpoint, "/v1/model-mount/snapshot", {
      timeoutMs,
    });
    return {
      configured: true,
      endpoint,
      status: "connected",
      error: null,
      snapshot,
    };
  } catch (error) {
    return {
      configured: true,
      endpoint,
      status: "degraded",
      error: error?.message || String(error),
      snapshot: null,
    };
  }
}

module.exports = {
  bridgeUrl,
  daemonEndpoint,
  daemonToken,
  normalizeBaseUrl,
  readDaemonModelSnapshot,
  requestJson,
};
