import crypto from "node:crypto";

export const NATIVE_BROWSER_CDP_EXECUTOR_SCHEMA_VERSION =
  "ioi.runtime.native-browser-cdp-executor.v1";

export async function executeNativeBrowserCdpAction({
  input = {},
  actionKind,
  approvalRef,
  targetRef = null,
  prompt = "",
  timeoutMs = 3_000,
} = {}) {
  const executorRef = `native_browser_cdp_${stableHash(JSON.stringify({
    actionKind,
    approvalRef,
    targetRef,
    prompt,
  })).slice(0, 16)}`;
  const normalizedActionKind = normalizeActionKind(actionKind);
  if (!approvalRef || !["click", "navigate"].includes(normalizedActionKind)) {
    return unavailableExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      errorClass: "NativeBrowserCdpUnsupportedAction",
      errorSummary:
        "The native-browser CDP executor currently supports approved navigate and click actions.",
    });
  }

  const endpoint = await resolveCdpEndpoint(input, { timeoutMs });
  if (!endpoint) {
    return unavailableExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      errorClass: "NativeBrowserCdpUnavailable",
      errorSummary:
        "No explicit CDP websocket or endpoint URL was provided for the approved native-browser action.",
    });
  }

  let client = null;
  try {
    client = await connectCdpWebSocket(endpoint.webSocketDebuggerUrl, { timeoutMs });
    await client.command("Page.enable");
    await client.command("Runtime.enable");
    const before = await observePage(client);
    const actionResult = normalizedActionKind === "navigate"
      ? await executeNavigate(client, input, prompt, { timeoutMs })
      : await executeClick(client, input, targetRef);
    const after = await observePage(client);
    return {
      schema_version: NATIVE_BROWSER_CDP_EXECUTOR_SCHEMA_VERSION,
      object: "ioi.runtime_native_browser_cdp_execution",
      executor_ref: executorRef,
      adapter_id: "ioi.native_browser.cdp",
      session_ref: endpoint.sessionRef,
      endpoint_ref: endpoint.endpointRef,
      endpoint_source: endpoint.source,
      action_kind: normalizedActionKind,
      approval_ref: approvalRef,
      status: "completed",
      before,
      after,
      action_result: actionResult,
      evidence_refs: compactValues([
        endpoint.endpointRef,
        endpoint.sessionRef,
        before?.observation_ref,
        after?.observation_ref,
      ]),
    };
  } catch (error) {
    return unavailableExecution({
      executorRef,
      actionKind: normalizedActionKind,
      approvalRef,
      endpoint,
      errorClass: error?.name ?? "NativeBrowserCdpExecutionError",
      errorSummary: String(error?.message ?? error).slice(0, 300),
    });
  } finally {
    await client?.close?.();
  }
}

async function executeNavigate(client, input, prompt, { timeoutMs }) {
  const url = normalizeNavigationUrl(
    stringValue(input.url ?? input.targetUrl ?? input.target_url) ??
      String(prompt ?? "").match(/https?:\/\/[^\s)]+/i)?.[0],
  );
  if (!url) {
    throw new Error("Approved navigate action requires an http(s) URL.");
  }
  const loadEvent = client.waitForEvent("Page.loadEventFired", {
    timeoutMs,
    optional: true,
  });
  const navigation = await client.command("Page.navigate", { url });
  await loadEvent;
  return {
    action: "navigate",
    url,
    frame_id: stringValue(navigation?.frameId) ?? null,
  };
}

async function executeClick(client, input, targetRef) {
  const selector = normalizeSelector(
    input.selector ??
      input.targetSelector ??
      input.target_selector ??
      input.cssSelector ??
      input.css_selector ??
      targetRef,
  );
  if (!selector) {
    throw new Error("Approved click action requires selector, targetSelector, or selector-shaped targetRef.");
  }
  const expression = `(() => {
    const selector = ${JSON.stringify(selector)};
    const element = document.querySelector(selector);
    if (!element) {
      return { clicked: false, selector, reason: "target_not_found" };
    }
    element.scrollIntoView({ block: "center", inline: "center" });
    const rect = element.getBoundingClientRect();
    const label = (element.innerText || element.textContent || element.value || "").trim().slice(0, 160);
    element.click();
    return {
      clicked: true,
      selector,
      tag: element.tagName,
      id: element.id || null,
      label,
      bounds: {
        x: rect.x,
        y: rect.y,
        width: rect.width,
        height: rect.height
      }
    };
  })()`;
  const value = await evaluateReturnByValue(client, expression);
  if (!value?.clicked) {
    throw new Error(`CDP click did not find target selector ${selector}.`);
  }
  return {
    action: "click",
    ...value,
  };
}

async function observePage(client) {
  const value = await evaluateReturnByValue(client, `(() => {
    const body = document.body;
    const html = document.documentElement ? document.documentElement.outerHTML : "";
    return {
      url: location.href,
      title: document.title || null,
      text: body ? (body.innerText || body.textContent || "").slice(0, 4000) : "",
      html: html.slice(0, 20000)
    };
  })()`);
  const hash = stableHash(JSON.stringify(value ?? {})).slice(0, 16);
  return {
    observation_ref: `cdp_observation_${hash}`,
    url: stringValue(value?.url),
    title: stringValue(value?.title),
    text_preview: stringValue(value?.text)?.slice(0, 1000) ?? "",
    html_ref: value?.html ? `artifact:cdp_dom_${hash}` : null,
    html_hash: value?.html ? stableHash(value.html) : null,
  };
}

async function evaluateReturnByValue(client, expression) {
  const response = await client.command("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (response?.exceptionDetails) {
    throw new Error(response.exceptionDetails.text ?? "Runtime.evaluate failed.");
  }
  return response?.result?.value ?? null;
}

async function resolveCdpEndpoint(input, { timeoutMs }) {
  const explicitWs =
    stringValue(input.cdpWebSocketUrl) ??
    stringValue(input.cdp_websocket_url) ??
    stringValue(input.cdpWsUrl) ??
    stringValue(input.cdp_ws_url) ??
    stringValue(input.webSocketDebuggerUrl) ??
    stringValue(input.websocketDebuggerUrl) ??
    stringValue(process.env.IOI_NATIVE_BROWSER_CDP_WS_URL);
  if (explicitWs?.startsWith("ws://") || explicitWs?.startsWith("wss://")) {
    return {
      webSocketDebuggerUrl: explicitWs,
      endpointRef: `cdp_endpoint_${stableHash(explicitWs).slice(0, 16)}`,
      sessionRef: `cdp_session_${stableHash(explicitWs).slice(0, 16)}`,
      source: "explicit_websocket",
    };
  }

  const endpointUrl = trimTrailingSlash(
    stringValue(input.cdpEndpointUrl) ??
      stringValue(input.cdp_endpoint_url) ??
      stringValue(input.cdpEndpoint) ??
      stringValue(input.cdp_endpoint) ??
      stringValue(process.env.IOI_NATIVE_BROWSER_CDP_ENDPOINT),
  );
  if (!endpointUrl) return null;
  const version = await fetchJsonWithTimeout(`${endpointUrl}/json/version`, timeoutMs);
  const webSocketDebuggerUrl = stringValue(version?.webSocketDebuggerUrl);
  if (!webSocketDebuggerUrl) {
    throw new Error(`CDP endpoint ${endpointUrl} did not expose webSocketDebuggerUrl.`);
  }
  return {
    webSocketDebuggerUrl,
    endpointRef: `cdp_endpoint_${stableHash(endpointUrl).slice(0, 16)}`,
    sessionRef: `cdp_session_${stableHash(webSocketDebuggerUrl).slice(0, 16)}`,
    source: "explicit_http_endpoint",
    browser: stringValue(version?.Browser),
    protocol_version: stringValue(version?.["Protocol-Version"]),
  };
}

async function fetchJsonWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function connectCdpWebSocket(url, { timeoutMs }) {
  if (typeof WebSocket !== "function") {
    throw new Error("Global WebSocket is unavailable in this Node runtime.");
  }
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  let nextId = 1;
  const pending = new Map();
  const waiters = new Set();
  const opened = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("CDP websocket open timed out.")), timeoutMs);
    socket.addEventListener("open", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error("CDP websocket connection failed."));
    }, { once: true });
  });
  socket.addEventListener("message", (event) => {
    const text = typeof event.data === "string"
      ? event.data
      : Buffer.from(event.data).toString("utf8");
    const message = JSON.parse(text);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject, timer } = pending.get(message.id);
      clearTimeout(timer);
      pending.delete(message.id);
      if (message.error) {
        reject(new Error(message.error.message ?? JSON.stringify(message.error)));
      } else {
        resolve(message.result ?? {});
      }
      return;
    }
    for (const waiter of Array.from(waiters)) {
      if (waiter.method === message.method) {
        clearTimeout(waiter.timer);
        waiters.delete(waiter);
        waiter.resolve(message.params ?? {});
      }
    }
  });
  socket.addEventListener("close", () => {
    for (const { reject, timer } of pending.values()) {
      clearTimeout(timer);
      reject(new Error("CDP websocket closed before command completed."));
    }
    pending.clear();
    for (const waiter of Array.from(waiters)) {
      clearTimeout(waiter.timer);
      waiters.delete(waiter);
      waiter.resolve(null);
    }
  });
  await opened;
  return {
    command(method, params = {}) {
      const id = nextId++;
      const payload = JSON.stringify({ id, method, params });
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`CDP command ${method} timed out.`));
        }, timeoutMs);
        pending.set(id, { resolve, reject, timer });
        socket.send(payload);
      });
    },
    waitForEvent(method, { timeoutMs: waitTimeoutMs, optional = false } = {}) {
      return new Promise((resolve, reject) => {
        const waiter = {
          method,
          resolve,
          reject,
          timer: setTimeout(() => {
            waiters.delete(waiter);
            if (optional) resolve(null);
            else reject(new Error(`Timed out waiting for CDP event ${method}.`));
          }, waitTimeoutMs ?? timeoutMs),
        };
        waiters.add(waiter);
      });
    },
    close() {
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close();
      }
    },
  };
}

function unavailableExecution({
  executorRef,
  actionKind,
  approvalRef,
  endpoint = null,
  errorClass,
  errorSummary,
}) {
  return {
    schema_version: NATIVE_BROWSER_CDP_EXECUTOR_SCHEMA_VERSION,
    object: "ioi.runtime_native_browser_cdp_execution",
    executor_ref: executorRef,
    adapter_id: "ioi.native_browser.cdp",
    session_ref: endpoint?.sessionRef ?? null,
    endpoint_ref: endpoint?.endpointRef ?? null,
    endpoint_source: endpoint?.source ?? null,
    action_kind: actionKind,
    approval_ref: approvalRef ?? null,
    status: "unavailable",
    error_class: errorClass,
    error_summary: errorSummary,
    evidence_refs: compactValues([endpoint?.endpointRef, endpoint?.sessionRef]),
  };
}

function normalizeActionKind(value) {
  const normalized = String(value ?? "").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (normalized === "type" || normalized === "input_text") return "type_text";
  if (normalized === "keypress") return "key_press";
  return normalized || "inspect";
}

function normalizeNavigationUrl(value) {
  const url = stringValue(value);
  if (!url) return null;
  if (!/^https?:\/\//i.test(url)) return null;
  return url;
}

function normalizeSelector(value) {
  const selector = stringValue(value);
  if (!selector) return null;
  if (/^(#|\.|\[|[a-zA-Z][\w-]*(?:[#.\[]|$))/.test(selector)) return selector;
  return null;
}

function trimTrailingSlash(value) {
  const text = stringValue(value);
  return text ? text.replace(/\/+$/, "") : null;
}

function stringValue(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function compactValues(values) {
  return values.filter((value) => value !== null && value !== undefined && value !== "");
}

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}
