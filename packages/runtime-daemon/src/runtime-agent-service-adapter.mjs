import { spawn } from "node:child_process";

const COMMAND_SCHEMA_VERSION = "ioi.runtime.bridge.command.v1";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;

export function createRuntimeAgentServiceCommandAdapter(options = {}) {
  return new RuntimeAgentServiceCommandAdapter(options);
}

export function createRuntimeAgentServiceCommandAdapterFromEnv(env = process.env, options = {}) {
  const command =
    options.command ??
    env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND ??
    env.IOI_RUNTIME_BRIDGE_COMMAND;
  if (!command) return null;
  return createRuntimeAgentServiceCommandAdapter({
    ...options,
    command,
    args:
      options.args ??
      parseCommandArgs(
        env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS ?? env.IOI_RUNTIME_BRIDGE_ARGS,
      ),
    bridgeId:
      options.bridgeId ??
      env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID ??
      env.IOI_RUNTIME_BRIDGE_ID,
    timeoutMs:
      options.timeoutMs ??
      parsePositiveInteger(
        env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_TIMEOUT_MS ??
          env.IOI_RUNTIME_BRIDGE_TIMEOUT_MS,
        DEFAULT_TIMEOUT_MS,
      ),
  });
}

export class RuntimeAgentServiceCommandAdapter {
  constructor(options = {}) {
    const command = String(options.command ?? "").trim();
    if (!command) {
      throw new RuntimeAgentServiceCommandAdapterError(
        "RuntimeAgentService command adapter requires a command.",
        { operation: "configure" },
      );
    }
    this.command = command;
    this.args = normalizeArgs(options.args);
    this.cwd = options.cwd;
    this.env = { ...(options.env ?? {}) };
    this.timeoutMs = parsePositiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS);
    this.maxOutputBytes = parsePositiveInteger(
      options.maxOutputBytes,
      DEFAULT_MAX_OUTPUT_BYTES,
    );
    this.bridgeId = options.bridgeId ?? "runtime_agent_service_command";
  }

  async startThread(input) {
    return this.callBridge("start_thread", input);
  }

  async submitTurn(input, options = {}) {
    return this.callBridge("submit_turn", input, options);
  }

  async callBridge(operation, input, options = {}) {
    const request = {
      schema_version: COMMAND_SCHEMA_VERSION,
      bridge_id: this.bridgeId,
      operation,
      input,
    };
    const response = await invokeJsonCommand({
      command: this.command,
      args: this.args,
      cwd: this.cwd,
      env: { ...process.env, ...this.env },
      timeoutMs: this.timeoutMs,
      maxOutputBytes: this.maxOutputBytes,
      request,
      onRuntimeEvent: options.onRuntimeEvent,
    });
    if (response?.ok === false) {
      throw new RuntimeAgentServiceCommandAdapterError(
        response.error?.message ?? "RuntimeAgentService bridge command returned an error.",
        {
          operation,
          bridgeId: this.bridgeId,
          adapterErrorCode: response.error?.code ?? "bridge_command_error",
          error: response.error,
        },
      );
    }
    const result = response?.result ?? response;
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new RuntimeAgentServiceCommandAdapterError(
        "RuntimeAgentService bridge command must return an object result.",
        { operation, bridgeId: this.bridgeId },
      );
    }
    return {
      bridge_id: result.bridge_id ?? result.bridgeId ?? this.bridgeId,
      source: result.source ?? "runtime_service",
      ...result,
    };
  }
}

export class RuntimeAgentServiceCommandAdapterError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "RuntimeAgentServiceCommandAdapterError";
    this.status = details.status ?? 502;
    this.code = details.code ?? "runtime_bridge_command";
    this.details = details;
  }
}

function invokeJsonCommand({
  command,
  args,
  cwd,
  env,
  timeoutMs,
  maxOutputBytes,
  request,
  onRuntimeEvent,
}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stdoutLineBuffer = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;
    let timer = null;
    const operation = request.operation;
    const bridgeId = request.bridge_id;
    const armActivityTimeout = () => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeoutMs);
    };
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        reject(error);
      } else {
        resolve(value);
      }
    };
    armActivityTimeout();

    child.on("error", (error) => {
      finish(
        new RuntimeAgentServiceCommandAdapterError(
          "Failed to spawn RuntimeAgentService bridge command.",
          {
            operation,
            bridgeId,
            command,
            error: String(error?.message ?? error),
          },
        ),
      );
    });
    const appendStdoutLine = (line, { final = false } = {}) => {
      if (!line && !final) return;
      const streamEvent = bridgeRuntimeEventFromLine(line);
      if (streamEvent) {
        armActivityTimeout();
        try {
          onRuntimeEvent?.(streamEvent);
        } catch (error) {
          child.kill("SIGKILL");
          finish(
            new RuntimeAgentServiceCommandAdapterError(
              "RuntimeAgentService bridge runtime event callback failed.",
              {
                operation,
                bridgeId,
                error: String(error?.message ?? error),
              },
            ),
          );
        }
        return;
      }
      stdout += `${line}${final ? "" : "\n"}`;
      if (Buffer.byteLength(stdout, "utf8") > maxOutputBytes) {
        child.kill("SIGKILL");
        finish(
          new RuntimeAgentServiceCommandAdapterError(
            "RuntimeAgentService bridge command stdout exceeded the configured limit.",
            { operation, bridgeId, maxOutputBytes },
          ),
        );
      }
    };
    child.stdout.on("data", (chunk) => {
      stdoutLineBuffer += chunk.toString("utf8");
      const lines = stdoutLineBuffer.split(/\r?\n/);
      stdoutLineBuffer = lines.pop() ?? "";
      for (const line of lines) {
        appendStdoutLine(line);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
      if (Buffer.byteLength(stderr, "utf8") > maxOutputBytes) {
        child.kill("SIGKILL");
        finish(
          new RuntimeAgentServiceCommandAdapterError(
            "RuntimeAgentService bridge command stderr exceeded the configured limit.",
            { operation, bridgeId, maxOutputBytes },
          ),
        );
      }
    });
    child.on("close", (code, signal) => {
      if (stdoutLineBuffer) {
        appendStdoutLine(stdoutLineBuffer, { final: true });
        stdoutLineBuffer = "";
      }
      if (timedOut) {
        finish(
          new RuntimeAgentServiceCommandAdapterError(
            "RuntimeAgentService bridge command timed out.",
            { operation, bridgeId, timeoutMs },
          ),
        );
        return;
      }
      if (code !== 0) {
        finish(
          new RuntimeAgentServiceCommandAdapterError(
            "RuntimeAgentService bridge command exited unsuccessfully.",
            {
              operation,
              bridgeId,
              exitCode: code,
              signal,
              stderr: trimOutput(stderr),
            },
          ),
        );
        return;
      }
      try {
        finish(null, parseJsonOutput(stdout, { operation, bridgeId }));
      } catch (error) {
        finish(error);
      }
    });
    child.stdin.end(`${JSON.stringify(request)}\n`);
  });
}

function bridgeRuntimeEventFromLine(line) {
  const trimmed = String(line ?? "").trim();
  if (!trimmed.startsWith("{")) return null;
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (
    parsed?.type === "runtime_event" &&
    parsed.event &&
    typeof parsed.event === "object" &&
    !Array.isArray(parsed.event)
  ) {
    return parsed.event;
  }
  return null;
}

function parseJsonOutput(output, details) {
  const trimmed = output.trim();
  if (!trimmed) {
    throw new RuntimeAgentServiceCommandAdapterError(
      "RuntimeAgentService bridge command returned empty stdout.",
      details,
    );
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    for (const line of trimmed.split(/\r?\n/).reverse()) {
      const candidate = line.trim();
      if (!candidate.startsWith("{")) continue;
      try {
        return JSON.parse(candidate);
      } catch {
        // Keep looking for a structured JSON line after command logs.
      }
    }
  }
  throw new RuntimeAgentServiceCommandAdapterError(
    "RuntimeAgentService bridge command stdout did not contain a JSON object.",
    { ...details, stdout: trimOutput(trimmed) },
  );
}

function normalizeArgs(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((item) => String(item));
  return [String(value)];
}

function parseCommandArgs(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return [];
  if (raw.startsWith("[")) {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new RuntimeAgentServiceCommandAdapterError(
        "RuntimeAgentService bridge args env must be a JSON array.",
        { operation: "configure" },
      );
    }
    return normalizeArgs(parsed);
  }
  return raw.split(/\s+/).filter(Boolean);
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function trimOutput(value) {
  const normalized = String(value ?? "").trim();
  return normalized.length <= 4000 ? normalized : `${normalized.slice(0, 4000)}...`;
}
