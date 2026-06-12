import { spawnSync } from "node:child_process";

export function createDaemonCoreCommandInvoker({
  command,
  daemonCoreInvoker,
  spawnSyncImpl = spawnSync,
  mockResult,
  mockSource,
  defaultBackend,
  ErrorClass,
  env,
  unconfiguredMessage,
  unconfiguredCode,
  spawnFailedMessage,
  spawnFailedCode,
  commandFailedMessage,
  commandFailedCode,
  invalidJsonMessage,
  invalidJsonCode,
  rejectedMessage,
  rejectedCode,
}) {
  const commandPath = optionalString(command);
  const directInvoker = optionalFunction(daemonCoreInvoker);
  return function invokeDaemonCoreCommand(request) {
    if (directInvoker) {
      return directInvoker(request);
    }
    if (mockResult) {
      const value = typeof mockResult === "function" ? mockResult(request) : mockResult;
      return {
        source: mockSource,
        backend: request.backend ?? defaultBackend,
        ...value,
      };
    }
    if (!commandPath) {
      throw new ErrorClass(unconfiguredMessage, unconfiguredCode, { env });
    }
    const output = spawnSyncImpl(commandPath, [], {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ErrorClass(spawnFailedMessage, spawnFailedCode, {
        error: String(output.error?.message ?? output.error),
      });
    }
    if (output.status !== 0) {
      throw new ErrorClass(commandFailedMessage, commandFailedCode, {
        status: output.status,
        stderr: String(output.stderr ?? "").slice(0, 4096),
      });
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new ErrorClass(invalidJsonMessage, invalidJsonCode, {
        error: String(error?.message ?? error),
      });
    }
    if (parsed?.ok === false) {
      throw new ErrorClass(
        parsed.error?.message ?? rejectedMessage,
        parsed.error?.code ?? rejectedCode,
        { error: parsed.error },
      );
    }
    return parsed.result ?? parsed;
  };
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function optionalFunction(value) {
  return typeof value === "function" ? value : null;
}
