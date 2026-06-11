import { spawnSync } from "node:child_process";

export function createStepModuleCommandInvoker({
  command,
  spawnSyncImpl = spawnSync,
  mockResult,
  ErrorClass,
  backend,
  env,
  workloadGrpcAddrEnv,
  shmemIdEnv,
}) {
  const commandPath = optionalString(command);
  return function invokeStepModuleCommand(request) {
    if (mockResult) {
      const value = typeof mockResult === "function" ? mockResult(request) : mockResult;
      return {
        source: "rust_workload_mock",
        invocation: request.invocation,
        ...value,
      };
    }
    if (!commandPath) {
      throw new ErrorClass(
        "Rust workload StepModule runner requires IOI_STEP_MODULE_COMMAND for command-bridge execution.",
        "rust_workload_bridge_unconfigured",
        {
          backend,
          env,
          workloadGrpcAddrEnv,
          shmemIdEnv,
        },
      );
    }
    const output = spawnSyncImpl(commandPath, [], {
      input: `${JSON.stringify(request)}\n`,
      encoding: "utf8",
      windowsHide: true,
    });
    if (output.error) {
      throw new ErrorClass(
        "Failed to spawn Rust workload StepModule bridge command.",
        "rust_workload_bridge_spawn_failed",
        { backend, error: String(output.error?.message ?? output.error) },
      );
    }
    if (output.status !== 0) {
      throw new ErrorClass(
        "Rust workload StepModule bridge command failed.",
        "rust_workload_bridge_failed",
        {
          backend,
          status: output.status,
          stderr: String(output.stderr ?? "").slice(0, 4096),
        },
      );
    }
    let parsed = null;
    try {
      parsed = JSON.parse(String(output.stdout ?? ""));
    } catch (error) {
      throw new ErrorClass(
        "Rust workload StepModule bridge command returned invalid JSON.",
        "rust_workload_bridge_invalid_json",
        { backend, error: String(error?.message ?? error) },
      );
    }
    if (parsed?.ok === false) {
      throw new ErrorClass(
        parsed.error?.message ?? "Rust workload StepModule bridge rejected the invocation.",
        parsed.error?.code ?? "rust_workload_bridge_rejected",
        { backend, error: parsed.error },
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
