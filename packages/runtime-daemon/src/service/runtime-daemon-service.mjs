import http from "node:http";
import path from "node:path";

export async function startRuntimeDaemonServiceWithStore({
  options = {},
  StateStore,
  handleRequest,
  writeError,
}) {
  const stateDir = path.resolve(options.stateDir ?? path.join(process.cwd(), ".ioi", "agentgres"));
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 0;
  if (Object.hasOwn(options, "contextPolicyRunner")) {
    throw new Error("contextPolicyRunner is retired; pass contextPolicyCore for the Rust daemon-core policy boundary.");
  }
  const store = new StateStore(stateDir, {
    cwd: options.cwd ?? process.cwd(),
    homeDir: options.homeDir,
    vaultSecrets: options.vaultSecrets,
    contextPolicyCore: options.contextPolicyCore,
    codingToolApprovalCore: options.codingToolApprovalCore,
    modelMountCore: options.modelMountCore,
    runtimeAgentgresAdmissionCore: options.runtimeAgentgresAdmissionCore,
    workspaceRestoreCore: options.workspaceRestoreCore,
    runtimeBridge: options.runtimeBridge,
    daemonCoreInvoker: options.daemonCoreInvoker,
    daemonCoreAgentgresApi: options.daemonCoreAgentgresApi,
    daemonCoreModelMountApi: options.daemonCoreModelMountApi,
    daemonCoreAuthorityApi: options.daemonCoreAuthorityApi,
    daemonCoreApprovalApi: options.daemonCoreApprovalApi,
    daemonCoreCteeApi: options.daemonCoreCteeApi,
    daemonCoreWorkerServiceApi: options.daemonCoreWorkerServiceApi,
    daemonCoreGovernedAdmissionApi: options.daemonCoreGovernedAdmissionApi,
    daemonCoreWorkspaceRestoreApi: options.daemonCoreWorkspaceRestoreApi,
  });
  const server = http.createServer((request, response) => {
    handleRequest({ request, response, store }).catch((error) => {
      writeError(response, {
        status: 500,
        code: "runtime",
        message: "IOI runtime daemon failed while handling request.",
        details: { error: String(error?.message ?? error) },
      });
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Runtime daemon did not bind to a TCP port.");
  }
  return {
    endpoint: `http://${address.address}:${address.port}`,
    stateDir,
    store,
    close: () =>
      new Promise((resolve, reject) => {
        store.close();
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
