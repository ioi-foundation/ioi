import { codingToolContracts } from "./coding-tools.mjs";
import {
  runtimeAccount,
  runtimeNodes,
  runtimeTools,
} from "./runtime-tool-catalog.mjs";

export function createRuntimeToolSurface({
  codingToolContracts: codingToolContractsDep = codingToolContracts,
  processEnv = process.env,
  runtimeAccount: runtimeAccountDep = runtimeAccount,
  runtimeNodes: runtimeNodesDep = runtimeNodes,
  runtimeTools: runtimeToolsDep = runtimeTools,
} = {}) {
  return {
    getAccount() {
      return runtimeAccountDep(processEnv);
    },
    listRuntimeNodes() {
      return runtimeNodesDep(processEnv);
    },
    listTools(options = {}) {
      return runtimeToolsDep(options, {
        codingToolContracts: codingToolContractsDep,
      });
    },
  };
}
