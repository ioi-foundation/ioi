import type {
  ChatArtifactMaterializationContract,
} from "./chat-artifacts";
import type {
  WorkGraphAgent,
} from "./session";

type LegacyWorkGraphMaterialization = Partial<ChatArtifactMaterializationContract> & {
  swarmPlan?: ChatArtifactMaterializationContract["workGraphPlan"];
  swarmExecution?: ChatArtifactMaterializationContract["workGraphExecution"];
  swarmWorkerReceipts?: ChatArtifactMaterializationContract["workerReceipts"];
  swarmChangeReceipts?: ChatArtifactMaterializationContract["changeReceipts"];
  swarmMergeReceipts?: ChatArtifactMaterializationContract["mergeReceipts"];
  swarmVerificationReceipts?: ChatArtifactMaterializationContract["verificationReceipts"];
};

type LegacyWorkGraphTask = {
  work_graph_tree?: WorkGraphAgent[] | null;
  swarm_tree?: WorkGraphAgent[] | null;
};

export function normalizeWorkGraphTree(task: LegacyWorkGraphTask): WorkGraphAgent[] {
  if (Array.isArray(task.work_graph_tree)) {
    return task.work_graph_tree;
  }
  if (Array.isArray(task.swarm_tree)) {
    return task.swarm_tree;
  }
  return [];
}

export function normalizeMaterializationWorkGraphFields(
  materialization: ChatArtifactMaterializationContract,
): ChatArtifactMaterializationContract {
  const legacy = materialization as LegacyWorkGraphMaterialization;
  return {
    ...materialization,
    workGraphPlan: materialization.workGraphPlan ?? legacy.swarmPlan ?? null,
    workGraphExecution:
      materialization.workGraphExecution ?? legacy.swarmExecution ?? null,
    workerReceipts:
      materialization.workerReceipts ?? legacy.swarmWorkerReceipts ?? [],
    changeReceipts:
      materialization.changeReceipts ?? legacy.swarmChangeReceipts ?? [],
    mergeReceipts:
      materialization.mergeReceipts ?? legacy.swarmMergeReceipts ?? [],
    verificationReceipts:
      materialization.verificationReceipts ??
      legacy.swarmVerificationReceipts ??
      [],
  };
}
