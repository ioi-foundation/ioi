import type {
  WorkflowProjectMaterializationRequest,
  WorkflowProjectMaterializationResult,
} from "@ioi/hypervisor-workbench";

import { hostWorkspaceAdapter } from "./workspaceAdapter";
import {
  persistCreatedWorkspaceRepository,
  persistPendingWorkspaceRepositoryOpen,
  type WorkspaceRepositoryRecord,
} from "./workspaceRepositoryRegistry";
import { createWorkflowProjectMaterializationPlan } from "./workflowProjectMaterializationPlan";

export async function materializeWorkflowProject(
  request: WorkflowProjectMaterializationRequest,
): Promise<WorkflowProjectMaterializationResult> {
  const plan = createWorkflowProjectMaterializationPlan(request);

  if (!request.dryRun) {
    await hostWorkspaceAdapter.createDirectory(".", plan.rootPath);
    for (const file of plan.files) {
      await hostWorkspaceAdapter.writeFile(".", file.path, file.content);
    }

    const now = Date.now();
    const repository: WorkspaceRepositoryRecord = {
      id: `created:${plan.rootPath}`,
      name: request.projectName,
      description: "Autonomous System Package / workflow materialization",
      environment: "Local",
      rootPath: plan.rootPath,
      source: "created",
      category: "applications",
      template: "autonomous-system-package",
      createdAtMs: now,
      lastOpenedAtMs: now,
      favorite: false,
    };
    persistCreatedWorkspaceRepository(repository);
    persistPendingWorkspaceRepositoryOpen(repository);
  }

  return {
    receiptId: `workflow-project-materialization:${request.workflowId}:${request.requestedAtMs}`,
    status: request.dryRun ? "proposed" : "opened",
    rootPath: plan.rootPath,
    manifestPath: plan.manifestPath,
    workflowPath: plan.workflowPath,
    evalPath: plan.evalPath,
    expectedReceiptsPath: plan.expectedReceiptsPath,
    openedInWorkspace: !request.dryRun,
    blockers: [],
  };
}
