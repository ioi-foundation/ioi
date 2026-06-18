import {
  type AgentWorkbenchRuntime,
  type WorkflowComposerPreflightSeed,
  WorkflowComposer,
} from "@ioi/hypervisor-workbench";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface MissionControlWorkflowsViewProps {
  runtime: AgentWorkbenchRuntime;
  currentProject: ProjectScope;
  workflowPreflightSeed?: WorkflowComposerPreflightSeed | null;
  onConsumeWorkflowPreflightSeed?: () => void;
}

export function MissionControlWorkflowsView({
  runtime,
  currentProject,
  workflowPreflightSeed,
  onConsumeWorkflowPreflightSeed,
}: MissionControlWorkflowsViewProps) {
  return (
    <div className="mission-control-view mission-control-view--workflows mission-control-view--workflow-canvas">
      <WorkflowComposer
        runtime={runtime}
        currentProject={currentProject}
        preflightSeed={workflowPreflightSeed}
        onPreflightSeedConsumed={onConsumeWorkflowPreflightSeed}
      />
    </div>
  );
}
