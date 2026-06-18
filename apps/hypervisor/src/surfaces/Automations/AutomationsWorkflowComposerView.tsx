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

interface AutomationsWorkflowComposerViewProps {
  runtime: AgentWorkbenchRuntime;
  currentProject: ProjectScope;
  workflowPreflightSeed?: WorkflowComposerPreflightSeed | null;
  onConsumeWorkflowPreflightSeed?: () => void;
}

export function AutomationsWorkflowComposerView({
  runtime,
  currentProject,
  workflowPreflightSeed,
  onConsumeWorkflowPreflightSeed,
}: AutomationsWorkflowComposerViewProps) {
  return (
    <div className="hypervisor-surface-view hypervisor-surface-view--workflows hypervisor-surface-view--workflow-canvas">
      <WorkflowComposer
        runtime={runtime}
        currentProject={currentProject}
        preflightSeed={workflowPreflightSeed}
        onPreflightSeedConsumed={onConsumeWorkflowPreflightSeed}
      />
    </div>
  );
}
