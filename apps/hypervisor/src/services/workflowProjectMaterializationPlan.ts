import type { WorkflowProjectMaterializationRequest } from "@ioi/hypervisor-workbench";

export interface WorkflowProjectMaterializationFile {
  path: string;
  content: string;
}

export interface WorkflowProjectMaterializationPlan {
  rootPath: string;
  manifestPath: string;
  workflowPath: string;
  evalPath: string;
  expectedReceiptsPath: string;
  files: WorkflowProjectMaterializationFile[];
}

function slugifyWorkflowProjectName(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "workflow-project";
}

function joinWorkspacePath(...parts: string[]): string {
  return parts
    .flatMap((part) => part.split("/"))
    .filter((part) => part && part !== ".")
    .join("/");
}

function prettyJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function createWorkflowProjectMaterializationPlan(
  request: WorkflowProjectMaterializationRequest,
): WorkflowProjectMaterializationPlan {
  const slug = slugifyWorkflowProjectName(request.projectName);
  const rootPath = joinWorkspacePath(
    request.projectRoot,
    ".agents",
    "materialized-projects",
    slug,
  );
  const manifestPath = joinWorkspacePath(rootPath, "autonomous-system.manifest.json");
  const workflowPath = joinWorkspacePath(rootPath, "workflow.workflow.json");
  const evalPath = joinWorkspacePath(rootPath, "evals", "fixture.json");
  const expectedReceiptsPath = joinWorkspacePath(
    rootPath,
    "receipts",
    "expected-receipts.json",
  );

  const manifest = {
    schemaVersion: "ioi.autonomous-system-package.v1",
    packageId: `workflow-package:${slug}`,
    name: request.projectName,
    sourceWorkflow: {
      id: request.workflowId,
      name: request.workflowName,
      path: request.workflowPath,
    },
    runtimeTruth: "daemon-runtime",
    projectRoot: request.projectRoot,
    artifacts: {
      workflow: workflowPath,
      evalFixture: evalPath,
      expectedReceipts: expectedReceiptsPath,
    },
    lifecycle: {
      composed: true,
      bound: false,
      simulated: false,
      authorized: false,
      run: false,
      verified: false,
      packaged: true,
      deployed: false,
      promoted: false,
    },
    requestedAtMs: request.requestedAtMs,
  };

  const evalFixture = {
    schemaVersion: "ioi.workflow-project-eval-fixture.v1",
    packageId: manifest.packageId,
    goal: `Smoke-test ${request.workflowName}`,
    mode: "fixture",
    assertions: [
      {
        id: "workflow-loads",
        kind: "manifest_ref_exists",
        target: workflowPath,
      },
      {
        id: "receipts-declared",
        kind: "expected_receipts_declared",
        target: expectedReceiptsPath,
      },
    ],
  };

  const expectedReceipts = {
    schemaVersion: "ioi.expected-receipts.v1",
    packageId: manifest.packageId,
    receipts: [
      {
        kind: "workflow_project_materialized",
        required: true,
        refs: [manifestPath, workflowPath, evalPath],
      },
      {
        kind: "workspace_open",
        required: true,
        refs: [rootPath],
      },
    ],
  };

  return {
    rootPath,
    manifestPath,
    workflowPath,
    evalPath,
    expectedReceiptsPath,
    files: [
      {
        path: joinWorkspacePath(rootPath, "README.md"),
        content: [
          `# ${request.projectName}`,
          "",
          "Generated from an Autopilot workflow as an Autonomous System Package scaffold.",
          "",
          "This package contains the workflow manifest, an eval fixture, and expected receipt declarations. Runtime execution remains governed by daemon authority, wallet grants, and Agentgres receipts.",
          "",
        ].join("\n"),
      },
      {
        path: manifestPath,
        content: prettyJson(manifest),
      },
      {
        path: workflowPath,
        content: prettyJson(request.workflowSnapshot),
      },
      {
        path: evalPath,
        content: prettyJson(evalFixture),
      },
      {
        path: expectedReceiptsPath,
        content: prettyJson(expectedReceipts),
      },
    ],
  };
}
