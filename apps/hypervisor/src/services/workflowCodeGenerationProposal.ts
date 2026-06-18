export interface WorkflowCodeGenerationProposalRequest {
  requestId?: string | null;
  requestedAtMs?: number | null;
  workflowRef?: string | null;
  packageRef?: string | null;
  goal?: string | null;
  targetWorkspace?: string | null;
  modelCapabilityRef?: string | null;
  toolCapabilityRefs?: string[];
  authorityScope?: string | null;
  evalProfileRef?: string | null;
  proposalOnly?: boolean;
}

export interface WorkflowCodeGenerationProposalFile {
  path: string;
  content: string;
}

export interface WorkflowCodeGenerationProposalPlan {
  workspaceRoot: string;
  proposalRootPath: string;
  requestPath: string;
  proposalPath: string;
  diffPath: string;
  checkPath: string;
  receiptPath: string;
  approvalReceiptPath: string;
  applyReceiptPath: string;
  checkReceiptPath: string;
  evalReceiptPath: string;
  files: WorkflowCodeGenerationProposalFile[];
}

export interface WorkflowCodeGenerationProposalMaterialization {
  status: "proposed" | "blocked";
  proposalRootPath: string;
  requestPath: string;
  proposalPath: string;
  diffPath: string;
  checkPath: string;
  receiptPath: string;
  approvalReceiptPath: string;
  applyReceiptPath: string;
  checkReceiptPath: string;
  evalReceiptPath: string;
  blockers: string[];
}

function slugify(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "") || "workflow-code-generation"
  );
}

function joinPath(...parts: string[]): string {
  return parts
    .flatMap((part) => part.split("/"))
    .filter((part) => part && part !== ".")
    .join("/");
}

function prettyJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function stableRequestRef(request: WorkflowCodeGenerationProposalRequest): string {
  return request.requestId?.trim() || `workflow-codegen:${request.requestedAtMs || Date.now()}`;
}

export function createWorkflowCodeGenerationProposalPlan(
  request: WorkflowCodeGenerationProposalRequest,
): WorkflowCodeGenerationProposalPlan {
  const requestedAtMs = request.requestedAtMs || Date.now();
  const workflowRef = request.workflowRef || "workflow:active";
  const packageRef = request.packageRef || "package:active";
  const goal =
    request.goal?.trim() || "Generate a proposal-first code change from this workflow.";
  const workspaceRoot = request.targetWorkspace || ".";
  const proposalSlug = slugify(`${workflowRef}-${requestedAtMs}`);
  const proposalRootPath = joinPath(".agents", "workflow-code-proposals", proposalSlug);
  const requestPath = joinPath(proposalRootPath, "request.json");
  const proposalPath = joinPath(proposalRootPath, "proposal.md");
  const diffPath = joinPath(proposalRootPath, "diffs", "proposed.patch");
  const checkPath = joinPath(proposalRootPath, "checks", "checklist.md");
  const receiptPath = joinPath(
    proposalRootPath,
    "receipts",
    "workflow-code-generation-receipt.json",
  );
  const approvalReceiptPath = joinPath(proposalRootPath, "receipts", "approval-required.json");
  const applyReceiptPath = joinPath(proposalRootPath, "receipts", "apply-blocked.json");
  const checkReceiptPath = joinPath(proposalRootPath, "receipts", "checks-required.json");
  const evalReceiptPath = joinPath(proposalRootPath, "receipts", "eval-required.json");
  const requestRef = stableRequestRef(request);
  const artifactRef = `artifact://workflow-code-proposal/${proposalSlug}`;
  const diffRef = `${artifactRef}/diff`;
  const receiptRef = `receipt://workflow-code-generation/${proposalSlug}`;
  const approvalReceiptRef = `${receiptRef}/approval-required`;
  const applyReceiptRef = `${receiptRef}/apply-blocked`;
  const checkReceiptRef = `${receiptRef}/checks-required`;
  const evalReceiptRef = `${receiptRef}/eval-required`;
  const proposalOnly = request.proposalOnly !== false;
  const blockers = proposalOnly
    ? ["target code not applied; approval and runtime-settled diff required"]
    : ["direct apply requested but normal Workbench adapter path is proposal-first"];

  const normalizedRequest = {
    schemaVersion: "ioi.workbench-integration.v1",
    requestId: requestRef,
    requestedAtMs,
    workflowRef,
    packageRef,
    goal,
    boundModelCapabilityRef:
      request.modelCapabilityRef || "model-capability:unbound",
    boundToolCapabilityRefs: request.toolCapabilityRefs ?? [],
    targetWorkspace: workspaceRoot,
    authorityScope: request.authorityScope || "workspace.fs.proposal",
    evalProfileRef: request.evalProfileRef || null,
    proposalOnly: true,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
  };

  const approvalReceipt = {
    schemaVersion: "ioi.workbench-integration.v1",
    receiptId: approvalReceiptRef,
    requestRef,
    status: "approval_required",
    authorityScope: normalizedRequest.authorityScope,
    summary: "A human or policy approval is required before source files can be changed.",
    blockers,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
  };

  const applyReceipt = {
    schemaVersion: "ioi.workbench-integration.v1",
    receiptId: applyReceiptRef,
    requestRef,
    status: "blocked",
    appliedFiles: [],
    changedFiles: [],
    summary:
      "No workspace source files were changed. Apply is blocked until IOI runtime settles an approved patch.",
    blockers,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
  };

  const checkReceipt = {
    schemaVersion: "ioi.workbench-integration.v1",
    receiptId: checkReceiptRef,
    requestRef,
    status: "blocked",
    checkRefs: [],
    summary: "Checks are pending an approved patch and apply receipt.",
    blockers: ["approved patch and apply receipt missing"],
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
  };

  const evalReceipt = {
    schemaVersion: "ioi.workbench-integration.v1",
    receiptId: evalReceiptRef,
    requestRef,
    status: "blocked",
    evalProfileRef: normalizedRequest.evalProfileRef,
    scorecardRefs: [],
    summary: "Evaluation is pending check evidence from the applied proposal.",
    blockers: ["check receipt evidence missing"],
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
  };

  const receipt = {
    schemaVersion: "ioi.workbench-integration.v1",
    receiptId: receiptRef,
    requestRef,
    status: "proposed",
    createdFiles: [
      requestPath,
      proposalPath,
      diffPath,
      checkPath,
      receiptPath,
      approvalReceiptPath,
      applyReceiptPath,
      checkReceiptPath,
      evalReceiptPath,
    ],
    changedFiles: [],
    diffRefs: [diffRef],
    runRefs: [],
    approvalReceiptRefs: [approvalReceiptRef],
    applyReceiptRefs: [applyReceiptRef],
    verificationRefs: [checkReceiptRef],
    evalReceiptRefs: [evalReceiptRef],
    promotionBlockers: blockers,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "hypervisor-code-editor-adapter",
    ownsRuntimeState: false,
    runtimeRefs: {
      threadId: null,
      runId: null,
      turnId: null,
      receiptRefs: [
        receiptRef,
        approvalReceiptRef,
        applyReceiptRef,
        checkReceiptRef,
        evalReceiptRef,
      ],
      artifactRefs: [artifactRef, diffRef],
      authorityRefs: [normalizedRequest.authorityScope],
      manifestRefs: [packageRef],
      capabilityRefs: [
        normalizedRequest.boundModelCapabilityRef,
        ...normalizedRequest.boundToolCapabilityRefs,
      ].filter(Boolean),
    },
  };

  return {
    workspaceRoot,
    proposalRootPath,
    requestPath,
    proposalPath,
    diffPath,
    checkPath,
    receiptPath,
    approvalReceiptPath,
    applyReceiptPath,
    checkReceiptPath,
    evalReceiptPath,
    files: [
      {
        path: requestPath,
        content: prettyJson(normalizedRequest),
      },
      {
        path: proposalPath,
        content: [
          `# Workflow Code Proposal`,
          "",
          `Workflow: ${workflowRef}`,
          `Package: ${packageRef}`,
          `Goal: ${goal}`,
          `Workspace: ${workspaceRoot}`,
          "",
          "This is a proposal artifact only. The native Workbench adapter contribution has not changed target source files.",
          "A model/runtime pass must produce the final diff, collect approval, and emit apply/check receipts before mutation.",
          "",
        ].join("\n"),
      },
      {
        path: diffPath,
        content: [
          "# Proposal-first placeholder diff.",
          "# Target source files are unchanged until IOI runtime settles an approved patch.",
          "# The final model-generated patch should replace this file before apply.",
          "",
        ].join("\n"),
      },
      {
        path: checkPath,
        content: [
          "# Verification Checklist",
          "",
          "- [ ] Review model-generated diff.",
          "- [ ] Confirm authority scope and approval profile.",
          "- [ ] Apply only after approval.",
          "- [ ] Run relevant checks/evals.",
          "- [ ] Verify `WorkflowCodeGenerationReceipt` and apply receipt refs.",
          "",
        ].join("\n"),
      },
      {
        path: receiptPath,
        content: prettyJson(receipt),
      },
      {
        path: approvalReceiptPath,
        content: prettyJson(approvalReceipt),
      },
      {
        path: applyReceiptPath,
        content: prettyJson(applyReceipt),
      },
      {
        path: checkReceiptPath,
        content: prettyJson(checkReceipt),
      },
      {
        path: evalReceiptPath,
        content: prettyJson(evalReceipt),
      },
    ],
  };
}

export async function materializeWorkflowCodeGenerationProposal(
  request: WorkflowCodeGenerationProposalRequest,
): Promise<WorkflowCodeGenerationProposalMaterialization> {
  const { hostWorkspaceAdapter } = await import("./workspaceAdapter");
  const plan = createWorkflowCodeGenerationProposalPlan(request);
  await hostWorkspaceAdapter.createDirectory(plan.workspaceRoot, plan.proposalRootPath);
  for (const file of plan.files) {
    await hostWorkspaceAdapter.writeFile(plan.workspaceRoot, file.path, file.content);
  }

  return {
    status: "proposed",
    proposalRootPath: plan.proposalRootPath,
    requestPath: plan.requestPath,
    proposalPath: plan.proposalPath,
    diffPath: plan.diffPath,
    checkPath: plan.checkPath,
    receiptPath: plan.receiptPath,
    approvalReceiptPath: plan.approvalReceiptPath,
    applyReceiptPath: plan.applyReceiptPath,
    checkReceiptPath: plan.checkReceiptPath,
    evalReceiptPath: plan.evalReceiptPath,
    blockers: ["target code not applied; approval and runtime-settled diff required"],
  };
}
