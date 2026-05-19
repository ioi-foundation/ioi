import assert from "node:assert/strict";
import test from "node:test";

import { createWorkflowCodeGenerationProposalPlan } from "./workflowCodeGenerationProposal.ts";

test("workflow code generation proposal plan writes proposal-only artifacts", () => {
  const plan = createWorkflowCodeGenerationProposalPlan({
    requestId: "request://workflow-codegen/1",
    requestedAtMs: 1_779_209_601_000,
    workflowRef: "workflow://repo-agent",
    packageRef: "package://repo-agent",
    goal: "Add a focused unit test.",
    targetWorkspace: "/tmp/example-workspace",
    modelCapabilityRef: "model-capability:autopilot.mounted.local-coder",
    toolCapabilityRefs: ["tool-capability:workspace.apply-patch"],
    authorityScope: "workspace.fs.proposal",
    evalProfileRef: "eval://repo-agent/unit",
    proposalOnly: true,
  });

  assert.equal(plan.workspaceRoot, "/tmp/example-workspace");
  assert.match(
    plan.proposalRootPath,
    /^\.agents\/workflow-code-proposals\/workflow-repo-agent-/,
  );
  assert.equal(
    plan.requestPath,
    `${plan.proposalRootPath}/request.json`,
  );
  assert.equal(
    plan.receiptPath,
    `${plan.proposalRootPath}/receipts/workflow-code-generation-receipt.json`,
  );
  assert.equal(
    plan.applyReceiptPath,
    `${plan.proposalRootPath}/receipts/apply-blocked.json`,
  );

  const requestFile = plan.files.find((file) => file.path === plan.requestPath);
  const proposalFile = plan.files.find((file) => file.path === plan.proposalPath);
  const diffFile = plan.files.find((file) => file.path === plan.diffPath);
  const receiptFile = plan.files.find((file) => file.path === plan.receiptPath);
  const approvalReceiptFile = plan.files.find(
    (file) => file.path === plan.approvalReceiptPath,
  );
  const applyReceiptFile = plan.files.find(
    (file) => file.path === plan.applyReceiptPath,
  );
  const checkReceiptFile = plan.files.find(
    (file) => file.path === plan.checkReceiptPath,
  );
  const evalReceiptFile = plan.files.find(
    (file) => file.path === plan.evalReceiptPath,
  );
  assert.ok(requestFile);
  assert.ok(proposalFile);
  assert.ok(diffFile);
  assert.ok(receiptFile);
  assert.ok(approvalReceiptFile);
  assert.ok(applyReceiptFile);
  assert.ok(checkReceiptFile);
  assert.ok(evalReceiptFile);

  const request = JSON.parse(requestFile.content);
  const receipt = JSON.parse(receiptFile.content);
  const approvalReceipt = JSON.parse(approvalReceiptFile.content);
  const applyReceipt = JSON.parse(applyReceiptFile.content);
  const checkReceipt = JSON.parse(checkReceiptFile.content);
  const evalReceipt = JSON.parse(evalReceiptFile.content);
  assert.equal(request.runtimeTruthSource, "daemon-runtime");
  assert.equal(request.projectionOwner, "openvscode-workbench-adapter");
  assert.equal(request.ownsRuntimeState, false);
  assert.equal(request.proposalOnly, true);
  assert.equal(receipt.status, "proposed");
  assert.deepEqual(receipt.changedFiles, []);
  assert.deepEqual(applyReceipt.changedFiles, []);
  assert.equal(approvalReceipt.status, "approval_required");
  assert.equal(applyReceipt.status, "blocked");
  assert.equal(checkReceipt.status, "blocked");
  assert.equal(evalReceipt.status, "blocked");
  assert.equal(applyReceipt.ownsRuntimeState, false);
  assert.equal(checkReceipt.runtimeTruthSource, "daemon-runtime");
  assert.equal(evalReceipt.projectionOwner, "openvscode-workbench-adapter");
  assert.deepEqual(receipt.applyReceiptRefs, [applyReceipt.receiptId]);
  assert.deepEqual(receipt.evalReceiptRefs, [evalReceipt.receiptId]);
  assert.match(
    diffFile.content,
    /Target source files are unchanged until IOI runtime settles an approved patch/,
  );
  assert.match(proposalFile.content, /proposal artifact only/i);
  assert.doesNotMatch(JSON.stringify(receipt), /OpenAI|Anthropic|provider/i);
});
