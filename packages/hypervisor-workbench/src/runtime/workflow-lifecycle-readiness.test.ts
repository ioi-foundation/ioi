import assert from "node:assert/strict";
import test from "node:test";
import type { Node, WorkflowProject, WorkflowTestCase } from "../types/graph";
import {
  AUTONOMOUS_SYSTEM_MANIFEST_SCHEMA_VERSION,
  WORKFLOW_LIFECYCLE_LOOP,
  WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION,
  autonomousSystemManifestFromWorkflow,
  workflowLifecycleReadinessProjection,
} from "./workflow-lifecycle-readiness";
import { validateWorkflowProject } from "./workflow-validation";

const modelNode = (overrides: Partial<Node> = {}): Node =>
  ({
    id: "model",
    type: "model_call",
    name: "Plan safe repo change",
    x: 320,
    y: 0,
    config: {
      logic: {
        modelRef: "reasoning",
      },
    },
    ...overrides,
  }) as Node;

const toolNode = (overrides: Partial<Node> = {}): Node =>
  ({
    id: "proposal-tool",
    type: "plugin_tool",
    name: "Create patch proposal",
    x: 640,
    y: 0,
    config: {
      logic: {
        toolBinding: {
          bindingKind: "coding_tool_pack",
          toolRef: "file.apply_patch",
          toolCapabilityRef: "tool-capability:file.apply_patch",
          mockBinding: false,
          credentialReady: true,
          credentialReadiness: { status: "ready" },
          grantReadiness: { status: "ready" },
          policyPosture: { status: "allowed" },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          receiptBehavior: {
            receiptRequired: true,
            requiredReceiptTypes: ["proposal", "approval", "apply"],
          },
          primitiveCapabilities: ["prim:fs.write"],
          authorityScopeRequirements: ["scope:workspace.write"],
          authorityScopes: ["scope:workspace.write"],
          sideEffectClass: "write",
          requiresApproval: true,
        },
      },
      law: {
        requireHumanGate: true,
      },
    },
    ...overrides,
  }) as Node;

const workflow = (overrides: Partial<WorkflowProject> = {}): WorkflowProject =>
  ({
    version: "workflow.v1",
    metadata: {
      id: "repo-maintenance",
      name: "Repo maintenance",
      slug: "repo-maintenance",
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: ".agents/workflows/repo-maintenance.workflow.json",
      autonomousSystemPackage: {
        systemId: "system://repo-maintenance",
        manifestId: "ai://autonomous-system/repo-maintenance",
        workerRef: "worker://repo-maintenance",
        displayName: "Repo maintenance",
        responsibility: "Inspect, propose, approve, and apply safe repo changes.",
        promotionProfileRef: "profile://promotion/repo-maintenance",
      },
    },
    nodes: [
      {
        id: "trigger",
        type: "trigger",
        name: "Manual task",
        x: 0,
        y: 0,
        config: { logic: { triggerKind: "manual" } },
      },
      modelNode(),
      toolNode(),
      {
        id: "approval",
        type: "human_gate",
        name: "Approve patch",
        x: 960,
        y: 0,
        config: { logic: {} },
      },
      {
        id: "output",
        type: "output",
        name: "Receipts",
        x: 1280,
        y: 0,
        config: { logic: {} },
      },
    ],
    edges: [
      {
        id: "trigger-model",
        from: "trigger",
        to: "model",
        fromPort: "output",
        toPort: "input",
        type: "data",
      },
      {
        id: "model-tool",
        from: "model",
        to: "proposal-tool",
        fromPort: "output",
        toPort: "input",
        type: "data",
      },
      {
        id: "approval-tool",
        from: "approval",
        to: "proposal-tool",
        fromPort: "output",
        toPort: "input",
        type: "control",
      },
      {
        id: "tool-output",
        from: "proposal-tool",
        to: "output",
        fromPort: "output",
        toPort: "input",
        type: "data",
      },
    ],
    global_config: {
      env: "test",
      environmentProfile: {
        target: "local",
        credentialScope: "local",
        mockBindingPolicy: "block",
      },
      modelBindings: {
        reasoning: {
          modelId: "local-fixture",
          modelCapabilityRef: "model-capability:route.local-first",
          routeId: "route.local-first",
          mockBinding: false,
          credentialReadiness: { status: "ready" },
          grantReadiness: { status: "ready" },
          policyPosture: { status: "allowed" },
          workflowAvailability: { available: true },
          agentAvailability: { available: true },
          receiptBehavior: {
            receiptRequired: true,
            requiredReceiptTypes: ["model_route_selection", "model_invocation"],
          },
          authorityScopeRequirements: ["scope:model.invoke.local"],
          authorityScopes: ["scope:model.invoke.local"],
        },
      },
      requiredCapabilities: {},
      policy: { maxBudget: 5, maxSteps: 10, timeoutMs: 30_000 },
      contract: { developerBond: 0, adjudicationRubric: "fixture" },
      meta: {
        name: "Repo maintenance",
        description: "Safe proposal-first repo maintenance package.",
      },
      production: {
        evaluationSetPath: "internal-docs/examples/repo-maintenance/evals",
        expectedTimeSavedMinutes: 12,
        mcpAccessReviewed: true,
      },
    },
    tests: [testCase],
    ...overrides,
  }) as WorkflowProject;

const testCase: WorkflowTestCase = {
  id: "propose-safe-doc-fix",
  name: "Propose safe doc fix",
  targetNodeIds: ["output"],
  assertion: {
    kind: "node_exists",
    expected: "output",
  },
};

test("workflow lifecycle readiness projects old workflows into draft packages", () => {
  const legacyWorkflow = workflow({
    metadata: {
      ...workflow().metadata,
      autonomousSystemPackage: undefined,
    } as unknown as WorkflowProject["metadata"],
  });

  const projection = workflowLifecycleReadinessProjection({
    workflow: legacyWorkflow,
    tests: [testCase],
    validationResult: validateWorkflowProject(legacyWorkflow, [testCase]),
  });

  assert.equal(
    projection.schemaVersion,
    WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION,
  );
  assert.equal(projection.packageArtifact, "Autonomous System Package");
  assert.deepEqual(projection.lifecycleLoop, WORKFLOW_LIFECYCLE_LOOP);
  assert.equal(projection.compatibility.projectedFromLegacyWorkflow, true);
  assert.equal(projection.manifest.schemaVersion, AUTONOMOUS_SYSTEM_MANIFEST_SCHEMA_VERSION);
  assert.equal(projection.manifest.systemId, "system://repo-maintenance");
});

test("workflow lifecycle readiness separates run, authority, package, evaluation, deployment, and promotion", () => {
  const project = workflow();
  const projection = workflowLifecycleReadinessProjection({
    workflow: project,
    tests: [testCase],
    validationResult: validateWorkflowProject(project, [testCase]),
  });

  assert.deepEqual(
    projection.categories.map((category) => category.kind),
    ["run", "authority", "package", "evaluation", "deployment", "promotion"],
  );
  assert.equal(projection.status, "ready");
  assert.equal(
    projection.categories.find((category) => category.kind === "package")?.status,
    "ready",
  );
  assert.equal(
    projection.categories.find((category) => category.kind === "promotion")?.status,
    "ready",
  );
});

test("workflow lifecycle readiness blocks missing model capability without breaking compatibility", () => {
  const project = workflow({
    global_config: {
      ...workflow().global_config,
      modelBindings: {},
    },
  });
  const projection = workflowLifecycleReadinessProjection({
    workflow: project,
    tests: [testCase],
    validationResult: validateWorkflowProject(project, [testCase]),
  });

  assert.equal(projection.status, "blocked");
  assert.equal(
    projection.categories.find((category) => category.kind === "package")?.blockers.some(
      (blocker) => blocker.code === "package_model_capability_missing",
    ),
    true,
  );
  assert.equal(projection.manifest.status, "runnable");
});

test("workflow lifecycle readiness blocks missing authority, eval, and deployment slots independently", () => {
  const missingAuthority = workflow({
    nodes: [
      ...workflow().nodes.filter((node) => node.id !== "proposal-tool"),
      toolNode({
        config: {
          logic: {
            toolBinding: {
              bindingKind: "coding_tool_pack",
              toolRef: "file.inspect",
              toolCapabilityRef: "tool-capability:file.inspect",
              mockBinding: false,
              credentialReady: false,
              credentialReadiness: { status: "unknown" },
              grantReadiness: { status: "unknown" },
              policyPosture: { status: "unknown" },
              workflowAvailability: { available: false },
              agentAvailability: { available: false },
              receiptBehavior: {
                receiptRequired: true,
                requiredReceiptTypes: ["inspect"],
              },
              capabilityScope: ["file.inspect"],
              sideEffectClass: "read",
              requiresApproval: false,
            },
          },
          law: {},
        },
      }),
    ],
    global_config: {
      ...workflow().global_config,
      environmentProfile: undefined,
      production: {
        expectedTimeSavedMinutes: 12,
      },
    },
    tests: [],
  } as unknown as Partial<WorkflowProject>);

  const projection = workflowLifecycleReadinessProjection({
    workflow: missingAuthority,
    tests: [],
    validationResult: validateWorkflowProject(missingAuthority, []),
  });

  assert.equal(
    projection.categories.find((category) => category.kind === "authority")?.status,
    "blocked",
  );
  assert.equal(
    projection.categories.find((category) => category.kind === "evaluation")?.status,
    "blocked",
  );
  assert.equal(
    projection.categories.find((category) => category.kind === "deployment")?.status,
    "blocked",
  );
});

test("autonomous system manifest includes package contract fields from workflow bindings", () => {
  const manifest = autonomousSystemManifestFromWorkflow(workflow(), {
    tests: [testCase],
  });

  assert.equal(manifest.systemId, "system://repo-maintenance");
  assert.equal(manifest.worker.workerRef, "worker://repo-maintenance");
  assert.deepEqual(manifest.capabilities.modelCapabilityRefs, [
    "model-capability:route.local-first",
  ]);
  assert.deepEqual(manifest.capabilities.toolCapabilityRefs, [
    "tool-capability:file.apply_patch",
  ]);
  assert.deepEqual(manifest.authority.authorityScopeRequirements, [
    "scope:model.invoke.local",
    "scope:workspace.write",
  ]);
  assert.equal(manifest.evaluation.evalProfileRefs.length, 2);
  assert.equal(manifest.runtimeProfiles[0].kind, "local_daemon");
});
