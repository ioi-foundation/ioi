import type {
  GraphGlobalConfig,
  WorkflowExecutionMode,
  WorkflowKind,
  Node,
  WorkflowProject,
  WorkflowProposal,
  WorkflowTestCase,
  WorkflowValidationResult,
} from "../../types/graph";
import { workflowNodeDeclaredOutputSchema } from "../../runtime/workflow-schema";
import {
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowNodeName,
} from "../../runtime/workflow-rail-model";

export function CreateWorkflowModal({
  name,
  projectRoot,
  workflowKind,
  executionMode,
  onNameChange,
  onWorkflowKindChange,
  onExecutionModeChange,
  onClose,
  onCreate,
}: {
  name: string;
  projectRoot: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  onNameChange: (value: string) => void;
  onWorkflowKindChange: (value: WorkflowKind) => void;
  onExecutionModeChange: (value: WorkflowExecutionMode) => void;
  onClose: () => void;
  onCreate: () => void;
}) {
  return (
    <div
      className="workflow-create-backdrop"
      role="presentation"
      data-testid="workflow-create-modal"
    >
      <form
        className="workflow-create-dialog"
        onSubmit={(event) => {
          event.preventDefault();
          onCreate();
        }}
      >
        <header>
          <h3>Create Workflow</h3>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
        </header>
        <label>
          Name
          <input
            data-testid="workflow-create-name"
            value={name}
            onChange={(event) => onNameChange(event.target.value)}
          />
        </label>
        <label>
          Git location
          <input
            data-testid="workflow-create-location"
            value={projectRoot}
            readOnly
          />
        </label>
        <label>
          Starting point
          <div
            className="workflow-create-starting-point"
            data-testid="workflow-scratch-start"
          >
            <button
              type="button"
              className="is-active"
              onClick={() => onNameChange("New blank workflow")}
            >
              Blank canvas
            </button>
          </div>
        </label>
        <p className="workflow-create-summary">
          Create an empty workflow and add nodes from the canvas.
        </p>
        <div className="workflow-create-options">
          {[
            ["agent_workflow", "Agent workflow"],
            ["scheduled_workflow", "Scheduled workflow"],
            ["event_workflow", "Event workflow"],
            ["evaluation_workflow", "Evaluation workflow"],
          ].map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={workflowKind === value ? "is-active" : ""}
              onClick={() => onWorkflowKindChange(value as WorkflowKind)}
              data-testid={`workflow-create-kind-${value}`}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="workflow-create-options">
          {[
            ["local", "Local"],
            ["external_adapter", "External adapter"],
            ["hybrid", "Hybrid"],
          ].map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={executionMode === value ? "is-active" : ""}
              onClick={() =>
                onExecutionModeChange(value as WorkflowExecutionMode)
              }
              data-testid={`workflow-create-mode-${value}`}
            >
              {label}
            </button>
          ))}
        </div>
        <footer>
          <button type="submit" data-testid="workflow-create-submit">
            Create blank workflow
          </button>
        </footer>
      </form>
    </div>
  );
}

export function ImportPackageModal({
  projectRoot,
  packagePath,
  packageName,
  onPackagePathChange,
  onPackageNameChange,
  onClose,
  onImport,
}: {
  projectRoot: string;
  packagePath: string;
  packageName: string;
  onPackagePathChange: (value: string) => void;
  onPackageNameChange: (value: string) => void;
  onClose: () => void;
  onImport: () => void;
}) {
  return (
    <div
      className="workflow-create-backdrop"
      role="presentation"
      data-testid="workflow-import-package-modal"
    >
      <form
        className="workflow-create-dialog"
        onSubmit={(event) => {
          event.preventDefault();
          onImport();
        }}
      >
        <header>
          <h3>Import Workflow Package</h3>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
        </header>
        <label>
          Package directory
          <input
            data-testid="workflow-import-package-path"
            placeholder="/path/to/workflow.portable"
            value={packagePath}
            onChange={(event) => onPackagePathChange(event.target.value)}
          />
        </label>
        <label>
          Workflow name
          <input
            data-testid="workflow-import-package-name"
            placeholder="Keep package name"
            value={packageName}
            onChange={(event) => onPackageNameChange(event.target.value)}
          />
        </label>
        <label>
          Destination
          <input value={projectRoot} readOnly />
        </label>
        <p className="workflow-create-summary">
          Import a portable workflow bundle into this checkout. Run readiness
          after import before activation.
        </p>
        <footer>
          <button type="submit" data-testid="workflow-import-package-submit">
            Import package
          </button>
        </footer>
      </form>
    </div>
  );
}

export function ModelBindingModal({
  globalConfig,
  onClose,
  onUpdate,
}: {
  globalConfig: GraphGlobalConfig;
  onClose: () => void;
  onUpdate: (
    updater: (current: GraphGlobalConfig) => GraphGlobalConfig,
  ) => void;
}) {
  const bindingKeys = ["reasoning", "vision", "embedding", "image"];
  const modelBindings = bindingKeys.map(
    (bindingKey) =>
      [
        bindingKey,
        globalConfig.modelBindings[bindingKey] ?? {
          modelId: "",
          required: false,
        },
      ] as const,
  );
  const requiredCount = modelBindings.filter(
    ([, binding]) => binding.required,
  ).length;
  const boundCount = modelBindings.filter(([, binding]) =>
    String(binding.modelId ?? "").trim(),
  ).length;
  const missingRequiredCount = modelBindings.filter(
    ([, binding]) => binding.required && !String(binding.modelId ?? "").trim(),
  ).length;
  return (
    <div
      className="workflow-create-backdrop"
      role="presentation"
      data-testid="workflow-model-binding-modal"
    >
      <form className="workflow-create-dialog workflow-config-dialog">
        <header>
          <h3>Model bindings</h3>
          <button type="button" onClick={onClose}>
            Close
          </button>
        </header>
        <dl
          className="workflow-binding-summary"
          data-testid="workflow-model-binding-summary"
        >
          <div>
            <dt>Bindings</dt>
            <dd>{modelBindings.length}</dd>
          </div>
          <div>
            <dt>Bound</dt>
            <dd>{boundCount}</dd>
          </div>
          <div>
            <dt>Required</dt>
            <dd>{requiredCount}</dd>
          </div>
          <div>
            <dt>Missing</dt>
            <dd>{missingRequiredCount}</dd>
          </div>
        </dl>
        <div
          className="workflow-binding-list"
          data-testid="workflow-model-binding-list"
        >
          {modelBindings.map(([bindingKey, binding]) => {
            const ready = Boolean(String(binding.modelId ?? "").trim());
            return (
              <section
                key={bindingKey}
                className={`workflow-binding-row is-${ready ? "ready" : binding.required ? "blocked" : "idle"}`}
                data-testid={`workflow-model-binding-row-${bindingKey}`}
              >
                <header>
                  <strong>{bindingKey}</strong>
                  <span>
                    {ready
                      ? "bound"
                      : binding.required
                        ? "required"
                        : "optional"}
                  </span>
                </header>
                <label>
                  Model id
                  <input
                    value={binding.modelId ?? ""}
                    placeholder={`${bindingKey} model id`}
                    onChange={(event) =>
                      onUpdate((current) => ({
                        ...current,
                        modelBindings: {
                          ...current.modelBindings,
                          [bindingKey]: {
                            ...(current.modelBindings[bindingKey] ?? {
                              required: false,
                            }),
                            modelId: event.target.value,
                          },
                        },
                      }))
                    }
                  />
                </label>
                <label className="workflow-binding-checkbox">
                  <input
                    type="checkbox"
                    data-testid={`workflow-model-binding-required-${bindingKey}`}
                    checked={Boolean(binding.required)}
                    onChange={(event) =>
                      onUpdate((current) => ({
                        ...current,
                        modelBindings: {
                          ...current.modelBindings,
                          [bindingKey]: {
                            ...(current.modelBindings[bindingKey] ?? {
                              modelId: "",
                            }),
                            required: event.target.checked,
                          },
                        },
                      }))
                    }
                  />
                  Required for activation
                </label>
              </section>
            );
          })}
        </div>
        <footer>
          <button type="button" onClick={onClose}>
            Done
          </button>
        </footer>
      </form>
    </div>
  );
}

export function ConnectorBindingModal({
  workflow,
  onClose,
  onInspectNode,
  onOpenNodeLibrary,
}: {
  workflow: WorkflowProject;
  onClose: () => void;
  onInspectNode: (nodeId: string) => void;
  onOpenNodeLibrary: () => void;
}) {
  const connectorNodes = workflow.nodes.filter(
    (nodeItem) =>
      nodeItem.type === "adapter" || nodeItem.type === "plugin_tool",
  );
  const bindingRows = connectorNodes.map((nodeItem) => {
    const connectorBinding = nodeItem.config?.logic.connectorBinding;
    const toolBinding = nodeItem.config?.logic.toolBinding;
    const ref = String(
      connectorBinding?.connectorRef ?? toolBinding?.toolRef ?? "",
    );
    const mockBinding = Boolean(
      connectorBinding?.mockBinding ?? toolBinding?.mockBinding,
    );
    const credentialReady =
      toolBinding?.bindingKind === "workflow_tool"
        ? true
        : Boolean(
            connectorBinding?.credentialReady ?? toolBinding?.credentialReady,
          );
    const requiresApproval = Boolean(
      connectorBinding?.requiresApproval ?? toolBinding?.requiresApproval,
    );
    const sideEffectClass = String(
      connectorBinding?.sideEffectClass ??
        toolBinding?.sideEffectClass ??
        "read",
    );
    return {
      nodeItem,
      ref,
      mockBinding,
      credentialReady,
      requiresApproval,
      sideEffectClass,
      ready: ref.trim().length > 0,
      bindingKind: connectorBinding
        ? "connector"
        : String(toolBinding?.bindingKind ?? "plugin_tool"),
    };
  });
  const readyCount = bindingRows.filter((row) => row.ready).length;
  const mockCount = bindingRows.filter((row) => row.mockBinding).length;
  const credentialReadyCount = bindingRows.filter(
    (row) => row.credentialReady,
  ).length;
  return (
    <div
      className="workflow-create-backdrop"
      role="presentation"
      data-testid="workflow-connector-binding-modal"
    >
      <div className="workflow-create-dialog workflow-config-dialog">
        <header>
          <h3>Connectors and plugins</h3>
          <button type="button" onClick={onClose}>
            Close
          </button>
        </header>
        <dl
          className="workflow-binding-summary"
          data-testid="workflow-connector-binding-summary"
        >
          <div>
            <dt>Nodes</dt>
            <dd>{connectorNodes.length}</dd>
          </div>
          <div>
            <dt>Bound</dt>
            <dd>{readyCount}</dd>
          </div>
          <div>
            <dt>Mock</dt>
            <dd>{mockCount}</dd>
          </div>
          <div>
            <dt>Credentials</dt>
            <dd>{credentialReadyCount}</dd>
          </div>
        </dl>
        {connectorNodes.length === 0 ? (
          <p>No connector or plugin nodes in this workflow.</p>
        ) : (
          <div
            className="workflow-binding-list"
            data-testid="workflow-connector-binding-list"
          >
            {bindingRows.map((row) => (
              <article
                key={row.nodeItem.id}
                className={`workflow-binding-row is-${row.ready ? (row.mockBinding ? "warning" : "ready") : "blocked"}`}
                data-testid={`workflow-connector-binding-row-${row.nodeItem.id}`}
              >
                <header>
                  <strong>{row.nodeItem.name}</strong>
                  <span>{row.ready ? row.ref : "unbound"}</span>
                </header>
                <dl>
                  <div>
                    <dt>Kind</dt>
                    <dd>{row.bindingKind}</dd>
                  </div>
                  <div>
                    <dt>Mode</dt>
                    <dd>{row.mockBinding ? "mock" : "live"}</dd>
                  </div>
                  <div>
                    <dt>Side effect</dt>
                    <dd>{row.sideEffectClass}</dd>
                  </div>
                  <div>
                    <dt>Credentials</dt>
                    <dd>
                      {row.credentialReady
                        ? "ready"
                        : row.mockBinding
                          ? "mock"
                          : "missing"}
                    </dd>
                  </div>
                  <div>
                    <dt>Approval</dt>
                    <dd>
                      {row.requiresApproval ? "required" : "not required"}
                    </dd>
                  </div>
                </dl>
                <button
                  type="button"
                  onClick={() => onInspectNode(row.nodeItem.id)}
                >
                  Configure node
                </button>
              </article>
            ))}
          </div>
        )}
        <footer>
          <button type="button" onClick={onOpenNodeLibrary}>
            Add connector node
          </button>
          <button type="button" onClick={onClose}>
            Done
          </button>
        </footer>
      </div>
    </div>
  );
}

export function TestEditorModal({
  workflow,
  existingTests,
  name,
  targets,
  selectedNode,
  kind,
  expected,
  expression,
  onNameChange,
  onTargetsChange,
  onKindChange,
  onExpectedChange,
  onExpressionChange,
  onClose,
  onSubmit,
}: {
  workflow: WorkflowProject;
  existingTests: WorkflowTestCase[];
  name: string;
  targets: string;
  selectedNode: Node | null;
  kind: WorkflowTestCase["assertion"]["kind"];
  expected: string;
  expression: string;
  onNameChange: (value: string) => void;
  onTargetsChange: (value: string) => void;
  onKindChange: (value: WorkflowTestCase["assertion"]["kind"]) => void;
  onExpectedChange: (value: string) => void;
  onExpressionChange: (value: string) => void;
  onClose: () => void;
  onSubmit: () => void;
}) {
  const targetIds = (targets || selectedNode?.id || "")
    .split(",")
    .map((target) => target.trim())
    .filter(Boolean);
  const targetNodes = targetIds
    .map(
      (targetId) =>
        workflow.nodes.find((nodeItem) => nodeItem.id === targetId) ?? null,
    )
    .filter((nodeItem): nodeItem is Node => Boolean(nodeItem));
  const coveredByExistingTests = existingTests.filter((test) =>
    targetIds.some((targetId) => test.targetNodeIds.includes(targetId)),
  );
  const selectedNodeSchema = selectedNode
    ? workflowNodeDeclaredOutputSchema(selectedNode)
    : null;
  const assertionGuidance =
    kind === "schema_matches"
      ? "Provide a JSON schema that the selected node output must satisfy."
      : kind === "output_contains"
        ? "Provide text or JSON that should be present in the selected node output."
        : kind === "custom"
          ? "Write a sandboxed expression that returns true for passing input."
          : "Confirm that every target node still exists in this workflow.";
  return (
    <div
      className="workflow-create-backdrop"
      role="presentation"
      data-testid="workflow-test-editor-modal"
    >
      <form
        className="workflow-create-dialog workflow-config-dialog"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <header>
          <h3>Unit test</h3>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
        </header>
        <dl
          className="workflow-test-editor-summary"
          data-testid="workflow-test-editor-summary"
        >
          <div>
            <dt>Targets</dt>
            <dd>{targetIds.length}</dd>
          </div>
          <div>
            <dt>Covered</dt>
            <dd>{coveredByExistingTests.length}</dd>
          </div>
          <div>
            <dt>Assertion</dt>
            <dd>{kind}</dd>
          </div>
          <div>
            <dt>Schema</dt>
            <dd>{selectedNodeSchema ? "available" : "none"}</dd>
          </div>
        </dl>
        <section
          className="workflow-test-target-summary"
          data-testid="workflow-test-target-summary"
        >
          <h4>Targets</h4>
          {targetNodes.length > 0 ? (
            targetNodes.map((nodeItem) => (
              <article key={nodeItem.id} className="workflow-test-target-row">
                <strong>{nodeItem.name}</strong>
                <span>
                  {nodeItem.type} · {nodeItem.id}
                </span>
              </article>
            ))
          ) : (
            <p>Select a node or enter one or more target node ids.</p>
          )}
        </section>
        <label>
          Name
          <input
            data-testid="workflow-test-name"
            value={name}
            onChange={(event) => onNameChange(event.target.value)}
          />
        </label>
        <label>
          Target node ids
          <input
            data-testid="workflow-test-targets"
            value={targets || selectedNode?.id || ""}
            onChange={(event) => onTargetsChange(event.target.value)}
            placeholder="node-a, node-b"
          />
        </label>
        <label>
          Assertion
          <select
            data-testid="workflow-test-assertion-kind"
            value={kind}
            onChange={(event) =>
              onKindChange(
                event.target.value as WorkflowTestCase["assertion"]["kind"],
              )
            }
          >
            <option value="node_exists">Node exists</option>
            <option value="schema_matches">Output matches schema</option>
            <option value="output_contains">Output contains value</option>
            <option value="custom">Custom sandbox assertion</option>
          </select>
        </label>
        <p
          className="workflow-test-assertion-guidance"
          data-testid="workflow-test-assertion-guidance"
        >
          {assertionGuidance}
        </p>
        {kind === "schema_matches" || kind === "output_contains" ? (
          <label>
            Expected value
            <textarea
              data-testid="workflow-test-expected"
              value={expected}
              onChange={(event) => onExpectedChange(event.target.value)}
              placeholder={
                kind === "schema_matches"
                  ? '{"type":"object","required":["result"]}'
                  : "expected text or JSON"
              }
            />
          </label>
        ) : null}
        {kind === "custom" ? (
          <label>
            Expression
            <textarea
              data-testid="workflow-test-expression"
              value={expression}
              onChange={(event) => onExpressionChange(event.target.value)}
              placeholder="return input.value.result?.status === 'ok';"
            />
          </label>
        ) : null}
        {selectedNodeSchema ? (
          <section
            className="workflow-test-schema-preview"
            data-testid="workflow-test-schema-preview"
          >
            <h4>Selected node output schema</h4>
            <pre>{JSON.stringify(selectedNodeSchema, null, 2)}</pre>
          </section>
        ) : null}
        <footer>
          <button type="submit" data-testid="workflow-test-submit">
            Add test
          </button>
        </footer>
      </form>
    </div>
  );
}

export function ProposalPreviewModal({
  proposal,
  onClose,
  onApply,
}: {
  proposal: WorkflowProposal;
  onClose: () => void;
  onApply: () => void;
}) {
  const graphDiff = proposal.graphDiff ?? {};
  const configDiff = proposal.configDiff ?? {};
  const sidecarDiff = proposal.sidecarDiff ?? {};
  const graphChanged =
    (graphDiff.addedNodeIds?.length ?? 0) +
    (graphDiff.removedNodeIds?.length ?? 0) +
    (graphDiff.changedNodeIds?.length ?? 0);
  const configChanged =
    (configDiff.changedNodeIds?.length ?? 0) +
    (configDiff.changedGlobalKeys?.length ?? 0) +
    (configDiff.changedMetadataKeys?.length ?? 0);
  const sidecarRoles = sidecarDiff.changedRoles ?? [];
  const proposalBoundsIssues = workflowProposalBoundsIssues(proposal);
  const applyBlocked =
    proposal.status !== "open" || proposalBoundsIssues.length > 0;
  return (
    <div className="workflow-create-backdrop" role="presentation">
      <div className="workflow-create-dialog workflow-config-dialog workflow-proposal-preview-dialog">
        <header>
          <h3>Proposal preview</h3>
          <button type="button" onClick={onClose}>
            Close
          </button>
        </header>
        <article className="workflow-output-row workflow-proposal-review-summary">
          <strong>{proposal.title}</strong>
          <span>{proposal.summary}</span>
          <dl data-testid="workflow-proposal-review-summary">
            <div>
              <dt>Graph</dt>
              <dd>{graphChanged}</dd>
            </div>
            <div>
              <dt>Config</dt>
              <dd>{configChanged}</dd>
            </div>
            <div>
              <dt>Sidecars</dt>
              <dd>{sidecarRoles.length}</dd>
            </div>
            <div>
              <dt>Bounds</dt>
              <dd>
                {proposalBoundsIssues.length === 0
                  ? "ready"
                  : `${proposalBoundsIssues.length} issue${proposalBoundsIssues.length === 1 ? "" : "s"}`}
              </dd>
            </div>
          </dl>
        </article>
        <dl>
          <dt>Bounded targets</dt>
          <dd>{proposal.boundedTargets.join(", ") || "None"}</dd>
          <dt>Status</dt>
          <dd>{proposal.status}</dd>
        </dl>
        <section
          className="workflow-proposal-section"
          data-testid="workflow-proposal-bounds-check"
        >
          <h4>Bounds check</h4>
          {proposalBoundsIssues.length === 0 ? (
            <p>Patch changes are inside the declared proposal bounds.</p>
          ) : (
            <ul>
              {proposalBoundsIssues.map((issue) => (
                <li key={issue}>{issue}</li>
              ))}
            </ul>
          )}
        </section>
        <section
          className="workflow-proposal-section"
          data-testid="workflow-proposal-graph-diff"
        >
          <h4>Graph changes</h4>
          {graphChanged > 0 ? (
            <dl>
              <dt>Added nodes</dt>
              <dd>{graphDiff.addedNodeIds?.join(", ") || "None"}</dd>
              <dt>Removed nodes</dt>
              <dd>{graphDiff.removedNodeIds?.join(", ") || "None"}</dd>
              <dt>Changed nodes</dt>
              <dd>{graphDiff.changedNodeIds?.join(", ") || "None"}</dd>
            </dl>
          ) : (
            <p>No graph changes declared.</p>
          )}
        </section>
        <section
          className="workflow-proposal-section"
          data-testid="workflow-proposal-config-diff"
        >
          <h4>Configuration changes</h4>
          {configChanged > 0 ? (
            <dl>
              <dt>Nodes</dt>
              <dd>{configDiff.changedNodeIds?.join(", ") || "None"}</dd>
              <dt>Workflow settings</dt>
              <dd>{configDiff.changedGlobalKeys?.join(", ") || "None"}</dd>
              <dt>Metadata</dt>
              <dd>{configDiff.changedMetadataKeys?.join(", ") || "None"}</dd>
            </dl>
          ) : (
            <p>No configuration changes declared.</p>
          )}
        </section>
        <section
          className="workflow-proposal-section"
          data-testid="workflow-proposal-sidecar-diff"
        >
          <h4>Sidecar changes</h4>
          {sidecarRoles.length > 0 ? (
            <dl>
              <dt>Changed roles</dt>
              <dd>{sidecarRoles.join(", ")}</dd>
              <dt>Functions</dt>
              <dd>{sidecarDiff.functionsChanged ? "Changed" : "Unchanged"}</dd>
              <dt>Tests</dt>
              <dd>{sidecarDiff.testsChanged ? "Changed" : "Unchanged"}</dd>
              <dt>Bindings</dt>
              <dd>{sidecarDiff.bindingsChanged ? "Changed" : "Unchanged"}</dd>
            </dl>
          ) : (
            <p>No sidecar changes declared.</p>
          )}
        </section>
        {proposal.codeDiff ? (
          <section
            className="workflow-proposal-section"
            data-testid="workflow-proposal-code-diff"
          >
            <h4>Code or function diff</h4>
            <pre>{proposal.codeDiff}</pre>
          </section>
        ) : null}
        {proposal.workflowPatch ? (
          <section
            className="workflow-proposal-section"
            data-testid="workflow-proposal-patch-preview"
          >
            <h4>Patch preview</h4>
            <pre>
              {JSON.stringify(
                {
                  nodes: proposal.workflowPatch.nodes.length,
                  edges: proposal.workflowPatch.edges.length,
                  workflow: proposal.workflowPatch.metadata.name,
                },
                null,
                2,
              )}
            </pre>
          </section>
        ) : null}
        <footer className="workflow-proposal-preview-footer">
          <span data-testid="workflow-proposal-apply-status">
            {applyBlocked
              ? "Apply is blocked until the proposal is open and all changes are inside bounds."
              : "Ready to apply declared bounded changes."}
          </span>
          <button
            type="button"
            data-testid="workflow-proposal-apply"
            onClick={onApply}
            disabled={applyBlocked}
          >
            Apply proposal
          </button>
        </footer>
      </div>
    </div>
  );
}

function workflowProposalBoundsIssues(proposal: WorkflowProposal): string[] {
  const bounds = new Set(proposal.boundedTargets);
  const graphWideBound = bounds.has("workflow") || bounds.has("graph");
  const changedNodeIds = new Set([
    ...(proposal.graphDiff?.addedNodeIds ?? []),
    ...(proposal.graphDiff?.removedNodeIds ?? []),
    ...(proposal.graphDiff?.changedNodeIds ?? []),
    ...(proposal.configDiff?.changedNodeIds ?? []),
  ]);
  const issues = Array.from(changedNodeIds)
    .filter((nodeId) => !graphWideBound && !bounds.has(nodeId))
    .map((nodeId) => `Node '${nodeId}' is changed but not included in bounds.`);
  if (
    (proposal.configDiff?.changedGlobalKeys?.length ?? 0) > 0 &&
    !bounds.has("workflow") &&
    !bounds.has("workflow-config") &&
    !bounds.has("global-config")
  ) {
    issues.push("Workflow settings changed but workflow-config is not included in bounds.");
  }
  if (
    (proposal.configDiff?.changedMetadataKeys?.length ?? 0) > 0 &&
    !bounds.has("workflow") &&
    !bounds.has("workflow-metadata") &&
    !bounds.has("metadata")
  ) {
    issues.push("Workflow metadata changed but workflow-metadata is not included in bounds.");
  }
  return issues;
}

export function DeployModal({
  workflow,
  validationResult,
  readinessResult,
  onCheckReadiness,
  onInspectNode,
  onClose,
  onDeploy,
}: {
  workflow: WorkflowProject;
  validationResult: WorkflowValidationResult | null;
  readinessResult: WorkflowValidationResult | null;
  onCheckReadiness: () => void;
  onInspectNode: (nodeId: string) => void;
  onClose: () => void;
  onDeploy: () => void;
}) {
  const readinessIssues = readinessResult
    ? [
        ...readinessResult.errors,
        ...(readinessResult.executionReadinessIssues ?? []),
        ...readinessResult.missingConfig,
        ...readinessResult.connectorBindingIssues,
        ...(readinessResult.verificationIssues ?? []),
      ]
    : [];
  const readinessWarnings = readinessResult?.warnings ?? [];
  const readinessChecklist = [
    { label: "Readiness checked", ready: Boolean(readinessResult) },
    {
      label: "No activation blockers",
      ready: readinessResult?.status === "passed",
    },
    {
      label: "Outputs defined",
      ready: !readinessIssues.some(
        (issue) => issue.code === "missing_output_node",
      ),
    },
    {
      label: "Tests present",
      ready: !readinessIssues.some(
        (issue) => issue.code === "missing_unit_tests",
      ),
    },
    {
      label: "Live bindings ready",
      ready: !readinessIssues.some(
        (issue) => issue.code === "mock_binding_active",
      ),
    },
  ];
  const policyRequiredNodeIds = readinessResult?.policyRequiredNodes ?? [];
  const blocked = readinessResult?.status !== "passed";
  return (
    <div className="workflow-create-backdrop" role="presentation">
      <div className="workflow-create-dialog workflow-config-dialog">
        <header>
          <h3>Activate workflow</h3>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
        </header>
        <p>
          {readinessResult
            ? `Readiness: ${readinessResult.status}`
            : validationResult
              ? `Last validation: ${validationResult.status}. Check readiness before activation.`
              : "Check readiness before activation to see blockers and warnings."}
        </p>
        <section
          className="workflow-activation-summary"
          data-testid="workflow-activation-readiness"
        >
          <dl
            className="workflow-activation-stats"
            data-testid="workflow-activation-summary-stats"
          >
            <div>
              <dt>Status</dt>
              <dd>{readinessResult?.status ?? "not checked"}</dd>
            </div>
            <div>
              <dt>Checks</dt>
              <dd>
                {readinessChecklist.filter((item) => item.ready).length}/
                {readinessChecklist.length}
              </dd>
            </div>
            <div>
              <dt>Blockers</dt>
              <dd>{readinessIssues.length}</dd>
            </div>
            <div>
              <dt>Warnings</dt>
              <dd>{readinessWarnings.length}</dd>
            </div>
          </dl>
          <div
            className="workflow-activation-checklist"
            data-testid="workflow-activation-checklist"
          >
            {readinessChecklist.map((item) => (
              <article
                key={item.label}
                className={`workflow-test-row is-${item.ready ? "passed" : "blocked"}`}
              >
                <strong>{item.label}</strong>
                <span>{item.ready ? "ready" : "needs attention"}</span>
              </article>
            ))}
          </div>
          {readinessIssues.length === 0 ? (
            <article
              className={`workflow-test-row is-${readinessResult?.status === "passed" ? "passed" : "idle"}`}
            >
              <strong>
                {readinessResult?.status === "passed"
                  ? "Ready to activate"
                  : "Readiness not checked"}
              </strong>
              <span>
                {readinessResult?.status === "passed"
                  ? "All operational checks passed."
                  : "Run readiness before saving an activation checkpoint."}
              </span>
            </article>
          ) : (
            <section
              className="workflow-activation-blockers"
              data-testid="workflow-activation-blockers"
            >
              {readinessIssues.slice(0, 8).map((issue, index) =>
                issue.nodeId ? (
                  <button
                    key={`${issue.code}-${issue.nodeId}-${index}`}
                    type="button"
                    className="workflow-search-result is-blocked"
                    data-testid={`workflow-activation-blocker-${index}`}
                    onClick={() => onInspectNode(issue.nodeId!)}
                  >
                    <strong>{workflowNodeName(workflow, issue.nodeId)}</strong>
                    <span>{issue.message}</span>
                    <small>{workflowIssueTitle(issue)}</small>
                    <small>{workflowIssueActionLabel(issue)}</small>
                  </button>
                ) : (
                  <article
                    key={`${issue.code}-workflow-${index}`}
                    className="workflow-output-row is-blocked"
                    data-testid={`workflow-activation-blocker-${index}`}
                  >
                    <strong>{workflowIssueTitle(issue)}</strong>
                    <span>{issue.message}</span>
                    <small>{workflowIssueActionLabel(issue)}</small>
                  </article>
                ),
              )}
            </section>
          )}
          {policyRequiredNodeIds.length > 0 ? (
            <section
              className="workflow-activation-policy-nodes"
              data-testid="workflow-activation-policy-nodes"
            >
              <h4>Approval-sensitive nodes</h4>
              {policyRequiredNodeIds.map((nodeId) => (
                <button
                  key={nodeId}
                  type="button"
                  className="workflow-search-result is-warning"
                  onClick={() => onInspectNode(nodeId)}
                >
                  <strong>{workflowNodeName(workflow, nodeId)}</strong>
                  <span>
                    Activation requires an explicit approval path for this node.
                  </span>
                </button>
              ))}
            </section>
          ) : null}
          {readinessWarnings.length > 0 ? (
            <section
              className="workflow-activation-warnings"
              data-testid="workflow-activation-warnings"
            >
              <h4>Warnings</h4>
              {readinessWarnings.slice(0, 5).map((issue, index) => (
                <article
                  key={`${issue.code}-${index}`}
                  className="workflow-output-row is-warning"
                >
                  <strong>
                    {issue.nodeId
                      ? workflowNodeName(workflow, issue.nodeId)
                      : "Workflow"}
                  </strong>
                  <span>{issue.message}</span>
                  <small>{workflowIssueTitle(issue)}</small>
                </article>
              ))}
            </section>
          ) : null}
        </section>
        <footer>
          <button
            type="button"
            data-testid="workflow-check-readiness"
            onClick={onCheckReadiness}
          >
            Check readiness
          </button>
          <button
            type="button"
            data-testid="workflow-activate-submit"
            disabled={blocked}
            onClick={onDeploy}
          >
            Save activation checkpoint
          </button>
        </footer>
      </div>
    </div>
  );
}
