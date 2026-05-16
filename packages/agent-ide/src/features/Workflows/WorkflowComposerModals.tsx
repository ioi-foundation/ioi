import { useState } from "react";
import type {
  GraphGlobalConfig,
  WorkflowExecutionMode,
  WorkflowKind,
  Node,
  WorkflowConnectorBinding,
  WorkflowProject,
  WorkflowProposal,
  WorkflowTestCase,
  WorkflowToolBinding,
  WorkflowValidationResult,
} from "../../types/graph";
import { workflowNodeDeclaredOutputSchema } from "../../runtime/workflow-schema";
import {
  MODEL_AUTHORITY_BINDING_ENDPOINT,
  MODEL_CAPABILITY_BINDING_ENDPOINT,
  WORKFLOW_MODEL_BINDING_KEYS,
  normalizeGraphModelBinding,
  workflowModelBindingIsReady,
} from "../../runtime/workflow-model-capability-binding";
import {
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingIsReady,
  workflowToolBindingIsReady,
} from "../../runtime/workflow-tool-connector-capability-binding";
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
  const modelBindings = WORKFLOW_MODEL_BINDING_KEYS.map(
    (bindingKey) =>
      [
        bindingKey,
        normalizeGraphModelBinding(bindingKey, globalConfig.modelBindings[bindingKey]),
      ] as const,
  );
  const requiredCount = modelBindings.filter(
    ([, binding]) => binding.required,
  ).length;
  const boundCount = modelBindings.filter(([, binding]) =>
    workflowModelBindingIsReady(binding),
  ).length;
  const missingRequiredCount = modelBindings.filter(
    ([, binding]) => binding.required && !workflowModelBindingIsReady(binding),
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
            const ready = workflowModelBindingIsReady(binding);
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
                <p className="workflow-create-summary">
                  Bind through {MODEL_CAPABILITY_BINDING_ENDPOINT} or{" "}
                  {MODEL_AUTHORITY_BINDING_ENDPOINT}; legacy model ids are
                  projected into capability refs for compatibility.
                </p>
                <label>
                  Model capability ref
                  <input
                    data-testid={`workflow-model-binding-capability-ref-${bindingKey}`}
                    value={binding.modelCapabilityRef ?? ""}
                    placeholder="model-capability:route.local-first"
                    onChange={(event) =>
                      onUpdate((current) => ({
                        ...current,
                        modelBindings: {
                          ...current.modelBindings,
                          [bindingKey]: {
                            ...normalizeGraphModelBinding(
                              bindingKey,
                              current.modelBindings[bindingKey],
                            ),
                            modelCapabilityRef: event.target.value,
                          },
                        },
                      }))
                    }
                  />
                </label>
                <label>
                  Route id
                  <input
                    data-testid={`workflow-model-binding-route-id-${bindingKey}`}
                    value={binding.routeId ?? ""}
                    placeholder="route.local-first"
                    onChange={(event) =>
                      onUpdate((current) => ({
                        ...current,
                        modelBindings: {
                          ...current.modelBindings,
                          [bindingKey]: normalizeGraphModelBinding(bindingKey, {
                            ...current.modelBindings[bindingKey],
                            routeId: event.target.value,
                            modelCapabilityRef: `model-capability:${event.target.value || "route.local-first"}`,
                          }),
                        },
                      }))
                    }
                  />
                </label>
                <label>
                  Authority scopes
                  <input
                    data-testid={`workflow-model-binding-authority-scopes-${bindingKey}`}
                    value={(binding.authorityScopes ?? binding.authorityScopeRequirements ?? []).join(", ")}
                    placeholder="route.use:route.local-first, model.chat:*"
                    onChange={(event) => {
                      const authorityScopes = event.target.value
                        .split(",")
                        .map((value) => value.trim())
                        .filter(Boolean);
                      onUpdate((current) => ({
                        ...current,
                        modelBindings: {
                          ...current.modelBindings,
                          [bindingKey]: normalizeGraphModelBinding(bindingKey, {
                            ...current.modelBindings[bindingKey],
                            authorityScopes,
                            authorityScopeRequirements: authorityScopes,
                          }),
                        },
                      }));
                    }}
                  />
                </label>
                <label>
                  Legacy model id
                  <input
                    data-testid={`workflow-model-binding-legacy-model-id-${bindingKey}`}
                    value={binding.modelId ?? ""}
                    placeholder="compatibility only"
                    onChange={(event) =>
                      onUpdate((current) => ({
                        ...current,
                        modelBindings: {
                          ...current.modelBindings,
                          [bindingKey]: normalizeGraphModelBinding(bindingKey, {
                            ...current.modelBindings[bindingKey],
                            modelId: event.target.value,
                          }),
                        },
                      }))
                    }
                  />
                </label>
                <dl>
                  <div>
                    <dt>Readiness</dt>
                    <dd>{binding.credentialReadiness?.status ?? "unknown"}</dd>
                  </div>
                  <div>
                    <dt>Receipts</dt>
                    <dd>{binding.receiptBehavior?.receiptRequired ? "required" : "missing"}</dd>
                  </div>
                  <div>
                    <dt>Policy</dt>
                    <dd>{String((binding.policyPosture as { status?: unknown })?.status ?? "unknown")}</dd>
                  </div>
                </dl>
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
                            ...normalizeGraphModelBinding(
                              bindingKey,
                              current.modelBindings[bindingKey],
                            ),
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
  toolCatalog,
  connectorCatalog,
  catalogLoading,
  catalogError,
  onClose,
  onInspectNode,
  onOpenNodeLibrary,
  onApplyCatalogBinding,
}: {
  workflow: WorkflowProject;
  toolCatalog: WorkflowToolBinding[];
  connectorCatalog: WorkflowConnectorBinding[];
  catalogLoading: boolean;
  catalogError: string | null;
  onClose: () => void;
  onInspectNode: (nodeId: string) => void;
  onOpenNodeLibrary: () => void;
  onApplyCatalogBinding: (
    nodeId: string,
    binding:
      | { kind: "tool"; value: WorkflowToolBinding }
      | { kind: "connector"; value: WorkflowConnectorBinding },
  ) => void;
}) {
  const [selectedCatalogRefs, setSelectedCatalogRefs] = useState<
    Record<string, string>
  >({});
  const connectorNodes = workflow.nodes.filter(
    (nodeItem) =>
      nodeItem.type === "adapter" || nodeItem.type === "plugin_tool",
  );
  const bindingRows = connectorNodes.map((nodeItem) => {
    const connectorBinding = nodeItem.config?.logic.connectorBinding;
    const toolBinding = nodeItem.config?.logic.toolBinding;
    const normalizedConnector = connectorBinding
      ? normalizeWorkflowConnectorBinding(connectorBinding)
      : null;
    const normalizedTool = toolBinding
      ? normalizeWorkflowToolBinding(toolBinding)
      : null;
    const ref = String(
      normalizedConnector?.connectorCapabilityRef ??
        normalizedTool?.toolCapabilityRef ??
        normalizedConnector?.connectorRef ??
        normalizedTool?.toolRef ??
        "",
    );
    const mockBinding = Boolean(
      normalizedConnector?.mockBinding ?? normalizedTool?.mockBinding,
    );
    const credentialReady =
      normalizedTool?.bindingKind === "workflow_tool"
        ? true
        : Boolean(
            normalizedConnector?.credentialReady ?? normalizedTool?.credentialReady,
          );
    const requiresApproval = Boolean(
      normalizedConnector?.requiresApproval ?? normalizedTool?.requiresApproval,
    );
    const sideEffectClass = String(
      normalizedConnector?.sideEffectClass ??
        normalizedTool?.sideEffectClass ??
        "read",
    );
    return {
      nodeItem,
      ref,
      catalogKind:
        normalizedConnector || nodeItem.type === "adapter"
          ? ("connector" as const)
          : ("tool" as const),
      mockBinding,
      credentialReady,
      requiresApproval,
      sideEffectClass,
      ready: normalizedConnector
        ? workflowConnectorBindingIsReady(normalizedConnector)
        : workflowToolBindingIsReady(normalizedTool),
      bindingKind: connectorBinding
        ? "connector"
        : String(normalizedTool?.bindingKind ?? "plugin_tool"),
    };
  });
  const readyCount = bindingRows.filter((row) => row.ready).length;
  const mockCount = bindingRows.filter((row) => row.mockBinding).length;
  const credentialReadyCount = bindingRows.filter(
    (row) => row.credentialReady,
  ).length;
  const catalogOptionForRow = (row: (typeof bindingRows)[number]) => {
    if (row.catalogKind === "connector") {
      return connectorCatalog.map((binding) => ({
        ref:
          binding.connectorCapabilityRef ??
          `connector-capability:${binding.connectorRef}`,
        label: binding.connectorRef,
        description: binding.operation ?? binding.sideEffectClass,
        ready: workflowConnectorBindingIsReady(binding),
        binding,
      }));
    }
    return toolCatalog.map((binding) => ({
      ref: binding.toolCapabilityRef ?? `tool-capability:${binding.toolRef}`,
      label: binding.toolRef,
      description: binding.bindingKind ?? binding.sideEffectClass,
      ready: workflowToolBindingIsReady(binding),
      binding,
    }));
  };
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
        <p
          className="workflow-create-summary"
          data-testid="workflow-capability-catalog-summary"
        >
          Catalog{" "}
          {catalogLoading
            ? "loading from runtime..."
            : `${toolCatalog.length} tools and ${connectorCatalog.length} connectors ready for capability binding.`}
          {catalogError ? ` ${catalogError}` : ""}
        </p>
        {connectorNodes.length === 0 ? (
          <p>No connector or plugin nodes in this workflow.</p>
        ) : (
          <div
            className="workflow-binding-list"
            data-testid="workflow-connector-binding-list"
          >
            {bindingRows.map((row) => {
              const catalogOptions = catalogOptionForRow(row);
              const currentSelectedRef =
                selectedCatalogRefs[row.nodeItem.id] ??
                catalogOptions.find((option) => option.ref === row.ref)?.ref ??
                "";
              const selectedOption = catalogOptions.find(
                (option) => option.ref === currentSelectedRef,
              );
              return (
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
                  <label>
                    Capability catalog
                    <select
                      data-testid={`workflow-catalog-picker-${row.nodeItem.id}`}
                      value={currentSelectedRef}
                      onChange={(event) =>
                        setSelectedCatalogRefs((current) => ({
                          ...current,
                          [row.nodeItem.id]: event.target.value,
                        }))
                      }
                    >
                      <option value="">Choose a capability</option>
                      {catalogOptions.map((option) => (
                        <option key={option.ref} value={option.ref}>
                          {option.label} · {option.description} ·{" "}
                          {option.ready ? "ready" : "needs readiness"}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="workflow-binding-actions">
                    <button
                      type="button"
                      onClick={() => onInspectNode(row.nodeItem.id)}
                    >
                      Configure node
                    </button>
                    <button
                      type="button"
                      data-testid={`workflow-catalog-apply-${row.nodeItem.id}`}
                      disabled={!selectedOption}
                      onClick={() => {
                        if (!selectedOption) return;
                        if (row.catalogKind === "connector") {
                          onApplyCatalogBinding(row.nodeItem.id, {
                            kind: "connector",
                            value:
                              selectedOption.binding as WorkflowConnectorBinding,
                          });
                          return;
                        }
                        onApplyCatalogBinding(row.nodeItem.id, {
                          kind: "tool",
                          value: selectedOption.binding as WorkflowToolBinding,
                        });
                      }}
                    >
                      Apply catalog binding
                    </button>
                  </div>
                </article>
              );
            })}
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
