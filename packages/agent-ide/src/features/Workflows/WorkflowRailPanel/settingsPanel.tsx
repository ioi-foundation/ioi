import type { ReactNode } from "react";
import type {
  GraphGlobalConfig,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
} from "../../../types/graph";
import type { WorkflowBindingRegistryRow } from "../../../runtime/workflow-rail-model";
import type { WorkflowSettingsModel } from "../../../runtime/workflow-settings-model";

type WorkflowSettingsPanelProps = {
  model: WorkflowSettingsModel;
  supportedLocales: readonly string[];
  bindingRegistryRows: WorkflowBindingRegistryRow[];
  bindingCheckResults: Record<string, WorkflowBindingCheckResult>;
  bindingManifest: WorkflowBindingManifest | null;
  children?: ReactNode;
  onUpdateWorkflowChromeLocale?: (locale: string) => void;
  onUpdateEnvironmentProfile: (
    updates: Partial<NonNullable<GraphGlobalConfig["environmentProfile"]>>,
  ) => void;
  onUpdateProductionProfile: (
    updates: NonNullable<GraphGlobalConfig["production"]>,
  ) => void;
  onGenerateBindingManifest: () => void;
  onCheckBindingRow: (row: WorkflowBindingRegistryRow) => void;
  onInspectNode: (nodeId: string) => void;
};

export function WorkflowSettingsPanel({
  model,
  supportedLocales,
  bindingRegistryRows,
  bindingCheckResults,
  bindingManifest,
  children,
  onUpdateWorkflowChromeLocale,
  onUpdateEnvironmentProfile,
  onUpdateProductionProfile,
  onGenerateBindingManifest,
  onCheckBindingRow,
  onInspectNode,
}: WorkflowSettingsPanelProps) {
  const {
    metadata,
    workflowReadOnly,
    chromeLocale,
    environmentProfile,
    bindingRegistrySummary,
    modelBindingItems,
    requiredCapabilityItems,
    policy,
    productionProfile,
    productionSummary,
    packageReadinessStatus,
  } = model;

  return (
    <>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-metadata"
      >
        <h4>Workflow</h4>
        <article className="workflow-file-row">
          <strong>{metadata.name}</strong>
          <code>{metadata.workflowPath}</code>
          <span>
            {metadata.branch} · {metadata.dirty ? "modified" : "saved"}
          </span>
        </article>
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-chrome-locale"
        data-workflow-chrome-locale={chromeLocale}
        data-model-output-localized="false"
      >
        <h4>Chrome locale</h4>
        <label className="workflow-settings-select-row">
          <span>Workflow chrome</span>
          <select
            data-testid="workflow-settings-chrome-locale-select"
            value={chromeLocale}
            disabled={workflowReadOnly || !onUpdateWorkflowChromeLocale}
            onChange={(event) =>
              onUpdateWorkflowChromeLocale?.(event.target.value)
            }
          >
            {supportedLocales.map((locale) => (
              <option key={locale} value={locale}>
                {locale}
              </option>
            ))}
          </select>
        </label>
      </section>
      {children}
      <section
        className="workflow-rail-section"
        data-testid="workflow-environment-profile"
      >
        <h4>Environment</h4>
        <dl className="workflow-rail-stats">
          <div>
            <dt>Target</dt>
            <dd>{environmentProfile.target}</dd>
          </div>
          <div>
            <dt>Credentials</dt>
            <dd>{environmentProfile.credentialScope || "local"}</dd>
          </div>
          <div>
            <dt>Mock policy</dt>
            <dd>{environmentProfile.mockBindingPolicy || "warn"}</dd>
          </div>
          <div>
            <dt>Bindings</dt>
            <dd>
              {bindingRegistrySummary.ready}/{bindingRegistrySummary.total}
            </dd>
          </div>
        </dl>
        <div className="workflow-settings-production-editor">
          <label>
            Target
            <select
              data-testid="workflow-environment-target"
              value={environmentProfile.target}
              disabled={workflowReadOnly}
              onChange={(event) =>
                onUpdateEnvironmentProfile({
                  target: event.target.value as NonNullable<
                    GraphGlobalConfig["environmentProfile"]
                  >["target"],
                })
              }
            >
              <option value="local">Local</option>
              <option value="sandbox">Sandbox</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
          </label>
          <label>
            Credential scope
            <input
              data-testid="workflow-environment-credential-scope"
              value={environmentProfile.credentialScope ?? ""}
              disabled={workflowReadOnly}
              placeholder="local, sandbox, staging, production"
              onChange={(event) =>
                onUpdateEnvironmentProfile({
                  credentialScope: event.target.value,
                })
              }
            />
          </label>
          <label>
            Mock bindings
            <select
              data-testid="workflow-environment-mock-policy"
              value={environmentProfile.mockBindingPolicy ?? "warn"}
              disabled={workflowReadOnly}
              onChange={(event) =>
                onUpdateEnvironmentProfile({
                  mockBindingPolicy: event.target.value as NonNullable<
                    GraphGlobalConfig["environmentProfile"]
                  >["mockBindingPolicy"],
                })
              }
            >
              <option value="allow">Allow in this environment</option>
              <option value="warn">Warn before activation</option>
              <option value="block">Block activation</option>
            </select>
          </label>
        </div>
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-binding-registry"
      >
        <h4>Binding registry</h4>
        <dl
          className="workflow-rail-stats"
          data-testid="workflow-binding-registry-summary"
        >
          <div>
            <dt>Total</dt>
            <dd>{bindingRegistrySummary.total}</dd>
          </div>
          <div>
            <dt>Ready</dt>
            <dd>{bindingRegistrySummary.ready}</dd>
          </div>
          <div>
            <dt>Mock</dt>
            <dd>{bindingRegistrySummary.mock}</dd>
          </div>
          <div>
            <dt>Approvals</dt>
            <dd>{bindingRegistrySummary.approval}</dd>
          </div>
        </dl>
        <div className="workflow-rail-list">
          {bindingRegistryRows.map((row) => {
            const checkResult = bindingCheckResults[row.id];

            return (
              <article
                key={row.id}
                className={`workflow-binding-row is-${
                  checkResult?.status ?? (row.ready ? "ready" : "blocked")
                }`}
                data-testid={`workflow-binding-registry-row-${row.nodeItem.id}`}
              >
                <header>
                  <div>
                    <strong>{row.nodeItem.name}</strong>
                    <span>
                      {row.bindingKind} · {row.mode} ·{" "}
                      {row.ready ? "ready" : "needs setup"}
                    </span>
                  </div>
                  <div className="workflow-binding-actions">
                    <button
                      type="button"
                      data-testid={`workflow-binding-check-${row.id}`}
                      onClick={() => onCheckBindingRow(row)}
                    >
                      Check
                    </button>
                    <button
                      type="button"
                      data-testid={`workflow-binding-inspect-${row.nodeItem.id}`}
                      onClick={() => onInspectNode(row.nodeItem.id)}
                    >
                      Configure
                    </button>
                  </div>
                </header>
                <dl>
                  <div>
                    <dt>Ref</dt>
                    <dd>{row.ref || "not set"}</dd>
                  </div>
                  <div>
                    <dt>Scope</dt>
                    <dd>{row.scope}</dd>
                  </div>
                  <div>
                    <dt>Side effect</dt>
                    <dd>{row.sideEffectClass}</dd>
                  </div>
                  <div>
                    <dt>Approval</dt>
                    <dd>{row.approval}</dd>
                  </div>
                </dl>
                {checkResult ? (
                  <p
                    className="workflow-binding-check-result"
                    data-testid={`workflow-binding-check-result-${row.id}`}
                    data-status={checkResult.status}
                  >
                    <strong>{checkResult.summary}</strong>
                    <span>{checkResult.detail}</span>
                  </p>
                ) : null}
              </article>
            );
          })}
          {bindingRegistryRows.length === 0 ? (
            <article className="workflow-output-row">
              <strong>No bindings</strong>
              <span>
                Add model, connector, parser, or tool primitives to populate
                this registry.
              </span>
            </article>
          ) : null}
        </div>
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-binding-manifest"
      >
        <h4>Binding manifest</h4>
        <div className="workflow-package-actions">
          <button
            type="button"
            data-testid="workflow-generate-binding-manifest"
            onClick={onGenerateBindingManifest}
          >
            Refresh manifest
          </button>
        </div>
        {bindingManifest ? (
          <>
            <dl
              className="workflow-rail-stats"
              data-testid="workflow-binding-manifest-summary"
            >
              <div>
                <dt>Total</dt>
                <dd>{bindingManifest.summary.total}</dd>
              </div>
              <div>
                <dt>Ready</dt>
                <dd>{bindingManifest.summary.ready}</dd>
              </div>
              <div>
                <dt>Blocked</dt>
                <dd>{bindingManifest.summary.blocked}</dd>
              </div>
              <div>
                <dt>Approvals</dt>
                <dd>{bindingManifest.summary.approvalRequired}</dd>
              </div>
            </dl>
            <p data-testid="workflow-binding-manifest-environment">
              {bindingManifest.environmentProfile.target} ·{" "}
              {bindingManifest.environmentProfile.credentialScope ?? "local"} ·
              mocks{" "}
              {bindingManifest.environmentProfile.mockBindingPolicy ?? "block"}
            </p>
          </>
        ) : (
          <article className="workflow-output-row">
            <strong>No manifest generated</strong>
            <span>
              Refresh after binding changes to capture environment readiness
              for packaging.
            </span>
          </article>
        )}
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-model-bindings"
      >
        <h4>Model bindings</h4>
        {modelBindingItems.map(([bindingKey, binding]) => (
          <article
            key={bindingKey}
            className={`workflow-test-row is-${
              binding.modelId ? "passed" : binding.required ? "blocked" : "idle"
            }`}
          >
            <strong>{bindingKey}</strong>
            <span>
              {binding.modelId || (binding.required ? "required" : "optional")}
            </span>
          </article>
        ))}
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-capabilities"
      >
        <h4>Required capabilities</h4>
        {requiredCapabilityItems.length > 0 ? (
          requiredCapabilityItems.map(([capability, requirement]) => (
            <article key={capability} className="workflow-output-row">
              <strong>{capability}</strong>
              <span>
                {requirement.bindingKey
                  ? `binding: ${requirement.bindingKey}`
                  : (requirement.notes ?? "required")}
              </span>
            </article>
          ))
        ) : (
          <article className="workflow-output-row">
            <strong>No required capabilities</strong>
            <span>Nodes can still declare their own binding requirements.</span>
          </article>
        )}
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-policy"
      >
        <h4>Run policy</h4>
        <dl className="workflow-rail-stats">
          <div>
            <dt>Budget</dt>
            <dd>{policy.maxBudget}</dd>
          </div>
          <div>
            <dt>Steps</dt>
            <dd>{policy.maxSteps}</dd>
          </div>
          <div>
            <dt>Timeout</dt>
            <dd>{policy.timeoutMs} ms</dd>
          </div>
          <div>
            <dt>Package</dt>
            <dd>{packageReadinessStatus}</dd>
          </div>
        </dl>
      </section>
      <section
        className="workflow-rail-section"
        data-testid="workflow-settings-production-profile"
      >
        <h4>Production checklist</h4>
        <dl className="workflow-rail-stats">
          <div>
            <dt>Error path</dt>
            <dd>{productionSummary.errorPath}</dd>
          </div>
          <div>
            <dt>Evaluations</dt>
            <dd>{productionSummary.evaluations}</dd>
          </div>
          <div>
            <dt>Value estimate</dt>
            <dd>{productionSummary.valueEstimate}</dd>
          </div>
          <div>
            <dt>MCP access</dt>
            <dd>{productionSummary.mcpAccess}</dd>
          </div>
        </dl>
        <div
          className="workflow-settings-production-editor"
          data-testid="workflow-production-profile-editor"
        >
          <label>
            Error workflow path
            <input
              data-testid="workflow-production-error-path"
              value={productionProfile.errorWorkflowPath ?? ""}
              disabled={workflowReadOnly}
              placeholder=".agents/workflows/error-handler.workflow.json"
              onChange={(event) =>
                onUpdateProductionProfile({
                  errorWorkflowPath: event.target.value,
                })
              }
            />
          </label>
          <label>
            Evaluation set path
            <input
              data-testid="workflow-production-evaluation-path"
              value={productionProfile.evaluationSetPath ?? ""}
              disabled={workflowReadOnly}
              placeholder=".agents/workflows/evaluations/reporting.tests.json"
              onChange={(event) =>
                onUpdateProductionProfile({
                  evaluationSetPath: event.target.value,
                })
              }
            />
          </label>
          <label>
            Expected time saved per run
            <input
              data-testid="workflow-production-time-saved"
              type="number"
              min={0}
              step={1}
              value={productionProfile.expectedTimeSavedMinutes ?? 0}
              disabled={workflowReadOnly}
              onChange={(event) =>
                onUpdateProductionProfile({
                  expectedTimeSavedMinutes: Number(event.target.value || 0),
                })
              }
            />
          </label>
          <label className="workflow-config-checkbox">
            <input
              data-testid="workflow-production-mcp-reviewed"
              type="checkbox"
              checked={productionProfile.mcpAccessReviewed === true}
              disabled={workflowReadOnly}
              onChange={(event) =>
                onUpdateProductionProfile({
                  mcpAccessReviewed: event.target.checked,
                })
              }
            />
            MCP access reviewed
          </label>
        </div>
      </section>
    </>
  );
}
