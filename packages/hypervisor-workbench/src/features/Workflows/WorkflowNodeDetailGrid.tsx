import { useState } from "react";
import type {
  Node,
  WorkflowNodeFixture,
  WorkflowNodeRun,
  WorkflowPortDefinition,
  WorkflowValidationIssue,
} from "../../types/graph";
import { workflowFixtureSourceLabel } from "../../runtime/workflow-fixture-model";
import {
  type WorkflowChildRunLineage,
  workflowDurationLabel,
  workflowIssueActionLabel,
  workflowIssueTitle,
  workflowTimeLabel,
} from "../../runtime/workflow-rail-model";
import {
  workflowSchemaFieldReferences,
  type WorkflowSchemaFieldReference,
} from "../../runtime/workflow-schema";
import { workflowValuePreview } from "../../runtime/workflow-value-preview";
import type { WorkflowUpstreamReference } from "./WorkflowNodeConfigTypes";

interface WorkflowNodeDetailGridProps {
  node: Node;
  inputPorts: WorkflowPortDefinition[];
  outputPorts: WorkflowPortDefinition[];
  inputSchemaFields: WorkflowSchemaFieldReference[];
  outputSchemaFields: WorkflowSchemaFieldReference[];
  upstreamReferences: WorkflowUpstreamReference[];
  selectedNodeRun: WorkflowNodeRun | null;
  workflowToolLineage: WorkflowChildRunLineage | null;
  macroPeerNodes: Node[];
  nodeIssues: WorkflowValidationIssue[];
  staleFixtureCount: number;
  fixtures: WorkflowNodeFixture[];
  onApplyUpstreamReference: (reference: WorkflowUpstreamReference) => void;
  onApplyUpstreamFieldReference: (
    reference: WorkflowUpstreamReference,
    field: WorkflowSchemaFieldReference,
  ) => void;
  onInspectNode: (nodeId: string) => void;
  onCaptureFixture: () => void;
  onImportFixture: (rawText: string) => void;
  onPinFixture: (fixture: WorkflowNodeFixture) => void;
  onDryRunFixture: (fixture?: WorkflowNodeFixture) => void;
}

export function WorkflowNodeDetailGrid({
  node,
  inputPorts,
  outputPorts,
  inputSchemaFields,
  outputSchemaFields,
  upstreamReferences,
  selectedNodeRun,
  workflowToolLineage,
  macroPeerNodes,
  nodeIssues,
  staleFixtureCount,
  fixtures,
  onApplyUpstreamReference,
  onApplyUpstreamFieldReference,
  onInspectNode,
  onCaptureFixture,
  onImportFixture,
  onPinFixture,
  onDryRunFixture,
}: WorkflowNodeDetailGridProps) {
  const [fixtureImportText, setFixtureImportText] = useState("");
  const latestOutputPreview = workflowValuePreview(selectedNodeRun?.output);
  const latestInputPreview = workflowValuePreview(selectedNodeRun?.input);
  const latestErrorPreview = workflowValuePreview(selectedNodeRun?.error);
  const viewMacro = node.config?.logic.viewMacro;
  const currentFixtureCount = fixtures.length - staleFixtureCount;
  const inputMappings = Object.entries(
    node.config?.logic.inputMapping ?? {},
  ).filter((entry): entry is [string, string] => typeof entry[1] === "string");
  const fieldMappings = Object.entries(
    node.config?.logic.fieldMappings ?? {},
  ).filter(
    (entry): entry is [
      string,
      { source: string; path: string; type?: string },
    ] => {
      const value = entry[1];
      return Boolean(
        value &&
          typeof value === "object" &&
          !Array.isArray(value) &&
          typeof (value as { source?: unknown }).source === "string" &&
          typeof (value as { path?: unknown }).path === "string",
      );
    },
  );

  return (
    <section
      className="workflow-config-detail-grid"
      data-testid="workflow-node-detail-workbench"
    >
      <article
        data-config-section="inputs"
        data-testid="workflow-config-section-inputs"
        tabIndex={-1}
      >
        <strong>Inputs</strong>
        <div
          className="workflow-config-port-table"
          data-testid="workflow-config-input-port-table"
        >
          {inputPorts.length > 0 ? (
            inputPorts.map((port) => (
              <div key={port.id}>
                <span data-connection-class={port.connectionClass}>
                  {port.connectionClass}
                </span>
                <strong>{port.label}</strong>
                <small>
                  {port.dataType} · {port.required ? "required" : "optional"} ·{" "}
                  {port.cardinality}
                </small>
              </div>
            ))
          ) : (
            <p>No input ports.</p>
          )}
        </div>
        <div
          className="workflow-config-schema-fields"
          data-testid="workflow-config-input-schema-fields"
        >
          {inputSchemaFields.length > 0 ? (
            inputSchemaFields.map((field) => (
              <span key={field.path}>
                {field.path}
                <small>{field.type}</small>
              </span>
            ))
          ) : (
            <small>No declared input fields.</small>
          )}
        </div>
        <div
          className="workflow-node-value-preview"
          data-testid="workflow-node-input-preview"
        >
          <strong>{latestInputPreview.kind}</strong>
          <span>{latestInputPreview.summary}</span>
          <small>{latestInputPreview.detail}</small>
        </div>
        <details className="workflow-config-json-details">
          <summary>Raw input payload</summary>
          <pre>{JSON.stringify(selectedNodeRun?.input ?? null, null, 2)}</pre>
        </details>
      </article>
      <article data-testid="workflow-upstream-references">
        <strong>Upstream data</strong>
        {upstreamReferences.length > 0 ? (
          <div className="workflow-upstream-list">
            {upstreamReferences.map((reference) => (
              <div
                key={`${reference.nodeId}-${reference.portId}`}
                className="workflow-upstream-row"
              >
                <div>
                  <strong>{reference.nodeName}</strong>
                  <span>
                    {reference.portId} · {reference.connectionClass}
                  </span>
                  <code>{reference.expression}</code>
                  <div
                    className="workflow-upstream-field-picker"
                    data-testid="workflow-upstream-field-picker"
                  >
                    {workflowSchemaFieldReferences(
                      reference.schema,
                      reference.latestOutput,
                    ).length > 0 ? (
                      workflowSchemaFieldReferences(
                        reference.schema,
                        reference.latestOutput,
                      ).map((field) => (
                        <button
                          key={`${reference.nodeId}-${reference.portId}-${field.path}`}
                          type="button"
                          data-testid="workflow-map-upstream-field"
                          title={`Map ${field.path} from ${reference.nodeName}`}
                          onClick={() =>
                            onApplyUpstreamFieldReference(reference, field)
                          }
                        >
                          <span>{field.path}</span>
                          <small>{field.type}</small>
                        </button>
                      ))
                    ) : (
                      <small>No schema fields inferred.</small>
                    )}
                  </div>
                </div>
                <button
                  type="button"
                  data-testid="workflow-insert-upstream-reference"
                  onClick={() => onApplyUpstreamReference(reference)}
                >
                  Map
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p>No incoming data yet.</p>
        )}
      </article>
      <article
        data-config-section="mapping"
        data-testid="workflow-config-section-mapping"
        tabIndex={-1}
      >
        <strong>Field mapping</strong>
        <p>
          Browse connected outputs and map exact fields into this node's inputs.
        </p>
        <div
          className="workflow-config-mapping-grid"
          data-testid="workflow-field-mapping-workbench"
        >
          <section>
            <strong>Available upstream fields</strong>
            {upstreamReferences.length > 0 ? (
              upstreamReferences.map((reference) => {
                const fields = workflowSchemaFieldReferences(
                  reference.schema,
                  reference.latestOutput,
                );
                return (
                  <div key={`${reference.nodeId}-${reference.portId}-mapping`}>
                    <code>{reference.expression}</code>
                    <div className="workflow-upstream-field-picker">
                      {fields.length > 0 ? (
                        fields.map((field) => (
                          <button
                            key={`${reference.nodeId}-${field.path}-mapping`}
                            type="button"
                            data-testid="workflow-mapping-field-reference"
                            onClick={() =>
                              onApplyUpstreamFieldReference(reference, field)
                            }
                          >
                            <span>{field.path}</span>
                            <small>{field.type}</small>
                          </button>
                        ))
                      ) : (
                        <small>No field schema inferred.</small>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <small>Connect a source node to enable field mapping.</small>
            )}
          </section>
          <section>
            <strong>Current mappings</strong>
            {fieldMappings.length > 0 || inputMappings.length > 0 ? (
              <dl data-testid="workflow-current-field-mappings">
                {fieldMappings.map(([key, mapping]) => (
                  <div key={`field-${key}`}>
                    <dt>{key}</dt>
                    <dd>
                      <code>{mapping.source}</code> · {mapping.path}
                      {mapping.type ? ` · ${mapping.type}` : ""}
                    </dd>
                  </div>
                ))}
                {inputMappings
                  .filter(([key]) => !fieldMappings.some(([fieldKey]) => fieldKey === key))
                  .map(([key, expression]) => (
                    <div key={`input-${key}`}>
                      <dt>{key}</dt>
                      <dd>
                        <code>{expression}</code>
                      </dd>
                    </div>
                  ))}
              </dl>
            ) : (
              <small>No mapped fields yet.</small>
            )}
          </section>
        </div>
      </article>
      {viewMacro ? (
        <article
          data-config-section="composition"
          data-testid="workflow-node-macro-cluster"
          tabIndex={-1}
        >
          <strong>Composition</strong>
          <p>
            {viewMacro.macroLabel} expands into explicit workflow primitives.
            This node is the {viewMacro.role} role.
          </p>
          <div className="workflow-node-macro-peer-list" data-testid="workflow-node-macro-peer-list">
            {macroPeerNodes.map((peer) => {
              const peerMacro = peer.config?.logic.viewMacro;
              const isCurrent = peer.id === node.id;
              return (
                <button
                  key={peer.id}
                  type="button"
                  className={isCurrent ? "is-current" : ""}
                  data-testid="workflow-node-macro-peer"
                  disabled={isCurrent}
                  onClick={() => onInspectNode(peer.id)}
                >
                  <strong>{peer.name}</strong>
                  <span>{peerMacro?.role ?? peer.type}</span>
                </button>
              );
            })}
          </div>
        </article>
      ) : null}
      <article
        data-config-section="outputs"
        data-testid="workflow-config-section-outputs"
        tabIndex={-1}
      >
        <strong>Outputs</strong>
        <div
          className="workflow-config-port-table"
          data-testid="workflow-config-output-port-table"
        >
          {outputPorts.length > 0 ? (
            outputPorts.map((port) => (
              <div key={port.id}>
                <span data-connection-class={port.connectionClass}>
                  {port.connectionClass}
                </span>
                <strong>{port.label}</strong>
                <small>
                  {port.dataType} · {port.required ? "required" : "optional"} ·{" "}
                  {port.cardinality}
                </small>
              </div>
            ))
          ) : (
            <p>No output ports.</p>
          )}
        </div>
        <div
          className="workflow-config-schema-fields"
          data-testid="workflow-config-output-schema-fields"
        >
          {outputSchemaFields.length > 0 ? (
            outputSchemaFields.map((field) => (
              <span key={field.path}>
                {field.path}
                <small>{field.type}</small>
              </span>
            ))
          ) : (
            <small>No declared output fields.</small>
          )}
        </div>
        <div className="workflow-node-value-preview" data-testid="workflow-node-output-preview">
          <strong>{latestOutputPreview.kind}</strong>
          <span>{latestOutputPreview.summary}</span>
          <small>{latestOutputPreview.detail}</small>
        </div>
        <details className="workflow-config-json-details">
          <summary>Raw output payload</summary>
          <pre>{JSON.stringify(selectedNodeRun?.output ?? null, null, 2)}</pre>
        </details>
      </article>
      <article
        data-config-section="schema"
        data-testid="workflow-upstream-schema-preview"
        tabIndex={-1}
      >
        <strong>Schema references</strong>
        <div
          className="workflow-config-upstream-schema-list"
          data-testid="workflow-config-upstream-schema-fields"
        >
          {upstreamReferences.length > 0 ? (
            upstreamReferences.map((reference) => {
              const fields = workflowSchemaFieldReferences(
                reference.schema,
                reference.latestOutput,
              );
              return (
                <section key={`${reference.nodeId}-${reference.portId}`}>
                  <strong>{reference.nodeName}</strong>
                  <small>
                    {reference.portId} · {reference.connectionClass}
                  </small>
                  <div className="workflow-config-schema-fields">
                    {fields.length > 0 ? (
                      fields.map((field) => (
                        <span key={field.path}>
                          {field.path}
                          <small>{field.type}</small>
                        </span>
                      ))
                    ) : (
                      <small>No fields inferred.</small>
                    )}
                  </div>
                </section>
              );
            })
          ) : (
            <p>No upstream schema references.</p>
          )}
        </div>
      </article>
      <article
        data-config-section="run-data"
        data-testid="workflow-config-section-run-data"
        tabIndex={-1}
      >
        <strong>Run data</strong>
        <div
          className="workflow-node-run-report"
          data-testid="workflow-node-run-report"
        >
          <dl>
            <div>
              <dt>Status</dt>
              <dd>{selectedNodeRun?.status ?? node.status ?? "idle"}</dd>
            </div>
            <div>
              <dt>Attempt</dt>
              <dd>{selectedNodeRun?.attempt ?? "none"}</dd>
            </div>
            <div>
              <dt>Duration</dt>
              <dd>
                {workflowDurationLabel(
                  selectedNodeRun?.startedAtMs,
                  selectedNodeRun?.finishedAtMs,
                )}
              </dd>
            </div>
            <div>
              <dt>Checkpoint</dt>
              <dd>{selectedNodeRun?.checkpointId ?? "none"}</dd>
            </div>
            <div data-testid="workflow-node-run-lifecycle">
              <dt>Run steps</dt>
              <dd>{selectedNodeRun?.lifecycle?.length ?? 0}</dd>
            </div>
          </dl>
          {selectedNodeRun?.lifecycle?.length ? (
            <div
              className="workflow-node-run-lifecycle"
              data-testid="workflow-node-run-lifecycle-list"
            >
              {selectedNodeRun.lifecycle.map((step) => (
                <span key={step}>{step.replace(/_/g, " ")}</span>
              ))}
            </div>
          ) : null}
          <section data-testid="workflow-node-run-input">
            <strong>Input</strong>
            <span>{latestInputPreview.summary}</span>
            <small>{latestInputPreview.detail}</small>
            <details className="workflow-config-json-details">
              <summary>Raw input</summary>
              <pre>
                {JSON.stringify(selectedNodeRun?.input ?? null, null, 2)}
              </pre>
            </details>
          </section>
          <section data-testid="workflow-node-run-output">
            <strong>Output</strong>
            <span>{latestOutputPreview.summary}</span>
            <small>{latestOutputPreview.detail}</small>
            <details className="workflow-config-json-details">
              <summary>Raw output</summary>
              <pre>
                {JSON.stringify(selectedNodeRun?.output ?? null, null, 2)}
              </pre>
            </details>
          </section>
          <section data-testid="workflow-node-run-error">
            <strong>Error</strong>
            <span>{selectedNodeRun?.error ? latestErrorPreview.summary : "No error recorded."}</span>
            {selectedNodeRun?.error ? <small>{latestErrorPreview.detail}</small> : null}
          </section>
          {workflowToolLineage ? (
            <section
              className="workflow-tool-lineage"
              data-testid="workflow-tool-child-lineage"
            >
              <strong>Child workflow run</strong>
              <dl>
                <div>
                  <dt>Status</dt>
                  <dd>{workflowToolLineage.childRunStatus}</dd>
                </div>
                <div>
                  <dt>Run</dt>
                  <dd>{workflowToolLineage.childRunId}</dd>
                </div>
                <div>
                  <dt>Thread</dt>
                  <dd>{workflowToolLineage.childThreadId}</dd>
                </div>
                <div>
                  <dt>Workflow</dt>
                  <dd>{workflowToolLineage.childWorkflowPath}</dd>
                </div>
              </dl>
            </section>
          ) : null}
        </div>
      </article>
      <article data-testid="workflow-node-config-issues">
        <strong>Needs attention</strong>
        {nodeIssues.length > 0 ? (
          <div className="workflow-node-config-issue-list">
            {nodeIssues.slice(0, 6).map((issue, index) => (
              <div
                key={`${issue.code}-${index}`}
                className="workflow-node-config-issue"
              >
                <strong>{workflowIssueTitle(issue)}</strong>
                <span>{issue.message}</span>
                <small>{workflowIssueActionLabel(issue)}</small>
              </div>
            ))}
          </div>
        ) : (
          <p>No node-specific validation issues.</p>
        )}
      </article>
      <article
        data-config-section="fixtures"
        data-testid="workflow-config-section-fixtures"
        tabIndex={-1}
      >
        <strong>Fixtures</strong>
        {staleFixtureCount > 0 && currentFixtureCount === 0 ? (
          <small
            className="workflow-fixture-stale"
            data-testid="workflow-fixture-stale-warning"
          >
            {staleFixtureCount} fixture{staleFixtureCount === 1 ? "" : "s"} need
            refresh after node changes.
          </small>
        ) : staleFixtureCount > 0 ? (
          <small
            className="workflow-fixture-note"
            data-testid="workflow-fixture-stale-warning"
          >
            {staleFixtureCount} older fixture{staleFixtureCount === 1 ? "" : "s"} need
            refresh; the selected sample is current.
          </small>
        ) : null}
        <div className="workflow-config-inline-actions">
          <button
            type="button"
            data-testid="workflow-capture-node-fixture"
            onClick={onCaptureFixture}
          >
            Capture latest sample
          </button>
          <button
            type="button"
            data-testid="workflow-dry-run-node-fixture"
            disabled={fixtures.length === 0}
            onClick={() => onDryRunFixture(fixtures[0])}
          >
            Replay fixture
          </button>
        </div>
        <div
          className="workflow-fixture-list"
          data-testid="workflow-fixture-list"
        >
          {fixtures.length > 0 ? (
            fixtures.slice(0, 4).map((fixture) => {
              const inputPreview = workflowValuePreview(fixture.input);
              const outputPreview = workflowValuePreview(fixture.output);
              return (
                <article
                  key={fixture.id}
                  className={`workflow-fixture-card${fixture.stale ? " is-stale" : ""}`}
                  data-testid="workflow-fixture-card"
                >
                  <div>
                    <strong>{fixture.name}</strong>
                    <span>
                      {fixture.pinned ? "pinned · " : ""}
                      {workflowFixtureSourceLabel(fixture)} ·{" "}
                      {workflowTimeLabel(fixture.createdAtMs)}
                    </span>
                    <small data-testid="workflow-fixture-validation-status">
                      {fixture.validationStatus ?? "not_declared"}
                      {fixture.validationMessage ? ` · ${fixture.validationMessage}` : ""}
                    </small>
                  </div>
                  <div className="workflow-fixture-card-actions">
                    <button
                      type="button"
                      data-testid="workflow-fixture-pin"
                      disabled={fixture.pinned === true}
                      onClick={() => onPinFixture(fixture)}
                    >
                      {fixture.pinned ? "Pinned" : "Pin"}
                    </button>
                    <button
                      type="button"
                      data-testid="workflow-fixture-replay"
                      onClick={() => onDryRunFixture(fixture)}
                    >
                      Replay
                    </button>
                  </div>
                  <section data-testid="workflow-fixture-input-preview">
                    <strong>Input</strong>
                    <span>{inputPreview.summary}</span>
                    <small>{inputPreview.detail}</small>
                    <details className="workflow-config-json-details">
                      <summary>Raw input</summary>
                      <pre>{JSON.stringify(fixture.input ?? null, null, 2)}</pre>
                    </details>
                  </section>
                  <section data-testid="workflow-fixture-output-preview">
                    <strong>Output</strong>
                    <span>{outputPreview.summary}</span>
                    <small>{outputPreview.detail}</small>
                    <details className="workflow-config-json-details">
                      <summary>Raw output</summary>
                      <pre>{JSON.stringify(fixture.output ?? null, null, 2)}</pre>
                    </details>
                  </section>
                </article>
              );
            })
          ) : (
            <p data-testid="workflow-fixture-empty">
              No fixtures captured for this node.
            </p>
          )}
        </div>
        <label className="workflow-fixture-import">
          Import sample JSON
          <textarea
            data-testid="workflow-import-fixture-json"
            value={fixtureImportText}
            placeholder='{"input":{"payload":"sample"},"output":{"result":"ok"}}'
            onChange={(event) => setFixtureImportText(event.target.value)}
          />
        </label>
        <button
          type="button"
          data-testid="workflow-import-node-fixture"
          disabled={!fixtureImportText.trim()}
          onClick={() => {
            onImportFixture(fixtureImportText);
            setFixtureImportText("");
          }}
        >
          Import fixture
        </button>
      </article>
    </section>
  );
}
