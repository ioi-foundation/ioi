import type {
  FirewallPolicy,
  Node,
  NodeLogic,
  WorkflowFunctionBinding,
  WorkflowJsonSchema,
  WorkflowSandboxPolicy,
} from "../../types/graph";
import { workflowValuePreview } from "../../runtime/workflow-value-preview";

interface WorkflowFunctionBindingEditorProps {
  logic: NodeLogic;
  law: FirewallPolicy;
  dryRunView: {
    status: string;
    nodeRun?: { attempt?: number } | null;
    sandbox: Record<string, unknown>;
    resultPayload: unknown;
    stdout?: string;
    stderr?: string;
    error?: string;
  } | null;
  onUpdate: (updates: Partial<Node>) => void;
  updateLogic: (nextLogic: NodeLogic) => void;
  onDryRun: () => void;
}

const DEFAULT_SANDBOX_POLICY: WorkflowSandboxPolicy = {
  timeoutMs: 1000,
  memoryMb: 64,
  outputLimitBytes: 32768,
  permissions: [],
};

const defaultFunctionBinding = (
  logic: NodeLogic,
  law: FirewallPolicy,
): WorkflowFunctionBinding => ({
  language:
    logic.functionBinding?.language === "typescript" ||
    logic.functionBinding?.language === "python" ||
    logic.language === "typescript" ||
    logic.language === "python"
      ? (logic.functionBinding?.language ?? logic.language) as WorkflowFunctionBinding["language"]
      : "javascript",
  code: String(
    logic.functionBinding?.code ?? logic.code ?? "return { result: input };",
  ),
  inputSchema: logic.functionBinding?.inputSchema ??
    logic.inputSchema ?? { type: "object" },
  outputSchema: logic.functionBinding?.outputSchema ??
    logic.outputSchema ?? { type: "object" },
  sandboxPolicy:
    logic.functionBinding?.sandboxPolicy ??
    law.sandboxPolicy ??
    DEFAULT_SANDBOX_POLICY,
  testInput: logic.functionBinding?.testInput ??
    logic.testInput ?? { payload: "sample" },
});

const parseJsonSchema = (
  value: string,
  fallback: WorkflowJsonSchema,
): WorkflowJsonSchema => {
  try {
    return JSON.parse(value || "{}") as WorkflowJsonSchema;
  } catch {
    return fallback;
  }
};

export function WorkflowFunctionBindingEditor({
  logic,
  law,
  dryRunView,
  onUpdate,
  updateLogic,
  onDryRun,
}: WorkflowFunctionBindingEditorProps) {
  const binding = defaultFunctionBinding(logic, law);
  const sandboxPolicy = binding.sandboxPolicy ?? DEFAULT_SANDBOX_POLICY;
  const dryRunPayloadPreview = workflowValuePreview(dryRunView?.resultPayload);

  return (
    <>
      <label>
        Runtime
        <select
          data-testid="workflow-function-runtime"
          value={binding.language}
          onChange={(event) => {
            const language = event.target.value as WorkflowFunctionBinding["language"];
            updateLogic({
              ...logic,
              language,
              functionBinding: {
                ...binding,
                language,
              },
            });
          }}
        >
          <option value="javascript">JavaScript</option>
          <option value="typescript">TypeScript</option>
          <option value="python">Python (blocked until sandbox support)</option>
        </select>
      </label>
      <label>
        Function code
        <textarea
          data-testid="workflow-function-code"
          value={String(logic.functionBinding?.code ?? logic.code ?? "")}
          onChange={(event) => {
            const code = event.target.value;
            updateLogic({
              ...logic,
              language: binding.language,
              code,
              functionBinding: {
                ...binding,
                code,
              },
            });
          }}
        />
      </label>
      <label>
        Input schema
        <textarea
          data-testid="workflow-function-input-schema"
          value={JSON.stringify(binding.inputSchema, null, 2)}
          onChange={(event) => {
            const inputSchema = parseJsonSchema(
              event.target.value,
              binding.inputSchema ?? { type: "object" },
            );
            updateLogic({
              ...logic,
              inputSchema,
              functionBinding: {
                ...binding,
                inputSchema,
              },
            });
          }}
        />
      </label>
      <label>
        Output schema
        <textarea
          data-testid="workflow-function-output-schema"
          value={JSON.stringify(binding.outputSchema, null, 2)}
          onChange={(event) => {
            const outputSchema = parseJsonSchema(
              event.target.value,
              binding.outputSchema ?? { type: "object" },
            );
            updateLogic({
              ...logic,
              outputSchema,
              functionBinding: {
                ...binding,
                outputSchema,
              },
            });
          }}
        />
      </label>
      <label>
        Test input
        <textarea
          data-testid="workflow-function-test-input"
          value={JSON.stringify(binding.testInput, null, 2)}
          onChange={(event) => {
            let testInput: unknown = { payload: "sample" };
            try {
              testInput = JSON.parse(event.target.value || "{}");
            } catch {
              testInput = event.target.value;
            }
            updateLogic({
              ...logic,
              testInput,
              functionBinding: {
                ...binding,
                testInput,
              },
            });
          }}
        />
      </label>
      <fieldset className="workflow-config-fieldset">
        <legend>Sandbox</legend>
        {(["timeoutMs", "memoryMb", "outputLimitBytes"] as const).map(
          (field) => (
            <label key={field}>
              {field}
              <input
                data-testid={`workflow-function-sandbox-${field}`}
                type="number"
                min={field === "timeoutMs" ? 100 : 1}
                value={Number(
                  sandboxPolicy[field] ??
                    (field === "timeoutMs"
                      ? 1000
                      : field === "memoryMb"
                        ? 64
                        : 32768),
                )}
                onChange={(event) => {
                  const nextSandbox = {
                    ...sandboxPolicy,
                    [field]: Number(event.target.value),
                  };
                  onUpdate({
                    config: {
                      law: { ...law, sandboxPolicy: nextSandbox },
                      logic: {
                        ...logic,
                        functionBinding: {
                          ...binding,
                          sandboxPolicy: nextSandbox,
                        },
                      },
                    },
                  });
                }}
              />
            </label>
          ),
        )}
        <div className="workflow-config-checks">
          {(["filesystem", "network", "process"] as const).map((permission) => {
            const permissions = sandboxPolicy.permissions ?? [];
            return (
              <label key={permission}>
                <input
                  data-testid={`workflow-function-permission-${permission}`}
                  type="checkbox"
                  checked={permissions.includes(permission)}
                  onChange={(event) => {
                    const nextPermissions = event.target.checked
                      ? [...permissions, permission]
                      : permissions.filter((item) => item !== permission);
                    const nextSandbox = {
                      ...sandboxPolicy,
                      permissions: nextPermissions,
                    };
                    onUpdate({
                      config: {
                        law: { ...law, sandboxPolicy: nextSandbox },
                        logic: {
                          ...logic,
                          functionBinding: {
                            ...binding,
                            sandboxPolicy: nextSandbox,
                          },
                        },
                      },
                    });
                  }}
                />
                {permission}
              </label>
            );
          })}
        </div>
      </fieldset>
      <button
        type="button"
        data-testid="workflow-function-dry-run"
        onClick={onDryRun}
      >
        Dry run function
      </button>
      {dryRunView ? (
        <div
          className="workflow-function-dry-run-result"
          data-testid="workflow-function-dry-run-result"
        >
          <dl>
            <div>
              <dt>Status</dt>
              <dd>{dryRunView.status}</dd>
            </div>
            <div>
              <dt>Attempt</dt>
              <dd>{dryRunView.nodeRun?.attempt ?? 1}</dd>
            </div>
            <div>
              <dt>Sandbox</dt>
              <dd>
                {Object.keys(dryRunView.sandbox).length > 0
                  ? "configured"
                  : "default"}
              </dd>
            </div>
          </dl>
          <section data-testid="workflow-function-dry-run-payload">
            <strong>Result</strong>
            <div className="workflow-node-value-preview" data-testid="workflow-function-dry-run-payload-preview">
              <span>{dryRunPayloadPreview.summary}</span>
              <small>{dryRunPayloadPreview.detail}</small>
            </div>
            <details className="workflow-config-json-details">
              <summary>Raw result payload</summary>
              <pre>{JSON.stringify(dryRunView.resultPayload, null, 2)}</pre>
            </details>
          </section>
          <section data-testid="workflow-function-dry-run-stdout">
            <strong>Stdout</strong>
            <pre>{dryRunView.stdout || "No stdout captured."}</pre>
          </section>
          <section data-testid="workflow-function-dry-run-stderr">
            <strong>Stderr</strong>
            <pre>
              {dryRunView.stderr ||
                dryRunView.error ||
                "No stderr captured."}
            </pre>
          </section>
        </div>
      ) : null}
    </>
  );
}
