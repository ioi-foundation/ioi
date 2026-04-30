import type {
  FirewallPolicy,
  Node,
  NodeLogic,
  WorkflowJsonSchema,
  WorkflowTestCase,
} from "../../types/graph";
import { WorkflowFunctionBindingEditor } from "./WorkflowFunctionBindingEditor";

interface WorkflowNodeBindingEditorProps {
  node: Node;
  logic: NodeLogic;
  law: FirewallPolicy;
  sectionStatus: string;
  sectionDetail: string;
  modelAttachmentCounts: {
    model: number;
    memory: number;
    tool: number;
    parser: number;
  };
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

const asRecord = (value: unknown): Record<string, any> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, any>)
    : {};

const parseJsonField = (value: string, fallback: unknown): unknown => {
  try {
    return JSON.parse(value || "{}");
  } catch {
    return fallback;
  }
};

const OUTPUT_FORMAT_OPTIONS = [
  ["markdown", "Markdown"],
  ["json", "JSON"],
  ["svg", "SVG"],
  ["image", "Image"],
  ["chart", "Chart"],
  ["diff", "Diff"],
  ["patch", "Patch"],
  ["dataset", "Dataset"],
  ["message", "Message"],
  ["report", "Report"],
] as const;

const OUTPUT_RENDERER_OPTIONS = [
  ["markdown", "Markdown"],
  ["json", "JSON"],
  ["table", "Table"],
  ["media", "Media"],
  ["diff", "Diff"],
  ["report", "Report"],
  ["patch", "Patch"],
] as const;

const OUTPUT_DISPLAY_MODE_OPTIONS = [
  ["inline", "Inline"],
  ["canvas_preview", "Canvas preview"],
  ["table", "Table"],
  ["json", "JSON"],
  ["media", "Media"],
  ["diff", "Diff"],
  ["report", "Report"],
  ["artifact_panel", "Chat panel"],
] as const;

const SOURCE_KIND_OPTIONS = [
  ["manual", "Manual input"],
  ["file", "File input"],
  ["media", "Media input"],
  ["dataset", "Dataset/table"],
  ["api_payload", "API payload"],
] as const;

const MEDIA_KIND_OPTIONS = [
  ["image", "Image"],
  ["audio", "Audio"],
  ["video", "Video"],
  ["document", "Document"],
] as const;

function defaultSourceLogicForKind(
  kind: NonNullable<NodeLogic["sourceKind"]>,
): Partial<NodeLogic> {
  switch (kind) {
    case "file":
      return {
        sourceKind: kind,
        sourcePath: "",
        fileExtension: "",
        mimeType: "application/octet-stream",
        sanitizeInput: true,
        validateMime: true,
        stripMetadata: false,
        payload: { file: "" },
        schema: { type: "object" },
      };
    case "media":
      return {
        sourceKind: kind,
        sourcePath: "input.jpg",
        fileExtension: "jpg",
        mediaKind: "image",
        mimeType: "image/jpeg",
        sanitizeInput: true,
        validateMime: true,
        stripMetadata: true,
        payload: { file: "input.jpg", mediaKind: "image", extension: "jpg" },
        schema: { type: "object" },
      };
    case "dataset":
      return {
        sourceKind: kind,
        mimeType: "application/json",
        sanitizeInput: true,
        validateMime: true,
        payload: { rows: [], schema: {} },
        schema: { type: "object" },
      };
    case "api_payload":
      return {
        sourceKind: kind,
        mimeType: "application/json",
        sanitizeInput: true,
        validateMime: true,
        payload: { body: {} },
        schema: { type: "object" },
      };
    case "manual":
    default:
      return {
        sourceKind: "manual",
        payload: { request: "Describe the input for this workflow." },
        schema: { type: "object" },
      };
  }
}

export function WorkflowNodeBindingEditor({
  node,
  logic,
  law,
  sectionStatus,
  sectionDetail,
  modelAttachmentCounts,
  dryRunView,
  onUpdate,
  updateLogic,
  onDryRun,
}: WorkflowNodeBindingEditorProps) {
  return (
    <section
      className="workflow-config-section-block"
      data-config-section="bindings"
      data-testid="workflow-config-section-bindings"
      tabIndex={-1}
    >
      <header>
        <div>
          <h4>Bindings</h4>
          <p>Runtime-specific settings for this primitive.</p>
        </div>
        <span data-section-status={sectionStatus}>{sectionDetail}</span>
      </header>
      {node.type === "source" ? (
        <>
          <label>
            Input kind
            <select
              data-testid="workflow-source-kind"
              value={String(logic.sourceKind ?? "manual")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  ...defaultSourceLogicForKind(
                    event.target.value as NonNullable<NodeLogic["sourceKind"]>,
                  ),
                })
              }
            >
              {SOURCE_KIND_OPTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          {logic.sourceKind === "file" || logic.sourceKind === "media" ? (
            <>
              <label>
                Source path
                <input
                  data-testid="workflow-source-path"
                  value={String(logic.sourcePath ?? "")}
                  placeholder="inputs/file.jpg"
                  onChange={(event) =>
                    updateLogic({ ...logic, sourcePath: event.target.value })
                  }
                />
              </label>
              <label>
                File extension
                <input
                  data-testid="workflow-source-extension"
                  value={String(logic.fileExtension ?? "")}
                  placeholder="jpg"
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      fileExtension: event.target.value,
                    })
                  }
                />
              </label>
              <label>
                MIME type
                <input
                  data-testid="workflow-source-mime"
                  value={String(logic.mimeType ?? "")}
                  placeholder="image/jpeg"
                  onChange={(event) =>
                    updateLogic({ ...logic, mimeType: event.target.value })
                  }
                />
              </label>
            </>
          ) : null}
          {logic.sourceKind === "media" ? (
            <label>
              Media kind
              <select
                data-testid="workflow-source-media-kind"
                value={String(logic.mediaKind ?? "image")}
                onChange={(event) =>
                  updateLogic({
                    ...logic,
                    mediaKind: event.target.value as NonNullable<
                      NodeLogic["mediaKind"]
                    >,
                  })
                }
              >
                {MEDIA_KIND_OPTIONS.map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          {logic.sourceKind === "file" ||
          logic.sourceKind === "media" ||
          logic.sourceKind === "dataset" ||
          logic.sourceKind === "api_payload" ? (
            <div className="workflow-config-checks">
              <label>
                <input
                  data-testid="workflow-source-sanitize-input"
                  type="checkbox"
                  checked={Boolean(logic.sanitizeInput)}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      sanitizeInput: event.target.checked,
                    })
                  }
                />
                Sanitize input
              </label>
              <label>
                <input
                  data-testid="workflow-source-validate-mime"
                  type="checkbox"
                  checked={Boolean(logic.validateMime)}
                  onChange={(event) =>
                    updateLogic({ ...logic, validateMime: event.target.checked })
                  }
                />
                Validate MIME
              </label>
              {logic.sourceKind === "media" ? (
                <label>
                  <input
                    data-testid="workflow-source-strip-metadata"
                    type="checkbox"
                    checked={Boolean(logic.stripMetadata)}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        stripMetadata: event.target.checked,
                      })
                    }
                  />
                  Strip metadata
                </label>
              ) : null}
            </div>
          ) : null}
          <label>
            Sample payload
            <textarea
              data-testid="workflow-source-payload"
              value={JSON.stringify(
                logic.payload ??
                  defaultSourceLogicForKind(
                    logic.sourceKind ?? "manual",
                  ).payload,
                null,
                2,
              )}
              onChange={(event) => {
                let payload: unknown = event.target.value;
                try {
                  payload = JSON.parse(event.target.value || "{}");
                } catch {
                  payload = event.target.value;
                }
                updateLogic({ ...logic, payload });
              }}
            />
          </label>
        </>
      ) : null}
      {node.type === "trigger" ? (
        <>
          <label>
            Trigger kind
            <select
              data-testid="workflow-trigger-kind"
              value={String(logic.triggerKind ?? "manual")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  triggerKind: event.target.value as
                    | "manual"
                    | "scheduled"
                    | "event",
                })
              }
            >
              <option value="manual">Manual</option>
              <option value="scheduled">Scheduled</option>
              <option value="event">Event</option>
            </select>
          </label>
          <label>
            Schedule
            <input
              data-testid="workflow-trigger-schedule"
              value={String(logic.cronSchedule ?? "")}
              placeholder="0 9 * * 1"
              onChange={(event) =>
                updateLogic({ ...logic, cronSchedule: event.target.value })
              }
            />
          </label>
          <label>
            Event source
            <input
              data-testid="workflow-trigger-event-source"
              value={String(logic.eventSourceRef ?? "")}
              placeholder="slack.channel.message"
              onChange={(event) =>
                updateLogic({ ...logic, eventSourceRef: event.target.value })
              }
            />
          </label>
          <label>
            Dedupe key
            <input
              data-testid="workflow-trigger-dedupe-key"
              value={String(logic.dedupeKey ?? "")}
              placeholder="{{event.id}}"
              onChange={(event) =>
                updateLogic({ ...logic, dedupeKey: event.target.value })
              }
            />
          </label>
        </>
      ) : null}
      {node.type === "model_call" ? (
        <>
          <div
            className="workflow-model-attachment-summary"
            data-testid="workflow-model-attachment-summary"
          >
            <span>Models {modelAttachmentCounts.model}</span>
            <span>Memory {modelAttachmentCounts.memory}</span>
            <span>Tools {modelAttachmentCounts.tool}</span>
            <span>Parsers {modelAttachmentCounts.parser}</span>
          </div>
          <label>
            Model binding
            <input
              data-testid="workflow-model-ref"
              value={String(logic.modelRef ?? "")}
              onChange={(event) =>
                onUpdate({
                  config: {
                    logic: {
                      ...logic,
                      modelRef: event.target.value,
                      modelBinding: {
                        modelRef: event.target.value,
                        mockBinding: logic.modelBinding?.mockBinding ?? true,
                        capabilityScope: logic.modelBinding
                          ?.capabilityScope ?? ["reasoning"],
                        argumentSchema: logic.modelBinding?.argumentSchema ??
                          logic.inputSchema ?? { type: "object" },
                        resultSchema: logic.modelBinding?.resultSchema ??
                          logic.outputSchema ?? { type: "object" },
                        sideEffectClass:
                          logic.modelBinding?.sideEffectClass ?? "none",
                        requiresApproval:
                          logic.modelBinding?.requiresApproval ?? false,
                        credentialReady:
                          logic.modelBinding?.credentialReady ?? false,
                        toolUseMode:
                          logic.modelBinding?.toolUseMode ??
                          logic.toolUseMode ??
                          "none",
                      },
                    },
                    law: node.config?.law ?? {},
                  },
                })
              }
            />
          </label>
          <label>
            Tool-use mode
            <select
              data-testid="workflow-model-tool-use-mode"
              value={String(
                logic.modelBinding?.toolUseMode ?? logic.toolUseMode ?? "none",
              )}
              onChange={(event) => {
                const toolUseMode = event.target.value as
                  | "none"
                  | "explicit"
                  | "auto";
                updateLogic({
                  ...logic,
                  toolUseMode,
                  modelBinding: {
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    mockBinding: logic.modelBinding?.mockBinding ?? true,
                    capabilityScope: logic.modelBinding?.capabilityScope ?? [
                      "reasoning",
                    ],
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema: logic.modelBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady:
                      logic.modelBinding?.credentialReady ?? false,
                    toolUseMode,
                  },
                });
              }}
            >
              <option value="none">None</option>
              <option value="explicit">Explicit tool ports</option>
              <option value="auto">Auto within bound tools</option>
            </select>
          </label>
          <label>
            Structured output schema
            <textarea
              data-testid="workflow-model-output-schema"
              value={JSON.stringify(
                logic.modelBinding?.resultSchema ??
                  logic.outputSchema ?? {
                    type: "object",
                    properties: { message: { type: "string" } },
                  },
                null,
                2,
              )}
              onChange={(event) => {
                const resultSchema = parseJsonField(
                  event.target.value,
                  logic.modelBinding?.resultSchema ??
                    logic.outputSchema ?? { type: "object" },
                ) as WorkflowJsonSchema;
                updateLogic({
                  ...logic,
                  outputSchema: resultSchema,
                  modelBinding: {
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    mockBinding: logic.modelBinding?.mockBinding ?? true,
                    capabilityScope: logic.modelBinding?.capabilityScope ?? [
                      "reasoning",
                    ],
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema,
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady:
                      logic.modelBinding?.credentialReady ?? false,
                    toolUseMode:
                      logic.modelBinding?.toolUseMode ??
                      logic.toolUseMode ??
                      "none",
                  },
                });
              }}
            />
          </label>
          <label>
            Parser ref
            <input
              data-testid="workflow-model-parser-ref"
              value={String(logic.parserRef ?? "")}
              placeholder="optional parser node or binding"
              onChange={(event) =>
                updateLogic({ ...logic, parserRef: event.target.value })
              }
            />
          </label>
          <label>
            Memory key
            <input
              data-testid="workflow-model-memory-key"
              value={String(logic.memoryKey ?? "")}
              placeholder="optional state key"
              onChange={(event) =>
                updateLogic({ ...logic, memoryKey: event.target.value })
              }
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-model-structured-validation"
              type="checkbox"
              checked={Boolean(
                logic.validateStructuredOutput ?? logic.jsonMode,
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  validateStructuredOutput: event.target.checked,
                  jsonMode: event.target.checked,
                })
              }
            />
            Validate structured output
          </label>
          <label>
            Prompt
            <textarea
              data-testid="workflow-model-prompt"
              value={String(logic.prompt ?? "")}
              onChange={(event) =>
                onUpdate({
                  config: {
                    logic: { ...logic, prompt: event.target.value },
                    law: node.config?.law ?? {},
                  },
                })
              }
            />
          </label>
        </>
      ) : null}
      {node.type === "model_binding" ? (
        <>
          <label>
            Model ref
            <input
              data-testid="workflow-model-binding-ref"
              value={String(
                logic.modelBinding?.modelRef ?? logic.modelRef ?? "",
              )}
              placeholder="reasoning"
              onChange={(event) => {
                const modelRef = event.target.value;
                updateLogic({
                  ...logic,
                  modelRef,
                  modelBinding: {
                    modelRef,
                    mockBinding: logic.modelBinding?.mockBinding ?? true,
                    capabilityScope: logic.modelBinding?.capabilityScope ?? [
                      "reasoning",
                    ],
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema: logic.modelBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady:
                      logic.modelBinding?.credentialReady ?? false,
                    toolUseMode: logic.modelBinding?.toolUseMode ?? "none",
                  },
                });
              }}
            />
          </label>
          <label>
            Capability scope
            <input
              data-testid="workflow-model-binding-capability-scope"
              value={(
                logic.modelBinding?.capabilityScope ?? ["reasoning"]
              ).join(", ")}
              placeholder="reasoning, vision"
              onChange={(event) => {
                const capabilityScope = event.target.value
                  .split(",")
                  .map((value) => value.trim())
                  .filter(Boolean);
                updateLogic({
                  ...logic,
                  modelBinding: {
                    modelRef: String(
                      logic.modelBinding?.modelRef ??
                        logic.modelRef ??
                        "reasoning",
                    ),
                    mockBinding: logic.modelBinding?.mockBinding ?? true,
                    capabilityScope,
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema: logic.modelBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady:
                      logic.modelBinding?.credentialReady ?? false,
                    toolUseMode: logic.modelBinding?.toolUseMode ?? "none",
                  },
                });
              }}
            />
          </label>
          <label>
            Result schema
            <textarea
              data-testid="workflow-model-binding-result-schema"
              value={JSON.stringify(
                logic.modelBinding?.resultSchema ??
                  logic.outputSchema ?? { type: "object" },
                null,
                2,
              )}
              onChange={(event) => {
                const resultSchema = parseJsonField(
                  event.target.value,
                  logic.modelBinding?.resultSchema ??
                    logic.outputSchema ?? { type: "object" },
                ) as WorkflowJsonSchema;
                updateLogic({
                  ...logic,
                  outputSchema: resultSchema,
                  modelBinding: {
                    modelRef: String(
                      logic.modelBinding?.modelRef ??
                        logic.modelRef ??
                        "reasoning",
                    ),
                    mockBinding: logic.modelBinding?.mockBinding ?? true,
                    capabilityScope: logic.modelBinding?.capabilityScope ?? [
                      "reasoning",
                    ],
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema,
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady:
                      logic.modelBinding?.credentialReady ?? false,
                    toolUseMode: logic.modelBinding?.toolUseMode ?? "none",
                  },
                });
              }}
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-model-binding-mock-mode"
              type="checkbox"
              checked={logic.modelBinding?.mockBinding !== false}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  modelBinding: {
                    modelRef: String(
                      logic.modelBinding?.modelRef ??
                        logic.modelRef ??
                        "reasoning",
                    ),
                    mockBinding: event.target.checked,
                    capabilityScope: logic.modelBinding?.capabilityScope ?? [
                      "reasoning",
                    ],
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema: logic.modelBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady:
                      logic.modelBinding?.credentialReady ?? false,
                    toolUseMode: logic.modelBinding?.toolUseMode ?? "none",
                  },
                })
              }
            />
            Mock model binding
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-model-binding-credential-ready"
              type="checkbox"
              checked={Boolean(logic.modelBinding?.credentialReady)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  modelBinding: {
                    modelRef: String(
                      logic.modelBinding?.modelRef ??
                        logic.modelRef ??
                        "reasoning",
                    ),
                    mockBinding: logic.modelBinding?.mockBinding ?? true,
                    capabilityScope: logic.modelBinding?.capabilityScope ?? [
                      "reasoning",
                    ],
                    argumentSchema: logic.modelBinding?.argumentSchema ??
                      logic.inputSchema ?? { type: "object" },
                    resultSchema: logic.modelBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    sideEffectClass:
                      logic.modelBinding?.sideEffectClass ?? "none",
                    requiresApproval:
                      logic.modelBinding?.requiresApproval ?? false,
                    credentialReady: event.target.checked,
                    toolUseMode: logic.modelBinding?.toolUseMode ?? "none",
                  },
                })
              }
            />
            Live credentials ready
          </label>
        </>
      ) : null}
      {node.type === "parser" ? (
        <>
          <label>
            Parser ref
            <input
              data-testid="workflow-parser-ref"
              value={String(
                logic.parserBinding?.parserRef ?? logic.parserRef ?? "",
              )}
              placeholder="json_schema"
              onChange={(event) => {
                const parserRef = event.target.value;
                updateLogic({
                  ...logic,
                  parserRef,
                  parserBinding: {
                    parserRef,
                    parserKind:
                      logic.parserBinding?.parserKind ?? "json_schema",
                    resultSchema: logic.parserBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    mockBinding: logic.parserBinding?.mockBinding ?? true,
                  },
                });
              }}
            />
          </label>
          <label>
            Parser kind
            <select
              data-testid="workflow-parser-kind"
              value={String(logic.parserBinding?.parserKind ?? "json_schema")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  parserBinding: {
                    parserRef: String(
                      logic.parserBinding?.parserRef ??
                        logic.parserRef ??
                        "json_schema",
                    ),
                    parserKind: event.target.value as
                      | "json_schema"
                      | "structured_output"
                      | "text",
                    resultSchema: logic.parserBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    mockBinding: logic.parserBinding?.mockBinding ?? true,
                  },
                })
              }
            >
              <option value="json_schema">JSON schema</option>
              <option value="structured_output">Structured output</option>
              <option value="text">Text parser</option>
            </select>
          </label>
          <label>
            Result schema
            <textarea
              data-testid="workflow-parser-result-schema"
              value={JSON.stringify(
                logic.parserBinding?.resultSchema ??
                  logic.outputSchema ?? { type: "object" },
                null,
                2,
              )}
              onChange={(event) => {
                const resultSchema = parseJsonField(
                  event.target.value,
                  logic.parserBinding?.resultSchema ??
                    logic.outputSchema ?? { type: "object" },
                ) as WorkflowJsonSchema;
                updateLogic({
                  ...logic,
                  outputSchema: resultSchema,
                  parserBinding: {
                    parserRef: String(
                      logic.parserBinding?.parserRef ??
                        logic.parserRef ??
                        "json_schema",
                    ),
                    parserKind:
                      logic.parserBinding?.parserKind ?? "json_schema",
                    resultSchema,
                    mockBinding: logic.parserBinding?.mockBinding ?? true,
                  },
                });
              }}
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-parser-mock-binding"
              type="checkbox"
              checked={logic.parserBinding?.mockBinding !== false}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  parserBinding: {
                    parserRef: String(
                      logic.parserBinding?.parserRef ??
                        logic.parserRef ??
                        "json_schema",
                    ),
                    parserKind:
                      logic.parserBinding?.parserKind ?? "json_schema",
                    resultSchema: logic.parserBinding?.resultSchema ??
                      logic.outputSchema ?? { type: "object" },
                    mockBinding: event.target.checked,
                  },
                })
              }
            />
            Mock parser binding
          </label>
        </>
      ) : null}
      {node.type === "function" ? (
        <WorkflowFunctionBindingEditor
          logic={logic}
          law={law}
          dryRunView={dryRunView}
          onUpdate={onUpdate}
          updateLogic={updateLogic}
          onDryRun={onDryRun}
        />
      ) : null}
      {node.type === "decision" ? (
        <>
          <label>
            Routes
            <input
              data-testid="workflow-decision-routes"
              value={(logic.routes ?? ["left", "right"]).join(", ")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  routes: event.target.value
                    .split(",")
                    .map((route) => route.trim())
                    .filter(Boolean),
                })
              }
            />
          </label>
          <label>
            Default route
            <input
              data-testid="workflow-decision-default-route"
              value={String(logic.defaultRoute ?? "left")}
              onChange={(event) =>
                updateLogic({ ...logic, defaultRoute: event.target.value })
              }
            />
          </label>
        </>
      ) : null}
      {node.type === "state" ? (
        <>
          <label>
            State key
            <input
              data-testid="workflow-state-key"
              value={String(logic.stateKey ?? "memory")}
              onChange={(event) =>
                updateLogic({ ...logic, stateKey: event.target.value })
              }
            />
          </label>
          <label>
            Operation
            <select
              data-testid="workflow-state-operation"
              value={String(logic.stateOperation ?? "merge")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  stateOperation: event.target.value as
                    | "read"
                    | "write"
                    | "append"
                    | "merge",
                  reducer:
                    event.target.value === "append"
                      ? "append"
                      : event.target.value === "merge"
                        ? "merge"
                        : "replace",
                })
              }
            >
              <option value="read">Read</option>
              <option value="write">Write</option>
              <option value="append">Append</option>
              <option value="merge">Merge</option>
            </select>
          </label>
          <label>
            Reducer
            <select
              data-testid="workflow-state-reducer"
              value={String(logic.reducer ?? "merge")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  reducer: event.target.value as
                    | "replace"
                    | "append"
                    | "merge",
                })
              }
            >
              <option value="replace">Replace state</option>
              <option value="append">Append item</option>
              <option value="merge">Merge object</option>
            </select>
          </label>
          <label>
            Initial value
            <textarea
              data-testid="workflow-state-initial-value"
              value={JSON.stringify(logic.initialValue ?? {}, null, 2)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  initialValue: parseJsonField(
                    event.target.value,
                    logic.initialValue ?? {},
                  ),
                })
              }
            />
          </label>
        </>
      ) : null}
      {node.type === "loop" ? (
        <>
          <label>
            Max iterations
            <input
              data-testid="workflow-loop-max-iterations"
              type="number"
              min={1}
              max={50}
              value={Number(logic.maxIterations ?? 3)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  maxIterations: Number(event.target.value),
                })
              }
            />
          </label>
          <label>
            Loop condition
            <textarea
              data-testid="workflow-loop-condition"
              value={String(
                logic.loopCondition ?? "return input.iteration < 3;",
              )}
              onChange={(event) =>
                updateLogic({ ...logic, loopCondition: event.target.value })
              }
            />
          </label>
        </>
      ) : null}
      {node.type === "barrier" ? (
        <label>
          Barrier strategy
          <select
            data-testid="workflow-barrier-strategy"
            value={String(logic.barrierStrategy ?? "all")}
            onChange={(event) =>
              updateLogic({
                ...logic,
                barrierStrategy: event.target.value as "all" | "any",
              })
            }
          >
            <option value="all">All inputs</option>
            <option value="any">Any input</option>
          </select>
        </label>
      ) : null}
      {node.type === "subgraph" ? (
        <>
          <label>
            Workflow path
            <input
              data-testid="workflow-subgraph-path"
              value={String(logic.subgraphRef?.workflowPath ?? "")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  subgraphRef: {
                    ...(logic.subgraphRef ?? { workflowPath: "" }),
                    workflowPath: event.target.value,
                  },
                })
              }
            />
          </label>
          <label>
            Input mapping
            <textarea
              data-testid="workflow-subgraph-input-mapping"
              value={JSON.stringify(
                logic.subgraphRef?.inputMapping ?? {},
                null,
                2,
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  subgraphRef: {
                    ...(logic.subgraphRef ?? { workflowPath: "" }),
                    inputMapping: parseJsonField(
                      event.target.value,
                      logic.subgraphRef?.inputMapping ?? {},
                    ) as Record<string, string>,
                  },
                })
              }
            />
          </label>
          <label>
            Output mapping
            <textarea
              data-testid="workflow-subgraph-output-mapping"
              value={JSON.stringify(
                logic.subgraphRef?.outputMapping ?? {},
                null,
                2,
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  subgraphRef: {
                    ...(logic.subgraphRef ?? { workflowPath: "" }),
                    outputMapping: parseJsonField(
                      event.target.value,
                      logic.subgraphRef?.outputMapping ?? {},
                    ) as Record<string, string>,
                  },
                })
              }
            />
          </label>
          <div
            className="workflow-config-two-column"
            data-testid="workflow-subgraph-run-controls"
          >
            <label>
              Timeout ms
              <input
                data-testid="workflow-subgraph-timeout"
                type="number"
                min={1000}
                value={Number(logic.timeoutMs ?? 30000)}
                onChange={(event) =>
                  updateLogic({
                    ...logic,
                    timeoutMs: Number(event.target.value),
                  })
                }
              />
            </label>
            <label>
              Attempts
              <input
                data-testid="workflow-subgraph-attempts"
                type="number"
                min={1}
                max={5}
                value={Number(logic.retry?.maxAttempts ?? 1)}
                onChange={(event) =>
                  updateLogic({
                    ...logic,
                    retry: {
                      ...(logic.retry ?? {}),
                      maxAttempts: Number(event.target.value),
                    },
                  })
                }
              />
            </label>
          </div>
        </>
      ) : null}
      {node.type === "human_gate" ? (
        <label>
          Approval prompt
          <textarea
            data-testid="workflow-human-gate-prompt"
            value={String(
              logic.text ??
                "Review and approve this workflow step before continuing.",
            )}
            onChange={(event) =>
              onUpdate({
                config: {
                  logic: { ...logic, text: event.target.value },
                  law: { ...law, requireHumanGate: true },
                },
              })
            }
          />
        </label>
      ) : null}
      {node.type === "output" ? (
        <>
          <label>
            Output format
            <select
              data-testid="workflow-output-format"
              value={String(logic.format ?? "report")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  format: event.target.value as (typeof OUTPUT_FORMAT_OPTIONS)[number][0],
                })
              }
            >
              {OUTPUT_FORMAT_OPTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Renderer
            <select
              data-testid="workflow-output-renderer"
              value={String(
                asRecord(logic.rendererRef).rendererId ?? "markdown",
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  rendererRef: {
                    ...asRecord(logic.rendererRef),
                    rendererId: event.target.value,
                    displayMode: String(
                      asRecord(logic.rendererRef).displayMode ?? "inline",
                    ) as
                      | "inline"
                      | "canvas_preview"
                      | "table"
                      | "json"
                      | "media"
                      | "diff"
                      | "report"
                      | "artifact_panel",
                  },
                })
              }
            >
              {OUTPUT_RENDERER_OPTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Display mode
            <select
              data-testid="workflow-output-display-mode"
              value={String(
                asRecord(logic.rendererRef).displayMode ?? "inline",
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  rendererRef: {
                    ...asRecord(logic.rendererRef),
                    rendererId: String(
                      asRecord(logic.rendererRef).rendererId ?? "markdown",
                    ),
                    displayMode: event.target.value as
                      | "inline"
                      | "canvas_preview"
                      | "table"
                      | "json"
                      | "media"
                      | "diff"
                      | "report"
                      | "artifact_panel",
                  },
                })
              }
            >
              {OUTPUT_DISPLAY_MODE_OPTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Asset path
            <input
              data-testid="workflow-output-asset-path"
              value={String(
                asRecord(logic.materialization).assetPath ?? logic.path ?? "",
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  materialization: {
                    ...asRecord(logic.materialization),
                    enabled: event.target.value.trim().length > 0,
                    assetPath: event.target.value,
                  },
                })
              }
              placeholder="optional materialized asset path"
            />
          </label>
          <label>
            Asset kind
            <select
              data-testid="workflow-output-asset-kind"
              value={String(asRecord(logic.materialization).assetKind ?? "file")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  materialization: {
                    ...asRecord(logic.materialization),
                    enabled:
                      Boolean(asRecord(logic.materialization).enabled) ||
                      String(asRecord(logic.materialization).assetPath ?? "")
                        .trim()
                        .length > 0,
                    assetKind: event.target.value as
                      | "file"
                      | "blob"
                      | "report"
                      | "svg"
                      | "chart"
                      | "patch"
                      | "dataset",
                  },
                })
              }
            >
              <option value="file">File</option>
              <option value="blob">Blob</option>
              <option value="report">Report</option>
              <option value="svg">SVG/media</option>
              <option value="chart">Chart</option>
              <option value="patch">Patch</option>
              <option value="dataset">Dataset/table</option>
            </select>
          </label>
          <label>
            Delivery target
            <select
              data-testid="workflow-output-delivery-target"
              value={String(
                asRecord(logic.deliveryTarget).targetKind ?? "none",
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  deliveryTarget: {
                    ...asRecord(logic.deliveryTarget),
                    targetKind: event.target.value as
                      | "none"
                      | "chat_inline"
                      | "local_file"
                      | "repo_patch"
                      | "ticket_draft"
                      | "message_draft"
                      | "connector_write"
                      | "deploy",
                  },
                })
              }
            >
              <option value="none">None</option>
              <option value="chat_inline">Chat inline</option>
              <option value="local_file">Local file</option>
              <option value="repo_patch">Repo patch</option>
              <option value="ticket_draft">Ticket draft</option>
              <option value="message_draft">Message draft</option>
              <option value="connector_write">Connector write</option>
              <option value="deploy">Deploy</option>
            </select>
          </label>
          <label>
            Delivery target ref
            <input
              data-testid="workflow-output-delivery-target-ref"
              value={String(asRecord(logic.deliveryTarget).targetRef ?? "")}
              placeholder="channel, file path, ticket queue, deploy target"
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  deliveryTarget: {
                    ...asRecord(logic.deliveryTarget),
                    targetKind: String(
                      asRecord(logic.deliveryTarget).targetKind ?? "none",
                    ) as
                      | "none"
                      | "chat_inline"
                      | "local_file"
                      | "repo_patch"
                      | "ticket_draft"
                      | "message_draft"
                      | "connector_write"
                      | "deploy",
                    targetRef: event.target.value,
                  },
                })
              }
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-output-delivery-approval"
              type="checkbox"
              checked={Boolean(asRecord(logic.deliveryTarget).requiresApproval)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  deliveryTarget: {
                    ...asRecord(logic.deliveryTarget),
                    targetKind: String(
                      asRecord(logic.deliveryTarget).targetKind ?? "none",
                    ) as
                      | "none"
                      | "chat_inline"
                      | "local_file"
                      | "repo_patch"
                      | "ticket_draft"
                      | "message_draft"
                      | "connector_write"
                      | "deploy",
                    requiresApproval: event.target.checked,
                  },
                })
              }
            />
            Require approval before delivery
          </label>
          <label>
            Retention/versioning
            <select
              data-testid="workflow-output-retention"
              value={String(
                asRecord(logic.retentionPolicy).retentionKind ?? "run_scoped",
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  retentionPolicy: {
                    ...asRecord(logic.retentionPolicy),
                    retentionKind: event.target.value as
                      | "ephemeral"
                      | "run_scoped"
                      | "workflow_scoped"
                      | "versioned",
                  },
                  versioning: {
                    ...asRecord(logic.versioning),
                    enabled: true,
                  },
                })
              }
            >
              <option value="ephemeral">Ephemeral</option>
              <option value="run_scoped">Run scoped</option>
              <option value="workflow_scoped">Workflow scoped</option>
              <option value="versioned">Versioned</option>
            </select>
          </label>
        </>
      ) : null}
      {node.type === "test_assertion" ? (
        <>
          <label>
            Assertion
            <select
              data-testid="workflow-node-test-assertion-kind"
              value={String(
                logic.assertionKind ?? logic.assertion?.kind ?? "node_exists",
              )}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  assertionKind: event.target
                    .value as WorkflowTestCase["assertion"]["kind"],
                })
              }
            >
              <option value="node_exists">Input exists</option>
              <option value="schema_matches">Input matches schema</option>
              <option value="output_contains">Input contains value</option>
              <option value="custom">Custom sandbox assertion</option>
            </select>
          </label>
          <label>
            Expected
            <textarea
              data-testid="workflow-node-test-expected"
              value={JSON.stringify(logic.expected ?? {}, null, 2)}
              onChange={(event) => {
                let expected: unknown = event.target.value;
                try {
                  expected = JSON.parse(event.target.value || "{}");
                } catch {
                  expected = event.target.value;
                }
                updateLogic({ ...logic, expected });
              }}
            />
          </label>
          <label>
            Custom expression
            <textarea
              data-testid="workflow-node-test-expression"
              value={String(logic.expression ?? "")}
              onChange={(event) =>
                updateLogic({ ...logic, expression: event.target.value })
              }
              placeholder="return input.value.result?.passed === true;"
            />
          </label>
        </>
      ) : null}
      {node.type === "proposal" ? (
        <>
          <label>
            Proposal action
            <select
              data-testid="workflow-proposal-action"
              value={String(logic.proposalAction?.actionKind ?? "create")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  proposalAction: {
                    ...(logic.proposalAction ?? {
                      actionKind: "create",
                      boundedTargets: [],
                      requiresApproval: true,
                    }),
                    actionKind: event.target.value as
                      | "create"
                      | "preview"
                      | "apply",
                    requiresApproval: true,
                  },
                })
              }
            >
              <option value="create">Create</option>
              <option value="preview">Preview</option>
              <option value="apply">Apply</option>
            </select>
          </label>
          <label>
            Bounded targets
            <input
              data-testid="workflow-proposal-bounds"
              value={(logic.proposalAction?.boundedTargets ?? []).join(", ")}
              placeholder="node-a, tests, function-file"
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  proposalAction: {
                    ...(logic.proposalAction ?? {
                      actionKind: "create",
                      boundedTargets: [],
                      requiresApproval: true,
                    }),
                    boundedTargets: event.target.value
                      .split(",")
                      .map((item) => item.trim())
                      .filter(Boolean),
                    requiresApproval: true,
                  },
                })
              }
            />
          </label>
          <label>
            Proposal summary
            <textarea
              data-testid="workflow-proposal-summary"
              value={String(
                logic.text ??
                  "Describe the bounded graph, config, code, or test change.",
              )}
              onChange={(event) =>
                updateLogic({ ...logic, text: event.target.value })
              }
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-proposal-requires-approval"
              type="checkbox"
              checked={logic.proposalAction?.requiresApproval !== false}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  proposalAction: {
                    ...(logic.proposalAction ?? {
                      actionKind: "create",
                      boundedTargets: [],
                    }),
                    requiresApproval: event.target.checked,
                  },
                })
              }
            />
            Require explicit apply approval
          </label>
        </>
      ) : null}
      {node.type === "adapter" ? (
        <>
          <label>
            Connector ref
            <input
              data-testid="workflow-connector-ref"
              value={String(logic.connectorBinding?.connectorRef ?? "")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: event.target.value,
                    mockBinding: logic.connectorBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.connectorBinding?.credentialReady ?? false,
                    capabilityScope: logic.connectorBinding
                      ?.capabilityScope ?? ["read"],
                    sideEffectClass:
                      logic.connectorBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.connectorBinding?.requiresApproval ?? false,
                    operation: logic.connectorBinding?.operation ?? "read",
                  },
                })
              }
            />
          </label>
          <label>
            Binding mode
            <select
              data-testid="workflow-connector-binding-mode"
              value={
                logic.connectorBinding?.mockBinding === false ? "live" : "mock"
              }
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: logic.connectorBinding?.connectorRef ?? "",
                    mockBinding: event.target.value !== "live",
                    credentialReady:
                      event.target.value === "live"
                        ? (logic.connectorBinding?.credentialReady ?? false)
                        : false,
                    capabilityScope: logic.connectorBinding
                      ?.capabilityScope ?? ["read"],
                    sideEffectClass:
                      logic.connectorBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.connectorBinding?.requiresApproval ?? false,
                    operation: logic.connectorBinding?.operation ?? "read",
                  },
                })
              }
            >
              <option value="mock">Mock/sandbox</option>
              <option value="live">Live credentials</option>
            </select>
          </label>
          <label>
            Operation
            <input
              data-testid="workflow-connector-operation"
              value={String(logic.connectorBinding?.operation ?? "read")}
              placeholder="read, search, create_ticket, send_message"
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: logic.connectorBinding?.connectorRef ?? "",
                    mockBinding: logic.connectorBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.connectorBinding?.credentialReady ?? false,
                    capabilityScope:
                      logic.connectorBinding?.capabilityScope ?? ["read"],
                    sideEffectClass:
                      logic.connectorBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.connectorBinding?.requiresApproval ?? false,
                    operation: event.target.value,
                  },
                })
              }
            />
          </label>
          <label>
            Capability scope
            <input
              data-testid="workflow-connector-capability-scope"
              value={(logic.connectorBinding?.capabilityScope ?? ["read"]).join(
                ", ",
              )}
              placeholder="read, write, ticket:create"
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: logic.connectorBinding?.connectorRef ?? "",
                    mockBinding: logic.connectorBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.connectorBinding?.credentialReady ?? false,
                    capabilityScope: event.target.value
                      .split(",")
                      .map((item) => item.trim())
                      .filter(Boolean),
                    sideEffectClass:
                      logic.connectorBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.connectorBinding?.requiresApproval ?? false,
                    operation: logic.connectorBinding?.operation ?? "read",
                  },
                })
              }
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-connector-credential-ready"
              type="checkbox"
              checked={logic.connectorBinding?.credentialReady === true}
              disabled={logic.connectorBinding?.mockBinding !== false}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: logic.connectorBinding?.connectorRef ?? "",
                    mockBinding: logic.connectorBinding?.mockBinding ?? true,
                    credentialReady: event.target.checked,
                    capabilityScope: logic.connectorBinding
                      ?.capabilityScope ?? ["read"],
                    sideEffectClass:
                      logic.connectorBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.connectorBinding?.requiresApproval ?? false,
                    operation: logic.connectorBinding?.operation ?? "read",
                  },
                })
              }
            />
            Credentials ready
          </label>
          <label>
            Side effect
            <select
              data-testid="workflow-connector-side-effect"
              value={logic.connectorBinding?.sideEffectClass ?? "read"}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: logic.connectorBinding?.connectorRef ?? "",
                    mockBinding: logic.connectorBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.connectorBinding?.credentialReady ?? false,
                    capabilityScope: logic.connectorBinding
                      ?.capabilityScope ?? ["read"],
                    sideEffectClass: event.target.value as any,
                    requiresApproval:
                      event.target.value !== "read" &&
                      event.target.value !== "none",
                    operation: logic.connectorBinding?.operation ?? "read",
                  },
                })
              }
            >
              {[
                "read",
                "write",
                "external_write",
                "financial_write",
                "admin",
              ].map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-connector-requires-approval"
              type="checkbox"
              checked={Boolean(logic.connectorBinding?.requiresApproval)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  connectorBinding: {
                    connectorRef: logic.connectorBinding?.connectorRef ?? "",
                    mockBinding: logic.connectorBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.connectorBinding?.credentialReady ?? false,
                    capabilityScope:
                      logic.connectorBinding?.capabilityScope ?? ["read"],
                    sideEffectClass:
                      logic.connectorBinding?.sideEffectClass ?? "read",
                    requiresApproval: event.target.checked,
                    operation: logic.connectorBinding?.operation ?? "read",
                  },
                })
              }
            />
            Require approval for connector action
          </label>
        </>
      ) : null}
      {node.type === "plugin_tool" ? (
        <>
          <label>
            Tool kind
            <select
              data-testid="workflow-tool-kind"
              value={String(logic.toolBinding?.bindingKind ?? "plugin_tool")}
              onChange={(event) => {
                const bindingKind = event.target.value as
                  | "plugin_tool"
                  | "mcp_tool"
                  | "workflow_tool";
                updateLogic({
                  ...logic,
                  toolBinding: {
                    toolRef:
                      bindingKind === "workflow_tool"
                        ? "workflow_tool"
                        : (logic.toolBinding?.toolRef ?? ""),
                    bindingKind,
                    mockBinding:
                      bindingKind === "workflow_tool"
                        ? false
                        : (logic.toolBinding?.mockBinding ?? true),
                    credentialReady:
                      bindingKind === "workflow_tool"
                        ? true
                        : (logic.toolBinding?.credentialReady ?? false),
                    capabilityScope:
                      bindingKind === "workflow_tool"
                        ? ["invoke"]
                        : (logic.toolBinding?.capabilityScope ?? ["read"]),
                    sideEffectClass:
                      logic.toolBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.toolBinding?.requiresApproval ?? false,
                    arguments: logic.toolBinding?.arguments ?? {},
                    workflowTool:
                      bindingKind === "workflow_tool"
                        ? (logic.toolBinding?.workflowTool ?? {
                            workflowPath: "",
                            argumentSchema: { type: "object" },
                            resultSchema: { type: "object" },
                            timeoutMs: 30000,
                            maxAttempts: 1,
                          })
                        : undefined,
                  },
                });
              }}
            >
              <option value="plugin_tool">Plugin tool</option>
              <option value="mcp_tool">MCP tool</option>
              <option value="workflow_tool">Workflow tool</option>
            </select>
          </label>
          <label>
            Tool ref
            <input
              data-testid="workflow-tool-ref"
              value={String(logic.toolBinding?.toolRef ?? "")}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  toolBinding: {
                    toolRef: event.target.value,
                    bindingKind:
                      logic.toolBinding?.bindingKind ?? "plugin_tool",
                    mockBinding: logic.toolBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.toolBinding?.credentialReady ?? false,
                    capabilityScope: logic.toolBinding?.capabilityScope ?? [
                      "read",
                    ],
                    sideEffectClass:
                      logic.toolBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.toolBinding?.requiresApproval ?? false,
                    arguments: logic.toolBinding?.arguments ?? {},
                    workflowTool: logic.toolBinding?.workflowTool,
                  },
                })
              }
            />
          </label>
          {logic.toolBinding?.bindingKind === "workflow_tool" ? (
            <section
              className="workflow-tool-contract"
              data-testid="workflow-tool-contract"
            >
              <label>
                Child workflow path
                <input
                  data-testid="workflow-tool-child-path"
                  value={String(
                    logic.toolBinding?.workflowTool?.workflowPath ?? "",
                  )}
                  placeholder=".agents/workflows/child.workflow.json"
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      toolBinding: {
                        toolRef: logic.toolBinding?.toolRef ?? "workflow_tool",
                        bindingKind: "workflow_tool",
                        mockBinding: false,
                        capabilityScope: logic.toolBinding?.capabilityScope ?? [
                          "invoke",
                        ],
                        sideEffectClass:
                          logic.toolBinding?.sideEffectClass ?? "read",
                        requiresApproval:
                          logic.toolBinding?.requiresApproval ?? false,
                        arguments: logic.toolBinding?.arguments ?? {},
                        workflowTool: {
                          workflowPath: event.target.value,
                          argumentSchema: logic.toolBinding?.workflowTool
                            ?.argumentSchema ?? { type: "object" },
                          resultSchema: logic.toolBinding?.workflowTool
                            ?.resultSchema ?? { type: "object" },
                          timeoutMs:
                            logic.toolBinding?.workflowTool?.timeoutMs ?? 30000,
                          maxAttempts:
                            logic.toolBinding?.workflowTool?.maxAttempts ?? 1,
                        },
                      },
                    })
                  }
                />
              </label>
              <div className="workflow-tool-contract-grid">
                <label>
                  Timeout ms
                  <input
                    data-testid="workflow-tool-timeout-ms"
                    type="number"
                    min={1}
                    value={Number(
                      logic.toolBinding?.workflowTool?.timeoutMs ?? 30000,
                    )}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef:
                            logic.toolBinding?.toolRef ?? "workflow_tool",
                          bindingKind: "workflow_tool",
                          mockBinding: false,
                          capabilityScope: logic.toolBinding
                            ?.capabilityScope ?? ["invoke"],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          workflowTool: {
                            workflowPath:
                              logic.toolBinding?.workflowTool?.workflowPath ??
                              "",
                            argumentSchema: logic.toolBinding?.workflowTool
                              ?.argumentSchema ?? { type: "object" },
                            resultSchema: logic.toolBinding?.workflowTool
                              ?.resultSchema ?? { type: "object" },
                            timeoutMs: Number(event.target.value || 0),
                            maxAttempts:
                              logic.toolBinding?.workflowTool?.maxAttempts ?? 1,
                          },
                        },
                      })
                    }
                  />
                </label>
                <label>
                  Max attempts
                  <input
                    data-testid="workflow-tool-max-attempts"
                    type="number"
                    min={1}
                    max={5}
                    value={Number(
                      logic.toolBinding?.workflowTool?.maxAttempts ?? 1,
                    )}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef:
                            logic.toolBinding?.toolRef ?? "workflow_tool",
                          bindingKind: "workflow_tool",
                          mockBinding: false,
                          capabilityScope: logic.toolBinding
                            ?.capabilityScope ?? ["invoke"],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          workflowTool: {
                            workflowPath:
                              logic.toolBinding?.workflowTool?.workflowPath ??
                              "",
                            argumentSchema: logic.toolBinding?.workflowTool
                              ?.argumentSchema ?? { type: "object" },
                            resultSchema: logic.toolBinding?.workflowTool
                              ?.resultSchema ?? { type: "object" },
                            timeoutMs:
                              logic.toolBinding?.workflowTool?.timeoutMs ??
                              30000,
                            maxAttempts: Number(event.target.value || 0),
                          },
                        },
                      })
                    }
                  />
                </label>
              </div>
              <label>
                Argument schema
                <textarea
                  data-testid="workflow-tool-argument-schema"
                  value={JSON.stringify(
                    logic.toolBinding?.workflowTool?.argumentSchema ?? {
                      type: "object",
                    },
                    null,
                    2,
                  )}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      toolBinding: {
                        toolRef: logic.toolBinding?.toolRef ?? "workflow_tool",
                        bindingKind: "workflow_tool",
                        mockBinding: false,
                        capabilityScope: logic.toolBinding?.capabilityScope ?? [
                          "invoke",
                        ],
                        sideEffectClass:
                          logic.toolBinding?.sideEffectClass ?? "read",
                        requiresApproval:
                          logic.toolBinding?.requiresApproval ?? false,
                        arguments: logic.toolBinding?.arguments ?? {},
                        workflowTool: {
                          workflowPath:
                            logic.toolBinding?.workflowTool?.workflowPath ?? "",
                          argumentSchema: parseJsonField(
                            event.target.value,
                            logic.toolBinding?.workflowTool?.argumentSchema ?? {
                              type: "object",
                            },
                          ) as WorkflowJsonSchema,
                          resultSchema: logic.toolBinding?.workflowTool
                            ?.resultSchema ?? { type: "object" },
                          timeoutMs:
                            logic.toolBinding?.workflowTool?.timeoutMs ?? 30000,
                          maxAttempts:
                            logic.toolBinding?.workflowTool?.maxAttempts ?? 1,
                        },
                      },
                    })
                  }
                />
              </label>
              <label>
                Result schema
                <textarea
                  data-testid="workflow-tool-result-schema"
                  value={JSON.stringify(
                    logic.toolBinding?.workflowTool?.resultSchema ?? {
                      type: "object",
                    },
                    null,
                    2,
                  )}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      toolBinding: {
                        toolRef: logic.toolBinding?.toolRef ?? "workflow_tool",
                        bindingKind: "workflow_tool",
                        mockBinding: false,
                        capabilityScope: logic.toolBinding?.capabilityScope ?? [
                          "invoke",
                        ],
                        sideEffectClass:
                          logic.toolBinding?.sideEffectClass ?? "read",
                        requiresApproval:
                          logic.toolBinding?.requiresApproval ?? false,
                        arguments: logic.toolBinding?.arguments ?? {},
                        workflowTool: {
                          workflowPath:
                            logic.toolBinding?.workflowTool?.workflowPath ?? "",
                          argumentSchema: logic.toolBinding?.workflowTool
                            ?.argumentSchema ?? { type: "object" },
                          resultSchema: parseJsonField(
                            event.target.value,
                            logic.toolBinding?.workflowTool?.resultSchema ?? {
                              type: "object",
                            },
                          ) as WorkflowJsonSchema,
                          timeoutMs:
                            logic.toolBinding?.workflowTool?.timeoutMs ?? 30000,
                          maxAttempts:
                            logic.toolBinding?.workflowTool?.maxAttempts ?? 1,
                        },
                      },
                    })
                  }
                />
              </label>
            </section>
          ) : null}
          {logic.toolBinding?.bindingKind !== "workflow_tool" ? (
            <section
              className="workflow-tool-credential-contract"
              data-testid="workflow-tool-credential-contract"
            >
              <label>
                Binding mode
                <select
                  data-testid="workflow-tool-binding-mode"
                  value={
                    logic.toolBinding?.mockBinding === false ? "live" : "mock"
                  }
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      toolBinding: {
                        toolRef: logic.toolBinding?.toolRef ?? "",
                        bindingKind:
                          logic.toolBinding?.bindingKind ?? "plugin_tool",
                        mockBinding: event.target.value !== "live",
                        credentialReady:
                          event.target.value === "live"
                            ? (logic.toolBinding?.credentialReady ?? false)
                            : false,
                        capabilityScope: logic.toolBinding?.capabilityScope ?? [
                          "read",
                        ],
                        sideEffectClass:
                          logic.toolBinding?.sideEffectClass ?? "read",
                        requiresApproval:
                          logic.toolBinding?.requiresApproval ?? false,
                        arguments: logic.toolBinding?.arguments ?? {},
                        workflowTool: undefined,
                      },
                    })
                  }
                >
                  <option value="mock">Mock/sandbox</option>
                  <option value="live">Live credentials</option>
                </select>
              </label>
              <label className="workflow-config-checkbox-row">
                <input
                  data-testid="workflow-tool-credential-ready"
                  type="checkbox"
                  checked={logic.toolBinding?.credentialReady === true}
                  disabled={logic.toolBinding?.mockBinding !== false}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      toolBinding: {
                        toolRef: logic.toolBinding?.toolRef ?? "",
                        bindingKind:
                          logic.toolBinding?.bindingKind ?? "plugin_tool",
                        mockBinding: logic.toolBinding?.mockBinding ?? true,
                        credentialReady: event.target.checked,
                        capabilityScope: logic.toolBinding?.capabilityScope ?? [
                          "read",
                        ],
                        sideEffectClass:
                          logic.toolBinding?.sideEffectClass ?? "read",
                        requiresApproval:
                          logic.toolBinding?.requiresApproval ?? false,
                        arguments: logic.toolBinding?.arguments ?? {},
                        workflowTool: undefined,
                      },
                    })
                  }
                />
                Credentials ready
              </label>
            </section>
          ) : null}
          <label>
            Arguments
            <textarea
              data-testid="workflow-tool-arguments"
              value={JSON.stringify(
                logic.toolBinding?.arguments ?? {},
                null,
                2,
              )}
              onChange={(event) => {
                let args: Record<string, unknown> = {};
                try {
                  args = JSON.parse(event.target.value || "{}");
                } catch {
                  args = logic.toolBinding?.arguments ?? {};
                }
                updateLogic({
                  ...logic,
                  toolBinding: {
                    toolRef: logic.toolBinding?.toolRef ?? "",
                    bindingKind:
                      logic.toolBinding?.bindingKind ?? "plugin_tool",
                    mockBinding: logic.toolBinding?.mockBinding ?? true,
                    credentialReady:
                      logic.toolBinding?.credentialReady ?? false,
                    capabilityScope: logic.toolBinding?.capabilityScope ?? [
                      "read",
                    ],
                    sideEffectClass:
                      logic.toolBinding?.sideEffectClass ?? "read",
                    requiresApproval:
                      logic.toolBinding?.requiresApproval ?? false,
                    arguments: args,
                    workflowTool: logic.toolBinding?.workflowTool,
                  },
                });
              }}
            />
          </label>
        </>
      ) : null}
    </section>
  );
}
