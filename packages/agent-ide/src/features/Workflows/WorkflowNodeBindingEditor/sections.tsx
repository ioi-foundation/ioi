import { WorkflowFunctionBindingEditor } from "../WorkflowFunctionBindingEditor";
import {
  asRecord,
  defaultSourceLogicForKind,
  MEDIA_KIND_OPTIONS,
  OUTPUT_DISPLAY_MODE_OPTIONS,
  OUTPUT_FORMAT_OPTIONS,
  OUTPUT_RENDERER_OPTIONS,
  parseJsonField,
  SOURCE_KIND_OPTIONS,
} from "./helpers";
import type {
  NodeLogic,
  WorkflowJsonSchema,
  WorkflowTestCase,
} from "../../../types/graph";
import { WorkflowSubagentStateFields } from "./subagentFields";
import type { WorkflowNodeBindingSectionsProps } from "./types";

export function WorkflowNodeBindingSections({
  node,
  logic,
  law,
  modelAttachmentCounts,
  dryRunView,
  onUpdate,
  updateLogic,
  onDryRun,
}: WorkflowNodeBindingSectionsProps) {
  const skillContext: NonNullable<NodeLogic["skillContext"]> = logic.skillContext ?? {
    mode: "discover",
    goalSource: "node_input",
    goal: "",
    minScoreBps: 6500,
    maxSkills: 3,
    onNoMatch: "warn",
    pinnedSkills: [],
    onMissingPinned: "block",
    includeMarkdown: true,
    guidanceMaxChars: 1800,
  };
  const updateSkillContext = (
    next: NonNullable<NodeLogic["skillContext"]>,
  ) => updateLogic({ ...logic, skillContext: next });
  const codingToolPackDefaults = {
    pack: "coding",
    workspaceStatusEnabled: true,
    gitEnabled: true,
    filesystemEnabled: true,
    writeEnabled: true,
    testEnabled: true,
    diagnosticsEnabled: true,
    artifactEnabled: true,
    resultRetrievalEnabled: true,
    allowedTestCommandIds: ["node.test", "npm.test", "cargo.test", "cargo.check"],
    allowedDiagnosticCommandIds: ["auto", "node.check", "typescript.check"],
    diagnosticsMode: "advisory" as const,
    defaultDiagnosticCommandId: "auto",
    restorePolicy: "apply_with_approval" as const,
    restoreConflictPolicy: "block" as const,
    diagnosticsRepairDefault: "repair_retry" as const,
    operatorOverrideRequiresApproval: true,
    timeoutMs: 60000,
    dryRun: false,
    allowedPaths: [] as string[],
  };
  const codingToolPack = {
    ...codingToolPackDefaults,
    ...(logic.toolBinding?.toolPack ?? {}),
  };
  const mcpBinding = {
    serverId: "",
    toolName: "",
    catalogRef: "mcp.tool.catalog.read",
    catalogMode: "deferred",
    catalogSearchQuery: "",
    configSourceMode: "workspace_and_global",
    validateBeforeInvoke: true,
    containmentMode: "read_only" as const,
    ...(logic.toolBinding?.mcp ?? {}),
  };
  const mcpToolRefFor = (serverId: string, toolName: string) =>
    serverId.trim() && toolName.trim()
      ? `mcp.${serverId.trim()}.${toolName.trim()}`
      : (logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read");
  const mcpServerConfigPatch = (
    patch: Record<string, unknown>,
    logicPatch: Partial<NodeLogic> = {},
  ) => {
    const current = asRecord(
      parseJsonField(String(logic.mcpServerConfigJson ?? "{}"), {}),
    );
    updateLogic({
      ...logic,
      ...logicPatch,
      mcpServerConfigJson: JSON.stringify({ ...current, ...patch }, null, 2),
    });
  };
  const updateCodingToolPack = (nextPack: typeof codingToolPack) => {
    const capabilityScope = [
      nextPack.workspaceStatusEnabled ? "workspace.status" : null,
      nextPack.gitEnabled ? "git.diff" : null,
      nextPack.filesystemEnabled ? "file.inspect" : null,
      nextPack.writeEnabled ? "file.apply_patch" : null,
      nextPack.testEnabled ? "test.run" : null,
      nextPack.diagnosticsEnabled ? "lsp.diagnostics" : null,
      nextPack.artifactEnabled ? "artifact.read" : null,
      nextPack.resultRetrievalEnabled ? "tool.retrieve_result" : null,
    ].filter(Boolean) as string[];
    updateLogic({
      ...logic,
      toolBinding: {
        toolRef: logic.toolBinding?.toolRef ?? "workspace.status",
        bindingKind: "coding_tool_pack",
        mockBinding: false,
        credentialReady: true,
        capabilityScope,
        sideEffectClass: nextPack.writeEnabled ? "write" : "read",
        requiresApproval: Boolean(nextPack.writeEnabled && !nextPack.dryRun),
        arguments: logic.toolBinding?.arguments ?? {},
        toolPack: nextPack,
      },
    });
  };
  const modelBindingFor = (
    overrides: Partial<NonNullable<NodeLogic["modelBinding"]>> = {},
  ): NonNullable<NodeLogic["modelBinding"]> => ({
    modelRef: String(
      logic.modelBinding?.modelRef ?? logic.modelRef ?? "reasoning",
    ),
    modelId: logic.modelBinding?.modelId ?? logic.modelId,
    routeId: logic.modelBinding?.routeId ?? logic.routeId,
    reasoningEffort:
      logic.modelBinding?.reasoningEffort ??
      logic.reasoningEffort ??
      "medium",
    mockBinding: logic.modelBinding?.mockBinding ?? true,
    capabilityScope: logic.modelBinding?.capabilityScope ?? ["reasoning"],
    argumentSchema: logic.modelBinding?.argumentSchema ??
      logic.inputSchema ?? { type: "object" },
    resultSchema: logic.modelBinding?.resultSchema ??
      logic.outputSchema ?? { type: "object" },
    sideEffectClass: logic.modelBinding?.sideEffectClass ?? "none",
    requiresApproval: logic.modelBinding?.requiresApproval ?? false,
    credentialReady: logic.modelBinding?.credentialReady ?? false,
    toolUseMode: logic.modelBinding?.toolUseMode ?? logic.toolUseMode ?? "none",
    ...overrides,
  });

  return (
    <>
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
              {logic.stateOperation === "mcp_add" ? (
                <>
                  <label>
                    MCP label
                    <input
                      data-testid="workflow-state-mcp-server-label"
                      value={String(logic.mcpServerLabel ?? "")}
                      onChange={(event) =>
                        updateLogic({ ...logic, mcpServerLabel: event.target.value })
                      }
                    />
                  </label>
                  <label>
                    MCP server config JSON
                    <textarea
                      data-testid="workflow-state-mcp-server-config"
                      value={String(logic.mcpServerConfigJson ?? "{}")}
                      onChange={(event) =>
                        updateLogic({ ...logic, mcpServerConfigJson: event.target.value })
                      }
                    />
                  </label>
                </>
              ) : null}
              {logic.stateOperation === "mcp_import" ? (
                <label>
                  MCP import JSON
                  <textarea
                    data-testid="workflow-state-mcp-import-json"
                    value={String(logic.mcpImportJson ?? "{\"mcpServers\":{}}")}
                    onChange={(event) =>
                      updateLogic({ ...logic, mcpImportJson: event.target.value })
                    }
                  />
                </label>
              ) : null}
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
      {node.type === "skill_context" ? (
        <>
          <label>
            Skill mode
            <select
              data-testid="workflow-skill-context-mode"
              value={skillContext.mode}
              onChange={(event) =>
                updateSkillContext({
                  ...skillContext,
                  mode: event.target.value as "discover" | "pinned",
                })
              }
            >
              <option value="discover">Discover</option>
              <option value="pinned">Pinned</option>
            </select>
          </label>
          {skillContext.mode === "discover" ? (
            <>
              <label>
                Goal source
                <select
                  data-testid="workflow-skill-context-goal-source"
                  value={skillContext.goalSource ?? "node_input"}
                  onChange={(event) =>
                    updateSkillContext({
                      ...skillContext,
                      goalSource: event.target.value as
                        | "workflow_goal"
                        | "node_input"
                        | "static",
                    })
                  }
                >
                  <option value="node_input">Node input</option>
                  <option value="workflow_goal">Workflow goal</option>
                  <option value="static">Static goal</option>
                </select>
              </label>
              <label>
                Static goal
                <textarea
                  data-testid="workflow-skill-context-goal"
                  value={String(skillContext.goal ?? "")}
                  onChange={(event) =>
                    updateSkillContext({
                      ...skillContext,
                      goal: event.target.value,
                    })
                  }
                />
              </label>
              <label>
                Minimum score
                <input
                  data-testid="workflow-skill-context-min-score"
                  type="number"
                  min={0}
                  max={10000}
                  step={100}
                  value={Number(skillContext.minScoreBps ?? 6500)}
                  onChange={(event) =>
                    updateSkillContext({
                      ...skillContext,
                      minScoreBps: Number(event.target.value) || 0,
                    })
                  }
                />
              </label>
              <label>
                Max skills
                <input
                  data-testid="workflow-skill-context-max-skills"
                  type="number"
                  min={1}
                  max={10}
                  value={Number(skillContext.maxSkills ?? 3)}
                  onChange={(event) =>
                    updateSkillContext({
                      ...skillContext,
                      maxSkills: Number(event.target.value) || 1,
                    })
                  }
                />
              </label>
              <label>
                No match behavior
                <select
                  data-testid="workflow-skill-context-no-match"
                  value={skillContext.onNoMatch ?? "warn"}
                  onChange={(event) =>
                    updateSkillContext({
                      ...skillContext,
                      onNoMatch: event.target.value as "warn" | "block",
                    })
                  }
                >
                  <option value="warn">Warn</option>
                  <option value="block">Block</option>
                </select>
              </label>
            </>
          ) : (
            <>
              <label>
                Pinned skills
                <textarea
                  data-testid="workflow-skill-context-pinned-skills"
                  value={(skillContext.pinnedSkills ?? [])
                    .map((skill) => skill.skillHash || skill.name || "")
                    .join("\n")}
                  placeholder="skill hash or exact name, one per line"
                  onChange={(event) => {
                    const pinnedSkills = event.target.value
                      .split(/\n|,/)
                      .map((value) => value.trim())
                      .filter(Boolean)
                      .map((value) =>
                        value.length >= 16 || value.startsWith("sha")
                          ? { skillHash: value, required: true }
                          : { name: value, required: true },
                      );
                    updateSkillContext({ ...skillContext, pinnedSkills });
                  }}
                />
              </label>
              <label>
                Missing pinned behavior
                <select
                  data-testid="workflow-skill-context-missing-pinned"
                  value={skillContext.onMissingPinned ?? "block"}
                  onChange={(event) =>
                    updateSkillContext({
                      ...skillContext,
                      onMissingPinned: event.target.value as "warn" | "block",
                    })
                  }
                >
                  <option value="block">Block</option>
                  <option value="warn">Warn</option>
                </select>
              </label>
            </>
          )}
          <label>
            Guidance clipping
            <input
              data-testid="workflow-skill-context-guidance-max"
              type="number"
              min={200}
              max={12000}
              step={100}
              value={Number(skillContext.guidanceMaxChars ?? 1800)}
              onChange={(event) =>
                updateSkillContext({
                  ...skillContext,
                  guidanceMaxChars: Number(event.target.value) || 1800,
                })
              }
            />
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-skill-context-include-markdown"
              type="checkbox"
              checked={skillContext.includeMarkdown !== false}
              onChange={(event) =>
                updateSkillContext({
                  ...skillContext,
                  includeMarkdown: event.target.checked,
                })
              }
            />
            Include markdown guidance
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
                      modelBinding: modelBindingFor({
                        modelRef: event.target.value,
                      }),
                    },
                    law: node.config?.law ?? {},
                  },
                })
              }
            />
          </label>
          <label>
            Model id
            <input
              data-testid="workflow-model-id"
              value={String(logic.modelBinding?.modelId ?? logic.modelId ?? "")}
              placeholder="auto"
              onChange={(event) => {
                const modelId = event.target.value || null;
                updateLogic({
                  ...logic,
                  modelId,
                  modelBinding: modelBindingFor({
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    modelId,
                  }),
                });
              }}
            />
          </label>
          <label>
            Route
            <input
              data-testid="workflow-model-route-id"
              value={String(logic.modelBinding?.routeId ?? logic.routeId ?? "")}
              placeholder="route.local-first"
              onChange={(event) => {
                const routeId = event.target.value;
                updateLogic({
                  ...logic,
                  routeId,
                  modelBinding: modelBindingFor({
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    routeId,
                  }),
                });
              }}
            />
          </label>
          <label>
            Thinking
            <select
              data-testid="workflow-model-thinking"
              value={String(
                logic.modelBinding?.reasoningEffort ??
                  logic.reasoningEffort ??
                  "medium",
              )}
              onChange={(event) => {
                const reasoningEffort = event.target.value as
                  | "low"
                  | "medium"
                  | "high"
                  | "xhigh";
                updateLogic({
                  ...logic,
                  reasoningEffort,
                  modelBinding: modelBindingFor({
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    reasoningEffort,
                  }),
                });
              }}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="xhigh">XHigh</option>
            </select>
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
                  modelBinding: modelBindingFor({
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    toolUseMode,
                  }),
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
                  modelBinding: modelBindingFor({
                    modelRef: String(logic.modelRef ?? "reasoning"),
                    resultSchema,
                  }),
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
          <label>
            Memory scope
            <select
              data-testid="workflow-model-memory-scope"
              value={logic.memoryScope ?? "thread"}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  memoryScope: event.target.value as NonNullable<
                    NodeLogic["memoryScope"]
                  >,
                })
              }
            >
              <option value="thread">Thread</option>
              <option value="workflow">Workflow</option>
              <option value="workspace">Workspace</option>
              <option value="subagent">Subagent</option>
              <option value="global">Global</option>
            </select>
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-model-memory-injection-enabled"
              type="checkbox"
              checked={logic.memoryInjectionEnabled ?? true}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  memoryInjectionEnabled: event.target.checked,
                })
              }
            />
            Inject memory
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-model-memory-read-only"
              type="checkbox"
              checked={Boolean(logic.memoryReadOnly)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  memoryReadOnly: event.target.checked,
                })
              }
            />
            Read-only memory
          </label>
          <label className="workflow-config-checkbox-row">
            <input
              data-testid="workflow-model-memory-write-approval"
              type="checkbox"
              checked={Boolean(logic.memoryWriteRequiresApproval)}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  memoryWriteRequiresApproval: event.target.checked,
                })
              }
            />
            Require write approval
          </label>
          <label>
            Subagent memory
            <select
              data-testid="workflow-model-memory-subagent-inheritance"
              value={logic.memorySubagentInheritance ?? "explicit"}
              onChange={(event) =>
                updateLogic({
                  ...logic,
                  memorySubagentInheritance: event.target
                    .value as NonNullable<NodeLogic["memorySubagentInheritance"]>,
                })
              }
            >
              <option value="none">None</option>
              <option value="explicit">Explicit</option>
              <option value="read_only">Read only</option>
              <option value="full">Full</option>
            </select>
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
                  modelBinding: modelBindingFor({
                    modelRef,
                  }),
                });
              }}
            />
          </label>
          <label>
            Model id
            <input
              data-testid="workflow-model-binding-model-id"
              value={String(logic.modelBinding?.modelId ?? logic.modelId ?? "")}
              placeholder="auto"
              onChange={(event) => {
                const modelId = event.target.value || null;
                updateLogic({
                  ...logic,
                  modelId,
                  modelBinding: modelBindingFor({ modelId }),
                });
              }}
            />
          </label>
          <label>
            Route
            <input
              data-testid="workflow-model-binding-route-id"
              value={String(logic.modelBinding?.routeId ?? logic.routeId ?? "")}
              placeholder="route.local-first"
              onChange={(event) => {
                const routeId = event.target.value;
                updateLogic({
                  ...logic,
                  routeId,
                  modelBinding: modelBindingFor({ routeId }),
                });
              }}
            />
          </label>
          <label>
            Thinking
            <select
              data-testid="workflow-model-binding-thinking"
              value={String(
                logic.modelBinding?.reasoningEffort ??
                  logic.reasoningEffort ??
                  "medium",
              )}
              onChange={(event) => {
                const reasoningEffort = event.target.value as
                  | "low"
                  | "medium"
                  | "high"
                  | "xhigh";
                updateLogic({
                  ...logic,
                  reasoningEffort,
                  modelBinding: modelBindingFor({ reasoningEffort }),
                });
              }}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="xhigh">XHigh</option>
            </select>
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
                  modelBinding: modelBindingFor({
                    capabilityScope,
                  }),
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
                  modelBinding: modelBindingFor({
                    resultSchema,
                  }),
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
                  modelBinding: modelBindingFor({
                    mockBinding: event.target.checked,
                  }),
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
                  modelBinding: modelBindingFor({
                    credentialReady: event.target.checked,
                  }),
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
                  stateOperation: event.target
                    .value as NonNullable<NodeLogic["stateOperation"]>,
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
              <option value="mcp_status">MCP status</option>
              <option value="mcp_tool_search">MCP tool search</option>
              <option value="mcp_tool_fetch">MCP tool fetch</option>
              <option value="mcp_tool_invoke">MCP tool invoke</option>
              <option value="mcp_import">MCP import</option>
              <option value="mcp_add">MCP add</option>
              <option value="mcp_serve">MCP serve</option>
              <option value="mcp_remove">MCP remove</option>
              <option value="mcp_enable">MCP enable</option>
              <option value="mcp_disable">MCP disable</option>
              <option value="subagent_list">Subagent pool</option>
              <option value="subagent_spawn">Subagent spawn</option>
              <option value="subagent_wait">Subagent join/wait</option>
              <option value="subagent_result">Subagent result</option>
              <option value="subagent_send_input">Subagent send input</option>
              <option value="subagent_cancel">Subagent cancel</option>
              <option value="subagent_cancel_propagation">Subagent cancel propagation</option>
              <option value="subagent_resume">Subagent resume</option>
              <option value="subagent_assign">Subagent role assign</option>
              <option value="memory_status">Memory status</option>
              <option value="memory_policy">Memory policy</option>
              <option value="memory_search">Memory search</option>
              <option value="memory_list">Memory list</option>
              <option value="memory_remember">Memory remember</option>
              <option value="memory_edit">Memory edit</option>
              <option value="memory_delete">Memory delete</option>
            </select>
          </label>
          {logic.stateOperation === "mcp_status" ||
          logic.stateOperation === "mcp_tool_search" ||
          logic.stateOperation === "mcp_tool_fetch" ||
          logic.stateOperation === "mcp_tool_invoke" ||
          logic.stateOperation === "mcp_import" ||
          logic.stateOperation === "mcp_add" ||
          logic.stateOperation === "mcp_serve" ||
          logic.stateOperation === "mcp_remove" ||
          logic.stateOperation === "mcp_enable" ||
          logic.stateOperation === "mcp_disable" ? (
            <>
              {logic.stateOperation !== "mcp_serve" ? (
                <label>
                  MCP server
                  <input
                    data-testid="workflow-state-mcp-server-id"
                    value={String(logic.mcpServerId ?? "")}
                    onChange={(event) =>
                      updateLogic({ ...logic, mcpServerId: event.target.value })
                    }
                  />
                </label>
              ) : null}
              {logic.stateOperation === "mcp_status" ||
              logic.stateOperation === "mcp_tool_search" ||
              logic.stateOperation === "mcp_tool_fetch" ||
              logic.stateOperation === "mcp_tool_invoke" ? (
                <>
                  <label>
                    MCP config sources
                    <select
                      data-testid="workflow-state-mcp-config-source-mode"
                      value={String(logic.mcpConfigSourceMode ?? "workspace_and_global")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpConfigSourceMode: event.target.value,
                        })
                      }
                    >
                      <option value="workspace_and_global">Workspace + global IOI</option>
                      <option value="workspace">Workspace/thread only</option>
                      <option value="global">Global IOI only</option>
                    </select>
                  </label>
                  <label>
                    MCP catalog mode
                    <select
                      data-testid="workflow-state-mcp-catalog-mode"
                      value={String(logic.mcpCatalogMode ?? "summary")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpCatalogMode: event.target.value,
                        })
                      }
                    >
                      <option value="summary">Summary/deferred</option>
                      <option value="full">Full catalog</option>
                    </select>
                  </label>
                  <label>
                    MCP catalog preview limit
                    <input
                      data-testid="workflow-state-mcp-catalog-preview-limit"
                      type="number"
                      min={1}
                      max={200}
                      value={Number(logic.mcpToolCatalogPreviewLimit ?? 50)}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpToolCatalogPreviewLimit: Number(event.target.value || 0),
                        })
                      }
                    />
                  </label>
                </>
              ) : null}
              {logic.stateOperation === "mcp_tool_search" ? (
                <label>
                  MCP tool search
                  <input
                    data-testid="workflow-state-mcp-tool-search-query"
                    value={String(logic.mcpToolSearchQuery ?? "")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        mcpToolSearchQuery: event.target.value,
                      })
                    }
                  />
                </label>
              ) : null}
              {logic.stateOperation === "mcp_tool_fetch" ||
              logic.stateOperation === "mcp_tool_invoke" ? (
                <label>
                  MCP tool
                  <input
                    data-testid="workflow-state-mcp-tool-name"
                    value={String(logic.mcpToolName ?? "")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        mcpToolName: event.target.value,
                      })
                    }
                  />
                </label>
              ) : null}
              {logic.stateOperation === "mcp_tool_invoke" ? (
                <>
                  <label>
                    MCP tool input JSON
                    <textarea
                      data-testid="workflow-state-mcp-tool-input"
                      value={String(logic.mcpToolInputJson ?? "{}")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpToolInputJson: event.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    MCP containment
                    <select
                      data-testid="workflow-state-mcp-containment-mode"
                      value={String(logic.mcpContainmentMode ?? "sandboxed")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpContainmentMode: event.target.value as
                            | "read_only"
                            | "sandboxed"
                            | "review_required",
                        })
                      }
                    >
                      <option value="read_only">Read only</option>
                      <option value="sandboxed">Sandboxed</option>
                      <option value="review_required">Review required</option>
                    </select>
                  </label>
                  <label>
                    MCP invoke vault header refs JSON
                    <textarea
                      data-testid="workflow-state-mcp-vault-header-refs"
                      value={String(logic.mcpVaultHeaderRefsJson ?? "{}")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpVaultHeaderRefsJson: event.target.value,
                        })
                      }
                    />
                  </label>
                  <label className="workflow-config-checkbox-row">
                    <input
                      data-testid="workflow-state-mcp-allow-network-egress"
                      type="checkbox"
                      checked={logic.mcpAllowNetworkEgress === true}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpAllowNetworkEgress: event.target.checked,
                        })
                      }
                    />
                    Allow network egress for this invoke
                  </label>
                </>
              ) : null}
              {logic.stateOperation === "mcp_serve" ? (
                <>
                  <label>
                    MCP serve endpoint
                    <input
                      data-testid="workflow-state-mcp-serve-endpoint"
                      value={String(
                        logic.mcpServeEndpoint ??
                          "/v1/threads/{thread_id}/mcp/serve",
                      )}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpServeEndpoint: event.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    MCP serve allowed tools JSON
                    <textarea
                      data-testid="workflow-state-mcp-serve-allowed-tools"
                      value={String(
                        logic.mcpServeAllowedToolsJson ??
                          "[\"workspace.status\",\"git.diff\",\"file.inspect\"]",
                      )}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpServeAllowedToolsJson: event.target.value,
                        })
                      }
                    />
                  </label>
                </>
              ) : null}
              {logic.stateOperation === "mcp_add" ? (
                <>
                  <label>
                    MCP transport
                    <select
                      data-testid="workflow-state-mcp-transport"
                      value={String(logic.mcpTransport ?? "stdio")}
                      onChange={(event) =>
                        mcpServerConfigPatch(
                          { transport: event.target.value },
                          {
                            mcpTransport: event.target.value as
                              | "stdio"
                              | "http"
                              | "sse",
                          },
                        )
                      }
                    >
                      <option value="stdio">Stdio</option>
                      <option value="http">HTTP</option>
                      <option value="sse">SSE</option>
                    </select>
                  </label>
                  {logic.mcpTransport === "http" ||
                  logic.mcpTransport === "sse" ? (
                    <>
                      <label>
                        MCP server URL
                        <input
                          data-testid="workflow-state-mcp-server-url"
                          value={String(logic.mcpServerUrl ?? "")}
                          placeholder={
                            logic.mcpTransport === "sse"
                              ? "http://127.0.0.1:3000/sse"
                              : "http://127.0.0.1:3000/mcp"
                          }
                          onChange={(event) =>
                            mcpServerConfigPatch(
                              { url: event.target.value },
                              { mcpServerUrl: event.target.value },
                            )
                          }
                        />
                      </label>
                      <label>
                        MCP vault header refs JSON
                        <textarea
                          data-testid="workflow-state-mcp-server-headers"
                          value={String(logic.mcpServerHeadersJson ?? "{}")}
                          onChange={(event) =>
                            mcpServerConfigPatch(
                              {
                                headers: parseJsonField(
                                  event.target.value,
                                  {},
                                ),
                              },
                              { mcpServerHeadersJson: event.target.value },
                            )
                          }
                        />
                      </label>
                    </>
                  ) : null}
                  <label>
                    MCP label
                    <input
                      data-testid="workflow-state-mcp-server-label"
                      value={String(logic.mcpServerLabel ?? "")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpServerLabel: event.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    MCP server config JSON
                    <textarea
                      data-testid="workflow-state-mcp-server-config"
                      value={String(logic.mcpServerConfigJson ?? "{}")}
                      onChange={(event) =>
                        updateLogic({
                          ...logic,
                          mcpServerConfigJson: event.target.value,
                        })
                      }
                    />
                  </label>
                </>
              ) : null}
              {logic.stateOperation === "mcp_import" ? (
                <label>
                  MCP import JSON
                  <textarea
                    data-testid="workflow-state-mcp-import-json"
                    value={String(logic.mcpImportJson ?? "{\"mcpServers\":{}}")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        mcpImportJson: event.target.value,
                      })
                    }
                  />
                </label>
              ) : null}
            </>
          ) : null}
          <WorkflowSubagentStateFields logic={logic} updateLogic={updateLogic} />
          {logic.stateOperation === "memory_status" ||
          logic.stateOperation === "memory_policy" ||
          logic.stateOperation === "memory_search" ||
          logic.stateOperation === "memory_list" ||
          logic.stateOperation === "memory_remember" ||
          logic.stateOperation === "memory_edit" ||
          logic.stateOperation === "memory_delete" ? (
            <>
              <label>
                Memory scope
                <select
                  data-testid="workflow-state-memory-scope"
                  value={logic.memoryScope ?? "thread"}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      memoryScope: event.target.value as NonNullable<
                        NodeLogic["memoryScope"]
                      >,
                    })
                  }
                >
                  <option value="thread">Thread</option>
                  <option value="workflow">Workflow</option>
                  <option value="workspace">Workspace</option>
                  <option value="subagent">Subagent</option>
                  <option value="global">Global</option>
                </select>
              </label>
              <label>
                Memory key
                <input
                  data-testid="workflow-state-memory-key"
                  value={String(logic.memoryKey ?? "")}
                  onChange={(event) =>
                    updateLogic({ ...logic, memoryKey: event.target.value })
                  }
                />
              </label>
              <label>
                Query
                <input
                  data-testid="workflow-state-memory-query"
                  value={String(logic.query ?? "")}
                  onChange={(event) =>
                    updateLogic({ ...logic, query: event.target.value })
                  }
                />
              </label>
              <label>
                Limit
                <input
                  data-testid="workflow-state-memory-limit"
                  type="number"
                  min={1}
                  max={200}
                  value={Number(logic.limit ?? 10)}
                  onChange={(event) =>
                    updateLogic({ ...logic, limit: Number(event.target.value) })
                  }
                />
              </label>
              <label>
                Redaction
                <select
                  data-testid="workflow-state-memory-redaction"
                  value={logic.memoryRedaction ?? "none"}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      memoryRedaction: event.target
                        .value as NonNullable<NodeLogic["memoryRedaction"]>,
                    })
                  }
                >
                  <option value="none">None</option>
                  <option value="redacted">Redacted</option>
                </select>
              </label>
              {logic.stateOperation === "memory_edit" ||
              logic.stateOperation === "memory_delete" ? (
                <label>
                  Memory record
                  <input
                    data-testid="workflow-state-memory-record-id"
                    value={String(logic.memoryRecordId ?? "")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        memoryRecordId: event.target.value,
                      })
                    }
                  />
                </label>
              ) : null}
              {logic.stateOperation === "memory_remember" ||
              logic.stateOperation === "memory_edit" ? (
                <label>
                  Memory text
                  <input
                    data-testid="workflow-state-memory-text"
                    value={String(logic.memoryText ?? "")}
                    onChange={(event) =>
                      updateLogic({ ...logic, memoryText: event.target.value })
                    }
                  />
                </label>
              ) : null}
            </>
          ) : null}
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
                  | "workflow_tool"
                  | "coding_tool_pack";
                updateLogic({
                  ...logic,
                  toolBinding: {
                    toolRef:
                      bindingKind === "workflow_tool"
                        ? "workflow_tool"
                        : bindingKind === "coding_tool_pack"
                          ? "workspace.status"
                          : bindingKind === "mcp_tool"
                            ? logic.toolBinding?.bindingKind === "mcp_tool"
                              ? (logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read")
                              : "mcp.tool.catalog.read"
                        : (logic.toolBinding?.toolRef ?? ""),
                    bindingKind,
                    mockBinding:
                      bindingKind === "workflow_tool" || bindingKind === "coding_tool_pack"
                        ? false
                        : bindingKind === "mcp_tool"
                          ? logic.toolBinding?.bindingKind === "mcp_tool"
                            ? (logic.toolBinding?.mockBinding ?? true)
                            : true
                        : (logic.toolBinding?.mockBinding ?? true),
                    credentialReady:
                      bindingKind === "workflow_tool" || bindingKind === "coding_tool_pack"
                        ? true
                        : bindingKind === "mcp_tool"
                          ? logic.toolBinding?.bindingKind === "mcp_tool"
                            ? (logic.toolBinding?.credentialReady ?? false)
                            : false
                        : (logic.toolBinding?.credentialReady ?? false),
                    capabilityScope:
                      bindingKind === "workflow_tool"
                        ? ["invoke"]
                        : bindingKind === "coding_tool_pack"
                          ? ["workspace.status", "git.diff", "file.inspect", "file.apply_patch", "test.run"]
                          : bindingKind === "mcp_tool"
                            ? ["mcp.provider.read", "mcp.tool.catalog.read"]
                        : (logic.toolBinding?.capabilityScope ?? ["read"]),
                    sideEffectClass:
                      bindingKind === "coding_tool_pack"
                        ? (logic.toolBinding?.sideEffectClass ?? "write")
                        : (logic.toolBinding?.sideEffectClass ?? "read"),
                    requiresApproval:
                      bindingKind === "coding_tool_pack"
                        ? true
                        : (logic.toolBinding?.requiresApproval ?? false),
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
                    toolPack:
                      bindingKind === "coding_tool_pack"
                        ? (logic.toolBinding?.toolPack ?? codingToolPackDefaults)
                        : undefined,
                    mcp:
                      bindingKind === "mcp_tool"
                        ? (logic.toolBinding?.mcp ?? mcpBinding)
                        : undefined,
                  },
                });
              }}
            >
              <option value="plugin_tool">Plugin tool</option>
              <option value="mcp_tool">MCP tool</option>
              <option value="workflow_tool">Workflow tool</option>
              <option value="coding_tool_pack">Coding tool pack</option>
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
                    toolPack: logic.toolBinding?.toolPack,
                    mcp: logic.toolBinding?.mcp,
                  },
                })
              }
            />
          </label>
          {logic.toolBinding?.bindingKind === "mcp_tool" ? (
            <section
              className="workflow-tool-contract"
              data-testid="workflow-mcp-tool-contract"
            >
              <div className="workflow-tool-contract-grid">
                <label>
                  MCP server
                  <input
                    data-testid="workflow-mcp-server-id"
                    value={String(mcpBinding.serverId ?? "")}
                    onChange={(event) => {
                      const serverId = event.target.value;
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef: mcpToolRefFor(serverId, String(mcpBinding.toolName ?? "")),
                          bindingKind: "mcp_tool",
                          mockBinding: logic.toolBinding?.mockBinding ?? true,
                          credentialReady:
                            logic.toolBinding?.credentialReady ?? false,
                          capabilityScope:
                            logic.toolBinding?.capabilityScope ?? [
                              "mcp.provider.read",
                              "mcp.tool.catalog.read",
                            ],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          mcp: {
                            ...mcpBinding,
                            serverId,
                          },
                        },
                      });
                    }}
                  />
                </label>
                <label>
                  MCP tool
                  <input
                    data-testid="workflow-mcp-tool-name"
                    value={String(mcpBinding.toolName ?? "")}
                    onChange={(event) => {
                      const toolName = event.target.value;
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef: mcpToolRefFor(String(mcpBinding.serverId ?? ""), toolName),
                          bindingKind: "mcp_tool",
                          mockBinding: logic.toolBinding?.mockBinding ?? true,
                          credentialReady:
                            logic.toolBinding?.credentialReady ?? false,
                          capabilityScope:
                            logic.toolBinding?.capabilityScope ?? [
                              "mcp.provider.read",
                              "mcp.tool.catalog.read",
                            ],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          mcp: {
                            ...mcpBinding,
                            toolName,
                          },
                        },
                      });
                    }}
                  />
                </label>
                <label>
                  Catalog mode
                  <select
                    data-testid="workflow-mcp-catalog-mode"
                    value={String(mcpBinding.catalogMode ?? "deferred")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef: logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read",
                          bindingKind: "mcp_tool",
                          mockBinding: logic.toolBinding?.mockBinding ?? true,
                          credentialReady:
                            logic.toolBinding?.credentialReady ?? false,
                          capabilityScope:
                            logic.toolBinding?.capabilityScope ?? [
                              "mcp.provider.read",
                              "mcp.tool.catalog.read",
                            ],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          mcp: {
                            ...mcpBinding,
                            catalogMode: event.target.value,
                          },
                        },
                      })
                    }
                  >
                    <option value="deferred">Deferred search</option>
                    <option value="full">Full catalog</option>
                  </select>
                </label>
                <label>
                  Catalog search
                  <input
                    data-testid="workflow-mcp-catalog-search-query"
                    value={String(mcpBinding.catalogSearchQuery ?? "")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef: logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read",
                          bindingKind: "mcp_tool",
                          mockBinding: logic.toolBinding?.mockBinding ?? true,
                          credentialReady:
                            logic.toolBinding?.credentialReady ?? false,
                          capabilityScope:
                            logic.toolBinding?.capabilityScope ?? [
                              "mcp.provider.read",
                              "mcp.tool.catalog.read",
                            ],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          mcp: {
                            ...mcpBinding,
                            catalogSearchQuery: event.target.value,
                          },
                        },
                      })
                    }
                  />
                </label>
                <label>
                  Config sources
                  <select
                    data-testid="workflow-mcp-config-source-mode"
                    value={String(mcpBinding.configSourceMode ?? "workspace_and_global")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef: logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read",
                          bindingKind: "mcp_tool",
                          mockBinding: logic.toolBinding?.mockBinding ?? true,
                          credentialReady:
                            logic.toolBinding?.credentialReady ?? false,
                          capabilityScope:
                            logic.toolBinding?.capabilityScope ?? [
                              "mcp.provider.read",
                              "mcp.tool.catalog.read",
                            ],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          mcp: {
                            ...mcpBinding,
                            configSourceMode: event.target.value,
                          },
                        },
                      })
                    }
                  >
                    <option value="workspace_and_global">Workspace + global IOI</option>
                    <option value="workspace">Workspace/thread only</option>
                    <option value="global">Global IOI only</option>
                  </select>
                </label>
                <label>
                  Containment
                  <select
                    data-testid="workflow-mcp-containment-mode"
                    value={String(mcpBinding.containmentMode ?? "read_only")}
                    onChange={(event) =>
                      updateLogic({
                        ...logic,
                        toolBinding: {
                          toolRef: logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read",
                          bindingKind: "mcp_tool",
                          mockBinding: logic.toolBinding?.mockBinding ?? true,
                          credentialReady:
                            logic.toolBinding?.credentialReady ?? false,
                          capabilityScope:
                            logic.toolBinding?.capabilityScope ?? [
                              "mcp.provider.read",
                              "mcp.tool.catalog.read",
                            ],
                          sideEffectClass:
                            logic.toolBinding?.sideEffectClass ?? "read",
                          requiresApproval:
                            logic.toolBinding?.requiresApproval ?? false,
                          arguments: logic.toolBinding?.arguments ?? {},
                          mcp: {
                            ...mcpBinding,
                            containmentMode: event.target.value as
                              | "read_only"
                              | "sandboxed"
                              | "review_required",
                          },
                        },
                      })
                    }
                  >
                    <option value="read_only">Read only</option>
                    <option value="sandboxed">Sandboxed</option>
                    <option value="review_required">Review required</option>
                  </select>
                </label>
              </div>
              <label className="workflow-config-checkbox-row">
                <input
                  data-testid="workflow-mcp-validate-before-invoke"
                  type="checkbox"
                  checked={mcpBinding.validateBeforeInvoke !== false}
                  onChange={(event) =>
                    updateLogic({
                      ...logic,
                      toolBinding: {
                        toolRef: logic.toolBinding?.toolRef ?? "mcp.tool.catalog.read",
                        bindingKind: "mcp_tool",
                        mockBinding: logic.toolBinding?.mockBinding ?? true,
                        credentialReady:
                          logic.toolBinding?.credentialReady ?? false,
                        capabilityScope:
                          logic.toolBinding?.capabilityScope ?? [
                            "mcp.provider.read",
                            "mcp.tool.catalog.read",
                          ],
                        sideEffectClass:
                          logic.toolBinding?.sideEffectClass ?? "read",
                        requiresApproval:
                          logic.toolBinding?.requiresApproval ?? false,
                        arguments: logic.toolBinding?.arguments ?? {},
                        mcp: {
                          ...mcpBinding,
                          validateBeforeInvoke: event.target.checked,
                        },
                      },
                    })
                  }
                />
                Validate before invoke
              </label>
            </section>
          ) : null}
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
          {logic.toolBinding?.bindingKind === "coding_tool_pack" ? (
            <section
              className="workflow-tool-contract"
              data-testid="workflow-coding-tool-pack-contract"
            >
              <div className="workflow-tool-contract-grid">
                {[
                  ["workspaceStatusEnabled", "Workspace status"],
                  ["gitEnabled", "Git diff"],
                  ["filesystemEnabled", "File inspect"],
                  ["writeEnabled", "File patch"],
                  ["testEnabled", "Test run"],
                  ["diagnosticsEnabled", "Diagnostics"],
                  ["artifactEnabled", "Artifact read"],
                  ["resultRetrievalEnabled", "Retrieve result"],
                  ["dryRun", "Dry run"],
                ].map(([key, label]) => (
                  <label
                    key={key}
                    className="workflow-config-checkbox-row"
                  >
                    <input
                      data-testid={`workflow-coding-tool-pack-${key}`}
                      type="checkbox"
                      checked={Boolean(
                        codingToolPack[
                          key as keyof typeof codingToolPack
                        ],
                      )}
                      onChange={(event) =>
                        updateCodingToolPack({
                          ...codingToolPack,
                          [key]: event.target.checked,
                        })
                      }
                    />
                    {label}
                  </label>
                ))}
              </div>
              <label>
                Allowed paths
                <input
                  data-testid="workflow-coding-tool-pack-allowed-paths"
                  value={(codingToolPack.allowedPaths ?? []).join(", ")}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      allowedPaths: event.target.value
                        .split(",")
                        .map((item) => item.trim())
                        .filter(Boolean),
                    })
                  }
                />
              </label>
              <label>
                Test commands
                <input
                  data-testid="workflow-coding-tool-pack-test-commands"
                  value={(codingToolPack.allowedTestCommandIds ?? []).join(
                    ", ",
                  )}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      allowedTestCommandIds: event.target.value
                        .split(",")
                        .map((item) => item.trim())
                        .filter(Boolean),
                    })
                  }
                />
              </label>
              <label>
                Diagnostics mode
                <select
                  data-testid="workflow-coding-tool-pack-diagnostics-mode"
                  value={String(codingToolPack.diagnosticsMode ?? "advisory")}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      diagnosticsMode: event.target.value as
                        | "advisory"
                        | "blocking"
                        | "skip",
                    })
                  }
                >
                  <option value="advisory">Advisory</option>
                  <option value="blocking">Blocking</option>
                  <option value="skip">Skip</option>
                </select>
              </label>
              <label>
                Diagnostic commands
                <input
                  data-testid="workflow-coding-tool-pack-diagnostic-commands"
                  value={(codingToolPack.allowedDiagnosticCommandIds ?? []).join(
                    ", ",
                  )}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      allowedDiagnosticCommandIds: event.target.value
                        .split(",")
                        .map((item) => item.trim())
                        .filter(Boolean),
                    })
                  }
                />
              </label>
              <label>
                Default diagnostic command
                <input
                  data-testid="workflow-coding-tool-pack-default-diagnostic-command"
                  value={String(
                    codingToolPack.defaultDiagnosticCommandId ?? "auto",
                  )}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      defaultDiagnosticCommandId: event.target.value.trim(),
                    })
                  }
                />
              </label>
              <label>
                Restore policy
                <select
                  data-testid="workflow-coding-tool-pack-restore-policy"
                  value={String(
                    codingToolPack.restorePolicy ?? "apply_with_approval",
                  )}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      restorePolicy: event.target.value as
                        | "disabled"
                        | "preview_only"
                        | "apply_with_approval",
                    })
                  }
                >
                  <option value="apply_with_approval">Apply with approval</option>
                  <option value="preview_only">Preview only</option>
                  <option value="disabled">Disabled</option>
                </select>
              </label>
              <label>
                Restore conflicts
                <select
                  data-testid="workflow-coding-tool-pack-restore-conflict-policy"
                  value={String(codingToolPack.restoreConflictPolicy ?? "block")}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      restoreConflictPolicy: event.target.value as
                        | "block"
                        | "require_approval"
                        | "allow_override",
                    })
                  }
                >
                  <option value="block">Block conflicts</option>
                  <option value="require_approval">Require approval</option>
                  <option value="allow_override">Allow override</option>
                </select>
              </label>
              <label>
                Repair default
                <select
                  data-testid="workflow-coding-tool-pack-diagnostics-repair-default"
                  value={String(
                    codingToolPack.diagnosticsRepairDefault ?? "repair_retry",
                  )}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      diagnosticsRepairDefault: event.target.value as
                        | "repair_retry"
                        | "restore_preview"
                        | "restore_apply"
                        | "operator_override",
                    })
                  }
                >
                  <option value="repair_retry">Repair retry</option>
                  <option value="restore_preview">Restore preview</option>
                  <option value="restore_apply">Restore apply</option>
                  <option value="operator_override">Operator override</option>
                </select>
              </label>
              <label className="workflow-config-checkbox-row">
                <input
                  data-testid="workflow-coding-tool-pack-operator-override-requires-approval"
                  type="checkbox"
                  checked={codingToolPack.operatorOverrideRequiresApproval !== false}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      operatorOverrideRequiresApproval: event.target.checked,
                    })
                  }
                />
                Operator override requires approval
              </label>
              <label>
                Timeout ms
                <input
                  data-testid="workflow-coding-tool-pack-timeout-ms"
                  type="number"
                  min={1}
                  value={Number(codingToolPack.timeoutMs ?? 60000)}
                  onChange={(event) =>
                    updateCodingToolPack({
                      ...codingToolPack,
                      timeoutMs: Number(event.target.value || 0),
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
                        toolPack: logic.toolBinding?.toolPack,
                        mcp: logic.toolBinding?.mcp,
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
                        toolPack: logic.toolBinding?.toolPack,
                        mcp: logic.toolBinding?.mcp,
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
                    toolPack: logic.toolBinding?.toolPack,
                    mcp: logic.toolBinding?.mcp,
                  },
                });
              }}
            />
          </label>
        </>
      ) : null}
    </>
  );
}
