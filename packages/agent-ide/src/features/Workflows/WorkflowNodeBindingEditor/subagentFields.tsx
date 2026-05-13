import type { NodeLogic } from "../../../types/graph";

const SUBAGENT_STATE_OPERATIONS: Array<NonNullable<NodeLogic["stateOperation"]>> = [
  "subagent_list",
  "subagent_spawn",
  "subagent_wait",
  "subagent_result",
  "subagent_send_input",
  "subagent_cancel",
  "subagent_resume",
  "subagent_assign",
];

const SUBAGENT_TARGET_OPERATIONS: Array<NonNullable<NodeLogic["stateOperation"]>> = [
  "subagent_wait",
  "subagent_result",
  "subagent_send_input",
  "subagent_cancel",
  "subagent_resume",
  "subagent_assign",
];

const SUBAGENT_PROMPT_OPERATIONS: Array<NonNullable<NodeLogic["stateOperation"]>> = [
  "subagent_spawn",
  "subagent_send_input",
];

interface WorkflowSubagentStateFieldsProps {
  logic: NodeLogic;
  updateLogic: (nextLogic: NodeLogic) => void;
}

export function WorkflowSubagentStateFields({
  logic,
  updateLogic,
}: WorkflowSubagentStateFieldsProps) {
  if (!isSubagentStateOperation(logic.stateOperation)) return null;

  return (
    <>
      <label>
        Subagent role
        <select
          data-testid="workflow-state-subagent-role"
          value={String(logic.subagentRole ?? "general")}
          onChange={(event) =>
            updateLogic({ ...logic, subagentRole: event.target.value })
          }
        >
          <option value="general">General</option>
          <option value="explore">Explore</option>
          <option value="plan">Plan</option>
          <option value="review">Review</option>
          <option value="implementer">Implementer</option>
          <option value="verifier">Verifier</option>
          <option value="browser_operator">Browser operator</option>
          <option value="gui_operator">GUI operator</option>
          <option value="security_reviewer">Security reviewer</option>
          <option value="policy_reviewer">Policy reviewer</option>
          <option value="workflow_designer">Workflow designer</option>
          <option value="connector_author">Connector author</option>
          <option value="model_router">Model router</option>
          <option value="receipt_auditor">Receipt auditor</option>
          <option value="custom">Custom</option>
        </select>
      </label>
      {SUBAGENT_TARGET_OPERATIONS.includes(
        logic.stateOperation as NonNullable<NodeLogic["stateOperation"]>,
      ) ? (
        <label>
          Subagent id
          <input
            data-testid="workflow-state-subagent-id"
            value={String(logic.subagentId ?? "")}
            onChange={(event) =>
              updateLogic({ ...logic, subagentId: event.target.value })
            }
          />
        </label>
      ) : null}
      {SUBAGENT_PROMPT_OPERATIONS.includes(
        logic.stateOperation as NonNullable<NodeLogic["stateOperation"]>,
      ) ? (
        <label>
          {logic.stateOperation === "subagent_send_input"
            ? "Subagent input"
            : "Subagent prompt"}
          <textarea
            data-testid="workflow-state-subagent-prompt"
            value={String(
              logic.stateOperation === "subagent_send_input"
                ? logic.subagentInput ?? logic.subagentPrompt ?? ""
                : logic.subagentPrompt ?? "",
            )}
            onChange={(event) =>
              updateLogic({
                ...logic,
                ...(logic.stateOperation === "subagent_send_input"
                  ? { subagentInput: event.target.value }
                  : { subagentPrompt: event.target.value }),
              })
            }
          />
        </label>
      ) : null}
      <label>
        Parent turn id
        <input
          data-testid="workflow-state-subagent-parent-turn-id"
          value={String(logic.subagentParentTurnId ?? "")}
          onChange={(event) =>
            updateLogic({
              ...logic,
              subagentParentTurnId: event.target.value,
            })
          }
        />
      </label>
      <label>
        Model route
        <input
          data-testid="workflow-state-subagent-model-route"
          value={String(logic.subagentModelRoute ?? "")}
          onChange={(event) =>
            updateLogic({
              ...logic,
              subagentModelRoute: event.target.value,
            })
          }
        />
      </label>
      <label>
        Tool pack
        <input
          data-testid="workflow-state-subagent-tool-pack"
          value={String(logic.subagentToolPack ?? "coding")}
          onChange={(event) =>
            updateLogic({ ...logic, subagentToolPack: event.target.value })
          }
        />
      </label>
      {logic.stateOperation === "subagent_spawn" ? (
        <label className="workflow-config-checkbox-row">
          <input
            data-testid="workflow-state-subagent-fork-context"
            type="checkbox"
            checked={logic.subagentForkContext === true}
            onChange={(event) =>
              updateLogic({
                ...logic,
                subagentForkContext: event.target.checked,
              })
            }
          />
          Fork parent context into child
        </label>
      ) : null}
      {logic.stateOperation === "subagent_list" ||
      logic.stateOperation === "subagent_spawn" ? (
        <label>
          Max concurrency
          <input
            data-testid="workflow-state-subagent-max-concurrency"
            type="number"
            min={1}
            max={32}
            value={Number(logic.subagentMaxConcurrency ?? 2)}
            onChange={(event) =>
              updateLogic({
                ...logic,
                subagentMaxConcurrency: Number(event.target.value || 0),
              })
            }
          />
        </label>
      ) : null}
      {logic.stateOperation === "subagent_wait" ? (
        <label>
          Wait timeout ms
          <input
            data-testid="workflow-state-subagent-wait-timeout-ms"
            type="number"
            min={1000}
            value={Number(logic.subagentWaitTimeoutMs ?? 300000)}
            onChange={(event) =>
              updateLogic({
                ...logic,
                subagentWaitTimeoutMs: Number(event.target.value || 0),
              })
            }
          />
        </label>
      ) : null}
      <label>
        Budget JSON
        <textarea
          data-testid="workflow-state-subagent-budget-json"
          value={String(logic.subagentBudgetJson ?? "{}")}
          onChange={(event) =>
            updateLogic({
              ...logic,
              subagentBudgetJson: event.target.value,
            })
          }
        />
      </label>
      <label>
        Output contract JSON
        <textarea
          data-testid="workflow-state-subagent-output-contract-json"
          value={String(
            logic.subagentOutputContractJson ??
              "[\"SUMMARY\",\"CHANGES\",\"EVIDENCE\",\"RISKS\",\"BLOCKERS\",\"RECEIPTS\"]",
          )}
          onChange={(event) =>
            updateLogic({
              ...logic,
              subagentOutputContractJson: event.target.value,
            })
          }
        />
      </label>
      <label>
        Merge policy
        <select
          data-testid="workflow-state-subagent-merge-policy"
          value={String(logic.subagentMergePolicy ?? "manual")}
          onChange={(event) =>
            updateLogic({
              ...logic,
              subagentMergePolicy: event.target.value,
            })
          }
        >
          <option value="manual">Manual</option>
          <option value="append">Append</option>
          <option value="replace">Replace</option>
          <option value="merge">Merge</option>
          <option value="evidence_only">Evidence only</option>
        </select>
      </label>
      <label>
        Cancellation inheritance
        <select
          data-testid="workflow-state-subagent-cancellation-inheritance"
          value={String(logic.subagentCancellationInheritance ?? "propagate")}
          onChange={(event) =>
            updateLogic({
              ...logic,
              subagentCancellationInheritance: event.target.value,
            })
          }
        >
          <option value="propagate">Propagate</option>
          <option value="detach">Detach</option>
          <option value="manual">Manual</option>
        </select>
      </label>
    </>
  );
}

function isSubagentStateOperation(
  operation: NodeLogic["stateOperation"],
): operation is NonNullable<NodeLogic["stateOperation"]> {
  return SUBAGENT_STATE_OPERATIONS.includes(
    operation as NonNullable<NodeLogic["stateOperation"]>,
  );
}
