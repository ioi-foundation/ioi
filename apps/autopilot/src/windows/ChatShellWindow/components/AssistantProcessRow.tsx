import type { AssistantProcessItem } from "../utils/assistantTurnProcessModel";
import { icons } from "../../../components/ui/icons";

function processIcon(item: AssistantProcessItem) {
  if (item.status === "blocked" || item.status === "failed") {
    return icons.alert;
  }
  switch (item.kind) {
    case "tool_call":
      return icons.wrench;
    case "source_read":
      return icons.globe;
    case "evidence_ref":
      return icons.check;
    case "approval_gate":
      return icons.alert;
    case "validation_check":
      return icons.check;
    case "error":
      return icons.alert;
    case "plan_step":
    case "thought_summary":
    default:
      return icons.sparkles;
  }
}

export function AssistantProcessRow({ item }: { item: AssistantProcessItem }) {
  return (
    <div
      className={`assistant-process-row assistant-process-row--${item.status} assistant-process-row--${item.kind}`}
    >
      <span className="assistant-process-row__icon" aria-hidden="true">
        {processIcon(item)}
      </span>
      <span className="assistant-process-row__main">
        <span className="assistant-process-row__label">{item.label}</span>
        {item.detail ? (
          <span className="assistant-process-row__detail">{item.detail}</span>
        ) : null}
        {item.preview ? (
          <span className="assistant-process-row__preview">{item.preview}</span>
        ) : null}
      </span>
      {item.authority === "model_note" ? (
        <span className="assistant-process-row__authority">Model note</span>
      ) : null}
    </div>
  );
}
