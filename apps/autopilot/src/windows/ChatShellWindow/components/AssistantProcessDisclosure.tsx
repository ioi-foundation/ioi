import { useEffect, useState } from "react";
import type { AssistantTurnProcess } from "../utils/assistantTurnProcessModel";
import { hasMeaningfulProcess } from "../utils/assistantTurnProcessModel";
import { icons } from "../../../components/ui/icons";
import { AssistantProcessRow } from "./AssistantProcessRow";
import { ToolCallRow } from "./ToolCallRow";

export function AssistantProcessDisclosure({
  process,
}: {
  process: AssistantTurnProcess;
}) {
  const meaningful = hasMeaningfulProcess(process);
  const defaultOpen =
    process.status === "running" ||
    process.status === "thinking" ||
    process.status === "blocked" ||
    process.status === "failed" ||
    process.items.length > 0;
  const [open, setOpen] = useState(defaultOpen);

  useEffect(() => {
    setOpen(defaultOpen);
  }, [defaultOpen, process.summaryLine, process.status]);

  if (!meaningful) {
    return null;
  }

  return (
    <section className="assistant-process" aria-label="Assistant process">
      <button
        className="assistant-process__trigger"
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        <span className="assistant-process__status" aria-hidden="true">
          {process.status === "running" || process.status === "thinking"
            ? icons.sparkles
            : icons.check}
        </span>
        <span className="assistant-process__summary">
          {process.summaryLine}
        </span>
        <span className="assistant-process__meta">
          {process.items.length > 0
            ? `${process.items.length} ${process.items.length === 1 ? "step" : "steps"}`
            : "working"}
        </span>
        <span
          className={`assistant-process__chevron ${open ? "is-open" : ""}`}
          aria-hidden="true"
        >
          {icons.chevronDown}
        </span>
      </button>
      {open && process.items.length > 0 ? (
        <div className="assistant-process__rows">
          {process.items.map((item) =>
            item.kind === "tool_call" ? (
              <ToolCallRow key={item.id} item={item} />
            ) : (
              <AssistantProcessRow key={item.id} item={item} />
            ),
          )}
        </div>
      ) : null}
    </section>
  );
}
