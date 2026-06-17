import { useMemo, useState } from "react";
import type { ThoughtSummary } from "../../../types";
import { icons } from "../../../components/ui/icons";

export function ReasoningDisclosure({
  label,
  thoughtSummary,
}: {
  label: string;
  thoughtSummary: ThoughtSummary | null;
}) {
  const notes = useMemo(() => {
    if (!thoughtSummary) {
      return [];
    }
    return thoughtSummary.agents.flatMap((agent) =>
      agent.notes.map((note, index) => ({
        key: `${agent.agentLabel}:${index}`,
        agentLabel: agent.agentLabel,
        note,
      })),
    );
  }, [thoughtSummary]);
  const [open, setOpen] = useState(false);

  if (notes.length === 0) {
    return null;
  }

  return (
    <section className="spot-reasoning-disclosure" aria-label="Reasoning disclosure">
      <button
        type="button"
        className="spot-reasoning-disclosure__trigger"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        <span className="spot-reasoning-disclosure__icon" aria-hidden="true">
          {icons.sparkles}
        </span>
        <span className="spot-reasoning-disclosure__label">{label}</span>
        <span
          className={`spot-reasoning-disclosure__chevron ${open ? "is-open" : ""}`}
          aria-hidden="true"
        >
          {icons.chevronDown}
        </span>
      </button>
      {open ? (
        <div className="spot-reasoning-disclosure__content">
          {notes.map((note) => (
            <p key={note.key}>
              <strong>{note.agentLabel}</strong> {note.note}
            </p>
          ))}
        </div>
      ) : null}
    </section>
  );
}
