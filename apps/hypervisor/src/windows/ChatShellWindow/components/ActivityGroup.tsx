import { useMemo, useState } from "react";
import type { ActivityGroup as ActivityGroupModel } from "../../../types";
import { MicroEventCard } from "./MicroEventCard";

interface ActivityGroupProps {
  group: ActivityGroupModel;
  defaultExpanded?: boolean;
  onOpenArtifact?: (artifactId: string) => void;
}

function digestText(group: ActivityGroupModel): string {
  const first = group.events[0]?.event;
  if (!first) {
    return "No activity recorded";
  }

  const tool = String(group.events[0]?.toolName || "").trim();
  const base = tool ? `${first.title} · ${tool}` : first.title;
  return base;
}

export function ActivityGroup({
  group,
  defaultExpanded = false,
  onOpenArtifact,
}: ActivityGroupProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);

  const digest = useMemo(() => digestText(group), [group]);

  return (
    <section className="activity-group" aria-label={group.title}>
      <button
        className="activity-group-header"
        onClick={() => setExpanded((value) => !value)}
        type="button"
      >
        <div className="activity-group-title-wrap">
          <h4 className="activity-group-title">{group.title}</h4>
          <span className="activity-group-count">{group.events.length} events</span>
        </div>
        <span className={`activity-group-chevron ${expanded ? "expanded" : ""}`}>⌄</span>
      </button>

      <p className="activity-group-digest">{digest}</p>

      {expanded && (
        <div className="activity-group-events">
          {group.events.map((entry) => (
            <MicroEventCard
              key={entry.key}
              event={entry.event}
              kind={entry.kind}
              toolName={entry.toolName}
              onOpenArtifact={onOpenArtifact || (() => undefined)}
            />
          ))}
        </div>
      )}
    </section>
  );
}
