import { useMemo, useState } from "react";
import type { ActivityGroup as ActivityGroupModel, ActivitySummary } from "../../../types";
import { ActivityGroup } from "./ActivityGroup";

interface ActivityRailProps {
  summary: ActivitySummary;
  groups: ActivityGroupModel[];
  defaultCollapsed?: boolean;
  onOpenArtifact?: (artifactId: string) => void;
  onOpenArtifacts?: () => void;
}

const INITIAL_GROUP_COUNT = 6;
const GROUP_LOAD_INCREMENT = 8;

export function ActivityRail({
  summary,
  groups,
  defaultCollapsed = true,
  onOpenArtifact,
  onOpenArtifacts,
}: ActivityRailProps) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [visibleGroups, setVisibleGroups] = useState(INITIAL_GROUP_COUNT);

  const chips = useMemo(
    () => [
      { label: "Search", value: summary.searchCount },
      { label: "Read", value: summary.readCount },
      { label: "Receipts", value: summary.receiptCount },
      { label: "Reasoning", value: summary.reasoningCount },
      { label: "System", value: summary.systemCount },
      { label: "Artifacts", value: summary.artifactCount },
    ],
    [summary],
  );

  const displayedGroups = groups.slice(0, visibleGroups);
  const hasMore = groups.length > displayedGroups.length;

  return (
    <section className="activity-rail" aria-label="Execution activity">
      <div className="activity-rail-topbar">
        <button
          className="activity-rail-header"
          onClick={() => setCollapsed((value) => !value)}
          type="button"
        >
          <div className="activity-rail-title-wrap">
            <h3 className="activity-rail-title">Activity</h3>
            <span className="activity-rail-subtitle">{groups.length} steps</span>
          </div>
          <span className={`activity-rail-chevron ${collapsed ? "" : "expanded"}`}>⌄</span>
        </button>
        {onOpenArtifacts && (
          <button
            className="activity-open-thoughts"
            onClick={onOpenArtifacts}
            type="button"
          >
            Artifacts
          </button>
        )}
      </div>

      <div className="activity-chip-row">
        {chips.map((chip) => (
          <span className="activity-chip" key={chip.label}>
            <span className="activity-chip-label">{chip.label}</span>
            <span className="activity-chip-value">{chip.value}</span>
          </span>
        ))}
      </div>

      {!collapsed && (
        <div className="activity-rail-body">
          {displayedGroups.map((group, index) => (
            <ActivityGroup
              key={`${group.stepIndex}-${group.title}`}
              group={group}
              defaultExpanded={index === displayedGroups.length - 1}
              onOpenArtifact={onOpenArtifact}
            />
          ))}

          {hasMore && (
            <button
              className="activity-load-more"
              onClick={() =>
                setVisibleGroups((value) => Math.min(value + GROUP_LOAD_INCREMENT, groups.length))
              }
              type="button"
            >
              Load more activity
            </button>
          )}
        </div>
      )}
    </section>
  );
}
