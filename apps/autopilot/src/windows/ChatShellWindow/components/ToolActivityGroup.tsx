import { useEffect, useMemo, useState } from "react";
import type {
  ToolActivityGroupPresentation,
  ToolActivityRow,
} from "../../../types";
import { icons } from "../../../components/ui/icons";

function rowIcon(row: ToolActivityRow) {
  switch (row.kind) {
    case "search":
      return icons.search;
    case "read":
      return icons.globe;
    case "write":
      return icons.code;
    case "verify":
      return row.status === "blocked" ? icons.alert : icons.check;
    case "preview":
    case "present":
      return icons.externalLink;
    case "route":
      return icons.cube;
    case "understand":
      return icons.search;
    case "guidance":
      return icons.sparkles;
    default:
      return icons.wrench;
  }
}

function ToolActivityRowItem({ row }: { row: ToolActivityRow }) {
  const expandable = !!row.preview || !!row.detail;
  const [open, setOpen] = useState(
    row.status === "active" || (row.kind === "read" && !!row.preview),
  );
  useEffect(() => {
    if (row.status === "active") {
      setOpen(true);
    }
  }, [row.key, row.status]);
  const detailPreview = useMemo(() => {
    if (row.preview) {
      return row.preview;
    }
    return row.detail;
  }, [row.detail, row.preview]);

  if (!expandable) {
    return (
      <div className={`spot-tool-row spot-tool-row--${row.status}`}>
        <span className="spot-tool-row__icon" aria-hidden="true">
          {rowIcon(row)}
        </span>
        <span className="spot-tool-row__label">{row.label}</span>
      </div>
    );
  }

  return (
    <div className={`spot-tool-row spot-tool-row--${row.status}`}>
      <button
        type="button"
        className="spot-tool-row__trigger"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        <span className="spot-tool-row__icon" aria-hidden="true">
          {rowIcon(row)}
        </span>
        <span className="spot-tool-row__label">{row.label}</span>
        <span
          className={`spot-tool-row__chevron ${open ? "is-open" : ""}`}
          aria-hidden="true"
        >
          {icons.chevronDown}
        </span>
      </button>
      {open && detailPreview ? (
        <div className="spot-tool-row__detail">
          <pre>{detailPreview}</pre>
        </div>
      ) : null}
    </div>
  );
}

export function ToolActivityGroup({
  group,
}: {
  group: ToolActivityGroupPresentation;
}) {
  const [open, setOpen] = useState(group.defaultOpen);

  useEffect(() => {
    setOpen(group.defaultOpen);
  }, [group.defaultOpen, group.key]);

  return (
    <section className="spot-tool-group" aria-label="Tool activity">
      <button
        type="button"
        className="spot-tool-group__trigger"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        <span className="spot-tool-group__icon" aria-hidden="true">
          {icons.wrench}
        </span>
        <span className="spot-tool-group__label">{group.label}</span>
        <span
          className={`spot-tool-group__chevron ${open ? "is-open" : ""}`}
          aria-hidden="true"
        >
          {icons.chevronDown}
        </span>
      </button>
      {open ? (
        <div className="spot-tool-group__rows">
          {group.rows.map((row) => (
            <ToolActivityRowItem key={row.key} row={row} />
          ))}
        </div>
      ) : null}
    </section>
  );
}
