import { useMemo, useState } from "react";
import type {
  ToolActivityGroupPresentation,
  ToolActivityRow,
} from "../../../types";
import { icons } from "./Icons";

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
      return icons.externalLink;
    default:
      return icons.wrench;
  }
}

function ToolActivityRowItem({ row }: { row: ToolActivityRow }) {
  const expandable = !!row.preview || !!row.detail;
  const [open, setOpen] = useState(
    row.status === "active" || (row.kind === "read" && !!row.preview),
  );
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
