import { useMemo } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { SourceSummary } from "../../../types";
import { icons } from "../../../components/ui/icons";

type SourceChip = {
  key: string;
  label: string;
  url: string | null;
  faviconUrl: string | null;
};

const MAX_SOURCE_CHIPS = 6;

async function openSourceLink(url: string) {
  try {
    await openUrl(url);
  } catch {
    window.open(url, "_blank", "noopener,noreferrer");
  }
}

export function SourceChipRow({
  sourceSummary,
  onOpenSummary,
}: {
  sourceSummary: SourceSummary | null;
  onOpenSummary?: (summary: SourceSummary) => void;
}) {
  const chips = useMemo<SourceChip[]>(() => {
    if (!sourceSummary) {
      return [];
    }

    const browseChips = sourceSummary.browses.map((browse) => ({
      key: `browse:${browse.url}`,
      label: browse.title?.trim() || browse.domain,
      url: browse.url,
      faviconUrl:
        sourceSummary.domains.find((domain) => domain.domain === browse.domain)
          ?.faviconUrl || null,
    }));
    if (browseChips.length > 0) {
      return browseChips.slice(0, MAX_SOURCE_CHIPS);
    }

    return sourceSummary.domains.slice(0, MAX_SOURCE_CHIPS).map((domain) => ({
      key: `domain:${domain.domain}`,
      label: domain.domain,
      url: null,
      faviconUrl: domain.faviconUrl || null,
    }));
  }, [sourceSummary]);

  if (!sourceSummary || chips.length === 0) {
    return null;
  }

  return (
    <div className="spot-source-chip-row" aria-label="Sources used">
      {onOpenSummary ? (
        <button
          type="button"
          className="spot-source-chip spot-source-chip--summary"
          onClick={() => onOpenSummary(sourceSummary)}
        >
          {sourceSummary.totalSources}{" "}
          {sourceSummary.totalSources === 1 ? "source" : "sources"}
        </button>
      ) : null}
      {chips.map((chip) => {
        const content = (
          <>
            {chip.faviconUrl ? (
              <img
                className="spot-source-chip__icon"
                src={chip.faviconUrl}
                alt=""
              />
            ) : (
              <span
                className="spot-source-chip__icon spot-source-chip__icon--fallback"
                aria-hidden="true"
              >
                {icons.globe}
              </span>
            )}
            <span className="spot-source-chip__label">{chip.label}</span>
          </>
        );

        if (chip.url) {
          return (
            <button
              key={chip.key}
              type="button"
              className="spot-source-chip"
              onClick={() => {
                void openSourceLink(chip.url!);
              }}
            >
              {content}
            </button>
          );
        }

        return (
          <span key={chip.key} className="spot-source-chip spot-source-chip--static">
            {content}
          </span>
        );
      })}
    </div>
  );
}
