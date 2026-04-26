import { useCallback } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { AssistantSourceRef } from "../utils/assistantTurnProcessModel";
import { icons } from "../../../components/ui/icons";

function fallbackIcon(source: AssistantSourceRef) {
  switch (source.iconFallback) {
    case "file":
    case "terminal":
      return icons.code;
    case "image":
      return icons.externalLink;
    case "shield":
    case "check":
      return icons.check;
    case "globe":
    default:
      return icons.globe;
  }
}

async function openSource(href: string) {
  try {
    await openUrl(href);
  } catch {
    window.open(href, "_blank", "noopener,noreferrer");
  }
}

export function SourcePill({ source }: { source: AssistantSourceRef }) {
  const handleOpen = useCallback(() => {
    if (!source.href) {
      return;
    }
    void openSource(source.href);
  }, [source.href]);

  const content = (
    <>
      <span className="assistant-source-pill__icon" aria-hidden="true">
        {source.faviconUrl ? (
          <img src={source.faviconUrl} alt="" loading="lazy" />
        ) : (
          fallbackIcon(source)
        )}
      </span>
      <span className="assistant-source-pill__label">{source.label}</span>
      {source.detail ? (
        <span className="assistant-source-pill__detail">{source.detail}</span>
      ) : null}
    </>
  );

  if (source.href) {
    return (
      <button
        className="assistant-source-pill"
        type="button"
        onClick={handleOpen}
        title={source.detail || source.href}
      >
        {content}
      </button>
    );
  }

  return (
    <span className="assistant-source-pill" title={source.detail || source.label}>
      {content}
    </span>
  );
}
