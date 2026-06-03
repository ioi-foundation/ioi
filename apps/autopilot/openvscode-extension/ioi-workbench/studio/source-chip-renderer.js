function defaultStringValue(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function defaultFirstArray(value) {
  return Array.isArray(value) ? value : [];
}

function defaultCompactWhitespace(value = "") {
  return defaultStringValue(value).replace(/\s+/g, " ").trim();
}

function defaultEscapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function createStudioSourceChipRenderer(deps = {}) {
  const compactStudioWhitespace = deps.compactStudioWhitespace || defaultCompactWhitespace;
  const escapeHtml = deps.escapeHtml || defaultEscapeHtml;
  const firstArray = deps.firstArray || defaultFirstArray;
  const stringValue = deps.stringValue || defaultStringValue;
  const studioRecordValue = deps.studioRecordValue || ((value) => value && typeof value === "object" && !Array.isArray(value) ? value : {});

  function studioSourceChipIconDataUri(source = {}) {
    const domain = compactStudioWhitespace(source.domain || source.hostname || "");
    const title = compactStudioWhitespace(source.title || domain || "source");
    const glyph = escapeHtml((domain || title || "source").replace(/^www\./i, "").slice(0, 1).toUpperCase() || "S");
    const hue = Math.abs(Array.from(domain || title).reduce((sum, char) => sum + char.charCodeAt(0), 0)) % 360;
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><rect width="16" height="16" rx="4" fill="hsl(${hue} 45% 30%)"/><text x="8" y="11" text-anchor="middle" font-family="system-ui, sans-serif" font-size="9" font-weight="700" fill="white">${glyph}</text></svg>`;
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  }

  function sanitizeStudioSourceUrl(value = "") {
    const raw = stringValue(value).trim();
    if (!raw || /[\u0000-\u001f\u007f]/.test(raw)) {
      return "";
    }
    if (/^(?:https?:\/\/|data:image\/)/i.test(raw)) {
      return raw;
    }
    return "";
  }

  function studioSourceChipFaviconUrl(source = {}) {
    const explicit = sanitizeStudioSourceUrl(source.faviconUrl || source.favicon_url || source.iconUrl || source.icon_url || "");
    if (/^(?:https?:\/\/|data:image\/)/i.test(explicit)) {
      return explicit;
    }
    const rawUrl = sanitizeStudioSourceUrl(source.url || source.href || source.link || "");
    let domain = compactStudioWhitespace(source.domain || source.hostname || "").replace(/^www\./i, "");
    if (!domain && rawUrl) {
      try {
        domain = new URL(rawUrl).hostname.replace(/^www\./i, "");
      } catch {
        domain = "";
      }
    }
    if (!domain && !rawUrl) {
      return "";
    }
    const domainUrl = rawUrl || `https://${domain}`;
    return `https://www.google.com/s2/favicons?sz=32&domain_url=${encodeURIComponent(domainUrl)}`;
  }

  function studioSourceChipRows(sourceRefs = [], { limit = 6 } = {}) {
    return firstArray(sourceRefs).slice(0, limit).map((source) => {
      const record = studioRecordValue(source);
      const url = stringValue(record.url || record.href || record.link);
      const title = compactStudioWhitespace(record.title || record.name || record.label || record.domain || url).slice(0, 96);
      const domain = compactStudioWhitespace(record.domain || record.hostname || (() => {
        try { return new URL(url).hostname.replace(/^www\./i, ""); } catch { return ""; }
      })()).replace(/^www\./i, "");
      const excerpt = compactStudioWhitespace(record.excerpt || record.snippet || record.summary || "").slice(0, 180);
      const state = compactStudioWhitespace(record.state || record.status || "used").slice(0, 32);
      if (!title && !domain && !url) return "";
      const label = title || domain || url;
      const titleAttr = [label, domain, excerpt].filter(Boolean).join(" - ");
      const iconUrl = studioSourceChipFaviconUrl({ ...record, url, domain, title }) || studioSourceChipIconDataUri({ ...record, domain, title });
      const chipBody = `
      <img src="${escapeHtml(iconUrl)}" alt="" aria-hidden="true">
      <span>${escapeHtml(label)}</span>
      ${domain && domain !== label ? `<small>${escapeHtml(domain)}</small>` : ""}
      ${state ? `<em>${escapeHtml(state)}</em>` : ""}
    `;
      if (/^https?:\/\//i.test(url)) {
        return `<a class="studio-source-chip" href="${escapeHtml(url)}" title="${escapeHtml(titleAttr)}" rel="noreferrer noopener">${chipBody}</a>`;
      }
      return `<span class="studio-source-chip" title="${escapeHtml(titleAttr)}">${chipBody}</span>`;
    }).join("");
  }

  function studioTurnSourceRows(turn = {}) {
    const directSourceRefs = firstArray(turn.sourceRefs || turn.source_refs);
    const artifactSourceRefs = firstArray(turn.artifacts).flatMap((artifact) =>
      firstArray(artifact?.sourceRefs || artifact?.source_refs)
    );
    const seen = new Set();
    const sourceRefs = [...directSourceRefs, ...artifactSourceRefs]
      .map((source) => studioRecordValue(source))
      .filter((source) => /^https?:\/\//i.test(stringValue(source.url)))
      .filter((source) => {
        const key = `${stringValue(source.url)} ${stringValue(source.title || source.name || source.label)}`.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    if (!sourceRefs.length) {
      return "";
    }
    return `
    <footer class="studio-answer-sources" data-testid="studio-answer-sources">
      <span>Sources</span>
      <div class="studio-source-chip-list">
        ${studioSourceChipRows(sourceRefs, { limit: 6 })}
      </div>
    </footer>
  `;
  }

  return {
    sanitizeStudioSourceUrl,
    studioSourceChipFaviconUrl,
    studioSourceChipIconDataUri,
    studioSourceChipRows,
    studioTurnSourceRows,
  };
}

module.exports = {
  createStudioSourceChipRenderer,
};
