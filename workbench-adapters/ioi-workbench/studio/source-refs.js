function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function stringValue(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function compactWhitespace(value = "") {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function studioJsonObjectFromText(value = "") {
  const text = String(value || "").trim();
  if (!text || !/^[{\[]/.test(text)) {
    return {};
  }
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function studioJsonValueFromText(value = "") {
  const text = String(value || "").trim();
  if (!text || !/^[{\[]/.test(text)) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function studioUnescapeJsonStringFragment(value = "") {
  const text = String(value || "");
  try {
    return JSON.parse(`"${text.replace(/\r/g, "\\r").replace(/\n/g, "\\n")}"`);
  } catch {
    return text.replace(/\\"/g, '"').replace(/\\n/g, " ").replace(/\\\\/g, "\\");
  }
}

function studioPartialJsonFieldValue(objectText = "", keys = []) {
  for (const key of firstArray(keys)) {
    const pattern = new RegExp(`"${key}"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`, "i");
    const match = pattern.exec(objectText);
    if (match?.[1]) {
      return studioUnescapeJsonStringFragment(match[1]);
    }
  }
  return "";
}

function studioRecordValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function studioSourceRefFromRecord(record = {}) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return null;
  }
  const url = stringValue(
    record.url ||
      record.href ||
      record.link ||
      record.sourceUrl ||
      record.source_url ||
      record.canonicalUrl ||
      record.canonical_url,
  );
  if (!/^https?:\/\//i.test(url)) {
    return null;
  }
  let domain = stringValue(record.domain || record.hostname);
  try {
    domain ||= new URL(url).hostname;
  } catch {
    domain ||= url;
  }
  const title = compactWhitespace(
    record.title ||
      record.name ||
      record.label ||
      domain ||
      url,
  ).slice(0, 96);
  return {
    title: title || domain || url,
    url,
    domain: compactWhitespace(domain).replace(/^www\./i, ""),
    excerpt: compactWhitespace(record.excerpt || record.snippet || record.summary || "").slice(0, 260),
    state: compactWhitespace(record.state || record.status || record.sourceHealth || "used").slice(0, 40) || "used",
  };
}

function collectStudioSourceRefsFromPartialJsonText(value = "", refs = []) {
  if (refs.length >= 8) {
    return;
  }
  const text = String(value || "");
  if (!/"(?:url|href|link|sourceUrl|source_url|canonicalUrl|canonical_url)"\s*:\s*"https?:\/\//i.test(text)) {
    return;
  }
  const urlPattern = /"(?:url|href|link|sourceUrl|source_url|canonicalUrl|canonical_url)"\s*:\s*"((?:\\.|[^"\\])*)"/gi;
  let match;
  while ((match = urlPattern.exec(text)) && refs.length < 8) {
    const url = studioUnescapeJsonStringFragment(match[1]);
    if (!/^https?:\/\//i.test(url)) {
      continue;
    }
    const objectStart = Math.max(0, text.lastIndexOf("{", match.index));
    let objectEnd = text.indexOf("\n    }", match.index);
    if (objectEnd === -1) objectEnd = text.indexOf("\n  }", match.index);
    if (objectEnd === -1) objectEnd = text.indexOf("}", match.index);
    if (objectEnd === -1) objectEnd = Math.min(text.length, match.index + 1800);
    const objectText = text.slice(objectStart, Math.min(text.length, objectEnd + 1));
    const recovered = studioSourceRefFromRecord({
      url,
      title: studioPartialJsonFieldValue(objectText, ["title", "name", "label"]),
      snippet: studioPartialJsonFieldValue(objectText, ["snippet", "excerpt", "summary"]),
      domain: studioPartialJsonFieldValue(objectText, ["domain", "hostname"]),
      state: studioPartialJsonFieldValue(objectText, ["state", "status", "sourceHealth"]),
    });
    if (recovered) {
      refs.push(recovered);
    }
  }
}

const SOURCE_REF_CONTAINER_KEYS = [
  "sources",
  "source",
  "sourceRefs",
  "source_refs",
  "sourceObservations",
  "source_observations",
  "documents",
  "document",
  "items",
  "results",
  "citations",
  "references",
  "payload",
  "payload_summary",
  "payloadSummary",
  "kernel_event",
  "kernelEvent",
  "AgentActionResult",
  "WorkloadReceipt",
  "WebRetrieve",
  "receipt",
  "data",
  "result",
  "output",
  "preview",
  "raw_output",
  "rawOutput",
];

function collectStudioSourceRefs(value, refs, depth = 0) {
  if (depth > 10 || refs.length >= 8 || value == null) {
    return;
  }
  const parsed = typeof value === "string" ? studioJsonValueFromText(value) : value;
  if (!parsed) {
    if (typeof value === "string") {
      collectStudioSourceRefsFromPartialJsonText(value, refs);
    }
    return;
  }
  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      collectStudioSourceRefs(item, refs, depth + 1);
      if (refs.length >= 8) break;
    }
    return;
  }
  if (typeof parsed !== "object") {
    return;
  }
  const sourceRef = studioSourceRefFromRecord(parsed);
  if (sourceRef) {
    refs.push(sourceRef);
  }
  for (const key of SOURCE_REF_CONTAINER_KEYS) {
    if (parsed[key] !== undefined) {
      collectStudioSourceRefs(parsed[key], refs, depth + 1);
    }
    if (refs.length >= 8) break;
  }
}

function uniqueStudioSourceRefs(refs = []) {
  const seen = new Set();
  return refs.filter((ref) => {
    const key = `${ref.url} ${ref.title}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6);
}

function studioSourceRefsFromRuntimeEvents(events = []) {
  const refs = [];
  for (const event of firstArray(events)) {
    collectStudioSourceRefs(event?.payload, refs);
    collectStudioSourceRefs(event?.payload_summary, refs);
    collectStudioSourceRefs(event?.payloadSummary, refs);
    collectStudioSourceRefs(event?.data, refs);
    if (refs.length >= 8) break;
  }
  return uniqueStudioSourceRefs(refs);
}

function studioSourceRefsFromRuntimeEvent(event = {}, summary = "") {
  const refs = [];
  collectStudioSourceRefs(event?.payload, refs);
  collectStudioSourceRefs(event?.payload_summary, refs);
  collectStudioSourceRefs(event?.payloadSummary, refs);
  collectStudioSourceRefs(event?.data, refs);
  collectStudioSourceRefs(summary, refs);
  return uniqueStudioSourceRefs(refs);
}

function studioFirstSourceExcerptFromEvent(event = {}, summary = "") {
  const candidates = [];
  function visit(value, depth = 0) {
    if (depth > 10 || candidates.length >= 6 || value == null) return;
    const parsed = typeof value === "string" ? studioJsonValueFromText(value) : value;
    if (!parsed) return;
    if (Array.isArray(parsed)) {
      for (const item of parsed) visit(item, depth + 1);
      return;
    }
    if (typeof parsed !== "object") return;
    for (const key of ["snippet", "excerpt", "excerpt_preview", "excerptPreview", "summary", "text", "content"]) {
      const text = compactWhitespace(parsed[key]);
      if (text && !/^\{/.test(text)) candidates.push(text.slice(0, 280));
    }
    for (const key of SOURCE_REF_CONTAINER_KEYS.filter((item) => item !== "raw_output" && item !== "rawOutput")) {
      visit(parsed[key], depth + 1);
    }
  }
  visit(event?.payload);
  visit(event?.payload_summary);
  visit(event?.payloadSummary);
  visit(event?.data);
  visit(summary);
  return candidates[0] || "";
}

module.exports = {
  collectStudioSourceRefs,
  collectStudioSourceRefsFromPartialJsonText,
  studioFirstSourceExcerptFromEvent,
  studioJsonObjectFromText,
  studioJsonValueFromText,
  studioPartialJsonFieldValue,
  studioRecordValue,
  studioSourceRefFromRecord,
  studioSourceRefsFromRuntimeEvent,
  studioSourceRefsFromRuntimeEvents,
  studioUnescapeJsonStringFragment,
};
