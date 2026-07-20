import fs from "node:fs";
import path from "node:path";
import { fromMarkdown } from "mdast-util-from-markdown";
import {
  parseSovereignLocalCompletenessJson,
  SLC_REQUIREMENT_IDS,
  validateSovereignLocalCompletenessMatrix,
} from "./sovereign-local-completeness-matrix.mjs";
import {
  CPO_REQUIREMENT_IDS,
  parsePlatformFaultMatrixJson,
  validatePlatformFaultMatrix,
} from "./platform-fault-matrix.mjs";

function markdownFilesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return markdownFilesUnder(absolute);
    return entry.isFile() && entry.name.endsWith(".md") ? [absolute] : [];
  });
}

function githubAnchors(markdown) {
  const anchors = new Set();
  const counts = new Map();
  for (const line of markdown.split(/\r?\n/u)) {
    const match = /^#{1,6}\s+(.+?)\s*#*\s*$/u.exec(line);
    if (!match) continue;
    const base = match[1]
      .trim()
      .toLowerCase()
      .replace(/<[^>]+>/gu, "")
      .replace(/[`*~]/gu, "")
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/\s+/gu, "-")
      .replace(/-+/gu, "-");
    const count = counts.get(base) ?? 0;
    counts.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  return anchors;
}

function localTarget(rawTarget) {
  let target = rawTarget.trim();
  if (!target.startsWith("<")) {
    target = target.split(/\s+/u, 1)[0];
  }
  if (target.startsWith("<") && target.endsWith(">")) {
    target = target.slice(1, -1);
  }
  if (
    target.startsWith("http://") ||
    target.startsWith("https://") ||
    target.startsWith("mailto:")
  ) {
    return null;
  }
  const hashIndex = target.indexOf("#");
  const file = hashIndex === -1 ? target : target.slice(0, hashIndex);
  const anchor = hashIndex === -1 ? "" : target.slice(hashIndex + 1);
  return {
    file: decodeURIComponent(file),
    anchor: decodeURIComponent(anchor),
  };
}

function sourceText(markdown, node) {
  const start = node.position?.start?.offset;
  const end = node.position?.end?.offset;
  return Number.isInteger(start) && Number.isInteger(end)
    ? markdown.slice(start, end)
    : "";
}

function escapedAt(source, index) {
  let backslashes = 0;
  for (let cursor = index - 1; cursor >= 0 && source[cursor] === "\\"; cursor -= 1) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

function closingBracket(source, opening) {
  let depth = 0;
  for (let index = opening; index < source.length; index += 1) {
    if (escapedAt(source, index)) continue;
    if (source[index] === "[") depth += 1;
    if (source[index] === "]") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function normalizedReferenceLabel(label) {
  return label.trim().replace(/\s+/gu, " ").toLowerCase();
}

function unresolvedReferencesInText(source, { taskListMarker = false } = {}) {
  const unresolved = [];
  for (let index = 0; index < source.length; index += 1) {
    const image = source[index] === "!" && source[index + 1] === "[";
    const opening = image ? index + 1 : index;
    if (source[opening] !== "[" || escapedAt(source, opening)) continue;
    const closing = closingBracket(source, opening);
    if (closing === -1) continue;
    const text = source.slice(opening + 1, closing);
    let cursor = closing + 1;
    while (cursor < source.length && /[ \t\r\n]/u.test(source[cursor])) {
      cursor += 1;
    }
    if (source[cursor] === "(") {
      unresolved.push({
        malformedLink: true,
        display: source.slice(index, Math.min(source.length, cursor + 80)).trim(),
      });
      index = closing;
      continue;
    }
    if (source[cursor] === "[") {
      const labelClosing = closingBracket(source, cursor);
      if (labelClosing === -1) {
        unresolved.push({
          malformedLink: true,
          display: source.slice(index).trim(),
        });
        break;
      }
      const explicit = source.slice(cursor + 1, labelClosing);
      const label = normalizedReferenceLabel(explicit || text);
      unresolved.push({
        missingDefinition: label,
        display: source.slice(index, labelClosing + 1),
      });
      index = labelClosing;
      continue;
    }
    const label = normalizedReferenceLabel(text);
    const isTaskListMarker =
      taskListMarker &&
      opening === 0 &&
      closing === 2 &&
      /^(?:x|-)$/iu.test(label) &&
      (source.length === closing + 1 || /\s/u.test(source[closing + 1]));
    if (
      label &&
      !label.startsWith("^") &&
      !isTaskListMarker
    ) {
      unresolved.push({
        missingDefinition: label,
        display: source.slice(index, closing + 1),
      });
    }
    index = closing;
  }
  return unresolved;
}

function markdownLinks(markdown) {
  const tree = fromMarkdown(markdown);
  const definitions = new Map();
  const links = [];

  function collectDefinitions(node) {
    if (node.type === "definition" && !definitions.has(node.identifier)) {
      definitions.set(node.identifier, node.url);
    }
    for (const child of node.children ?? []) collectDefinitions(child);
  }
  collectDefinitions(tree);

  function collectLinks(node, insideLink = false, ancestors = []) {
    if (node.type === "link" || node.type === "image") {
      links.push({
        target: node.url,
        display: sourceText(markdown, node) || node.url,
      });
      return;
    }
    if (node.type === "linkReference" || node.type === "imageReference") {
      const target = definitions.get(node.identifier);
      if (target === undefined) {
        links.push({
          missingDefinition: node.identifier,
          display: sourceText(markdown, node),
        });
      } else {
        links.push({
          target,
          display: sourceText(markdown, node),
        });
      }
      return;
    }
    if (
      node.type === "text" &&
      !insideLink
    ) {
      const paragraph = ancestors.at(-1);
      const listItem = ancestors.at(-2);
      const taskListMarker =
        paragraph?.type === "paragraph" &&
        listItem?.type === "listItem" &&
        listItem.children?.[0] === paragraph &&
        paragraph.children?.[0] === node;
      links.push(
        ...unresolvedReferencesInText(sourceText(markdown, node), {
          taskListMarker,
        }),
      );
    }
    if (
      node.type === "code" ||
      node.type === "inlineCode" ||
      node.type === "definition" ||
      node.type === "html"
    ) {
      return;
    }
    for (const child of node.children ?? []) {
      collectLinks(
        child,
        insideLink ||
          node.type === "link" ||
          node.type === "linkReference",
        [...ancestors, node],
      );
    }
  }
  collectLinks(tree);
  return links;
}

export function checkConformanceDocsIntegrity({
  root,
  conformanceRoot = path.join(root, "docs", "conformance"),
}) {
  const failures = [];
  if (!fs.existsSync(conformanceRoot)) {
    return ["docs/conformance is missing"];
  }
  const markdownFiles = markdownFilesUnder(conformanceRoot);
  for (const file of markdownFiles) {
    const content = fs.readFileSync(file, "utf8");
    const relativeFile = path.relative(root, file);
    for (const link of markdownLinks(content)) {
      if (link.malformedLink) {
        failures.push(
          `${relativeFile} has malformed Markdown link syntax: ${link.display}`,
        );
        continue;
      }
      if (link.missingDefinition) {
        failures.push(
          `${relativeFile} has missing reference definition: ${link.display}`,
        );
        continue;
      }
      let target;
      try {
        target = localTarget(link.target);
      } catch (error) {
        failures.push(
          `${relativeFile} has an invalid encoded link ${link.display}: ${error.message}`,
        );
        continue;
      }
      if (!target) continue;
      const resolved = target.file
        ? path.resolve(path.dirname(file), target.file)
        : file;
      const relativeTarget = path.relative(root, resolved);
      if (
        relativeTarget === ".." ||
        relativeTarget.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relativeTarget)
      ) {
        failures.push(`${relativeFile} links outside the repository: ${link.display}`);
        continue;
      }
      if (!fs.existsSync(resolved)) {
        failures.push(`${relativeFile} has broken local link: ${link.display}`);
        continue;
      }
      if (
        target.anchor &&
        fs.statSync(resolved).isFile() &&
        resolved.endsWith(".md") &&
        !githubAnchors(fs.readFileSync(resolved, "utf8")).has(
          target.anchor.toLowerCase(),
        )
      ) {
        failures.push(`${relativeFile} has broken local anchor: ${link.display}`);
      }
    }
  }
  const platformFaultMatrix = path.join(
    conformanceRoot,
    "hypervisor-core",
    "platform-fault-matrix.v1.json",
  );
  if (fs.existsSync(platformFaultMatrix)) {
    let matrix;
    try {
      matrix = parsePlatformFaultMatrixJson(
        fs.readFileSync(platformFaultMatrix, "utf8"),
      );
    } catch (error) {
      failures.push(
        `docs/conformance/hypervisor-core/platform-fault-matrix.v1.json is invalid JSON: ${error.message}`,
      );
    }
    if (matrix !== undefined) {
      failures.push(
        ...validatePlatformFaultMatrix(matrix).map((failure) => (
          `docs/conformance/hypervisor-core/platform-fault-matrix.v1.json: ${failure}`
        )),
      );
    }
  }
  const platformOperabilityContract = path.join(
    conformanceRoot,
    "hypervisor-core",
    "platform-operability.md",
  );
  if (fs.existsSync(platformOperabilityContract)) {
    const requirementHeadings = [
      ...fs.readFileSync(platformOperabilityContract, "utf8").matchAll(
        /^### (CPO-\d+)\s+—/gmu,
      ),
    ].map((match) => match[1]);
    if (
      JSON.stringify(requirementHeadings)
        !== JSON.stringify(CPO_REQUIREMENT_IDS)
    ) {
      failures.push(
        "docs/conformance/hypervisor-core/platform-operability.md must define exactly CPO-1 through CPO-12 in order",
      );
    }
  }
  const sovereignLocalMatrix = path.join(
    conformanceRoot,
    "hypervisor-core",
    "sovereign-local-completeness-matrix.v1.json",
  );
  if (fs.existsSync(sovereignLocalMatrix)) {
    let matrix;
    try {
      matrix = parseSovereignLocalCompletenessJson(
        fs.readFileSync(sovereignLocalMatrix, "utf8"),
      );
    } catch (error) {
      failures.push(
        `docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json is invalid JSON: ${error.message}`,
      );
    }
    if (matrix !== undefined) {
      failures.push(
        ...validateSovereignLocalCompletenessMatrix(matrix).map((failure) => (
          `docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json: ${failure}`
        )),
      );
    }
  }
  const sovereignLocalContract = path.join(
    conformanceRoot,
    "hypervisor-core",
    "sovereign-local-completeness.md",
  );
  if (fs.existsSync(sovereignLocalContract)) {
    const requirementHeadings = [
      ...fs.readFileSync(sovereignLocalContract, "utf8").matchAll(
        /^### (SLC-\d{2})\s+—/gmu,
      ),
    ].map((match) => match[1]);
    if (
      JSON.stringify(requirementHeadings)
        !== JSON.stringify(SLC_REQUIREMENT_IDS)
    ) {
      failures.push(
        "docs/conformance/hypervisor-core/sovereign-local-completeness.md must define exactly SLC-01 through SLC-12 in order",
      );
    }
  }
  return failures;
}
