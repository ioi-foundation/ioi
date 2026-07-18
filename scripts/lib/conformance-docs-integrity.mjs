import fs from "node:fs";
import path from "node:path";

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

function normalizedReferenceLabel(label) {
  return label.trim().replace(/\s+/gu, " ").toLowerCase();
}

function referenceDefinitions(markdown) {
  const definitions = new Map();
  const definitionPattern =
    /^[ \t]{0,3}\[([^\]\n]+)\]:[ \t]*(<[^>\n]+>|\S+)(?:[ \t]+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?[ \t]*$/gmu;
  for (const match of markdown.matchAll(definitionPattern)) {
    const label = normalizedReferenceLabel(match[1]);
    if (!definitions.has(label)) {
      definitions.set(label, match[2]);
    }
  }
  return definitions;
}

function markdownLinks(markdown) {
  const definitions = referenceDefinitions(markdown);
  const links = [];
  const linkPattern =
    /!?\[([^\]\n]+)\](?:\(([^)\n]+)\)|\[([^\]\n]*)\])?/gu;
  for (const match of markdown.matchAll(linkPattern)) {
    const lineStart = markdown.lastIndexOf("\n", match.index - 1) + 1;
    const before = markdown.slice(lineStart, match.index);
    const after = markdown.slice(match.index + match[0].length);
    if (/^[ \t]{0,3}$/u.test(before) && after.startsWith(":")) continue;

    if (match[2] !== undefined) {
      links.push({ target: match[2], display: match[2] });
      continue;
    }

    const explicitReference = match[3] !== undefined;
    const label = normalizedReferenceLabel(
      explicitReference && match[3] !== "" ? match[3] : match[1],
    );
    if (!definitions.has(label)) {
      if (explicitReference) {
        links.push({
          missingDefinition: label,
          display: match[0],
        });
      }
      continue;
    }
    links.push({
      target: definitions.get(label),
      display: match[0],
    });
  }
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
  return failures;
}
