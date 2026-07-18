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

export function checkConformanceDocsIntegrity({
  root,
  conformanceRoot = path.join(root, "docs", "conformance"),
}) {
  const failures = [];
  if (!fs.existsSync(conformanceRoot)) {
    return ["docs/conformance is missing"];
  }
  const markdownFiles = markdownFilesUnder(conformanceRoot);
  const markdownLinkPattern = /\[[^\]]+\]\(([^)\n]+)\)/gu;
  for (const file of markdownFiles) {
    const content = fs.readFileSync(file, "utf8");
    const relativeFile = path.relative(root, file);
    for (const match of content.matchAll(markdownLinkPattern)) {
      let target;
      try {
        target = localTarget(match[1]);
      } catch (error) {
        failures.push(
          `${relativeFile} has an invalid encoded link ${match[1]}: ${error.message}`,
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
        failures.push(`${relativeFile} links outside the repository: ${match[1]}`);
        continue;
      }
      if (!fs.existsSync(resolved)) {
        failures.push(`${relativeFile} has broken local link: ${match[1]}`);
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
        failures.push(`${relativeFile} has broken local anchor: ${match[1]}`);
      }
    }
  }
  return failures;
}
