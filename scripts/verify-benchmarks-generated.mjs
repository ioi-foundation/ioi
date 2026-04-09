import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";

const repoRoot = process.cwd();
const targets = [
  "apps/benchmarks/src/generated/benchmark-data.json",
  "apps/benchmarks/public/generated/benchmark-data.json",
];

function readWorkingTreeJson(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  return JSON.parse(fs.readFileSync(absolutePath, "utf8"));
}

function escapeForRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizePathLikeString(value, knownRoots) {
  let normalized = value.replace(/\\/g, "/");
  for (const root of knownRoots) {
    if (!root || typeof root !== "string") {
      continue;
    }
    const normalizedRoot = root.replace(/\\/g, "/").replace(/\/+$/, "");
    if (!normalizedRoot) {
      continue;
    }
    const rootPattern = new RegExp(`^${escapeForRegExp(normalizedRoot)}(?:/|$)`);
    normalized = normalized.replace(rootPattern, "$REPO_ROOT/");
    normalized = normalized.replace(
      new RegExp(`^file://${escapeForRegExp(normalizedRoot)}(?:/|$)`),
      "file://$REPO_ROOT/",
    );
  }
  normalized = normalized.replace(/\$REPO_ROOT\/\/+/g, "$REPO_ROOT/");
  return normalized;
}

function normalizeValue(value, knownRoots) {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeValue(entry, knownRoots));
  }

  if (value && typeof value === "object") {
    const parsed = value;
    const nextRoots = new Set(knownRoots);
    if (typeof parsed.repoRoot === "string" && parsed.repoRoot.trim()) {
      nextRoots.add(parsed.repoRoot);
    }

    const normalized = {};
    for (const [key, entry] of Object.entries(parsed)) {
      if (key === "generatedAt") {
        normalized[key] = "$GENERATED_AT";
        continue;
      }
      if (key === "repoRoot") {
        normalized[key] = "$REPO_ROOT";
        continue;
      }
      normalized[key] = normalizeValue(entry, [...nextRoots]);
    }
    return normalized;
  }

  if (typeof value === "string") {
    return normalizePathLikeString(value, knownRoots);
  }

  return value;
}

function canonicalJson(value) {
  return JSON.stringify(value, null, 2);
}

function findFirstDifference(left, right, currentPath = "$") {
  if (typeof left !== typeof right) {
    return { path: currentPath, left, right };
  }

  if (Array.isArray(left)) {
    if (!Array.isArray(right) || left.length !== right.length) {
      return { path: `${currentPath}.length`, left: left.length, right: right.length };
    }

    for (let index = 0; index < left.length; index += 1) {
      const difference = findFirstDifference(
        left[index],
        right[index],
        `${currentPath}[${index}]`,
      );
      if (difference) {
        return difference;
      }
    }
    return null;
  }

  if (left && typeof left === "object") {
    const leftKeys = Object.keys(left);
    const rightKeys = Object.keys(right);
    if (
      leftKeys.length !== rightKeys.length ||
      leftKeys.some((key, index) => key !== rightKeys[index])
    ) {
      return { path: `${currentPath}.keys`, left: leftKeys, right: rightKeys };
    }

    for (const key of leftKeys) {
      const difference = findFirstDifference(left[key], right[key], `${currentPath}.${key}`);
      if (difference) {
        return difference;
      }
    }
    return null;
  }

  return left === right ? null : { path: currentPath, left, right };
}

function verifyTarget(relativePath, beforeJson, afterJson) {
  const knownRoots = [
    repoRoot,
    typeof beforeJson?.repoRoot === "string" ? beforeJson.repoRoot : null,
    typeof afterJson?.repoRoot === "string" ? afterJson.repoRoot : null,
  ].filter(Boolean);

  const normalizedBefore = normalizeValue(beforeJson, knownRoots);
  const normalizedAfter = normalizeValue(afterJson, knownRoots);

  if (canonicalJson(normalizedBefore) !== canonicalJson(normalizedAfter)) {
    const difference = findFirstDifference(normalizedBefore, normalizedAfter);
    const detail = difference
      ? ` First difference at ${difference.path}: ${JSON.stringify(difference.left)} -> ${JSON.stringify(
          difference.right,
        )}.`
      : "";
    throw new Error(
      `Generated benchmark payload drift detected in ${relativePath}; run the generator and commit the refreshed artifact.${detail}`,
    );
  }
}

function verifyMirroredOutputs(leftPath, rightPath) {
  const leftJson = readWorkingTreeJson(leftPath);
  const rightJson = readWorkingTreeJson(rightPath);
  const knownRoots = [
    repoRoot,
    typeof leftJson?.repoRoot === "string" ? leftJson.repoRoot : null,
    typeof rightJson?.repoRoot === "string" ? rightJson.repoRoot : null,
  ].filter(Boolean);

  const normalizedLeft = normalizeValue(leftJson, knownRoots);
  const normalizedRight = normalizeValue(rightJson, knownRoots);

  if (canonicalJson(normalizedLeft) !== canonicalJson(normalizedRight)) {
    throw new Error(
      `Generated benchmark payloads are not mirrored between ${leftPath} and ${rightPath}`,
    );
  }
}

function main() {
  const beforeJsonByTarget = Object.fromEntries(
    targets.map((relativePath) => [relativePath, readWorkingTreeJson(relativePath)]),
  );

  execFileSync("npm", ["run", "generate:data", "--workspace=apps/benchmarks"], {
    cwd: repoRoot,
    stdio: "inherit",
  });

  for (const relativePath of targets) {
    verifyTarget(relativePath, beforeJsonByTarget[relativePath], readWorkingTreeJson(relativePath));
  }
  verifyMirroredOutputs(targets[0], targets[1]);
  console.log("Generated benchmark payloads are current.");
}

main();
