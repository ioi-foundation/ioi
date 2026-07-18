import fs from "node:fs";
import path from "node:path";

function isWithin(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative))
  );
}

function nearestExistingAncestor(absolutePath) {
  let candidate = absolutePath;
  while (!fs.existsSync(candidate)) {
    const parent = path.dirname(candidate);
    if (parent === candidate) return null;
    candidate = parent;
  }
  return candidate;
}

export function safeRepositoryPath({
  root,
  boundaryRoot = root,
  relativePath,
  at,
  mustExist = false,
}) {
  if (
    typeof relativePath !== "string" ||
    relativePath.length === 0 ||
    relativePath.includes("\\") ||
    path.isAbsolute(relativePath) ||
    path.win32.isAbsolute(relativePath)
  ) {
    throw new Error(
      `${at}: path must be a non-empty repository-relative POSIX path`,
    );
  }
  const normalized = path.posix.normalize(relativePath);
  if (
    normalized !== relativePath ||
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../")
  ) {
    throw new Error(`${at}: path escapes or is not normalized: ${relativePath}`);
  }

  const rootAbsolute = path.resolve(root);
  const rootReal = fs.realpathSync(rootAbsolute);
  const boundaryAbsolute = path.resolve(boundaryRoot);
  if (!fs.existsSync(boundaryAbsolute)) {
    throw new Error(`${at}: path boundary does not exist: ${boundaryAbsolute}`);
  }
  const boundaryReal = fs.realpathSync(boundaryAbsolute);
  if (!isWithin(rootReal, boundaryReal)) {
    throw new Error(`${at}: path boundary resolves outside the repository`);
  }

  const absolute = path.resolve(boundaryAbsolute, relativePath);
  if (!isWithin(boundaryAbsolute, absolute)) {
    throw new Error(`${at}: path escapes its declared boundary: ${relativePath}`);
  }
  if (mustExist && !fs.existsSync(absolute)) {
    throw new Error(`${at}: path does not exist: ${relativePath}`);
  }
  const ancestor = nearestExistingAncestor(absolute);
  if (ancestor === null) {
    throw new Error(`${at}: path has no existing ancestor: ${relativePath}`);
  }
  const ancestorReal = fs.realpathSync(ancestor);
  if (!isWithin(boundaryReal, ancestorReal)) {
    throw new Error(
      `${at}: path resolves outside its declared boundary through a symlink: ${relativePath}`,
    );
  }
  if (fs.existsSync(absolute)) {
    const real = fs.realpathSync(absolute);
    if (!isWithin(boundaryReal, real)) {
      throw new Error(
        `${at}: path resolves outside its declared boundary through a symlink: ${relativePath}`,
      );
    }
  }
  return absolute;
}
