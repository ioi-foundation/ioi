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

function lstatIfPresent(candidate) {
  try {
    return fs.lstatSync(candidate);
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return null;
    }
    throw error;
  }
}

function assertNoSymlinkComponents({ base, candidate, at, relativePath }) {
  const baseStat = lstatIfPresent(base);
  if (baseStat === null) {
    throw new Error(`${at}: path boundary does not exist: ${base}`);
  }
  if (baseStat.isSymbolicLink()) {
    throw new Error(
      `${at}: path contains a symlink component: ${relativePath}`,
    );
  }

  const relative = path.relative(base, candidate);
  let current = base;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    const stat = lstatIfPresent(current);
    if (stat === null) break;
    if (stat.isSymbolicLink()) {
      throw new Error(
        `${at}: path contains a symlink component: ${relativePath}`,
      );
    }
  }
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
  const rootStat = lstatIfPresent(rootAbsolute);
  if (rootStat === null || !rootStat.isDirectory()) {
    throw new Error(`${at}: repository root is not a directory: ${rootAbsolute}`);
  }
  if (rootStat.isSymbolicLink()) {
    throw new Error(`${at}: repository root must not be a symlink`);
  }
  const rootReal = fs.realpathSync(rootAbsolute);
  const boundaryAbsolute = path.resolve(boundaryRoot);
  if (!isWithin(rootAbsolute, boundaryAbsolute)) {
    throw new Error(`${at}: path boundary escapes the repository`);
  }
  assertNoSymlinkComponents({
    base: rootAbsolute,
    candidate: boundaryAbsolute,
    at,
    relativePath: path.relative(rootAbsolute, boundaryAbsolute) || ".",
  });
  const boundaryStat = lstatIfPresent(boundaryAbsolute);
  if (boundaryStat === null || !boundaryStat.isDirectory()) {
    throw new Error(`${at}: path boundary is not a directory: ${boundaryAbsolute}`);
  }
  const boundaryReal = fs.realpathSync(boundaryAbsolute);
  if (!isWithin(rootReal, boundaryReal)) {
    throw new Error(`${at}: path boundary resolves outside the repository`);
  }

  const absolute = path.resolve(boundaryAbsolute, relativePath);
  if (!isWithin(boundaryAbsolute, absolute)) {
    throw new Error(`${at}: path escapes its declared boundary: ${relativePath}`);
  }
  assertNoSymlinkComponents({
    base: boundaryAbsolute,
    candidate: absolute,
    at,
    relativePath,
  });
  const targetStat = lstatIfPresent(absolute);
  if (mustExist && targetStat === null) {
    throw new Error(`${at}: path does not exist: ${relativePath}`);
  }
  if (targetStat !== null) {
    const real = fs.realpathSync(absolute);
    if (!isWithin(boundaryReal, real)) {
      throw new Error(
        `${at}: path resolves outside its declared boundary through a symlink: ${relativePath}`,
      );
    }
  }
  return absolute;
}
