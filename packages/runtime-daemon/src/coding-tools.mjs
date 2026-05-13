import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export const CODING_TOOL_PACK_SCHEMA_VERSION = "ioi.runtime.coding-tool-pack.v1";
export const CODING_TOOL_RESULT_SCHEMA_VERSION = "ioi.runtime.coding-tool-result.v1";
export const CODING_TOOL_PACK_ID = "coding";
export const CODING_TOOL_IDS = new Set(["workspace.status", "git.diff", "file.inspect"]);

const CODING_TOOL_DEFAULT_PREVIEW_BYTES = 16 * 1024;
const CODING_TOOL_MAX_PREVIEW_BYTES = 64 * 1024;
const CODING_TOOL_DIFF_MAX_BYTES = 64 * 1024;

export function codingToolContracts() {
  return [
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "workspace.status",
      displayName: "Workspace status",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:workspace.status", "prim:git.status"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "workspace",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          includeIgnored: { type: "boolean" },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "git", "changedFiles", "shellFallbackUsed"],
      },
      evidenceRequirements: ["workspace_status_receipt", "coding_tool_receipt"],
      workflowNodeType: "CodingToolNode",
      workflowConfigFields: ["toolPack.coding.workspaceStatus", "toolPack.coding.gitEnabled"],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "git.diff",
      displayName: "Git diff",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:git.diff"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "git",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          paths: { type: "array", items: { type: "string" } },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_DIFF_MAX_BYTES },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "paths", "diff", "diffHash", "shellFallbackUsed"],
      },
      evidenceRequirements: ["git_diff_receipt", "coding_tool_receipt"],
      workflowNodeType: "GitToolNode",
      workflowConfigFields: ["toolPack.coding.gitEnabled", "toolPack.coding.allowedPaths"],
    },
    {
      schemaVersion: CODING_TOOL_PACK_SCHEMA_VERSION,
      stableToolId: "file.inspect",
      displayName: "Inspect file",
      pack: CODING_TOOL_PACK_ID,
      primitiveCapabilities: ["prim:fs.inspect"],
      authorityScopeRequirements: [],
      effectClass: "local_read",
      riskDomain: "filesystem",
      inputSchema: {
        type: "object",
        required: ["path"],
        additionalProperties: false,
        properties: {
          path: { type: "string" },
          maxBytes: { type: "integer", minimum: 1, maximum: CODING_TOOL_MAX_PREVIEW_BYTES },
          previewLines: { type: "integer", minimum: 1, maximum: 500 },
        },
      },
      outputSchema: {
        type: "object",
        required: ["workspaceRoot", "path", "kind", "exists", "shellFallbackUsed"],
      },
      evidenceRequirements: ["file_inspect_receipt", "coding_tool_receipt"],
      workflowNodeType: "FilesystemToolNode",
      workflowConfigFields: ["toolPack.coding.filesystemEnabled", "toolPack.coding.allowedPaths"],
    },
  ];
}

export function codingToolInputForRequest(request = {}) {
  if (!request || typeof request !== "object" || Array.isArray(request)) return {};
  const input = Object.hasOwn(request, "input") ? request.input : request;
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  return input;
}

export function executeCodingTool(toolId, workspaceRoot, input = {}) {
  switch (toolId) {
    case "workspace.status":
      return workspaceStatusTool(workspaceRoot, input);
    case "git.diff":
      return gitDiffTool(workspaceRoot, input);
    case "file.inspect":
      return fileInspectTool(workspaceRoot, input);
    default:
      throw codingToolError(404, "not_found", `Coding tool not found: ${toolId}`, {
        toolId,
        pack: CODING_TOOL_PACK_ID,
      });
  }
}

export function codingToolInputSummary(toolId, input = {}) {
  if (toolId === "file.inspect") return { path: optionalString(input.path) ?? null };
  if (toolId === "git.diff") return { paths: codingToolRawPathSummary(input) };
  if (toolId === "workspace.status") {
    return { includeIgnored: Boolean(input.includeIgnored ?? input.include_ignored) };
  }
  return {};
}

export function codingToolResultSummary(toolId, result = {}) {
  if (toolId === "workspace.status") {
    return {
      changed: Number(result?.counts?.changed ?? 0),
      branch: result?.git?.branch ?? null,
      gitAvailable: Boolean(result?.git?.available),
    };
  }
  if (toolId === "git.diff") {
    return {
      paths: normalizeArray(result?.paths),
      diffBytes: Number(result?.diffBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  if (toolId === "file.inspect") {
    return {
      path: result?.path ?? null,
      kind: result?.kind ?? null,
      sizeBytes: Number(result?.sizeBytes ?? 0),
      truncated: Boolean(result?.truncated),
    };
  }
  return {};
}

export function codingToolSummary(toolId, result = {}, status = "completed") {
  if (status === "failed") return `${toolId} failed.`;
  if (toolId === "workspace.status") {
    return `Workspace status inspected ${Number(result?.counts?.changed ?? 0)} changed file(s).`;
  }
  if (toolId === "git.diff") {
    return `Git diff inspected ${Number(result?.diffBytes ?? 0)} byte(s).`;
  }
  if (toolId === "file.inspect") {
    return `Inspected ${result?.kind ?? "path"} ${result?.path ?? ""}`.trim();
  }
  return `${toolId} completed.`;
}

export function codingToolSourceEventKind(toolId) {
  return `CodingTool.${toolId
    .split(".")
    .map((part) => part.slice(0, 1).toUpperCase() + part.slice(1))
    .join("")}`;
}

function workspaceStatusTool(workspaceRoot, input = {}) {
  const includeIgnored = Boolean(input.includeIgnored ?? input.include_ignored);
  const args = ["status", "--short", "--branch", "--untracked-files=all"];
  if (includeIgnored) args.push("--ignored");
  const status = execGitReadOnly(workspaceRoot, args);
  if (!status.ok) {
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      workspaceRoot,
      git: {
        available: false,
        status: "not_git_repository",
        error: status.stderr || status.stdout || "git status failed",
      },
      changedFiles: [],
      counts: { changed: 0, untracked: 0, ignored: 0 },
      shellFallbackUsed: false,
    };
  }
  const lines = status.stdout.split(/\r?\n/).filter(Boolean);
  const branch = lines.find((line) => line.startsWith("##"))?.replace(/^##\s*/, "") ?? null;
  const changedFiles = lines
    .filter((line) => !line.startsWith("##"))
    .map((line) => ({
      status: line.slice(0, 2).trim() || "modified",
      path: line.slice(3).trim(),
    }))
    .filter((entry) => entry.path);
  const counts = changedFiles.reduce(
    (acc, entry) => {
      acc.changed += 1;
      if (entry.status.includes("?")) acc.untracked += 1;
      if (entry.status.includes("!")) acc.ignored += 1;
      return acc;
    },
    { changed: 0, untracked: 0, ignored: 0 },
  );
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    git: {
      available: true,
      branch,
      porcelainHash: hashText(status.stdout),
    },
    changedFiles,
    counts,
    shellFallbackUsed: false,
  };
}

function gitDiffTool(workspaceRoot, input = {}) {
  const paths = codingToolPaths(workspaceRoot, input);
  const maxBytes = boundedInteger(
    input.maxBytes ?? input.max_bytes,
    CODING_TOOL_DIFF_MAX_BYTES,
    1,
    CODING_TOOL_DIFF_MAX_BYTES,
  );
  const args = ["diff", "--", ...paths.map((entry) => entry.relativePath)];
  const diffResult = execGitReadOnly(workspaceRoot, args);
  if (!diffResult.ok) {
    throw codingToolError(400, "git_diff_failed", "git diff failed for the requested workspace path(s).", {
      workspaceRoot,
      paths: paths.map((entry) => entry.relativePath),
      error: diffResult.stderr || diffResult.stdout,
    });
  }
  const statResult = execGitReadOnly(workspaceRoot, [
    "diff",
    "--stat",
    "--",
    ...paths.map((entry) => entry.relativePath),
  ]);
  const preview = utf8Preview(diffResult.stdout, maxBytes);
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    paths: paths.map((entry) => entry.relativePath),
    git: { available: true },
    diff: preview.text,
    diffBytes: Buffer.byteLength(diffResult.stdout, "utf8"),
    diffHash: hashText(diffResult.stdout),
    truncated: preview.truncated,
    stat: statResult.ok ? statResult.stdout : "",
    shellFallbackUsed: false,
  };
}

function fileInspectTool(workspaceRoot, input = {}) {
  const selectedPath = optionalString(input.path);
  if (!selectedPath) {
    throw codingToolError(400, "file_inspect_path_required", "file.inspect requires a workspace-relative path.", {
      toolId: "file.inspect",
    });
  }
  const target = resolveWorkspacePath(workspaceRoot, selectedPath);
  if (!fs.existsSync(target.absolutePath)) {
    throw codingToolError(404, "not_found", `File not found: ${target.relativePath}`, {
      workspaceRoot,
      path: target.relativePath,
    });
  }
  const stat = fs.statSync(target.absolutePath);
  if (stat.isDirectory()) {
    const entries = fs
      .readdirSync(target.absolutePath, { withFileTypes: true })
      .slice(0, 100)
      .map((entry) => ({
        name: entry.name,
        kind: entry.isDirectory() ? "directory" : entry.isFile() ? "file" : "other",
      }));
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      workspaceRoot,
      path: target.relativePath,
      kind: "directory",
      exists: true,
      sizeBytes: stat.size,
      entries,
      entryCount: entries.length,
      shellFallbackUsed: false,
    };
  }
  if (!stat.isFile()) {
    return {
      schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
      workspaceRoot,
      path: target.relativePath,
      kind: "other",
      exists: true,
      sizeBytes: stat.size,
      shellFallbackUsed: false,
    };
  }
  const maxBytes = boundedInteger(
    input.maxBytes ?? input.max_bytes,
    CODING_TOOL_DEFAULT_PREVIEW_BYTES,
    1,
    CODING_TOOL_MAX_PREVIEW_BYTES,
  );
  const previewLines = boundedInteger(input.previewLines ?? input.preview_lines, 200, 1, 500);
  const bytesToRead = Math.min(stat.size, maxBytes);
  const buffer = Buffer.alloc(bytesToRead);
  const fd = fs.openSync(target.absolutePath, "r");
  let bytesRead = 0;
  try {
    bytesRead = fs.readSync(fd, buffer, 0, bytesToRead, 0);
  } finally {
    fs.closeSync(fd);
  }
  const preview = buffer.subarray(0, bytesRead).toString("utf8");
  const lines = preview.split(/\r?\n/);
  const linePreview = lines.slice(0, previewLines).join("\n");
  return {
    schemaVersion: CODING_TOOL_RESULT_SCHEMA_VERSION,
    workspaceRoot,
    path: target.relativePath,
    kind: "file",
    exists: true,
    sizeBytes: stat.size,
    preview: linePreview,
    previewBytes: Buffer.byteLength(linePreview, "utf8"),
    previewHash: hashText(linePreview),
    truncated: bytesRead < stat.size || lines.length > previewLines,
    previewLineCount: Math.min(lines.length, previewLines),
    shellFallbackUsed: false,
  };
}

function codingToolPaths(workspaceRoot, input = {}) {
  const rawPaths = [
    ...codingToolPathList(input.paths),
    ...codingToolPathList(input.path),
  ].map((value) => optionalString(value)).filter(Boolean);
  return rawPaths.length
    ? rawPaths.map((selectedPath) => resolveWorkspacePath(workspaceRoot, selectedPath))
    : [];
}

function codingToolPathList(value) {
  if (Array.isArray(value)) return value;
  const text = optionalString(value);
  return text ? [text] : [];
}

function resolveWorkspacePath(workspaceRoot, selectedPath) {
  const root = path.resolve(workspaceRoot);
  const absolutePath = path.isAbsolute(selectedPath)
    ? path.resolve(selectedPath)
    : path.resolve(root, selectedPath);
  const relativePath = path.relative(root, absolutePath) || ".";
  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw codingToolError(403, "policy", "Coding tool path must stay inside the workspace root.", {
      workspaceRoot: root,
      path: selectedPath,
    });
  }
  return { absolutePath, relativePath };
}

function execGitReadOnly(workspaceRoot, args) {
  try {
    return {
      ok: true,
      stdout: execFileSync("git", ["-C", workspaceRoot, ...args], {
        encoding: "utf8",
        maxBuffer: 4 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      }),
      stderr: "",
      exitCode: 0,
    };
  } catch (error) {
    return {
      ok: false,
      stdout: String(error?.stdout ?? ""),
      stderr: String(error?.stderr ?? error?.message ?? ""),
      exitCode: Number(error?.status ?? error?.code ?? 1),
    };
  }
}

function boundedInteger(value, fallback, min, max) {
  const number = Number(value ?? fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(number)));
}

function utf8Preview(text, maxBytes) {
  const buffer = Buffer.from(String(text ?? ""), "utf8");
  if (buffer.byteLength <= maxBytes) {
    return { text: String(text ?? ""), truncated: false };
  }
  return {
    text: buffer.subarray(0, maxBytes).toString("utf8"),
    truncated: true,
  };
}

function codingToolRawPathSummary(input = {}) {
  return [
    ...codingToolPathList(input.paths),
    ...codingToolPathList(input.path),
  ].map((value) => optionalString(value)).filter(Boolean);
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}

function hashText(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function codingToolError(status, code, message, details) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}
