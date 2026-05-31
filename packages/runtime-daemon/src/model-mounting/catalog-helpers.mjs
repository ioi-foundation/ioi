import fs from "node:fs";
import path from "node:path";

import {
  normalizeNonNegativeInteger,
  normalizeOptionalBytes,
  normalizeScopes,
  runtimeError,
  safeFileName,
  safeId,
  stableHash,
  truthy,
} from "./io.mjs";

export function modelCatalogFileFormat(filePath) {
  const lower = String(filePath ?? "").toLowerCase();
  if (lower.endsWith(".gguf")) return "gguf";
  if (lower.includes("mlx")) return "mlx";
  if (lower.endsWith(".safetensors")) return "safetensors";
  return null;
}


export function catalogCompatibilityForFormat(format) {
  if (format === "gguf") return ["native_local_fixture", "llama_cpp"];
  if (format === "mlx") return ["mlx", "local_import"];
  if (format === "safetensors") return ["vllm", "openai_compatible"];
  if (format === "ollama") return ["ollama"];
  return ["local_import"];
}


export function huggingFaceResolveUrl(baseUrl, repoId, filePath) {
  const base = String(baseUrl).replace(/\/+$/, "");
  const pathPart = String(filePath)
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return `${base}/${repoId}/resolve/main/${pathPart}`;
}


export function modelFileScore(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.endsWith(".gguf")) return 3;
  if (name.endsWith(".safetensors")) return 2;
  if (name.endsWith(".onnx") || name.endsWith(".bin")) return 1;
  return 0;
}

export function catalogBackendCompatibility(entry) {
  const format = String(entry.format ?? "").toLowerCase();
  const compatibility = new Set(normalizeScopes(entry.compatibility, []));
  const rows = [
    backendCompatibilityRow("native_local_fixture", compatibility.has("native_local_fixture") || format === "gguf", format === "gguf" ? 92 : 70, "Autopilot native-local can import local model artifacts."),
    backendCompatibilityRow("llama_cpp", compatibility.has("llama_cpp") || format === "gguf", format === "gguf" ? 90 : 25, "llama.cpp expects GGUF artifacts."),
    backendCompatibilityRow("ollama", compatibility.has("ollama") || format === "gguf", format === "ollama" ? 88 : format === "gguf" ? 62 : 20, "Ollama can run catalog-listed Ollama models and local GGUF through import/create workflows when configured."),
    backendCompatibilityRow("vllm", compatibility.has("vllm") || format === "safetensors", format === "safetensors" ? 88 : 18, "vLLM expects Hugging Face/safetensors-style artifacts."),
  ];
  return rows;
}

export function backendCompatibilityRow(backendKind, compatible, score, reason) {
  return {
    backendKind,
    score: compatible ? score : Math.min(score, 20),
    status: compatible ? (score >= 80 ? "ready" : "compatible") : "unsupported",
    reason,
  };
}

export function catalogBenchmarkReadiness(entry) {
  const text = [entry.modelId, entry.family, entry.sourceLabel, ...(entry.tags ?? []), ...(entry.compatibility ?? [])].join(" ").toLowerCase();
  const embeddings = /embed|embedding|nomic|bge|e5/.test(text);
  const rerank = /rerank|cross-encoder/.test(text);
  const vision = /vision|llava|vlm|multimodal|image/.test(text);
  const chat = !embeddings && !rerank;
  return {
    chat,
    embeddings,
    rerank,
    vision,
    structuredOutput: chat,
    hints: [
      chat ? "chat-ready" : null,
      embeddings ? "embedding-ready" : null,
      rerank ? "rerank-ready" : null,
      vision ? "vision-ready" : null,
      entry.format === "gguf" ? "local-gguf-benchmark" : null,
      entry.format === "safetensors" ? "vllm-benchmark" : null,
    ].filter(Boolean),
  };
}

export function catalogDownloadRisk(entry, { storage = {}, artifacts = [], maxBytes = null } = {}) {
  const reasons = [];
  const sizeBytes = Number(entry.sizeBytes ?? 0);
  const byteCap = normalizeOptionalBytes(maxBytes);
  const existingArtifactCollision = artifacts.some((artifact) => artifact.modelId === entry.modelId || artifact.displayName === entry.modelId || artifact.id === entry.id);
  const quotaBytes = Number(storage.quotaBytes ?? 0) || null;
  const totalBytes = Number(storage.totalBytes ?? 0) || 0;
  let score = 10;
  let byteCapStatus = "not_set";
  if (byteCap) {
    byteCapStatus = sizeBytes && sizeBytes > byteCap ? "over_cap" : "within_cap";
    if (byteCapStatus === "over_cap") {
      score += 80;
      reasons.push("variant exceeds configured byte cap");
    }
  }
  if (quotaBytes && sizeBytes && totalBytes + sizeBytes > quotaBytes) {
    score += 55;
    reasons.push("download would exceed storage quota");
  }
  if (existingArtifactCollision) {
    score += 20;
    reasons.push("model id collides with an existing artifact");
  }
  if (!sizeBytes) {
    score += 15;
    reasons.push("variant size is unknown");
  }
  if (String(storage.quotaStatus ?? "") === "over_quota") {
    score += 40;
    reasons.push("storage is already over quota");
  }
  if (reasons.length === 0) reasons.push("size and storage projection are acceptable");
  const bounded = Math.min(100, score);
  return {
    score: bounded,
    status: bounded >= 85 ? "blocked" : bounded >= 55 ? "high" : bounded >= 30 ? "medium" : "low",
    reasons,
    existingArtifactCollision,
    byteCapStatus,
    storageStatus: String(storage.quotaStatus ?? "unknown"),
  };
}

export function catalogRecommendation({ backendCompatibility, benchmarkReadiness, downloadRisk }) {
  const primary = [...backendCompatibility].sort((left, right) => right.score - left.score)[0] ?? null;
  const readinessBoost = benchmarkReadiness.chat || benchmarkReadiness.embeddings ? 8 : 0;
  const riskPenalty = downloadRisk.status === "blocked" ? 80 : downloadRisk.status === "high" ? 35 : downloadRisk.status === "medium" ? 15 : 0;
  const score = Math.max(0, Math.min(100, (primary?.score ?? 0) + readinessBoost - riskPenalty));
  const label = downloadRisk.status === "blocked" ? "blocked" : score >= 80 ? "recommended" : "review";
  return {
    score,
    label,
    primaryBackend: primary?.backendKind ?? null,
    reasons: [
      primary ? `${primary.backendKind} ${primary.status}` : "no compatible backend",
      ...downloadRisk.reasons.slice(0, 2),
      ...benchmarkReadiness.hints.slice(0, 2),
    ],
  };
}

export function catalogApprovalDecision({ isFixture, body = {} }) {
  const approved = Boolean(body.transfer_approved ?? body.transferApproved ?? isFixture);
  return {
    required: !isFixture,
    approved,
    source: approved ? "operator_or_fixture" : "not_provided",
  };
}

export function normalizeDownloadPolicy(body = {}, { isFixture, maxBytes, source } = {}) {
  const bandwidthLimitBps = normalizeOptionalBytes(
    body.bandwidth_bps ??
      body.bandwidthBps ??
      body.bandwidth_limit_bps ??
      body.bandwidthLimitBps ??
      process.env.IOI_MODEL_DOWNLOAD_BANDWIDTH_BPS,
  );
  const retryLimit = normalizeNonNegativeInteger(body.retry_limit ?? body.retryLimit ?? body.retries ?? 0, 0);
  const resume = truthy(body.resume ?? body.resume_download ?? body.resumeDownload ?? true);
  const cleanupPartialOnCancel = truthy(body.cleanup_partial ?? body.cleanupPartial ?? true);
  const approvalDecision = catalogApprovalDecision({ isFixture, body });
  return {
    maxBytes,
    bandwidthLimitBps,
    retryLimit,
    resume,
    cleanupPartialOnCancel,
    externalTransferRequired: approvalDecision.required,
    externalTransferApproved: approvalDecision.approved,
    approvalDecision,
    sourceHash: stableHash(source),
    status: approvalDecision.required && !approvalDecision.approved ? "blocked_approval_required" : "ready",
    evidenceRefs: ["model_download_transfer_policy", "external_transfer_approval_receipt"],
  };
}

export function assertDownloadPolicyAllowed(policy, source) {
  if (!policy.externalTransferRequired || policy.externalTransferApproved) return;
  throw runtimeError({
    status: 403,
    code: "external_transfer_approval_required",
    message: "External model transfers require explicit operator approval.",
    details: {
      sourceHash: stableHash(source),
      approvalDecision: policy.approvalDecision,
      evidenceRefs: policy.evidenceRefs,
    },
  });
}

export function destructiveConfirmationState(body = {}, { required = true, action = "destructive_action" } = {}) {
  const confirmed = Boolean(body.confirm_destructive ?? body.confirmDestructive ?? body.destructive_confirmed ?? body.destructiveConfirmed ?? false);
  return {
    required,
    confirmed: required ? confirmed : true,
    action,
    source: confirmed ? "operator_confirmation" : required ? "not_provided" : "not_required",
  };
}

export function inferModelArchitecture(value) {
  const text = String(value ?? "").toLowerCase();
  if (/qwen/.test(text)) return "qwen";
  if (/llama|mistral|mixtral|vicuna|alpaca/.test(text)) return "llama";
  if (/nomic/.test(text)) return "nomic";
  if (/bge/.test(text)) return "bge";
  if (/gemma/.test(text)) return "gemma";
  if (/phi/.test(text)) return "phi";
  if (/bert|e5/.test(text)) return "bert";
  return "unknown";
}

export function inferParameterCount(value) {
  const match = String(value ?? "").match(/(?:^|[^a-z0-9])(\d+(?:\.\d+)?)\s?([bBmMkK])(?:[^a-z0-9]|$)/);
  if (!match) return null;
  return `${match[1]}${match[2].toUpperCase()}`;
}

export function modelIdFromSourceUrl(sourceUrl) {
  return safeId(String(sourceUrl).split(/[/?#]/).filter(Boolean).at(-1) ?? "catalog-model").replaceAll(".", "-");
}

export function sourceLabelForUrl(source) {
  if (String(source).startsWith("fixture://")) return "Fixture catalog";
  if (String(source).includes("huggingface.co")) return "Hugging Face";
  return "Model catalog";
}

export function normalizeImportMode(value) {
  const mode = String(value ?? "reference").toLowerCase().replaceAll("-", "_");
  if (["reference", "operator"].includes(mode)) return mode;
  if (["copy", "move", "hardlink", "symlink", "dry_run"].includes(mode)) return mode;
  throw runtimeError({
    status: 400,
    code: "bad_request",
    message: "Import mode must be copy, move, hardlink, symlink, dry_run, or reference.",
    details: { importMode: mode },
  });
}

export function importTargetPath(modelRoot, modelId, sourcePath) {
  const extension = path.extname(sourcePath) || ".gguf";
  return path.join(modelRoot, "imports", safeFileName(modelId), `${safeFileName(modelId)}${extension}`);
}

export function materializeImportArtifact(modelRoot, modelId, sourcePath, importMode) {
  if (["reference", "operator"].includes(importMode)) return sourcePath;
  const targetPath = importTargetPath(modelRoot, modelId, sourcePath);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.rmSync(targetPath, { force: true });
  if (importMode === "copy") fs.copyFileSync(sourcePath, targetPath);
  if (importMode === "move") fs.renameSync(sourcePath, targetPath);
  if (importMode === "hardlink") fs.linkSync(sourcePath, targetPath);
  if (importMode === "symlink") fs.symlinkSync(sourcePath, targetPath);
  return targetPath;
}

export function listModelFiles(root) {
  if (!fs.existsSync(root)) return [];
  const results = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const entryPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...listModelFiles(entryPath));
    } else if (entry.isFile() && modelFileScore(entryPath) > 0) {
      results.push(entryPath);
    }
  }
  return results.sort();
}
