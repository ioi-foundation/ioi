#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import zlib from "node:zlib";
import * as acorn from "acorn";
import {
  checkDeterministic,
  failWith,
  implementationRelative,
  implementationRoot,
  readJson,
  repoRelative,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  writeDeterministic,
} from "./lib.mjs";
import {
  EMBED_THREAD_ROUTES,
  SURFACES,
  boundSurface,
  embeddableRoutes,
} from "../../../apps/hypervisor/scripts/surface-registry.mjs";
import { appCatalog } from "../../../apps/hypervisor/scripts/app-catalog.mjs";

const OUTPUT = path.join(
  implementationRoot,
  "generated",
  "hypervisor-surface-coverage.v1.json",
);
const LIVE_CRAWL_EVIDENCE = path.join(
  implementationRoot,
  "evidence",
  "hypervisor-live-read-only-crawl.v1.json",
);
const VISUAL_EVIDENCE_ROOT = path.join(implementationRoot, "evidence");
const REQUIRED_VISUAL_VIEWPORTS = ["desktop", "narrow"];

const rel = (value) => repoRelative(value);
const fromRepo = (...parts) => path.join(repoRoot, ...parts);
const readText = (file) => fs.readFileSync(file, "utf8");
const sorted = (values) => [...values].sort((left, right) => left.localeCompare(right));
const uniqueSorted = (values) => sorted(new Set(values));

function resolveVisualEvidenceArtifact(
  relativePath,
  { artifactPathBase = implementationRoot, evidenceRoot = VISUAL_EVIDENCE_ROOT } = {},
) {
  if (typeof relativePath !== "string" || relativePath.length === 0 || path.isAbsolute(relativePath)) {
    return { error: "artifact path must be a non-empty implementation-relative path" };
  }
  const absolute = path.resolve(artifactPathBase, relativePath);
  const relativeToEvidence = path.relative(evidenceRoot, absolute);
  if (
    relativeToEvidence.length === 0 ||
    relativeToEvidence.startsWith(`..${path.sep}`) ||
    relativeToEvidence === ".." ||
    path.isAbsolute(relativeToEvidence)
  ) {
    return { error: `${relativePath} must resolve below evidence/` };
  }
  if (!fs.existsSync(absolute)) return { error: `${relativePath} does not exist` };
  if (!fs.statSync(absolute).isFile()) return { error: `${relativePath} is not a regular file` };
  const realEvidenceRoot = fs.realpathSync(evidenceRoot);
  const realAbsolute = fs.realpathSync(absolute);
  const realRelative = path.relative(realEvidenceRoot, realAbsolute);
  if (
    realRelative.length === 0 ||
    realRelative.startsWith(`..${path.sep}`) ||
    realRelative === ".." ||
    path.isAbsolute(realRelative)
  ) {
    return { error: `${relativePath} resolves outside evidence/` };
  }
  return { absolute };
}

function inspectPng(file) {
  const bytes = fs.readFileSync(file);
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (bytes.length < 45 || !bytes.subarray(0, 8).equals(signature)) return null;
  const chunks = [];
  let offset = 8;
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) return null;
    const length = bytes.readUInt32BE(offset);
    const end = offset + 12 + length;
    if (end > bytes.length) return null;
    const typeBytes = bytes.subarray(offset + 4, offset + 8);
    const type = typeBytes.toString("ascii");
    if (!/^[A-Za-z]{4}$/u.test(type)) return null;
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    const expectedCrc = bytes.readUInt32BE(offset + 8 + length);
    if (crc32(Buffer.concat([typeBytes, data])) !== expectedCrc) return null;
    chunks.push({ type, data });
    offset = end;
  }
  if (offset !== bytes.length || chunks.length < 3) return null;
  if (chunks[0].type !== "IHDR" || chunks[0].data.length !== 13) return null;
  if (chunks.at(-1).type !== "IEND" || chunks.at(-1).data.length !== 0) return null;
  if (chunks.filter((chunk) => chunk.type === "IHDR").length !== 1) return null;
  if (chunks.filter((chunk) => chunk.type === "IEND").length !== 1) return null;
  const knownCritical = new Set(["IHDR", "PLTE", "IDAT", "IEND"]);
  if (chunks.some((chunk) => /^[A-Z]/u.test(chunk.type) && !knownCritical.has(chunk.type))) return null;

  const ihdr = chunks[0].data;
  const widthPx = ihdr.readUInt32BE(0);
  const heightPx = ihdr.readUInt32BE(4);
  const bitDepth = ihdr[8];
  const colorType = ihdr[9];
  const compression = ihdr[10];
  const filter = ihdr[11];
  const interlace = ihdr[12];
  const legalBitDepths = new Map([
    [0, new Set([1, 2, 4, 8, 16])],
    [2, new Set([8, 16])],
    [3, new Set([1, 2, 4, 8])],
    [4, new Set([8, 16])],
    [6, new Set([8, 16])],
  ]);
  if (
    widthPx === 0
    || heightPx === 0
    || !legalBitDepths.get(colorType)?.has(bitDepth)
    || compression !== 0
    || filter !== 0
    || interlace !== 0
  ) return null;
  const idatIndexes = chunks
    .map((chunk, index) => chunk.type === "IDAT" ? index : -1)
    .filter((index) => index >= 0);
  if (idatIndexes.length === 0) return null;
  if (idatIndexes.some((index, position) => position > 0 && index !== idatIndexes[position - 1] + 1)) return null;
  const paletteIndex = chunks.findIndex((chunk) => chunk.type === "PLTE");
  if (colorType === 3 && (paletteIndex < 0 || paletteIndex > idatIndexes[0])) return null;
  let inflated;
  try {
    inflated = zlib.inflateSync(Buffer.concat(idatIndexes.map((index) => chunks[index].data)));
  } catch {
    return null;
  }
  const channelsByColorType = new Map([[0, 1], [2, 3], [3, 1], [4, 2], [6, 4]]);
  const scanlineBytes = Math.ceil(widthPx * channelsByColorType.get(colorType) * bitDepth / 8);
  if (inflated.length !== heightPx * (scanlineBytes + 1)) return null;
  for (let row = 0; row < heightPx; row += 1) {
    if (inflated[row * (scanlineBytes + 1)] > 4) return null;
  }
  return { width_px: widthPx, height_px: heightPx };
}

// Visual evidence has two honest terminal shapes. A capability failure remains an
// explicit SKIP. A capture is admitted only when the separately retained crawl
// artifact names both viewport classes, the in-app browser, read-only observations,
// and content-addressed PNGs whose actual dimensions agree with the declarations.
export function inspectVisualBrowserAttempt(
  attempt,
  {
    safeRoutes = [],
    requiredRoutes = [],
    artifactPathBase = implementationRoot,
    evidenceRoot = VISUAL_EVIDENCE_ROOT,
  } = {},
) {
  const errors = [];
  const artifactFiles = [];
  const expect = (condition, message) => { if (!condition) errors.push(message); };
  const safeRouteSet = new Set(safeRoutes);
  const requiredRouteSet = new Set(requiredRoutes);
  const requiredViewports = Array.isArray(attempt?.required_viewports)
    ? attempt.required_viewports
    : [];
  expect(!!attempt && typeof attempt === "object" && !Array.isArray(attempt), "visual_browser_attempt is missing");
  expect(new Set(["SKIP", "EVIDENCE_CAPTURED"]).has(attempt?.result), "visual_browser_attempt result must be SKIP or EVIDENCE_CAPTURED");
  expect(
    stableJson(requiredViewports) === stableJson(REQUIRED_VISUAL_VIEWPORTS),
    "visual_browser_attempt must retain the exact desktop and narrow viewport obligations",
  );
  expect(requiredRouteSet.size === requiredRoutes.length, "required visual route inventory contains duplicates");
  for (const requiredRoute of requiredRouteSet) {
    expect(safeRouteSet.has(requiredRoute), `required visual route ${requiredRoute} is not in the current safe GET inventory`);
  }

  if (attempt?.result === "SKIP") {
    expect(attempt.reason_code === "in_app_browser_unavailable", "visual SKIP reason must be in_app_browser_unavailable");
    expect(
      typeof attempt.detail === "string" && attempt.detail.includes("Browser is not available: iab"),
      "visual SKIP must retain the exact in-app-browser capability failure",
    );
    expect(
      typeof attempt.nonclaim === "string" && attempt.nonclaim.includes("not visual evidence"),
      "visual SKIP must state that the HTTP crawl is not visual evidence",
    );
    return { errors, artifact_files: artifactFiles };
  }

  if (attempt?.result !== "EVIDENCE_CAPTURED") return { errors, artifact_files: artifactFiles };
  expect(attempt.capture_tool === "in_app_browser", "captured visual evidence must identify the in-app browser");
  expect(attempt.interaction_policy === "read_only", "captured visual evidence must remain read-only");
  expect(
    typeof attempt.captured_at === "string" && /Z$/u.test(attempt.captured_at) && Number.isFinite(Date.parse(attempt.captured_at)),
    "captured visual evidence must retain an ISO-8601 UTC captured_at value",
  );
  const scopes = Array.isArray(attempt.scopes) ? attempt.scopes : [];
  expect(scopes.length === REQUIRED_VISUAL_VIEWPORTS.length, "captured visual evidence must contain exactly two viewport scopes");
  expect(
    stableJson(scopes.map((scope) => scope.viewport)) === stableJson(REQUIRED_VISUAL_VIEWPORTS),
    "captured visual evidence scopes must be ordered desktop then narrow",
  );
  for (const scope of scopes) {
    const label = `visual ${scope?.viewport || "unknown"} scope`;
    expect(scope?.interaction_policy === "read_only", `${label} must remain read-only`);
    expect(Number.isInteger(scope?.width_px) && scope.width_px > 0, `${label} lacks a positive integer width_px`);
    expect(Number.isInteger(scope?.height_px) && scope.height_px > 0, `${label} lacks a positive integer height_px`);
    if (scope?.viewport === "desktop") expect(scope.width_px >= 1024, `${label} must be at least 1024px wide`);
    if (scope?.viewport === "narrow") expect(scope.width_px >= 280 && scope.width_px < 768, `${label} must be 280-767px wide`);

    const observations = Array.isArray(scope?.route_observations)
      ? scope.route_observations
      : [];
    expect(observations.length > 0, `${label} lacks route-level observations`);
    expect(
      new Set(observations.map((observation) => observation?.route)).size === observations.length,
      `${label} contains duplicate route observations`,
    );
    const observedRoutes = new Set(observations.map((observation) => observation?.route));
    for (const requiredRoute of requiredRouteSet) {
      expect(observedRoutes.has(requiredRoute), `${label} is missing required registered surface route ${requiredRoute}`);
    }
    for (const observation of observations) {
      expect(
        typeof observation?.route === "string" && safeRouteSet.has(observation.route),
        `${label} observation ${observation?.route || "<missing>"} is not in the current safe GET inventory`,
      );
      expect(
        typeof observation?.observation === "string" && observation.observation.trim().length > 0,
        `${label} observation ${observation?.route || "<missing>"} lacks an honest observation`,
      );
    }

    const evidenceRefs = Array.isArray(scope?.evidence_refs) ? scope.evidence_refs : [];
    expect(evidenceRefs.length > 0, `${label} lacks retained screenshot references`);
    expect(
      new Set(evidenceRefs.map((ref) => ref?.path)).size === evidenceRefs.length,
      `${label} contains duplicate screenshot paths`,
    );
    for (const ref of evidenceRefs) {
      const refLabel = `${label} artifact ${ref?.path || "<missing>"}`;
      expect(ref?.kind === "viewport_screenshot", `${refLabel} must have kind viewport_screenshot`);
      expect(ref?.media_type === "image/png", `${refLabel} must have media_type image/png`);
      expect(/^[0-9a-f]{64}$/u.test(ref?.sha256 || ""), `${refLabel} lacks a SHA-256 digest`);
      const resolved = resolveVisualEvidenceArtifact(ref?.path, {
        artifactPathBase,
        evidenceRoot,
      });
      if (resolved.error) {
        errors.push(`${refLabel}: ${resolved.error}`);
        continue;
      }
      artifactFiles.push(resolved.absolute);
      expect(sha256File(resolved.absolute) === ref.sha256, `${refLabel} digest does not match the retained file`);
      const dimensions = inspectPng(resolved.absolute);
      expect(!!dimensions, `${refLabel} is not a complete decodable non-interlaced PNG`);
      if (dimensions) {
        expect(dimensions.width_px === scope.width_px, `${refLabel} width does not match scope width_px`);
        expect(dimensions.height_px === scope.height_px, `${refLabel} height does not match scope height_px`);
      }
    }
  }
  const nonclaims = Array.isArray(attempt.nonclaims) ? attempt.nonclaims : [];
  const nonclaimText = nonclaims.join(" ").toLowerCase();
  expect(nonclaims.length >= 3, "captured visual evidence must retain at least three nonclaims");
  expect(nonclaimText.includes("point-in-time"), "captured visual evidence must remain a point-in-time claim");
  expect(nonclaimText.includes("implementation"), "captured visual evidence must deny implementation proof");
  expect(nonclaimText.includes("program status"), "captured visual evidence must deny program-status authority");
  expect(
    typeof attempt.remaining_obligation === "string" && attempt.remaining_obligation.trim().length > 0,
    "captured visual evidence must retain a remaining obligation",
  );
  return { errors, artifact_files: uniqueSorted(artifactFiles) };
}

function buildVisualVerification(liveCrawl) {
  const attempt = liveCrawl?.visual_browser_attempt;
  if (attempt?.result === "EVIDENCE_CAPTURED") {
    const attemptScopes = Array.isArray(attempt.scopes) ? attempt.scopes : [];
    return {
      result: "EVIDENCE_CAPTURED",
      verification_state: "retained_viewport_evidence",
      evidence_role: "point-in-time read-only viewport evidence; never implementation, workflow-completeness, or program-status proof",
      evidence_path: implementationRelative(LIVE_CRAWL_EVIDENCE),
      evidence_sha256: sha256File(LIVE_CRAWL_EVIDENCE),
      captured_at: attempt.captured_at,
      capture_tool: attempt.capture_tool,
      interaction_policy: attempt.interaction_policy,
      required_scopes: REQUIRED_VISUAL_VIEWPORTS.map((viewport) => {
        const scope = attemptScopes.find((candidate) => candidate.viewport === viewport) || {};
        const routeObservations = Array.isArray(scope.route_observations)
          ? scope.route_observations
          : [];
        const evidenceRefs = Array.isArray(scope.evidence_refs) ? scope.evidence_refs : [];
        return {
          viewport,
          interaction_policy: scope.interaction_policy,
          verification_state: "evidence_captured",
          width_px: scope.width_px,
          height_px: scope.height_px,
          route_observation_count: routeObservations.length,
          route_observations: routeObservations,
          evidence_refs: evidenceRefs,
        };
      }),
      remaining_obligation: attempt.remaining_obligation,
      nonclaims: Array.isArray(attempt.nonclaims) ? attempt.nonclaims : [],
    };
  }
  if (attempt?.result === "SKIP") {
    return {
      result: "SKIP",
      verification_state: "unverified",
      reason_code: attempt.reason_code,
      skip_detail: attempt.detail,
      required_scopes: REQUIRED_VISUAL_VIEWPORTS.map((viewport) => ({
        viewport,
        interaction_policy: "read_only",
        verification_state: "unverified",
      })),
      remaining_obligation: "Repeat the desktop and narrow read-only surface crawl with the in-app browser when that capability is available; record route-level observations separately from this static projection.",
      nonclaims: [
        "Static source coverage is not visual verification.",
        "An HTTP 200 response proves transport reachability only; it does not prove rendering, interaction, responsive behavior, accessibility, or workflow completeness.",
        "No desktop or narrow-viewport surface is visually verified by this record.",
      ],
    };
  }
  return {
    result: "MISSING",
    verification_state: "unverified",
    required_scopes: REQUIRED_VISUAL_VIEWPORTS.map((viewport) => ({
      viewport,
      interaction_policy: "read_only",
      verification_state: "unverified",
    })),
    remaining_obligation: "Retain either the exact in-app-browser-unavailable SKIP or content-addressed desktop and narrow in-app-browser evidence.",
    nonclaims: ["No visual verification evidence is retained by this projection."],
  };
}

function countBy(values, keyOf) {
  const counts = {};
  for (const value of values) {
    const key = keyOf(value);
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)));
}

function walkFiles(root, accept = () => true) {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && accept(absolute)) files.push(absolute);
    }
  };
  visit(root);
  return sorted(files);
}

function treeSnapshot(files) {
  const rows = sorted(files).map((file) => `${rel(file)}\u0000${sha256File(file)}`);
  return { file_count: rows.length, sha256: sha256(`${rows.join("\n")}\n`) };
}

function oneAsset(publicRoot, prefix) {
  const matches = fs
    .readdirSync(path.join(publicRoot, "static", "assets"))
    .filter((name) => name.startsWith(prefix) && name.endsWith(".js"))
    .sort();
  if (matches.length !== 1) {
    throw new Error(`expected one ${prefix}*.js asset under ${rel(publicRoot)}, found ${matches.length}`);
  }
  return path.join(publicRoot, "static", "assets", matches[0]);
}

// The safe crawl is a deliberately finite read-only survey: 35 current shell/native GETs plus
// the 39 executable reference seed routes. It is reachability coverage, never a workflow claim.
const SAFE_NATIVE_GETS = [
  "/ai",
  "/projects",
  "/__ioi/home",
  "/__ioi/sessions",
  "/__ioi/applications",
  "/__ioi/search",
  "/__ioi/code",
  "/__ioi/run-timeline",
  "/__ioi/run-replay",
  "/__ioi/agent-studio",
  "/__ioi/studio/designer",
  "/__ioi/studio/machinery",
  "/__ioi/automations",
  "/__ioi/automations/monitors",
  "/__ioi/ontology/manager",
  "/__ioi/ontology/explorer",
  "/__ioi/odk",
  "/__ioi/data/sources",
  "/__ioi/pipeline",
  "/__ioi/governance",
  "/__ioi/governance/approvals",
  "/__ioi/missions",
  "/__ioi/missions/incidents",
  "/__ioi/work-ledger",
  "/__ioi/evaluations",
  "/__ioi/evaluations/evalsuites",
  "/__ioi/improvement/changes",
  "/__ioi/foundry",
  "/__ioi/foundry/models",
  "/__ioi/marketplace",
  "/__ioi/connections",
  "/__ioi/environments",
  "/__ioi/operations",
  "/__ioi/domain-apps",
  "/__ioi/workbench",
];

// Normalization is audit notation over finite handler branches and module action descriptors.
// Placeholder names do not create open-ended authority; the underlying sources enumerate the
// accepted kind/action/transition vocabularies and the projection retains their source hashes.
const NORMALIZED_IOI_ROUTE_TEMPLATES = [
  "GET|POST /__ioi/login",
  "GET /__ioi/login/sso/:configId",
  "GET /__ioi/login/sso/callback",
  "GET|POST /__ioi/invite/:inviteId",
  "GET /__ioi/logout",
  "POST /__ioi/run-publish/:runId",
  "GET /__ioi/github-app/start",
  "GET /__ioi/github-app/callback",
  "GET /__ioi/github-app/installed",
  "GET /__ioi/integrations/connect/:connectorId",
  "GET /__ioi/integrations/oauth/callback",
  "GET|POST /__ioi/slack/setup",
  "GET /__ioi/connections",
  "GET|POST /__ioi/connections/add",
  "GET /__ioi/editor/open",
  "GET /__ioi/run-timeline/:runId",
  "GET /__ioi/run-timeline/goal-run/:goalRunId",
  "GET /__ioi/run-timeline/env/:environmentId",
  "GET /__ioi/run-timeline/draft/:draftId",
  "GET /__ioi/env-latest-run/:environmentId",
  "GET /__ioi/agent-runs/:runId/timeline",
  "GET /__ioi/agent-runs/:runId/conversation",
  "GET /__ioi/agent-runs/:runId/conversation/history",
  "GET /__ioi/agent-runs/:runId/conversation/live",
  "POST /__ioi/api/new-session/launch",
  "POST /__ioi/api/ioi-agent/preview",
  "POST /__ioi/api/ioi-agent/launch",
  "GET|PUT|POST /__ioi/api/placement/venue-policy",
  "GET|POST /__ioi/automations",
  "GET /__ioi/automations.json",
  "GET /__ioi/automations/new",
  "GET /__ioi/automations/cron-preview",
  "GET /__ioi/automations/monitors",
  "GET /__ioi/automations/:automationId",
  "POST /__ioi/automations/:automationId/run",
  "POST /__ioi/automations/:automationId/pause",
  "POST /__ioi/automations/:automationId/resume",
  "POST /__ioi/automations/:automationId/patch",
  "POST /__ioi/automations/:automationId/webhook-rotate",
  "POST /__ioi/automations/:automationId/delete",
  "GET|POST /__ioi/feedback",
  "POST /__ioi/feedback/:feedbackId/transition",
  "GET|POST /__ioi/evaluations",
  "GET /__ioi/evaluations/evalsuites",
  "GET /__ioi/improvement/changes",
  "POST /__ioi/evaluations/:suiteId/delete",
  "POST /__ioi/agent-studio/intel/:kind",
  "POST /__ioi/agent-studio/intel/:kind/:id/:transition",
  "POST /__ioi/agent-studio/improvements/:id/simulate",
  "POST /__ioi/agent-studio/improvements/propose",
  "POST /__ioi/agent-studio/improvements/:id/:decision",
  "POST /__ioi/agent-studio/improvements/:id/governance/:action",
  "POST /__ioi/agent-studio/governance/:kind/:id/:transition",
  "POST /__ioi/agent-studio/proposals/:id/:decision",
  "POST /__ioi/agent-studio/launch-policies",
  "POST /__ioi/agent-studio/launch-policies/:id/:action",
  "POST /__ioi/agent-studio/launch-policies/:id/rollout/:action",
  "POST /__ioi/agent-studio/model-routes/:id/:action",
  "POST /__ioi/agent-studio/harness-profiles/:id/:action",
  "GET /__ioi/intelligence/simulations/:id",
  "GET /__ioi/intelligence/projections/:id/explain",
  "GET /__ioi/agent-studio/vault/export",
  "POST /__ioi/agent-studio/vault/import",
  "GET /__ioi/agent-studio",
  "GET /__ioi/agent-studio/intel/graph",
  "GET /__ioi/api/applications",
  "GET /__ioi/api/new-session/context",
  "GET /__ioi/applications",
  "GET /__ioi/code",
  "GET /__ioi/environments",
  "GET /__ioi/home",
  "GET /__ioi/lineage",
  "GET /__ioi/missions/incidents",
  "GET /__ioi/operations",
  "GET /__ioi/run-replay",
  "GET /__ioi/run-timeline",
  "GET /__ioi/search",
  "GET /__ioi/sessions",
  "GET /__ioi/studio/designer",
  "GET /__ioi/studio/machinery",
  "GET /__ioi/vertex",
  "GET /__ioi/work-ledger",
  "GET /__ioi/workbench",
  "GET /__ioi/foundry",
  "GET /__ioi/foundry/models",
  "GET /__ioi/foundry/specs/new",
  "POST /__ioi/foundry/specs",
  "GET /__ioi/foundry/specs/:id",
  "GET /__ioi/foundry/specs/:id/edit",
  "POST /__ioi/foundry/specs/:id/patch",
  "POST /__ioi/foundry/specs/:id/delete",
  "GET /__ioi/foundry/run-plans/new",
  "POST /__ioi/foundry/run-plans",
  "GET /__ioi/foundry/run-plans/:id",
  "POST /__ioi/foundry/run-plans/:id/delete",
  "GET /__ioi/odk/:kind/new",
  "GET /__ioi/odk",
  "POST /__ioi/odk/:kind",
  "GET /__ioi/odk/:kind/:id",
  "GET /__ioi/odk/:kind/:id/edit",
  "POST /__ioi/odk/:kind/:id/patch",
  "POST /__ioi/odk/:kind/:id/delete",
  "GET|POST /__ioi/domain-apps",
  "GET /__ioi/domain-apps/new",
  "GET /__ioi/domain-apps/:id",
  "GET /__ioi/domain-apps/:id/edit",
  "POST /__ioi/domain-apps/:id/:action",
  "GET /__ioi/domain-app-runtime/:runtimeId",
  "GET /__ioi/governance",
  "POST /__ioi/governance/:kind",
  "POST /__ioi/governance/:kind/:id/transition",
  "POST /__ioi/governance/:kind/:id/delete",
  "POST /__ioi/governance/kill-switches/:id/enforce",
  "GET|POST /__ioi/marketplace/listings",
  "GET /__ioi/marketplace",
  "GET /__ioi/marketplace/listings/new",
  "GET /__ioi/marketplace/listings/:id",
  "GET /__ioi/marketplace/listings/:id/edit",
  "POST /__ioi/marketplace/listings/:id/:action",
  "POST /__ioi/marketplace/candidates/:id/:action",
  "POST /__ioi/marketplace/reviews/:id",
  "POST /__ioi/marketplace/offers/:id",
  "POST /__ioi/pipeline/actions/admit-run",
  "POST /__ioi/pipeline/:id/submit-lease-grant",
  "POST /__ioi/pipeline/:id/cancel-run",
  "POST /__ioi/pipeline/:id/release-lease",
  "POST /__ioi/pipeline/:id/admit-session",
  "POST /__ioi/pipeline/:id/submit-session-grant",
  "POST /__ioi/pipeline/:id/release-session",
  "POST /__ioi/pipeline/:id/execute",
  "POST /__ioi/data/sources/actions/declare",
  "POST /__ioi/ontology/manager/actions/create-ontology",
  "POST /__ioi/ontology/manager/actions/update-metadata",
  "POST /__ioi/ontology/manager/actions/upsert-value-type",
  "POST /__ioi/ontology/manager/actions/upsert-object-type",
  "POST /__ioi/ontology/manager/actions/upsert-property",
  "POST /__ioi/ontology/manager/actions/upsert-link-type",
  "POST /__ioi/ontology/manager/actions/upsert-action-type",
  "POST /__ioi/governance/approvals/:id/transition",
];

const CANONICAL_TAXONOMY_HEADINGS = {
  "Core workspaces": "core_workspace",
  "Owner applications": "owner_application",
  "Substrate applications (type 1 + 2 face)": "substrate_application",
  "Conditional specialist owner application": "conditional_owner_application",
};

// These are handler infrastructure, test, or normalization branches rather than product-route
// templates. Every other exact /__ioi pathname branch must have a normalized template.
const NON_PRODUCT_IOI_EXACT_ROUTES = new Set([
  "/__ioi/__test/boom",
  "/__ioi/fallthrough",
  "/__ioi/fallthrough/reset",
]);

// Updated only when a review accounts for every changed source-derived route decision and its
// normalized template mapping. The projection also emits the full guard inventory, so this is a
// change detector rather than an opaque claim of coverage.
const REVIEWED_IOI_HANDLER_GUARD_INVENTORY_SHA256 = "182e40e3e0325fe10d289e13f67622a1af82d8a9983d883b8b21a5f89df6aea4";

const NORMALIZED_IOI_SOURCE_ANCHOR_OVERRIDES = {
  "GET /__ioi/run-timeline/draft/:draftId": [
    '/__ioi/run-timeline/',
    'rest.startsWith("draft/")',
  ],
};

const PROXY_SUFFIX_FAMILIES = [
  "/assets/content-addressable-storage/*",
  "/v1/*",
  "/scim/*",
  "/supervisor/*",
  "/supervisor/:environmentId/supervisor.v1.EnvironmentOpsService/:method",
  "/supervisor.v1.EnvironmentOpsService/* (websocket family)",
  "/segment/*",
  "/sentry*",
  "/sentry-tunnel",
  "/api/*",
];

const INTERCEPT_PATTERNS = [
  "/interventions/api/interventions/v2/list",
  "/interventions/api/interventions/ri.interventions.main.intervention.:kind/stats/search",
  "/interventions/api/interventions/ri.interventions.main.intervention.:kind/compass/stats/search",
  "/interventions/api/record/visit",
  "/graphql-gateway/api/graphql*",
  "/marketplace/api/block-set-transport/permissions/user-upload-quota",
  "/issues/api/search/issues/v2/search",
  "/issues/api/search/issues/v2/batch",
  "/approvals/api/search/task-requests",
  "/approvals/api/search/task-requests/counts",
];

const CURRENT_TARGET_CROSSWALK = {
  Home: { current_evidence_routes: ["/ai", "/__ioi/home"], registered_surface_slugs: [] },
  Systems: { current_evidence_routes: [], registered_surface_slugs: [] },
  Projects: { current_evidence_routes: ["/projects"], registered_surface_slugs: [] },
  Applications: { current_evidence_routes: ["/__ioi/applications"], registered_surface_slugs: [] },
  Work: { current_evidence_routes: ["/__ioi/sessions", "/__ioi/missions"], registered_surface_slugs: ["missions"] },
  Studio: { current_evidence_routes: ["/__ioi/agent-studio", "/__ioi/studio/designer", "/__ioi/studio/machinery"], registered_surface_slugs: ["designer", "machinery"] },
  Automations: { current_evidence_routes: ["/automations", "/__ioi/automations", "/__ioi/automations/monitors"], registered_surface_slugs: ["monitors"] },
  Ontology: { current_evidence_routes: ["/__ioi/ontology/manager", "/__ioi/ontology/explorer", "/__ioi/odk"], registered_surface_slugs: ["schema", "explorer"] },
  Data: { current_evidence_routes: ["/__ioi/data/sources", "/__ioi/pipeline"], registered_surface_slugs: ["sources", "pipeline"] },
  Governance: { current_evidence_routes: ["/__ioi/governance", "/__ioi/governance/approvals"], registered_surface_slugs: ["approvals"] },
  Provenance: { current_evidence_routes: ["/__ioi/work-ledger", "/__ioi/lineage", "/__ioi/vertex"], registered_surface_slugs: [] },
  Evaluations: { current_evidence_routes: ["/__ioi/evaluations", "/__ioi/evaluations/evalsuites", "/__ioi/feedback"], registered_surface_slugs: ["evalsuites"] },
  Improvement: { current_evidence_routes: ["/__ioi/improvement/changes"], registered_surface_slugs: ["changes"] },
  Foundry: { current_evidence_routes: ["/__ioi/foundry", "/__ioi/foundry/models"], registered_surface_slugs: ["models"] },
  Packages: { current_evidence_routes: ["/__ioi/marketplace", "/__ioi/marketplace/listings"], registered_surface_slugs: ["listings"] },
  "Developer Workspace": { current_evidence_routes: ["/__ioi/workbench", "/__ioi/code"], registered_surface_slugs: [], dormant_seed_slugs: ["workspaces"] },
  "Developer Console": { current_evidence_routes: ["/__ioi/connections"], registered_surface_slugs: [], dormant_seed_slugs: ["widgets"] },
  Environments: { current_evidence_routes: ["/__ioi/environments"], registered_surface_slugs: [] },
  Operations: { current_evidence_routes: ["/__ioi/operations"], registered_surface_slugs: [] },
  "Embodied Systems": { current_evidence_routes: [], registered_surface_slugs: [] },
};

const OPERATIONAL_JOURNEY_OWNER_IDS = {
  Home: "m6-home-workspace-operational-journey",
  Systems: "m6-systems-workspace-operational-journey",
  Projects: "m6-projects-workspace-operational-journey",
  Applications: "m6-applications-workspace-operational-journey",
  Work: "m6-work-workspace-operational-journey",
  Studio: "m7-studio-operational-journey",
  Automations: "m6-automations-operational-journey",
  Ontology: "m7-ontology-operational-journey",
  Data: "m7-data-operational-journey",
  Governance: "m9-governance-operational-journey",
  Provenance: "m9-provenance-operational-journey",
  Evaluations: "m8-evaluations-operational-journey",
  Improvement: "m8-improvement-operational-journey",
  Foundry: "m8-foundry-operational-journey",
  Packages: "m6-packages-operational-journey",
  "Developer Workspace": "m6-developer-workspace-operational-journey",
  "Developer Console": "m9-developer-console-operational-journey",
  Environments: "m9-environments-operational-journey",
  Operations: "m10-operations-operational-journey",
  "Embodied Systems": "m11-embodied-systems-nonlive-operational-journey",
};

const SUPPORTING_TARGET_PLAN_IDS = {
  Systems: ["m6-systems-work-projection-and-mission-alias-migration"],
  Work: ["m6-systems-work-projection-and-mission-alias-migration"],
  "Embodied Systems": [
    "m11-canonical-embodied-contract-alignment",
    "m11-embodied-nonlive-graph-proof",
  ],
};

const CORE_WORKSPACE_SHELL_OWNER_ID = "m6-product-surface-and-typed-workspaces";
const APPLICATION_SHELL_OWNER_ID = "m6-owner-application-registration-and-shell-state-coverage";
const ACTION_AUTHORITY_PLAN_OWNER_ID = "m6-consequential-action-authority-receipt-unification";

const REQUIRED_STATE_SPECS = [
  { name: "loading", pattern: /\bloading\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "empty", pattern: /\bempty\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "denied", pattern: /\bdenied\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "unavailable", pattern: /\bunavailable\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "degraded", pattern: /\bdegraded\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "stale", pattern: /\bstale\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "conflict", pattern: /\bconflict\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "recovery", pattern: /\brecovery\b/giu, owner_ids: [APPLICATION_SHELL_OWNER_ID] },
  { name: "receipt", pattern: /\breceipts?\b/giu, owner_ids: [ACTION_AUTHORITY_PLAN_OWNER_ID] },
  { name: "modal", pattern: /\bmodals?\b/giu, owner_ids: ["m6-catalog-route-alias-migration-accessibility"], visual: true },
  { name: "embed", pattern: /\bembed(?:ded|dable)?\b/giu, owner_ids: ["m6-catalog-route-alias-migration-accessibility"], visual: true },
  { name: "keyboard", pattern: /\bkeyboard\b/giu, owner_ids: ["m6-catalog-route-alias-migration-accessibility"], visual: true },
  { name: "focus", pattern: /\bfocus\b/giu, owner_ids: ["m6-catalog-route-alias-migration-accessibility"], visual: true },
  { name: "narrow-layout", pattern: /\bnarrow(?:[-_ ]layout)?\b/giu, owner_ids: ["m6-catalog-route-alias-migration-accessibility"], visual: true },
];

function parseAst(file) {
  return acorn.parse(readText(file), { ecmaVersion: "latest", sourceType: "module" });
}

function walkAst(node, visit, ancestors = []) {
  if (!node || typeof node !== "object") return;
  visit(node, ancestors);
  const nextAncestors = [...ancestors, node];
  for (const [key, value] of Object.entries(node)) {
    if (new Set(["start", "end", "loc"]).has(key)) continue;
    if (Array.isArray(value)) {
      for (const child of value) walkAst(child, visit, nextAncestors);
    } else {
      walkAst(value, visit, nextAncestors);
    }
  }
}

function parseCanonicalTaxonomy(canonSource) {
  const taxonomyBlock = canonSource.match(
    /The product estate has dimensional classes[\s\S]*?```text\n(Core workspaces[\s\S]*?)\n```\n\n### Canonical Target Routes And Compatibility Aliases/u,
  )?.[1];
  if (!taxonomyBlock) throw new Error("canonical product-taxonomy block is missing");

  const classes = Object.fromEntries(
    Object.values(CANONICAL_TAXONOMY_HEADINGS).map((surfaceClass) => [surfaceClass, []]),
  );
  let activeClass = null;
  for (const line of taxonomyBlock.split("\n")) {
    const headingClass = CANONICAL_TAXONOMY_HEADINGS[line.trim()];
    if (headingClass) {
      activeClass = headingClass;
      continue;
    }
    if (/^(Tool surfaces|Extension applications)$/u.test(line.trim())) {
      activeClass = null;
      continue;
    }
    if (!activeClass || !/^  \S/u.test(line)) continue;
    const name = line.trim().replace(/\s+\(.*$/u, "").trim();
    if (!name) throw new Error(`empty canonical taxonomy identity under ${activeClass}`);
    classes[activeClass].push(name);
  }

  const identities = Object.values(classes).flat();
  if (identities.length === 0 || new Set(identities).size !== identities.length) {
    throw new Error("canonical product-taxonomy identities are empty or duplicated");
  }

  const routeSection = canonSource.match(
    /### Canonical Target Routes And Compatibility Aliases([\s\S]*?)(?:\n## |\n### )/u,
  )?.[1];
  if (!routeSection) throw new Error("canonical target-route ledger is missing");
  const routeRows = [...routeSection.matchAll(/^\| ([^|]+?) \| `([^`]+)`(?: reserved)? \|/gmu)].map(
    (match) => ({
      identity_or_action: match[1].trim(),
      canonical_target_route: match[2].replace(/ reserved$/u, ""),
    }),
  );
  const routeNames = routeRows.map((row) => row.identity_or_action);
  const expectedRouteNames = [...identities, "New Session"];
  if (stableJson(sorted(routeNames)) !== stableJson(sorted(expectedRouteNames))) {
    throw new Error(
      `canonical target-route ledger identities/actions changed without taxonomy mapping: expected ${expectedRouteNames.join(", ")}; found ${routeNames.join(", ")}`,
    );
  }
  const targetRoutes = Object.fromEntries(
    routeRows
      .filter((row) => identities.includes(row.identity_or_action))
      .map((row) => [row.identity_or_action, row.canonical_target_route]),
  );
  return {
    classes,
    identities,
    route_rows: routeRows,
    target_routes: targetRoutes,
  };
}

function normalizedHandlerInventory(templates) {
  const grouped = [];
  const atomic = [];
  const groupedKeys = new Set();
  const atomicKeys = new Set();
  for (const template of templates) {
    const match = template.match(/^([A-Z]+(?:\|[A-Z]+)*) (\/\S+)$/u);
    if (!match) throw new Error(`invalid normalized IOI route template: ${template}`);
    if (groupedKeys.has(template)) throw new Error(`duplicate normalized IOI route template: ${template}`);
    groupedKeys.add(template);
    const methods = match[1].split("|");
    const routeTemplate = match[2];
    grouped.push({ methods, route_template: routeTemplate, grouped_template: template });
    for (const method of methods) {
      const routeKey = `${method} ${routeTemplate}`;
      if (atomicKeys.has(routeKey)) throw new Error(`duplicate atomic IOI route template: ${routeKey}`);
      atomicKeys.add(routeKey);
      atomic.push({ method, route_template: routeTemplate, route_key: routeKey });
    }
  }
  return {
    grouped,
    atomic: atomic.sort((left, right) => left.route_key.localeCompare(right.route_key)),
  };
}

function handlerFunctionAst(serveFile) {
  const ast = parseAst(serveFile);
  let handler = null;
  walkAst(ast, (node) => {
    if (node.type === "FunctionDeclaration" && node.id?.name === "handleEstateRequest") {
      handler = node;
    }
  });
  if (!handler) throw new Error("handleEstateRequest is missing from Hypervisor serve source");
  return handler;
}

function patternNames(pattern, names = []) {
  if (!pattern) return names;
  if (pattern.type === "Identifier") names.push(pattern.name);
  else if (pattern.type === "ArrayPattern" || pattern.type === "ObjectPattern") {
    for (const item of pattern.elements || pattern.properties || []) {
      patternNames(item?.value || item?.argument || item, names);
    }
  } else if (pattern.type === "AssignmentPattern" || pattern.type === "RestElement") {
    patternNames(pattern.left || pattern.argument, names);
  }
  return names;
}

function buildSourceHandlerGuardCensus(serveFile, serveSource, routeInventory, actions) {
  const handler = handlerFunctionAst(serveFile);
  const nativeStart = serveSource.indexOf('if (pathname === "/__ioi/fallthrough")', handler.start);
  const nativeEnd = serveSource.indexOf('if (pathname === "/api/ioi.v1.EventService/WatchEvents")', nativeStart);
  if (nativeStart < 0 || nativeEnd < 0 || nativeEnd <= nativeStart) {
    throw new Error("could not bound the native /__ioi handler region");
  }
  const inNativeRegion = (node) => node.start >= nativeStart && node.start < nativeEnd;
  const sourceOf = (node) => serveSource.slice(node.start, node.end).replace(/\s+/gu, " ").trim();

  const directRouteDerivedNames = new Set(["pathname"]);
  const declarations = [];
  walkAst(handler, (node) => {
    if (node.type === "VariableDeclarator" && inNativeRegion(node) && node.init) declarations.push(node);
  });
  let changed = true;
  while (changed) {
    changed = false;
    for (const declaration of declarations) {
      const names = patternNames(declaration.id);
      if (names.every((name) => directRouteDerivedNames.has(name))) continue;
      const initSource = sourceOf(declaration.init);
      const directlyDerived = /\bpathname\.(?:match|slice)\b/u.test(initSource);
      const derivedReference = [...directRouteDerivedNames].some((name) =>
        new RegExp(`\\b${name.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}\\b`, "u").test(initSource),
      );
      const allowedDerivation =
        /\.(?:split|slice)\s*\(/u.test(initSource) ||
        /^decodeURIComponent\s*\(/u.test(initSource) ||
        declaration.init.type === "MemberExpression" ||
        declaration.init.type === "LogicalExpression";
      if (directlyDerived || (derivedReference && allowedDerivation)) {
        for (const name of names) directRouteDerivedNames.add(name);
        changed = true;
      }
    }
  }

  const recordsBySignature = new Map();
  const addGuard = (node, kind) => {
    const signature = sourceOf(node);
    const current = recordsBySignature.get(signature) || {
      signature,
      kind,
      occurrence_count: 0,
      source_lines: [],
      route_literals: [],
    };
    current.occurrence_count += 1;
    current.source_lines.push(node.loc?.start?.line || null);
    current.route_literals = uniqueSorted([
      ...current.route_literals,
      ...[...signature.matchAll(/["'](\/__ioi[^"']*)["']/gu)].map((match) => match[1]),
    ]);
    recordsBySignature.set(signature, current);
  };

  walkAst(handler, (node) => {
    if (!inNativeRegion(node)) return;
    if (node.type === "VariableDeclarator" && node.init && /\bpathname\.match\s*\(/u.test(sourceOf(node.init))) {
      addGuard(node.init, "pathname_regex_matcher");
      return;
    }
    if (node.type !== "IfStatement" && node.type !== "ConditionalExpression") return;
    const test = node.test;
    const testSource = sourceOf(test);
    const directPathDecision = /\bpathname\b/u.test(testSource);
    const methodDecision = /\breq\.method\b/u.test(testSource);
    const derivedDecision = [...directRouteDerivedNames]
      .filter((name) => name !== "pathname")
      .some((name) => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\\]\\]/g, "\\$&")}\\b`, "u").test(testSource));
    if (directPathDecision || methodDecision || derivedDecision) {
      addGuard(test, node.type === "IfStatement" ? "if_route_decision" : "conditional_route_decision");
    }
  });

  const records = [...recordsBySignature.values()]
    .map((record) => ({ ...record, source_lines: record.source_lines.filter(Boolean).sort((a, b) => a - b) }))
    .sort((left, right) => left.signature.localeCompare(right.signature));
  const inventoryDigest = sha256(stableJson(records.map((record) => ({
    signature: record.signature,
    occurrence_count: record.occurrence_count,
  }))));

  const exactSourceRoutes = new Set();
  walkAst(handler, (node) => {
    if (!inNativeRegion(node) || node.type !== "BinaryExpression" || !new Set(["===", "=="]).has(node.operator)) return;
    for (const [left, right] of [[node.left, node.right], [node.right, node.left]]) {
      if (left.type === "Identifier" && left.name === "pathname" && right.type === "Literal") {
        const value = String(right.value);
        if (value.startsWith("/__ioi/")) exactSourceRoutes.add(value);
      }
    }
  });
  const normalizedPaths = new Set(routeInventory.grouped.map((entry) => entry.route_template));
  const unmappedExactSourceRoutes = sorted(exactSourceRoutes).filter(
    (route) => !NON_PRODUCT_IOI_EXACT_ROUTES.has(route) && !normalizedPaths.has(route),
  );
  const sourceAnchorFiles = [serveSource, ...actions.map((action) => action.route_template)];
  const templatesWithoutSourceAnchor = routeInventory.grouped
    .filter((entry) => {
      const staticPrefix = entry.route_template.split(/:[A-Za-z][A-Za-z0-9_]*/u)[0];
      const overrideAnchors = NORMALIZED_IOI_SOURCE_ANCHOR_OVERRIDES[entry.grouped_template] || [];
      const directAnchor = sourceAnchorFiles.some((source) =>
        source.includes(entry.route_template) || source.includes(staticPrefix),
      );
      const overrideAnchor = overrideAnchors.length > 0 && overrideAnchors.every((anchor) =>
        sourceAnchorFiles.some((source) => source.includes(anchor)),
      );
      return !directAnchor && !overrideAnchor;
    })
    .map((entry) => entry.grouped_template);

  return {
    source_path: rel(serveFile),
    native_region_start_line: serveSource.slice(0, nativeStart).split("\n").length,
    native_region_end_line: serveSource.slice(0, nativeEnd).split("\n").length,
    route_derived_identifiers: sorted(directRouteDerivedNames),
    guard_count: records.reduce((total, record) => total + record.occurrence_count, 0),
    unique_guard_count: records.length,
    guard_inventory_sha256: inventoryDigest,
    reviewed_guard_inventory_sha256: REVIEWED_IOI_HANDLER_GUARD_INVENTORY_SHA256,
    reviewed_guard_inventory_matches: inventoryDigest === REVIEWED_IOI_HANDLER_GUARD_INVENTORY_SHA256,
    guards: records,
    exact_source_routes: sorted(exactSourceRoutes),
    excluded_non_product_exact_routes: sorted(NON_PRODUCT_IOI_EXACT_ROUTES),
    unmapped_exact_source_routes: unmappedExactSourceRoutes,
    normalized_templates_without_source_anchor: templatesWithoutSourceAnchor,
    coverage_rule: "Every changed native-handler route decision changes this source-derived guard inventory and fails review; every exact product pathname branch and every normalized template must also map in both directions.",
  };
}

function topVariables(ast) {
  const variables = new Map();
  for (const statement of ast.body) {
    if (statement.type !== "VariableDeclaration") continue;
    for (const declaration of statement.declarations) {
      if (declaration.id.type === "Identifier") variables.set(declaration.id.name, declaration.init);
    }
  }
  return variables;
}

function functionReturn(ast, name) {
  const declaration = ast.body.find(
    (node) => node.type === "FunctionDeclaration" && node.id?.name === name,
  );
  return declaration?.body?.body?.find((node) => node.type === "ReturnStatement")?.argument || null;
}

function extractRouteTree(rootNode, variables, substitutions = {}) {
  const routes = new Set();
  const joinRoute = (base, child) => {
    if (child === "*") return "*";
    if (child.startsWith("/")) return child;
    return `${base === "/" ? "" : base.replace(/\/$/, "")}/${child}`;
  };
  const literalValue = (node, env) => {
    if (!node) return null;
    if (node.type === "Literal") return String(node.value);
    if (node.type === "Identifier") return env[node.name] ?? null;
    if (node.type !== "TemplateLiteral") return null;
    let value = "";
    for (let index = 0; index < node.quasis.length; index += 1) {
      value += node.quasis[index].value.cooked;
      if (index < node.expressions.length) {
        const expression = node.expressions[index];
        value += env[expression.name] ?? substitutions[expression.name] ?? `:${expression.name}`;
      }
    }
    return value;
  };
  const property = (node, name) =>
    node.properties.find(
      (candidate) =>
        candidate.type === "Property" &&
        !candidate.computed &&
        (candidate.key.name || candidate.key.value) === name,
    );
  const visit = (node, base = "/", env = {}) => {
    if (!node) return;
    if (node.type === "SpreadElement") return visit(node.argument, base, env);
    if (node.type === "Identifier" && variables.has(node.name)) {
      return visit(variables.get(node.name), base, env);
    }
    if (node.type === "ArrayExpression") {
      for (const element of node.elements) visit(element, base, env);
      return;
    }
    if (node.type === "CallExpression") {
      const isMap =
        node.callee.type === "MemberExpression" &&
        node.callee.property?.name === "map" &&
        node.callee.object.type === "ArrayExpression";
      if (!isMap) return;
      const callback = node.arguments[0];
      const parameter = callback.params?.[0]?.name;
      for (const element of node.callee.object.elements) {
        visit(callback.body, base, { ...env, [parameter]: literalValue(element, env) });
      }
      return;
    }
    if (node.type !== "ObjectExpression") return;
    let ownBase = base;
    const pathProperty = property(node, "path");
    if (pathProperty) {
      const route = literalValue(pathProperty.value, env);
      if (route !== null) {
        ownBase = joinRoute(base, route);
        routes.add(ownBase);
      }
    }
    const childrenProperty = property(node, "children");
    if (childrenProperty) visit(childrenProperty.value, ownBase, env);
  };
  visit(rootNode);
  return routes;
}

function extractCapturedSpaRoutes(mainAsset, segmentAsset) {
  const mainAst = parseAst(mainAsset);
  const variables = topVariables(mainAst);
  const routes = extractRouteTree(variables.get("uv"), variables, { v: "/join-organization" });
  const segmentAst = parseAst(segmentAsset);
  const environmentRoutes = extractRouteTree(functionReturn(segmentAst, "aj"), new Map());
  for (const route of environmentRoutes) routes.add(route);
  if (!routes.has("/ai")) throw new Error("captured router no longer declares /ai");
  routes.add("/ai#new-session");
  return sorted(routes);
}

function staticRouteScanFiles() {
  const roots = [
    fromRepo("apps", "hypervisor", "src"),
    fromRepo("apps", "hypervisor", "scripts"),
    fromRepo("apps", "hypervisor", "surfaces"),
    fromRepo("apps", "hypervisor", "ux-seeds"),
  ];
  const files = roots.flatMap((root) =>
    walkFiles(root, (file) => /\.(?:mjs|js|ts|tsx|json|md)$/.test(file)),
  );
  files.push(
    fromRepo("apps", "hypervisor", "harvest-app-parity-matrix.json"),
    fromRepo("apps", "hypervisor", "harvest-starting-points.json"),
    fromRepo("apps", "hypervisor", "application-operational-depth.json"),
  );
  return uniqueSorted(files);
}

function extractStaticRouteStrings(files) {
  const routes = new Set();
  const pattern = /\/(?:__ioi|__apps)\/[A-Za-z0-9_./:-]*/g;
  for (const file of files) {
    for (const match of readText(file).matchAll(pattern)) {
      const route = match[0];
      if (route === "/__ioi/" || route === "/__apps/" || route.endsWith(".")) continue;
      routes.add(route);
    }
  }
  return sorted(routes);
}

function parseStringArray(source, declaration) {
  const match = source.match(new RegExp(`const ${declaration} = \\[([^;]+)\\];`));
  if (!match) throw new Error(`could not find ${declaration} string array`);
  return [...match[1].matchAll(/["']([^"']+)["']/g)].map((item) => item[1]);
}

function proxyFamilies(serveSource) {
  const mirror = parseStringArray(serveSource, "MIRROR_API_PREFIXES").map(
    (prefix) => `${prefix.replace(/\/$/, "")}/*`,
  );
  return [...mirror, ...PROXY_SUFFIX_FAMILIES];
}

function connectOperations(adapterSource, serveSource) {
  const literal = uniqueSorted(
    [...`${adapterSource}\n${serveSource}`.matchAll(/["'`]\/(?:api\/ioi\.v1\.[A-Za-z]+\/[A-Za-z]+)["'`]/g)].map(
      (match) => match[0].slice(1, -1),
    ),
  );
  const projectBlock = adapterSource.match(/const PROJECT_OPS = new Set\(\[([^\]]+)\]\)/)?.[1];
  if (!projectBlock) throw new Error("ProjectService dynamic operation set is missing");
  const names = [...projectBlock.matchAll(/["']([A-Za-z]+)["']/g)].map((match) => match[1]);
  if (/op === "ListProjectEnvironmentClasses"/.test(adapterSource)) names.push("ListProjectEnvironmentClasses");
  const dynamic = uniqueSorted(names.map((name) => `/api/ioi.v1.ProjectService/${name}`));
  return { literal, dynamic, all: uniqueSorted([...literal, ...dynamic]) };
}

function fixtureInventory(publicRoot, ownedRoot) {
  const relativeFiles = (root) =>
    walkFiles(root).map((file) => path.relative(root, file).split(path.sep).join("/"));
  const publicFiles = relativeFiles(publicRoot);
  const ownedFiles = relativeFiles(ownedRoot);
  if (stableJson(publicFiles) !== stableJson(ownedFiles)) {
    throw new Error("captured fixture trees do not contain the same endpoint paths");
  }
  const endpoints = publicFiles.map((relativePath) => {
    const publicFile = path.join(publicRoot, relativePath);
    const ownedFile = path.join(ownedRoot, relativePath);
    const publicHash = sha256File(publicFile);
    const ownedHash = sha256File(ownedFile);
    return {
      endpoint: `/api/${relativePath}`,
      public_sha256: publicHash,
      owned_sha256: ownedHash,
      byte_identical: publicHash === ownedHash,
    };
  });
  return { endpoints, source_files: [...publicFiles.map((file) => path.join(publicRoot, file)), ...ownedFiles.map((file) => path.join(ownedRoot, file))] };
}

function featureFlagInventory(publicFile, ownedFile) {
  if (sha256File(publicFile) !== sha256File(ownedFile)) {
    throw new Error("public and owned ConfigCat snapshots differ");
  }
  const config = readJson(publicFile);
  const typeNames = { b: "boolean", i: "integer", s: "string", d: "double" };
  return Object.entries(config.f || {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, definition]) => {
      const defaultKey = Object.keys(definition.v || {})[0] || "unknown";
      return {
        name,
        default_type: typeNames[defaultKey] || defaultKey,
        default_value_sha256: sha256(stableJson(definition.v || null)),
        targeting_rule_count: Array.isArray(definition.r) ? definition.r.length : 0,
      };
    });
}

function planRecordRef(workItemId) {
  const file = path.join(implementationRoot, "work-items", `${workItemId}.v1.json`);
  if (!fs.existsSync(file)) throw new Error(`planning owner record is missing: ${workItemId}`);
  const record = readJson(file);
  if (record.work_item_id !== workItemId) {
    throw new Error(`planning owner identity mismatch: ${workItemId}`);
  }
  return {
    work_item_id: record.work_item_id,
    stage_id: record.stage_id,
    path: implementationRelative(file),
  };
}

function planRecordRefs() {
  const ids = new Set([
    CORE_WORKSPACE_SHELL_OWNER_ID,
    APPLICATION_SHELL_OWNER_ID,
    ACTION_AUTHORITY_PLAN_OWNER_ID,
    ...Object.values(OPERATIONAL_JOURNEY_OWNER_IDS),
    ...Object.values(SUPPORTING_TARGET_PLAN_IDS).flat(),
    ...REQUIRED_STATE_SPECS.flatMap((state) => state.owner_ids),
  ]);
  return sorted(ids).map(planRecordRef);
}

function buildCanonicalCrosswalk(taxonomy, allSourceRoutes, registeredSlugs, dormantSlugs) {
  const expectedIdentities = sorted(taxonomy.identities);
  for (const [mappingName, mapping] of [
    ["current target crosswalk", CURRENT_TARGET_CROSSWALK],
    ["operational journey owners", OPERATIONAL_JOURNEY_OWNER_IDS],
  ]) {
    const mappedIdentities = sorted(Object.keys(mapping));
    if (stableJson(mappedIdentities) !== stableJson(expectedIdentities)) {
      throw new Error(`${mappingName} must exactly cover the canon-derived taxonomy: expected ${expectedIdentities.join(", ")}; found ${mappedIdentities.join(", ")}`);
    }
  }
  for (const name of Object.keys(SUPPORTING_TARGET_PLAN_IDS)) {
    if (!expectedIdentities.includes(name)) throw new Error(`supporting target plan mapping names unknown canon identity ${name}`);
  }
  return Object.entries(taxonomy.classes).flatMap(([surfaceClass, names]) =>
    names.map((name) => {
      const current = CURRENT_TARGET_CROSSWALK[name];
      if (!current) throw new Error(`current target crosswalk missing ${name}`);
      const operationalJourneyOwnerId = OPERATIONAL_JOURNEY_OWNER_IDS[name];
      if (!operationalJourneyOwnerId) throw new Error(`operational journey owner missing for ${name}`);
      const shellOwnerId = surfaceClass === "core_workspace"
        ? CORE_WORKSPACE_SHELL_OWNER_ID
        : APPLICATION_SHELL_OWNER_ID;
      const m6ShellOwner = planRecordRef(shellOwnerId);
      const operationalJourneyOwner = planRecordRef(operationalJourneyOwnerId);
      if (m6ShellOwner.stage_id !== "M6") throw new Error(`${name} shell owner is not an M6 record`);
      for (const slug of current.registered_surface_slugs || []) {
        if (!registeredSlugs.has(slug)) throw new Error(`${name} crosswalk names unknown registered slug ${slug}`);
      }
      for (const slug of current.dormant_seed_slugs || []) {
        if (!dormantSlugs.has(slug)) throw new Error(`${name} crosswalk names unknown dormant slug ${slug}`);
      }
      for (const route of current.current_evidence_routes || []) {
        if (!allSourceRoutes.has(route)) throw new Error(`${name} crosswalk route is absent from source: ${route}`);
      }
      const canonicalRoute = taxonomy.target_routes[name];
      return {
        name,
        surface_class: surfaceClass,
        canonical_target_route: canonicalRoute,
        canonical_target_route_present_in_current_source: allSourceRoutes.has(canonicalRoute),
        current_evidence_routes: current.current_evidence_routes || [],
        registered_surface_slugs: current.registered_surface_slugs || [],
        dormant_seed_slugs: current.dormant_seed_slugs || [],
        evidence_posture:
          name === "Embodied Systems"
            ? "conditional_target_nonlaunchable_until_built"
            : (current.current_evidence_routes || []).length === 0
              ? "no_current_route_evidence"
              : "current_route_or_child_surface_evidence_only",
        m6_shell_owner: m6ShellOwner,
        operational_journey_owner: operationalJourneyOwner,
        shell_evidence_is_operational_depth: false,
        supporting_plan_record_ids: SUPPORTING_TARGET_PLAN_IDS[name] || [],
        plan_record_refs: uniqueSorted([
          m6ShellOwner.work_item_id,
          operationalJourneyOwner.work_item_id,
          ...(SUPPORTING_TARGET_PLAN_IDS[name] || []),
        ]),
      };
    }),
  );
}

function compactAction(surface, action) {
  const grantFieldNamed = (action.fields || []).includes("wallet_approval_grant");
  return {
    surface_slug: surface.slug,
    id: action.id,
    method: action.method,
    route_template: `${surface.route}${action.route}`,
    transition: action.transition || null,
    declared_fields: action.fields || [],
    context_fields: action.context || [],
    authority: action.authority,
    receipt: action.receipt,
    confirmation_required: !!action.confirm,
    planning_owner: {
      stage_id: "M6",
      work_item_id: ACTION_AUTHORITY_PLAN_OWNER_ID,
    },
    authority_chain_planning: {
      wallet_authority: {
        evidence_state: "current_descriptor_gap",
        declared_plane: action.authority?.plane || null,
        declared_operation: action.authority?.operation || null,
        nonclaim: "A route-local plane/operation coordinate is not a wallet grant or authority proof.",
      },
      sealed_intent_or_grant: {
        evidence_state: grantFieldNamed
          ? "descriptor_only_not_proven"
          : "current_descriptor_gap",
        wallet_approval_grant_field_named: grantFieldNamed,
        nonclaim: grantFieldNamed
          ? "Naming a wallet_approval_grant input does not prove sealing, signature validity, scope, freshness, or consumption."
          : "The current action descriptor declares no sealed-intent or wallet-grant input.",
      },
      final_invoker_revalidation: {
        evidence_state: "current_descriptor_gap",
        nonclaim: "The current action descriptor does not prove final-invoker grant revalidation immediately before effect.",
      },
      effect_receipt: {
        evidence_state: action.receipt
          ? "descriptor_only_not_proven"
          : "current_descriptor_gap",
        declared_receipt_contract: action.receipt || null,
        nonclaim: "A declared receipt type does not prove durable issuance, effect binding, replay behavior, or receipt verification.",
      },
      negative_behavior: {
        evidence_state: action.refusal
          ? "descriptor_only_not_proven"
          : "current_descriptor_gap",
        declared_refusal_presentation: action.refusal || null,
        nonclaim: "A refusal presentation label does not prove denial before effect, stale-grant rejection, replay rejection, rollback, or fault recovery.",
      },
    },
    unsigned_workflow_evidence_is_authority: false,
  };
}

function mutationAuthorityChain(boundActions, governedControls) {
  const grantFieldNamed = boundActions.some((action) =>
    (action.declared_fields || []).includes("wallet_approval_grant"),
  );
  const receiptContracts = uniqueSorted(
    boundActions.map((action) => action.receipt).filter(Boolean),
  );
  const authorityCoordinates = boundActions
    .map((action) => action.authority)
    .filter((authority) => authority?.plane && authority?.operation)
    .map((authority) => ({ plane: authority.plane, operation: authority.operation }));
  return {
    wallet_authority: {
      evidence_state: authorityCoordinates.length > 0
        ? "descriptor_only_not_proven"
        : "current_handler_gap",
      declared_route_local_coordinates: authorityCoordinates,
      nonclaim: authorityCoordinates.length > 0
        ? "Route-local plane/operation coordinates are descriptor evidence, not a wallet grant or authority proof."
        : "No bound descriptor supplies even route-local wallet-authority coordinates for this normalized mutation path.",
    },
    sealed_intent_or_grant: {
      evidence_state: grantFieldNamed
        ? "descriptor_only_not_proven"
        : "current_handler_gap",
      wallet_approval_grant_field_named: grantFieldNamed,
      nonclaim: grantFieldNamed
        ? "Naming a wallet_approval_grant input does not prove sealing, signature validity, scope, freshness, or consumption."
        : "No joined descriptor names a sealed intent or wallet-grant input for this normalized mutation path.",
    },
    final_invoker_revalidation: {
      evidence_state: "current_handler_gap",
      nonclaim: "Neither a source handler branch nor a descriptor proves final-invoker grant revalidation immediately before effect.",
    },
    effect_receipt: {
      evidence_state: receiptContracts.length > 0 || governedControls.length > 0
        ? "descriptor_only_not_proven"
        : "current_handler_gap",
      declared_receipt_contracts: receiptContracts,
      governed_control_pointer_count: governedControls.length,
      nonclaim: receiptContracts.length > 0 || governedControls.length > 0
        ? "A receipt declaration or atlas pointer does not prove durable issuance, exact-effect binding, replay behavior, or verification."
        : "No joined descriptor or governed-control pointer declares an effect receipt for this normalized mutation path.",
    },
    negative_behavior: {
      evidence_state: boundActions.some((action) => !!action.authority_chain_planning?.negative_behavior?.declared_refusal_presentation)
        ? "descriptor_only_not_proven"
        : "current_handler_gap",
      nonclaim: "The current evidence does not prove denial before effect, stale-grant rejection, replay rejection, rollback, or fault recovery for this normalized mutation path.",
    },
  };
}

function buildMutationPathDispositions(routeInventory, actions, governedControls) {
  const planningOwner = planRecordRef(ACTION_AUTHORITY_PLAN_OWNER_ID);
  const actionByRouteKey = new Map();
  for (const action of actions) {
    const routeKey = `${action.method} ${action.route_template}`;
    const values = actionByRouteKey.get(routeKey) || [];
    values.push(action);
    actionByRouteKey.set(routeKey, values);
  }
  const dispositions = routeInventory.atomic
    .filter((route) => route.method !== "GET")
    .map((route) => {
      const boundActions = actionByRouteKey.get(route.route_key) || [];
      const exactGovernedControls = governedControls.filter((control) =>
        typeof control.binding === "string" && control.binding.includes(route.route_template),
      );
      const surfaceContextControls = governedControls.filter((control) =>
        boundActions.some((action) => action.surface_slug === control.surface_slug) &&
        !exactGovernedControls.includes(control),
      );
      const descriptorPosture = boundActions.length > 0 && exactGovernedControls.length > 0
        ? "bound_action_descriptor_and_exact_governed_control_pointer"
        : boundActions.length > 0
          ? "bound_action_descriptor"
          : exactGovernedControls.length > 0
            ? "exact_governed_control_pointer"
            : "flat_handler_without_bound_descriptor";
      return {
        method: route.method,
        route_template: route.route_template,
        route_key: route.route_key,
        descriptor_posture: descriptorPosture,
        bound_action_descriptors: boundActions.map((action) => ({
          surface_slug: action.surface_slug,
          action_id: action.id,
          route_template: action.route_template,
          authority: action.authority,
          receipt: action.receipt,
        })),
        exact_governed_control_pointers: exactGovernedControls.map((control) => ({
          surface_slug: control.surface_slug,
          control_id: control.control_id,
          binding: control.binding,
        })),
        surface_context_governed_control_pointers: surfaceContextControls.map((control) => ({
          surface_slug: control.surface_slug,
          control_id: control.control_id,
          binding: control.binding,
          nonclaim: "Same-surface atlas context is not an exact binding to this mutation path.",
        })),
        planning_owner: planningOwner,
        authority_chain_planning: mutationAuthorityChain(boundActions, exactGovernedControls),
        disposition: `${descriptorPosture}_with_proposed_authority_chain_gap`,
        unsigned_workflow_evidence_is_authority: false,
        nonclaim: "This disposition is a planning/evidence join only; it proves no authority check, effect, receipt, negative path, work-item status, or stage exit.",
      };
    });
  return dispositions.sort((left, right) => left.route_key.localeCompare(right.route_key));
}

function buildRequiredStateCoverage(files) {
  return REQUIRED_STATE_SPECS.map((spec) => {
    const evidenceRefs = [];
    for (const file of files) {
      const occurrenceCount = [...readText(file).matchAll(new RegExp(spec.pattern.source, spec.pattern.flags))].length;
      if (occurrenceCount > 0) evidenceRefs.push({ path: rel(file), occurrence_count: occurrenceCount });
    }
    const evidenceCount = evidenceRefs.reduce((total, evidence) => total + evidence.occurrence_count, 0);
    const disposition = spec.visual
      ? "unverified"
      : evidenceCount > 0
        ? "observed_source_evidence"
        : "planned_gap";
    return {
      state: spec.name,
      disposition,
      visual_dependency: spec.visual === true,
      current_source_occurrence_count: evidenceCount,
      current_evidence_ref_count: evidenceRefs.length,
      current_evidence_refs: evidenceRefs,
      owning_plan_records: spec.owner_ids.map(planRecordRef),
      nonclaim: spec.visual
        ? "Static occurrences do not visually verify this state; desktop and narrow read-only browser proof remains unverified."
        : evidenceCount > 0
          ? "A source-term occurrence is inventory evidence only; it does not prove reachable, honest, accessible, or recoverable product behavior."
          : "No exact current-source occurrence was derived; the owning plan record remains the implementation and exit-proof obligation.",
    };
  });
}

function buildSurfaceRows(atlas) {
  const rows = [];
  for (const surface of SURFACES) {
    const evidence = atlas.surfaces?.[surface.slug];
    if (!evidence) throw new Error(`operational-depth atlas missing ${surface.slug}`);
    const hit = boundSurface(surface.route, "GET");
    const actions = (hit?.impl?.actions || []).map((action) => compactAction(surface, action));
    const controls = (evidence.reference_control_census || []).map((control) => ({
      id: control.id,
      region: control.region,
      label: control.label,
      outcome: control.outcome,
      implemented: control.implemented,
      binding: control.binding || null,
      reason: control.reason || null,
    }));
    rows.push({
      slug: surface.slug,
      owner: surface.owner,
      title: surface.title,
      route: surface.route,
      verifier: surface.verifier,
      certification: surface.certification,
      implementation_kind: hit ? "bound_surface_module" : "flat_serve_handler",
      capabilities: surface.capabilities,
      operational_state_declaration: surface.operational_state,
      embedded_shell_state: surface.embedded_shell_state,
      interaction_parity_state: surface.interaction_parity_state,
      declared_actions: actions,
      reference_reached_states: evidence.reference_reached_states || [],
      atlas_is_operational_assertion: evidence.is_operational === true,
      missing_authority_contracts: evidence.missing_authority_contracts || [],
      existing_daemon_evidence: evidence.existing_daemon || { routes: [], actions: [], receipts: [] },
      control_counts: {
        total: controls.length,
        implemented: controls.filter((control) => control.implemented).length,
        unimplemented: controls.filter((control) => !control.implemented).length,
        by_outcome: countBy(controls, (control) => control.outcome),
      },
      controls,
    });
  }
  return rows;
}

function buildSeedRows(parity, starting, registeredSlugs) {
  const startingBySlug = new Map((starting.seeds || []).map((seed) => [seed.slug, seed]));
  return (parity.seeds || []).map((seed) => {
    const capture = startingBySlug.get(seed.slug);
    if (!capture) throw new Error(`harvest starting-point inventory missing ${seed.slug}`);
    const currentEvidence = !!(seed.candidate_surface || seed.port_surface || seed.substrate_surface);
    return {
      slug: seed.slug,
      owner: seed.owner,
      reference_route: seed.app_route,
      reference_workspace: seed.reference_workspace,
      intended_grammar: seed.grammar,
      parity_class: seed.parity_class,
      capture_state: seed.capture_state,
      reference_clean_state: seed.reference_clean_state,
      candidate_surface: seed.candidate_surface || null,
      shell_pixel_certified: seed.shell_pixel_certified === true,
      served_status_snapshot: capture.served,
      booted_past_shell_snapshot: capture.booted_past_shell === true,
      capture_control_count: capture.controls,
      capture_panel_count: capture.panels,
      rebound_lane: capture.rebound_lane,
      unbound_note: capture.unbound_note,
      evidence_disposition: registeredSlugs.has(seed.slug)
        ? "registered_surface_evidence"
        : currentEvidence
          ? "nonregistry_current_surface_evidence"
          : "reference_capture_evidence_only",
    };
  });
}

export function buildHypervisorSurfaceCoverage() {
  const canonFile = fromRepo("docs", "architecture", "components", "hypervisor", "core-clients-surfaces.md");
  const parityFile = fromRepo("apps", "hypervisor", "harvest-app-parity-matrix.json");
  const startingFile = fromRepo("apps", "hypervisor", "harvest-starting-points.json");
  const dormantFile = fromRepo("apps", "hypervisor", "ux-seeds", "manifest.json");
  const atlasFile = fromRepo("apps", "hypervisor", "application-operational-depth.json");
  const registryFile = fromRepo("apps", "hypervisor", "scripts", "surface-registry.mjs");
  const catalogFile = fromRepo("apps", "hypervisor", "scripts", "app-catalog.mjs");
  const serveFile = fromRepo("apps", "hypervisor", "scripts", "serve-product-ui.mjs");
  const adapterFile = fromRepo("apps", "hypervisor", "scripts", "ioi-api-adapter.mjs");
  const projectionFile = fromRepo("apps", "hypervisor", "scripts", "ioi-projection.mjs");
  const serverFile = fromRepo("apps", "hypervisor", "product-ui", "server.cjs");
  const viteMainFile = fromRepo("apps", "hypervisor", "src", "main.tsx");
  const ownedPublic = fromRepo("apps", "hypervisor", "product-ui", "owned", "public");
  const publicRoot = fromRepo("apps", "hypervisor", "product-ui", "public");
  const mainAsset = oneAsset(ownedPublic, "main-");
  const segmentAsset = oneAsset(ownedPublic, "SegmentProvider-");
  const publicFlags = path.join(publicRoot, "feature-flags", "configcat", "configuration-files", "configcat-proxy", "default", "config_v6.json");
  const ownedFlags = path.join(ownedPublic, "feature-flags", "configcat", "configuration-files", "configcat-proxy", "default", "config_v6.json");
  const publicFixtures = path.join(publicRoot, "api");
  const ownedFixtures = path.join(ownedPublic, "api");
  const liveCrawl = fs.existsSync(LIVE_CRAWL_EVIDENCE)
    ? readJson(LIVE_CRAWL_EVIDENCE)
    : null;

  const canonSource = readText(canonFile);
  const canonicalTaxonomy = parseCanonicalTaxonomy(canonSource);
  const parity = readJson(parityFile);
  const starting = readJson(startingFile);
  const dormant = readJson(dormantFile);
  const atlas = readJson(atlasFile);
  const serveSource = readText(serveFile);
  const adapterSource = readText(adapterFile);
  const staticFiles = staticRouteScanFiles();
  const staticRoutes = extractStaticRouteStrings(staticFiles);
  const capturedRoutes = extractCapturedSpaRoutes(mainAsset, segmentAsset);
  const allSourceRoutes = new Set([...staticRoutes, ...capturedRoutes]);
  const registeredSlugs = new Set(SURFACES.map((surface) => surface.slug));
  const dormantSlugs = new Set((dormant.seeds || []).map((seed) => seed.slug));
  const surfaceRows = buildSurfaceRows(atlas);
  const seedRows = buildSeedRows(parity, starting, registeredSlugs);
  const fixtures = fixtureInventory(publicFixtures, ownedFixtures);
  const flags = featureFlagInventory(publicFlags, ownedFlags);
  const connect = connectOperations(adapterSource, serveSource);
  const proxies = proxyFamilies(serveSource);
  const catalog = appCatalog();
  const safeGets = [...SAFE_NATIVE_GETS, ...(parity.seeds || []).map((seed) => seed.app_route)];
  for (const surface of surfaceRows) {
    if (!safeGets.includes(surface.route)) safeGets.push(surface.route);
  }
  const visualInspection = inspectVisualBrowserAttempt(liveCrawl?.visual_browser_attempt, {
    safeRoutes: safeGets,
    requiredRoutes: surfaceRows.map((surface) => surface.route),
  });
  const actions = surfaceRows.flatMap((surface) => surface.declared_actions);
  const routeInventory = normalizedHandlerInventory(NORMALIZED_IOI_ROUTE_TEMPLATES);
  const governedControls = surfaceRows.flatMap((surface) =>
    surface.controls
      .filter((control) => control.outcome === "governed_receipted_action")
      .map((control) => ({
        surface_slug: surface.slug,
        control_id: control.id,
        label: control.label,
        binding: control.binding,
        action_descriptor_complete: false,
        authority_chain_evidence: "atlas_evidence_pointer_only",
        planning_gap: "Map the control to a source action descriptor and prove wallet authority, sealed intent/grant, final-invoker revalidation, effect receipt, and negative behavior.",
      })),
  );
  const allControls = surfaceRows.flatMap((surface) => surface.controls);
  const sourceHandlerGuardCensus = buildSourceHandlerGuardCensus(
    serveFile,
    serveSource,
    routeInventory,
    actions,
  );
  const mutationPathDispositions = buildMutationPathDispositions(
    routeInventory,
    actions,
    governedControls,
  );
  const requiredStateCoverage = buildRequiredStateCoverage(staticFiles);
  const planningRecordRefs = planRecordRefs();
  const mainGeneratorFile = fileURLToPath(import.meta.url);
  const moduleFiles = SURFACES
    .map((surface) => boundSurface(surface.route, "GET")?.impl?.meta)
    .filter(Boolean)
    .map((meta) => fromRepo("apps", "hypervisor", meta.module || `surfaces/${meta.slug}/index.mjs`))
    .filter((file) => fs.existsSync(file));
  // The six active bindings have stable source paths even when a module's meta omits `module`.
  for (const file of [
    fromRepo("apps", "hypervisor", "surfaces", "pipeline", "index.mjs"),
    fromRepo("apps", "hypervisor", "surfaces", "sources", "index.mjs"),
    fromRepo("apps", "hypervisor", "surfaces", "ontology-manager", "index.mjs"),
    fromRepo("apps", "hypervisor", "surfaces", "object-explorer", "index.mjs"),
    fromRepo("apps", "hypervisor", "surfaces", "approvals", "index.mjs"),
    fromRepo("apps", "hypervisor", "surfaces", "missions", "index.mjs"),
  ]) moduleFiles.push(file);
  const primaryFiles = uniqueSorted([
    mainGeneratorFile,
    canonFile,
    parityFile,
    startingFile,
    dormantFile,
    atlasFile,
    registryFile,
    catalogFile,
    serveFile,
    adapterFile,
    projectionFile,
    serverFile,
    viteMainFile,
    mainAsset,
    segmentAsset,
    publicFlags,
    ownedFlags,
    ...(liveCrawl ? [LIVE_CRAWL_EVIDENCE] : []),
    ...visualInspection.artifact_files,
    ...moduleFiles,
  ]);
  const planningFiles = planningRecordRefs.map((record) => path.join(implementationRoot, record.path));
  const sourceSnapshot = {
    primary_files: primaryFiles.map((file) => ({ path: rel(file), sha256: sha256File(file) })),
    static_route_scan_tree: treeSnapshot(staticFiles),
    captured_fixture_tree: treeSnapshot(fixtures.source_files),
    planning_owner_record_tree: treeSnapshot(planningFiles),
  };

  return {
    schema_version: "ioi.hypervisor.surface-coverage.v1",
    record_role: "status-free private projection",
    generator: {
      path: "internal-docs/implementation/tools/generate-hypervisor-surface-coverage.mjs",
      write_command: "node internal-docs/implementation/tools/generate-hypervisor-surface-coverage.mjs --write",
      check_command: "node internal-docs/implementation/tools/check-hypervisor-surface-coverage.mjs",
    },
    source_snapshot: sourceSnapshot,
    source_snapshot_sha256: sha256(stableJson(sourceSnapshot)),
    doctrine: {
      architecture_owner: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
      program_sequencer: "internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md",
      purpose: "Machine-recomputed breadth projection over canonical product taxonomy and current Hypervisor source/evidence; it owns neither architecture, implementation sequence, nor program status.",
      status_truth: "Program status lives only in private work-item records and program-state.json; this projection carries source declarations and point-in-time evidence classifications only.",
    },
    canonical_product_taxonomy: {
      counts: {
        core_workspaces: canonicalTaxonomy.classes.core_workspace.length,
        owner_applications: canonicalTaxonomy.classes.owner_application.length,
        substrate_applications: canonicalTaxonomy.classes.substrate_application.length,
        conditional_owner_applications: canonicalTaxonomy.classes.conditional_owner_application.length,
      },
      canon_derived_classes: canonicalTaxonomy.classes,
      canon_derived_identity_count: canonicalTaxonomy.identities.length,
      canon_derived_route_ledger: canonicalTaxonomy.route_rows,
      mapping_rule: "Class membership and the target-route ledger are parsed from canon. Every finite canon identity must have exactly one current-evidence crosswalk and one operational-journey owner; additions fail until both mappings exist.",
      targets: buildCanonicalCrosswalk(canonicalTaxonomy, allSourceRoutes, registeredSlugs, dormantSlugs),
    },
    current_catalog_and_registry: {
      counts: {
        registered_surfaces: surfaceRows.length,
        bound_surface_modules: surfaceRows.filter((surface) => surface.implementation_kind === "bound_surface_module").length,
        flat_serve_handlers: surfaceRows.filter((surface) => surface.implementation_kind === "flat_serve_handler").length,
        app_catalog_entries: catalog.apps.length,
        embeddable_routes: embeddableRoutes().size,
        generic_embed_thread_routes: EMBED_THREAD_ROUTES.length,
      },
      app_catalog_entries: catalog.apps.map((entry) => ({
        slug: entry.slug,
        title: entry.title,
        family: entry.family,
        route: entry.route,
        icon_present: !!entry.icon,
      })),
      embeddable_routes: sorted(embeddableRoutes()),
      surfaces: surfaceRows,
    },
    reference_and_shell_evidence: {
      executable_seed_counts: {
        total: seedRows.length,
        by_parity_class: countBy(seedRows, (seed) => seed.parity_class),
        by_capture_state: countBy(seedRows, (seed) => seed.capture_state),
        shell_pixel_certified: seedRows.filter((seed) => seed.shell_pixel_certified).length,
        booted_past_shell: seedRows.filter((seed) => seed.booted_past_shell_snapshot).length,
        served_200: seedRows.filter((seed) => seed.served_status_snapshot === 200).length,
      },
      executable_seeds: seedRows,
      dormant_seed_count: (dormant.seeds || []).length,
      dormant_seeds: (dormant.seeds || []).map((seed) => ({
        slug: seed.slug,
        canonical_owner: seed.canonical_owner,
        first_meaningful_pull: seed.first_meaningful_pull,
        proposed_route: seed.proposed_route,
        active_registration: seed.active_registration,
        active_parity_class: seed.active_parity_class,
        activation_requirements: seed.activation_requirements,
      })),
    },
    route_and_adapter_coverage: {
      counts: {
        safe_get_survey_routes: safeGets.length,
        captured_spa_routes: capturedRoutes.length,
        static_ioi_and_reference_route_strings: staticRoutes.length,
        normalized_ioi_handler_templates: routeInventory.grouped.length,
        atomic_normalized_ioi_handler_templates: routeInventory.atomic.length,
        wildcard_proxy_families: proxies.length,
        exact_local_asset_routes: 2,
        locally_intercepted_mirror_paths: INTERCEPT_PATTERNS.length,
        connect_adapter_operations: connect.all.length,
        literal_connect_adapter_operations: connect.literal.length,
        dynamic_project_service_operations: connect.dynamic.length,
        unique_fixture_endpoints: fixtures.endpoints.length,
        physical_fixture_files: fixtures.source_files.length,
        vite_diagnostic_routes: 1,
      },
      safe_get_survey_routes: safeGets,
      captured_spa_routes: capturedRoutes,
      static_ioi_and_reference_route_strings: staticRoutes,
      normalized_ioi_handler_templates: NORMALIZED_IOI_ROUTE_TEMPLATES,
      atomic_normalized_ioi_handler_templates: routeInventory.atomic,
      source_handler_guard_census: sourceHandlerGuardCensus,
      wildcard_proxy_families: proxies,
      exact_local_asset_routes: ["GET /ioi-augmentation.js", "ANY /static/assets/Terminal-CAzwFiqq.js"],
      locally_intercepted_mirror_paths: INTERCEPT_PATTERNS,
      connect_adapter: {
        literal_operations: connect.literal,
        dynamic_project_service_operations: connect.dynamic,
        operations: connect.all,
      },
      captured_fixtures: {
        duplicate_trees: [rel(publicFixtures), rel(ownedFixtures)],
        all_pairs_byte_identical: fixtures.endpoints.every((endpoint) => endpoint.byte_identical),
        endpoints: fixtures.endpoints,
      },
      vite_diagnostic_routes: ["/workspace-preview"],
    },
    state_and_control_coverage: {
      counts: {
        controls: allControls.length,
        implemented_controls: allControls.filter((control) => control.implemented).length,
        unimplemented_controls: allControls.filter((control) => !control.implemented).length,
        by_outcome: countBy(allControls, (control) => control.outcome),
        feature_flags: flags.length,
        operational_state_declarations: countBy(surfaceRows, (surface) => surface.operational_state_declaration),
      },
      disabled_missing_authority: surfaceRows.flatMap((surface) =>
        surface.controls
          .filter((control) => control.outcome === "disabled_missing_authority")
          .map((control) => ({ surface_slug: surface.slug, ...control })),
      ),
      unsupported_reference_session: surfaceRows.flatMap((surface) =>
        surface.controls
          .filter((control) => control.outcome === "unsupported_reference_session")
          .map((control) => ({ surface_slug: surface.slug, ...control })),
      ),
      required_state_coverage: requiredStateCoverage,
      feature_flags: flags,
    },
    consequential_action_authority: {
      declared_module_action_count: actions.length,
      declared_module_actions: actions,
      governed_receipted_control_count: governedControls.length,
      governed_receipted_controls: governedControls,
      normalized_mutation_template_count: mutationPathDispositions.length,
      normalized_mutation_path_dispositions: mutationPathDispositions,
      governed_control_descriptor_gap: "The 24 governed/receipted atlas controls are evidence pointers, not complete action descriptors; each remains pending mapping to the five-part authority chain.",
      unsigned_workflow_evidence_is_authority: false,
      boundary_note: "Bound module action descriptors carry route-local coordinates and receipt type declarations only. They do not prove wallet authority, a sealed intent/grant, final-invoker revalidation, durable effect receipt, or negative behavior. Atlas controls and flat serve handlers remain evidence pointers and acquire no authority from this projection.",
    },
    live_read_only_crawl: liveCrawl
      ? {
          result: "EVIDENCE_CAPTURED",
          evidence_role: "per-cut transport reachability evidence; not implementation or status proof",
          evidence_path: implementationRelative(LIVE_CRAWL_EVIDENCE),
          evidence_sha256: sha256File(LIVE_CRAWL_EVIDENCE),
          captured_at: liveCrawl.captured_at,
          base_url: liveCrawl.base_url,
          supported_start_command: liveCrawl.supported_start_command,
          expected_route_count: liveCrawl.route_inventory?.expected_route_count,
          captured_route_count: liveCrawl.summary?.captured_route_count,
          response_status_counts: liveCrawl.summary?.response_status_counts,
          transport_reachable_count: liveCrawl.summary?.transport_reachable_count,
          request_error_count: liveCrawl.summary?.request_error_count,
          expected_routes_match_current_inventory:
            stableJson(liveCrawl.route_inventory?.expected_routes || []) === stableJson(safeGets),
          nonclaim: "A retained GET result proves only point-in-time transport reachability for its response; it does not prove rendering, interaction, accessibility, authority, workflow completeness, or program status.",
        }
      : {
          result: "MISSING",
          evidence_role: "required per-cut transport reachability evidence",
          evidence_path: implementationRelative(LIVE_CRAWL_EVIDENCE),
          nonclaim: "The static inventory does not prove that any route was reachable in this cut.",
        },
    visual_verification: buildVisualVerification(liveCrawl),
    private_plan_record_refs: planningRecordRefs,
    honest_nonclaims: [
      "This deterministic projection performs no HTTP request, DOM interaction, desktop/narrow visual check, accessibility walk, or mutation; it references a separately retained read-only crawl artifact when one is present.",
      "A route literal, registration, catalog entry, HTTP 200, redirect, captured page, or fixture endpoint is reachability/source evidence only; none proves a complete workflow.",
      "Shell pixel certification and parity classes preserve presentation evidence only; they do not establish canonical product membership, authority, operational completeness, or an M-stage exit.",
      "The three dormant UX seeds are unregistered evidence and stay nonlaunchable until an owner-led implementation decision satisfies their activation requirements.",
      "The operational-depth atlas is a point-in-time source assertion. Its implemented flag and operational_state declarations do not close program work or override work-item status.",
      "The 173 unimplemented controls remain explicit; disabled_missing_authority and unsupported_reference_session are not silently reclassified as implemented.",
      "Captured fixture trees and wildcard mock fallthrough remain production-truth risks. Plausible fixture data on daemon loss is not daemon truth and requires the planned fallback-retirement proof.",
      "A feature flag is captured configuration, not a canonical requirement, admission decision, grant, receipt, or implementation-status claim.",
      "Consequential product authority remains with wallet grants, sealed intents, final-invoker revalidation, and durable receipts. Workflow evidence is not product authority.",
      "No federation, multi-node, cohort, L1, two-sovereign, embodied-live, or stage-closure claim is made by this projection.",
    ],
  };
}

export function validateHypervisorSurfaceCoverage(projection) {
  const errors = [];
  const expect = (condition, message) => { if (!condition) errors.push(message); };
  const canonical = projection.canonical_product_taxonomy;
  const registry = projection.current_catalog_and_registry;
  const seeds = projection.reference_and_shell_evidence;
  const routes = projection.route_and_adapter_coverage;
  const states = projection.state_and_control_coverage;
  const live = projection.live_read_only_crawl;
  const visual = projection.visual_verification;
  const planById = new Map(
    projection.private_plan_record_refs.map((record) => [record.work_item_id, record]),
  );
  expect(projection.schema_version === "ioi.hypervisor.surface-coverage.v1", "schema_version mismatch");
  expect(projection.record_role === "status-free private projection", "record_role must stay status-free");
  const derivedClasses = canonical.canon_derived_classes || {};
  const derivedIdentities = Object.values(derivedClasses).flat();
  expect(stableJson(Object.keys(derivedClasses)) === stableJson(Object.values(CANONICAL_TAXONOMY_HEADINGS)), "canon-derived taxonomy class vocabulary or order changed");
  expect(canonical.counts.core_workspaces === derivedClasses.core_workspace?.length, "canonical workspace count is not canon-derived");
  expect(canonical.counts.owner_applications === derivedClasses.owner_application?.length, "canonical owner-application count is not canon-derived");
  expect(canonical.counts.substrate_applications === derivedClasses.substrate_application?.length, "canonical substrate-application count is not canon-derived");
  expect(canonical.counts.conditional_owner_applications === derivedClasses.conditional_owner_application?.length, "conditional owner-application count is not canon-derived");
  expect(canonical.canon_derived_identity_count === derivedIdentities.length, "canon-derived identity count is inconsistent");
  expect(new Set(derivedIdentities).size === derivedIdentities.length, "canon-derived taxonomy contains duplicate identities");
  expect(canonical.targets.length === derivedIdentities.length, "canonical target crosswalk does not exactly cover canon-derived identities");
  expect(stableJson(sorted(canonical.targets.map((target) => target.name))) === stableJson(sorted(derivedIdentities)), "canonical target identities differ from the canon-derived taxonomy");
  expect(stableJson(sorted(Object.keys(CURRENT_TARGET_CROSSWALK))) === stableJson(sorted(derivedIdentities)), "current target mappings do not exactly cover canon-derived identities");
  expect(stableJson(sorted(Object.keys(OPERATIONAL_JOURNEY_OWNER_IDS))) === stableJson(sorted(derivedIdentities)), "operational-journey mappings do not exactly cover canon-derived identities");
  expect((canonical.canon_derived_route_ledger || []).length === derivedIdentities.length + 1, "canon-derived route ledger must cover every identity plus New Session");
  for (const target of canonical.targets) {
    const expectedOperationalOwner = OPERATIONAL_JOURNEY_OWNER_IDS[target.name];
    const expectedShellOwner = target.surface_class === "core_workspace"
      ? CORE_WORKSPACE_SHELL_OWNER_ID
      : APPLICATION_SHELL_OWNER_ID;
    expect(!!expectedOperationalOwner, `${target.name} lacks a fixed operational-journey owner`);
    expect(target.operational_journey_owner?.work_item_id === expectedOperationalOwner, `${target.name} has the wrong operational-journey owner`);
    expect(target.operational_journey_owner?.stage_id === planById.get(expectedOperationalOwner)?.stage_id, `${target.name} operational-journey stage is stale`);
    expect(target.m6_shell_owner?.work_item_id === expectedShellOwner, `${target.name} has the wrong M6 shell owner`);
    expect(target.m6_shell_owner?.stage_id === "M6", `${target.name} shell owner must be M6`);
    expect(target.shell_evidence_is_operational_depth === false, `${target.name} conflates shell evidence with operational depth`);
    expect(planById.has(expectedOperationalOwner), `${target.name} operational-journey owner is absent from private plan refs`);
    expect(planById.has(expectedShellOwner), `${target.name} shell owner is absent from private plan refs`);
  }
  expect(registry.counts.registered_surfaces === 14, "registered surface count must be 14");
  expect(registry.counts.bound_surface_modules === 6, "bound module count must be 6");
  expect(registry.counts.flat_serve_handlers === 8, "flat handler count must be 8");
  expect(registry.counts.app_catalog_entries === 14, "app catalog count must be 14");
  expect(registry.counts.embeddable_routes === 18, "embeddable route count must be 18");
  expect(seeds.executable_seed_counts.total === 39, "executable seed count must be 39");
  expect(seeds.executable_seed_counts.by_parity_class.daemon_wired === 13, "daemon_wired seed count must be 13");
  expect(seeds.executable_seed_counts.by_parity_class.substrate_bound === 3, "substrate_bound seed count must be 3");
  expect(seeds.executable_seed_counts.by_parity_class.reference_capture === 23, "reference_capture seed count must be 23");
  expect(seeds.executable_seed_counts.shell_pixel_certified === 13, "pixel-certified seed count must be 13");
  expect(seeds.executable_seed_counts.booted_past_shell === 15, "booted seed count must be 15");
  expect(seeds.executable_seed_counts.served_200 === 35, "served-200 seed count must be 35");
  expect(seeds.dormant_seed_count === 3, "dormant seed count must be 3");
  expect(routes.counts.safe_get_survey_routes === 75, "safe GET survey count must be 75");
  expect(routes.counts.captured_spa_routes === 76, "captured SPA route count must be 76");
  expect(routes.counts.static_ioi_and_reference_route_strings === 202, "static route-string count must be 202");
  const normalizedInventory = normalizedHandlerInventory(routes.normalized_ioi_handler_templates || []);
  expect(routes.counts.normalized_ioi_handler_templates === normalizedInventory.grouped.length, "normalized IOI grouped-template count is inconsistent");
  expect(routes.counts.atomic_normalized_ioi_handler_templates === normalizedInventory.atomic.length, "normalized IOI atomic-template count is inconsistent");
  expect(stableJson(routes.atomic_normalized_ioi_handler_templates) === stableJson(normalizedInventory.atomic), "atomic normalized IOI templates are stale or incomplete");
  const guardCensus = routes.source_handler_guard_census || {};
  expect(guardCensus.reviewed_guard_inventory_matches === true, "native /__ioi handler decisions changed without reviewed normalized-route mapping");
  expect(guardCensus.guard_inventory_sha256 === guardCensus.reviewed_guard_inventory_sha256, "native /__ioi handler guard digest is not the reviewed digest");
  expect(guardCensus.unique_guard_count === guardCensus.guards?.length, "source handler unique-guard count is inconsistent");
  expect(guardCensus.guard_count === (guardCensus.guards || []).reduce((total, guard) => total + guard.occurrence_count, 0), "source handler guard count is inconsistent");
  expect((guardCensus.unmapped_exact_source_routes || []).length === 0, `exact source routes lack normalized mappings: ${(guardCensus.unmapped_exact_source_routes || []).join(", ")}`);
  expect((guardCensus.normalized_templates_without_source_anchor || []).length === 0, `normalized handler templates lack source anchors: ${(guardCensus.normalized_templates_without_source_anchor || []).join(", ")}`);
  expect(routes.counts.wildcard_proxy_families === 36, "proxy-family count must be 36");
  expect(routes.counts.exact_local_asset_routes === 2, "exact local asset route count must be 2");
  expect(routes.counts.locally_intercepted_mirror_paths === 10, "intercepted mirror path count must be 10");
  expect(routes.counts.connect_adapter_operations === 103, "Connect operation count must be 103");
  expect(routes.counts.literal_connect_adapter_operations === 98, "literal Connect operation count must be 98");
  expect(routes.counts.dynamic_project_service_operations === 5, "dynamic ProjectService operation count must be 5");
  expect(routes.counts.unique_fixture_endpoints === 55, "fixture endpoint count must be 55");
  expect(routes.counts.physical_fixture_files === 110, "physical fixture count must be 110");
  expect(routes.captured_fixtures.all_pairs_byte_identical, "fixture tree pairs must remain byte-identical");
  expect(states.counts.controls === 563, "control count must be 563");
  expect(states.counts.implemented_controls === 390, "implemented control count must be 390");
  expect(states.counts.unimplemented_controls === 173, "unimplemented control count must be 173");
  expect(states.counts.by_outcome.disabled_missing_authority === 172, "disabled_missing_authority count must be 172");
  expect(states.counts.by_outcome.unsupported_reference_session === 75, "unsupported_reference_session count must be 75");
  expect(states.counts.feature_flags === 99, "feature flag count must be 99");
  const requiredStateNames = REQUIRED_STATE_SPECS.map((state) => state.name);
  const projectedStateNames = (states.required_state_coverage || []).map((state) => state.state);
  expect(stableJson(projectedStateNames) === stableJson(requiredStateNames), "required state vocabulary or order is incomplete");
  for (const state of states.required_state_coverage || []) {
    expect(new Set(["observed_source_evidence", "planned_gap", "unverified"]).has(state.disposition), `${state.state} has an invalid disposition`);
    expect(Array.isArray(state.current_evidence_refs), `${state.state} lacks source evidence refs`);
    expect(Number.isInteger(state.current_source_occurrence_count), `${state.state} lacks a source occurrence count`);
    expect(state.current_evidence_ref_count === state.current_evidence_refs?.length, `${state.state} source evidence-ref count is inconsistent`);
    const counted = (state.current_evidence_refs || []).reduce((total, evidence) => total + evidence.occurrence_count, 0);
    expect(counted === state.current_source_occurrence_count, `${state.state} source occurrence count is inconsistent`);
    expect(Array.isArray(state.owning_plan_records) && state.owning_plan_records.length > 0, `${state.state} lacks a planning owner`);
    for (const owner of state.owning_plan_records || []) {
      expect(planById.has(owner.work_item_id), `${state.state} planning owner ${owner.work_item_id} is absent from private plan refs`);
      expect(planById.get(owner.work_item_id)?.stage_id === owner.stage_id, `${state.state} planning owner stage is stale`);
    }
    if (state.visual_dependency) {
      expect(state.disposition === "unverified", `${state.state} must remain unverified without state-bound visual evidence`);
    }
  }
  expect(projection.consequential_action_authority.declared_module_action_count === 19, "declared module action count must be 19");
  expect(projection.consequential_action_authority.governed_receipted_control_count === 24, "governed control count must be 24");
  expect(projection.consequential_action_authority.unsigned_workflow_evidence_is_authority === false, "unsigned workflow evidence must never be authority");
  const mutationRoutes = normalizedInventory.atomic.filter((route) => route.method !== "GET");
  const mutationDispositions = projection.consequential_action_authority.normalized_mutation_path_dispositions || [];
  expect(projection.consequential_action_authority.normalized_mutation_template_count === mutationRoutes.length, "normalized mutation-template count is incomplete");
  expect(mutationDispositions.length === mutationRoutes.length, "every non-GET normalized template must have one mutation disposition");
  expect(new Set(mutationDispositions.map((item) => item.route_key)).size === mutationDispositions.length, "normalized mutation dispositions contain duplicate route keys");
  expect(stableJson(mutationDispositions.map((item) => item.route_key)) === stableJson(mutationRoutes.map((item) => item.route_key)), "normalized mutation dispositions do not exactly cover the non-GET handler templates");
  for (const disposition of mutationDispositions) {
    expect(disposition.method !== "GET", `${disposition.route_key} is not a mutation template`);
    expect(disposition.route_key === `${disposition.method} ${disposition.route_template}`, `${disposition.route_key} has inconsistent route coordinates`);
    expect(disposition.planning_owner?.work_item_id === ACTION_AUTHORITY_PLAN_OWNER_ID, `${disposition.route_key} lacks the proposed authority-chain planning owner`);
    expect(disposition.planning_owner?.stage_id === planById.get(ACTION_AUTHORITY_PLAN_OWNER_ID)?.stage_id, `${disposition.route_key} planning-owner stage is stale`);
    expect(disposition.unsigned_workflow_evidence_is_authority === false, `${disposition.route_key} treats unsigned workflow evidence as authority`);
    expect(typeof disposition.disposition === "string" && disposition.disposition.endsWith("_with_proposed_authority_chain_gap"), `${disposition.route_key} lacks an explicit proposed-gap disposition`);
    const chain = disposition.authority_chain_planning || {};
    for (const field of [
      "wallet_authority",
      "sealed_intent_or_grant",
      "final_invoker_revalidation",
      "effect_receipt",
      "negative_behavior",
    ]) {
      expect(!!chain[field], `${disposition.route_key} lacks ${field} planning`);
      expect(new Set(["current_handler_gap", "descriptor_only_not_proven"]).has(chain[field]?.evidence_state), `${disposition.route_key} makes an unsupported ${field} proof claim`);
      expect(typeof chain[field]?.nonclaim === "string" && chain[field].nonclaim.length > 0, `${disposition.route_key} lacks the ${field} nonclaim`);
    }
    for (const descriptor of disposition.bound_action_descriptors || []) {
      const matchingAction = projection.consequential_action_authority.declared_module_actions.find((action) =>
        action.surface_slug === descriptor.surface_slug &&
        action.id === descriptor.action_id &&
        action.method === disposition.method &&
        action.route_template === disposition.route_template,
      );
      expect(!!matchingAction, `${disposition.route_key} joins an unresolved bound action descriptor`);
    }
    for (const pointer of disposition.exact_governed_control_pointers || []) {
      const matchingControl = projection.consequential_action_authority.governed_receipted_controls.find((control) =>
        control.surface_slug === pointer.surface_slug &&
        control.control_id === pointer.control_id &&
        control.binding === pointer.binding,
      );
      expect(!!matchingControl && pointer.binding.includes(disposition.route_template), `${disposition.route_key} joins a non-exact governed-control pointer`);
    }
  }
  expect(live.result === "EVIDENCE_CAPTURED", "current retained live read-only crawl evidence is required");
  expect(live.expected_route_count === routes.counts.safe_get_survey_routes, "live-crawl expected route count is stale");
  expect(live.captured_route_count === routes.counts.safe_get_survey_routes, "live-crawl captured route count is incomplete");
  expect(live.expected_routes_match_current_inventory === true, "live-crawl route inventory is stale");
  expect(live.request_error_count === 0, "live-crawl evidence contains request errors");
  expect(live.transport_reachable_count === routes.counts.safe_get_survey_routes, "not every safe GET was transport-reachable");
  expect(/^[0-9a-f]{64}$/u.test(live.evidence_sha256 || ""), "live-crawl evidence digest is missing");
  expect(live.nonclaim?.includes("transport reachability"), "live-crawl evidence lacks its transport-only nonclaim");
  const retainedVisualAttempt = fs.existsSync(LIVE_CRAWL_EVIDENCE)
    ? readJson(LIVE_CRAWL_EVIDENCE).visual_browser_attempt
    : null;
  const visualInspection = inspectVisualBrowserAttempt(retainedVisualAttempt, {
    safeRoutes: routes.safe_get_survey_routes || [],
    requiredRoutes: (projection.current_catalog_and_registry?.surfaces || [])
      .map((surface) => surface.route),
  });
  for (const error of visualInspection.errors) expect(false, error);
  expect(new Set(["SKIP", "EVIDENCE_CAPTURED"]).has(visual.result), "visual verification must be an explicit SKIP or retained EVIDENCE_CAPTURED");
  expect(visual.required_scopes?.length === 2, "visual verification must retain desktop and narrow obligations");
  expect(
    stableJson((visual.required_scopes || []).map((scope) => scope.viewport)) === stableJson(REQUIRED_VISUAL_VIEWPORTS),
    "visual verification scopes must be ordered desktop then narrow",
  );
  expect((visual.required_scopes || []).every((scope) => scope.interaction_policy === "read_only"), "visual verification scopes must remain read-only");
  expect(
    stableJson(visual) === stableJson(buildVisualVerification(fs.existsSync(LIVE_CRAWL_EVIDENCE) ? readJson(LIVE_CRAWL_EVIDENCE) : null)),
    "visual verification is not an exact projection of the retained evidence artifact",
  );
  if (visual.result === "SKIP") {
    expect(visual.verification_state === "unverified", "visual verification state must remain unverified after SKIP");
    expect(visual.reason_code === "in_app_browser_unavailable", "visual verification skip reason must be explicit");
    expect(visual.skip_detail?.includes("Browser is not available: iab"), "visual verification skip must retain the browser capability failure");
    expect((visual.required_scopes || []).every((scope) => scope.verification_state === "unverified"), "SKIP cannot verify either viewport scope");
    expect(visual.nonclaims?.some((nonclaim) => nonclaim.includes("No desktop or narrow-viewport surface")), "visual SKIP lacks its viewport nonclaim");
  }
  if (visual.result === "EVIDENCE_CAPTURED") {
    expect(visual.verification_state === "retained_viewport_evidence", "captured visual evidence must use the bounded retained-viewport state");
    expect(visual.capture_tool === "in_app_browser", "captured visual evidence must name the in-app browser");
    expect(visual.interaction_policy === "read_only", "captured visual evidence must remain read-only");
    expect(visual.evidence_path === implementationRelative(LIVE_CRAWL_EVIDENCE), "captured visual evidence path is stale");
    expect(visual.evidence_sha256 === sha256File(LIVE_CRAWL_EVIDENCE), "captured visual evidence digest is stale");
    expect((visual.required_scopes || []).every((scope) => scope.verification_state === "evidence_captured"), "captured visual evidence must cover both viewport scopes");
    expect((visual.required_scopes || []).every((scope) => scope.route_observation_count === scope.route_observations?.length && scope.route_observation_count > 0), "captured visual evidence lacks route-level observations");
    expect((visual.required_scopes || []).every((scope) => Array.isArray(scope.evidence_refs) && scope.evidence_refs.length > 0), "captured visual evidence lacks retained screenshot references");
    const visualNonclaims = (visual.nonclaims || []).join(" ").toLowerCase();
    expect(visualNonclaims.includes("implementation"), "captured visual evidence lacks its implementation nonclaim");
    expect(visualNonclaims.includes("program status"), "captured visual evidence lacks its program-status nonclaim");
  }
  for (const action of projection.consequential_action_authority.declared_module_actions) {
    expect(action.method !== "GET", `${action.surface_slug}/${action.id} must be consequential`);
    expect(!!action.authority?.plane && !!action.authority?.operation, `${action.surface_slug}/${action.id} lacks authority coordinates`);
    expect(!!action.receipt, `${action.surface_slug}/${action.id} lacks a receipt declaration`);
    expect(action.planning_owner?.work_item_id === ACTION_AUTHORITY_PLAN_OWNER_ID, `${action.surface_slug}/${action.id} lacks its authority-chain planning owner`);
    expect(action.unsigned_workflow_evidence_is_authority === false, `${action.surface_slug}/${action.id} treats unsigned workflow evidence as authority`);
    const chain = action.authority_chain_planning || {};
    for (const field of [
      "wallet_authority",
      "sealed_intent_or_grant",
      "final_invoker_revalidation",
      "effect_receipt",
      "negative_behavior",
    ]) {
      expect(!!chain[field], `${action.surface_slug}/${action.id} lacks ${field} planning`);
      expect(new Set(["current_descriptor_gap", "descriptor_only_not_proven"]).has(chain[field]?.evidence_state), `${action.surface_slug}/${action.id} makes an unsupported ${field} proof claim`);
      expect(typeof chain[field]?.nonclaim === "string" && chain[field].nonclaim.length > 0, `${action.surface_slug}/${action.id} lacks the ${field} nonclaim`);
    }
  }
  for (const control of projection.consequential_action_authority.governed_receipted_controls) {
    expect(control.action_descriptor_complete === false, `${control.surface_slug}/${control.control_id} is incorrectly action-descriptor complete`);
    expect(control.authority_chain_evidence === "atlas_evidence_pointer_only", `${control.surface_slug}/${control.control_id} is not marked as an atlas pointer`);
    expect(typeof control.planning_gap === "string" && control.planning_gap.length > 0, `${control.surface_slug}/${control.control_id} lacks an authority-chain gap`);
  }
  expect(projection.honest_nonclaims.length >= 10, "honest nonclaims are incomplete");
  failWith("hypervisor surface coverage validation", errors);
}

export function checkHypervisorSurfaceCoverage() {
  const projection = buildHypervisorSurfaceCoverage();
  validateHypervisorSurfaceCoverage(projection);
  const result = checkDeterministic(OUTPUT, projection);
  failWith("hypervisor surface coverage check", result.ok ? [] : [result.reason]);
  process.stdout.write(
    `hypervisor surface coverage check passed: ${projection.current_catalog_and_registry.counts.registered_surfaces} registered surfaces, ${projection.reference_and_shell_evidence.executable_seed_counts.total} executable seeds, ${projection.state_and_control_coverage.counts.controls} controls, ${projection.route_and_adapter_coverage.counts.static_ioi_and_reference_route_strings} static route strings, ${projection.live_read_only_crawl.captured_route_count} retained safe GETs; visual ${projection.visual_verification.result}\n`,
  );
  return projection;
}

function crc32(value) {
  let crc = 0xffffffff;
  for (const byte of value) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([typeBytes, data])), 0);
  return Buffer.concat([length, typeBytes, data, checksum]);
}

function solidTransparentPng(widthPx, heightPx) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(widthPx, 0);
  ihdr.writeUInt32BE(heightPx, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const scanlineBytes = widthPx * 4 + 1;
  const pixels = Buffer.alloc(scanlineBytes * heightPx);
  return Buffer.concat([
    signature,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlib.deflateSync(pixels)),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function runVisualEvidenceSelfTest() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-hypervisor-visual-contract-"));
  const require = (condition, message) => {
    if (!condition) throw new Error(`visual evidence self-test: ${message}`);
  };
  try {
    const relativeToEstate = path.relative(implementationRoot, tempRoot);
    require(
      relativeToEstate === ".." || relativeToEstate.startsWith(`..${path.sep}`),
      `temporary root must remain outside the private estate: ${tempRoot}`,
    );
    const desktopFile = path.join(tempRoot, "desktop.png");
    const narrowFile = path.join(tempRoot, "narrow.png");
    const desktopPng = solidTransparentPng(1280, 720);
    const narrowPng = solidTransparentPng(390, 844);
    fs.writeFileSync(desktopFile, desktopPng);
    fs.writeFileSync(narrowFile, narrowPng);
    const attempt = {
      result: "EVIDENCE_CAPTURED",
      capture_tool: "in_app_browser",
      interaction_policy: "read_only",
      captured_at: "2000-01-01T00:00:00.000Z",
      required_viewports: ["desktop", "narrow"],
      scopes: [
        {
          viewport: "desktop",
          interaction_policy: "read_only",
          width_px: 1280,
          height_px: 720,
          route_observations: [
            {
              route: "/ai",
              observation: "Hermetic contract fixture only; this is not retained product evidence.",
            },
            {
              route: "/__ioi/surface-two",
              observation: "Second required surface fixture; this is not retained product evidence.",
            },
          ],
          evidence_refs: [{
            path: "desktop.png",
            kind: "viewport_screenshot",
            media_type: "image/png",
            sha256: sha256File(desktopFile),
          }],
        },
        {
          viewport: "narrow",
          interaction_policy: "read_only",
          width_px: 390,
          height_px: 844,
          route_observations: [
            {
              route: "/ai",
              observation: "Hermetic contract fixture only; this is not retained product evidence.",
            },
            {
              route: "/__ioi/surface-two",
              observation: "Second required surface fixture; this is not retained product evidence.",
            },
          ],
          evidence_refs: [{
            path: "narrow.png",
            kind: "viewport_screenshot",
            media_type: "image/png",
            sha256: sha256File(narrowFile),
          }],
        },
      ],
      remaining_obligation: "Real retained in-app-browser observations remain required outside this self-test.",
      nonclaims: [
        "This is a point-in-time structural fixture only.",
        "This fixture does not prove product implementation or workflow completeness.",
        "This fixture does not change program status.",
      ],
    };
    const options = {
      safeRoutes: ["/ai", "/__ioi/surface-two"],
      requiredRoutes: ["/ai", "/__ioi/surface-two"],
      artifactPathBase: tempRoot,
      evidenceRoot: tempRoot,
    };

    const valid = inspectVisualBrowserAttempt(attempt, options);
    require(valid.errors.length === 0, `valid case failed: ${valid.errors.join("; ")}`);
    require(valid.artifact_files.length === 2, "valid case did not retain both content-addressed PNGs");

    const incompleteRoutes = cloneJson(attempt);
    incompleteRoutes.scopes[0].route_observations.pop();
    const incompleteRouteResult = inspectVisualBrowserAttempt(incompleteRoutes, options);
    require(
      incompleteRouteResult.errors.some((error) => error.includes("missing required registered surface route")),
      "missing-required-surface case was accepted",
    );

    const missing = cloneJson(attempt);
    missing.scopes[0].evidence_refs = [];
    const missingResult = inspectVisualBrowserAttempt(missing, options);
    require(
      missingResult.errors.some((error) => error.includes("lacks retained screenshot references")),
      "missing-screenshot case was accepted",
    );

    fs.appendFileSync(desktopFile, Buffer.from("tampered", "ascii"));
    const tamperedResult = inspectVisualBrowserAttempt(attempt, options);
    require(
      tamperedResult.errors.some((error) => error.includes("digest does not match")),
      "tampered-screenshot case was accepted",
    );
    fs.writeFileSync(desktopFile, desktopPng);

    const truncatedFile = path.join(tempRoot, "truncated.png");
    fs.writeFileSync(truncatedFile, desktopPng.subarray(0, 24));
    const truncated = cloneJson(attempt);
    truncated.scopes[0].evidence_refs = [{
      path: "truncated.png",
      kind: "viewport_screenshot",
      media_type: "image/png",
      sha256: sha256File(truncatedFile),
    }];
    const truncatedResult = inspectVisualBrowserAttempt(truncated, options);
    require(
      truncatedResult.errors.some((error) => error.includes("not a complete decodable")),
      "truncated-PNG case was accepted",
    );

    const wrongTool = cloneJson(attempt);
    wrongTool.capture_tool = "generic_browser";
    const wrongToolResult = inspectVisualBrowserAttempt(wrongTool, options);
    require(
      wrongToolResult.errors.some((error) => error.includes("identify the in-app browser")),
      "wrong-tool case was accepted",
    );

    const mutating = cloneJson(attempt);
    mutating.interaction_policy = "mutation_allowed";
    for (const scope of mutating.scopes) scope.interaction_policy = "mutation_allowed";
    const mutatingResult = inspectVisualBrowserAttempt(mutating, options);
    require(
      mutatingResult.errors.some((error) => error.includes("must remain read-only")),
      "mutating-interaction case was accepted",
    );
  } finally {
    fs.rmSync(tempRoot, { recursive: true });
  }
  require(!fs.existsSync(tempRoot), "temporary fixture directory was not removed");
  process.stdout.write(
    "visual evidence self-test passed: valid desktop+narrow required-surface coverage and complete content-addressed PNGs accepted; missing-surface, missing-file, truncated, tampered, wrong-tool, and mutating cases rejected; temporary fixtures removed\n",
  );
}

function main() {
  const mode = process.argv[2];
  if (!new Set(["--write", "--check", "--self-test-visual-evidence"]).has(mode) || process.argv.length !== 3) {
    process.stderr.write("usage: node internal-docs/implementation/tools/generate-hypervisor-surface-coverage.mjs --write|--check|--self-test-visual-evidence\n");
    process.exit(2);
  }
  if (mode === "--self-test-visual-evidence") {
    runVisualEvidenceSelfTest();
    return;
  }
  const projection = buildHypervisorSurfaceCoverage();
  validateHypervisorSurfaceCoverage(projection);
  if (mode === "--write") {
    writeDeterministic(OUTPUT, projection);
    process.stdout.write(`wrote ${implementationRelative(OUTPUT)}\n`);
    return;
  }
  const result = checkDeterministic(OUTPUT, projection);
  failWith("hypervisor surface coverage check", result.ok ? [] : [result.reason]);
  process.stdout.write(`hypervisor surface coverage check passed: ${implementationRelative(OUTPUT)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) main();
