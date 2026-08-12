import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  access,
  lstat,
  readFile,
  readdir,
  readlink,
  stat,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { inspectProductionSourceGraph } from "./vite-production-authority-scan.mjs";

const execFileAsync = promisify(execFile);

export const DEFAULT_REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
export const DEFAULT_MANIFEST_PATH =
  "docs/architecture/_meta/shipped-products.v1.json";

export const CANONICAL_PRODUCT_IDS = Object.freeze([
  "hypervisor-owned-served-ui",
  "hypervisor-vite-workbench",
  "hypervisor-web",
  "developers-ioi-ai",
  "aiagent-xyz",
  "sas-xyz",
]);

export const VALIDATION_PHASES = Object.freeze([
  "structure-only",
  "preflight",
  "post-build",
]);

const REQUIRED_NONSHIPPED_ROOTS = new Map([
  ["apps/ioi-ai", "nonshipped_vendor"],
  ["apps/hypervisor/product-ui/public", "nonshipped_vendor"],
  ["apps/hypervisor/ux-seeds", "nonshipped_fixture"],
  ["apps/aiagent-xyz/fixtures/legacy-ui", "nonshipped_fixture"],
  ["apps/sas-xyz/fixtures/legacy-ui", "nonshipped_fixture"],
]);

const PRODUCT_DISPOSITIONS = new Set(["shipped"]);
const NONSHIPPED_DISPOSITIONS = new Set([
  "nonshipped_vendor",
  "nonshipped_fixture",
]);
const RELEASE_POSTURES = new Set([
  "development_only",
  "production_candidate",
  "production_refused",
]);
const STATE_AUTHORITY_MODES = new Set([
  "daemon_authoritative_projection",
  "daemon_development_preview",
  "presentation_only",
  "retained_evidence_projection",
  "development_domain_projection",
]);
const STATIC_BOUNDARY_MODES = new Set([
  "ported_seed_with_declared_gaps",
  "development_notice_only",
  "source_addressed_illustration",
  "query_gated_preview",
  "quarantined_legacy_fixture",
  "owned_derivative_with_committed_vendor_snapshot",
]);
const VERIFICATION_KINDS = new Set([
  "browser",
  "integration",
  "scanner",
  "test",
]);
const MATERIALIZATIONS = new Set(["tracked", "generated"]);
const DIGEST_POLICIES = new Set(["record", "verify"]);
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

const normalize = (value) =>
  String(value)
    .split(path.sep)
    .join("/")
    .replace(/^\.\//u, "")
    .replace(/\/$/u, "");
const isRecord = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const inside = (parent, candidate) =>
  candidate === parent || candidate.startsWith(`${parent}${path.sep}`);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function exists(target, type = null) {
  try {
    await access(target);
    if (!type) return true;
    const metadata = await stat(target);
    return type === "file" ? metadata.isFile() : metadata.isDirectory();
  } catch {
    return false;
  }
}

function duplicates(values) {
  const seen = new Set();
  const repeated = new Set();
  for (const value of values) {
    if (seen.has(value)) repeated.add(value);
    seen.add(value);
  }
  return [...repeated].sort();
}

function exactSet(left, right) {
  return (
    left.length === right.length && left.every((value) => right.includes(value))
  );
}

function addRequiredString(failures, value, label) {
  if (typeof value !== "string" || value.trim() === "")
    failures.push(`${label} must be a non-empty string`);
}

function resolveRepoPath(repoRoot, relativePath, failures, label) {
  addRequiredString(failures, relativePath, label);
  if (typeof relativePath !== "string" || relativePath.trim() === "")
    return null;
  if (path.isAbsolute(relativePath)) {
    failures.push(`${label} must be repository-relative: ${relativePath}`);
    return null;
  }
  const resolved = path.resolve(repoRoot, relativePath);
  if (!inside(repoRoot, resolved)) {
    failures.push(`${label} escapes the repository: ${relativePath}`);
    return null;
  }
  return resolved;
}

function addTrackedPath(trackedPaths, repoRoot, absolutePath, label) {
  if (!absolutePath || !inside(repoRoot, absolutePath)) return;
  const relativePath = normalize(path.relative(repoRoot, absolutePath));
  const labels = trackedPaths.get(relativePath) ?? new Set();
  labels.add(label);
  trackedPaths.set(relativePath, labels);
}

export function routeInventorySha256(routes) {
  return sha256(`${JSON.stringify(routes)}\n`);
}

export class ShippedProductsManifestError extends Error {
  constructor(failures) {
    super(
      `shipped-products manifest validation failed (${failures.length}):\n${failures.map((failure) => `- ${failure}`).join("\n")}`,
    );
    this.name = "ShippedProductsManifestError";
    this.failures = failures;
  }
}

export async function loadShippedProductsManifest({
  repoRoot = DEFAULT_REPO_ROOT,
  manifestPath = DEFAULT_MANIFEST_PATH,
} = {}) {
  const resolved = path.resolve(repoRoot, manifestPath);
  return JSON.parse(await readFile(resolved, "utf8"));
}

async function walkArtifact(artifactPath) {
  const metadata = await lstat(artifactPath);
  if (metadata.isSymbolicLink()) {
    const target = await readlink(artifactPath);
    const bytes = Buffer.from(target);
    return [
      {
        absolute_path: artifactPath,
        path: path.basename(artifactPath),
        bytes: bytes.length,
        sha256: sha256(bytes),
      },
    ];
  }
  if (metadata.isFile()) {
    const bytes = await readFile(artifactPath);
    return [
      {
        absolute_path: artifactPath,
        path: path.basename(artifactPath),
        bytes: bytes.length,
        sha256: sha256(bytes),
      },
    ];
  }
  if (!metadata.isDirectory())
    throw new Error(
      `artifact is neither a file nor a directory: ${artifactPath}`,
    );

  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolutePath);
        continue;
      }
      const entryMetadata = await lstat(absolutePath);
      const bytes = entryMetadata.isSymbolicLink()
        ? Buffer.from(await readlink(absolutePath))
        : await readFile(absolutePath);
      files.push({
        absolute_path: absolutePath,
        path: normalize(path.relative(artifactPath, absolutePath)),
        bytes: bytes.length,
        sha256: sha256(bytes),
      });
    }
  }
  await visit(artifactPath);
  return files;
}

export async function inspectBuildArtifact(artifactPath) {
  const files = await walkArtifact(artifactPath);
  const treeHash = createHash("sha256");
  for (const file of files) {
    treeHash.update(file.path);
    treeHash.update("\0");
    treeHash.update(file.sha256);
    treeHash.update("\0");
  }
  return {
    file_count: files.length,
    bytes: files.reduce((total, file) => total + file.bytes, 0),
    sha256: treeHash.digest("hex"),
    files,
  };
}

async function validateArtifactIdentityGate(
  identityGate,
  artifact,
  artifactPath,
  product,
  repoRoot,
  failures,
  trackedPaths,
) {
  if (identityGate === undefined) return;
  const label = `${product.id}.build_artifact.identity_gate`;
  if (!isRecord(identityGate)) {
    failures.push(`${label} must be an object`);
    return;
  }
  for (const field of ["schema_version", "endpoint", "tree"])
    addRequiredString(failures, identityGate[field], `${label}.${field}`);
  if (!String(identityGate.endpoint ?? "").startsWith("/"))
    failures.push(`${label}.endpoint must be an absolute application path`);
  const ledgerPath = resolveRepoPath(
    repoRoot,
    identityGate.ledger_path,
    failures,
    `${label}.ledger_path`,
  );
  const verifierPath = resolveRepoPath(
    repoRoot,
    identityGate.verifier_entry,
    failures,
    `${label}.verifier_entry`,
  );
  const indexPath = resolveRepoPath(
    repoRoot,
    identityGate.index_path,
    failures,
    `${label}.index_path`,
  );
  for (const [absolutePath, relativePath, name] of [
    [ledgerPath, identityGate.ledger_path, "ledger"],
    [verifierPath, identityGate.verifier_entry, "verifier"],
    [indexPath, identityGate.index_path, "index"],
  ]) {
    if (!absolutePath || !(await exists(absolutePath, "file")))
      failures.push(
        `${product.id}: artifact identity ${name} does not exist: ${String(relativePath)}`,
      );
    else addTrackedPath(trackedPaths, repoRoot, absolutePath, label);
  }
  if (indexPath && artifactPath && !inside(artifactPath, indexPath))
    failures.push(
      `${product.id}: artifact identity index is outside the artifact root: ${identityGate.index_path}`,
    );
  if (!SHA256_PATTERN.test(String(identityGate.index_sha256 ?? "")))
    failures.push(`${label}.index_sha256 must be a lowercase SHA-256`);
  else if (indexPath && (await exists(indexPath, "file"))) {
    const actual = sha256(await readFile(indexPath));
    if (actual !== identityGate.index_sha256)
      failures.push(
        `${product.id}: artifact identity index digest mismatch: expected ${identityGate.index_sha256}, got ${actual}`,
      );
  }
}

async function validateBuildArtifact(
  artifact,
  product,
  repoRoot,
  phase,
  failures,
  trackedPaths,
  artifactReports,
) {
  const label = `${product.id}.build_artifacts`;
  if (!isRecord(artifact)) {
    failures.push(`${label} entries must be objects`);
    return;
  }
  const artifactPath = resolveRepoPath(
    repoRoot,
    artifact.path,
    failures,
    `${label}.path`,
  );
  if (!MATERIALIZATIONS.has(artifact.materialization))
    failures.push(
      `${product.id}: unknown build artifact materialization ${String(artifact.materialization)}`,
    );
  if (!DIGEST_POLICIES.has(artifact.digest_policy))
    failures.push(
      `${product.id}: unknown build artifact digest policy ${String(artifact.digest_policy)}`,
    );
  if (artifact.digest_policy === "verify") {
    if (!SHA256_PATTERN.test(String(artifact.expected_sha256 ?? "")))
      failures.push(
        `${product.id}: verify artifact ${String(artifact.path)} requires expected_sha256`,
      );
    if (
      !Number.isInteger(artifact.expected_file_count) ||
      artifact.expected_file_count < 1
    )
      failures.push(
        `${product.id}: verify artifact ${String(artifact.path)} requires expected_file_count`,
      );
  } else if (
    artifact.expected_sha256 !== undefined ||
    artifact.expected_file_count !== undefined
  ) {
    failures.push(
      `${product.id}: record-only artifact ${String(artifact.path)} cannot claim an expected digest/count`,
    );
  }

  const mustExist =
    artifact.materialization === "tracked" || phase === "post-build";
  const artifactExists = artifactPath && (await exists(artifactPath));
  if (mustExist && !artifactExists)
    failures.push(
      `${product.id}: ${artifact.materialization} build artifact does not exist in ${phase}: ${String(artifact.path)}`,
    );

  if (artifact.materialization === "generated") {
    if (!isRecord(artifact.producer)) {
      failures.push(
        `${product.id}: generated artifact ${String(artifact.path)} has no producer`,
      );
    } else {
      const packagePath = resolveRepoPath(
        repoRoot,
        artifact.producer.package_json,
        failures,
        `${product.id}.artifact.producer.package_json`,
      );
      addRequiredString(
        failures,
        artifact.producer.script,
        `${product.id}.artifact.producer.script`,
      );
      if (!packagePath || !(await exists(packagePath, "file"))) {
        failures.push(
          `${product.id}: artifact producer package does not exist: ${String(artifact.producer.package_json)}`,
        );
      } else {
        addTrackedPath(
          trackedPaths,
          repoRoot,
          packagePath,
          `${product.id}.artifact.producer.package_json`,
        );
        try {
          const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
          if (!packageJson.scripts?.[artifact.producer.script])
            failures.push(
              `${product.id}: artifact producer script is missing: ${artifact.producer.package_json}#${artifact.producer.script}`,
            );
        } catch (error) {
          failures.push(
            `${product.id}: cannot read artifact producer package: ${error.message}`,
          );
        }
      }
    }
  }

  await validateArtifactIdentityGate(
    artifact.identity_gate,
    artifact,
    artifactPath,
    product,
    repoRoot,
    failures,
    trackedPaths,
  );

  if (!artifactExists) {
    artifactReports.push({
      product_id: product.id,
      path: artifact.path,
      materialization: artifact.materialization,
      status: "declared",
    });
    return;
  }
  if (artifact.materialization !== "tracked" && phase !== "post-build") {
    artifactReports.push({
      product_id: product.id,
      path: artifact.path,
      materialization: artifact.materialization,
      status: "declared",
    });
    return;
  }

  const inspection = await inspectBuildArtifact(artifactPath);
  if (artifact.materialization === "tracked") {
    for (const file of inspection.files)
      addTrackedPath(
        trackedPaths,
        repoRoot,
        file.absolute_path,
        `${product.id}.tracked_artifact`,
      );
  }
  let verified = artifact.digest_policy === "record";
  if (artifact.digest_policy === "verify") {
    verified =
      inspection.sha256 === artifact.expected_sha256 &&
      inspection.file_count === artifact.expected_file_count;
    if (inspection.sha256 !== artifact.expected_sha256)
      failures.push(
        `${product.id}: artifact digest mismatch for ${artifact.path}: expected ${artifact.expected_sha256}, got ${inspection.sha256}`,
      );
    if (inspection.file_count !== artifact.expected_file_count)
      failures.push(
        `${product.id}: artifact file count mismatch for ${artifact.path}: expected ${artifact.expected_file_count}, got ${inspection.file_count}`,
      );
  }
  artifactReports.push({
    product_id: product.id,
    path: artifact.path,
    materialization: artifact.materialization,
    status: "hashed",
    digest_policy: artifact.digest_policy,
    file_count: inspection.file_count,
    bytes: inspection.bytes,
    sha256: inspection.sha256,
    verified,
  });
}

async function validateSourceAssertions(
  product,
  repoRoot,
  failures,
  trackedPaths,
) {
  const boundary = product.permitted_static_boundary;
  if (!isRecord(boundary)) {
    failures.push(`${product.id}: permitted_static_boundary must be an object`);
    return;
  }
  if (!STATIC_BOUNDARY_MODES.has(boundary.mode))
    failures.push(
      `${product.id}: unknown static boundary mode ${String(boundary.mode)}`,
    );
  addRequiredString(
    failures,
    boundary.summary,
    `${product.id}.permitted_static_boundary.summary`,
  );
  if (
    !Array.isArray(boundary.source_assertions) ||
    boundary.source_assertions.length === 0
  ) {
    failures.push(
      `${product.id}: static/illustrative boundary has no source-addressed assertion`,
    );
    return;
  }
  for (const assertion of boundary.source_assertions) {
    if (!isRecord(assertion)) {
      failures.push(`${product.id}: source assertion must be an object`);
      continue;
    }
    const assertionPath = resolveRepoPath(
      repoRoot,
      assertion.path,
      failures,
      `${product.id}.source_assertion.path`,
    );
    if (!assertionPath || !(await exists(assertionPath, "file"))) {
      failures.push(
        `${product.id}: source assertion target does not exist: ${String(assertion.path)}`,
      );
      continue;
    }
    addTrackedPath(
      trackedPaths,
      repoRoot,
      assertionPath,
      `${product.id}.source_assertion`,
    );
    if (!Array.isArray(assertion.contains) || assertion.contains.length === 0) {
      failures.push(
        `${product.id}: source assertion ${assertion.path} has no required markers`,
      );
      continue;
    }
    const source = await readFile(assertionPath, "utf8");
    for (const marker of assertion.contains) {
      addRequiredString(
        failures,
        marker,
        `${product.id}.source_assertion.contains`,
      );
      if (typeof marker === "string" && marker && !source.includes(marker))
        failures.push(
          `${product.id}: ${assertion.path} is missing boundary marker ${JSON.stringify(marker)}`,
        );
    }
  }
}

async function nearestPackageJson(start, repoRoot) {
  let directory = path.dirname(start);
  while (inside(repoRoot, directory)) {
    const packagePath = path.join(directory, "package.json");
    if (await exists(packagePath, "file")) return packagePath;
    if (directory === repoRoot) break;
    directory = path.dirname(directory);
  }
  return null;
}

async function packageJsonForInvocation(repoRoot, entryPath, invocation) {
  if (!invocation.scope) return path.join(repoRoot, "package.json");
  if (invocation.scopeKind === "prefix") {
    const candidate = path.resolve(repoRoot, invocation.scope, "package.json");
    return inside(repoRoot, candidate) ? candidate : null;
  }
  const pathCandidate = path.resolve(
    repoRoot,
    invocation.scope,
    "package.json",
  );
  if (inside(repoRoot, pathCandidate) && (await exists(pathCandidate, "file")))
    return pathCandidate;
  const nearest = entryPath
    ? await nearestPackageJson(entryPath, repoRoot)
    : null;
  if (nearest) {
    try {
      const packageJson = JSON.parse(await readFile(nearest, "utf8"));
      if (packageJson.name === invocation.scope) return nearest;
    } catch {
      return nearest;
    }
  }
  return null;
}

function parseVerificationCommand(command) {
  if (typeof command !== "string" || command.trim() === "") return null;
  if (/[;&|`<>]|\$\(/u.test(command)) return { type: "unsafe" };
  const npm = command.match(
    /^npm\s+(?:(?:run\s+([a-zA-Z0-9:_-]+))|(test))(?:\s+--(workspace|prefix)(?:=|\s+)([^\s]+))?$/u,
  );
  if (npm)
    return {
      type: "package-script",
      script: npm[1] || "test",
      scopeKind: npm[3] ?? null,
      scope: npm[4] ?? null,
    };
  const node = command.match(
    /^node\s+(--test\s+)?([^\s]+)(?:\s+([a-zA-Z0-9_./:=+-]+(?:\s+[a-zA-Z0-9_./:=+-]+)*))?$/u,
  );
  if (node)
    return {
      type: "direct-node",
      test: Boolean(node[1]),
      entry: normalize(node[2]),
      args: node[3] ?? "",
    };
  return { type: "unsupported" };
}

async function validateVerificationCommand(
  verification,
  product,
  repoRoot,
  entryPath,
  failures,
  trackedPaths,
) {
  const invocation = parseVerificationCommand(verification.command);
  if (!invocation) return;
  if (invocation.type === "unsafe" || invocation.type === "unsupported") {
    failures.push(
      `${product.id}: verification ${verification.id} has an unsupported or unsafe command: ${verification.command}`,
    );
    return;
  }
  if (invocation.type === "direct-node") {
    if (invocation.entry !== normalize(verification.entry))
      failures.push(
        `${product.id}: direct-node verification ${verification.id} executes ${invocation.entry}, not its declared entry ${verification.entry}`,
      );
    return;
  }
  const packagePath = await packageJsonForInvocation(
    repoRoot,
    entryPath,
    invocation,
  );
  if (!packagePath || !(await exists(packagePath, "file"))) {
    failures.push(
      `${product.id}: verification ${verification.id} package scope does not resolve: ${invocation.scope ?? "repository root"}`,
    );
    return;
  }
  addTrackedPath(
    trackedPaths,
    repoRoot,
    packagePath,
    `${product.id}.verification.package_json`,
  );
  if (
    invocation.scope &&
    entryPath &&
    !inside(path.dirname(packagePath), entryPath)
  )
    failures.push(
      `${product.id}: verification ${verification.id} entry is outside its package scope: ${verification.entry}`,
    );
  try {
    const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
    if (!packageJson.scripts?.[invocation.script])
      failures.push(
        `${product.id}: verification ${verification.id} references missing package script ${normalize(path.relative(repoRoot, packagePath))}#${invocation.script}`,
      );
    if (
      invocation.scopeKind === "workspace" &&
      !invocation.scope.includes("/") &&
      packageJson.name !== invocation.scope
    )
      failures.push(
        `${product.id}: verification ${verification.id} resolved workspace ${invocation.scope} to package ${String(packageJson.name)}`,
      );
  } catch (error) {
    failures.push(
      `${product.id}: cannot read verification package ${packagePath}: ${error.message}`,
    );
  }
}

async function validateVerification(product, repoRoot, failures, trackedPaths) {
  if (
    !Array.isArray(product.required_verification) ||
    product.required_verification.length === 0
  ) {
    failures.push(`${product.id}: shipped lane is unverified`);
    return;
  }
  const ids = product.required_verification.map((item) => item?.id);
  for (const duplicate of duplicates(ids))
    failures.push(`${product.id}: duplicate verification id ${duplicate}`);
  const kinds = new Set();
  for (const verification of product.required_verification) {
    if (!isRecord(verification)) {
      failures.push(`${product.id}: verification entries must be objects`);
      continue;
    }
    addRequiredString(
      failures,
      verification.id,
      `${product.id}.verification.id`,
    );
    if (!VERIFICATION_KINDS.has(verification.kind))
      failures.push(
        `${product.id}: unknown verification kind ${String(verification.kind)}`,
      );
    else kinds.add(verification.kind);
    if (verification.implementation !== undefined) {
      if (verification.implementation !== "builtin:production-source-graph")
        failures.push(
          `${product.id}: unknown verification implementation ${String(verification.implementation)}`,
        );
      if (
        verification.command !== undefined ||
        verification.entry !== undefined
      )
        failures.push(
          `${product.id}: builtin verification ${verification.id} cannot also declare entry/command`,
        );
      continue;
    }
    const entryPath = resolveRepoPath(
      repoRoot,
      verification.entry,
      failures,
      `${product.id}.verification.entry`,
    );
    if (!entryPath || !(await exists(entryPath, "file")))
      failures.push(
        `${product.id}: verification entry does not exist: ${String(verification.entry)}`,
      );
    else
      addTrackedPath(
        trackedPaths,
        repoRoot,
        entryPath,
        `${product.id}.verification.entry`,
      );
    addRequiredString(
      failures,
      verification.command,
      `${product.id}.verification.command`,
    );
    await validateVerificationCommand(
      verification,
      product,
      repoRoot,
      entryPath,
      failures,
      trackedPaths,
    );
  }
  if (!kinds.has("scanner"))
    failures.push(`${product.id}: shipped lane has no required scanner`);
  if (!kinds.has("browser"))
    failures.push(
      `${product.id}: shipped lane has no required browser verification`,
    );
}

function validateRouteInventory(product, failures) {
  const inventory = product.route_inventory;
  const label = `${product.id}.route_inventory`;
  if (!isRecord(inventory)) {
    failures.push(`${label} must be an object`);
    return;
  }
  if (inventory.inventory_version !== 1)
    failures.push(`${label}.inventory_version must be 1`);
  if (!Array.isArray(inventory.routes) || inventory.routes.length === 0) {
    failures.push(`${label}.routes must be a non-empty array`);
    return;
  }
  const routes = inventory.routes;
  for (const route of routes) {
    if (
      typeof route !== "string" ||
      !route.startsWith("/") ||
      route.includes("?") ||
      route.includes("#") ||
      (route !== "/" && route.endsWith("/"))
    )
      failures.push(`${label} has an invalid route pattern: ${String(route)}`);
  }
  for (const duplicate of duplicates(routes))
    failures.push(`${label} has duplicate route ${duplicate}`);
  const sorted = [...routes].sort();
  if (routes.some((route, index) => route !== sorted[index]))
    failures.push(`${label}.routes must be sorted for a stable digest`);
  if (inventory.expected_count !== routes.length)
    failures.push(
      `${label} count mismatch: expected ${String(inventory.expected_count)}, found ${routes.length}`,
    );
  const digest = routeInventorySha256(routes);
  if (inventory.sha256 !== digest)
    failures.push(
      `${label} digest mismatch: expected ${String(inventory.sha256)}, got ${digest}`,
    );
  addRequiredString(
    failures,
    inventory.browser_verification_id,
    `${label}.browser_verification_id`,
  );
  const verification = product.required_verification?.find(
    (candidate) => candidate?.id === inventory.browser_verification_id,
  );
  if (!verification || verification.kind !== "browser")
    failures.push(
      `${label} is not bound to a declared browser verification: ${String(inventory.browser_verification_id)}`,
    );
}

async function validateSourceGraph(
  product,
  repoRoot,
  fixtureRoots,
  nonshippedByRoot,
  failures,
  trackedPaths,
) {
  const graph = product.source_graph;
  if (!isRecord(graph)) {
    failures.push(`${product.id}: source_graph must be an object`);
    return null;
  }
  const graphRoot = resolveRepoPath(
    repoRoot,
    graph.root,
    failures,
    `${product.id}.source_graph.root`,
  );
  if (!graphRoot || !(await exists(graphRoot, "directory"))) {
    failures.push(
      `${product.id}: source graph root does not exist: ${String(graph.root)}`,
    );
    return null;
  }
  if (!Array.isArray(graph.entries) || graph.entries.length === 0) {
    failures.push(`${product.id}: source graph has no entries`);
    return null;
  }
  if (
    !Array.isArray(graph.allowed_source_roots) ||
    !Array.isArray(graph.quarantined_roots)
  ) {
    failures.push(
      `${product.id}: source graph source-root lists must be arrays`,
    );
    return null;
  }

  for (const fixture of graph.quarantined_roots) {
    const absolute = path.resolve(graphRoot, fixture);
    if (!fixtureRoots.some((fixtureRoot) => fixtureRoot === absolute))
      failures.push(
        `${product.id}: quarantined root is not registered nonshipped_fixture: ${fixture}`,
      );
  }
  for (const allowedRoot of graph.allowed_source_roots) {
    const absolute = path.resolve(graphRoot, allowedRoot);
    const record = nonshippedByRoot.get(absolute);
    if (!record || record.disposition !== "nonshipped_vendor")
      failures.push(
        `${product.id}: external source root is not a registered nonshipped_vendor: ${allowedRoot}`,
      );
  }

  try {
    const report = await inspectProductionSourceGraph({
      root: graphRoot,
      entries: graph.entries,
      fixtureRoots: graph.quarantined_roots,
      allowedSourceRoots: graph.allowed_source_roots,
    });
    for (const file of report.files)
      addTrackedPath(
        trackedPaths,
        repoRoot,
        path.resolve(graphRoot, file),
        `${product.id}.source_graph`,
      );
    return report;
  } catch (error) {
    failures.push(`${product.id}: ${error.message}`);
    return null;
  }
}

async function validatePathOwnership(
  product,
  repoRoot,
  productRoot,
  governedPaths,
  failures,
  trackedPaths,
) {
  const ownership = product.path_ownership;
  if (!isRecord(ownership)) {
    failures.push(`${product.id}: path_ownership must be an object`);
    return [];
  }
  if (!Array.isArray(ownership.lane_roots) || ownership.lane_roots.length === 0)
    failures.push(`${product.id}: path_ownership.lane_roots must be non-empty`);
  if (!Array.isArray(ownership.shared_dependencies))
    failures.push(
      `${product.id}: path_ownership.shared_dependencies must be an array`,
    );
  const laneRoots = [];
  for (const root of ownership.lane_roots || []) {
    const absolute = resolveRepoPath(
      repoRoot,
      root,
      failures,
      `${product.id}.path_ownership.lane_root`,
    );
    if (absolute) {
      laneRoots.push(absolute);
      if (productRoot && !inside(productRoot, absolute))
        failures.push(
          `${product.id}: lane root is outside the product root: ${root}`,
        );
    }
  }
  const sharedRoots = [];
  for (const dependency of ownership.shared_dependencies || []) {
    if (!isRecord(dependency)) {
      failures.push(`${product.id}: shared dependency must be an object`);
      continue;
    }
    const absolute = resolveRepoPath(
      repoRoot,
      dependency.root,
      failures,
      `${product.id}.path_ownership.shared_dependency.root`,
    );
    addRequiredString(
      failures,
      dependency.owner_ref,
      `${product.id}.path_ownership.shared_dependency.owner_ref`,
    );
    addRequiredString(
      failures,
      dependency.reason,
      `${product.id}.path_ownership.shared_dependency.reason`,
    );
    const ownerRef = resolveRepoPath(
      repoRoot,
      dependency.owner_ref,
      failures,
      `${product.id}.path_ownership.shared_dependency.owner_ref`,
    );
    if (!ownerRef || !(await exists(ownerRef, "file")))
      failures.push(
        `${product.id}: shared dependency owner ref does not exist: ${String(dependency.owner_ref)}`,
      );
    else
      addTrackedPath(
        trackedPaths,
        repoRoot,
        ownerRef,
        `${product.id}.path_ownership.shared_dependency.owner_ref`,
      );
    if (absolute) sharedRoots.push(absolute);
  }
  for (const governed of governedPaths) {
    if (!governed.absolute) continue;
    if (
      ![...laneRoots, ...sharedRoots].some((root) =>
        inside(root, governed.absolute),
      )
    )
      failures.push(
        `${product.id}: ${governed.kind} crosses its declared lane ownership: ${governed.relative}`,
      );
  }
  return laneRoots;
}

async function validateWorkspaceCoverage(manifest, repoRoot, failures) {
  const packagePath = path.join(repoRoot, "package.json");
  if (!(await exists(packagePath, "file"))) return;
  let packageJson;
  try {
    packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  } catch (error) {
    failures.push(
      `cannot read root package.json for product discovery: ${error.message}`,
    );
    return;
  }
  const dispositionedRoots = [
    ...manifest.products.map((product) => normalize(product.root)),
    ...manifest.nonshipped_roots.map((record) => normalize(record.root)),
  ];
  for (const workspace of packageJson.workspaces || []) {
    if (
      typeof workspace !== "string" ||
      !workspace.startsWith("apps/") ||
      workspace.includes("*")
    )
      continue;
    const normalized = normalize(workspace);
    if (
      !dispositionedRoots.some(
        (root) =>
          normalized === root ||
          normalized.startsWith(`${root}/`) ||
          root.startsWith(`${normalized}/`),
      )
    )
      failures.push(
        `executable app workspace is undispositioned: ${workspace}`,
      );
  }
}

async function gitTrackedPaths(repoRoot, relativePath) {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["-C", repoRoot, "ls-files", "--stage", "-z", "--", relativePath],
      { encoding: "buffer", maxBuffer: 64 * 1024 * 1024 },
    );
    return stdout
      .toString("utf8")
      .split("\0")
      .filter(Boolean)
      .map((line) =>
        normalize(line.replace(/^[0-9]+ [a-f0-9]+ [0-9]+\t/u, "")),
      );
  } catch (error) {
    throw new Error(`cannot inspect Git index: ${error.message}`);
  }
}

async function validateTrackedPaths(repoRoot, trackedPaths, failures) {
  for (const [relativePath, labels] of [...trackedPaths.entries()].sort()) {
    const matches = await gitTrackedPaths(repoRoot, relativePath);
    const absolutePath = path.resolve(repoRoot, relativePath);
    const metadata = await lstat(absolutePath).catch(() => null);
    const exactTracked = metadata?.isDirectory()
      ? matches.length > 0
      : matches.includes(relativePath);
    if (!exactTracked)
      failures.push(
        `declared path is not tracked in the Git index: ${relativePath} (${[...labels].sort().join(", ")})`,
      );
  }
}

export async function validateShippedProductsManifest(
  manifest,
  {
    repoRoot = DEFAULT_REPO_ROOT,
    laneId = null,
    phase = "preflight",
    manifestPath = DEFAULT_MANIFEST_PATH,
    canonicalProductIds = CANONICAL_PRODUCT_IDS,
    requiredNonshippedRoots = REQUIRED_NONSHIPPED_ROOTS,
  } = {},
) {
  const failures = [];
  const trackedPaths = new Map();
  const artifactReports = [];
  if (!VALIDATION_PHASES.includes(phase))
    failures.push(`unknown validation phase ${String(phase)}`);
  if (!isRecord(manifest))
    throw new ShippedProductsManifestError(["manifest root must be an object"]);
  if (manifest.schema_version !== "ioi.shipped-products.v1")
    failures.push(`unknown schema_version ${String(manifest.schema_version)}`);
  addRequiredString(failures, manifest.authority, "authority");
  if (!Array.isArray(manifest.required_shipped_product_ids))
    failures.push("required_shipped_product_ids must be an array");
  if (!Array.isArray(manifest.products))
    failures.push("products must be an array");
  if (!Array.isArray(manifest.nonshipped_roots))
    failures.push("nonshipped_roots must be an array");
  if (manifestPath) {
    const absoluteManifest = resolveRepoPath(
      repoRoot,
      manifestPath,
      failures,
      "manifest_path",
    );
    if (!absoluteManifest || !(await exists(absoluteManifest, "file")))
      failures.push(`manifest path does not exist: ${manifestPath}`);
    else addTrackedPath(trackedPaths, repoRoot, absoluteManifest, "manifest");
  }
  if (failures.length) throw new ShippedProductsManifestError(failures);

  const requiredIds = manifest.required_shipped_product_ids;
  const productIds = manifest.products.map((product) => product?.id);
  for (const duplicate of duplicates(requiredIds))
    failures.push(`duplicate required product id ${duplicate}`);
  for (const duplicate of duplicates(productIds))
    failures.push(`duplicate product id ${duplicate}`);
  if (!exactSet(requiredIds, canonicalProductIds))
    failures.push(
      `required product inventory must be exactly: ${canonicalProductIds.join(", ")}`,
    );
  if (!exactSet(productIds, requiredIds)) {
    const missing = requiredIds.filter((id) => !productIds.includes(id));
    const extra = productIds.filter((id) => !requiredIds.includes(id));
    if (missing.length)
      failures.push(`missing shipped products: ${missing.join(", ")}`);
    if (extra.length)
      failures.push(`unknown shipped products: ${extra.join(", ")}`);
  }
  if (laneId && !productIds.includes(laneId))
    failures.push(`unknown requested lane ${laneId}`);

  const nonshippedIds = manifest.nonshipped_roots.map((record) => record?.id);
  const nonshippedRoots = manifest.nonshipped_roots.map((record) =>
    normalize(record?.root),
  );
  for (const duplicate of duplicates(nonshippedIds))
    failures.push(`duplicate nonshipped id ${duplicate}`);
  for (const duplicate of duplicates(nonshippedRoots))
    failures.push(`duplicate nonshipped root ${duplicate}`);

  const nonshippedByRoot = new Map();
  const fixtureRoots = [];
  for (const record of manifest.nonshipped_roots) {
    if (!isRecord(record)) {
      failures.push("nonshipped root entries must be objects");
      continue;
    }
    addRequiredString(failures, record.id, "nonshipped.id");
    addRequiredString(failures, record.owner, `${record.id}.owner`);
    const ownerRef = resolveRepoPath(
      repoRoot,
      record.owner_ref,
      failures,
      `${record.id}.owner_ref`,
    );
    if (!ownerRef || !(await exists(ownerRef, "file")))
      failures.push(
        `${record.id}: owner ref does not exist: ${String(record.owner_ref)}`,
      );
    else
      addTrackedPath(
        trackedPaths,
        repoRoot,
        ownerRef,
        `${record.id}.owner_ref`,
      );
    addRequiredString(failures, record.summary, `${record.id}.summary`);
    if (!NONSHIPPED_DISPOSITIONS.has(record.disposition))
      failures.push(
        `${record.id}: unknown disposition ${String(record.disposition)}`,
      );
    const absoluteRoot = resolveRepoPath(
      repoRoot,
      record.root,
      failures,
      `${record.id}.root`,
    );
    if (!absoluteRoot || !(await exists(absoluteRoot, "directory")))
      failures.push(
        `${record.id}: nonshipped root does not exist: ${String(record.root)}`,
      );
    if (absoluteRoot) {
      nonshippedByRoot.set(absoluteRoot, record);
      if (record.disposition === "nonshipped_fixture")
        fixtureRoots.push(absoluteRoot);
    }
    const verificationEntry = resolveRepoPath(
      repoRoot,
      record.verification_entry,
      failures,
      `${record.id}.verification_entry`,
    );
    if (!verificationEntry || !(await exists(verificationEntry, "file")))
      failures.push(
        `${record.id}: verification entry does not exist: ${String(record.verification_entry)}`,
      );
    else
      addTrackedPath(
        trackedPaths,
        repoRoot,
        verificationEntry,
        `${record.id}.verification_entry`,
      );
  }
  for (const [requiredRoot, disposition] of requiredNonshippedRoots) {
    const record = manifest.nonshipped_roots.find(
      (candidate) => normalize(candidate.root) === requiredRoot,
    );
    if (!record)
      failures.push(
        `missing explicit nonshipped classification for ${requiredRoot}`,
      );
    else if (record.disposition !== disposition)
      failures.push(`${requiredRoot} must be classified ${disposition}`);
  }

  const reports = [];
  const laneRootsByProduct = new Map();
  const selectedProducts = laneId
    ? manifest.products.filter((product) => product.id === laneId)
    : manifest.products;
  for (const product of selectedProducts) {
    if (!isRecord(product)) {
      failures.push("product entries must be objects");
      continue;
    }
    addRequiredString(failures, product.id, "product.id");
    addRequiredString(failures, product.name, `${product.id}.name`);
    addRequiredString(failures, product.owner, `${product.id}.owner`);
    const ownerRef = resolveRepoPath(
      repoRoot,
      product.owner_ref,
      failures,
      `${product.id}.owner_ref`,
    );
    if (!ownerRef || !(await exists(ownerRef, "file")))
      failures.push(
        `${product.id}: owner ref does not exist: ${String(product.owner_ref)}`,
      );
    else
      addTrackedPath(
        trackedPaths,
        repoRoot,
        ownerRef,
        `${product.id}.owner_ref`,
      );
    if (!PRODUCT_DISPOSITIONS.has(product.disposition))
      failures.push(
        `${product.id}: unknown disposition ${String(product.disposition)}`,
      );
    if (!RELEASE_POSTURES.has(product.release_posture))
      failures.push(
        `${product.id}: unknown release posture ${String(product.release_posture)}`,
      );
    if (!STATE_AUTHORITY_MODES.has(product.state_authority_mode))
      failures.push(
        `${product.id}: unknown state authority mode ${String(product.state_authority_mode)}`,
      );
    const productRoot = resolveRepoPath(
      repoRoot,
      product.root,
      failures,
      `${product.id}.root`,
    );
    if (!productRoot || !(await exists(productRoot, "directory")))
      failures.push(
        `${product.id}: product root does not exist: ${String(product.root)}`,
      );

    const governedPaths = [];
    if (
      !Array.isArray(product.production_entries) ||
      product.production_entries.length === 0
    )
      failures.push(`${product.id}: no production entries`);
    for (const entry of product.production_entries || []) {
      const entryPath = resolveRepoPath(
        repoRoot,
        entry,
        failures,
        `${product.id}.production_entry`,
      );
      governedPaths.push({
        kind: "production entry",
        relative: entry,
        absolute: entryPath,
      });
      if (!entryPath || !(await exists(entryPath, "file")))
        failures.push(
          `${product.id}: production entry does not exist: ${String(entry)}`,
        );
      else
        addTrackedPath(
          trackedPaths,
          repoRoot,
          entryPath,
          `${product.id}.production_entry`,
        );
      if (
        entryPath &&
        fixtureRoots.some((fixtureRoot) => inside(fixtureRoot, entryPath))
      )
        failures.push(
          `${product.id}: production entry is inside a nonshipped fixture: ${entry}`,
        );
    }
    if (
      !Array.isArray(product.route_sources) ||
      product.route_sources.length === 0
    )
      failures.push(`${product.id}: no route sources`);
    for (const routeSource of product.route_sources || []) {
      const routePath = resolveRepoPath(
        repoRoot,
        routeSource,
        failures,
        `${product.id}.route_source`,
      );
      governedPaths.push({
        kind: "route source",
        relative: routeSource,
        absolute: routePath,
      });
      if (!routePath || !(await exists(routePath, "file")))
        failures.push(
          `${product.id}: route source does not exist: ${String(routeSource)}`,
        );
      else
        addTrackedPath(
          trackedPaths,
          repoRoot,
          routePath,
          `${product.id}.route_source`,
        );
    }
    if (
      !Array.isArray(product.build_artifacts) ||
      product.build_artifacts.length === 0
    )
      failures.push(`${product.id}: no build artifact disposition`);
    for (const artifact of product.build_artifacts || []) {
      const artifactPath =
        isRecord(artifact) && typeof artifact.path === "string"
          ? path.resolve(repoRoot, artifact.path)
          : null;
      governedPaths.push({
        kind: "build artifact",
        relative: artifact?.path,
        absolute: artifactPath,
      });
      await validateBuildArtifact(
        artifact,
        product,
        repoRoot,
        phase,
        failures,
        trackedPaths,
        artifactReports,
      );
    }
    const laneRoots = await validatePathOwnership(
      product,
      repoRoot,
      productRoot,
      governedPaths,
      failures,
      trackedPaths,
    );
    laneRootsByProduct.set(product.id, laneRoots);
    validateRouteInventory(product, failures);
    await validateSourceAssertions(product, repoRoot, failures, trackedPaths);
    await validateVerification(product, repoRoot, failures, trackedPaths);
    const graphReport = await validateSourceGraph(
      product,
      repoRoot,
      fixtureRoots,
      nonshippedByRoot,
      failures,
      trackedPaths,
    );
    if (graphReport) reports.push({ id: product.id, ...graphReport });
  }

  if (!laneId) {
    const laneRootRows = [...laneRootsByProduct.entries()].flatMap(
      ([productId, roots]) => roots.map((root) => ({ productId, root })),
    );
    for (let left = 0; left < laneRootRows.length; left += 1) {
      for (let right = left + 1; right < laneRootRows.length; right += 1) {
        const a = laneRootRows[left];
        const b = laneRootRows[right];
        if (a.productId === b.productId) continue;
        if (inside(a.root, b.root) || inside(b.root, a.root))
          failures.push(
            `shipped lane roots overlap across ${a.productId} and ${b.productId}: ${normalize(path.relative(repoRoot, a.root))} <> ${normalize(path.relative(repoRoot, b.root))}`,
          );
      }
    }
    for (const fixtureRoot of fixtureRoots) {
      const quarantined = manifest.products.some((product) => {
        if (!isRecord(product.source_graph)) return false;
        const graphRoot = path.resolve(repoRoot, product.source_graph.root);
        return (product.source_graph.quarantined_roots || []).some(
          (fixture) => path.resolve(graphRoot, fixture) === fixtureRoot,
        );
      });
      if (!quarantined)
        failures.push(
          `nonshipped fixture has no production-graph quarantine: ${normalize(path.relative(repoRoot, fixtureRoot))}`,
        );
    }
    await validateWorkspaceCoverage(manifest, repoRoot, failures);
  }

  if (phase !== "structure-only")
    await validateTrackedPaths(repoRoot, trackedPaths, failures);

  if (failures.length) throw new ShippedProductsManifestError(failures);
  return {
    schema_version: manifest.schema_version,
    phase,
    product_count: selectedProducts.length,
    nonshipped_root_count: manifest.nonshipped_roots.length,
    tracked_path_count: phase === "structure-only" ? null : trackedPaths.size,
    source_graphs: reports,
    artifacts: artifactReports,
  };
}
