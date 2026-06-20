import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";
import { deriveWorkspaceInitializer } from "./runtime-environment-status-projection.mjs";

export { deriveWorkspaceInitializer };

const DEFAULT_SESSIONS_DIRNAME = "ioi-hypervisor-sessions";

function provisionError({ status, code, message, details }) {
  return runtimeError({ status, code, message, details });
}

function artifactRefFor(workspaceRoot, initializer) {
  const digest = createHash("sha256")
    .update(`${workspaceRoot}\n${JSON.stringify(initializer ?? {})}`)
    .digest("hex")
    .slice(0, 24);
  // Encrypted-blob workspace state ref. The bytes are sealed by the
  // storage/custody layer (Phase 4/5); this is the stable handle for them.
  return `agentgres://artifact/workspace/${digest}`;
}

/**
 * Provision a REAL isolated session workspace.
 *
 * Driven by a HypervisorWorkspaceInitializer: mkdtemp an isolated directory
 * under the sessions root (never the daemon cwd / repo), then realize the
 * initializer specs under the session custody_posture — shallow-clone a git
 * remote when one is given and a git runner is available; otherwise leave a
 * fresh scratch workspace the harness fills. Returns the provisioned absolute
 * path plus the component transitions the environment status projects from.
 *
 * Async and route-level by design so the synchronous buildHarnessSessionSpawn
 * (and its many callers/tests) is untouched.
 */
export async function provisionSessionWorkspace(input = {}, deps = {}) {
  const initializer =
    objectRecord(input.initializer) ??
    deriveWorkspaceInitializer({
      workspaceMountPolicy: optionalString(input.workspaceMountPolicy),
      authorityScopeRefs: input.authorityScopeRefs,
    });

  const mkdtemp = deps.mkdtemp ?? ((prefix) => fs.mkdtemp(prefix));
  const mkdir = deps.mkdir ?? ((dir) => fs.mkdir(dir, { recursive: true }));
  const runGit = typeof deps.runGit === "function" ? deps.runGit : null;
  const sessionsRoot =
    optionalString(deps.sessionsRoot) ??
    path.join(os.tmpdir(), DEFAULT_SESSIONS_DIRNAME);

  await mkdir(sessionsRoot);
  const sessionTag = safeId(
    optionalString(input.sessionRef) ?? initializer.initializer_ref ?? "session",
  ).slice(0, 48);
  const workspaceRoot = await mkdtemp(
    path.join(sessionsRoot, `${sessionTag}-`),
  );

  if (workspaceRoot === path.parse(workspaceRoot).root) {
    throw provisionError({
      status: 500,
      code: "workspace_provision_root_forbidden",
      message: "Provisioned workspace resolved to a filesystem root.",
      details: { workspace_root: workspaceRoot },
    });
  }

  // Component transitions the environment status reads. The provisioner is
  // ready once the isolated dir exists; workspace_content depends on whether
  // the initializer content was realized.
  const components = { provisioner: "ready", workspace_content: "ready" };
  const realizedSpecs = [];

  for (const spec of normalizeArray(initializer.specs)
    .map(objectRecord)
    .filter(Boolean)) {
    const git = objectRecord(spec.git);
    if (git && optionalString(git.remote_uri)) {
      if (!runGit) {
        // No git runner available in this slice: record the spec as deferred
        // rather than faking a clone. The scratch workspace is still real.
        components.workspace_content = "initializing";
        realizedSpecs.push({ git: git.remote_uri, realized: false });
        continue;
      }
      const target = optionalString(git.clone_target) ?? ".";
      const cloneInto =
        target === "." ? workspaceRoot : path.join(workspaceRoot, target);
      await runGit(
        ["clone", "--depth", "1", git.remote_uri, cloneInto],
        { cwd: workspaceRoot },
      );
      realizedSpecs.push({ git: git.remote_uri, realized: true });
      continue;
    }
    const contextUrl = optionalString(spec.context_url);
    if (contextUrl) {
      // Context-URL realization (download/extract) is owned by a later phase;
      // record it deferred so the status reflects the truth.
      components.workspace_content = "initializing";
      realizedSpecs.push({ context_url: contextUrl, realized: false });
    }
  }

  return {
    provisioned: true,
    workspace_root: workspaceRoot,
    workspace_artifact_ref: artifactRefFor(workspaceRoot, initializer),
    custody_posture: initializer.custody_posture,
    initializer,
    realized_specs: realizedSpecs,
    components,
    provisioned_at:
      (deps.nowIso ?? (() => new Date().toISOString()))(),
    runtimeTruthSource: "daemon-runtime",
  };
}

/**
 * Best-effort cleanup of a provisioned session workspace. Used by the daemon on
 * session teardown; safe to call with an unprovisioned/missing path.
 */
export async function disposeSessionWorkspace(workspaceRoot, deps = {}) {
  const target = optionalString(workspaceRoot);
  if (!target) return false;
  const sessionsRoot =
    optionalString(deps.sessionsRoot) ??
    path.join(os.tmpdir(), DEFAULT_SESSIONS_DIRNAME);
  // Only ever remove paths under the sessions root — never an arbitrary dir.
  const normalized = path.normalize(target);
  if (!normalized.startsWith(path.normalize(sessionsRoot) + path.sep)) {
    return false;
  }
  const rm = deps.rm ?? ((dir) => fs.rm(dir, { recursive: true, force: true }));
  await rm(normalized);
  return true;
}
