#!/usr/bin/env node
// ENVIRONMENT-LEASE AUTHORITY — the env-ops seam authorizes on a lease's ACTION, not merely its
// resources, and the lease minters resolve a caller instead of hardcoding the operator.
//
// WHAT THIS EXISTS TO CATCH, PROVEN LIVE BEFORE IT WAS FIXED. Next-legs XIV Leg 4 drove a real daemon
// end to end and produced side effects — a file written, `bash -lc` executed — through a privilege
// escalation that every green gate in the estate had missed and that canon actively asserted CLOSED:
//
//   · `POST /v1/hypervisor/environments/:id/ports/:port/expose` resolved no caller and minted an
//     `environment.port` capability lease, returning it as `accessToken`.
//   · `supervisor_routes::lease_binds_env` — the check the `/supervisor/` env-ops consumer runs —
//     tested only that the grant's RESOURCES named the environment, NEVER its ACTION. So a
//     port-forward lease, or an `environment.editor.open` lease, was a full ReadFile/WriteFile/Exec
//     bearer over the workspace.
//   · `/supervisor/:env/...EnvironmentOpsService/:method` is OUTSIDE `/v1/`, so `auth_gate` never
//     sees it — the lease check is its only protection.
//
// THE FIX, AND WHAT THIS GATE ASSERTS AS ITS FINDING (the exploit, run as the test):
//   1. THE CHOKEPOINT. A lease may drive env-ops iff its action is `environment.ops`. A port lease
//      and an editor lease are minted, and each is PROVEN UNABLE to WriteFile or Exec — asserted by
//      the ABSENCE OF THE SIDE EFFECT (no file on disk, no marker from a command), never by a status
//      code alone. A response is the writer's own product; the file is the truth.
//   2. THE POSITIVE CONTROL. A legitimate `environment.ops` lease CAN drive them — so assertion 1 is
//      not merely "every request 401s".
//   3. THE MINTERS RESOLVE A CALLER. In `exposed_untrusted` posture the ops-lease and port-expose
//      minters REFUSE, where they used to mint an operator lease for anyone.
//
// OWNER-BINDING. The environment create route now binds its daemon-minted id to the authenticated
// principal in the substrate scope chain before the environment record exists. Every lease minter
// below resolves that pin. A second authenticated principal in the same org therefore proves that
// tenant membership is not being mistaken for ownership.

import fs from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");

const B64 = (s) => Buffer.from(s, "utf8").toString("base64");
const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const entryCount = (dir) => {
  try { return fs.readdirSync(dir).length; } catch { return 0; }
};
const errorCode = (reply) => reply?.j?.error?.code ?? reply?.j?.error?.message ?? reply?.j?.code ?? reply?.j?.reason;
const filesUnder = (root) => {
  const found = [];
  const walk = (dir) => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(absolute);
      else if (entry.isFile()) found.push(absolute);
    }
  };
  walk(root);
  return found;
};
// Request-scope truth lives in Agentgres frames rather than a convenience JSON directory. The
// frames still carry their exact JSON payload bytes, so this derives the bound environment ids from
// durable substrate files without asking the daemon that just wrote them to self-report success.
const environmentScopeRefs = (dataDir) => {
  const refs = new Set();
  for (const file of filesUnder(dataDir)) {
    let bytes;
    try { bytes = fs.readFileSync(file); } catch { continue; }
    if (!bytes.includes(Buffer.from("hypervisor-environment"))) continue;
    const text = bytes.toString("utf8");
    for (const match of text.matchAll(/env_[0-9a-f]{12,}/gu)) refs.add(match[0]);
  }
  return refs;
};

async function jd(url, { method = "GET", headers = {}, body } = {}) {
  const r = await fetch(url, { method, headers: { "content-type": "application/json", ...headers }, body });
  const t = await r.text();
  let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, j };
}

const opsUrl = (D, env, m) => `${D}/supervisor/${env}/supervisor.v1.EnvironmentOpsService/${m}`;

const listenMarker = (marker) => new Promise((resolve, reject) => {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(marker);
  });
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => resolve({
    server,
    port: server.address().port,
    marker,
  }));
});

const closeMarker = ({ server }) => new Promise((resolve) => {
  server.closeAllConnections?.();
  server.close(resolve);
});

async function run() {
  const previewAuthority = spawnSync("cargo", [
    "test", "--locked", "-q", "-p", "ioi-node", "--bin", "hypervisor-daemon",
    "preview_listener_requires_the_exact_live_capability_on_every_request",
  ], { cwd: ROOT, encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
  ok("HANDLE 4/7 — the live preview listener refuses absent, wrong, and revoked capabilities while admitting the exact active one on every request",
    previewAuthority.status === 0,
    previewAuthority.status === 0 ? "targeted live TCP test passed" : `cargo status=${previewAuthority.status}: ${(previewAuthority.stderr || previewAuthority.stdout || "").trim().slice(-500)}`);
  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.error("BLOCKED — no daemon binary (exit 2)"); process.exit(2); }
  const D = plane.daemonUrl;
  const dataDir = plane.dataDir;
  const markers = [];
  try {
    // Two real principals share org://local. The first creates the environment; the second is the
    // adversarial authenticated non-owner. A tenant-only check would admit both.
    const log = (() => { try { return fs.readFileSync(path.join(dataDir, "isolated-daemon.log"), "utf8"); } catch { return ""; } })();
    const btok = (log.match(/(ioi_bootstrap_[0-9a-f]+)/) || [])[1];
    let ownerAuth = {};
    if (btok) {
      const bs = await jd(`${D}/v1/hypervisor/auth/bootstrap`, { method: "POST", body: JSON.stringify({ token: btok, password: "verifier-pw-123" }) });
      if (bs.j?.session_token) ownerAuth = { authorization: `Bearer ${bs.j.session_token}` };
    }
    ok("an owner session was acquired before the environment creation seam", !!ownerAuth.authorization, ownerAuth.authorization ? "session acquired" : "NO session (bootstrap token not found)");
    const memberEmail = "env-lease-non-owner@ioi.local";
    const memberPassword = "env-lease-non-owner-v1";
    const member = await jd(`${D}/v1/hypervisor/principals`, { method: "POST", headers: ownerAuth,
      body: JSON.stringify({ email: memberEmail, name: "Environment lease non-owner", role: "member", password: memberPassword }) });
    const memberId = member.j?.principal?.principal_id;
    await jd(`${D}/v1/hypervisor/principals/${memberId}/tenant-memberships`, { method: "POST", headers: ownerAuth,
      body: JSON.stringify({ tenant_ref: "org://local", expected_revision: 0, idempotency_key: "env-lease-member", reason: "owner-model verifier" }) });
    const memberLogin = await jd(`${D}/v1/hypervisor/auth/login`, { method: "POST",
      body: JSON.stringify({ email: memberEmail, password: memberPassword }) });
    const nonOwnerAuth = memberLogin.j?.session_token ? { authorization: `Bearer ${memberLogin.j.session_token}` } : {};
    ok("a distinct authenticated non-owner shares the owner's org tenant", !!memberId && !!nonOwnerAuth.authorization,
      `member=${memberId || "NONE"} session=${!!nonOwnerAuth.authorization}`);

    // ---------------------------------------------------------------- the one creation seam
    const forcedId = "env_caller_chosen_forbidden";
    const forcedRecordsBefore = entryCount(path.join(dataDir, "environments"));
    const forcedScopesBefore = environmentScopeRefs(dataDir);
    const forcedCreate = await jd(`${D}/v1/hypervisor/environments`, { method: "POST", headers: ownerAuth,
      body: JSON.stringify({ environment_id: forcedId, spec: {} }) });
    const forcedScopesAfter = environmentScopeRefs(dataDir);
    ok("the only creation seam refuses a caller-supplied environment id before either a record or immutable owner pin exists",
      forcedCreate.status === 400 && errorCode(forcedCreate) === "environment_id_server_minted"
        && entryCount(path.join(dataDir, "environments")) === forcedRecordsBefore
        && !fs.existsSync(path.join(dataDir, "environments", `${forcedId}.json`))
        && forcedScopesAfter.size === forcedScopesBefore.size,
      `status=${forcedCreate.status}/${errorCode(forcedCreate)} records=${forcedRecordsBefore}->${entryCount(path.join(dataDir, "environments"))} scopes=${forcedScopesBefore.size}->${forcedScopesAfter.size}`);

    const absentId = "env_00000000000000000000000000000000";
    const absentGet = await jd(`${D}/v1/hypervisor/environments/${absentId}`, { headers: ownerAuth });
    const absentStart = await jd(`${D}/v1/hypervisor/environments/${absentId}/start`, { method: "POST", headers: ownerAuth, body: "{}" });
    ok("authenticated GET and lifecycle action on a nonexistent canonical id both return 404 and materialize no record, pin, or workspace",
      absentGet.status === 404 && absentStart.status === 404
        && !fs.existsSync(path.join(dataDir, "environments", `${absentId}.json`))
        && !fs.existsSync(path.join(dataDir, "environments", absentId))
        && !environmentScopeRefs(dataDir).has(absentId),
      `get=${absentGet.status}/${errorCode(absentGet)} start=${absentStart.status}/${errorCode(absentStart)}`);

    const ownPreview = await listenMarker("m032-owner-preview");
    const victimPreview = await listenMarker("m032-victim-preview");
    markers.push(ownPreview, victimPreview);
    const declaredPorts = [8080, 9090, ownPreview.port, victimPreview.port]
      .map((port) => ({ port, protocol: "tcp", access_policy: "session_lease" }));
    const createdEnv = await jd(`${D}/v1/hypervisor/environments`, { method: "POST", headers: ownerAuth,
      body: JSON.stringify({ spec: { declared_ports: declaredPorts } }) });
    const env = createdEnv.j?.environment?.id;
    const safeId = String(env || "missing").replace(/[^A-Za-z0-9_-]/g, "_");
    const ws = path.join(dataDir, "environments", safeId, "workspace");
    const startedEnv = env ? await jd(`${D}/v1/hypervisor/environments/${env}/start`, { method: "POST", headers: ownerAuth, body: "{}" }) : { status: 0 };
    ok("the authenticated creation seam daemon-mints an id and the owner materializes its workspace",
      createdEnv.status === 200 && String(env).startsWith("env_") && startedEnv.status === 200 && fs.existsSync(ws),
      `create=${createdEnv.status} id=${env} start=${startedEnv.status} workspace=${fs.existsSync(ws)}`);

    // M03.2 — declaration alone is not sufficient if another environment owns the same provider
    // target. The vulnerable handler accepted the path number, minted a lease, and bound its proxy
    // before adding that number to the caller's status row. Here both environments name the victim
    // target so the cross-environment fence, not merely an "undeclared" check, has to refuse it.
    const victimCreated = await jd(`${D}/v1/hypervisor/environments`, { method: "POST", headers: ownerAuth,
      body: JSON.stringify({ spec: { declared_ports: [{ port: victimPreview.port, protocol: "tcp", access_policy: "private" }] } }) });
    const victimEnv = victimCreated.j?.environment?.id;
    const victimStarted = victimEnv ? await jd(`${D}/v1/hypervisor/environments/${victimEnv}/start`, { method: "POST", headers: ownerAuth, body: "{}" }) : { status: 0 };
    const grantsBeforeCrossPreview = entryCount(path.join(dataDir, "authority-grants"));
    const ownerRecordBeforeCrossPreview = fs.readFileSync(path.join(dataDir, "environments", `${safeId}.json`));
    const crossPreview = await jd(`${D}/v1/hypervisor/environments/${env}/ports/${victimPreview.port}/expose`, { method: "POST", headers: ownerAuth, body: "{}" });
    const ownerRecordAfterCrossPreview = fs.readFileSync(path.join(dataDir, "environments", `${safeId}.json`));
    ok("M03.2 CROSS-CONSUMER NEGATIVE — an owner cannot make its preview proxy reach a host target claimed by another environment, even when its own declaration repeats that port; refusal mints no lease and mutates no environment record",
      victimCreated.status === 200 && victimStarted.status === 200
        && crossPreview.j?.ok === false && crossPreview.j?.reason === "environment_port_target_owned_by_another_environment"
        && !crossPreview.j?.accessToken && !crossPreview.j?.public_proxy_port
        && entryCount(path.join(dataDir, "authority-grants")) === grantsBeforeCrossPreview
        && ownerRecordBeforeCrossPreview.equals(ownerRecordAfterCrossPreview),
      `victim=${victimCreated.status}/${victimStarted.status} expose=${crossPreview.status}/${crossPreview.j?.reason} grants=${grantsBeforeCrossPreview}->${entryCount(path.join(dataDir, "authority-grants"))} record_unchanged=${ownerRecordBeforeCrossPreview.equals(ownerRecordAfterCrossPreview)}`);

    const ownPreviewMint = await jd(`${D}/v1/hypervisor/environments/${env}/ports/${ownPreview.port}/expose`, { method: "POST", headers: ownerAuth, body: "{}" });
    const ownPreviewToken = ownPreviewMint.j?.accessToken;
    const ownPreviewReply = ownPreviewMint.j?.url && ownPreviewToken
      ? await fetch(ownPreviewMint.j.url).then(async (response) => ({ status: response.status, body: await response.text() }))
      : { status: 0, body: "" };
    ok("M03.2 POSITIVE CONTROL — an exact lease reaches the environment's unique admitted TCP target, proving the negative is a target-ownership fence rather than a disabled preview plane",
      ownPreviewMint.j?.ok === true && !!ownPreviewToken
        && ownPreviewReply.status === 200 && ownPreviewReply.body === ownPreview.marker,
      `mint=${ownPreviewMint.status}/${ownPreviewMint.j?.ok} proxy=${ownPreviewReply.status} marker=${ownPreviewReply.body}`);
    await jd(`${D}/v1/hypervisor/environments/${env}/ports/${ownPreview.port}/unexpose`, { method: "POST", headers: ownerAuth, body: "{}" });

    // Bind precedes record bytes. Induce the second write to fail by replacing the fixture's
    // environment-record directory with a file, then prove the freshly minted substrate pin
    // survives while neither record nor workspace can exist. The fixture directory is restored in
    // a finally block before any later assertion runs.
    const environmentDir = path.join(dataDir, "environments");
    const savedEnvironmentDir = path.join(dataDir, "environments.owner-model-saved");
    const scopesBeforeWriteFailure = environmentScopeRefs(dataDir);
    let failedCreate = { status: 0, j: {} };
    try {
      fs.renameSync(environmentDir, savedEnvironmentDir);
      fs.writeFileSync(environmentDir, "deliberate record-directory obstruction\n");
      failedCreate = await jd(`${D}/v1/hypervisor/environments`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ spec: {} }) });
    } finally {
      try { fs.rmSync(environmentDir, { force: true }); } catch { /* fixture cleanup best effort */ }
      fs.renameSync(savedEnvironmentDir, environmentDir);
    }
    const scopesAfterWriteFailure = environmentScopeRefs(dataDir);
    const pinsFromFailedWrite = [...scopesAfterWriteFailure].filter((ref) => !scopesBeforeWriteFailure.has(ref));
    const failedWriteId = pinsFromFailedWrite.length === 1 ? pinsFromFailedWrite[0] : null;
    ok("an induced environment-record write failure leaves the already-committed immutable owner pin intact but no environment record or workspace",
      failedCreate.status === 500 && pinsFromFailedWrite.length === 1
        && !fs.existsSync(path.join(environmentDir, `${failedWriteId}.json`))
        && !fs.existsSync(path.join(environmentDir, String(failedWriteId))),
      `status=${failedCreate.status}/${errorCode(failedCreate)} new_pins=${pinsFromFailedWrite.join(",") || "NONE"} record=${!!failedWriteId && fs.existsSync(path.join(environmentDir, `${failedWriteId}.json`))}`);

    const alias = `${env}.`;
    const aliasRecordsBefore = entryCount(path.join(dataDir, "hypervisor-environment-backups"));
    const aliasLease = await jd(`${D}/v1/hypervisor/environments/${encodeURIComponent(alias)}/ops-lease`, { method: "POST", headers: ownerAuth, body: "{}" });
    const aliasBackup = await jd(`${D}/v1/hypervisor/environments/${encodeURIComponent(alias)}/backups`, { method: "POST", headers: ownerAuth, body: "{}" });
    ok("noncanonical aliases are refused consistently by both a capability minter and the managed-backup consumer without durable backup material",
      aliasLease.status === 400 && aliasBackup.status === 400
        && entryCount(path.join(dataDir, "hypervisor-environment-backups")) === aliasRecordsBefore,
      `lease=${aliasLease.status}/${errorCode(aliasLease)} backup=${aliasBackup.status}/${errorCode(aliasBackup)} records=${aliasRecordsBefore}->${entryCount(path.join(dataDir, "hypervisor-environment-backups"))}`);

    // ---------------------------------------------------------------- seven-handle owner boundary
    const envRecordPath = path.join(dataDir, "environments", `${safeId}.json`);
    const envBefore = fs.existsSync(envRecordPath) ? fs.readFileSync(envRecordPath) : Buffer.alloc(0);
    const crossGet = await jd(`${D}/v1/hypervisor/environments/${env}`, { headers: nonOwnerAuth });
    const crossStart = await jd(`${D}/v1/hypervisor/environments/${env}/start`, { method: "POST", headers: nonOwnerAuth, body: "{}" });
    const envAfter = fs.existsSync(envRecordPath) ? fs.readFileSync(envRecordPath) : Buffer.alloc(0);
    ok("HANDLE 1/7 — the environment id refuses same-tenant non-owner reads and lifecycle actions without changing its durable record",
      crossGet.status === 403 && crossStart.status === 403 && envBefore.equals(envAfter),
      `get=${crossGet.status} start=${crossStart.status} record_unchanged=${envBefore.equals(envAfter)}`);

    const terminalsBefore = entryCount(path.join(dataDir, "terminals"));
    const crossTerminal = await jd(`${D}/v1/hypervisor/terminals`, { method: "POST", headers: nonOwnerAuth,
      body: JSON.stringify({ environment_ref: `environment:${env}`, shell: "/bin/sh" }) });
    const terminalsAfter = entryCount(path.join(dataDir, "terminals"));
    ok("HANDLE 2/7 — the terminal id cannot be minted by a non-owner, and no PTY log appears",
      crossTerminal.status === 403 && terminalsAfter === terminalsBefore,
      `status=${crossTerminal.status} terminal_artifacts=${terminalsBefore}->${terminalsAfter}`);

    const workrunsBefore = entryCount(path.join(dataDir, "workruns")) + entryCount(path.join(dataDir, "workrun-workspaces"));
    const gitBefore = fs.existsSync(path.join(ws, ".git"));
    const crossWorkrun = await jd(`${D}/v1/hypervisor/workruns`, { method: "POST", headers: nonOwnerAuth,
      body: JSON.stringify({ environment_id: env, objective: "must not create a branch" }) });
    const workrunsAfter = entryCount(path.join(dataDir, "workruns")) + entryCount(path.join(dataDir, "workrun-workspaces"));
    const gitAfter = fs.existsSync(path.join(ws, ".git"));
    ok("HANDLE 5/7 — the workrun id cannot be minted by a non-owner, with no workrun record, worktree, or Git initialization side effect",
      crossWorkrun.status === 403 && workrunsAfter === workrunsBefore && gitAfter === gitBefore,
      `status=${crossWorkrun.status} artifacts=${workrunsBefore}->${workrunsAfter} git=${gitBefore}->${gitAfter}`);

    const conversationsBefore = entryCount(path.join(dataDir, "agentops-conversations"));
    const crossConversation = await jd(`${D}/v1/hypervisor/agentops/conversations`, { method: "POST", headers: nonOwnerAuth,
      body: JSON.stringify({ environment_id: env, title: "must not exist" }) });
    const conversationsAfter = entryCount(path.join(dataDir, "agentops-conversations"));
    ok("HANDLE 6/7 — the conversation id cannot be minted by a non-owner, and no conversation record appears",
      crossConversation.status === 403 && conversationsAfter === conversationsBefore,
      `status=${crossConversation.status} records=${conversationsBefore}->${conversationsAfter}`);

    const editorsBefore = entryCount(path.join(dataDir, "editor-services"));
    const crossEditor = await jd(`${D}/v1/hypervisor/editor-services`, { method: "POST", headers: nonOwnerAuth,
      body: JSON.stringify({ environment_id: env }) });
    const editorsAfter = entryCount(path.join(dataDir, "editor-services"));
    ok("HANDLE 7/7 — the editor-service id cannot be minted by a non-owner, and no service record appears",
      crossEditor.status === 403 && editorsAfter === editorsBefore,
      `status=${crossEditor.status} records=${editorsBefore}->${editorsAfter}`);

    const filesBefore = entryCount(ws);
    const crossFile = await jd(`${D}/v1/hypervisor/env-files`, { method: "POST", headers: nonOwnerAuth,
      body: JSON.stringify({ environment_id: env, op: "write", path: "nonowner-env-files.txt", content: "forbidden" }) });
    ok("the direct env-files handle also refuses the non-owner before any workspace write",
      crossFile.status === 403 && !fs.existsSync(path.join(ws, "nonowner-env-files.txt")) && entryCount(ws) === filesBefore,
      `status=${crossFile.status} file=${fs.existsSync(path.join(ws, "nonowner-env-files.txt"))}`);

    // ---------------------------------------------------------------- the port lease
    const portMint = await jd(`${D}/v1/hypervisor/environments/${env}/ports/8080/expose`, { method: "POST", headers: ownerAuth, body: "{}" });
    const portTok = portMint.j?.accessToken;
    ok("a port-forward lease still mints (it has a legitimate purpose — this gate does not forbid the lease, it forbids the lease driving env-ops)",
      portMint.status === 200 && !!portTok, `status=${portMint.status} token=${portTok ? portTok.slice(0, 16) + "…" : "NONE"}`);

    const portMarker = `port-lease-write-${safeId}.txt`;
    const wfPort = await jd(opsUrl(D, env, "WriteFile"), { method: "POST", headers: { authorization: `Bearer ${portTok}` }, body: JSON.stringify({ path: portMarker, content: B64("x") }) });
    const portWroteFile = fs.existsSync(path.join(ws, portMarker));
    ok("THE CHOKEPOINT — a port lease CANNOT WriteFile through the env-ops seam, PROVEN BY THE ABSENCE OF THE FILE, not by the status alone: its action is `environment.port`, and the seam requires `environment.ops`",
      wfPort.status !== 200 && !portWroteFile, `status=${wfPort.status} file_on_disk=${portWroteFile}`);

    const portExec = path.join(dataDir, `port-lease-exec-${safeId}`);
    const exPort = await jd(opsUrl(D, env, "Exec"), { method: "POST", headers: { authorization: `Bearer ${portTok}` }, body: JSON.stringify({ command: `touch ${portExec}` }) });
    ok("THE CHOKEPOINT — a port lease CANNOT Exec through the env-ops seam, PROVEN BY THE ABSENCE OF THE COMMAND'S SIDE EFFECT: no marker file was created",
      exPort.status !== 200 && !fs.existsSync(portExec), `status=${exPort.status} side_effect=${fs.existsSync(portExec)}`);

    // ---------------------------------------------------------------- the editor lease
    let editorTok = null;
    if (ownerAuth.authorization) {
      const em = await jd(`${D}/v1/hypervisor/editor-access-leases`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ environment_id: env, service_id: "eds_x" }) });
      editorTok = em.j?.lease_id ?? em.j?.grant?.grant_id;
    }
    const editorMarker = `editor-lease-write-${safeId}.txt`;
    const wfEditor = editorTok ? await jd(opsUrl(D, env, "WriteFile"), { method: "POST", headers: { authorization: `Bearer ${editorTok}` }, body: JSON.stringify({ path: editorMarker, content: B64("x") }) }) : { status: "no-lease" };
    const editorWroteFile = fs.existsSync(path.join(ws, editorMarker));
    ok("THE CHOKEPOINT — an `environment.editor.open` lease CANNOT WriteFile through the env-ops seam either, PROVEN BY THE ABSENCE OF THE FILE: the action check does not special-case one non-ops action, it requires the ops action",
      !!editorTok && wfEditor.status !== 200 && !editorWroteFile, `editorTok=${!!editorTok} status=${wfEditor.status} file_on_disk=${editorWroteFile}`);

    // ---------------------------------------------------------------- the positive control
    const opsMint = await jd(`${D}/v1/hypervisor/environments/${env}/ops-lease`, { method: "POST", headers: ownerAuth, body: "{}" });
    const opsTok = opsMint.j?.accessToken;
    const opsMarker = `ops-lease-write-${safeId}.txt`;
    const wfOps = opsTok ? await jd(opsUrl(D, env, "WriteFile"), { method: "POST", headers: { authorization: `Bearer ${opsTok}` }, body: JSON.stringify({ path: opsMarker, content: B64("legit") }) }) : { status: "no-lease" };
    const opsWroteFile = fs.existsSync(path.join(ws, opsMarker));
    ok("THE POSITIVE CONTROL — a legitimate `environment.ops` lease CAN WriteFile, so the chokepoint assertions above are refusing on the ACTION and not merely 401-ing every request",
      wfOps.status === 200 && opsWroteFile, `status=${wfOps.status} file_on_disk=${opsWroteFile}`);

    // ---------------------------------------------------------------- the minters resolve a caller
    const EXPOSED = { "x-forwarded-for": "203.0.113.9" };
    const opsExposed = await jd(`${D}/v1/hypervisor/environments/${env}/ops-lease`, { method: "POST", headers: EXPOSED, body: "{}" });
    ok("the OPS-LEASE MINTER refuses an exposed-untrusted surface (it used to hardcode the operator subject and mint for anyone); the refusal is a 401/403, not a minted token",
      opsExposed.status === 401 || opsExposed.status === 403, `status=${opsExposed.status} token=${opsExposed.j?.accessToken ?? "none"}`);
    const portExposed = await jd(`${D}/v1/hypervisor/environments/${env}/ports/8080/expose`, { method: "POST", headers: EXPOSED, body: "{}" });
    ok("the PORT-EXPOSE MINTER refuses an exposed-untrusted surface for the same reason",
      portExposed.status === 401 || portExposed.status === 403, `status=${portExposed.status} token=${portExposed.j?.accessToken ?? "none"}`);

    // ---------------------------------------------------------------- the EDITOR-EXPOSE seam, WIRED
    // The chokepoint above closes the `/supervisor/` env-ops consumer. The editor proxy is a SECOND
    // consumer of the workspace: `handle_editor_service_expose` used to gate only on a lease being
    // ACTIVE — action-blind and resource-blind — so a port lease, an ops lease, or an editor lease
    // for ANOTHER environment could bind a victim's IDE proxy. The pure predicate is unit-tested six
    // ways in Rust; THIS asserts the HANDLER actually calls it, because a refactor that drops the
    // call would leave those unit tests green while the hole reopens — the exact failure class this
    // run exists to end.
    //
    // The fixture is the product record shape: the service is CREATED through its real route, then
    // advanced to `ready` with an internal port — the one transition `editor_host` provisioning would
    // make once openvscode is installed, which the sandbox cannot do. The auth gate reads the
    // service's `environment_id` and the lease; it never consults the live runtime, so the auth
    // decision is identical whether openvscode is real or the record is advanced here.
    if (ownerAuth.authorization) {
      const created = await jd(`${D}/v1/hypervisor/editor-services`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ environment_id: env }) });
      const svcId = created.j?.editorService?.service_id ?? created.j?.service?.service_id ?? created.j?.service_id;
      const recPath = svcId ? path.join(dataDir, "editor-services", `${svcId}.json`) : null;
      if (recPath && fs.existsSync(recPath)) {
        const rec = JSON.parse(fs.readFileSync(recPath, "utf8"));
        const productShape = rec.schema_version === "ioi.hypervisor.editor-access-service.v1" && rec.environment_id === env;
        rec.phase = "ready";
        rec.internal_port = 59999; // no live runtime behind it; the auth gate does not read it
        fs.writeFileSync(recPath, JSON.stringify(rec));
        ok("the editor-service fixture is the PRODUCT RECORD SHAPE — created through its own route and advanced to `ready`, the transition provisioning makes; only phase+port moved, so the auth gate sees exactly what it sees in production",
          productShape, `schema=${rec.schema_version} env=${rec.environment_id}`);

        const editEal = await jd(`${D}/v1/hypervisor/editor-access-leases`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ environment_id: env, service_id: svcId }) });
        const editTok = editEal.j?.lease_id ?? editEal.j?.grant?.grant_id;
        const goodExpose = editTok ? await jd(`${D}/v1/hypervisor/editor-services/${svcId}/expose`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ lease_id: editTok }) }) : { status: "no-lease", j: {} };
        ok("THE POSITIVE CONTROL — a matching `environment.editor.open` lease naming this service DOES expose it, so the refusals below are on the action/resource and not a blanket denial",
          goodExpose.j?.ok !== false && goodExpose.status !== 403, `status=${goodExpose.status} ok=${goodExpose.j?.ok}`);

        const proxyPort = goodExpose.j?.public_proxy_port;
        const tokenlessProxy = proxyPort ? await jd(`http://127.0.0.1:${proxyPort}/`) : { status: "no-proxy" };
        const wrongTokenProxy = proxyPort ? await jd(`http://127.0.0.1:${proxyPort}/?lease=wrong`) : { status: "no-proxy" };
        const exactTokenProxy = proxyPort ? await jd(`http://127.0.0.1:${proxyPort}/?lease=${encodeURIComponent(editTok)}`) : { status: "no-proxy" };
        ok("the live editor proxy refuses absent and wrong tokens while the exact active token crosses the authority gate (then reaches the deliberately absent fixture runtime)",
          tokenlessProxy.status === 403 && wrongTokenProxy.status === 403 && exactTokenProxy.status === 502,
          `none=${tokenlessProxy.status} wrong=${wrongTokenProxy.status} exact=${exactTokenProxy.status}`);

        const portMint2 = await jd(`${D}/v1/hypervisor/environments/${env}/ports/9090/expose`, { method: "POST", headers: ownerAuth, body: "{}" });
        const portTok2 = portMint2.j?.accessToken;
        const portExpose = portTok2 ? await jd(`${D}/v1/hypervisor/editor-services/${svcId}/expose`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ lease_id: portTok2 }) }) : { status: "no-lease", j: {} };
        ok("THE WIRING — the editor-expose handler REFUSES a port lease (action `environment.port`), proving it calls the action/resource predicate and does not merely check the lease is active; a 403, not a bound proxy",
          portExpose.status === 403 && portExpose.j?.ok === false, `status=${portExpose.status} ok=${portExpose.j?.ok}`);

        // an editor lease for a DIFFERENT environment must not expose THIS service
        const otherCreated = await jd(`${D}/v1/hypervisor/environments`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ spec: {} }) });
        const otherEnv = otherCreated.j?.environment?.id;
        const otherEal = await jd(`${D}/v1/hypervisor/editor-access-leases`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ environment_id: otherEnv, service_id: "eds_other" }) });
        const otherTok = otherEal.j?.lease_id ?? otherEal.j?.grant?.grant_id;
        const crossExpose = otherTok ? await jd(`${D}/v1/hypervisor/editor-services/${svcId}/expose`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ lease_id: otherTok }) }) : { status: "no-lease", j: {} };
        ok("THE WIRING, cross-environment — an `environment.editor.open` lease minted for a DIFFERENT environment cannot expose this service; the resource check is on THIS service's environment",
          crossExpose.status === 403 && crossExpose.j?.ok === false, `status=${crossExpose.status} ok=${crossExpose.j?.ok}`);

        const revoked = await jd(`${D}/v1/hypervisor/editor-access-leases/${editTok}/revoke`, { method: "POST", headers: ownerAuth, body: "{}" });
        const revokedTokenProxy = proxyPort ? await jd(`http://127.0.0.1:${proxyPort}/?lease=${encodeURIComponent(editTok)}`) : { status: "no-proxy" };
        ok("the same live editor proxy refuses its exact token immediately after durable revocation",
          revoked.status === 200 && revoked.j?.ok === true && revokedTokenProxy.status === 403,
          `revoke=${revoked.status}/${revoked.j?.ok} proxy=${revokedTokenProxy.status}`);
      } else {
        ok("the editor-service fixture was created for the wiring assertions", false, `service_id=${svcId} recPath=${recPath}`);
      }
    }

    // ---------------------------------------------------------------- the owner boundary
    // The second principal is authenticated and belongs to the same tenant, but does not own this
    // environment. Refusal at the minter plus absence of a workspace side effect proves that the
    // substrate owner pin — not mere authentication or tenant membership — controls the lease.
    let ownerBoundaryClosed = false, ownerBoundaryDetail = "no non-owner session to test with";
    if (nonOwnerAuth.authorization) {
      const crossMint = await jd(`${D}/v1/hypervisor/environments/${env}/ops-lease`, { method: "POST", headers: nonOwnerAuth, body: "{}" });
      const crossTok = crossMint.j?.accessToken;
      const crossMarker = `nonowner-refused-${safeId}.txt`;
      const wfCross = crossTok ? await jd(opsUrl(D, env, "WriteFile"), { method: "POST", headers: { authorization: `Bearer ${crossTok}` }, body: JSON.stringify({ path: crossMarker, content: B64("must-not-write") }) }) : { status: "no-lease" };
      const crossWroteFile = fs.existsSync(path.join(ws, crossMarker));
      ownerBoundaryClosed = (crossMint.status === 401 || crossMint.status === 403) && !crossTok && !crossWroteFile;
      ownerBoundaryDetail = `authenticated non-owner mint status=${crossMint.status}, token=${!!crossTok}, env-ops write status=${wfCross.status}, wrote=${crossWroteFile}`;
    }
    ok("HANDLE 3/7 — an authenticated same-tenant NON-OWNER cannot mint an `environment.ops` lease for another principal's environment and cannot produce a workspace side effect",
      ownerBoundaryClosed, ownerBoundaryDetail);

    // ---------------------------------------------------------------- enumeration, legacy, and deprovisioned-owner disposal
    const memberCreated = await jd(`${D}/v1/hypervisor/environments`, { method: "POST", headers: nonOwnerAuth, body: JSON.stringify({ spec: {} }) });
    const memberEnv = memberCreated.j?.environment?.id;
    const adminList = await jd(`${D}/v1/hypervisor/environments`, { headers: ownerAuth });
    const memberList = await jd(`${D}/v1/hypervisor/environments`, { headers: nonOwnerAuth });
    const adminIds = (adminList.j?.environments ?? []).map((record) => record.id);
    const memberIds = (memberList.j?.environments ?? []).map((record) => record.id);
    const adminReadMember = await jd(`${D}/v1/hypervisor/environments/${memberEnv}`, { headers: ownerAuth });
    ok("environment enumeration is owner-scoped and organization-administrator status grants no read authority over a member-owned environment",
      memberCreated.status === 200 && adminList.status === 200 && memberList.status === 200
        && !adminIds.includes(memberEnv) && memberIds.includes(memberEnv) && adminReadMember.status === 403,
      `create=${memberCreated.status} admin_has=${adminIds.includes(memberEnv)} member_has=${memberIds.includes(memberEnv)} admin_get=${adminReadMember.status}`);

    const legacyId = `env_legacy_unadopted_${Date.now().toString(16)}`;
    const legacyPath = path.join(dataDir, "environments", `${legacyId}.json`);
    const legacyRecord = JSON.parse(fs.readFileSync(envRecordPath, "utf8"));
    legacyRecord.id = legacyId;
    legacyRecord.status.phase = "stopped";
    legacyRecord.status.desired_phase = "stopped";
    legacyRecord.status.workspace_root = null;
    legacyRecord.status.vm = null;
    legacyRecord.status.deleted = false;
    fs.writeFileSync(legacyPath, JSON.stringify(legacyRecord));
    const ordinaryLegacyDelete = await jd(`${D}/v1/hypervisor/environments/${legacyId}/delete`, { method: "POST", headers: nonOwnerAuth, body: "{}" });
    const adminLegacyGet = await jd(`${D}/v1/hypervisor/environments/${legacyId}`, { headers: ownerAuth });
    const legacyReceiptsBefore = entryCount(path.join(dataDir, "environment-disposal-receipts"));
    const adminLegacyDelete = await jd(`${D}/v1/hypervisor/environments/${legacyId}/delete`, { method: "POST", headers: ownerAuth, body: "{}" });
    const legacyReceiptsAfter = entryCount(path.join(dataDir, "environment-disposal-receipts"));
    const legacyDeleted = JSON.parse(fs.readFileSync(legacyPath, "utf8"));
    ok("a product-shape legacy environment without an immutable pin grants no ordinary or administrator read path, but an administrator may dispose it only with a durable legacy-unadopted receipt",
      ordinaryLegacyDelete.status === 403 && errorCode(ordinaryLegacyDelete) === "environment_unadopted"
        && adminLegacyGet.status === 403 && adminLegacyDelete.status === 200
        && legacyReceiptsAfter === legacyReceiptsBefore + 1
        && legacyDeleted.status?.phase === "deleted" && legacyDeleted.status?.deleted === true,
      `ordinary=${ordinaryLegacyDelete.status}/${errorCode(ordinaryLegacyDelete)} admin_get=${adminLegacyGet.status} delete=${adminLegacyDelete.status} receipts=${legacyReceiptsBefore}->${legacyReceiptsAfter} phase=${legacyDeleted.status?.phase}`);

    const deactivate = await jd(`${D}/v1/hypervisor/principals/${memberId}`, { method: "DELETE", headers: ownerAuth });
    const staleOwnerGet = await jd(`${D}/v1/hypervisor/environments/${memberEnv}`, { headers: nonOwnerAuth });
    const adminDeactivatedGet = await jd(`${D}/v1/hypervisor/environments/${memberEnv}`, { headers: ownerAuth });
    const adminDeactivatedFile = await jd(`${D}/v1/hypervisor/env-files`, { method: "POST", headers: ownerAuth,
      body: JSON.stringify({ environment_id: memberEnv, op: "read", path: "README.md" }) });
    const deactivatedReceiptsBefore = entryCount(path.join(dataDir, "environment-disposal-receipts"));
    const adminDeactivatedDelete = await jd(`${D}/v1/hypervisor/environments/${memberEnv}/delete`, { method: "POST", headers: ownerAuth, body: "{}" });
    const deactivatedReceiptsAfter = entryCount(path.join(dataDir, "environment-disposal-receipts"));
    const deactivatedRecord = JSON.parse(fs.readFileSync(path.join(dataDir, "environments", `${memberEnv}.json`), "utf8"));
    ok("deactivating an owner revokes its session and creates no administrator read path; the environment remains administrator-disposable with a durable receipt",
      deactivate.status === 200 && staleOwnerGet.status === 401 && adminDeactivatedGet.status === 403
        && adminDeactivatedFile.status === 403 && adminDeactivatedDelete.status === 200
        && deactivatedReceiptsAfter === deactivatedReceiptsBefore + 1
        && deactivatedRecord.status?.phase === "deleted" && deactivatedRecord.status?.deleted === true,
      `deactivate=${deactivate.status} stale=${staleOwnerGet.status} admin_get=${adminDeactivatedGet.status} file=${adminDeactivatedFile.status} delete=${adminDeactivatedDelete.status} receipts=${deactivatedReceiptsBefore}->${deactivatedReceiptsAfter}`);

    const fails = results.filter((r) => !r.pass);
    for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
    console.log(`\n${results.length - fails.length}/${results.length} passed`);
    emitVerifierCensus({ verifierId: "env-lease-authority", sourceUrl: import.meta.url, results });
    await Promise.all(markers.map(closeMarker));
    await plane.stop();
    process.exit(fails.length ? 1 : 0);
  } catch (error) {
    for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
    console.error(`FAIL env-lease-authority — ${error?.stack || error}`);
    await Promise.all(markers.map(closeMarker));
    await plane.stop();
    process.exit(1);
  }
}

const INVOKED = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED) run();
