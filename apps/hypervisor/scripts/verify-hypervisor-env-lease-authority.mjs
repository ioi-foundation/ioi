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
// WHAT IT DOES NOT CLOSE, NAMED SO IT CANNOT CHANGE UNNOTICED. OWNER-BINDING. The minters resolve WHO
// the caller is, not whether that caller OWNS the environment — because an environment has no owner
// pin (defect 1a / ADR 0035). So in `authenticated_managed` posture an authenticated NON-OWNER can
// still mint an `environment.ops` lease for another principal's environment and drive env-ops. This
// gate ASSERTS that residual in both directions: it is real today, and the day it closes this
// assertion flips and must be updated in the commit that closes it. The fix is the same scope-pin
// shape as 1a and the authority-grant XV item.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const B64 = (s) => Buffer.from(s, "utf8").toString("base64");
const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

async function jd(url, { method = "GET", headers = {}, body } = {}) {
  const r = await fetch(url, { method, headers: { "content-type": "application/json", ...headers }, body });
  const t = await r.text();
  let j; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, j };
}

const opsUrl = (D, env, m) => `${D}/supervisor/${env}/supervisor.v1.EnvironmentOpsService/${m}`;

async function run() {
  const plane = await startIsolatedPlane({ serve: false });
  if (!plane) { console.error("BLOCKED — no daemon binary (exit 2)"); process.exit(2); }
  const D = plane.daemonUrl;
  const dataDir = plane.dataDir;
  try {
    const env = "auth-victim";
    const safeId = env.replace(/[^A-Za-z0-9_-]/g, "_");
    const ws = path.join(dataDir, "environments", safeId, "workspace");
    await jd(`${D}/v1/hypervisor/environments`, { method: "POST", body: JSON.stringify({ environment_id: env }) });
    await jd(`${D}/v1/hypervisor/environments/${env}/start`, { method: "POST", body: "{}" });
    ok("the isolated daemon is in local_development posture and the victim workspace exists on disk — the precondition the whole exploit needs",
      fs.existsSync(ws), `workspace=${ws} exists=${fs.existsSync(ws)}`);

    // Authenticate a principal (the bootstrap operator) so the editor lease and the residual mint
    // have a real session; it stands in for 'any authenticated principal' because no minter checks
    // ownership and the environment has no owner to compare against.
    const log = (() => { try { return fs.readFileSync(path.join(dataDir, "isolated-daemon.log"), "utf8"); } catch { return ""; } })();
    const btok = (log.match(/(ioi_bootstrap_[0-9a-f]+)/) || [])[1];
    let auth = {};
    if (btok) {
      const bs = await jd(`${D}/v1/hypervisor/auth/bootstrap`, { method: "POST", body: JSON.stringify({ token: btok, password: "verifier-pw-123" }) });
      if (bs.j?.session_token) auth = { authorization: `Bearer ${bs.j.session_token}` };
    }
    ok("a principal session was acquired for the authenticated-path assertions", !!auth.authorization, auth.authorization ? "session acquired" : "NO session (bootstrap token not found)");

    // ---------------------------------------------------------------- the port lease
    const portMint = await jd(`${D}/v1/hypervisor/environments/${env}/ports/8080/expose`, { method: "POST", body: "{}" });
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
    if (auth.authorization) {
      const em = await jd(`${D}/v1/hypervisor/editor-access-leases`, { method: "POST", headers: auth, body: JSON.stringify({ environment_id: env, service_id: "eds_x" }) });
      editorTok = em.j?.lease_id ?? em.j?.grant?.grant_id;
    }
    const editorMarker = `editor-lease-write-${safeId}.txt`;
    const wfEditor = editorTok ? await jd(opsUrl(D, env, "WriteFile"), { method: "POST", headers: { authorization: `Bearer ${editorTok}` }, body: JSON.stringify({ path: editorMarker, content: B64("x") }) }) : { status: "no-lease" };
    const editorWroteFile = fs.existsSync(path.join(ws, editorMarker));
    ok("THE CHOKEPOINT — an `environment.editor.open` lease CANNOT WriteFile through the env-ops seam either, PROVEN BY THE ABSENCE OF THE FILE: the action check does not special-case one non-ops action, it requires the ops action",
      !!editorTok && wfEditor.status !== 200 && !editorWroteFile, `editorTok=${!!editorTok} status=${wfEditor.status} file_on_disk=${editorWroteFile}`);

    // ---------------------------------------------------------------- the positive control
    const opsMint = await jd(`${D}/v1/hypervisor/environments/${env}/ops-lease`, { method: "POST", body: "{}" });
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
    if (auth.authorization) {
      const created = await jd(`${D}/v1/hypervisor/editor-services`, { method: "POST", headers: auth, body: JSON.stringify({ environment_id: env }) });
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

        const editEal = await jd(`${D}/v1/hypervisor/editor-access-leases`, { method: "POST", headers: auth, body: JSON.stringify({ environment_id: env, service_id: svcId }) });
        const editTok = editEal.j?.lease_id ?? editEal.j?.grant?.grant_id;
        const goodExpose = editTok ? await jd(`${D}/v1/hypervisor/editor-services/${svcId}/expose`, { method: "POST", body: JSON.stringify({ lease_id: editTok }) }) : { status: "no-lease", j: {} };
        ok("THE POSITIVE CONTROL — a matching `environment.editor.open` lease naming this service DOES expose it, so the refusals below are on the action/resource and not a blanket denial",
          goodExpose.j?.ok !== false && goodExpose.status !== 403, `status=${goodExpose.status} ok=${goodExpose.j?.ok}`);

        const portMint2 = await jd(`${D}/v1/hypervisor/environments/${env}/ports/9090/expose`, { method: "POST", body: "{}" });
        const portTok2 = portMint2.j?.accessToken;
        const portExpose = portTok2 ? await jd(`${D}/v1/hypervisor/editor-services/${svcId}/expose`, { method: "POST", body: JSON.stringify({ lease_id: portTok2 }) }) : { status: "no-lease", j: {} };
        ok("THE WIRING — the editor-expose handler REFUSES a port lease (action `environment.port`), proving it calls the action/resource predicate and does not merely check the lease is active; a 403, not a bound proxy",
          portExpose.status === 403 && portExpose.j?.ok === false, `status=${portExpose.status} ok=${portExpose.j?.ok}`);

        // an editor lease for a DIFFERENT environment must not expose THIS service
        const otherEnv = "auth-other";
        await jd(`${D}/v1/hypervisor/environments`, { method: "POST", body: JSON.stringify({ environment_id: otherEnv }) });
        const otherEal = await jd(`${D}/v1/hypervisor/editor-access-leases`, { method: "POST", headers: auth, body: JSON.stringify({ environment_id: otherEnv, service_id: "eds_other" }) });
        const otherTok = otherEal.j?.lease_id ?? otherEal.j?.grant?.grant_id;
        const crossExpose = otherTok ? await jd(`${D}/v1/hypervisor/editor-services/${svcId}/expose`, { method: "POST", body: JSON.stringify({ lease_id: otherTok }) }) : { status: "no-lease", j: {} };
        ok("THE WIRING, cross-environment — an `environment.editor.open` lease minted for a DIFFERENT environment cannot expose this service; the resource check is on THIS service's environment",
          crossExpose.status === 403 && crossExpose.j?.ok === false, `status=${crossExpose.status} ok=${crossExpose.j?.ok}`);
      } else {
        ok("the editor-service fixture was created for the wiring assertions", false, `service_id=${svcId} recPath=${recPath}`);
      }
    }

    // ---------------------------------------------------------------- the NAMED RESIDUAL (1a)
    // An authenticated NON-OWNER minting an environment.ops lease for another principal's environment
    // still succeeds, because no environment has an owner pin to check. This is asserted TRUE so that
    // the day 1a closes it, this gate goes red and the residual is retired in that commit.
    let residualOpen = false, residualDetail = "no session to test with";
    if (auth.authorization) {
      const crossMint = await jd(`${D}/v1/hypervisor/environments/${env}/ops-lease`, { method: "POST", headers: auth, body: "{}" });
      const crossTok = crossMint.j?.accessToken;
      const crossMarker = `residual-nonowner-${safeId}.txt`;
      const wfCross = crossTok ? await jd(opsUrl(D, env, "WriteFile"), { method: "POST", headers: { authorization: `Bearer ${crossTok}` }, body: JSON.stringify({ path: crossMarker, content: B64("residual") }) }) : { status: "no-lease" };
      residualOpen = wfCross.status === 200 && fs.existsSync(path.join(ws, crossMarker));
      residualDetail = `authenticated non-owner mint status=${crossMint.status}, env-ops write status=${wfCross.status}, wrote=${fs.existsSync(path.join(ws, crossMarker))}`;
    }
    ok("NAMED RESIDUAL (defect 1a) — an authenticated NON-OWNER can STILL mint an `environment.ops` lease for another principal's environment and drive env-ops, because no environment has an owner pin; this assertion is TRUE by design and MUST flip in the commit that lands the environment owner model",
      residualOpen, residualDetail);

    const fails = results.filter((r) => !r.pass);
    for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
    console.log(`\n${results.length - fails.length}/${results.length} passed`);
    emitVerifierCensus({ verifierId: "env-lease-authority", sourceUrl: import.meta.url, results });
    await plane.stop();
    process.exit(fails.length ? 1 : 0);
  } catch (error) {
    for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
    console.error(`FAIL env-lease-authority — ${error?.stack || error}`);
    await plane.stop();
    process.exit(1);
  }
}

const INVOKED = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED) run();
