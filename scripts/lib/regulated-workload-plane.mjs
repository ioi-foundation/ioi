// M09.9 PLANE — the regulated-workload assurance plane driven against a real isolated daemon.
//
// What only a live plane can show, and no schema or library can:
//
//  1. THE VERDICT IS THE PLANE'S. A caller POSTs a `profile_ref` and nothing else; the refusals come
//     back derived from what the ESTATE admitted. A caller-authored verdict is refused by its own
//     typed code, because the subject may not grade its own homework.
//  2. THE REFUSALS THAT NEED AN ADMITTED RECORD. A profile binding a pack the estate holds is clean
//     on that axis; one binding a pack nobody holds is `binding_missing`; one pinning a version the
//     admitted pack no longer carries is `binding_stale`. A contract can seal a profile — it cannot
//     know what the estate admitted.
//  3. THE NAMED ABSENCE IS REAL AND EXACTLY THREE. With the pack current, the only refusals about
//     owners are the three `binding_owner_absent` ones. If that count ever moves, either an owner
//     landed (good, and this leg says so) or a binding silently stopped being checked.
//  4. THE PLANE WRITES TO NEITHER OWNER IT READS. The pack store is byte-identical before and after
//     an evaluation, because a read model that writes is not a read model.
//  5. An unauthenticated caller is owed 401 and never an existence oracle.

import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { isIsolatedDaemonLogName, sanitizedVerifierBaseEnv, startIsolatedPlane } from "../../apps/hypervisor/scripts/lib/isolated-daemon.mjs";

const META = "docs/architecture/_meta/schemas";

function canonical(value) {
  if (value === null || typeof value !== "object") { const e = JSON.stringify(value); return e === undefined ? "" : e; }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}
const at = (value, p) => p.replace(/^\$\./u, "").split(".").reduce((acc, k) => (acc == null ? undefined : acc[k]), value);

/** The pack root is derived from the REGISTERED rule's own material_fields, so the leg cannot drift from it. */
function packRootOf(ROOT, record) {
  const rule = JSON.parse(readFileSync(join(ROOT, META, "invariants", "jurisdiction-policy-pack.v1.invariants.json"), "utf8"))
    .rules.find((r) => r.rule_id === "jurisdiction_policy_pack.root.recomputes");
  if (!rule) throw new Error("jurisdiction_policy_pack.root.recomputes is not registered");
  const material = {};
  for (const [field, d] of Object.entries(rule.expression.material_fields)) material[field] = at(record, d.path);
  return `sha256:${createHash("sha256").update(canonical(material)).digest("hex")}`;
}

async function call(base, method, path, body, headers = {}) {
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, base), { method, headers: { "content-type": "application/json", ...(payload === undefined ? {} : { "content-length": Buffer.byteLength(payload) }), ...headers } }, (response) => {
      const chunks = [];
      response.on("data", (c) => chunks.push(c));
      response.on("end", () => { clearTimeout(deadline); const raw = Buffer.concat(chunks).toString("utf8"); let parsed = {}; try { parsed = raw ? JSON.parse(raw) : {}; } catch { parsed = { raw }; } resolve({ status: response.statusCode, body: parsed }); });
    });
    const deadline = setTimeout(() => request.destroy(new Error(`HTTP timeout at ${method} ${path}`)), 120_000);
    request.on("error", (error) => { clearTimeout(deadline); reject(error); });
    if (payload !== undefined) request.write(payload);
    request.end();
  });
}

const codeOf = (reply) => String(reply.body?.error?.code ?? "");

/**
 * WHAT A REAL CALLER SENDS. `recorded_by_ref` is REQUIRED on an admitted record and ABSENT on the
 * wire — the plane resolves it from the caller's identity and refuses a caller-authored one. The
 * fixtures are admitted records, so they carry it; a POST must not.
 */
const asSent = (record) => { const { recorded_by_ref: _stamped, ...wire } = record; return wire; };

const reasonsFor = (rows, member) => rows.filter((r) => r.member === member).map((r) => r.reason);
const countDir = (dir) => { try { return readdirSync(dir).length; } catch { return -1; } };

export async function planeLeg({ ROOT }) {
  const started = Date.now();
  const findings = [];
  const observed = { admitted: {}, refusals: {}, derived: {}, writes: {}, identity: {} };
  const note = (what) => findings.push(what);
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m099-regulated-workload-"));
  let plane;
  try {
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env: {}, serve: false });
    if (!plane) return { blocked: true, findings: ["BLOCKED: build target/debug/hypervisor-daemon first"], seconds: 0, observed };
    const DAEMON = plane.daemonUrl;

    const log = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = log.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1];
    if (!token) return { blocked: true, findings: ["BLOCKED: the isolated daemon exposed no bootstrap token"], seconds: 0, observed };
    const boot = await call(DAEMON, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "m099-regulated-workload-password", email: "m099@ioi.local" });
    const session = boot.status === 200 && boot.body?.session_token;
    if (!session) return { blocked: true, findings: [`BLOCKED: operator bootstrap failed ${boot.status}`], seconds: 0, observed };
    const H = { authorization: `Bearer ${session}` };

    // ---- an admitted pack for the profile to bind ------------------------------------------------
    //
    // THE PACK IS SCOPED TO THE ORG THAT ISSUED IT, so its `issuer.issuer_ref` must be a tenant this
    // caller holds or M06.10's plane refuses the admission with a scope refusal — which is that
    // plane working correctly, and which this leg has to respect rather than route around. Rewriting
    // the issuer means re-sealing the pack, and the seal is taken from the REGISTERED invariant's own
    // material_fields so this leg cannot drift from the rule the contract checks.
    const whoami = await call(DAEMON, "GET", "/v1/hypervisor/auth/whoami", undefined, H);
    const tenants = whoami.body?.principal?.tenant_refs ?? [];
    observed.identity.tenant_refs = tenants;
    observed.identity.principal_ref = whoami.body?.principal?.principal_ref ?? whoami.body?.principal?.principal_id;
    const ISSUER = tenants.find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("domain://")))
      ?? tenants[0]
      ?? observed.identity.principal_ref;
    if (!ISSUER) {
      return { blocked: true, findings: [`BLOCKED: the bootstrap operator holds no tenant to issue a pack under (${JSON.stringify(whoami.body?.principal ?? {}).slice(0, 220)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }
    const packFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "jurisdiction-policy-pack-v1", "positive-eu-serious-incident.json"), "utf8"));
    packFixture.issuer = { ...packFixture.issuer, issuer_ref: ISSUER };
    packFixture.pack_root = packRootOf(ROOT, packFixture);
    const admittedPack = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-packs", asSent(packFixture), H);
    observed.admitted.pack = admittedPack.status;
    if (admittedPack.status !== 200) {
      return { blocked: true, findings: [`BLOCKED: the jurisdiction pack this leg binds did not admit (${admittedPack.status} ${JSON.stringify(admittedPack.body).slice(0, 220)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }

    // ---- the profile, bound to THAT pack at THAT version ------------------------------------------
    const LIB = await import("../../apps/hypervisor/scripts/lib/regulated-workload-assurance.mjs");
    const profileFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "regulated-workload-assurance-profile-v1", "positive-a-regulated-claims-workload.json"), "utf8"));
    // `policy_bindings` is merged rather than replaced. An earlier version of this leg did
    // `Object.assign(p, over)` first, which REPLACED the whole binding object with the one member a
    // case wanted to change and dropped the view ref with it — so the profile failed its contract,
    // the admission 422'd, and the case that followed reported an empty refusal list. The leg then
    // read as "the plane did not refuse" when nothing had ever been admitted to refuse.
    const buildProfile = (over = {}) => {
      const { policy_bindings: bindingOver, ...rest } = over;
      const p = JSON.parse(JSON.stringify(profileFixture));
      Object.assign(p, rest);
      p.policy_bindings = {
        ...profileFixture.policy_bindings,
        jurisdiction_policy_pack_ref: packFixture.pack_id,
        jurisdiction_policy_pack_version: packFixture.version,
        ...(bindingOver ?? {}),
      };
      p.profile_root = LIB.rootOf(p, LIB.PROFILE_MATERIAL);
      return p;
    };

    /** Admit a profile and REFUSE TO CONTINUE SILENTLY if it did not take. */
    const admitProfile = async (p, what) => {
      const reply = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-assurance-profiles", asSent(p), H);
      if (reply.status !== 200) {
        note(`${what}: the profile did not admit (${reply.status} ${JSON.stringify(reply.body).slice(0, 200)}), so what follows tests nothing`);
        return false;
      }
      return true;
    };

    const profile = buildProfile();
    const admitted = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-assurance-profiles", asSent(profile), H);
    observed.admitted.profile = admitted.status;
    if (admitted.status !== 200) {
      return { blocked: true, findings: [`BLOCKED: the profile did not admit (${admitted.status} ${JSON.stringify(admitted.body).slice(0, 300)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }

    // ---- the caller may not author the recorder ---------------------------------------------------
    const authoredRecorder = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-assurance-profiles",
      { ...asSent(buildProfile({ profile_id: "regulated_workload_assurance_profile://acme/authored-recorder/v1" })), recorded_by_ref: "principal://someone-else" }, H);
    observed.refusals.recorder_authored = codeOf(authoredRecorder);
    if (!codeOf(authoredRecorder).endsWith("recorder_authored")) {
      note(`a caller-authored recorder was not refused recorder_authored (${authoredRecorder.status} ${codeOf(authoredRecorder) || JSON.stringify(authoredRecorder.body).slice(0, 160)})`);
    }

    // ---- THE VERDICT IS THE PLANE'S ---------------------------------------------------------------
    const authoredVerdict = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-admission-cases",
      { profile_ref: profile.profile_id, verdict: "admitted", refusals: [] }, H);
    observed.refusals.verdict_authored = codeOf(authoredVerdict);
    if (!codeOf(authoredVerdict).endsWith("verdict_authored")) {
      note(`a caller-authored verdict was not refused verdict_authored (${authoredVerdict.status} ${codeOf(authoredVerdict) || JSON.stringify(authoredVerdict.body).slice(0, 160)})`);
    }

    const packDir = join(dataDir, "jurisdiction-policy-packs");
    const before = countDir(packDir);

    const derived = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-admission-cases", { profile_ref: profile.profile_id }, H);
    observed.admitted.case = derived.status;
    if (derived.status !== 200) {
      note(`the case did not derive over its own profile (${derived.status} ${JSON.stringify(derived.body).slice(0, 300)})`);
    } else {
      const record = derived.body.case ?? {};
      const rows = Array.isArray(record.refusals) ? record.refusals : [];
      observed.derived.verdict = record.verdict;
      observed.derived.reasons = rows.map((r) => `${r.reason}:${r.member}`);

      if (record.legal_conformity_claim !== "not_determined") note(`the derived case expressed a legal conformity claim (${record.legal_conformity_claim})`);
      if (record.performs_no_action !== true) note("the derived case does not disclaim acting on its subject");
      if (record.verdict !== "refused") note(`the derived verdict was ${record.verdict}; with three unresolved owners it can only be refused`);

      // THE PACK IS CURRENT, so nothing about it may be refused.
      const packReasons = [
        ...reasonsFor(rows, "policy_bindings.jurisdiction_policy_pack_ref"),
        ...reasonsFor(rows, "policy_bindings.jurisdiction_policy_pack_version"),
      ];
      if (packReasons.length !== 0) note(`the admitted pack was refused anyway (${packReasons.join(",")})`);

      // THE NAMED ABSENCE IS EXACTLY THREE.
      const absent = rows.filter((r) => r.reason === "binding_owner_absent");
      if (absent.length !== 3) note(`expected exactly three binding_owner_absent refusals, got ${absent.length} (${absent.map((r) => r.member).join(",")})`);
      for (const member of LIB.UNOWNED_MEMBERS) {
        if (!absent.some((r) => r.member === `unowned_bindings.${member}`)) note(`no owner-absent refusal named unowned_bindings.${member}`);
      }

      // The view was never admitted here, so it must be named missing rather than passed over.
      if (!reasonsFor(rows, "policy_bindings.policy_bound_data_view_ref").includes("binding_missing")) {
        note("a view the estate never admitted was not named binding_missing");
      }

      // THE CASE READS BACK IDENTICALLY, so the record served is the record stored.
      const fetched = await call(DAEMON, "GET", `/v1/hypervisor/regulated-workload-admission-cases/${encodeURIComponent(record.case_id)}`, undefined, H);
      if (JSON.stringify(fetched.body?.case) !== JSON.stringify(record)) note("the stored case is not the case the derivation returned");
    }

    observed.writes.pack_dir_before = before;
    observed.writes.pack_dir_after = countDir(packDir);
    if (observed.writes.pack_dir_before !== observed.writes.pack_dir_after) {
      note(`the plane wrote to the pack store it may only read (${before} -> ${observed.writes.pack_dir_after})`);
    }

    // ---- a pack nobody holds, and a version that moved ---------------------------------------------
    const orphan = buildProfile({
      profile_id: "regulated_workload_assurance_profile://acme/orphan-pack/v1",
      policy_bindings: { jurisdiction_policy_pack_ref: "jurisdiction_policy_pack://nobody/holds/v1" },
    });
    const orphanAdmitted = await admitProfile(orphan, "the orphan-pack profile");
    const orphanCase = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-admission-cases", { profile_ref: orphan.profile_id }, H);
    const orphanRows = orphanCase.body?.case?.refusals ?? [];
    observed.refusals.binding_missing = reasonsFor(orphanRows, "policy_bindings.jurisdiction_policy_pack_ref");
    if (orphanAdmitted && !reasonsFor(orphanRows, "policy_bindings.jurisdiction_policy_pack_ref").includes("binding_missing")) {
      note(`a profile binding a pack nobody holds was not refused binding_missing (${JSON.stringify(observed.refusals.binding_missing)})`);
    }

    const moved = buildProfile({
      profile_id: "regulated_workload_assurance_profile://acme/moved-version/v1",
      policy_bindings: { jurisdiction_policy_pack_version: "99.0.0" },
    });
    const movedAdmitted = await admitProfile(moved, "the moved-version profile");
    const movedCase = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-admission-cases", { profile_ref: moved.profile_id }, H);
    const movedRows = movedCase.body?.case?.refusals ?? [];
    observed.refusals.binding_stale = reasonsFor(movedRows, "policy_bindings.jurisdiction_policy_pack_version");
    if (movedAdmitted && !reasonsFor(movedRows, "policy_bindings.jurisdiction_policy_pack_version").includes("binding_stale")) {
      note(`a profile pinning a version the admitted pack no longer carries was not refused binding_stale (${JSON.stringify(observed.refusals.binding_stale)})`);
    }

    // ---- a profile nobody holds ---------------------------------------------------------------------
    const unadmitted = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-admission-cases", { profile_ref: "regulated_workload_assurance_profile://nobody/holds/v1" }, H);
    observed.refusals.profile_unadmitted = codeOf(unadmitted);
    if (!codeOf(unadmitted).endsWith("profile_unadmitted")) {
      note(`evaluating a profile nobody holds was not refused profile_unadmitted (${codeOf(unadmitted) || unadmitted.status})`);
    }

    // ---- re-admission is refused, because an edit is not a version ----------------------------------
    const again = await call(DAEMON, "POST", "/v1/hypervisor/regulated-workload-assurance-profiles", asSent(profile), H);
    observed.refusals.already_admitted = codeOf(again);
    if (!codeOf(again).endsWith("already_admitted")) {
      note(`re-admitting a different body at the same profile id was not refused already_admitted (${codeOf(again) || again.status})`);
    }

    // ---- the tenant line ------------------------------------------------------------------------------
    const anonymous = await call(DAEMON, "GET", `/v1/hypervisor/regulated-workload-assurance-profiles/${encodeURIComponent(profile.profile_id)}`);
    observed.identity = { anonymous_status: anonymous.status, anonymous_code: codeOf(anonymous) };
    if (anonymous.status === 200) note("an unauthenticated caller read the profile");
    if (anonymous.status === 404) note("an unauthenticated caller was answered with an existence oracle (404) rather than a scope refusal");

    return { findings, seconds: Math.round((Date.now() - started) / 1000), observed };
  } catch (error) {
    return { findings: [`the plane leg threw: ${error.message}`], seconds: Math.round((Date.now() - started) / 1000), observed };
  } finally {
    try { await plane?.stop?.(); } catch { /* the harness owns its own teardown */ }
    try { if (statSync(dataDir).isDirectory()) rmSync(dataDir, { recursive: true, force: true }); } catch { /* already gone */ }
  }
}
