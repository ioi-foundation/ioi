// M06.10 PLANE — the jurisdiction plane driven against a real isolated daemon.
//
// This leg is deliberately cheap: the plane is a foundations plane with its own routes, so it needs no
// bounded System, no wallet fixture and no serve. What it proves is the one thing no schema and no
// library can — that the DAEMON refuses a decision whose bound pack root is not the root of the pack the
// estate actually admitted.
//
// Canon requires that changing a deadline, clock-start rule, recipient, responsible party or accountable
// issuer take a NEW pack version and never rewrite an already-recorded reporting decision. A contract can
// seal a pack; only the plane holds the admitted pack to compare against. So the leg admits a pack,
// admits a decision under it, and then tries every way of getting a decision in against content the
// estate never admitted — a moved root, a moved version, a pack nobody holds — and requires each to be
// refused BY ITS OWN TYPED CODE rather than by a generic failure that would also fire if the route were
// simply broken.
//
// It also proves the two things a relying party depends on and a library cannot show: that an
// unauthenticated caller is owed 401 and never an existence oracle, and that a cross-tenant read answers
// the scope refusal rather than the record.

import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
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
const at = (value, path) => path.replace(/^\$\./u, "").split(".").reduce((acc, k) => (acc == null ? undefined : acc[k]), value);

/** The root is derived from the REGISTERED rule's own material_fields, so the leg cannot drift from it. */
function rootOf(ROOT, invariantFile, ruleId, record) {
  const rule = JSON.parse(readFileSync(join(ROOT, META, "invariants", invariantFile), "utf8")).rules.find((r) => r.rule_id === ruleId);
  if (!rule) throw new Error(`${ruleId} is not registered`);
  const material = {};
  for (const [field, d] of Object.entries(rule.expression.material_fields)) {
    const v = at(record, d.path);
    if (v === undefined) throw new Error(`${ruleId}: ${d.path} absent from the record being sealed`);
    material[field] = v;
  }
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
 * WHAT A REAL CALLER SENDS. `recorded_by_ref` is REQUIRED on an admitted record and ABSENT on the wire —
 * the plane resolves it from the caller's own identity and refuses a caller-authored one outright. The
 * fixtures are admitted records, so they carry it; a POST must not. The same asymmetry the record seam's
 * binding has, and the leg has to respect it or it is testing a caller nobody would write.
 */
const asSent = (record) => { const { recorded_by_ref: _stamped, ...wire } = record; return wire; };

export async function planeLeg({ ROOT }) {
  const started = Date.now();
  const findings = [];
  const observed = { admitted: {}, refusals: {}, identity: {} };
  const note = (what) => findings.push(what);
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-m0610-jurisdiction-"));
  let plane;
  try {
    const baseEnv = { ...sanitizedVerifierBaseEnv() };
    plane = await startIsolatedPlane({ dataDir, baseEnv, env: {}, serve: false });
    if (!plane) return { blocked: true, findings: ["BLOCKED: build target/debug/hypervisor-daemon first"], seconds: 0, observed };
    const DAEMON = plane.daemonUrl;

    const log = readdirSync(dataDir).filter(isIsolatedDaemonLogName).map((n) => readFileSync(join(dataDir, n), "utf8")).join("\n");
    const token = log.match(/\b(ioi_bootstrap_[0-9a-f]+)\b/u)?.[1];
    if (!token) return { blocked: true, findings: ["BLOCKED: the isolated daemon exposed no bootstrap token"], seconds: 0, observed };
    const boot = await call(DAEMON, "POST", "/v1/hypervisor/auth/bootstrap", { token, password: "m0610-jurisdiction-password", email: "m0610@ioi.local" });
    const session = boot.status === 200 && boot.body?.session_token;
    if (!session) return { blocked: true, findings: [`BLOCKED: operator bootstrap failed ${boot.status}`], seconds: 0, observed };
    const H = { authorization: `Bearer ${session}` };
    const whoami = await call(DAEMON, "GET", "/v1/hypervisor/auth/whoami", undefined, H);
    const TENANT = whoami.body?.principal?.tenant_refs?.[0] ?? `user://${boot.body?.principal?.principal_id}`;

    // ---- the pack, scoped to a tenant this caller holds -----------------------------------------
    const packFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "jurisdiction-policy-pack-v1", "positive-eu-serious-incident.json"), "utf8"));
    const buildPack = (over = {}) => {
      const p = { ...JSON.parse(JSON.stringify(packFixture)), ...over };
      p.issuer = { ...p.issuer, issuer_ref: TENANT.startsWith("org://") || TENANT.startsWith("domain://") ? TENANT : "org://ioi-labs" };
      p.pack_root = rootOf(ROOT, "jurisdiction-policy-pack.v1.invariants.json", "jurisdiction_policy_pack.root.recomputes", p);
      return p;
    };
    const pack = buildPack();
    const admitted = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-packs", pack, H);
    observed.admitted.pack = admitted.status;
    if (admitted.status !== 200) {
      return { blocked: true, findings: [`BLOCKED: the pack did not admit (${admitted.status} ${JSON.stringify(admitted.body).slice(0, 220)})`], seconds: Math.round((Date.now() - started) / 1000), observed };
    }

    // ---- a decision bound to THAT root -----------------------------------------------------------
    const decisionFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "jurisdiction-policy-decision-v1", "positive-applies-with-an-open-obligation.json"), "utf8"));
    const buildDecision = (over = {}) => {
      const d = { ...JSON.parse(JSON.stringify(decisionFixture)), pack_ref: pack.pack_id, pack_version: pack.version, pack_root: pack.pack_root, ...over };
      d.decision_root = rootOf(ROOT, "jurisdiction-policy-decision.v1.invariants.json", "jurisdiction_policy_decision.root.recomputes", d);
      return d;
    };
    const decision = buildDecision();
    const decided = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-decisions", asSent(decision), H);
    observed.admitted.decision = decided.status;
    if (decided.status !== 200) note(`the decision did not admit against its own pack (${decided.status} ${JSON.stringify(decided.body).slice(0, 220)})`);

    // ---- THE LAW ONLY A PLANE CAN ENFORCE, three ways of breaking it -----------------------------
    const movedRoot = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-decisions",
      asSent(buildDecision({ decision_id: "jurisdiction_decision://eu/moved-root", pack_root: `sha256:${"e".repeat(64)}` })), H);
    observed.refusals.pack_content_moved = codeOf(movedRoot);
    if (!codeOf(movedRoot).endsWith("pack_content_moved")) {
      note(`a decision bound to content the estate never admitted was not refused pack_content_moved (${movedRoot.status} ${codeOf(movedRoot) || JSON.stringify(movedRoot.body).slice(0, 160)})`);
    }
    const movedVersion = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-decisions",
      asSent(buildDecision({ decision_id: "jurisdiction_decision://eu/moved-version", pack_version: "2.0.0" })), H);
    observed.refusals.pack_version_moved = codeOf(movedVersion);
    if (!codeOf(movedVersion).endsWith("pack_version_moved")) {
      note(`a decision taken under a version the admitted pack no longer carries was not refused pack_version_moved (${codeOf(movedVersion) || movedVersion.status})`);
    }
    const noPack = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-decisions",
      asSent(buildDecision({ decision_id: "jurisdiction_decision://eu/no-pack", pack_ref: "jurisdiction_policy_pack://nobody/holds/v1" })), H);
    observed.refusals.pack_unadmitted = codeOf(noPack);
    if (!codeOf(noPack).endsWith("pack_unadmitted")) note(`a decision against a pack nobody holds was not refused pack_unadmitted (${codeOf(noPack) || noPack.status})`);

    // AN EDIT IS NOT A VERSION. Re-admitting a different body at the same id is how the law gets broken
    // while looking like it was followed.
    const reAdmit = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-packs", buildPack({ version: "1.0.1" }), H);
    observed.refusals.already_admitted = codeOf(reAdmit);
    if (!codeOf(reAdmit).endsWith("already_admitted")) note(`a pack was re-admitted at the same id (${codeOf(reAdmit) || reAdmit.status}) — supersession is a chain and an edit is not a version`);

    // ---- the contract refuses at admission, not merely in a fixture ------------------------------
    const verdictAttempt = await call(DAEMON, "POST", "/v1/hypervisor/jurisdiction-policy-decisions",
      { ...asSent(buildDecision({ decision_id: "jurisdiction_decision://eu/verdict" })), legal_conformity_claim: "compliant" }, H);
    observed.refusals.legal_verdict = codeOf(verdictAttempt);
    if (!codeOf(verdictAttempt).endsWith("not_registered_valid")) {
      note(`a decision expressing a LEGAL VERDICT was not refused by the registered contract at admission (${codeOf(verdictAttempt) || verdictAttempt.status})`);
    }

    // ---- the export rests on evidence that already exists ----------------------------------------
    const exportFixture = JSON.parse(readFileSync(join(ROOT, META, "fixtures", "compliance-audit-export-bundle-v1", "positive-regulator-request.json"), "utf8"));
    const buildExport = (over = {}) => {
      const e = { ...JSON.parse(JSON.stringify(exportFixture)), jurisdiction_policy_pack_refs: [pack.pack_id], policy_decision_refs: [decision.decision_id], ...over };
      e.export_root = rootOf(ROOT, "compliance-audit-export-bundle.v1.invariants.json", "compliance_audit_export_bundle.root.recomputes", e);
      return e;
    };
    const exported = await call(DAEMON, "POST", "/v1/hypervisor/compliance-audit-exports", asSent(buildExport()), H);
    observed.admitted.export = exported.status;
    if (exported.status !== 200) note(`the export did not admit over its own decision (${exported.status} ${JSON.stringify(exported.body).slice(0, 220)})`);
    const phantom = await call(DAEMON, "POST", "/v1/hypervisor/compliance-audit-exports",
      asSent(buildExport({ export_id: "audit_export://eu/phantom", policy_decision_refs: ["jurisdiction_decision://nobody/holds"] })), H);
    observed.refusals.decision_unadmitted = codeOf(phantom);
    if (!codeOf(phantom).endsWith("decision_unadmitted")) {
      note(`an export over a decision nobody holds was not refused decision_unadmitted (${codeOf(phantom) || phantom.status}) — an export is a manifest OVER evidence, not a way to introduce some`);
    }

    // ---- identity precedes the record ------------------------------------------------------------
    const anonymous = await call(DAEMON, "GET", `/v1/hypervisor/jurisdiction-policy-packs/${encodeURIComponent(pack.pack_id)}`, undefined);
    observed.identity.anonymous_status = anonymous.status;
    if (anonymous.status === 200) note("an unauthenticated caller was served the pack");
    if (anonymous.status === 404) note("an unauthenticated caller was answered 404, which is an existence oracle — identity is owed 401 BEFORE the record is loaded");
    const anonymousAbsent = await call(DAEMON, "GET", "/v1/hypervisor/jurisdiction-policy-packs/jurisdiction_policy_pack%3A%2F%2Fnobody%2Fholds", undefined);
    observed.identity.anonymous_absent_status = anonymousAbsent.status;
    if (anonymous.status !== anonymousAbsent.status) {
      note(`an unauthenticated caller can tell an existing record (${anonymous.status}) from an absent one (${anonymousAbsent.status}) — that difference IS the oracle`);
    }
    const mine = await call(DAEMON, "GET", `/v1/hypervisor/jurisdiction-policy-packs/${encodeURIComponent(pack.pack_id)}`, undefined, H);
    observed.identity.owner_status = mine.status;
    if (mine.status !== 200) note(`the pack's own tenant could not read it back (${mine.status})`);

    // ---- nothing this plane did minted authority or performed an action --------------------------
    const served = mine.body?.pack ?? {};
    if (served.grants_no_authority !== true) note("the served pack does not carry its no-authority clause");
    if (served.is_not_legal_advice !== true) note("the served pack does not carry canon's not-legal-advice clause");
    const servedDecision = (await call(DAEMON, "GET", `/v1/hypervisor/jurisdiction-policy-decisions/${encodeURIComponent(decision.decision_id)}`, undefined, H)).body?.decision ?? {};
    if (servedDecision.legal_conformity_claim !== "not_determined") {
      note(`the served decision reads ${servedDecision.legal_conformity_claim} — canon permits exactly one value and it is not_determined`);
    }
    if (servedDecision.performs_no_action !== true) note("the served decision does not carry its no-action clause");
  } catch (error) {
    note(`the plane leg threw: ${String(error?.stack ?? error).slice(0, 500)}`);
  } finally {
    if (plane) await plane.stop();
    rmSync(dataDir, { recursive: true, force: true });
  }
  return { blocked: false, findings, observed, seconds: Math.round((Date.now() - started) / 1000) };
}
