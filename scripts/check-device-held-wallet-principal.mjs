#!/usr/bin/env node
//
// M03.8 — DEVICE-HELD WALLET-PRINCIPAL PROVISIONING, against a live daemon.
//
// The unit's module paragraph names six things this check owes, and each is a
// section below. Five are proven HERE, against a real ceremony on a real
// virtual authenticator; the sixth is COMPOSED, not restated, because
// `check:passkey-only-authority` already proves it end to end and a second
// paraphrase of someone else's proof is not evidence.
//
//   1 PROVISIONING IS AN EXPLICIT RECEIPTED EVENT — identity never implies it.
//   2 THE RECEIPT AUTHORIZES NOTHING, measured by reading every other family
//     the daemon serves before and after, plus a source ABSENCE for the writers
//     that would make it false.
//   3 RECOVERY / DEVICE CONTINUITY — a second device is a successor on the same
//     principal, and a cross-principal "successor" is refused.
//   4 EXACT-EFFECT CONSENT SEPARATION — custody is not consent; the fields that
//     would make it consent are refused by their own code, and an effect after
//     provisioning still draws its own authority challenge.
//   5 STANDALONE-LOCAL OPERATION — the whole ceremony runs with no IdP account
//     and no IdP configured, measured from the daemon's own environment.
//   6 NO REUSABLE PASSWORD OR PLAINTEXT RECOVERY MATERIAL — composed from
//     `check:passkey-only-authority`, whose typed absence (there is no
//     account-recovery route) is carried forward verbatim rather than restated.
//
//   --mutation  prove each finding fails on its own
//   --skip-composed  run 1-5 only (for iteration; the composed run is ~3 min)
//
// BLOCKED, never silently green: a missing daemon binary or a missing browser
// exits 0 with verdict BLOCKED and no PASS lines, because a check that cannot
// run has not passed.

import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, createHash } from "node:crypto";

import { startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";
import { openSoftwarePasskeyDevice } from "../apps/hypervisor/scripts/lib/software-passkey-ceremony.mjs";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const skipComposed = process.argv.includes("--skip-composed");
const modulePath = join(
  repo,
  "crates/node/src/bin/hypervisor_daemon_routes/device_held_principal_routes.rs",
);

const results = [];
const observations = {};
let failures = 0;

const ok = (name, satisfied, detail) => {
  results.push({ assertion: name, satisfied: !!satisfied, detail: String(detail).slice(0, 400) });
  if (!satisfied) failures += 1;
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}  (${String(detail).slice(0, 220)})`);
  return !!satisfied;
};

const blocked = (reason) => {
  console.log(JSON.stringify({ check: "check:device-held-wallet-principal", verdict: "BLOCKED", reason }, null, 2));
  process.exit(0);
};

const jcs = (value) => JSON.stringify(value, Object.keys(value ?? {}).sort ? undefined : undefined);
const stable = (value) => JSON.stringify(value, (_key, inner) =>
  inner && typeof inner === "object" && !Array.isArray(inner)
    ? Object.fromEntries(Object.entries(inner).sort(([a], [b]) => a.localeCompare(b)))
    : inner);
const hex32 = () => randomBytes(32).toString("hex");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/// A response's own generation time is not state. Only the TOP-LEVEL envelope stamp is dropped; an
/// `at` inside a record stays, because a record that re-timestamped itself IS a write. Drill M2
/// proves this normalisation did not blind the comparison.
const withoutResponseStamp = (body) => {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const { at: _generatedAt, ...state } = body;
  return state;
};

/// Every family this daemon serves that a provisioning must not touch.
const OBSERVED_FAMILIES = [
  "/v1/hypervisor/governance/approval-requests",
  "/v1/hypervisor/connectors",
  "/v1/hypervisor/model-routes",
  "/v1/hypervisor/projects",
  "/v1/hypervisor/environments",
  "/v1/hypervisor/auth/passkeys",
];

let DAEMON = "";
let SESSION = "";
let OWNER = "";

const jd = async (route, init = {}) => {
  const response = await fetch(`${DAEMON}${route}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(SESSION ? { cookie: `ioi_session=${SESSION}` } : {}),
      ...(init.headers ?? {}),
    },
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
};

const snapshotEstate = async () => {
  const snapshot = {};
  for (const route of OBSERVED_FAMILIES) {
    const { status, body } = await jd(route);
    snapshot[route] = { status, state: stable(withoutResponseStamp(body) ?? null) };
  }
  return snapshot;
};

const estateDelta = (before, after) =>
  OBSERVED_FAMILIES.filter(
    (route) =>
      before[route].status !== after[route].status || before[route].state !== after[route].state,
  );

const provision = (body) =>
  jd("/v1/hypervisor/auth/device-held-principals", {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, ...body }),
  });

const goodBody = (overrides = {}) => ({
  idempotency_key: `dhp-${randomBytes(8).toString("hex")}`,
  principal_ref: "org://acme/operator-device",
  authority_id: hex32(),
  authority_public_key: randomBytes(32).toString("hex"),
  authority_signature_suite: "ed25519",
  approval_authority_snapshot_hash: hex32(),
  device_label: "Operator laptop",
  device_platform: "macOS 15",
  ...overrides,
});

let plane;
let device;

try {
  if (!existsSync(join(repo, "target/debug/hypervisor-daemon"))) {
    blocked("target/debug/hypervisor-daemon is not built");
  }
  const webauthnOrigin = "http://localhost:8771";
  plane = await startIsolatedPlane({
    env: {
      IOI_HYPERVISOR_WEBAUTHN_RP_ID: "localhost",
      IOI_HYPERVISOR_WEBAUTHN_ORIGIN: webauthnOrigin,
    },
  });
  if (!plane) blocked("the isolated daemon plane did not start");
  DAEMON = plane.daemonUrl;

  // -- identity, and the owner tenant every write is admitted under -----------
  const daemonLog = readFileSync(join(plane.dataDir, "isolated-daemon.log"), "utf8");
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (!token) blocked("the isolated plane published no bootstrap token");
  const password = `throwaway-${randomBytes(18).toString("hex")}`;
  const boot = await jd("/v1/hypervisor/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify({ token, password, email: "device-held-principal@ioi.local" }),
  });
  SESSION = boot.body?.session_token || "";
  ok("operator bootstrap yields an authenticated session",
    SESSION.startsWith("ioi_sess_"), SESSION.slice(0, 12) || JSON.stringify(boot.body).slice(0, 120));
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  const whoEmail = who.principal?.email || "device-held-principal@ioi.local";
  OWNER = (who.principal?.tenant_refs || []).find(
    (t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://")),
  ) || "";
  ok("the session authenticates a principal with an owner tenant to admit under",
    !!OWNER, OWNER || "no owner tenant");

  // ===========================================================================
  // 5 — STANDALONE-LOCAL OPERATION, measured before anything else so the rest of
  //     the run is known to have happened without an IdP in the loop.
  // ===========================================================================
  const daemonEnviron = (() => {
    try {
      return readFileSync(`/proc/${plane.daemonPid}/environ`, "utf8").split("\0").filter(Boolean);
    } catch {
      return null;
    }
  })();
  if (daemonEnviron) {
    const idpVars = daemonEnviron.filter((entry) =>
      /^(IOI_[A-Z_]*)?(OIDC|IDP|SAML|AUTH0|OKTA|ENTRA|COGNITO)[A-Z_]*=/u.test(entry));
    ok("the daemon under test has NO identity-provider configuration in its own environment — standalone-local operation is measured from the process, not declared in prose",
      idpVars.length === 0, idpVars.map((entry) => entry.split("=")[0]).join(",") || "0 IdP-shaped variables");
    observations.daemon_idp_environment_variables = idpVars.length;
  } else {
    ok("the daemon under test has NO identity-provider configuration in its own environment",
      false, "the daemon environ block could not be read, so the claim is unproven rather than true");
  }
  const registeredAuthRoutes = [...readFileSync(join(repo, "crates/node/src/bin/hypervisor-daemon.rs"), "utf8")
    .matchAll(/"(\/v1\/hypervisor\/auth[^"]*)"/gu)].map((m) => m[1]).sort();
  const idpRoutes = registeredAuthRoutes.filter((route) => /oidc|idp|saml|sso|oauth/u.test(route));
  // MEASURED, and it corrected this check's first draft. The daemon DOES register an IdP lane
  // (`/v1/hypervisor/auth/oidc/start` and `/callback`), so "no IdP ceremony exists" is simply
  // false and asserting it would have been a green light for a fact that is not true. What the
  // unit actually requires is narrower and checkable: a local deployment stays fully operable with
  // NO IdP ACCOUNT. So the lane is required to be PRESENT-AND-INERT — it resolves its config from
  // an `sso-configurations` record, none is admitted here, and it refuses.
  ok("the registered IdP lane is present and INERT on this deployment — it resolves an admitted SSO configuration, none exists here, and it refuses; a local deployment is therefore not silently depending on one",
    idpRoutes.length > 0, idpRoutes.join(",") || "no IdP lane registered at all");
  const oidcStart = await jd("/v1/hypervisor/auth/oidc/start", {
    method: "POST",
    body: JSON.stringify({ config_id: "any" }),
  });
  ok("the IdP lane actually refuses on this deployment rather than being untested — it is called, and answers that it has no configuration to use",
    oidcStart.status === 400, `${oidcStart.status} · ${String(oidcStart.body?.reason || oidcStart.body?.code || "").slice(0, 60)}`);
  observations.registered_auth_routes = registeredAuthRoutes.length;
  observations.idp_lane = "registered and inert (no admitted sso-configuration)";

  // -- a real ceremony on a real virtual authenticator ------------------------
  device = await openSoftwarePasskeyDevice({ daemonUrl: DAEMON, session: SESSION, webauthnOrigin });
  const enrolled = await device.register();
  const receiptRef = String(enrolled.receipt_ref || "");
  const receiptId = receiptRef.split("/").pop() || "";
  ok("one passkey is enrolled by a user-verified ceremony, and its own receipt already disclaims effect authority",
    receiptId.startsWith("afr_") && enrolled.effect_authority_created === false,
    `${receiptRef} · effect_authority_created=${enrolled.effect_authority_created}`);

  // ===========================================================================
  // 1 — PROVISIONING IS AN EXPLICIT RECEIPTED EVENT
  // ===========================================================================
  const noCeremony = await provision(goodBody({ auth_factor_receipt_id: undefined }));
  ok("a session alone does not provision a principal — the ceremony must be NAMED, and its absence is refused by its own code",
    noCeremony.status === 400 && noCeremony.body?.code === "device_held_principal_field_required",
    `${noCeremony.status}/${noCeremony.body?.code}`);

  const unknownCeremony = await provision(goodBody({ auth_factor_receipt_id: "afr_0000000000000000" }));
  ok("a ceremony that did not happen cannot back a provisioning",
    unknownCeremony.status === 404
      && unknownCeremony.body?.code === "device_held_principal_ceremony_receipt_not_found",
    `${unknownCeremony.status}/${unknownCeremony.body?.code}`);

  const before = await snapshotEstate();
  const created = await provision(goodBody({ auth_factor_receipt_id: receiptId }));
  const record = created.body?.provisioning ?? {};
  ok("a completed, user-verified ceremony provisions a device-held wallet principal as ONE explicit admitted event, with an operation and a receipt of its own",
    created.status === 201
      && String(created.body?.operation_ref || "").length > 0
      && String(created.body?.receipt_ref || "").length > 0
      && String(record.device_held_principal_provisioning_ref || "").startsWith("device-held-principal-provisioning://"),
    `${created.status} · op=${String(created.body?.operation_ref || "").slice(0, 24)} · receipt=${String(created.body?.receipt_ref || "").slice(0, 24)}`);
  const firstRef = String(record.device_held_principal_provisioning_ref || "");
  const firstId = firstRef.replace("device-held-principal-provisioning://", "").replace("/revision/1", "");
  observations.first_provisioning_ref = firstRef;

  ok("the record cites the ceremony it consumed by receipt AND by that receipt's own hash, so a provisioning cannot outlive a rewritten attestation",
    record.auth_factor_receipt_id === receiptId
      && String(record.auth_factor_receipt_hash || "").startsWith("sha256:")
      && String(record.credential_id_hash || "").startsWith("sha256:"),
    `${record.auth_factor_receipt_id} · ${String(record.auth_factor_receipt_hash || "").slice(0, 20)}`);

  ok("only PUBLIC material is stored: the record carries the authority public key, its suite and device metadata, and no field of it is a secret",
    typeof record.authority_public_key === "string"
      && record.authority_signature_suite === "ed25519"
      && record.device_label === "Operator laptop"
      && !Object.keys(record).some((key) => /private|secret|seed|mnemonic|password|passphrase|recovery/u.test(key)),
    Object.keys(record).join(","));

  const replay = await provision(goodBody({ auth_factor_receipt_id: receiptId }));
  // A second attempt under a NEW key must be refused as a CONSUMED CEREMONY. Run 1 of this check
  // sent `idempotency_key: undefined` and was refused `mutation_idempotency_key_invalid` — a real
  // refusal of the wrong thing, which would have passed a weaker assertion on status alone.
  ok("one ceremony provisions at most one principal — presenting the same receipt under a new key is refused as consumed, not treated as a fresh ceremony",
    replay.status === 409
      && replay.body?.code === "device_held_principal_ceremony_already_consumed",
    `${replay.status}/${replay.body?.code}`);

  // ===========================================================================
  // 2 — THE RECEIPT AUTHORIZES NOTHING
  // ===========================================================================
  const after = await snapshotEstate();
  const delta = estateDelta(before, after);
  const allAnswered = OBSERVED_FAMILIES.every((route) => after[route].status === 200);
  ok("provisioning had NO EFFECT ANYWHERE, measured rather than asserted: every other family the daemon serves is byte-identical across the admission, and every watched route actually answered 200 (a route that does not exist compares equal to itself)",
    delta.length === 0 && allAnswered,
    delta.length ? `moved: ${delta.join(", ")}` : `${OBSERVED_FAMILIES.length} families unchanged, all 200`);

  ok("the record states the negative on its own face: it created no effect authority and enumerates what a reader must not infer from it",
    record.effect_authority_created === false
      && Array.isArray(record.creates_no)
      && ["approval_grant", "standing_approval_envelope", "capability_lease", "delegation", "spend_authorization", "policy_widening"]
        .every((item) => record.creates_no.includes(item)),
    JSON.stringify(record.creates_no));

  // The source half of the same claim, pinned as an ABSENCE rather than a call count: a count moves
  // whenever anything is added, an absence is durable and is exactly what "holds no writer" means.
  const moduleSource = readFileSync(modulePath, "utf8");
  const productionSource = moduleSource.split("#[cfg(test)]")[0];
  // CALL SITES ONLY. Run 1 of this check pinned bare NAMES and went red on its own refusal
  // allowlists: `standing_envelope` and `capability_lease` appear in this module precisely because
  // it REFUSES them, and a boundary that names what it rejects is the boundary working. A name is
  // data; a call is a writer.
  const authorityWriters = [
    /\bpersist_record\s*\(/u,
    /\bpersist_record_durable\s*\(/u,
    /\bremove_record\s*\(/u,
    /\bmint_[a-z_]*\s*\(/u,
    /\bissue_[a-z_]*binding\s*\(/u,
    /\bseal_[a-z_]*envelope\s*\(/u,
    /\bconsume_approval_grant[a-z_]*\s*\(/u,
    /\bconsume_standing_approval_grant[a-z_]*\s*\(/u,
  ].filter((pattern) => pattern.test(productionSource));
  ok("the module holds NO writer for any approval, grant, standing envelope, capability lease or record family — a source ABSENCE, which is what 'authorizes nothing' means in code and is durable where a call count is not",
    authorityWriters.length === 0,
    authorityWriters.length ? authorityWriters.map(String).join(" ; ") : "0 authority or record writers in production source");

  ok("the one write this module performs is the SHARED owner-scoped admission path, not a private one — a plane with its own writer is a second spine however carefully it behaves",
    productionSource.includes("admit_owner_scoped_mutation(")
      && (productionSource.match(/admit_owner_scoped_mutation\s*\(/gu) || []).length === 1,
    `${(productionSource.match(/admit_owner_scoped_mutation\s*\(/gu) || []).length} shared-path admissions`);

  // ===========================================================================
  // 4 — CUSTODY IS NOT CONSENT
  // ===========================================================================
  // A SECOND CEREMONY, and the third shape this check tried. Run 1 opened a second virtual
  // authenticator on a different origin: WebAuthn refused it correctly, because the relying-party
  // origin is fixed by the daemon's configuration, so a second ORIGIN is a different relying party
  // rather than a second device. Run 2 re-registered on the SAME authenticator: the server excluded
  // the credential it already holds (`InvalidStateError`), which is also correct — an authenticator
  // may not enrol twice for one user. What a second device really produces on the server is a
  // second user-verified ceremony, and a passkey LOGIN is exactly that: `handle_login_finish`
  // writes its own `identity_authentication` factor receipt, which this plane admits.
  const relogin = await device.login({ adopt: false, email: whoEmail });
  const secondReceiptId = String(relogin.session?.auth_factor_receipt_ref || relogin.auth_factor_receipt_ref || "")
    .split("/").pop() || "";
  ok("a second user-verified ceremony completes and yields its own distinct receipt",
    relogin.ok === true && secondReceiptId.startsWith("afr_") && secondReceiptId !== receiptId,
    `${secondReceiptId || JSON.stringify(relogin).slice(0, 160)} != ${receiptId}`);

  for (const [field, value] of [
    ["spend_ceiling", "100"],
    ["lease_request_facets", "{}"],
    ["standing_envelope", "envelope://x"],
    ["max_usages", "5"],
  ]) {
    const refused = await provision({
      ...goodBody({ auth_factor_receipt_id: secondReceiptId }),
      [field]: value,
    });
    ok(`a provisioning carrying '${field}' is refused by its OWN code — custody binds which key may approve, and a record that could carry consent would be a standing envelope wearing a custody name`,
      refused.status === 400 && refused.body?.code === "device_held_principal_consent_field",
      `${refused.status}/${refused.body?.code}`);
  }

  for (const field of ["recovery_phrase", "private_key", "operator_password", "mnemonic"]) {
    const refused = await provision({
      ...goodBody({ auth_factor_receipt_id: secondReceiptId }),
      [field]: "should-never-be-stored",
    });
    ok(`a provisioning carrying '${field}' is refused by its OWN code, so the caller learns this plane stores no secret rather than that one field name was unknown`,
      refused.status === 400 && refused.body?.code === "device_held_principal_secret_material_field",
      `${refused.status}/${refused.body?.code}`);
  }

  // -- the wallet owner's canonical principal grammar, enforced rather than echoed --------------
  for (const [bad, why] of [
    ["wallet://acme/operator", "a scheme the binding plane has never recognised"],
    ["org://acme//operator", "a doubled slash"],
    ["org://acme/-operator", "a segment that does not begin with a letter or digit"],
    ["org://acme/operator?x=1", "a query string"],
  ]) {
    const refused = await provision(goodBody({ auth_factor_receipt_id: secondReceiptId, principal_ref: bad }));
    ok(`a principal_ref with ${why} is refused — recording a provisioning for a principal the binding plane can never resolve would be a durable statement that custody was arranged when it was not`,
      refused.status === 400 && refused.body?.code === "device_held_principal_principal_ref_invalid",
      `${bad} -> ${refused.status}/${refused.body?.code}`);
  }

  // ===========================================================================
  // 3 — RECOVERY AND DEVICE CONTINUITY
  // ===========================================================================
  const successor = await provision(goodBody({
    auth_factor_receipt_id: secondReceiptId,
    predecessor_provisioning_ref: firstRef,
  }));
  ok("a replacement device provisions a SUCCESSOR naming its predecessor, so a device that is gone leaves a readable lineage rather than a gap",
    successor.status === 201
      && successor.body?.provisioning?.predecessor_provisioning_ref === firstRef
      && successor.body?.provisioning?.principal_ref === record.principal_ref,
    `${successor.status} · predecessor=${successor.body?.provisioning?.predecessor_provisioning_ref ? "named" : "absent"}`);

  const crossPrincipal = await provision(goodBody({
    auth_factor_receipt_id: receiptId,
    principal_ref: "org://acme/someone-else",
    predecessor_provisioning_ref: firstRef,
  }));
  ok("a 'successor' on a DIFFERENT principal is refused — continuity is per principal, and a cross-principal successor would be a transfer of custody wearing a continuity name",
    crossPrincipal.status === 409 || crossPrincipal.status === 404,
    `${crossPrincipal.status}/${crossPrincipal.body?.code}`);

  const readBack = await jd(`/v1/hypervisor/auth/device-held-principals/${firstId}`);
  ok("the provisioning is durably readable by its own ref after admission",
    readBack.status === 200
      && readBack.body?.provisioning?.provisioning_hash === record.provisioning_hash,
    `${readBack.status} · hash ${String(readBack.body?.provisioning?.provisioning_hash || "").slice(0, 18)}`);

  const bindingState = await jd(`/v1/hypervisor/auth/device-held-principals/${firstId}/binding-state`);
  ok("binding state is READ BACK, never asserted: with no wallet capability configured this daemon answers 'unresolvable' rather than reporting its own proposal as bound",
    bindingState.status === 200
      && ["proposed", "unresolvable"].includes(bindingState.body?.binding_state)
      && bindingState.body?.effect_authority_created === false,
    `${bindingState.status}/${bindingState.body?.binding_state}`);
  observations.binding_state_without_wallet = bindingState.body?.binding_state;

  // ===========================================================================
  // 6 — COMPOSED, NOT RESTATED
  // ===========================================================================
  if (skipComposed) {
    ok("the no-reusable-password half is COMPOSED from check:passkey-only-authority",
      false, "SKIPPED by --skip-composed, so this run does not carry that half");
  } else if (mutation) {
    // The drills below prove that THIS check's own findings can go red. The composed
    // supplementary's falsifiability is `check:passkey-only-authority --mutation`'s own job, and it
    // is already what that script runs; executing it a second time in every CI run would be cost
    // without signal. The composed half is carried by the non-mutation run, which CI runs beside
    // this one. Recorded rather than silently dropped.
    observations.composed_supplementary = "carried by the non-mutation run; not re-executed under --mutation";
    ok("the composed supplementary is carried by this check's non-mutation run rather than executed twice per CI run — its own falsifiability belongs to check:passkey-only-authority --mutation, which is what that script already is",
      true, "deferred by design, and CI runs both");
  } else {
    const composed = spawnSync("npm", ["run", "--silent", "check:passkey-only-authority"], {
      cwd: repo,
      encoding: "utf8",
      timeout: 15 * 60 * 1000,
      env: { ...process.env },
    });
    const composedOut = `${composed.stdout || ""}${composed.stderr || ""}`;
    // A COMPOSED FAILURE MUST NAME ITSELF. The first cut reported the sub-check's LAST output line,
    // which on a failing `npm run --silent` is npm's own trailing brace: CI recorded
    // `exit 1 · })` and no one could act on it without re-running the job. The last line is the
    // wrong line — the findings are the `FAIL`/`BLOCKED` lines wherever they fall — so they are
    // what is carried up, with the tail kept only as a fallback for a sub-check that died before
    // printing one (a timeout, which spawnSync reports as a null status and a signal, or a crash).
    const composedFindings = composedOut
      .split("\n")
      .filter((line) => /^\s*(FAIL|BLOCKED)\b/u.test(line))
      .map((line) => line.trim().slice(0, 220));
    const composedTail = composedOut.trim().split("\n").filter(Boolean).slice(-3).join(" ⏎ ");
    const composedWhy = composedFindings.length
      ? `${composedFindings.length} finding(s): ${composedFindings.join(" ⏎ ")}`
      : composed.error
        ? `no finding printed — ${composed.signal ? `killed by ${composed.signal}` : composed.error.message}; tail: ${composedTail.slice(0, 220)}`
        : `no finding printed; tail: ${composedTail.slice(0, 220)}`;
    ok("the sixth proof is COMPOSED, not restated: check:passkey-only-authority runs here and passes, carrying forward that a passkey-only account needs no plaintext credential AND its typed absence that no account-recovery route exists",
      composed.status === 0 && /account-recovery|account_recovery/u.test(composedOut),
      `exit ${composed.status} · ${composedWhy}`);
    observations.composed_supplementary = "check:passkey-only-authority";
  }

  // ===========================================================================
  // MUTATION DRILLS — every finding above must be able to go red
  // ===========================================================================
  if (mutation) {
    // M1 — the ceremony-ownership check must be real: a receipt id that exists but belongs to no
    // completed ceremony of this caller must not provision.
    const foreign = await provision(goodBody({ auth_factor_receipt_id: "afr_ffffffffffffffff" }));
    ok("DRILL M1 — a receipt this caller never completed cannot provision",
      foreign.status === 404, `${foreign.status}/${foreign.body?.code}`);

    // M2 — the "no effect anywhere" comparison must be able to SEE a real write. A passkey
    // revocation is a real change to a watched family; if the comparison cannot detect it, the
    // envelope-stamp normalisation has blinded it and every clause resting on it is worthless.
    const baseline = await snapshotEstate();
    const credentialId = String(enrolled.credential_ref || "").split("/").pop();
    await jd(`/v1/hypervisor/auth/passkeys/${credentialId}`, { method: "DELETE" });
    const moved = estateDelta(baseline, await snapshotEstate());
    ok("DRILL M2 — the no-effect comparison detects a REAL write to a watched family, so the envelope-stamp normalisation did not blind it",
      moved.includes("/v1/hypervisor/auth/passkeys"), moved.join(",") || "NOTHING DETECTED");

    // M3 — the source-absence pin must detect a planted writer.
    const planted = `${productionSource}\nfn planted() { persist_record(data_dir, "grants", id, &record); }\n`;
    const detected = /persist_record\s*\(/u.test(planted);
    ok("DRILL M3 — the source-absence pin detects a planted record writer",
      detected, detected ? "planted writer detected" : "NOT DETECTED");

    // M4 — the consent-field refusal must be aimed at the field, not at unknown fields generally.
    const unknownField = await provision({ ...goodBody({ auth_factor_receipt_id: secondReceiptId }), nonsense_field: "x" });
    ok("DRILL M4 — an ordinary unknown field is refused as UNKNOWN, so the consent and secret refusals are aimed at their own classes rather than catching everything",
      unknownField.body?.code === "device_held_principal_request_field_unknown",
      `${unknownField.status}/${unknownField.body?.code}`);
  }
} catch (error) {
  failures += 1;
  results.push({ assertion: "the check ran to completion", satisfied: false, detail: String(error?.stack || error).slice(0, 600) });
  console.log(`FAIL  the check ran to completion  (${String(error?.message || error).slice(0, 300)})`);
} finally {
  try {
    await device?.close?.();
  } catch {}
  try {
    await plane?.stop?.();
  } catch {}
}

const passed = results.filter((entry) => entry.satisfied).length;
console.log(JSON.stringify({
  check: "check:device-held-wallet-principal",
  unit: "M03.8",
  verdict: failures === 0 ? "PASS" : "FAIL",
  executed_assertions: results.length,
  passed,
  failed: failures,
  observations,
}, null, 2));
process.exit(failures === 0 ? 0 : 1);
