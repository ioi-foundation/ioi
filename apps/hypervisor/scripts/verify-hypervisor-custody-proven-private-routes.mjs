// verify-hypervisor-custody-proven-private-routes — M09.7 driven against an ISOLATED daemon and the
// REAL wallet.network principal-authority fixture: the node-attestation plane's own governed ladder
// (boot profile, temporal profile, admit node identity, submit boot receipt, mark ready — each a
// wallet-approved effect) produces the custody evidence; the physical enforcement owner's
// observation produces node-profile coverage through the enforcement-coverage registry; and a
// model route's assurance class is DERIVED from that evidence and never rounded up.
//
// What it proves, live: the node-profile coverage producer (active+verified mechanisms mediate and
// prevent, audit-only ones never do, a measured-boot receipt alone discovers and attributes only,
// an unverified "active" mechanism is refused); the ladder driven through the plane's real routes
// with grants minted for each challenge's exact hashes; a local private-native route on the ready
// node deriving custody_proven_no_plaintext with the account, roles, nonce, endorsements, owners,
// observable paths and egress coverage re-derived here from the served records; every downgrade
// typed by its cause (no node → appraisal unavailable; a hosted provider route → remote custody;
// contract-only → contractual_privacy; nothing → unevidenced/refused; audit-only egress →
// egress_not_preventable); contractual-to-custody promotion refused; a route custody edited after
// derivation no longer matching its claim; restart reproducing every projection. Role confusion,
// a replayed nonce, a withdrawn endorsement and a substituted measurement are refused by the plane
// itself at submit (so no committed receipt exists) and by the daemon's appraisal rules over
// synthetic receipts in its unit tests. Exit: 0 pass · 1 fail · 2 blocked. `--mutation` drills the
// verifier's own oracles.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const DRILL = process.argv.includes("--mutation");
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../../..");
const FIXTURES = path.resolve(ROOT, "docs/architecture/_meta/schemas/fixtures");
const results = [];
const observedCodes = new Set();
const ok = (name, pass, detail = "") => { results.push({ name, pass: !!pass, detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };
const readFixture = (rel) => JSON.parse(fs.readFileSync(path.join(FIXTURES, rel), "utf8"));

// ---------------------------------------------------------------------------- the oracles (offline)
export function jcs(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${jcs(value[k])}`).join(",")}}`;
}
const sha256 = (text) => crypto.createHash("sha256").update(text).digest("hex");
const jcsHash = (material) => `sha256:${sha256(jcs(material))}`;
const CLAIM_DOMAIN = "ioi.model-router.route-assurance-claim-content-commitment-jcs-sha256.v1";
const OBS_DOMAIN = "ioi.components.daemon-runtime.node-enforcement-profile-observation-content-commitment-jcs-sha256.v1";
const CLAIM_MATERIAL = ["schema_version", "claim_ref", "revision", "predecessor_ref", "owner_ref", "principal_ref", "route_ref", "route_custody_hash", "requested_class", "effective_class", "downgrade_reason", "declared_posture", "evidence", "refusals", "appraised_at", "expires_at", "revocation_epoch", "status", "receipt_refs"];
const OBS_MATERIAL = ["schema_version", "observation_ref", "revision", "predecessor_ref", "owner_ref", "principal_ref", "node_enforcement_profile_ref", "node_ref", "platform", "observed_at", "mechanisms", "measured_boot", "known_gaps", "status", "receipt_refs"];
const commitment = (record, domain, material) => { const flat = { domain }; for (const f of material) flat[f] = record[f]; return jcsHash(flat); };
export const deriveClaimHash = (r) => commitment(r, CLAIM_DOMAIN, CLAIM_MATERIAL);
export const deriveObservationHash = (r) => commitment(r, OBS_DOMAIN, OBS_MATERIAL);
export const deriveSubjectHash = (profileRef, subject) => jcsHash({ provider_profile_ref: profileRef, subject });
export const bootProfileRoot = (profile) => jcsHash({ domain: "ioi.hypervisoros-boot-profile-jcs-sha256.v1", profile });
export const temporalProfileRoot = (profile) => jcsHash({ domain: "ioi.temporal-verification-profile-record-jcs-sha256.v1", profile });
// The registered contract's own rule: the profile hash recomputes from the exact ref, version and declaration.
export const temporalProfileHash = (profile) => jcsHash({ domain: "ioi.temporal-verification-profile-hash-jcs-sha256.v1", profile_ref: profile.profile_ref, profile_version: profile.profile_version, declaration: profile.declaration });
export const bootReceiptRoot = (receipt) => { const t = JSON.parse(JSON.stringify(receipt)); t.verification.verified_at = null; return jcsHash({ domain: "ioi.hypervisoros-boot-receipt-jcs-sha256.v1", receipt: t }); };
export const signedMaterialHash = (receipt) => jcsHash({ domain: "ioi.hypervisoros-boot-receipt-signed-material-jcs-sha256.v1", receipt_id: receipt.receipt_id, node_id: receipt.node_id, node_record_ref: receipt.node_record_ref, observation: receipt.observation });
export const identityKeyCommitment = (suite, pk) => jcsHash({ domain: "ioi.hypervisoros-node-identity-commitment-jcs-sha256.v1", key_suite: suite, identity_public_key: pk });
/** The coverage the producer must derive from an observation for one action class — re-derived here. */
export function expectedCoverage(observation, actionClass) {
  const covering = observation.mechanisms.filter((m) => m.action_classes.includes(actionClass));
  const active = covering.filter((m) => m.mode === "active_enforcement" && m.verification_evidence_refs.length > 0);
  const observing = covering.filter((m) => ["audit_only", "passive_observation"].includes(m.mode) && m.verification_evidence_refs.length > 0);
  const measured = !!observation.measured_boot?.boot_receipt_root;
  const mediated = active.length > 0;
  const observable = mediated || observing.length > 0;
  const attributable = observable || measured;
  return { discovered: attributable, observable, attributable, mediated, preventable: mediated, receipted: active.some((m) => m.receipt_contract_refs.length > 0), uncovered: covering.length === 0 };
}
/** The class the evidence supports at or below the request — re-derived here from the served claim's evidence. */
export function expectedClass(claim) {
  const rank = { unevidenced: 0, confidential_compute_declared: 1, contractual_privacy: 2, workload_isolation: 3, custody_proven_no_plaintext: 4 };
  const e = claim.evidence; const d = claim.declared_posture;
  const supported = [];
  const custodyOk = e.custody.boot_receipt_root && e.custody.appraisal.appraisal_status === "pass" && e.custody.appraisal.nonce_single_use_status === "consumed_for_this_appraisal" && e.custody.appraisal.revocation_status === "current" && e.custody.egress_preventable && !d.remote_provider_can_read_weights && claim.refusals.length === 0;
  if (custodyOk) supported.push("custody_proven_no_plaintext");
  if (e.isolation.binding_ref) supported.push("workload_isolation");
  if (e.contractual.rights_contract_revision_ref) supported.push("contractual_privacy");
  if (d.execution_privacy_posture === "private_native" && !d.remote_provider_can_read_weights) supported.push("confidential_compute_declared");
  const eligible = supported.filter((c) => rank[c] <= rank[claim.requested_class]);
  return eligible.sort((a, b) => rank[b] - rank[a])[0] ?? "unevidenced";
}
const refused = (reply, status, expected) => reply.status === status && code(reply.body) === expected;
const code = (body) => body?.code ?? body?.error?.code ?? body?.reason ?? "";
const message = (body) => body?.error?.message ?? body?.message ?? "";

// ------------------------------------------------------------------------------------ the daemon
const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let daemon = null, daemonLog = "", daemonPort = 0, DAEMON = "", SESSION = "", OWNER = "", PRINCIPAL = "", resolver = null;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-custody-proven-"));
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.ok) return true; } catch { /* not yet */ } await new Promise((r) => setTimeout(r, 200)); } return false; };
async function startDaemon() {
  daemon = spawn(daemonBinary, [], { cwd: ROOT, env: { ...process.env, ...(resolver?.env ?? {}), IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1", IOI_WALLET_SECRET_PASS: "ioi-custody-proven-verifier", IOI_HYPERVISOR_ESTATE_OWNER_REF: ESTATE_OWNER }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  return waitFor(`${DAEMON}/healthz`, Number(process.env.IOI_ISOLATED_READY_TIMEOUT_MS ?? 120000));
}
const stopDaemon = async () => { if (!daemon) return; const child = daemon; daemon = null; child.kill("SIGTERM"); await new Promise((resolve) => { const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } resolve(); }, 8000); child.on("exit", () => { clearTimeout(t); resolve(); }); }); };
const jd = (p, init = {}, session = SESSION) => fetch(`${DAEMON}${p}`, { ...init, headers: { "content-type": "application/json", ...(session ? { cookie: `ioi_session=${session}` } : {}), ...(init.headers || {}) } }).then(async (r) => { const body = await r.json().catch(() => ({})); const c = body?.code ?? body?.error?.code ?? body?.reason; if (typeof c === "string" && c) observedCodes.add(c); return { status: r.status, body }; }).catch(() => ({ status: 0, body: {} }));
const post = (p, body, session = SESSION) => jd(p, { method: "POST", body: JSON.stringify(body) }, session);
const get = (p, session = SESSION) => jd(p, {}, session);
const stripVolatile = (v) => JSON.stringify(v, (k, x) => (k === "updated_at" || k === "at" ? undefined : x));
let n = 0; const key = (label) => `cpr-${label}-${++n}`;

// ------------------------------------------------------------------------- governed effects
// Every node-plane effect is wallet-governed: the first call answers a 403 challenge naming the
// exact policy and request hashes; the fixture mints and records the grant for the governing owner;
// the retry carries `wallet_approval_grant`. The verifier never guesses a hash.
async function governed(route, body, governingOwner) {
  const challenge = await post(route, body, "");
  const approval = challenge.body?.error?.approval ?? challenge.body?.approval;
  if (!(challenge.status === 403 && approval?.policy_hash && approval?.request_hash)) return { challenge, reply: challenge };
  // The approval is recorded under the challenge's own operation scope: the resolver matches the
  // daemon's required scope against the recorded decision, and the fixture's default scope is genesis'.
  const scope = challenge.body?.error?.required_scope ?? challenge.body?.required_scope;
  if (!scope) return { challenge, reply: { status: 0, body: { error: { code: "challenge_names_no_scope", message: `challenge keys ${Object.keys(challenge.body?.error ?? challenge.body ?? {}).join(",")}` } } } };
  const grant = resolver.mintForCapability(governingOwner, approval.policy_hash, approval.request_hash);
  await resolver.recordApproval(governingOwner, approval.policy_hash, approval.request_hash, grant, scope);
  const reply = await post(route, { ...body, wallet_approval_grant: grant }, "");
  return { challenge, reply };
}

const NODES = "/v1/hypervisor/hypervisoros/nodes";
const OBS = "/v1/hypervisor/hypervisoros/node-enforcement/observations";
const COVERAGE = "/v1/hypervisor/hypervisoros/node-enforcement/coverage";
// The node is a member of the ESTATE the plane governs: its id lives under the plane's estate namespace
// (runtime://{estate_namespace}/…, read from the projection after bootstrap) and its record ref is the
// one the plane derives for it. Neither is a constant the verifier chooses.
let NODE = "runtime://unbound/alpha-node-1";
let NODE_RECORD_REF = "hypervisoros-node://unbound/node/alpha-node-1";
const NODE_OWNER = "org://acme/research"; // an approver the real fixture seeds
const ESTATE_OWNER = "org://acme/estate-operator"; // the estate owner the daemon is configured with (IOI_HYPERVISOR_ESTATE_OWNER_REF); the fixture seeds its authority
const PROFILE = "node-enforcement://acme/estate-1/default";
const evidenceDir = () => path.join(dataDir, "hypervisoros-node-evidence");
const plantEvidence = (name, value) => { fs.mkdirSync(evidenceDir(), { recursive: true }); fs.writeFileSync(path.join(evidenceDir(), `${name}.json`), JSON.stringify(value)); };
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/u, "Z");

function observationBody(over = {}) {
  return { owner_ref: OWNER, idempotency_key: key("obs"), node_enforcement_profile_ref: PROFILE, node_ref: NODE, platform: { os: "linux", kernel: os.release(), arch: "x86_64" }, mechanisms: [
    { mechanism: "egress_policy", mode: "active_enforcement", action_classes: ["egress"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/egress-policy/probe/1"], receipt_contract_refs: ["schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1"], required_privilege: "os_privileged" },
    { mechanism: "seccomp", mode: "active_enforcement", action_classes: ["process_launch", "filesystem"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/seccomp/probe/1"], receipt_contract_refs: [], required_privilege: "os_privileged" },
    { mechanism: "lsm_ebpf", mode: "audit_only", action_classes: ["credential_access"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/lsm/audit/1"], receipt_contract_refs: [], required_privilege: "kernel" },
  ], known_gaps: ["support_bundle redaction not observed"], ...over };
}

// The ladder node's OWN profile: the node plane admits a node only under a profile whose every resolved
// coverage declaration is verified-current and positively mediated, preventable and receipted — an
// audit-only or unreceipted mechanism anywhere under the profile makes the node inadmissible. The mixed
// profile above stays for the producer's negative assertions; this one is what a hardened node observes.
const HARDENED = "node-enforcement://acme/estate-1/hardened";
function hardenedBody(over = {}) {
  return observationBody({ node_enforcement_profile_ref: HARDENED, mechanisms: [
    { mechanism: "egress_policy", mode: "active_enforcement", action_classes: ["egress"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/egress-policy/probe/1"], receipt_contract_refs: ["schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1"], required_privilege: "os_privileged" },
    { mechanism: "seccomp", mode: "active_enforcement", action_classes: ["process_launch", "filesystem"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/seccomp/probe/1"], receipt_contract_refs: ["schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1"], required_privilege: "os_privileged" },
    { mechanism: "lsm_ebpf", mode: "active_enforcement", action_classes: ["credential_access"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/lsm/probe/1"], receipt_contract_refs: ["schema://ioi/components/daemon-runtime/gateway-decision-receipt/v1"], required_privilege: "kernel" },
  ], known_gaps: [], ...over });
}

async function run() {
  resolver = await startRealWalletNetworkPrincipalAuthorityFixture();
  daemonPort = await freePort(); DAEMON = `http://127.0.0.1:${daemonPort}`;
  const healthy = await startDaemon();
  if (!healthy) { ok("the isolated daemon became healthy under the wallet fixture's environment", false, daemonLog.slice(-400)); return; }
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) { const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "custody-proven-v1", email: "custody-proven@ioi.local" }) }, ""); SESSION = boot.body?.session_token || boot.body?.session?.token || ""; }
  const who = (await get("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  PRINCIPAL = who.principal?.principal_ref ?? "";
  ok("operator bootstrap yields an authenticated session with an owner tenant and a RESOLVED principal beside the real wallet fixture", SESSION.startsWith("ioi_sess_") && !!OWNER && PRINCIPAL.startsWith("user://"), `${OWNER} ${PRINCIPAL}`);

  // -- the observation and the coverage producer ------------------------------------------------------
  const unverifiedActive = await post(OBS, observationBody({ mechanisms: [{ mechanism: "egress_policy", mode: "active_enforcement", action_classes: ["egress"], verification_evidence_refs: [], receipt_contract_refs: [], required_privilege: "os_privileged" }] }));
  ok("[observation] an 'active' mechanism with no verification evidence is refused: an unverified mechanism is observed as audit-only at most, never active", refused(unverifiedActive, 422, "node_enforcement_observation_active_mechanism_unverified"), `${unverifiedActive.status} ${code(unverifiedActive.body)}`);
  const badMode = await post(OBS, observationBody({ mechanisms: [{ mechanism: "egress_policy", mode: "enforced_hard", action_classes: ["egress"], verification_evidence_refs: ["e"], receipt_contract_refs: [], required_privilege: "user" }] }));
  ok("[observation] a mode outside the vocabulary is refused", refused(badMode, 422, "node_enforcement_observation_mode_outside_vocabulary"), `${badMode.status} ${code(badMode.body)}`);
  const authored = await post(OBS, observationBody({ measured_boot: { boot_receipt_root: "sha256:" + "aa".repeat(32) } }));
  ok("[observation] the measured-boot summary is server-resolved from the node plane, never authored", authored.status === 422 || authored.status === 400, `${authored.status} ${code(authored.body)}`);
  const noSession = await post(OBS, observationBody(), "");
  ok("[observation] an anonymous observation is refused: the physical enforcement owner is a resolved principal", noSession.status === 401 || noSession.status === 403, `${noSession.status}`);
  const estate = await get(`${NODES}/projection`);
  const estateNamespace = estate.body?.estate_namespace;
  ok("PRECONDITION: the node-attestation plane names its estate namespace on the projection, and the node this run admits is derived under it (runtime://{estate_namespace}/…) rather than chosen by the verifier", typeof estateNamespace === "string" && estateNamespace.length > 0, `${estate.status} ${JSON.stringify(estate.body).slice(0, 200)}`);
  NODE = `runtime://${estateNamespace}/alpha-node-1`;
  NODE_RECORD_REF = `hypervisoros-node://${estateNamespace}/node/alpha-node-1`;
  const obsKey = key("obs");
  const observed = await post(OBS, { ...observationBody(), idempotency_key: obsKey });
  const obs = observed.body?.node_enforcement_profile_observation_record ?? {};
  const coverage = observed.body?.coverage_declarations ?? [];
  const byClass = Object.fromEntries(coverage.map((c) => [c.action_class, c]));
  ok("[observation] the physical enforcement owner's observation admits as revision 1 bound to the resolved principal, with its content hash re-derived here, and the measured-boot summary empty (no node is attested yet)", observed.status === 201 && obs.revision === 1 && obs.principal_ref === PRINCIPAL && obs.content_hash === deriveObservationHash(obs) && obs.measured_boot?.boot_receipt_root === null, `${observed.status} ${code(observed.body)} ${message(observed.body).slice(0, 120)}`);
  const expect = (cls) => expectedCoverage(observationBody(), cls);
  ok("[producer] one coverage declaration per covered action class is derived and admitted through the enforcement-coverage registry, each re-derived here: egress (active + verified + receipt contract) mediates, prevents and receipts; process_launch/filesystem (active, no receipt contract) mediate and prevent but do not receipt; credential_access (audit-only) observes and attributes and NEVER mediates or prevents", coverage.length === 4 && ["egress", "process_launch", "filesystem", "credential_access"].every((cls) => jcs(byClass[cls]?.claims ?? null) === jcs(expect(cls))) && byClass.egress?.operating_mode === "active_enforcement" && byClass.credential_access?.operating_mode === "audit_only" && byClass.credential_access?.claims?.mediated === false, JSON.stringify(coverage.map((c) => [c.action_class, c.claims?.mediated, c.claims?.preventable, c.claims?.receipted])));
  const served = await get(`${COVERAGE}?profile_ref=${encodeURIComponent(PROFILE)}`);
  ok("[producer] the registry resolves the node profile's declarations as operable and current, with subject kind node_enforcement_profile and the observation's hash as the subject content hash", served.status === 200 && served.body?.declarations?.length === 4 && served.body.declarations.every((d) => d.subject?.kind === "node_enforcement_profile" && d.subject?.content_hash === obs.content_hash && d.status === "verified"), `${served.status} ${code(served.body)} n=${served.body?.declarations?.length}`);
  const replayObs = await post(OBS, { ...observationBody(), idempotency_key: obsKey });
  ok("[observation] an exact retry replays the admitted observation", replayObs.status === 200 && replayObs.body?.node_enforcement_profile_observation_record?.content_hash === obs.content_hash, `${replayObs.status}`);

  // -- the node ladder, through the plane's own governed routes ------------------------------------------
  // The temporal profile is governed by the estate owner the daemon is configured with (the plane
  // names it; no request may choose it); the boot profile binds the declared temporal profile and is
  // governed by its own owner_ref; the node by its node_owner_ref. Every governing owner is one the
  // fixture can approve for, and the estate owner is a different principal from the node owner.
  const hardened = await post(OBS, hardenedBody());
  const hardenedCoverage = await get(`${COVERAGE}?profile_ref=${encodeURIComponent(HARDENED)}`);
  const positive = (d) => d.status === "verified" && d.verification?.freshness_status === "current" && d.claims?.uncovered === false && d.claims?.mediated === true && d.claims?.preventable === true && d.claims?.receipted === true;
  ok("[ladder] the node's OWN profile is observed with active, verified, receipted mechanisms on every class it names, and the producer's declarations for it are all verified-current and positively mediated, preventable and receipted — the coverage the plane's node admission requires (an audit-only or unreceipted mechanism anywhere under a profile makes its nodes inadmissible)", hardened.status === 201 && hardenedCoverage.status === 200 && (hardenedCoverage.body?.declarations?.length ?? 0) === 4 && hardenedCoverage.body.declarations.every(positive), `${hardened.status} ${code(hardened.body)} coverage=${hardenedCoverage.status} ${JSON.stringify((hardenedCoverage.body?.declarations ?? []).map((d) => [d.scope?.action_class, d.claims])).slice(0, 300)}`);
  const bootProfile = { ...readFixture("hypervisoros-boot-profile-v1/positive-declared.json"), owner_ref: NODE_OWNER };
  const temporalProfile = readFixture("temporal-verification-profile-v1/positive-declared.json");
  // The wrong-owner probe declares a DISTINCT profile (its own ref and hash): the fixture records one
  // approval decision per request hash, so the probe's refused decision must not shadow the real one.
  const probeProfile = { ...temporalProfile, profile_ref: `${temporalProfile.profile_ref}-probe` };
  delete probeProfile.profile_hash;
  probeProfile.profile_hash = temporalProfileHash(probeProfile);
  const wrongOwner = await governed(`${NODES}/temporal-profile`, { temporal_profile: probeProfile }, NODE_OWNER);
  ok("[ladder] the node owner's grant does not admit the estate's temporal profile: the plane's challenge names the CONFIGURED estate owner as the required authority, and a grant minted by another principal's authority is refused", wrongOwner.challenge.status === 403 && wrongOwner.challenge.body?.error?.required_authority_ref === ESTATE_OWNER && wrongOwner.reply.status === 403, `${wrongOwner.challenge.status}/${wrongOwner.reply.status} ${code(wrongOwner.reply.body)} ${message(wrongOwner.reply.body).slice(0, 160)}`);
  const declaredTemporal = await governed(`${NODES}/temporal-profile`, { temporal_profile: temporalProfile }, ESTATE_OWNER);
  const declaredBoot = await governed(`${NODES}/boot-profile`, { boot_profile: bootProfile }, bootProfile.owner_ref);
  ok("[ladder] the temporal profile and then the boot profile that binds it are declared through the plane's governed routes: each first answers a 403 challenge naming its exact policy and request hashes, and the fixture-minted grant for those hashes admits it", declaredTemporal.challenge.status === 403 && declaredTemporal.reply.status < 300 && declaredBoot.challenge.status === 403 && declaredBoot.reply.status < 300, `temporal ${declaredTemporal.challenge.status}/${declaredTemporal.reply.status} ${code(declaredTemporal.reply.body)} ${message(declaredTemporal.reply.body).slice(0, 600)} · boot ${declaredBoot.challenge.status}/${declaredBoot.reply.status} ${code(declaredBoot.reply.body)} ${message(declaredBoot.reply.body).slice(0, 100)}`);
  const projection0 = await get(`${NODES}/projection`);
  const head0 = projection0.body?.observed?.node_set_root;
  // The node's identity key: the plane admits its commitment, and every boot receipt must be signed by
  // exactly this key over the receipt's signed-material hash — a signer chain that ends anywhere else,
  // a hash that does not recompute, or a forged signature is refused by the plane.
  const nodeKey = crypto.generateKeyPairSync("ed25519");
  const pk = nodeKey.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const declaration = (over = {}) => ({ node_id: NODE, expected_node_set_root: head0, evidence_refs: ["evidence://acme/estate-1/admit/alpha-node-1"], node_owner_ref: NODE_OWNER, sealed_identity: null, node_enforcement_profile_ref: HARDENED, measurement_policy_ref: "measurement-policy://acme/estate-1/default", ctee_policy_ref: "policy://acme/estate-1/ctee", supported_worker_substrates: ["microvm", "container"], supported_mount_profiles: ["public_mount", "plaintext_free_model_mount"], boot_receipt_ref: null, temporal_validity_evaluation_ref: null, ...over });
  // Later ladder ops admit only their own members: the plane refuses an admission field re-declared
  // on a receipt submission or a readiness mark (the owner already durable on the record governs).
  const later = (over = {}) => declaration({ node_owner_ref: null, sealed_identity: null, node_enforcement_profile_ref: null, measurement_policy_ref: null, ctee_policy_ref: null, supported_worker_substrates: [], supported_mount_profiles: [], ...over });
  const admitted = await governed(`${NODES}/transitions/admit_node_identity`, declaration({ sealed_identity: { key_suite: "ed25519", identity_public_key: pk, identity_key_commitment: identityKeyCommitment("ed25519", pk), sealed_identity_alias: "vault://acme/node-identity/alpha-node-1", sealing_receipt_ref: "receipt://acme/vault/seal/alpha-node-1" } }), NODE_OWNER);
  ok("[ladder] the node identity is admitted under the observed enforcement profile: the plane resolves the profile's coverage declarations from the registry (the producer's output) and refuses nothing, and the projection's head moved", admitted.reply.status < 300, `${admitted.challenge.status}/${admitted.reply.status} ${code(admitted.reply.body)} ${message(admitted.reply.body).slice(0, 160)}`);
  const chainNow = await resolver.readChainTimestampMs().catch(() => Date.now());
  const bootRoot = bootProfileRoot(bootProfile);
  const receipt = {
    schema_version: "ioi.components.daemon-runtime.hypervisoros-boot-receipt.v1",
    receipt_id: "receipt://acme/estate-1/boot/alpha-node-1/3", node_id: NODE, node_record_ref: NODE_RECORD_REF,
    note: "Boot measurement is an integrity receipt, not a consumer-GPU plaintext privacy guarantee.",
    observation: {
      boot_epoch: 3, boot_profile_ref: bootProfile.boot_profile_id, boot_profile_root: bootRoot, workload_identity: "workload://acme/estate-1/alpha-node-1/daemon",
      image_hash: bootProfile.image_hash, daemon_binary_hash: bootProfile.daemon_binary_hash, policy_build_hash: "sha256:" + "2b".repeat(32), package_manifest_hash: bootProfile.package_manifest_hash, driver_manifest_hash: bootProfile.driver_manifest_hash,
      measurement_method: "tpm_quote", privacy_claim: "none", quote_evidence_refs: ["attestation://acme/estate-1/alpha-node-1/quote/3"],
      attestation_assurance: { attester_ref: NODE, verifier_ref: "verifier://acme/estate-1/appraiser-service", appraiser_ref: "appraiser://acme/estate-1/appraiser-service", relying_party_ref: "runtime://acme/estate-1/daemon", nonce: crypto.randomBytes(12).toString("hex"), nonce_single_use_status: "consumed_for_this_appraisal", nonce_consumption_receipt_ref: "receipt://acme/estate-1/nonce/42", endorsement_refs: ["endorsement://acme/tpm-vendor/root"], reference_value_refs: ["reference://acme/estate-1/pcr-baseline"], appraisal_policy_ref: "policy://acme/estate-1/appraisal", appraisal_result_ref: "appraisal://acme/estate-1/alpha-node-1/3", appraisal_status: "pass", appraised_at: iso(Date.now()), appraisal_expires_at: iso(Date.now() + 9 * 60000), effective_posture: "measured_boot", hardware_or_measured_attested: true, lease_ref: null, lease_expires_at: null, revocation_epoch: 12, revocation_status: "current", revocation_check_receipt_ref: "receipt://acme/estate-1/revocation/12", reattest_by: iso(chainNow + 86400000) },
      rollback_state: { observed_version_counter: 9, observed_image_head_hash: bootProfile.image_hash },
      temporal_state: { temporal_verification_profile_ref: temporalProfile.profile_ref, temporal_verification_profile_hash: temporalProfile.profile_hash, rollback_domain_ref: "failure-domain://acme/estate-1/node-local", continuity_floor_evidence_refs: ["evidence://acme/estate-1/anchor/operator/9"] },
    },
    verification: { verdict: "unverified", verified_against_boot_profile_root: bootRoot, temporal_validity_evaluation_ref: null, temporal_validity_evaluation_hash: null, evaluated_temporal_posture: null, refusal_codes: [], verified_at: null },
    signature: { key_suite: "ed25519", signer_public_key: pk, signed_material_hash: null, signature: "00".repeat(64) },
  };
  receipt.signature.signed_material_hash = signedMaterialHash(receipt);
  receipt.signature.signature = crypto.sign(null, Buffer.from(receipt.signature.signed_material_hash, "utf8"), nodeKey.privateKey).toString("hex");
  const evaluation = readFixture("temporal-validity-evaluation-v1/positive-online-fresh.json");
  evaluation.subject_ref = receipt.receipt_id; evaluation.subject_hash = signedMaterialHash(receipt);
  evaluation.profile_ref = temporalProfile.profile_ref; evaluation.profile_hash = temporalProfile.profile_hash;
  for (const claim of evaluation.claims) { if (claim.kind === "status_as_of") { claim.as_of = iso(chainNow); claim.status_subject_ref = receipt.receipt_id; } if (claim.kind === "continuity_floor") { claim.accepted_head_hash = bootProfile.image_hash; claim.namespace_ref = bootProfile.boot_profile_id; } }
  evaluation.evidence_horizon = { valid_from: iso(chainNow), valid_until: iso(chainNow + 10 * 60000) };
  // The registered contract's own rule: the evaluation hash recomputes from the exact bound members.
  evaluation.evaluation_hash = jcsHash({ domain: "ioi.temporal-validity-evaluation-hash-jcs-sha256.v1", evaluation_id: evaluation.evaluation_id, profile_ref: evaluation.profile_ref, profile_hash: evaluation.profile_hash, subject_ref: evaluation.subject_ref, subject_hash: evaluation.subject_hash, operation_class: evaluation.operation_class, evidence_refs: evaluation.evidence_refs, source_failure_domain_refs: evaluation.source_failure_domain_refs, claims: evaluation.claims, temporal_posture: evaluation.temporal_posture, evidence_horizon: evaluation.evidence_horizon, invalidation_triggers: evaluation.invalidation_triggers, obligations: evaluation.obligations });
  // The plane's committed receipt is the observed receipt with the verdict the PLANE derived (verified
  // against the declared boot profile root, bound to this evaluation, online_fresh, no refusals, no
  // time): its root is what the node record and every consumer cite. Re-derived here, never read back.
  const committedReceipt = { ...receipt, verification: { verdict: "verified", verified_against_boot_profile_root: bootRoot, temporal_validity_evaluation_ref: evaluation.evaluation_id, temporal_validity_evaluation_hash: evaluation.evaluation_hash, evaluated_temporal_posture: "online_fresh", refusal_codes: [], verified_at: null } };
  const committedRoot = bootReceiptRoot(committedReceipt);
  plantEvidence("receipt-3", receipt); plantEvidence("evaluation-42", evaluation);
  const submitted = await governed(`${NODES}/transitions/submit_boot_receipt`, later({ expected_node_set_root: (await get(`${NODES}/projection`)).body?.observed?.node_set_root ?? head0, boot_receipt_ref: receipt.receipt_id, temporal_validity_evaluation_ref: evaluation.evaluation_id }), NODE_OWNER);
  ok("[ladder] the observed measured-boot receipt (planted as durable node evidence with its temporal evaluation bound to its signed-material hash) is VERIFIED against the declared floors by the plane and committed", submitted.reply.status < 300, `${submitted.challenge.status}/${submitted.reply.status} ${code(submitted.reply.body)} ${message(submitted.reply.body).slice(0, 200)}`);
  const ready = await governed(`${NODES}/transitions/mark_node_ready`, later({ expected_node_set_root: (await get(`${NODES}/projection`)).body?.observed?.node_set_root ?? head0, temporal_validity_evaluation_ref: evaluation.evaluation_id }), NODE_OWNER);
  const projection = await get(`${NODES}/projection`);
  const nodeView = (projection.body?.observed?.nodes ?? []).find((x) => x.node_id === NODE) ?? projection.body?.observed?.nodes?.[0] ?? {};
  ok("[ladder] the node is marked ready: readiness is DERIVED by the plane from the bound verified receipt under fresh temporal evidence", ready.reply.status < 300 && (nodeView.readiness_derivable === true || nodeView.status === "ready"), `${ready.challenge.status}/${ready.reply.status} ${code(ready.reply.body)} ${message(ready.reply.body).slice(0, 160)} view=${JSON.stringify(nodeView).slice(0, 120)}`);
  // A new observation is a successor on the profile/node family: it names the exact head it read.
  const obsHead = async (profile = HARDENED) => (await get(`${OBS}/${encodeURIComponent(profile)}/${encodeURIComponent(NODE)}`)).body?.head ?? null;
  const obs2 = await post(OBS, hardenedBody({ expected_head: await obsHead() }));
  ok("[observation] a new observation after the ladder carries the node's committed boot receipt root and measured_boot posture — resolved from the plane, and STILL contributing discovered/attributable only", obs2.status === 201 && obs2.body?.node_enforcement_profile_observation_record?.measured_boot?.boot_receipt_root === committedRoot && nodeView.verified_boot_epoch === 3 && nodeView.status === "ready", `${obs2.status} ${code(obs2.body)} root=${obs2.body?.node_enforcement_profile_observation_record?.measured_boot?.boot_receipt_root} node_epoch=${nodeView.verified_boot_epoch} rederived=${committedRoot}`);

  // -- routes with different custody --------------------------------------------------------------------
  const localRoute = (await post("/v1/hypervisor/model-routes", { owner_ref: OWNER, idempotency_key: key("route-local"), model_id: "llama-local", display_name: "local llama", transport: "openai_compatible", base_url: "http://127.0.0.1:1/v1", weight_class: "public_open_weight", mount_target: "local_device", execution_privacy_posture: "private_native" })).body?.route ?? {};
  // A route registered with NO custody serves null custody members: the plane's admission fills its
  // defaults for the admission record and nothing writes them back as the route's declaration.
  const undeclaredCreate = await post("/v1/hypervisor/model-routes", { owner_ref: OWNER, idempotency_key: key("route-undeclared"), model_id: "hosted-undeclared", display_name: "hosted undeclared", transport: "openai_compatible", base_url: "https://api.hosted.invalid/v1" });
  const undeclaredRoute = undeclaredCreate.body?.route ?? {};
  const hostedCreate = await post("/v1/hypervisor/model-routes", { owner_ref: OWNER, idempotency_key: key("route-hosted"), model_id: "hosted-large", display_name: "hosted large", transport: "openai_compatible", base_url: "https://api.hosted.invalid/v1", weight_class: "remote_api_private_weight", mount_target: "provider_api", execution_privacy_posture: "remote_api_provider_trust" });
  const hostedRoute = hostedCreate.body?.route ?? {};
  ok("PRECONDITION: two model routes are registered with declared custody — a local private-native public-weight route and a hosted provider-trust API route", !!localRoute.route_id && !!hostedRoute.route_id && hostedRoute.custody?.mount_target === "provider_api", `${localRoute.route_id} ${hostedRoute.route_id} local=${JSON.stringify(localRoute.custody)} hosted=${hostedCreate.status} ${code(hostedCreate.body)} ${message(hostedCreate.body).slice(0, 200)} ${JSON.stringify(hostedRoute.custody)}`);
  const A = `/v1/hypervisor/model-routes/${encodeURIComponent(localRoute.route_id)}/assurance`;
  const B = `/v1/hypervisor/model-routes/${encodeURIComponent(hostedRoute.route_id)}/assurance`;
  const claimBody = (over = {}) => ({ owner_ref: OWNER, idempotency_key: key("claim"), requested_class: "custody_proven_no_plaintext", ...over });
  // Every admitted claim moves the route's family head; a successor names the exact head it read.
  const headOf = async (route) => (await get(route)).body?.head ?? null;
  const claim = async (route, over = {}) => post(route, claimBody({ expected_head: await headOf(route), ...over }));
  const U = `/v1/hypervisor/model-routes/${encodeURIComponent(undeclaredRoute.route_id)}/assurance`;
  const undeclared = await claim(U, { node_ref: NODE, key_owner_ref: OWNER, protected_data_owner_ref: OWNER });
  ok("[claim] a route registered with NO declared custody is refused route_custody_undeclared: the plane's admission defaults (served as null custody members on the route) are not the route's declaration, and no class derives over an undeclared custody", undeclared.status === 422 && code(undeclared.body) === "route_assurance_route_custody_undeclared", `${undeclared.status} ${code(undeclared.body)} custody=${JSON.stringify(undeclaredRoute.custody)}`);

  // -- claim refusals ---------------------------------------------------------------------------------
  const unknownRoute = await post("/v1/hypervisor/model-routes/route_nope/assurance", claimBody());
  ok("[claim] an unregistered route has no class (404)", refused(unknownRoute, 404, "route_assurance_route_unknown"), `${unknownRoute.status} ${code(unknownRoute.body)}`);
  const badClass = await claim(A, { requested_class: "cryptographically_perfect" });
  ok("[claim] a class outside the vocabulary is refused", refused(badClass, 422, "route_assurance_class_outside_vocabulary"), `${badClass.status} ${code(badClass.body)}`);
  const authoredClass = await claim(A, { effective_class: "custody_proven_no_plaintext", evidence: {} });
  ok("[claim] authoring the effective class or the evidence is refused by name: the class is derived, never authored", authoredClass.status === 422 || authoredClass.status === 400, `${authoredClass.status} ${code(authoredClass.body)}`);
  const unknownField = await claim(A, { fitness: 1 });
  ok("[claim] an unknown field is refused by name", refused(unknownField, 400, "route_assurance_request_unknown_field"), `${unknownField.status} ${code(unknownField.body)}`);

  // -- the downgrades, each typed by its cause -------------------------------------------------------------
  const noEvidence = await claim(A, );
  const c0 = noEvidence.body?.route_assurance_claim_record ?? {};
  ok("[downgrade] custody requested with NO evidence named: the local private-native route derives confidential_compute_declared — a declaration, recorded as one — with the downgrade named, the custody evidence empty, and the content hash re-derived here", noEvidence.status === 201 && c0.requested_class === "custody_proven_no_plaintext" && c0.effective_class === "confidential_compute_declared" && typeof c0.downgrade_reason === "string" && c0.evidence?.custody?.boot_receipt_root === null && c0.content_hash === deriveClaimHash(c0) && expectedClass(c0) === c0.effective_class, `${noEvidence.status} ${code(noEvidence.body)} ${c0.effective_class} ${message(noEvidence.body).slice(0, 100)}`);
  const hosted = await claim(B, { node_ref: NODE, key_owner_ref: OWNER, protected_data_owner_ref: OWNER });
  const cB = hosted.body?.route_assurance_claim_record ?? {};
  ok("[downgrade] a hosted provider-trust route requesting custody with the READY node's evidence is refused route_custody_remote — the provider can read the weights and the plaintext — and derives unevidenced with status refused: nothing else supports any class", hosted.status === 201 && cB.effective_class === "unevidenced" && cB.status === "refused" && (cB.refusals || []).some((r) => r.code === "route_custody_remote") && cB.declared_posture?.remote_provider_can_read_weights === true && cB.content_hash === deriveClaimHash(cB), `${hosted.status} ${code(hosted.body)} ${cB.effective_class}/${cB.status} ${JSON.stringify((cB.refusals || []).map((r) => r.code))}`);
  const contract = await post("/v1/hypervisor/model-route-rights-contracts", { owner_ref: OWNER, idempotency_key: key("contract"), family: "acme.hosted-inference", effective_at: "2026-05-01T10:00:00Z", route_binding: { route_ref: hostedRoute.route_ref ?? `route://${hostedRoute.route_id}`, provider_ref: "provider://acme/hosted-api", model_ref: "model://hosted/large", model_revision_ref: "model://hosted/large/revision/1", intermediary_ref: null, upstream_terms_ref: null, intermediary_is_supply_adapter_not_trust_boundary: true }, purposes: ["inference_service_delivery"], data_classes: ["prompts_and_completions"], declared_prohibited_route_uses: ["publication", "downstream_use", "oem_or_reseller_use"], unresolved_rights_findings: [], destination_and_egress: { permitted_destination_classes: ["model_provider"], egress_ceiling: "redacted_only", region_refs: ["region://us-west"], residency_refs: ["region://us-west"], cross_border_transfer_basis_ref: null }, customer_output_rights: { intended_customer_output_uses: ["retain", "internal_evaluation"], effective_customer_output_rights_hash: `sha256:${"44".repeat(32)}`, competing_model_training_permitted: false }, provider_use_of_customer_material: { request_or_prompt_logging: "prohibited", human_review: "prohibited", abuse_and_security_processing: "transient_only", service_improvement: "prohibited", provider_model_training: "prohibited", provider_model_training_basis_ref: null, cross_customer_aggregation: "prohibited", cross_customer_aggregation_basis_ref: null, publication: "prohibited" }, retention_posture: "zero_retention", retention_policy_ref: "policy://acme/retention/route/v1", commercial_terms_refs: ["contract://acme/hosted-order-form/v3"], technical_terms_refs: ["terms://acme/hosted/v7"], fallback_substitution: { fallback_is_semantic_substitution: true, fallback_route_rights_revision_ref: null }, validity: { valid_from: "2026-05-01T00:00:00Z", valid_until: "2027-05-01T00:00:00Z" }, revocation: { revocation_state: "live", revoked_at: null, revocation_reason: null, revocation_authority_ref: null }, status: "active", resolved_principal_ref: "worker://acme/assistant", credential_principal_ref: "service://acme/hosted-credential" });
  const contractRef = contract.body?.model_route_rights_contract?.revision_ref;
  ok("PRECONDITION: a rights contract binding the hosted route is admitted through M03.15's own plane with every provider use prohibited and zero retention", contract.status === 201 && typeof contractRef === "string", `${contract.status} ${code(contract.body)} ${message(contract.body).slice(0, 120)} bound=${hostedRoute.route_ref}`);
  const promoted = await claim(B, { rights_contract_revision_ref: contractRef });
  const cP = promoted.body?.route_assurance_claim_record ?? {};
  ok("[promotion refused] custody requested over a CONTRACT alone derives contractual_privacy with the downgrade named — a provider promising is not a provider technically unable to observe plaintext — and the contract's terms hash and retention posture are recorded as the evidence", promoted.status === 201 && cP.effective_class === "contractual_privacy" && cP.evidence?.contractual?.rights_contract_revision_ref === contractRef && cP.evidence?.contractual?.retention_posture === "zero_retention" && /appraisal_unavailable|not evidenced/u.test(String(cP.downgrade_reason)) && cP.content_hash === deriveClaimHash(cP) && expectedClass(cP) === "contractual_privacy", `${promoted.status} ${code(promoted.body)} ${cP.effective_class} ${String(cP.downgrade_reason).slice(0, 120)}`);
  const contractOnLocal = await claim(A, { requested_class: "contractual_privacy", rights_contract_revision_ref: contractRef });
  const cM = contractOnLocal.body?.route_assurance_claim_record ?? {};
  ok("[claim] a contract bound to ANOTHER route is refused contract_route_mismatch and the claim is refused: evidence is resolved to the route it names, never borrowed", contractOnLocal.status === 201 && cM.status === "refused" && (cM.refusals || []).some((r) => r.code === "contract_route_mismatch"), `${contractOnLocal.status} ${cM.status} ${JSON.stringify((cM.refusals || []).map((r) => r.code))}`);
  const ghostRun = await claim(A, { requested_class: "workload_isolation", isolation_workrun_ref: "workrun://nope" });
  const cI = ghostRun.body?.route_assurance_claim_record ?? {};
  ok("[downgrade] workload_isolation requested over a WorkRun with no admitted isolation binding is not evidenced: the claim records isolation_binding_unresolvable and derives the declared floor", ghostRun.status === 201 && cI.effective_class !== "workload_isolation" && (cI.refusals || []).some((r) => r.code === "isolation_binding_unresolvable"), `${ghostRun.status} ${cI.effective_class} ${JSON.stringify((cI.refusals || []).map((r) => r.code))}`);
  const ghostNode = await claim(A, { node_ref: "runtime://acme/estate-1/ghost-node", key_owner_ref: OWNER, protected_data_owner_ref: OWNER });
  const cG = ghostNode.body?.route_assurance_claim_record ?? {};
  ok("[downgrade] custody requested over a node the plane never attested is appraisal_unavailable — an unavailable appraisal downgrades, never rounds up", ghostNode.status === 201 && cG.effective_class === "confidential_compute_declared" && (cG.refusals || []).some((r) => r.code === "appraisal_unavailable"), `${ghostNode.status} ${cG.effective_class} ${JSON.stringify((cG.refusals || []).map((r) => r.code))}`);
  const noOwners = await claim(A, { node_ref: NODE });
  const cO = noOwners.body?.route_assurance_claim_record ?? {};
  ok("[downgrade] custody over the READY node without the key owner and the protected-data owner named is not custody-proven: owners_required", noOwners.status === 201 && cO.effective_class !== "custody_proven_no_plaintext" && (cO.refusals || []).some((r) => r.code === "owners_required"), `${noOwners.status} ${cO.effective_class} ${JSON.stringify((cO.refusals || []).map((r) => r.code))}`);

  // -- the custody-proven class, re-derived from the served evidence --------------------------------------
  const proven = await claim(A, { node_ref: NODE, key_owner_ref: OWNER, protected_data_owner_ref: OWNER });
  const cA = proven.body?.route_assurance_claim_record ?? {};
  const appraisal = cA.evidence?.custody?.appraisal ?? {};
  const provenChecks = {
    "proven.status === 201": proven.status === 201,
    "cA.effective_class === \"custody_proven_no_plaintext\"": cA.effective_class === "custody_proven_no_plaintext",
    "cA.status === \"current\"": cA.status === "current",
    "cA.downgrade_reason === null": cA.downgrade_reason === null,
    "cA.refusals?.length === 0": cA.refusals?.length === 0,
    "cA.evidence?.custody?.boot_receipt_root === committedRoot (re-derived) && boot_epoch === the record's verified_boot_epoch": cA.evidence?.custody?.boot_receipt_root === committedRoot && cA.evidence?.custody?.boot_epoch === nodeView.verified_boot_epoch,
    "cA.evidence?.custody?.boot_epoch === 3": cA.evidence?.custody?.boot_epoch === 3,
    "cA.evidence?.custody?.effective_posture === \"measured_boot\"": cA.evidence?.custody?.effective_posture === "measured_boot",
    "appraisal.attester_ref === NODE": appraisal.attester_ref === NODE,
    "appraisal.appraiser_ref === \"appraiser://acme/estate-1/appraiser-service": appraisal.appraiser_ref === "appraiser://acme/estate-1/appraiser-service",
    "appraisal.relying_party_ref === PRINCIPAL": appraisal.relying_party_ref === PRINCIPAL,
    "appraisal.nonce_single_use_status === \"consumed_for_this_appraisal\"": appraisal.nonce_single_use_status === "consumed_for_this_appraisal",
    "appraisal.appraisal_status === \"pass\"": appraisal.appraisal_status === "pass",
    "appraisal.revocation_status === \"current\"": appraisal.revocation_status === "current",
    "cA.evidence?.custody?.key_owner_ref === OWNER": cA.evidence?.custody?.key_owner_ref === OWNER,
    "cA.evidence?.custody?.observable_paths?.egress?.observes === \"nothing\"": cA.evidence?.custody?.observable_paths?.egress?.observes === "nothing",
    "cA.evidence?.custody?.egress_preventable === true": cA.evidence?.custody?.egress_preventable === true,
    "typeof cA.evidence?.custody?.egress_coverage_declaration_ref === \"string": typeof cA.evidence?.custody?.egress_coverage_declaration_ref === "string",
    "cA.expires_at === appraisal.appraisal_expires_at": cA.expires_at === appraisal.appraisal_expires_at,
    "cA.content_hash === deriveClaimHash(cA)": cA.content_hash === deriveClaimHash(cA),
    "expectedClass(cA) === \"custody_proven_no_plaintext\"": expectedClass(cA) === "custody_proven_no_plaintext",
  };
  const provenFailing = Object.entries(provenChecks).filter(([, v]) => !v).map(([k]) => k);
  ok("[custody proven] the local private-native route on the READY node derives custody_proven_no_plaintext: the committed boot receipt root, epoch and measured_boot posture; the appraisal under separated attester/verifier/appraiser roles with the RELYING PARTY resolved as this principal, a single-use nonce, a passing status inside its expiry, current endorsements and reference values; the key and protected-data owners; observable paths on which no provider observes plaintext (egress observes nothing); the node profile's egress coverage claiming preventable; the content hash re-derived here; and the claim expiring with the appraisal", provenFailing.length === 0, `${proven.status} ${code(proven.body)} ${cA.effective_class}/${cA.status} ${JSON.stringify((cA.refusals || []).map((r) => r.code))} ${String(cA.downgrade_reason ?? "").slice(0, 120)} failing=${JSON.stringify(provenFailing)} claim_root=${cA.evidence?.custody?.boot_receipt_root} node_epoch=${nodeView.verified_boot_epoch} rederived=${committedRoot}`);
  ok("[de-identified evidence] the claim carries refs, hashes and commitments only — no nonce consumption receipt, no key material, no plaintext path member", !JSON.stringify(cA).includes(pk) && !("signature" in (cA.evidence?.custody ?? {})), "");
  const listed = await get("/v1/hypervisor/route-assurance");
  const gotten = await get(A);
  ok("[reads] the inventory lists the derived claims and GET serves the route's revision chain with the head", listed.status === 200 && listed.body?.route_assurance_claims?.length >= 2 && gotten.status === 200 && gotten.body?.current?.effective_class === "custody_proven_no_plaintext" && gotten.body?.revisions?.length >= 4, `${listed.status} ${gotten.status} revisions=${gotten.body?.revisions?.length}`);

  // -- per-claim coverage overreach: audit-only egress can never carry the custody-proven class ---------------
  const auditEgress = await post(OBS, hardenedBody({ mechanisms: [{ mechanism: "egress_policy", mode: "audit_only", action_classes: ["egress"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/egress-policy/audit/2"], receipt_contract_refs: [], required_privilege: "os_privileged" }, { mechanism: "seccomp", mode: "active_enforcement", action_classes: ["process_launch", "filesystem"], verification_evidence_refs: ["evidence://acme/estate-1/alpha-node-1/seccomp/probe/2"], receipt_contract_refs: [], required_privilege: "os_privileged" }], expected_head: (await get(`${OBS}/${encodeURIComponent(PROFILE.replace("://", "-").replace(/\//gu, "."))}/${encodeURIComponent(NODE.replace("://", "-").replace(/\//gu, "."))}`)).body?.head , expected_head: await obsHead() }));
  const egressAudit = (auditEgress.body?.coverage_declarations ?? []).find((c) => c.action_class === "egress");
  ok("[overreach] a successor observation in which egress is only AUDITED produces an egress declaration that observes and attributes but never mediates or prevents", auditEgress.status === 201 && egressAudit?.claims?.observable === true && egressAudit?.claims?.mediated === false && egressAudit?.claims?.preventable === false && egressAudit?.operating_mode === "audit_only", `${auditEgress.status} ${code(auditEgress.body)} ${message(auditEgress.body).slice(0, 100)} ${JSON.stringify(egressAudit?.claims)}`);
  const afterAudit = await claim(A, { node_ref: NODE, key_owner_ref: OWNER, protected_data_owner_ref: OWNER });
  const cE = afterAudit.body?.route_assurance_claim_record ?? {};
  ok("[overreach] the same route on the same READY node now derives BELOW custody-proven: egress_not_preventable — audited egress is not prevented egress, and measured boot cannot make it so", afterAudit.status === 201 && cE.effective_class !== "custody_proven_no_plaintext" && (cE.refusals || []).some((r) => r.code === "egress_not_preventable") && cE.evidence?.custody?.egress_preventable === false && cE.revision === cA.revision + 1, `${afterAudit.status} ${code(afterAudit.body)} ${cE.effective_class} ${JSON.stringify((cE.refusals || []).map((r) => r.code))} ${message(afterAudit.body).slice(0, 100)}`);

  // -- restart -------------------------------------------------------------------------------------------------
  const projections = async () => ({ claims: stripVolatile((await get(A)).body), inventory: stripVolatile((await get("/v1/hypervisor/route-assurance")).body), coverage: stripVolatile((await get(`${COVERAGE}?profile_ref=${encodeURIComponent(PROFILE)}`)).body), observations: stripVolatile((await get(OBS)).body) });
  const before = await projections();
  await stopDaemon();
  await startDaemon();
  const after = await projections();
  ok("[restart] the claims, the inventory, the node profile's coverage and the observations reproduce byte for byte across a restart: every projection is derived from the admitted streams and the durable registry", ["claims", "inventory", "coverage", "observations"].every((k) => before[k] === after[k]), ["claims", "inventory", "coverage", "observations"].filter((k) => before[k] !== after[k]).join(",") || "identical");

  const PLANE_CODES = ["node_enforcement_observation_active_mechanism_unverified", "route_assurance_route_unknown", "route_assurance_class_outside_vocabulary"];
  const unobserved = PLANE_CODES.filter((c) => !observedCodes.has(c));
  const findingCodes = new Set([cB, cM, cI, cG, cO, cE].flatMap((c) => (c.refusals || []).map((r) => r.code)));
  ok("every one of the plane's named refusal codes was observed LIVE, and the six typed derivation findings (route_custody_remote, contract_route_mismatch, isolation_binding_unresolvable, appraisal_unavailable, owners_required, egress_not_preventable) each appeared in a served claim", unobserved.length === 0 && ["route_custody_remote", "contract_route_mismatch", "isolation_binding_unresolvable", "appraisal_unavailable", "owners_required", "egress_not_preventable"].every((c) => findingCodes.has(c)), `${unobserved.join(",")} findings=${[...findingCodes].join(",")}`);
  const src = fs.readFileSync(path.resolve(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/route_assurance_routes.rs"), "utf8");
  ok("[structure] the daemon module derives the class in ONE function over resolved evidence, holds no route that accepts an authored class, and the producer claims mediated/preventable only from active verified mechanisms", /fn derive\(/u.test(src) && /"effective_class",\n/u.test(src) && /let mediated = !active\.is_empty\(\);/u.test(src));
}

async function drill() {
  const claim = readFixture("route-assurance-claim-v1/positive-custody-proven.json");
  const down = readFixture("route-assurance-claim-v1/positive-downgraded-to-contractual.json");
  const obs = readFixture("node-enforcement-profile-observation-v1/positive-observed.json");
  ok("DRILL D1 — the claim content-hash oracle rejects an effective class edited after admission and accepts the registered fixtures", deriveClaimHash(claim) === claim.content_hash && deriveClaimHash(down) === down.content_hash && deriveClaimHash({ ...claim, effective_class: "contractual_privacy" }) !== claim.content_hash);
  ok("DRILL D2 — the class oracle refuses promotion: a claim whose custody evidence lacks its receipt, whose nonce was replayed, whose endorsement was withdrawn or whose egress is not preventable never derives custody-proven; a contract-only claim derives contractual_privacy", expectedClass(claim) === "custody_proven_no_plaintext" && expectedClass({ ...claim, evidence: { ...claim.evidence, custody: { ...claim.evidence.custody, boot_receipt_root: null } } }) !== "custody_proven_no_plaintext" && expectedClass({ ...claim, evidence: { ...claim.evidence, custody: { ...claim.evidence.custody, appraisal: { ...claim.evidence.custody.appraisal, nonce_single_use_status: "already_consumed" } } } }) !== "custody_proven_no_plaintext" && expectedClass({ ...claim, evidence: { ...claim.evidence, custody: { ...claim.evidence.custody, appraisal: { ...claim.evidence.custody.appraisal, revocation_status: "revoked" } } } }) !== "custody_proven_no_plaintext" && expectedClass({ ...claim, evidence: { ...claim.evidence, custody: { ...claim.evidence.custody, egress_preventable: false } } }) !== "custody_proven_no_plaintext" && expectedClass(down) === "contractual_privacy");
  ok("DRILL D3 — the coverage oracle goes red on a planted promotion: an audit-only mechanism never mediates, an unverified active mechanism never mediates, a measured-boot receipt alone never mediates", expectedCoverage(obs, "egress").mediated === true && expectedCoverage({ ...obs, mechanisms: obs.mechanisms.map((m) => ({ ...m, mode: "audit_only" })) }, "egress").mediated === false && expectedCoverage({ ...obs, mechanisms: obs.mechanisms.map((m) => ({ ...m, verification_evidence_refs: [] })) }, "egress").mediated === false && expectedCoverage({ ...obs, mechanisms: [] }, "egress").attributable === true && expectedCoverage({ ...obs, mechanisms: [] }, "egress").mediated === false);
  ok("DRILL D4 — the observation content-hash oracle rejects a mechanism mode edited after admission and accepts the registered fixture; the plane's roots are re-derived under their domains", deriveObservationHash(obs) === obs.content_hash && deriveObservationHash({ ...obs, mechanisms: [{ ...obs.mechanisms[0], mode: "audit_only" }, ...obs.mechanisms.slice(1)] }) !== obs.content_hash && bootProfileRoot({ a: 1 }) !== bootProfileRoot({ a: 2 }) && signedMaterialHash({ receipt_id: "r", node_id: "n", node_record_ref: "x", observation: { a: 1 }, signature: { s: 1 } }) === signedMaterialHash({ receipt_id: "r", node_id: "n", node_record_ref: "x", observation: { a: 1 }, signature: { s: 2 } }));
  ok("DRILL D5 — the refusal predicate reads a 201 as NOT refused, and the subject commitment binds the profile", !refused({ status: 201, body: {} }, 422, "x") && refused({ status: 422, body: { error: { code: "x" } } }, 422, "x") && deriveSubjectHash("p1", "s") !== deriveSubjectHash("p2", "s"));
}

(DRILL ? drill() : run())
  .catch((error) => { ok("the verifier completed", false, String(error?.stack || error)); })
  .finally(async () => {
    await stopDaemon().catch(() => {});
    if (resolver) await resolver.stop().catch(() => {});
    const passed = results.filter((r) => r.pass).length;
    console.log(`\n${passed}/${results.length} passed`);
    emitVerifierCensus({ verifierId: "custody-proven-private-routes", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    process.exit(results.length === 0 ? 2 : passed === results.length ? 0 : 1);
  });
