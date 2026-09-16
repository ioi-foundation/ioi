// verify-hypervisor-provider-connection-lifecycle — M03.16 driven against an ISOLATED daemon with a
// STUB OAUTH PROVIDER the daemon talks to over the wire (authorize, token, userinfo, discovery, DCR),
// as M10.4 drove stub model servers. Connected is not authorized.
//
// What it proves, live: a registered single-use ceremony bound to the RESOLVED principal and the
// exact provider profile revision; every completion refusal admitted as the ceremony's own
// `refused` successor (another principal, redirect drift, profile drift, exchange failure, scope
// widening, account substitution, unresolvable subject, consumed, expired); the binding's
// commitments re-derived here from the records alone (content hash, provider profile revision,
// account subject); the credential sealed under the connection's coordinates with the raw tokens
// appearing NOWHERE in plaintext; THE FENCE at the single brokered-use gateway (428 vs 403 tells
// "credential resolved" from "credential fenced" without any wallet grant); verify observing
// provider revocation and advancing the epoch; reauthorize and reconnect as successor versions with
// successor credential bindings that never revive a predecessor; disconnect with durable dependent
// obligations; the legacy connector `oauth/start`/`callback` alias sharing the same lineage; restart
// reproducing every projection with the fence still holding; the offline verifier over the served
// chain. Exit: 0 pass · 1 fail · 2 blocked. `--mutation` drills the verifier's own oracles.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import {
  credentialIsFenced,
  deriveBindingHash,
  deriveCeremonyHash,
  deriveProviderProfileRef,
  deriveSubjectHash,
  pkceChallenge,
  verifyCeremony,
  verifyConnectionChain,
} from "./lib/provider-connection-offline-verifier.mjs";

const DRILL = process.argv.includes("--mutation");
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "../../..");
const results = [];
const observedCodes = new Set();
const ok = (name, pass, detail = "") => { results.push({ name, pass: !!pass, detail }); console.log(`${pass ? "PASS" : "FAIL"}  ${name}${pass ? "" : `  (${detail})`}`); };

// ------------------------------------------------------------------------------- the stub provider
// One OAuth authorization server the daemon reaches over HTTP. Modes are set by the verifier between
// requests: which subject to return, whether to include an id_token, whether to widen the scope,
// whether refresh is revoked, and whether the code is known.
const provider = { subject: "acct-1", tenant: "tenant-1", idToken: true, widen: false, revoked: false, tokenCalls: [], refreshCalls: 0, codes: new Map(), clientIds: 0, userinfoCalls: 0 };
const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const makeIdToken = (sub, tid) => `${b64url({ alg: "none", typ: "JWT" })}.${b64url({ sub, tid, iss: "stub" })}.sig`;
function startProvider() {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, "http://127.0.0.1");
      const origin = `http://127.0.0.1:${server.address().port}`;
      const send = (status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
      let raw = ""; for await (const chunk of req) raw += chunk;
      if (url.pathname === "/.well-known/oauth-protected-resource") return send(200, { resource: origin, authorization_servers: [origin], scopes_supported: ["mail.read", "mail.send"] });
      if (url.pathname === "/.well-known/oauth-authorization-server") return send(200, { issuer: origin, authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, registration_endpoint: `${origin}/register`, userinfo_endpoint: `${origin}/userinfo` });
      if (url.pathname === "/register") { provider.clientIds += 1; return send(201, { client_id: `dcr_${provider.clientIds}` }); }
      if (url.pathname === "/authorize") {
        const code = `code_${crypto.randomBytes(8).toString("hex")}`;
        provider.codes.set(code, { challenge: url.searchParams.get("code_challenge"), redirect: url.searchParams.get("redirect_uri"), client: url.searchParams.get("client_id"), scope: url.searchParams.get("scope"), state: url.searchParams.get("state") });
        res.writeHead(302, { location: `${url.searchParams.get("redirect_uri")}?state=${encodeURIComponent(url.searchParams.get("state"))}&code=${code}` }); return res.end();
      }
      if (url.pathname === "/token") {
        const form = new URLSearchParams(raw);
        if (form.get("grant_type") === "refresh_token") { provider.refreshCalls += 1; if (provider.revoked) return send(400, { error: "invalid_grant" }); return send(200, { access_token: `at_refreshed_${provider.refreshCalls}`, token_type: "bearer", expires_in: 3600 }); }
        const issued = provider.codes.get(form.get("code"));
        provider.tokenCalls.push({ code: form.get("code"), verifier: form.get("code_verifier"), redirect: form.get("redirect_uri"), client: form.get("client_id") });
        if (!issued) return send(400, { error: "invalid_grant" });
        if (pkceChallenge(form.get("code_verifier") || "") !== issued.challenge) return send(400, { error: "invalid_grant", error_description: "pkce" });
        if (form.get("redirect_uri") !== issued.redirect) return send(400, { error: "invalid_grant", error_description: "redirect" });
        provider.codes.delete(form.get("code"));
        const body = { access_token: `at_${crypto.randomBytes(12).toString("hex")}`, refresh_token: `rt_${crypto.randomBytes(12).toString("hex")}`, token_type: "bearer", expires_in: 3600, scope: provider.widen ? `${issued.scope} admin.all` : issued.scope };
        if (provider.idToken) body.id_token = makeIdToken(provider.subject, provider.tenant);
        provider.lastTokens = body;
        return send(200, body);
      }
      if (url.pathname === "/userinfo") { provider.userinfoCalls += 1; if (provider.revoked) return send(401, { error: "invalid_token" }); return send(200, { sub: provider.subject, tid: provider.tenant }); }
      send(404, { error: "not_found" });
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, origin: `http://127.0.0.1:${server.address().port}` }));
  });
}

// ------------------------------------------------------------------------------------ the daemon
const daemonBinary = path.resolve(ROOT, process.env.IOI_HYPERVISOR_DAEMON_BINARY ?? "target/debug/hypervisor-daemon");
let daemon = null, daemonLog = "", daemonPort = 0, DAEMON = "", SESSION = "", OWNER = "", PRINCIPAL = "", SESSION_B = "", PRINCIPAL_B = "";
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-provider-connection-"));
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => resolve(p)); }); });
const waitFor = async (url, ms) => { const until = Date.now() + ms; while (Date.now() < until) { try { const r = await fetch(url); if (r.ok) return true; } catch { /* not yet */ } await new Promise((r) => setTimeout(r, 200)); } return false; };
async function startDaemon(extraEnv = {}) {
  daemon = spawn(daemonBinary, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}`, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:1/v1", IOI_WALLET_SECRET_PASS: "ioi-provider-connection-verifier", ...extraEnv }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  daemon.stderr.on("data", (c) => { daemonLog = `${daemonLog}${c}`.slice(-64000); });
  await waitFor(`${DAEMON}/healthz`, 30000);
}
const stopDaemon = async () => { if (!daemon) return; const child = daemon; daemon = null; child.kill("SIGTERM"); await new Promise((resolve) => { const t = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* gone */ } resolve(); }, 8000); child.on("exit", () => { clearTimeout(t); resolve(); }); }); };
const jd = (p, init = {}, session = SESSION) => fetch(`${DAEMON}${p}`, { ...init, headers: { "content-type": "application/json", ...(session ? { cookie: `ioi_session=${session}` } : {}), ...(init.headers || {}) } }).then(async (r) => { const body = await r.json().catch(() => ({})); const c = body?.code ?? body?.error?.code ?? body?.reason; if (typeof c === "string" && c) observedCodes.add(c); return { status: r.status, body }; }).catch(() => ({ status: 0, body: {} }));
const post = (p, body, session = SESSION) => jd(p, { method: "POST", body: JSON.stringify(body) }, session);
const get = (p, session = SESSION) => jd(p, {}, session);
const code = (body) => body?.code ?? body?.error?.code ?? body?.reason ?? "";
const message = (body) => body?.error?.message ?? body?.message ?? "";
const refused = (reply, status, expected) => reply.status === status && code(reply.body) === expected;
const stripVolatile = (v) => JSON.stringify(v, (k, x) => (k === "updated_at" || k === "at" ? undefined : x));

const CONNECTIONS = "/v1/hypervisor/auth/connections";
const REDIRECT = "http://127.0.0.1:4173/__ioi/integrations/oauth/callback";
let n = 0; const key = (label) => `pcl-${label}-${++n}`;
const startBody = (connectorId, over = {}) => ({ owner_ref: OWNER, idempotency_key: key("start"), connector_id: connectorId, redirect_uri: REDIRECT, requested_scopes: ["mail.read", "mail.send"], ...over });
async function authorize(authorizeUrl) {
  // Follow the provider's redirect by hand: the browser would; here the verifier is the browser.
  const r = await fetch(authorizeUrl, { redirect: "manual" });
  const loc = r.headers.get("location") || "";
  const u = new URL(loc);
  return { status: r.status, state: u.searchParams.get("state"), code: u.searchParams.get("code"), redirect: `${u.origin}${u.pathname}` };
}
async function completeFlow(startReply, over = {}) {
  const auth = await authorize(startReply.body.authorize_url);
  return post(`${CONNECTIONS}/authorization/complete`, { owner_ref: OWNER, idempotency_key: key("complete"), state: auth.state, code: auth.code, ...over });
}
async function registerConnector(name, origin, withProfile = true) {
  const r = await post("/v1/hypervisor/connectors", { service: `pcl-${name}`, base_url: origin, name: `PCL ${name}`, kind: "http", requires_credential: true, allowed_tools: [{ name: "mail.list", method: "GET", path: "/mail" }], ...(withProfile ? { auth_profile: { type: "oauth_authcode_pkce", authorization_endpoint: `${origin}/authorize`, token_endpoint: `${origin}/token`, userinfo_endpoint: `${origin}/userinfo`, client_id: `client_${name}`, scopes: ["mail.read", "mail.send"] } } : {}) });
  return r.body?.connector ?? {};
}
const credentialRecord = (connectorId) => { try { return JSON.parse(fs.readFileSync(path.join(dataDir, "connector-credentials", `${connectorId}.json`), "utf8")); } catch { return null; } };
function plaintextLeak(needles) {
  const hits = [];
  const walk = (dir) => { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const p = path.join(dir, entry.name); if (entry.isDirectory()) walk(p); else if (entry.isFile()) { const text = fs.readFileSync(p, "latin1"); for (const needle of needles) if (needle && text.includes(needle)) hits.push(`${path.relative(dataDir, p)}:${needle.slice(0, 8)}`); } } };
  walk(dataDir); return hits;
}
async function invoke(connectorId) { return post(`/v1/hypervisor/connectors/${encodeURIComponent(connectorId)}/invoke`, { tool: "mail.list", input: {} }); }
// The gateway resolves the credential FIRST (428 when missing or fenced) and only then asks the
// authority stage, which on this fixture answers its own typed refusal (no wallet grant, no
// authority provider). So "resolved" reads as the AUTHORITY stage's answer, never a 428.
const resolvedThroughToAuthority = (reply) => [403, 501].includes(reply.status) && /authority_required/u.test(code(reply.body));

// ------------------------------------------------------------------------------------------ run
async function run() {
  const stub = await startProvider();
  daemonPort = await freePort(); DAEMON = `http://127.0.0.1:${daemonPort}`;
  await startDaemon();
  const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (token) { const boot = await jd("/v1/hypervisor/auth/bootstrap", { method: "POST", body: JSON.stringify({ token, password: "provider-connection-v1", email: "provider-connection-a@ioi.local" }) }, ""); SESSION = boot.body?.session_token || boot.body?.session?.token || ""; }
  const who = (await get("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find((t) => typeof t === "string" && (t.startsWith("org://") || t.startsWith("project://"))) || "";
  PRINCIPAL = who.principal?.principal_ref ?? "";
  const createdB = await post("/v1/hypervisor/principals", { email: "provider-connection-b@ioi.local", name: "Principal B", role: "member", password: "provider-connection-v1-B" });
  const pidB = createdB.body?.principal?.principal_id ?? "";
  await post(`/v1/hypervisor/principals/${pidB}/tenant-memberships`, { tenant_ref: OWNER, expected_revision: 0, idempotency_key: "pcl-grant-b", reason: "verifier fixture: a second member of the organization" });
  const loginB = await post("/v1/hypervisor/auth/login", { email: "provider-connection-b@ioi.local", password: "provider-connection-v1-B" }, "");
  SESSION_B = loginB.body?.session_token ?? "";
  PRINCIPAL_B = ((await get("/v1/hypervisor/auth/whoami", SESSION_B)).body?.principal?.principal_ref) ?? "";
  ok("operator bootstrap yields an authenticated session with an owner tenant and a RESOLVED principal, and a second real principal in the same organization logs in separately", SESSION.startsWith("ioi_sess_") && !!OWNER && PRINCIPAL.startsWith("user://") && PRINCIPAL_B.startsWith("user://") && PRINCIPAL_B !== PRINCIPAL, `${OWNER} ${PRINCIPAL} ${PRINCIPAL_B}`);

  const c1 = await registerConnector("mail", stub.origin);
  const c2 = await registerConnector("bare", stub.origin, false);
  const c3 = await registerConnector("drift", stub.origin);
  ok("PRECONDITION: connectors are registered in the connector estate — one with an OAuth profile pointing at the stub provider, one without", !!c1.connector_id && !!c2.connector_id && !!c3.connector_id && c1.auth_profile?.token_endpoint === `${stub.origin}/token`, `${c1.connector_id} ${c2.connector_id}`);

  // -- start: refusals --------------------------------------------------------------------------------
  const unknown = await post(`${CONNECTIONS}/authorization/start`, startBody("cnx_nope"));
  ok("[start] an unregistered connector is refused 404: a ceremony binds a registered provider profile, never a name", refused(unknown, 404, "provider_connection_ceremony_connector_unknown"), `${unknown.status} ${code(unknown.body)}`);
  const noProfile = await post(`${CONNECTIONS}/authorization/start`, startBody(c2.connector_id));
  ok("[start] a connector without an OAuth profile is refused 409 profile_missing", refused(noProfile, 409, "provider_connection_ceremony_profile_missing"), `${noProfile.status} ${code(noProfile.body)}`);
  const authored = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id, { state: "mine", proof: { kind: "pkce_s256" } }));
  ok("[start] authoring the state or the proof is refused by name: state, nonce, challenge, profile revision, issue and expiry are all server-resolved", authored.status === 422 || authored.status === 400, `${authored.status} ${code(authored.body)}`);
  const unknownField = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id, { fitness: 1 }));
  ok("[start] an unknown field is refused by name", refused(unknownField, 400, "provider_connection_ceremony_request_unknown_field"), `${unknownField.status} ${code(unknownField.body)}`);
  const noRedirect = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id, { redirect_uri: "" }));
  ok("[start] a ceremony without an exact redirect is refused", refused(noRedirect, 422, "provider_connection_ceremony_redirect_required"), `${noRedirect.status} ${code(noRedirect.body)}`);
  const badAudience = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id, { permitted_audience_classes: ["everyone"] }));
  ok("[start] an audience class outside the vocabulary is refused", refused(badAudience, 422, "provider_connection_ceremony_audience_class_outside_vocabulary"), `${badAudience.status} ${code(badAudience.body)}`);
  const badCustody = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id, { credential_custody_profile_ref: "somewhere" }));
  ok("[start] a connection without a custody profile is refused: missing custody is a refusal, not a default", refused(badCustody, 422, "provider_connection_ceremony_custody_profile_required"), `${badCustody.status} ${code(badCustody.body)}`);

  // -- start: the ceremony ---------------------------------------------------------------------------
  const firstKey = key("start");
  const started = await post(`${CONNECTIONS}/authorization/start`, { ...startBody(c1.connector_id), idempotency_key: firstKey });
  const cer = started.body?.provider_connection_ceremony_record ?? {};
  const cerFindings = verifyCeremony(cer, { connector: c1 });
  ok("[ceremony] start admits a single-use, expiring ceremony bound to the RESOLVED principal, the connector and the exact provider profile revision — re-derived here from the connector's auth profile — with an S256 challenge, the requested scopes, custody, audience and session origin, status issued, and its content hash re-derived here", started.status === 201 && cer.status === "issued" && cer.principal_ref === PRINCIPAL && cer.owner_ref === OWNER && cer.connector_ref === `connector://${c1.connector_id}` && cer.provider_profile_ref === deriveProviderProfileRef(c1) && cer.content_hash === deriveCeremonyHash(cer) && cerFindings.length === 0 && Date.parse(cer.expires_at) - Date.parse(cer.issued_at) === 600000 && !("sealed_verifier" in cer) && !("code_verifier" in cer), `${started.status} ${code(started.body)} ${message(started.body).slice(0, 100)} findings=${cerFindings.join(";")}`);
  const authorizeUrl = String(started.body?.authorize_url ?? "");
  ok("[ceremony] the authorize URL carries the ceremony's state, nonce, S256 challenge and the requested scopes, and the PKCE verifier appears nowhere in the response or the record", authorizeUrl.startsWith(`${stub.origin}/authorize?`) && authorizeUrl.includes(`state=${encodeURIComponent(cer.state)}`) && authorizeUrl.includes(`code_challenge=${encodeURIComponent(cer.proof?.code_challenge)}`) && authorizeUrl.includes("code_challenge_method=S256") && !JSON.stringify(started.body).includes("verifier"), authorizeUrl.slice(0, 120));
  const replayed = await post(`${CONNECTIONS}/authorization/start`, { ...startBody(c1.connector_id), idempotency_key: firstKey });
  ok("[ceremony] an exact retry replays the same ceremony and the same state rather than minting a second", replayed.status === 200 && replayed.body?.provider_connection_ceremony_record?.ceremony_ref === cer.ceremony_ref && replayed.body?.state === cer.state, `${replayed.status} ${replayed.body?.state === cer.state}`);

  // -- complete: refusals, each admitted as the ceremony's own successor --------------------------------
  const ghost = await post(`${CONNECTIONS}/authorization/complete`, { owner_ref: OWNER, idempotency_key: key("c"), state: "st_never_issued", code: "x" });
  ok("[complete] an unknown state completes nothing (404)", refused(ghost, 404, "provider_connection_ceremony_unknown"), `${ghost.status} ${code(ghost.body)}`);
  const authB = await authorize(authorizeUrl);
  const byB = await post(`${CONNECTIONS}/authorization/complete`, { owner_ref: OWNER, idempotency_key: key("c"), state: authB.state, code: authB.code }, SESSION_B);
  ok("[complete] a completion by ANOTHER principal in the same organization is refused 403: the ceremony completes only under the principal that initiated it", byB.status === 403, `${byB.status} ${code(byB.body)}`);
  const drift = await post(`${CONNECTIONS}/authorization/complete`, { owner_ref: OWNER, idempotency_key: key("c"), state: authB.state, code: authB.code, redirect_uri: "http://127.0.0.1:9999/elsewhere" });
  const driftCer = drift.body?.ceremony ?? {};
  ok("[complete] redirect drift is refused 409 and ADMITTED as the ceremony's `refused` successor naming the code, so the chain says why the state token died", refused(drift, 409, "provider_connection_ceremony_redirect_drift") && driftCer.status === "refused" && driftCer.refusal?.code === "redirect_drift" && driftCer.content_hash === deriveCeremonyHash(driftCer), `${drift.status} ${code(drift.body)} ${driftCer.status} ${driftCer.refusal?.code}`);
  const consumed = await post(`${CONNECTIONS}/authorization/complete`, { owner_ref: OWNER, idempotency_key: key("c"), state: authB.state, code: authB.code });
  ok("[complete] a refused ceremony is consumed: a second completion is refused 404 (state index gone) or 409 (chain head moved) — never a second chance", [404, 409].includes(consumed.status), `${consumed.status} ${code(consumed.body)}`);

  const s2 = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id));
  const badCode = await post(`${CONNECTIONS}/authorization/complete`, { owner_ref: OWNER, idempotency_key: key("c"), state: s2.body?.state, code: "code_forged" });
  ok("[complete] a code the provider never issued is refused 502 exchange_failed and the ceremony is closed refused", refused(badCode, 502, "provider_connection_ceremony_exchange_failed") && badCode.body?.ceremony?.status === "refused", `${badCode.status} ${code(badCode.body)}`);

  provider.widen = true;
  const s3 = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id));
  const widened = await completeFlow(s3);
  provider.widen = false;
  ok("[complete] a provider granting scopes the ceremony never requested is refused 409 scope_widened: a connection binds the requested set or less, never more", refused(widened, 409, "provider_connection_ceremony_scope_widened") && widened.body?.ceremony?.refusal?.code === "scope_widened", `${widened.status} ${code(widened.body)}`);

  const s4 = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id, { declared_account_subject: "someone-else" }));
  const substituted = await completeFlow(s4);
  ok("[complete] a provider returning a different account than the ceremony declared is refused 409 account_substituted", refused(substituted, 409, "provider_connection_ceremony_account_substituted"), `${substituted.status} ${code(substituted.body)}`);

  provider.idToken = false;
  const cNoSub = await post("/v1/hypervisor/connectors", { service: "pcl-nosub2", base_url: stub.origin, name: "PCL nosub2", kind: "http", requires_credential: true, allowed_tools: [{ name: "mail.list", method: "GET", path: "/mail" }], auth_profile: { type: "oauth_authcode_pkce", authorization_endpoint: `${stub.origin}/authorize`, token_endpoint: `${stub.origin}/token`, client_id: "client_nosub", scopes: ["mail.read"] } });
  const s5 = await post(`${CONNECTIONS}/authorization/start`, startBody(cNoSub.body?.connector?.connector_id, { requested_scopes: ["mail.read"] }));
  const noSubject = await completeFlow(s5);
  provider.idToken = true;
  ok("[complete] a provider returning no account subject (no userinfo endpoint, no id_token, no sub) with none declared is refused 422 subject_unresolvable: a connection that cannot refuse substitution is not admitted", refused(noSubject, 422, "provider_connection_ceremony_subject_unresolvable"), `${noSubject.status} ${code(noSubject.body)}`);
  const s6 = await post(`${CONNECTIONS}/authorization/start`, startBody(cNoSub.body?.connector?.connector_id, { requested_scopes: ["mail.read"], declared_account_subject: "declared-acct" }));
  provider.idToken = false;
  const declaredOk = await completeFlow(s6);
  provider.idToken = true;
  ok("[complete] with no provider subject, the OWNER'S declared account stands and the evidence records subject_source owner_declared — typed, never silent", declaredOk.status === 201 && declaredOk.body?.subject_source === "owner_declared" && declaredOk.body?.connection?.provider_account_subject_hash === deriveSubjectHash(deriveProviderProfileRef(cNoSub.body.connector), "declared-acct"), `${declaredOk.status} ${code(declaredOk.body)} ${declaredOk.body?.subject_source}`);

  // profile drift: discovery + DCR rewrites the connector's auth profile after the ceremony was issued
  const s7 = await post(`${CONNECTIONS}/authorization/start`, startBody(c3.connector_id));
  const discovered = await post(`/v1/hypervisor/connectors/${encodeURIComponent(c3.connector_id)}/oauth/discover`, { redirect_uri: REDIRECT });
  const c3after = (await get("/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === c3.connector_id) ?? {};
  const drifted = await completeFlow(s7);
  ok("[complete] a provider profile edited after issue (discovery + dynamic client registration rewrote it) cannot complete the ceremony: 409 profile_drift, and the new revision differs from the one the ceremony bound", discovered.body?.ok === true && deriveProviderProfileRef(c3after) !== s7.body?.provider_connection_ceremony_record?.provider_profile_ref && refused(drifted, 409, "provider_connection_ceremony_profile_drift"), `${discovered.status} ${code(discovered.body)} / ${drifted.status} ${code(drifted.body)}`);

  // -- complete: the binding ------------------------------------------------------------------------------
  const s8 = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id));
  const done = await completeFlow(s8);
  const v1 = done.body?.connection ?? {};
  const cerDone = done.body?.ceremony ?? {};
  const CID = done.body?.connection_id;
  const profileRef = deriveProviderProfileRef(c1);
  ok("[binding] completion admits ProviderConnectionBinding version 1: active, epoch 0, no predecessor, the RESOLVED principal, the exact provider profile revision, the account subject committed as sha256(JCS{provider_profile_ref, subject}) — re-derived here from the stub's subject — the tenant likewise, granted scopes a subset of the requested, a versioned credential binding, a current verification with evidence, a reauthorization deadline thirty days out, and its content hash re-derived here", done.status === 201 && v1.status === "active" && v1.connection_version === 1 && v1.predecessor_ref === null && v1.connection_revocation_epoch === 0 && v1.principal_ref === PRINCIPAL && v1.provider_profile_ref === profileRef && v1.provider_account_subject_hash === deriveSubjectHash(profileRef, "acct-1") && v1.provider_tenant_subject_hash === deriveSubjectHash(profileRef, "tenant:tenant-1") && (v1.provider_granted_scopes || []).every((s) => ["mail.read", "mail.send"].includes(s)) && v1.provider_granted_scopes?.length > 0 && v1.credential_binding_ref?.endsWith("@1") && v1.last_provider_verification?.status === "current" && !!v1.last_provider_verification?.evidence_ref && Math.abs(Date.parse(v1.reauthorization_required_at) - Date.now() - 30 * 86400000) < 120000 && v1.content_hash === deriveBindingHash(v1), `${done.status} ${code(done.body)} ${message(done.body).slice(0, 120)}`);
  ok("[ceremony] the ceremony's own successor is `completed`, naming connection version 1, the subject commitments, the granted scopes and the evidence, and commits itself", cerDone.status === "completed" && cerDone.completion?.connection_ref === `${v1.connection_ref}@1` && cerDone.completion?.provider_account_subject_hash === v1.provider_account_subject_hash && cerDone.completion?.evidence_ref === v1.last_provider_verification?.evidence_ref && cerDone.content_hash === deriveCeremonyHash(cerDone) && verifyCeremony(cerDone, { connector: c1 }).length === 0, JSON.stringify(cerDone.completion).slice(0, 160));
  ok("[subject source] the subject came from the provider's userinfo endpoint, which the daemon called with the fresh access token", done.body?.subject_source === "userinfo" && provider.userinfoCalls >= 1, `${done.body?.subject_source} calls=${provider.userinfoCalls}`);
  const cred1 = credentialRecord(c1.connector_id);
  ok("[custody] the sealed credential record carries the connection's coordinates (ref, version 1, epoch 0, credential binding @1) and the principal, and is a sealed oauth-refresh credential", cred1?.connection_ref === v1.connection_ref && cred1?.connection_version === 1 && cred1?.connection_revocation_epoch === 0 && cred1?.credential_binding_ref === v1.credential_binding_ref && cred1?.principal_ref === PRINCIPAL && cred1?.kind === "oauth-refresh" && typeof cred1?.sealed_refresh_token === "string", JSON.stringify(cred1 ?? {}).slice(0, 160));
  const leaks = plaintextLeak([provider.lastTokens?.access_token, provider.lastTokens?.refresh_token]);
  ok("[secret non-possession] the raw access and refresh tokens the stub issued appear NOWHERE in the daemon's data directory in plaintext — not in the credential record, the chain, the evidence or the receipts", leaks.length === 0 && !JSON.stringify(done.body).includes(provider.lastTokens?.refresh_token ?? "∅"), leaks.join(",") || "none");

  // -- reads -----------------------------------------------------------------------------------------------
  const listed = await get(CONNECTIONS);
  const gotten = await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`);
  const deps0 = await get(`${CONNECTIONS}/${encodeURIComponent(CID)}/dependents`);
  ok("[reads] the inventory lists the connection by id with its version, status and epoch; GET serves the version chain with the head; dependents is derived and empty", listed.status === 200 && listed.body?.connections?.some((c) => c.connection_id === CID && c.status === "active") && gotten.status === 200 && gotten.body?.current?.connection_version === 1 && gotten.body?.versions?.length === 1 && !!gotten.body?.head && deps0.status === 200 && deps0.body?.dependents?.lease_grants?.length === 0, `${listed.status} ${gotten.status} ${deps0.status}`);
  const gottenB = await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`, SESSION_B);
  ok("[reads] another principal cannot read the connection: the substrate's principal-bound scope holds", gottenB.status === 403 || gottenB.status === 404, `${gottenB.status} ${code(gottenB.body)}`);

  // -- THE FENCE at the single brokered-use gateway ---------------------------------------------------------
  const bareInvoke = await invoke(c2.connector_id);
  const liveInvoke = await invoke(c1.connector_id);
  ok("[fence] the brokered crossing answers 428 credential_required for a connector with no credential, and the AUTHORITY stage's own refusal for the connected one — so the credential RESOLVED through its active connection before authority was even considered", bareInvoke.status === 428 && /credential_required/u.test(code(bareInvoke.body)) && resolvedThroughToAuthority(liveInvoke), `${bareInvoke.status} ${code(bareInvoke.body)} / ${liveInvoke.status} ${code(liveInvoke.body)}`);

  // -- verify: current, then provider-observed revocation ---------------------------------------------------
  const verifyBody = async () => ({ owner_ref: OWNER, idempotency_key: key("verify"), expected_head: (await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`)).body?.head });
  const verifyB = await post(`${CONNECTIONS}/${encodeURIComponent(CID)}/verify`, await verifyBody(), SESSION_B);
  ok("[verify] another principal cannot verify or move the connection", [403, 404].includes(verifyB.status), `${verifyB.status} ${code(verifyB.body)}`);
  const verified = await post(`${CONNECTIONS}/${encodeURIComponent(CID)}/verify`, await verifyBody());
  const v2 = verified.body?.provider_connection_binding_record ?? {};
  ok("[verify] a live re-mint through the sealed refresh token succeeds at the provider and admits version 2 with a current verification and new evidence; the epoch and the credential binding are unchanged", verified.status === 201 && v2.connection_version === 2 && v2.predecessor_ref === `${v1.connection_ref}@1` && v2.last_provider_verification?.status === "current" && v2.last_provider_verification?.evidence_ref !== v1.last_provider_verification?.evidence_ref && v2.connection_revocation_epoch === 0 && v2.credential_binding_ref === v1.credential_binding_ref && provider.refreshCalls >= 1 && v2.content_hash === deriveBindingHash(v2), `${verified.status} ${code(verified.body)} ${message(verified.body).slice(0, 100)}`);
  const invokeAfterVerify = await invoke(c1.connector_id);
  ok("[fence] a verification that changed nothing but the evidence leaves the credential resolvable (the authority stage answers, not a 428): the fence keys on the credential BINDING and the epoch the head names, not on the head's version number", resolvedThroughToAuthority(invokeAfterVerify), `${invokeAfterVerify.status} ${code(invokeAfterVerify.body)} ${invokeAfterVerify.body?.cause ?? ""}`);
  provider.revoked = true;
  const revokedVerify = await post(`${CONNECTIONS}/${encodeURIComponent(CID)}/verify`, await verifyBody());
  const v3 = revokedVerify.body?.provider_connection_binding_record ?? {};
  provider.revoked = false;
  ok("[verify] the provider refusing the refresh (invalid_grant) is observed as provider_revoked: version 3 carries status provider_revoked, the epoch advanced to 1 and the evidence names the refusal", revokedVerify.status === 201 && v3.status === "provider_revoked" && v3.connection_revocation_epoch === 1 && v3.last_provider_verification?.status === "provider_revoked" && v3.content_hash === deriveBindingHash(v3), `${revokedVerify.status} ${code(revokedVerify.body)} ${v3.status} epoch=${v3.connection_revocation_epoch}`);
  const fencedInvoke = await invoke(c1.connector_id);
  ok("[fence] after provider-observed revocation the brokered crossing is fenced 428 connection_fenced with a typed cause (the head is provider_revoked) — synchronously, with no cleanup awaited", fencedInvoke.status === 428 && code(fencedInvoke.body) === "connection_fenced" && /connection_provider_revoked/u.test(String(fencedInvoke.body?.cause ?? "")), `${fencedInvoke.status} ${code(fencedInvoke.body)} ${fencedInvoke.body?.cause ?? ""}`);

  // -- reauthorize: a successor version with a successor credential binding ----------------------------------
  const reauth = await post(`${CONNECTIONS}/${encodeURIComponent(CID)}/reauthorize`, { owner_ref: OWNER, idempotency_key: key("reauth"), redirect_uri: REDIRECT });
  const reauthCer = reauth.body?.provider_connection_ceremony_record ?? {};
  ok("[reauthorize] issues a new ceremony for the connection's connector under its principal with the granted scopes as the default request", reauth.status === 201 && reauthCer.status === "issued" && reauthCer.connector_ref === `connector://${c1.connector_id}` && reauthCer.requested_scopes?.length > 0, `${reauth.status} ${code(reauth.body)}`);
  const reauthDone = await completeFlow(reauth);
  const v4 = reauthDone.body?.connection ?? {};
  ok("[reauthorize] completion admits version 4: active again, predecessor @3, the SAME account, the epoch carried (1), a successor credential binding @2 and a renewed reauthorization deadline", reauthDone.status === 201 && v4.connection_version === 4 && v4.status === "active" && v4.predecessor_ref === `${v1.connection_ref}@3` && v4.provider_account_subject_hash === v1.provider_account_subject_hash && v4.connection_revocation_epoch === 1 && v4.credential_binding_ref?.endsWith("@2") && Date.parse(v4.reauthorization_required_at) > Date.parse(v1.reauthorization_required_at), `${reauthDone.status} ${code(reauthDone.body)} ${message(reauthDone.body).slice(0, 100)}`);
  const cred4 = credentialRecord(c1.connector_id);
  const invokeReauth = await invoke(c1.connector_id);
  ok("[fence] the credential record follows the successor (version 4, epoch 1, binding @2) and the brokered crossing resolves again (the authority stage answers, not a 428)", cred4?.connection_version === 4 && cred4?.connection_revocation_epoch === 1 && cred4?.credential_binding_ref === v4.credential_binding_ref && resolvedThroughToAuthority(invokeReauth), `${invokeReauth.status} ${code(invokeReauth.body)} ${invokeReauth.body?.cause ?? ""} cred=${cred4?.connection_version}/${cred4?.connection_revocation_epoch}`);

  // -- dependents and disconnect -------------------------------------------------------------------------------
  const pid = who.principal?.principal_id ?? "";
  const grant = await post(`/v1/hypervisor/principals/${encodeURIComponent(pid)}/lease-grants`, { connector_id: c1.connector_id, tools: ["mail.list"], expires_in_seconds: 3600 });
  const deps1 = await get(`${CONNECTIONS}/${encodeURIComponent(CID)}/dependents`);
  ok("[dependents] a principal lease grant over the connector is a DERIVED dependent of the connection", grant.status < 300 && deps1.body?.dependents?.lease_grants?.length === 1, `${grant.status} ${code(grant.body)} deps=${deps1.body?.dependents?.lease_grants?.length}`);
  const disconnected = await post(`${CONNECTIONS}/${encodeURIComponent(CID)}/disconnect`, { owner_ref: OWNER, idempotency_key: key("disc"), expected_head: (await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`)).body?.head, reason: "operator disconnect" });
  const v5 = disconnected.body?.provider_connection_binding_record ?? {};
  const cred5 = credentialRecord(c1.connector_id);
  const c1after = (await get("/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === c1.connector_id) ?? {};
  ok("[disconnect] admits version 5 disconnected with the epoch advanced to 2, retires the sealed material (no sealed_ member remains), unbinds the connector's auth posture and records a durable quarantine obligation for the dependent grant with a receipt", disconnected.status === 201 && v5.status === "disconnected" && v5.connection_revocation_epoch === 2 && !Object.keys(cred5 ?? {}).some((k) => k.startsWith("sealed_")) && cred5?.retired_by === "disconnect" && c1after.auth_posture === "token-lease:unbound" && (disconnected.body?.obligations || []).some((o) => o.subject_kind === "principal_lease_grant" && o.obligation === "quarantine" && o.receipt_ref), `${disconnected.status} ${code(disconnected.body)} ${message(disconnected.body).slice(0, 100)} obligations=${(disconnected.body?.obligations || []).length}`);
  const invokeDisc = await invoke(c1.connector_id);
  ok("[fence] after disconnect the brokered crossing is refused 428 — the fence keys on the connection, and the retired credential resolves nothing", invokeDisc.status === 428, `${invokeDisc.status} ${code(invokeDisc.body)} ${invokeDisc.body?.cause ?? ""}`);
  const deps2 = await get(`${CONNECTIONS}/${encodeURIComponent(CID)}/dependents`);
  ok("[dependents] the obligation is readable beside the dependents it covers", deps2.body?.dependents?.obligations?.length >= 1 && deps2.body?.dependents?.obligations?.[0]?.state === "open", JSON.stringify(deps2.body?.dependents?.obligations?.[0] ?? {}).slice(0, 120));
  const discAgain = await post(`${CONNECTIONS}/${encodeURIComponent(CID)}/disconnect`, { owner_ref: OWNER, idempotency_key: key("disc"), expected_head: (await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`)).body?.head });
  ok("[disconnect] a disconnected connection is not disconnected twice (409)", refused(discAgain, 409, "provider_connection_already_disconnected"), `${discAgain.status} ${code(discAgain.body)}`);

  // -- reconnect: a successor, never a revival; and account substitution on reconnect -------------------------
  provider.subject = "acct-2";
  const sSub = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id));
  const reconSubstituted = await completeFlow(sSub);
  provider.subject = "acct-1";
  ok("[reconnect] a reconnect that returns a DIFFERENT provider account is refused 409 account_substituted: a different account is a different connection, never a silent retarget", refused(reconSubstituted, 409, "provider_connection_ceremony_account_substituted"), `${reconSubstituted.status} ${code(reconSubstituted.body)}`);
  const sRe = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id));
  const reconnected = await completeFlow(sRe);
  const v6 = reconnected.body?.connection ?? {};
  const cred6 = credentialRecord(c1.connector_id);
  ok("[reconnect] the same account reconnects as version 6: active, predecessor @5 (the disconnected version), epoch carried at 2, a successor credential binding @3 — the predecessor's credential does not revive", reconnected.status === 201 && v6.connection_version === 6 && v6.status === "active" && v6.predecessor_ref === `${v1.connection_ref}@5` && v6.connection_revocation_epoch === 2 && v6.credential_binding_ref?.endsWith("@3") && cred6?.credential_binding_ref === v6.credential_binding_ref && typeof cred6?.sealed_refresh_token === "string", `${reconnected.status} ${code(reconnected.body)} ${message(reconnected.body).slice(0, 100)}`);
  const invokeRe = await invoke(c1.connector_id);
  ok("[fence] the reconnected credential resolves again (the authority stage answers, not a 428)", resolvedThroughToAuthority(invokeRe), `${invokeRe.status} ${code(invokeRe.body)} ${invokeRe.body?.cause ?? ""}`);
  const chain = (await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`)).body?.versions ?? [];
  const chainFindings = verifyConnectionChain(chain, { connector: c1, subject: "acct-1" });
  ok("[offline] the served version chain verifies OFFLINE from the records alone: every version commits itself, names its predecessor, moves version and epoch monotonically, never changes the bound account, and no reconnect reused a predecessor's credential binding", chain.length === 6 && chainFindings.length === 0, chainFindings.join("; ") || `${chain.length} versions`);
  ok("[offline] the offline fence agrees with the daemon's: the disconnected head fences the old credential, the reconnected head admits the new one, and the verified head still admitted the unrotated one", credentialIsFenced({ connection_ref: v1.connection_ref, credential_binding_ref: v4.credential_binding_ref, connection_revocation_epoch: 1 }, chain[4]).cause === "connection_disconnected" && credentialIsFenced(cred6, chain[5]).fenced === false && credentialIsFenced({ connection_ref: v1.connection_ref, credential_binding_ref: v1.credential_binding_ref, connection_revocation_epoch: 0 }, chain[1]).fenced === false, JSON.stringify(credentialIsFenced(cred6, chain[5])));

  // -- the legacy alias shares the lineage ------------------------------------------------------------------------
  const cL = await registerConnector("legacy", stub.origin);
  const legacyStart = await post(`/v1/hypervisor/connectors/${encodeURIComponent(cL.connector_id)}/oauth/start`, { redirect_uri: REDIRECT });
  const legacyAuth = await authorize(legacyStart.body?.authorize_url ?? `${stub.origin}/authorize?redirect_uri=${encodeURIComponent(REDIRECT)}&state=x`);
  const legacyDone = await post("/v1/hypervisor/connectors/oauth/callback", { state: legacyAuth.state, code: legacyAuth.code });
  const legacyConn = (await get(CONNECTIONS)).body?.connections?.find((c) => c.connector_ref === `connector://${cL.connector_id}`);
  ok("[alias] the product UI's connector oauth/start and oauth/callback routes now issue and complete the SAME registered ceremony (answering in the shape the UI reads) and admit a ProviderConnectionBinding — one lineage for the API, the SDK and the UI", legacyStart.status === 200 && legacyStart.body?.ok === true && typeof legacyStart.body?.authorize_url === "string" && legacyStart.body?.ceremony_ref?.startsWith("connection-ceremony://") && legacyDone.status === 200 && legacyDone.body?.connected === true && legacyDone.body?.state_consumed === true && legacyConn?.status === "active", `${legacyStart.status} ${code(legacyStart.body)} / ${legacyDone.status} ${code(legacyDone.body)} ${message(legacyDone.body).slice(0, 80)}`);
  ok("[alias] no unregistered oauth-pending record exists anywhere in the data directory: the prototype store is gone", !fs.existsSync(path.join(dataDir, "oauth-pending")) || fs.readdirSync(path.join(dataDir, "oauth-pending")).length === 0);

  // -- restart: derived projections and the fence -----------------------------------------------------------------
  const projections = async () => ({ list: stripVolatile((await get(CONNECTIONS)).body), get: stripVolatile((await get(`${CONNECTIONS}/${encodeURIComponent(CID)}`)).body), deps: stripVolatile((await get(`${CONNECTIONS}/${encodeURIComponent(CID)}/dependents`)).body) });
  const before = await projections();
  await stopDaemon();
  fs.rmSync(path.join(dataDir, "provider-connection-index"), { recursive: true, force: true });
  await startDaemon({ IOI_PROVIDER_CONNECTION_CEREMONY_TTL_MS: "1200" });
  const after = await projections();
  ok("[restart] the inventory, the version chain and the dependents reproduce byte for byte across a restart with the connection index destroyed: every projection is derived from the admitted streams", before.list === after.list && before.get === after.get && before.deps === after.deps, ["list", "get", "deps"].filter((k) => before[k] !== after[k]).join(",") || "identical");
  const invokeRestart = await invoke(c1.connector_id);
  ok("[restart] the reconnected credential still resolves after the restart (the authority stage answers), and the fence is read from the chain, not from process memory", resolvedThroughToAuthority(invokeRestart), `${invokeRestart.status} ${code(invokeRestart.body)}`);
  const sExp = await post(`${CONNECTIONS}/authorization/start`, startBody(c1.connector_id));
  await new Promise((r) => setTimeout(r, 1600));
  const expired = await completeFlow(sExp);
  ok("[expiry] a ceremony completed after its deadline (the daemon restarted with a 1.2 s ceremony TTL) is refused 410 expired and the chain records `expired`", refused(expired, 410, "provider_connection_ceremony_expired") && expired.body?.ceremony?.status === "expired", `${expired.status} ${code(expired.body)} ${expired.body?.ceremony?.status}`);

  const PLANE_CODES = ["provider_connection_ceremony_redirect_drift", "provider_connection_ceremony_profile_drift", "provider_connection_ceremony_exchange_failed", "provider_connection_ceremony_scope_widened", "provider_connection_ceremony_account_substituted", "provider_connection_ceremony_subject_unresolvable", "provider_connection_ceremony_expired", "connection_fenced", "provider_connection_already_disconnected"];
  const unobserved = PLANE_CODES.filter((c) => !observedCodes.has(c));
  ok("every one of the plane's nine named refusal codes was observed LIVE on this run", unobserved.length === 0, unobserved.join(",") || "all nine observed");
  const src = fs.readFileSync(path.resolve(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/provider_connection_routes.rs"), "utf8");
  ok("[structure] the daemon module holds the fence as ONE function the capability-lease gateway calls, and the legacy routes delegate to the ceremony", /pub\(crate\) fn fence_credential/u.test(src) && /pub\(crate\) async fn legacy_oauth_start/u.test(src) && /provider_connection_routes::fence_credential/u.test(fs.readFileSync(path.resolve(ROOT, "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"), "utf8")));

  await stopDaemon();
  stub.server.close();
}

async function drill() {
  const fixtures = path.resolve(ROOT, "docs/architecture/_meta/schemas/fixtures");
  const rf = (family, name) => JSON.parse(fs.readFileSync(path.join(fixtures, family, name), "utf8"));
  const cer = rf("provider-connection-ceremony-v1", "positive-completed.json");
  const bind = rf("provider-connection-binding-v1", "positive-active.json");
  const disc = rf("provider-connection-binding-v1", "positive-disconnected.json");
  ok("DRILL D1 — the ceremony content-hash oracle rejects a scope edited after admission and a proof swapped, and accepts the registered fixture", deriveCeremonyHash(cer) === cer.content_hash && deriveCeremonyHash({ ...cer, requested_scopes: ["admin.all"] }) !== cer.content_hash && deriveCeremonyHash({ ...cer, proof: { ...cer.proof, code_challenge: "x".repeat(43) } }) !== cer.content_hash);
  ok("DRILL D2 — the binding content-hash oracle rejects an epoch, a status or a credential binding edited after admission, and accepts the registered fixtures", deriveBindingHash(bind) === bind.content_hash && deriveBindingHash(disc) === disc.content_hash && deriveBindingHash({ ...bind, connection_revocation_epoch: 9 }) !== bind.content_hash && deriveBindingHash({ ...bind, status: "disconnected" }) !== bind.content_hash);
  ok("DRILL D3 — the chain oracle goes red on a rolled-back epoch, a skipped version, a changed account and a reused credential binding on reconnect", verifyConnectionChain([bind, { ...disc, connection_revocation_epoch: 0 }]).length > 0 && verifyConnectionChain([bind, { ...disc, connection_version: 3 }]).length > 0 && verifyConnectionChain([bind, { ...disc, provider_account_subject_hash: "sha256:" + "00".repeat(32) }]).length > 0 && verifyConnectionChain([disc, { ...bind, connection_version: 3, predecessor_ref: `${disc.connection_ref}@2`, connection_revocation_epoch: 1 }]).some((f) => /reused/u.test(f)) && verifyConnectionChain([bind, disc]).length === 0);
  ok("DRILL D4 — the provider-profile oracle moves on any unsealed member and ignores sealed ones; the subject oracle binds the profile", deriveProviderProfileRef({ connector_id: "c", auth_profile: { a: 1, sealed_x: "s" } }) === deriveProviderProfileRef({ connector_id: "c", auth_profile: { a: 1, sealed_x: "t" } }) && deriveProviderProfileRef({ connector_id: "c", auth_profile: { a: 1 } }) !== deriveProviderProfileRef({ connector_id: "c", auth_profile: { a: 2 } }) && deriveSubjectHash("p1", "s") !== deriveSubjectHash("p2", "s"));
  ok("DRILL D5 — the offline fence and the refusal predicate go red when planted: a fenced credential reads as fenced, a 201 reads as NOT refused, and the plaintext scan finds a planted needle", credentialIsFenced({ connection_ref: bind.connection_ref, credential_binding_ref: bind.credential_binding_ref, connection_revocation_epoch: 0 }, { ...bind, connection_revocation_epoch: 1 }).cause === "connection_epoch_advanced" && credentialIsFenced({ connection_ref: bind.connection_ref, credential_binding_ref: "credential://other@9", connection_revocation_epoch: 0 }, bind).cause === "connection_credential_superseded" && !refused({ status: 201, body: {} }, 409, "x") && refused({ status: 409, body: { error: { code: "x" } } }, 409, "x") && pkceChallenge("verifier") === crypto.createHash("sha256").update("verifier").digest("base64url"));
}

(DRILL ? drill() : run())
  .catch((error) => { ok("the verifier completed", false, String(error?.stack || error)); })
  .finally(async () => {
    await stopDaemon().catch(() => {});
    const passed = results.filter((r) => r.pass).length;
    console.log(`\n${passed}/${results.length} passed`);
    emitVerifierCensus({ verifierId: "provider-connection-lifecycle", sourceUrl: import.meta.url, results: results.map((r) => ({ name: r.name, pass: r.pass })) });
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
    process.exit(results.length === 0 ? 2 : passed === results.length ? 0 : 1);
  });
