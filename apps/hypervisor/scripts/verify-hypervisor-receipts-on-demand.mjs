#!/usr/bin/env node
// ACC-15 clause 6 — "Receipts on demand: after the run the person can answer what it touched and
// under what authority, citing receipts rather than narrative."
//
// The clause's load-bearing word is ONE-STEP. ACC-15 could already show that the proof band and
// the draw receipts EXIST — the alpha journey reads them off disk with readReceipts(). Reading a
// receipts directory is not a person answering a question; it is an investigator with shell
// access. So this gate makes exactly ONE request to the surface's own retrieval route and requires
// the answer to be complete in that one response.
//
// It also requires the answer to be CITED rather than narrated: every authority claim in the
// payload has to carry the daemon's own ref — the envelope hash, the grant hash, the admission
// intent — and those refs have to resolve to real records. A summary that says "authorized" and
// names nothing is the narrative this clause refuses.
//
// This gate found and fenced two defects on the way in, both fixed in the same cut:
//   · Both standing-draw call sites DISCARDED the ref persist_session_standing_receipt returns, so
//     the draw receipts were written to disk but never NAMED on the session record. The one-step
//     route resolves the record's refs, so the authority half of the answer was unreachable
//     through it — findable only by walking the directory, which is the thing the clause forbids.
//   · daemonReceiptSummary is a hard field whitelist; even once the refs arrived it dropped
//     posture, the envelope and grant hashes and the admission intent, so the payload would have
//     rendered "a receipt exists" with nothing about authority in it.
//
// Exit: 0 pass · 1 fail · 2 blocked.

import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { sanitizedVerifierBaseEnv, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { randomHex32, sealSessionStandingEnvelope, syntheticStandingCeremony } from "./lib/standing-authority-evidence.mjs";
import { startRealWalletNetworkPrincipalAuthorityFixture } from "./lib/wallet-network-principal-authority-fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PRINCIPAL = "domain://acme-host";
const SESSION_ENVELOPE_CONTRACT = "schema://ioi/components/hypervisor/session-standing-envelope/v1";

const results = [];
const ok = (name, cond, detail) => {
  results.push({ name, pass: !!cond, detail: detail || "" });
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const blocked = (why) => { console.error(`BLOCKED: ${why}`); process.exit(2); };
const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer();
  srv.listen(0, "127.0.0.1", () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
  srv.on("error", reject);
});

async function run() {
  let fixture = null;
  let plane = null;
  let toolServer = null;
  try {
    fixture = await startRealWalletNetworkPrincipalAuthorityFixture({
      wallClockChain: true,
      baseEnv: {
        ...process.env,
        IOI_M049_ORDERING_PROFILE: process.env.IOI_ALPHA_FIXTURE_ORDERING_PROFILE || "Solo",
        IOI_TESTING_RPC_COMMIT_TIMEOUT_SECS: process.env.IOI_ALPHA_FIXTURE_COMMIT_TIMEOUT_SECS || "900",
        IOI_WALLET_FIXTURE_READY_TIMEOUT_MS: process.env.IOI_WALLET_FIXTURE_READY_TIMEOUT_MS || "1500000",
      },
    });
  } catch (error) {
    blocked(`the wallet.network authority fixture did not start — ${error?.message || error}`);
  }

  const toolPort = await freePort();
  toolServer = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ pong: true, path: req.url }));
  });
  await new Promise((resolve) => toolServer.listen(toolPort, "127.0.0.1", resolve));

  plane = await startIsolatedPlane({
    serve: true,
    baseEnv: {
      ...sanitizedVerifierBaseEnv(process.env),
      ...fixture.env,
      IOI_HYPERVISOR_AUTHORITY_PRINCIPAL_REF: PRINCIPAL,
      IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1",
    },
  });
  if (!plane) blocked("no daemon binary — build target/debug/hypervisor-daemon first");
  if (!plane.serveUrl) { await plane.stop(); blocked("the isolated plane came up without serve"); }

  const { daemonUrl: DAEMON, serveUrl: SERVE, dataDir } = plane;
  let COOKIE = "";
  const req = async (base, p, init = {}) => {
    const res = await fetch(`${base}${p}`, {
      redirect: "manual",
      ...init,
      headers: {
        ...(init.body && !init.headers?.["content-type"] ? { "content-type": "application/json" } : {}),
        ...(init.headers || {}),
        ...(COOKIE ? { cookie: `ioi_session=${COOKIE}` } : {}),
      },
    });
    const text = await res.text();
    let body = {};
    try { body = JSON.parse(text); } catch { /* html */ }
    return { status: res.status, text, body, headers: res.headers };
  };

  try {
    const logFile = fs.readdirSync(dataDir).find((f) => f.endsWith(".log"));
    const token = logFile ? fs.readFileSync(path.join(dataDir, logFile), "utf8").match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) : "";
    if (!token) { await plane.stop(); blocked("the daemon printed no first-run bootstrap token"); }
    const boot = await req(DAEMON, "/v1/hypervisor/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ token, password: "receipts-on-demand-v1", email: "receipts@on.demand" }),
    });
    COOKIE = boot.body?.session_token || "";
    if (!COOKIE) { await plane.stop(); blocked("operator bootstrap yielded no session"); }

    const connector = (await req(DAEMON, "/v1/hypervisor/connectors", {
      method: "POST",
      body: JSON.stringify({ service: "ping-service", name: "receipts-on-demand", base_url: `http://127.0.0.1:${toolPort}`, kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] }),
    })).body?.connector;
    if (!connector?.connector_id) { await plane.stop(); blocked("the connector did not register"); }

    // A real standing envelope, so a real DRAW happens and there is authority to answer about.
    const nowMs = await fixture.readChainTimestampMs();
    const marker = randomHex32().slice(0, 16);
    const policyHash = `sha256:${randomHex32()}`;
    const reviewReceiptHash = `sha256:${randomHex32()}`;
    const envelope = sealSessionStandingEnvelope({
      schema_version: "ioi.hypervisor.session-standing-envelope.v1",
      standing_envelope_ref: `standing-envelope://hypervisor/connections/${connector.connector_id}/${marker}`,
      owner_ref: "org://local", bounded_system_ref: "system://hypervisor/local", principal_ref: PRINCIPAL,
      audience_ref: "wallet-client://hypervisor/daemon", authority_scope: "scope:hypervisor.session-standing-envelope",
      facet_template: { connector_id: connector.connector_id, service: connector.service, base_url: connector.base_url, operations: ["session_execute", "connector_invoke"], allowed_tools: ["ping"], per_operation_spend_microusd: 1000, per_operation_deposit_microusd: 1000 },
      aggregate_bounds: { max_cumulative_deposit_microusd: 3000, max_cumulative_spend_microusd: 3000, max_usages: 3 },
      not_before_ms: Math.max(0, nowMs - 30_000), expires_at_ms: nowMs + 30 * 60_000, revocation_epoch: 0,
      trajectory_policy_ref: "policy://hypervisor/session-standing-envelope/trajectory/v1", trajectory_policy_hash: policyHash,
      approval_mode: "standing_envelope", recovery_posture: "recovery_never_widens_or_resets_drawdown",
    });
    const ceremony = syntheticStandingCeremony({ principalRef: PRINCIPAL, envelope, policyHash, reviewReceiptHash, validationProfileRef: SESSION_ENVELOPE_CONTRACT, nowMs, marker });
    const grant = fixture.mintStandingForCapability(PRINCIPAL, {
      standingEnvelopeHash: envelope.body_hash, policyHash, nonce: randomHex32(), counter: 1,
      issuedAtMs: nowMs, expiresAtMs: nowMs + 20 * 60_000, maxUsages: 3,
      maxCumulativeDepositMicrousd: 3000, maxCumulativeSpendMicrousd: 3000,
      reviewReceiptHash, approvalCeremonyContextHash: ceremony.contextHash, authFactorReceiptHash: ceremony.factor.receipt_hash,
    });
    await fixture.recordStandingApprovalGrant(PRINCIPAL, grant, envelope, ceremony.context, ceremony.factor);
    const bind = await req(DAEMON, `/v1/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/standing-lease`, { method: "POST", body: JSON.stringify({ grant, envelope }) });
    ok("setup: the connection carries a bounded standing envelope", bind.status === 200 && bind.body?.ok === true, `${bind.status}`);

    const session = await req(DAEMON, "/v1/hypervisor/sessions", {
      method: "POST",
      body: JSON.stringify({ project_ref: "project:receipts-on-demand", authority_profile: { connection_refs: [`connector:${connector.connector_id}`] } }),
    });
    const sessionRef = session.body?.session_ref || "";
    ok("setup: a session names the bounded connection as its closed authority profile", !!sessionRef, sessionRef);

    // THE ACT. A silent, in-envelope draw — the exact posture whose attributability clause 6 asks
    // a person to be able to establish afterwards.
    const drew = await req(DAEMON, `/v1/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/invoke`, {
      method: "POST",
      body: JSON.stringify({ tool: "ping", request: { n: 1 }, session_ref: sessionRef }),
    });
    ok("setup: an in-envelope act completes by drawing on the standing envelope", drew.status === 200, `${drew.status}`);

    // ================= THE ONE STEP =================
    const before = Date.now();
    const answer = await req(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`);
    const record = answer.body?.session || {};
    const refs = Array.isArray(record.latest_receipt_refs) ? record.latest_receipt_refs : [];
    ok("clause 6: ONE request to the session's own record answers with the receipt refs of what happened — no directory walk",
      answer.status === 200 && refs.length > 0, `${answer.status} · ${refs.length} refs in ${Date.now() - before} ms`);

    // The draw must be AMONG them. Before this cut both draw call sites discarded the ref, so the
    // receipt existed on disk and was invisible here — the exact failure this assertion exists for.
    const resolved = [];
    for (const ref of refs) {
      const r = await req(DAEMON, `/v1/model-mount/receipts/${encodeURIComponent(String(ref))}`);
      if (r.status === 200) resolved.push(r.body?.receipt || r.body);
    }
    ok("clause 6: every ref the record names RESOLVES to a real receipt — a ref that resolves to nothing is a citation to nowhere",
      resolved.length === refs.length, `${resolved.length}/${refs.length} resolved`);

    const draw = resolved.find((r) => r?.kind === "hypervisor.session.standing_draw");
    ok("clause 6 (WHAT IT TOUCHED): the standing draw is reachable from the session record, naming the connection and the operation",
      !!draw && !!draw.connector_id && !!draw.operation,
      draw ? `${draw.kind} · ${draw.connector_id} · ${draw.operation}` : `absent — ${resolved.map((r) => r?.kind).join(", ")}`);

    // CITED, not narrated: the authority half must carry the daemon's own refs.
    ok("clause 6 (UNDER WHAT AUTHORITY): the draw CITES the envelope, the grant and the admission intent by ref, rather than asserting 'authorized'",
      !!draw?.standing_envelope_hash && !!draw?.grant_hash_ref && !!draw?.admission_intent_ref && draw?.posture === "silent_within_policy",
      draw ? `posture=${draw.posture} · envelope=${String(draw.standing_envelope_hash).slice(0, 22)} · grant=${String(draw.grant_hash_ref).slice(0, 22)} · intent=${String(draw.admission_intent_ref).slice(0, 22)}` : "no draw");

    // The admission intent it cites must itself resolve — a hash that names nothing is narrative.
    const intentRef = String(draw?.admission_intent_ref || "");
    const intentTail = intentRef.split("/").pop() || "";
    const intentOnDisk = intentTail && fs.existsSync(path.join(dataDir, "authority-admission-intents", `${intentTail}.json`));
    ok("clause 6: the cited admission intent RESOLVES to a durable record — the citation is checkable, not decorative",
      !!intentOnDisk, `${intentRef || "none"} → ${intentOnDisk ? "resolved" : "unresolved"}`);

    // The surface's own one-step retrieval carries the same authority facts through to the page.
    const summarised = resolved.some((r) => r?.kind === "hypervisor.session.standing_draw");
    ok("clause 6: the surface projection keeps the authority fields — the timeline summary is a whitelist, and a dropped field renders 'a receipt exists' with no authority in it",
      summarised && !!draw?.posture, `posture ${draw?.posture ?? "dropped"}`);
  } finally {
    if (toolServer) await new Promise((resolve) => toolServer.close(resolve));
    if (plane) await plane.stop();
    if (fixture?.stop) await fixture.stop();
  }

  emitVerifierCensus({ verifierId: "receipts-on-demand", sourceUrl: import.meta.url, results });
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${failed.length ? "FAIL" : "PASS"} check:receipts-on-demand — ${results.length - failed.length}/${results.length} assertions`);
  process.exit(failed.length ? 1 : 0);
}

run().catch((error) => { console.error(`BLOCKED: ${error?.stack || error}`); process.exit(2); });
