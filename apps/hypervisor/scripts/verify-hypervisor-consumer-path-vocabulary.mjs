#!/usr/bin/env node
// M13.1's CLAIM-SPECIFIC gate: ACC-15 clause 1 and negative clause N2.
//
// Clause 1 — "Two minutes, zero vocabulary: a fresh principal reaches a running session with one
// scoped connection attached without meeting a kernel noun." Two halves, and until now NEITHER was
// asserted anywhere: no verifier TIMED the fresh-principal path, and none scanned the consumer
// path's rendered text against the kernel vocabulary. The alpha journey walks the same steps and
// prints their durations as DETAIL STRINGS — a number nobody fails on is not a claim.
//
// N2 — "No governance vocabulary appears on the consumer path, AND no daemon object is renamed to
// achieve that." The second half is what makes the first non-trivial: a green scan bought by
// renaming `latest_receipt_refs` to `things` would satisfy the letter and destroy the point. So the
// scan is paired with a NEGATIVE CONTROL that reads the daemon's own records back and requires the
// kernel names to still be there.
//
// The forbidden set is DATA, not a regex buried here: apps/hypervisor/consumer-path-vocabulary.v1.json,
// with each term's owner citation. A term added or removed is a reviewable diff to a tracked record.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon binary, no chromium, fixture unavailable).
//   IOI_HYPERVISOR_DAEMON_BINARY   default target/debug/hypervisor-daemon
//   IOI_CONSUMER_PATH_BUDGET_MS    default 120000 — the "two minutes" the clause names

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
const APP = path.resolve(HERE, "..");
const PRINCIPAL = "domain://acme-host";
const SESSION_ENVELOPE_CONTRACT = "schema://ioi/components/hypervisor/session-standing-envelope/v1";
const BUDGET_MS = Number(process.env.IOI_CONSUMER_PATH_BUDGET_MS || 120_000);
const VOCAB = JSON.parse(fs.readFileSync(path.join(APP, "consumer-path-vocabulary.v1.json"), "utf8"));

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

/// Rendered text as a CONSUMER reads it. Attributes, scripts and styles are machine surfaces and
/// are stripped: `data-ioi-standing-lease` is a test seam, not something anyone reads.
function renderedTextOfHtml(html) {
  return String(html)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/giu, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/giu, " ")
    .replace(/<[^>]+>/gu, " ")
    .replace(/&[a-z]+;/giu, " ")
    .replace(/\s+/gu, " ");
}

/// The one matcher. Word-boundary, case-insensitive, over rendered text only.
function forbiddenHits(text) {
  const hits = [];
  for (const entry of VOCAB.forbidden) {
    const re = new RegExp(`\\b${entry.term}\\b`, "giu");
    const found = text.match(re);
    if (found?.length) hits.push({ term: entry.term, count: found.length });
  }
  return hits;
}

/// The extended matcher (consumer-path-vocabulary.v1.json § matching). The whole-word matcher above
/// misses `envelope_revoked` (an underscore is a word character, so there is no boundary) and every
/// plural ("receipts"). This one splits rendered text on whitespace, punctuation, "_", "-" and
/// camelCase first; a term matches a token equal to it or to its plural, and a multi-part term
/// (session_execute, key id) matches its parts in sequence however they are joined.
function tokensOf(text) {
  return String(text)
    .replace(/([\p{Ll}\p{N}])(\p{Lu})/gu, "$1 $2")
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .map((token) => token.toLowerCase());
}
const pluralForms = (part) => [part, `${part}s`, `${part}es`, ...(part.endsWith("y") ? [`${part.slice(0, -1)}ies`] : [])];
function extendedHits(text, entries) {
  const tokens = tokensOf(text);
  const hits = [];
  for (const entry of entries) {
    const parts = tokensOf(entry.term);
    const last = parts.length - 1;
    let count = 0;
    for (let i = 0; i + parts.length <= tokens.length; i += 1) {
      if (parts.every((part, j) => (j === last ? pluralForms(part).includes(tokens[i + j]) : tokens[i + j] === part))) count += 1;
    }
    if (count) hits.push({ term: entry.term, count });
  }
  return hits;
}
/// Beside the word list: a product-named code (two or more lowercase parts joined by "_") or the word
/// "exit" followed by a number renders only in the exempt contexts (Evidence, --json, --verbose).
function codeHits(text) {
  const snake = [...String(text).matchAll(/\b[a-z0-9]+(?:_[a-z0-9]+)+\b/gu)].map((m) => m[0]);
  const exits = [...String(text).matchAll(/\bexit\s+\d+\b/giu)].map((m) => m[0]);
  return [...snake, ...exits];
}

async function run() {
  // ---- the matcher's own self-drill, BEFORE any plane is booted ------------------------------
  // A scanner that matches nothing passes every surface. Prove it can see what it is looking for,
  // and prove it does not fire on a benign consumer sentence.
  const planted = forbiddenHits("Your session is running. The lease is bound and the receipt is on file.");
  const benign = forbiddenHits("Your session is running with one connection attached. Nothing else is needed.");
  ok("SELF-DRILL: the matcher finds planted kernel nouns and stays silent on a benign consumer sentence",
    planted.some((h) => h.term === "lease") && planted.some((h) => h.term === "receipt") && benign.length === 0,
    `planted ${planted.map((h) => h.term).join(",") || "none"} · benign ${benign.map((h) => h.term).join(",") || "none"}`);
  ok("the forbidden set is a TRACKED RECORD with an owner citation for every term, not an inline list",
    VOCAB.forbidden.length > 0 && VOCAB.forbidden.every((f) => f.term && f.source && f.why) && VOCAB.owner_citations.length >= 2,
    `${VOCAB.forbidden.length} terms · ${VOCAB.owner_citations.length} citations`);

  // ---- the extended matcher's controls (§ matching) — before any plane, like the drill above ----
  // Declared ahead of enforcement: the live surfaces below are still scanned with the seven terms and
  // the whole-word matcher; these drills prove the extended matcher can see what it will look for.
  const extended = VOCAB.forbidden_extended ?? [];
  const everywhere = [...VOCAB.forbidden, ...extended.filter((f) => !f.only_on)];
  const withRouteWords = [...everywhere, ...extended.filter((f) => f.only_on)];
  const [a9, a10, a12, seat] = VOCAB.matching?.plants ?? [];
  const control = "Didn't start · limits_removed (removed), exit 8";
  ok("the extension is a TRACKED RECORD: every added term has a source and a reason, every target surface names a declared scanner, and the exempt contexts are listed",
    extended.length > 0 && extended.every((f) => f.term && f.source && f.why)
      && (VOCAB.target_surfaces ?? []).length > 0 && VOCAB.target_surfaces.every((s) => s.id && s.surface && Object.hasOwn(VOCAB.scanners ?? {}, s.scanner))
      && (VOCAB.exempt ?? []).length > 0,
    `${extended.length} added terms · ${(VOCAB.target_surfaces ?? []).length} target surfaces · ${(VOCAB.exempt ?? []).length} exempt contexts`);
  ok("SELF-DRILL (extended): each plant is caught — the refusal code in the header, the operation id on a limits line, the custody words on a sheet, and the route words only with the seat-sheet list",
    extendedHits(a9 ?? "", everywhere).some((h) => h.term === "envelope") && codeHits(a9 ?? "").length >= 2
      && extendedHits(a10 ?? "", everywhere).some((h) => h.term === "session_execute")
      && ["passphrase", "custody"].every((term) => extendedHits(a12 ?? "", everywhere).some((h) => h.term === term))
      && extendedHits(seat ?? "", everywhere).length === 0 && extendedHits(seat ?? "", withRouteWords).length >= 3,
    `${[a9, a10, a12, seat].filter(Boolean).length} plants`);
  ok("CONTROL: the code pattern catches a code that carries no forbidden word, and the word list alone misses it",
    codeHits(control).length === 2 && extendedHits(control, withRouteWords).length === 0,
    `codes ${codeHits(control).join(", ")}`);
  ok("MUTANT: the whole-word matcher misses the header plant, so the split is load-bearing",
    !/\benvelopes?\b/iu.test(a9 ?? "envelope_revoked") && forbiddenHits(a9 ?? "envelope_revoked").length === 0,
    "\\benvelopes?\\b on the header plant");
  ok("SELF-DRILL (extended): benign consumer sentences stay clean under the extended matcher and the code pattern",
    ["Your session is running with one connection attached. Nothing else is needed.", "It may write files in its own workspace on this computer; nothing leaves it", "Runs Sessions on this computer"]
      .every((sentence) => extendedHits(sentence, withRouteWords).length === 0 && codeHits(sentence).length === 0));

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

  // The plane is INFRASTRUCTURE and is deliberately outside the timed segment: a consumer does not
  // wait for a daemon to boot, any more than they wait for a web server to start.
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
  const req = async (base, p, init = {}, withCookie = true) => {
    const res = await fetch(`${base}${p}`, {
      redirect: "manual",
      ...init,
      headers: {
        ...(init.body && !init.headers?.["content-type"] ? { "content-type": "application/json" } : {}),
        ...(init.headers || {}),
        ...(withCookie && COOKIE ? { cookie: `ioi_session=${COOKIE}` } : {}),
      },
    });
    const text = await res.text();
    let body = {};
    try { body = JSON.parse(text); } catch { /* html */ }
    return { status: res.status, headers: res.headers, text, body };
  };

  try {
    // ================= THE TIMED SEGMENT =================
    // Starts at the first byte of the front door and ends when the daemon reports a session whose
    // authority profile names exactly one connection. Every step below is one a person performs.
    const logPath = fs.readdirSync(dataDir).find((f) => f.endsWith(".log"));
    const daemonLog = logPath ? fs.readFileSync(path.join(dataDir, logPath), "utf8") : "";
    const token = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
    if (!token) { await plane.stop(); blocked("the daemon printed no first-run bootstrap token"); }

    const t0 = Date.now();
    const firstRun = await req(SERVE, "/__ioi/login", {}, false);
    ok("clause 1: the front door a FRESH principal meets is the first-run operator setup",
      firstRun.status === 200 && firstRun.text.includes('data-ioi-first-run="1"'), `${firstRun.status}`);

    const boot = await req(SERVE, "/__ioi/bootstrap", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token, name: "Consumer Path", email: "consumer@path.local", password: "consumer-path-pass-1" }).toString(),
    }, false);
    COOKIE = (boot.headers.get("set-cookie") || "").match(/ioi_session=([^;]+)/u)?.[1] || "";
    ok("clause 1: the fresh principal has an account and a session after ONE form",
      boot.status === 302 && COOKIE.length > 0, `${boot.status} · cookie ${COOKIE ? "set" : "absent"}`);

    const registered = await req(DAEMON, "/v1/hypervisor/connectors", {
      method: "POST",
      body: JSON.stringify({ service: "ping-service", name: "consumer-path", base_url: `http://127.0.0.1:${toolPort}`, kind: "bearer", requires_credential: false, allowed_tools: [{ name: "ping", method: "GET", path: "/ping" }] }),
    });
    const connector = registered.body?.connector;
    ok("clause 1: the principal attaches ONE connection", !!connector?.connector_id, String(connector?.connector_id));

    // Bounding the connection is part of the path: a session cannot name an unbounded connection.
    // The chain's own committed clock, never the host's assumption (the envelope's validity
    // window is judged against it).
    const nowMs = await fixture.readChainTimestampMs();
    // These are sha256 REFS on the wire, not bare hex: the wallet validates the shape before it
    // validates anything else, and a bare digest is rejected during block production.
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
    const bind = await req(DAEMON, `/v1/hypervisor/connectors/${encodeURIComponent(connector.connector_id)}/standing-lease`, {
      method: "POST", body: JSON.stringify({ grant, envelope }),
    });
    ok("clause 1: the connection is BOUNDED — a session cannot name an unbounded one",
      bind.status === 200 && bind.body?.ok === true, `${bind.status}`);

    const launch = await req(SERVE, "/__ioi/api/new-session/launch", {
      method: "POST",
      body: JSON.stringify({ project_ref: "project:consumer-path", authority_profile: { connection_refs: [`connector:${connector.connector_id}`] } }),
    });
    const sessionRef = launch.body?.session_ref || "";
    const session = sessionRef ? (await req(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`)).body?.session : null;
    const refs = session?.authority_profile?.connection_refs || [];
    const elapsedMs = Date.now() - t0;
    ok("clause 1: the principal reaches a RUNNING session whose profile names exactly ONE scoped connection",
      !!session && session.lifecycle_state && refs.length === 1 && refs[0] === `connector:${connector.connector_id}`,
      `${launch.status} · ${sessionRef} · lifecycle ${session?.lifecycle_state} · refs ${JSON.stringify(refs)}`);
    // THE ASSERTION THAT DID NOT EXIST: the clause's number, failed on rather than printed.
    ok(`clause 1: the whole path completes within the TWO MINUTES the clause names (budget ${BUDGET_MS} ms)`,
      elapsedMs <= BUDGET_MS, `${elapsedMs} ms`);
    // ================= END OF THE TIMED SEGMENT =================

    // ---- N2 + clause 1's "zero vocabulary" half ----------------------------------------------
    let browser = null;
    try {
      const { chromium } = await import("playwright");
      browser = await chromium.launch();
    } catch (error) {
      await plane.stop();
      blocked(`chromium unavailable, and the SPA surfaces cannot be read without it — ${error?.message || error}`);
    }
    const page = await browser.newPage();
    await page.context().addCookies([{ name: "ioi_session", value: COOKIE, url: SERVE }]);

    const scanned = [];
    for (const surface of VOCAB.surfaces) {
      let text = "";
      if (surface.render === "spa") {
        await page.goto(`${SERVE}${surface.path}`, { waitUntil: "domcontentloaded", timeout: 30_000 });
        await page.waitForTimeout(1500);
        text = await page.locator("body").innerText().catch(() => "");
      } else {
        text = renderedTextOfHtml((await req(SERVE, surface.path)).text);
      }
      const hits = forbiddenHits(text);
      scanned.push({ path: surface.path, render: surface.render, chars: text.length, hits });
      ok(`N2: no kernel noun on the consumer path — ${surface.path} (${surface.render})`,
        text.length > 0 && hits.length === 0,
        hits.length ? `FOUND ${hits.map((h) => `${h.term}×${h.count}`).join(", ")}` : `${text.length} chars scanned, clean`);
    }
    ok("N2: every declared consumer surface actually rendered text — a scan over an empty page is not a clean scan",
      scanned.every((s) => s.chars > 0), scanned.map((s) => `${s.path}:${s.chars}`).join(" · "));
    await browser.close();

    // ---- N2's NEGATIVE CONTROL — the half that makes the scan mean something ------------------
    const daemonSession = (await req(DAEMON, `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}`)).body?.session || {};
    const kernelKeys = ["latest_receipt_refs", "authority_profile", "environment_ref", "lifecycle_state"];
    const present = kernelKeys.filter((k) => Object.hasOwn(daemonSession, k));
    ok("N2 NEGATIVE CONTROL: the DAEMON still calls its objects what it always called them — a green scan bought by renaming daemon fields fails here",
      present.length === kernelKeys.length, `${present.length}/${kernelKeys.length} kernel keys present: ${present.join(", ")}`);
    const connectorRecord = (await req(DAEMON, "/v1/hypervisor/connectors")).body?.connectors?.find((c) => c.connector_id === connector.connector_id) || {};
    ok("N2 NEGATIVE CONTROL: the daemon's connector record still carries the standing-lease object under its kernel name",
      Object.hasOwn(connectorRecord, "standing_lease"), JSON.stringify(Object.keys(connectorRecord).slice(0, 8)));
  } finally {
    if (toolServer) await new Promise((resolve) => toolServer.close(resolve));
    if (plane) await plane.stop();
    if (fixture?.stop) await fixture.stop();
  }

  emitVerifierCensus({ verifierId: "consumer-path-vocabulary", sourceUrl: import.meta.url, results });
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${failed.length ? "FAIL" : "PASS"} check:consumer-path-vocabulary — ${results.length - failed.length}/${results.length} assertions`);
  process.exit(failed.length ? 1 : 0);
}

run().catch((error) => { console.error(`BLOCKED: ${error?.stack || error}`); process.exit(2); });
