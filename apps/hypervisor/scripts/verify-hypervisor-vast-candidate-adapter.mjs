#!/usr/bin/env node
// Vast candidate-source adapter done-bar (quote + preflight + candidate enrichment ONLY).
//
// Proves the first external GPU supply source feeding the decentralized.cloud candidate
// plane: credentials absent → candidate_source_unavailable with evidence; sealed bearer
// resolves only inside the daemon; unreachable endpoint → degraded_unreachable with evidence
// and ZERO fake quotes; fixture-backed offers normalize into CloudResourceCandidates with
// ProviderQuote/SpendEstimate taken VERBATIM from offer data, unmistakably marked
// fixture_evidence (live is never claimed); candidates expire and lose eligibility; no
// provider mutation, no fee objects, no RoutingDecisionReceipt; the advisory shows Vast as
// advisory-only supply without ever recommending it; pinned-provider override survives.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-vast-candidate-adapter.mjs

import path from "node:path";
import os from "node:os";
import { writeFileSync, rmSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const SHELL = (process.env.IOI_HYPERVISOR_APP_URL || "http://127.0.0.1:4173").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
async function jd(method, url, body) {
  const r = await fetch(url.startsWith("http") ? url : `${DAEMON}${url}`, {
    method, headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: r.status, j: await r.json().catch(() => ({})) };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const vastSource = async () => {
  const s = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  return (s.sources || []).find((x) => x.source === "vast") || {};
};

async function run() {
  const tag = Date.now().toString(16);
  const SECRET = `VAST-API-KEY-${tag}`;
  const priorPolicy = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};
  // Deterministic offer fixture — REAL Vast offer field shapes, explicit fixture marking.
  const fixtureDir = path.join(os.homedir(), ".ioi", "hypervisor", "vast-fixture");
  mkdirSync(fixtureDir, { recursive: true });
  const fixtureFile = path.join(fixtureDir, `offers-${tag}.json`);
  writeFileSync(fixtureFile, JSON.stringify({
    fixture: true,
    offers: [
      { id: 90001, gpu_name: "RTX 4090", num_gpus: 2, gpu_ram: 24564, dph_total: 0.842, geolocation: "Sweden, SE", reliability2: 0.9973, verified: true, inet_down: 812, inet_up: 402, disk_space: 512 },
      { id: 90002, gpu_name: "A100 SXM4", num_gpus: 1, gpu_ram: 81920, dph_total: 1.612, geolocation: "US-TX", reliability2: 0.9812, verified: false, inet_down: 1024, inet_up: 512, disk_space: 1024 },
      { id: 90003, gpu_name: "H100 PCIE", num_gpus: 4, gpu_ram: 81559, geolocation: "Norway, NO", reliability2: 0.99, verified: true },
    ],
  }, null, 2));

  // ── 1. No vast account → source unavailable with evidence ──
  const s0 = await vastSource();
  ok("no vast account → candidate_source_unavailable with evidence",
    s0.state === "candidate_source_unavailable" && /vast_credential_absent/.test(s0.reason || "") && !!s0.evidence);

  // ── 2. Account without credential → still unavailable ──
  const vast = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "vast", display_name: `Vast ${tag}` })).j.account || {};
  const s1 = await vastSource();
  ok("account without credential → still unavailable (credential posture named)",
    s1.state === "candidate_source_unavailable" && s1.evidence?.vast_accounts >= 1);

  // ── 3. Bind + preflight: sealed bearer resolves only daemon-side ──
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/credential`, { api_key: SECRET });
  const pf = await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  ok("bearer credential binds sealed and preflight verifies via the daemon-side resolver",
    pf.j.ok === true && pf.j.account?.status === "verified"
    && !JSON.stringify(pf.j).includes(SECRET));
  const s2 = await vastSource();
  ok("verified credential, no fetch yet → credential_verified_unprobed (honest, no supply claim)",
    s2.state === "credential_verified_unprobed");

  // ── 4. Unreachable live endpoint → degraded with evidence, ZERO fake quotes ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { mode: "live", endpoint: "http://127.0.0.1:9" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`); // endpoint change → re-verify
  const intent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime"], gpu: { required: true },
  })).j.intent || {};
  const degraded = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const s3 = await vastSource();
  ok("unreachable endpoint → degraded_unreachable with evidence; no fake quotes emitted",
    s3.state === "degraded_unreachable" && /fetch failed|error/.test(JSON.stringify(s3.evidence || {}))
    && !(degraded.candidates || []).some((c) => c.provider_kind === "vast")
    && (degraded.rejected || []).some((r) => r.reason_code === "candidate_source_degraded"));

  // ── 5. Fixture mode: normalization from real offer shapes, unmistakably marked ──
  await jd("PATCH", `/v1/hypervisor/provider-accounts/${vast.account_id}`, { endpoint: { mode: "fixture", fixture_file: fixtureFile } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${vast.account_id}/preflight`);
  const refreshed = (await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref })).j;
  const vcands = (refreshed.candidates || []).filter((c) => c.provider_kind === "vast");
  ok("fixture offers normalize into CloudResourceCandidates (priced offers only — the quoteless one is skipped, not estimated)",
    vcands.length === 2, `got ${vcands.length}`);
  const c4090 = vcands.find((c) => c.gpu?.model === "RTX 4090") || {};
  ok("ProviderQuote + SpendEstimate carry the offer price VERBATIM (no invented numbers)",
    c4090.quote?.usd_per_hour === 0.842 && c4090.spend_estimate?.usd_per_hour === 0.842
    && String(c4090.quote?.quote_ref || "").startsWith("provider-quote://")
    && /verbatim/.test(c4090.quote?.basis || "")
    && c4090.spend_estimate?.cost_owner === "customer"
    && /not spend authority/.test(c4090.spend_estimate?.authority || ""));
  ok("GPU/region/reliability/network normalize from offer fields",
    c4090.gpu?.count === 2 && c4090.gpu?.vram_gb === 24 && c4090.region === "Sweden, SE"
    && c4090.reliability?.host_reliability === 0.9973 && c4090.reliability?.verified_host === true
    && c4090.network?.inet_down_mbps === 812);
  ok("quote-only posture: advisory_only eligibility, lifecycle quote_preflight_only, execution blocked by name",
    vcands.every((c) => c.placement_eligible === "advisory_only"
      && c.lifecycle === "quote_preflight_only"
      && c.execution_blocked_reason === "provider_kind_lifecycle_not_implemented"
      && (c.eligibility_labels || []).includes("lifecycle_adapter_absent")));
  ok("custody honesty: marketplace_host_NOT_private, Standard only; interruption risk labeled",
    vcands.every((c) => c.custody_plan?.privacy === "marketplace_host_NOT_private"
      && (c.custody_plan?.supported_postures || []).join() === "Standard"
      && (c.risk_labels || []).includes("marketplace_rental_interruption")));
  ok("fixture evidence is UNMISTAKABLE: candidates, quotes, and evidence all say fixture_evidence — live is never claimed",
    vcands.every((c) => c.evidence_mode === "fixture_evidence" && c.quote?.evidence_mode === "fixture_evidence"
      && c.evidence?.evidence_mode === "fixture_evidence"
      && (c.risk_labels || []).includes("fixture_evidence_not_live_supply"))
    && (await vastSource()).state === "fixture_quote_source"
    && !JSON.stringify(refreshed).includes("live_evidence"));
  ok("every vast candidate is evidence-bound with expiry timestamps on candidate AND quote",
    vcands.every((c) => c.evidence?.observed_at && c.evidence?.expires_at && c.expires_at && c.quote?.expires_at));

  // ── 6. Expiry: quotes/candidates expire and lose eligibility ──
  await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref, ttl_seconds: 5 });
  await sleep(6500);
  const stale = ((await jd("GET", `/v1/hypervisor/cloud-candidates/candidates?intent_ref=${intent.intent_ref}`)).j.candidates || [])
    .filter((c) => c.provider_kind === "vast" && c.status !== "superseded");
  ok("vast candidates expire and become ineligible (expired_requires_requote)",
    stale.length > 0 && stale.every((c) => c.status === "expired" && c.placement_eligible === false
      && (c.eligibility_labels || []).includes("expired_requires_requote")));

  // ── 7. Advisory includes Vast only as fresh advisory supply, never as the recommendation ──
  const advisory = (await jd("GET", `/v1/hypervisor/cloud-candidates/placement-advisory?intent_ref=${intent.intent_ref}`)).j;
  const advVast = (advisory.candidates || []).filter((c) => c.provider_kind === "vast" && c.status === "active");
  ok("advisory shows fresh Vast candidates as advisory-only supply; recommendation never picks them",
    advVast.length === 2
    && advisory.recommendation?.venue !== "pick_provider"
    && !(advisory.candidate_refs || []).some((r) => advVast.some((c) => c.candidate_ref === r)));
  ok("GPU intent stays honestly unplaceable: advisory supply visible, no_eligible_candidate explicit",
    /no_eligible_candidate/.test(advisory.no_eligible_candidate || "") && advisory.effective_venue === "run_local");

  // ── 8. No mutation happened; candidate/quote refs are not authority ──
  const ops = ((await jd("GET", "/v1/hypervisor/provider-operations")).j.operations || [])
    .filter((o) => o.account_ref === vast.account_ref);
  ok("no provider mutation occurred on the quote path (zero admitted ops for the vast account)", ops.length === 0);
  const asGrant = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: vast.account_id, op: "create", environment_ref: `env-vast-${tag}`,
    wallet_approval_grant: { quote_ref: c4090.quote_ref },
  });
  // The gate ladder fails closed in ORDER: budget discovery (409 budget_blocked without an
  // external_spend budget) → wallet challenge (403) → named not-implemented. A quote ref is
  // authority at NONE of those steps.
  ok("a quote presented as authority never admits: budget/quote/wallet/lifecycle gates all fail closed",
    asGrant.j.ok !== true
    && (asGrant.status === 409 || asGrant.status === 403 || asGrant.status === 422
      || /NOT_IMPLEMENTED/.test(asGrant.j.reason || "")));

  // ── 9. Fee/receipt invariants ──
  const audit = JSON.stringify({ refreshed, advisory, sources: await vastSource() }).toLowerCase();
  ok("no fee objects, no RoutingDecisionReceipt, no markup anywhere on the vast path",
    !audit.includes("routingdecisionreceipt") && !audit.includes("routing_fee_amount")
    && !audit.includes("fee_amount") && !audit.includes("markup\":"));

  // ── 10. Pinned-provider override still works ──
  const pinned = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "pick_provider", provider_account_ref: vast.account_ref });
  ok("pinned-provider override still works (vast account pinnable under pick_provider)",
    pinned.j.ok === true && pinned.j.policy?.effective_venue === "pick_provider");

  // ── 11. UI: candidate cards carry GPU / price / region / custody warning / fixture marker ──
  await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "hypervisor_choose" });
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Environments advisory card shows the Vast candidate with GPU, price, region, custody + fixture warnings",
    /RTX 4090/.test(envHtml) && /\$0\.842\/hr/.test(envHtml) && /Sweden, SE/.test(envHtml)
    && /NOT private custody/i.test(envHtml) && /fixture_evidence — deterministic local fixture/i.test(envHtml)
    && /no fee object minted/i.test(envHtml) && /quote_preflight_only/.test(envHtml));
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error" && !/ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED/.test(m.text())) consoleErrors.push(m.text()); });
  await page.goto(`${SHELL}/`, { waitUntil: "networkidle" });
  await page.click('[data-testid="create-session-button"]');
  // New Session now routes to the composer page; the owned modal opens via Advanced launch.
  await page.waitForSelector("#ioi-ns-advanced", { timeout: 15000 });
  await page.click("#ioi-ns-advanced");
  await page.waitForSelector("#ioi-ns-placement", { timeout: 15000 });
  await page.click('.ioi-ns-venue-opt[data-venue="hypervisor_choose"]');
  await page.waitForFunction(() => /Vast/.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 15000 });
  const feeText = await page.locator("#ioi-ns-venue-fee").innerText();
  ok("modal advisory list shows the Vast quote line (GPU, $/hr, fixture + custody warnings)",
    /RTX 4090/.test(feeText) && /\$0\.842\/hr/.test(feeText)
    && /fixture_evidence \(not live\)/i.test(feeText) && /not private custody/i.test(feeText));
  ok("no console errors across the vast candidate flow", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup ──
  if (priorPolicy.venue && priorPolicy.default !== true && priorPolicy.venue !== "hypervisor_choose") {
    await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: priorPolicy.venue, provider_account_ref: priorPolicy.provider_account_ref || undefined });
  } else {
    await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "run_local" });
  }
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${vast.account_id}`);
  rmSync(fixtureFile, { force: true });
  const sFinal = await vastSource();
  ok("cleanup: account removed → source honestly unavailable again; policy restored",
    sFinal.state === "candidate_source_unavailable");
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`vast candidate adapter readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
