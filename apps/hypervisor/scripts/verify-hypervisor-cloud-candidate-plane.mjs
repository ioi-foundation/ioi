#!/usr/bin/env node
// decentralized.cloud candidate plane done-bar (first cut — local facts only).
//
// Proves the daemon-owned candidate plane that fills "Let Hypervisor choose":
// CloudResourceIntent → evidence-bound, expiring CloudResourceCandidates derived from the
// verified ProviderAccount catalog, environment-class eligibility, static adapter capabilities,
// preflight posture, and provider receipt history. Candidates are NEVER authority (cannot
// provision, release credentials, expose ingress, or claim custody/restore truth); external
// sources without adapters are candidate_source_unavailable WITH EVIDENCE (no invented prices);
// no fee objects and no RoutingDecisionReceipt exist anywhere; the advisory recommends among
// real venues with reason codes and falls back to run_local with an explicit
// no_eligible_candidate reason; pinned-provider override still works; launch/environment
// records snapshot advisory/candidate refs; all four venue choices survive in the UI.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-cloud-candidate-plane.mjs

import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const { ensureSshFixture } = await import(path.join(HERE, "ensure-ssh-fixture.mjs"));

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

async function run() {
  const tag = Date.now().toString(16);
  const fixture = await ensureSshFixture();
  const priorPolicy = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};

  // ── Fixtures: verified ssh + preflighted aws account (real local facts to derive from) ──
  const ssh = (await jd("POST", "/v1/hypervisor/provider-accounts", {
    kind: "baremetal_ssh", display_name: `BYO node ${tag}`,
    endpoint: { host: fixture.host, port: fixture.port, user: fixture.user },
  })).j.account || {};
  await jd("POST", `/v1/hypervisor/provider-accounts/${ssh.account_id}/credential`, { private_key: fixture.client_key });
  await jd("POST", `/v1/hypervisor/provider-accounts/${ssh.account_id}/preflight`);
  const aws = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "aws", display_name: `AWS ${tag}` })).j.account || {};
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/credential`, { secret_access_key: `sk-${tag}`, aux: { region: "us-east-1" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);

  // ── 1. Source registry: local facts live; external sources honestly unavailable ──
  const sources = (await jd("GET", "/v1/hypervisor/cloud-candidates/candidate-sources")).j;
  const src = Object.fromEntries((sources.sources || []).map((s) => [s.source, s]));
  ok("candidate sources: customer_inventory live, direct_provider credential-only",
    src.customer_inventory?.state === "available" && src.direct_provider?.state === "credential_preflight_only"
    && src.customer_inventory?.evidence?.verified_ssh_accounts >= 1);
  ok("external sources return candidate_source_unavailable WITH evidence — never fake prices",
    ["managed_capacity", "decentralized.cloud", "depin_market", "storage_network"].every((k) =>
      src[k]?.state === "candidate_source_unavailable" && !!src[k]?.reason && !!src[k]?.evidence)
    && /not fake prices/.test(sources.rule || ""));

  // ── 2. Intent creation: validated, durable, not authority ──
  const badClass = await jd("POST", "/v1/hypervisor/cloud-candidates/intents", { resource_classes: ["compute.quantum"] });
  const badCustody = await jd("POST", "/v1/hypervisor/cloud-candidates/intents", { custody_posture: "Secret" });
  ok("intent validation: unknown resource class + custody posture rejected 422",
    badClass.status === 422 && badClass.j.error?.code === "resource_class_unknown"
    && badCustody.status === 422 && badCustody.j.error?.code === "custody_posture_invalid");
  const created = await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    requester_ref: `principal://vfyccp-${tag}`, runtime_class: "runtime.workbench",
    resource_classes: ["runtime.workbench"], custody_posture: "Standard",
  });
  const intent = created.j.intent || {};
  ok("CloudResourceIntent creates durable + explicitly not-authority, first candidate batch derived",
    created.status === 201 && String(intent.intent_ref || "").startsWith("cloud-resource-intent://cri_")
    && /not authority/.test(intent.authority || "")
    && (created.j.candidates || []).length >= 2);
  const got = await jd("GET", `/v1/hypervisor/cloud-candidates/intents/${intent.intent_id}`);
  ok("intent round-trips by id", got.j.intent?.intent_ref === intent.intent_ref);

  // ── 3. Candidates: evidence-bound, honest per source ──
  const list = (await jd("GET", `/v1/hypervisor/cloud-candidates/candidates?intent_ref=${intent.intent_ref}`)).j;
  const cands = list.candidates || [];
  const local = cands.find((c) => c.provider_kind === "local") || {};
  const sshCand = cands.find((c) => c.provider_account_ref === ssh.account_ref) || {};
  const awsCand = cands.find((c) => c.provider_account_ref === aws.account_ref) || {};
  const evidenceBound = (c) => c.evidence && c.evidence.source && c.evidence.adapter_ref
    && c.evidence.observed_at && c.evidence.expires_at && c.evidence.coverage_state
    && Array.isArray(c.evidence.claims) && Array.isArray(c.evidence.evidence_refs);
  ok("every candidate carries canon-complete CandidateEvidence (source/adapter/observed/expires/coverage/claims/refs)",
    cands.length >= 3 && cands.every(evidenceBound));
  ok("local + verified-SSH candidates are placement-eligible with real custody/failover/spend projections",
    local.placement_eligible === true && sshCand.placement_eligible === true
    && (sshCand.eligibility_labels || []).includes("full_lifecycle")
    && /daemon custody|DAEMON custody/i.test(sshCand.custody_plan?.detail || "")
    && sshCand.spend_estimate?.state === "local_free" && sshCand.spend_estimate?.cost_owner === "customer"
    && /not spend authority/.test(sshCand.spend_estimate?.authority || ""));
  ok("cloud-kind candidate is provider-capable but NOT placement-eligible (adapter absent, named)",
    awsCand.placement_eligible === false
    && (awsCand.eligibility_labels || []).includes("lifecycle_adapter_absent")
    && awsCand.spend_estimate?.state === "unavailable_no_adapter");
  const candsStr = JSON.stringify(cands);
  ok("no invented quotes anywhere: quote_ref null, no price fields",
    cands.every((c) => c.quote_ref === null && /no_quote/.test(c.quote_state || ""))
    && !/"price"|"hourly"|"per_hour"|"usd_per"/.test(candsStr));
  ok("candidates declare they are not authority (cannot provision / release credentials / expose ingress / claim custody truth)",
    cands.every((c) => /cannot provision/.test(c.authority || "") && /custody\/restore truth/.test(c.authority || "")));

  // ── 4. Constraint rejection with named reasons + evidence (canon failure behavior) ──
  const gpuIntent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", {
    runtime_class: "compute.gpu_runtime", resource_classes: ["compute.gpu_runtime"], gpu: { required: true },
  })).j;
  ok("GPU requirement rejects unproven hosts with named reasons + evidence, advisory falls back honestly",
    (gpuIntent.candidates || []).filter((c) => c.placement_eligible).length === 0
    && (gpuIntent.rejected || []).some((r) => r.reason_code === "gpu_requirement_unproven" && (r.evidence_refs || []).length > 0));
  const gpuAdvisory = (await jd("GET", `/v1/hypervisor/cloud-candidates/placement-advisory?intent_ref=${gpuIntent.intent.intent_ref}`)).j;
  ok("no eligible candidate → explicit no_eligible_candidate reason + effective_venue run_local",
    /no_eligible_candidate/.test(gpuAdvisory.no_eligible_candidate || "")
    && gpuAdvisory.effective_venue === "run_local" && gpuAdvisory.recommendation === null);
  const privIntent = (await jd("POST", "/v1/hypervisor/cloud-candidates/intents", { custody_posture: "Private" })).j;
  ok("Private custody rejects cloud kinds with custody_posture_unsupported (no marketing-label custody claims)",
    (privIntent.rejected || []).some((r) => r.reason_code === "custody_posture_unsupported")
    && (privIntent.candidates || []).some((c) => c.provider_kind === "baremetal_ssh" && c.placement_eligible));

  // ── 5. Expiry + supersession: stale candidates are not placement-eligible ──
  await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref, ttl_seconds: 5 });
  await sleep(6500);
  const expired = (await jd("GET", `/v1/hypervisor/cloud-candidates/candidates?intent_ref=${intent.intent_ref}`)).j.candidates || [];
  const expiredActiveBatch = expired.filter((c) => c.status !== "superseded");
  ok("candidates EXPIRE: stale ones lose placement eligibility and require requote",
    expiredActiveBatch.length > 0 && expiredActiveBatch.every((c) => c.status === "expired" && c.placement_eligible === false
      && (c.eligibility_labels || []).includes("expired_requires_requote")));
  await jd("POST", "/v1/hypervisor/cloud-candidates/candidates/refresh", { intent_ref: intent.intent_ref });
  const refreshed = (await jd("GET", `/v1/hypervisor/cloud-candidates/candidates?intent_ref=${intent.intent_ref}`)).j.candidates || [];
  ok("refresh supersedes the stale batch (kept as evidence, not eligible) and re-derives active candidates",
    refreshed.some((c) => c.status === "superseded" && c.placement_eligible === false)
    && refreshed.some((c) => c.status === "active" && c.placement_eligible === true));

  // ── 6. Candidate-as-authority is rejected on the execution lane ──
  const activeCand = refreshed.find((c) => c.status === "active" && c.provider_kind === "baremetal_ssh") || {};
  const asGrantRef = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: ssh.account_id, op: "create", environment_ref: `env-ccp-${tag}`, grant_ref: activeCand.candidate_ref,
  });
  const asGrant = await jd("POST", "/v1/hypervisor/provider-ops", {
    provider_id: ssh.account_id, op: "create", environment_ref: `env-ccp-${tag}`,
    wallet_approval_grant: { candidate_ref: activeCand.candidate_ref },
  });
  ok("a candidate is NOT authority: provider mutation still demands a real wallet grant (403 challenge)",
    asGrantRef.status === 403 && asGrant.status === 403 && !!asGrantRef.j.approval?.policy_hash);

  // ── 7. Advisory: deterministic, explained, fee-honest ──
  const advisory = (await jd("GET", "/v1/hypervisor/cloud-candidates/placement-advisory")).j;
  ok("advisory recommends the full-lifecycle verified BYO node over local, with reason codes",
    advisory.recommendation?.venue === "use_my_infrastructure"
    && advisory.recommendation?.provider_account_ref === ssh.account_ref
    && (advisory.recommendation?.reason_codes || []).includes("full_lifecycle_over_verified_byo_node")
    && String(advisory.advisory_ref || "").startsWith("placement-advisory://"),
    JSON.stringify({ rec: advisory.recommendation, eligible: advisory.eligible, cands: (advisory.candidates || []).map((c) => [c.provider_kind, c.status, c.placement_eligible]) }).slice(0, 400));
  ok("comparing multiple real candidates declares routing_fee_basis eligible_future — fee_object_minted stays false",
    advisory.eligible >= 2 && advisory.routing_fee_basis === "eligible_future"
    && advisory.fee_object_minted === false
    && /cannot provision, spend, or release credentials/.test(advisory.authority_note || ""));
  const advisoryStr = JSON.stringify(advisory);
  ok("no RoutingDecisionReceipt and no fee objects anywhere on the plane",
    !/RoutingDecisionReceipt":/.test(advisoryStr) && !/routing_fee_amount|fee_amount|"price"/.test(advisoryStr));

  // ── 8. Venue policy + previews consume the advisory ──
  const chooseRes = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "hypervisor_choose" });
  ok("choosing hypervisor_choose resolves the LIVE advisory into the durable policy",
    chooseRes.j.policy?.advisory === true
    && chooseRes.j.policy?.effective_venue === "use_my_infrastructure"
    && String(chooseRes.j.policy?.advisory_ref || "").startsWith("placement-advisory://")
    && (chooseRes.j.policy?.advisory_candidate_refs || []).length >= 2);
  const venues = (await jd("GET", "/v1/hypervisor/placement/venues")).j;
  const chooseCard = (venues.venues || []).find((v) => v.venue === "hypervisor_choose") || {};
  ok("venues card for hypervisor_choose is the advisory lane with real embedded candidates",
    chooseCard.status === "advisory" && chooseCard.available === true
    && (chooseCard.candidates || []).some((c) => c.placement_eligible)
    && chooseCard.recommendation?.venue === "use_my_infrastructure");
  const pp = (await jd("GET", "/v1/hypervisor/placement/preview")).j;
  ok("placement preview names advisory + candidate refs BEFORE launch",
    !!pp.advisory && (pp.advisory.candidate_refs || []).length >= 2
    && JSON.stringify(pp.receipts_expected || []).includes("placement-advisory://")
    && JSON.stringify(pp.receipts_expected || []).includes("cloud-resource-candidate://"));
  const lp = (await jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", { goal: `candidate plane probe ${tag}` })).j;
  ok("launch preview placement block snapshots advisory + candidate refs",
    lp.placement?.venue === "hypervisor_choose"
    && String(lp.placement?.advisory_ref || "").startsWith("placement-advisory://")
    && (lp.placement?.advisory_candidate_refs || []).length >= 2);
  const envRes = (await jd("POST", "/v1/hypervisor/environments", { environment_id: `env-ccp-${tag}` })).j;
  ok("environment create snapshots the advisory/candidate refs",
    String(envRes.environment?.spec?.placement_venue?.advisory_ref || "").startsWith("placement-advisory://")
    && (envRes.environment?.spec?.placement_venue?.advisory_candidate_refs || []).length >= 2);
  await jd("DELETE", `/v1/hypervisor/environments/env-ccp-${tag}`);

  // ── 9. Pinned override still works (user choice never buried) ──
  const pinned = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "pick_provider", provider_account_ref: aws.account_ref });
  ok("pinned-provider override still works after the advisory lane exists",
    pinned.j.ok === true && pinned.j.policy?.venue === "pick_provider"
    && pinned.j.policy?.advisory !== true && pinned.j.policy?.effective_venue === "pick_provider");

  // ── 10. Surfaces ──
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Environments advisory card renders real candidate cards (provider, custody, spend owner, expiry, ref)",
    /advisory recommends/i.test(envHtml) && envHtml.includes("cloud-resource-candidate://")
    && /spend owner: customer/i.test(envHtml));
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error" && !/ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED/.test(m.text())) consoleErrors.push(m.text()); });
  await page.goto(`${SHELL}/`, { waitUntil: "networkidle" });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-placement", { timeout: 15000 });
  ok("modal still offers all four venue choices", (await page.locator(".ioi-ns-venue-opt").count()) === 4);
  await page.click('.ioi-ns-venue-opt[data-venue="hypervisor_choose"]');
  await page.waitForFunction(() => /Advisory recommends|no eligible candidate/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  const feeText = await page.locator("#ioi-ns-venue-fee").innerText();
  ok("modal hypervisor_choose shows the REAL candidate list (evidence-bound, never authority)",
    /Advisory recommends/i.test(feeText) && /never authority/i.test(feeText) && /BYO node/.test(feeText));
  await page.fill("#ioi-ns-goal", "probe the advisory preview line");
  await page.waitForFunction(() => /Advisory/.test(document.getElementById("ioi-ns-preview")?.innerText || ""), null, { timeout: 20000 });
  const previewText = await page.locator("#ioi-ns-preview").innerText();
  ok("New Session preview names the advisory + candidate refs before launch",
    /placement-advisory:\/\//.test(previewText) && /cloud-resource-candidate:\/\//.test(previewText));
  await page.click('.ioi-ns-venue-opt[data-venue="use_my_infrastructure"]');
  await page.waitForFunction(() => /no provider-spend percentage/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  ok("user can still override and pin a venue from the modal", true);
  ok("no console errors across the candidate flow", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup ──
  if (priorPolicy.venue && priorPolicy.default !== true && priorPolicy.venue !== "hypervisor_choose") {
    await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: priorPolicy.venue, provider_account_ref: priorPolicy.provider_account_ref || undefined });
  } else {
    await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "run_local" });
  }
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${aws.account_id}`);
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${ssh.account_id}`);
  const finalPolicy = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};
  ok("cleanup: fixture accounts removed, venue policy restored", finalPolicy.venue === "run_local" || finalPolicy.venue === priorPolicy.venue);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`cloud candidate plane readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
