#!/usr/bin/env node
// Placement venue picker + fee/receipt preview done-bar.
//
// Proves the placement EXPERIENCE over the BYO provider plane: four explicit venues
// (run_local · use_my_infrastructure · pick_provider · hypervisor_choose) composed live from
// ProviderAccount records, environment-class eligibility, and preflight posture; per-venue fee
// bases as DECLARED COPY (no fee objects, no invented quotes, no RoutingDecisionReceipt);
// "Let Hypervisor choose" as a planned/advisory placeholder (never a hidden auto); the durable
// venue policy consumed by New Session previews and environment create; receipts NAMED before
// launch; and provider receipts reachable from Operations and the Work Ledger proof stream.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-placement-venue-picker.mjs

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

async function run() {
  const tag = Date.now().toString(16);
  const fixture = await ensureSshFixture();
  const priorPolicy = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};

  // ── Fixtures: one verified SSH account + one cloud (aws) account ──
  const ssh = (await jd("POST", "/v1/hypervisor/provider-accounts", {
    kind: "baremetal_ssh", display_name: `BYO node ${tag}`,
    endpoint: { host: fixture.host, port: fixture.port, user: fixture.user },
  })).j.account || {};
  await jd("POST", `/v1/hypervisor/provider-accounts/${ssh.account_id}/credential`, { private_key: fixture.client_key });
  const sshPf = await jd("POST", `/v1/hypervisor/provider-accounts/${ssh.account_id}/preflight`);
  const aws = (await jd("POST", "/v1/hypervisor/provider-accounts", { kind: "aws", display_name: `AWS ${tag}` })).j.account || {};
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/credential`, { secret_access_key: `sk-${tag}`, aux: { access_key_id: "AKIA-TEST", region: "us-east-1" } });
  await jd("POST", `/v1/hypervisor/provider-accounts/${aws.account_id}/preflight`);
  ok("fixtures ready (verified ssh + preflighted aws account)", sshPf.j.ok === true && !!aws.account_id);

  // ── 1. Venue catalog: four explicit venues, live-composed, fee taxonomy declared ──
  const venuesRes = (await jd("GET", "/v1/hypervisor/placement/venues")).j;
  const venues = Object.fromEntries((venuesRes.venues || []).map((v) => [v.venue, v]));
  ok("four venues compose live (local · my infrastructure · pick cloud · hypervisor choose)",
    ["run_local", "use_my_infrastructure", "pick_provider", "hypervisor_choose"].every((v) => venues[v])
    && /customer-borne/.test(venuesRes.spend_rule || "")
    && ["none", "subscription_control_plane", "adapter_orchestration_fee", "routing_fee", "managed_margin"].every((f) => venuesRes.fee_bases[f]));
  ok("venue availability is honest (BYO available only via verified account; cloud lists connected + not-connected kinds)",
    venues.run_local.available === true
    && venues.use_my_infrastructure.available === true
    && (venues.use_my_infrastructure.providers || []).some((p) => p.account_ref === ssh.account_ref && p.status === "verified")
    && (venues.pick_provider.providers || []).some((p) => p.account_ref === aws.account_ref && p.connected === true)
    && (venues.pick_provider.providers || []).some((p) => p.connected === false && p.status === "not_connected"));
  const sshCard = (venues.use_my_infrastructure.providers || []).find((p) => p.account_ref === ssh.account_ref) || {};
  ok("provider cards carry classes + capability hints + cost owner (kind-level hints, never probed claims)",
    (sshCard.environment_classes?.supported || []).includes("byo-ssh-node")
    && ["gpu", "persistent_storage", "ip", "snapshot"].every((k) => sshCard.capability_hints?.[k])
    && /kind-level hints/.test(sshCard.capability_hints?.basis || "")
    && sshCard.cost_owner === "customer");

  // ── 2. Fee copy per venue: declared basis, no fee objects, no percentages on BYO ──
  ok("direct BYO path shows NO provider-spend percentage (fee basis none)",
    venues.use_my_infrastructure.fee?.fee_basis === "none"
    && /no provider-spend percentage/i.test(venues.use_my_infrastructure.fee?.fee_explanation || "")
    && venues.use_my_infrastructure.fee?.fee_object_minted === false);
  ok("pinned-provider path declares the orchestration fee basis honestly (nothing charged today)",
    venues.pick_provider.fee?.fee_basis === "adapter_orchestration_fee"
    && /never a percentage/i.test(venues.pick_provider.fee?.fee_explanation || "")
    && /nothing is charged today/i.test(venues.pick_provider.fee?.fee_explanation || ""));
  ok("hypervisor_choose is the ADVISORY lane: candidate plane fills it, routing-fee covenant still named",
    venues.hypervisor_choose.status === "advisory"
    && venues.hypervisor_choose.fee?.fee_basis === "routing_fee"
    && /RoutingDecisionReceipt/.test(venues.hypervisor_choose.fee?.fee_explanation || "")
    && venues.hypervisor_choose.fee_object_minted === false
    && Array.isArray(venues.hypervisor_choose.candidates));
  const venuesStr = JSON.stringify(venuesRes);
  ok("no invented quotes and no fee objects anywhere in the catalog",
    venues.pick_provider.quote === null && /no invented quotes/.test(venues.pick_provider.quote_policy || "")
    && !/"price"|"quote_amount"|"fee_amount"|"hourly"/.test(venuesStr)
    && /no fee object/.test(venuesRes.no_fee_objects || ""));

  // ── 3. Durable venue policy: explicit, validated, never hidden ──
  const badVenue = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "somewhere_else" });
  const noAccount = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "use_my_infrastructure" });
  const kindMismatch = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "pick_provider", provider_account_ref: ssh.account_ref });
  ok("venue policy PUT validates: unknown venue 422, provider venues need a matching account",
    badVenue.status === 422 && badVenue.j.error?.code === "placement_venue_invalid"
    && noAccount.status === 422 && noAccount.j.error?.code === "placement_provider_account_required"
    && kindMismatch.status === 422 && kindMismatch.j.error?.code === "placement_provider_kind_mismatch");
  const chooseByo = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "use_my_infrastructure", provider_account_ref: ssh.account_ref });
  ok("choosing BYO persists the durable policy with a provider snapshot",
    chooseByo.j.ok === true && chooseByo.j.policy?.venue === "use_my_infrastructure"
    && chooseByo.j.policy?.provider_snapshot?.status_at_choice === "verified"
    && chooseByo.j.fee?.fee_basis === "none");
  const chooseAuto = await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "hypervisor_choose" });
  ok("hypervisor_choose records an ADVISORY preference — live advisory resolves the effective venue, note explicit",
    chooseAuto.j.policy?.advisory === true
    && ["run_local", "use_my_infrastructure", "pick_provider"].includes(chooseAuto.j.policy?.effective_venue)
    && String(chooseAuto.j.policy?.advisory_ref || "").startsWith("placement-advisory://")
    && /never a hidden auto/.test(chooseAuto.j.policy?.advisory_note || ""));
  const history = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy?.history || [];
  ok("venue changes append history (the choice trail is auditable)",
    history.some((h) => h.venue === "use_my_infrastructure"));

  // ── 4. Placement preview NAMES receipts before launch ──
  await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "use_my_infrastructure", provider_account_ref: ssh.account_ref });
  const byoPreview = (await jd("GET", "/v1/hypervisor/placement/preview")).j;
  const byoReceipts = JSON.stringify(byoPreview.receipts_expected || []);
  ok("BYO preview names the receipt kinds a run will mint (provider receipts, admitted ops, lease, placement decision, budget note)",
    /provider-receipt\/prc_/.test(byoReceipts) && /provider-operation/.test(byoReceipts)
    && /capability-lease/.test(byoReceipts) && /placement-decision/.test(byoReceipts)
    && /local_free/.test(byoReceipts) && byoPreview.provider_card?.account_ref === ssh.account_ref);
  const cloudPreview = (await jd("GET", `/v1/hypervisor/placement/preview?venue=pick_provider&provider_account_ref=${aws.account_ref}`)).j;
  const cloudReceipts = JSON.stringify(cloudPreview.receipts_expected || []);
  ok("pinned-cloud preview names external_spend budget discovery + fail-closed honesty (no fake provisioning)",
    /external_spend/.test(cloudReceipts) && /PROVIDER_KIND_LIFECYCLE_NOT_IMPLEMENTED/.test(cloudReceipts)
    && cloudPreview.quote === null && cloudPreview.fee?.fee_basis === "adapter_orchestration_fee");

  // ── 5. New Session + Environments consume the chosen policy ──
  const lp = (await jd("POST", "/v1/hypervisor/ioi-agent/launch-preview", { goal: `placement preview probe ${tag}` })).j;
  ok("ioi-agent launch preview carries the placement block (venue, fee copy, receipts named)",
    lp.placement?.venue === "use_my_infrastructure"
    && lp.placement?.provider_account_ref === ssh.account_ref
    && lp.placement?.fee?.fee_basis === "none"
    && (lp.placement?.receipts_expected || []).length > 0);
  const envRes = (await jd("POST", "/v1/hypervisor/environments", { environment_id: `env-pvp-${tag}` })).j;
  const envVenue = envRes.environment?.spec?.placement_venue || {};
  ok("environment create snapshots the venue policy in force (provenance on the env record)",
    envVenue.venue === "use_my_infrastructure" && envVenue.provider_account_ref === ssh.account_ref);
  await jd("DELETE", `/v1/hypervisor/environments/env-pvp-${tag}`);

  // ── 6. Operations + Work Ledger show provider receipt links ──
  const ledger = (await jd("GET", "/v1/hypervisor/work-ledger")).j.entries || [];
  const crossing = ledger.find((e) => e.kind === "provider_crossing" && e.account_ref === ssh.account_ref);
  ok("Work Ledger indexes provider crossings as proof entries (receipt ref + provider health link)",
    !!crossing && String(crossing.receipt_ref || "").startsWith("agentgres://provider-receipt/")
    && String(crossing.provider_health_ref || "").includes("/__ioi/operations"));
  const opsHtml = await fetch(`${SHELL}/__ioi/operations`).then((r) => r.text());
  ok("Operations links provider receipts into the ledger proof stream",
    opsHtml.includes('id="ops-provider-health"') && /ledger →/.test(opsHtml)
    && opsHtml.includes('href="/__ioi/work-ledger"'));
  const wlHtml = await fetch(`${SHELL}/__ioi/work-ledger`).then((r) => r.text());
  ok("Work Ledger surface renders the provider-crossing facet", /Provider crossings/.test(wlHtml));

  // ── 7. Environments surface: venue cards + fee copy ──
  const envHtml = await fetch(`${SHELL}/__ioi/environments`).then((r) => r.text());
  ok("Environments shows the four venue cards with fee copy and the chosen venue marked",
    envHtml.includes('id="env-placement-venues"')
    && ["Run local", "Use my infrastructure", "Pick a cloud", "Let Hypervisor choose"].every((n) => envHtml.includes(n))
    && /no provider-spend percentage/i.test(envHtml)
    && /adapter_orchestration_fee/.test(envHtml)
    && /planned/.test(envHtml)
    && envHtml.includes(ssh.account_ref));

  // ── 8. Playwright: all four choices + fee copy in the New Session modal ──
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on("pageerror", (e) => consoleErrors.push(String(e)));
  // External docs-image probes (docs.ioi.com) DNS-fail in offline runs — resource noise, not
  // a surface error; page errors and real console errors still fail the gate.
  page.on("console", (m) => { if (m.type() === "error" && !/ERR_NAME_NOT_RESOLVED|ERR_INTERNET_DISCONNECTED/.test(m.text())) consoleErrors.push(m.text()); });
  await page.goto(`${SHELL}/`, { waitUntil: "networkidle" });
  await page.click('[data-testid="create-session-button"]');
  await page.waitForSelector("#ioi-ns-modal.open", { timeout: 15000 });
  await page.waitForSelector("#ioi-ns-placement", { timeout: 15000 });
  const venueBtns = await page.locator(".ioi-ns-venue-opt").count();
  ok("modal offers all four venue choices", venueBtns === 4);
  const feeText = async () => (await page.locator("#ioi-ns-venue-fee").innerText());
  await page.click('.ioi-ns-venue-opt[data-venue="run_local"]');
  await page.waitForFunction(() => /No fee/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  ok("run_local fee copy: no fee, subscription covers the control plane", /subscription/i.test(await feeText()));
  await page.click('.ioi-ns-venue-opt[data-venue="use_my_infrastructure"]');
  await page.waitForFunction(() => /no provider-spend percentage/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  ok("BYO fee copy in modal: no provider-spend percentage; provider select pins the account",
    (await page.locator("#ioi-ns-venue-provider").isVisible()) === true);
  await page.click('.ioi-ns-venue-opt[data-venue="pick_provider"]');
  await page.waitForFunction(() => /orchestration fee/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  ok("pinned-cloud fee copy in modal explains the orchestration fee (never a percentage)",
    /never a percentage/i.test(await feeText()));
  const advisoryBadge = await page.locator('.ioi-ns-venue-opt[data-venue="hypervisor_choose"] .ioi-ns-venue-badge').innerText();
  await page.click('.ioi-ns-venue-opt[data-venue="hypervisor_choose"]');
  await page.waitForFunction(() => /routing fee|RoutingDecisionReceipt/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  ok("hypervisor_choose renders the ADVISORY lane and states the routing-fee covenant — never a hidden auto",
    /advisory/i.test(advisoryBadge) && /Advisory recommends|no eligible candidate/i.test(await feeText()));
  // The preview consumes the chosen policy: placement line + venue receipts named before launch.
  await page.click('.ioi-ns-venue-opt[data-venue="use_my_infrastructure"]');
  await page.waitForFunction(() => /no provider-spend percentage/i.test(document.getElementById("ioi-ns-venue-fee")?.innerText || ""), null, { timeout: 10000 });
  await page.fill("#ioi-ns-goal", "probe the placement preview line");
  await page.waitForFunction(() => /Placement/.test(document.getElementById("ioi-ns-preview")?.innerText || ""), null, { timeout: 20000 });
  const previewText = await page.locator("#ioi-ns-preview").innerText();
  ok("New Session preview states the venue, fee basis, and venue receipts BEFORE launch",
    /venue use_my_infrastructure/.test(previewText) && /fee basis none/.test(previewText)
    && /Venue receipts/.test(previewText) && /provider-receipt/.test(previewText));
  ok("no console errors across the picker flow", consoleErrors.length === 0, consoleErrors.slice(0, 2).join(" | "));
  await browser.close();
  const ft = await fetch(`${SHELL}/__ioi/fallthrough`).then((r) => r.json()).catch(() => ({}));
  ok("fallthrough stays empty", Array.isArray(ft.proxied) && ft.proxied.length === 0);

  // ── Cleanup: restore the prior venue policy, remove fixture accounts ──
  if (priorPolicy.venue && priorPolicy.default !== true) {
    await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: priorPolicy.venue, provider_account_ref: priorPolicy.provider_account_ref || undefined });
  } else {
    await jd("PUT", "/v1/hypervisor/placement/venue-policy", { venue: "run_local" });
  }
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${aws.account_id}`);
  await jd("DELETE", `/v1/hypervisor/provider-accounts/${ssh.account_id}`);
  const finalPolicy = (await jd("GET", "/v1/hypervisor/placement/venue-policy")).j.policy || {};
  ok("cleanup: fixture accounts removed, venue policy restored",
    finalPolicy.venue === (priorPolicy.default !== true && priorPolicy.venue ? priorPolicy.venue : "run_local"));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`placement venue picker readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
