#!/usr/bin/env node
// Sources GOVERNED DECLARE-SOURCE verifier (#69) — the focused done-bar for the surface's
// browse → act promotion, run END-TO-END in a real browser against an ISOLATED daemon+serve pair
// (temp IOI_HYPERVISOR_DATA_DIR, random ports) so every successful and rejected declaration
// journey leaves the REAL daemon's registry and receipts untouched (asserted exactly at the end).
//
//   1. CONTRACT — registry: sources = act with [browse, select, create]; the module binds with
//      ONE declared mutation (authority + dsr_ receipt + server-side confirmation).
//   2. FORM = DAEMON VOCABULARY — the kind picker and per-kind endpoint requirement derive from
//      GET /data-sources/overview source_kinds (exact option match); postures from
//      credential_postures; NO free-text secret field exists anywhere.
//   3. HAPPY JOURNEY — New source (enabled) → declare pane → fill → confirm → PRG redirect with
//      acted/receipt/record → banner with the dsr_ receipt → the new record SELECTED, catalog
//      count incremented, daemon round-trip + exact receipt-file evidence.
//   4. TYPED REFUSALS IN PLACE — daemon fail-closed rejections and runtime refusals
//      (confirmation_required, endpoint_required, endpoint_credentialed, kind_invalid,
//      posture_invalid) all render as typed banners with state unchanged; the runtime allowlist
//      NEVER forwards an undeclared field (a posted plaintext `password` dies at the runtime).
//   5. BOUNDARY — sanitized endpoint rendering (scheme+host+path only), credential sentinel never
//      rendered or persisted, hostile return refused, embed=1 preserved through the action,
//      everything past declaration disabled with its EXACT missing contract.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-sources-action.mjs
// Exit 2 = BLOCKED (daemon binary not built).

import { existsSync } from "node:fs";
import { startIsolatedPlane, receiptFileCount } from "./lib/isolated-daemon.mjs";
import { SURFACES, boundSurface, boundActionRoute } from "./surface-registry.mjs";
import * as sourcesModule from "../surfaces/sources/index.mjs";

const REAL_DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");
const REAL_DATA_DIR = process.env.IOI_HYPERVISOR_DATA_DIR || `${process.env.HOME}/.ioi/hypervisor/data`;
const RECEIPT_FAMILY = "data-source-registry-receipts";

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  const realBefore = await fetch(`${REAL_DAEMON}/v1/hypervisor/data-sources`).then((r) => r.json()).catch(() => null);
  const realReceiptsBefore = receiptFileCount(REAL_DATA_DIR, RECEIPT_FAMILY);

  // 1. CONTRACT (static, from the live registry import — the same objects the serve boots with).
  const reg = SURFACES.find((s) => s.slug === "sources");
  ok("registry: sources is act with capabilities [browse, select, create]", reg && reg.operational_state === "act" && JSON.stringify(reg.capabilities.slice().sort()) === JSON.stringify(["browse", "create", "select"]), `${reg && reg.operational_state} / ${reg && reg.capabilities.join(",")}`);
  const bhit = boundSurface("/__ioi/data/sources", "GET");
  ok("registry binds the sources module (identity, not a copy)", !!bhit && bhit.impl.render === sourcesModule.render && bhit.impl.load === sourcesModule.load);
  const ahit = boundActionRoute("/__ioi/data/sources/actions/declare", "POST");
  ok("ONE declared mutation: declare — authority POST /v1/hypervisor/data-sources, dsr_ receipt family, server-side confirmation, allowlisted fields only", !!ahit && ahit.actions.length === 1 && sourcesModule.actions.length === 1 && (() => { const a = sourcesModule.actions[0]; return a.id === "declare" && a.confirm === true && a.receipt === "ioi.hypervisor.data-source-receipt.v1" && a.authority.operation === "POST /v1/hypervisor/data-sources" && JSON.stringify(a.fields) === JSON.stringify(["name", "kind", "endpoint", "credential_posture"]); })());

  const plane = await startIsolatedPlane({ serve: true });
  if (!plane) { console.error("BLOCKED: target/debug/hypervisor-daemon is not built — cargo build -p ioi-node --bin hypervisor-daemon"); process.exit(2); }
  const { daemonUrl, serveUrl, dataDir } = plane;

  try {
    const overview = await fetch(`${daemonUrl}/v1/hypervisor/data-sources/overview`).then((r) => r.json());
    const dsCount = async () => (await fetch(`${daemonUrl}/v1/hypervisor/data-sources`).then((r) => r.json())).data_sources.length;
    // Raw form-encoded POST straight at the serve action route (the same wire a browser form uses).
    const post = async (fields) => {
      const body = new URLSearchParams(fields).toString();
      const r = await fetch(`${serveUrl}/__ioi/data/sources/actions/declare`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body, redirect: "manual" });
      return { status: r.status, location: r.headers.get("location") || "" };
    };

    const { chromium } = await import("playwright");
    const browser = await chromium.launch();
    const pg = await browser.newPage({ viewport: { width: 1440, height: 900 } });

    // 2. Bare certified render: NO form; New source + Connect-to-external-system ENABLED.
    await pg.goto(`${serveUrl}/__ioi/data/sources`, { waitUntil: "domcontentloaded" });
    let html = await pg.content();
    ok("bare certified render carries NO form (the declare pane exists only under ?declare=1)", !html.includes("<form"));
    ok("New source is ENABLED (an anchor into the declare pane, no aria-disabled)", /<a class="src-hbtn success" href="[^"]*declare=1[^"]*"/.test(html) && !/src-hbtn success gap/.test(html));
    ok("Connect to external system (set-up card) is ENABLED into the same declare pane", /<a class="src-opt c1" href="[^"]*declare=1[^"]*"/.test(html) && !html.includes("Live-connection setup is not a bound lane"));
    ok("everything past declaration stays DISABLED with its exact missing contract (tabs ×4 · store · Help · upload · synthesis · installs ×2 · favorites)", (html.match(/aria-disabled="true"/g) || []).length >= 10 && html.includes("Sync scheduling is not a bound lane") && html.includes("Connection agents are a reference-only lane") && html.includes("Listeners are a reference-only lane") && html.includes("External stacks are a reference-only lane") && html.includes("Static upload is a reference-only lane") && html.includes("Data synthesis is a reference-only lane") && html.includes("Marketplace example installs are a reference-only lane"), `${(html.match(/aria-disabled="true"/g) || []).length} disabled`);

    // 3. The declare pane derives its vocabulary from the DAEMON projection.
    await pg.click('a.src-hbtn.success');
    await pg.waitForURL(/declare=1/);
    const kindOptions = await pg.$$eval('select[name="kind"] option', (os) => os.map((o) => ({ value: o.value, label: o.textContent })));
    ok("kind picker options EXACTLY equal the daemon's source_kinds projection (order + membership)", JSON.stringify(kindOptions.map((o) => o.value)) === JSON.stringify(overview.source_kinds.map((k) => k.kind)), `${kindOptions.length} kinds`);
    ok("each kind option carries the daemon-declared endpoint requirement in its label", kindOptions.every((o) => { const k = overview.source_kinds.find((x) => x.kind === o.value); return k && o.label.includes(k.requires_endpoint ? "endpoint required" : "no endpoint (local)"); }));
    const postureOptions = await pg.$$eval('select[name="credential_posture"] option', (os) => os.map((o) => o.value));
    ok("credential posture options EXACTLY equal the daemon's credential_postures (a declared pick — never a value)", JSON.stringify(postureOptions) === JSON.stringify(overview.credential_postures));
    const inputAudit = await pg.$$eval("#declare-pane input", (ins) => ins.map((i) => `${i.type}:${i.name}`));
    ok("NO free-text secret field exists anywhere in the form (no password input; only name/endpoint text + confirm/return/hidden)", inputAudit.every((d) => !d.startsWith("password:")) && inputAudit.every((d) => !/(secret|token|api_key|apikey|credential|password)$/.test(d)), inputAudit.join(" "));
    ok("declaration is guarded by an explicit REQUIRED confirmation naming permanence (no delete authority)", (await pg.getAttribute('input[name="confirm"]', "required")) !== null && (await pg.content()).includes("permanent"));

    // 4. The endpoint requirement re-derives per kind (server render, daemon truth).
    await pg.selectOption('select[name="kind"]', "local_folder");
    await pg.waitForURL(/kind=local_folder/);
    ok("local kind → endpoint NOT required (server re-render from the projection)", (await pg.getAttribute('input[name="endpoint"]', "required")) === null && (await pg.locator(".src-dechint").textContent()).includes("optional"));
    await pg.selectOption('select[name="kind"]', "rest_api");
    await pg.waitForURL(/kind=rest_api/);
    ok("network kind → endpoint REQUIRED (server re-render from the projection)", (await pg.getAttribute('input[name="endpoint"]', "required")) !== null);

    // 5. HAPPY JOURNEY — declare through the real browser form.
    const marker = `Action Verify Source ${Date.now().toString(36)}`;
    await pg.fill('input[name="name"]', marker);
    await pg.fill('input[name="endpoint"]', "https://api.example.invalid/v1");
    await pg.selectOption('select[name="credential_posture"]', "wallet_credential_lease");
    await pg.check('input[name="confirm"]');
    await pg.click(".src-decsubmit");
    await pg.waitForURL(/acted=declare/);
    const successUrl = pg.url();
    html = await pg.content();
    const recordId = (successUrl.match(/[?&]record=(ds_[a-f0-9]+)/) || [])[1] || "";
    ok("declare → PRG redirect carrying acted/receipt/record + the banner anchor + the NEW RECORD SELECTED", /acted=declare/.test(successUrl) && /receipt=agentgres/.test(successUrl) && !!recordId && successUrl.includes(`dataSource=${recordId}`) && successUrl.includes("#ap-result"), successUrl.slice(0, 140));
    ok("success banner renders the durable dsr_ receipt in place", (await pg.locator("#ap-result").textContent()).includes("agentgres://data-source-receipt/") && (await pg.locator("#ap-result").isVisible()));
    ok("the declared record renders selected with its semantic panel + per-record disabled mutations naming EXACT missing routes", html.includes(marker) && html.includes("PATCH /v1/hypervisor/data-sources/:id does not exist") && html.includes("DELETE /v1/hypervisor/data-sources/:id does not exist") && html.includes("No connection-test authority exists"));
    const rec = (await fetch(`${daemonUrl}/v1/hypervisor/data-sources/${recordId}`).then((r) => r.json())).data_source;
    const bannerReceipt = decodeURIComponent((successUrl.match(/receipt=([^&#]+)/) || [])[1] || "");
    ok("daemon round-trip: the record exists with the EXACT receipt the banner showed (receipt_refs[0])", rec && rec.name === marker && rec.receipt_refs[0] === bannerReceipt, bannerReceipt.slice(0, 60));
    ok("exact durable evidence on the isolated plane: 1 source, 1 receipt file", (await dsCount()) === 1 && receiptFileCount(dataDir, RECEIPT_FAMILY) === 1);
    ok("catalog count reflects the declaration", (await pg.content()).includes('Declared source catalog <span class="src-count">1</span>'));

    // 6. TYPED REFUSALS IN PLACE — state unchanged after each.
    // (a) In-browser: a credential-bearing endpoint passes native validation, the DAEMON refuses.
    await pg.goto(`${serveUrl}/__ioi/data/sources?declare=1&kind=rest_api`, { waitUntil: "domcontentloaded" });
    await pg.fill('input[name="name"]', "refused-source");
    await pg.fill('input[name="endpoint"]', "https://sentinel-user:sentinel-XyZZy@h.example.invalid/x");
    await pg.check('input[name="confirm"]');
    await pg.click(".src-decsubmit");
    await pg.waitForURL(/refused=/);
    html = await pg.content();
    ok("credentialed endpoint → typed refusal IN PLACE (daemon code, state-unchanged wording, pane re-opened with the kind echoed)", pg.url().includes("refused=data_source_endpoint_credentialed") && pg.url().includes("declare=1") && pg.url().includes("kind=rest_api") && html.includes("state unchanged"));
    ok("the credential sentinel is NEVER rendered and NEVER in the URL (the rejected endpoint is not echoed)", !html.includes("XyZZy") && !pg.url().includes("XyZZy"));
    // (b) Runtime confirmation gate (server-side, independent of the browser's required attr).
    const noConfirm = await post({ name: "x", kind: "local_folder", credential_posture: "no_credentials_required" });
    ok("missing confirmation → typed confirmation_required refusal (server-enforced)", noConfirm.status === 303 && noConfirm.location.includes("refused=confirmation_required"));
    // (c) Daemon fail-closed lanes through the runtime.
    const noEp = await post({ name: "x", kind: "postgres", credential_posture: "no_credentials_required", confirm: "1" });
    ok("network kind without endpoint → typed endpoint_required refusal in place", noEp.location.includes("refused=data_source_endpoint_required") && noEp.location.includes("declare=1"));
    const badKind = await post({ name: "x", kind: "bogus", confirm: "1" });
    ok("unknown kind → typed kind_invalid refusal", badKind.location.includes("refused=data_source_kind_invalid"));
    const badPosture = await post({ name: "x", kind: "local_folder", credential_posture: "paste_it_here", confirm: "1" });
    ok("invalid posture → typed posture_invalid refusal (a malformed posture NEVER defaults)", badPosture.location.includes("refused=data_source_credential_posture_invalid"));
    const noName = await post({ kind: "local_folder", confirm: "1" });
    ok("missing name → typed name_required refusal", noName.location.includes("refused=data_source_name_required"));
    ok("EVERY refusal above changed nothing (still 1 source, 1 receipt file)", (await dsCount()) === 1 && receiptFileCount(dataDir, RECEIPT_FAMILY) === 1);
    // (d) The runtime allowlist: an undeclared plaintext-secret field is NEVER forwarded.
    const sneaky = await post({ name: "allowlist proof", kind: "local_folder", credential_posture: "no_credentials_required", confirm: "1", password: "hunter2-sentinel" });
    const allJson = JSON.stringify(await fetch(`${daemonUrl}/v1/hypervisor/data-sources`).then((r) => r.json()));
    ok("undeclared `password` field is DROPPED by the runtime allowlist — the declaration succeeds WITHOUT it and the secret persists NOWHERE", sneaky.location.includes("acted=declare") && (await dsCount()) === 2 && !allJson.includes("hunter2-sentinel"));
    // (e) Hostile return target — refused to a safe same-origin fallback.
    const hostile = await post({ name: "x", kind: "bogus", confirm: "1", return: "https://evil.example/phish" });
    ok("hostile return target falls back to the surface route (same-origin bounded)", hostile.location.startsWith("/__ioi/data/sources"));

    // 7. Sanitized endpoint rendering — query strings never reach the catalog row.
    const q = await post({ name: "query endpoint", kind: "rest_api", endpoint: "https://h.example.invalid/rows?cursor=abc&limit=5", credential_posture: "no_credentials_required", confirm: "1" });
    ok("a plain query-string endpoint is accepted (cursor/limit are not credential keys)", q.location.includes("acted=declare"));
    await pg.goto(`${serveUrl}/__ioi/data/sources`, { waitUntil: "domcontentloaded" });
    html = await pg.content();
    ok("catalog rows render endpoints scheme+host+path ONLY (the query string is stripped at display)", html.includes("https://h.example.invalid/rows") && !html.includes("cursor=abc") && (html.match(/class="src-rowpath">[^<]+/g) || []).every((p) => (p.match(/https?:\/\/\S+/g) || []).every((u) => !/[?@#]/.test(u.replace(/^https?:\/\//, "")))));

    // 8. EMBED preservation (native container contract) through render AND action.
    const em = await fetch(`${serveUrl}/__ioi/data/sources?embed=1&declare=1`).then((r) => r.text());
    ok("embedded declare pane: ported global rail structurally ABSENT, app-local tabs kept, form carries the hidden embed field", !em.includes('<aside class="og-grail') && em.includes("src-tabs") && /name="embed" value="1"/.test(em));
    const emPost = await post({ name: "embedded declare", kind: "local_folder", credential_posture: "no_credentials_required", confirm: "1", embed: "1" });
    ok("the action redirect PRESERVES embed=1 (success stays inside the native slot)", emPost.location.includes("acted=declare") && emPost.location.includes("embed=1"));

    await browser.close();
  } finally {
    await plane.stop();
  }
  ok("isolated plane torn down: the temp data dir is removed", !existsSync(dataDir));

  // 9. ISOLATION PROOF — the real daemon is byte-untouched by every journey above.
  const realAfter = await fetch(`${REAL_DAEMON}/v1/hypervisor/data-sources`).then((r) => r.json()).catch(() => null);
  ok("REAL daemon source count unchanged", (realBefore === null && realAfter === null) || (realBefore?.data_sources || []).length === (realAfter?.data_sources || []).length, realBefore ? `${(realBefore.data_sources || []).length} before/after` : "real daemon not running");
  ok("REAL daemon receipt-file count unchanged", realReceiptsBefore === receiptFileCount(REAL_DATA_DIR, RECEIPT_FAMILY), `${realReceiptsBefore} before/after`);
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`sources-action readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
