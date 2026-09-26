#!/usr/bin/env node
// check:notification-panel — ADR 0056 P1, the inbox UI: the shell's panel over the notification inbox.
//
// The inbox is a daemon projection (check:notification-inbox proves it). This proves the SURFACE that
// renders it, in a real browser on the verifier's own daemon and serve: the bell beside What's new opens
// a dialog whose rows are exactly what GET /v1/hypervisor/notifications answers the same person — same
// items, same order, one link per item to the record that owns it — grouped by day; the family chips are
// the envelope's own counts and filter as the API filters; the certified rail's Notifications item lands
// on the panel and claims no count; and the states are distinct and truthful: a signed-out visitor is
// told to sign in (never shown an empty inbox), a dead daemon is said as unavailable. Nothing is marked
// read or unread: the daemon keeps no read state.
//
// Exit 0 pass · 1 fail · 2 blocked (no daemon binary or no browser).

import { chromium } from "playwright";
import { isolatedOperatorSession, startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { callerOwnerRef } from "../surfaces/kit.mjs";

const results = [];
const ok = (name, cond, detail = "") => {
  results.push({ name, pass: !!cond, detail: String(detail).slice(0, 300) });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : ` — ${String(detail).slice(0, 300)}`}`);
};

let plane = null;
let browser = null;
let exitCode = 1;
try {
  plane = await startIsolatedPlane({ serve: true, env: { IOI_PRODUCT_SIGNIN_REQUIRED: "0" } });
  if (!plane) { console.error("BLOCKED: target/debug/hypervisor-daemon is not built"); process.exit(2); }
  const D = plane.daemonUrl;
  const S = plane.serveUrl;
  const session = await isolatedOperatorSession(plane);
  const H = { cookie: `ioi_session=${session}` };
  const get = (base, p, h = H) => fetch(`${base}${p}`, { headers: { accept: "application/json", ...h } }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => null) }));
  const post = (p, b) => fetch(`${D}${p}`, { method: "POST", headers: { ...H, "content-type": "application/json" }, body: JSON.stringify(b) }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));

  // Owner events, raised through the owners' own routes: an approval request and a filed issue.
  const imp = await post("/v1/hypervisor/intelligence/improvement-proposals", { proposal_kind: "skill_improvement", signal: "notification-panel", evidence_refs: ["agent-run-transcript://notification-panel"], rationale: "panel verifier" });
  const proposalRef = imp.j.proposal?.proposal_ref || "";
  const appr = await post("/v1/hypervisor/governance/approval-requests", { subject_ref: proposalRef, request_kind: "improvement_apply", reason: "notification panel verifier" });
  const owner = callerOwnerRef((await get(D, "/v1/hypervisor/auth/whoami")).j);
  const inc = await post("/v1/hypervisor/support-incidents", { owner_ref: owner, idempotency_key: "notification-panel-1", title: "Panel verifier issue", severity: "minor", affected_object_refs: ["dataset://notification-panel/orders"] });
  const direct = await get(S, "/v1/hypervisor/notifications?limit=25");
  const items = direct.j?.items || [];
  ok("SETUP — owner events raised through the owners' routes, and the inbox answers them through the serve",
    appr.j.approval_request?.ref && inc.j.incident?.incident_id && direct.status === 200 && items.length >= 2,
    `${appr.status} ${inc.status} inbox ${direct.status} items ${items.length}`);

  try { browser = await chromium.launch({ headless: true }); } catch (error) { console.error(`BLOCKED: no browser (${error.message})`); process.exit(2); }
  const origin = new URL(S);
  const signedIn = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  await signedIn.addCookies([{ name: "ioi_session", value: session, domain: origin.hostname, path: "/" }]);
  const page = await signedIn.newPage();
  await page.goto(`${S}/ai`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  const bell = page.locator("#ioi-notif-bell");
  await bell.waitFor({ state: "visible", timeout: 90_000 });
  const beside = await page.evaluate(() => {
    const b = document.getElementById("ioi-notif-bell");
    const w = document.querySelector('[data-testid="changelog-button"]');
    return !!(b && w && b.closest("div").parentElement === w.parentElement.parentElement);
  });
  await bell.click();
  const panel = page.locator("#ioi-notif-panel");
  await page.locator('#ioi-notif-panel [data-ioi-notif-state="ready"]').waitFor({ timeout: 60_000 });
  const dialog = await panel.evaluate((el) => ({ role: el.getAttribute("role"), modal: el.getAttribute("aria-modal"), label: el.getAttribute("aria-label"), open: el.classList.contains("open") }));
  ok("THE BELL — beside What's new in the shell's footer, it opens a dialog (role, aria-modal, label)",
    beside && dialog.role === "dialog" && dialog.modal === "true" && dialog.label === "Notifications" && dialog.open, JSON.stringify({ beside, dialog }));

  const rows = await page.$$eval("#ioi-notif-panel [data-ioi-notif-item]", (els) => els.map((el) => ({
    id: el.getAttribute("data-ioi-notif-item"),
    title: el.querySelector(".ioi-notif-title")?.textContent || "",
    links: [...el.querySelectorAll("a[data-ioi-notif-link]")].map((a) => a.getAttribute("href")),
  })));
  ok("ROWS ARE THE INBOX — the same items, in the same order, as the API answers the same person, each titled as the owner titled it",
    rows.length === items.length && rows.every((r, i) => r.id === items[i].notification_projection_id && r.title === (items[i].title || items[i].event_kind)),
    `${rows.length} rows vs ${items.length} items`);
  ok("ONE LINK PER ITEM — back to the record that owns it (the item's canonical detail route), nothing else",
    rows.every((r, i) => r.links.length === 1 && r.links[0] === items[i].canonical_detail_route), JSON.stringify(rows.map((r) => r.links)).slice(0, 200));
  const days = await page.$$eval("#ioi-notif-panel .ioi-notif-day", (els) => els.map((e) => e.textContent));
  const counts = await page.getAttribute("#ioi-notif-panel [data-ioi-notif-counts]", "data-ioi-notif-counts");
  const text = await panel.innerText();
  ok("GROUPED BY DAY, WITH THE ENVELOPE'S OWN COUNT — shown of total in the last N days, and nothing marked read or unread",
    days.length >= 1 && counts === `${direct.j.counts.shown}/${direct.j.counts.total}` && text.includes(`in the last ${direct.j.window_days} days`) && !/\bunread\b(?! state)/iu.test(text.replace(/read or unread/iu, "")),
    `days ${days.length} counts ${counts}`);
  ok("THE ABSENCES ARE NAMED — the envelope's typed absences, email delivery and configuring notifications are listed as not built, not hidden",
    (direct.j.typed_absences || []).every((a) => text.includes(a.code)) && text.includes("configure notifications") && text.toLowerCase().includes("email"));

  const chips = await page.$$eval("#ioi-notif-panel [data-ioi-notif-family]", (els) => els.map((e) => e.getAttribute("data-ioi-notif-family")));
  const fams = Object.keys(direct.j.counts.by_family || {});
  await page.click('#ioi-notif-panel [data-ioi-notif-family="approval"]');
  await page.locator('#ioi-notif-panel [data-ioi-notif-state="ready"]').waitFor({ timeout: 60_000 });
  const filteredRows = await page.$$eval("#ioi-notif-panel [data-ioi-notif-item]", (els) => els.map((el) => el.getAttribute("data-ioi-notif-item")));
  const filtered = (await get(S, "/v1/hypervisor/notifications?limit=25&family=approval")).j?.items || [];
  ok("FAMILY CHIPS — All plus the envelope's own families; choosing one shows exactly what ?family= answers",
    chips[0] === "" && JSON.stringify(chips.slice(1).sort()) === JSON.stringify(fams.sort()) && filteredRows.length === filtered.length && filteredRows.every((id, i) => id === filtered[i].notification_projection_id),
    `chips ${chips.join(",")} · filtered ${filteredRows.length}/${filtered.length}`);

  const landings = [];
  for (const route of [...new Set(items.map((i) => i.canonical_detail_route).filter(Boolean))]) {
    const r = await fetch(`${S}${route}`, { headers: { ...H, accept: "text/html" } });
    landings.push(`${route} ${r.status}`);
  }
  ok("EVERY LINK LANDS — each item's route answers the signed-in person with a page", landings.length >= 2 && landings.every((l) => / 200$/u.test(l)), landings.join(" · "));

  await page.keyboard.press("Escape");
  const closed = await panel.evaluate((el) => !el.classList.contains("open"));
  await page.goto(`${S}/ai#notifications`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  const fromHash = await page.locator('#ioi-notif-panel.open [data-ioi-notif-state]').waitFor({ timeout: 90_000 }).then(() => true, () => false);
  ok("ESC CLOSES IT, AND /ai#notifications OPENS IT", closed && fromHash, `closed ${closed} · hash ${fromHash}`);

  const railed = await fetch(`${S}/__ioi/missions/incidents`, { headers: { ...H, accept: "text/html" } }).then((r) => r.text());
  ok("THE CERTIFIED RAIL — its Notifications item links to the panel and no rail claims a count (no badge)",
    railed.includes('href="/ai#notifications"') && !railed.includes("og-gbadge"), `link ${railed.includes('href="/ai#notifications"')} · badge ${railed.includes("og-gbadge")}`);

  const narrow = await browser.newContext({ viewport: { width: 390, height: 780 }, colorScheme: "dark" });
  await narrow.addCookies([{ name: "ioi_session", value: session, domain: origin.hostname, path: "/" }]);
  const small = await narrow.newPage();
  await small.goto(`${S}/ai#notifications`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  await small.locator('#ioi-notif-panel.open [data-ioi-notif-state="ready"]').waitFor({ timeout: 90_000 }).catch(() => {});
  const fits = await small.evaluate(() => { const p = document.querySelector("#ioi-notif-panel .ioi-notif"); return p ? p.getBoundingClientRect().width <= window.innerWidth + 1 : false; });
  ok("A PHONE-WIDTH, DARK SHELL — the panel fits the viewport", fits);

  const anonymous = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  const anon = await anonymous.newPage();
  await anon.goto(`${S}/ai#notifications`, { waitUntil: "domcontentloaded", timeout: 90_000 });
  const anonState = await anon.locator("#ioi-notif-panel.open [data-ioi-notif-state]").getAttribute("data-ioi-notif-state", { timeout: 90_000 }).catch(() => null);
  const anonText = anonState ? await anon.locator("#ioi-notif-panel").innerText() : "";
  ok("SIGNED OUT IS NOT EMPTY — a visitor with no session is told to sign in, never shown an empty inbox",
    anonState === "signed_out" && anonText.includes("Sign in") && !anonText.includes("No notifications"), `state ${anonState}`);

  // The panel is open from the /ai#notifications step; close it (its backdrop covers the bell), kill
  // the daemon, and open it again: the read that answers must be the outage, not the stale list.
  await page.keyboard.press("Escape");
  process.kill(plane.daemonPid, "SIGKILL");
  await new Promise((r) => setTimeout(r, 800));
  await page.click("#ioi-notif-bell", { timeout: 30_000 }).catch(() => {});
  await page.locator('#ioi-notif-panel.open [data-ioi-notif-state]:not([data-ioi-notif-state="loading"])').waitFor({ timeout: 60_000 }).catch(() => {});
  const downState = await page.locator("#ioi-notif-panel.open [data-ioi-notif-state]").getAttribute("data-ioi-notif-state", { timeout: 5_000 }).catch(() => null);
  ok("A DEAD DAEMON IS SAID — the panel names the outage and shows no notification", downState === "unavailable" && (await page.$$("#ioi-notif-panel [data-ioi-notif-item]")).length === 0, `state ${downState}`);

  exitCode = results.every((r) => r.pass) ? 0 : 1;
} catch (error) {
  console.error(`verifier crashed: ${error.stack || error.message}`);
  exitCode = 1;
} finally {
  try { await browser?.close(); } catch { /* gone */ }
  try { await plane?.stop(); } catch { /* gone */ }
}
const passed = results.filter((r) => r.pass).length;
console.log(`\n${passed}/${results.length} passed`);
emitVerifierCensus({ verifierId: "notification-panel", sourceUrl: import.meta.url, results });
process.exit(exitCode);
