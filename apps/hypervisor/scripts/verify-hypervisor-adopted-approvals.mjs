#!/usr/bin/env node
// THE ADOPTED APPROVALS APP IS THE DAEMON'S OWN ASKS, AND NOTHING RECORDED (R-241, Approvals A1).
//
// The reference Approvals app (booted by the local mirror, routed at /workspace/approvals-app) answers from the daemon's
// approvals truth (adopted-approvals.mjs), in a real browser against an ISOLATED stack: a sealed deployment authority node,
// a daemon pointed at it, and a serve with the adopted surfaces on.
//   - the fixture is real: two session executes without a grant park two wallet challenges through the live authority;
//     governance approval requests stand pending, approved and rejected, and a second principal asks one of their own;
//   - Your inbox is what waits on the operator (the parked effects and the open governance requests), counted; Created by
//     you and All requests sift; a status group, a reference type with no Hypervisor counterpart, search and sort sift;
//   - a request's page is its record: a challenge's intent, scope, policy and hashes; a governance request's ask;
//   - Approve on a parked effect is refused by name toward the approval card (the page has no passphrase field and the UI
//     server holds no key); Reject and close is the daemon's own deny, with the typed reason; Approve on a governance
//     request is the governance plane's own transition, receipted; every other write is refused by name and writes nothing;
//   - no read reaches the mirror but the reference's chrome, an unbound read is a named 501, never the serve's HTML;
//   - with the daemon stopped, the inbox shows its error, never an empty inbox.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon or authority binary, or the local mirror cannot boot the reference app).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon (the authority: IOI_WALLET_AUTHORITY_BINARY)
//   node apps/hypervisor/scripts/verify-hypervisor-adopted-approvals.mjs     (several minutes: the authority starts a chain)

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { startLocalAuthority, DEFAULT_BINARY as AUTHORITY_BINARY, OPERATOR_PASS_ENV } from "./lib/wallet-network-local-authority.mjs";
import { startIsolatedPlane, isolatedOperatorSession, sanitizedVerifierBaseEnv, ISOLATED_OPERATOR, DAEMON_BINARY } from "./lib/isolated-daemon.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const MIRROR = process.env.IOI_HARVEST_CAPTURE_URL || "http://127.0.0.1:9225";
const BASE = "/workspace/approvals-app";
// the reference's chrome reads the mirror still answers (the other adopted apps' set)
const CHROME = new Set(["GET /multipass/api/sessions/definitions/current", "GET /multipass/api/sessions/selection", "POST /documentation/api/v2/release-notes/pagination",
  "POST /documentation/api/v2/release-notes/paginationV2", "GET /aip-assist/api/chat/checkAvailability", "GET /workspace/api/lifecycleStatusByApplication", "POST /log-receiver/api/beacon"]);
// unique per run: the passphrase seals this run's authority keys and appears nowhere the adopted app can reach
const OPERATOR_PASS = `adopted-approvals-${randomBytes(12).toString("hex")}`;

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const waitFor = async (url, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };

let authority = null, plane = null, serve = null;
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-adopted-approvals-authority-"));

async function run() {
  if (!fs.existsSync(DAEMON_BINARY) || !fs.existsSync(process.env.IOI_WALLET_AUTHORITY_BINARY || AUTHORITY_BINARY)) { console.log(`BLOCKED: no daemon (${DAEMON_BINARY}) or authority binary`); process.exit(2); }
  if (!(await fetch(`${MIRROR}${BASE}/`, { signal: AbortSignal.timeout(3000) }).then((r) => r.ok).catch(() => false))) { console.log(`BLOCKED: the local mirror (${MIRROR}) does not boot ${BASE}/`); process.exit(2); }
  delete process.env[OPERATOR_PASS_ENV];
  authority = await startLocalAuthority({ stateDir, principalRef: "domain://adopted-approvals", operatorPass: OPERATOR_PASS, log: () => {} });
  plane = await startIsolatedPlane({ baseEnv: sanitizedVerifierBaseEnv(process.env), env: { ...authority.daemonEnv, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_WALLET_TEST_SIGNER: "" } });
  if (!plane) { console.log("BLOCKED: the isolated daemon did not start"); process.exit(2); }
  const DAEMON = plane.daemonUrl;
  const session = await isolatedOperatorSession(plane);
  const COOKIE = `ioi_session=${session}`;
  const d = (method, route, body, cookie = COOKIE) => fetch(`${DAEMON}${route}`, { method, headers: { cookie, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(900000) })
    .then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  // the serve names no authority binary or state dir: it holds no key
  const servePort = await freePort();
  const SERVE = `http://127.0.0.1:${servePort}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: DAEMON, IOI_PRODUCT_SIGNIN_REQUIRED: "0", IOI_ADOPTED_SURFACES: "1", IOI_HARVEST_CAPTURE_URL: MIRROR },
    stdio: ["ignore", "pipe", "pipe"],
  });
  serve.stdout.on("data", () => {}); serve.stderr.on("data", () => {});
  await waitFor(`${SERVE}/__ioi/login`);

  // ---- the fixture: two effects parked through the live authority, and governance requests in three statuses ----------
  const me = (await d("GET", "/v1/hypervisor/auth/whoami")).j.principal || {};
  const env = await d("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "adopted-approvals" } });
  const envId = env.j.environment?.id;
  await d("POST", `/v1/hypervisor/environments/${encodeURIComponent(envId)}/start`);
  for (let i = 0; i < 60 && !(await d("GET", `/v1/hypervisor/environments/${encodeURIComponent(envId)}`)).j.environment?.status?.workspace_root; i++) await sleep(500);
  const sessionRef = "session:adopted-approvals";
  await d("POST", "/v1/hypervisor/sessions", { session_ref: sessionRef, project_ref: "project:adopted-approvals", environment_id: envId });
  const execute = (intent) => d("POST", `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`, { intent, lane: "native_local" });
  const parkedA = await execute("create a file named APPROVED.md");
  const parkedB = await execute("delete the build cache");
  const cA = parkedA.j.approval_challenge?.challenge_id, cB = parkedB.j.approval_challenge?.challenge_id;
  const challenge = async (id) => (await d("GET", `/v1/hypervisor/authority/challenges/${id}`)).j.challenge || {};
  const gov = (body, cookie) => d("POST", "/v1/hypervisor/governance/approval-requests", body, cookie).then((x) => x.j.approval_request || {});
  const g1 = await gov({ subject_ref: "authority-action://spend", request_kind: "spend_increase", reason: "raise the model spend ceiling for the nightly eval", required_authority_refs: ["authority://spend"], would_call: ["POST /v1/hypervisor/limits"] });
  const g2 = await gov({ subject_ref: "connector:conn_github", request_kind: "connector_attach", reason: "attach the GitHub connector to the payments project" });
  await d("PATCH", `/v1/hypervisor/governance/approval-requests/${g2.id}`, { transition: "approve" });
  const g3 = await gov({ subject_ref: "lease_import", request_kind: "lease_extend", reason: "extend the import lease" });
  await d("PATCH", `/v1/hypervisor/governance/approval-requests/${g3.id}`, { transition: "reject" });
  // a second principal, and a request of their own
  await d("POST", "/v1/hypervisor/principals", { email: "mo@adopted-approvals.invalid", name: "Mo Member", role: "member", password: "adopted-approvals-member-1" });
  const member = await fetch(`${DAEMON}/v1/hypervisor/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "mo@adopted-approvals.invalid", password: "adopted-approvals-member-1" }) }).then((r) => r.json()).catch(() => ({}));
  const g4 = await gov({ subject_ref: "authority-action://publish-payments-console", request_kind: "domain_app_publish", reason: "publish the payments console to the team" }, `ioi_session=${member.session_token}`);
  const [A0, B0] = [await challenge(cA), await challenge(cB)];
  ok("PRECONDITION: two wallet challenges are parked through a live sealed authority (session executes without a grant), and governance approval requests stand pending, approved and rejected — one asked by a second principal",
    parkedA.status === 403 && parkedA.j.reason === "execution_authority_required" && A0.state === "pending" && B0.state === "pending" && cA !== cB && A0.requester_ref === me.principal_ref
      && g1.status === "pending" && g2.id && g3.id && g4.created_by_principal_ref && g4.created_by_principal_ref !== me.principal_ref,
    `execute ${parkedA.status} ${parkedA.j.reason} · challenges ${A0.state}/${B0.state} · governance ${[g1, g2, g3, g4].map((g) => g.id ? "ok" : "MISSING").join(",")}`);

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: session, url: SERVE }]);
    const pg = await ctx.newPage();
    let phase = "read";
    const passthrough = new Set(), fenced = new Set(), unnamed = new Set(), htmlAnswers = new Set(), gqlErrors = new Set(), refusals = [], pageErrors = [];
    pg.on("pageerror", (e) => { if (phase === "read") pageErrors.push(String(e.message).slice(0, 160)); });
    pg.on("response", async (r) => {
      const u = new URL(r.url()); const key = `${r.request().method()} ${u.pathname.replace(/ri\.[\w.-]+/gu, "<rid>")}`;
      if (r.headers()["x-ioi-mirror-passthrough"] === "1") passthrough.add(key);
      if (/^\/[a-z][a-z0-9-]*\/api\//u.test(u.pathname) && /text\/html/u.test(r.headers()["content-type"] || "")) htmlAnswers.add(key);
      if (r.status() === 501) { fenced.add(key); const j = await r.json().catch(() => ({})); if (j.errorName !== "Hypervisor:ApprovalsReadNotBound") unnamed.add(key); }
      if (r.status() === 409) { const j = await r.json().catch(() => ({})); refusals.push(j.errorName || "?"); }
      if (/graphql/u.test(u.pathname)) {
        const t = await r.text().catch(() => "");
        for (const m of t.matchAll(/"errorName":"(Hypervisor:[A-Za-z]+)"/gu)) refusals.push(m[1]);
        if (phase === "read") for (const m of t.matchAll(/"message":"([^"]{0,90})/gu)) gqlErrors.add(m[1]);
      }
    });
    const text = async () => (await pg.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const visit = async (p, until) => { await pg.goto(`${SERVE}${p}`, { waitUntil: "domcontentloaded", timeout: 60000 }); let t = ""; for (let i = 0; i < 25; i++) { await pg.waitForTimeout(800); t = await text(); if (!until || until.test(t)) break; } return t; };
    const settle = async (until, n = 20) => { let t = ""; for (let i = 0; i < n; i++) { await pg.waitForTimeout(600); t = await text(); if (until.test(t)) break; } return t; };
    const after = (t, marker, n = 200) => (t.includes(marker) ? t.slice(t.indexOf(marker), t.indexOf(marker) + n) : `(no "${marker}")`);
    // a list has loaded when its skeleton is gone and it shows the expected number of rows (each "Created by … on <date>")
    const rowsIn = (t, marker) => (/Placeholder User/u.test(t) ? -1 : (after(t, marker, 4000).match(/ on [A-Z][a-z]{2} \d{1,2}, \d{4}/gu) || []).length);
    const waitRows = async (marker, n, must = [], tries = 30) => { let t = ""; for (let i = 0; i < tries; i++) { await pg.waitForTimeout(600); t = await text(); if (rowsIn(t, marker) === n && must.every((m) => after(t, marker, 4000).includes(m))) break; } return after(t, marker, 4000); };
    const waitAnyRows = async (marker) => { for (let i = 0; i < 30; i++) { await pg.waitForTimeout(600); if (rowsIn(await text(), marker) > 0) return; } };
    // the inbox with every request listed (the app keeps its filters in local storage across visits)
    const inboxAll = async () => {
      await visit(`${BASE}/`, /Your inbox\(\d+\)|All requests\(\d+\)|Created by you\(\d+\)/u);
      await pg.getByText("All requests", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
      await pg.waitForTimeout(800);
      await pg.getByRole("button", { name: "Clear", exact: true }).first().click({ timeout: 3000 }).catch(() => {});
      await waitAnyRows("All requests(");
    };
    const counts = (t) => { const m = /Your inbox (\d+) Created by you (\d+) All requests (\d+)/u.exec(t); return m ? m.slice(1).map(Number) : null; };
    const openRequest = async (title, until) => {
      let href = null;
      for (let i = 0; i < 30 && !href; i++) { href = await pg.evaluate((x) => [...document.querySelectorAll("a")].find((a) => a.innerText.trim() === x)?.getAttribute("href"), title); if (!href) await pg.waitForTimeout(600); }
      if (!href) return { href: null, t: "" };
      await pg.goto(new URL(href, pg.url()).href, { waitUntil: "domcontentloaded" });
      return { href, t: await settle(until || /Justification|cannot be found|error/iu, 25) };
    };
    const TITLE = { A: `Approve session-execute on ${sessionRef}`, g1: "spend_increase — authority-action://spend", g2: "connector_attach — connector:conn_github",
      g3: "lease_extend — lease_import", g4: "domain_app_publish — authority-action://publish-payments-console" };
    const MY_NAME = ISOLATED_OPERATOR.name;

    // ---- the inbox -----------------------------------------------------------------------------------------------------
    await visit(`${BASE}/`, /Your inbox\(\d+\)|Failed to load requests/u);
    const list = await waitRows("Your inbox(", 4);
    const c0 = counts(await text());
    ok("Your inbox is what waits on the operator, over daemon truth: the parked effects and the open governance requests, each under its title, requester and status, with the quick filters counted",
      /^Your inbox\(4\)/u.test(list) && (list.match(new RegExp(TITLE.A.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "gu")) || []).length === 2 && list.includes(TITLE.g1) && list.includes(TITLE.g4)
        && !list.includes(TITLE.g2) && !list.includes(TITLE.g3) && (list.match(/Pending approval/gu) || []).length === 4 && list.includes(`Created by ${MY_NAME}`) && list.includes("Created by Mo Member")
        && JSON.stringify(c0) === JSON.stringify([4, 3, 4]),
      `${list.slice(0, 260)} · counts ${JSON.stringify(c0)}`);

    // ---- the filters -----------------------------------------------------------------------------------------------------
    await pg.getByText("Created by you", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    const mine = await waitRows("Created by you(", 3);
    await pg.getByText("All requests", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await waitRows("All requests(", 4);
    await pg.getByRole("button", { name: "Clear", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    const everything = await waitRows("All requests(", 6, [TITLE.g1, TITLE.g2, TITLE.g3, TITLE.g4]);
    await pg.getByText("Select status", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(800);
    await pg.locator(".bp6-popover .bp6-menu-item").filter({ hasText: /^Closed$/u }).first().click({ timeout: 8000 }).catch(() => {});
    const closed = await waitRows("All requests(", 2, [TITLE.g2, TITLE.g3]);
    await pg.keyboard.press("Escape").catch(() => {});
    ok("the filters sift the inbox over daemon truth: Created by you is what the operator asked, All requests with no status lists every request, and the Closed group only the decided ones",
      /^Created by you\(3\)/u.test(mine) && !mine.includes(TITLE.g4) && /^All requests\(6\)/u.test(everything) && [TITLE.g1, TITLE.g2, TITLE.g3, TITLE.g4].every((x) => everything.includes(x))
        && everything.includes("Completed") && everything.includes("Rejected and closed") && /^All requests\(2\)/u.test(closed) && closed.includes(TITLE.g2) && closed.includes(TITLE.g3) && !closed.includes(TITLE.g1),
      `mine ${rowsIn(mine, "Created by you(")} rows${mine.includes(TITLE.g4) ? " (WITH the member's)" : ""} · all ${rowsIn(everything, "All requests(")} rows, missing ${[TITLE.g1, TITLE.g2, TITLE.g3, TITLE.g4].filter((x) => !everything.includes(x)).join(",") || "none"} · closed ${rowsIn(closed, "All requests(")} rows${closed.includes(TITLE.g1) ? " (WITH an open one)" : ""}: ${closed.slice(0, 160)}`);
    await pg.getByRole("button", { name: "Clear", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await waitRows("All requests(", 6);
    await pg.getByText("Type", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(800);
    await pg.locator(".bp6-popover .bp6-menu-item").filter({ hasText: /^Ontology proposals$/u }).first().click({ timeout: 8000 }).catch(() => {});
    const ontology = after(await settle(/No requests found/u), "All requests(", 200);
    // several types together (the menu stays open): Ontology proposals and Access requests list the union — every request
    await pg.locator(".bp6-popover .bp6-menu-item").filter({ hasText: /^Access requests$/u }).first().click({ timeout: 8000 }).catch(() => {});
    const union = (await waitRows("All requests(", 6)).slice(0, 40);
    await pg.keyboard.press("Escape").catch(() => {});
    await pg.getByRole("button", { name: "Clear", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await waitRows("All requests(", 6);
    await pg.locator("input[placeholder^='Search for requests']").first().fill("spend").catch(() => {});
    const searched = await waitRows("All requests(", 1);
    await pg.locator("input[placeholder^='Search for requests']").first().fill("").catch(() => {});
    await waitRows("All requests(", 6);
    await pg.getByText("Sort: Recently created", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(600);
    await pg.getByText("Sort: Oldest created", { exact: true }).last().click({ timeout: 8000 }).catch(() => {});
    const oldest = after(await settle(/Sort: Oldest created/u), "Sort: Oldest created", 400);
    ok("a reference request type with no Hypervisor counterpart lists none and several types together list the union, search sifts by title, and Oldest created reorders — the oldest parked effect first",
      /^All requests\(0\) Sort: Recently created No requests found\./u.test(ontology) && /^All requests\(6\)/u.test(union) && /^All requests\(1\)/u.test(searched) && searched.includes(TITLE.g1)
        && oldest.replace("Sort: Oldest created ", "").startsWith(TITLE.A),
      `${ontology.slice(0, 80)} · union ${union} · ${searched.slice(0, 80)} · ${oldest.slice(0, 120)}`);
    // the Created by picker offers the principals the daemon names, and picking one sifts to what they asked
    await pg.getByRole("button", { name: "Clear", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await waitRows("All requests(", 6);
    await pg.getByText("Select user", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.locator(".bp6-popover input").first().fill("Mo").catch(() => {});
    const offered = await settle(/Search results \(\d+\)/u, 10);
    const pick = async (name) => { const item = pg.locator(".bp6-popover [class*='item-selector__item-row'], .bp6-popover .bp6-menu-item, .bp6-popover [role=option]").filter({ hasText: name }).first();
      if (await item.count().catch(() => 0)) await item.click({ timeout: 8000 }).catch(() => {}); else await pg.getByText(name, { exact: true }).first().click({ timeout: 8000 }).catch(() => {}); };
    await pick("Mo Member");
    const byMember = await waitRows("All requests(", 1);
    await pg.keyboard.press("Escape").catch(() => {});
    ok("the Created by picker offers the principals the daemon's directory names, and picking the second principal sifts to the one request they asked",
      /Search results \(1\) Mo Member/u.test(offered) && /^All requests\(1\)/u.test(byMember) && byMember.includes(TITLE.g4), `${after(offered, "Search results", 40)} · ${byMember.slice(0, 120)}`);

    // ---- a request's page ----------------------------------------------------------------------------------------------
    await inboxAll();
    const pageA = await openRequest(TITLE.A);
    // the page names one of the two parked effects by its intent: that challenge's record is what it must show
    const shown = [A0, B0].find((c) => pageA.t.includes(`Intent: ${c.published_preimage?.request_preimage?.intent}`)) || null;
    const recA = shown || A0;
    const pageATitle = !!shown;
    ok("a parked effect's page is its record: what it asks, who asked, its intent and scopes, the target scope, the policy and its hash, the request hash and the audience — the challenge the daemon holds",
      /\/task\/ri\.approvals\.main\.task-request\.[0-9a-f-]{36}$/u.test(pageA.href || "") && /Pending approval/u.test(pageA.t) && pageATitle
        && pageA.t.includes(`Requested by: ${MY_NAME}`) && pageA.t.includes(`Target scope: ${recA.target_scope}`) && pageA.t.includes(`Policy hash: ${recA.policy_hash}`)
        && pageA.t.includes(`Request hash: ${recA.request_hash}`) && pageA.t.includes(`Audience: ${recA.audience}`) && pageA.t.includes(`Approval ref: ${recA.approval_ref}`) && /Scopes: [a-z_]+/u.test(pageA.t),
      `${(pageA.href || "(no link)").replace(/ri\.[\w.-]+/u, "<rid>")} · ${after(pageA.t, "Justification:", 260)}`);
    await inboxAll();
    const pageG = await openRequest(TITLE.g1);
    await pg.locator("a, span").filter({ hasText: new RegExp(`^${MY_NAME}$`, "u") }).first().click({ timeout: 8000 }).catch(() => {});
    const card = await settle(new RegExp(ISOLATED_OPERATOR.email.replace(/[.]/gu, "\\."), "u"), 10);
    await pg.keyboard.press("Escape").catch(() => {});
    ok("a governance request's page is its record: what it asks, who asked, its subject and kind, the authority it needs and what it would call — and the requester's name opens their card",
      card.includes(ISOLATED_OPERATOR.email) && /Pending approval/u.test(pageG.t) && pageG.t.includes("Asks: raise the model spend ceiling for the nightly eval") && pageG.t.includes(`Requested by: ${MY_NAME}`)
        && pageG.t.includes("Subject: authority-action://spend") && pageG.t.includes("Required authority: authority://spend") && pageG.t.includes("Would call: POST /v1/hypervisor/limits") && pageG.t.includes(`Record: ${g1.ref}`),
      after(pageG.t, "Justification:", 260));
    ok("no read reached the mirror beyond the reference's chrome, every read the adopted layer does not bind is a named gap (never the serve's HTML page), and no GraphQL operation or page on the inbox and a request's page failed",
      [...passthrough].every((p) => CHROME.has(p)) && unnamed.size === 0 && htmlAnswers.size === 0 && fenced.size === 0 && gqlErrors.size === 0 && pageErrors.length === 0,
      `passthrough ${[...passthrough].filter((p) => !CHROME.has(p)).join(",") || "chrome only"} · fenced ${[...fenced].join(",") || "none"} · unnamed ${[...unnamed].join(",") || "none"} · html ${[...htmlAnswers].join(",") || "none"} · gql ${[...gqlErrors].slice(0, 2).join(" | ") || "none"} · page ${pageErrors.slice(0, 1).join("") || "none"}`);

    // (the reference throws on its own not-found answer, so this page is outside the read-phase error census)
    phase = "not-found";
    const unknown = await visit(`${BASE}/task/ri.approvals.main.task-request.00000000-0000-0000-0000-000000000000`, /cannot be found|error/iu);
    ok("an unknown request is the reference's own not-found page", /The request cannot be found\. Please confirm the request id is correct\. Return to inbox/u.test(unknown), after(unknown, "The request", 100));

    // ---- decisions -----------------------------------------------------------------------------------------------------
    phase = "write";
    const ridA = pageA.href.split("/").pop();
    const idA = recA.challenge_id, idB = recA === A0 ? B0.challenge_id : A0.challenge_id;
    await visit(`${BASE}/task/${ridA}`, /Justification/u);
    refusals.length = 0;
    await pg.getByRole("button", { name: "Approve", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    const toast = await settle(/approve on the Hypervisor's own approval card/u);
    const A1 = await challenge(idA);
    ok("Approve on a parked effect is refused by name toward the approval card — the page has no passphrase field and holds no key — and the challenge stays pending on the daemon, with no decision and no grant",
      refusals.includes("Hypervisor:ApprovalsApproveNeedsPassphrase") && /approve on the Hypervisor's own approval card for the run that asked/u.test(toast) && /Pending approval/u.test(toast)
        && A1.state === "pending" && A1.decision === null && A1.grant_ref === null,
      `${refusals.join(",") || "no refusal"} · daemon ${A1.state} decision ${JSON.stringify(A1.decision)} grant ${A1.grant_ref}`);
    // Reject and close on the other parked effect: the daemon's deny, with the typed reason
    const ridB = (await (async () => { await inboxAll(); return pg.evaluate((x) => [...document.querySelectorAll("a")].filter((a) => a.innerText.trim() === x).map((a) => a.getAttribute("href")), TITLE.A); })()).map((h) => h.split("/").pop()).find((r) => r !== ridA);
    await visit(`${BASE}/task/${ridB}`, /Justification/u);
    await pg.getByRole("button", { name: "Reject", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByText("Reject and Close", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.locator(".bp6-dialog input.bp6-input").first().fill("not this effect").catch(() => {});
    await pg.getByRole("button", { name: "Reject and close", exact: true }).last().click({ timeout: 8000 }).catch(() => {});
    const rejected = await settle(/Rejected and closed/u, 25);
    const B1 = await challenge(idB);
    const reread = await visit(`${BASE}/task/${ridB}`, /Justification/u);
    ok("Reject and close on a parked effect is the daemon's own deny (no key needed; it mints nothing), with the reason typed: the challenge is denied by the operator, and the page reads Rejected and closed with the decision in its record",
      B1.state === "denied" && B1.decision?.decision === "deny" && B1.decision?.decided_by === me.principal_ref && B1.decision?.reason === "not this effect" && B1.grant_ref === null
        && /Rejected and closed/u.test(rejected) && reread.includes(`Decided: deny by ${MY_NAME}`) && reread.includes("— not this effect"),
      `daemon ${B1.state} ${JSON.stringify(B1.decision)?.slice(0, 160)} · page ${/Rejected and closed/u.test(rejected) ? "Rejected and closed" : "NOT rejected"} · ${after(reread, "Decided:", 80)}`);
    // Approve on a governance request: the plane's own transition, the reviewer named by the daemon
    await inboxAll();
    const g1Page = await openRequest(TITLE.g1);
    await pg.getByRole("button", { name: "Approve", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    const approved = await settle(/Completed/u, 25);
    const G1 = (await d("GET", `/v1/hypervisor/governance/approval-requests/${g1.id}`)).j.approval_request || {};
    ok("Approve on a governance request is the governance plane's own transition: approved, the operator named reviewer by the daemon from the session, one receipt — and the page reads Completed",
      !!g1Page.href && G1.status === "approved" && G1.reviewer_ref === me.principal_ref && (G1.receipt_refs || []).length === 1 && /Completed/u.test(approved) && /Request has been completed/u.test(approved),
      `daemon ${G1.status} by ${G1.reviewer_ref} · ${(G1.receipt_refs || []).length} receipt · page ${/Completed/u.test(approved) ? "Completed" : "NOT completed"}`);

    // ---- every other write, refused by name ---------------------------------------------------------------------------
    refusals.length = 0;
    await inboxAll();
    const g4Page = await openRequest(TITLE.g4);
    await pg.getByRole("button", { name: "Reject", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByText("Reject and Close", { exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.locator(".bp6-dialog input.bp6-input").first().fill("not now").catch(() => {});
    await pg.getByRole("button", { name: "Reject and close", exact: true }).last().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(3000);
    await visit(`${BASE}/task/${ridA}`, /Justification/u);
    await pg.getByRole("button", { name: "Close", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.getByRole("button", { name: "Close request", exact: true }).last().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(2500);
    await visit(`${BASE}/task/${ridA}`, /Justification/u);
    await pg.getByRole("button", { name: "Invite reviewers", exact: true }).first().click({ timeout: 8000 }).catch(() => {});
    await pg.locator(".bp6-popover input.bp6-input").first().fill("Mo").catch(() => {});
    for (let i = 0; i < 15 && !(await pg.locator(".bp6-popover").filter({ hasText: "Mo Member" }).count().catch(() => 0)); i++) await pg.waitForTimeout(600);
    await pick("Mo Member");
    const save = pg.getByRole("button", { name: "Save", exact: true }).last();
    for (let i = 0; i < 10 && !(await save.isEnabled().catch(() => false)); i++) await pg.waitForTimeout(500);
    await save.click({ timeout: 8000 }).catch(() => {});
    for (let i = 0; i < 10 && !refusals.includes("Hypervisor:ApprovalsWriteNotBound"); i++) await pg.waitForTimeout(500);
    await visit(`${BASE}/task/${ridA}`, /Justification/u);
    await pg.locator(".public-DraftEditor-content, [contenteditable=true], textarea").last().fill("please hold this").catch(() => {});
    await pg.getByRole("button", { name: "Add comment", exact: true }).last().click({ timeout: 8000 }).catch(() => {});
    await pg.waitForTimeout(2500);
    const H = { cookie: COOKIE, "content-type": "application/json", referer: `${SERVE}${BASE}/task/${ridA}` };
    const rest = await fetch(`${SERVE}/approvals/api/task-requests/${ridA}/reviewers`, { method: "PUT", headers: H, body: "{}" }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
    const [A2, G4] = [await challenge(idA), (await d("GET", `/v1/hypervisor/governance/approval-requests/${g4.id}`)).j.approval_request || {}];
    const want = ["Hypervisor:ApprovalsRejectionReasonNotKept", "Hypervisor:ApprovalsCloseNotBound", "Hypervisor:ApprovalsWriteNotBound", "Hypervisor:ApprovalsCommentsNotKept"];
    ok("every other write is refused by name and writes nothing: Reject on a governance request (its rejection keeps no reason), Close on an open request, inviting a reviewer, a comment, and any REST write",
      !!g4Page.href && want.every((w) => refusals.includes(w)) && rest.status === 409 && rest.j.errorName === "Hypervisor:ApprovalsWriteNotBound" && A2.state === "pending" && A2.decision === null
        && G4.status === "pending" && !G4.reviewer_ref,
      `${[...new Set(refusals)].join(",") || "no refusal"} · REST ${rest.status} ${rest.j.errorName} · challenge ${A2.state} · governance ${G4.status}`);

    // ---- the fence: an unbound read is a named gap, never the recorded tenant's answer or the serve's HTML --------------
    const probe = (method, p) => fetch(`${SERVE}${p}`, { method, headers: H, body: method === "GET" ? undefined : "{}" }).then(async (r) => ({ status: r.status, pass: r.headers.get("x-ioi-mirror-passthrough"), j: await r.json().catch(() => ({})) }));
    const probes = await Promise.all([probe("GET", "/approvals/api/policies/v2"), probe("GET", "/control-panel/api/enrollments/rids"), probe("POST", "/multipass/api/organizations/access"), probe("POST", "/checkpoints/api/checkpoints/configuration/getConfigsV5")]);
    ok("the fence holds: an approvals, Control Panel, directory or checkpoint read the adopted layer does not bind is a named 501 (Hypervisor:ApprovalsReadNotBound) — never the recorded tenant's answer or the serve's HTML",
      probes.every((x) => x.status === 501 && x.j.errorName === "Hypervisor:ApprovalsReadNotBound" && !x.pass), probes.map((x) => `${x.status} ${x.j.errorName || "?"}`).join(" · "));

    // ---- degraded: the daemon stopped ---------------------------------------------------------------------------------
    await plane.stop();
    plane = null;
    const down = await visit(`${BASE}/`, /Failed to load requests|Your inbox\(\d+\)/u);
    ok("with the daemon stopped, the inbox shows its error — never an empty inbox",
      /Failed to load requests\./u.test(down) && !/No requests found/u.test(down) && !down.includes(TITLE.g1) && counts(down) === null, after(down, "Your inbox(", 80));
  } finally {
    await browser.close();
  }
}

async function cleanup() {
  try { serve?.kill("SIGTERM"); } catch { /* gone */ }
  try { await plane?.stop(); } catch { /* gone */ }
  try { await authority?.stop(); } catch { /* gone */ }
  try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(async () => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "adopted-approvals", sourceUrl: import.meta.url, results });
  await cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
