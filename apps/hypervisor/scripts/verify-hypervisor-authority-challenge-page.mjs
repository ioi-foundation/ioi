#!/usr/bin/env node
// A PARKED EFFECT IS APPROVED ON ITS OWN PAGE, WHOEVER PARKED IT (R-240, parked-effect approval page).
//
// Until /__ioi/authority/challenges/:id, a wallet challenge parked by anything but a run the Hypervisor started (a direct
// session execute, a capability-lease gate) had no Hypervisor page that could approve it. This verifier drives the page in
// a real browser against an ISOLATED stack — a sealed deployment authority node (its own temp dir, a per-run passphrase),
// a daemon pointed at it, and a serve that names no authority binary or state dir (it holds no key) — and asserts every
// outcome against DAEMON truth (GET /v1/hypervisor/authority/challenges/:id), never the page's own claim:
//   - two direct session executes without a grant park two challenges; the list page links each, and the governance
//     approvals band links the list;
//   - the operator's page shows the daemon's record (what effect, the exact hashes, target scope and audience a grant would
//     bind, who asked, when it expires) with an Approve form (the one shared passphrase field) and a Deny form (a reason),
//     and every live-looking control on it is one of those or a link that lands;
//   - a member sees the challenge and no form, and a decision they post anyway is refused by the daemon, in its words;
//   - a wrong passphrase through the page is the daemon's refusal verbatim, the record untouched;
//   - the right passphrase through the page's form: the daemon's record is approved with a grant_ref for exactly its
//     hashes, and the requester's retry consumes it once (the page reads Completed);
//   - Deny through the page, with a reason: denied, the reason and the operator in the record;
//   - a challenge whose scope is outside the deployment approver's allowlist (a System genesis scope — planted on this
//     verifier's OWN data dir, because no daemon gate parks one today: both park sites are live-route scopes) is refused
//     by the authority itself, and the page shows that refusal verbatim, not a crash; the allowlist is untouched;
//   - an unknown or malformed id is the daemon's refusal; an ask past its expiry (the daemon restarted with its pending
//     window shortened) reads Closed and a decision on it is the daemon's 410;
//   - the passphrase reaches no serve output, no page and no file of the daemon's data dir;
//   - with the daemon stopped, the page says so (503) and shows no challenge and no form.
//
// Exit: 0 pass · 1 fail · 2 blocked (no daemon or authority binary).
//   IOI_HYPERVISOR_DAEMON_BINARY  default target/debug/hypervisor-daemon (the authority: IOI_WALLET_AUTHORITY_BINARY)
//   IOI_CHALLENGE_PAGE_SCREENSHOTS=<dir>  also save a screenshot of each state the page renders (numbers do not see pictures)
//   node apps/hypervisor/scripts/verify-hypervisor-authority-challenge-page.mjs     (several minutes: the authority starts a chain)

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { startLocalAuthority, DEFAULT_BINARY as AUTHORITY_BINARY, OPERATOR_PASS_ENV } from "./lib/wallet-network-local-authority.mjs";
import { startIsolatedPlane, isolatedOperatorSession, sanitizedVerifierBaseEnv, ISOLATED_OPERATOR, DAEMON_BINARY } from "./lib/isolated-daemon.mjs";
import { ENUMERATE } from "./lib/dead-control-page.mjs";
import { isLiveLooking } from "./lib/dead-control-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
// unique per run: a scan for either can only find THIS run's
const OPERATOR_PASS = `challenge-page-${randomBytes(12).toString("hex")}`;
const WRONG_PASS = `challenge-page-wrong-${randomBytes(12).toString("hex")}`;
const SHORT_TTL_MS = 15000;
const GENESIS_SCOPE = "scope:autonomous_system.genesis_admit";
const APPROVE_WAIT_MS = 900000;
const SHOTS = process.env.IOI_CHALLENGE_PAGE_SCREENSHOTS || "";

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = s.address().port; s.close(() => r(p)); }); });
const waitFor = async (url, ms = 60000) => { const end = Date.now() + ms; while (Date.now() < end) { try { const r = await fetch(url); if (r.status < 500) return true; } catch { /* not yet */ } await sleep(300); } return false; };
const pagePath = (id) => `/__ioi/authority/challenges/${id}`;
// the daemon's own id derivation (authority_challenge_routes.rs challenge_id_for): sha256 over the JCS of the coordinates
const challengeIdFor = (scope, policy, request, audience) => `wac_${createHash("sha256").update(JSON.stringify({ audience, domain: "ioi.hypervisor.wallet-approval-challenge.id.v1", policy_hash: policy, request_hash: request, target_scope: scope })).digest("hex").slice(0, 32)}`;

let authority = null, plane = null, serve = null, serveOutput = "";
// a crash must not orphan this verifier's serve (the daemon and authority helpers carry their own exit hooks)
process.on("exit", () => { try { serve?.kill("SIGTERM"); } catch { /* gone */ } });
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-challenge-page-authority-"));
const planeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-challenge-page-plane-"));

// the serve names no authority binary or state dir: it holds no key. Its output is kept for the passphrase scan.
async function startServe(daemonUrl) {
  const servePort = await freePort();
  const url = `http://127.0.0.1:${servePort}`;
  const child = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...sanitizedVerifierBaseEnv(process.env), PORT: String(servePort), PRODUCT_UI_PORT: String(await freePort()), IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_HYPERVISOR_DAEMON_URL: daemonUrl, IOI_PRODUCT_SIGNIN_REQUIRED: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const keep = (chunk) => { serveOutput = `${serveOutput}${chunk}`.slice(-4_000_000); };
  child.stdout.on("data", keep); child.stderr.on("data", keep);
  await waitFor(`${url}/__ioi/login`);
  return { child, url };
}
const stopServe = async (child) => {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const gone = new Promise((r) => child.once("exit", r));
  try { child.kill("SIGTERM"); } catch { /* gone */ }
  await Promise.race([gone, sleep(5000)]);
};
// every file under a directory that holds a needle (bounded: large files are read in full only below 64 MB)
function filesHolding(dir, needles) {
  const found = [];
  const walk = (d) => {
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) { try { if (fs.statSync(p).size < 64 * 1024 * 1024) { const b = fs.readFileSync(p); if (needles.some((n) => b.includes(n))) found.push(p); } } catch { /* unreadable */ } }
    }
  };
  walk(dir);
  return found;
}

async function run() {
  if (!fs.existsSync(DAEMON_BINARY) || !fs.existsSync(process.env.IOI_WALLET_AUTHORITY_BINARY || AUTHORITY_BINARY)) { console.log(`BLOCKED: no daemon (${DAEMON_BINARY}) or authority binary`); process.exit(2); }
  delete process.env[OPERATOR_PASS_ENV];
  authority = await startLocalAuthority({ stateDir, principalRef: "domain://authority-challenge-page", operatorPass: OPERATOR_PASS, log: () => {} });
  const DAEMON_ENV = { ...authority.daemonEnv, IOI_HYPERVISOR_MODEL_UPSTREAM: "http://127.0.0.1:9/v1", IOI_WALLET_TEST_SIGNER: "" };
  plane = await startIsolatedPlane({ dataDir: planeDir, baseEnv: sanitizedVerifierBaseEnv(process.env), env: DAEMON_ENV });
  if (!plane) { console.log("BLOCKED: the isolated daemon did not start"); process.exit(2); }
  let DAEMON = plane.daemonUrl;
  let COOKIE = `ioi_session=${await isolatedOperatorSession(plane)}`;
  const d = (method, route, body, cookie = COOKIE) => fetch(`${DAEMON}${route}`, { method, headers: { cookie, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(APPROVE_WAIT_MS) })
    .then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  let SERVE;
  ({ child: serve, url: SERVE } = await startServe(DAEMON));

  // ---- the fixture: two effects parked by DIRECT session executes (no Hypervisor run), and a second principal ----------
  const me = (await d("GET", "/v1/hypervisor/auth/whoami")).j.principal || {};
  const env = await d("POST", "/v1/hypervisor/environments", { spec: { environment_class_id: "local-workspace-v0", project_id: "challenge-page" } });
  const envId = env.j.environment?.id;
  await d("POST", `/v1/hypervisor/environments/${encodeURIComponent(envId)}/start`);
  for (let i = 0; i < 60 && !(await d("GET", `/v1/hypervisor/environments/${encodeURIComponent(envId)}`)).j.environment?.status?.workspace_root; i++) await sleep(500);
  const sessionRef = "session:challenge-page";
  await d("POST", "/v1/hypervisor/sessions", { session_ref: sessionRef, project_ref: "project:challenge-page", environment_id: envId });
  const execute = (intent, approvalRef) => d("POST", `/v1/hypervisor/sessions/${encodeURIComponent(sessionRef)}/execute`, { intent, lane: "native_local", ...(approvalRef ? { approval_ref: approvalRef } : {}) });
  const parkedA = await execute("create a file named PAGE_APPROVED.md");
  const parkedB = await execute("delete the build cache");
  const idA = parkedA.j.approval_challenge?.challenge_id, idB = parkedB.j.approval_challenge?.challenge_id;
  const challenge = async (id) => (await d("GET", `/v1/hypervisor/authority/challenges/${id}`)).j.challenge || {};
  const [A0, B0] = [await challenge(idA), await challenge(idB)];
  await d("POST", "/v1/hypervisor/principals", { email: "mo@challenge-page.invalid", name: "Mo Member", role: "member", password: "challenge-page-member-1" });
  const member = await fetch(`${DAEMON}/v1/hypervisor/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "mo@challenge-page.invalid", password: "challenge-page-member-1" }) }).then((r) => r.json()).catch(() => ({}));
  const MEMBER_COOKIE = `ioi_session=${member.session_token}`;
  ok("PRECONDITION: two direct session executes without a grant (no Hypervisor run) park two challenges through a live sealed authority, both pending with the operator as requester, and a second principal (a member) can sign in",
    parkedA.status === 403 && parkedA.j.reason === "execution_authority_required" && A0.state === "pending" && B0.state === "pending" && idA !== idB && A0.requester_ref === me.principal_ref && A0.decidable === true && !!member.session_token,
    `execute ${parkedA.status} ${parkedA.j.reason} · ${A0.state}/${B0.state} · decidable ${A0.decidable} · member ${member.session_token ? "signed in" : "NOT signed in"}`);

  const { chromium } = await import(path.join(ROOT, "node_modules", "playwright", "index.mjs"));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 1400, height: 1000 } });
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const pg = await ctx.newPage();
    const pageErrors = [];
    pg.on("pageerror", (e) => pageErrors.push(String(e.message).slice(0, 160)));
    const posts = [];
    pg.on("request", (r) => { if (r.method() === "POST") posts.push(new URL(r.url()).pathname); });
    const text = async (p = pg) => (await p.evaluate(() => document.body.innerText)).replace(/\s+/gu, " ");
    const attr = (sel, name, p = pg) => p.evaluate(([s, n]) => document.querySelector(s)?.getAttribute(n) ?? null, [sel, name]);
    const inner = (sel, p = pg) => p.evaluate((s) => document.querySelector(s)?.textContent ?? null, sel);
    const shot = async (name, p = pg) => { if (SHOTS) { fs.mkdirSync(SHOTS, { recursive: true }); await p.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true }).catch(() => {}); } };
    const visit = async (p, route) => { const r = await p.goto(`${SERVE}${route}`, { waitUntil: "domcontentloaded", timeout: 60000 }); return r ? r.status() : 0; };
    // submit one of the page's decision forms and wait for the answer the serve gives it (a 303 back to the page, or the
    // page itself carrying the daemon's refusal)
    const decide = async (which, fill) => {
      await visit(pg, pagePath(fill.id));
      if (fill.passphrase !== undefined) await pg.fill("form[data-ioi-challenge-decision=approve] [data-ioi-operator-passphrase]", fill.passphrase);
      if (fill.reason !== undefined) await pg.fill("form[data-ioi-challenge-decision=deny] input[name=reason]", fill.reason);
      // (a 303 lands back on the page's own URL, so the wait is for the NEW document, redirect included — never the old one;
      // an approve can take minutes, far past a click's own wait for the navigation it starts, so the click does not wait)
      const answered = pg.waitForResponse((r) => r.request().method() === "POST" && new URL(r.url()).pathname === `${pagePath(fill.id)}/${which}`, { timeout: APPROVE_WAIT_MS }).catch((e) => e);
      const landed = pg.waitForNavigation({ waitUntil: "domcontentloaded", timeout: APPROVE_WAIT_MS }).catch((e) => e);
      await pg.click(`form[data-ioi-challenge-decision=${which}] button[type=submit]`, { noWaitAfter: true });
      const res = await answered;
      if (res instanceof Error) throw res;
      const nav = await landed;
      if (nav instanceof Error) throw nav;
      return { status: res.status(), location: res.headers().location || null, url: pg.url(), html: await pg.content(), t: await text() };
    };

    // ---- the list, and where it is linked from --------------------------------------------------------------------------
    const listStatus = await visit(pg, "/__ioi/authority/challenges");
    const listRows = await pg.evaluate(() => [...document.querySelectorAll("[data-ioi-challenge-row]")].map((r) => ({ id: r.getAttribute("data-ioi-challenge-row"), href: r.querySelector("a")?.getAttribute("href"), state: r.querySelector("[data-ioi-challenge-state]")?.getAttribute("data-ioi-challenge-state") })));
    const waiting = await attr("[data-ioi-challenge-count]", "data-ioi-challenge-count");
    await shot("00-list");
    const band = await fetch(`${SERVE}/__ioi/governance/approvals`, { headers: { cookie: COOKIE } }).then((r) => r.text()).catch(() => "");
    const bandLink = /<a class="ap-xchip" href="\/__ioi\/authority\/challenges">wallet approval challenge <b>2<\/b> →<\/a>/u.test(band);
    ok("the list page links each parked challenge to its own page with its state, counts the two waiting, and the governance approvals band's parked-effect count links to it",
      listStatus === 200 && listRows.length === 2 && [idA, idB].every((id) => listRows.some((r) => r.id === id && r.href === pagePath(id) && r.state === "pending")) && waiting === "2" && bandLink,
      `list ${listStatus} · rows ${JSON.stringify(listRows).slice(0, 220)} · waiting ${waiting} · band link ${bandLink ? "yes" : "NO"}`);

    // ---- the operator's page: the daemon's record, and the two forms ----------------------------------------------------
    const aStatus = await visit(pg, pagePath(idA));
    await shot("01-pending-operator");
    const shown = {
      state: await attr("[data-ioi-challenge-state]", "data-ioi-challenge-state"), id: await attr("[data-ioi-challenge]", "data-ioi-challenge"),
      scope: await inner("[data-ioi-challenge-target-scope]"), policy: await inner("[data-ioi-challenge-policy-hash]"), request: await inner("[data-ioi-challenge-request-hash]"),
      audience: await inner("[data-ioi-challenge-audience]"), intent: await inner("[data-ioi-challenge-intent]"), requester: await inner("[data-ioi-challenge-requester]"), expires: await inner("[data-ioi-challenge-expires]"),
      preimage: await inner("[data-ioi-challenge-preimage]"),
      approveForm: await pg.evaluate(() => { const f = document.querySelector("form[data-ioi-challenge-decision=approve]"); const i = f?.querySelector("[data-ioi-operator-passphrase]"); return f ? { action: f.getAttribute("action"), method: f.getAttribute("method"), type: i?.getAttribute("type"), name: i?.getAttribute("name"), autocomplete: i?.getAttribute("autocomplete"), required: i?.required } : null; }),
      denyForm: await pg.evaluate(() => { const f = document.querySelector("form[data-ioi-challenge-decision=deny]"); return f ? { action: f.getAttribute("action"), reason: !!f.querySelector("input[name=reason]") } : null; }),
    };
    ok("the operator's page is the daemon's record: the effect's intent, the exact target scope, policy hash, request hash and audience a grant would bind, the preimage those hashes commit to, who asked (named) and when it expires — with an Approve form (a password field named operator_passphrase, never autofilled) and a Deny form (a reason), both posting to this challenge's own decision routes",
      aStatus === 200 && shown.state === "pending" && shown.id === idA && shown.scope === A0.target_scope && shown.policy === A0.policy_hash && shown.request === A0.request_hash && shown.audience === A0.audience
        && shown.intent === A0.published_preimage?.request_preimage?.intent && shown.requester === `${ISOLATED_OPERATOR.name} ${A0.requester_ref}` && shown.expires === new Date(Number(A0.expires_at_ms)).toISOString()
        && JSON.stringify(JSON.parse(shown.preimage || "null")) === JSON.stringify(A0.published_preimage)
        && shown.approveForm?.action === `${pagePath(idA)}/approve` && shown.approveForm.method === "post" && shown.approveForm.type === "password" && shown.approveForm.name === "operator_passphrase" && shown.approveForm.autocomplete === "off" && shown.approveForm.required === true
        && shown.denyForm?.action === `${pagePath(idA)}/deny` && shown.denyForm.reason,
      JSON.stringify({ ...shown, preimage: shown.preimage ? "(shown)" : null }).slice(0, 700));

    // ---- dead-control hygiene: every live-looking control is one the page's decisions use, a link that lands, or the
    // preimage disclosure; an Approve with no passphrase says what it needs on the page and sends nothing ----------------
    const controls = (await pg.evaluate(ENUMERATE)).filter(isLiveLooking);
    const verdicts = [];
    for (const el of controls) {
      if (el.tag === "A" && el.href) {
        const r = await ctx.request.get(new URL(el.href, `${SERVE}${pagePath(idA)}`).href, { failOnStatusCode: false, timeout: 60000 }).catch(() => null);
        verdicts.push({ what: `link ${el.href}`, alive: !!r && r.status() < 400, why: r ? `HTTP ${r.status()}` : "no answer" });
      } else if (el.tag === "SUMMARY") {
        const opened = await pg.evaluate(() => { const s = document.querySelector("details > summary"); s.click(); return s.parentElement.open; });
        verdicts.push({ what: "the preimage disclosure", alive: opened === true, why: opened ? "opens" : "did not open" });
      } else {
        const inForm = await pg.evaluate((css) => document.querySelector(css)?.closest("form[data-ioi-challenge-decision]")?.getAttribute("data-ioi-challenge-decision") || null, el.css);
        verdicts.push({ what: `${el.tag.toLowerCase()} "${el.text}"`, alive: inForm === "approve" || inForm === "deny", why: inForm ? `the ${inForm} form (exercised below)` : "belongs to no decision form" });
      }
    }
    const postsBefore = posts.length;
    await pg.click("form[data-ioi-challenge-decision=approve] button[type=submit]");
    await sleep(600);
    const hint = await inner("[data-ioi-field-hint]");
    await shot("02-pending-empty-passphrase-hint");
    const A1 = await challenge(idA);
    ok("every live-looking control on the page is alive: a decision form's field or button (each exercised below), a link that lands, or the preimage disclosure — and Approve with no passphrase says on the page what it needs and sends nothing",
      controls.length >= 5 && verdicts.every((v) => v.alive) && verdicts.filter((v) => v.alive && /form \(exercised below\)/u.test(v.why)).length === 4 && /Operator passphrase is needed to approve/u.test(hint || "") && posts.length === postsBefore && A1.state === "pending",
      `${verdicts.map((v) => `${v.what}: ${v.alive ? "alive" : "DEAD"} (${v.why})`).join(" · ").slice(0, 900)} · hint "${hint}" · posts ${posts.length - postsBefore} · daemon ${A1.state}`);

    // ---- a member: the challenge, no form; a decision posted anyway is the daemon's refusal ------------------------------
    const mctx = await browser.newContext();
    await mctx.addCookies([{ name: "ioi_session", value: member.session_token, url: SERVE }]);
    const mp = await mctx.newPage();
    const mStatus = await visit(mp, pagePath(idA));
    await shot("03-pending-member", mp);
    const mShown = { state: await attr("[data-ioi-challenge-state]", "data-ioi-challenge-state", mp), decide: await attr("[data-ioi-challenge-decide]", "data-ioi-challenge-decide", mp), forms: await mp.evaluate(() => document.querySelectorAll("form, [data-ioi-operator-passphrase]").length), t: await text(mp) };
    await mctx.close();
    const forged = async (which, body) => fetch(`${SERVE}${pagePath(idA)}/${which}`, { method: "POST", headers: { cookie: MEMBER_COOKIE, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body).toString(), redirect: "manual" })
      .then(async (r) => ({ status: r.status, html: await r.text() }));
    const forgedApprove = await forged("approve", { operator_passphrase: OPERATOR_PASS });
    const forgedDeny = await forged("deny", { reason: "a member's denial" });
    // (a bare attribute reads `data-x` in the serve's HTML and `data-x=""` in the browser's serialization of it)
    const refusalOf = (html) => ({ code: /data-ioi-challenge-refusal="([^"]+)"/u.exec(html)?.[1] || null, message: /<span data-ioi-challenge-refusal-message(?:="")?>([^<]*)<\/span>/u.exec(html)?.[1] || null });
    const A2 = await challenge(idA);
    const fa = refusalOf(forgedApprove.html), fd = refusalOf(forgedDeny.html);
    ok("a member sees the parked effect and no decision form (only the operator decides), and an approval or denial they post anyway is refused by the daemon — its code and message on the page, at its status — with the record untouched",
      mStatus === 200 && mShown.state === "pending" && mShown.decide === "not-operator" && mShown.forms === 0 && /You are signed in as Mo Member/u.test(mShown.t)
        && forgedApprove.status === 403 && fa.code === "approval_decider_not_operator" && fa.message === "only the deployment's operator (an administrator) decides approval challenges"
        && forgedDeny.status === 403 && fd.code === "approval_decider_not_operator" && A2.state === "pending" && A2.decision === null && A2.grant_ref === null,
      `member page ${mStatus} ${mShown.state}/${mShown.decide} forms ${mShown.forms} · forged approve ${forgedApprove.status} ${fa.code}: ${fa.message} · forged deny ${forgedDeny.status} ${fd.code} · daemon ${A2.state}`);

    // ---- a wrong passphrase through the page: the daemon's refusal verbatim, nothing recorded ----------------------------
    const wrong = await decide("approve", { id: idA, passphrase: WRONG_PASS });
    const wr = refusalOf(wrong.html);
    await shot("04-refused-wrong-passphrase");
    const A3 = await challenge(idA);
    const typedBack = await pg.evaluate(() => document.querySelector("[data-ioi-operator-passphrase]")?.value ?? null);
    ok("a wrong passphrase through the page's form is the daemon's refusal verbatim (operator_passphrase_refused, at 403) above the record re-read — still pending, no decision, no grant — and neither the page nor its field gives the passphrase back",
      wrong.status === 403 && wr.code === "operator_passphrase_refused" && wr.message === "the operator passphrase did not open the sealed approver key; nothing was signed or recorded"
        && /data-ioi-challenge-state="pending"/u.test(wrong.html) && A3.state === "pending" && A3.decision === null && A3.grant_ref === null && !wrong.html.includes(WRONG_PASS) && typedBack === "",
      `POST ${wrong.status} ${wr.code}: ${wr.message} · daemon ${A3.state} · field "${typedBack}"`);

    // ---- the right passphrase through the page's form: approved, one grant for exactly its hashes ------------------------
    const t0 = Date.now();
    const approved = await decide("approve", { id: idA, passphrase: OPERATOR_PASS });
    const A4 = await challenge(idA);
    const shownGrant = await inner("[data-ioi-challenge-grant-ref]");
    await shot("05-approved");
    ok("the operator approves through the page's form with the passphrase: the serve answers 303 back to the page (the passphrase in no URL), and the daemon's record is approved by the operator with a grant_ref, a live grant expiry, and exactly the parked coordinates — the page reads Approved (grant minted, not yet run) with that grant",
      approved.status === 303 && approved.location === pagePath(idA) && !String(approved.location).includes(OPERATOR_PASS) && !approved.url.includes(OPERATOR_PASS)
        && A4.state === "approved" && !!A4.grant_ref && Number(A4.grant_expires_at_ms) > Date.now() && A4.decision?.decision === "approve" && A4.decision?.decided_by === me.principal_ref
        && A4.policy_hash === A0.policy_hash && A4.request_hash === A0.request_hash && A4.target_scope === A0.target_scope && A4.audience === A0.audience && A4.consumed_by === null
        && /data-ioi-challenge-state="approved">Approved — grant minted, not yet run/u.test(approved.html) && shownGrant === (typeof A4.grant_ref === "string" ? A4.grant_ref : JSON.stringify(A4.grant_ref)) && !approved.html.includes("<form"),
      `POST ${approved.status} → ${approved.location} in ${Math.round((Date.now() - t0) / 1000)} s · daemon ${A4.state} grant ${JSON.stringify(A4.grant_ref)} by ${A4.decision?.decided_by} · page grant ${shownGrant} · ${approved.t.slice(0, 160)}`);

    // ---- the requester's retry: the grant consumed once; the page reads Completed ---------------------------------------
    const intentA = A0.published_preimage?.request_preimage?.intent;
    const retried = await execute(intentA, A4.approval_ref);
    const A5 = await challenge(idA);
    const replay = await execute(intentA, A4.approval_ref);
    await visit(pg, pagePath(idA));
    const done = { state: await attr("[data-ioi-challenge-state]", "data-ioi-challenge-state"), by: await inner("[data-ioi-challenge-consumed-by]") };
    await shot("06-completed");
    ok("the requester's retry naming the approval runs the effect once: the daemon's record is consumed by the run's admission, a replay is refused (approval_ref_consumed), and the page reads Completed with that admission",
      A5.state === "consumed" && String(A5.consumed_by || "").startsWith("authority-admission-intents/") && replay.status === 403 && replay.j.reason === "approval_ref_consumed" && done.state === "completed" && done.by === A5.consumed_by,
      `retry ${retried.status} ${retried.j.decision || retried.j.reason || ""} · daemon ${A5.state} by ${A5.consumed_by} · replay ${replay.status} ${replay.j.reason} · page ${done.state} ${done.by}`);

    // ---- Deny through the page, with a reason ----------------------------------------------------------------------------
    const denied = await decide("deny", { id: idB, reason: "not this effect" });
    const B1 = await challenge(idB);
    await shot("07-denied");
    ok("Deny through the page's form, with a reason: the serve answers 303 back to the page, the daemon's record is denied by the operator with that reason and no grant, and the page reads Denied with the reason",
      denied.status === 303 && B1.state === "denied" && B1.decision?.decision === "deny" && B1.decision?.decided_by === me.principal_ref && B1.decision?.reason === "not this effect" && B1.grant_ref === null
        && /data-ioi-challenge-state="denied"/u.test(denied.html) && /data-ioi-challenge-reason(?:="")?>not this effect</u.test(denied.html) && !denied.html.includes("<form"),
      `POST ${denied.status} · daemon ${B1.state} ${JSON.stringify(B1.decision)?.slice(0, 160)}`);

    // ---- a scope outside the deployment approver's allowlist: the authority's own refusal, verbatim ----------------------
    // (planted on this verifier's own data dir, beside the real records: B's pending coordinates re-scoped to System genesis)
    const family = filesHolding(planeDir, [Buffer.from(`"challenge_id":"${idB}"`), Buffer.from(`"challenge_id": "${idB}"`)]).map((p) => path.dirname(p)).find((p) => fs.existsSync(path.join(p, `${idB}.json`))) || null;
    const idG = challengeIdFor(GENESIS_SCOPE, B0.policy_hash, B0.request_hash, B0.audience);
    const { decidable: _decidable, decision_route: _route, ...plantedBase } = B0;
    if (family) fs.writeFileSync(path.join(family, `${idG}.json`), JSON.stringify({ ...plantedBase, challenge_id: idG, approval_ref: `wallet-approval-challenge://${idG}`, target_scope: GENESIS_SCOPE, state: "pending", decision: null, grant: null, grant_ref: null, history: undefined, created_at: new Date().toISOString(), last_parked_at: new Date().toISOString(), expires_at_ms: Date.now() + 3_600_000 }));
    const G0 = await challenge(idG);
    await visit(pg, pagePath(idG));
    const gScope = await inner("[data-ioi-challenge-target-scope]");
    const genesis = await decide("approve", { id: idG, passphrase: OPERATOR_PASS });
    const gr = refusalOf(genesis.html);
    await shot("08-refused-outside-allowlist");
    const G1 = await challenge(idG);
    // the daemon's own words for the same decision (refused again before any secret is opened: nothing is recorded)
    const direct = await d("POST", `/v1/hypervisor/authority/challenges/${idG}/decision`, { decision: "approve", operator_passphrase: OPERATOR_PASS });
    const unescape = (s) => String(s || "").replace(/&quot;/gu, "\"").replace(/&gt;/gu, ">").replace(/&lt;/gu, "<").replace(/&amp;/gu, "&");
    ok("a challenge whose scope is outside the deployment approver's allowlist (System genesis; planted on this verifier's own data dir — no daemon gate parks one today) shows its scope, and approving it with the right passphrase is the authority's own refusal, verbatim on the page at the daemon's status — the record still pending with no grant, and the allowlist untouched",
      !!family && G0.state === "pending" && G0.target_scope === GENESIS_SCOPE && gScope === GENESIS_SCOPE && genesis.status === 502 && gr.code === "authority_approve_refused"
        && unescape(gr.message) === direct.j.error?.message && /target scope scope:autonomous_system\.genesis_admit is outside the deployment approver's allowlist \(scope:hypervisor\.live-route\.\*\)/u.test(unescape(gr.message))
        && G1.state === "pending" && G1.decision === null && G1.grant_ref === null && /data-ioi-challenge-state="pending"/u.test(genesis.html),
      `family ${family ? "found" : "NOT FOUND"} · planted ${G0.state} ${G0.target_scope} · page scope ${gScope} · POST ${genesis.status} ${gr.code}: ${unescape(gr.message).slice(0, 220)} · daemon's own: ${direct.status} ${direct.j.error?.code} · record ${G1.state}`);

    // ---- an id the daemon does not hold, and one it refuses to parse ---------------------------------------------------
    const unknownStatus = await visit(pg, pagePath(`wac_${"0".repeat(32)}`));
    const unknownCode = await attr("[data-ioi-challenge-missing]", "data-error-code");
    const badStatus = await visit(pg, pagePath("not-a-challenge"));
    const badCode = await attr("[data-ioi-challenge-missing]", "data-error-code");
    ok("an id the daemon holds no challenge for is its 404 (challenge_not_found), and a malformed one its 400 (challenge_id_invalid) — each named on the page, no form",
      unknownStatus === 404 && unknownCode === "challenge_not_found" && badStatus === 400 && badCode === "challenge_id_invalid" && !(await pg.content()).includes("<form"),
      `unknown ${unknownStatus} ${unknownCode} · malformed ${badStatus} ${badCode}`);

    ok("no page error on any page this verifier opened", pageErrors.length === 0, pageErrors.slice(0, 2).join(" | ") || "none");

    // ---- Closed: the daemon restarts on the same data with its pending window shortened, and an ask expires undecided ----
    await stopServe(serve);
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir: planeDir, baseEnv: sanitizedVerifierBaseEnv(process.env), env: { ...DAEMON_ENV, IOI_HYPERVISOR_AUTHORITY_CHALLENGE_TTL_MS: String(SHORT_TTL_MS) } });
    DAEMON = plane.daemonUrl;
    COOKIE = `ioi_session=${await isolatedOperatorSession(plane)}`;
    ({ child: serve, url: SERVE } = await startServe(DAEMON));
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const parkedC = await execute("archive the old build logs");
    const idC = parkedC.j.approval_challenge?.challenge_id;
    const C0 = idC ? await challenge(idC) : {};
    while (Number(C0.expires_at_ms) && Date.now() <= Number(C0.expires_at_ms) + 1000) await sleep(500);
    const cStatus = await visit(pg, pagePath(idC));
    const cState = await attr("[data-ioi-challenge-state]", "data-ioi-challenge-state");
    const cForms = await pg.evaluate(() => document.querySelectorAll("form").length);
    await shot("09-expired");
    const late = await fetch(`${SERVE}${pagePath(idC)}/deny`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/x-www-form-urlencoded" }, body: "reason=too+late", redirect: "manual" }).then(async (r) => ({ status: r.status, html: await r.text() }));
    const C1 = idC ? await challenge(idC) : {};
    ok("an ask nobody decided reads Closed once it expires (the daemon restarted with its pending window shortened — it can only be shortened): no form, and a decision posted anyway is the daemon's 410 challenge_expired on the page, the record still undecided",
      parkedC.status === 403 && C0.state === "pending" && cStatus === 200 && cState === "expired" && cForms === 0 && late.status === 410 && refusalOf(late.html).code === "challenge_expired" && C1.state === "pending" && C1.decision === null,
      `park ${parkedC.status} · page ${cStatus} ${cState} forms ${cForms} · late deny ${late.status} ${refusalOf(late.html).code} · daemon ${C1.state}`);

    // ---- the passphrase: in no serve output, no page, no file of the daemon's data dir ---------------------------------
    const leaks = filesHolding(planeDir, [Buffer.from(OPERATOR_PASS), Buffer.from(WRONG_PASS)]);
    ok("the passphrase (right or wrong) appears in no serve output and in no file of the daemon's data dir (its records and logs)",
      !serveOutput.includes(OPERATOR_PASS) && !serveOutput.includes(WRONG_PASS) && leaks.length === 0,
      `serve output ${serveOutput.length} chars, ${serveOutput.includes(OPERATOR_PASS) || serveOutput.includes(WRONG_PASS) ? "HOLDS IT" : "clean"} · data dir files holding it: ${leaks.length ? leaks.join(", ") : "none"}`);

    // ---- degraded: the daemon stopped -------------------------------------------------------------------------------------
    await plane.stop();
    plane = null;
    const downStatus = await visit(pg, pagePath(idA));
    const down = { degraded: await attr("[data-ioi-challenge-degraded]", "data-error-code"), t: await text(), forms: await pg.evaluate(() => document.querySelectorAll("form, [data-ioi-challenge-state]").length) };
    await shot("10-degraded");
    const downList = await visit(pg, "/__ioi/authority/challenges");
    ok("with the daemon stopped, the page says so (503, daemon_unavailable) and shows no challenge and no form; the list says so too",
      downStatus === 503 && down.degraded === "daemon_unavailable" && /The daemon is not answering/u.test(down.t) && down.forms === 0 && !down.t.includes(A0.request_hash) && downList === 503,
      `page ${downStatus} ${down.degraded} forms ${down.forms} · list ${downList}`);
  } finally {
    await browser.close();
  }
}

async function cleanup() {
  await stopServe(serve);
  try { await plane?.stop(); } catch { /* gone */ }
  try { await authority?.stop(); } catch { /* gone */ }
  try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch { /* keep */ }
  try { fs.rmSync(planeDir, { recursive: true, force: true }); } catch { /* keep */ }
}

run().then(async () => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "authority-challenge-page", sourceUrl: import.meta.url, results });
  await cleanup();
  process.exit(fails.length ? 1 : 0);
}).catch(async (e) => { console.error(e); await cleanup(); process.exit(1); });
