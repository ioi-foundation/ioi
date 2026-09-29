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
//   - a challenge under a System lifecycle scope (genesis admission — planted on this verifier's OWN data dir: parking one
//     through a daemon gate needs a whole System, which the journey gate drives) is approved through the page with one grant
//     from the deployment authority (the approver's allowlist names the System lifecycle scopes since 2026-09-29), and one
//     under a scope still outside the list (an unlisted sibling) is refused by the authority itself, verbatim on the page;
//   - an unknown or malformed id is the daemon's refusal; an ask past its expiry (the daemon restarted with its pending
//     window shortened) reads Closed and a decision on it is the daemon's 410;
//   - (R-240, challenge states + re-ask; the daemon restarted with its decision wait shortened to DECISION_WAIT_MS, so a real
//     ~30 s approve outlives the route's wait) a page approve the daemon answers 202 reads Still deciding, never a refusal;
//     the page re-read is Deciding — started when, by whom — with Approve and Deny disabled by that reason, and a decision
//     posted anyway is the daemon's 409; the approve settles on its own;
//   - an interrupted approve whose outcome is unknown (PLANTED on this verifier's own data dir: no live stack interrupts an
//     approve on demand) reads Outcome unknown with the daemon's named reason, Approve disabled by that name and Deny open;
//     Deny through the page makes the daemon reconcile from the authority's record first — nothing recorded, so a REAL
//     `interrupted` history entry — and the page lists it;
//   - an approval whose grant expired unused (its expiry moved into the past on this verifier's own data dir: the
//     authority's grant lives far longer than a run) is never approved again: the requester's retry naming it is refused
//     approval_ref_expired in true words and parks a successor for the same effect under a fresh nonce (a new request hash
//     the verifier re-derives); the old page reads expired and links the successor, which names what it supersedes; the
//     daemon never takes the old request hash to the authority again; the successor approved through its page is consumed
//     by the requester's retry once, and a replay of the old approval_ref stays refused;
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
// the route's bounded wait on the second restart: far under a real approve, so the route answers 202 and the approve settles
const DECISION_WAIT_MS = 1500;
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

    // ---- a System lifecycle scope is approvable through the page; a scope outside the list is the authority's refusal ------
    // The deployment approver's allowlist is the live-route family plus the System lifecycle scopes the daemon asks of a
    // System's governing authority, each named exactly (owner approval 2026-09-29; wallet_network_local_authority.rs). Both
    // challenges are planted on this verifier's own data dir, beside the real records (a daemon gate that parks a System
    // genesis challenge needs a whole System on the stack — the journey gate drives that one): B's denied coordinates
    // re-scoped to System genesis (the authority recorded no decision for them), and a fresh ask under an unlisted sibling.
    const family = filesHolding(planeDir, [Buffer.from(`"challenge_id":"${idB}"`), Buffer.from(`"challenge_id": "${idB}"`)]).map((p) => path.dirname(p)).find((p) => fs.existsSync(path.join(p, `${idB}.json`))) || null;
    const { decidable: _decidable, decision_route: _route, ...plantedBase } = B0;
    const plantAsk = (scope, policy, request) => {
      const id = challengeIdFor(scope, policy, request, B0.audience);
      if (family) fs.writeFileSync(path.join(family, `${id}.json`), JSON.stringify({ ...plantedBase, challenge_id: id, approval_ref: `wallet-approval-challenge://${id}`, target_scope: scope, policy_hash: policy, request_hash: request, state: "pending", decision: null, grant: null, grant_ref: null, history: undefined, created_at: new Date().toISOString(), last_parked_at: new Date().toISOString(), expires_at_ms: Date.now() + 3_600_000 }));
      return id;
    };
    const unescape = (s) => String(s || "").replace(/&quot;/gu, "\"").replace(/&gt;/gu, ">").replace(/&lt;/gu, "<").replace(/&amp;/gu, "&");
    const idG = plantAsk(GENESIS_SCOPE, B0.policy_hash, B0.request_hash);
    const G0 = await challenge(idG);
    await visit(pg, pagePath(idG));
    const gScope = await inner("[data-ioi-challenge-target-scope]");
    const genesis = await decide("approve", { id: idG, passphrase: OPERATOR_PASS });
    await shot("08-approved-system-scope");
    const G1 = await challenge(idG);
    ok("a challenge under a System lifecycle scope (genesis admission; planted on this verifier's own data dir) is approvable through its page: the right passphrase answers 303 back to the page, and the daemon's record is approved by the operator with one grant from the deployment authority, for exactly its hashes under that scope",
      !!family && G0.state === "pending" && G0.target_scope === GENESIS_SCOPE && gScope === GENESIS_SCOPE && genesis.status === 303
        && G1.state === "approved" && G1.decision?.decision === "approve" && G1.decision?.decided_by === me.principal_ref && typeof G1.grant_ref === "string" && G1.grant_ref.length > 0
        && G1.target_scope === GENESIS_SCOPE && G1.policy_hash === B0.policy_hash && G1.request_hash === B0.request_hash && /data-ioi-challenge-state="approved"/u.test(genesis.html),
      `family ${family ? "found" : "NOT FOUND"} · planted ${G0.state} ${G0.target_scope} · page scope ${gScope} · POST ${genesis.status} · daemon ${G1.state} grant ${G1.grant_ref} by ${G1.decision?.decided_by}`);
    const OUTSIDE_SCOPE = "scope:autonomous_system.ordering.recover";
    const hash = () => `sha256:${randomBytes(32).toString("hex")}`;
    const idO = plantAsk(OUTSIDE_SCOPE, hash(), hash());
    const O0 = await challenge(idO);
    const outside = await decide("approve", { id: idO, passphrase: OPERATOR_PASS });
    const or = refusalOf(outside.html);
    await shot("09-refused-outside-allowlist");
    const O1 = await challenge(idO);
    // the daemon's own words for the same decision (refused again before any secret is opened: nothing is recorded)
    const direct = await d("POST", `/v1/hypervisor/authority/challenges/${idO}/decision`, { decision: "approve", operator_passphrase: OPERATOR_PASS });
    ok("a challenge whose scope is outside the deployment approver's allowlist (an unlisted System sibling, ordering recovery; planted) is refused by the authority itself before any key is opened, verbatim on the page at the daemon's status — the record still pending with no grant",
      !!family && O0.state === "pending" && O0.target_scope === OUTSIDE_SCOPE && outside.status === 502 && or.code === "authority_approve_refused"
        && unescape(or.message) === direct.j.error?.message && /target scope scope:autonomous_system\.ordering\.recover is outside the deployment approver's allowlist \(scope:hypervisor\.live-route\.\* and \d+ named System lifecycle scopes\)/u.test(unescape(or.message))
        && O1.state === "pending" && O1.decision === null && O1.grant_ref === null && /data-ioi-challenge-state="pending"/u.test(outside.html),
      `planted ${O0.state} ${O0.target_scope} · POST ${outside.status} ${or.code}: ${unescape(or.message).slice(0, 220)} · daemon's own: ${direct.status} ${direct.j.error?.code} · record ${O1.state}`);

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

    // ---- R-240, challenge states + re-ask: the daemon restarts on the same data with the route's wait shortened ---------
    await stopServe(serve);
    await plane.stop();
    plane = await startIsolatedPlane({ dataDir: planeDir, baseEnv: sanitizedVerifierBaseEnv(process.env), env: { ...DAEMON_ENV, IOI_HYPERVISOR_AUTHORITY_DECISION_WAIT_MS: String(DECISION_WAIT_MS) } });
    DAEMON = plane.daemonUrl;
    COOKIE = `ioi_session=${await isolatedOperatorSession(plane)}`;
    ({ child: serve, url: SERVE } = await startServe(DAEMON));
    await ctx.addCookies([{ name: "ioi_session", value: COOKIE.split("=")[1], url: SERVE }]);
    const familyDir = filesHolding(planeDir, [Buffer.from(`"challenge_id":"${idA}"`), Buffer.from(`"challenge_id": "${idA}"`)]).map((p) => path.dirname(p)).find((p) => fs.existsSync(path.join(p, `${idA}.json`))) || null;
    const plant = (id, change) => { const file = path.join(familyDir, `${id}.json`); fs.writeFileSync(file, JSON.stringify(change(JSON.parse(fs.readFileSync(file, "utf8"))))); };
    // one read of everything a page shows about its state (a page being decided reloads itself every few seconds)
    const pageState = (p = pg) => p.evaluate(() => {
      const q = (s) => document.querySelector(s);
      const reasonOf = (label) => [...document.querySelectorAll("button[aria-disabled=true]")].find((b) => b.textContent.trim() === label)?.getAttribute("data-ioi-disabled-reason") || null;
      return { state: q("[data-ioi-challenge-state]")?.getAttribute("data-ioi-challenge-state") || null, label: q("[data-ioi-challenge-state]")?.textContent || null,
        since: q("[data-ioi-challenge-deciding-since]")?.textContent || null, by: q("[data-ioi-challenge-deciding-by]")?.textContent || null,
        approveWhy: reasonOf("Approve"), denyWhy: reasonOf("Deny"), forms: [...document.querySelectorAll("form[data-ioi-challenge-decision]")].map((f) => f.getAttribute("data-ioi-challenge-decision")),
        passphrase: !!q("[data-ioi-operator-passphrase]"), reload: q("[data-ioi-challenge-reload]")?.getAttribute("href") || null,
        unknownReason: q("[data-ioi-challenge-unknown-reason]")?.textContent || null, stillDeciding: !!q("[data-ioi-challenge-still-deciding]"), refusal: q("[data-ioi-challenge-refusal]")?.getAttribute("data-ioi-challenge-refusal") || null,
        supersededBy: q("[data-ioi-challenge-superseded-by] a")?.getAttribute("href") || null, supersedes: q("[data-ioi-challenge-supersedes]")?.getAttribute("data-ioi-challenge-supersedes") || null,
        history: [...document.querySelectorAll("[data-ioi-challenge-history]")].map((r) => ({ state: r.getAttribute("data-ioi-challenge-history"), text: r.textContent })) };
    });
    const settledOf = async (id) => { const end = Date.now() + APPROVE_WAIT_MS; let c = await challenge(id); while (Date.now() < end && c.state === "pending" && c.deciding) { await sleep(1000); c = await challenge(id); } return c; };

    // ---- Outcome unknown (planted), and Deny's real reconciliation leaving an `interrupted` history entry ----------------
    const parkedF = await execute("rotate the staging keys");
    const idF = parkedF.j.approval_challenge?.challenge_id;
    const UNKNOWN_REASON = "authority_record_unreadable";
    if (familyDir && idF) plant(idF, (c) => ({ ...c, outcome_unknown: { reason: UNKNOWN_REASON, message: "the authority's record for this request hash could not be read (planted by the challenge-page verifier); nothing is concluded until it can be", since: new Date().toISOString(), checked_at: new Date().toISOString(),
      attempt: { attempt_id: "dec_planted_by_verifier", process: "dp_planted_by_verifier", decided_by: me.principal_ref, reason: "", started_at: new Date().toISOString(), started_at_ms: Date.now(), child_pid: null } } }));
    const F0 = idF ? await challenge(idF) : {};
    await visit(pg, pagePath(idF));
    const fShown = await pageState();
    await shot("11-outcome-unknown");
    ok("an interrupted approve whose outcome is unknown (PLANTED on this verifier's own data dir) reads Outcome unknown with the daemon's named reason: Approve disabled by that name (aria-disabled + data-ioi-disabled-reason, no passphrase asked) and the Deny form open",
      !!familyDir && F0.state === "pending" && F0.outcome_unknown?.reason === UNKNOWN_REASON && fShown.state === "outcome_unknown" && fShown.label === `Outcome unknown — ${UNKNOWN_REASON}` && fShown.unknownReason === UNKNOWN_REASON
        && String(fShown.approveWhy || "").includes(`(${UNKNOWN_REASON})`) && /Deny stays open/u.test(fShown.approveWhy || "") && !fShown.passphrase && JSON.stringify(fShown.forms) === JSON.stringify(["deny"]),
      `daemon ${F0.state} unknown ${F0.outcome_unknown?.reason} · page ${fShown.state} "${fShown.label}" · approve why "${String(fShown.approveWhy).slice(0, 120)}" · forms ${JSON.stringify(fShown.forms)} · passphrase field ${fShown.passphrase}`);
    const fDenied = await decide("deny", { id: idF, reason: "interrupted; not needed" });
    const F1 = await challenge(idF);
    const fAfter = await pageState();
    await shot("12-denied-after-reconciliation");
    const fLast = (F1.history || []).at(-1) || {};
    ok("Deny through the page on that ask: the daemon first reconciles it from the authority's own record (nothing recorded for its request hash, no approve running) — a REAL `interrupted` entry in its history — then denies it, and the page lists the Interrupted entry under the denial",
      fDenied.status === 303 && F1.state === "denied" && F1.decision?.reason === "interrupted; not needed" && !F1.outcome_unknown && fLast.state === "interrupted" && fLast.reconciliation?.authority_record === "absent" && fLast.reconciliation?.attempt?.attempt_id === "dec_planted_by_verifier"
        && fAfter.state === "denied" && fAfter.history.some((h) => h.state === "interrupted" && /Interrupted/u.test(h.text) && /the authority recorded nothing for this request hash/u.test(h.text)),
      `POST ${fDenied.status} · daemon ${F1.state} · last history ${JSON.stringify({ state: fLast.state, record: fLast.reconciliation?.authority_record })} · page ${fAfter.state} history ${JSON.stringify(fAfter.history.map((h) => h.state))}`);

    // ---- Deciding and Still deciding: a real approve outlives the route's shortened wait ---------------------------------
    const parkedD = await execute("write the release notes");
    const idD = parkedD.j.approval_challenge?.challenge_id;
    const D0 = idD ? await challenge(idD) : {};
    const still = await decide("approve", { id: idD, passphrase: OPERATOR_PASS });
    const stillShown = await pageState();
    const D1 = await challenge(idD);
    await shot("13-still-deciding");
    ok("an approve the daemon is still recording when the route's wait runs out answers 202 and reads Still deciding (a status, in the daemon's words — never a refusal), above the record re-read, which the daemon marks as being decided by the operator",
      still.status === 202 && stillShown.stillDeciding && stillShown.refusal === null && /challenge_decision_still_running/u.test(still.t) && !/The daemon refused/u.test(still.t)
        && D1.state === "pending" && D1.deciding?.decided_by === me.principal_ref && !still.html.includes(OPERATOR_PASS) && !still.url.includes(OPERATOR_PASS),
      `POST ${still.status} still-deciding ${stillShown.stillDeciding} refusal ${stillShown.refusal} · daemon ${D1.state} deciding ${JSON.stringify(D1.deciding ? { by: D1.deciding.decided_by, at: D1.deciding.started_at } : null)}`);
    await visit(pg, pagePath(idD));
    const dShown = await pageState();
    await shot("14-deciding");
    const busy = await fetch(`${SERVE}${pagePath(idD)}/deny`, { method: "POST", headers: { cookie: COOKIE, "content-type": "application/x-www-form-urlencoded" }, body: "reason=while+deciding", redirect: "manual" }).then(async (r) => ({ status: r.status, html: await r.text() }));
    const D2 = await challenge(idD);
    ok("the page re-read while it runs reads Deciding — started when, by whom (the daemon's marker) — with Approve and Deny disabled by that reason and no form or passphrase field, a reload link to itself; and a decision posted anyway is the daemon's 409 challenge_decision_in_progress, the record still being decided",
      dShown.state === "deciding" && dShown.since === D1.deciding?.started_at && dShown.by === `${ISOLATED_OPERATOR.name} ${me.principal_ref}` && /already running/u.test(dShown.approveWhy || "") && /already running/u.test(dShown.denyWhy || "")
        && dShown.forms.length === 0 && !dShown.passphrase && dShown.reload === pagePath(idD)
        && busy.status === 409 && refusalOf(busy.html).code === "challenge_decision_in_progress" && D2.state === "pending" && D2.deciding?.attempt_id === D1.deciding?.attempt_id,
      `page ${dShown.state} "${dShown.label}" since ${dShown.since} by ${dShown.by} · approve why "${String(dShown.approveWhy).slice(0, 90)}" · deny why ${dShown.denyWhy ? "set" : "NONE"} · forms ${dShown.forms.length} · reload ${dShown.reload} · posted deny ${busy.status} ${refusalOf(busy.html).code} · daemon ${D2.state}`);
    const D3 = await settledOf(idD);
    ok("the approve settles on its own in the daemon: the record approved by the operator with a grant for exactly its coordinates, the marker gone",
      D3.state === "approved" && !D3.deciding && !!D3.grant_ref && D3.decision?.decided_by === me.principal_ref && D3.request_hash === D0.request_hash,
      `daemon ${D3.state} grant ${JSON.stringify(D3.grant_ref)} by ${D3.decision?.decided_by}`);

    // ---- an approval whose grant expired unused is asked again, never approved again ------------------------------------
    // (the authority's grant lives far longer than this run: its expiry is moved into the past on this verifier's own data)
    if (familyDir && idD) plant(idD, (c) => ({ ...c, grant_expires_at_ms: Date.now() - 1000 }));
    const intentD = D0.published_preimage?.request_preimage?.intent;
    const stale = await execute(intentD, D3.approval_ref);
    const idE = stale.j.approval_challenge?.challenge_id;
    const E0 = idE ? await challenge(idE) : {};
    const D4 = await challenge(idD);
    const reaskHash = (base, nonce) => `sha256:${createHash("sha256").update(JSON.stringify({ ask_nonce: nonce, domain: "ioi.hypervisor.wallet-approval-challenge.reask.v1", request_hash: base })).digest("hex")}`;
    ok("the requester's retry naming an approval whose grant expired unused is refused approval_ref_expired in true words (never \"approve again\") and parks a SUCCESSOR for the same effect: pending, a new request hash re-derived here from the old one and a fresh nonce, a new id naming what it supersedes; the old record keeps its approval and names the successor",
      stale.status === 403 && stale.j.reason === "approval_ref_expired" && /cannot be approved again/u.test(stale.j.message || "") && /asked again/u.test(stale.j.message || "") && !/approve again/u.test(stale.j.message || "")
        && !!idE && idE !== idD && stale.j.approval_challenge?.supersedes === idD && E0.state === "pending" && E0.supersedes === idD && E0.base_request_hash === D0.request_hash && E0.request_hash !== D0.request_hash
        && E0.request_hash === reaskHash(D0.request_hash, E0.ask_nonce) && E0.policy_hash === D0.policy_hash && E0.target_scope === D0.target_scope && idE === challengeIdFor(D0.target_scope, D0.policy_hash, E0.request_hash, D0.audience)
        && D4.state === "approved" && D4.superseded_by === idE && D4.request_hash === D0.request_hash,
      `retry ${stale.status} ${stale.j.reason}: ${String(stale.j.message || "").slice(0, 160)} · successor ${idE} ${E0.state} supersedes ${E0.supersedes} · request ${E0.request_hash === reaskHash(D0.request_hash, E0.ask_nonce) ? "re-derived" : "NOT re-derived"} · old ${D4.state} → ${D4.superseded_by}`);
    await visit(pg, pagePath(idD));
    const oldShown = await pageState();
    await shot("15-grant-expired-asked-again");
    await visit(pg, pagePath(idE));
    const newShown = await pageState();
    await shot("16-successor");
    const againOld = await d("POST", `/v1/hypervisor/authority/challenges/${idD}/decision`, { decision: "approve", operator_passphrase: OPERATOR_PASS });
    const D5 = await challenge(idD);
    ok("the old page reads Approved — grant expired unused; the action must be asked again, with no form and a link to the successor; the successor's page names what it supersedes and carries the operator's forms; and the old request hash is never taken to the authority again (the daemon's 410 challenge_grant_expired, nothing started)",
      oldShown.state === "grant_expired" && /grant expired unused; the action must be asked again/u.test(oldShown.label || "") && oldShown.forms.length === 0 && oldShown.supersededBy === pagePath(idE)
        && newShown.state === "pending" && newShown.supersedes === idD && newShown.forms.includes("approve") && newShown.forms.includes("deny")
        && againOld.status === 410 && againOld.j.error?.code === "challenge_grant_expired" && againOld.j.superseded_by === idE && D5.state === "approved" && JSON.stringify(D5.decision) === JSON.stringify(D4.decision),
      `old page ${oldShown.state} "${oldShown.label}" forms ${oldShown.forms.length} → ${oldShown.supersededBy} · new page ${newShown.state} supersedes ${newShown.supersedes} forms ${JSON.stringify(newShown.forms)} · approve old ${againOld.status} ${againOld.j.error?.code}`);
    const eAsk = await decide("approve", { id: idE, passphrase: OPERATOR_PASS });
    const E1 = await settledOf(idE);
    const ran = await execute(intentD, E1.approval_ref);
    const E2 = await challenge(idE);
    const replayOld = await execute(intentD, D3.approval_ref);
    // R-240, authority follow-ups: the effect has now run once under the successor, so the replay is a NEW crossing of
    // it. It is still refused approval_ref_expired (nothing runs), and it is asked again as the consumed successor's own
    // successor — pending, a request hash the authority has never decided — never the consumed record (which read
    // `consumed` here until this change, and which a decision could only answer 409 challenge_consumed).
    const idNext = String(replayOld.j.approval_challenge?.challenge_id || "");
    const [E3, N0] = await Promise.all([challenge(idE), idNext ? challenge(idNext) : Promise.resolve({})]);
    ok("the operator approves the successor through its page: the authority mints a grant for the NEW request hash, the requester's retry naming it runs the effect once (consumed by its admission), and a replay of the old approval_ref is still refused approval_ref_expired — the effect having run once, the replay is asked again as the consumed successor's own successor, pending under a new request hash, and the consumed one stays consumed",
      (eAsk.status === 202 || eAsk.status === 303) && E1.state === "approved" && !!E1.grant_ref && E1.request_hash === E0.request_hash
        && E2.state === "consumed" && String(E2.consumed_by || "").startsWith("authority-admission-intents/")
        && replayOld.status === 403 && replayOld.j.reason === "approval_ref_expired"
        && /^wac_[0-9a-f]{32}$/u.test(idNext) && idNext !== idE && idNext !== idD && replayOld.j.approval_challenge?.challenge_state === "pending"
        && replayOld.j.approval_challenge?.supersedes === idE && N0.supersedes_reason === "consumed" && N0.request_hash && N0.request_hash !== E0.request_hash && N0.request_hash !== D0.request_hash
        && E3.state === "consumed" && E3.superseded_by === idNext,
      `approve ${eAsk.status} · daemon ${E1.state} grant ${JSON.stringify(E1.grant_ref)} · retry ${ran.status} ${ran.j.decision || ran.j.reason || ""} · ${E2.state} by ${E2.consumed_by} · old replay ${replayOld.status} ${replayOld.j.reason} → ${idNext} ${replayOld.j.approval_challenge?.challenge_state} supersedes ${replayOld.j.approval_challenge?.supersedes} (${N0.supersedes_reason}) · successor ${E3.state} → ${E3.superseded_by}`);

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
