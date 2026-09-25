#!/usr/bin/env node
// AGENT STUDIO WRITE LANES verifier (R-240, 2026-09-25) — the forms S5-1 orphaned, submitted for real.
//
// S5-1 (6e48f8874) took goal pursuit out of the Hypervisor and deleted, with it, the serve handlers behind
// seven Agent Studio write lanes that were never goal pursuit: the improvement proposals' Approve / Reject /
// Apply, their governance gates (Request approval, Create release gate, attach), the memory/skill lifecycle
// transitions, the portable vault's export and import, and the memory-mutation proposal inbox. Every daemon
// route they relay to still existed and the page kept rendering the forms, so each button posted into the
// vendored app shell (HTTP 200, nothing happened). check:dead-controls could not see it: it aborts every
// write, so a form that lands nowhere reads exactly like one that lands. Only a real submission can tell.
//
// So this verifier OWNS its daemon (a fresh data directory, its own port) and its serve (its own ports, the
// sign-in gate ON), bootstraps its own operator through the serve's first-run form with the daemon's
// one-boot token, and then, as that signed-in person:
//   1. finds each lane's form ON THE RENDERED PAGE (a lane the page does not offer is not proven here), and
//   2. submits it, and judges it by the DAEMON'S RECORDED STATE, never by a status code alone: a 302 that
//      changed nothing is a dead control with a nicer redirect.
// A lane the daemon refuses must say why in the daemon's own code, and the verifier names which.
//
// Exit: 0 pass · 1 fail · 2 blocked (the daemon binary is missing or the stack did not come up).
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(HERE, "..");
const ROOT = path.resolve(APP, "..", "..");
const DAEMON_BIN = process.env.IOI_HYPERVISOR_DAEMON_BIN || path.join(ROOT, "target", "debug", "hypervisor-daemon");
const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail: String(detail).slice(0, 240) });

const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const waitFor = async (url, ms, what) => {
  const until = Date.now() + ms;
  for (;;) {
    try { const r = await fetch(url); if (r.status) return; } catch { /* retry */ }
    if (Date.now() > until) throw new Error(`${what} did not come up in ${ms / 1000}s`);
    await new Promise((r) => setTimeout(r, 400));
  }
};

if (!fs.existsSync(DAEMON_BIN)) { console.error(`BLOCKED: no daemon binary at ${DAEMON_BIN}`); process.exit(2); }
let daemon = null;
let serve = null;
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-studio-write-lanes-"));
let exitCode = 1;
try {
  const daemonPort = await freePort();
  let daemonOut = "";
  daemon = spawn(DAEMON_BIN, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${daemonPort}` }, stdio: ["ignore", "pipe", "pipe"] });
  daemon.stdout.on("data", (d) => { daemonOut += d; });
  daemon.stderr.on("data", (d) => { daemonOut += d; });
  const D = `http://127.0.0.1:${daemonPort}`;
  await waitFor(`${D}/v1/hypervisor/auth/bootstrap-status`, 120000, "this verifier's own daemon");
  const port = await freePort();
  const uiPort = await freePort();
  const SERVE = `http://127.0.0.1:${port}`;
  serve = spawn(process.execPath, [path.join(HERE, "serve-product-ui.mjs")], {
    cwd: APP,
    env: { ...process.env, PORT: String(port), PRODUCT_UI_PORT: String(uiPort), IOI_HYPERVISOR_DAEMON_URL: D, IOI_PRODUCT_UI_PUBLIC: path.join(APP, "product-ui", "owned", "public"), IOI_PRODUCT_SIGNIN_REQUIRED: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitFor(`${SERVE}/`, 60000, "this verifier's own serve");

  // THE OPERATOR, through the serve's own first-run form.
  const token = (daemonOut.match(/ioi_bootstrap_[A-Za-z0-9_-]+/u) || [])[0];
  if (!token) throw new Error("the daemon printed no one-boot bootstrap token");
  const boot = await fetch(`${SERVE}/__ioi/bootstrap`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token, name: "Studio Lanes", email: "lanes@agent-studio.invalid", password: "agent-studio-lanes-pass-1" }).toString() });
  const cookie = ((boot.headers.get("set-cookie") || "").match(/ioi_session=[^;]+/) || [])[0] || "";
  ok("SETUP — an operator is bootstrapped through the serve's own first-run form, and the session is signed in", boot.status === 302 && cookie.length > 20, `${boot.status}`);
  const H = { cookie };
  const page = () => fetch(`${SERVE}/__ioi/agent-studio`, { headers: { ...H, accept: "text/html" } }).then((r) => r.text());
  const submit = async (action, fields = {}) => {
    const r = await fetch(`${SERVE}${action}`, { method: "POST", redirect: "manual", headers: { ...H, "content-type": "application/x-www-form-urlencoded", accept: "text/html" }, body: new URLSearchParams(fields).toString() });
    const text = await r.text();
    return { status: r.status, loc: r.headers.get("location") || "", refusal: (text.match(/rejected fail-closed: <code>([^<]+)<\/code>/) || text.match(/Rejected fail-closed: <code>([^<]+)<\/code>/) || [])[1] || "", text };
  };
  // The daemon, read as the same person: the serve forwards the session cookie itself, so do we.
  const dget = (p) => fetch(`${D}${p}`, { headers: H }).then((r) => r.json()).catch(() => ({}));
  const dpost = (p, b) => fetch(`${D}${p}`, { method: "POST", headers: { ...H, "content-type": "application/json" }, body: JSON.stringify(b) }).then((r) => r.json()).catch(() => ({}));
  const offers = (html, action) => html.includes(`action="${action}"`);
  // Agent Studio renders its panels only once an agent exists ("No agents yet" otherwise), so the
  // operator gets one first — the daemon's own agent create, as that person.
  const agent = await dpost("/v1/agents", { options: {} });
  ok("SETUP — an agent exists, so Agent Studio renders its panels", !!(agent && agent.id), JSON.stringify(agent).slice(0, 120));
  const tag = `asl${Date.now().toString(36).slice(-6)}`;

  // 1. IMPROVEMENT PROPOSALS and their governance gates. Seeded through the Propose lane (which S5-1 kept).
  const seed = await submit("/__ioi/agent-studio/improvements/propose", { candidate_json: JSON.stringify({ candidate_kind: "skill_improvement", signal: `${tag}-a`, evidence_refs: [`agent-run-transcript://${tag}`], confidence: 0.6, suggested: { title: `Lanes ${tag} A` }, occurrences: 2 }) });
  const findImp = async (sig) => ((await dget("/v1/hypervisor/intelligence/improvement-proposals")).proposals || []).find((p) => p.signal === sig);
  let impA = await findImp(`${tag}-a`);
  ok("SEED — the Propose lane records an improvement proposal", seed.status === 302 && !!impA, seed.refusal || seed.status);
  const iid = impA?.improvement_id || "none";
  let html = await page();
  const reqAppr = `/__ioi/agent-studio/improvements/${iid}/governance/request-approval`;
  const openRel = `/__ioi/agent-studio/improvements/${iid}/governance/open-release`;
  // The card offers the governance row only on the HIGH-IMPACT path (the daemon's gate posture is
  // awaiting_approval / awaiting_release / ready); a proposal nobody has simulated sits at no_simulation.
  // So the check is that the page offers the gates EXACTLY when the daemon's gate asks for them — the
  // lanes are then submitted either way, because a restored lane must land whenever it is reached.
  const highPath = ["awaiting_approval", "awaiting_release", "ready"].includes(impA?.gate?.posture);
  ok(`the page offers the governance gates exactly when the daemon's gate asks for them (posture ${impA?.gate?.posture || "?"})`,
    highPath === (offers(html, reqAppr) && offers(html, openRel)) && highPath === html.includes(`data-gov="${iid}"`), `high=${highPath}`);
  const g1 = await submit(reqAppr);
  const g2 = await submit(openRel);
  impA = await findImp(`${tag}-a`);
  ok("Request approval LANDS: the proposal now names an approval request the governance plane issued", g1.status === 302 && /^approval-request:\/\//.test(impA?.approval_request_ref || ""), g1.refusal || impA?.approval_request_ref);
  ok("Create release gate LANDS: the proposal now names a release control the governance plane issued", g2.status === 302 && /^release-control:\/\//.test(impA?.release_control_ref || ""), g2.refusal || impA?.release_control_ref);
  html = await page();
  const approveA = `/__ioi/agent-studio/improvements/${iid}/approve`;
  const a1 = offers(html, approveA) ? await submit(approveA) : { status: 0, refusal: "the page does not offer Approve" };
  impA = await findImp(`${tag}-a`);
  ok("Approve LANDS: the proposal's recorded state moves off pending, or the daemon refuses in its own words", (a1.status === 302 && impA?.state && impA.state !== "pending") || (a1.status === 200 && a1.refusal && a1.refusal !== "daemon unavailable"), `${a1.status} ${a1.refusal || impA?.state}`);
  const applyA = `/__ioi/agent-studio/improvements/${iid}/apply`;
  html = await page();
  const p1 = offers(html, applyA) ? await submit(applyA) : { status: 0, refusal: "the page does not offer Apply" };
  const after = await findImp(`${tag}-a`);
  ok("Apply LANDS or refuses in the daemon's own words (an unmet gate is a reason, never an outage)", (p1.status === 302 && after?.state === "applied") || (p1.status === 200 && p1.refusal && p1.refusal !== "daemon unavailable"), `${p1.status} ${p1.refusal || after?.state}`);
  await submit("/__ioi/agent-studio/improvements/propose", { candidate_json: JSON.stringify({ candidate_kind: "automation_readiness", signal: `${tag}-b`, evidence_refs: [`agent-run-transcript://${tag}`], confidence: 0.4, suggested: { title: `Lanes ${tag} B` }, occurrences: 1 }) });
  const impB = await findImp(`${tag}-b`);
  html = await page();
  const rejectB = `/__ioi/agent-studio/improvements/${impB?.improvement_id || "none"}/reject`;
  const r1 = offers(html, rejectB) ? await submit(rejectB, { reason: "verifier" }) : { status: 0, refusal: "the page does not offer Reject" };
  const impB2 = await findImp(`${tag}-b`);
  ok("Reject LANDS: the second proposal is recorded rejected", r1.status === 302 && impB2?.state === "rejected", `${r1.status} ${r1.refusal || impB2?.state}`);

  // 2. THE MEMORY-MUTATION PROPOSAL INBOX: a proposal a run would raise, decided on the page.
  const raise = async (title) => (await dpost("/v1/hypervisor/memory-mutation-proposals", { operation: "add", target_family: "memory", mutation_type: "fact", source_authority: "user", suggested: { title, body: `${tag} ${title}` } }))?.proposal?.mutation_id || "";
  const m1 = await raise(`${tag} keep`);
  const m2 = await raise(`${tag} drop`);
  html = await page();
  const apAct = `/__ioi/agent-studio/proposals/${encodeURIComponent(m1)}/approve`;
  const rjAct = `/__ioi/agent-studio/proposals/${encodeURIComponent(m2)}/reject`;
  ok("the page OFFERS the open proposals in its inbox (Approve · Reject)", !!m1 && !!m2 && offers(html, apAct) && offers(html, rjAct), `${m1} ${m2}`);
  const pa = await submit(apAct);
  const pr = await submit(rjAct);
  const props = (await dget("/v1/hypervisor/memory-mutation-proposals")).proposals || [];
  const st = (id) => props.find((p) => p.mutation_id === id)?.review_state;
  ok("inbox Approve LANDS: the proposal is recorded approved (and so writes its entry with a receipt)", pa.status === 302 && st(m1) === "approved", `${pa.status} ${pa.refusal || st(m1)}`);
  ok("inbox Reject LANDS: the proposal is recorded rejected", pr.status === 302 && st(m2) === "rejected", `${pr.status} ${pr.refusal || st(m2)}`);

  // 3. MEMORY LIFECYCLE on the entry the approval wrote.
  const entries = ((await dget("/v1/hypervisor/memory-entries")).entries || []);
  const entry = entries.find((e) => JSON.stringify(e).includes(`${tag} keep`));
  html = await page();
  const lcAct = `/__ioi/agent-studio/intel/memory/${encodeURIComponent(entry?.entry_id || "none")}/lifecycle`;
  const q0 = entry?.quality_state || "";
  const lc = offers(html, lcAct) ? await submit(lcAct, { transition: q0 === "candidate" ? "promote" : "mark_stale" }) : { status: 0, refusal: "the page does not offer a lifecycle transition" };
  const entry2 = ((await dget("/v1/hypervisor/memory-entries")).entries || []).find((e) => e.entry_id === entry?.entry_id);
  ok("a memory lifecycle transition LANDS: the entry's recorded quality state changes", lc.status === 302 && !!entry2 && entry2.quality_state !== q0, `${lc.status} ${lc.refusal || `${q0} -> ${entry2?.quality_state}`}`);

  // 4. THE PORTABLE VAULT: export, then import the export back (idempotent: nothing new, nothing lost).
  const ex = await fetch(`${SERVE}/__ioi/agent-studio/vault/export`, { headers: H }).then(async (r) => ({ status: r.status, disp: r.headers.get("content-disposition") || "", text: await r.text() }));
  let vault = null; try { vault = JSON.parse(ex.text); } catch { vault = null; }
  ok("vault export answers the vault as a download", ex.status === 200 && /attachment/.test(ex.disp) && vault && typeof vault === "object", `${ex.status}`);
  html = await page();
  const im = offers(html, "/__ioi/agent-studio/vault/import") ? await submit("/__ioi/agent-studio/vault/import", { vault_json: ex.text }) : { status: 0, text: "", refusal: "the page does not offer vault import" };
  ok("vault import LANDS: re-importing the export reports the daemon's own tally (imported / unchanged / conflicts)", im.status === 200 && /<h1>Vault imported<\/h1>/.test(im.text) && /Unchanged \(idempotent\)/.test(im.text), `${im.status} ${im.refusal}`);

  exitCode = results.every((r) => r.pass) ? 0 : 1;
} catch (e) {
  console.error(`BLOCKED: ${e.message}`);
  exitCode = results.length ? 1 : 2;
} finally {
  serve?.kill();
  daemon?.kill();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}
const passed = results.filter((r) => r.pass).length;
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.pass || !r.detail ? "" : `  (${r.detail})`}`);
console.log(`${passed}/${results.length} passed`);
emitVerifierCensus({ verifierId: "agent-studio-write-lanes", sourceUrl: import.meta.url, results });
process.exit(exitCode);
