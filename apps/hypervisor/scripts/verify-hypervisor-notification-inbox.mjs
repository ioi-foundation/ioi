#!/usr/bin/env node
// NOTIFICATION INBOX verifier (ADR 0056 P1, 2026-09-25) — the inbox is a PROJECTION of owner events, and
// this proves it on a daemon of its own: canon says notifications introduce no notification-event truth
// plane, so every item must be re-derived from the owner record that changed, carry one link back to it,
// and survive a restart without anything having been stored.
//
// It OWNS its daemon (fresh data directory, own port), bootstraps an operator with the one-boot token, then
// raises real owner events through the owners' own routes — an approval request over an improvement
// proposal, and a filed support incident — and reads GET /v1/hypervisor/notifications as that person:
//   1. IDENTITY FIRST — a signed-out read is refused in the owners' words, never answered with an inbox.
//   2. EACH OWNER EVENT PROJECTS ONE ITEM with the owner's own dotted transition and a link back to it.
//   3. TRANSITIONS, RE-DERIVED — deciding the approval changes its item's kind; nothing was updated in place.
//   4. THE ENVELOPE IS HONEST — the cap is named, the three absent families are typed absences, email is
//      named as absent, `stores_nothing`.
//   5. REFUSALS ARE TYPED — an unknown family and an out-of-range limit.
//   6. NOTHING IS STORED — the read writes no file, and after a restart the same items come back.
// Exit: 0 pass · 1 fail · 2 blocked (daemon binary missing or the daemon did not come up).
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { callerOwnerRef } from "../surfaces/kit.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const DAEMON_BIN = process.env.IOI_HYPERVISOR_DAEMON_BIN || path.join(ROOT, "target", "debug", "hypervisor-daemon");
const results = [];
const ok = (name, cond, detail = "") => results.push({ name, pass: !!cond, detail: String(detail).slice(0, 240) });
const freePort = () => new Promise((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
const waitFor = async (url, ms) => {
  const until = Date.now() + ms;
  for (;;) {
    try { const r = await fetch(url); if (r.status) return; } catch { /* retry */ }
    if (Date.now() > until) throw new Error(`the daemon did not come up in ${ms / 1000}s`);
    await new Promise((r) => setTimeout(r, 400));
  }
};
const countFiles = (dir) => { let n = 0; const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { if (e.isDirectory()) walk(path.join(d, e.name)); else n += 1; } }; walk(dir); return n; };

if (!fs.existsSync(DAEMON_BIN)) { console.error(`BLOCKED: no daemon binary at ${DAEMON_BIN}`); process.exit(2); }
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "notification-inbox-"));
let daemon = null;
let exitCode = 1;
const start = async (port) => {
  let out = "";
  const child = spawn(DAEMON_BIN, [], { cwd: ROOT, env: { ...process.env, IOI_HYPERVISOR_DATA_DIR: dataDir, IOI_HYPERVISOR_DAEMON_ADDR: `127.0.0.1:${port}` }, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  await waitFor(`http://127.0.0.1:${port}/v1/hypervisor/auth/bootstrap-status`, 120000);
  return { child, out: () => out };
};
try {
  const port = await freePort();
  const D = `http://127.0.0.1:${port}`;
  let run = await start(port);
  daemon = run.child;
  const token = (run.out().match(/ioi_bootstrap_[A-Za-z0-9_-]+/u) || [])[0];
  if (!token) throw new Error("the daemon printed no one-boot bootstrap token");
  const boot = await fetch(`${D}/v1/hypervisor/auth/bootstrap`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, name: "Inbox Verifier", email: "inbox@notifications.invalid", password: "notification-inbox-pass-1" }) }).then((r) => r.json()).catch(() => ({}));
  const session = boot.session_token || "";
  ok("SETUP — an operator is bootstrapped with the daemon's one-boot token", session.length > 20, JSON.stringify(boot).slice(0, 120));
  const H = { cookie: `ioi_session=${session}` };
  const get = (p, h = H) => fetch(`${D}${p}`, { headers: h }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));
  const post = (p, b, method = "POST") => fetch(`${D}${p}`, { method, headers: { ...H, "content-type": "application/json" }, body: JSON.stringify(b) }).then(async (r) => ({ status: r.status, j: await r.json().catch(() => ({})) }));

  // 1. Identity first.
  const anon = await get("/v1/hypervisor/notifications", {});
  ok("IDENTITY FIRST — a signed-out read is refused in the owners' words, never answered with an inbox",
    anon.status === 401 && (anon.j.code || anon.j.error?.code) === "request_principal_required" && !Array.isArray(anon.j.items), `${anon.status} ${JSON.stringify(anon.j).slice(0, 100)}`);

  // Owner events, raised through the owners' own routes.
  const imp = await post("/v1/hypervisor/intelligence/improvement-proposals", { proposal_kind: "skill_improvement", signal: "inbox-verifier", evidence_refs: ["agent-run-transcript://inbox-verifier"], confidence: 0.5, suggested: { title: "Inbox verifier" }, reason: "verifier" });
  const proposalRef = imp.j.proposal?.proposal_ref || "";
  const appr = await post("/v1/hypervisor/governance/approval-requests", { subject_ref: proposalRef, request_kind: "improvement_apply", reason: "inbox verifier" });
  const apprRef = appr.j.approval_request?.ref || "";
  const apprTail = apprRef.replace("approval-request://", "");
  const who = (await get("/v1/hypervisor/auth/whoami")).j;
  const owner = callerOwnerRef(who);
  const inc = await post("/v1/hypervisor/support-incidents", { owner_ref: owner, idempotency_key: "inbox-verifier-1", title: "Orders feed stopped syncing", severity: "minor", affected_object_refs: ["data-source:ds_inbox"], product: "", redacted_diagnostics: "", assigned_owner_ref: "" });
  const incRef = inc.j.incident?.incident_id || "";
  // A health check whose probe cannot run (its environment does not exist) is ERRORED when evaluated —
  // an Operations owner event (ADR 0056 P2). file_on never: this check files no issue of its own.
  const hc = await post("/v1/hypervisor/health-checks", { owner_ref: owner, idempotency_key: "inbox-verifier-hc", display_name: "Inbox probe", target_ref: "environment://env_absent", check_kind: "command_exit", probe: { environment_ref: "environment://env_absent", command: "true" }, severity: "minor", incident_policy: { file_on: "never" } });
  const hcRef = hc.j.health_check?.health_check_id || "";
  const hcTail = hcRef.replace("health-check://", "");
  const hcEval = hcTail ? await post(`/v1/hypervisor/health-checks/${hcTail}/evaluate`, { owner_ref: owner, idempotency_key: "inbox-verifier-hc-1" }) : { status: 0, j: {} };
  ok("SETUP — owner events raised through the owners' routes (an approval request, a filed issue, a health check that could not run)",
    !!apprRef && !!incRef && hcEval.j.health_check_result?.outcome === "errored", `${appr.status} ${inc.status} ${hcEval.status} ${hcEval.j.health_check_result?.outcome || JSON.stringify(hcEval.j).slice(0, 100)}`);

  // 2. Each owner event projects one item with a link back.
  const before = countFiles(dataDir);
  const inbox = await get("/v1/hypervisor/notifications");
  const after = countFiles(dataDir);
  const items = Array.isArray(inbox.j.items) ? inbox.j.items : [];
  const apprItem = items.find((i) => i.owner_ref === apprRef);
  const incItem = items.find((i) => i.owner_ref === incRef);
  ok("the pending approval projects `approval.requested` with one link back to the request on Governance / Approvals",
    inbox.status === 200 && apprItem?.event_kind === "approval.requested" && apprItem?.canonical_detail_route === `/governance/approvals?req=${apprTail}` && apprItem?.owner_event_family === "approval", JSON.stringify(apprItem).slice(0, 160));
  ok("the filed issue projects `incident.opened` (an Operations owner event) with one link back to it on Operations / Issues",
    incItem?.event_kind === "incident.opened" && incItem?.canonical_detail_route === `/operations/issues?issue=${incRef.replace("support-incident://", "")}` && incItem?.owner_event_family === "owner_event", JSON.stringify(incItem).slice(0, 160));
  const hcItem = items.find((i) => i.owner_ref === hcRef);
  ok("the health check that could not run projects `health_check.errored` (an Operations owner event) with one link back to the check on Operations / Health",
    hcItem?.event_kind === "health_check.errored" && hcItem?.canonical_detail_route === `/operations/health?check=${hcTail}` && hcItem?.owner_event_family === "owner_event"
      && hcItem?.owner_revision === hcEval.j.health_check_result?.result_id, JSON.stringify(hcItem).slice(0, 160));
  ok("every item is a registered projection with no read or delivery state",
    items.length >= 3 && items.every((i) => i.schema_version === "ioi.hypervisor.notification-projection.v1" && i.read_model_only === true && !("read" in i) && !("delivered" in i)));

  // 4. The envelope is honest.
  const env = inbox.j;
  ok("the envelope names its cap, types the two absent families, names email as absent, and stores nothing",
    env.schema_version === "ioi.hypervisor.notification-inbox.v1" && env.counts?.total >= 3 && env.counts?.shown === items.length && env.limit === 25
      && (env.typed_absences || []).map((a) => a.family).sort().join(",") === "lease,operation" && env.delivery?.email === null && env.stores_nothing === true && env.policy_filtered_before_counts === true);

  // 3. Transitions, re-derived.
  await fetch(`${D}/v1/hypervisor/governance/approval-requests/${encodeURIComponent(apprTail)}`, { method: "PATCH", headers: { ...H, "content-type": "application/json" }, body: JSON.stringify({ transition: "approve" }) });
  const decided = (await get("/v1/hypervisor/notifications")).j.items || [];
  const d1 = decided.filter((i) => i.owner_ref === apprRef);
  ok("deciding the approval RE-DERIVES its item: one item, now `approval.approved`, the request event gone (nothing updated in place)",
    d1.length === 1 && d1[0].event_kind === "approval.approved", JSON.stringify(d1).slice(0, 160));

  // 5. Refusals are typed.
  const fam = await get("/v1/hypervisor/notifications?family=approval");
  const badFam = await get("/v1/hypervisor/notifications?family=timer");
  const badLim = await get("/v1/hypervisor/notifications?limit=0");
  ok("a family filter narrows to that family; an unknown family and an out-of-range limit are typed refusals",
    (fam.j.items || []).length >= 1 && (fam.j.items || []).every((i) => i.owner_event_family === "approval")
      && badFam.status === 400 && badFam.j.error?.code === "notification_family_unknown" && badLim.status === 400 && badLim.j.error?.code === "hypervisor.page_size_out_of_bounds");

  // 6. Nothing is stored.
  ok("NOTHING IS STORED — the inbox read wrote no file", before === after, `${before} -> ${after}`);
  const keep = JSON.stringify(decided.map((i) => [i.notification_projection_id, i.event_kind]).sort());
  daemon.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 1500));
  run = await start(port);
  daemon = run.child;
  const again = (await get("/v1/hypervisor/notifications")).j.items || [];
  ok("after a restart the same items come back — re-derived from the owners' records, never from a store",
    JSON.stringify(again.map((i) => [i.notification_projection_id, i.event_kind]).sort()) === keep && !fs.existsSync(path.join(dataDir, "notifications")), `${again.length} items`);

  exitCode = results.every((r) => r.pass) ? 0 : 1;
} catch (e) {
  console.error(`BLOCKED: ${e.message}`);
  exitCode = results.length ? 1 : 2;
} finally {
  daemon?.kill();
  try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* best effort */ }
}
const passed = results.filter((r) => r.pass).length;
for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.pass || !r.detail ? "" : `  (${r.detail})`}`);
console.log(`${passed}/${results.length} passed`);
emitVerifierCensus({ verifierId: "notification-inbox", sourceUrl: import.meta.url, results });
process.exit(exitCode);
