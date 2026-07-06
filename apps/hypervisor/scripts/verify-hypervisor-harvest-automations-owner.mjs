#!/usr/bin/env node
// Automations owner-surface verifier — the THIRD harvest shape: owner-surface daemon authority.
//
// When a captured seed makes no single reboundable data lane (a canvas/wizard grammar), the daemon
// truth lives on the IOI-OWNED surface and the seed stays a linked, SECONDARY reference. This
// verifies that contract for Automations (canon: Automations owns durable orchestration):
//   - the /__ioi/automations surface renders the estate's REAL daemon automations (count + names
//     match an independent daemon read — no fabrication);
//   - the object-monitoring capture seed is present but visibly SECONDARY (a linked reference/
//     walkthrough, never a rebound surface);
//   - NO captured walkthrough row is presented as a daemon automation (the seed's example content
//     never leaks into the owner surface as truth);
//   - trigger/steps render from daemon truth; the surface is brand-clean.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-automations-owner.mjs
// Exit 2 = BLOCKED (daemon not running).

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const DAEMON = (process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

async function run() {
  const dmUp = await fetch(`${DAEMON}/v1/hypervisor/automations`).then((r) => r.ok).catch(() => false);
  if (!dmUp) { console.error("BLOCKED: daemon not reachable at " + DAEMON); process.exit(2); }

  // Independent daemon read — the truth the surface must equal.
  const auto = await fetch(`${DAEMON}/v1/hypervisor/automations`).then((r) => r.json());
  const automations = auto.automations || [];
  ok("daemon exposes durable automations", automations.length >= 1, `${automations.length} automations`);
  const names = automations.map((a) => a.name || a.automation_id).filter(Boolean);
  const ids = automations.map((a) => a.automation_id);

  const page = await fetch(`${SERVE}/__ioi/automations`).then(async (r) => ({ status: r.status, text: await r.text() }));
  ok("Automations owner surface serves, brand-clean", page.status === 200 && !/\bPalantir\b/.test(page.text));

  // 1. Owner section renders the REAL daemon automations (count + names + ids).
  ok("surface states the real daemon automation count", new RegExp(`<b>${automations.length}</b> record`).test(page.text), String(automations.length));
  const renderedNames = names.filter((n) => page.text.includes(esc(n)));
  ok("every daemon automation name renders on the surface (no omission)", renderedNames.length === names.length, `${renderedNames.length}/${names.length}`);
  const renderedIds = ids.filter((id) => page.text.includes(id));
  ok("daemon automation ids render (traceable to real records, not fabricated)", renderedIds.length === ids.length, `${renderedIds.length}/${ids.length}`);
  const cardCount = (page.text.match(/class="card automation-card"/g) || []).length;
  ok("card count equals the daemon automation count (no phantom rows)", cardCount === automations.length, `${cardCount} cards vs ${automations.length}`);

  // 2. The capture seed is present but SECONDARY (linked reference, not a rebound surface).
  ok("monitor-wizard capture is linked", page.text.includes("/__apps/monitors"));
  ok("capture seed framed as a SECONDARY reference (not daemon truth)", /reference|walkthrough|secondary/i.test(page.text) && /not a rebound surface|never (shown|fabricates)|never a rebound/i.test(page.text));

  // 3. NO captured walkthrough content is presented as a daemon automation. The object-monitoring /
  //    aip-assist captures render "… Walkthrough" rows; none may appear on the owner surface.
  ok("no captured walkthrough row is presented as a daemon automation", !/Walkthrough<\/|AIP Chatbot with transcribed/i.test(page.text));
  ok("no aip-assist walkthrough creator leaks onto the surface", !page.text.includes("aip-assist"));

  // 4. Trigger/steps render from daemon truth (the card meta reflects the real spec).
  const a0 = automations[0];
  const trig0 = (a0.trigger && (a0.trigger.kind || a0.trigger.trigger_kind)) || a0.trigger_kind || "manual";
  ok("card renders the daemon trigger kind", page.text.includes(`>${esc(trig0)}<`), trig0);
  ok("card renders daemon step counts", /\d+ step/.test(page.text));
}

run().then(() => {
  let fail = 0;
  for (const r of results) { console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`); if (!r.pass) fail++; }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`harvest automations-owner readiness: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
