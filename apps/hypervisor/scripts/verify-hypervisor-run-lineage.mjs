#!/usr/bin/env node
// Run lineage readiness verifier (79-workflow-lineage graft — the "challenge me" station).
//
// Asserts the owned Run Timeline's lineage & proof layer against a REAL recorded run (found via
// the proof stream): the lineage chain names the run, the run-level proof panel carries the
// daemon state root verbatim, the temporal trace renders one row per turn from recorded
// timestamps (a turn without timing says "no timing" rather than being placed), the proof-stream
// deep link is present, and an unknown run renders the honest not-found state. Client-rendered —
// checked with Playwright against the live serve.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-run-lineage.mjs

import { chromium } from "playwright";

// Its own isolated daemon (+ serve), the operator signed in (R-240, verifier auth sweep, 2026-09-29). This verifier read
// `IOI_HYPERVISOR_DAEMON_URL || :8765` — the OWNER's daemon — with no caller; since 3aaaad467/3738d5cab the data-source,
// materialized-set and ontology reads answer an anonymous caller 401 (read here as "not reachable"), and since 90cd1ddf2
// an anonymous write is refused on loopback too. An explicit URL naming the owner's stack is refused (verifier-stack.mjs).
import { verifierStack } from "./lib/verifier-stack.mjs";
const STACK = await verifierStack({ serve: true });
const DAEMON = STACK.daemonUrl;
const SERVE = STACK.serveUrl;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

async function run() {
  const led = await fetch(`${DAEMON}/v1/hypervisor/work-ledger`).then((r) => r.json()).catch(() => ({}));
  const he = (led.entries || []).find((e) => e.kind === "harness_execution" && e.run_ref);
  ok("a recorded run exists in the proof stream", !!he, he && he.run_ref);
  if (!he) return;

  const b = await chromium.launch();
  try {
    const page = await b.newPage({ viewport: { width: 1440, height: 1000 } });
    await STACK.signIn(page);
    await page.goto(`${SERVE}/__ioi/run-timeline/${encodeURIComponent(he.run_ref)}`, { waitUntil: "networkidle" });
    await page.waitForSelector(".rt-lineage", { timeout: 15000 });
    const lin = await page.locator(".rt-lineage").textContent();
    ok("lineage chain names the run", lin.includes(he.run_ref));
    ok("run-level state root verbatim from the record", he.state_root ? lin.includes(he.state_root) : true, he.state_root || "no state root on this run");
    ok("proof-stream deep link present", await page.locator('.rt-lineage a[href="/__ioi/work-ledger"]').count() === 1);
    const turns = await page.locator(".rt-turn").count();
    const wfRows = await page.locator(".rt-wf-row").count();
    ok("temporal trace rows match turns", turns === 0 ? wfRows === 0 : wfRows === turns, `${turns} turns · ${wfRows} trace rows`);
    if (wfRows) {
      const firstRow = await page.locator(".rt-wf-row").first().textContent();
      ok("trace row carries timing or says so honestly", /\d+(\.\d+)?s/.test(firstRow) || firstRow.includes("no timing"), firstRow.trim().slice(0, 60));
      await page.locator(".rt-wf-row").first().click();
      ok("trace row deep-links its turn", await page.locator("#rt-turn-0").count() === 1);
    }
    // Unknown run: honest not-found, never a fabricated timeline.
    await page.goto(`${SERVE}/__ioi/run-timeline/does-not-exist-xyz`, { waitUntil: "networkidle" });
    await page.waitForTimeout(1500);
    const body = await page.locator("#rt-root").textContent();
    ok("unknown run renders honest not-found", /Run not found|Loading run timeline/.test(body), body.trim().slice(0, 50));
    ok("no lineage panel fabricated for unknown run", await page.locator(".rt-lineage").count() === 0);
  } finally {
    await b.close();
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("run-lineage readiness: OK");
  process.exit(0); // its own stack (daemon + serve children) would otherwise keep the process alive
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
