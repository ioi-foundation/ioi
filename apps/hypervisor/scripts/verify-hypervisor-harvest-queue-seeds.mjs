#!/usr/bin/env node
// Harvest-port QUEUE-seeds readiness verifier — the remaining porting-queue surfaces adopted on
// their WORKING artifact seeds (suite-guide §9). Ten seeds boot under the estate to their real
// UI and are linked from their owning suite surface; three are NAMED GAPS (serve but do not
// mount/render on the auth-dead mirror — they light up via live re-harvest once auth is
// refreshed, or an asset-level origin fold). Editor enrichments for the gap surfaces follow the
// live-re-harvest route (suite-guide §2a), not native authoring.
//
//   Ontology     : schema (ontology manager) · explorer (object explorer)
//   Data         : ingest (hyperauto) · sources (data-connection)
//   Evaluations  : evalsuites (AIP Evals) · analysis (insight)
//   Missions     : jobs (job-tracker) · incidents (issues)
//   Marketplace  : listings (marketplace)     [registry/artifacts = gap: React-crash on 404]
//   Foundry      : models (model-catalog)
//   Developer Console: [devconsole + widgets = gap: origin baked in a JS chunk → no mount]
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-harvest-queue-seeds.mjs
// Exit 2 = BLOCKED (harvest mirror not running).

import { chromium } from "playwright";

const SERVE = (process.env.IOI_HYPERVISOR_SERVE_URL || "http://127.0.0.1:4173").replace(/\/$/, "");
const MIRROR = (process.env.IOI_HARVEST_MIRROR_URL || "http://127.0.0.1:9225").replace(/\/$/, "");

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };

// Ten seeds that boot to real UI, each linked from its owning suite surface.
const CLEAN = [
  { slug: "schema", ownerUrl: "/__ioi/odk", owner: "Ontology", title: /Ontology/i },
  { slug: "explorer", ownerUrl: "/__ioi/odk", owner: "Ontology", title: /Explorer/i },
  { slug: "ingest", ownerUrl: "/__ioi/odk", owner: "Data", title: null },
  { slug: "sources", ownerUrl: "/__ioi/odk", owner: "Data", title: /Data Connection/i },
  { slug: "evalsuites", ownerUrl: "/__ioi/feedback", owner: "Evaluations", title: /Eval/i },
  { slug: "analysis", ownerUrl: "/__ioi/feedback", owner: "Evaluations", title: /Insight/i },
  { slug: "jobs", ownerUrl: "/__ioi/sessions", owner: "Missions", title: /Build/i },
  { slug: "incidents", ownerUrl: "/__ioi/sessions", owner: "Missions", title: /Issue/i },
  { slug: "listings", ownerUrl: "/__ioi/marketplace", owner: "Marketplace", title: /Marketplace/i },
  { slug: "models", ownerUrl: "/__ioi/foundry", owner: "Foundry", title: /Model Catalog/i },
];
// Three registered seeds that serve but do not render on the auth-dead mirror — NAMED GAPS.
const GAPS = ["registry", "devconsole", "widgets"];

const CRASH = /Failed to initialize|An error occurred|Something went wrong/i;

async function run() {
  const mirrorUp = await fetch(`${MIRROR}/workspace/ontology/`).then((r) => r.ok).catch(() => false);
  if (!mirrorUp) { console.error("BLOCKED: harvest mirror not reachable at " + MIRROR); process.exit(2); }
  ok("harvest mirror live", true, MIRROR);

  const b = await chromium.launch();
  try {
    for (const seed of CLEAN) {
      const doc = await fetch(`${SERVE}/__apps/${seed.slug}`).then(async (r) => ({ status: r.status, ct: r.headers.get("content-type") || "", text: await r.text() }));
      ok(`[${seed.slug}] serves under the estate`, doc.status === 200 && doc.ct.includes("text/html"));
      ok(`[${seed.slug}] brand-cased strings rebranded at the wire`, !doc.text.includes("Palantir"));

      const page = await b.newPage({ viewport: { width: 1600, height: 1000 } });
      await page.goto(`${SERVE}/__apps/${seed.slug}`, { waitUntil: "domcontentloaded", timeout: 40000 }).catch(() => {});
      await page.waitForTimeout(7000);
      const st = await page.evaluate(() => ({
        c: document.querySelectorAll("button, [role=button]").length,
        t: (document.body.innerText || "").replace(/\s+/g, " ").trim(),
      }));
      await page.close();
      const booted = st.c > 5 && st.t.length > 30 && !CRASH.test(st.t.slice(0, 400)) && (!seed.title || seed.title.test(st.t));
      ok(`[${seed.slug}] boots to its real UI (${seed.owner})`, booted, `${st.c} controls`);

      const owner = await fetch(`${SERVE}${seed.ownerUrl}`).then((r) => r.text());
      ok(`[${seed.slug}] ${seed.owner} surface links the seed`, owner.includes(`href="/__apps/${seed.slug}"`));
    }

    // Named gaps: they SERVE (registered seeds), documented as blocked on re-harvest / asset fold.
    for (const slug of GAPS) {
      const r = await fetch(`${SERVE}/__apps/${slug}`).then((x) => x.status).catch(() => 0);
      ok(`[${slug}] registered seed serves (NAMED GAP — awaits live re-harvest / asset fold)`, r === 200);
    }
  } finally {
    await b.close();
  }

  ok("unknown seed is honest", (await fetch(`${SERVE}/__apps/nonesuch`).then((r) => r.status)) === 404);
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("harvest queue-seeds readiness: OK");
}).catch((e) => { console.error("verifier crashed:", e); process.exit(1); });
