#!/usr/bin/env node
// PARITY verifier — Studio · Workshop (STU-1/STU-2, remediation v2): the D6 COMBINED-SEED port.
// The workshop capture is byte-dead; module's capture boots as "Workshop — Home" and is the
// recorded donor. The port is an I-4 splash-grammar instance over the REAL domain-app + ODK
// surface-descriptor planes — read-first, honest-empty, unified gap contract, atlas-backed.
// Usage: node apps/hypervisor/scripts/verify-hypervisor-app-parity-workshop.mjs   (exit 2 = BLOCKED)
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
// Its own isolated daemon (+ serve), the operator signed in (R-240, verifier auth sweep, 2026-09-29). This verifier read
// `IOI_HYPERVISOR_DAEMON_URL || :8765` — the OWNER's daemon — with no caller; since 3aaaad467/3738d5cab the data-source,
// materialized-set and ontology reads answer an anonymous caller 401 (read here as "not reachable"), and since 90cd1ddf2
// an anonymous write is refused on loopback too. An explicit URL naming the owner's stack is refused (verifier-stack.mjs).
import { verifierStack } from "./lib/verifier-stack.mjs";
const STACK = await verifierStack({ serve: true });
const SERVE = STACK.serveUrl;
const DAEMON = STACK.daemonUrl;
const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

const probe = await STACK.requireRead("/v1/hypervisor/domain-apps", "the domain-app plane");
const da = probe.domain_apps || [];
const sd = await fetch(`${DAEMON}/v1/hypervisor/odk/surface-descriptors`).then((r) => r.json()).then((j) => j.surface_descriptors || []).catch(() => []);

// 1. Matrix truth (generated, current).
const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
ok("matrix: module is reference_ported at /__ioi/studio/workshop (the D6 combined-seed port), origin-aligned to the splash lane", bySlug.module?.parity_class === "reference_ported" && bySlug.module?.candidate_surface === "/__ioi/studio/workshop" && bySlug.module?.reference_url_override === "http://localhost:9225/workspace/module/splash", bySlug.module?.parity_class);
ok("matrix: workshop is donor_ported via module with its adjudication cited", bySlug.workshop?.remediation_state === "donor_ported" && bySlug.workshop?.donor_capture === "module" && /reference-seed-adjudications/.test(bySlug.workshop?.adjudication_ref || ""));

// 2. The port page — I-4 grammar + truth.
const p = await page(`${SERVE}/__ioi/studio/workshop`);
const t = p.text;
ok("port renders 200 with the I-4 grammar, RAILLESS (owner ruling 2026-08-20)", p.status === 200 && !t.includes("og-grail") && t.includes("Workshop") && t.includes("Recents") && t.includes("Favorites"), String(p.status));
ok("row count equals the REAL planes (domain-apps + surface-descriptors; honest empty when zero)", (t.match(/class="spl-row"/g) || []).length === da.length + sd.length && (da.length + sd.length > 0 || /never fabricates rows/.test(t)), `rows=${(t.match(/class="spl-row"/g) || []).length} plane=${da.length + sd.length}`);
ok("every gap control carries the UNIFIED contract (aria-disabled count === data-ioi count)", (t.match(/aria-disabled="true"/g) || []).length >= 4 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length, `${(t.match(/aria-disabled="true"/g) || []).length} gaps`);
// 2026-09-29 (R-240, verifier auth sweep — first run since the anonymous 401 BLOCKED it): 1bb4ef99e rewrote the reason to say
// what is missing (a descriptor binds a PUBLISHED ontology revision, which this product cannot publish yet); the claim is
// unchanged — New module is disabled in place and names why.
ok("New module is a NAMED gap (authoring = ODK authority cut), never silent", /aria-disabled="true"[^>]*data-ioi-disabled-reason="A module is composed from a surface descriptor[^"]*no module can be composed here/.test(t.replace(/\n/g, " ")) || (t.includes("New module") && /data-ioi-disabled-reason="A module is composed from a surface descriptor[^"]*no module can be composed here/.test(t)));
ok("the lane is READ-ONLY (no forms)", !t.includes("<form"));
ok("the D6 donor story + evidence are cited ON the surface (adjudication + atlas + dead-lane truth)", /reference-seed-adjudications\.v1\.json#workshop/.test(t) && /reference-family-atlas\.v1\.json/.test(t) && /307\/octet-stream/.test(t));
ok("truth links land on the owner planes (domain-apps · ODK · Agent Studio)", t.includes("/__ioi/domain-apps") && t.includes("/__ioi/odk") && t.includes("/__ioi/agent-studio"));
ok("IOI surface brand-clean (no Palantir)", !/\bPalantir\b/.test(t));

const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
console.log(`\n${results.length - fails.length}/${results.length} passed`);
console.log(`app-parity-workshop readiness: ${fails.length ? "FAIL" : "OK"}`);
process.exit(fails.length ? 1 : 0);
