#!/usr/bin/env node
// PARITY verifier — Domain Apps · Logic + Contour (DOM-1, remediation v2): origin-aligned I-4
// landings over TYPED-ABSENT bodies (no no-code-function / analysis-workbook planes exist).
// The done-bar here is HONESTY: grammar renders, absences are named in both vocabularies, no rows
// are fabricated, evidence is cited on-surface.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "..");
const SERVE = process.env.IOI_SERVE_URL || "http://127.0.0.1:4173";
const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });
const page = (url) => fetch(url).then(async (r) => ({ status: r.status, text: await r.text() })).catch(() => ({ status: 0, text: "" }));

const matrix = JSON.parse(readFileSync(path.join(appRoot, "harvest-app-parity-matrix.json"), "utf8"));
const bySlug = Object.fromEntries((matrix.seeds || []).map((s) => [s.slug, s]));
for (const [slug, route, title, absentPhrase] of [
  ["logic", "/__ioi/domain-apps/logic", "Logic", "no no-code-function plane"],
  ["contour", "/__ioi/domain-apps/contour", "Contour", "EVA-2"],
]) {
  ok(`matrix: ${slug} is reference_ported at ${route}, origin-aligned`, bySlug[slug]?.parity_class === "reference_ported" && bySlug[slug]?.candidate_surface === route && /localhost:9225/.test(bySlug[slug]?.reference_url_override || ""), bySlug[slug]?.parity_class);
  const p = await page(`${SERVE}${route}`);
  const t = p.text;
  ok(`${slug}: renders 200 with the I-4 grammar (rail + ${title} + Recents/Favorites)`, p.status === 200 && t.includes("og-grail") && t.includes(title) && t.includes("Recents") && t.includes("Favorites"), String(p.status));
  ok(`${slug}: the BODY is a NAMED typed absence — zero fabricated rows`, (t.match(/class="spl-row"/g) || []).length === 0 && /NOT an empty plane but a missing one/.test(t) && new RegExp(absentPhrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(t));
  ok(`${slug}: every gap carries the UNIFIED contract (aria === data-ioi count)`, (t.match(/aria-disabled="true"/g) || []).length >= 4 && (t.match(/aria-disabled="true"/g) || []).length === (t.match(/data-ioi-disabled-reason=/g) || []).length);
  ok(`${slug}: READ-ONLY + evidence cited (adjudication + atlas) + owner link`, !t.includes("<form") && new RegExp(`reference-seed-adjudications\\.v1\\.json#${slug}`).test(t) && /reference-family-atlas\.v1\.json/.test(t) && t.includes("/__ioi/domain-apps"));
  ok(`${slug}: brand-clean (no Palantir; the rail's AIP-Assist chrome is estate-standard)`, !/\bPalantir\b/.test(t));
}
const fails = results.filter((r) => !r.pass);
for (const r of results) console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
console.log(`\n${results.length - fails.length}/${results.length} passed`);
console.log(`app-parity-domain-landings readiness: ${fails.length ? "FAIL" : "OK"}`);
process.exit(fails.length ? 1 : 0);
