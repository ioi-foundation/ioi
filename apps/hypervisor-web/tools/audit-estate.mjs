// Estate parity + banned-phrase audit for hypervisor.com. Runs in prebuild;
// fails the build on any violation. Mirrors the enforcement model of
// ioi-ai/tools/audit-seo.mjs (single-owner strings + machine checks).
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const failures = [];

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const s = statSync(p);
    if (s.isDirectory()) walk(p, out);
    else if (/\.(jsx?|html)$/.test(name)) out.push(p);
  }
  return out;
}

const files = [...walk(join(ROOT, "src")), join(ROOT, "index.html")];
const read = (p) => readFileSync(p, "utf8");

/* 1 — banned phrases: unbacked claims, retired domains, retired taxonomy. */
const BANNED = [
  "SOC 2",
  "GDPR",
  "Fortune 500",
  "Proven in production",
  "hypervisor.io",
  "1.2M",
  "Production telemetry",
  "Request for Agent",
];
for (const f of files) {
  const text = read(f);
  for (const b of BANNED) {
    if (f.endsWith("audit-estate.mjs")) continue;
    if (text.includes(b)) failures.push(`${f}: banned phrase "${b}"`);
  }
}

/* 2 — required literals: honest status + cross-property links present. */
const REQUIRED = [
  ["src/site/HomeSections.jsx", "Local private preview"],
  ["src/site/Chrome.jsx", "internetofintelligence.com"],
  ["src/site/HomeSections.jsx", "wallet.network"],
  ["src/site/HomeSections.jsx", "Agentgres"],
];
for (const [rel, needle] of REQUIRED) {
  if (!read(join(ROOT, rel)).includes(needle)) {
    failures.push(`${rel}: missing required literal "${needle}"`);
  }
}

/* 3 — status manifest integrity + ProductData resolution. */
const status = (await import(join(ROOT, "src/config/estateStatus.js"))).default;
for (const [surface, stage] of Object.entries(status.surfaces)) {
  if (!status.labels[stage]) {
    failures.push(`estateStatus.js: surface "${surface}" uses undefined stage "${stage}"`);
  }
}
const productData = read(join(ROOT, "src/site/ProductData.jsx"));
for (const m of productData.matchAll(/_st\("([^"]+)"\)/g)) {
  if (!status.surfaces[m[1]]) {
    failures.push(`ProductData.jsx: _st("${m[1]}") has no entry in estateStatus.js`);
  }
}

/* 4 — doctrine pipeline parity between spine and rendered Home copy. */
const spine = (await import(join(ROOT, "src/config/estateMessaging.js"))).default;
const home = read(join(ROOT, "src/site/HomeSections.jsx"));
for (const [k, v] of spine.DOCTRINE_PIPELINE) {
  if (!home.includes(`["${k}", "${v}"]`)) {
    failures.push(`HomeSections.jsx: doctrine chip ["${k}", "${v}"] drifted from estateMessaging.DOCTRINE_PIPELINE`);
  }
}

if (failures.length) {
  console.error(`estate audit: ${failures.length} violation(s)`);
  for (const f of failures) console.error(`  ✕ ${f}`);
  process.exit(1);
}
console.log("estate audit: clean");
