#!/usr/bin/env node
// check:machinery-surface-owner — M08.5. OQ-2 was ruled on 2026-09-11 (R-29): AUTOMATIONS owns the
// machinery surface (process/state-machine graphs are automation machinery). This check binds that
// one owner across the five enforcement sites that held the line while the question was open, and
// fails if any site names another owner or the open-question exception returns:
//   1. apps/hypervisor/scripts/surface-registry.mjs — the machinery entry's owner;
//   2. apps/hypervisor/seed-ux-provenance.v1.json — the machinery source's canonical_owner, with NO
//      owner_mapping_note (the typed exception the provenance validator accepted only while OQ-2 stood);
//   3. apps/hypervisor/scripts/verify-hypervisor-studio-journey.mjs — the "no machinery content on
//      /studio" assertion references the ruling, not an open question;
//   4. apps/hypervisor/scripts/v2-route-shell.mjs — the /studio shell's machinery note names Automations;
//   5. docs/architecture/components/hypervisor/core-clients-surfaces.md — the local-ownership block
//      lists process/state-machine graphs (Machinery) under Automations.
// Exit 0 pass · 1 fail.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OWNER = "Automations";
const results = [];
const ok = (name, cond, detail = "") => { results.push({ name, pass: !!cond }); console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), "utf8");

const registry = read("apps/hypervisor/scripts/surface-registry.mjs");
const entry = registry.match(/\{\s*slug:\s*"machinery"[^}]*\}/u)?.[0] || "";
const registryOwner = entry.match(/owner:\s*"([^"]+)"/u)?.[1] || "";
ok("1. surface-registry.mjs: the machinery entry's owner is Automations", registryOwner === OWNER, `owner "${registryOwner}"`);

const provenance = JSON.parse(read("apps/hypervisor/seed-ux-provenance.v1.json"));
const sources = [];
(function walk(v) { if (Array.isArray(v)) v.forEach(walk); else if (v && typeof v === "object") { if (v.slug === "machinery" && v.starting_route === "/__ioi/studio/machinery") sources.push(v); Object.values(v).forEach(walk); } })(provenance);
ok("2. seed-ux-provenance.v1.json: the machinery source's canonical_owner is Automations and the OQ-2 owner_mapping_note is gone", sources.length === 1 && sources[0].canonical_owner === OWNER && !("owner_mapping_note" in sources[0]), `${sources.length} source(s) · owner "${sources[0]?.canonical_owner || ""}" · note ${"owner_mapping_note" in (sources[0] || {}) ? "present" : "absent"}`);

const studio = read("apps/hypervisor/scripts/verify-hypervisor-studio-journey.mjs");
ok("3. verify-hypervisor-studio-journey.mjs: the no-machinery-on-/studio assertion references the ruling (R-29), not an open question", /NO machinery content on \/studio \(machinery is Automations-owned — OQ-2 ruled R-29\)/u.test(studio) && !/OQ-2 held\)/u.test(studio));

const shell = read("apps/hypervisor/scripts/v2-route-shell.mjs");
const note = shell.match(/href:\s*"\/__ioi\/studio\/machinery"[^}]*note:\s*"([^"]+)"/u)?.[1] || "";
ok("4. v2-route-shell.mjs: the /studio shell's machinery note names Automations and the ruling", /Automations-owned/u.test(note) && /R-29/u.test(note), note.slice(0, 90));

const canon = read("docs/architecture/components/hypervisor/core-clients-surfaces.md");
const block = canon.slice(canon.indexOf("Local ownership stays explicit"));
const automations = block.match(/\nAutomations\n([\s\S]*?)\n\n/u)?.[1] || "";
ok("5. core-clients-surfaces.md: the Automations ownership entry lists process/state-machine graphs (the Machinery surface) with the ruling", /state-machine graphs/u.test(automations) && /Machinery/u.test(automations) && /R-29/u.test(automations));

const manifestPath = path.join(ROOT, "internal-docs/implementation/program/manifest.v1.json");
if (fs.existsSync(manifestPath)) {
  const oq = (JSON.parse(fs.readFileSync(manifestPath, "utf8")).open_questions || []).find((q) => q.id === "OQ-2");
  ok("private register (present on this host): OQ-2 reads resolved with the same owner", !oq || (oq.status === "resolved" && /Automations owns/u.test(String(oq.ruling || ""))), oq ? oq.status : "no OQ-2 row");
}

const failed = results.filter((r) => !r.pass).length;
console.log(`${failed ? "FAIL" : "PASS"} check:machinery-surface-owner — ${results.length - failed}/${results.length} · owner ${OWNER} (OQ-2 ruled R-29, 2026-09-11)`);
process.exit(failed ? 1 : 0);
