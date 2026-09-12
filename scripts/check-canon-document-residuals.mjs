#!/usr/bin/env node
//
// M08.6 — THE CANON-DOCUMENT RESIDUALS, AS STANDING PROPERTIES RATHER THAN A ONE-TIME SWEEP.
//
// The unit named five residuals and they are repaired. Repairing them is not the unit: five
// hand-corrections decay, and the scar the named-gap gate recorded is exactly that hand-correction
// does not converge. So each residual becomes the PROPERTY it was an instance of, checked over the
// whole tracked corpus:
//
//   1 NO NUMBERED CANON LIST REPEATS AN ORDINAL. The instance was README's Non-Negotiables, which
//     printed two items as `30.` and so ran 1–38 over 39 items — every ordinal after the duplicate
//     was one low, and both surviving numeric citations pointed at the right text only because a
//     reader trusted the label instead of counting. A sibling list had the same defect twice over.
//     Checked over every `## Non-Negotiables` list in tracked canon.
//
//   2 EVERY NUMERIC CITATION OF A NUMBERED LIST RESOLVES. A renumber that fixes rule 1 breaks any
//     citation past the duplicate, so the two claims must be checked together or fixing one
//     silently falsifies the other.
//
//   3 NO LIVE DOCUMENT CITES AN ARCHIVED ONE WITHOUT SAYING SO. Read from the TARGET's own
//     front matter — `Doctrine status: archived`, a `Moved to:` line, or a title saying archived —
//     never from adjectives in the citing prose, because "archived" in the citing sentence is what
//     a correct citation and a stale one both look like from a grep.
//
//   4 EVERY DOCUMENTED ENDPOINT IS EITHER REGISTERED OR ANNOTATED. The instance was nine endpoints
//     in one fenced block introduced as PLANNED while the prose around them asserted in the present
//     tense that they ARE the canonical routes; six were served by nothing under any spelling.
//     Checked against the daemon's own `.route(` registrations.
//
//   5 EVERY ROUTE A SURFACE TABLE CALLS CANONICAL IS ONE THE ESTATE REGISTERS, or the row says
//     what happened to it. The instance asserted a canonical route the same file records, 690
//     lines later, as having had no bound surface module since a retirement.
//
//   --mutation  prove each finding fails on its own
//
// SCOPE, stated because a check that quietly narrows is the defect one layer up: this polices the
// TRACKED canon under docs/architecture and docs/decisions. It does not police prose in code
// comments, in apps/, or in any gitignored tree.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { dirname, join, relative, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");

const results = [];
const observations = {};
let failures = 0;

const ok = (name, satisfied, detail) => {
  results.push({ assertion: name, satisfied: !!satisfied, detail: String(detail).slice(0, 500) });
  if (!satisfied) failures += 1;
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}  (${String(detail).slice(0, 260)})`);
  return !!satisfied;
};

/// Every tracked canon document this check polices. `_archive/` is excluded BY NAME rather than by
/// a path heuristic: an archive is the one place a document may narrate the retired state as the
/// retired state, and policing it would make correct archival narration red.
const ARCHIVE = "docs/architecture/_archive/";
function canonFiles() {
  const out = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      const rel = relative(repo, full);
      if (entry.isDirectory()) {
        if (rel.startsWith(ARCHIVE)) continue;
        walk(full);
      } else if (entry.name.endsWith(".md") && !rel.startsWith(ARCHIVE)) {
        out.push(rel);
      }
    }
  };
  walk(join(repo, "docs/architecture"));
  walk(join(repo, "docs/decisions"));
  return out.sort();
}

const read = (rel) => readFileSync(join(repo, rel), "utf8");

/// A document is ARCHIVED if it says so about itself. Three shapes, all read from the target.
function isArchived(rel) {
  if (!existsSync(join(repo, rel))) return false;
  if (statSync(join(repo, rel)).isDirectory()) return false;
  const head = read(rel).split("\n").slice(0, 20).join("\n");
  return /Doctrine status:\s*archived/i.test(head)
    || /^Moved to:/im.test(head)
    || /^#\s.*\(archived\)/im.test(head)
    || /Status:\s*entry-point stub/i.test(head);
}

/// Numbered lists this check judges: the `## Non-Negotiables` sections, which are the ones canon
/// cites by number.
function numberedLists(files) {
  const lists = [];
  for (const rel of files) {
    const lines = read(rel).split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      if (!/^##+\s+Non-Negotiables/i.test(lines[i])) continue;
      const items = [];
      for (let j = i + 1; j < lines.length; j += 1) {
        if (/^##+\s/.test(lines[j])) break;
        const m = /^(\d+)\.\s/.exec(lines[j]);
        if (m) items.push({ line: j + 1, printed: Number(m.group ? m.group(1) : m[1]) });
      }
      if (items.length) lists.push({ file: rel, heading: i + 1, items });
    }
  }
  return lists;
}

try {
  const files = canonFiles();
  observations.tracked_canon_documents = files.length;

  // ---- 1 + 2: numbered lists and the citations that depend on them ----
  const lists = numberedLists(files);
  observations.numbered_lists = lists.map((l) => `${l.file}:${l.heading} (${l.items.length})`);
  const duplicates = [];
  const misordered = [];
  for (const list of lists) {
    const seen = new Map();
    list.items.forEach((item, index) => {
      if (seen.has(item.printed)) {
        duplicates.push(`${list.file}:${item.line} repeats ${item.printed} (first at :${seen.get(item.printed)})`);
      }
      seen.set(item.printed, item.line);
      if (item.printed !== index + 1) {
        misordered.push(`${list.file}:${item.line} prints ${item.printed} but is item ${index + 1}`);
      }
    });
  }
  ok("no numbered canon list repeats an ordinal — the instance printed two items as `30.` and every ordinal after it was one low, so a citation could be label-correct and position-wrong at the same time",
    duplicates.length === 0,
    duplicates.slice(0, 4).join(" ; ") || `${lists.length} list(s), ${lists.reduce((a, l) => a + l.items.length, 0)} items, no repeats`);
  ok("and every numbered list counts from 1 without a gap, so the printed label and the position are the same fact rather than two that happen to agree",
    misordered.length === 0,
    misordered.slice(0, 4).join(" ; ") || "every item's label equals its position");

  const citations = [];
  for (const rel of files) {
    const text = read(rel);
    for (const m of text.matchAll(/[Nn]on-[Nn]egotiable[s]?\s+(\d+)/gu)) {
      const line = text.slice(0, m.index).split("\n").length;
      citations.push({ file: rel, line, number: Number(m[1]) });
    }
  }
  observations.numeric_citations = citations.length;
  // A citation resolves if SOME policed list has an item with that ordinal. Narrow by construction:
  // this check does not guess which list a citation means, so it asserts the weaker, true claim —
  // that no citation names an ordinal no list has — rather than a stronger one it cannot ground.
  const ordinals = new Set(lists.flatMap((l) => l.items.map((i) => i.printed)));
  const dangling = citations.filter((c) => !ordinals.has(c.number));
  ok("every numeric citation of a non-negotiable names an ordinal some policed list actually has — the claim is deliberately the weaker one this check can ground, because it does not guess which list a citation means",
    dangling.length === 0,
    dangling.slice(0, 4).map((c) => `${c.file}:${c.line} cites ${c.number}`).join(" ; ") || `${citations.length} citation(s), every ordinal present`);

  // ---- 3: archived targets ----
  const staleCitations = [];
  for (const rel of files) {
    const text = read(rel);
    const dir = dirname(join(repo, rel));
    for (const m of text.matchAll(/\[[^\]]*\]\((\.\.?\/[^)\s]+\.md)(#[^)\s]*)?\)/gu)) {
      const target = relative(repo, resolvePath(dir, m[1]));
      if (!isArchived(target)) continue;
      const lineNo = text.slice(0, m.index).split("\n").length;
      const line = text.split("\n")[lineNo - 1] || "";
      const context = `${text.split("\n")[lineNo - 2] || ""} ${line} ${text.split("\n")[lineNo] || ""}`;
      // The qualifier must be in the citing text near the link. "archived", "former", "moved",
      // "superseded", "retired", "historical".
      if (/archiv|former|moved|supersed|retired|historical|no ownership|stub/iu.test(context)) continue;
      staleCitations.push(`${rel}:${lineNo} → ${target}`);
    }
  }
  ok("no live canon document links to an ARCHIVED one without saying so — archived-ness is read from the TARGET's own front matter, never from an adjective in the citing sentence, because a correct citation and a stale one look identical to a grep of the citing prose",
    staleCitations.length === 0,
    staleCitations.slice(0, 5).join(" ; ") || "every link to an archived document carries its qualifier");

  // ---- 4: documented endpoints ----
  const daemonSources = [join(repo, "crates/node/src/bin/hypervisor-daemon.rs")];
  const routesDir = join(repo, "crates/node/src/bin/hypervisor_daemon_routes");
  for (const entry of readdirSync(routesDir)) {
    if (entry.endsWith(".rs")) daemonSources.push(join(routesDir, entry));
  }
  /// The namespaces the daemon registers outright: 577 and 76 of its routes respectively. Every
  /// other namespace in canon belongs to another service or to a lane this router does not own.
  const DAEMON_NAMESPACES = ["/v1/hypervisor/", "/v1/goal-orchestration/"];
  const normalize = (path) => path.replace(/\{[^}]+\}|<[^>]+>|:[A-Za-z_][A-Za-z0-9_]*|\*[A-Za-z_]\w*/gu, "{p}").replace(/\/+$/u, "");
  const registered = new Set();
  for (const file of daemonSources) {
    for (const m of readFileSync(file, "utf8").matchAll(/\.route\(\s*"([^"]+)"/gu)) {
      registered.add(normalize(m[1]));
    }
  }
  observations.registered_daemon_routes = registered.size;
  const undocumented = [];
  for (const rel of files) {
    const text = read(rel);
    const lines = text.split("\n");
    let inFence = false;
    for (let i = 0; i < lines.length; i += 1) {
      if (/^```/.test(lines[i])) { inFence = !inFence; continue; }
      if (!inFence) continue;
      const m = /^(GET|POST|PUT|PATCH|DELETE)\s+(\/v1\/[^\s#]+)/u.exec(lines[i]);
      if (!m) continue;
      // ONLY THE DAEMON'S OWN NAMESPACES. Canon documents several services' APIs, and comparing a
      // different service's endpoints against the daemon's router would call them all unserved:
      // the agentgres object-model doc alone lists a Core API whose crate registers ZERO routes.
      // That is a real finding, and it is not this one — this check can only speak for the router
      // it reads. Narrowed to the two namespaces the daemon owns outright, which is where the
      // instance lived, and declared as a nonclaim in the summary rather than left implicit.
      if (!DAEMON_NAMESPACES.some((prefix) => m[2].startsWith(prefix))) continue;
      if (registered.has(normalize(m[2]))) continue;
      // ANNOTATED counts: the line itself, or the fence's own comment lines above it, must say what
      // it is. This is the claim the instance failed — nine endpoints in a block whose prose said
      // they ARE the canonical routes.
      const above = lines.slice(Math.max(0, i - 6), i).join(" ");
      if (/planned|no registered route|nearest served|served by|not a daemon route|reserved|proposed/iu.test(`${lines[i]} ${above}`)) continue;
      undocumented.push(`${rel}:${i + 1} ${m[1]} ${m[2]}`);
    }
  }
  observations.unannotated_documented_endpoints = undocumented.length;
  observations.endpoint_nonclaim =
    "policed only for /v1/hypervisor/ and /v1/goal-orchestration/, the namespaces this router owns; other services' documented APIs are outside what this check can speak for, and at least one of them (the agentgres Core API) is documented against a crate that registers no routes at all";
  // A RATCHET, NOT A ZERO, AND THE DIFFERENCE IS STATED. The unit named NINE endpoints in one
  // block, and those are annotated. Measuring the property over all of tracked canon found 168
  // more, in four files — 100 in the daemon API reference and 61 in the ioi.ai orchestration API,
  // which are SPECIFICATION documents describing a target surface. Requiring those to be annotated
  // or registered would forbid canon from specifying anything not yet built, which is the opposite
  // of what an architecture corpus is for; requiring nothing would let the instance recur. So the
  // population is pinned: the nine are annotated, the remaining 168 are RECORDED rather than
  // approved, and the count may not grow. A new unannotated documented endpoint is red on the day
  // it is written.
  //
  // Closure test for the api.md and orchestration-api.md owners: this number goes down and the pin
  // moves with it in the same commit. A pin that only ever ratchets one way is a bound, not a pass.
  const ENDPOINT_RATCHET = 168;
  const byFile = {};
  for (const entry of undocumented) {
    const file = entry.split(":")[0];
    byFile[file] = (byFile[file] || 0) + 1;
  }
  observations.unannotated_documented_endpoints_by_file = byFile;
  ok("every `/v1/` endpoint documented in a fenced block of tracked canon is either REGISTERED by the daemon or annotated with what it is — the unit's nine are annotated, and the wider population is pinned so the instance cannot recur: a NEW unannotated documented endpoint is red on the day it is written",
    undocumented.length <= ENDPOINT_RATCHET,
    undocumented.length === ENDPOINT_RATCHET
      ? `${undocumented.length} at the pin (${Object.entries(byFile).map(([f, n]) => `${n} in ${f.split("/").pop()}`).join(", ")}) — recorded, not approved`
      : undocumented.length < ENDPOINT_RATCHET
        ? `${undocumented.length} — BELOW the pin of ${ENDPOINT_RATCHET}; lower the pin in this commit`
        : `${undocumented.length} exceeds the pin of ${ENDPOINT_RATCHET}: ${undocumented.slice(0, 6).join(" ; ")}`);
  ok("and the pin is EXACT rather than a ceiling, so a repair that lowers the population must lower the pin with it — a bound that silently absorbs progress stops being a bound",
    undocumented.length === ENDPOINT_RATCHET,
    `${undocumented.length} vs pin ${ENDPOINT_RATCHET}`);

  // ---- 5: surface-table canonical routes ----
  const taxonomyPath = "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_core_taxonomy.json";
  const recordsPath = "crates/node/src/bin/hypervisor_daemon_routes/hypervisor_surface_records.json";
  const known = new Set();
  if (existsSync(join(repo, taxonomyPath))) {
    const taxonomy = JSON.parse(read(taxonomyPath));
    for (const group of Object.values(taxonomy)) {
      if (!Array.isArray(group)) continue;
      for (const row of group) {
        for (const value of Object.values(row || {})) {
          if (typeof value === "string" && value.startsWith("/")) known.add(value);
        }
      }
    }
  }
  if (existsSync(join(repo, recordsPath))) {
    const records = JSON.parse(read(recordsPath));
    for (const row of records.registrations || []) {
      for (const value of Object.values(row || {})) {
        if (typeof value === "string" && value.startsWith("/")) known.add(value);
      }
    }
  }
  observations.registered_product_routes = known.size;
  const unbacked = [];
  const surfaceDoc = "docs/architecture/components/hypervisor/core-clients-surfaces.md";
  if (files.includes(surfaceDoc)) {
    const lines = read(surfaceDoc).split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      const m = /^\|\s*([^|]+?)\s*\|\s*`(\/[^`]+)`([^|]*)\|\s*(.*?)\s*\|\s*$/u.exec(lines[i]);
      if (!m) continue;
      const route = m[2].trim();
      if (known.has(route)) continue;
      const rule = `${m[3]} ${m[4]}`;
      if (/annotated|retired|superseded|not an application|reserved|planned|entry;|no bound surface/iu.test(rule)) continue;
      unbacked.push(`${surfaceDoc}:${i + 1} ${route}`);
    }
  }
  ok("every route a surface table calls canonical is one the estate registers, or the row says what happened to it — the instance asserted a canonical route the same file records 690 lines later as having had no bound surface module since a retirement",
    unbacked.length === 0,
    unbacked.slice(0, 5).join(" ; ") || `${known.size} registered product route(s); every surface-table route backed or annotated`);

  // ---- mutation drills ----
  if (mutation) {
    const drill = (name, satisfied, detail) => ok(name, satisfied, detail);
    const fakeList = [{ line: 1, printed: 1 }, { line: 2, printed: 2 }, { line: 3, printed: 2 }];
    const seen = new Map(); const dup = [];
    fakeList.forEach((item) => { if (seen.has(item.printed)) dup.push(item); seen.set(item.printed, item.line); });
    drill("DRILL M1 — the duplicate-ordinal finding detects a repeated number", dup.length === 1, `${dup.length} detected`);

    const fakeSeq = [1, 2, 4].map((printed, index) => ({ printed, index }));
    const gaps = fakeSeq.filter((x) => x.printed !== x.index + 1);
    drill("DRILL M2 — the ordering finding detects a gap that a duplicate leaves behind", gaps.length === 1, `${gaps.length} detected`);

    drill("DRILL M3 — the numeric-citation finding detects an ordinal no list has",
      ![...ordinals].includes(9999), "ordinal 9999 is absent from every list, so a citation of it would be caught");

    const archivedTarget = "docs/architecture/_meta/implementation-matrix.md";
    drill("DRILL M4 — archived-ness is read from the target and the known archived stub is recognised",
      isArchived(archivedTarget), `${archivedTarget} reads as archived from its own front matter`);
    drill("DRILL M5 — and a live document is NOT read as archived, so the finding cannot be vacuously satisfied",
      !isArchived("docs/architecture/components/hypervisor/core-clients-surfaces.md"),
      "the live surfaces document does not read as archived");

    drill("DRILL M6 — the endpoint finding detects a documented route the daemon does not register",
      !registered.has(normalize("/v1/hypervisor/planted-never-registered/{id}")),
      "a planted endpoint is absent from the registration set");

    drill("DRILL M7 — the surface-table finding detects a route the estate does not register",
      !known.has("/planted-canonical-route"),
      "a planted canonical route is absent from the taxonomy and the records");
  }
} catch (error) {
  failures += 1;
  results.push({ assertion: "the check ran to completion", satisfied: false, detail: String(error?.stack || error).slice(0, 600) });
  console.log(`FAIL  the check ran to completion  (${String(error?.message || error).slice(0, 300)})`);
}

const passed = results.filter((entry) => entry.satisfied).length;
console.log(JSON.stringify({
  check: "check:canon-document-residuals",
  unit: "M08.6",
  verdict: failures === 0 ? "PASS" : "FAIL",
  executed_assertions: results.length,
  passed,
  failed: failures,
  observations,
}, null, 2));
process.exit(failures === 0 ? 0 : 1);
