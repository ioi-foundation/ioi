#!/usr/bin/env node
// The ontology plane's ADMISSION CENSUS — derived from the daemon's own source, at the layer the
// property lives.
//
// WHY THIS EXISTS, and why it is not a journey gate. Next-legs XIII spent five merge-blocking review
// rounds strengthening one journey verifier's proof that "no second admission path writes ontology
// truth" — keyed first on the route name, then the changed file name, then the response bytes, then
// the caller's request — and each round a review defeated the PROOF while the code under test stayed
// correct and green. The owner ruled the iteration terminated and the claim MIS-SCOPED FOR ITS
// OBSERVER: a whole-program property cannot be entailed by a black-box journey verifier, because the
// observer sits inside the system it is trying to bound. The journey gate's labels were re-scoped to
// the journey-scoped fact they check, the property was filed as a named residual, and building the
// real proof HERE — from the module source — was commissioned as next-legs XIV Leg 3a.
//
// WHAT IT ENTAILS. For each of the ontology plane's FOUR record families, exactly ONE module in the
// daemon admits it. That is a statement about the whole program, and source is where the whole
// program is visible at once. A second admission path has to appear in some module's text to exist
// at all, so a census that classifies EVERY mention in EVERY module can see one however it is
// spelled — which is precisely what a request/response observer cannot do.
//
// HOW IT DERIVES, and the three disciplines XIII paid for:
//
//   1. PATTERNS DO NOT DEFINE THE CENSUS; CLASSIFICATION OF EVERY MENTION DOES. XIII's first pass at
//      this by hand used a write-pattern and a read-pattern and reported `domain_apps_routes` as
//      neither — it reads the family through a BARE LITERAL the patterns did not cover. A census
//      whose coverage is the union of the patterns its author thought of is an allowlist wearing a
//      derivation. Every mention here lands in a closed vocabulary or the run is RED.
//
//   2. ALIASES ARE RESOLVED, NEVER NAME-MATCHED. The family argument at a write site is resolved to
//      its string LITERAL through the daemon's own `const NAME: &str = "..."` declarations and
//      through `use ... as` renames. A module-local constant pointing at another family's literal
//      is the evasion that a name-match cannot see, and XIII's push found the same shape one level
//      up when a module-local `identity()` wrapper hid the canonical resolver from an estate-wide
//      census.
//
//   3. TWO DIRECTIONS (scar 4). Nothing unclassified, AND no stale entry: every family's expected
//      owner must still actually admit it. A census that only checks one direction goes quietly
//      empty when the thing it counts is renamed away.
//
// WHAT IT DOES NOT ENTAIL, stated so the label claims only what it checks. This reads the daemon's
// Rust source. It does not see a write performed by a dependency crate on the daemon's behalf, a
// write through a macro that expands to a writer, or a write by a process that is not this daemon.
// Those are outside the source it censuses, and it says so rather than implying otherwise.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..", "..", "..");
const ROUTES_DIR = path.join(ROOT, "crates/node/src/bin/hypervisor_daemon_routes");
const DAEMON_MAIN = path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

// ---------------------------------------------------------------- the scanner
// String-aware, because a `//` inside a string literal is not a comment. XIII shipped a naive
// `.replace(/\/\/[^\n]*/g, "")` that ate 74 characters of executable code off four `org://` lines
// and let a writer parked after such a literal go invisible; then its repair mishandled `'\''` and
// `'\u{..}'` and desynchronised the same way. Handles: "…", escapes, r"…", r#"…"#, char literals
// including escaped and non-BMP, `//`, and nested `/* */`.
export function stripRustComments(src) {
  let out = "";
  for (let i = 0; i < src.length;) {
    const c = src[i];
    if (c === "r" && (src[i + 1] === '"' || src[i + 1] === "#")) {
      let j = i + 1, hashes = 0;
      while (src[j] === "#") { hashes += 1; j += 1; }
      if (src[j] === '"') {
        const close = `"${"#".repeat(hashes)}`;
        const end = src.indexOf(close, j + 1);
        const stop = end === -1 ? src.length : end + close.length;
        out += src.slice(i, stop); i = stop; continue;
      }
    }
    if (c === '"') {
      let j = i + 1;
      while (j < src.length) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === '"') { j += 1; break; }
        j += 1;
      }
      out += src.slice(i, j); i = j; continue;
    }
    if (c === "'") {
      let j = i + 1;
      if (src[i + 1] === "\\") {
        if (src[i + 2] === "u" && src[i + 3] === "{") {
          const close = src.indexOf("}", i + 4);
          j = close === -1 ? src.length : close + 1;
        } else if (src[i + 2] === "x") { j = i + 5; }
        else { j = i + 3; }
      } else {
        // A non-BMP char literal is two UTF-16 units, so the close is not at a fixed offset.
        let k = i + 1;
        while (k < src.length && k <= i + 3 && src[k] !== "'") k += 1;
        if (src[k] !== "'") { out += c; i += 1; continue; }   // a lifetime, not a literal
        j = k;
      }
      if (src[j] === "'") { out += src.slice(i, j + 1); i = j + 1; continue; }
      out += c; i += 1; continue;
    }
    if (c === "/" && src[i + 1] === "/") { while (i < src.length && src[i] !== "\n") i += 1; continue; }
    if (c === "/" && src[i + 1] === "*") {
      let depth = 1; i += 2;
      while (i < src.length && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") { depth += 1; i += 2; continue; }
        if (src[i] === "*" && src[i + 1] === "/") { depth -= 1; i += 2; continue; }
        i += 1;
      }
      continue;
    }
    out += c; i += 1;
  }
  return out;
}

// ---------------------------------------------------------------- the closed world of modules
const moduleFiles = () => {
  const files = fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith(".rs")).sort()
    .map((f) => path.join(ROUTES_DIR, f));
  files.push(DAEMON_MAIN);
  return files;
};
const modName = (f) => path.basename(f, ".rs");

// ---------------------------------------------------------------- the families under census
// The plane's four record families. XIII's journey observation watched TWO of them and a review
// named the other two as the identical attack one family over; a source census has no reason to
// watch a subset.
const FAMILIES = {
  "odk-domain-ontologies": "odk_routes",
  "odk-ontology-receipts": "odk_routes",
  "odk-ontology-proposals": "ontology_workbench_routes",
  "odk-saved-object-sets": "ontology_workbench_routes",
};

// Durable record writers. `\w*` covers suffixed spellings (`persist_record_durable`), which XIII
// found a bare-name pattern could not see.
const WRITER = "(?:persist_record|remove_record|persist_promoted|admit_required)\\w*";
// Record readers. A read is a legitimate, non-admitting mention and must classify as one.
const READER = "(?:load|read_record_dir|json_get|record_path|load_record)\\w*";

function run() {
  const files = moduleFiles();
  const sources = new Map();
  for (const f of files) sources.set(f, stripRustComments(fs.readFileSync(f, "utf8")));
  const rawSources = new Map();
  for (const f of files) rawSources.set(f, fs.readFileSync(f, "utf8"));

  ok("the module world is DERIVED from the daemon's route directory, not listed — a census over a hand-written module list cannot notice a module that was added",
    files.length > 50 && files.some((f) => modName(f) === "odk_routes") && files.some((f) => modName(f) === "ontology_workbench_routes"),
    `${files.length} modules censused`);

  // ------------------------------------------------------------ alias resolution
  // Every `const NAME: &str = "literal"` in the daemon, so a family argument spelled as a constant
  // resolves to what it POINTS AT rather than to what it is called.
  const constLiteral = new Map();
  for (const [, src] of sources) {
    for (const m of src.matchAll(/const\s+(\w+)\s*:\s*&'?\w*\s*str\s*=\s*"([^"]*)"/gu)) {
      constLiteral.set(m[1], m[2]);
    }
  }
  ok("every family constant in the daemon resolves to its string LITERAL, so a family argument is read by what it POINTS AT and not by what it is named — a module-local constant aimed at another family is the evasion a name-match cannot see",
    [...Object.keys(FAMILIES)].every((lit) => [...constLiteral.values()].includes(lit)),
    `${constLiteral.size} string constants resolved`);

  // `use path::CONST as ALIAS;` renames, per module.
  const aliasFor = new Map();   // module -> Map(alias -> literal)
  for (const [f, src] of sources) {
    const m2 = new Map();
    for (const d of src.matchAll(/use\s+([^;]*);/gu)) {
      for (const a of d[1].matchAll(/(\w+)\s+as\s+(\w+)/gu)) {
        if (constLiteral.has(a[1])) m2.set(a[2], constLiteral.get(a[1]));
      }
    }
    aliasFor.set(modName(f), m2);
  }

  const resolveArg = (mod, arg) => {
    const a = arg.trim();
    if (a.startsWith('"')) return a.slice(1, a.lastIndexOf('"'));
    const name = a.split("::").pop().replace(/[^\w]/gu, "");
    return aliasFor.get(mod)?.get(name) ?? constLiteral.get(name) ?? null;
  };

  // ------------------------------------------------------------ classify EVERY mention
  // A mention is any occurrence of a family literal, or of any constant that resolves to one.
  const familyLiterals = new Set(Object.keys(FAMILIES));
  const familyNames = new Set([...constLiteral.entries()].filter(([, v]) => familyLiterals.has(v)).map(([k]) => k));
  const mentionRe = new RegExp(
    `"(?:${[...familyLiterals].map((s) => s.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")).join("|")})"|\\b(?:${[...familyNames].join("|")})\\b`,
    "gu",
  );

  const admits = new Map();       // literal -> Set(module)
  const mentions = [];            // {mod, index, text, kind}
  for (const lit of familyLiterals) admits.set(lit, new Set());

  for (const [f, src] of sources) {
    const mod = modName(f);
    const aliasNames = [...(aliasFor.get(mod)?.keys() ?? [])];
    const localRe = aliasNames.length
      ? new RegExp(`${mentionRe.source}|\\b(?:${aliasNames.join("|")})\\b`, "gu")
      : new RegExp(mentionRe.source, "gu");

    // CLASSIFY BY SPAN, NOT BY POINT. The first cut recorded where a write's family ARGUMENT begins
    // and compared it to where the mention regex matched — and for
    // `read_record_dir(data_dir, crate::odk_routes::KIND_ONT)` those differ, because the mention is
    // the bare constant NAME inside a qualified path. Six real, correctly-written mentions came back
    // unclassified. A mention now classifies as the kind of the span that CONTAINS it.
    const spans = [];
    const addSpans = (re, kind) => {
      for (const m of src.matchAll(re)) {
        const arg = m[1];
        const lit = resolveArg(mod, arg);
        if (!lit || !familyLiterals.has(lit)) continue;
        const at = m.index + m[0].lastIndexOf(arg);
        spans.push({ start: at, end: at + arg.length, kind });
        if (kind === "admits") admits.get(lit).add(mod);
      }
    };
    addSpans(new RegExp(`${WRITER}\\(\\s*&?[\\w.]+\\s*,\\s*([^,]+?)\\s*,`, "gu"), "admits");
    addSpans(new RegExp(`${READER}\\(\\s*&?[\\w.]+\\s*,\\s*([^,)]+?)\\s*[,)]`, "gu"), "reads");
    // scheme-mapper arms: `"ontology" => Some("odk-domain-ontologies")` / `=> Some(KIND)`
    addSpans(/=>\s*Some\(\s*([^)]+?)\s*\)/gu, "resolves");
    // THE DECLARATION, BOTH HALVES: the literal AND the name bound to it. Classifying only the
    // literal left every `const KIND_ONT: &str = "..."` NAME mention unreadable.
    for (const m of src.matchAll(/const\s+(\w+)\s*:\s*&'?\w*\s*str\s*=\s*"([^"]*)"/gu)) {
      if (!familyLiterals.has(m[2])) continue;
      const nameAt = m.index + m[0].indexOf(m[1]);
      spans.push({ start: nameAt, end: nameAt + m[1].length, kind: "declares" });
      const litAt = m.index + m[0].lastIndexOf(`"${m[2]}"`);
      spans.push({ start: litAt, end: litAt + m[2].length + 2, kind: "declares" });
    }
    // AN IMPORT IS ITS OWN KIND. `use super::odk_routes::{…, KIND_ONT};` brings the family name into
    // scope; it is neither a read nor a write, and folding it into either would be a lie about what
    // that line does. It is worth classifying separately for a second reason: an import is how a
    // module ACQUIRES the ability to name another family, so the set of modules importing a family
    // constant is the shortlist a reviewer should look at first.
    for (const m of src.matchAll(/use\s+[^;]*;/gu)) {
      for (const n of m[0].matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/gu)) {
        const lit = constLiteral.get(n[1]) ?? aliasFor.get(mod)?.get(n[1]);
        if (!lit || !familyLiterals.has(lit)) continue;
        const at = m.index + m[0].indexOf(n[1]);
        spans.push({ start: at, end: at + n[1].length, kind: "imports" });
      }
    }
    // A family constant used as a PATH COMPONENT inside the module's own `#[cfg(test)]` block —
    // `std::fs::write(dir.join(KIND_ONT_RECEIPT), b"blocker")` plants a fixture, it does not admit a
    // record. Classified as its own kind rather than waved through, and the production denylist
    // below resolves constants precisely because this shape OUTSIDE a test block WOULD be a second
    // admission path and a literal-only denylist could not see it.
    for (const t of testRegions(src)) spans.push({ ...t, kind: "test-fixture" });

    for (const m of src.matchAll(localRe)) {
      // Narrowest containing span wins, so a family argument inside a test block still reads as the
      // argument it is rather than being swallowed by the block.
      const hit = spans.filter((sp) => m.index >= sp.start && m.index < sp.end)
        .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0];
      mentions.push({ mod, index: m.index, text: m[0], kind: hit?.kind ?? null });
    }
  }

  // ------------------------------------------------------------ direction 1: nothing unclassified
  const unclassified = mentions.filter((m) => m.kind === null);
  ok("EVERY mention of an ontology-plane family in EVERY daemon module lands in the closed vocabulary {admits, reads, resolves, declares, imports, test-fixture} — patterns do not define this census, classification of every mention does, and an unreadable mention is RED rather than silently dropped",
    mentions.length > 0 && unclassified.length === 0,
    unclassified.length
      ? `UNCLASSIFIED: ${unclassified.slice(0, 6).map((m) => `${m.mod}:${m.text}@${m.index}`).join(" ; ")}`
      : `${mentions.length} mentions, all classified`);

  // ------------------------------------------------------------ the entailment
  for (const [lit, owner] of Object.entries(FAMILIES)) {
    const got = [...admits.get(lit)].sort();
    ok(`EXACTLY ONE module admits \`${lit}\` — and it is \`${owner}\`; a second admission path for this family would have to appear in some module's source to exist, so a census that classifies every mention sees it however it is spelled`,
      got.length === 1 && got[0] === owner,
      `admitted by [${got.join(",") || "none"}]`);
  }

  // ------------------------------------------------------------ direction 2: no stale entry
  ok("and no expected owner is STALE — each of the four families is still actually admitted by the module this census names, so the claim cannot go quietly true by the writes being renamed away",
    Object.entries(FAMILIES).every(([lit]) => admits.get(lit).size > 0),
    Object.entries(FAMILIES).map(([lit]) => `${lit}:${admits.get(lit).size}`).join(" "));

  // ------------------------------------------------------------ resolver flow
  // `governance_routes` and `marketplace_routes` map `"ontology" => Some("odk-domain-ontologies")`
  // through a GENERIC scheme-mapper. Today both feed a `load(...)` existence check — but the shape
  // is the one that becomes a second admission path the moment a resolved name reaches a writer, so
  // what is asserted is WHERE THE RESOLUTION FLOWS, not merely that it exists.
  const resolverMods = [...new Set(mentions.filter((m) => m.kind === "resolves").map((m) => m.mod))].sort();
  const resolverSinks = [];
  for (const mod of resolverMods) {
    const f = files.find((x) => modName(x) === mod);
    const src = sources.get(f);
    // the binding the match arm lands in, e.g. `let kind = match scheme { ... };`
    for (const m of src.matchAll(/let\s+(\w+)\s*=\s*match\s+\w+\s*\{[\s\S]*?\n\s*\};/gu)) {
      if (!familyLiterals.has(resolveArgFromArms(m[0], mod, resolveArg, familyLiterals))) continue;
      const after = src.slice(m.index + m[0].length, m.index + m[0].length + 1600);
      // FOLLOW THE REBINDING, or this assertion is decorative. The resolved family lands in `kind`
      // and the code that USES it immediately unwraps: `if let Some(k) = kind { … load(data_dir, k,
      // id) … }`. Tracking only the match binding meant a writer taking `k` was invisible — a
      // mutation putting `persist_record(data_dir, k, …)` right there passed GREEN, which is exactly
      // the evasion this assertion exists for. Names are closed over transitively: any `let X = Y`
      // or `if let Some(X) = Y` where Y is already tracked makes X tracked too.
      const tracked = new Set([m[1]]);
      for (let pass = 0; pass < 4; pass += 1) {
        for (const t of [...tracked]) {
          for (const rb of after.matchAll(new RegExp(`(?:if\\s+let\\s+Some\\(\\s*(\\w+)\\s*\\)|let\\s+(\\w+))\\s*=\\s*\\*?${t}\\b`, "gu"))) {
            tracked.add(rb[1] ?? rb[2]);
          }
        }
      }
      for (const t of tracked) {
        for (const use of after.matchAll(new RegExp(`(\\w+)\\s*\\(\\s*[^)]*?\\b${t}\\b`, "gu"))) {
          resolverSinks.push({ mod, sink: use[1], via: t });
        }
      }
    }
  }
  const writerSinks = resolverSinks.filter((s) => new RegExp(`^${WRITER}$`, "u").test(s.sink));
  ok("and every scheme-mapper that RESOLVES a family name flows only into READ sinks — the generic `\"ontology\" => Some(...)` arms in governance and marketplace are the exact shape that becomes a second admission path the moment a resolved name reaches a writer, so where it flows is asserted, not just that it exists",
    resolverMods.length > 0 && writerSinks.length === 0,
    writerSinks.length
      ? `RESOLVED NAME REACHES A WRITER: ${writerSinks.map((s) => `${s.mod}->${s.sink}`).join(" ; ")}`
      : `${resolverMods.join(",")} resolve into sinks [${[...new Set(resolverSinks.map((s) => s.sink))].sort().join(",") || "none"}]`);

  // ------------------------------------------------------------ no raw filesystem write into a family dir
  // A denylist, and LABELLED as one: it bounds a known attack and cannot entail that no raw write
  // exists. The entailment above is what carries the claim.
  // THE DENYLIST RESOLVES CONSTANTS, because a literal-only scan is blind to the shape this census
  // actually found. `odk_routes` plants fixtures with `std::fs::write(dir.join(KIND_ONT_RECEIPT), …)`
  // — inside `#[cfg(test)]`, so benign — and a literal-only pattern could not see it at all. The
  // same line OUTSIDE a test block is a raw write straight into a family directory, so the scan
  // resolves the constant AND excludes only genuine test regions rather than the whole file.
  const rawWrites = [];
  const FS_WRITE = /(?:fs\s*::\s*(?:write|create|create_new|remove_file|remove_dir_all|copy|rename|hard_link|OpenOptions)|File\s*::\s*create)/gu;
  for (const [f, src] of sources) {
    const mod = modName(f);
    const tests = testRegions(src);
    const inTest = (i) => tests.some((t) => i >= t.start && i < t.end);
    for (const m of src.matchAll(FS_WRITE)) {
      if (inTest(m.index)) continue;
      const tail = src.slice(m.index, m.index + 240);
      for (const tok of tail.matchAll(/"([^"]+)"|\b([A-Z][A-Z0-9_]{2,})\b/gu)) {
        const lit = tok[1] ?? constLiteral.get(tok[2]) ?? aliasFor.get(mod)?.get(tok[2]);
        if (lit && familyLiterals.has(lit)) rawWrites.push(`${mod}->${lit} @${m.index}`);
      }
    }
  }
  ok("no PRODUCTION raw filesystem write in this daemon targets an ontology-plane family, with the family resolved through constants and not just literals — a DENYLIST bounding a known attack, not a proof that no raw write exists; the per-family entailment above is what carries the claim",
    rawWrites.length === 0, [...new Set(rawWrites)].join(" ; ") || "no denylisted raw write outside test blocks");

  // ------------------------------------------------------------ the scanner is honest about itself
  const rawTotal = [...rawSources.values()].join("").length;
  const strippedTotal = [...sources.values()].join("").length;
  ok("the comment stripper removed only comments — the censused source is shorter than the raw source but every family literal survives it, because a stripper that eats code makes a write invisible and fails OPEN (XIII shipped exactly that)",
    strippedTotal < rawTotal
      && [...familyLiterals].every((lit) => [...sources.values()].some((s) => s.includes(lit))),
    `${rawTotal} -> ${strippedTotal} chars`);

  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "ontology-admission-census", sourceUrl: import.meta.url, results });
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length) process.exit(1);
}

/**
 * The byte spans of this module's `#[cfg(test)]` blocks.
 *
 * Brace-matched from the attribute rather than line-counted, because a test block that a regex
 * closes at the wrong brace would either hide production code inside a "test" region — which is
 * exactly how a second admission path would get waved through — or truncate the region and leave
 * real fixture lines unclassified.
 */
export function testRegions(src) {
  const out = [];
  for (const m of src.matchAll(/#\[cfg\(test\)\]/gu)) {
    const open = src.indexOf("{", m.index);
    if (open === -1) continue;
    let depth = 0;
    let i = open;
    for (; i < src.length; i += 1) {
      if (src[i] === "{") depth += 1;
      else if (src[i] === "}") { depth -= 1; if (depth === 0) break; }
    }
    out.push({ start: m.index, end: Math.min(i + 1, src.length) });
  }
  return out;
}

/** The literal a `match` block's arms resolve to, if any arm names a censused family. */
function resolveArgFromArms(block, mod, resolveArg, familyLiterals) {
  for (const arm of block.matchAll(/=>\s*Some\(\s*([^)]+?)\s*\)/gu)) {
    const lit = resolveArg(mod, arm[1]);
    if (lit && familyLiterals.has(lit)) return lit;
  }
  return null;
}

// RUN ONLY WHEN INVOKED, NEVER ON IMPORT. XIII killed a mutation battery mid-run by importing a
// module whose top level had side effects; the timeout skipped its `finally` and left a mutant in
// the tree. A verifier that executes on import is the same hazard for anything that wants to reuse
// its scanner.
const INVOKED_DIRECTLY = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED_DIRECTLY) {
  try {
    run();
  } catch (error) {
    console.error(`FAIL ontology-admission-census — ${error?.stack || error}`);
    process.exit(1);
  }
}
