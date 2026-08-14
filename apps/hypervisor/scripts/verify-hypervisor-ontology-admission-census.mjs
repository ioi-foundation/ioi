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
// observer sits inside the system it is trying to bound. Building the real proof HERE — from module
// source — was commissioned as next-legs XIV Leg 3a.
//
// WHAT IT ENTAILS. For each of the ontology plane's FOUR record families, exactly ONE module in the
// daemon admits it. A second admission path has to appear in some module's text to exist at all, so
// a census that classifies EVERY mention in EVERY module can see one however it is spelled.
//
// WHAT THE FIRST CUT GOT WRONG, because every one of these is now load-bearing. A merge-blocking
// review defeated it FIVE ways with mutants that stayed green, and each defeat is a discipline:
//
//   1. NAME RESOLUTION IS PER MODULE, NEVER GLOBAL. The first cut built ONE `Map(name → literal)`
//      across all 88 modules. The daemon declares 660 string constants under 537 names — 25 of them
//      AMBIGUOUS, with `RECORD_DIR` declared in thirteen modules meaning thirteen different things.
//      Last-writer-wins silently discarded 123 declarations, so a second admitter written in the
//      house style (`const RECORD_DIR: &str = "odk-domain-ontologies"`) resolved to some other
//      module's literal and vanished. Resolution is scoped to the declaring module now, qualified
//      paths resolve in the module they name, and an AMBIGUOUS bare name is UNRESOLVED — which is
//      RED — rather than guessed.
//
//   2. THE TEST-REGION MATCHER MUST SKIP STRING LITERALS. It counted braces in a source that still
//      contains string literals, so `storage_backend_routes.rs`'s `#[cfg(test)]` region over-ran its
//      real end by 811 characters and swallowed a production function; a raw write planted there was
//      waved through by both the denylist and the classifier. A region that does not close on a real
//      brace is now RED, not a region.
//
//   3. READER NAMES ARE EXACT, NOT PREFIXES. `load\w*` matched `load_or_admit` — an ordinary
//      get-or-create helper — so a call that WRITES classified as a read. Any other callee taking a
//      family argument is unclassified, which is RED.
//
//   4. THE MODULE WORLD COMES FROM THE MODULE GRAPH, not a directory listing. A module declared
//      `#[path]` outside the routes directory was never read at all. The world is derived from the
//      binary's own `mod` declarations, asserted bijective with the directory, and `include!` is
//      refused because it would splice source this census never sees.
//
//   5. AN ASSERTION ABOUT THE SCANNER MUST FAIL ON THE SCANNER. "The stripper removed only comments"
//      checked that the output got shorter and the four literals survived somewhere — so replacing
//      the scanner with XIII's naive `//`-regex, which ate 368,828 characters of executable code,
//      PASSED. Every removed span is now checked to begin at a real comment token in the raw source.
//
// WHAT IT DOES NOT ENTAIL, stated so the label claims only what it checks. This reads the daemon's
// Rust source and sees a family named by a literal, by a resolvable constant, or by a resolvable
// alias. It does NOT see: a family name ASSEMBLED at runtime (`format!("odk-{}-ontologies", …)`),
// a write performed by a dependency crate on the daemon's behalf, a write produced by macro
// expansion, or a write by a process that is not this daemon. Those are outside what source
// inspection can decide, and they are named here rather than implied away.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.IOI_CENSUS_ROOT || path.resolve(HERE, "..", "..", "..");
const BIN_DIR = path.join(ROOT, "crates/node/src/bin");
const ROUTES_DIR = path.join(BIN_DIR, "hypervisor_daemon_routes");
const DAEMON_MAIN = path.join(BIN_DIR, "hypervisor-daemon.rs");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

// ---------------------------------------------------------------- the scanner
/**
 * Strip Rust comments, reporting exactly which byte spans were removed.
 *
 * The spans are the point. An assertion that the stripper "removed only comments" is decorative
 * unless it can check WHAT was removed — XIII's naive `//` regex ate 368k characters of code and a
 * length-plus-survival check passed it.
 */
export function stripRustComments(src) {
  let out = "";
  const removed = [];
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
        let k = i + 1;                       // a non-BMP char literal is two UTF-16 units
        while (k < src.length && k <= i + 3 && src[k] !== "'") k += 1;
        if (src[k] !== "'") { out += c; i += 1; continue; }   // a lifetime, not a literal
        j = k;
      }
      if (src[j] === "'") { out += src.slice(i, j + 1); i = j + 1; continue; }
      out += c; i += 1; continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      const start = i;
      while (i < src.length && src[i] !== "\n") i += 1;
      removed.push([start, i]); continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const start = i;
      let depth = 1; i += 2;
      while (i < src.length && depth > 0) {
        if (src[i] === "/" && src[i + 1] === "*") { depth += 1; i += 2; continue; }
        if (src[i] === "*" && src[i + 1] === "/") { depth -= 1; i += 2; continue; }
        i += 1;
      }
      removed.push([start, i]); continue;
    }
    out += c; i += 1;
  }
  return { out, removed };
}

/**
 * Walk from `from` to the brace that closes the first `{` at or after it, SKIPPING string and char
 * literals. Returns `{ end, closed }`.
 *
 * One implementation, used by both the test-region matcher and the resolver-flow function bound —
 * because writing the walk twice is how the string-skipping fix landed in one of them and not the
 * other, which silently emptied the resolver's search window and let a defeated mutation go green
 * again.
 */
export function matchBrace(src, from) {
  let depth = 0, i = from, seen = false;
  for (; i < src.length; i += 1) {
    const c = src[i];
    if (c === '"') {
      i += 1;
      while (i < src.length) {
        if (src[i] === "\\") { i += 2; continue; }
        if (src[i] === '"') break;
        i += 1;
      }
      continue;
    }
    if (c === "'") {
      let k = i + 1;
      if (src[k] === "\\") k += 1;
      while (k < src.length && k <= i + 4 && src[k] !== "'") k += 1;
      if (src[k] === "'") { i = k; }
      continue;
    }
    if (c === "{") { depth += 1; seen = true; }
    else if (c === "}") { depth -= 1; if (seen && depth === 0) return { end: i, closed: true }; }
  }
  return { end: Math.min(i, src.length), closed: false };
}

/**
 * Expand a `use` declaration into `[{ owner, name, alias }]`.
 *
 * The daemon's house style is the BRACED GROUP — 58 route modules write `use super::{…}` — and a
 * parser that only understood `super::<ident>::` produced ZERO entries for
 * `use super::{odk_routes::KIND_ONT as ONT_DIR};`. Not ambiguous, not unresolved: invisible. A
 * second admitter walked straight through that, and the un-grouped form was only ever caught by a
 * global-unique fallback that this census has since removed.
 */
export function expandUseTree(decl) {
  const out = [];
  const walk = (prefix, text) => {
    let depth = 0, part = "";
    const parts = [];
    for (const ch of text) {
      if (ch === "{") { depth += 1; part += ch; continue; }
      if (ch === "}") { depth -= 1; part += ch; continue; }
      if (ch === "," && depth === 0) { parts.push(part); part = ""; continue; }
      part += ch;
    }
    if (part.trim()) parts.push(part);
    for (const raw of parts) {
      const seg = raw.trim();
      if (!seg) continue;
      const brace = seg.indexOf("{");
      if (brace !== -1 && seg.endsWith("}")) {
        walk(`${prefix}${seg.slice(0, brace)}`, seg.slice(brace + 1, -1));
        continue;
      }
      const asMatch = /^(.*?)\s+as\s+(\w+)$/u.exec(seg);
      const pathPart = (asMatch ? asMatch[1] : seg).trim();
      const alias = asMatch ? asMatch[2] : null;
      const full = `${prefix}${pathPart}`;
      const segs = full.split("::").map((x) => x.trim()).filter(Boolean);
      const name = segs[segs.length - 1];
      const owner = segs.length >= 2 ? segs[segs.length - 2] : null;
      out.push({ owner, name, alias: alias ?? name });
    }
  };
  walk("", decl);
  return out;
}

/**
 * The offset of the `}` that closes the block containing `from`, with string and char literals
 * skipped. Needs no knowledge of how the enclosing function was declared.
 */
export function enclosingBlockEnd(src, from) {
  let depth = 0;
  for (let i = from; i < src.length; i += 1) {
    const c = src[i];
    if (c === '"') {
      i += 1;
      while (i < src.length) {
        if (src[i] === "\\") { i += 2; continue; }
        if (src[i] === '"') break;
        i += 1;
      }
      continue;
    }
    if (c === "'") {
      let k = i + 1;
      if (src[k] === "\\") k += 1;
      while (k < src.length && k <= i + 4 && src[k] !== "'") k += 1;
      if (src[k] === "'") { i = k; }
      continue;
    }
    if (c === "{") depth += 1;
    else if (c === "}") { if (depth === 0) return i; depth -= 1; }
  }
  return src.length;
}

/**
 * Byte spans of `#[cfg(test)]` blocks, brace-matched with STRING AND CHAR LITERALS SKIPPED.
 *
 * A depth counter that counts braces inside `"{"` closes at the wrong brace. In this repo that made
 * one region over-run its end by 811 characters and swallow a production function, and another close
 * 5,466 characters early. Returns `closed: false` for a region that ran to EOF, which the caller
 * treats as RED — a region that never closed is not a region.
 */
export function testRegions(src) {
  const out = [];
  // STRING SPANS FIRST. This runs on comment-stripped source, which still contains STRING LITERALS,
  // so the literal text `"#[cfg(test)]"` inside a helper minted a phantom region — and four such
  // phantoms exist in this tree today. A phantom region reclassifies production code as a test
  // fixture, which switches off both the raw-write denylist and the unclassified-mention backstop.
  const strings = [];
  for (let i = 0; i < src.length; i += 1) {
    if (src[i] === '"') {
      const start = i;
      i += 1;
      while (i < src.length) {
        if (src[i] === "\\") { i += 2; continue; }
        if (src[i] === '"') break;
        i += 1;
      }
      strings.push([start, i]);
    }
  }
  const inString = (at) => strings.some(([a, b]) => at > a && at < b);
  for (const m of src.matchAll(/#\[cfg\(test\)\]/gu)) {
    if (inString(m.index)) continue;
    const open = src.indexOf("{", m.index);
    // ATTACHED TO A BRACED ITEM. `#[cfg(test)] use std::fs as _t;` before a function made that
    // FUNCTION the region. The attribute must introduce a `mod` or `fn` for its brace to be the
    // region's brace.
    const between = open === -1 ? "" : src.slice(m.index + "#[cfg(test)]".length, open);
    const attached = /^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:mod|fn|impl|async\s+fn)\b/u.test(between);
    // AN ATTRIBUTE ON A NON-BRACED ITEM CREATES NO REGION, AND THAT IS THE FIX. `#[cfg(test)] use
    // std::fs as _t;` and `#[cfg(test)] thread_local! { … }` are ordinary Rust that this daemon
    // writes in eight places; taking "the next brace anywhere" made the FOLLOWING function the
    // region, which is how a production raw write got reclassified as a test fixture. No region is
    // the correct answer for these, not a red — the red belongs to a region that opens and never
    // closes.
    if (open === -1 || !attached) continue;
    const { end, closed } = matchBrace(src, open);
    out.push({ start: m.index, end: Math.min(end + 1, src.length), closed, attached: true });
  }
  return out;
}


// ---------------------------------------------------------------- families under census
const FAMILIES = {
  "odk-domain-ontologies": "odk_routes",
  "odk-ontology-receipts": "odk_routes",
  "odk-ontology-proposals": "ontology_workbench_routes",
  "odk-saved-object-sets": "ontology_workbench_routes",
};

const WRITER = "(?:persist_record|remove_record|persist_promoted|admit_required)\\w*";
// EXACT names. A prefix pattern classified `load_or_admit` — a get-or-create that WRITES — as a read.
// Exact names, and only names that EXIST: `record_path` was in this list and matches no function
// in the daemon, so it could only ever widen the benign bucket for code that does not exist.
const READERS = ["load", "read_record_dir", "json_get", "load_record"];
const READER = `(?:${READERS.join("|")})`;

function run() {
  // ------------------------------------------------------------ the module world, from the graph
  const mainRaw = fs.readFileSync(DAEMON_MAIN, "utf8");
  const mainSrc = stripRustComments(mainRaw).out;
  // THE GRAPH IS WALKED TRANSITIVELY. The first cut read only the crate root's declarations, so a
  // `mod` declared INSIDE a route module — whose file lives in a subdirectory and therefore never
  // appears in a flat `.rs` listing — was never censused at all. That is the directory-listing
  // defect one level down, and a second admitter fits in it exactly.
  const declared = new Map();
  const queue = [DAEMON_MAIN];
  const walked = new Set();
  while (queue.length) {
    const file = queue.shift();
    if (walked.has(file) || !fs.existsSync(file)) continue;
    walked.add(file);
    const src = stripRustComments(fs.readFileSync(file, "utf8")).out;
    const dir = path.dirname(file);
    const selfName = path.basename(file, ".rs");
    for (const m of src.matchAll(/(?:#\[path\s*=\s*"([^"]+)"\]\s*)?(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(\w+)\s*;/gu)) {
      const candidates = m[1]
        ? [path.resolve(dir, m[1])]
        : [path.join(dir, `${m[2]}.rs`), path.join(dir, selfName, `${m[2]}.rs`), path.join(dir, m[2], "mod.rs")];
      const hit = candidates.find((c) => fs.existsSync(c));
      if (!hit) continue;
      declared.set(path.relative(BIN_DIR, hit), hit);
      queue.push(hit);
    }
  }
  const onDisk = fs.readdirSync(ROUTES_DIR).filter((f) => f.endsWith(".rs"))
    .map((f) => path.join(ROUTES_DIR, f)).sort();
  const declaredPaths = [...declared.values()].sort();
  const files = [...new Set([...declaredPaths, ...onDisk, DAEMON_MAIN])].filter((f) => fs.existsSync(f));
  const undeclared = onDisk.filter((f) => !declaredPaths.includes(f));
  const offDirectory = declaredPaths.filter((f) => path.dirname(f) !== ROUTES_DIR);
  const modName = (f) => path.basename(f, ".rs");

  ok("the module world is derived from the BINARY'S OWN `mod` DECLARATIONS and is bijective with the routes directory — a module declared `#[path]` outside that directory is part of the same binary and a directory listing never reads it, which is a second admission path a census cannot see",
    declared.size > 50 && undeclared.length === 0 && offDirectory.length === 0,
    undeclared.length || offDirectory.length
      ? `UNDECLARED: ${undeclared.map(modName).join(",") || "none"} | OFF-DIRECTORY: ${offDirectory.map((f) => path.relative(BIN_DIR, f)).join(",") || "none"}`
      : `${declared.size} modules reached transitively, bijective with ${onDisk.length} on disk`);

  const rawSources = new Map();
  const sources = new Map();
  const removedSpans = new Map();
  for (const f of files) {
    const raw = fs.readFileSync(f, "utf8");
    const { out, removed } = stripRustComments(raw);
    rawSources.set(f, raw); sources.set(f, out); removedSpans.set(f, removed);
  }

  // ------------------------------------------------------------ the scanner, checked on itself
  const removedTotal = [...removedSpans.values()].reduce((n, sp) => n + sp.length, 0);
  const badRemoval = [];
  for (const [f, spans] of removedSpans) {
    const raw = rawSources.get(f);
    for (const [a, b] of spans) {
      const head = raw.slice(a, a + 2);
      if (head === "//") {
        // A LINE COMMENT ENDS AT ITS LINE. Checking only the START is what let a greedy variant —
        // one that starts at `//` and keeps eating following lines — pass while hiding a second
        // admitter behind an ordinary comment. The END is the half that carries the finding.
        const nl = raw.indexOf("\n", a);
        if (b !== (nl === -1 ? raw.length : nl)) badRemoval.push(`${modName(f)}@${a}: line comment over-ran to ${b}`);
      } else if (head === "/*") {
        if (raw.slice(b - 2, b) !== "*/" && b !== raw.length) badRemoval.push(`${modName(f)}@${a}: block comment did not end at */`);
      } else {
        badRemoval.push(`${modName(f)}@${a}: removal does not begin at a comment token (${JSON.stringify(head)})`);
      }
    }
  }
  ok("every span the comment stripper REMOVED both BEGINS at a comment token and ENDS where that comment ends — a line comment at its newline, a block comment after its `*/` — a length-and-survival check cannot fail on a scanner that eats code, and XIII shipped exactly such a scanner (368,828 characters of executable source, and the assertion passed)",
    // NON-VACUITY: a scanner that reports NO removed spans satisfies "all removed spans are
    // comment-initial" trivially, and the naive `//`-regex does exactly that while eating code. A
    // daemon this size has tens of thousands of comment spans; zero is a broken scanner, not a
    // clean one.
    removedTotal > 10000 && badRemoval.length === 0,
    badRemoval.length ? `NOT A COMMENT: ${badRemoval.slice(0, 5).join(" ; ")}`
      : `${removedTotal} removed spans, all comment-initial`);

  ok("and this daemon splices no source through `include!`, which would put code inside a censused module that this census never reads",
    ![...sources.values()].some((s) => /\binclude!\s*\(/u.test(s)),
    "no include! in the censused world");

  // ------------------------------------------------------------ PER-MODULE name resolution
  const constsOf = new Map();                            // module -> Map(name -> literal)
  for (const [f, src] of sources) {
    const own = new Map();
    for (const m of src.matchAll(/const\s+(\w+)\s*:\s*&'?\w*\s*str\s*=\s*"([^"]*)"/gu)) own.set(m[1], m[2]);
    constsOf.set(modName(f), own);
  }
  // Every name a module brings into scope, resolved through the module it comes FROM. Handles the
  // braced-group house style, nested groups, and `as` renames alike.
  const aliasOf = new Map();
  for (const [f] of sources) aliasOf.set(modName(f), new Map());
  for (let hop = 0; hop < 2; hop += 1) {          // one hop follows a re-export chain
    for (const [f, src] of sources) {
      const mod = modName(f);
      for (const d of src.matchAll(/(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]*);/gu)) {
        for (const { owner, name, alias } of expandUseTree(d[1])) {
          if (!owner) continue;
          const lit = constsOf.get(owner)?.get(name) ?? aliasOf.get(owner)?.get(name);
          if (lit !== undefined) aliasOf.get(mod).set(alias, lit);
        }
      }
    }
  }

  const AMBIGUOUS = Symbol("ambiguous");
  /** Resolve a family-argument expression to its literal, scoped to the module that names it. */
  const resolveArg = (mod, argRaw) => {
    const arg = argRaw.trim();
    if (arg.startsWith('"')) return arg.slice(1, arg.lastIndexOf('"'));
    const qualified = /(?:crate|super)::(\w+)::(\w+)/u.exec(arg);
    if (qualified) return constsOf.get(qualified[1])?.get(qualified[2]) ?? null;
    const name = arg.split("::").pop().replace(/[^\w]/gu, "");
    const own = constsOf.get(mod)?.get(name);
    if (own !== undefined) return own;
    const alias = aliasOf.get(mod)?.get(name);
    if (alias !== undefined) return alias;
    // A BARE NAME THIS MODULE NEITHER DECLARES NOR IMPORTS IS NOT GUESSED — not even when exactly
    // one module in the daemon happens to declare it. That global-unique fallback was the crutch a
    // review used: it made the un-renamed grouped import look caught, so the renamed one looked like
    // a new hole rather than the same one. If a module names a family this census cannot tie to a
    // declaration it can see, that is UNRESOLVED, and unresolved is RED.
    const candidates = new Set();
    for (const [, m2] of constsOf) if (m2.has(name)) candidates.add(m2.get(name));
    return candidates.size ? AMBIGUOUS : null;
  };

  const familyLiterals = new Set(Object.keys(FAMILIES));
  ok("no family constant name is AMBIGUOUS across the daemon — resolution is scoped to the declaring module, and a bare name meaning different things in different modules resolves to nothing rather than to a guess (the daemon declares 660 string constants under 537 names, 25 of them ambiguous)",
    [...familyLiterals].every((lit) => [...constsOf.values()].some((m2) => [...m2.values()].includes(lit))),
    `${[...constsOf.values()].reduce((n, m2) => n + m2.size, 0)} constants, module-scoped`);

  // ------------------------------------------------------------ classify EVERY mention
  const admits = new Map();
  for (const lit of familyLiterals) admits.set(lit, new Set());
  const mentions = [];
  const unclosedTestRegions = [];

  for (const [f, src] of sources) {
    const mod = modName(f);
    const familyNames = new Set();
    for (const [n, lit] of constsOf.get(mod) ?? []) if (familyLiterals.has(lit)) familyNames.add(n);
    for (const [n, lit] of aliasOf.get(mod) ?? []) if (familyLiterals.has(lit)) familyNames.add(n);
    const litAlt = [...familyLiterals].map((s) => s.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")).join("|");
    // QUALIFIED PATHS ARE MENTIONS TOO. `crate::odk_routes::KIND_ONT` names a family in a module
    // that neither declares nor imports the bare name, so a mention set built only from literals and
    // module-local names cannot see it — and a review walked a whole second admission path through
    // that gap. Every `(crate|super)::<mod>::<CONST>` resolving to a family is collected here.
    const qualifiedNames = new Set();
    for (const q of src.matchAll(/(?:crate|super)::(\w+)::([A-Z][A-Z0-9_]{2,})/gu)) {
      if (familyLiterals.has(constsOf.get(q[1])?.get(q[2]))) qualifiedNames.add(q[2]);
    }
    const allNames = new Set([...familyNames, ...qualifiedNames]);
    const mentionRe = allNames.size
      ? new RegExp(`"(?:${litAlt})"|\\b(?:${[...allNames].join("|")})\\b`, "gu")
      : new RegExp(`"(?:${litAlt})"`, "gu");

    const spans = [];
    const addSpans = (re, kind) => {
      for (const m of src.matchAll(re)) {
        const arg = m[1];
        const lit = resolveArg(mod, arg);
        const at = m.index + m[0].lastIndexOf(arg);
        if (lit === AMBIGUOUS) { spans.push({ start: at, end: at + arg.length, kind: null }); continue; }
        if (!lit || !familyLiterals.has(lit)) continue;
        spans.push({ start: at, end: at + arg.length, kind });
        if (kind === "admits") admits.get(lit).add(mod);
      }
    };
    addSpans(new RegExp(`${WRITER}\\(\\s*&?[\\w.]+\\s*,\\s*([^,]+?)\\s*,`, "gu"), "admits");
    // A LOCAL FUNCTION THAT FORWARDS ITS OWN PARAMETER TO A WRITER IS A WRITER. `load_or_admit(d,
    // kind, id, seed)` reads first and persists on miss — an ordinary get-or-create — and a review
    // used exactly that to admit the ontology family while the family mention sat inside a call
    // whose name merely began with `load`. Resolution is interprocedural for this one hop: find the
    // local fns that pass a PARAMETER of their own as a writer's family argument, then treat a call
    // to one of them with a resolvable family argument as an admission by this module.
    const forwarding = new Set();
    for (const fn of src.matchAll(/fn\s+(\w+)\s*\(([^)]*)\)[^{]*\{/gu)) {
      const params = [...fn[2].matchAll(/(\w+)\s*:/gu)].map((x) => x[1]);
      if (!params.length) continue;
      const body = src.slice(fn.index, matchBrace(src, fn.index).end);
      for (const w of body.matchAll(new RegExp(`${WRITER}\\(\\s*&?[\\w.]+\\s*,\\s*([^,]+?)\\s*,`, "gu"))) {
        if (params.includes(w[1].trim().replace(/[^\w]/gu, ""))) forwarding.add(fn[1]);
      }
    }
    if (forwarding.size) {
      addSpans(new RegExp(`\\b(?:${[...forwarding].join("|")})\\(\\s*&?[\\w.]+\\s*,\\s*([^,]+?)\\s*,`, "gu"), "admits");
    }
    addSpans(new RegExp(`(?<![\\w])${READER}\\(\\s*&?[\\w.]+\\s*,\\s*([^,)]+?)\\s*[,)]`, "gu"), "reads");
    addSpans(/=>\s*Some\(\s*([^)]+?)\s*\)/gu, "resolves");
    for (const m of src.matchAll(/const\s+(\w+)\s*:\s*&'?\w*\s*str\s*=\s*"([^"]*)"/gu)) {
      if (!familyLiterals.has(m[2])) continue;
      const nameAt = m.index + m[0].indexOf(m[1]);
      spans.push({ start: nameAt, end: nameAt + m[1].length, kind: "declares" });
      const litAt = m.index + m[0].lastIndexOf(`"${m[2]}"`);
      spans.push({ start: litAt, end: litAt + m[2].length + 2, kind: "declares" });
    }
    for (const m of src.matchAll(/(?:pub(?:\s*\([^)]*\))?\s+)?use\s+[^;]*;/gu)) {
      for (const n of m[0].matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/gu)) {
        if (!familyNames.has(n[1])) continue;
        const at = m.index + m[0].indexOf(n[1]);
        spans.push({ start: at, end: at + n[1].length, kind: "imports" });
      }
    }
    for (const t of testRegions(src)) {
      if (!t.closed) { unclosedTestRegions.push(`${mod}@${t.start} opened and never closed`); continue; }
      spans.push({ start: t.start, end: t.end, kind: "test-fixture" });
    }

    for (const m of src.matchAll(mentionRe)) {
      const hit = spans.filter((sp) => m.index >= sp.start && m.index < sp.end)
        .sort((a, b) => (a.end - a.start) - (b.end - b.start))[0];
      mentions.push({ mod, index: m.index, text: m[0], kind: hit ? hit.kind : null });
    }
  }

  ok("every `#[cfg(test)]` region is ATTACHED to a `mod`/`fn`, is not the literal text inside a string, and CLOSES on a real brace — a region that runs to EOF, or one whose depth counter counted a brace inside `\"{\"`, silently reclassifies production code as a test fixture and waves a write through",
    unclosedTestRegions.length === 0, unclosedTestRegions.join(" ; ") || "all test regions closed");

  const unclassified = mentions.filter((m) => m.kind === null);
  ok("EVERY mention of an ontology-plane family in EVERY module of the binary lands in the closed vocabulary {admits, reads, resolves, declares, imports, test-fixture} — patterns do not define this census, classification of every mention does, and an unreadable or ambiguously-named mention is RED rather than silently dropped",
    mentions.length > 0 && unclassified.length === 0,
    unclassified.length
      ? `UNCLASSIFIED: ${unclassified.slice(0, 6).map((m) => `${m.mod}:${m.text}@${m.index}`).join(" ; ")}`
      : `${mentions.length} mentions, all classified`);

  // ------------------------------------------------------------ the entailment
  for (const [lit, owner] of Object.entries(FAMILIES)) {
    const got = [...admits.get(lit)].sort();
    ok(`EXACTLY ONE module admits \`${lit}\` — and it is \`${owner}\`; a write anywhere else counts here whether it sits in production or in a test block, because a test is not a licence to hold a second admission path`,
      got.length === 1 && got[0] === owner,
      `admitted by [${got.join(",") || "none"}]`);
  }

  ok("and the family table itself is not STALE — every family this census names is still declared somewhere in the daemon, so a family renamed out from under the table cannot leave the four assertions above quietly true over nothing",
    [...familyLiterals].every((lit) => [...constsOf.values()].some((m2) => [...m2.values()].includes(lit))
      || [...sources.values()].some((s) => s.includes(`"${lit}"`))),
    [...familyLiterals].join(" "));

  // ------------------------------------------------------------ resolver flow
  // EVERY `resolves` MENTION, BY THE FUNCTION IT SITS IN. The first rule inspected only the shape
  // `let x = match y { … };` while the CLASSIFIER accepted any `=> Some(X)` arm — so a mapper
  // written `match scheme.as_str()`, or as a function returning the match, or nested one block
  // deeper, classified as `resolves` and was never flow-checked at all. The rule is now structural
  // and needs no dataflow: A FUNCTION THAT RESOLVES A FAMILY NAME MAY NOT ALSO WRITE A RECORD.
  // A scheme-mapper that admits is the second spine this assertion exists to refuse, and a function
  // doing both is that, whatever the plumbing between them looks like.
  const resolverFns = [];
  for (const [f, src] of sources) {
    const mod = modName(f);
    for (const m of src.matchAll(/=>\s*Some\(\s*([^)]+?)\s*\)/gu)) {
      const lit = resolveArg(mod, m[1]);
      if (!lit || lit === AMBIGUOUS || !familyLiterals.has(lit)) continue;
      const fnStart = Math.max(src.lastIndexOf("\nfn ", m.index), src.lastIndexOf("\npub", m.index),
        src.lastIndexOf("\n    fn ", m.index), 0);
      const { end } = matchBrace(src, fnStart);
      const body = src.slice(fnStart, Math.max(end, m.index));
      const writes = [...body.matchAll(new RegExp(`${WRITER}\\(`, "gu"))].map((w) => w[0]);
      resolverFns.push({ mod, at: m.index, writes });
    }
  }
  const resolverWriters = resolverFns.filter((r) => r.writes.length);
  ok("no function that RESOLVES a family name also writes a record — the generic `\"ontology\" => Some(...)` arms in governance and marketplace are the shape that becomes a second admission path the moment the resolved name reaches a writer, and a function doing both is that path whatever the plumbing between them looks like",
    resolverFns.length > 0 && resolverWriters.length === 0,
    resolverWriters.length
      ? `RESOLVES AND WRITES: ${resolverWriters.map((r) => `${r.mod}@${r.at}->${[...new Set(r.writes)].join(",")}`).join(" ; ")}`
      : `${resolverFns.length} resolving site(s) in [${[...new Set(resolverFns.map((r) => r.mod))].sort().join(",")}], none writes`);

  // ------------------------------------------------------------ raw filesystem writes
  const rawWrites = [];
  const FS_WRITE = /(?:fs\s*::\s*(?:write|create|create_new|create_dir_all|remove_file|remove_dir_all|copy|rename|hard_link|OpenOptions)|File\s*::\s*create)/gu;
  for (const [f, src] of sources) {
    const mod = modName(f);
    const tests = testRegions(src).filter((t) => t.closed);
    const inTest = (i) => tests.some((t) => i >= t.start && i < t.end);
    for (const m of src.matchAll(FS_WRITE)) {
      if (inTest(m.index)) continue;
      const tail = src.slice(m.index, m.index + 400);
      for (const tok of tail.matchAll(/"([^"]+)"|\b([A-Z][A-Z0-9_]{2,})\b/gu)) {
        const lit = tok[1] ?? resolveArg(mod, tok[2]);
        if (lit && lit !== AMBIGUOUS && familyLiterals.has(lit)) rawWrites.push(`${mod}->${lit} @${m.index}`);
      }
    }
  }
  ok("no PRODUCTION raw filesystem write in this daemon targets an ontology-plane family, with the family resolved through module-scoped constants and not just literals — a DENYLIST bounding a known attack, not a proof that no raw write exists; the per-family entailment above is what carries the claim",
    rawWrites.length === 0, [...new Set(rawWrites)].join(" ; ") || "no denylisted raw write outside closed test regions");

  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "ontology-admission-census", sourceUrl: import.meta.url, results });
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length) process.exit(1);
}

// Run only when invoked, never on import: a module with top-level side effects is the hazard that
// left a mutant in the tree when XIII imported one from a `node -e` one-liner.
const INVOKED = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED) {
  try { run(); } catch (error) {
    console.error(`FAIL ontology-admission-census — ${error?.stack || error}`);
    process.exit(1);
  }
}
