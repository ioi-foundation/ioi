#!/usr/bin/env node

// Handler-level classification for MEF-GAP-008.
//
// The file-level census (audit-daemon-mutation-foundation.mjs) counts INDICATORS. This one applies
// MEF-GAP-001's discriminator per handler, which is what the gap actually asks for:
//
//   (1) the handler returns SUCCESS on a path where a write was discarded, AND
//   (2) the written record kind is READ BACK as state elsewhere in the daemon.
//
// Both widenings recorded in MEF-GAP-008.classifier_coverage_defect are applied here, because the
// hand-built list they were derived from missed eleven handlers across four already-audited modules:
//
//   * Test (1) is NOT "the response embeds the written record". A handler returning a CLAIM about
//     the record — {ok:true, connected:true} over two discarded writes — is equally defective.
//     Success is any 2xx status or an `"ok": true` body reachable after the discarded write.
//   * A discarded write is not only `let _ = persist_record(`. A bare `remove_record(..);`
//     statement whose bool is dropped is the same defect wearing different syntax, and
//     `remove_record` cannot distinguish "nothing was there" from "deletion failed" in either form.
//
// This reports a CANDIDATE SET. A candidate is a lead, not a finding: the gap's own rule is that
// each handler still needs its own reading before it is called a defect. What this guarantees is
// that the reading list is not silently short.

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const routeRoot = path.join(repoRoot, "crates/node/src/bin/hypervisor_daemon_routes");
const registryPath = path.join(
  repoRoot,
  "docs/architecture/_meta/mutation-event-foundation-coverage.v1.json",
);
const relative = (absolute) => path.relative(repoRoot, absolute).split(path.sep).join("/");

// Blank out line comments, block comments and string literals so brace matching and call detection
// cannot be thrown off by punctuation inside them. Offsets are preserved by replacing in place.
function blankNonCode(source) {
  const out = source.split("");
  let i = 0;
  const blank = (from, to) => {
    for (let j = from; j < to && j < out.length; j += 1) {
      if (out[j] !== "\n") out[j] = " ";
    }
  };
  while (i < source.length) {
    const two = source.slice(i, i + 2);
    if (two === "//") {
      const end = source.indexOf("\n", i);
      const stop = end === -1 ? source.length : end;
      blank(i, stop);
      i = stop;
    } else if (two === "/*") {
      const end = source.indexOf("*/", i + 2);
      const stop = end === -1 ? source.length : end + 2;
      blank(i, stop);
      i = stop;
    } else if (/^r#*"/u.test(source.slice(i, i + 8))) {
      // Rust raw string: r"..." or r#"..."# with matching hash counts.
      const hashes = /^r(#*)"/u.exec(source.slice(i, i + 8))[1];
      const terminator = `"${hashes}`;
      const end = source.indexOf(terminator, i + hashes.length + 2);
      const stop = end === -1 ? source.length : end + terminator.length;
      blank(i, stop);
      i = stop;
    } else if (source[i] === "'" && /^'(?:\\.|[^\\'])'/u.test(source.slice(i, i + 5))) {
      // Rust CHAR literal. This must be consumed BEFORE the string branch: `.trim_matches('"')`
      // contains a double-quote, and treating it as a string opener blanks everything up to the
      // next quote — which silently swallowed whole handler signatures and made this checker
      // report false negatives against handlers it had already been shown.
      const width = /^'(?:\\.|[^\\'])'/u.exec(source.slice(i, i + 5))[0].length;
      blank(i, i + width);
      i += width;
    } else if (source[i] === '"') {
      let j = i + 1;
      while (j < source.length) {
        if (source[j] === "\\") j += 2;
        else if (source[j] === '"') break;
        else j += 1;
      }
      blank(i + 1, j);
      i = j + 1;
    } else {
      i += 1;
    }
  }
  return out.join("");
}

// Brace-match a body starting from the `{` at or after `from`. Returns [open, close] or null.
function bodySpan(code, from) {
  const open = code.indexOf("{", from);
  if (open === -1) return null;
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    if (code[i] === "{") depth += 1;
    else if (code[i] === "}") {
      depth -= 1;
      if (depth === 0) return [open, i];
    }
  }
  return null;
}

// Every fn in a module — not just handlers. A discarded write is just as lost when it sits in a
// helper the handler calls: `handle_editor_services_list` reaches one through `save_service`, and
// scanning only handler bodies missed it and four others the hand-built list had caught.
function allFnSpans(code) {
  const spans = [];
  const signature = /(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*[(<]/gu;
  let match;
  while ((match = signature.exec(code)) !== null) {
    const span = bodySpan(code, match.index);
    if (!span) continue;
    spans.push({ name: match[1], start: span[0], end: span[1] });
  }
  return spans;
}

// Span of every `pub(crate) async fn handle_*` body, by brace matching over blanked code.
function handlerSpans(code) {
  const spans = [];
  const signature = /pub\(crate\)\s+async\s+fn\s+(handle_[A-Za-z0-9_]*)\s*\(/gu;
  let match;
  while ((match = signature.exec(code)) !== null) {
    const open = code.indexOf("{", match.index);
    if (open === -1) continue;
    let depth = 0;
    let end = -1;
    for (let i = open; i < code.length; i += 1) {
      if (code[i] === "{") depth += 1;
      else if (code[i] === "}") {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }
    if (end === -1) continue;
    // The return type decides what "returns success" means. A handler declared `-> Json<Value>`
    // has an IMPLICIT 200: axum serializes the body with no status of its own, so a plain
    // `Json(json!({ "binding": .. }))` after a discarded write is a success response even though it
    // carries neither `StatusCode::OK` nor `"ok": true`. Requiring an explicit success marker made
    // this checker miss handle_binding_create — one of the two handlers the gap had already
    // hand-verified as a defect.
    const returnType = code.slice(match.index, open);
    spans.push({ name: match[1], start: open, end, implicit200: !returnType.includes("StatusCode") });
  }
  return spans;
}

// Split a call's argument list on top-level commas.
function callArgs(code, openParen) {
  const args = [];
  let depth = 0;
  let current = "";
  for (let i = openParen; i < code.length; i += 1) {
    const ch = code[i];
    if (ch === "(" || ch === "[" || ch === "{") depth += 1;
    if (ch === ")" || ch === "]" || ch === "}") {
      depth -= 1;
      if (depth === 0) {
        args.push(current.trim());
        return args;
      }
    }
    if (ch === "," && depth === 1) {
      args.push(current.trim());
      current = "";
      continue;
    }
    if (depth >= 1 && !(depth === 1 && ch === "(" && i === openParen)) current += ch;
  }
  return args;
}

// Every discarded write inside [start,end), with the record kind it targets.
// `raw` is the ORIGINAL source: kinds are string literals, which are blanked in `code`.
function discardedWrites(code, raw, start, end) {
  const found = [];
  const patterns = [
    { re: /let\s+_\s*=\s*(?:super::)?persist_record\s*\(/gu, form: "let _ = persist_record" },
    { re: /let\s+_\s*=\s*(?:super::)?remove_record\s*\(/gu, form: "let _ = remove_record" },
    // Bare statement form: the bool is dropped without even `let _ =`. Preceded by a statement
    // boundary so `if remove_record(..)` and `= remove_record(..)` are not matched.
    { re: /(?:^|[{};])\s*(?:super::)?remove_record\s*\(/gmu, form: "bare remove_record" },
  ];
  for (const { re, form } of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) !== null) {
      if (m.index < start || m.index >= end) continue;
      const open = code.indexOf("(", m.index + (m[0].endsWith("(") ? m[0].length - 1 : 0));
      const args = callArgs(raw, open);
      // A write that has been deliberately classified as tolerable carries its reasoning in a
      // `CLASSIFIED` comment directly above it. Without this the checker can never go green:
      // MEF-GAP-001's acceptance explicitly allows "intentionally best-effort" as an outcome, and
      // a gate that cannot represent its own allowed outcomes is not a gate. It also stops the
      // call-graph closure dragging read-only handlers in — handle_policies_get merely calls
      // ensure_policy_seed, whose tolerated write is classified at its site.
      const preceding = raw.slice(Math.max(0, m.index - 600), m.index);
      const classified = /\/\/[^\n]*\bCLASSIFIED\b/u.test(preceding.split("\n").slice(-12).join("\n"));
      found.push({ form, offset: m.index, kind: (args[1] || "").trim(), classified });
    }
  }
  return found.sort((a, b) => a.offset - b.offset);
}

// Is a SUCCESS response reachable after `offset`?
//
// For a handler carrying explicit statuses, that means a 2xx or an `"ok": true`-shaped body. For an
// implicit-200 handler (`-> Json<Value>`), ANY response after the write is a 200 unless everything
// remaining is an explicit failure body — so the absence of a success marker proves nothing.
//
// This errs toward inclusion on purpose. The output is a candidate set that a human then reads;
// over-inclusion costs a reading, under-inclusion is the defect being repaired here.
function successAfter(code, raw, offset, end, implicit200) {
  const region = raw.slice(offset, end);
  const codeRegion = code.slice(offset, end);
  const explicitSuccess =
    /StatusCode::(OK|CREATED|ACCEPTED|NO_CONTENT)/u.test(codeRegion) ||
    /"ok"\s*:\s*true/u.test(region) ||
    /"connected"\s*:\s*true/u.test(region) ||
    /"ok"\s*:\s*removed/u.test(region);
  if (explicitSuccess) return true;
  if (!implicit200) return false;
  const returnsSomething = /\bJson\s*\(/u.test(codeRegion);
  const onlyFailureBodies =
    /"ok"\s*:\s*false/u.test(region) && !/Json\s*\(\s*json!\(\{\s*"[a-z_]+"\s*:/u.test(region);
  return returnsSomething && !onlyFailureBodies;
}

const routeFiles = (await readdir(routeRoot, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith(".rs"))
  .map((entry) => path.join(routeRoot, entry.name));
const sourceFiles = [path.join(repoRoot, "crates/node/src/bin/hypervisor-daemon.rs"), ...routeFiles];

const files = new Map();
for (const sourcePath of sourceFiles) {
  const raw = await readFile(sourcePath, "utf8");
  files.set(sourcePath, { raw, code: blankNonCode(raw) });
}

// Test (2): is this record kind read back anywhere? A kind is read back when its token appears in
// a call that is not a write. Kinds arrive as a literal (`"connectors"`) or a constant
// (`ACCOUNT_KIND`); for constants the token itself is searched, for literals the quoted form.
const READERS = [
  "read_record_dir",
  "find_by_key",
  "load_record",
  "read_owner_scoped_head",
  "read_owner_scoped_history",
];
function isReadBack(kind) {
  if (!kind) return false;
  const token = kind.startsWith('"') ? kind : kind.replace(/^&/u, "");
  for (const { raw } of files.values()) {
    for (const reader of READERS) {
      const re = new RegExp(
        `${reader}\\s*\\([^;]{0,160}${token.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`,
        "u",
      );
      if (re.test(raw)) return true;
    }
    // `load(data_dir, KIND, id)` and `Path::new(dir).join(KIND)` are the module-local read shapes.
    const local = new RegExp(
      `(?:\\bload\\s*\\(|\\.join\\s*\\()[^;]{0,120}${token.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&")}`,
      "u",
    );
    if (local.test(raw)) return true;
  }
  return false;
}

const readBackCache = new Map();
const readBack = (kind) => {
  if (!readBackCache.has(kind)) readBackCache.set(kind, isReadBack(kind));
  return readBackCache.get(kind);
};

const byModule = {};
const distinctWriteSites = new Set();
let classifiedTolerated = 0;
let handlersWithDiscards = 0;
let bothTests = 0;
let neverReadBack = 0;
const detail = [];

for (const [sourcePath, { raw, code }] of files) {
  const moduleName = path.basename(sourcePath);

  // Per-module call graph over local fns, so writes reached through helpers are attributed to the
  // handler that reaches them. Transitive, so a helper calling a helper still counts.
  const fns = allFnSpans(code);
  const ownWrites = new Map();
  const callees = new Map();
  const fnNames = new Set(fns.map((f) => f.name));
  for (const fn of fns) {
    ownWrites.set(fn.name, discardedWrites(code, raw, fn.start, fn.end));
    const called = new Set();
    const callRe = /([A-Za-z0-9_]+)\s*\(/gu;
    let c;
    const body = code.slice(fn.start, fn.end);
    while ((c = callRe.exec(body)) !== null) {
      if (fnNames.has(c[1]) && c[1] !== fn.name) called.add(c[1]);
    }
    callees.set(fn.name, called);
  }
  const reachableWrites = (name, seen = new Set()) => {
    if (seen.has(name)) return [];
    seen.add(name);
    const out = [...(ownWrites.get(name) ?? [])];
    for (const callee of callees.get(name) ?? []) out.push(...reachableWrites(callee, seen));
    return out;
  };

  for (const span of handlerSpans(code)) {
    const inline = discardedWrites(code, raw, span.start, span.end);
    const viaHelpers = reachableWrites(span.name).filter(
      (w) => w.offset < span.start || w.offset >= span.end,
    );
    const allWrites = [...inline, ...viaHelpers];
    classifiedTolerated += allWrites.filter((w) => w.classified).length;
    // Classified writes are a recorded disposition, not an open candidate.
    const writes = allWrites.filter((w) => !w.classified);
    if (writes.length === 0) continue;
    handlersWithDiscards += 1;
    // An inline write is judged from its own position; a write inside a helper has no position in
    // this body, so the whole handler counts as "after" it.
    const succeeds = writes.some((w) =>
      w.offset >= span.start && w.offset < span.end
        ? successAfter(code, raw, w.offset, span.end, span.implicit200)
        : successAfter(code, raw, span.start, span.end, span.implicit200),
    );
    const anyReadBack = writes.some((w) => readBack(w.kind));
    if (succeeds && anyReadBack) {
      bothTests += 1;
      for (const w of writes) distinctWriteSites.add(`${moduleName}:${w.offset}`);
      (byModule[moduleName] ||= []).push(span.name);
      detail.push({
        module: moduleName,
        handler: span.name,
        kinds: [...new Set(writes.map((w) => w.kind))],
        forms: [...new Set(writes.map((w) => w.form))],
        discarded_writes: writes.length,
      });
    } else if (succeeds && !anyReadBack) {
      neverReadBack += 1;
    }
  }
}

for (const key of Object.keys(byModule)) byModule[key].sort();
const sortedModules = Object.fromEntries(
  Object.entries(byModule).sort(([a], [b]) => b.length - a.length || a.localeCompare(b)),
);

const registry = JSON.parse(await readFile(registryPath, "utf8"));
const gap = registry.open_gaps.find((entry) => entry.id === "MEF-GAP-008");
const declared = gap?.handler_level_classification?.meets_both_tests_by_module ?? {};
const declaredSet = new Set(Object.values(declared).flat());
const foundSet = new Set(Object.values(sortedModules).flat());
const missingFromRegistry = [...foundSet].filter((h) => !declaredSet.has(h)).sort();
const closedSinceRegistry = [...declaredSet].filter((h) => !foundSet.has(h)).sort();

const output = {
  schema_version: "ioi.hypervisor.mutation_handler_classification.v1",
  method:
    "MEF-GAP-001's discriminator per handler, with both widenings from " +
    "MEF-GAP-008.classifier_coverage_defect applied: success is any 2xx or ok:true reachable after " +
    "the discarded write (not only a response embedding the record), and a bare `remove_record(..);` " +
    "statement counts as a discarded write alongside `let _ = persist_record(`.",
  candidate_set_not_defect_count:
    "Each handler still needs its own reading before it is called a defect.",
  totals: {
    handlers_with_discarded_writes: handlersWithDiscards,
    both_tests_hold: bothTests,
    success_but_kind_never_read_back: neverReadBack,
    // The handler count is EXPOSURE and double-counts by design: one shared helper holding a
    // discarded write is reached by every handler that calls it. The actionable unit is the write
    // SITE, so both are reported and neither is presented as the other.
    distinct_write_sites: distinctWriteSites.size,
    // Writes carrying a `CLASSIFIED` comment: a recorded disposition, not an open candidate.
    classified_tolerated_reaches: classifiedTolerated,
  },
  registry_delta: {
    registry_both_tests_hold: declaredSet.size,
    found_both_tests_hold: foundSet.size,
    in_source_but_absent_from_registry: missingFromRegistry,
    in_registry_but_no_longer_present: closedSinceRegistry,
  },
  meets_both_tests_by_module: sortedModules,
  detail: detail.sort(
    (a, b) => a.module.localeCompare(b.module) || a.handler.localeCompare(b.handler),
  ),
};

process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);

if (process.argv.includes("--check") && missingFromRegistry.length > 0) {
  process.stderr.write(
    `handler classification is stale: ${missingFromRegistry.length} handlers meet both tests in ` +
      "source but are absent from MEF-GAP-008; classify them or record why they are not owed\n",
  );
  process.exitCode = 1;
}
