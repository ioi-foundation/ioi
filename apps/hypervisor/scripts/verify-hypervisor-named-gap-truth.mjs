#!/usr/bin/env node
// NAMED-GAP TRUTH — every reason and user-reaching string checked AT ITS EMISSION POINT against the
// router, derived from source rather than grepped.
//
// WHY THIS EXISTS. Next-legs XIII spent SIX merge-blocking rounds chasing one class by hand: a named
// gap whose stated reason had gone false. It lived in the depth ledger's prose, then in the
// machine-readable `outcome`, then in the string the product renders; then in one journey of three;
// then in the atlas's `missing_authority_contracts`, a workflow line, a landing note, a security
// paragraph keyed on the plane NOT existing, and two `aria-label`s carrying the replaced word on the
// same lines whose `title` had just been fixed. Six rounds did not converge, and TWO SURVIVORS WERE
// INVISIBLE TO GREP:
//
//   - a green, CI-wired, floor-pinned gate asserting two families were ABSENT while probing
//     `/domain-ontologies/:id/proposals` — a URL that was never a route in any build — so it could
//     not have failed in any world, and grepping the family names could never have found it;
//   - a verifier's expected-string pinning the OLD wording, so correcting the falsehood turned that
//     gate red and the wording became load-bearing.
//
// Hand-correction does not converge and grep is not the instrument. This is the gate XIII filed and
// XIV Leg 3b commissioned.
//
// WHAT IT ENTAILS, and the discipline it follows. The stripper lesson from Leg 3a generalises: an
// assertion must check THE HALF THAT CARRIES THE FINDING. For a reason string, the half that carries
// the finding is not whether the sentence is well-formed — it is WHETHER THE THING IT NAMES EXISTS.
// So every emission is classified by its POLARITY and checked against the router:
//
//   POSITIVE — the reason names a route as existing ("the plane exists as daemon truth (POST /x)").
//              Every route it names MUST be registered. A reason that credits a plane the daemon
//              does not serve is a falsehood in the other direction, and this run produced one.
//   NEGATIVE — the reason asserts an absence ("no object-instance search plane") AND names a route.
//              Every route it names MUST NOT be registered. This is the XIII class proper.
//
// And for verifiers specifically: A PROBE THAT ASSERTS AN ABSENCE MUST PROBE A REAL ROUTE. Asserting
// "the family is absent" against a URL the router never had proves nothing about the family, and
// that is the survivor grep could not see.
//
// WHAT IT DOES NOT ENTAIL, so the label claims only what it checks. A reason that asserts an absence
// WITHOUT naming a route is not decidable from source here — "no branching plane exists" names no
// path, and mapping prose to routes by keyword would be the grep this gate exists to replace. Those
// are counted and reported as UNDECIDABLE, deliberately visible, rather than passed over in silence.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = process.env.IOI_GAPTRUTH_ROOT || path.resolve(HERE, "..", "..", "..");
const APP = path.join(ROOT, "apps/hypervisor");
const DAEMON_MAIN = path.join(ROOT, "crates/node/src/bin/hypervisor-daemon.rs");
const ATLAS = path.join(APP, "application-operational-depth.json");
const SURFACES = path.join(APP, "surfaces");
const SCRIPTS = path.join(APP, "scripts");

const results = [];
const ok = (name, cond, detail) => results.push({ name, pass: !!cond, detail: detail || "" });

/**
 * Every route the daemon registers, as `path -> Set(method)`.
 *
 * METHODS MATTER, and the gate's first run proved it. The atlas says
 * `PATCH/PUT /v1/hypervisor/data-sources/:id — … (route :id is GET-only; no update authority)`.
 * That claim is TRUE and precise: the path exists, the methods do not. A path-only check called it
 * a falsified reason. An assertion that cannot tell a missing METHOD from a missing PATH is not
 * checking the half that carries the finding.
 */
export function registeredRoutes(src) {
  const out = new Map();
  for (const m of src.matchAll(/\.route\(\s*"([^"]+)"\s*,([\s\S]*?)\n\s*\)/gu)) {
    const methods = new Set([...m[2].matchAll(/(?<![a-z_])(get|post|patch|put|delete)\s*\(/gu)].map((x) => x[1].toUpperCase()));
    out.set(m[1], new Set([...(out.get(m[1]) ?? []), ...methods]));
  }
  return out;
}

/** Does the router serve this path (any method, or a specific one), allowing `:param` segments? */
export function routeExists(routes, candidate, method = null) {
  const clean = candidate.replace(/\/+$/u, "");
  const check = (ms) => (method ? ms.has(method) : ms.size > 0);
  if (routes.has(clean)) return check(routes.get(clean));
  const parts = clean.split("/");
  for (const [r, ms] of routes) {
    const rp = r.split("/");
    if (rp.length !== parts.length) continue;
    if (rp.every((seg, i) => seg.startsWith(":") || seg === parts[i])) return check(ms);
  }
  return false;
}

/**
 * The CLAUSE a route mention sits in.
 *
 * Polarity belongs to the sentence making the claim, not to the paragraph containing it. Run over a
 * whole 400-character note, the word "No" in `'No requests found.'` — a quoted UI string about
 * DATA — made an unrelated approvals route read as a falsified reason. The finding is carried by the
 * clause that names the route.
 */
export function clauseAround(text, at) {
  const before = Math.max(
    text.lastIndexOf(". ", at), text.lastIndexOf("; ", at),
    text.lastIndexOf(" — ", at), text.lastIndexOf("\n", at), -1,
  );
  let after = text.length;
  for (const sep of [". ", "; ", " — ", "\n"]) {
    const i = text.indexOf(sep, at);
    if (i !== -1 && i < after) after = i;
  }
  return text.slice(before + 1, after);
}

// POLARITY COMES FROM THE FIELD, NOT FROM THE PROSE.
//
// The first cut inferred polarity by regex over the sentence, and its own first run showed why that
// is the wrong layer: `"absent FROM THIS SURFACE"` is a scoped claim, not a route claim;
// `"daemon exposes GET /x …, no FEDERATED search"` is positive about the route it names and negative
// about a different capability; `"read from GET /x (no fabricated fields)"` negates FIELDS. English
// negation scope is not a finite construct class — unlike Rust syntax, there is no complete set of
// forms to model — so inferring it is the unbounded version of the problem this gate exists to end.
//
// The atlas already declares what each field MEANS. `existing_daemon.actions` lists routes the daemon
// SERVES; `missing_authority_contracts` lists authority that is ABSENT. That is the emission's own
// declared semantics, it is machine-readable, and it is what the check keys on. Prose that names a
// route without a field semantics is counted as UNDECIDABLE and reported.
const FIELD_POLARITY = [
  [/(?:^|\.)existing_daemon\.actions(\[|$)/u, "positive"],
  [/(?:^|\.)missing_authority_contracts(\[|$)/u, "negative"],
];
// Used ONLY to decide whether a VERIFIER LABEL claims an absence — a much narrower job than
// deciding prose polarity in general, because a verifier label is a single written assertion about
// one probe, and the failure mode it guards (a probe against a URL that was never a route) is
// visible from the probe itself regardless of how the label is worded.
const ABSENCE_LABEL = /\b(absent|does not exist|no .{0,24}(?:plane|family|route|contract))\b/iu;
const fieldPolarity = (where) => FIELD_POLARITY.find(([re]) => re.test(where))?.[1] ?? null;

const ROUTE_IN_TEXT = /\/v1\/hypervisor\/[A-Za-z0-9/_:-]+/gu;

/** Walk every string in a JSON value, with a dotted path for the diagnostic. */
function* jsonStrings(node, at = "") {
  if (typeof node === "string") { yield [at, node]; return; }
  if (Array.isArray(node)) { for (let i = 0; i < node.length; i += 1) yield* jsonStrings(node[i], `${at}[${i}]`); return; }
  if (node && typeof node === "object") { for (const [k, v] of Object.entries(node)) yield* jsonStrings(v, at ? `${at}.${k}` : k); }
}

const listFiles = (dir, pred) => {
  const out = [];
  const walk = (d) => {
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (pred(full)) out.push(full);
    }
  };
  walk(dir);
  return out.sort();
};

function run() {
  const routerSrc = fs.readFileSync(DAEMON_MAIN, "utf8");
  const routes = registeredRoutes(routerSrc);
  ok("the router's registered route set is DERIVED from the daemon source, not listed — every claim below is checked against what this binary actually serves",
    routes.size > 200 && routes.get("/v1/hypervisor/odk/object-instance-search")?.has("POST"),
    `${routes.size} registered routes, method-aware`);

  // ------------------------------------------------------------ emission sites, closed world
  const emissions = [];
  const atlas = JSON.parse(fs.readFileSync(ATLAS, "utf8"));
  for (const [at, text] of jsonStrings(atlas)) {
    if (text.length < 12) continue;
    emissions.push({ site: "atlas", where: at, text });
  }
  for (const f of listFiles(SURFACES, (p) => p.endsWith(".mjs"))) {
    const src = fs.readFileSync(f, "utf8");
    // The strings a USER receives: a rendered title, an aria-label, a declared gap reason. XIII left
    // an `aria-label` carrying the replaced word on the same line whose `title` had just been fixed,
    // and the accessible name is the only text an assistive-technology user gets.
    for (const m of src.matchAll(/(?:title|aria-label)="([^"]{12,})"|\breason:\s*"([^"]{12,})"|\bgap:\s*"([^"]{12,})"/gu)) {
      emissions.push({ site: `surface:${path.basename(path.dirname(f))}`, where: `@${m.index}`, text: m[1] ?? m[2] ?? m[3] });
    }
  }
  for (const f of listFiles(SCRIPTS, (p) => /verify-hypervisor-.*\.mjs$/u.test(p))) {
    const src = fs.readFileSync(f, "utf8");
    for (const m of src.matchAll(/\bok\(\s*(?:`([^`]{12,})`|"([^"]{12,})")/gu)) {
      emissions.push({ site: `verifier:${path.basename(f, ".mjs")}`, where: `@${m.index}`, text: m[1] ?? m[2], verifier: f });
    }
  }
  ok("the emission world is DERIVED by walking the atlas, every surface module and every verifier — a reason lives wherever it is EMITTED, and two of XIII's six rounds missed a survivor precisely because they searched for family names rather than for the places a claim is made",
    emissions.length > 500,
    `${emissions.length} emissions across atlas, surfaces and verifiers`);

  // ------------------------------------------------------------ polarity + route truth
  const falseNegatives = [];   // a field declaring an absence names a route that EXISTS
  const falsePositives = [];   // a field declaring existence names a route that does NOT
  let undecidable = 0;
  let decided = 0;
  for (const e of emissions) {
    const polarity = e.site === "atlas" ? fieldPolarity(e.where) : null;
    for (const m of e.text.matchAll(ROUTE_IN_TEXT)) {
      const r = m[0].replace(/[.,;:)]+$/u, "");
      if (!polarity) { undecidable += 1; continue; }
      const clause = clauseAround(e.text, m.index);
      const methods = [...new Set([...clause.matchAll(/\b(GET|POST|PATCH|PUT|DELETE)\b/gu)].map((x) => x[1]))];
      decided += 1;
      // THE TWO DIRECTIONS ASK DIFFERENT QUESTIONS, and conflating them made the positive side
      // noisy. `existing_daemon.actions` writes the compact family form `POST/PATCH/DELETE /x`,
      // meaning the FAMILY serves those verbs across `/x` and `/x/:id` — so the decidable claim
      // there is that the family's path is served at all. A MISSING-authority claim is method-
      // precise by nature ("PATCH/PUT /x — route is GET-only"), so that side keeps the method check.
      const exists = polarity === "positive"
        ? (routeExists(routes, r) || routeExists(routes, `${r}/:id`))
        : (methods.length ? methods.some((mm) => routeExists(routes, r, mm)) : routeExists(routes, r));
      if (polarity === "negative" && exists) {
        falseNegatives.push(`${e.where}: declares MISSING authority, but ${methods.join("/") || "some method on"} ${r} IS registered`);
      }
      if (polarity === "positive" && !exists) {
        falsePositives.push(`${e.where}: declares the daemon SERVES ${methods.join("/") || ""} ${r}, which is NOT registered`);
      }
    }
  }

  ok("NO FIELD DECLARING AN AUTHORITY MISSING NAMES A ROUTE THIS DAEMON SERVES — the falsified-reason class proper, keyed on the atlas's OWN declared field semantics rather than on parsing English negation, and checked against the router at the point the claim is emitted",
    decided > 0 && falseNegatives.length === 0,
    falseNegatives.length ? `FALSIFIED: ${falseNegatives.slice(0, 6).join(" ; ")}` : `${decided} route-naming claims checked`);

  ok("and NO FIELD DECLARING WHAT THE DAEMON SERVES NAMES A ROUTE IT DOES NOT — a correction that overclaims is the same defect facing the other way, and this gate found four on its first run, credited `[EXISTS]` at paths the router never had",
    falsePositives.length === 0,
    falsePositives.length ? `OVERCLAIMED: ${falsePositives.slice(0, 6).join(" ; ")}` : "no emission credits an unregistered route");

  // ------------------------------------------------------------ the survivor grep could not see
  // A verifier that asserts an ABSENCE by probing a URL proves nothing unless the URL is a route the
  // daemon would serve if the family existed. XIII's gate probed `/domain-ontologies/:id/proposals`
  // — never a route in any build — and answered 404 for a reason having nothing to do with its
  // subject, so it could not have failed in any world.
  const decorativeProbes = [];
  for (const f of listFiles(SCRIPTS, (p) => /verify-hypervisor-.*\.mjs$/u.test(p))) {
    const src = fs.readFileSync(f, "utf8");
    // THE PROBE PRECEDES THE LABEL. A first cut searched FORWARD from `ok(` and found nothing,
    // because this estate writes `const x = await jd("/route"); ok("… absent …", x.status === 404)`.
    // Looking only downstream of the assertion misses the request the assertion is about — which is
    // the half that carries the finding. Probes are bound to their VARIABLE, then the variable is
    // looked up from the label.
    // THE FIRST DAEMON ROUTE IN THE CALL, whatever the helper's signature. This estate writes both
    // `jd(url)` and `jd(method, url)`, so taking argument one captured the string "POST" as a URL.
    // And only `/v1/hypervisor/...` paths are in scope: `/__ioi/...` is served by the product-UI
    // serve lane, not by the daemon router this gate checks against, so judging those here would be
    // comparing a claim to the wrong authority.
    const probeOf = new Map();
    for (const m of src.matchAll(/(?:const|let)\s+(\w+)\s*=\s*await\s+\w+\(([^;]{0,200})/gu)) {
      const url = /["'`](\/v1\/hypervisor\/[^"'`]*)["'`]/u.exec(m[2])?.[1];
      if (url) probeOf.set(m[1], url);
    }
    for (const m of src.matchAll(/\bok\(\s*(?:`([^`]{12,})`|"([^"]{12,})")([\s\S]{0,400}?)\)\s*;/gu)) {
      const label = m[1] ?? m[2];
      if (!ABSENCE_LABEL.test(label)) continue;
      const body = m[3] ?? "";
      const urls = new Set();
      for (const u of body.matchAll(/["'`](\/v1\/hypervisor\/[A-Za-z0-9/_${}.:-]*)["'`]/gu)) urls.add(u[1]);
      for (const v of body.matchAll(/\b(\w+)\b/gu)) if (probeOf.has(v[1])) urls.add(probeOf.get(v[1]));
      for (const raw of urls) {
        const probed = raw.replace(/\$\{[^}]*\}/gu, ":id").replace(/[?].*$/u, "").replace(/\/+$/u, "");
        // An interpolated probe that does not resolve to a concrete path shape is not evidence of a
        // decorative probe — it is a path this gate cannot read, and saying so is the honest answer.
        if (!probed.startsWith("/v1/hypervisor/")) continue;
        if (routeExists(routes, probed)) continue;
        // THE DEFECT IS NOT "PROBED AN UNREGISTERED PATH" — that is how one honestly demonstrates a
        // family the daemon genuinely lacks, and this estate does it deliberately (`no versions
        // route`, probed at the path a versions route would occupy). The defect is probing the WRONG
        // PATH FOR A FAMILY THAT EXISTS: XIII's survivor asserted the proposal family absent against
        // `/domain-ontologies/:id/proposals` while the family was live at `/odk/ontology-proposals`,
        // so it answered 404 for a reason having nothing to do with its subject. The separator is
        // whether the family noun this probe names is served ANYWHERE.
        // THE FAMILY IS THE PROBE'S OWN PATH PREFIX. Deriving it from the label re-introduced the
        // unbounded English problem this gate already refused for polarity: the automations label
        // mentions "cancel" and "revisions" in passing, which matched `/v1/threads/:id/cancel` and
        // an unrelated artifacts family. The decidable question is narrow and structural — does the
        // SAME family serve, at a different path, the thing this probe claims is absent?
        // XIII's survivor: probe `/v1/hypervisor/odk/domain-ontologies/:id/proposals`, family
        // `/v1/hypervisor/odk`, and `/v1/hypervisor/odk/ontology-proposals` serves `proposals`.
        const segs = probed.split("/").filter(Boolean);
        const family = `/${segs.slice(0, 3).join("/")}`;      // /v1/hypervisor/<family>
        const noun = segs.filter((x) => !x.startsWith(":")).pop();
        if (!noun || noun.length < 5) continue;
        const hit = [...routes.keys()].find((r) => r !== probed && r.startsWith(family) && r.includes(noun));
        if (hit) {
          decorativeProbes.push(`${path.basename(f, ".mjs")}: asserts \`${noun}\` absent against ${probed}, which is not a route — while the same family serves it at ${hit}`);
        }
      }
    }
  }
  ok("and NO VERIFIER ASSERTS A FAMILY ABSENT BY PROBING THE WRONG PATH FOR A FAMILY THAT IS SERVED ELSEWHERE — probing a path no route occupies is the honest way to demonstrate a family the daemon genuinely lacks; the defect is asserting absence at a path the family never used while it answers at its real one, which is how XIII's survivor stayed green and why grepping family names could never have found it",
    decorativeProbes.length === 0,
    decorativeProbes.length ? `DECORATIVE: ${[...new Set(decorativeProbes)].slice(0, 6).join(" ; ")}` : "every absence probe targets a real route template");

  // ------------------------------------------------------------ scar 4, both directions
  ok("the undecidable remainder is COUNTED AND VISIBLE, not passed over — a route named in PROSE carries no declared polarity, and deciding it would mean parsing English negation scope, which is the unbounded version of the problem this gate exists to end; it is reported rather than silently treated as true",
    undecidable > 0,
    `${undecidable} route mentions in prose carry no field semantics and are undecidable here`);

  const failed = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
  emitVerifierCensus({ verifierId: "named-gap-truth", sourceUrl: import.meta.url, results });
  console.log(`\n${results.length - failed.length}/${results.length} passed`);
  if (failed.length) process.exit(1);
}

const INVOKED = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (INVOKED) {
  try { run(); } catch (error) {
    console.error(`FAIL named-gap-truth — ${error?.stack || error}`);
    process.exit(1);
  }
}
