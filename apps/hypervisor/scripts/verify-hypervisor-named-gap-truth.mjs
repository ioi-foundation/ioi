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
// THE ROUTER SET IS DERIVED BY THE ESTATE'S OWN ALGORITHM, AND THAT IS NOT A STYLE CHOICE. The first
// cut of this gate matched `.route\(\s*"([^"]+)"\s*,([\s\S]*?)\n\s*\)` — a lazy scan that runs
// FORWARD PAST a single-line registration into the next one. It saw 700 of 754 registrations: 54
// routes were invisible and 13 paths were credited with methods they do not serve. Among the
// invisible was `/v1` — the route that SERVES this very derivation. `operability_routes.rs`
// already parses the router with a balanced-paren scan and publishes the result at `GET /v1` marked
// `"derivation": {"kind": "mechanical"}`; the substrate had ruled the question and this gate
// re-answered it worse. That algorithm is ported here, and the derived count is asserted against the
// raw `.route(` occurrence count so the scan cannot silently skip a registration again.
//
// POLARITY COMES FROM THE FIELD, AND THE FIELD WORLD IS CLOSED. An earlier cut inferred polarity by
// regex over the sentence, and its own first run showed why that is the wrong layer:
// `"absent FROM THIS SURFACE"` is a scoped claim, not a route claim; `"daemon exposes GET /x …, no
// FEDERATED search"` is positive about the route it names and negative about a different capability;
// `"read from GET /x (no fabricated fields)"` negates FIELDS. A later cut tried the same inference
// again at CLAUSE scope and accused five more true sentences — `"POST /v1/hypervisor/model-routes
// creates a PROVIDER route, not a Data-Connection-backed one"` negates the KIND, not the existence.
// English negation scope is not a finite construct class; unlike Rust syntax there is no complete set
// of forms to model, so inferring it is the unbounded version of the problem this gate exists to end.
//
// So the check keys on the atlas's OWN declared field semantics — and, crucially, on ALL of them. The
// previous cut named TWO fields and left thirteen unpoliced, including `reference_control_census[]
// .reason`, which is where XIII's corrections actually live: it policed where the falsehood had been
// COPIED and left the field it ORIGINATED in unchecked, and a field rename would have disarmed it
// silently. Every atlas field that names a route is enumerated below with its polarity, asserted in
// both directions per scar 4, and A FIELD NAMING A ROUTE THAT IS NOT IN THE TABLE IS RED. That is the
// scope ratchet: moving a claim out of a policed field no longer lowers a printed number, it fails.
//
// WHAT IT DOES NOT ENTAIL, so the label claims only what it checks. Within a POSITIVE field, prose
// that asserts an absence about something OTHER than the route it cites is not decidable here — those
// fields cite routes as EVIDENCE ("the plane exists as daemon truth (POST /x)") and the decidable
// half is whether the evidence is real. Fields whose content is prose or forward-looking (a
// recommended PR's scope names routes it intends to CREATE) are enumerated as such and counted, never
// silently treated as true.

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
 * EVERY ATLAS FIELD THAT NAMES A ROUTE, with what naming one MEANS there.
 *
 *   positive — the field cites routes as things the daemon SERVES. Every route named must be
 *              registered. `reference_control_census[].reason` is positive: a
 *              `disabled_missing_authority` row names the contract that EXISTS while the surface
 *              binding is what is missing, which the atlas's own taxonomy spells out.
 *   negative — the field declares authority ABSENT. Every route named must NOT be registered at the
 *              methods the clause names. This is the XIII class proper.
 *   forward  — a recommended PR: it names routes it intends to CREATE, so today's router says
 *              nothing about it. Counted, never checked, never treated as true.
 *   prose    — narrative. Route mentions carry no field-level polarity.
 *
 * A field that names a route and is absent from this table FAILS. That is what makes the table a
 * closed world rather than a filter: a claim relocated into an unpoliced field cannot go quiet.
 */
const FIELD_SEMANTICS = {
  "existing_daemon.actions[]": "positive",
  "existing_daemon.routes[]": "positive",
  "existing_daemon.receipts[]": "positive",
  "reference_control_census[].binding": "positive",
  "reference_control_census[].reason": "positive",
  "missing_authority_contracts[]": "negative",
  "recommended_next_pr.done_bar[]": "forward",
  "recommended_next_pr.scope": "forward",
  "recommended_next_pr.title": "forward",
  "ranking.evidence_order[].recommended_next_pr": "forward",
  "landing_vs_workflow_note": "prose",
  "security_credential_implications": "prose",
  "primary_workflow": "prose",
  "blockers[]": "prose",
  "ranking.evidence_order[].rationale": "prose",
};

/**
 * THE POPULATIONS THIS GATE EXAMINES, pinned. Coverage that can fall silently is the defect this run
 * has hit twice; a count that must be re-derived when it moves is the only version of "we checked
 * everything" that survives an edit.
 */
const PINNED = {
  registeredRoutes: 753,
  atlasRouteMentions: { decided: 230, unchecked: 46, citedInNegative: 1 },
  surfaceStringsNamingARoute: 8,
  // 74 includes this gate's OWN two absence-worded labels. It walks every verifier in the estate and
  // is one of them; excluding itself would be the first exemption, and exemptions are how a closed
  // world stops being one.
  verifierAbsenceLabels: 74,
  verifierAbsenceLabelsResolvingAUrl: 15,
};

/**
 * Every route the daemon registers, as `path -> Set(method)`, by the algorithm
 * `operability_routes.rs::parsed_router_routes` already uses: find `.route(`, take the first string
 * literal as the path, then a BALANCED-PAREN scan for that registration's own handler expression.
 *
 * METHODS MATTER, and this gate's first run proved it. The atlas says
 * `PATCH/PUT /v1/hypervisor/data-sources/:id — … (route :id is GET-only; no update authority)`.
 * That claim is TRUE and precise: the path exists, the methods do not. A path-only check called it a
 * falsified reason. An assertion that cannot tell a missing METHOD from a missing PATH is not
 * checking the half that carries the finding.
 */
export function registeredRoutes(source) {
  const out = new Map();
  let cursor = 0, occurrences = 0, withPathLiteral = 0;
  for (;;) {
    const found = source.indexOf(".route(", cursor);
    if (found === -1) break;
    occurrences += 1;
    const open = found + ".route(".length;
    cursor = open;
    const rest = source.slice(open);
    const q = rest.indexOf('"');
    if (q === -1) continue;
    const q2 = rest.indexOf('"', q + 1);
    if (q2 === -1) continue;
    const routePath = rest.slice(q + 1, q2);
    if (!routePath.startsWith("/")) continue;
    withPathLiteral += 1;
    let depth = 1, end = q2 + 1;
    while (end < rest.length && depth > 0) {
      const c = rest[end];
      if (c === "(") depth += 1;
      else if (c === ")") depth -= 1;
      end += 1;
    }
    const handlers = rest.slice(q2 + 1, Math.max(q2 + 1, end - 1));
    const methods = new Set();
    for (const [token, verb] of [["get(", "GET"], ["post(", "POST"], ["put(", "PUT"], ["patch(", "PATCH"], ["delete(", "DELETE"], ["any(", "ANY"]]) {
      let scan = 0;
      for (;;) {
        const hit = handlers.indexOf(token, scan);
        if (hit === -1) break;
        const prev = hit === 0 ? "" : handlers[hit - 1];
        if (!/[A-Za-z0-9_]/u.test(prev)) methods.add(verb);
        scan = hit + token.length;
      }
    }
    out.set(routePath, new Set([...(out.get(routePath) ?? []), ...methods]));
  }
  return { routes: out, occurrences, withPathLiteral };
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
 * The CLAUSE a route mention sits in — used ONLY to read the METHODS a negative claim is about, never
 * to infer polarity. Run over a whole 400-character note, the word "No" in `'No requests found.'` — a
 * quoted UI string about DATA — made an unrelated approvals route read as a falsified reason.
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

const ABSENCE_LABEL = /\b(absent|does not exist|no .{0,24}(?:plane|family|route|contract))\b/iu;
// THE POPULATION IS WHERE THIS GATE KEPT LOSING. Two live falsehoods sat in the atlas, green at
// 10/10, and neither was a polarity mistake — both were claims the matcher never looked at:
//
//   · `DELETE /v1/hypervisor/odk/domain-ontologies/{id} … not yet contracted`, while the router has
//     served GET/PATCH/DELETE on `:id` all along. The old character class excluded `{}`, so `{id}`
//     truncated the route to the parent collection and the method check ran against the wrong path.
//     Eighteen brace-form mentions were being silently re-pointed that way.
//   · `materialized-object-sets exposes GET-only routes … no POST retire/delete exists`, while
//     `.delete(handle_set_delete)` is registered. That one names no `/v1/` token at all, so it was in
//     NEITHER the decided nor the unchecked population and no pin could move.
//
// So: braces are part of a route token and normalise to `:param`; ANY `/v1/` prefix is in scope, not
// only `/v1/hypervisor/` (258 of the 753 registered routes are outside it); and a negative-field
// entry that names NO route is counted as its own pinned population rather than vanishing.
const ROUTE_IN_TEXT = /\/v1\/[A-Za-z0-9/_:{}-]+/gu;
/** `{id}` and `:id` are the same path parameter written two ways. */
const normaliseRoute = (r) => r
  // `{id}` is a path parameter; `{approve,reject,apply}` is an ALTERNATION of four routes written
  // compactly, and rewriting it to `:id` invents a path nobody registered. Only an identifier-shaped
  // brace is a parameter; anything else ends the token.
  .replace(/\{[A-Za-z_][A-Za-z0-9_]*\}/gu, ":id")
  .replace(/\{.*$/u, "")
  .replace(/[.,;:/)]+$/u, "");
const normaliseField = (at) => at.replace(/^surfaces\.[a-z_]+\./u, "").replace(/\[\d+\]/gu, "[]");

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
  const { routes, occurrences, withPathLiteral } = registeredRoutes(routerSrc);

  ok("the router's registered route set is DERIVED by the estate's OWN balanced-paren algorithm and reconciled against the raw `.route(` occurrence count — a lazy regex ran forward past every single-line registration into the next one and lost 54 routes including `/v1`, the route that serves this very derivation, so the reconciliation is the assertion and not a formality",
    withPathLiteral === occurrences && routes.size === PINNED.registeredRoutes && routes.get("/v1")?.has("GET"),
    `${occurrences} \`.route(\` occurrences, ${withPathLiteral} with a path literal, ${routes.size} distinct paths (pinned ${PINNED.registeredRoutes})`);

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
      emissions.push({ site: "surface", where: `${path.basename(path.dirname(f))}@${m.index}`, text: m[1] ?? m[2] ?? m[3] });
    }
  }
  for (const f of listFiles(SCRIPTS, (p) => /verify-hypervisor-.*\.mjs$/u.test(p))) {
    const src = fs.readFileSync(f, "utf8");
    for (const m of src.matchAll(/\bok\(\s*(?:`([^`]{12,})`|"([^"]{12,})")/gu)) {
      emissions.push({ site: "verifier", where: `${path.basename(f, ".mjs")}@${m.index}`, text: m[1] ?? m[2], verifier: f });
    }
  }
  ok("the emission world is DERIVED by walking the atlas, every surface module and every verifier — a reason lives wherever it is EMITTED, and two of XIII's six rounds missed a survivor precisely because they searched for family names rather than for the places a claim is made",
    emissions.length > 500,
    `${emissions.length} emissions across atlas, surfaces and verifiers`);

  // ------------------------------------------------------------ the field world is closed
  const unknownFields = new Set();
  const staleFields = new Set(Object.keys(FIELD_SEMANTICS));
  const falseNegatives = [], falsePositives = [];
  let decided = 0, unchecked = 0, citedInNegative = 0;
  for (const [at, text] of jsonStrings(atlas)) {
    ROUTE_IN_TEXT.lastIndex = 0;
    if (!ROUTE_IN_TEXT.test(text)) continue;
    const field = normaliseField(at);
    const polarity = FIELD_SEMANTICS[field];
    if (!polarity) { unknownFields.add(field); continue; }
    staleFields.delete(field);
    ROUTE_IN_TEXT.lastIndex = 0;
    for (const m of text.matchAll(ROUTE_IN_TEXT)) {
      const r = normaliseRoute(m[0]);
      if (polarity === "prose" || polarity === "forward") { unchecked += 1; continue; }
      const clause = clauseAround(text, m.index);
      const methods = [...new Set([...clause.matchAll(/\b(GET|POST|PATCH|PUT|DELETE)\b/gu)].map((x) => x[1]))];
      // THE TWO DIRECTIONS ASK DIFFERENT QUESTIONS. `existing_daemon.actions` writes the compact
      // family form `POST/PATCH/DELETE /x`, meaning the FAMILY serves those verbs across `/x` and
      // `/x/:id` — so the decidable claim there is that the family's path is served at all. A
      // MISSING-authority claim is method-precise by nature ("PATCH/PUT /x — route is GET-only"), so
      // that side keeps the method check.
      // A NEGATIVE FIELD MAY CITE A ROUTE AS EVIDENCE RATHER THAN DENY IT. `models`'
      // missing-authority row reads "Inference exists at /v1/chat/completions but is not a governed
      // catalog workflow" — true, precise, and naming a registered route on purpose. Reading every
      // mention in the field as a denial accused it, which is the third time in this run that
      // inferring intent from prose produced a false accusation against a true sentence.
      //
      // The structural separator, and NOT an English one: a denial is METHOD-PRECISE. XIII's class
      // and the falsehood this gate just found both name the verb they deny ("PATCH/PUT … is
      // GET-only", "DELETE … not yet contracted"). A mention with no method token is a citation, and
      // it is counted rather than judged.
      if (polarity === "negative" && !methods.length) { citedInNegative += 1; continue; }
      decided += 1;
      const exists = polarity === "positive"
        ? (routeExists(routes, r) || routeExists(routes, `${r}/:id`))
        : methods.some((mm) => routeExists(routes, r, mm));
      if (polarity === "negative" && exists) falseNegatives.push(`${at}: declares MISSING authority, but ${methods.join("/") || "some method on"} ${r} IS registered`);
      if (polarity === "positive" && !exists) falsePositives.push(`${at}: cites ${r} as daemon truth, which is NOT registered`);
    }
  }

  ok("EVERY ATLAS FIELD THAT NAMES A ROUTE IS ENUMERATED WITH ITS POLARITY, and a field outside that table FAILS — the previous cut named two fields and left thirteen unpoliced, among them the census `reason` where XIII's own corrections live, so it policed where a falsehood had been COPIED and left where it ORIGINATED unchecked; with the world closed, relocating a claim into an unpoliced field cannot lower a printed count, it goes red",
    unknownFields.size === 0,
    unknownFields.size ? `UNPOLICED: ${[...unknownFields].join(", ")}` : `${Object.keys(FIELD_SEMANTICS).length} route-naming fields, all with declared semantics`);

  ok("and the field table is NOT STALE — scar 4's second half: a closed world is only as wide as what it derives over, so a field that stops naming routes must leave the table in the commit that empties it rather than sitting there implying coverage it no longer provides",
    staleFields.size === 0,
    staleFields.size ? `STALE: ${[...staleFields].join(", ")}` : "every enumerated field still names at least one route");

  ok("NO FIELD DECLARING AN AUTHORITY MISSING NAMES A ROUTE THIS DAEMON SERVES — the falsified-reason class proper, keyed on the atlas's OWN declared field semantics rather than on parsing English negation, and checked against the router at the point the claim is emitted",
    decided > 0 && falseNegatives.length === 0,
    falseNegatives.length ? `FALSIFIED: ${falseNegatives.slice(0, 6).join(" ; ")}` : `${decided} route-naming claims checked`);

  ok("and NO FIELD CITING A ROUTE AS DAEMON TRUTH NAMES ONE THE ROUTER DOES NOT SERVE — a correction that overclaims is the same defect facing the other way, and this gate found four on its first run, credited at paths the router never had",
    falsePositives.length === 0,
    falsePositives.length ? `OVERCLAIMED: ${falsePositives.slice(0, 6).join(" ; ")}` : "no emission credits an unregistered route");

  ok("the DECIDED and UNCHECKED populations are both pinned — a claim moved from a checked field into a prose or forward-looking one changes these numbers, so the remainder this gate declines to judge cannot quietly absorb the claims it is supposed to be judging",
    decided === PINNED.atlasRouteMentions.decided && unchecked === PINNED.atlasRouteMentions.unchecked && citedInNegative === PINNED.atlasRouteMentions.citedInNegative,
    `${decided}/${PINNED.atlasRouteMentions.decided} decided, ${unchecked}/${PINNED.atlasRouteMentions.unchecked} prose or forward-looking, ${citedInNegative}/${PINNED.atlasRouteMentions.citedInNegative} cited as evidence inside an absence field without naming a method`);

  // ------------------------------------------------------------ the strings a user actually reads
  // THE SURFACE WALK IS LIVE. A previous cut collected these strings and then hardcoded their
  // polarity to null, so no surface string could fail anything — deleting all 23 surface modules left
  // it green. The accessible name is the only text an assistive-technology user gets, and XIII's
  // survivor pair were `aria-label`s.
  const surfaceEmissions = emissions.filter((e) => e.site === "surface");
  const surfaceNamingRoute = [], surfaceUnregistered = [], surfaceFalseAbsence = [];
  for (const e of surfaceEmissions) {
    ROUTE_IN_TEXT.lastIndex = 0;
    const found = [...e.text.matchAll(ROUTE_IN_TEXT)];
    if (!found.length) continue;
    surfaceNamingRoute.push(e);
    for (const m of found) {
      const r = normaliseRoute(m[0]);
      if (!routeExists(routes, r) && !routeExists(routes, `${r}/:id`)) {
        surfaceUnregistered.push(`${e.where}: names ${r}, which the router does not serve — "${e.text.slice(0, 70)}…"`);
      }
      // The one absence form that IS decidable without parsing English: the string states a METHOD
      // and a path and says, in those words, that it does not exist.
      const claim = /\b(GET|POST|PATCH|PUT|DELETE)\b[^.;]{0,60}?does not exist/iu.exec(e.text);
      if (claim && routeExists(routes, r, claim[1].toUpperCase())) {
        surfaceFalseAbsence.push(`${e.where}: tells the user ${claim[1]} ${r} does not exist, but the router serves it`);
      }
    }
  }
  ok("EVERY ROUTE NAMED IN A STRING THE USER ACTUALLY READS IS ONE THE ROUTER SERVES, and a string that tells the user a METHOD does not exist is checked against that method — a previous cut gathered these strings and pinned their polarity to null, so no surface string could fail anything and deleting all 23 surface modules left it green; the population is pinned so that silence means coverage rather than absence",
    surfaceUnregistered.length === 0 && surfaceFalseAbsence.length === 0 && surfaceNamingRoute.length === PINNED.surfaceStringsNamingARoute,
    [...surfaceUnregistered, ...surfaceFalseAbsence].join(" ; ") || `${surfaceNamingRoute.length}/${PINNED.surfaceStringsNamingARoute} user-reaching strings name a route, all served`);

  // ------------------------------------------------------------ the survivor grep could not see
  const decorativeProbes = [];
  let absenceLabels = 0, absenceWithUrl = 0;
  for (const f of listFiles(SCRIPTS, (p) => /verify-hypervisor-.*\.mjs$/u.test(p))) {
    const src = fs.readFileSync(f, "utf8");
    // THE PROBE PRECEDES THE LABEL. A first cut searched FORWARD from `ok(` and found nothing,
    // because this estate writes `const x = await jd("/route"); ok("… absent …", x.status === 404)`.
    // Looking only downstream of the assertion misses the request the assertion is about — which is
    // the half that carries the finding. Probes are bound to their VARIABLE, then the variable is
    // looked up from the label. Only `/v1/hypervisor/...` paths are in scope: `/__ioi/...` is served
    // by the product-UI serve lane, not by the daemon router this gate checks against.
    const probeOf = new Map();
    for (const m of src.matchAll(/(?:const|let)\s+(\w+)\s*=\s*await\s+\w+\(([^;]{0,200})/gu)) {
      const url = /["'`](\/v1\/hypervisor\/[^"'`]*)["'`]/u.exec(m[2])?.[1];
      if (url) probeOf.set(m[1], url);
    }
    for (const m of src.matchAll(/\bok\(\s*(?:`([^`]{12,})`|"([^"]{12,})")([\s\S]{0,400}?)\)\s*;/gu)) {
      const label = m[1] ?? m[2];
      if (!ABSENCE_LABEL.test(label)) continue;
      absenceLabels += 1;
      const body = m[3] ?? "";
      const urls = new Set();
      for (const u of body.matchAll(/["'`](\/v1\/hypervisor\/[A-Za-z0-9/_${}.:-]*)["'`]/gu)) urls.add(u[1]);
      for (const v of body.matchAll(/\b(\w+)\b/gu)) if (probeOf.has(v[1])) urls.add(probeOf.get(v[1]));
      if (urls.size) absenceWithUrl += 1;
      for (const raw of urls) {
        const probed = raw.replace(/\$\{[^}]*\}/gu, ":id").replace(/[?].*$/u, "").replace(/\/+$/u, "");
        if (!probed.startsWith("/v1/hypervisor/")) continue;
        if (routeExists(routes, probed)) continue;
        // THE DEFECT IS NOT "PROBED AN UNREGISTERED PATH" — that is how one honestly demonstrates a
        // family the daemon genuinely lacks, and this estate does it deliberately (`no versions
        // route`, probed at the path a versions route would occupy). The defect is probing the WRONG
        // PATH FOR A FAMILY THAT EXISTS: XIII's survivor asserted the proposal family absent against
        // `/domain-ontologies/:id/proposals` while the family was live at `/odk/ontology-proposals`,
        // so it answered 404 for a reason having nothing to do with its subject. THE FAMILY IS THE
        // PROBE'S OWN PATH PREFIX — deriving it from the label re-introduced the unbounded English
        // problem, matching `/v1/threads/:id/cancel` off the word "cancel".
        const segs = probed.split("/").filter(Boolean);
        const family = `/${segs.slice(0, 3).join("/")}`;
        const noun = segs.filter((x) => !x.startsWith(":")).pop();
        if (!noun || noun.length < 5) continue;
        const hit = [...routes.keys()].find((r) => r !== probed && r.startsWith(family) && r.includes(noun));
        if (hit) decorativeProbes.push(`${path.basename(f, ".mjs")}: asserts \`${noun}\` absent against ${probed}, which is not a route — while the same family serves it at ${hit}`);
      }
    }
  }
  ok("THE ABSENCE-PROBE POPULATION IS PINNED IN BOTH STAGES — how many verifier assertions claim an absence, and how many of those resolve to a URL this gate can follow; the previous cut examined six of seventy-two and printed nothing about the other sixty-six, and coverage that can fall silently is the same defect as coverage that was never there",
    absenceLabels === PINNED.verifierAbsenceLabels && absenceWithUrl === PINNED.verifierAbsenceLabelsResolvingAUrl,
    `${absenceLabels}/${PINNED.verifierAbsenceLabels} absence-worded assertions, ${absenceWithUrl}/${PINNED.verifierAbsenceLabelsResolvingAUrl} resolve to a probe URL`);

  ok("and NO VERIFIER ASSERTS A FAMILY ABSENT BY PROBING THE WRONG PATH FOR A FAMILY THAT IS SERVED ELSEWHERE — probing a path no route occupies is the honest way to demonstrate a family the daemon genuinely lacks; the defect is asserting absence at a path the family never used while it answers at its real one, which is how XIII's survivor stayed green and why grepping family names could never have found it",
    decorativeProbes.length === 0,
    decorativeProbes.length ? `DECORATIVE: ${[...new Set(decorativeProbes)].slice(0, 6).join(" ; ")}` : "every absence probe targets a real route template");

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
