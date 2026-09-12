#!/usr/bin/env node
//
// M07.2 — A RIGHTS CONTRACT CITED BY HASH IS NOT A RIGHTS CONTRACT APPLIED.
//
// M07.2's contract half is already proven and must not be restated here: `model-route-rights-
// contract.v1` is REGISTERED, its route-use vocabulary is closed at twelve with a registered
// invariant pinning the size, the unresolved lane is required to be the exact projection of the
// unresolved findings, and prohibitions must be covered exactly by the affirmative uses plus those.
// `check:architecture-contracts` is registry-driven and proves all of it. Repeating any of it here
// would be a second opinion on a settled question.
//
// THE RUNTIME HALF IS WHAT HAD NO GATE, and measuring it found a live defect. The shared resolver
// takes NO route-use argument — it resolves a contract — so per-use eligibility is necessarily the
// CALLER's to enforce, and nothing was checking that callers do. Of the three consumer planes, one
// enforced fully, one enforced a different axis deliberately and said so in its own comment, and
// the third called `is_live()` and nothing else before stamping the contract's revision and content
// hash into every compiled field contract it produced. That is the whole failure in one sentence: a
// contract cited by hash is evidence it was READ, never evidence its ceiling was OBEYED.
//
// SO THE PROPERTY IS AN ENTAILMENT OVER CALL SITES, not a sample of behaviours. Every function that
// resolves a rights contract must also CONSULT one — liveness alone is resolution without
// application. Stated that way it catches the instance that was found, every instance like it, and
// the fourth plane that has not been written yet, which a runtime probe of three known planes could
// not do.
//
// AND THE ACCESSOR VOCABULARY IS DERIVED FROM THE TYPE, NEVER HARDCODED. This matters because the
// first measurement of this very defect got it wrong: grepping for the FIELD names reported two
// planes unguarded, when the second reaches its ceiling through `permitted_destination_classes()`.
// Deriving a behaviour population by grepping a field name is the same error as deriving a test
// population by regex, which this program has already earned once. The vocabulary is read from the
// resolved type's own impl blocks, so an accessor added tomorrow is counted tomorrow.
//
//   --mutation  prove each finding fails on its own
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const findings = [];
const observations = {};
const ok = (name, satisfied, detail) => {
  findings.push({ name, satisfied: !!satisfied, detail: detail ?? "" });
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};

const ROUTES_DIR = join(repo, "crates/node/src/bin/hypervisor_daemon_routes");
const OWNER = "model_route_rights_routes.rs";
const RESOLVER = "resolve_admitted_model_route_rights_contract";
const RESOLVED_TYPE = "ResolvedModelRouteRights";
// Liveness is resolution, not application: a contract that is current still has a ceiling, and
// asking only whether it is current is exactly the defect this gate was written for.
const LIVENESS_ONLY = "is_live";
// The consumer planes, pinned. A plane that starts resolving rights contracts and is not listed
// here is a finding — silence must not read as coverage.
const CONSUMER_PLANES = [
  "institutional_learning_boundary_routes.rs",
  "policy_bound_data_view_revision_routes.rs",
  "vertical_pack_worker_binding_routes.rs",
];

const read = (file) => readFileSync(join(ROUTES_DIR, file), "utf8");

// ------------------------------------------------------ the accessor vocabulary, from the type
const ownerSource = read(OWNER);
const accessors = new Set();
for (const match of ownerSource.matchAll(new RegExp(`impl\\s+${RESOLVED_TYPE}\\s*\\{`, "gu"))) {
  let index = match.index + match[0].length;
  let depth = 1;
  while (index < ownerSource.length && depth > 0) {
    if (ownerSource[index] === "{") depth += 1;
    else if (ownerSource[index] === "}") depth -= 1;
    index += 1;
  }
  for (const fn of ownerSource.slice(match.index + match[0].length, index)
    .matchAll(/(?:pub\(crate\)|pub)\s+fn\s+([a-z_]+)/gu)) accessors.add(fn[1]);
}
const ceilingAccessors = [...accessors].filter((name) => name !== LIVENESS_ONLY).sort();
observations.accessors = [...accessors].sort();
observations.ceiling_accessors = ceilingAccessors;
ok("the ceiling vocabulary is DERIVED from the resolved type's own impl blocks rather than written down here — the first measurement of this defect grepped FIELD names and called a guarded plane unguarded, because that plane reaches its ceiling through an accessor; a vocabulary copied into a gate is a vocabulary that stops matching the type it describes",
  accessors.has(LIVENESS_ONLY) && ceilingAccessors.length >= 2,
  `${accessors.size} accessors, ${ceilingAccessors.length} of them ceilings: ${ceilingAccessors.join(", ")}`);

// ------------------------------------------------------ the consumer population, both directions
const allFiles = readdirSync(ROUTES_DIR).filter((name) => name.endsWith(".rs"));
const resolvingFiles = allFiles.filter((file) => file !== OWNER && read(file).includes(`${RESOLVER}(`));
const unexpected = resolvingFiles.filter((file) => !CONSUMER_PLANES.includes(file));
const missing = CONSUMER_PLANES.filter((file) => !resolvingFiles.includes(file));
observations.resolving_planes = resolvingFiles.sort();
ok("the consumer population is CLOSED in both directions — every plane that resolves a rights contract is one this gate knows about, and every plane it knows about still resolves one. A fourth plane written tomorrow is a finding rather than an omission, which is the only way silence stops reading as coverage",
  unexpected.length === 0 && missing.length === 0,
  unexpected.length || missing.length
    ? `unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"}`
    : `${resolvingFiles.length}/${CONSUMER_PLANES.length} planes, both directions`);

// ------------------------------------------------------ THE PROPERTY: resolve implies apply
//
// The enclosing function of each call is found by scanning backwards to the nearest `fn` at column
// zero indentation and forwards by brace balance, rather than by splitting on blank lines: a helper
// nested inside a handler would otherwise be read as the handler itself.
const enclosingFunctions = (source) => {
  const spans = [];
  for (const match of source.matchAll(/^(?:pub(?:\([a-z()]+\))?\s+)?(?:async\s+)?fn\s+([a-z_0-9]+)/gmu)) {
    let index = source.indexOf("{", match.index);
    if (index < 0) continue;
    let depth = 1;
    let cursor = index + 1;
    while (cursor < source.length && depth > 0) {
      if (source[cursor] === "{") depth += 1;
      else if (source[cursor] === "}") depth -= 1;
      cursor += 1;
    }
    spans.push({ name: match[1], start: match.index, end: cursor, body: source.slice(index, cursor) });
  }
  return spans;
};

// THE PROPERTY IS ABOUT THE RESOLVED VALUE'S FATE, NOT THE FUNCTION'S TEXT, and getting there took
// three corrections — each a real one, each recorded because the error shape keeps recurring.
//
//   1. Grepping the FIELD names called a guarded plane unguarded: it reaches its ceiling through an
//      accessor. Fixed by deriving the vocabulary from the type.
//   2. "Every resolving function must itself call a ceiling" then accused TWO more functions. Both
//      were innocent for DIFFERENT reasons, which is what made the rule wrong rather than strict:
//      one resolves and never binds the result at all — its stated purpose is that the reference
//      RESOLVES under the caller's own owner binding, which is a real check and not a ceiling one —
//      and the other binds the value and passes it onward to the fold that applies the ceiling.
//   3. "Cites revision_ref or content_hash" was no better: those are ordinary field names on many
//      objects in these modules, so counting them counts other families' citations too.
//
// What actually separates the defect from the innocent cases is what happens to the BOUND value. A
// function that never binds it is doing resolvability. A function that binds it and passes it on
// has handed the obligation to where it flows. A function that binds it, reads its identity, and
// applies nothing is citing a contract it never consulted — which is the defect, exactly.
const bindingPattern = new RegExp(`(?:Ok\\(([a-z_]+)\\)|let\\s+([a-z_]+)\\s*=\\s*match)\\s*(?:=>)?[^;]{0,80}${RESOLVER}\\(|${RESOLVER}\\([^;]*\\)\\s*\\{[^}]*Ok\\(([a-z_]+)\\)`, "u");
const citedWithoutApplying = [];
let resolvingFunctions = 0;
let boundFunctions = 0;
for (const file of resolvingFiles) {
  const source = read(file);
  const spans = enclosingFunctions(source);
  for (const span of spans) {
    if (!span.body.includes(`${RESOLVER}(`)) continue;
    const inner = spans.filter((other) => other.start >= span.start && other.end <= span.end && other.body.includes(`${RESOLVER}(`));
    if (inner.length > 1 && inner[inner.length - 1].name !== span.name) continue;
    resolvingFunctions += 1;

    // Which name, if any, the Ok value is bound to.
    const bound = [...span.body.matchAll(/Ok\(([a-z_][a-z_0-9]*)\)\s*=>/gu)].map((match) => match[1]);
    const boundToResolver = bound.filter((name) => {
      // The binding belongs to THIS resolver only if the match arm follows a call to it.
      const armIndex = span.body.indexOf(`Ok(${name}) =>`);
      const callIndex = span.body.lastIndexOf(`${RESOLVER}(`, armIndex);
      return callIndex >= 0 && !span.body.slice(callIndex, armIndex).includes("match ");
    });
    if (boundToResolver.length === 0) continue; // resolvability only: nothing was retained
    boundFunctions += 1;

    const appliesHere = ceilingAccessors.some((accessor) => span.body.includes(`${accessor}(`));
    const passedOnward = boundToResolver.some((name) =>
      new RegExp(`\\b[a-z_]+\\(\\s*[^)]*\\b${name}\\b|\\.push\\(\\s*${name}\\s*\\)`, "u").test(span.body));
    if (!appliesHere && !passedOnward) citedWithoutApplying.push(`${file}::${span.name}`);
  }
}
observations.resolving_functions = resolvingFunctions;
observations.functions_binding_the_resolved_value = boundFunctions;
ok("A FUNCTION THAT RETAINS A RESOLVED RIGHTS CONTRACT EITHER APPLIES ONE OF ITS CEILINGS OR HANDS IT ON — retaining it, reading its identity into what you emit, and applying nothing is citing a contract you never consulted. That is what the vertical-pack worker binding did: it kept the value, stamped its revision and content hash into every compiled field contract, and asked only whether the contract was live. The shared resolver takes no route-use argument, so this obligation is structurally the caller's and nothing was checking that callers met it",
  citedWithoutApplying.length === 0 && boundFunctions >= 2,
  citedWithoutApplying.length
    ? `retained without applying or handing on: ${citedWithoutApplying.join(", ")}`
    : `${resolvingFunctions} resolving function(s), ${boundFunctions} of them retaining the value, all accounted for`);

// ------------------------------------------------------ the binding's own typed causes
const bindingSource = read("vertical_pack_worker_binding_routes.rs");
const bindingCodes = ["route_rights_not_live", "route_rights_inference_unresolved", "route_rights_inference_not_permitted"];
const presentCodes = bindingCodes.filter((code) => bindingSource.includes(`"${code}"`));
ok("and the binding's three causes are THREE CODES, because they go to three desks — a contract that is not current, a right nobody has settled, and a use the contract affirmatively does not carry are different findings for different owners, and one code covering them would send two of the three to the wrong person",
  presentCodes.length === bindingCodes.length,
  `${presentCodes.length}/${bindingCodes.length}: ${presentCodes.join(", ")}`);

// ------------------------------------------------------ drills
if (mutation) {
  const drill = (name, satisfied, detail) => ok(`DRILL — ${name}`, satisfied, detail);

  // The property is re-evaluated over MUTATED SOURCE, never over a predicate in isolation: a drill
  // that cannot fail while the gate is broken is not a drill. This is the same evaluator the
  // assertion above uses, so a drill passing means the assertion would have caught the defect.
  const evaluate = (file, source) => {
    const bad = [];
    const spans = enclosingFunctions(source);
    for (const span of spans) {
      if (!span.body.includes(`${RESOLVER}(`)) continue;
      const inner = spans.filter((other) => other.start >= span.start && other.end <= span.end && other.body.includes(`${RESOLVER}(`));
      if (inner.length > 1 && inner[inner.length - 1].name !== span.name) continue;
      const bound = [...span.body.matchAll(/Ok\(([a-z_][a-z_0-9]*)\)\s*=>/gu)].map((match) => match[1])
        .filter((name) => {
          const armIndex = span.body.indexOf(`Ok(${name}) =>`);
          const callIndex = span.body.lastIndexOf(`${RESOLVER}(`, armIndex);
          return callIndex >= 0 && !span.body.slice(callIndex, armIndex).includes("match ");
        });
      if (bound.length === 0) continue;
      const appliesHere = ceilingAccessors.some((accessor) => span.body.includes(`${accessor}(`));
      const passedOnward = bound.some((name) =>
        new RegExp(`\\b[a-z_]+\\(\\s*[^)]*\\b${name}\\b|\\.push\\(\\s*${name}\\s*\\)`, "u").test(span.body));
      if (!appliesHere && !passedOnward) bad.push(`${file}::${span.name}`);
    }
    return bad;
  };

  // THE ONE THAT MATTERS: the fix reverted. Everything else is a variation on it.
  const reverted = bindingSource
    .replace(/\s*const BINDING_ROUTE_USE[\s\S]*?route_rights_inference_not_permitted[\s\S]*?\n    \}\n/u, "\n");
  drill("the defect REPLANTED is caught — the binding's ceiling removed, leaving it resolving, retaining and citing while asking only whether the contract is live",
    evaluate("vertical_pack_worker_binding_routes.rs", reverted).length === 1,
    evaluate("vertical_pack_worker_binding_routes.rs", reverted).join(", ") || "NOT CAUGHT — the drill failed to plant it");

  drill("and the plane as it stands is clean, so the finding above comes from the planted defect and not from the scanner",
    evaluate("vertical_pack_worker_binding_routes.rs", bindingSource).length === 0, "clean");

  const invented = `fn sneaks(a: u8) -> u8 { let route = match ${RESOLVER}(w, x, y, z) { Ok(route) => route, Err(e) => return e }; if !route.is_live() { return 0; } route.revision_ref }`;
  drill("a NEW plane that retains and cites without applying is caught by the same property, so this is a rule about retaining a contract rather than a list of three files",
    evaluate("invented_plane.rs", invented).length === 1, evaluate("invented_plane.rs", invented).join(", ") || "NOT CAUGHT");

  // The two innocents, which an earlier cut of this gate accused. Both must stay clean, for their
  // own different reasons, or the rule is strict rather than right.
  const learning = read("institutional_learning_boundary_routes.rs");
  drill("the plane that resolves WITHOUT BINDING stays clean — its purpose is that the reference resolves under the caller's own owner binding, which is a real check and not a ceiling one, and an earlier cut of this gate wrongly accused it",
    !evaluate("institutional_learning_boundary_routes.rs", learning).includes("institutional_learning_boundary_routes.rs::handle_source_rights_claim_admit"),
    "resolvability-only, exempt by construction rather than by exemption list");

  drill("and the plane that binds and HANDS THE VALUE ON stays clean — the ceiling is applied where the value flows, and an earlier cut of this gate wrongly accused it too",
    !evaluate("institutional_learning_boundary_routes.rs", learning).includes("institutional_learning_boundary_routes.rs::handle_boundary_profile_admit"),
    "retained and passed to the fold that applies");

  const withoutCode = bindingSource.replaceAll('"route_rights_inference_unresolved"', '"route_rights_not_live"');
  drill("collapsing the unresolved cause into the liveness code is caught, so the three-desk separation is asserted rather than assumed",
    bindingCodes.filter((code) => withoutCode.includes(`"${code}"`)).length < bindingCodes.length,
    `${bindingCodes.filter((code) => withoutCode.includes(`"${code}"`)).length}/${bindingCodes.length} codes survive`);
}

const failed = findings.filter((finding) => !finding.satisfied);
console.log(JSON.stringify({
  check: "check:route-rights-contracts",
  unit: "M07.2",
  verdict: failed.length === 0 ? "PASS" : "FAIL",
  executed_assertions: findings.length,
  passed: findings.length - failed.length,
  failed: failed.length,
  observations,
  remaining_nonclaims: [
    "THE CONTRACT HALF IS NOT RESTATED HERE. The registered contract's closed twelve-use vocabulary, its pinned vocabulary size, the requirement that the unresolved lane be the exact projection of the unresolved findings, and the requirement that prohibitions be covered exactly by the affirmative uses plus those are all registered invariants that the registry-driven contracts gate already proves. A second opinion on a settled question is not coverage.",
    "THIS PROVES RESOLVE-IMPLIES-APPLY, NOT THAT EACH PLANE APPLIES THE RIGHT CEILING. Which of the twelve uses a given plane must require is a canon question per plane, and it is answered per plane in that plane's own source — the worker binding requires model_inference because it compiles a worker that will infer through the route. A plane that applied a ceiling for the wrong use would satisfy this gate; catching that needs the plane's own runtime gate, which is a different unit of work than closing the class where nothing was checked at all.",
    "ACC-16 AND ACC-18 ARE OUT. M07.2's acceptance names them beside ACC-11, and both are product_track under the worker-construction track this program puts deliberately out. A unit does not become product_track because its acceptance mentions one, and an mvp_required unit does not pull one back in by citation; this gate covers ACC-11's share.",
  ],
}, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
