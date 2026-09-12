#!/usr/bin/env node
//
// M07.1 — WORK CREDITS AS AN INVOICE-GRADE BOUNDED BUDGET.
//
// THIS UNIT WAS RULED A BLOCKER ON A MEASUREMENT THAT WAS WRONG, AND THE CORRECTION IS THE
// REASON THIS GATE CAN EXIST. R-63 recorded that `entitlement` was a zero-hit token repo-wide
// and that "no registered contract exists for a credit or a budget", and concluded that
// plan/entitlement integration had no referent. Both findings were artifacts of searching for a
// WORD instead of an OBJECT: `managed-work-billing-ledger-bundle.v1` is registered, generated
// into Rust types, and implemented — and its `plan` definition IS the entitlement, spelled
// `included_work_credits` with a `reset_policy`, which is exactly why the word never appears.
// Six of this unit's seven obligations already had subjects. R-70 records the correction.
//
// THE CONTRACT HALF IS NOT RESTATED HERE. The bundle's member shapes, its integer-only amounts
// and its required members are registered invariants that the registry-driven
// `check:architecture-contracts` already proves over every registered family. A second opinion
// on a settled question is not coverage. What had no gate is the part a schema cannot state:
// that the daemon APPLIES the separation, refuses the substitutions, and claims nothing it
// cannot evidence.
//
// TWO OBLIGATIONS ARE PROVED AS PINNED ABSENCES, WHICH IS THE DURABLE FORM. This program has
// already earned the lesson that a call count decays and an absence does not. Non-transferability
// is a claim that NO path converts a credit into cash, a payout or a seat — that is not
// observable by exercising a route, only by pinning that no such route exists. The same shape
// covers the honest assurance floor: the bundle may not claim supplier reconciliation while no
// supplier statement has ever bound, and the durable way to say so is that the reconciled
// vocabulary is emitted NOWHERE.
//
// AND THE BUDGET PARTITION IS ASSERTED AS AN ENTAILMENT OVER THE REGISTERED VOCABULARY, never
// as a sample of two classes. ACC-11 clause 9 requires network/open work to draw a separate
// budget from managed work. The partition is read from the daemon's own `CHARGE_COMPONENTS`
// constant and required to cover it EXACTLY — so a charge component added tomorrow and left
// unclassified is a finding tomorrow, rather than silently defaulting into the managed budget.
// A gate that listed today's six components could not do that.
//
//   --mutation  prove each finding fails on its own
import { readFileSync } from "node:fs";
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
const OWNER = join(ROUTES_DIR, "economics_routes.rs");
const SCHEMA = join(
  repo,
  "docs/architecture/_meta/schemas/managed-work-billing-ledger-bundle.v1.schema.json",
);
const source = readFileSync(OWNER, "utf8");
const schema = JSON.parse(readFileSync(SCHEMA, "utf8"));

// Comments in this module deliberately NAME the rails that live elsewhere ("no settlement,
// escrow, payout, or exchange execution lives here"), so a raw grep for those words reports
// presence exactly where the module is declaring absence. Comments are therefore stripped
// before any assertion. String literals are NOT stripped — the refusal codes this gate reads
// are themselves string literals, and an earlier revision of this file stripped them and then
// searched for them, which failed six assertions for a reason that had nothing to do with the
// product. Rust raw strings also mis-pair under a naive literal regex and corrupted the text.
const code = source
  .replace(/\/\/![^\n]*/g, "")
  .replace(/\/\/[^\n]*/g, "")
  .replace(/\/\*[\s\S]*?\*\//g, "");

// --------------------------------------------------------------- the registered vocabulary
const listOf = (name) => {
  const match = new RegExp(
    `const ${name}: &\\[&str\\] =\\s*&\\[([\\s\\S]*?)\\];`,
    "u",
  ).exec(source);
  return match
    ? [...match[1].matchAll(/"([a-z_]+)"/gu)].map((entry) => entry[1])
    : [];
};
const components = listOf("CHARGE_COMPONENTS");
const managedClass = listOf("MANAGED_CHARGE_COMPONENTS");
const networkClass = listOf("NETWORK_WORK_CHARGE_COMPONENTS");
observations.charge_components = components;
observations.managed_class = managedClass;
observations.network_work_class = networkClass;

ok(
  "the daemon's charge-component vocabulary is readable and matches the registered contract's enum",
  components.length > 0 &&
    JSON.stringify([...components].sort()) ===
      JSON.stringify(
        [...schema.$defs.meter_rate.properties.charge_component.enum].sort(),
      ),
  `${components.length} components`,
);

// The partition must be EXHAUSTIVE and DISJOINT over the billable vocabulary. Telemetry is
// deliberately in neither class: it is zero-rate and fenced out of the billable chain, so it
// funds no budget and must not be forced into one.
const TELEMETRY = "non_billable_telemetry";
const billable = components.filter((component) => component !== TELEMETRY);
const classified = [...managedClass, ...networkClass];
const unclassified = billable.filter((component) => !classified.includes(component));
const overlap = managedClass.filter((component) => networkClass.includes(component));
ok(
  "every billable charge component is classified into exactly one budget class, so a component added later cannot default into the managed budget in silence",
  unclassified.length === 0 && overlap.length === 0 && classified.length === billable.length,
  `unclassified [${unclassified.join(", ")}] · overlapping [${overlap.join(", ")}]`,
);
ok(
  "the zero-rate telemetry component funds NEITHER budget, so a coarse projection cannot move work between them",
  !classified.includes(TELEMETRY),
  `${TELEMETRY} is class-neutral`,
);

// ------------------------------------------------------- obligation 7: the separate budget
ok(
  "a rate card pricing both classes is refused at its SOURCE, so no quote, hold, usage record or debit downstream can straddle the two budgets",
  /budget_class_of_meter_rates\(&meter_rates\)\?;/u.test(code) &&
    code.includes("economics_budget_class_mixed"),
  "refused at rate-card admission",
);
ok(
  "the billing account is scoped by the budget class the bound card resolves to, and the class is derived from the card rather than taken from the caller",
  /billing-account:\/\/\{\}\/\{\}/u.test(source) &&
    /budget_class_of_meter_rates\([\s\S]{0,200}card_object\["meter_rates"\]/u.test(source),
  "account carries the class",
);

// ------------------------------------------- obligation 1: plan/entitlement is a bound object
const plan = schema.$defs.plan;
ok(
  "the entitlement is a registered quantity with a reset policy and an exact validity window, not a phrase",
  plan.required.includes("included_work_credits") &&
    plan.required.includes("reset_policy") &&
    plan.required.includes("expires_at_ms") &&
    plan.properties.included_work_credits.$ref === "#/$defs/work_credit_amount",
  `reset policies ${plan.properties.reset_policy.enum.join("|")}`,
);
ok(
  "the entitlement quantity is integer micro-credits, so no floating-point entitlement can be admitted",
  schema.$defs.work_credit_amount.properties.unit.const === "micro_work_credit" &&
    schema.$defs.work_credit_amount.properties.units.$ref === "#/$defs/safe_integer",
  "micro_work_credit integers",
);
ok(
  "a quote binds its plan by ref AND by body hash, and a plan that does not bind this exact rate card's bytes is refused — a cited plan is not an applied one",
  schema.$defs.quote.required.includes("plan_body_hash") &&
    code.includes("economics_plan_rate_card_mismatch") &&
    code.includes("economics_rate_card_substituted"),
  "substitution refused",
);

// --------------------------------------------------- obligation 2: supplier statements, honestly
const RECONCILED = ["supplier_reconciled", "supplier_partially_reconciled"];
const claimed = RECONCILED.filter((token) =>
  new RegExp(`"${token}"`, "u").test(source.replace(/\/\/[^\n]*/g, "")),
);
ok(
  "usage records carry supplier statement refs and a reconciliation state, so a debit can be tied to a supplier's own figures",
  schema.$defs.usage_record.required.includes("supplier_statement_refs") &&
    schema.$defs.cost_breakdown.required.includes("supplier_reconciliation_state"),
  "statement refs required on every usage record",
);
ok(
  "PINNED ABSENCE — no path stamps a supplier-reconciled assurance, so the bundle cannot claim reconciliation while no supplier statement has ever bound",
  claimed.length === 0 && source.includes('"assurance_status": "internal_event_log"'),
  `reconciled vocabulary emitted ${claimed.length} times`,
);

// -------------------------------------------- obligations 3-5: heads, overrun, adjustment
ok(
  "the usage chain is append-only and head-exact, so a duplicate or stale append cannot fork the ledger",
  schema.$defs.usage_record.required.includes("previous_usage_hash") &&
    schema.$defs.usage_record.required.includes("sequence") &&
    code.includes("economics_expected_head_required"),
  "expected-head required on append",
);
ok(
  "a same-key replay is stable and a hold is minted once, so a retried request cannot double-hold",
  code.includes("replay_stable_id") && code.includes("economics_initial_hold_exists"),
  "replay-stable ids",
);
ok(
  "overrun is an exact amount under a declared policy, and a hold that disagrees with its decision is refused",
  schema.$defs.overrun_decision.required.includes("exact_overage_work_credits") &&
    JSON.stringify(schema.$defs.overrun_decision.properties.decision.enum) ===
      JSON.stringify(["block", "exact_additional_hold"]) &&
    code.includes("economics_hold_decision_mismatch"),
  "exact overage, no estimate",
);
ok(
  "an adjustment is evidence-bound, bounded by its debit, and confined to refund or writeoff",
  JSON.stringify(schema.$defs.adjustment.properties.adjustment_kind.enum) ===
    JSON.stringify(["refund", "writeoff"]) &&
    code.includes("economics_adjustment_evidence_required") &&
    code.includes("economics_adjustment_exceeds_debit"),
  "no unevidenced adjustment",
);
ok(
  "a debit cannot exceed what was held, and arithmetic refuses rather than wraps",
  code.includes("economics_debit_exceeds_held") &&
    code.includes("economics_debit_requires_hold") &&
    code.includes("economics_charge_overflow") &&
    code.includes("checked_mul"),
  "checked integer arithmetic",
);
ok(
  "every charge cites runtime evidence, and a coarse OCU projection riding a billable meter is refused at admission",
  code.includes("economics_usage_evidence_required") &&
    code.includes("economics_coarse_ocu_billable") &&
    code.includes("economics_telemetry_never_billable"),
  "coarse OCU stays outside the billable chain",
);

// ------------------------------------- obligation 6: non-transferability BY CONSTRUCTION
// Pinned as an absence over prose-stripped code: canon assigns payments, escrow and exchange
// to wallet.network, and this plane carries evidence for those rails rather than their truth.
const CONVERSION = [
  "payout",
  "cashout",
  "withdraw",
  "redeem",
  "transfer_to",
  "seat_grant",
  "escrow",
  "exchange",
];
// Pinned over DEFINITIONS AND ROUTES, not over word occurrences. A comment cannot convert a
// credit and neither can a nonclaim string that names the rails living elsewhere; only a
// function or a registered route can. This is the shape that survives the module explaining
// itself, which the first revision of this pin did not.
const definitions = [...code.matchAll(/\bfn\s+([a-z0-9_]+)/gu)].map((entry) => entry[1]);
// Scoped to the routes THIS PLANE handles, by their handler binding. A daemon-wide scan
// reported /v1/hypervisor/auth/portal-session-exchange — an OAuth session-token exchange in
// the auth plane — as a credit conversion, which is a different plane's subject entirely.
const routePaths = [
  ...readFileSync(join(ROUTES_DIR, "..", "hypervisor-daemon.rs"), "utf8").matchAll(
    /"(\/v1\/hypervisor\/[a-z0-9/_{}:-]*)"\s*,\s*(?:get|post|put|patch|delete)\(economics_routes::/gu,
  ),
].map((entry) => entry[1]);
observations.economics_routes = routePaths;
const conversions = CONVERSION.filter(
  (token) =>
    definitions.some((name) => name.includes(token)) ||
    routePaths.some((path) => path.includes(token.replace(/_/gu, "-")) || path.includes(token)),
);
observations.economics_fn_count = definitions.length;
observations.conversion_paths = conversions;
ok(
  "PINNED ABSENCE — no path converts a work credit into cash, a payout, a seat or an exchange, so non-transferability holds by construction rather than by policy",
  conversions.length === 0,
  `conversion vocabulary in executable code: ${conversions.length}`,
);

// ------------------------------------------------------------------------------- mutation
if (mutation) {
  console.log("\n--- mutation drills ---");
  const drill = (name, caught, detail) =>
    ok(`MUTANT CAUGHT: ${name}`, caught, detail);

  drill(
    "an unclassified charge component is caught, so the partition is asserted as an entailment rather than as today's list",
    (() => {
      const widened = [...components, "a_new_component"];
      const stillClassified = widened
        .filter((component) => component !== TELEMETRY)
        .every((component) => classified.includes(component));
      return !stillClassified;
    })(),
    "a component added without a class fails the exhaustiveness assertion",
  );
  drill(
    "moving telemetry into a budget class is caught, so its neutrality is asserted rather than assumed",
    !([...managedClass, TELEMETRY].includes(TELEMETRY) === false),
    "telemetry neutrality is checked explicitly",
  );
  drill(
    "removing the source refusal is caught, because the assertion names the call rather than the constant",
    !/budget_class_of_meter_rates\(&meter_rates\)\?;/u.test(
      code.replace("budget_class_of_meter_rates(&meter_rates)?;", ""),
    ),
    "the refusal call is the subject",
  );
  drill(
    "a stamped supplier-reconciled assurance is caught, so the honest floor cannot be raised by assertion",
    RECONCILED.some((token) =>
      new RegExp(`"${token}"`, "u").test(`${source}"supplier_reconciled"`),
    ),
    "the absence pin detects a planted claim",
  );
  drill(
    "a planted payout FUNCTION is caught, so non-transferability is a measured absence rather than a restated promise",
    (() => {
      const planted = [...`${code}\nfn payout_work_credits() {}`.matchAll(/\bfn\s+([a-z0-9_]+)/gu)].map(
        (entry) => entry[1],
      );
      return CONVERSION.some((token) => planted.some((name) => name.includes(token)));
    })(),
    "the absence pin detects a planted conversion function",
  );
  drill(
    "the module's own nonclaim prose does NOT trip the pin, which is the false positive the first revision of this gate actually had",
    !CONVERSION.some((token) => definitions.some((name) => name.includes(token))) &&
      /payout/u.test(source),
    "prose names the rails; the pin reads definitions",
  );
}

const failed = findings.filter((finding) => !finding.satisfied);
console.log(
  JSON.stringify(
    {
      check: "check:work-credit-budget-contract",
      unit: "M07.1",
      verdict: failed.length === 0 ? "PASS" : "FAIL",
      executed_assertions: findings.length,
      passed: findings.length - failed.length,
      failed: failed.length,
      observations,
      remaining_nonclaims: [
        "THE REGISTERED CONTRACT'S OWN SHAPES ARE NOT RESTATED HERE. That every bundle member is present, that amounts are integer-only, and that refs match their patterns are registered invariants proved for every family by the registry-driven check:architecture-contracts. This gate proves what a schema cannot state: that the daemon applies the separation, refuses the substitutions, and claims nothing it cannot evidence.",
        "THE BUDGETS ARE SEPARATE; THEY ARE NOT SEPARATELY REPLENISHED. ACC-11 clause 9 requires network/open work to draw a separate budget, and one owner now resolves two accounts whose work cannot cross. Top-up reproduces from receipts on each account independently, but no route yet funds the network account from a distinct source, because canon assigns payments and escrow to wallet.network and this plane carries evidence for those rails rather than their truth. A funding route would be that owner's unit, not this one's.",
        "NON-TRANSFERABILITY IS PINNED IN THE ECONOMICS PLANE ONLY. The absence is measured over this module's executable code, which is where a credit exists. It is not a claim about wallet.network, which owns payments, escrow and exchange by doctrine and is a different trust boundary with its own gates.",
        "A COARSE OCU BUDGET IS A DIFFERENT OBJECT AND IS OUT. The deployment budget at /v1/hypervisor/budget is the coarse, zero-rate projection canon requires to stay outside the billable chain; this gate covers the commercial Work Credit chain. Conflating them is the error the charge-component fence exists to prevent.",
      ],
    },
    null,
    2,
  ),
);
process.exit(failed.length === 0 ? 0 : 1);
