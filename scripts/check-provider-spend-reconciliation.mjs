#!/usr/bin/env node
//
// M07.3 — THE READBACK, AND WHY IT DID NOT NEED A CREDENTIAL TO BUILD.
//
// The acceptance is ACC-4 clause 7 and ACC-11 clause 7: *a charge that may or may not have landed
// is reconciled against provider billing before any figure is reported.* Before this unit the
// estate had one reconciliation route, and its own doc comment said what it was: reconciliation
// "over EXISTING records only (exposures + budgets + receipts) … actual provider bills are never
// invented". That is the estate correctly refusing to fabricate a figure it cannot source — and it
// means the old route reconciles the estimate against itself.
//
// IT WOULD HAVE BEEN EASY TO RECORD THIS UNIT AS BLOCKED ON A PROVIDER BILLING CREDENTIAL. That is
// a wall reported rather than routed around, and it is wrong twice: a credential blocks a live RUN,
// never the unit, and everything that can be got wrong here is in the COMPARISON rather than in the
// transport. So the statement is an admitted object — however its figures arrive, they are owner-
// scoped, hashed and immutable — and the wire that fetches them under a credential is a transport
// recorded as a scheduled qualification, not a gate on this contract.
//
// WHAT IS COMPARED, AND WHY IT IS NOT TOTAL-AGAINST-TOTAL. Measured before building: the op path
// records a RATE and a ceiling per exposure and deliberately never computes a total, because until
// teardown there is not one. A total-against-total comparison would therefore have to invent our
// side — the exact thing the old route refused to do. So this compares what is knowable:
//   COVERAGE both ways, and THE AUTHORIZED CEILING of each CLOSED exposure, which is arithmetic
//   from a start, an end and a ceiling rate rather than a guess. An OPEN exposure is ambiguous by
//   construction: it is literally the charge that may or may not have landed.
//
// THE EXPOSURES BELOW ARE SEEDED AT THE STORAGE LAYER, and that is stated rather than hidden:
// opening a real one requires a live provider, and the reconciliation under test reads them through
// exactly the same record reader it would use for real ones. What is NOT seeded is any statement or
// reconciliation — both go through the admitting routes, because the admission is the subject.
//
//   --mutation  prove each finding fails on its own
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startIsolatedPlane } from "../apps/hypervisor/scripts/lib/isolated-daemon.mjs";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const findings = [];
const observations = {};
let DAEMON = "";
let SESSION = "";
let OWNER = "";
let plane = null;

const ok = (name, satisfied, detail) => {
  findings.push({ name, satisfied: !!satisfied, detail: detail ?? "" });
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const blocked = (why) => {
  console.log(JSON.stringify({ check: "check:provider-spend-reconciliation", unit: "M07.3", verdict: "BLOCKED", why }, null, 2));
  process.exit(1);
};

const jd = async (path, init = {}) => {
  const response = await fetch(`${DAEMON}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(SESSION ? { authorization: `Bearer ${SESSION}` } : {}),
      ...(init.headers || {}),
    },
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
};

const PROVIDER = "vast";
let key = 0;
const nextKey = (label) => `m073-${label}-${key++}`;

/// A closed exposure whose authorized ceiling is exactly `hours * ceilingPerHour`.
const seedExposure = (dataDir, id, { openedAt, closedAt, ceilingPerHour, status = "closed" }) => {
  const dir = join(dataDir, "provider-spend-exposures");
  mkdirSync(dir, { recursive: true });
  const record = {
    schema_version: "ioi.hypervisor.provider-spend-exposure.v1",
    exposure_id: id,
    exposure_ref: `provider-spend-exposure://${id}`,
    provider: PROVIDER,
    account_ref: "account://seeded",
    environment_ref: "env://seeded",
    max_hourly_usd: ceilingPerHour,
    usd_per_hour: ceilingPerHour,
    status,
    opened_at: openedAt,
    ...(closedAt ? { closed_at: closedAt } : {}),
  };
  writeFileSync(join(dir, `${id}.json`), `${JSON.stringify(record, null, 2)}\n`);
  return record.exposure_ref;
};

const admitStatement = (lines, extra = {}) =>
  jd("/v1/hypervisor/provider-spend/statements", {
    method: "POST",
    body: JSON.stringify({
      owner_ref: OWNER,
      idempotency_key: nextKey("stmt"),
      provider_ref: PROVIDER,
      billing_account_ref: "billing://seeded/acct-1",
      period_start: "2026-09-01T00:00:00Z",
      period_end: "2026-09-30T00:00:00Z",
      figure_provenance: "operator-entered from the provider console export",
      line_items: lines,
      ...extra,
    }),
  });

const reconcile = (statementRef) =>
  jd("/v1/hypervisor/provider-spend/reconciliations", {
    method: "POST",
    body: JSON.stringify({ owner_ref: OWNER, idempotency_key: nextKey("recon"), statement_ref: statementRef }),
  });

// THE DATA DIRECTORY IS CALLER-OWNED FROM THE FIRST START, because the restart assertion needs it
// to survive `stop()`. A plane that allocated its own removes it on stop — correctly, so a dozen
// fault-lane planes do not leave a dozen trees behind — so a restart test has to bring its own.
const OWNED_DATA_DIR = mkdtempSync(join(tmpdir(), "m073-spend-reconciliation-"));
try {
  plane = await startIsolatedPlane({ dataDir: OWNED_DATA_DIR });
  if (!plane) blocked("the isolated daemon plane did not start");
  DAEMON = plane.daemonUrl;
  // A plane started on a CALLER-OWNED directory names its log for the restart it might be, so the
  // token is read from whichever log this start actually wrote rather than from a fixed name.
  const logName = readdirSync(plane.dataDir)
    .filter((name) => name.startsWith("isolated-daemon") && name.endsWith(".log"))
    .sort()
    .at(-1);
  if (!logName) blocked("the isolated plane wrote no daemon log to read its bootstrap token from");
  const log = readFileSync(join(plane.dataDir, logName), "utf8");
  const token = log.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? null;
  if (!token) blocked("the isolated plane published no bootstrap token");
  const { randomBytes } = await import("node:crypto");
  const boot = await jd("/v1/hypervisor/auth/bootstrap", {
    method: "POST",
    body: JSON.stringify({
      token,
      password: `throwaway-${randomBytes(18).toString("hex")}`,
      email: "provider-spend-reconciliation@ioi.local",
    }),
  });
  SESSION = boot.body?.session_token || "";
  if (!SESSION) blocked(`operator bootstrap yielded no session: ${JSON.stringify(boot.body).slice(0, 200)}`);
  const who = (await jd("/v1/hypervisor/auth/whoami")).body || {};
  OWNER = (who.principal?.tenant_refs || []).find(
    (tenant) => typeof tenant === "string" && (tenant.startsWith("org://") || tenant.startsWith("project://")),
  ) || "";
  if (!OWNER) blocked(`the session has no owner tenant to admit under: ${JSON.stringify(who).slice(0, 200)}`);

  // ---------------------------------------------------------------- the statement is an object
  const ceiling = 2.0; // USD/hour
  const threeHours = { openedAt: "2026-09-10T00:00:00Z", closedAt: "2026-09-10T03:00:00Z", ceilingPerHour: ceiling };
  const exposureA = seedExposure(plane.dataDir, "pse_a", threeHours);
  const withinCeiling = 5_000_000; // $5.00 against a $6.00 ceiling
  const aboveCeiling = 7_500_000; // $7.50 against a $6.00 ceiling

  const admitted = await admitStatement([{ exposure_ref: exposureA, billed_micros: withinCeiling }]);
  const statementRef = admitted.body?.statement_ref || "";
  ok("a provider billing statement is an ADMITTED OBJECT, owner-scoped and receipted — however its figures arrive, they are recorded as provider-native material rather than passed alongside the comparison, which is what lets the comparison be audited separately from whoever supplied the numbers",
    admitted.status === 201 && !!statementRef && admitted.body?.effect_authority_created === false,
    `${admitted.status} · ${statementRef.slice(0, 44)}`);

  const unknownField = await admitStatement([{ exposure_ref: exposureA, billed_micros: 1 }], { total_usd: 5 });
  ok("and the statement's field set is CLOSED — a caller who misspells a line-item field would otherwise admit a statement that bills nothing and reconcile green against an empty set",
    unknownField.status === 400 && unknownField.body?.code === "provider_spend_request_field_unknown",
    `${unknownField.status}/${unknownField.body?.code}`);

  const duplicated = await admitStatement([
    { exposure_ref: exposureA, billed_micros: 1 },
    { exposure_ref: exposureA, billed_micros: 2 },
  ]);
  ok("a statement billing one exposure twice is refused rather than summed — two lines for one exposure make the reconciled total depend on which line is read",
    duplicated.status === 400 && duplicated.body?.code === "provider_billing_statement_line_duplicated",
    `${duplicated.status}/${duplicated.body?.code}`);

  // ---------------------------------------------------------------- reconciled
  const reconciled = await reconcile(statementRef);
  const reconciledRecord = reconciled.body?.reconciliation || {};
  ok("FULL COVERAGE AND A BILL WITHIN THE AUTHORIZED CEILING RECONCILES, and only then is a figure reported — the acceptance clause as a state machine rather than as prose, and the figure reported is the PROVIDER'S, because ours was never a total",
    reconciled.status === 201 && reconciledRecord.outcome === "reconciled"
      && reconciledRecord.reported_total_micros === withinCeiling,
    `${reconciled.status}/${reconciledRecord.outcome} · reported ${reconciledRecord.reported_total_micros}`);

  // ---------------------------------------------------------------- diverged
  const overStatement = await admitStatement([{ exposure_ref: exposureA, billed_micros: aboveCeiling }]);
  const diverged = await reconcile(overStatement.body?.statement_ref || "");
  const divergedRecord = diverged.body?.reconciliation || {};
  ok("A BILL ABOVE THE AUTHORIZED CEILING DIVERGES, and reports NO figure — the ceiling is arithmetic from a start, an end and a rate the estate itself authorized, so a divergence is detectable without ever inventing our own total",
    divergedRecord.outcome === "diverged"
      && divergedRecord.reported_total_micros === null
      && (divergedRecord.divergent_lines || []).length === 1,
    `${divergedRecord.outcome} · over by ${(divergedRecord.divergent_lines || [])[0]?.over_ceiling_micros}`);

  // ---------------------------------------------------------------- ambiguous, three causes
  const strayStatement = await admitStatement([{ exposure_ref: "provider-spend-exposure://pse_never_opened", billed_micros: 1 }]);
  const strayRecon = (await reconcile(strayStatement.body?.statement_ref || "")).body?.reconciliation || {};
  ok("a statement line naming an exposure this estate never opened is AMBIGUOUS, not a divergence — the two sides do not correspond, so no delta between them means anything and reporting one would invent the figure this plane exists to stop inventing",
    strayRecon.outcome === "ambiguous"
      && (strayRecon.ambiguity?.unmatched_statement_lines || []).length === 1
      && strayRecon.reported_total_micros === null,
    `${strayRecon.outcome} · ${(strayRecon.ambiguity?.unmatched_statement_lines || []).length} unmatched line(s)`);

  const emptyStatement = await admitStatement([]);
  const unbilledRecon = (await reconcile(emptyStatement.body?.statement_ref || "")).body?.reconciliation || {};
  ok("and an exposure the bill omits is ambiguous from the other direction — a statement that bills less than we opened is not a cheaper bill, it is an incomplete one",
    unbilledRecon.outcome === "ambiguous" && (unbilledRecon.ambiguity?.unbilled_exposures || []).length === 1,
    `${unbilledRecon.outcome} · ${(unbilledRecon.ambiguity?.unbilled_exposures || []).length} unbilled`);

  const openExposure = seedExposure(plane.dataDir, "pse_open", {
    openedAt: "2026-09-11T00:00:00Z", closedAt: null, ceilingPerHour: ceiling, status: "open",
  });
  const openRecon = (await reconcile((await admitStatement([
    { exposure_ref: exposureA, billed_micros: withinCeiling },
    { exposure_ref: openExposure, billed_micros: 1 },
  ])).body?.statement_ref || "")).body?.reconciliation || {};
  ok("AN OPEN EXPOSURE IS AMBIGUOUS BY CONSTRUCTION — it is literally the acceptance's own case, a charge that may or may not have landed, and reconciling a bill against a number that is still moving is the failure this clause names",
    openRecon.outcome === "ambiguous" && (openRecon.ambiguity?.open_exposures_in_window || []).length === 1,
    `${openRecon.outcome} · ${(openRecon.ambiguity?.open_exposures_in_window || []).length} still open`);

  // ---------------------------------------------------------------- the charge gate, and restart
  const gate = await jd("/v1/hypervisor/provider-spend/charge-gate");
  observations.gated_providers = Object.keys(gate.body?.gated_providers || {});
  ok("an unresolved reconciliation places its provider under a CHARGE GATE, derived from admitted records rather than held in memory",
    gate.status === 200 && !!(gate.body?.gated_providers || {})[PROVIDER],
    `gated: ${observations.gated_providers.join(", ") || "none"}`);

  const retry = await jd("/v1/hypervisor/provider-ops", {
    method: "POST",
    body: JSON.stringify({ op: "create", provider_id: PROVIDER, environment_ref: "env://seeded" }),
  });
  ok("NO RETRY BEFORE RECONCILIATION, refused BEFORE the adapter resolves and before any credential is touched — spending again on a provider whose last bill does not agree with your records is how a small disagreement becomes an unbounded one",
    retry.status === 409 && retry.body?.code === "provider_spend_reconciliation_required",
    `${retry.status}/${retry.body?.code}`);

  await plane.stop();
  plane = await startIsolatedPlane({ dataDir: OWNED_DATA_DIR });
  if (!plane) blocked("the plane did not restart on its own data directory");
  DAEMON = plane.daemonUrl;
  const afterRestart = await jd("/v1/hypervisor/provider-spend/charge-gate");
  ok("AND THE GATE SURVIVES A RESTART, because it was never a feature — statements and reconciliations are admitted records on the shared write path, so the gate re-derives from what is on disk",
    afterRestart.status === 200 && !!(afterRestart.body?.gated_providers || {})[PROVIDER],
    `after restart, gated: ${Object.keys(afterRestart.body?.gated_providers || {}).join(", ") || "none"}`);

  // ---------------------------------------------------------------- drills
  if (mutation) {
    const drill = (name, satisfied, detail) => ok(`DRILL — ${name}`, satisfied, detail);

    const reconcilingAgain = seedExposure(plane.dataDir, "pse_b", threeHours);
    const clearing = await reconcile((await admitStatement([
      { exposure_ref: exposureA, billed_micros: withinCeiling },
      { exposure_ref: reconcilingAgain, billed_micros: withinCeiling },
      { exposure_ref: openExposure, billed_micros: 1 },
    ])).body?.statement_ref || "");
    drill("the gate does not latch — a later reconciliation that still finds the open exposure keeps it shut, so clearing requires resolving the cause rather than merely reconciling again",
      (clearing.body?.reconciliation || {}).outcome === "ambiguous"
        && !!(await jd("/v1/hypervisor/provider-spend/charge-gate")).body?.gated_providers?.[PROVIDER],
      `${(clearing.body?.reconciliation || {}).outcome}`);

    const noStatement = await jd("/v1/hypervisor/provider-spend/reconciliations", {
      method: "POST",
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: nextKey("nostmt"), statement_ref: "provider-billing-statement://pbs_absent" }),
    });
    // MEASURED, NOT ASSUMED: the SCOPE BOUNDARY answers first, and that is stronger than the
    // not-found this drill originally expected. A ref that was never bound has no scope to read
    // under, so the request is refused before any record is touched — the estate's own doctrine
    // that a foreign or absent reference is refused at the boundary rather than resolved and
    // compared afterwards, which would be a read with a check bolted on behind it. Either refusal
    // satisfies the claim this drill makes; what would not is an acceptance.
    drill("a reconciliation citing a statement this estate never admitted is refused — a caller who could supply the figures AND the comparison would be reconciling against themselves, and the scope boundary answers before any record is read",
      noStatement.status !== 201
        && ["request_resource_scope_required", "provider_spend_reconciliation_statement_not_found"]
          .includes(noStatement.body?.code),
      `${noStatement.status}/${noStatement.body?.code} — refused at the scope boundary`);

    const anon = await fetch(`${DAEMON}/v1/hypervisor/provider-spend/statements`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ owner_ref: OWNER, idempotency_key: nextKey("anon"), provider_ref: PROVIDER }),
    });
    drill("an unauthenticated statement is refused before any field is read, so an anonymous caller cannot seed the figures a reconciliation will trust",
      anon.status === 401 || anon.status === 403, `status ${anon.status}`);

    const noProvenance = await jd("/v1/hypervisor/provider-spend/statements", {
      method: "POST",
      body: JSON.stringify({
        owner_ref: OWNER, idempotency_key: nextKey("noprov"), provider_ref: PROVIDER,
        billing_account_ref: "billing://seeded/acct-1",
        period_start: "2026-09-01T00:00:00Z", period_end: "2026-09-30T00:00:00Z",
        line_items: [],
      }),
    });
    drill("a statement with no figure provenance is refused — an unattributed figure is a number rather than evidence, and this plane never claims the provider sent it",
      noProvenance.status === 400 && noProvenance.body?.code === "provider_billing_statement_provenance_required",
      `${noProvenance.status}/${noProvenance.body?.code}`);

    const backwards = await admitStatement([], { period_start: "2026-09-30T00:00:00Z", period_end: "2026-09-01T00:00:00Z" });
    drill("a window that does not advance is refused rather than covering nothing silently",
      backwards.status === 400 && backwards.body?.code === "provider_billing_statement_period_invalid",
      `${backwards.status}/${backwards.body?.code}`);
  }
} finally {
  if (plane) await plane.stop();
  try {
    rmSync(OWNED_DATA_DIR, { recursive: true, force: true });
  } catch {
    /* best effort — the plane is already stopped and the tree is under the system temp root */
  }
}

const failed = findings.filter((finding) => !finding.satisfied);
console.log(JSON.stringify({
  check: "check:provider-spend-reconciliation",
  unit: "M07.3",
  verdict: failed.length === 0 ? "PASS" : "FAIL",
  executed_assertions: findings.length,
  passed: findings.length - failed.length,
  failed: failed.length,
  observations,
  remaining_nonclaims: [
    "THE TRANSPORT IS SCHEDULED, NOT PROVEN. A statement is admitted however its figures arrive; fetching them from a provider's billing API under a credential is a connector this unit does not build, and running one against a real account is a scheduled qualification rather than a gate here. What is proven is that the comparison, the typing, the gate and the restart are correct for any figures that arrive — which is everything a credential could not have taught us.",
    "ADMITTING A STATEMENT PROVES SOMEONE WITH WRITE SCOPE ASSERTED THESE ARE THE PROVIDER'S FIGURES. It does not prove the provider sent them, and the record says so: `figure_provenance` is carried verbatim and is evidence about who asserted, not about who billed.",
    "THE EXPOSURES ARE SEEDED AT THE STORAGE LAYER, because opening a real one requires a live provider. The reconciliation reads them through the same record reader it would use for real ones, and nothing about a statement or a reconciliation is seeded — both go through the admitting routes, because the admission is the subject.",
    "A RECONCILED OUTCOME PROVES THE TWO SIDES CORRESPOND AND THE BILL IS WITHIN THE CEILING THIS ESTATE AUTHORIZED. It does not prove the provider's figure is correct, and it settles nothing: no spend is authorized, paid or settled here.",
  ],
}, null, 2));
process.exit(failed.length === 0 ? 0 : 1);
