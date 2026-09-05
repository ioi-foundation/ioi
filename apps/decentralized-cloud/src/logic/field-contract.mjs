// THE FIELD CONTRACT — every name this surface reads out of a daemon body.
//
// This exists because of a defect I shipped. The Sources surface read
// `provider_kind`, `source_ref`, `reason`, `rule`, `http_status` and `offers_seen`.
// The daemon sends `source`, `coverage`, `state` and an `evidence` object. Not one of
// the names I used exists, so thirteen of thirteen rows rendered "—" in the Source
// column and dropped nearly all the evidence — on the surface whose subtitle promises
// it shows the evidence the daemon already sent.
//
// Nothing caught it. Every gate was green, because a field name is a fact about the
// DAEMON and every assertion I had read my own source. I ported a renderer and guessed
// what the fields were called.
//
// So: the names are declared here, once, and the gate fetches ONE LIVE BODY per read
// route and checks them against it. A surface may not read a field the daemon does not
// send.
//
// WHAT THIS CATCHES, stated exactly, because an instrument oversold is one people
// learn to ignore: it catches a name that appears on NO record in a live response —
// which is what a typo, a rename, and a ported guess all look like. It does NOT catch
// a field legitimately absent from some records but present on others; `quote` is
// absent on every non-live candidate by design, and requiring it on all of them would
// fail on correct behaviour. `sampled` fields are asserted to appear at least once
// across the returned items, and the gate prints the ratio so a field sliding from
// "usually there" to "once in fifty" is visible even though it does not fail.

export const FIELD_CONTRACT = {
  "/api/candidate-sources": {
    read_by: "src/surfaces/Sources.jsx",
    container: "sources",
    // Present on every item the daemon returns.
    every: ["state"],
    // Present on at least one item. `coverage` and `evidence` are per-source.
    sampled: ["source", "coverage", "evidence"],
    // Read defensively and never required. Named so the list of what the surface
    // touches is complete rather than only the parts that happen to be enforced.
    optional: ["observed_at"],
  },
  "/api/candidates": {
    read_by: "src/surfaces/Candidates.jsx + src/logic/batches.mjs + src/logic/classify.mjs",
    container: "candidates",
    // NOTHING is required on every candidate, and `evidence_mode` is the reason this
    // note exists. I declared it as required and the gate reported it missing on
    // 609 of 2981 items — so I checked whether the code or the contract was wrong,
    // and it was the contract. `classify()` has an explicit branch for the absence:
    // it renders the refusal reason `evidence_mode absent`, by name, to the reader.
    // A candidate arriving without it is a state this product handles deliberately,
    // so requiring it would have been an assertion failing on correct behaviour —
    // which is the kind that gets switched off rather than fixed.
    every: [],
    // `quote` and its fields exist only on candidates that carry a price; `batch`,
    // `observed_at` and `expires_at` are what the live rule and the latest-batch rule
    // are computed from, and a sweep with no live candidate at all is a real state.
    sampled: ["provider_kind", "observed_at", "expires_at", "batch", "quote"],
    optional: ["quote.usd_per_hour", "quote.basis", "quote.quote_ref", "quote.evidence_mode",
               "eligibility_labels", "candidate_ref"],
  },
  "/api/placement-advisory": {
    read_by: "src/surfaces/Placement.jsx",
    container: null,
    every: [],
    sampled: [],
    // The whole body is optional by design: "the daemon returned no advisory for this
    // intent" is a correct and renderable answer, so nothing here may be required.
    optional: ["decision", "decision.selected.provider_kind", "considered", "at"],
  },
  "/api/jobs": {
    read_by: "src/surfaces/Receipts.jsx + src/logic/job-door.mjs",
    container: "jobs",
    every: ["job_id", "state"],
    sampled: ["authority", "budget_ref", "created_at", "evidence_refs"],
    optional: ["authority.caller_kind", "authority.mode", "authority.authority_ref",
               "budget_discovery.discovered_before_mutation", "receipts",
               "receipt_requirements", "redundancy"],
  },
  "/api/budgets": {
    read_by: "src/surfaces/Job.jsx",
    container: "budgets",
    every: ["budget_id", "scope"],
    sampled: ["currency"],
    optional: ["name", "limit", "remaining", "spent"],
  },
};

// Resolve a dotted path against an object. Returns { present, value }.
export function pathIn(obj, path) {
  let node = obj;
  for (const key of path.split(".")) {
    if (node === null || node === undefined || typeof node !== "object") return { present: false };
    if (!(key in node)) return { present: false };
    node = node[key];
  }
  return { present: true, value: node };
}

// Check one live body against one route's contract. Framework-free so the gate can
// import it, and pure so it can be reasoned about without a daemon.
export function checkBody(route, body) {
  const c = FIELD_CONTRACT[route];
  if (!c) return { route, unknown: true, failures: [`no contract declared for ${route}`] };

  const failures = [];
  const notes = [];

  let items = [body];
  if (c.container) {
    const got = pathIn(body, c.container);
    if (!got.present || !Array.isArray(got.value)) {
      failures.push(`container '${c.container}' is absent or not an array in the live body`);
      return { route, failures, notes };
    }
    items = got.value;
    if (items.length === 0) {
      notes.push(`'${c.container}' came back empty — nothing to check the item fields against`);
      // `checked: 0` is the important part of this return. An empty container produces
      // no failures, and "no failures" is indistinguishable from "verified" unless the
      // count travels alongside it. The gate refuses to score a zero as a pass.
      return { route, failures, notes, checked: 0 };
    }
  }

  // Every (item, declared field) pair actually examined, reported so a contract that
  // has quietly stopped describing anything cannot read as a clean bill of health.
  let checked = 0;

  for (const p of c.every) {
    const missing = items.filter((it) => !pathIn(it, p).present).length;
    checked += items.length;
    if (missing > 0) failures.push(`'${p}' missing on ${missing}/${items.length} items`);
  }
  for (const p of c.sampled) {
    const present = items.filter((it) => pathIn(it, p).present).length;
    checked += items.length;
    if (present === 0) failures.push(`'${p}' present on 0/${items.length} items — the surface reads a name the daemon never sends`);
    else notes.push(`'${p}' on ${present}/${items.length}`);
  }

  // OPTIONAL paths are inspected too, and reported, though never required.
  //
  // /api/placement-advisory declares nothing but optional fields — correctly, because
  // "the daemon returned no advisory for this intent" is a renderable answer. That
  // made its contract check inspect ZERO things and pass, which the vacuity rule
  // caught. The fix is not to require what must stay optional; it is to LOOK at them
  // and say what was found, so the check reports a fact instead of a blank.
  for (const p of c.optional || []) {
    const present = items.filter((it) => pathIn(it, p).present).length;
    checked += items.length;
    notes.push(`'${p}' (optional) on ${present}/${items.length}`);
  }
  return { route, failures, notes, checked };
}
