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
    read_by: "src/surfaces/Sources.jsx + src/surfaces/Catalog.jsx + src/logic/catalog.mjs",
    container: "sources",
    // Present on every item the daemon returns.
    every: ["state"],
    // Present on at least one item. `coverage` and `evidence` are per-source.
    sampled: ["source", "coverage", "evidence"],
    // Read defensively and never required. Named so the list of what the surface
    // touches is complete rather than only the parts that happen to be enforced.
    // The catalog reads these evidence keys by name to write one sentence per venue;
    // each is present on some sources and not others by design, and the catalog
    // renders whichever are there.
    optional: ["observed_at", "evidence.basis", "evidence.offers_seen",
               "evidence.gpu_types_priced", "evidence.verified_backends",
               "evidence.verified_ssh_accounts", "evidence.connected_cloud_accounts",
               "evidence.aws_accounts", "evidence.gcp_accounts", "evidence.azure_accounts",
               "evidence.k8s_accounts", "evidence.lambda_cloud_accounts", "evidence.akash_accounts"],
  },
  "/api/candidates": {
    read_by: "src/surfaces/Candidates.jsx + src/components/Hero.jsx + src/logic/routing.mjs + src/logic/batches.mjs + src/logic/classify.mjs",
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
               "eligibility_labels", "candidate_ref",
               // The hero names the cheapest quote in the daemon's own words — its
               // display name, GPU memory and region — each present on priced
               // candidates and absent on some unpriced ones by design.
               "display_name", "gpu.vram_gb", "region"],
    // TOP-LEVEL fields, checked against the BODY rather than against each item.
    // The surface reads `selection.considered` for its population line — the number
    // five cold readers could not reconcile against Placement's — and a contract that
    // only ever inspects items would have left the one field the counts depend on
    // entirely unchecked. Required, because with `latest=true` the daemon always sends
    // it and a missing selection would silently make the set-aside count wrong rather
    // than absent.
    root: ["selection.considered", "selection.returned", "selection.latest_batch_only"],
  },
  "/api/placement-advisory": {
    read_by: "src/surfaces/Placement.jsx + src/components/Hero.jsx + src/logic/routing.mjs",
    container: null,
    // A CONTRACT IN WHICH EVERYTHING IS OPTIONAL CANNOT FAIL, and this one was exactly
    // that. It declared `decision`, `decision.selected.provider_kind` and `considered`
    // — none of which the daemon sends — with every path optional, so their absence was
    // permitted and the surface rendered "the daemon returned no advisory" against a
    // body containing a complete advisory. The vacuity rule reported this route
    // inspecting ZERO fields, which is how it was found.
    //
    // These are the names from a live body. `advisory_ref` and `at` are required
    // because an advisory that cannot say what it is or when it was taken is not
    // evidence.
    every: ["advisory_ref", "at"],
    sampled: ["recommendation", "considered", "eligible", "authority_note"],
    // Genuinely optional, and each for a stated reason: `recommendation` is absent when
    // nothing is eligible, and the fee fields are absent on advisories that predate
    // fee accounting.
    optional: ["recommendation.venue", "recommendation.reason_codes",
               "recommendation.candidate_ref", "recommendation.display_name", "effective_venue",
               "no_eligible_candidate", "routing_fee_basis", "fee_object_minted"],
  },
  "/api/jobs": {
    read_by: "src/surfaces/Receipts.jsx + src/logic/job-door.mjs",
    container: "jobs",
    every: ["job_id", "state"],
    sampled: ["authority", "budget_ref", "created_at", "evidence_refs"],
    optional: ["authority.caller_kind", "authority.mode", "authority.authority_ref",
               "budget_discovery.discovered_before_mutation", "receipts",
               // THE SHAPE, not just the name. This contract said `receipts` EXISTS and
               // nothing about what it is. It is an ARRAY, `typeof [] === "object"`
               // passed it through untouched, and the surface rendered
               // Object.keys(receipts) — indices — as evidence chips under a column
               // headed Receipts. A shape assumption is exactly as much a fact about
               // the daemon as a field name is, and this contract was only checking
               // the names.
               "receipts.0.receipt_ref", "receipts.0.receipt_root",
               "receipts.0.fee_object_minted", "receipts.0.schema_version",
               "receipt_requirements", "redundancy"],
  },
  "/api/budgets": {
    read_by: "src/surfaces/Job.jsx + src/surfaces/Spend.jsx + src/surfaces/Home.jsx",
    container: "budgets",
    every: ["budget_id", "scope"],
    sampled: ["currency"],
    optional: ["name", "limit", "remaining", "spent", "created_at", "authority_required"],
  },
  // Answered by the surface itself and never by the daemon — but Settings reads it by
  // name, and a name read is a name declared, whichever process answers.
  "/api/face-config": {
    read_by: "src/surfaces/Settings.jsx",
    container: null,
    every: [],
    sampled: [],
    root: ["refresh_cadence_seconds", "daemon_reads", "capability", "note"],
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

  // ROOT-LEVEL fields, checked against the body itself before the container is opened.
  // A contract with a container inspected ONLY its items, so a top-level field the
  // surface reads — `selection.considered`, which every count on Candidates now derives
  // from — was outside anything the contract could see.
  let rootChecked = 0;
  for (const p of c.root || []) {
    rootChecked += 1;
    if (!pathIn(body, p).present) failures.push(`'${p}' absent from the body root`);
  }

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
      return { route, failures, notes, checked: rootChecked };
    }
  }

  // Every (item, declared field) pair actually examined, reported so a contract that
  // has quietly stopped describing anything cannot read as a clean bill of health.
  let checked = rootChecked;

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
