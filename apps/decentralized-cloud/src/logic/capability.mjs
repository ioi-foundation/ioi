// What this surface can ask the daemon — THE authority, not a description of it.
//
// This file exists because the same list was written down in four places and had
// already drifted in three of them:
//
//   - the proxy's READS map held six routes; a seventh (a job read by id) lived in a
//     regex BELOW the map, and the write lane's dry-run route lived in another regex
//     below that. So "the closed, named list" was a list plus two exceptions, and the
//     exceptions were the two routes the job door added — the newest and least
//     reviewed ones.
//   - the API surface hand-copied seven rows and introduced them as "the same four
//     reads the server enforces".
//   - the proxy's own 404 body told a caller their path was "not one of the four
//     daemon reads this surface exposes" while enforcing seven.
//   - the header chip counted the writes by hand.
//
// None of those were lies when written. Each was true, then a route was added, and a
// sentence that was true stayed put. That is the entire failure mode: prose does not
// go red. A count written by hand is a claim maintained by memory, and this programme
// has now shipped three false sentences on a surface whose subject is not shipping
// false sentences.
//
// So the sentences are GENERATED from the table below, and the proxy DISPATCHES from
// the same table. A route cannot be added without the count changing, and a claim
// about what the surface does cannot survive the surface doing something else.
//
// The one thing this file cannot do is make a route safe. `spends` is a declaration by
// the author, and the spend fence in the proxy is what actually enforces it. What this
// file guarantees is narrower and worth stating exactly: THE SENTENCES AGREE WITH THE
// TABLE. If someone declares a spending write, the surface stops claiming nothing
// spends — it does not stop the spend. The fence does that, and is tested separately.

// The proxy overwrites `dry_run: true` server-side on every execute. This constant is
// here so the generated prose and the fence read the SAME flag: if a non-dry-run lane
// is ever opened, the sentence that promises no request reaches a provider stops being
// generated, in the same edit that opens it.
export const DRY_RUN_ONLY = true;

// A path parameter, bounded identically wherever it appears. A path that is not a job
// id is refused here rather than forwarded and refused somewhere with more privilege.
const PARAM = "[A-Za-z0-9_.:-]{1,128}";

// ── The table ────────────────────────────────────────────────────────────────
// `face`   what a visitor's browser asks for, with :params
// `daemon` the daemon route it stands for, with the same :params, or null if this
//          surface answers it itself and never leaves the process
// `query`  query parameters forwarded; everything else is DROPPED, not passed on
// `spends` whether reaching this route can cause a metered provider operation
// `does`   rendered to the reader on the API surface; the row and the sentence about
//          the row cannot disagree, because they are the same object
export const ROUTES = [
  {
    face: "/api/candidate-sources",
    method: "GET",
    daemon: "/v1/hypervisor/cloud-candidates/candidate-sources",
    query: [],
    spends: false,
    does: "Which candidate sources answered, and what each one's evidence is worth.",
  },
  {
    face: "/api/candidates",
    method: "GET",
    daemon: "/v1/hypervisor/cloud-candidates/candidates",
    query: ["intent_ref"],
    spends: false,
    does: "The candidates the daemon holds for one intent, with their evidence mode.",
  },
  {
    face: "/api/placement-advisory",
    method: "GET",
    daemon: "/v1/hypervisor/cloud-candidates/placement-advisory",
    query: ["intent_ref"],
    spends: false,
    does: "The daemon's placement advisory. Advisory is the daemon's word, not a hedge added here.",
  },
  {
    face: "/api/venues",
    method: "GET",
    daemon: "/v1/hypervisor/placement/venues",
    query: [],
    spends: false,
    does: "The venues placement can choose between.",
  },
  {
    face: "/api/jobs",
    method: "GET",
    daemon: "/v1/hypervisor/cloud-jobs",
    query: [],
    spends: false,
    does: "Every job record this daemon holds, including its refusals.",
  },
  {
    // Lived in a regex below the map until this cut, which is exactly why the counts
    // above it were wrong.
    face: "/api/jobs/:id",
    method: "GET",
    daemon: "/v1/hypervisor/cloud-jobs/:id",
    query: [],
    spends: false,
    does: "One job record, by id — the record the receipts are rendered from.",
  },
  {
    face: "/api/budgets",
    method: "GET",
    daemon: "/v1/hypervisor/resource/budgets",
    query: [],
    spends: false,
    does:
      "The budgets the daemon already has. The form can only offer one of these and can " +
      "only send back a ref it was given, so an amount cannot be typed into this surface.",
  },
  {
    // Answered in-process. It is on the table because a route absent from the table is
    // a route absent from the count, and the count is the claim.
    face: "/api/face-config",
    method: "GET",
    daemon: null,
    query: [],
    spends: false,
    does: "This surface's own configuration. It never leaves the process and asks the daemon nothing.",
  },
  {
    face: "/api/jobs",
    method: "POST",
    daemon: "/v1/hypervisor/cloud-jobs",
    kind: "admit",
    query: [],
    spends: false,
    does:
      "Admits a proposal. The daemon's own words: admission is a proposal and this " +
      "record authorizes nothing. No provider is touched and nothing is spent.",
  },
  {
    face: "/api/jobs/:id/dry-run",
    method: "POST",
    daemon: "/v1/hypervisor/cloud-jobs/:id/execute",
    kind: "dry-run",
    query: [],
    spends: false,
    does:
      "Runs the placement decision and stops at the receipt. The proxy sets dry_run " +
      "itself rather than forwarding what the caller sent, so no request a client can " +
      "compose reaches a metered provider operation.",
  },
];

// ── Matching ─────────────────────────────────────────────────────────────────
// One matcher for every route, built from the same `face` string the reader is shown.
// The proxy no longer carries a path regex of its own; there is nowhere for an
// eighth route to hide.
const compiled = ROUTES.map((route) => ({
  route,
  params: (route.face.match(/:([a-z]+)/g) || []).map((s) => s.slice(1)),
  re: new RegExp(`^${route.face.replace(/:[a-z]+/g, `(${PARAM})`)}$`),
}));

// Resolve a request to its daemon target, substituting path parameters. Returns null
// when nothing matches — the caller refuses by name, which is the point of the list.
export function matchRoute(method, pathname) {
  for (const { route, params, re } of compiled) {
    if (route.method !== method) continue;
    const m = re.exec(pathname);
    if (!m) continue;
    let daemon = route.daemon;
    if (daemon) {
      params.forEach((name, i) => {
        daemon = daemon.replace(`:${name}`, encodeURIComponent(m[i + 1]));
      });
    }
    return { route, daemon, params: Object.fromEntries(params.map((n, i) => [n, m[i + 1]])) };
  }
  return null;
}

export const readRoutes = () => ROUTES.filter((r) => r.method === "GET");
export const writeRoutes = () => ROUTES.filter((r) => r.method !== "GET");
export const daemonReadRoutes = () => readRoutes().filter((r) => r.daemon);

// ── The sentences ────────────────────────────────────────────────────────────
// Small counts read badly as digits in prose, and "2 writes" in a header chip is the
// kind of detail that makes a careful page look generated. It IS generated; it should
// not look it.
const WORDS = ["no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];
const count = (n) => (n < WORDS.length ? WORDS[n] : String(n));
const plural = (n, one, many) => (n === 1 ? one : many);

// Whether any route on the table can reach a metered provider operation. Derived, so
// that declaring one flips every sentence below in the same edit.
export const anySpends = (routes = ROUTES) => routes.some((r) => r.spends);

// The spend clause. There are three states and each is a different sentence, because
// a surface with a spending route must not be able to reach the wording of one
// without.
function spendClause(routes = ROUTES, dryRunOnly = DRY_RUN_ONLY) {
  const writes = routes.filter((r) => r.method !== "GET");
  const spenders = writes.filter((r) => r.spends);
  if (spenders.length === 0) {
    if (!dryRunOnly) {
      // Reachable only if someone opens a non-dry-run lane without declaring it as
      // spending. The honest sentence is the one that says nobody checked.
      return "none of them is declared as spending, but this surface has a non-dry-run lane";
    }
    return writes.length === 2 ? "neither spends" : `${count(spenders.length)} of them spends`;
  }
  return `${count(spenders.length)} of them can reach a metered provider operation`;
}

// The table and the flag are PARAMETERS with the shipping values as defaults, so the
// gate can hand this generator a mutated table — a write declared as spending, a
// non-dry-run lane — and assert the sentences change. A generator that can only be
// called one way can only be read, and reading it is what this programme keeps
// getting wrong.
export function capabilitySentences(routes = ROUTES, dryRunOnly = DRY_RUN_ONLY) {
  const reads = routes.filter((r) => r.method === "GET" && r.daemon);
  const writes = routes.filter((r) => r.method !== "GET");
  const localOnly = routes.filter((r) => r.method === "GET" && !r.daemon);
  const clause = spendClause(routes, dryRunOnly);

  return {
    // The header chip. It carried the old no-writes claim for a build after the door
    // was wired. (That phrase is deliberately not repeated here: this module is
    // BUNDLED AND SERVED, comments included, and the gate's absence check reads served
    // bytes rather than source. A comment quoting the false sentence would put the
    // false sentence back on the wire — which is how an earlier assertion in this
    // programme first fired on a CSS comment.)
    chip: `reads · ${count(writes.length)} ${plural(writes.length, "write", "writes")}, ${clause}`,

    // The API surface's introduction, and the proxy's own refusal bodies. One count,
    // one place, and the 404 a caller receives now agrees with what is enforced.
    readAllowlist:
      `${count(reads.length)} daemon ${plural(reads.length, "read", "reads")}, exact-match and GET only` +
      (localOnly.length
        ? `, plus ${count(localOnly.length)} this surface answers itself`
        : ""),

    // Bare counting phrases, for slotting into a refusal body where a full sentence
    // would read as glued-together generated text — which it is, and should not look
    // like.
    writePhrase: `${count(writes.length)} ${plural(writes.length, "write", "writes")}`,
    readPhrase: `${count(reads.length)} daemon ${plural(reads.length, "read", "reads")}`,

    // The spend clause on its own, so a caller can compose a sentence around it
    // instead of string-editing one of the sentences below. An earlier draft of this
    // module made the API surface strip a prefix off `writeSummary` with a regex,
    // which would have gone quietly wrong the first time the wording changed — the
    // same class of defect the whole file exists to remove, reintroduced one layer up.
    spendClause: clause,

    writeSummary:
      `${count(writes.length)} ${plural(writes.length, "write", "writes")}, and ${clause}`,

    // The absence claim, stated POSITIVELY. A surface may not say what it does not do;
    // it says what it does, and the count is generated, so the sentence goes stale the
    // moment the table changes rather than the moment someone notices.
    whatItDoes:
      `Everything this surface can ask the daemon: ${count(reads.length)} ` +
      `${plural(reads.length, "read", "reads")} and ${count(writes.length)} ` +
      `${plural(writes.length, "write", "writes")}. ${
        dryRunOnly && !anySpends(routes)
          ? "A real execution is a metered provider spend and no request composed by a " +
            "client reaches one through this surface."
          : "At least one route here can reach a metered provider operation."
      }`,
  };
}
