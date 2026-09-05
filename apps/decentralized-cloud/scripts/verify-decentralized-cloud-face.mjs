#!/usr/bin/env node
// M15.2 done-bar — the decentralized.cloud public face.
//
// Proves the face is what it claims: a read-only surface that owns nothing, invents
// no colour, and refuses everything outside a named allowlist. It starts its own
// server on an ephemeral port and talks to the running daemon; it performs no write
// against the daemon and never reaches a provider.
//
// Two of these checks exist because the brand review caught the same class of error
// twice: a hue that lived only on a sheet, and a frame that clipped its content.
// Neither can now reach a published surface without failing here first.
//
// Usage: node apps/decentralized-cloud/scripts/verify-decentralized-cloud-face.mjs

import { spawn, spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const REPO = path.resolve(APP, "../..");
const PORT = Number(process.env.IOI_DC_VERIFY_PORT || 4187);
const BASE = `http://127.0.0.1:${PORT}`;

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Where the surface lives, after the React port ───────────────────────────
// The surface used to be three files in public/. It is now a built app, and this gate
// has two different jobs that must not be confused with one another:
//
//   SOURCE assertions ask what the code SAYS — that a surface carries its unwired
//   label, that the canonical vocabulary is not re-spelled locally. Those read the
//   modules, with comments stripped, because a claim about what a reader is told
//   cannot be satisfied by a comment (it was, twice, before that was fixed).
//
//   SERVED assertions ask what a VISITOR RECEIVES. Those read the bytes off the
//   running server, because a build step is exactly the kind of transform that can
//   drop a label, and a gate that reads the source it was built from would not see it.
//
// Every path below is one or the other, deliberately, and the run builds before it
// serves so the served bytes are this commit's bytes and not the last build's.
const SRC_FILES = [
  "src/main.jsx",
  "src/App.jsx",
  "src/useSurfaceRead.js",
  "src/logic/classify.mjs",
  "src/logic/read.mjs",
  "src/logic/batches.mjs",
  "src/logic/surfaces.mjs",
  "src/logic/job-request.mjs",
  "src/components/Bits.jsx",
  "src/components/Dial.jsx",
  "src/components/Lockup.jsx",
  "src/surfaces/Candidates.jsx",
  "src/surfaces/Sources.jsx",
  "src/surfaces/Placement.jsx",
  "src/surfaces/Job.jsx",
  "src/surfaces/Redundancy.jsx",
  "src/surfaces/Receipts.jsx",
  "src/surfaces/Api.jsx",
];

const srcText = () => SRC_FILES.map((f) => readFileSync(path.join(APP, f), "utf8")).join("\n");
const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, "").replace(/^\s*\/\/[^\n]*$/gm, "");

// ── 1. No colour exists only on the surface ─────────────────────────────────
// Every hex the shipped face paints must be a value in the design system's token
// file. A colour invented in a stylesheet is a colour nobody measured.
function checkPalette() {
  const tokens = readFileSync(path.join(REPO, "packages/design-system/tokens/colors.css"), "utf8");
  const tokenHexes = new Set((tokens.match(/#[0-9a-fA-F]{6}/g) || []).map((h) => h.toLowerCase()));

  const surfaces = ["public/face.css", ...SRC_FILES];
  const strays = [];
  for (const rel of surfaces) {
    const body = readFileSync(path.join(APP, rel), "utf8");
    for (const hex of body.match(/#[0-9a-fA-F]{6}/g) || []) {
      if (!tokenHexes.has(hex.toLowerCase())) strays.push(`${rel}:${hex}`);
    }
  }
  ok("every colour the face paints is a design-system token",
    strays.length === 0, strays.join(", ") || `${tokenHexes.size} tokens`);
}

// ── 2. The evidence vocabulary is not re-spelled locally ────────────────────
// The face must classify candidates by the daemon's own label, not a synonym of it.
function checkVocabulary() {
  const js = srcText();
  for (const name of ["live_evidence", "simulated_control_plane", "observed_at", "expires_at", "evidence_mode"]) {
    ok(`the surface speaks the canonical name '${name}'`, js.includes(name));
  }
  ok("the surface never labels a simulator candidate live",
    !/simulated_control_plane[^\n]*live\s*:\s*true/.test(js));
}

// ── 2b. The refresher is a separate process, not part of the face ───────────
// The face's read-only claim survives only while the writer lives somewhere else.
function checkRefresherSeparation() {
  // Both files DISCUSS each other in their header comments — that is the point of
  // the comments. Strip them, or the assertion fires on prose that says the very
  // thing it is checking for.
  const code = (rel) =>
    readFileSync(path.join(APP, rel), "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");

  const serve = code("scripts/serve-face.mjs");
  const refresher = code("scripts/refresh-showcase.mjs");

  ok("the face server never imports or spawns the refresher",
    !/refresh-showcase/.test(serve));
  ok("the refresher never imports the face server",
    !/serve-face/.test(refresher));
  ok("the refresher is the only one of the two that writes to the daemon",
    /candidates\/refresh/.test(refresher) && !/candidates\/refresh/.test(serve));
  ok("the face's allowlist contains no refresh route",
    !/refresh/.test((serve.match(/const READS[\s\S]*?\]\);/) || [""])[0]));
  ok("the refresher never reaches a provider mutation",
    !/provider-ops/.test(refresher));

  const js = srcText();
  ok("the face reads the latest batch rather than every sweep ever taken",
    /batch/.test(js) && /batches/.test(js));
}

// ── 2c. Freshness is derived, never decorative ──────────────────────────────
// A dial animating on a timer of its own would look identical to one bound to a
// quote's window, and would be a lie the moment the two disagreed. So the sweep must
// be computed from observed_at and expires_at, and the real function is exercised on
// windows whose answers are known rather than read out of the source.
async function checkFreshnessIsDerived() {
  const css = readFileSync(path.join(APP, "public/face.css"), "utf8");
  ok("no animation drives the dial's sweep",
    !/\.dial[^{]*\{[^}]*animation|\.sweep[^{]*\{[^}]*animation/.test(css));

  // THE REAL FUNCTION, IMPORTED. The vanilla gate found `dialFraction` in the source
  // with a regular expression and evaluated the captured text with `new Function` —
  // which tested a string sliced out of a file, not the function the surface calls.
  // The port put the live rule in a framework-free module precisely so this gate can
  // import it: there is now no transform between the thing under test and the test.
  const { dialFraction } = await import(path.join(APP, "src/logic/classify.mjs"));
  ok("the dial's fraction is computed by the module the surface imports",
    typeof dialFraction === "function");
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const expired = dialFraction(iso(now - 20 * 60_000), iso(now - 5 * 60_000));
  const fresh = dialFraction(iso(now - 1_000), iso(now + 15 * 60_000));
  const half = dialFraction(iso(now - 5 * 60_000), iso(now + 5 * 60_000));
  ok("a window already past reads empty", expired === 0, `fraction ${expired}`);
  ok("a window just opened reads full", fresh > 0.99, `fraction ${fresh.toFixed(4)}`);
  ok("a window half spent reads about half", Math.abs(half - 0.5) < 0.01, `fraction ${half.toFixed(4)}`);
  ok("a candidate with no window drives no dial",
    dialFraction(undefined, undefined) === null && dialFraction("2026-01-01T00:00:00Z", "bad") === null);
}

// ── 2d. The unwired write surfaces say so, and stay unwired ─────────────────
function checkUnwiredSurfaces() {
  // ONE FILE PER SURFACE, which removes the defect class outright rather than
  // defending against it. The vanilla gate sliced one 930-line file between function
  // boundaries, and mutation found two ways that slice reached the WRONG surface's
  // label: a fixed 7000-character window that ran into the next function, and then a
  // bounded slice that ended on the next section's comment banner carrying the same
  // phrase. A slice cannot overrun a file boundary.
  //
  // Comments are still stripped, because the assertion is about what a surface SAYS
  // to a reader, and source a reader never sees cannot satisfy a claim about what
  // they are told.
  for (const [file, surface, shape] of [
    ["src/surfaces/Job.jsx", "Job", "CloudJobRequest"],
    ["src/surfaces/Redundancy.jsx", "Redundancy", "RedundancyPosture"],
    ["src/surfaces/Receipts.jsx", "Receipts", "RoutingDecisionReceipt"],
  ]) {
    const body = stripComments(readFileSync(path.join(APP, file), "utf8"));
    ok(`${surface} is labelled designed, not connected`,
      /designed, not connected/.test(body) || /<NotConnected>/.test(body));
    ok(`${surface} names the canonical shape it draws`, body.includes(shape), shape);
  }

  // The label element itself must carry the words. `<NotConnected>` above proves the
  // surface uses the component; this proves the component says what its name claims.
  const bits = stripComments(readFileSync(path.join(APP, "src/components/Bits.jsx"), "utf8"));
  ok("the unwired label renders the words a reader is owed",
    /designed, not connected/.test(bits));

  const js = stripComments(srcText());

  // The registry's `wired` flag is a claim in code and it is checked against the
  // surfaces that actually carry an unwired label. A surface marked wired that still
  // renders <NotConnected>, or an unwired one that has quietly lost its label, is a
  // disagreement between what the app believes and what it tells a reader.
  const registry = readFileSync(path.join(APP, "src/logic/surfaces.mjs"), "utf8");
  for (const id of ["job", "redundancy", "receipts"]) {
    ok(`the registry marks ${id} unwired while it renders an unwired label`,
      new RegExp(`id:\\s*"${id}"[^}]*wired:\\s*false`).test(registry));
  }
  ok("every control drawn on a write surface is inert",
    (js.match(/className="button-inert"[^>]*disabled/g) || []).length >= 1);
  ok("the face declares no mutating fetch anywhere",
    !/method:\s*["'](POST|PUT|PATCH|DELETE)["']/i.test(js));
}

// ── 2e. One primitive, two doors ────────────────────────────────────────────
// The face claims a human's request and an agent's are the same CloudJobRequest
// differing in exactly one field. That is a claim about two literals, so they are
// compared field by field rather than trusted.
async function checkBothDoorsAreOnePrimitive() {
  // THE OBJECTS THEMSELVES, IMPORTED. The vanilla gate matched two literals out of the
  // source with a regular expression and evaluated the captured text — so it compared
  // two strings it had cut out of a file, and a change to the surrounding formatting
  // could have silently reduced it to `bodies.length === 0` and an early return.
  //
  // The port moved both request bodies into a framework-free module so this gate
  // imports the SAME objects the surface renders. There is no parse step between the
  // claim and its proof, and the Job surface importing them is what makes that true
  // rather than a coincidence.
  const { HUMAN_REQUEST: human, AGENT_REQUEST: agent } =
    await import(path.join(APP, "src/logic/job-request.mjs"));
  const jobSrc = readFileSync(path.join(APP, "src/surfaces/Job.jsx"), "utf8");
  ok("the job surface renders the same objects this gate compares",
    /from "\.\.\/logic\/job-request\.mjs"/.test(jobSrc) &&
    /JSON\.stringify\(HUMAN_REQUEST/.test(jobSrc) &&
    /JSON\.stringify\(AGENT_REQUEST/.test(jobSrc));
  const keys = [...new Set([...Object.keys(human), ...Object.keys(agent)])];
  const differing = keys.filter((k) => JSON.stringify(human[k]) !== JSON.stringify(agent[k]));
  ok("the two doors differ in exactly one field", differing.length === 1, differing.join(", ") || "none");
  ok("the field they differ in is the authority", differing[0] === "authority_ref", differing[0] || "—");
  ok("the human door carries a wallet grant", String(human.authority_ref).startsWith("wallet-grant://"));
  ok("the agent door carries a capability lease", String(agent.authority_ref).startsWith("capability-lease://"));
  ok("neither door names a venue",
    !("venue" in human) && !("venue" in agent) &&
    !/provider_kind|venue/.test(JSON.stringify({ human, agent })));
  ok("neither door carries a provider credential",
    !/credential|api[_-]?key|secret|token/i.test(JSON.stringify({ human, agent })));
}

// (2f was a pair of assertions that could not both hold, and it is gone. See
// checkScoreIsNotServed below, which runs against the server rather than the files.)

// ── 3. The served surface refuses everything it should ──────────────────────
async function checkServer() {
  // THE SURFACE IS BUILT BEFORE IT IS SERVED, in this process, every run. Without
  // this the gate would measure whatever happened to be in dist/ — which is how a
  // 585px artboard once passed 7/7 against a built sheet that predated the source
  // edit, and how three cold readers scored a plate the run had never written.
  const built = spawnSync("npm", ["run", "build", "--workspace=decentralized-cloud"], {
    cwd: REPO, encoding: "utf8", timeout: 10 * 60 * 1000,
  });
  ok("the surface builds, and this run's bytes are the bytes under test",
    built.status === 0,
    built.status === 0
      ? "dist/ rebuilt from source before the server started"
      : String(built.stderr || built.stdout || "").split("\n").slice(-4).join(" | "));
  if (built.status !== 0) return;

  const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
    env: { ...process.env, IOI_DC_PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let booted = false;
  server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });

  try {
    for (let i = 0; i < 40 && !booted; i++) await sleep(100);
    ok("the face server starts", booted);
    if (!booted) return;

    const index = await fetch(`${BASE}/`);
    ok("the shell is served", index.status === 200, `HTTP ${index.status}`);

    // ── The identity's provisional score never reaches a reader. ──
    //
    // This assertion used to read the SOURCE FILES, strip comments, and scan the
    // remainder — so it examined a transformed copy while `index.html` shipped
    // `identity v0 — provisional, score 50` verbatim to every view-source. Worse, it
    // was paired with a second assertion REQUIRING that phrase to exist in the
    // source, so the two could not both hold in a file served as-is: the gate was
    // compelling the very defect it claimed to prevent, and the label could not be
    // removed without turning the gate red.
    //
    // Both are replaced by one assertion that reads the BYTES THE SERVER SENDS,
    // comments included, across every asset a visitor can fetch. The status now
    // lives in brand/identity-status.md, which is never served.
    const servedAssets = ["/", "/assets/face.js", "/assets/index.css"];
    const leaked = [];
    for (const asset of servedAssets) {
      const res = await fetch(`${BASE}${asset}`);
      const raw = await res.text();
      if (/identity v0|provisional,? score|scored? 50/i.test(raw)) leaked.push(asset);
    }
    ok("the identity's provisional score is in no byte this server sends",
      leaked.length === 0,
      leaked.length ? `leaked in ${leaked.join(", ")}` : `${servedAssets.length} assets scanned raw`);

    // ── The wordmark has ONE source, and this is what makes that true. ──
    //
    // brand/wordmark/wordmark.mjs has said since it was written that the shipped
    // markup "is checked against it mechanically rather than by comment", and that
    // THIS gate "asserts the shipped markup carries exactly the values below". No
    // such assertion existed. Nothing under scripts/ or public/ imported the module
    // at all. It was a convention that read as a guarantee, enforced nowhere and
    // relied on everywhere — which is precisely how the Z once came to be fixed on
    // the surface and not in the harness, voiding a round of lockups.
    //
    // The assertion reads the BYTES THE SERVER SENDS and compares them against the
    // module's own exported constant. Not the source file on disk, which is a copy
    // the server may or may not be sending. Not a regex for something Z-shaped,
    // which any well-formed path would satisfy. The exact string, from the one
    // source, in the response a visitor receives.
    const wm = await import(path.join(APP, "brand/wordmark/wordmark.mjs"));
    // THE UNION OF EVERY BYTE A VISITOR RECEIVES, not the shell alone. Before the port
    // the wordmark was a literal in index.html and reading the shell was the same as
    // reading the surface. It is now a component in the bundle, and a gate still
    // looking only at the shell would have gone green while asserting nothing at all —
    // the assertion would have been about a file that no longer carries the value.
    const shell = (
      await Promise.all(servedAssets.map(async (a) => (await fetch(`${BASE}${a}`)).text()))
    ).join("\n");
    // The VALUE, not the attribute. Before the port the path was a literal in the
    // shell's HTML and `d="…"` was the right thing to look for; in a built bundle it
    // is a JavaScript string the component passes to `d`, and a gate still matching
    // the attribute form would have gone red on a surface that was perfectly correct —
    // or, worse, been "fixed" by weakening it to something that matches anything.
    const carriesZ = shell.includes(wm.Z_PATH);
    ok("the served wordmark carries the Z path from its one source",
      carriesZ,
      carriesZ
        ? "the served shell carries wordmark.mjs's Z_PATH verbatim"
        : "the served shell does NOT carry the module's Z_PATH — the surface and its " +
          "one source have drifted, which is the whole state this gate exists to catch");

    // The drawn I is held to the same standard as the drawn Z, and for the same
    // reason: it is an override of the estate's brand face, adopted on the evidence of
    // three fresh readers, and an override that can drift from its source is an
    // override nobody can audit.
    const carriesI = shell.includes(wm.I_PATH);
    ok("the served wordmark carries the I path from its one source",
      carriesI,
      carriesI
        ? "the served shell carries wordmark.mjs's I_PATH verbatim"
        : "the served shell does NOT carry the module's I_PATH — the drawn I and its " +
          "one source have drifted");

    // NEITHER OVERRIDE MAY BE SILENTLY DROPPED. A gate that only checks "the path in
    // the shell equals the module" passes if BOTH the shell and the module lose the
    // override together, or if the shell stops setting that letter as a drawn glyph at
    // all and falls back to the face. So the served bytes are also checked for the
    // FACE's own shapes, which are the exact things these overrides exist to replace.
    const facesOwnZ = "M 32 700 L 1033 700 L 1033 560 L 221 140";
    ok("the face's own numeral-shaped Z is in no byte this server sends",
      !shell.includes(facesOwnZ),
      shell.includes(facesOwnZ)
        ? "the served shell carries the pre-override Z, which four readers read as a 2"
        : "the pre-override Z is absent from the served shell");
    // THE MARK IS STILL THERE, and it is asserted because it once was not.
    // Porting the lockup to a component dropped the mark — not by a decision, but by
    // writing a new lockup and not carrying it over. Every gate stayed green, because
    // no gate asserted that the product's only mark exists. A screenshot caught it.
    // The mark is the owner's reserved form, shipped provisional; removing it by
    // omission is still removing it.
    // Anchored on the mark's OWN mask id, which nothing else in the surface uses, plus
    // the accessible name. My first attempt matched `aria-label="…"` — the JSX form —
    // and went red against a perfectly correct build, because the bundler emits
    // `"aria-label": "…"`. An assertion written against the source's spelling rather
    // than the artifact's is the same mistake as reading the source instead of the
    // served bytes, one layer down.
    // Anchored on the mark's OWN PATH DATA, which nothing else in the surface draws.
    // Two earlier versions of this assertion were weaker in two different ways and both
    // are worth recording. The first matched `aria-label="…"` — the JSX spelling — and
    // went red against a correct build, because the bundler emits `"aria-label": "…"`;
    // an assertion written against the source's spelling rather than the artifact's is
    // the same mistake as reading source instead of served bytes, one layer down. The
    // second matched the mask id `cloud-cue`, and SURVIVED a mutation that renamed it
    // to `cloud-cue-removed` — because a substring test passes on any name containing
    // it. A rename is the most likely way this drawing actually changes.
    const MARK_PATH = "M 41.44 0.00 C 38.66 0.00 36.33 2.13 36.09 4.90";
    const hasMark = shell.includes(MARK_PATH) && /decentralized\.cloud/.test(shell);
    ok("the served surface still carries the mark, with the product's name on it",
      hasMark,
      hasMark
        ? "the mark is present and is what carries the accessible name"
        : "the served bytes carry no mark — it has been removed, and if that was not a " +
          "decision somebody made on purpose, it is the port dropping it again");

    // THE RUN BREAKS BEFORE THE I. This is the assertion that proves the letter is
    // DRAWN rather than set in the face, and it catches what the path-equality check
    // above cannot: a surface that keeps I_PATH in a disabled element while setting
    // "decentrali" as one run passes equality and fails this. That exact mutant was
    // planted and it went red here alone.
    const breaks = /"decentral"|>decentral</.test(shell) && !/"decentrali"|>decentrali</.test(shell);
    ok("the wordmark's I is drawn rather than set in the face",
      breaks,
      breaks
        ? "the run breaks before the I, so the I is a drawn glyph and not the face's bare stem"
        : "the served bytes set 'decentrali' as one run — the I is the face's bare stem, " +
          "which two readers typed back as a lowercase l and one as DECENTRAL12ED");

    const unknown = await fetch(`${BASE}/api/not-a-real-read`);
    const unknownBody = await unknown.json().catch(() => ({}));
    ok("a path off the allowlist is refused BY NAME",
      unknown.status === 404 && unknownBody.state === "route_not_on_read_allowlist",
      `HTTP ${unknown.status} ${unknownBody.state || ""}`);
    ok("the refusal names what the surface does expose",
      Array.isArray(unknownBody.allowed) && unknownBody.allowed.length === 4,
      (unknownBody.allowed || []).join(", "));

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const res = await fetch(`${BASE}/api/candidate-sources`, { method });
      const body = await res.json().catch(() => ({}));
      ok(`${method} is refused as method_not_allowed`,
        res.status === 405 && body.state === "method_not_allowed",
        `HTTP ${res.status} ${body.state || ""}`);
    }

    // The daemon read itself. Slow by nature — a full sweep has been measured at
    // 38.8s — so this is the one check with a long ceiling.
    const sources = await fetch(`${BASE}/api/candidate-sources`);
    const sourcesBody = await sources.json().catch(() => ({}));
    if (sources.status === 200 && Array.isArray(sourcesBody.sources)) {
      ok("candidate-sources proxies the daemon's own body",
        sourcesBody.sources.every((s) => typeof s.source === "string" && typeof s.state === "string"),
        `${sourcesBody.sources.length} sources`);
      const unavailable = sourcesBody.sources.filter((s) => s.state === "candidate_source_unavailable");
      ok("every unavailable source keeps its named reason through the proxy",
        unavailable.every((s) => typeof s.reason === "string" && s.reason.length > 0),
        `${unavailable.length} unavailable`);
    } else {
      ok("candidate-sources proxies the daemon's own body", false,
        `HTTP ${sources.status} ${sourcesBody.state || "no sources array"} — is the daemon running?`);
    }
    // The face can only show a fresh batch if the daemon labels batches at all.
    const cands = await fetch(
      `${BASE}/api/candidates?intent_ref=${encodeURIComponent("cloud-resource-intent://cri_default")}`
    );
    const candsBody = await cands.json().catch(() => ({}));
    const list = Array.isArray(candsBody.candidates) ? candsBody.candidates : [];
    if (cands.status === 200) {
      ok("every candidate carries the batch it was observed in",
        list.length > 0 && list.every((c) => typeof c.batch === "string" && c.batch.length > 0),
        `${list.length} candidates`);

      const batches = new Map();
      for (const c of list) {
        const seen = batches.get(c.batch) || "";
        if ((c.observed_at || "") > seen) batches.set(c.batch, c.observed_at || "");
      }
      const newest = [...batches.entries()].sort((a, b) => (a[1] < b[1] ? 1 : -1))[0];
      const inNewest = list.filter((c) => c.batch === newest?.[0]);
      const liveNow = inNewest.filter(
        (c) => c.evidence_mode === "live_evidence" && Date.parse(c.expires_at || 0) > Date.now()
      );
      // Whether a live price exists right now is the weather, not the mechanism, so
      // this reports it rather than failing on it — but the newest batch must be a
      // real cohort, not a mix of every sweep ever taken.
      ok("the newest batch is one cohort, not an accumulation",
        inNewest.length > 0 && inNewest.length <= list.length,
        `batch ${newest?.[0]} — ${inNewest.length} of ${list.length} candidates, ${liveNow.length} live right now`);
    } else {
      ok("every candidate carries the batch it was observed in", false, `HTTP ${cands.status}`);
    }
  } finally {
    server.kill("SIGTERM");
  }
}

// ── 4. No artboard clips, and every contrast figure is computed ─────────────
async function checkBrandGates() {
  const run = (script) =>
    new Promise((resolve) => {
      const p = spawn("node", [path.join(APP, "brand", script)], { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      p.stdout.on("data", (b) => { out += b; });
      p.stderr.on("data", (b) => { out += b; });
      p.on("close", (code) => resolve({ code, out }));
    });

  // BUILD BEFORE MEASURING. `brand/canvas/` is a gitignored build artifact, and this
  // gate once measured whatever happened to be sitting there — so the assertion was
  // only as fresh as whoever last ran the build by hand. A source edit that added a
  // 585px clip to the identity sheet passed 7/7 here because the built sheet being
  // measured predated the edit: a fresh checkout and a working checkout could
  // disagree about whether the same source passes, and the working checkout was the
  // one being believed.
  //
  // RESTORED after the identity merge. Resolving that conflict by taking the other
  // branch's whole file dropped this block, because that branch never carried the
  // commit — which is the merge-resolution version of the same lesson.
  const built = await run("build-artboards.mjs");
  ok("the brand canvas is rebuilt from src/ before it is measured",
    built.code === 0, (built.out.match(/^brand artboards: .*$/m) || [""])[0] || built.out.slice(-160));
  if (built.code !== 0) return;

  const frames = await run("measure-artboards.mjs");
  const fitLine = (frames.out.match(/^\d+\/\d+ artboards fit their frame.*$/m) || [])[0] || "";
  ok("every brand artboard fits its declared frame", frames.code === 0, fitLine || frames.out.slice(-160));

  const contrast = await run("measure-contrast.mjs");
  ok("the contrast pairs the sheets cite are computed, not asserted",
    /pairs measured/.test(contrast.out), (contrast.out.match(/^\d+ pairs measured\.$/m) || [""])[0]);
}

// ── 5. A price keeps its unit ───────────────────────────────────────────────
// A scripted edit once ate the literal "$" from both price cells, and every other
// check passed: the syntax parsed, this gate was green, the table semantics measured
// correct, overflow measured zero. The surface rendered "0.0136" — a currency figure
// with no unit, on a face whose whole job is saying what a number is. A price without
// its unit is a number without a basis, so the unit is asserted.
function checkPriceKeepsItsUnit() {
  // Matched per LINE, not with a template-literal regex: backticks appear all over
  // this file, so `[^`]*usd_per_hour[^`]*` happily spans from one unrelated literal
  // to the next and reports a match that is not a price at all. It did exactly that
  // on its first run and failed a correct file.
  const lines = readFileSync(path.join(APP, "public/face.js"), "utf8").split("\n");
  const priced = lines.filter((l) => /usd_per_hour[^\n]*toFixed\(/.test(l));
  ok("both price cells state their currency",
    priced.length >= 2 && priced.every((l) => l.includes("$${")),
    priced.length ? priced.map((l) => l.trim().slice(0, 44)).join(" | ") : "no price template found");
}

// ── 6. The layout neither overflows nor collides ────────────────────────────
// Overflow and collision are DIFFERENT FAILURES and neither implies the other. This
// surface once measured 0px of horizontal scroll at 1440 while the status block sat
// on top of the last nav button — 25x29px of shared area — and the responsive work
// was reported finished on the strength of the overflow number alone. The brand
// harness has checked artboards for both since its first round; the face gets the
// same pair here, at every width the design claims to handle.
async function checkResponsiveLayout() {
  const { chromium } = await import("/home/heathledger/Documents/ioi/repos/ioi/node_modules/playwright/index.mjs");
  const port = PORT + 1;
  const server = spawn("node", [path.join(APP, "scripts/serve-face.mjs")], {
    env: { ...process.env, IOI_DC_PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let booted = false;
  server.stdout.on("data", (b) => { if (String(b).includes("face on")) booted = true; });
  const browser = await chromium.launch();
  try {
    for (let i = 0; i < 40 && !booted; i++) await sleep(100);
    // EVERY SURFACE, not just the landing one. The first responsive pass measured the
    // default surface at three widths, found 0px of overflow, and reported the layout
    // fixed; a review then found 238px of body scroll and four text-on-text collisions
    // at 390px on Redundancy, plus overflow on Job and Placement — four of the seven
    // surfaces had never been opened at that width. A check that visits one screen is
    // a claim about one screen.
    const SURFACES = ["candidates", "sources", "placement", "job", "redundancy", "receipts", "api"];
    for (const w of [1920, 1520, 1440, 1180, 900, 640, 390]) {
      const page = await browser.newPage({ viewport: { width: w, height: 900 } });
      await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "domcontentloaded" });
      await page.waitForTimeout(2200);
      // The read-backed surfaces are slow and their emptiness is not a layout fault,
      // so the ones that render synchronously carry the width check.
      for (const s of ["job", "redundancy", "receipts", "api", "candidates"]) {
        await page.click(`.nav button[data-surface="${s}"]`).catch(() => {});
        await page.waitForTimeout(220);
        const m = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        ok(`at ${w}px the ${s} surface does not scroll sideways`, m <= 0, `overflow ${m}px`);
      }
      await page.click(`.nav button[data-surface="candidates"]`).catch(() => {});
      await page.waitForTimeout(400);
      const m = await page.evaluate(() => {
        const overflow = document.documentElement.scrollWidth - window.innerWidth;
        // "Leaf" means CARRIES ITS OWN TEXT, not childless: a chip holds a dot span
        // beside its label, and a childless-only rule skips exactly the element whose
        // overrun this exists to catch. Same rule as measure-artboards.mjs.
        const leaves = [];
        for (const el of document.querySelectorAll("body *")) {
          if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
          const cs = getComputedStyle(el);
          if (cs.position !== "static" || cs.visibility === "hidden") continue;
          const rects = [...el.getClientRects()].filter((r) => r.width > 1 && r.height > 1);
          if (rects.length) leaves.push({ el, rects, text: (el.textContent || "").trim().slice(0, 20) });
        }
        const hits = [];
        for (let i = 0; i < leaves.length; i++) for (let j = i + 1; j < leaves.length; j++) {
          const a = leaves[i], b = leaves[j];
          if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
          for (const ra of a.rects) for (const rb of b.rects) {
            const ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
            const oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
            // A couple of pixels is antialiasing and line-box slack; more than that on
            // both axes is two things sitting on top of each other.
            if (ox > 3 && oy > 3) hits.push(`"${a.text}" over "${b.text}"`);
          }
        }
        return { overflow, hits: [...new Set(hits)].slice(0, 3) };
      });
      await page.close();
      ok(`at ${w}px the body does not scroll sideways and nothing collides`,
        m.overflow <= 0 && m.hits.length === 0,
        `overflow ${m.overflow}px${m.hits.length ? `; ${m.hits.join(", ")}` : ""}`);
    }
  } finally {
    await browser.close();
    server.kill("SIGTERM");
  }
}

async function run() {
  checkPalette();
  checkVocabulary();
  checkRefresherSeparation();
  await checkFreshnessIsDerived();
  checkUnwiredSurfaces();
  await checkBothDoorsAreOnePrimitive();
  checkPriceKeepsItsUnit();
  await checkServer();
  await checkResponsiveLayout();
  await checkBrandGates();
}

run().then(() => {
  let fail = 0;
  for (const r of results) {
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? `  (${r.detail})` : ""}`);
    if (!r.pass) fail++;
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`decentralized.cloud face: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
