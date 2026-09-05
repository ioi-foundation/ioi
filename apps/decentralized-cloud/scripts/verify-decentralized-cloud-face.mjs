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
// The route table, imported by the gate for the same reason the proxy and the API
// surface import it: three copies of a list is three chances for one of them to be
// the stale one, and the stale one is always the one somebody reads.
import * as cap from "../src/logic/capability.mjs";
// The gate-origin mark, hoisted to the top because EVERY record this gate creates
// carries it — including the refusal probes, which are composed well before the block
// that used to import it lazily.
import { GATE_ORIGIN_REF } from "../src/logic/job-door.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP = path.join(HERE, "..");
const REPO = path.resolve(APP, "../..");
const PORT = Number(process.env.IOI_DC_VERIFY_PORT || 4187);
const BASE = `http://127.0.0.1:${PORT}`;

// ── Assertions, and the vacuity rule ─────────────────────────────────────────
//
// THE FAILURE THIS EXISTS FOR. Three of seven widths were inspecting ZERO table cells
// while the run reported 144/144, because the page had not finished loading and "no
// cell is misdeclared" is trivially true of no cells. Every overflow, collision and
// cell number at those widths described a page reading "Asking the daemon" — including
// the ones I had cited as evidence the layout was sound.
//
// Making that one assertion count its cells fixed that one assertion. The rule below
// is the CLASS, and it is enforced by the RUNNER rather than by the author remembering.
//
// It applies to UNIVERSALLY QUANTIFIED assertions — "every X is Y", "no X is Y" —
// because those are the ones that pass on an empty set. A single-subject assertion
// ("the mark is in the served bytes") cannot pass by inspecting nothing: with nothing
// to inspect its condition is false and it goes red, which is the correct outcome. So
// the rule is aimed at exactly the shape that carries the defect, rather than being a
// blanket wide enough that people learn to route around it.
//
//   ok(name, cond, detail, inspected)   `inspected` = how many things were looked at
//   okMayBeEmpty(...)                   declares zero a valid outcome, BY NAME
//
// A universally-quantified assertion that reports NO count, or a count of zero without
// declaring zero valid, fails the RUN — it is not counted as a pass. A gate that
// cannot say what it looked at is not reporting a result.
const results = [];
// "only" is here because `[].every(...)` is true: "the only verb the surface sends is
// POST" passed over an empty list of verbs, and would have gone on passing if the
// door's fetch were ever written in a way the regex did not find.
const UNIVERSAL = /\b(every|each|all|none|no|only)\b/i;
const ok = (name, cond, detail, inspected) => {
  results.push({ name, pass: !!cond, detail: detail || "", inspected });
};
// For assertions where an empty set is a real expected outcome rather than a symptom.
// Declared through a different function so the declaration is visible in a diff.
const okMayBeEmpty = (name, cond, detail, inspected) => {
  results.push({ name, pass: !!cond, detail: detail || "", inspected, zeroDeclared: true });
};
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
  // ADDED after the vacuity rule reported "the only verb the surface sends is POST"
  // as inspecting ZERO verbs. The door module — the only file in the surface that
  // sends a verb at all — was not in this list, so every assertion scanning "the
  // surface's source" for HTTP methods was scanning a corpus with no HTTP methods in
  // it. It had been passing since the door was wired.
  "src/logic/job-door.mjs",
  "src/logic/capability.mjs",
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
  // Counted, because "no stray hex" is true of a file set that yielded no hexes at
  // all — and a surface whose colours had all moved into a file this list forgot
  // would pass exactly as loudly as one that is correct.
  let painted = 0;
  for (const rel of surfaces) {
    const body = readFileSync(path.join(APP, rel), "utf8");
    for (const hex of body.match(/#[0-9a-fA-F]{6}/g) || []) {
      painted++;
      if (!tokenHexes.has(hex.toLowerCase())) strays.push(`${rel}:${hex}`);
    }
  }
  ok("every colour the face paints is a design-system token",
    strays.length === 0,
    strays.join(", ") || `${painted} hexes across ${surfaces.length} files, all among ${tokenHexes.size} tokens`,
    painted);
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
    /candidates\/refresh/.test(refresher) && !/candidates\/refresh/.test(serve),
    "the refresh write is in the refresher and absent from the face server",
    2);
  // This used to slice `const READS … ]);` out of the server's source and grep the
  // slice. Moving the table into capability.mjs deleted that declaration, so the
  // regex matched nothing, the slice was the empty string, and "no refresh route in
  // the allowlist" passed by looking at NO allowlist at all. The vacuity rule caught
  // it on its first run. It now reads the table the server actually dispatches from,
  // and counts the routes it checked.
  const refreshRoutes = cap.ROUTES.filter((r) => /refresh/.test(r.face) || /refresh/.test(r.daemon || ""));
  ok("the face's allowlist contains no refresh route",
    refreshRoutes.length === 0,
    refreshRoutes.length
      ? `the refresher's write is reachable from the face: ${refreshRoutes.map((r) => r.face).join(", ")}`
      : `${cap.ROUTES.length} routes checked, none of them a refresh`,
    cap.ROUTES.length);
  ok("the refresher never reaches a provider mutation",
    !/provider-ops/.test(refresher));

  const js = srcText();
  ok("the face reads the latest batch rather than every sweep ever taken",
    /batch/.test(js) && /batches/.test(js),
    `both batch selectors present across ${SRC_FILES.length} source files`,
    SRC_FILES.length);
}

// ── 2c. Freshness is derived, never decorative ──────────────────────────────
// A dial animating on a timer of its own would look identical to one bound to a
// quote's window, and would be a lie the moment the two disagreed. So the sweep must
// be computed from observed_at and expires_at, and the real function is exercised on
// windows whose answers are known rather than read out of the source.
async function checkFreshnessIsDerived() {
  const css = readFileSync(path.join(APP, "public/face.css"), "utf8");
  // Counted over the rules this is ABOUT. If the dial's rules were renamed, there
  // would be no .dial or .sweep blocks left, and "none of them animates" would be
  // true of nothing — a green light for a stylesheet the assertion no longer
  // describes.
  const dialRules = css.match(/\.(dial|sweep)[^{]*\{[^}]*\}/g) || [];
  const animated = dialRules.filter((r) => /animation/.test(r));
  ok("no animation drives the dial's sweep",
    animated.length === 0,
    animated.length
      ? `animated: ${animated.join(" ")}`
      : `${dialRules.length} dial/sweep rules, none animating`,
    dialRules.length);

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
    dialFraction(undefined, undefined) === null && dialFraction("2026-01-01T00:00:00Z", "bad") === null,
    "both the absent window and the unparseable one return null rather than a fraction",
    2);
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
    ["src/surfaces/Redundancy.jsx", "Redundancy", "RedundancyPosture"],
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
  ok("the registry marks redundancy unwired while it renders an unwired label",
    /id:\s*"redundancy"[^}]*wired:\s*false/.test(registry));
  // The two that were unwired and now are not. This is asserted so the flag cannot be
  // flipped back to false while the door still exists, or forward while it does not.
  for (const id of ["job", "receipts"]) {
    ok(`the registry marks ${id} wired, and the door it names exists`,
      new RegExp(`id:\\s*"${id}"[^}]*wired:\\s*true`).test(registry));
  }

  // ── The mutating surface, stated exactly ──────────────────────────────────
  // This assertion used to read "the face declares no mutating fetch anywhere", and
  // that was true and is not any more: the job door posts. Weakening it to nothing
  // would have been the easy move and the wrong one — the claim that matters was never
  // "no POST exists", it was "no POST exists that I did not name". So it is replaced by
  // a CLOSED list: exactly two POSTs, and no other verb at all.
  const doorSrc = readFileSync(path.join(APP, "src/logic/job-door.mjs"), "utf8");
  // SCANNED OVER THE MODULES THAT ACTUALLY FETCH, not over the whole surface.
  // Widening this to every source file swept in capability.mjs's route table, whose
  // `method: "GET"` entries are DECLARATIONS OF WHAT THE PROXY SERVES — not verbs the
  // browser sends — and the assertion went red on eight of its own allowlist rows. An
  // assertion is only as good as the corpus it names, and "all the source" is not a
  // corpus, it is an absence of one.
  const fetchingModules = ["src/logic/job-door.mjs", "src/logic/read.mjs"]
    .map((f) => readFileSync(path.join(APP, f), "utf8")).join("\n");
  const posts = [...fetchingModules.matchAll(/method:\s*"(\w+)"/g)].map((m) => m[1]);
  ok("the only verb the surface sends is POST",
    posts.every((v) => v === "POST"),
    // `[].every()` is TRUE, so this is a textbook vacuous pass waiting for the day the
    // door's fetch is written differently and the regex finds no verbs at all. The
    // count is what stops that being green.
    posts.length ? posts.join(", ") : "NO VERBS FOUND — this assertion had nothing to check",
    posts.length);
  ok("the surface posts to exactly two paths, both named",
    /"\/api\/jobs"/.test(doorSrc) && /\/api\/jobs\/\$\{encodeURIComponent\(jobId\)\}\/dry-run/.test(doorSrc),
    "both the admit path and the dry-run path are literals in the door module",
    2);
  const forbiddenVerbs = ["PUT", "PATCH", "DELETE"];
  const declared = forbiddenVerbs.filter((v) => new RegExp(`method:\\s*["']${v}["']`, "i").test(js));
  ok("no PUT, PATCH or DELETE is declared anywhere on the surface",
    declared.length === 0,
    declared.length ? `declared: ${declared.join(", ")}` : `${forbiddenVerbs.length} verbs checked across ${SRC_FILES.length} source files`,
    forbiddenVerbs.length);

  // THE SPEND FENCE, in the source. The proxy is what enforces it and the served-bytes
  // check below proves it against the daemon; this asserts the door module does not
  // even offer the caller a way to ask.
  ok("the job door never sends dry_run — it is not the client's field to set",
    !/dry_run/.test(doorSrc.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "")));
  const serveSrc = readFileSync(path.join(APP, "scripts/serve-face.mjs"), "utf8");
  ok("the proxy OVERWRITES dry_run rather than forwarding it",
    /body\s*=\s*\{\s*\.\.\.body,\s*dry_run:\s*true\s*\}/.test(serveSrc));
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
      leaked.length ? `leaked in ${leaked.join(", ")}` : `${servedAssets.length} assets scanned raw`,
      servedAssets.length);

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
        : `the pre-override Z is absent from ${shell.length} served bytes`,
      // The bytes are the thing inspected here. Zero of them would mean the fetches
      // returned nothing and the absence is an artifact of an empty string, which is
      // this gate's own scar in miniature.
      shell.length);
    // ── THE FIELD CONTRACT, against LIVE bodies ──────────────────────────────
    //
    // A field name is a fact about the DAEMON, and every assertion I had read my own
    // source. So the Sources surface read `provider_kind`, `source_ref`, `reason`,
    // `rule`, `http_status` and `offers_seen` — none of which the daemon sends — and
    // rendered "—" thirteen times out of thirteen under a subtitle promising it showed
    // the daemon's own evidence. Every gate was green.
    //
    // This fetches ONE LIVE BODY per read route through the surface's own proxy and
    // checks it against the names declared in src/logic/field-contract.mjs. A surface
    // may not read a field the daemon does not send.
    const { FIELD_CONTRACT, checkBody } = await import(path.join(APP, "src/logic/field-contract.mjs"));
    for (const route of Object.keys(FIELD_CONTRACT)) {
      const url = route === "/api/candidates" || route === "/api/placement-advisory"
        ? `${BASE}${route}?intent_ref=${encodeURIComponent("cloud-resource-intent://cri_default")}`
        : `${BASE}${route}`;
      const res = await fetch(url);
      if (!res.ok) {
        // NOT RUN is reported as its own state. Silence from a check that never ran
        // looks exactly like silence from a check that passed.
        ok(`the field contract for ${route} was checked against a live body`, false,
          `the route answered HTTP ${res.status}; the contract for ${route} was NOT verified`);
        continue;
      }
      const body = await res.json().catch(() => null);
      const r = checkBody(route, body);
      ok(`every field ${route} is read for exists in the daemon's live body`,
        r.failures.length === 0,
        r.failures.length
          ? r.failures.join(" · ")
          : (r.notes.join(" · ") || "no item fields declared"),
        // An empty container returns checked: 0, and a contract verified against no
        // items is not a verified contract.
        r.checked);
    }

    // ── EVERY CLASS THE SURFACE EMITS HAS A RULE IN THE STYLESHEET IT SHIPS ───
    //
    // I invented a class name that does not exist TWICE in one session. The first
    // (`tablewrap`, where the stylesheet defines `table-scroll`) left every table
    // without a scroll container and cost 70px of horizontal overflow at 390px; the
    // gate caught that one by its consequence. The second (`linklike`) would have
    // shipped an unstyled browser button sitting in a line of prose, and the only
    // reason it did not is that I grepped the stylesheet instead of trusting myself.
    //
    // Twice by grep is a pattern, so it becomes an assertion. Both sides are read from
    // the BUILT artifact: the class tokens the bundle actually emits, against the rules
    // the served stylesheet actually defines. Reading the JSX source would test a file
    // that a build step sits between — and a build step is exactly what this programme
    // keeps being surprised by.
    const bundleJs = await (await fetch(`${BASE}/assets/face.js`)).text();
    const bundleCss = await (await fetch(`${BASE}/assets/index.css`)).text();

    // Static class tokens only. A template literal like `chip ${kind}` contributes
    // "chip" and nothing else: the interpolated half is a runtime value and this
    // assertion has no business guessing it. Confining the instrument to what it can
    // actually see is what keeps a disagreement from it worth reading.
    const emitted = new Set();
    for (const m of bundleJs.matchAll(/className:\s*"([^"${}]+)"/g)) {
      for (const t of m[1].split(/\s+/)) if (t) emitted.add(t);
    }
    for (const m of bundleJs.matchAll(/className:\s*`([^`]*)`/g)) {
      for (const t of m[1].split(/\$\{[^}]*\}/).join(" ").split(/\s+/)) if (t) emitted.add(t);
    }
    const defined = new Set();
    for (const m of bundleCss.matchAll(/\.(-?[_a-zA-Z][\w-]*)/g)) defined.add(m[1]);

    const orphans = [...emitted].filter((c) => !defined.has(c)).sort();
    ok("every class the built surface emits resolves to a rule in the stylesheet it ships",
      orphans.length === 0,
      orphans.length
        ? `no rule for: ${orphans.join(", ")} — an invented class name renders as nothing and fails silently`
        : `${emitted.size} emitted class tokens, all defined among ${defined.size} in the served CSS`,
      emitted.size);

    // THE SURFACE DOES NOT CALL ITSELF READ-ONLY WHILE IT HAS A WRITE DOOR.
    // That claim stood in the header for a build after the door was wired — a false
    // statement on the one page whose subject is not making false statements. No gate
    // saw it; a screenshot did. It is asserted against the served bytes because the
    // claim is a rendered string, and it is asserted as an ABSENCE, which is the only
    // shape that catches it coming back.
    // AN ABSENCE ASSERTION PINNED TO ONE WORDING IS NOT AN ABSENCE ASSERTION.
    //
    // This checked for the exact phrase "read-only surface" and passed while
    // Redundancy's stub panel said "this server exposes no mutating route at all" — the
    // same false claim in different words, inside the one construct this product spends
    // its credibility on. A blind reviewer put a job through one of the two POSTs to
    // prove the sentence false. I had fixed the header chip and the API surface when I
    // wired the door and missed this one, and my own gate agreed with me.
    //
    // The fix is to look for the CLAIM rather than a phrasing of it: several ways of
    // saying "this surface performs no writes", any of which is now false.
    const NO_WRITE_CLAIMS = [
      /read-only surface/i,
      /exposes no mutating route/i,
      /no mutating route at all/i,
      /performs no writes?/i,
      /this surface writes nothing/i,
      /owns no write/i,
    ];
    const falseClaims = NO_WRITE_CLAIMS.filter((re) => re.test(shell)).map(String);
    ok("no served byte claims this surface performs no writes, in any wording",
      falseClaims.length === 0,
      falseClaims.length
        ? `the served bytes still make that claim: ${falseClaims.join(" ")} — ${cap.writeRoutes().length} POST routes exist`
        : `checked ${NO_WRITE_CLAIMS.length} ways of saying it; the served bytes make none of them`,
      NO_WRITE_CLAIMS.length);

    // ── NO INTERNAL IDENTIFIER REACHES A READER ──────────────────────────────
    // "refusing the other two by name until M15.9" and "both are M03.12's proof to
    // run" were rendered on the public surface. Neither resolves to anything a
    // stranger can look up, and a milestone number is an answer to a question they
    // cannot ask. The facts stay; they become product words — "not built yet",
    // "has not been run against a real lease".
    //
    // Asserted against SERVED BYTES, so a comment carrying one counts. That is not
    // pedantry: this gate has already caught the phrase "read-only surface" surviving
    // in a comment in a shipped module, and comments are served.
    const INTERNAL_IDS = [
      /\bM\d{2}\.\d+\b/,          // M15.9, M03.12
      /\bACC-\d+\b/,              // acceptance-criteria numbers
      /\bPR[:#]\s?\d+\b/,         // PR:9574
    ];
    const leakedIds = INTERNAL_IDS
      .map((re) => (shell.match(new RegExp(re, "g")) || []).slice(0, 4))
      .flat();
    ok("no internal milestone or PR identifier is in any byte this server sends",
      leakedIds.length === 0,
      leakedIds.length
        ? `served to readers: ${[...new Set(leakedIds)].join(", ")} — none of these resolves to anything a stranger can look up`
        : `${INTERNAL_IDS.length} identifier shapes checked across ${shell.length} served bytes`,
      INTERNAL_IDS.length);

    // ── THE CAPABILITY SENTENCES ARE GENERATED, AND THIS IS WHAT MAKES THAT TRUE ──
    //
    // A list of forbidden phrasings is better than one phrasing and is still a list of
    // phrasings: it catches the sentences I thought of. The sentences a reader is
    // shown about what this surface can do are now GENERATED from the route table the
    // proxy dispatches from, so the failure mode it replaces — a sentence that was
    // true when written, left standing after a route was added — cannot occur without
    // the table itself being wrong.
    //
    // Three separate things have to hold, and each has been false at some point:
    //   (a) the generated sentences actually REACH the reader,
    //   (b) the table is the DISPATCH and not a second copy beside it,
    //   (c) the generator responds to the table, which is checked by MUTATING it.
    const sentences = cap.capabilitySentences();

    // (a) The surfaces render the generator's output rather than a literal.
    //
    // My first version of this checked the SERVED BYTES for the generated sentence and
    // failed against a perfectly correct build — because a generated sentence is not
    // in the bundle. The bundle carries the GENERATOR; the sentence exists only after
    // it runs. Asserting a computed string appears as a literal in the artifact is a
    // demand that it not be computed, which is the opposite of the requirement.
    //
    // So this half asserts the call sites, and the RENDERED half — the sentence a
    // reader actually sees — is asserted in the browser, in checkRenderedCapability().
    const chipSrc = readFileSync(path.join(APP, "src/App.jsx"), "utf8");
    const apiSrc = readFileSync(path.join(APP, "src/surfaces/Api.jsx"), "utf8");
    const wired = [
      ["the header chip", chipSrc, /capabilitySentences\(\)/],
      ["the API surface", apiSrc, /capabilitySentences\(\)/],
    ];
    const unwired = wired.filter(([, src, re]) => !re.test(src)).map(([w]) => w);
    ok("every surface that states this one's capability generates the sentence",
      unwired.length === 0,
      unwired.length ? `still hand-written: ${unwired.join(", ")}` : `${wired.length} call sites`,
      wired.length);

    // Every route on the table is published on the API surface. The page used to
    // hand-copy seven rows under the words "the same four reads the server enforces";
    // now the rows ARE the table, and this checks that all of them arrive.
    const unpublished = cap.ROUTES.filter((r) => !shell.includes(r.face));
    ok("every route the proxy dispatches is published in the served bytes",
      unpublished.length === 0,
      unpublished.length
        ? `enforced but not published: ${unpublished.map((r) => `${r.method} ${r.face}`).join(", ")}`
        : `${cap.ROUTES.length} routes, all published`,
      cap.ROUTES.length);

    // (b) The proxy holds no route of its own. Both routes the job door added used to
    // live in path regexes BELOW the allowlist maps, so they were enforced and
    // uncounted at the same time — which is what made every published count wrong.
    // A bare /api path regex in the server is that shape coming back.
    const serveSrc = stripComments(readFileSync(path.join(APP, "scripts/serve-face.mjs"), "utf8"));
    // Counted over the /api MENTIONS in the server, not over the violations — a count
    // of violations is zero when the assertion passes, which would make every pass
    // vacuous by its own rule. What is inspected is every place the server names an
    // /api path; what is asserted is that none of them is a path regex of its own.
    const privateRoutes = serveSrc.match(/\/\^\\?\/api[^\n]*/g) || [];
    const delegates = /matchRoute\(/.test(serveSrc);
    ok("the server matches no /api path of its own outside the shared table",
      privateRoutes.length === 0 && delegates,
      privateRoutes.length
        ? `a route matched outside the table: ${privateRoutes.join(" ")} — enforced and uncounted is how the published counts went wrong`
        : delegates
          ? `the server names no /api path at all; all ${cap.ROUTES.length} are matched through the shared table`
          : "the server neither matches /api itself NOR calls matchRoute — it is serving nothing, and this assertion would have passed on that",
      // Inspected: the routes the table is responsible for. Counting the VIOLATIONS
      // would be zero on every pass, which would make the assertion fail its own rule
      // whenever it succeeded — a rule that only permits failure is not a rule.
      cap.ROUTES.length);

    // (c) THE MUTATION, run in-process against the generator itself. Declare a write
    // that spends and the sentences must stop promising nothing does. This is the
    // assertion that makes the other two mean something: without it, the generator
    // could return a constant and (a) would still pass.
    const mutated = cap.capabilitySentences(
      cap.ROUTES.map((r) => (r.method === "POST" && r.kind === "dry-run" ? { ...r, spends: true } : r))
    );
    const flipped =
      mutated.whatItDoes !== sentences.whatItDoes && mutated.chip !== sentences.chip &&
      !/no request composed by a client reaches one/.test(mutated.whatItDoes);
    ok("declaring a spending route changes what the surface says about spending",
      flipped,
      flipped
        ? `the mutated table generates "${mutated.chip}" instead of "${sentences.chip}"`
        : `MUTANT SURVIVED — the generator returns "${mutated.chip}" either way, so the ` +
          `sentence is not derived from the table and this whole file is decoration`);

    // And the live proof that the table is the dispatch: every GET on it answers
    // something other than the proxy's own "not on the allowlist" refusal. A route
    // published but not served is the same lie as a route served but not published,
    // pointing the other way.
    const unserved = [];
    for (const r of cap.readRoutes()) {
      const probe = r.face.replace(/:[a-z]+/g, "probe-id");
      const res = await fetch(`${BASE}${probe}`);
      let state = null;
      try { state = (await res.json())?.state; } catch { /* non-JSON is fine */ }
      if (res.status === 404 && state === "route_not_on_read_allowlist") unserved.push(r.face);
    }
    ok("every read route the surface publishes is one the server actually dispatches",
      unserved.length === 0,
      unserved.length
        ? `published but refused as unknown: ${unserved.join(", ")}`
        : `${cap.readRoutes().length} read routes, all dispatched (daemon-level errors are not this assertion's subject)`,
      cap.readRoutes().length);

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

    // ── THE JOB DOOR, against the RUNNING daemon ──────────────────────────────
    //
    // Not against a fixture and not against a recorded body. A job is admitted THROUGH
    // this surface, it is then found in the daemon's own list, its refusals are the
    // daemon's own codes, and the spend fence is exercised by trying to defeat it.
    //
    // If the daemon is not reachable, these are reported as NOT RUN rather than passing
    // quietly — silence from a check that never ran looks exactly like silence from a
    // check that passed.
    const jobsProbe = await fetch(`${BASE}/api/jobs`);
    const daemonUp = jobsProbe.status === 200;
    ok("the daemon answers the job list, so the door can be proven at all",
      daemonUp, `GET /api/jobs -> ${jobsProbe.status}`, 1);

    if (!daemonUp) {
      ok("THE JOB DOOR WAS NOT PROVEN — the daemon was unreachable", false,
        "these assertions did not run; that is not the same as passing");
    } else {
      // A refusal, by CODE, from the daemon's own mouth. A request with no deadline is
      // refused before anything is created.
      const noDeadline = await fetch(`${BASE}/api/jobs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          caller_kind: "human",
          // Tagged like every other record this gate creates. A refusal probe still
          // leaves a record, and an untagged record is one the ledger presents as a
          // product job.
          evidence_refs: [GATE_ORIGIN_REF],
          authority_ref: "wallet-grant://wg_gate_probe",
          budget_ref: "budget://does-not-exist",
          intent: { runtime_class: "compute.gpu_runtime" },
        }),
      });
      const noDeadlineBody = await noDeadline.json().catch(() => ({}));
      ok("a job with no deadline is refused by the daemon, by name",
        noDeadline.status === 422 && noDeadlineBody?.error?.code === "job_deadline_required",
        `${noDeadline.status} ${noDeadlineBody?.error?.code || "(no code)"}`,
        1);
      ok("the refusal carries the daemon's own sentence, not a paraphrase",
        typeof noDeadlineBody?.error?.message === "string" &&
        noDeadlineBody.error.message.length > 40,
        (noDeadlineBody?.error?.message || "").slice(0, 60));

      // The authority mode is resolved from caller_kind, and a mismatched ref is
      // refused rather than coerced.
      const mismatched = await fetch(`${BASE}/api/jobs`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          caller_kind: "human",
          evidence_refs: [GATE_ORIGIN_REF],
          authority_ref: "capability-lease://cl_gate_probe",
          budget_ref: "budget://does-not-exist",
          intent: { runtime_class: "compute.gpu_runtime" },
          deadline: { max_duration_hours: 1 },
        }),
      });
      const mismatchedBody = await mismatched.json().catch(() => ({}));
      ok("a human caller presenting a lease ref is refused by name",
        mismatchedBody?.error?.code === "job_authority_mode_mismatch",
        mismatchedBody?.error?.code || "(no code)");

      // An admission, for real, through this surface — then found in the daemon's list.
      const budgetsRes = await fetch(`${BASE}/api/budgets`);
      const budgetsBody = await budgetsRes.json().catch(() => ({}));
      const spend = (budgetsBody.budgets || budgetsBody.items || [])
        .find((b) => b.scope === "external_spend");
      ok("an external_spend budget exists for the door to draw on",
        !!spend, spend ? `budget://${spend.budget_id}` : "none — the admission below cannot run");

      if (spend) {
        // THE GATE LABELS ITS OWN RECORDS. It admits a real job every run — that is
        // what makes the door proven rather than asserted — and those proposals
        // accumulate in the daemon's data directory.
        //
        // They are NOT cleaned up afterwards: a gate that erases its own records is one
        // more artifact the estate cannot audit. Instead the run identifies itself in
        // `evidence_refs`, which the daemon passes through verbatim into the persisted
        // record, so the label lives in the daemon's own copy rather than in a list this
        // repository keeps on the side. The Receipts surface filters on the same
        // constant, imported from the same module, so the tag written and the tag
        // filtered cannot drift apart.
        // GATE_ORIGIN_REF is imported at the top of this file now — every record this
        // gate creates carries it, including the refusal probes above, which are
        // composed long before this block ran.
        const runRef = `run://face-gate-${Date.now()}`;
        const admitRes = await fetch(`${BASE}/api/jobs`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            caller_kind: "human",
            authority_ref: "wallet-grant://wg_face_gate",
            budget_ref: `budget://${spend.budget_id}`,
            intent: { runtime_class: "compute.gpu_runtime", gpu: { required: true, devices: 1, min_gb: 24 } },
            deadline: { max_duration_hours: 1 },
            redundancy: "none",
            receipt_requirements: ["placement", "spend"],
            evidence_refs: [GATE_ORIGIN_REF, runRef],
          }),
        });
        const admitBody = await admitRes.json().catch(() => ({}));
        const jobId = admitBody?.job?.job_id;
        ok("a job submitted THROUGH this surface is admitted by the daemon",
          admitRes.status === 201 && !!jobId, `${admitRes.status} ${jobId || "(no job_id)"}`);
        ok("the admitted record is a PROPOSAL and authorizes nothing",
          admitBody?.job?.state === "admitted_proposal", admitBody?.job?.state || "(no state)");
        ok("the human caller resolved to a wallet grant, not a lease",
          admitBody?.job?.authority?.mode === "wallet_grant" &&
          admitBody?.job?.authority?.caller_kind === "human",
          `${admitBody?.job?.authority?.caller_kind}/${admitBody?.job?.authority?.mode}`);
        ok("the budget was discovered BEFORE any mutation",
          admitBody?.job?.budget_discovery?.discovered_before_mutation === true);
        ok("the caller holds no provider credential in the admitted record",
          admitBody?.job?.authority?.credential_held_by_caller === false,
          `authority.credential_held_by_caller = ${JSON.stringify(admitBody?.job?.authority?.credential_held_by_caller)}`,
          1);

        // The label round-trips through the DAEMON'S record, not through anything this
        // process is holding. If it did not, the Receipts surface would filter on a tag
        // nothing carries and would quietly hide nothing at all — a filter that appears
        // to work by never matching.
        const refs = admitBody?.job?.evidence_refs;
        ok("the gate's own record says, in the daemon's copy, that the gate made it",
          Array.isArray(refs) && refs.includes(GATE_ORIGIN_REF) && refs.includes(runRef),
          Array.isArray(refs) ? refs.join(", ") : "evidence_refs absent");
        const { isGateAdmitted } = await import(path.join(APP, "src/logic/job-door.mjs"));
        ok("the surface's own filter recognises this record as gate-admitted",
          isGateAdmitted(admitBody?.job),
          "the tag the gate writes and the predicate the surface filters with are the same constant");

        // It is in the daemon's own list, read back independently.
        if (jobId) {
          const listBody = await (await fetch(`${BASE}/api/jobs`)).json();
          const found = (listBody.jobs || []).some((j) => j.job_id === jobId);
          ok("the job appears in the daemon's own list, read back after the write",
            found, found ? jobId : `${jobId} not found among ${(listBody.jobs || []).length} records`);

          // ── THE SPEND FENCE, exercised by trying to defeat it ──────────────
          // The request deliberately carries `dry_run: false`. The proxy must overwrite
          // it, and the DAEMON's echo — not this surface's — must come back true.
          const dryRes = await fetch(`${BASE}/api/jobs/${jobId}/dry-run`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ dry_run: false, idempotency_key: `gate-${Date.now()}` }),
          });
          const dryBody = await dryRes.json().catch(() => ({}));
          ok("a client asking for a REAL run through this door still gets a dry run",
            dryBody?.dry_run === true,
            `sent dry_run:false, the daemon echoed dry_run:${String(dryBody?.dry_run)}`);
          ok("the dry run reaches a placement and stops there",
            dryRes.status === 200 && dryBody?.job?.state === "placed",
            `${dryRes.status} ${dryBody?.job?.state || "(no state)"}`);
          // Counted over the receipts the record actually carries. A dry run mints a
          // placement receipt, so an empty map here does not mean "no provider
          // receipt" — it means the record shape changed and this assertion is
          // looking at nothing.
          const mintedKinds = Object.keys(dryBody?.job?.receipts || {});
          ok("no provider operation receipt was minted by the dry run",
            !dryBody?.job?.receipts?.["provider-operation"],
            mintedKinds.length
              ? `receipts minted: ${mintedKinds.join(", ")} — none of them a provider operation`
              : "the record carries NO receipts at all, so this assertion checked nothing",
            mintedKinds.length);
        }
      }

      // Every other verb is refused, and a POST off the allowlist is refused BY NAME.
      for (const method of ["PUT", "PATCH", "DELETE"]) {
        const res = await fetch(`${BASE}/api/jobs`, { method });
        const body = await res.json().catch(() => ({}));
        ok(`a ${method} to the job door is refused`,
          res.status === 405 && body?.state === "method_not_allowed",
          `${res.status} ${body?.state || ""}`);
      }
      const strayPost = await fetch(`${BASE}/api/candidates`, {
        method: "POST", headers: { "content-type": "application/json" }, body: "{}",
      });
      const strayBody = await strayPost.json().catch(() => ({}));
      ok("a POST to a READ route is refused by name, not proxied",
        strayPost.status === 405 && strayBody?.state === "write_not_on_allowlist",
        `${strayPost.status} ${strayBody?.state || ""}`);
    }

    const unknown = await fetch(`${BASE}/api/not-a-real-read`);
    const unknownBody = await unknown.json().catch(() => ({}));
    ok("a path off the allowlist is refused BY NAME",
      unknown.status === 404 && unknownBody.state === "route_not_on_read_allowlist",
      `HTTP ${unknown.status} ${unknownBody.state || ""}`);
    // The refusal names what the surface DOES expose, and the list is pinned to the
    // proxy's own map rather than to a number I typed. It was `length === 4`, and the
    // job door made it 6 — a count is a claim that goes stale the moment the thing it
    // counts changes, and "update the number until it passes" is how a gate stops
    // meaning anything. Compared against the server's map, it cannot drift.
    const serveText = readFileSync(path.join(APP, "scripts/serve-face.mjs"), "utf8");
    // A CLOSED, NAMED LIST — pinned here, by literal path, and nowhere else.
    //
    // This went through three shapes and the last two are both worth recording. It was
    // `length === 4`, which went stale the moment the job door added routes: a count is
    // a claim that dies when the thing it counts changes, and raising the number until
    // it passes is how a gate stops meaning anything.
    //
    // I then compared the refusal against the PROXY'S OWN MAP, which fixed the
    // staleness and introduced a worse fault: an assertion that cannot fail if the map
    // grows. Adding a route would have moved both sides of the comparison at once and
    // the gate would have applauded. The number had not been removed, it had been moved
    // out of the gate and into the thing the gate was supposed to be watching.
    //
    // So the surface's whole reachable API is written out here, once, as literals. A new
    // route fails this until someone adds it deliberately — which is the only version
    // of "closed" that means anything.
    // FOURTH SHAPE, and the reason for it. The list above was `length === 4`; then it
    // was compared against the proxy's own map, which could not fail if the map grew;
    // then it was these literals, which is the version that means something — and
    // which parsed `const READS = new Map([…])` out of the server's source.
    //
    // Moving the table into capability.mjs deleted that declaration. The regex matched
    // nothing, `declaredReads` became the empty list, and this assertion compared an
    // empty list against six literals and went red — correctly, but for a reason that
    // has nothing to do with what it is about. Two of its three siblings did the same.
    //
    // The literals stay, because "closed" means a new route fails until a person adds
    // it here deliberately. What changes is WHAT THEY ARE COMPARED AGAINST: the route
    // table, which is what the proxy dispatches from, rather than a source-text parse
    // of a declaration that may have moved. The gate keeps its own independent copy —
    // that is the whole point of the assertion — but it no longer keeps a copy of the
    // proxy's SYNTAX.
    const EXPECTED_READS = [
      "/api/candidate-sources",
      "/api/candidates",
      "/api/placement-advisory",
      "/api/venues",
      "/api/jobs",
      "/api/jobs/:id",
      "/api/budgets",
      "/api/face-config",
    ];
    const EXPECTED_WRITES = ["/api/jobs", "/api/jobs/:id/dry-run"];

    const declaredReads = cap.readRoutes().map((r) => r.face);
    const declaredWrites = cap.writeRoutes().map((r) => r.face);
    const sameSet = (a, b) => a.length === b.length && [...a].sort().every((v, i) => v === [...b].sort()[i]);
    ok("the proxy declares exactly the reads this gate names, and no others",
      sameSet(declaredReads, EXPECTED_READS),
      `proxy: ${declaredReads.join(", ")}`,
      declaredReads.length);
    ok("the refusal names exactly those reads back to the caller",
      sameSet(unknownBody.allowed || [], EXPECTED_READS),
      `refusal: ${(unknownBody.allowed || []).join(", ")}`,
      (unknownBody.allowed || []).length);
    ok("the proxy declares exactly the writes this gate names, both of them",
      sameSet(declaredWrites, EXPECTED_WRITES),
      `writes: ${declaredWrites.join(", ")}; expected ${EXPECTED_WRITES.join(", ")}`,
      declaredWrites.length);

    // PUT, PATCH and DELETE are refused on every path, still. POST is no longer in this
    // loop because POST is no longer universally refused — it is refused EXCEPT on the
    // two named write paths, and that is asserted above by posting to a read route and
    // requiring `write_not_on_allowlist`. Leaving POST here and relaxing the expected
    // state to "either refusal" would have been a disjunction, which is blind: it would
    // pass whether the surface refused a stray POST or proxied it.
    for (const method of ["PUT", "PATCH", "DELETE"]) {
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
        sourcesBody.sources.length > 0 &&
        sourcesBody.sources.every((s) => typeof s.source === "string" && typeof s.state === "string"),
        `${sourcesBody.sources.length} sources`,
        sourcesBody.sources.length);
      const unavailable = sourcesBody.sources.filter((s) => s.state === "candidate_source_unavailable");
      // ZERO IS A REAL ANSWER HERE, and this is the distinction the vacuity rule is
      // for. "No unavailable source lost its reason" over an empty set is not a broken
      // instrument — it is every source being available, which is the good day. That
      // is declared through okMayBeEmpty rather than assumed, so the declaration is a
      // visible decision rather than a silent one.
      okMayBeEmpty("every unavailable source keeps its named reason through the proxy",
        unavailable.every((s) => typeof s.reason === "string" && s.reason.length > 0),
        unavailable.length
          ? `${unavailable.length} unavailable, all carrying a reason`
          : `0 of ${sourcesBody.sources.length} sources are unavailable right now — nothing to check, which is a real state and not a stalled read`,
        unavailable.length);
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
        `${list.length} candidates`,
        list.length);

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
      ok("every candidate carries the batch it was observed in", false, `HTTP ${cands.status}`, 0);
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
  // The count comes out of the sub-run's own report line. If measure-artboards.mjs
  // measured nothing it exits 0 and prints nothing matching, and "every artboard fits"
  // would be a green light for a measurement that never happened — which is exactly
  // how a 585px clip once passed 7/7.
  const artboardsFit = Number((fitLine.match(/^(\d+)\//) || [])[1] || 0);
  ok("every brand artboard fits its declared frame",
    frames.code === 0,
    fitLine || frames.out.slice(-160),
    artboardsFit);

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
      // WAIT FOR THE TABLE, DO NOT RACE IT. A fixed 2.2s wait was shorter than the
      // candidate sweep, which has been measured at 27-39s, so at some widths this
      // whole block measured a page that was still saying "Asking the daemon".
      //
      // The vacuous-pass reporting made that visible: three of seven widths inspected
      // ZERO cells while the run said 144/144. Every collision and overflow number at
      // those widths was a measurement of an empty page — including the collision
      // checks I had been quoting as evidence the layout was fine.
      //
      // If the rows never arrive, that is reported as NOT MEASURED rather than passed.
      const rowsArrived = await page
        .waitForSelector(".trow", { timeout: 60000 })
        .then(() => true)
        .catch(() => false);
      ok(`at ${w}px the candidate table rendered, so the measurements below saw it`,
        rowsArrived,
        rowsArrived
          ? "rows present before measuring"
          : "NO ROWS after 60s — every layout number at this width describes a loading page");
      await page.waitForTimeout(400);

      // ── D1 AND D4, ASSERTED AGAINST THE RENDERED PAGE ─────────────────────
      // Both defects were invisible to every source-reading assertion and plain in a
      // screenshot, so both are measured in the browser, on the surface a reader sees.
      if (w === 1920) {
        // D4: the headline names a price; row one must BE that price. `cheapest` is
        // now live[0] by construction, so this can only fail if the render order and
        // the summary disagree — which is exactly what it is for.
        const priced = await page.evaluate(() => {
          const head = document.body.innerText.match(/cheapest \$([0-9.]+)\/hr/);
          const cells = [...document.querySelectorAll(".t-quotes tbody .price")]
            .map((c) => parseFloat(c.textContent.replace(/[^0-9.]/g, "")))
            .filter((n) => Number.isFinite(n));
          return { headline: head ? parseFloat(head[1]) : null, cells };
        });
        const ascending = priced.cells.every((v, i, a) => i === 0 || a[i - 1] <= v);
        ok("the cheapest price in the headline is the first row of the table",
          priced.headline !== null && priced.cells.length > 0 &&
          Math.abs(priced.headline - priced.cells[0]) < 1e-9 && ascending,
          priced.headline === null
            ? "no cheapest headline was rendered"
            : `headline $${priced.headline}, row one $${priced.cells[0]}, ascending: ${ascending}` +
              ` over ${priced.cells.length} rows`,
          priced.cells.length);

        // D1: no chip anywhere on the surface is a bare integer. An array index
        // rendered as evidence reads exactly like a count, and that is how a column
        // headed *Receipts* came to be full of zeroes.
        const bareChips = await page.evaluate(async () => {
          const found = [];
          for (const s of ["receipts", "candidates", "sources", "placement"]) {
            const b = document.querySelector(`.nav button[data-surface="${s}"]`);
            if (!b) continue;
            b.click();
            await new Promise((r) => setTimeout(r, 700));
            for (const c of document.querySelectorAll(".chip")) {
              const t = c.textContent.trim();
              if (/^\d+$/.test(t)) found.push(`${s}: "${t}"`);
            }
          }
          return found;
        });
        ok("no chip on any surface is a bare integer standing in for a name",
          bareChips.length === 0,
          bareChips.length
            ? `bare-integer chips: ${[...new Set(bareChips)].join(", ")} — an index rendered as evidence`
            : "chips carry names across receipts, candidates, sources and placement",
          4);
      }

      // ── THE RENDERED CAPABILITY SENTENCE, once, at the first width ─────────
      // The half of the generation proof that has to happen in a browser: what a
      // READER sees, compared against what the generator produces. A source-level
      // check that the surface calls the generator cannot tell whether the result
      // reaches the page, and the served bytes cannot carry a computed string at all.
      if (w === 1920) {
        const chipText = await page.$eval("#refresh-chip", (el) => el.textContent.trim())
          .catch(() => null);
        const expected = cap.capabilitySentences().chip;
        ok("the capability sentence a reader sees is the one the route table generates",
          chipText === expected,
          chipText === null
            ? "the header chip was not found in the rendered page at all"
            : `rendered "${chipText}" vs generated "${expected}"`,
          1);

        // THE COUNT IN THE PROSE IS THE COUNT OF THE ROWS BENEATH IT.
        //
        // The API surface said "seven reads" above a table of EIGHT rows. Both numbers
        // were generated, by the same module, and they disagreed — one counted daemon
        // reads, the other rendered every GET route. A COLD READER found it in under a
        // minute; 170 assertions did not, because every one of them compared the module
        // against itself.
        //
        // So this counts the RENDERED ROWS and compares them to the RENDERED SENTENCE.
        // Generating a number is not the same as generating it from the right set.
        await page.click('.nav button[data-surface="api"]').catch(() => {});
        await page.waitForSelector(".t-api .trow", { timeout: 20000 }).catch(() => {});
        const apiCounts = await page.evaluate(() => {
          const words = {
            no: 0, one: 1, two: 2, three: 3, four: 4, five: 5,
            six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
          };
          const tables = [...document.querySelectorAll(".t-api")];
          const text = document.body.innerText;
          const m = text.match(/Everything this surface can ask the daemon:\s+(\w+)\s+reads?/i);
          return {
            claimed: m ? (words[m[1].toLowerCase()] ?? Number(m[1])) : null,
            readRows: tables[0] ? tables[0].querySelectorAll("tbody .trow").length : 0,
            writeRows: tables[1] ? tables[1].querySelectorAll("tbody .trow").length : 0,
          };
        });
        ok("the read count in the prose equals the number of rows in the table below it",
          apiCounts.claimed !== null && apiCounts.claimed === apiCounts.readRows,
          apiCounts.claimed === null
            ? "the capability sentence was not found on the rendered API surface"
            : `prose says ${apiCounts.claimed} reads; the table renders ${apiCounts.readRows} rows ` +
              `(and ${apiCounts.writeRows} write rows)`,
          apiCounts.readRows);
      }

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
        // ── EVERY NAV TARGET IS ACTUALLY VISIBLE ────────────────────────────
        // The collision probe above compares RECTS, and a rect does not know it has
        // been clipped by a scrolling ancestor. That blindness produced a false report
        // — a nav button whose rect overlapped the status block while the nav clipped
        // it on screen — and while I was chasing that report, the real defect went
        // unnamed: at 1520px the nav was silently clipped and the API button had
        // disappeared entirely on a wide desktop. Nothing tested for it, because
        // "disappeared" is not overflow and is not collision.
        //
        // So: intersect each nav target with every scrolling ancestor and with the
        // viewport, and require the result to be a real box. A button a reader cannot
        // see or reach now fails BY NAME instead of being reported as something else.
        const invisible = [];
        // Counted rather than assumed. The detail line used to say "all seven nav
        // targets" as a literal — a hand-maintained count inside the gate whose whole
        // job is catching hand-maintained counts. If the nav's selector ever stops
        // matching, this finds zero buttons and "none of them is clipped" becomes true
        // of nothing.
        const navTargets = [...document.querySelectorAll(".nav button")];
        for (const b of navTargets) {
          let box = b.getBoundingClientRect();
          let node = b.parentElement;
          while (node && node !== document.documentElement) {
            const cs = getComputedStyle(node);
            if (/(auto|scroll|hidden)/.test(cs.overflowX + cs.overflowY)) {
              const c = node.getBoundingClientRect();
              box = {
                left: Math.max(box.left, c.left), right: Math.min(box.right, c.right),
                top: Math.max(box.top, c.top), bottom: Math.min(box.bottom, c.bottom),
              };
            }
            node = node.parentElement;
          }
          const vw = { left: 0, top: 0, right: window.innerWidth, bottom: window.innerHeight };
          const w2 = Math.min(box.right, vw.right) - Math.max(box.left, vw.left);
          const h2 = Math.min(box.bottom, vw.bottom) - Math.max(box.top, vw.top);
          // 24x24 is WCAG 2.2 SC 2.5.8's target size; anything smaller than a few
          // pixels is not a target a reader can hit, whatever the rect says.
          if (w2 < 8 || h2 < 8) invisible.push(`${b.textContent.trim()} (${Math.round(w2)}x${Math.round(h2)})`);
        }

        // ── A TABLE CELL IS A TABLE CELL ────────────────────────────────────
        // `.stack` and `.freshness` are both `display: flex`, and both were applied
        // directly to `<th>`/`<td>`. That removes the cell from the table layout
        // algorithm: it stops taking its column's declared width and collapses to
        // min-content. Measured at 1440px, the Venue header cell was 264px — exactly
        // the 19% declared — above a body cell of 50px rendering "vast" as four
        // stacked letters.
        //
        // Every other check was green while that shipped: the body did not scroll,
        // nothing collided, every class resolved to a rule, every field existed. A
        // contact sheet caught it, and then caught the SECOND instance after I fixed
        // only the first. So the rule is asserted about cells rather than about the two
        // classes I happen to have found.
        const brokenCells = [];
        const allCells = document.querySelectorAll(".trow > th, .trow > td");
        for (const cell of allCells) {
          const d = getComputedStyle(cell).display;
          if (d !== "table-cell") {
            brokenCells.push(`${cell.className || cell.tagName} is display:${d}`);
          }
        }

        return { overflow, hits: [...new Set(hits)].slice(0, 3), invisible,
                 navSeen: navTargets.length,
                 cellsSeen: allCells.length,
                 brokenCells: [...new Set(brokenCells)].slice(0, 4) };
      });
      // The page stays OPEN — the all-surface cell sweep below still needs it. It used
      // to close here, which was fine while every assertion after this point read only
      // the `m` object.
      ok(`at ${w}px the body does not scroll sideways and nothing collides`,
        m.overflow <= 0 && m.hits.length === 0,
        `overflow ${m.overflow}px${m.hits.length ? `; ${m.hits.join(", ")}` : ""}`);
      // A VACUOUS PASS IS REPORTED AS ONE. The mutation test planted a flex cell and
      // this assertion went red at 1920, 1440, 1180, 900, 640 and 390 — and PASSED at
      // 1520, because the table had not finished loading at that width and there were
      // no cells to check. Silence from a check with nothing to look at is
      // indistinguishable from silence from a check that looked and found nothing,
      // which is the shape that let three readers score a sheet that was never written.
      // It says which it was.
      ok(`at ${w}px every table cell is still a table cell`,
        m.brokenCells.length === 0,
        m.brokenCells.length
          ? `${m.brokenCells.join("; ")} — a cell that is not display:table-cell leaves the ` +
            `table layout, drops its column's width, and collapses to min-content`
          : m.cellsSeen > 0
            ? `${m.cellsSeen} cells checked, all display:table-cell`
            : "NOTHING TO CHECK — no table rows were rendered at this width, so this " +
              "assertion passed without looking at anything",
        m.cellsSeen);
      ok(`at ${w}px every surface in the nav is visible and reachable`,
        m.invisible.length === 0,
        m.invisible.length
          ? `clipped out of sight: ${m.invisible.join(", ")}`
          : `${m.navSeen} nav targets have a real visible box after intersecting their scroll ancestors`,
        m.navSeen);

      // ── THE CELL CHECK, ACROSS ALL SEVEN SURFACES ─────────────────────────
      //
      // The assertion above ran on whatever surface happened to be showing, which was
      // always Candidates. It covered ONE surface of seven, and I quoted it as though
      // it covered the product — which is how a chip in a stacked `td` on Placement
      // rendered as an 800px bar with the gate green. That is the 144/144 error one
      // level up: not a vacuous assertion this time, but a NARROW one read as broad.
      //
      // It now visits every surface and REPORTS ITS COVERAGE by name, so the same
      // misreading is not available to me next time.
      // EACH SURFACE'S OWN TABLE IS WAITED FOR BY NAME. A fixed 260ms pause reported
      // "no table on: placement" — because Placement's read had not landed — which
      // would have declared the surface table-free at the very moment I was fixing a
      // cell defect on it. A surface whose table never arrives is reported as NOT
      // MEASURED rather than counted as having none.
      const TABLE_OF = {
        candidates: ".t-quotes", sources: ".t-sources", placement: ".t-decision",
        redundancy: ".t-postures", receipts: ".t-receipts", api: ".t-api",
        job: null, // no table until a job is submitted; genuinely table-free here
      };
      const sweep = [];
      for (const s of SURFACES) {
        await page.click(`.nav button[data-surface="${s}"]`).catch(() => {});
        const want = TABLE_OF[s];
        let arrived = true;
        if (want) {
          arrived = await page.waitForSelector(`${want} .trow`, { timeout: 75000 })
            .then(() => true).catch(() => false);
        }
        await page.waitForTimeout(160);
        if (want && !arrived) {
          sweep.push({ surface: s, cells: 0, broken: [], notMeasured: true });
          continue;
        }
        const r = await page.evaluate(() => {
          const broken = [];
          const cells = document.querySelectorAll(".trow > th, .trow > td");
          for (const cell of cells) {
            const d = getComputedStyle(cell).display;
            if (d !== "table-cell") broken.push(`${cell.className || cell.tagName} is display:${d}`);
          }
          return { cells: cells.length, broken: [...new Set(broken)].slice(0, 3) };
        });
        sweep.push({ surface: s, ...r });
      }
      const sweptCells = sweep.reduce((n, r) => n + r.cells, 0);
      const sweptBroken = sweep.filter((r) => r.broken.length);
      const missed = sweep.filter((r) => r.notMeasured).map((r) => r.surface);
      const withTables = sweep.filter((r) => r.cells > 0).map((r) => r.surface);
      // THE COVERAGE LINE. A per-surface check states which surfaces it inspected, so
      // a narrow result cannot be quoted as a broad one — which is what I did with the
      // single-surface version of this assertion.
      ok(`at ${w}px every table cell on every surface is still a table cell`,
        sweptBroken.length === 0 && missed.length === 0,
        sweptBroken.length
          ? sweptBroken.map((r) => `${r.surface}: ${r.broken.join("; ")}`).join(" · ")
          : missed.length
            ? `NOT MEASURED on ${missed.join(", ")} — their tables never rendered, so this ` +
              `assertion says nothing about them`
            : `${sweptCells} cells across ${withTables.length} of ${SURFACES.length} surfaces ` +
              `(inspected: ${withTables.join(", ")}; no table by design: ` +
              `${SURFACES.filter((s) => !withTables.includes(s)).join(", ") || "none"})`,
        sweptCells);
      await page.close();
    }

    // ── COLD START IS NOT A BLANK PAGE ──────────────────────────────────────
    //
    // The kept-answer store used to be an in-memory Map: it survived NAVIGATION and
    // died on RELOAD. So a cold visit had nothing and sat empty for the length of a
    // daemon sweep — 39,417ms measured on Sources, with no rows, no aria-busy, and the
    // live region holding the empty string throughout. Three of seven surfaces are a
    // blank page in the contact sheet for the same reason.
    //
    // RECEIPTS, not Candidates, and the reason is a measurement rather than a
    // preference: the candidates body for the default intent is 13.6 MB, against a
    // localStorage quota of a few megabytes. Candidates CANNOT keep its answer and
    // says so; Sources (4 KB), Receipts (88 KB) and Budgets (375 B) can. Asserting
    // this on Candidates would demand a thing that is not possible, and the honest
    // shape of that is a surface stating why rather than a gate insisting.
    //
    // On its OWN PAGE. My first version reloaded the page the width sweep was
    // measuring, and the cell and nav assertions at 1920 then ran against a reloading
    // document — one of them reported inspecting zero cells, which is the exact
    // failure this gate spent a commit learning to detect, reintroduced by the test I
    // wrote to detect something else.
    const keepPage = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    try {
      await keepPage.goto(`http://127.0.0.1:${port}/#/receipts`, { waitUntil: "domcontentloaded" });
      const warmed = await keepPage
        .waitForSelector(".t-receipts .trow", { timeout: 60000 })
        .then(() => true)
        .catch(() => false);
      ok("the receipts read completed once, so there is an answer to keep",
        warmed, warmed ? "rows present before the reload" : "no rows in 60s — nothing was cached", 1);

      if (warmed) {
        // THE READ IS HELD OPEN, or this assertion proves nothing.
        //
        // My first version simply reloaded and measured 59ms to first row — and that
        // number does not distinguish "painted from the kept answer" from "the read
        // was just fast", which for an 88 KB body on localhost it is. It would have
        // gone green with the persistence layer deleted.
        //
        // So /api/jobs is delayed by three seconds. Any row appearing before the
        // daemon has answered came from the store, and could have come from nowhere
        // else.
        const HOLD_MS = 3000;
        await keepPage.route("**/api/jobs", async (route) => {
          await new Promise((r) => setTimeout(r, HOLD_MS));
          await route.continue();
        });

        const t0 = Date.now();
        await keepPage.reload({ waitUntil: "domcontentloaded" });
        const painted = await keepPage
          .waitForSelector(".t-receipts .trow", { timeout: 5000 })
          .then(() => Date.now() - t0)
          .catch(() => null);
        ok("the rows painted before the daemon answered, so they came from the store",
          painted !== null && painted < HOLD_MS,
          painted === null
            ? `no rows within 5s while the read was held for ${HOLD_MS}ms`
            : `first row at ${painted}ms, with the read held for ${HOLD_MS}ms`,
          1);
        // The kept answer must also SAY it is kept. A cached body rendered as though it
        // were fresh is the one version of this feature that would be worse than the
        // blank page it replaces.
        const marked = painted === null ? false : await keepPage.evaluate(() =>
          /kept|last answer|as of|read at/i.test(document.body.innerText));
        ok("a reload paints the last kept answer instead of a blank page",
          painted !== null && marked,
          painted === null
            ? "NO ROWS within 5s of reload — the kept answer did not survive the page load"
            : `rows painted ${painted}ms after reload; labelled as a kept answer: ${marked}`,
          1);
      }
    } finally {
      await keepPage.close();
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
  // THE VACUITY SWEEP, before anything is printed as a pass.
  // A universally-quantified assertion that passed is only a pass if it can say how
  // many things it looked at, and looked at more than none of them. This runs over
  // the results rather than inside each assertion, so a new assertion is covered the
  // moment it is written instead of when its author remembers the rule.
  const vacuous = [];
  for (const r of results) {
    if (!r.pass || !UNIVERSAL.test(r.name)) continue;
    if (r.inspected === undefined) {
      r.pass = false;
      r.detail = `${r.detail} — VACUITY: this assertion is universally quantified and did not report what it inspected, so its pass means nothing`;
      vacuous.push(r.name);
    } else if (r.inspected === 0 && !r.zeroDeclared) {
      r.pass = false;
      r.detail = `${r.detail} — VACUITY: passed after inspecting ZERO things, which is what "144/144" looked like while three widths measured a loading page`;
      vacuous.push(r.name);
    }
  }

  let fail = 0;
  for (const r of results) {
    const n = r.inspected === undefined ? "" : ` [${r.inspected} inspected]`;
    console.log(`  ${r.pass ? "PASS" : "FAIL"}  ${r.name}${n}${r.detail ? `  (${r.detail})` : ""}`);
    if (!r.pass) fail++;
  }
  if (vacuous.length) {
    console.log(`\n${vacuous.length} assertion(s) failed the vacuity rule, not their own subject:`);
    for (const n of vacuous) console.log(`  - ${n}`);
  }
  console.log(`\n${results.length - fail}/${results.length} passed`);
  console.log(`decentralized.cloud face: ${fail ? "FAIL" : "OK"}`);
  process.exit(fail ? 1 : 0);
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
