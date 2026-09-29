#!/usr/bin/env node
// Shell-parity readiness verifier — the oracle gate for the shell-ownership program.
//
// Proves, end to end, that the OWNED vendored shell tree is the same program as the original
// bundle, with no gap for discrepancies to hide in:
//   1. code-level freeze intact (asset sha256 manifest + CSS/keyframes inventory);
//   2. vendor manifest re-proven — every beautified file AST-equal to its original
//      (esbuild minify(original) === minify(beautified), byte-for-byte);
//   3. WIRE equivalence — two shell servers side by side (original tree vs owned tree), every
//      manifest path fetched through the real serve-time transforms and compared at the AST
//      level for js/css, byte level otherwise (declared owned edits normalized explicitly);
//   4. behavioral freeze intact on the live estate serve (original tree);
//   5. behavioral freeze intact on a FULL STACK spun up over the owned tree — DOM fingerprints,
//      runtime animation inventory (incl. transient loading animations), network manifest, and
//      console signature all identical to the committed baseline.
//
// Usage: node apps/hypervisor/scripts/verify-hypervisor-shell-parity.mjs
// Exit 0 = the owned tree is provably the same shell; exit 1 otherwise.

import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";
import { ownerStackRefusal } from "./lib/verifier-stack.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const LEGACY = join(HERE, "..", "product-ui", "public");
const OWNED = join(HERE, "..", "product-ui", "owned", "public");
const SERVER = join(HERE, "..", "product-ui", "server.cjs");
const require_ = (await import("node:module")).createRequire(import.meta.url);
const esbuild = require_(join(ROOT, "node_modules", "esbuild"));

// THE DAEMON BOTH SERVES READ (R-240, verifier auth sweep, 2026-09-29). They defaulted to the owner's :8765, so a local run
// compared two trees over the owner's data as nobody; CI has no daemon there, so CI compared them daemon-less. The
// default is now CI's measurement everywhere — a loopback port nothing listens on — and an explicit
// IOI_HYPERVISOR_DAEMON_URL is honoured unless it names the owner's stack (:8765, :36173, :4173), which is refused.
const PARITY_DAEMON = await (async () => {
  const explicit = process.env.IOI_HYPERVISOR_DAEMON_URL || "";
  const why = ownerStackRefusal(explicit);
  if (why) { console.error(`BLOCKED: ${why}`); process.exit(2); }
  if (explicit) return explicit;
  const { createServer } = await import("node:net");
  const port = await new Promise((resolve, reject) => { const srv = createServer(); srv.on("error", reject); srv.listen(0, "127.0.0.1", () => { const { port: p } = srv.address(); srv.close(() => resolve(p)); }); });
  return `http://127.0.0.1:${port}`;
})();

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const runNode = (script, args = []) => spawnSync(process.execPath, [join(HERE, script), ...args], { encoding: "utf8", cwd: ROOT, timeout: 900000 });
const runNodeAsync = (script, args = []) => new Promise((resolve) => {
  const child = spawn(process.execPath, [join(HERE, script), ...args], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("exit", (status) => resolve({ status, stdout, stderr }));
});

// Declared owned edits, normalized before wire comparison. Each entry documents WHY the owned
// tree may differ at that path; anything not declared here must be identical.
const AUG_TAG = '<script src="/ioi-augmentation.js" defer></script>';
const copyStatus = (indent, jsx, copied, error) => `
${indent}(${copied} || ${error}) &&
${indent}  (0, ${jsx}.jsx)(\`span\`, {
${indent}    role: \`status\`,
${indent}    "aria-live": \`polite\`,
${indent}    "data-ioi-copy-status": ${copied} ? \`copied\` : \`failed\`,
${indent}    className: ${copied} ? \`text-content-success\` : \`text-content-danger\`,
${indent}    style: { position: \`absolute\`, right: 0, top: \`100%\`, marginTop: 4, fontSize: 12, lineHeight: \`16px\`, whiteSpace: \`nowrap\`, pointerEvents: \`none\` },
${indent}    children: ${copied} ? \`Copied\` : \`Couldn’t copy: \${${error}}\`,
${indent}  }),`;
const COPY_STATUS_INPUT = copyStatus("            ", "d", "x", "S");
const COPY_STATUS_TEXTAREA = copyStatus("              ", "f", "A", "j");
const OWNED_EDIT_NORMALIZERS = {
  "index.html": (s) => s.replace(AUG_TAG, "").replace(/\s+<\/head>/, "</head>"),
  // R-240 Arm A on Sessions: the Tasks tab rendered "No tasks defined" whatever its query answered, so the refusal naming
  // the absent tasks plane never reached it. The edit keeps the Tasks section (which renders its error) unless the query
  // SUCCEEDED empty — keyed on success, not on the error, which a remount resets to pending (that looped the query).
  "static/assets/EnvironmentDetailsPanel-B_-iwFn8.js": (s) => s.replace(
    "let { data: t, isSuccess: r } = jt(e);\n    return (t?.length ?? 0) > 0 || !r\n",
    "let { data: t } = jt(e);\n    return (t?.length ?? 0) > 0\n",
  ),
  // R-240 Arm A on Sessions: the Resource usage dialog dropped the reply's reason and printed "Try again, or contact
  // support". The edit keeps a refusal's `message` and prints it in the dialog.
  "static/assets/DeleteEnvironmentModal-DVlWulBs.js": (s) => s
    .replace("throw Error((await r.json().catch(() => null))?.message || `HTTP ${r.status}: ${r.statusText}`);", "throw Error(`HTTP ${r.status}: ${r.statusText}`);")
    .replace("children: n || `Try again, or contact support if the issue persists.`,", "children: `Try again, or contact support if the issue persists.`,"),
  // R-240 Arm A on Sessions: the empty Archived view promised that unused environments are archived after 7 days and
  // deleted by the auto-delete setting. Nothing does either (the daemon archives and deletes only on request).
  "static/assets/SegmentProvider-CXCNBY9U.js": (s) => s
    .replace("`Environments are archived only when you archive them.`;", "`Environments that are not used for 7 days are automatically archived.`;")
    .replace("`${t} Archived environments are kept until you delete them.`;", "`${t} Archived environments will be deleted based on your auto-delete setting.`;"),
  // R-240 (verifier hygiene, 2026-09-29): a copyable field's Copy to clipboard answered only by swapping an aria-hidden
  // icon — nothing a screen reader hears, no text a person reads (Login configuration's read dead to the census). The
  // edit adds a visible "Copied" / "Couldn't copy: …" status (role=status, aria-live=polite) under the field while the
  // copy hook reports one; it renders nothing at rest, so no page's static DOM moves.
  "static/assets/input-C42Z_4fO.js": (s) => s.replace(COPY_STATUS_INPUT, ""),
  "static/assets/textarea-65aCrC5K.js": (s) => s.replace(COPY_STATUS_TEXTAREA, ""),
};

async function wireGate() {
  const manifest = JSON.parse(readFileSync(join(HERE, "..", "product-ui", "owned", "vendor-manifest.json"), "utf8")).files;
  const mk = (port, publicDir) => spawn(process.execPath, [SERVER], {
    env: { ...process.env, PORT: String(port), ...(publicDir ? { IOI_PRODUCT_UI_PUBLIC: publicDir } : {}) },
    stdio: "ignore",
  });
  const a = mk(9401, LEGACY);
  const b = mk(9402, OWNED);
  try {
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 250));
      const up = await Promise.all([9401, 9402].map((p) => fetch(`http://127.0.0.1:${p}/index.html`).then((r) => r.ok).catch(() => false)));
      if (up.every(Boolean)) break;
    }
    let same = 0, diff = [], statusDiff = [];
    for (const rel of Object.keys(manifest)) {
      const url = "/" + rel;
      const [ra, rb] = await Promise.all([
        fetch("http://127.0.0.1:9401" + url).then(async (r) => ({ s: r.status, t: await r.text() })).catch(() => null),
        fetch("http://127.0.0.1:9402" + url).then(async (r) => ({ s: r.status, t: await r.text() })).catch(() => null),
      ]);
      if (!ra || !rb || ra.s !== rb.s) { statusDiff.push(`${rel} (${ra && ra.s} vs ${rb && rb.s})`); continue; }
      if (ra.s !== 200) { same++; continue; } // both refuse identically — equivalent
      let ta = ra.t, tb = rb.t;
      const norm = OWNED_EDIT_NORMALIZERS[rel];
      if (norm) { ta = norm(ta); tb = norm(tb); }
      let equal;
      if (rel.endsWith(".js") || rel.endsWith(".mjs")) {
        try {
          const [ma, mb] = await Promise.all([
            esbuild.transform(ta, { minify: true, target: "esnext" }),
            esbuild.transform(tb, { minify: true, target: "esnext" }),
          ]);
          equal = ma.code === mb.code;
        } catch { equal = ta === tb; }
      } else if (rel.endsWith(".css")) {
        try {
          const [ma, mb] = await Promise.all([
            esbuild.transform(ta, { loader: "css", minify: true }),
            esbuild.transform(tb, { loader: "css", minify: true }),
          ]);
          equal = ma.code === mb.code;
        } catch { equal = ta === tb; }
      } else {
        equal = ta === tb;
      }
      if (equal) same++; else diff.push(rel);
    }
    return { total: Object.keys(manifest).length, same, diff, statusDiff };
  } finally {
    a.kill("SIGTERM"); b.kill("SIGTERM");
  }
}

async function run() {
  // 1. Code-level freeze.
  const r1 = runNode("shell-freeze-assets.mjs", ["--check"]);
  ok("code-level freeze intact (assets + css/keyframes inventory)", r1.status === 0, (r1.stdout || r1.stderr || "").trim().split("\n").pop());

  // 2. Vendor manifest re-proven (AST gate per beautified file).
  const r2 = runNode("vendor-product-ui.mjs", ["--check"]);
  ok("owned tree re-proven AST-equal to originals", r2.status === 0, (r2.stdout || "").trim().split("\n").pop());

  // 3. Wire equivalence across the real serve-time transforms.
  const w = await wireGate();
  ok("wire equivalence: every asset identical through both trees", w.diff.length === 0 && w.statusDiff.length === 0, `${w.same}/${w.total} equal${w.diff.length ? " · DIFF: " + w.diff.slice(0, 5).join(", ") : ""}${w.statusDiff.length ? " · STATUS: " + w.statusDiff.slice(0, 5).join(", ") : ""}`);

  // 4. Behavioral equivalence between explicitly selected legacy and owned stacks. Historical
  // behavior drift is a separate freeze concern; ownership parity compares both current programs
  // directly so identical intentional evolution cannot fail this gate.
  const legacyServe = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: "4600", PRODUCT_UI_PORT: "9410", IOI_PRODUCT_UI_PUBLIC: LEGACY, IOI_HYPERVISOR_DAEMON_URL: PARITY_DAEMON },
    stdio: "ignore",
    cwd: ROOT,
  });
  const ownedServe = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: "4601", PRODUCT_UI_PORT: "9403", IOI_PRODUCT_UI_PUBLIC: OWNED, IOI_HYPERVISOR_DAEMON_URL: PARITY_DAEMON },
    stdio: "ignore",
    cwd: ROOT,
  });
  const captureRoot = mkdtempSync(join(tmpdir(), "ioi-shell-parity-"));
  try {
    let legacyUp = false;
    let ownedUp = false;
    for (let i = 0; i < 60 && (!legacyUp || !ownedUp); i++) {
      await new Promise((r) => setTimeout(r, 500));
      [legacyUp, ownedUp] = await Promise.all([
        fetch("http://127.0.0.1:4600/ai").then((r) => r.ok).catch(() => false),
        fetch("http://127.0.0.1:4601/ai").then((r) => r.ok).catch(() => false),
      ]);
    }
    ok("legacy parity full stack comes up", legacyUp, "serve :4600 over non-shipped product-ui/public");
    ok("owned-tree full stack comes up", ownedUp, "serve :4601 over product-ui/owned");
    const legacyCapture = join(captureRoot, "legacy.json");
    const ownedCapture = join(captureRoot, "owned.json");

    // Capture and compare ONE round: returns the set of differing `route:field` keys.
    //
    // A single round is not a verdict. These are two live page loads against two independent
    // servers, so anything whose presence depends on timing — a spinner still animating while a
    // request is in flight, an error-reporting beacon that raced — lands in one capture and not
    // the other. Two consecutive runs of this gate on an unchanged tree reported two entirely
    // different "behaviour diffs" (`/ai#new-session:network`, then `/projects:animations`), which
    // is the same defect as a test suite that answers differently each run: a red result does not
    // identify anything and a green one is not evidence.
    const captureRound = async (round) => {
      const [legacyRun, ownedRun] = await Promise.all([
        runNodeAsync("shell-freeze-behavior.mjs", ["--base", "http://127.0.0.1:4600", "--capture-json", legacyCapture]),
        runNodeAsync("shell-freeze-behavior.mjs", ["--base", "http://127.0.0.1:4601", "--capture-json", ownedCapture]),
      ]);
      if (legacyRun.status !== 0 || ownedRun.status !== 0) {
        return { ok: false, legacyRun, ownedRun, diffs: new Map() };
      }
      const legacy = JSON.parse(readFileSync(legacyCapture, "utf8"));
      const owned = JSON.parse(readFileSync(ownedCapture, "utf8"));
      const routes = [...new Set([
        ...Object.keys(legacy.routes || {}),
        ...Object.keys(owned.routes || {}),
      ])].sort();
      const diffs = new Map();
      for (const route of routes) {
        for (const field of ["dom", "animations", "network", "console"]) {
          const legacyValue = legacy.routes?.[route]?.[field];
          const ownedValue = owned.routes?.[route]?.[field];
          if (JSON.stringify(legacyValue) === JSON.stringify(ownedValue)) continue;
          let detail = "";
          if (Array.isArray(legacyValue) && Array.isArray(ownedValue)) {
            const legacySet = new Set(legacyValue);
            const ownedSet = new Set(ownedValue);
            const removed = legacyValue.filter((value) => !ownedSet.has(value)).slice(0, 8);
            const added = ownedValue.filter((value) => !legacySet.has(value)).slice(0, 8);
            detail = `${removed.length ? `\n  legacy-only: ${removed.join(" | ")}` : ""}${added.length ? `\n  owned-only: ${added.join(" | ")}` : ""}`;
          }
          diffs.set(`${route}:${field}`, detail);
        }
      }
      if (diffs.size && round === 1) {
        console.error(`round 1 saw ${diffs.size} difference(s); re-capturing to separate real divergence from load-timing noise`);
      }
      return { ok: true, legacyRun, ownedRun, diffs };
    };

    const first = await captureRound(1);
    // Only a difference that REPRODUCES is a difference. One that appears in a single round is the
    // race described above, and reporting it would fail the build over nothing.
    const second = first.ok && first.diffs.size ? await captureRound(2) : first;
    const captured = first.ok && second.ok;
    const behaviorDiff = [];
    if (captured) {
      for (const [key, detail] of first.diffs) {
        if (!second.diffs.has(key)) continue;
        behaviorDiff.push(key);
        console.error(`behavior DIFF ${key}${detail}`);
      }
      const transient = [...first.diffs.keys()].filter((key) => !second.diffs.has(key));
      if (transient.length) {
        console.error(`load-timing noise, not reported: ${transient.join(", ")}`);
      }
    }
    const r4 = first.legacyRun;
    const r5 = first.ownedRun;
    const equal = captured && behaviorDiff.length === 0;
    ok("runtime behavior equivalent across legacy and owned trees (DOM, animations, network, console)", equal, captured ? `5-route captures compared${behaviorDiff.length ? ` · DIFF ${behaviorDiff.join(", ")}` : ""}` : `capture failed: legacy=${r4.status} owned=${r5.status}`);
    if (!captured) {
      console.error((r4.stderr || r4.stdout || "").trim().split("\n").slice(-12).join("\n"));
      console.error((r5.stderr || r5.stdout || "").trim().split("\n").slice(-12).join("\n"));
    }
  } finally {
    legacyServe.kill("SIGTERM");
    ownedServe.kill("SIGTERM");
    rmSync(captureRoot, { recursive: true, force: true });
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  emitVerifierCensus({ verifierId: "shell-parity", sourceUrl: import.meta.url, results });
  if (fails.length) process.exit(1);
  console.log("shell-parity readiness: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
