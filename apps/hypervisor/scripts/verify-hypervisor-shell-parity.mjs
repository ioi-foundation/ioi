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
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const OWNED = join(HERE, "..", "product-ui", "owned", "public");
const SERVER = join(HERE, "..", "product-ui", "server.cjs");
const require_ = (await import("node:module")).createRequire(import.meta.url);
const esbuild = require_(join(ROOT, "node_modules", "esbuild"));

const results = [];
const ok = (name, cond, detail) => { results.push({ name, pass: !!cond, detail: detail || "" }); };
const runNode = (script, args = []) => spawnSync(process.execPath, [join(HERE, script), ...args], { encoding: "utf8", cwd: ROOT, timeout: 900000 });

// Declared owned edits, normalized before wire comparison. Each entry documents WHY the owned
// tree may differ at that path; anything not declared here must be identical.
const AUG_TAG = '<script src="/ioi-augmentation.js" defer></script>';
const OWNED_EDIT_NORMALIZERS = {
  "index.html": (s) => s.replace(AUG_TAG, "").replace(/\s+<\/head>/, "</head>"),
};

async function wireGate() {
  const manifest = JSON.parse(readFileSync(join(HERE, "..", "product-ui", "owned", "vendor-manifest.json"), "utf8")).files;
  const mk = (port, publicDir) => spawn(process.execPath, [SERVER], {
    env: { ...process.env, PORT: String(port), ...(publicDir ? { IOI_PRODUCT_UI_PUBLIC: publicDir } : {}) },
    stdio: "ignore",
  });
  const a = mk(9401, null);
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

  // 4. Behavioral freeze on the live estate serve (original tree).
  const r4 = runNode("shell-freeze-behavior.mjs", ["--check"]);
  ok("behavioral freeze intact on the original tree", r4.status === 0, (r4.stdout || r4.stderr || "").trim().split("\n").pop());
  if (r4.status !== 0) console.error((r4.stderr || "").trim().split("\n").slice(-12).join("\n"));

  // 5. Behavioral freeze on a full stack over the OWNED tree.
  const serve = spawn(process.execPath, [join(HERE, "serve-product-ui.mjs")], {
    env: { ...process.env, PORT: "4601", PRODUCT_UI_PORT: "9403", IOI_PRODUCT_UI_PUBLIC: OWNED, IOI_HYPERVISOR_DAEMON_URL: process.env.IOI_HYPERVISOR_DAEMON_URL || "http://127.0.0.1:8765" },
    stdio: "ignore",
    cwd: ROOT,
  });
  try {
    let up = false;
    for (let i = 0; i < 60 && !up; i++) {
      await new Promise((r) => setTimeout(r, 500));
      up = await fetch("http://127.0.0.1:4601/ai").then((r) => r.ok).catch(() => false);
    }
    ok("owned-tree full stack comes up", up, "serve :4601 over product-ui/owned");
    const r5 = runNode("shell-freeze-behavior.mjs", ["--check", "--base", "http://127.0.0.1:4601"]);
    ok("behavioral freeze intact on the OWNED tree (DOM, animations, network, console)", r5.status === 0, (r5.stdout || r5.stderr || "").trim().split("\n").pop());
    if (r5.status !== 0) console.error((r5.stderr || "").trim().split("\n").slice(-12).join("\n"));
  } finally {
    serve.kill("SIGTERM");
  }
}

run().then(() => {
  const fails = results.filter((r) => !r.pass);
  for (const r of results) console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${results.length - fails.length}/${results.length} passed`);
  if (fails.length) process.exit(1);
  console.log("shell-parity readiness: OK");
}).catch((e) => {
  console.error("verifier crashed:", e);
  process.exit(1);
});
