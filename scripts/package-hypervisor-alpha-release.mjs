#!/usr/bin/env node
// package-hypervisor-alpha-release — build the signed, packaged release of the Hypervisor bounded
// alpha for the supported Linux x86_64 profile (bounded-alpha-profile.md step 1).
//
//   node scripts/package-hypervisor-alpha-release.mjs --out <dir> --signer-key <pkcs8.pem>
//        [--version <v>] [--profile debug|release] [--daemon <path>] [--node-bins <dir>] [--no-archive]
//   node scripts/package-hypervisor-alpha-release.mjs --generate-signer <dir>   (writes key pair)
//
// What goes in (and what does not): the daemon, the grant signer and the authority-node control
// binary from the checkout's build; the authority node's validator processes for the Solo/IAVL
// profile; the served App with the node packages its import graph reaches (nothing else from
// node_modules); the harness shims; the installer. The manifest names the exact checkout, whether
// the tree was dirty, the toolchains, the cargo build profile (this is a DEBUG-profile build until
// a release profile is qualified — the manifest says so), the SBOM (cargo resolve + the copied npm
// packages) and the prerequisites the package does NOT provide: a local OpenAI-compatible model
// route, and the authority node bring-up, which runs from this checkout (its launcher is not yet
// relocatable — recorded as a typed absence with its closure test, never as provided).

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import { builtinModules } from "node:module";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  MANIFEST_FILE, RELEASE_SCHEMA, RELEASE_TARGET, SIGNATURE_FILE, canonicalManifestBytes, digestTree,
  generateSignerKey, sha256Bytes, sha256File, signManifestBytes, signerKeyId,
} from "./lib/hypervisor-alpha-release.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

function parseArgs(argv) {
  const options = { archive: true };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--no-archive") { options.archive = false; continue; }
    if (!arg.startsWith("--")) throw new Error(`unexpected argument ${arg}`);
    const value = argv[i + 1];
    if (value === undefined) throw new Error(`${arg} needs a value`);
    options[arg.slice(2)] = value;
    i += 1;
  }
  return options;
}

const git = (...args) => { try { return execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim(); } catch { return ""; } };
const tool = (cmd, args) => { try { return execFileSync(cmd, args, { encoding: "utf8" }).trim(); } catch { return "unavailable"; } };

function copyFile(src, dst, mode) {
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
  if (mode !== undefined) fs.chmodSync(dst, mode);
}

function copyTree(src, dst, { skip = () => false } = {}) {
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dst, entry.name);
    if (skip(s, entry)) continue;
    if (entry.isSymbolicLink()) { const real = fs.realpathSync(s); if (fs.statSync(real).isDirectory()) copyTree(real, d, { skip }); else copyFile(real, d); continue; }
    if (entry.isDirectory()) copyTree(s, d, { skip });
    else copyFile(s, d);
  }
}

/** Bare package specifiers reachable from the entry files' static/dynamic import graph. */
function reachableBarePackages(entries) {
  const seen = new Set();
  const bare = new Set();
  const queue = [...entries];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) continue;
    seen.add(file);
    const text = fs.readFileSync(file, "utf8");
    // Real module edges only: import/export statements at line start, and dynamic import() /
    // require() calls with a literal specifier. Prose inside strings is not an edge.
    const specs = [
      ...[...text.matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+["']([^"'\n]+)["']/gmu)].map((m) => m[1]),
      ...[...text.matchAll(/^\s*import\s+["']([^"'\n]+)["']/gmu)].map((m) => m[1]),
      ...[...text.matchAll(/\b(?:import|require)\s*\(\s*["']([^"'\n]+)["']\s*\)/gu)].map((m) => m[1]),
    ];
    for (const spec of specs) {
      if (spec.startsWith("node:") || builtinModules.includes(spec.split("/")[0]) || /\s/u.test(spec)) continue;
      if (spec.startsWith(".") || spec.startsWith("/")) {
        const target = path.resolve(path.dirname(file), spec);
        for (const candidate of [target, `${target}.mjs`, `${target}.js`, `${target}.cjs`, path.join(target, "index.js")]) if (fs.existsSync(candidate)) { queue.push(candidate); break; }
        continue;
      }
      const name = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
      if (!/^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/u.test(name)) continue;
      bare.add(name);
    }
  }
  return { bare: [...bare].sort(), files: [...seen] };
}

function resolvePackageDir(name) {
  for (const base of [path.join(ROOT, "apps", "hypervisor", "node_modules"), path.join(ROOT, "node_modules")]) {
    const dir = path.join(base, name);
    if (fs.existsSync(path.join(dir, "package.json"))) return dir;
  }
  throw new Error(`runtime package ${name} is not installed under node_modules`);
}

function copyNpmPackageClosure(name, dst, sbom, seen = new Set()) {
  if (seen.has(name)) return;
  seen.add(name);
  const dir = resolvePackageDir(name);
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  copyTree(dir, path.join(dst, name), { skip: (s, e) => e.name === "node_modules" || e.name.startsWith(".") });
  sbom.push({ name: pkg.name, version: pkg.version, license: pkg.license || null, source: path.relative(ROOT, dir) });
  for (const dep of Object.keys(pkg.dependencies || {})) copyNpmPackageClosure(dep, dst, sbom, seen);
}

function cargoSbom() {
  const raw = spawnSync("cargo", ["metadata", "--format-version", "1", "--locked"], { cwd: ROOT, encoding: "utf8", maxBuffer: 1 << 28 });
  if (raw.status !== 0) return { available: false, reason: "cargo metadata failed", crates: [] };
  const metadata = JSON.parse(raw.stdout);
  const byId = new Map(metadata.packages.map((p) => [p.id, p]));
  const roots = metadata.packages.filter((p) => ["ioi-node", "ioi-cli"].includes(p.name)).map((p) => p.id);
  const nodes = new Map(metadata.resolve.nodes.map((n) => [n.id, n]));
  const seen = new Set();
  const stack = [...roots];
  while (stack.length) { const id = stack.pop(); if (seen.has(id)) continue; seen.add(id); for (const dep of nodes.get(id)?.dependencies || []) stack.push(dep); }
  const crates = [...seen].map((id) => byId.get(id)).filter(Boolean).map((p) => ({ name: p.name, version: p.version, source: p.source || "path", license: p.license || null })).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
  return { available: true, roots: ["ioi-node", "ioi-cli"], crates };
}

function nodeBinsDir(profile) {
  // The Solo/IAVL profile the authority node runs: the same resolution `TestValidator` performs
  // (crates/cli/src/testing/validator.rs), matched by the binaries' presence, for the requested
  // cargo profile (debug-<hash>/debug or release-<hash>/release).
  const base = path.join(ROOT, "target", "test-node-builds");
  const candidates = fs.existsSync(base) ? fs.readdirSync(base).filter((d) => d.startsWith(`${profile}-`)).map((d) => path.join(base, d, profile)) : [];
  const want = ["orchestration", "workload", "guardian", "ioi-signer"];
  const complete = candidates.filter((dir) => want.every((b) => fs.existsSync(path.join(dir, b))));
  // Prefer the most recently built complete profile dir.
  complete.sort((a, b) => fs.statSync(path.join(b, "orchestration")).mtimeMs - fs.statSync(path.join(a, "orchestration")).mtimeMs);
  return complete[0] || null;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options["generate-signer"]) {
    const dir = path.resolve(options["generate-signer"]);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const { privateKeyPem, publicKeyPem } = generateSignerKey();
    fs.writeFileSync(path.join(dir, "release-signer.pem"), privateKeyPem, { mode: 0o600 });
    fs.writeFileSync(path.join(dir, "release-signer.pub.pem"), publicKeyPem, { mode: 0o644 });
    console.log(`signer ${signerKeyId(publicKeyPem)} written to ${dir} (private key 0600; pin the .pub.pem on every installing host)`);
    return;
  }
  if (!options.out || !options["signer-key"]) throw new Error("--out and --signer-key are required");
  const privateKeyPem = fs.readFileSync(path.resolve(options["signer-key"]), "utf8");
  const publicKeyPem = (await import("node:crypto")).createPublicKey(privateKeyPem).export({ type: "spki", format: "pem" });
  const head = git("rev-parse", "HEAD");
  const dirty = git("status", "--porcelain").split("\n").filter(Boolean).length;
  const version = options.version || `0.1.0+g${head.slice(0, 12)}${dirty ? ".dirty" : ""}`;
  const name = `ioi-hypervisor-alpha-${version}-${RELEASE_TARGET}`;
  const outDir = path.resolve(options.out);
  const stage = path.join(outDir, name);
  fs.rmSync(stage, { recursive: true, force: true });
  fs.mkdirSync(stage, { recursive: true });

  // bin/
  const profile = options.profile || "debug";
  if (!["debug", "release"].includes(profile)) throw new Error("--profile must be debug or release");
  const daemon = path.resolve(ROOT, options.daemon || `target/${profile}/hypervisor-daemon`);
  // The two grant signers the App's attach passes invoke out of process: the exact-effect one and,
  // since R-14 (2026-09-09), the STANDING one the deployment-local operator mints an envelope with.
  // A package that ships only the first leaves step 5c unable to mint on a no-checkout host.
  const bins = { "hypervisor-daemon": daemon, "mint-approval-grant": path.join(ROOT, `target/${profile}/mint-approval-grant`), "mint-standing-approval-grant": path.join(ROOT, `target/${profile}/mint-standing-approval-grant`), "wallet-network-local-authority": path.join(ROOT, `target/${profile}/wallet-network-local-authority`) };
  for (const [n, src] of Object.entries(bins)) { if (!fs.existsSync(src)) throw new Error(`missing ${src}; build it first`); copyFile(src, path.join(stage, "bin", n), 0o755); }
  // node-bins/
  const nodeBins = options["node-bins"] ? path.resolve(options["node-bins"]) : nodeBinsDir(profile);
  if (!nodeBins) throw new Error(`no complete Solo/IAVL ${profile} node build under target/test-node-builds; build it first (or pass --node-bins)`);
  for (const b of ["orchestration", "workload", "guardian", "ioi-signer"]) copyFile(path.join(nodeBins, b), path.join(stage, "node-bins", b), 0o755);
  // app/
  const app = path.join(ROOT, "apps", "hypervisor");
  // The App and the shims keep their REPOSITORY paths inside the release so every relative import
  // the App makes (e.g. ../../../../scripts/lib/mint-approval-grant.mjs) and the daemon's default
  // cwd-relative shim lookup resolve exactly as in the checkout.
  const appDst = path.join(stage, "apps", "hypervisor");
  copyTree(path.join(app, "scripts"), path.join(appDst, "scripts"), { skip: (s, e) => e.name.endsWith(".test.mjs") || e.name === "__pycache__" });
  copyTree(path.join(app, "surfaces"), path.join(appDst, "surfaces"));
  copyTree(path.join(app, "product-ui", "owned"), path.join(appDst, "product-ui", "owned"), { skip: (s, e) => e.name === "node_modules" });
  for (const f of ["server.cjs", "package.json"]) if (fs.existsSync(path.join(app, "product-ui", f))) copyFile(path.join(app, "product-ui", f), path.join(appDst, "product-ui", f));
  for (const f of fs.readdirSync(app)) if (f.endsWith(".json")) copyFile(path.join(app, f), path.join(appDst, f));
  copyFile(path.join(app, "package.json"), path.join(appDst, "package.json"));
  const entries = ["scripts/serve-product-ui.mjs", "scripts/ioi-api-adapter.mjs", "scripts/ioi-agent-runs.mjs", "scripts/wallet-network-authority.mjs", "product-ui/server.cjs"].map((f) => path.join(app, f));
  const graph = reachableBarePackages(entries);
  const npmSbom = [];
  for (const pkgName of graph.bare) copyNpmPackageClosure(pkgName, path.join(appDst, "node_modules"), npmSbom);
  // shims/ + scripts the launcher and the signer need
  copyTree(path.join(ROOT, "packages", "hypervisor-harness-shims"), path.join(stage, "packages", "hypervisor-harness-shims"), { skip: (s, e) => e.name === "node_modules" });
  for (const f of ["scripts/lib/mint-approval-grant.mjs", "scripts/lib/mint-standing-approval-grant.mjs", "scripts/lib/hypervisor-alpha-release.mjs"]) copyFile(path.join(ROOT, f), path.join(stage, f));
  copyFile(path.join(HERE, "install-hypervisor-alpha-release.mjs"), path.join(stage, "install.mjs"), 0o755);

  const files = digestTree(stage);
  const byPath = new Map(files.map((f) => [f.path, f]));
  const component = (p, extra = {}) => ({ path: p, sha256: byPath.get(p).sha256, size: byPath.get(p).size, ...extra });
  const manifest = {
    schema: RELEASE_SCHEMA,
    product: "hypervisor-bounded-alpha",
    version,
    name,
    target: RELEASE_TARGET,
    built_at: new Date().toISOString(),
    provenance: {
      checkout: { head, dirty_paths: dirty, remote: git("remote", "get-url", "origin") },
      host: { platform: os.platform(), arch: os.arch(), release: os.release(), hostname_sha256: sha256Bytes(os.hostname()).slice(0, 16) },
      toolchain: { node: process.version, rustc: tool("rustc", ["--version"]), cargo: tool("cargo", ["--version"]) },
      cargo_profile: options.profile || "debug",
      cargo_profile_note: (options.profile || "debug") === "release" ? "release (optimized) binaries for the daemon, the signer, the authority control binary and the node binaries" : "debug (unoptimized + debuginfo) developer profile",
      node_bins_profile_dir: path.relative(ROOT, nodeBins),
    },
    components: {
      daemon: component("bin/hypervisor-daemon", { crate: "ioi-node", launch: "bin/hypervisor-daemon with cwd = the release root (env: IOI_HYPERVISOR_DAEMON_ADDR, IOI_HYPERVISOR_DATA_DIR, IOI_HYPERVISOR_MODEL, IOI_HYPERVISOR_MODEL_UPSTREAM, IOI_HYPERVISOR_HARNESS_SHIM=<install>/packages/hypervisor-harness-shims/generic-cli-local.mjs, plus <authority state>/daemon.env)" }),
      grant_signer: component("bin/mint-approval-grant", { crate: "ioi-node" }),
      standing_grant_signer: component("bin/mint-standing-approval-grant", { crate: "ioi-node", since: "R-14 (2026-09-09): the deployment-local operator's standing envelope" }),
      authority_node_control: component("bin/wallet-network-local-authority", { crate: "ioi-cli" }),
      served_app: { path: "apps/hypervisor/scripts/serve-product-ui.mjs", sha256: byPath.get("apps/hypervisor/scripts/serve-product-ui.mjs").sha256, product_ui_tree: "apps/hypervisor/product-ui/owned/public", launch: "node apps/hypervisor/scripts/serve-product-ui.mjs (env: IOI_HYPERVISOR_DAEMON_URL, PORT, IOI_PRODUCT_UI_PUBLIC=<install>/apps/hypervisor/product-ui/owned/public, IOI_MINT_APPROVAL_GRANT_BINARY=<install>/bin/mint-approval-grant, plus <authority state>/serve.env)", npm_packages: graph.bare },
      harness_shim: component("packages/hypervisor-harness-shims/generic-cli-local.mjs", { harness: "generic-cli-local" }),
      installer: component("install.mjs"),
    },
    prerequisites: {
      model_route: { kind: "local OpenAI-compatible model route", qualified: "Ollama serving qwen2.5:7b at http://127.0.0.1:11434/v1", provided_by_package: false },
      authority_node: {
        kind: "deployment-local wallet.network authority node",
        bring_up: "node apps/hypervisor/scripts/wallet-network-authority.mjs up --state-dir <dir> --principal-ref domain://<host> --binary <install>/bin/wallet-network-local-authority",
        provided_by_package: "control binary (bin/) and validator binaries (node-bins/: orchestration, workload, guardian, ioi-signer)",
        relocatable: "the launcher pins the node binaries to <install>/node-bins (IOI_NODE_BINARY_DIR) and never builds; a missing binary is a typed node_binaries_absent refusal. The claim is proved only by the closure test below on a host without a checkout or cargo; until that evidence is cited it is a design statement",
        closure_test: "`node <install>/apps/hypervisor/scripts/wallet-network-authority.mjs up --state-dir <dir> --principal-ref <ref>` from the unpacked package on a host WITHOUT a source checkout and with no cargo on PATH reaches READY, and the alpha journey passes against it (check:alpha-journey deployment + package mode with IOI_ALPHA_JOURNEY_NO_CHECKOUT=1)",
      },
      node: { runtime: "node >= 22 for the served App, the launcher and the installer", provided_by_package: false },
    },
    sbom: { cargo: cargoSbom(), npm: npmSbom },
    files,
    signer: { algorithm: "ed25519", key_id: signerKeyId(publicKeyPem), public_key_pem: publicKeyPem, signed_bytes: "sha256(release.json)" },
  };
  const manifestBytes = canonicalManifestBytes(manifest);
  fs.writeFileSync(path.join(stage, MANIFEST_FILE), manifestBytes);
  fs.writeFileSync(path.join(stage, SIGNATURE_FILE), `${signManifestBytes(manifestBytes, privateKeyPem)}\n`);
  const summary = { name, version, dir: stage, manifest_sha256: sha256Bytes(manifestBytes), daemon_sha256: manifest.components.daemon.sha256, files: files.length, signer: manifest.signer.key_id };
  if (options.archive) {
    const archive = path.join(outDir, `${name}.tar.zst`);
    const result = spawnSync("tar", ["--zstd", "-C", outDir, "-cf", archive, name], { stdio: "inherit" });
    if (result.status !== 0) throw new Error("tar --zstd failed");
    summary.archive = archive;
    summary.archive_sha256 = sha256File(archive);
    summary.archive_size = fs.statSync(archive).size;
  }
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((error) => { console.error(error?.stack || String(error)); process.exit(1); });
