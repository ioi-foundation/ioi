#!/usr/bin/env node
// install-hypervisor-alpha-release — the installer that ships INSIDE the packaged release as
// install.mjs (bounded-alpha-profile.md steps 1 and 12).
//
//   node install.mjs verify   --release <dir|.tar.zst> --trust <signer.pub.pem>
//   node install.mjs install  --release <dir|.tar.zst> --trust <signer.pub.pem> --prefix <dir>
//   node install.mjs activate --prefix <dir> --version <v> [--daemon-url http://127.0.0.1:PORT --cookie ... ]
//   node install.mjs rollback --prefix <dir>
//   node install.mjs status   --prefix <dir>
//   node install.mjs preview  --release <dir|.tar.zst> --trust <signer.pub.pem> --prefix <dir>   (read-only: writes nothing)
//   node install.mjs uninstall --prefix <dir>   (removes ONLY what install/activate wrote; never user data, keys, backups)
//
// Layout under --prefix: releases/<version>/ (verified, immutable), current -> releases/<version>
// (the activation), state/activation.json (the activation history the operator can read without
// a daemon). Install never activates; activate never installs; rollback re-activates the previous
// activation. None of them touches user data, the daemon's data dir, keys or the authority node.
//
// Preview and uninstall (2026-09-20, R-206, M12.2): preview computes what install+activate WOULD
// write and what they would never touch, and writes nothing — the trust bridge is inspectable before
// the host is mutated. Uninstall removes exactly the installer's own footprint under --prefix
// (releases/, current, state/) and preserves and LISTS everything else it finds there; a data wipe is
// a separately authorized effect this installer has no verb for (core-clients-surfaces.md § Zero-To-
// Operable Local Deployment: "Uninstall never implies deletion of user data, Agentgres truth, keys,
// packages, backups, or restore material").
//
// Trust: `--trust` pins the signer's public key on this host. The installer never reads a key from
// the package to trust the package.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
// Inside the package the library sits at scripts/lib/; in the checkout at ./lib/.
const LIB = ["scripts/lib/hypervisor-alpha-release.mjs", "lib/hypervisor-alpha-release.mjs"].map((p) => path.join(HERE, p)).find((p) => fs.existsSync(p));
const { MANIFEST_FILE, sha256File, verifyReleaseDir } = await import(LIB);

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument ${arg}`);
    const value = rest[i + 1];
    if (value === undefined) throw new Error(`${arg} needs a value`);
    options[arg.slice(2)] = value;
    i += 1;
  }
  return { command, options };
}

function unpackIfArchive(release) {
  const abs = path.resolve(release);
  if (fs.statSync(abs).isDirectory()) return { dir: abs, cleanup: () => {} };
  if (!abs.endsWith(".tar.zst")) throw new Error("--release must be an unpacked directory or a .tar.zst archive");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-alpha-release-"));
  const result = spawnSync("tar", ["--zstd", "-C", tmp, "-xf", abs], { stdio: "inherit" });
  if (result.status !== 0) throw new Error("tar --zstd extraction failed");
  const entries = fs.readdirSync(tmp);
  if (entries.length !== 1) throw new Error("archive must contain exactly one release directory");
  return { dir: path.join(tmp, entries[0]), cleanup: () => fs.rmSync(tmp, { recursive: true, force: true }), archive_sha256: sha256File(abs) };
}

function readState(prefix) {
  const file = path.join(prefix, "state", "activation.json");
  if (!fs.existsSync(file)) return { schema: "ioi.hypervisor.alpha-activation.v1", current: null, previous: null, history: [] };
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeState(prefix, state) {
  fs.mkdirSync(path.join(prefix, "state"), { recursive: true });
  const file = path.join(prefix, "state", "activation.json");
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`);
  fs.renameSync(tmp, file);
}

function readInstalledManifest(prefix, version) {
  const file = path.join(prefix, "releases", version, MANIFEST_FILE);
  if (!fs.existsSync(file)) throw new Error(`release ${version} is not installed under ${prefix}`);
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** The installer's own footprint under a prefix — the only things uninstall may remove. */
const FOOTPRINT = ["releases", "current", "state"];

/** What install + activate WOULD write under `prefix` for `manifest`, and what they would never touch. Pure. */
function previewPlan(prefix, manifest, unpacked) {
  const version = manifest.version;
  const dest = path.join(prefix, "releases", version);
  const alreadyInstalled = fs.existsSync(dest);
  const link = path.join(prefix, "current");
  const state = readState(prefix);
  const foreign = fs.existsSync(prefix) ? fs.readdirSync(prefix).filter((e) => !FOOTPRINT.includes(e)) : [];
  return {
    ok: true,
    read_only: true,
    version,
    manifest_sha256: unpacked.manifest_sha256,
    daemon_sha256: manifest.components?.daemon?.sha256 ?? null,
    would_write: {
      release_dir: dest,
      current_link: link,
      activation_state: path.join(prefix, "state", "activation.json"),
      already_installed: alreadyInstalled,
      would_replace_current: state.current?.version ?? null,
    },
    endpoints: {
      daemon: "the daemon binds the address the operator starts it with (IOI_HYPERVISOR_DAEMON_ADDR); the installer opens no port",
      served_app: "served from <prefix>/current by the operator's serve step; the installer serves nothing",
    },
    data_custody: {
      data_dir: "outside the prefix, chosen by the operator (IOI_HYPERVISOR_DATA_DIR); the installer never reads or writes it",
      keys: "the operator's pinned signer key and the daemon's identity keys are never written by the installer",
      backups_and_restore_material: "never written or removed by the installer",
    },
    supervisor: "none is shipped: the daemon runs attached/foreground or under the operator's own supervisor (core-clients-surfaces.md: a CLI/headless distribution supplies an attached/foreground recovery mode)",
    egress: "none during verify, preview, install, activate, rollback, status or uninstall; update discovery is optional egress the installer does not perform",
    preserved_if_present: foreign.map((e) => path.join(prefix, e)),
    note: "preview writes nothing; the plan above is what install then activate would do under this prefix",
  };
}

/** Remove exactly the installer's footprint under `prefix`; preserve and list everything else. */
function uninstall(prefix) {
  if (!fs.existsSync(prefix)) return { ok: true, prefix, removed: [], preserved: [], note: "prefix does not exist; nothing to remove" };
  const entries = fs.readdirSync(prefix);
  const removed = [];
  const preserved = [];
  for (const entry of entries) {
    const full = path.join(prefix, entry);
    if (FOOTPRINT.includes(entry)) { fs.rmSync(full, { recursive: true, force: true }); removed.push(full); }
    else preserved.push(full);
  }
  return {
    ok: true,
    prefix,
    removed,
    preserved,
    data_wipe: "not performed and not a verb of this installer: user data, Agentgres truth, keys, packages, backups and restore material are separately authorized effects",
    note: preserved.length ? "the prefix is kept because it holds material the installer did not write" : "the prefix's installer footprint is gone",
  };
}

/** Point `current` at a release with an atomic symlink swap (new link + rename). */
function switchCurrent(prefix, version) {
  const target = path.join("releases", version);
  const link = path.join(prefix, "current");
  const tmp = `${link}.${process.pid}.tmp`;
  fs.rmSync(tmp, { force: true });
  fs.symlinkSync(target, tmp);
  fs.renameSync(tmp, link);
}

function activate(prefix, version, act) {
  const manifest = readInstalledManifest(prefix, version);
  const state = readState(prefix);
  const previous = state.current;
  switchCurrent(prefix, version);
  const entry = { at: new Date().toISOString(), act, version, daemon_sha256: manifest.components.daemon.sha256, previous_version: previous?.version || null };
  state.previous = previous;
  state.current = { version, daemon_sha256: manifest.components.daemon.sha256, activated_at: entry.at };
  state.history.push(entry);
  writeState(prefix, state);
  return { ok: true, ...entry, current: path.join(prefix, "current"), note: "restart the daemon and the served App from <prefix>/current, then observe the release change plan on the daemon" };
}

const { command, options } = parseArgs(process.argv.slice(2));
try {
  if (command === "verify" || command === "install" || command === "preview") {
    if (!options.release || !options.trust) throw new Error(`${command} requires --release and --trust`);
    const trustedPublicKeyPem = fs.readFileSync(path.resolve(options.trust), "utf8");
    const unpacked = unpackIfArchive(options.release);
    try {
      const result = verifyReleaseDir(unpacked.dir, { trustedPublicKeyPem });
      if (!result.ok) {
        console.error(JSON.stringify({ ok: false, failures: result.failures }, null, 2));
        process.exit(1);
      }
      const summary = { ok: true, version: result.manifest.version, name: result.manifest.name, manifest_sha256: result.manifestSha256, daemon_sha256: result.manifest.components.daemon.sha256, signer: result.manifest.signer.key_id, files: result.manifest.files.length, archive_sha256: unpacked.archive_sha256 || null };
      if (command === "verify") { console.log(JSON.stringify(summary, null, 2)); process.exit(0); }
      if (command === "preview") {
        if (!options.prefix) throw new Error("preview requires --prefix");
        console.log(JSON.stringify(previewPlan(path.resolve(options.prefix), result.manifest, { manifest_sha256: result.manifestSha256 }), null, 2));
        process.exit(0);
      }
      if (!options.prefix) throw new Error("install requires --prefix");
      const prefix = path.resolve(options.prefix);
      const dest = path.join(prefix, "releases", result.manifest.version);
      if (fs.existsSync(dest)) {
        // Idempotent: an installed release is re-verified in place, never overwritten.
        const again = verifyReleaseDir(dest, { trustedPublicKeyPem });
        if (!again.ok) throw new Error(`installed release ${result.manifest.version} no longer verifies: ${again.failures.join("; ")}`);
        console.log(JSON.stringify({ ...summary, installed: dest, already_installed: true }, null, 2));
        process.exit(0);
      }
      fs.mkdirSync(path.join(prefix, "releases"), { recursive: true });
      const staging = `${dest}.installing.${process.pid}`;
      fs.cpSync(unpacked.dir, staging, { recursive: true });
      const staged = verifyReleaseDir(staging, { trustedPublicKeyPem });
      if (!staged.ok) { fs.rmSync(staging, { recursive: true, force: true }); throw new Error(`copied release does not verify: ${staged.failures.join("; ")}`); }
      fs.renameSync(staging, dest);
      console.log(JSON.stringify({ ...summary, installed: dest, activated: false }, null, 2));
    } finally {
      unpacked.cleanup();
    }
  } else if (command === "activate") {
    if (!options.prefix || !options.version) throw new Error("activate requires --prefix and --version");
    console.log(JSON.stringify(activate(path.resolve(options.prefix), options.version, "activate"), null, 2));
  } else if (command === "rollback") {
    if (!options.prefix) throw new Error("rollback requires --prefix");
    const prefix = path.resolve(options.prefix);
    const state = readState(prefix);
    if (!state.previous?.version) throw new Error("no previous activation to roll back to");
    console.log(JSON.stringify(activate(prefix, state.previous.version, "rollback"), null, 2));
  } else if (command === "uninstall") {
    if (!options.prefix) throw new Error("uninstall requires --prefix");
    if (options["wipe-data"] !== undefined) throw new Error("this installer has no data-wipe verb: a wipe is a separately authorized effect (core-clients-surfaces.md § Zero-To-Operable Local Deployment)");
    console.log(JSON.stringify(uninstall(path.resolve(options.prefix)), null, 2));
  } else if (command === "status") {
    if (!options.prefix) throw new Error("status requires --prefix");
    const prefix = path.resolve(options.prefix);
    const state = readState(prefix);
    const link = path.join(prefix, "current");
    const current = fs.existsSync(link) ? fs.readlinkSync(link) : null;
    const installed = fs.existsSync(path.join(prefix, "releases")) ? fs.readdirSync(path.join(prefix, "releases")).filter((d) => !d.includes(".installing.")) : [];
    const currentDaemon = current ? path.join(prefix, current, "bin", "hypervisor-daemon") : null;
    console.log(JSON.stringify({ prefix, current_link: current, current_daemon_sha256: currentDaemon && fs.existsSync(currentDaemon) ? sha256File(currentDaemon) : null, installed, activation: state }, null, 2));
  } else {
    console.error("usage: install.mjs <verify|preview|install|activate|rollback|status|uninstall> ...");
    process.exit(2);
  }
} catch (error) {
  console.error(JSON.stringify({ ok: false, error: String(error?.message || error) }));
  process.exit(1);
}
void execFileSync;
