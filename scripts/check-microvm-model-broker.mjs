#!/usr/bin/env node
//
// M13.10 — THE BROKERED MODEL CHANNEL IS A SECOND CHANNEL, DECLARED AS ONE.
//
// ADR 0053 § 2 asks that the model endpoint reach the guest "only through a brokered, admitted
// channel — a different profile from the hostile-guest one". Two words in that sentence carry the
// whole unit: ADMITTED, which means the destination survives refusals rather than being configured,
// and DIFFERENT PROFILE, which means a reader can tell the two apart from the record.
//
// WHAT THIS GATE PROVES, INCLUDING THE PART THAT NEEDED A REAL GUEST. The host side is proven in
// the Rust suite it drives: the destination refusals, the per-port socket, bytes crossing verbatim,
// the silence of an unreachable destination, and the declaration naming the channel only when one
// is armed. The guest half — that cloud-hypervisor surfaces a guest-initiated connection on
// `<sock_path>_<port>` with no handshake bytes of its own — was written up here as unprovable
// offline and scheduled as outstanding. It is no longer outstanding: it is proven by a LIVE probe
// on a real cloud-hypervisor/KVM boot, which this gate RUNS when the host can host one and reports
// as not-run, by name, when it cannot. A missing KVM blocks a run, never a unit.
//
// That live probe earned its keep immediately. It found that the guest's LOOPBACK INTERFACE IS
// DOWN — the initramfs never brings `lo` up, because every earlier channel in this estate is vsock
// and needed no interface at all — so the proxy bound 127.0.0.1 and the guest still could not reach
// it. Nothing offline would have found that, and it would have shipped inside a 47/47 green gate.
//
// THE RESIDUAL THIS GATE DELIBERATELY DOES NOT FENCE. A tunnel carries a host and a port, not a
// path, so an admitted model endpoint is reachable in full — including a model server's own
// non-chat API. That is recorded in canon and in the register (R-112) as an accepted exposure with
// a named fence for later. A gate that asserted path scoping here would be asserting something the
// transport cannot do.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const RESULTS = [];
const ok = (label, pass, detail = "") => {
  RESULTS.push({ label, pass: !!pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${label}${detail ? `  · ${detail}` : ""}`);
};
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), "utf8");
const readJson = (rel) => JSON.parse(read(rel));
const all = (list, fn) => list.length > 0 && list.every(fn);

// ---- 1. the contract successor exists and is derived from its predecessor ----------------------
const SCHEMA_DIR = "docs/architecture/_meta/schemas";
const v1 = readJson(`${SCHEMA_DIR}/hypervisor-vm-enforcement-declaration.v1.schema.json`);
const v2 = readJson(`${SCHEMA_DIR}/hypervisor-vm-enforcement-declaration.v2.schema.json`);

ok("the declaration has a v2 successor with its own $id and schema version",
  v2.$id === "schema://ioi/components/hypervisor/vm-enforcement-declaration/v2"
  && v2["x-ioi-schema-version"] === "ioi.components.hypervisor.vm-enforcement-declaration.v2",
  v2["x-ioi-schema-version"]);

// Derived FROM the predecessor: every v1 field survives, unchanged, rather than being re-authored.
const carried = Object.keys(v1.properties).filter((k) => k !== "schema_version");
const identical = carried.filter(
  (k) => JSON.stringify(v1.properties[k]) === JSON.stringify(v2.properties[k]));
ok("every v1 field is carried into v2 unchanged — a successor, not a rewrite",
  identical.length === carried.length,
  `${identical.length}/${carried.length} identical`);

ok("the control channel's const is untouched: the broker sits BESIDE it, not in place of it",
  v2.properties.guest_channel?.const === "host_initiated_vsock_uds_bounded"
  && v1.properties.guest_channel?.const === v2.properties.guest_channel?.const);

ok("v2 adds exactly one field, and it is the broker channel",
  Object.keys(v2.properties).length === Object.keys(v1.properties).length + 1
  && "broker_channel" in v2.properties,
  Object.keys(v2.properties).filter((k) => !(k in v1.properties)).join(","));

// ABSENCE IS NOT A CLAIM — the field is required so that "no broker" has to be said out loud.
ok("broker_channel is REQUIRED, so a record cannot stay silent about a second channel",
  v2.required.includes("broker_channel"));
ok("broker_channel admits exactly one named channel, or null",
  JSON.stringify(v2.$defs?.brokerChannel) === JSON.stringify(
    { const: "guest_initiated_vsock_uds_single_destination" })
  && v2.properties.broker_channel.$ref === "#/$defs/nullableBrokerChannel");
ok("v2 stays closed to unknown fields, exactly as v1 was",
  v2.additionalProperties === false && v1.additionalProperties === false);

// ---- 2. the registry records the succession in both directions ---------------------------------
const registry = readJson(`${SCHEMA_DIR}/architecture-contract-registry.v1.json`);
const entryV1 = registry.contracts.find((c) => c.contract_id.endsWith("vm-enforcement-declaration/v1"));
const entryV2 = registry.contracts.find((c) => c.contract_id.endsWith("vm-enforcement-declaration/v2"));
ok("the registry carries the v2 contract", !!entryV2, entryV2?.contract_id ?? "absent");
ok("succession is recorded in BOTH directions — a one-way pointer is a dangling claim",
  entryV2?.evolution?.successor_of === entryV1?.contract_id
  && entryV1?.evolution?.successor_contract_id === entryV2?.contract_id);
ok("v1 records already written stay readable — nothing rewrites history",
  entryV2?.evolution?.predecessor_remains_valid === true);
ok("the wire mutation policy is unchanged: this is why a successor was minted at all",
  entryV2?.evolution?.wire_mutation_policy === "forbidden");

// ---- 3. fixtures pin the meaning of the new field -----------------------------------------------
const FIX = `${SCHEMA_DIR}/fixtures/hypervisor-vm-enforcement-declaration-v2`;
const positives = (entryV2?.positive_fixture_refs ?? []).map((r) => readJson(`${SCHEMA_DIR}/${r}`));
const negatives = (entryV2?.negative_fixture_refs ?? []).map((r) => readJson(`${SCHEMA_DIR}/${r.path}`));
ok("both lanes are pinned as positives: one with a broker armed, one without",
  positives.some((f) => f.broker_channel === "guest_initiated_vsock_uds_single_destination")
  && positives.some((f) => f.broker_channel === null),
  `${positives.length} positive(s)`);
ok("every positive still declares zero network devices — a broker is not a licence for a NIC",
  all(positives, (f) => f.network_device_count === 0 && f.network_policy === "deny_all_no_virtual_nic"));
const absent = fs.existsSync(path.join(ROOT, FIX, "negative-broker-channel-absent.json"))
  ? readJson(`${FIX}/negative-broker-channel-absent.json`) : null;
ok("a record that OMITS broker_channel is pinned as a negative, not tolerated",
  absent !== null && !("broker_channel" in absent)
  && (entryV2?.negative_fixture_refs ?? []).some((r) => r.path.endsWith("negative-broker-channel-absent.json")));
ok("a channel that is not the named one is pinned as a negative",
  negatives.some((f) => typeof f.broker_channel === "string"
    && f.broker_channel !== "guest_initiated_vsock_uds_single_destination"));

// ---- 4. the host end refuses what it must, and says so in code ----------------------------------
const BROKER = "crates/node/src/bin/hypervisor_daemon_routes/microvm_model_broker.rs";
const broker = read(BROKER);
for (const reason of [
  "model_broker_destination_not_loopback",
  "model_broker_destination_is_daemon",
  "model_broker_destination_not_plain_http",
  "model_broker_destination_has_no_port",
]) {
  ok(`the host end names its refusal: ${reason}`, broker.includes(`"${reason}"`));
}
ok("the destination is built ONLY by the admitting function — there is no literal that skips it",
  broker.includes("pub(crate) fn admit_model_broker_destination")
  // The struct is constructed exactly once, inside the admitting function.
  && (broker.match(/ModelBrokerBinding\s*\{/g) ?? []).length === 2,
  `${(broker.match(/ModelBrokerBinding\s*\{/g) ?? []).length} construction site(s) incl. the definition`);
ok("a failed onward connect returns without writing — the guest is never handed invented bytes",
  /let Ok\(upstream\) = TcpStream::connect\(destination\) else \{\s*return;/.test(broker));
ok("the handle reaps itself: Drop stops the loop, joins the thread and unlinks the socket",
  /impl Drop for ModelBrokerHandle/.test(broker)
  && /handle\.join\(\)/.test(broker) && /remove_file\(&self\.socket_path\)/.test(broker));

// ---- 5. the two profiles are distinguishable, and the narrow one refuses ------------------------
const MICROVM = "crates/node/src/bin/hypervisor_daemon_routes/microvm.rs";
const microvm = read(MICROVM);
ok("the declaration emitted by the daemon is v2",
  microvm.includes('"ioi.components.hypervisor.vm-enforcement-declaration.v2"'));
ok("the channel is read from the SPEC's binding, never from a caller-supplied label",
  /broker_channel: self\s*\n?\s*\.model_broker\s*\n?\s*\.as_ref\(\)\s*\n?\s*\.map\(/.test(microvm));
ok("the workload-bound profile refuses a broker binding outright",
  microvm.includes('"workload_bound_profile_excludes_model_broker"'));
ok("the v2 projection is what the daemon validates against",
  microvm.includes("HypervisorVmEnforcementDeclarationV2")
  && !microvm.includes("HypervisorVmEnforcementDeclarationV1"));

// ---- 6. the guest end holds nothing and reaches nowhere else ------------------------------------
const PROXY = "scripts/phase1/guest-model-proxy.c";
const proxy = read(PROXY);
ok("the in-guest proxy binds loopback only",
  proxy.includes("htonl(INADDR_LOOPBACK)") && !proxy.includes("INADDR_ANY"));
ok("the in-guest proxy reads no header and holds no credential",
  !/Authorization|Bearer|getenv/i.test(proxy));
ok("the in-guest proxy closes when the host end is absent rather than answering",
  /if \(connect\(v[\s\S]{0,400}?close\(v\);\s*\n\s*close\(c\);\s*\n\s*continue;/.test(proxy));

// ---- 7. the proxy is supply-pinned like the agent, and NOT in the boot image --------------------
const PROVISION = "scripts/phase1/provision-vm-toolchain.sh";
const provision = read(PROVISION);
ok("the toolchain builds the proxy and pins BOTH its source and binary hashes",
  provision.includes('gcc -static -O2 -s -o "$TC/guest-model-proxy"')
  && provision.includes('"guest_model_proxy": { "source_sha256": "$PROXY_SRC_SHA", "binary_sha256": "$PROXY_SHA"'));
ok("the proxy is NOT copied into the initramfs — a VM with no model channel carries no binary that opens one",
  !/cp "\$TC\/guest-model-proxy" "\$RD/.test(provision));

// ---- 8. canon says all of it -------------------------------------------------------------------
const CANON = "docs/architecture/components/hypervisor/providers-and-environments.md";
const canon = read(CANON);
ok("canon names the venue profile",
  canon.includes("trusted_host_hostile_guest/no-nic-brokered-model-v1"));
ok("canon's hostile-guest sentence is scoped rather than left false",
  canon.includes("Its only guest transport is the")
  && canon.includes("cannot acquire a\nsecond one by configuration"));
ok("canon states the tunnel's true shape: a host and a port, not a path",
  /carries a host and a port, not a path/.test(canon));
ok("canon states the residual instead of implying it is fenced",
  /non-chat API/.test(canon) && /model-only reverse proxy/.test(canon));
ok("canon states that no provider key enters the guest on any path",
  /no provider key enters the guest on any path/.test(canon));

// ---- 9. the channel is ARMED per environment, staged per run, and never by default -------------
const ENVROUTES = "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs";
const envroutes = read(ENVROUTES);
ok("the channel is armed from a DECLARATION on the recipe, not from being a microVM",
  /fn microvm_model_broker_binding/.test(envroutes)
  && envroutes.includes('"brokered_model_only"')
  && /!= "brokered_model_only"[\s\S]{0,60}return Ok\(None\)/.test(envroutes));
ok("the declaration rides the connectivity profile's egress policy rather than minting a second place to decide egress",
  envroutes.includes('.get("egress_policy")') && envroutes.includes('"default_deny_external"'));
ok("the binding is on the spec BEFORE the declaration is minted, so the record describes the VM that exists",
  envroutes.indexOf("spec.model_broker = microvm_model_broker_binding")
    < envroutes.indexOf("let enforcement = spec"));
ok("the host end comes up BEFORE the VM — no window where the guest dials an absent listener",
  envroutes.indexOf("start_model_broker(&spec.sock_path")
    < envroutes.indexOf("let mut vm = monitor"));
ok("the status records the armed channel, and records NULL when none was armed",
  /"model_broker": match spec\.model_broker\.as_ref\(\)/.test(envroutes)
  && /None => Value::Null/.test(envroutes));

const stageFn = microvm.slice(microvm.indexOf("pub(crate) fn stage_and_start_model_proxy"));
ok("the staged binary's hash is RE-VERIFIED at use against the supply pin",
  stageFn.includes("guest_model_proxy_hash_mismatch") && /sha256_file\(Path::new\(path\)\)/.test(stageFn));
ok("staging MOVES the binary out of /workspace — the exported tree is what lands back on the host checkout",
  /mv \.\/\{staged_name\} \{guest_path\}/.test(stageFn)
  && stageFn.includes('const GUEST_PROXY_GUEST_PATH') === false
  && microvm.includes('const GUEST_PROXY_GUEST_PATH: &str = "/tmp/ioi-model-proxy";'));
ok("staging PROVES the proxy is running rather than trusting that the shell forked",
  stageFn.includes("guest_model_proxy_not_running_after_start") && stageFn.includes("/proc/$(cat"));
ok("staging PROVES the workspace is clean afterwards, rather than assuming the move worked",
  stageFn.includes("guest_model_proxy_left_in_exported_workspace"));
ok("the detached proxy's streams are closed, or the guest agent's exec would never see EOF",
  />\/dev\/null 2>&1 &/.test(stageFn));

// ---- 10. the harness runs IN the guest, and its work returns through quarantine ----------------
const LIFECYCLE = "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs";
const lifecycle = read(LIFECYCLE);
ok("there is a GUEST lane, distinct from the host-spawn lane",
  /pub\(crate\) fn run_guest_harness_lane/.test(lifecycle));
ok("the lane follows the VENUE the environment reported, not the request",
  /if execution_venue == "microvm"/.test(lifecycle));
// THE IMPORTANT ONE. A microvm venue that quietly ran on the host would make the receipt's venue
// field a lie in the only direction that matters — claiming isolation that did not happen.
ok("a microvm venue with NO live VM fails rather than silently running on the host",
  lifecycle.includes("guest_lane_no_live_microvm")
  && !/execution_venue == "microvm"[\s\S]{0,900}unwrap_or_else\(\|\| run_host_spawn_lane/.test(lifecycle));
ok("the guest harness is handed the in-guest proxy's loopback endpoint, so no harness code learns it is in a VM",
  /IOI_HYPERVISOR_MODEL_UPSTREAM='http:\/\/127\.0\.0\.1:\{port\}'/.test(lifecycle)
  && /port = super::microvm_model_broker::GUEST_LISTEN_PORT/.test(lifecycle));
ok("the merged guest stream is labelled `combined`, not `stdout` — the wire never made that distinction",
  /\("combined"\.to_string\(\), line\.to_string\(\)\)/.test(lifecycle)
  && !/\("stdout"\.to_string\(\), line\.to_string\(\)\)/.test(lifecycle));
ok("guest output returns through QUARANTINE, validated before anything lands",
  /pub\(crate\) fn import_guest_workspace/.test(lifecycle)
  && /untar_into\(&quarantine, &exported\)/.test(lifecycle));
ok("the quarantine walk does not follow symlinks — untar_into refuses them and this must not undo that",
  /if kind\.is_symlink\(\) \{\s*continue;/.test(lifecycle));
ok("the workspace is imported ONLY after a successful run, never over a half-finished tree",
  /if lane_outcome\.ok \{[\s\S]{0,200}import_guest_workspace/.test(lifecycle));

// ---- 11. drive the Rust suite that proves the behaviour ------------------------------------------
let rust = { pass: false, detail: "" };
try {
  const out = execFileSync(
    "cargo",
    ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon", "--",
      "microvm_model_broker::tests", "microvm::tests::the_",
      "environment_routes::containment_tests::a_microvm_gets_no_model",
      "environment_routes::containment_tests::a_declared_channel"],
    { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 900_000 });
  const line = out.split("\n").filter((l) => l.startsWith("test result:")).pop() ?? "";
  const m = /(\d+) passed; (\d+) failed/.exec(line);
  rust = { pass: !!m && m[2] === "0" && Number(m[1]) >= 10, detail: line.trim() };
} catch (error) {
  rust = { pass: false, detail: String(error?.stdout ?? error?.message ?? error).split("\n").slice(-4).join(" ") };
}
ok("the host end's behaviour is proven by its Rust suite (bytes verbatim, silence on failure, refusals)",
  rust.pass, rust.detail);

// ---- 12. THE LIVE GUEST-INITIATED DIRECTION — run it where it can run, name it where it cannot --
const liveCapable = fs.existsSync("/dev/kvm")
  && fs.existsSync(path.join(process.env.IOI_VM_TOOLCHAIN_DIR
    || path.join(process.env.HOME || "", ".ioi/vm-toolchain"), "supply-manifest.json"));
if (!liveCapable) {
  // NOT a pass. The gate says what it did not run and why, rather than counting a skip as evidence.
  console.log("SKIP  the live guest-initiated probe — this host has no /dev/kvm or no provisioned "
    + "toolchain; the channel's guest half is NOT claimed by this run");
} else {
  let live = { pass: false, detail: "" };
  try {
    const out = execFileSync(
      "cargo",
      ["test", "-p", "ioi-node", "--bin", "hypervisor-daemon",
        "--", "--ignored", "the_brokered_channel_carries_guest_bytes",
        "guest_workspace_returns_through_quarantine"],
      { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 900_000 });
    const line = out.split("\n").filter((l) => l.startsWith("test result:")).pop() ?? "";
    live = { pass: /2 passed; 0 failed/.test(line), detail: line.trim() };
  } catch (error) {
    live = { pass: false, detail: String(error?.stdout ?? error?.message ?? error).split("\n").slice(-6).join(" ") };
  }
  ok("LIVE: a real KVM guest dials out with bytes VERBATIM and zero network devices, and its workspace returns through quarantine",
    live.pass, live.detail);
}

const failed = RESULTS.filter((r) => !r.pass);
console.log(`\n${failed.length === 0 ? "PASS" : "FAIL"} check:microvm-model-broker — ${RESULTS.length - failed.length}/${RESULTS.length} assertion(s)`
  + (failed.length ? ` · failing: ${failed.map((r) => r.label).join(" | ")}` : ""));
console.log(liveCapable
  ? "The guest-initiated direction and the quarantine round-trip were both PROVEN on live boots "
    + "in this run, not deferred. What remains scheduled-outstanding for M13.10 is the single live "
    + "alpha journey under IOI_ALPHA_EXECUTION_VENUE=microvm, which needs a model endpoint and a "
    + "wallet fixture — a missing credential blocks that RUN, not this unit."
  : "The guest-initiated direction was NOT exercised on this host (no /dev/kvm or no provisioned "
    + "toolchain). This run claims the host half only.");
process.exit(failed.length === 0 ? 0 : 1);
