#!/usr/bin/env node
//! M5 event-substrate genericity verifier.
//!
//! Four properties, each chosen because the obvious way to check it would be
//! blind:
//!
//! 1. NO HANDLE-ACQUISITION PATH in the lifted core — checked on COMMENT-
//!    STRIPPED source. A raw grep counts the module's own doc comment saying
//!    it never calls those openers, which is prose matching prose. That is the
//!    same blindness class as a disjunctive assertion and it fired for real
//!    during the lift.
//!
//! 2. TWO OWNER NAMESPACES traverse identical code. The owner namespace is
//!    data; two unrelated owners must produce structurally identical admitted
//!    facts differing only where the namespace itself appears.
//!
//! 3. ZERO THREAD-PLANE TRAVERSAL from the automation-scheduler path, by
//!    POSITIVE DETECTION. "Zero" is worthless unless the instrument is proven
//!    able to read non-zero, so the plane is first driven and observed to
//!    MOVE; only then is the second namespace driven and the plane observed
//!    unchanged. If the instrument cannot see the plane at all, this FAILS
//!    CLOSED rather than reporting a comfortable zero.
//!
//! 4. BOOT INJECTION IS LIVE. The un-injected unit proof shows a boundary
//!    REFUSES when nothing is wired. It cannot show the daemon actually wires
//!    it — an un-injected build would leave production permanently refusing
//!    with every unit bar green. This drives a real admission through a booted
//!    daemon and requires it to succeed.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..", "..");
const EXPECTED_CHECKS = 54;

let passed = 0;
const failures = [];
function check(label, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`PASS ${label}${detail ? ` — ${detail}` : ""}`);
  } else {
    failures.push(label);
    console.log(`FAIL ${label}${detail ? ` — ${detail}` : ""}`);
  }
}

async function request(base, method, path, body, headers = {}) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed, raw: text };
}

/// Strip line and block comments so a structural claim is checked against
/// CODE. Without this the module's own prose satisfies the grep.
function codeOnly(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((line) => !line.trim().startsWith("//"))
    .join("\n");
}

/// Split code into the part that SHIPS and the `#[cfg(test)]` module.
///
/// Tests legitimately construct a handle — that is how the admission core is
/// exercised at all. The property under proof is that no SHIPPED path can
/// acquire one, so the split is named here and the test-only exception is
/// pinned below rather than waved through.
function shippedAndTest(source) {
  const marker = source.indexOf("#[cfg(test)]");
  return marker === -1
    ? { shipped: source, test: "" }
    : { shipped: source.slice(0, marker), test: source.slice(marker) };
}

function declaration(body) {
  return {
    event_class_declaration: {
      admitted_truth_classes: [
        {
          class_id: "demo.admitted",
          payload_schema_ref: "schema://demo/admitted/v1",
        },
      ],
      ephemeral_delivery_classes: [
        {
          class_id: "demo.ephemeral",
          payload_schema_ref: "schema://demo/ephemeral/v1",
        },
      ],
    },
    ...body,
  };
}

async function main() {
  // ---- 1. structural: the lifted core cannot acquire a handle -------------
  const corePath = join(REPO, "crates", "agentgres", "src", "event_stream.rs");
  const coreSource = readFileSync(corePath, "utf8");
  const coreCode = codeOnly(coreSource);
  const openerPattern =
    /spawn_mux_writer|MuxEngine::open|MuxHandle::open|WriterConfig/;

  check(
    "the comment-stripped opener check is not vacuous",
    openerPattern.test(coreSource) && coreSource.length > coreCode.length,
    "the raw source DOES match (its own doc comment names the openers), so a raw grep would be prose matching prose",
  );
  const { shipped, test: testModule } = shippedAndTest(coreCode);
  check(
    "lifted core has no handle-acquisition path in SHIPPED code",
    !openerPattern.test(shipped),
    "0 opener call sites in the part that ships, comments stripped",
  );
  check(
    "the only opener use is inside #[cfg(test)] and is therefore compiled out",
    openerPattern.test(testModule) && testModule.startsWith("#[cfg(test)]"),
    "the exception is named and gated, not waved through",
  );
  check(
    "the lifted core is the only admission discipline",
    !codeOnly(
      readFileSync(
        join(
          REPO,
          "crates/node/src/bin/hypervisor_daemon_routes/substrate_store.rs",
        ),
        "utf8",
      ),
    ).includes("canonical_event_stream_component"),
    "the binary-module implementation was deleted, not duplicated",
  );

  // ---- 2. structural: no caller-side idempotency scan survives ------------
  for (const [label, path] of [
    ["daemon", "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"],
    ["runtime bridge", "crates/services/src/agentic/runtime/event_log_bridge.rs"],
  ]) {
    const source = codeOnly(readFileSync(join(REPO, path), "utf8"));
    check(
      `no caller-side idempotency scan survives in the ${label}`,
      !source.includes("existing_event_by_idempotency_key"),
      "dedup is inherited from admission, not re-implemented",
    );
  }

  // ---- 3. the capability surface stays at four operations ----------------
  const traitBlock = coreCode.slice(
    coreCode.indexOf("pub trait EventStreamAdmission"),
  );
  const traitBody = traitBlock.slice(0, traitBlock.indexOf("\n}"));
  const traitMethods = (traitBody.match(/\n\s{4}fn\s+\w+/g) || []).map((m) =>
    m.trim().replace(/^fn\s+/, ""),
  );
  check(
    "the capability surface is exactly four operations",
    traitMethods.length === 4,
    `methods=${traitMethods.join(",") || "none"}`,
  );
  check(
    "the four operations are the ruled ones",
    ["admit_event", "read_head", "admit_lease_transition", "advance_checkpoint"]
      .every((name) => traitMethods.includes(name)),
    "a fifth requires a filed record",
  );

  // ---- live plane --------------------------------------------------------
  const plane = await startIsolatedPlane({});
  if (!plane) {
    console.log("M5_ENVIRONMENTAL_PREREQUISITE_FAILED=daemon_binary_absent");
    process.exit(2);
  }
  try {
    const principal = {
      email: "m5-genericity-owner@local",
      password: "m5-owner-password",
      principal_id: "usr_m5_genericity_owner",
    };
    await request(plane.daemonUrl, "POST", "/v1/hypervisor/principals", principal);
    const login = await request(plane.daemonUrl, "POST", "/v1/hypervisor/auth/login", {
      email: principal.email,
      password: principal.password,
    });
    const auth = { authorization: `Bearer ${login.body?.session_token}` };
    check(
      "the isolated plane authenticates an owner",
      typeof login.body?.session_token === "string" &&
        login.body.session_token.length > 0,
      `login=${login.status}`,
    );

    const declare = (namespace, tail, decl) =>
      request(
        plane.daemonUrl,
        "POST",
        `/v1/event-streams/${namespace}/${tail}`,
        decl === undefined ? declaration({}) : { event_class_declaration: decl },
        auth,
      );
    const append = (namespace, tail, key, payload, expectedHead) =>
      request(
        plane.daemonUrl,
        "POST",
        `/v1/event-streams/${namespace}/${tail}/events`,
        declaration({
          class_id: "demo.admitted",
          idempotency_key: key,
          recorded_at_ms: 1,
          payload,
          ...(expectedHead ? { expected_head: expectedHead } : {}),
        }),
        auth,
      );
    const readHead = (namespace, tail) =>
      request(
        plane.daemonUrl,
        "GET",
        `/v1/event-streams/${namespace}/${tail}`,
        undefined,
        auth,
      );

    // ---- 4. BOOT INJECTION IS LIVE ---------------------------------------
    // The un-injected unit proof shows the boundary refuses. Only a booted
    // daemon can show the wiring is actually present.
    // ---- F1: the declaration is DURABLE STREAM TRUTH -------------------
    const declared = await declare("thread-orchestration", "s1");
    check(
      "a stream is declared once, inside an expected-absent genesis operation",
      declared.status === 200 && declared.body?.declared === true,
      `status=${declared.status} seq=${declared.body?.agentgres_sequence}`,
    );
    const redeclare = await declare("thread-orchestration", "s1");
    check(
      "redeclaration is refused by the substrate's own compare-and-swap",
      redeclare.status === 409 &&
        redeclare.body?.error?.code === "event_stream_already_declared",
      `status=${redeclare.status} code=${redeclare.body?.error?.code}`,
    );
    const bothSides = await declare("automation-scheduler", "both", {
      admitted_truth_classes: [{ class_id: "x", payload_schema_ref: "schema://x/v1" }],
      ephemeral_delivery_classes: [{ class_id: "x", payload_schema_ref: "schema://x/v1" }],
    });
    check(
      "a class on BOTH sides of the event-class line refuses at declaration",
      bothSides.status === 422 &&
        bothSides.body?.error?.code === "event_class_on_both_sides",
      `status=${bothSides.status} code=${bothSides.body?.error?.code}`,
    );
    const undeclaredStream = await append("automation-scheduler", "nodecl", "k", { n: 1 });
    check(
      "an append to an UNDECLARED stream refuses rather than defaulting a side",
      undeclaredStream.status === 422 &&
        undeclaredStream.body?.error?.code === "event_stream_undeclared",
      `status=${undeclaredStream.status} code=${undeclaredStream.body?.error?.code}`,
    );

    // REVIEWER'S LIVE REPRODUCTION, verbatim as a regression test.
    // The defect: classify(&body, ...) took the declaration from each append
    // REQUEST, so a caller could assert which side of the event-class line its
    // own event fell on. Here the stream's admitted declaration says
    // demo.admitted is TRUTH; the request claims it is ephemeral. Durable
    // truth must win, or the line is a claim rather than a fact.
    const liar = await request(
      plane.daemonUrl,
      "POST",
      "/v1/event-streams/thread-orchestration/s1/events",
      {
        class_id: "demo.admitted",
        idempotency_key: "reviewer-repro",
        recorded_at_ms: 1,
        payload: { n: 0 },
        event_class_declaration: {
          admitted_truth_classes: [],
          ephemeral_delivery_classes: [
            { class_id: "demo.admitted", payload_schema_ref: "schema://demo/admitted/v1" },
          ],
        },
      },
      auth,
    );
    check(
      "a request-supplied declaration CANNOT reclassify an admitted class (reviewer repro)",
      liar.status === 200 && liar.body?.delivery === "admitted",
      `delivery=${liar.body?.delivery} (request claimed ephemeral; stream truth says admitted)`,
    );

    const first = await append("thread-orchestration", "s1", "k1", { n: 1 });
    check(
      "boot injection is LIVE: a real admission succeeds against a booted daemon",
      first.status === 200 && typeof first.body?.agentgres_sequence === "number",
      `status=${first.status} seq=${first.body?.agentgres_sequence}`,
    );
    check(
      "an un-injected build would be visible here, not silent",
      first.body?.error?.code !== "event_stream_admission_capability_absent",
      "the capability-absent refusal is the failure this assertion would show",
    );

    // ---- 5. POSITIVE DETECTION: the thread plane is instrumentable -------
    const planeAfterFirst = await readHead("thread-orchestration", "s1");
    const threadSeqBefore = planeAfterFirst.body?.agentgres_sequence;
    check(
      "the thread plane is READABLE — the instrument can see it at all",
      planeAfterFirst.status === 200 && typeof threadSeqBefore === "number",
      `status=${planeAfterFirst.status} seq=${threadSeqBefore}`,
    );
    const second = await append(
      "thread-orchestration",
      "s1",
      "k2",
      { n: 2 },
      first.body?.admitted_head?.resulting_head_ref,
    );
    const planeMoved = await readHead("thread-orchestration", "s1");
    check(
      "the instrument reads NON-ZERO movement when the thread plane IS traversed",
      second.status === 200 &&
        planeMoved.body?.agentgres_sequence > threadSeqBefore,
      `seq ${threadSeqBefore} -> ${planeMoved.body?.agentgres_sequence}`,
    );
    const instrumentProven =
      planeAfterFirst.status === 200 &&
      typeof threadSeqBefore === "number" &&
      planeMoved.body?.agentgres_sequence > threadSeqBefore;
    // FAIL CLOSED: without a proven instrument, "zero traversals" below would
    // be indistinguishable from "the plane is absent".
    check(
      "the zero-traversal assertion has a PROVEN instrument (fails closed otherwise)",
      instrumentProven,
      instrumentProven
        ? "movement observed before zero is claimed"
        : "instrument unproven — zero below would be meaningless",
    );

    const threadHeadBeforeScheduler = planeMoved.body?.admitted_head;
    const threadSeqBeforeScheduler = planeMoved.body?.agentgres_sequence;

    // ---- 6. TWO NAMESPACES traverse identical code ------------------------
    await declare("automation-scheduler", "s1");
    const scheduler = await append("automation-scheduler", "s1", "k1", { n: 1 });
    check(
      "a second, unrelated owner namespace admits through the same path",
      scheduler.status === 200 &&
        typeof scheduler.body?.agentgres_sequence === "number",
      `status=${scheduler.status}`,
    );
    const shape = (body) => Object.keys(body || {}).sort().join(",");
    check(
      "both namespaces produce structurally identical admitted facts",
      shape(first.body) === shape(scheduler.body) &&
        shape(first.body?.admitted_head) === shape(scheduler.body?.admitted_head),
      `keys=${shape(first.body)}`,
    );
    check(
      "each namespace brands with its OWN namespace and no other",
      first.body?.stream_id?.includes("thread-orchestration") &&
        scheduler.body?.stream_id?.includes("automation-scheduler") &&
        !scheduler.body?.stream_id?.includes("thread-orchestration") &&
        !JSON.stringify(scheduler.body).includes("thread-orchestration"),
      `scheduler stream=${scheduler.body?.stream_id}`,
    );
    check(
      "the two namespaces are separate object identities, not one shared chain",
      first.body?.admitted_head?.operation_ref !==
        scheduler.body?.admitted_head?.operation_ref,
      "distinct operation refs",
    );

    // ---- 7. ZERO THREAD-PLANE TRAVERSAL, now that the instrument is proven -
    const threadAfterScheduler = await readHead("thread-orchestration", "s1");
    check(
      "driving automation-scheduler produced ZERO thread-plane traversals",
      instrumentProven &&
        threadAfterScheduler.body?.agentgres_sequence ===
          threadSeqBeforeScheduler &&
        threadAfterScheduler.body?.admitted_head?.resulting_head_ref ===
          threadHeadBeforeScheduler?.resulting_head_ref,
      `thread seq ${threadSeqBeforeScheduler} -> ${threadAfterScheduler.body?.agentgres_sequence}`,
    );

    // ---- 8. whole-stream key enforcement, live ----------------------------
    const walked = [];
    let head = scheduler.body?.admitted_head?.resulting_head_ref;
    for (let n = 0; n < 4; n += 1) {
      const step = await append(
        "automation-scheduler",
        "s1",
        `filler-${n}`,
        { filler: n },
        head,
      );
      walked.push(step.status);
      head = step.body?.admitted_head?.resulting_head_ref;
    }
    check(
      "the stream walks forward under expected-head CAS",
      walked.every((status) => status === 200),
      `statuses=${walked.join(",")}`,
    );
    const replay = await append("automation-scheduler", "s1", "k1", { n: 1 }, head);
    check(
      "a duplicate key FIVE events back replays the original, live",
      replay.status === 200 &&
        replay.body?.replayed === true &&
        replay.body?.agentgres_sequence === scheduler.body?.agentgres_sequence,
      `replayed=${replay.body?.replayed} seq=${replay.body?.agentgres_sequence} original=${scheduler.body?.agentgres_sequence}`,
    );
    const conflict = await append(
      "automation-scheduler",
      "s1",
      "k1",
      { n: 999 },
      head,
    );
    check(
      "same key with different bytes refuses by its own name",
      conflict.status === 422 &&
        conflict.body?.error?.code === "event_stream_same_key_different_bytes",
      `status=${conflict.status} code=${conflict.body?.error?.code}`,
    );

    // ---- 9. the event-class line is structural ---------------------------
    const s2Genesis = await declare("automation-scheduler", "s2");
    const ephemeral = await request(
      plane.daemonUrl,
      "POST",
      "/v1/event-streams/automation-scheduler/s2/events",
      declaration({ class_id: "demo.ephemeral", payload: { n: 1 } }),
      auth,
    );
    check(
      "an ephemeral class mints no sequence, head, root, or receipt",
      ephemeral.status === 200 &&
        ephemeral.body?.delivery === "ephemeral" &&
        ephemeral.body?.agentgres_sequence === undefined &&
        ephemeral.body?.admitted_head === undefined,
      `delivery=${ephemeral.body?.delivery}`,
    );
    const ephemeralStream = await readHead("automation-scheduler", "s2");
    // A declared stream EXISTS -- its genesis is an admitted operation -- so
    // "no stream" is no longer the right property. The property that survives
    // declaration is that ephemeral delivery ADVANCES NOTHING: the head is
    // still the genesis it was before the ephemeral event was delivered.
    check(
      "ephemeral delivery advanced NOTHING: the head is still the genesis",
      ephemeralStream.status === 200 &&
        ephemeralStream.body?.agentgres_sequence ===
          s2Genesis.body?.agentgres_sequence &&
        ephemeralStream.body?.admitted_head?.resulting_head_ref ===
          s2Genesis.body?.admitted_head?.resulting_head_ref,
      `genesis seq=${s2Genesis.body?.agentgres_sequence} head seq=${ephemeralStream.body?.agentgres_sequence}`,
    );
    await declare("automation-scheduler", "s3");
    const undeclared = await request(
      plane.daemonUrl,
      "POST",
      "/v1/event-streams/automation-scheduler/s3/events",
      declaration({ class_id: "demo.unknown", payload: {} }),
      auth,
    );
    check(
      "an undeclared class refuses rather than defaulting to either side",
      undeclared.status === 422 &&
        undeclared.body?.error?.code === "event_class_undeclared",
      `status=${undeclared.status} code=${undeclared.body?.error?.code}`,
    );

    // ---- 10. CAS is real -------------------------------------------------
    const stale = await append(
      "automation-scheduler",
      "s1",
      "stale-key",
      { n: 1 },
      scheduler.body?.admitted_head?.resulting_head_ref,
    );
    check(
      "a stale expected head is refused, not silently accepted",
      stale.status === 409 &&
        stale.body?.error?.code === "event_stream_expected_head_conflict",
      `status=${stale.status} code=${stale.body?.error?.code}`,
    );
    const noncanonical = await append(
      "Thread-Orchestration",
      "s1",
      "k9",
      { n: 1 },
    );
    check(
      "a non-canonical owner namespace refuses",
      noncanonical.status === 422,
      `status=${noncanonical.status}`,
    );


    // ---- 12. THE LEASE PLANE (F2) ---------------------------------------
    // These assertions exist because the record's positive_proof[0] demands a
    // leased subscription that survives restart, resumes from its durable
    // acknowledged checkpoint, and reconstructs exact accepted history. The
    // previous cut reported complete with none of it implemented.
    const leaseNs = "automation-scheduler";
    const created = await request(plane.daemonUrl, "POST", "/v1/subscriptions", {
      owner_namespace: leaseNs,
      stream_tail: "s1",
      subscriber_ref: "subscriber://m5/verifier",
      lease_tail: "sub_1",
      permitted_event_class_ids: ["demo.admitted"],
      max_undelivered_events: 3,
      recorded_at_ms: 1,
    }, auth);
    const REQUIRED_LEASE_FIELDS = [
      "schema_version", "lease_id", "stream_id", "subscriber_ref", "lease_state",
      "projection_binding", "backpressure", "admitted_lease_transition",
    ];
    const missing = REQUIRED_LEASE_FIELDS.filter(
      (f) => created.body?.[f] === undefined || created.body?.[f] === null,
    );
    check(
      "the create response carries every REQUIRED field of the declared lease schema",
      created.status === 200 && missing.length === 0,
      `status=${created.status} missing=${missing.join(",") || "none"}`,
    );

    const leaseRead = await request(
      plane.daemonUrl, "GET", `/v1/subscriptions/${leaseNs}/sub_1`, undefined, auth);
    check(
      "a lease is READABLE as admitted truth, not adapter-local state",
      leaseRead.status === 200 && leaseRead.body?.lease_state === "active",
      `status=${leaseRead.status} state=${leaseRead.body?.lease_state}`,
    );

    const deliverFirst = await request(
      plane.daemonUrl, "GET", `/v1/subscriptions/${leaseNs}/sub_1/delivery`, undefined, auth);
    check(
      "delivery serves the stream's admitted events through the lease",
      deliverFirst.status === 200 && Array.isArray(deliverFirst.body?.events),
      `status=${deliverFirst.status} events=${deliverFirst.body?.events?.length} pending=${deliverFirst.body?.pending_total}`,
    );
    check(
      "lag resolves to a TYPED OUTCOME bounded by the declared window, never a silent drop",
      deliverFirst.body?.delivery_outcome === "bounded_by_backpressure_window" ||
        deliverFirst.body?.delivery_outcome === "drained",
      `outcome=${deliverFirst.body?.delivery_outcome} window=${deliverFirst.body?.backpressure_window} pending=${deliverFirst.body?.pending_total}`,
    );

    // Checkpoint substitution: the record names it as a fault that must fail
    // closed. An arbitrary integer must not become an acknowledged fact.
    const bogusCheckpoint = await request(
      plane.daemonUrl, "POST", `/v1/subscriptions/${leaseNs}/sub_1/checkpoint`,
      { acknowledged_seq: 9999, recorded_at_ms: 2 }, auth);
    check(
      "checkpoint substitution refuses: an unadmitted sequence cannot be acknowledged",
      bogusCheckpoint.status === 422 &&
        bogusCheckpoint.body?.error?.code === "subscription_checkpoint_not_admitted",
      `status=${bogusCheckpoint.status} code=${bogusCheckpoint.body?.error?.code}`,
    );

    const ackSeq = deliverFirst.body?.events?.[0]?.seq;
    const advanced = await request(
      plane.daemonUrl, "POST", `/v1/subscriptions/${leaseNs}/sub_1/checkpoint`,
      { acknowledged_seq: ackSeq, recorded_at_ms: 3 }, auth);
    check(
      "a checkpoint advance is an ADMITTED transition, not a scalar the adapter holds",
      advanced.status === 200 &&
        advanced.body?.acknowledged_checkpoint?.acknowledged_seq === ackSeq &&
        typeof advanced.body?.admitted_lease_transition?.operation_ref === "string",
      `status=${advanced.status} ack=${advanced.body?.acknowledged_checkpoint?.acknowledged_seq} op=${advanced.body?.admitted_lease_transition?.operation_ref?.slice(0, 48)}`,
    );
    const rewind = await request(
      plane.daemonUrl, "POST", `/v1/subscriptions/${leaseNs}/sub_1/checkpoint`,
      { acknowledged_seq: 0, recorded_at_ms: 4 }, auth);
    check(
      "a checkpoint cannot REWIND: re-delivering acknowledged events refuses",
      rewind.status === 409 &&
        rewind.body?.error?.code === "subscription_checkpoint_would_rewind",
      `status=${rewind.status} code=${rewind.body?.error?.code}`,
    );

    const deliverAfterAck = await request(
      plane.daemonUrl, "GET", `/v1/subscriptions/${leaseNs}/sub_1/delivery`, undefined, auth);
    check(
      "delivery RESUMES FROM THE DURABLE CHECKPOINT, not from the beginning",
      deliverAfterAck.status === 200 &&
        deliverAfterAck.body?.delivered_from_checkpoint === ackSeq &&
        deliverAfterAck.body?.events?.every((e) => e.seq > ackSeq),
      `from=${deliverAfterAck.body?.delivered_from_checkpoint} first=${deliverAfterAck.body?.events?.[0]?.seq}`,
    );

    // Revoked lease: delivery under it is UNLEASED delivery and must refuse by
    // name, not return an empty list. "Delivered nothing" and "may not
    // deliver" are different facts.
    const revoked = await request(
      plane.daemonUrl, "POST", `/v1/subscriptions/${leaseNs}/sub_1/revoke`,
      { recorded_at_ms: 5 }, auth);
    check(
      "revoke is an admitted lease transition",
      revoked.status === 200 && revoked.body?.lease_state === "revoked",
      `status=${revoked.status} state=${revoked.body?.lease_state}`,
    );
    const deliverRevoked = await request(
      plane.daemonUrl, "GET", `/v1/subscriptions/${leaseNs}/sub_1/delivery`, undefined, auth);
    check(
      "delivery under a REVOKED lease refuses by name rather than returning empty",
      deliverRevoked.status === 409 &&
        deliverRevoked.body?.error?.code === "subscription_lease_revoked",
      `status=${deliverRevoked.status} code=${deliverRevoked.body?.error?.code}`,
    );

    const expiring = await request(plane.daemonUrl, "POST", "/v1/subscriptions", {
      owner_namespace: leaseNs, stream_tail: "s1",
      subscriber_ref: "subscriber://m5/expiring", lease_tail: "sub_exp",
      permitted_event_class_ids: ["demo.admitted"], max_undelivered_events: 3,
      expires_at_ms: 1, recorded_at_ms: 1,
    }, auth);
    const deliverExpired = await request(
      plane.daemonUrl, "GET", `/v1/subscriptions/${leaseNs}/sub_exp/delivery`, undefined, auth);
    check(
      "delivery past EXPIRY refuses by name",
      expiring.status === 200 && deliverExpired.status === 409 &&
        deliverExpired.body?.error?.code === "subscription_lease_expired",
      `status=${deliverExpired.status} code=${deliverExpired.body?.error?.code}`,
    );


    // ---- 13. NO SILENT LOSS IS A CONTROL-FLOW FACT (F3) -----------------
    const bridgeSource = codeOnly(
      readFileSync(join(REPO, "crates/services/src/agentic/runtime/event_log_bridge.rs"), "utf8"),
    );
    check(
      "a broadcast lag ADMITS a typed gap instead of dropping silently",
      bridgeSource.includes("admit_delivery_gap") &&
        !/Lagged\(skipped\)[\s\S]{0,200}?tracing::warn!\(\s*skipped,\s*"event-log bridge lagged; dropped/.test(bridgeSource),
      "the silent-drop warn is gone and the gap is admitted onto the stream",
    );
    check(
      "the delivery gap is a first-class admitted EVENT, not metadata",
      bridgeSource.includes("DELIVERY_GAP_CLASS_ID") &&
        bridgeSource.includes("event_stream.append"),
      "it occupies a sequence and is replayed like any other event",
    );
    const sseSource = codeOnly(
      readFileSync(join(REPO, "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs"), "utf8"),
    );
    check(
      "the SSE body states its resume contract rather than requiring inference",
      sseSource.includes("x-ioi-resume-after-seq") &&
        sseSource.includes("x-ioi-delivery-source"),
      "resume point and source are read FROM the response, not reconstructed from it",
    );


    // ---- 14. WIRE BYTES, PINNED (F7) ------------------------------------
    // Comparable to the M4 refusal-byte proof. A status code plus a code
    // string leaves the rest of the body unpinned, so a field could be added,
    // renamed, or dropped without any bar noticing. These pin the exact key
    // set of each response shape and the exact bytes of each refusal.
    const keysOf = (body) => Object.keys(body || {}).sort().join(",");

    const PINNED_APPEND_KEYS =
      "admitted_head,agentgres_sequence,class_id,delivery,owner_namespace,payload_schema_ref,replayed,stream_id";
    check(
      "admitted-append response keys are pinned byte-for-byte",
      keysOf(first.body) === PINNED_APPEND_KEYS,
      `keys=${keysOf(first.body)}`,
    );
    check(
      "admitted_head sub-object keys are pinned",
      keysOf(first.body?.admitted_head) ===
        "admission_receipt_ref,admission_root_ref,operation_ref,resulting_head_ref",
      `keys=${keysOf(first.body?.admitted_head)}`,
    );
    const PINNED_LEASE_KEYS =
      "acknowledged_checkpoint,admitted_lease_transition,backpressure,delivery_adapter_kind,expires_at_ref,lease_id,lease_state,nonclaim,projection_binding,schema_version,stream_id,subscriber_ref";
    check(
      "lease response keys are pinned byte-for-byte",
      keysOf(created.body) === PINNED_LEASE_KEYS,
      `keys=${keysOf(created.body)}`,
    );
    check(
      "delivery response keys are pinned byte-for-byte",
      keysOf(deliverFirst.body) ===
        "backpressure_window,delivered_from_checkpoint,delivery_outcome,events,lease_id,nonclaim,pending_total,resume_after_seq",
      `keys=${keysOf(deliverFirst.body)}`,
    );

    // Refusal bodies, byte-exact. A refusal whose shape drifts is a refusal
    // callers stop being able to branch on.
    const PINNED_REFUSAL_BYTES = JSON.stringify({
      error: {
        code: "subscription_lease_revoked",
        message:
          "this lease is revoked; delivery under a revoked lease is unleased delivery",
      },
    });
    check(
      "a refusal body is byte-identical to its pinned bytes",
      deliverRevoked.raw === PINNED_REFUSAL_BYTES,
      `match=${deliverRevoked.raw === PINNED_REFUSAL_BYTES}`,
    );
    check(
      "every refusal body carries exactly {error:{code,message}} and nothing else",
      [bogusCheckpoint, rewind, deliverRevoked, deliverExpired, redeclare, bothSides].every(
        (r) => keysOf(r.body) === "error" && keysOf(r.body?.error) === "code,message",
      ),
      "uniform refusal envelope across six distinct refusals",
    );


    // ---- 15. RESTART SURVIVAL (positive_proof[0]) -----------------------
    // The record claims a leased subscription SURVIVES RESTART and resumes
    // from its durable acknowledged checkpoint. Lease state being admitted in
    // Agentgres makes that true by construction -- but "true by construction"
    // is the kind of claim this review disposition exists to stop accepting,
    // so it is proven against a genuinely restarted daemon over the same data
    // directory.
    const restarted = await startIsolatedPlane({ dataDir: plane.dataDir });
    if (restarted) {
      try {
        const relogin = await request(restarted.daemonUrl, "POST", "/v1/hypervisor/auth/login", {
          email: principal.email, password: principal.password,
        });
        const rauth = { authorization: `Bearer ${relogin.body?.session_token}` };
        const afterRestart = await request(
          restarted.daemonUrl, "GET", `/v1/subscriptions/${leaseNs}/sub_1`, undefined, rauth);
        check(
          "a lease SURVIVES RESTART with its admitted state intact",
          afterRestart.status === 200 &&
            afterRestart.body?.lease_state === revoked.body?.lease_state &&
            afterRestart.body?.acknowledged_checkpoint?.acknowledged_seq === ackSeq,
          `state=${afterRestart.body?.lease_state} ack=${afterRestart.body?.acknowledged_checkpoint?.acknowledged_seq}`,
        );
        const streamAfterRestart = await request(
          restarted.daemonUrl, "GET", `/v1/event-streams/thread-orchestration/s1`, undefined, rauth);
        check(
          "the stream reconstructs EXACT accepted history across restart",
          streamAfterRestart.status === 200 &&
            streamAfterRestart.body?.admitted_head?.resulting_head_ref ===
              planeMoved.body?.admitted_head?.resulting_head_ref,
          `head unchanged=${streamAfterRestart.body?.admitted_head?.resulting_head_ref === planeMoved.body?.admitted_head?.resulting_head_ref}`,
        );
      } finally {
        await restarted.stop();
      }
    } else {
      // Fail closed. An unavailable restart plane must not silently reduce the
      // assertion count and read as coverage.
      check("a lease SURVIVES RESTART with its admitted state intact", false,
        "restart plane unavailable — failing closed rather than skipping");
      check("the stream reconstructs EXACT accepted history across restart", false,
        "restart plane unavailable — failing closed rather than skipping");
    }

    // NOTE — no anonymous-refusal assertions here, deliberately.
    //
    // `auth_gate` enforces only when `auth_enforced()` says the deployment
    // posture requires it, and this isolated plane is local-dev, where
    // anonymous access is the DESIGNED posture. An assertion that anonymous
    // reads refuse would have been measuring the plane's posture, not the
    // gate. The M4 aggregate verifier already proves uniform anonymous
    // refusal under an exposed posture, byte-identical against a pinned
    // anchor; restating it weakly here would add a bar that passes for the
    // wrong reason.

  } finally {
    await plane.stop();
  }

  check(
    "the assertion count is pinned",
    passed + failures.length === EXPECTED_CHECKS,
    `ran=${passed + failures.length} expected=${EXPECTED_CHECKS}`,
  );

  const total = passed + failures.length;
  console.log(`${passed}/${total} passed`);
  if (failures.length) {
    console.log(`M5 event-substrate genericity: FAIL (${failures.join("; ")})`);
    process.exit(1);
  }
  console.log(
    "M5 event-substrate genericity: PASS (comment-stripped opener check, two-namespace traversal, positive-detection zero-thread-plane, live boot injection)",
  );
}

main().catch((error) => {
  console.log(`M5_ENVIRONMENTAL_PREREQUISITE_FAILED=${error?.message || error}`);
  process.exit(2);
});
