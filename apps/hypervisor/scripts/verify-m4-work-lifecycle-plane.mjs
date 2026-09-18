#!/usr/bin/env node

// M04.6 — the shared work-lifecycle persistence plane, driven live against an isolated daemon.
//
// R-192 slice S5-1 re-typed this verifier. It used to drive the plane through GoalRun creation,
// because the GoalRun admission path was the record chain's only writer. Goal runs and outcome
// rooms are ioi.ai compositions over thread orchestration primitives and are no longer Hypervisor
// surfaces, so the chain is now written through one generic owner-scoped route and this verifier
// drives THAT: a platform `work_run` object with a `harness_invocation` child. Nothing here knows
// what an application does with its lifecycle, which is the point.

import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startIsolatedPlane } from "./lib/isolated-daemon.mjs";
import { emitVerifierCensus } from "./lib/verifier-census.mjs";

const dataDir = mkdtempSync(join(tmpdir(), "ioi-m4-work-lifecycle-"));
const checks = [];
const check = (name, condition, detail = "") => checks.push({ name, pass: Boolean(condition), detail });

const OBJECT = "work_run://m046/bounded-lifecycle-1";
const CHILD = "harness_invocation://m046/invocation-1";

let session = "";
async function request(base, method, path, body, authenticated = true) {
  const response = await fetch(`${base}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(authenticated && session ? { cookie: `ioi_session=${session}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

// One lifecycle record. `record_hash` and `resulting_head` are stamped by the kernel; the caller
// states the head it expects to move against, which is the compare-and-swap precondition.
const record = (owner, { id, type, key, head, at, phase, child, kind = "work_run" }) => ({
  schema_version: "ioi.work-lifecycle-record.v1",
  record_id: `work-lifecycle://m046/${id}`,
  record_hash: "",
  record_type: type,
  object_kind: kind,
  object_ref: OBJECT,
  owner_ref: owner,
  expected_head: head,
  resulting_head: "",
  idempotency_key: key,
  authority_class: "owner",
  authority_ref: owner,
  authority_grant_refs: [],
  decision_receipt_ref: null,
  evidence_refs: [],
  receipt_refs: [`receipt://m046/${id}`],
  phase_transition: phase ?? null,
  child_reference: child ?? null,
  occurred_at_ms: at,
});

const append = (base, body, authenticated = true) =>
  request(base, "POST", "/v1/hypervisor/work-lifecycle/records", body, authenticated);

let plane;
try {
  plane = await startIsolatedPlane({ dataDir });
  if (!plane) {
    console.error("BLOCKED: build target/debug/hypervisor-daemon first");
    process.exitCode = 2;
  } else {
    const daemonLogName = readdirSync(dataDir)
      .filter((name) => name === "isolated-daemon.log" || name.startsWith("isolated-daemon-restart-"))
      .sort()
      .at(-1);
    const daemonLog = daemonLogName ? readFileSync(join(dataDir, daemonLogName), "utf8") : "";
    const bootstrapToken = daemonLog.match(/ioi_bootstrap_[a-f0-9]{64}/gu)?.at(-1) ?? "";
    const bootstrap = await request(plane.daemonUrl, "POST", "/v1/hypervisor/auth/bootstrap", {
      token: bootstrapToken,
      password: "m4-work-lifecycle-plane-v1",
      email: "m4-work-lifecycle@ioi.local",
    }, false);
    session = bootstrap.body?.session_token ?? "";
    const who = await request(plane.daemonUrl, "GET", "/v1/hypervisor/auth/whoami");
    const principalRef = who.body?.principal?.principal_ref
      || (who.body?.principal?.principal_id ? `user://${who.body.principal.principal_id}` : "");
    const emptyStatus = await request(plane.daemonUrl, "GET", "/v1/hypervisor/work-lifecycle/status");
    check(
      "the live verifier authenticates one principal and finds every durable family empty",
      session.startsWith("ioi_sess_") && principalRef.startsWith("user://")
        && emptyStatus.status === 200
        && Object.values(emptyStatus.body?.durable_family_object_counts ?? { x: 1 })
          .every((value) => value === 0),
      `${bootstrap.status}/${emptyStatus.status}/${principalRef}`,
    );

    const mine = (fields) => record(principalRef, fields);
    const genesis = await append(plane.daemonUrl, {
      record: mine({
        id: "0",
        type: "phase_transition",
        key: "m046-genesis",
        head: null,
        at: 1_000,
        phase: { from_phase: null, to_phase: "pending" },
      }),
    });
    const head1 = genesis.body?.resulting_head ?? "";
    const attached = await append(plane.daemonUrl, {
      record: mine({
        id: "1",
        type: "child_reference",
        key: "m046-attach-1",
        head: head1,
        at: 2_000,
        child: {
          operation: "attach",
          relation_kind: "harness_invocation",
          child_ref: CHILD,
          effect_recovery_class: "compensatable",
        },
      }),
    });
    const head2 = attached.body?.resulting_head ?? "";
    const activated = await append(plane.daemonUrl, {
      record: mine({
        id: "2",
        type: "phase_transition",
        key: "m046-active",
        head: head2,
        at: 3_000,
        phase: { from_phase: "pending", to_phase: "active" },
      }),
    });
    const head3 = activated.body?.resulting_head ?? "";
    check(
      "the generic writer admits a three-edge platform chain and returns each stamped head",
      genesis.status === 200 && attached.status === 200 && activated.status === 200
        && [head1, head2, head3].every((head) => /^sha256:[0-9a-f]{64}$/u.test(head))
        && new Set([head1, head2, head3]).size === 3
        && [genesis, attached, activated].every((reply) => reply.body?.replayed === false)
        && activated.body?.projection?.active_phase === "active",
      `${genesis.status}/${attached.status}/${activated.status}/${genesis.body?.error?.code ?? ""}`,
    );

    const replay = await append(plane.daemonUrl, {
      record: mine({
        id: "2",
        type: "phase_transition",
        key: "m046-active",
        head: head2,
        at: 3_000,
        phase: { from_phase: "pending", to_phase: "active" },
      }),
    });
    check(
      "an object-scoped idempotency key replays with identical bytes and appends no second record",
      replay.status === 200 && replay.body?.replayed === true
        && replay.body?.resulting_head === head3,
      `${replay.status}/${replay.body?.replayed}`,
    );

    const kindDrift = await append(plane.daemonUrl, {
      record: mine({
        id: "3",
        type: "phase_transition",
        key: "m046-kind-drift",
        head: head3,
        at: 4_000,
        kind: "automation_run",
        phase: { from_phase: "active", to_phase: "active" },
      }),
    });
    check(
      "the platform's continuity gate refuses a successor that re-declares the genesis object_kind",
      kindDrift.status === 422
        && kindDrift.body?.error?.code === "work_lifecycle_log_authority_refused"
        && String(kindDrift.body?.error?.message ?? "").includes("object_kind"),
      `${kindDrift.status}/${kindDrift.body?.error?.code}`,
    );

    const anonymousWrite = await append(plane.daemonUrl, {
      record: mine({
        id: "4",
        type: "phase_transition",
        key: "m046-anonymous",
        head: head3,
        at: 5_000,
        phase: { from_phase: "active", to_phase: "completed" },
      }),
    }, false);
    const substitutedOwner = await append(plane.daemonUrl, {
      record: record("user://foreign", {
        id: "5",
        type: "phase_transition",
        key: "m046-substituted-owner",
        head: head3,
        at: 5_000,
        phase: { from_phase: "active", to_phase: "completed" },
      }),
    });
    check(
      "the writer refuses an anonymous caller and a caller-substituted owner before it reads the chain",
      anonymousWrite.status === 401
        && substitutedOwner.status === 403
        && substitutedOwner.body?.error?.code === "work_lifecycle_owner_forbidden",
      `${anonymousWrite.status}/${substitutedOwner.status}/${substitutedOwner.body?.error?.code}`,
    );

    const encodedObject = encodeURIComponent(OBJECT);
    const encodedOwner = encodeURIComponent(principalRef);
    const records = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/records?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    check(
      "the shared record route reconstructs the exact chain the writer admitted and no refused edge",
      records.status === 200 && records.body?.record_count === 3
        && records.body?.records?.map((entry) => entry.resulting_head).join("|") === [head1, head2, head3].join("|")
        && records.body?.records?.every((entry) => entry.object_kind === "work_run"
          && entry.object_ref === OBJECT && entry.owner_ref === principalRef),
      `${records.status}/${records.body?.error?.code}`,
    );

    const projection = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    check(
      "the shared projection route rebuilds the active phase and typed child at the same head",
      projection.status === 200
        && projection.body?.projection?.head === head3
        && projection.body?.projection?.active_phase === "active"
        && projection.body?.projection?.record_count === 3
        && projection.body?.projection?.object_kind === "work_run"
        && projection.body?.projection?.active_children?.harness_invocation?.[0]?.child_ref === CHILD,
      `${projection.status}/${projection.body?.error?.code}`,
    );

    const status = await request(plane.daemonUrl, "GET", "/v1/hypervisor/work-lifecycle/status");
    const families = status.body?.durable_family_object_counts ?? {};
    const workRunKind = status.body?.per_kind_lifecycle_counts?.find((entry) => entry.object_kind === "work_run");
    check(
      "status reports the five durable families, the one untyped writer binding, and the kernel-truth nonclaim",
      status.status === 200 && status.body?.kernel_present === true
        && families["work-lifecycle-records"] === 1
        && families["work-lifecycle-projections"] === 1
        && families["work-lifecycle-cancellation-plans"] === 0
        && families["work-lifecycle-archive-segments"] === 0
        && families["work-lifecycle-snapshots"] === 0
        && workRunKind?.object_count === 1 && workRunKind?.record_count === 3
        && status.body?.live_owner_route_bindings?.length === 1
        && status.body?.live_owner_route_bindings?.[0]?.object_kind === "any"
        && status.body?.live_owner_route_bindings?.[0]?.route === "POST /v1/hypervisor/work-lifecycle/records"
        && status.body?.nonclaim?.includes("Session, launch, thread, HarnessInvocation"),
      `${status.status}/${JSON.stringify(families)}`,
    );
    check(
      "no retired goal-run or outcome-room binding survives in what this plane reports about itself",
      !JSON.stringify(status.body ?? {}).includes("goal-orchestration")
        && status.body?.live_owner_route_bindings?.every((binding) => binding.object_kind !== "goal_run"
          && binding.object_kind !== "outcome_room"),
    );

    const anonymousStatus = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
      undefined,
      false,
    );
    check("the shared status surface has no anonymous existence oracle", anonymousStatus.status === 401);

    const foreignOwner = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodeURIComponent("user://foreign")}`,
    );
    check(
      "owner-scoped lifecycle reads refuse a caller-substituted owner before object disclosure",
      foreignOwner.status === 403 && foreignOwner.body?.error?.code === "work_lifecycle_owner_forbidden",
      `${foreignOwner.status}/${foreignOwner.body?.error?.code}`,
    );

    const substitutedRequester = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/cancellation-plan",
      {
        object_ref: OBJECT,
        owner_ref: principalRef,
        requested_by_ref: "user://foreign",
        reason: "forged cancellation requester",
      },
    );
    const statusAfterSubstitution = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
    );
    check(
      "cancellation planning derives requester authority and persists nothing for substitution",
      substitutedRequester.status === 403
        && substitutedRequester.body?.error?.code === "work_lifecycle_requester_substitution"
        && statusAfterSubstitution.body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"] === 0,
      `${substitutedRequester.status}/${substitutedRequester.body?.error?.code}`,
    );

    // A `compensatable` child cannot be cancelled by request alone: the kernel refuses to plan a
    // compensating act it has no policy for, rather than defaulting one.
    const unpolicedCancellation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/cancellation-plan",
      {
        object_ref: OBJECT,
        owner_ref: principalRef,
        requested_by_ref: principalRef,
        reason: "cancellation with no compensation policy",
      },
    );
    check(
      "planning refuses a compensatable child with no compensation policy instead of defaulting one",
      unpolicedCancellation.status === 422
        && unpolicedCancellation.body?.error?.code === "work_lifecycle_cancellation_compensation_policy_required"
        && (await request(plane.daemonUrl, "GET", "/v1/hypervisor/work-lifecycle/status"))
          .body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"] === 0,
      `${unpolicedCancellation.status}/${unpolicedCancellation.body?.error?.code}`,
    );

    const cancellation = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/cancellation-plan",
      {
        object_ref: OBJECT,
        owner_ref: principalRef,
        requested_by_ref: principalRef,
        reason: "bounded verifier cancellation plan",
        compensation_policy_ref: "policy://ioi/work-lifecycle/compensate/v1",
      },
    );
    const cancellationPlan = cancellation.body?.cancellation_plan ?? {};
    const statusAfterCancellation = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
    );
    check(
      "the exact principal owner can durably plan child fanout without claiming child completion",
      cancellation.status === 200
        && cancellationPlan.schema_version === "ioi.cancellation-fanout-plan.v1"
        && cancellationPlan.object_ref === OBJECT
        && cancellationPlan.source_head === head3
        && cancellationPlan.requested_by_ref === principalRef
        && cancellationPlan.targets?.[0]?.relation_kind === "harness_invocation"
        && cancellationPlan.targets?.[0]?.target_ref === CHILD
        && cancellationPlan.targets?.[0]?.actions?.includes("compensate")
        && cancellationPlan.requires_completion_receipt === true
        && !JSON.stringify(cancellationPlan).includes("completed")
        && statusAfterCancellation.body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"] === 1,
      `${cancellation.status}/${cancellation.body?.error?.code}`,
    );
    check(
      "cancellation planning appends no lifecycle edge and leaves the object active",
      (await request(
        plane.daemonUrl,
        "GET",
        `/v1/hypervisor/work-lifecycle/records?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
      )).body?.record_count === 3
        && (await request(
          plane.daemonUrl,
          "GET",
          `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
        )).body?.projection?.active_phase === "active",
    );

    const compaction = await request(
      plane.daemonUrl,
      "POST",
      "/v1/hypervisor/work-lifecycle/compaction",
      { object_ref: OBJECT, owner_ref: principalRef },
    );
    const statusAfterCompaction = await request(
      plane.daemonUrl,
      "GET",
      "/v1/hypervisor/work-lifecycle/status",
    );
    check(
      "compaction returns the archive-first checkpoint bound to the exact head while retaining the hot log",
      compaction.status === 200
        && compaction.body?.through_head === head3
        && compaction.body?.archive_root?.startsWith("sha256:")
        && compaction.body?.archive_segment?.archive_root === compaction.body?.archive_root
        && compaction.body?.snapshot?.archive_root === compaction.body?.archive_root
        && compaction.body?.snapshot?.through_head === head3
        && statusAfterCompaction.body?.durable_family_object_counts?.["work-lifecycle-archive-segments"] === 1
        && statusAfterCompaction.body?.durable_family_object_counts?.["work-lifecycle-snapshots"] === 1
        && statusAfterCompaction.body?.durable_family_object_counts?.["work-lifecycle-records"] === 1,
      `${compaction.status}/${compaction.body?.error?.code}`,
    );

    await plane.stop();
    plane = await startIsolatedPlane({ dataDir });
    const replayedProjection = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/projection?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    const replayedRecords = await request(
      plane.daemonUrl,
      "GET",
      `/v1/hypervisor/work-lifecycle/records?object_ref=${encodedObject}&owner_ref=${encodedOwner}`,
    );
    const replayedStatus = await request(plane.daemonUrl, "GET", "/v1/hypervisor/work-lifecycle/status");
    check(
      "restart reconstructs the chain and its snapshot-plus-tail lifecycle state from durable truth alone",
      replayedProjection.status === 200
        && replayedProjection.body?.projection?.head === head3
        && replayedProjection.body?.projection?.active_phase === "active"
        && replayedRecords.body?.record_count === 3
        && replayedStatus.body?.durable_family_object_counts?.["work-lifecycle-cancellation-plans"] === 1
        && replayedStatus.body?.durable_family_object_counts?.["work-lifecycle-archive-segments"] === 1
        && replayedStatus.body?.durable_family_object_counts?.["work-lifecycle-snapshots"] === 1,
      `${replayedProjection.status}/${replayedRecords.status}/${replayedStatus.status}`,
    );
  }
} finally {
  if (plane) await plane.stop();
  rmSync(dataDir, { recursive: true, force: true });
}

for (const item of checks) {
  console.log(`${item.pass ? "PASS" : "FAIL"} ${item.name}${item.detail ? ` — ${item.detail}` : ""}`);
}
const failed = checks.filter((item) => !item.pass);
emitVerifierCensus({ verifierId: "m4-work-lifecycle-plane", sourceUrl: import.meta.url, results: checks });
if (failed.length) process.exitCode = 1;
else if (process.exitCode !== 2) console.log(`M04.6 work lifecycle isolated plane: PASS (${checks.length}/${checks.length})`);
