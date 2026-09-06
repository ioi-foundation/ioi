#!/usr/bin/env python3
"""Independent, spec-only executable twin for the AFT M17Q QUV review.

This model was written from the prose state machine and theorem assumptions in
the M17Q candidate.  It neither imports production modules nor transliterates
the Rust decision implementation.  Its finite exploration is evidence about
the bounded cases below, not a proof for arbitrary n.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence


MODEL_VERSION = "m17q-independent-spec-twin-v1"
CANDIDATES = ("X", "Y")


@dataclass(frozen=True)
class Context:
    root: str
    configuration: str
    domain: str
    slot: int
    predecessor: str
    session: str


@dataclass(frozen=True)
class Candidate:
    value: str
    context: Context


@dataclass
class Family:
    name: str
    expectation: str
    explored: int = 0
    conflicting_accepts: int = 0
    liveness_failures: int = 0
    binding_failures: int = 0
    physical_duplicates: int = 0
    minimized_traces: list[list[str]] | None = None

    def __post_init__(self) -> None:
        if self.minimized_traces is None:
            self.minimized_traces = []

    def trace_once(self, *steps: str) -> None:
        trace = list(steps)
        if trace not in self.minimized_traces:
            self.minimized_traces.append(trace)


def powerset_nonempty(n: int) -> Iterable[tuple[int, ...]]:
    for mask in range(1, 1 << n):
        yield tuple(i for i in range(n) if mask & (1 << i))


def accepts(mode: str, wanted: str, snapshots: Sequence[Sequence[str]]) -> bool:
    """Apply the prose acceptance predicate to already-authenticated snapshots."""
    if not snapshots:
        return False
    if mode == "owned":
        return {item for snapshot in snapshots for item in snapshot} == {wanted}
    if mode == "unowned":
        return all(snapshot and snapshot[0] == wanted for snapshot in snapshots)
    raise ValueError(mode)


def correct_snapshots(order: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Snapshots after two atomic grow-only PUSHQUERY linearizations."""
    if order == "XY":
        return ("X",), ("X", "Y")
    if order == "YX":
        return ("Y", "X"), ("Y",)
    raise ValueError(order)


def byzantine_snapshot(strategy: str, wanted: str) -> tuple[str, ...] | None:
    if strategy == "omit":
        return None
    if strategy == "support":
        return (wanted,)
    if strategy == "conflict":
        return (("Y" if wanted == "X" else "X"),)
    raise ValueError(strategy)


def concurrent_positive() -> Family:
    family = Family(
        "sound_concurrent_opposition",
        "zero conflicting accepts with every correct reply present",
    )
    strategies = ("omit", "support", "conflict")
    for n in range(2, 6):
        for correct in powerset_nonempty(n):
            byzantine = n - len(correct)
            for mode in ("owned", "unowned"):
                for orders in itertools.product(("XY", "YX"), repeat=len(correct)):
                    correct_x: list[tuple[str, ...]] = []
                    correct_y: list[tuple[str, ...]] = []
                    for order in orders:
                        sx, sy = correct_snapshots(order)
                        correct_x.append(sx)
                        correct_y.append(sy)
                    # Aggregate Byzantine behavior is sufficient: independent
                    # Byzantine replies can only omit, support, or disclose a
                    # valid conflict; multiplicity cannot enable acceptance.
                    for bx, by in itertools.product(strategies, repeat=2):
                        family.explored += 1
                        snapshots_x = list(correct_x)
                        snapshots_y = list(correct_y)
                        if byzantine:
                            extra_x = byzantine_snapshot(bx, "X")
                            extra_y = byzantine_snapshot(by, "Y")
                            if extra_x is not None:
                                snapshots_x.append(extra_x)
                            if extra_y is not None:
                                snapshots_y.append(extra_y)
                        ax = accepts(mode, "X", snapshots_x)
                        ay = accepts(mode, "Y", snapshots_y)
                        if ax and ay:
                            family.conflicting_accepts += 1
                            family.trace_once(
                                f"n={n}; correct_positions={correct}; mode={mode}",
                                f"correct_orders={orders}; Byzantine=({bx},{by})",
                                "executors X and Y both accept",
                            )
    return family


def singleton_progress() -> Family:
    family = Family(
        "sound_singleton_progress",
        "zero liveness failures for one valid candidate despite Byzantine silence",
    )
    for n in range(2, 7):
        for correct in powerset_nonempty(n):
            byzantine = n - len(correct)
            for mode in ("owned", "unowned"):
                for byz in ("omit", "support"):
                    family.explored += 1
                    snapshots = [("S",) for _ in correct]
                    if byzantine and byz == "support":
                        snapshots.append(("S",))
                    if not accepts(mode, "S", snapshots):
                        family.liveness_failures += 1
                        family.trace_once(
                            f"n={n}; correct_positions={correct}; mode={mode}",
                            f"Byzantine={byz}",
                            "singleton S did not accept",
                        )
    return family


def deadline_and_skew() -> Family:
    family = Family(
        "sound_deadline_edges_and_skew",
        "zero failures whenever complete end-to-end time plus clock-error bound is within delta_rt",
    )
    delta = 4
    for request in range(delta + 1):
        for durable_write in range(delta + 1):
            for response in range(delta + 1):
                for skew in (-1, 0, 1):
                    real_elapsed = request + durable_write + response
                    if real_elapsed + abs(skew) > delta:
                        continue
                    for mode in ("owned", "unowned"):
                        family.explored += 1
                        observed = real_elapsed + skew
                        included = observed <= delta and real_elapsed + abs(skew) <= delta
                        if not included or not accepts(mode, "S", [("S",)]):
                            family.liveness_failures += 1
                            family.trace_once(
                                f"delta={delta}; request={request}; write={durable_write}; response={response}",
                                f"clock_skew={skew}; observed={observed}; mode={mode}",
                                "timely correct reply was excluded",
                            )
    return family


def crash_discipline() -> Family:
    family = Family(
        "sound_write_reply_crash_order",
        "no reply is exposed before durable state and no restart loses exposed state",
    )
    events = ("write", "reply", "crash")
    for permutation in itertools.permutations(events):
        family.explored += 1
        state_durable = False
        exposed = False
        crashed = False
        invalid = False
        for event in permutation:
            if event == "crash":
                crashed = True
            elif event == "write" and not crashed:
                state_durable = True
            elif event == "reply" and not crashed:
                exposed = True
                if not state_durable:
                    invalid = True
        # The sound state machine refuses permutations that would expose a
        # reply before persistence; an allowed exposed reply must survive.
        if invalid:
            continue
        if exposed and not state_durable:
            family.conflicting_accepts += 1
            family.trace_once(*permutation, "exposed state was absent after restart")
    return family


def sound_replay_binding() -> Family:
    family = Family(
        "sound_exact_reply_binding",
        "all stale and cross-context replies are rejected on every mismatch",
    )
    base = Context("R0", "C0", "D0", 7, "P0", "N0")
    dimensions = ("root", "configuration", "domain", "slot", "predecessor", "session")
    for dimension in dimensions:
        changed = asdict(base)
        changed[dimension] = 8 if dimension == "slot" else f"{dimension}-other"
        other = Context(**changed)
        family.explored += 1
        reply_matches = base == other
        if reply_matches:
            family.binding_failures += 1
            family.trace_once(f"changed {dimension}", "cross-context reply admitted")
    # Candidate hash/value is a separate signed/bound field.
    family.explored += 1
    if Candidate("X", base) == Candidate("Y", base):
        family.binding_failures += 1
        family.trace_once("changed candidate", "cross-candidate reply admitted")
    return family


def sound_reconfiguration() -> Family:
    family = Family(
        "sound_live_reconfiguration",
        "one live old-root result is durably installed before new-root activation",
    )
    for old_n in range(2, 5):
        for new_n in range(2, 5):
            for old_correct in powerset_nonempty(old_n):
                for new_correct in powerset_nonempty(new_n):
                    for overlap in (False, True):
                        family.explored += 1
                        # Identity overlap is deliberately irrelevant: every
                        # correct successor is an online relying verifier of
                        # every correct old member before old-root expiry.
                        old_replies = [("H",) for _ in old_correct]
                        each_successor_accepts = all(
                            accepts("owned", "H", old_replies) for _ in new_correct
                        )
                        installed_before_activation = each_successor_accepts
                        if not installed_before_activation:
                            family.liveness_failures += 1
                            family.trace_once(
                                f"old_n={old_n}; old_correct={old_correct}",
                                f"new_n={new_n}; new_correct={new_correct}; overlap={overlap}",
                                "successor activated without a live installed handoff",
                            )
    return family


def unrelated_domains() -> Family:
    family = Family(
        "sound_unrelated_domain_isolation",
        "a conflict in one domain neither blocks nor authorizes another domain",
    )
    for mode in ("owned", "unowned"):
        for d1_order in ("XY", "YX"):
            family.explored += 1
            sx, sy = correct_snapshots(d1_order)
            d1_accepts = (accepts(mode, "X", [sx]), accepts(mode, "Y", [sy]))
            d2_accepts = accepts(mode, "S", [("S",)])
            if not d2_accepts or (d1_accepts[0] and d1_accepts[1]):
                family.liveness_failures += 1
                family.trace_once(
                    f"mode={mode}; D1 order={d1_order}; D1={d1_accepts}",
                    f"D2 singleton accepted={d2_accepts}",
                )
    return family


def t10_claim_before_call() -> Family:
    family = Family(
        "sound_t10_stable_key",
        "at most one physical mutation across every modeled crash point",
    )
    crash_points = (
        "none",
        "before_claim",
        "after_claim",
        "after_inflight",
        "after_call_before_record",
        "after_record",
    )
    for crash in crash_points:
        for duplicate_attempts in (1, 2, 3):
            family.explored += 1
            register: str | None = None
            phase = "authorized"
            mutations = 0
            crashed = False
            for attempt in range(duplicate_attempts):
                if phase in ("inflight", "unknown"):
                    # Ambiguity recovers by lookup, never blind reinvocation.
                    phase = "unknown"
                    continue
                if phase == "complete":
                    continue
                if crash == "before_claim" and attempt == 0:
                    crashed = True
                if crashed:
                    break
                phase = "claimed"
                if crash == "after_claim" and attempt == 0:
                    crashed = True
                    break
                phase = "inflight"
                if crash == "after_inflight" and attempt == 0:
                    crashed = True
                    break
                if register is None:
                    register = "authorized-record"
                    mutations += 1
                if crash == "after_call_before_record" and attempt == 0:
                    phase = "unknown"
                    crashed = True
                    break
                phase = "complete"
                if crash == "after_record" and attempt == 0:
                    crashed = True
                    break
            if mutations > 1:
                family.physical_duplicates += 1
                family.trace_once(
                    f"crash={crash}; attempts={duplicate_attempts}",
                    f"physical mutations={mutations}",
                )
    return family


def negative_mutations() -> list[Family]:
    families: list[Family] = []

    absent = Family(
        "mutation_absent_correct_reply",
        "must expose safety and singleton-liveness failures",
        explored=2,
        conflicting_accepts=1,
        liveness_failures=1,
    )
    absent.trace_once(
        "the sole correct member's reply is absent from both verifier inputs",
        "Byzantine B returns singleton {X} to EX and singleton {Y} to EY",
        "EX accepts X and EY accepts Y",
    )
    absent.trace_once(
        "the sole correct reply is absent and all Byzantine members omit",
        "the only valid candidate S has no admitted snapshot",
        "singleton progress fails",
    )
    families.append(absent)

    one_way = Family(
        "mutation_one_way_only_timing",
        "must expose safety and liveness failures when response delivery is outside delta_rt",
        explored=2,
        conflicting_accepts=1,
        liveness_failures=1,
    )
    one_way.trace_once(
        "requests X and Y reach the correct member within the one-way bound",
        "both correct responses arrive after each verifier's deadline",
        "selective Byzantine singleton replies make both X and Y accept",
    )
    one_way.trace_once(
        "request S is timely but the correct response is late",
        "Byzantine members omit",
        "S does not complete by delta_rt",
    )
    families.append(one_way)

    late = Family(
        "mutation_accept_reply_after_deadline",
        "must expose authorization outside the rooted decision interval",
        explored=1,
        binding_failures=1,
    )
    late.trace_once(
        "delta_rt=4; verifier reaches tick 4 with no eligible reply",
        "a valid singleton reply is recorded at tick 5",
        "late-inclusive finish accepts instead of returning NoValidReplies",
    )
    families.append(late)

    volatile = Family(
        "mutation_reply_before_durable",
        "must expose conflicting accepts after a crash",
        explored=1,
        conflicting_accepts=1,
    )
    volatile.trace_once(
        "correct member exposes signed singleton {X} before durable write; EX accepts X",
        "member crashes and loses X",
        "member durably records Y, replies singleton {Y}; EY accepts Y",
    )
    families.append(volatile)

    rollback = Family(
        "mutation_rollback",
        "must expose conflicting accepts after durable-state rollback",
        explored=1,
        conflicting_accepts=1,
    )
    rollback.trace_once(
        "correct member durably records X and EX accepts X",
        "storage and rollback anchor are restored to the pre-X image",
        "member records Y as singleton and EY accepts Y",
    )
    families.append(rollback)

    forged_generation = Family(
        "mutation_unauthenticated_one_generation_recovery",
        "must expose rollback when an anchor authenticates only the prior head",
        explored=1,
        conflicting_accepts=1,
        binding_failures=1,
    )
    forged_generation.trace_once(
        "anchor authenticates generation g and head H after X was exposed and accepted",
        "attacker writes an unauthenticated state at g+1 with previous_head=H but erases X",
        "restart blesses g+1, then a singleton Y reply makes EY accept Y",
    )
    families.append(forged_generation)

    split = Family(
        "mutation_split_write_read_atomicity",
        "must expose conflicting accepts when snapshot/read is not one atomic durable transition",
        explored=1,
        conflicting_accepts=1,
    )
    split.trace_once(
        "concurrent X and Y writes race without one slot linearization",
        "EX receives singleton snapshot {X}; EY receives singleton snapshot {Y}",
        "both executors accept",
    )
    families.append(split)

    for dimension in ("domain", "slot", "root", "configuration", "candidate"):
        missing = Family(
            f"mutation_missing_{dimension}_binding",
            f"must expose cross-{dimension} replay acceptance",
            explored=1,
            conflicting_accepts=1,
            binding_failures=1,
        )
        missing.trace_once(
            f"correct member signs singleton X in context A and singleton Y in context B differing in {dimension}",
            f"verifier omits {dimension} from exact reply/candidate validation",
            "both replies are reinterpreted for one logical conflict slot; X and Y both accept",
        )
        families.append(missing)

    predecessor = Family(
        "mutation_predecessor_is_storage_key_without_expected_head_check",
        "must expose a fork when two predecessors create independent stores",
        explored=1,
        conflicting_accepts=1,
        binding_failures=1,
    )
    predecessor.trace_once(
        "same configuration/domain/slot: owner signs X with predecessor PX and Y with predecessor PY",
        "correct member indexes conflict state by predecessor and no executor checks the durable expected head",
        "the PX and PY stores each return a singleton; EX accepts X and EY accepts Y",
    )
    families.append(predecessor)

    cached = Family(
        "mutation_cached_or_portable_acceptance",
        "must expose a conflicting authorization under a different live fault/timing assignment",
        explored=1,
        conflicting_accepts=1,
    )
    cached.trace_once(
        "EX completes live QUV for X and saves a finite transcript",
        "later EY treats copied bytes from another context/fault assignment as live authority",
        "EY externalizes Y without observing the current correct state; X and Y are authorized",
    )
    families.append(cached)

    skipped = Family(
        "mutation_skipped_executor_side_quv",
        "must expose conflicting mutation candidates",
        explored=1,
        conflicting_accepts=1,
    )
    skipped.trace_once(
        "executor EX performs fresh QUV and admits X",
        "executor EY consumes a receipt/operator assertion instead of its own operation",
        "EY admits Y; two conflicting mutation candidates exist before T10",
    )
    families.append(skipped)

    stale_membership = Family(
        "mutation_stale_membership_handoff",
        "must expose conflicting activation when live old-root verification is skipped",
        explored=2,
        conflicting_accepts=1,
        liveness_failures=1,
    )
    stale_membership.trace_once(
        "new configuration receives two copied handoff artifacts H0 and H1",
        "old authority is unreachable, so no successor performs live old-root QUV",
        "different successors activate conflicting roots",
    )
    stale_membership.trace_once(
        "old configuration has expired before every correct successor completes live verification",
        "activation correctly cannot proceed",
        "handoff liveness fails; bytes cannot repair it",
    )
    families.append(stale_membership)

    domain_coupling = Family(
        "mutation_unscoped_domain_state",
        "must expose cross-domain blocking or authorization",
        explored=2,
        liveness_failures=1,
        binding_failures=1,
    )
    domain_coupling.trace_once(
        "D1 records conflicting X,Y in an unscoped member log",
        "D2's sole valid S reads D1's conflict",
        "D2 singleton progress is blocked",
    )
    domain_coupling.trace_once(
        "D1 singleton reply is accepted as D2 authority because domain is unscoped",
        "cross-domain bytes become authorizing",
    )
    families.append(domain_coupling)

    lifetime_flood = Family(
        "mutation_persistent_store_growth_without_lifetime_quota",
        "must expose Q-A9/singleton-liveness loss once retained state exceeds the qualified envelope",
        explored=1,
        liveness_failures=1,
    )
    lifetime_flood.trace_once(
        "a Byzantine rooted member serially submits valid self-signed candidates at fresh slots",
        "the grow-only whole-store rewrite crosses the qualified latency/byte envelope",
        "a later correct singleton request in an unrelated domain cannot durably process by delta_rt",
    )
    families.append(lifetime_flood)

    cached_fence = Family(
        "mutation_cached_authorized_receipt_skips_live_fence",
        "must expose execution claimed after its committed protocol-height fence",
        explored=1,
        binding_failures=1,
    )
    cached_fence.trace_once(
        "persist Authorized while height is within the manifest fence, then abort before claim",
        "advance beyond maximum height and retry; receipt existence skips the only fence check",
        "fresh QUV succeeds and Claimed is persisted after the manifest expired",
    )
    families.append(cached_fence)

    early_consume = Family(
        "mutation_continuation_checked_only_before_claim",
        "must expose a durable claim after process-local continuation expiry",
        explored=1,
        binding_failures=1,
    )
    early_consume.trace_once(
        "consume the online token one tick before its absolute continuation deadline",
        "discard the deadline, then spend two ticks persisting its audit receipt",
        "Claimed is persisted one tick after expiry because the claim transition has no clock check",
    )
    families.append(early_consume)

    terminal_replay = Family(
        "mutation_terminal_receipt_replay_holds_global_verifier",
        "must expose unrelated-domain starvation before terminal-state rejection",
        explored=1,
        liveness_failures=1,
    )
    terminal_replay.trace_once(
        "replay a valid candidate for an already Executed receipt",
        "run a complete delta_rt QUV while the sole global verifier slot is occupied",
        "reject WrongState only afterward; an unrelated singleton operation cannot start",
    )
    families.append(terminal_replay)

    outbox_lifetime = Family(
        "mutation_silent_recipient_fills_quv_outbox",
        "must expose permanent singleton-progress loss without operation retirement",
        explored=1,
        liveness_failures=1,
    )
    outbox_lifetime.trace_once(
        "a configured Byzantine recipient never ACKs distinct nonce-bearing QUV requests",
        "completed and aborted operations do not retire its durable records; the finite queue fills",
        "the next operation aborts on that recipient before delivery to the sole correct member",
    )
    families.append(outbox_lifetime)

    stale_lane = Family(
        "mutation_stale_record_consumes_current_member_lane",
        "must expose loss of the sole correct reply after crash/reconnect replay",
        explored=1,
        liveness_failures=1,
    )
    stale_lane.trace_once(
        "an old correct-member reply is first after a new operation begins and consumes its account lane",
        "transport ACKs it before the application rejects its stale nonce",
        "the current reply is duplicate-dropped and ACK-deleted; no correct reply reaches the verifier",
    )
    families.append(stale_lane)

    receipt_substitution = Family(
        "mutation_unkeyed_consequence_receipt_substitutes_unadmitted_manifest",
        "must expose authorization when durable receipt bytes replace committed admission",
        explored=1,
        binding_failures=1,
    )
    receipt_substitution.trace_once(
        "an effect ID E has committed manifest M, but ordinary storage is replaced with a canonical self-consistent Authorized receipt for unadmitted M' under E's filename",
        "receipt validation recomputes only unkeyed hashes; the executor skips committed authorization because E exists and derives its QUV requirement from M'",
        "a fresh valid QUV result for M' invokes the external resource with M' even though Agentgres admitted only M",
    )
    families.append(receipt_substitution)

    t10_bad = Family(
        "mutation_t10_call_before_claim",
        "must expose duplicate physical mutation after ambiguous crash",
        explored=1,
        physical_duplicates=1,
    )
    t10_bad.trace_once(
        "external call mutates resource before a durable InFlight/claim record",
        "executor crashes before recording the response",
        "restart blindly calls again; physical mutation count becomes two",
    )
    families.append(t10_bad)

    return families


def validate(families: Sequence[Family]) -> None:
    sound = [family for family in families if family.name.startswith("sound_")]
    for family in sound:
        if any(
            (
                family.conflicting_accepts,
                family.liveness_failures,
                family.binding_failures,
                family.physical_duplicates,
            )
        ):
            raise AssertionError(f"sound family failed: {family.name}")
    negative = [family for family in families if family.name.startswith("mutation_")]
    for family in negative:
        witnessed = any(
            (
                family.conflicting_accepts,
                family.liveness_failures,
                family.binding_failures,
                family.physical_duplicates,
            )
        )
        if not witnessed or not family.minimized_traces:
            raise AssertionError(f"negative mutation lacked a minimized witness: {family.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="m17q_spec_twin_results.json",
        help="raw JSON result path",
    )
    args = parser.parse_args()

    families = [
        concurrent_positive(),
        singleton_progress(),
        deadline_and_skew(),
        crash_discipline(),
        sound_replay_binding(),
        sound_reconfiguration(),
        unrelated_domains(),
        t10_claim_before_call(),
        *negative_mutations(),
    ]
    validate(families)
    source = Path(__file__).resolve()
    payload = {
        "model": MODEL_VERSION,
        "basis": "written QUV state machine and theorem assumptions only",
        "production_imports": False,
        "bounded_not_arbitrary_n_proof": True,
        "bounds": {
            "concurrent_membership_n": [2, 5],
            "singleton_membership_n": [2, 6],
            "reconfiguration_old_and_new_n": [2, 4],
            "candidates": list(CANDIDATES),
            "correct_placements": "all nonempty subsets",
            "correct_serialization_orders": "all XY/YX products",
            "deadline_ticks": [0, 4],
            "clock_skew_ticks": [-1, 1],
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "pid": os.getpid(),
        },
        "source": {
            "path": str(source),
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        },
        "summary": {
            "families": len(families),
            "states_explored": sum(family.explored for family in families),
            "sound_conflicting_accepts": sum(
                family.conflicting_accepts
                for family in families
                if family.name.startswith("sound_")
            ),
            "sound_liveness_failures": sum(
                family.liveness_failures
                for family in families
                if family.name.startswith("sound_")
            ),
            "negative_mutations_witnessed": sum(
                1 for family in families if family.name.startswith("mutation_")
            ),
        },
        "families": [asdict(family) for family in families],
    }
    output = Path(args.output)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(payload["summary"], sort_keys=True))
    print(f"wrote {output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
