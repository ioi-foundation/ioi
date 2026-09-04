#!/usr/bin/env python3
"""R4 explicit-time and multi-correct bounded model for the AFT QUV candidate.

This model is evidence for M12b/M13Q, not an arbitrary-n proof.  It exhausts
the n=2, one-correct-member, two-verifier state space described below and
requires each deliberately broken mutation to recover a conflicting-accept
trace.

Time is discrete.  Operation V_j starts at t_j.  Its request delay,
admission-to-durable-linearization delay, and response delay are each in
[0, D].  A verifier clock may run fast by e in [0, E].  The known end-to-end
bound is DELTA_RT = 3*D + E, so the correct reply arrives no later than the
verifier deadline in sync mode.

Modes:
  sync             complete round-trip bound and atomic durable-before-reply
  oneway           deadline incorrectly covers only one-way delay
  replay_unbound   a genuine correct reply from another slot/config is reused
  replay_same_slot a stale monotone reply from this slot is reused
  volatile         reply-before-durable processing, with optional crash

Authority modes:
  honest           owner signs only X
  dishonest        owner signs both X and Y
  unowned          separately signed X and Y; correct member stores first

The Byzantine coalition is collapsed into one response source.  This is a
safety over-approximation for the modeled acceptance rule because additional
Byzantine members can add candidate evidence or remain silent, but cannot
remove the correct member's timely response in sync mode.

The model also exhausts an ordering abstraction with two and three correct
members.  The sound mode includes every correct reply for every operation.  A
split-witness mutation permits a different timely correct member per operation
and must recover the cross-member opposite-order conflict.
"""

import itertools
import json
import sys


D, E = 1, 1
DELTA_RT = 3 * D + E
VALUES = ("X", "Y")


def signed(authority):
    return ("X",) if authority == "honest" else VALUES


def simulate(
    authority,
    mode,
    initial_correct,
    initial_byzantine,
    candidates,
    starts,
    delays,
    skews,
    byzantine_replies,
    tie_order,
    crash_tick,
    replay_choices,
):
    """Return the accepted value for each accepting verifier operation."""
    count = len(candidates)
    correct_knowledge = list(initial_correct)
    pending_durable = []
    byzantine_knowledge = set(initial_byzantine)
    emitted = {}
    correct_reply_log = []

    # In the sound mode, delay[1] is the bounded interval from request arrival
    # to the operation's atomic durable linearization and snapshot.  Ties are
    # adversarially ordered.  In volatile mode it is instead the gap between
    # the premature reply and later durability.
    if mode == "volatile":
        events = sorted(
            ((starts[j] + delays[j][0], j) for j in range(count)),
            key=lambda item: (item[0], tie_order.index(item[1])),
        )
    else:
        events = sorted(
            (
                (starts[j] + delays[j][0] + delays[j][1], j)
                for j in range(count)
            ),
            key=lambda item: (item[0], tie_order.index(item[1])),
        )

    event_index = 0
    max_tick = max(starts) + DELTA_RT + 2
    for tick in range(max_tick + 1):
        if mode == "volatile" and crash_tick is not None and tick == crash_tick:
            pending_durable = []

        for durable_tick, value in list(pending_durable):
            if durable_tick <= tick:
                if value not in correct_knowledge:
                    correct_knowledge.append(value)
                pending_durable.remove((durable_tick, value))

        while event_index < len(events) and events[event_index][0] == tick:
            _, operation = events[event_index]
            event_index += 1
            value = candidates[operation]
            if mode == "volatile":
                snapshot = tuple(correct_knowledge) + (
                    (value,) if value not in correct_knowledge else ()
                )
                pending_durable.append((tick + delays[operation][1], value))
                emitted[operation] = (tick, snapshot)
            else:
                if value not in correct_knowledge:
                    correct_knowledge.append(value)
                emitted[operation] = (tick, tuple(correct_knowledge))
            correct_reply_log.append(emitted[operation][1])

    accepted = {}
    for operation in range(count):
        deadline = starts[operation] + (
            D if mode == "oneway" else DELTA_RT
        ) - skews[operation]
        correct_reply = None
        if operation in emitted:
            emit_tick, snapshot = emitted[operation]
            if emit_tick + delays[operation][2] <= deadline:
                correct_reply = snapshot

        if (
            mode == "replay_same_slot"
            and replay_choices[operation] is not None
            and replay_choices[operation] < len(correct_reply_log)
        ):
            correct_reply = correct_reply_log[replay_choices[operation]]
        if mode == "replay_unbound" and replay_choices[operation] is not None:
            correct_reply = (VALUES[replay_choices[operation]],)

        byzantine_content = byzantine_replies[operation]
        candidate = candidates[operation]
        if authority == "unowned":
            firsts = []
            if correct_reply:
                firsts.append(correct_reply[0])
            if byzantine_content:
                firsts.append(byzantine_content[0])
            if correct_reply is None and not byzantine_content:
                continue
            if all(first == candidate for first in firsts):
                accepted[operation] = candidate
        else:
            visible = {candidate}
            if correct_reply is not None:
                visible |= set(correct_reply)
            visible |= set(byzantine_content)
            if correct_reply is None and not byzantine_content:
                continue
            if visible == {candidate}:
                accepted[operation] = candidate
    return accepted


def run(authority, mode, verifier_count=2):
    valid = VALUES if authority == "unowned" else signed(authority)
    cases = 0
    conflicts = 0
    first_counterexample = None
    delay_options = list(itertools.product(range(D + 1), repeat=3))

    initial_correct_options = itertools.chain.from_iterable(
        itertools.permutations(selection)
        for size in range(len(valid) + 1)
        for selection in itertools.combinations(valid, size)
    )
    for initial_correct in initial_correct_options:
        for byzantine_mask in range(1 << len(valid)):
            initial_byzantine = tuple(
                value
                for index, value in enumerate(valid)
                if byzantine_mask >> index & 1
            )
            pool = set(initial_correct) | set(initial_byzantine)
            if not pool:
                continue
            for candidates in itertools.product(sorted(pool), repeat=verifier_count):
                replay_mode = mode.startswith("replay")
                starts_options = (
                    [(0,) * verifier_count]
                    if replay_mode
                    else itertools.product(range(2), repeat=verifier_count)
                )
                for starts in starts_options:
                    for delays in itertools.product(
                        delay_options, repeat=verifier_count
                    ):
                        skew_options = (
                            [(0,) * verifier_count]
                            if replay_mode
                            else itertools.product(range(E + 1), repeat=verifier_count)
                        )
                        for skews in skew_options:
                            for tie_order in itertools.permutations(
                                range(verifier_count)
                            ):
                                byzantine_holdings = set(initial_byzantine) | set(
                                    candidates
                                )
                                byzantine_options = [()] + [
                                    tuple(permutation)
                                    for size in range(1, len(byzantine_holdings) + 1)
                                    for permutation in itertools.permutations(
                                        sorted(byzantine_holdings), size
                                    )
                                ]
                                for byzantine_replies in itertools.product(
                                    byzantine_options, repeat=verifier_count
                                ):
                                    crashes = (
                                        [None]
                                        if mode != "volatile"
                                        else [None] + list(range(5))
                                    )
                                    replay_options = (
                                        list(
                                            itertools.product(
                                                [None, 0, 1], repeat=verifier_count
                                            )
                                        )
                                        if replay_mode
                                        else [(None,) * verifier_count]
                                    )
                                    for crash_tick in crashes:
                                        for replay_choices in replay_options:
                                            cases += 1
                                            accepted = simulate(
                                                authority,
                                                mode,
                                                initial_correct,
                                                initial_byzantine,
                                                candidates,
                                                starts,
                                                delays,
                                                skews,
                                                byzantine_replies,
                                                tie_order,
                                                crash_tick,
                                                replay_choices,
                                            )
                                            if len(set(accepted.values())) > 1:
                                                conflicts += 1
                                                if first_counterexample is None:
                                                    first_counterexample = {
                                                        "initial_correct": initial_correct,
                                                        "initial_byzantine": initial_byzantine,
                                                        "candidates": candidates,
                                                        "starts": starts,
                                                        "delays": delays,
                                                        "skews": skews,
                                                        "tie_order": tie_order,
                                                        "byzantine_replies": byzantine_replies,
                                                        "crash_tick": crash_tick,
                                                        "replay_choices": replay_choices,
                                                        "accepted": accepted,
                                                    }
    return {
        "authority": authority,
        "mode": mode,
        "n": 2,
        "correct_members": 1,
        "verifiers": verifier_count,
        "cases": cases,
        "conflicts": conflicts,
        "first_counterexample": first_counterexample,
    }


def run_solo_liveness(authority, verifier_count=2):
    """Exhaust exactly-one-candidate schedules, including a fresh correct state."""
    cases = 0
    failures = 0
    first_failure = None
    delay_options = list(itertools.product(range(D + 1), repeat=3))
    candidates = ("X",) * verifier_count
    for initial_correct in [(), ("X",)]:
        for initial_byzantine in [(), ("X",)]:
            for starts in itertools.product(range(2), repeat=verifier_count):
                for delays in itertools.product(delay_options, repeat=verifier_count):
                    for skews in itertools.product(range(E + 1), repeat=verifier_count):
                        for tie_order in itertools.permutations(range(verifier_count)):
                            for byzantine_replies in itertools.product(
                                [(), ("X",)], repeat=verifier_count
                            ):
                                cases += 1
                                accepted = simulate(
                                    authority,
                                    "sync",
                                    initial_correct,
                                    initial_byzantine,
                                    candidates,
                                    starts,
                                    delays,
                                    skews,
                                    byzantine_replies,
                                    tie_order,
                                    None,
                                    (None,) * verifier_count,
                                )
                                if len(accepted) != verifier_count:
                                    failures += 1
                                    if first_failure is None:
                                        first_failure = {
                                            "initial_correct": initial_correct,
                                            "initial_byzantine": initial_byzantine,
                                            "starts": starts,
                                            "delays": delays,
                                            "skews": skews,
                                            "tie_order": tie_order,
                                            "byzantine_replies": byzantine_replies,
                                            "accepted": accepted,
                                        }
    return {
        "authority": authority,
        "mode": "sync_exactly_one_candidate",
        "n": 2,
        "correct_members": 1,
        "verifiers": verifier_count,
        "cases": cases,
        "failures": failures,
        "includes_fresh_correct_state": True,
        "first_failure": first_failure,
    }


def snapshots_for_order(candidates, order):
    knowledge = []
    snapshots = {}
    for operation in order:
        candidate = candidates[operation]
        if candidate not in knowledge:
            knowledge.append(candidate)
        snapshots[operation] = tuple(knowledge)
    return snapshots


def run_multi_correct(authority, correct_members, split_witness=False):
    """Enumerate independent correct-member serialization orders.

    The sound case delivers every correct member's operation-bound reply.  The
    mutation delivers one correct reply per operation, allowing the witness to
    differ and exposing why the same-member-across-operations interpretation is
    insufficient.
    """
    candidates = VALUES
    operations = tuple(range(len(candidates)))
    cases = 0
    conflicts = 0
    first_counterexample = None
    order_options = tuple(itertools.permutations(operations))
    for orders in itertools.product(order_options, repeat=correct_members):
        snapshots = [
            snapshots_for_order(candidates, order) for order in orders
        ]
        witness_options = (
            itertools.product(range(correct_members), repeat=len(operations))
            if split_witness
            else [(None,) * len(operations)]
        )
        for witnesses in witness_options:
            cases += 1
            accepted = {}
            for operation, candidate in enumerate(candidates):
                selected = (
                    [snapshots[witnesses[operation]][operation]]
                    if split_witness
                    else [member[operation] for member in snapshots]
                )
                if authority == "unowned":
                    if all(snapshot[0] == candidate for snapshot in selected):
                        accepted[operation] = candidate
                else:
                    visible = set().union(*(set(snapshot) for snapshot in selected))
                    if visible == {candidate}:
                        accepted[operation] = candidate
            if len(set(accepted.values())) > 1:
                conflicts += 1
                if first_counterexample is None:
                    first_counterexample = {
                        "orders": orders,
                        "witnesses": witnesses,
                        "snapshots": snapshots,
                        "accepted": accepted,
                    }
    return {
        "authority": authority,
        "mode": "split_witness_mutation" if split_witness else "all_correct_timely",
        "correct_members": correct_members,
        "operations": len(operations),
        "cases": cases,
        "conflicts": conflicts,
        "first_counterexample": first_counterexample,
    }


def main():
    plan = [
        ("honest", "sync"),
        ("dishonest", "sync"),
        ("unowned", "sync"),
        ("dishonest", "oneway"),
        ("dishonest", "volatile"),
        ("unowned", "oneway"),
        ("dishonest", "replay_unbound"),
        ("dishonest", "replay_same_slot"),
    ]
    rows = [run(authority, mode) for authority, mode in plan]
    solo_liveness_rows = [
        run_solo_liveness(authority)
        for authority in ("honest", "dishonest", "unowned")
    ]
    multi_correct_rows = [
        run_multi_correct(authority, correct_members)
        for correct_members in (2, 3)
        for authority in ("dishonest", "unowned")
    ] + [
        run_multi_correct(authority, 2, split_witness=True)
        for authority in ("dishonest", "unowned")
    ]
    for row in rows:
        print(
            "%-9s %-16s cases=%8d conflicts=%6d"
            % (
                row["authority"],
                row["mode"],
                row["cases"],
                row["conflicts"],
            )
        )
        if row["first_counterexample"]:
            print("  first:", row["first_counterexample"])
    for row in solo_liveness_rows:
        print(
            "%-9s %-28s cases=%8d failures=%6d"
            % (row["authority"], row["mode"], row["cases"], row["failures"])
        )
    for row in multi_correct_rows:
        print(
            "%-9s %-28s correct=%d cases=%4d conflicts=%4d"
            % (
                row["authority"],
                row["mode"],
                row["correct_members"],
                row["cases"],
                row["conflicts"],
            )
        )
        if row["first_counterexample"]:
            print("  first:", row["first_counterexample"])

    summary = {
        "sync_safe_all_authorities": all(
            row["conflicts"] == 0 for row in rows if row["mode"] == "sync"
        ),
        "universal_solo_liveness": all(
            row["failures"] == 0 for row in solo_liveness_rows
        ),
        "all_correct_timely_multi_correct_safe": all(
            row["conflicts"] == 0
            for row in multi_correct_rows
            if row["mode"] == "all_correct_timely"
        ),
        "split_witness_mutation_breaks": all(
            row["conflicts"] > 0
            for row in multi_correct_rows
            if row["mode"] == "split_witness_mutation"
        ),
        "oneway_bound_mutation_breaks": all(
            row["conflicts"] > 0 for row in rows if row["mode"] == "oneway"
        ),
        "unbound_reply_replay_mutation_breaks": all(
            row["conflicts"] > 0
            for row in rows
            if row["mode"] == "replay_unbound"
        ),
        "same_slot_stale_replay_is_harmless": all(
            row["conflicts"] == 0
            for row in rows
            if row["mode"] == "replay_same_slot"
        ),
        "reply_before_durable_mutation_breaks": all(
            row["conflicts"] > 0 for row in rows if row["mode"] == "volatile"
        ),
    }
    result = {
        "model": "aft_quv_explicit_time_r4",
        "bounded_scope": "explicit time: n=2/H=1/two operations; serialization abstraction: H=2..3/two operations",
        "D": D,
        "E": E,
        "DELTA_RT": DELTA_RT,
        "rows": rows,
        "solo_liveness_rows": solo_liveness_rows,
        "multi_correct_rows": multi_correct_rows,
        "summary": summary,
    }
    print(json.dumps(summary, indent=2))
    with open("quv_timed_results_r4.json", "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    success = all(summary.values())
    print("ALL EXPECTATIONS MET" if success else "EXPECTATION FAILURE")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
