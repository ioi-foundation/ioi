#!/usr/bin/env python3
"""Explicit-time bounded model for the AFT QUV candidate.

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
    solo_failures = 0
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
                                            if (
                                                authority == "honest"
                                                and "X" in initial_correct
                                                and all(
                                                    value == "X"
                                                    for value in candidates
                                                )
                                                and mode == "sync"
                                                and len(accepted) != verifier_count
                                            ):
                                                solo_failures += 1

    return {
        "authority": authority,
        "mode": mode,
        "n": 2,
        "correct_members": 1,
        "verifiers": verifier_count,
        "cases": cases,
        "conflicts": conflicts,
        "universal_solo_liveness_failures": solo_failures,
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
    for row in rows:
        print(
            "%-9s %-16s cases=%8d conflicts=%6d solo_fail=%d"
            % (
                row["authority"],
                row["mode"],
                row["cases"],
                row["conflicts"],
                row["universal_solo_liveness_failures"],
            )
        )
        if row["first_counterexample"]:
            print("  first:", row["first_counterexample"])

    summary = {
        "sync_safe_all_authorities": all(
            row["conflicts"] == 0 for row in rows if row["mode"] == "sync"
        ),
        "universal_solo_liveness": all(
            row["universal_solo_liveness_failures"] == 0
            for row in rows
            if row["mode"] == "sync"
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
        "model": "aft_quv_explicit_time_r3",
        "bounded_scope": "n=2, one correct member, two verifier operations",
        "D": D,
        "E": E,
        "DELTA_RT": DELTA_RT,
        "rows": rows,
        "summary": summary,
    }
    print(json.dumps(summary, indent=2))
    with open("quv_timed_results_r3.json", "w", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    success = all(summary.values())
    print("ALL EXPECTATIONS MET" if success else "EXPECTATION FAILURE")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
