use std::collections::BTreeSet;

type MemberSet = BTreeSet<usize>;

fn combinations(
    member_count: usize,
    choose: usize,
    start: usize,
    current: &mut Vec<usize>,
    output: &mut Vec<MemberSet>,
) {
    if current.len() == choose {
        output.push(current.iter().copied().collect());
        return;
    }
    for member in start..member_count {
        current.push(member);
        combinations(member_count, choose, member + 1, current, output);
        current.pop();
    }
}

fn all_sets_of_size(member_count: usize, choose: usize) -> Vec<MemberSet> {
    let mut output = Vec::new();
    let mut current = Vec::new();
    combinations(member_count, choose, 0, &mut current, &mut output);
    output
}

fn quorum_sets(member_count: usize, threshold: usize) -> Vec<MemberSet> {
    let mut quorums = Vec::new();
    for choose in threshold..=member_count {
        quorums.extend(all_sets_of_size(member_count, choose));
    }
    quorums
}

fn all_byzantine_sets_up_to(member_count: usize, max_byzantine: usize) -> Vec<MemberSet> {
    let mut sets = vec![MemberSet::new()];
    for choose in 1..=max_byzantine.min(member_count) {
        sets.extend(all_sets_of_size(member_count, choose));
    }
    sets
}

fn conflicting_certificates_possible(
    member_count: usize,
    threshold: usize,
    byzantine_members: &MemberSet,
) -> bool {
    let quorums = quorum_sets(member_count, threshold);
    quorums.iter().enumerate().any(|(left_index, left)| {
        quorums.iter().skip(left_index + 1).any(|right| {
            let overlap: MemberSet = left.intersection(right).copied().collect();
            overlap
                .iter()
                .all(|member| byzantine_members.contains(member))
        })
    })
}

fn safety_holds_under_budget(member_count: usize, threshold: usize, max_byzantine: usize) -> bool {
    all_byzantine_sets_up_to(member_count, max_byzantine)
        .into_iter()
        .all(|byzantine_members| {
            !conflicting_certificates_possible(member_count, threshold, &byzantine_members)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn majority_quorums_always_intersect_for_small_committees() {
        for member_count in 1..=7 {
            let threshold = (member_count / 2) + 1;
            let quorums = quorum_sets(member_count, threshold);
            for (left_index, left) in quorums.iter().enumerate() {
                for right in quorums.iter().skip(left_index + 1) {
                    assert!(
                        left.intersection(right).next().is_some(),
                        "expected intersecting quorums for n={member_count}, t={threshold}, left={left:?}, right={right:?}",
                    );
                }
            }
        }
    }

    #[test]
    fn guardian_majority_safety_holds_below_quorum_intersection_budget() {
        for member_count in 3..=7 {
            let threshold: usize = (member_count / 2) + 1;
            let min_intersection = (2 * threshold).saturating_sub(member_count);
            let max_byzantine = min_intersection.saturating_sub(1);
            assert!(
                safety_holds_under_budget(member_count, threshold, max_byzantine),
                "expected no conflicting certificates for n={member_count}, t={threshold}, f={max_byzantine}",
            );
        }
    }

    #[test]
    fn odd_sized_majority_committees_fail_with_one_equivocator() {
        let mut one_byzantine = MemberSet::new();
        one_byzantine.insert(0);
        assert!(
            conflicting_certificates_possible(5, 3, &one_byzantine),
            "for n=5, t=3 the quorum intersection can be a single equivocator"
        );
    }

    #[test]
    fn even_sized_majority_committees_tolerate_one_equivocator_but_not_two() {
        let mut one_byzantine = MemberSet::new();
        one_byzantine.insert(0);
        assert!(
            !conflicting_certificates_possible(4, 3, &one_byzantine),
            "for n=4, t=3 one equivocator is below the minimum quorum intersection"
        );

        let two_byzantine = [0usize, 1usize].into_iter().collect();
        assert!(
            conflicting_certificates_possible(4, 3, &two_byzantine),
            "for n=4, t=3 two equivocators can cover the quorum intersection"
        );
    }

    #[test]
    fn non_majority_thresholds_admit_conflicts_without_equivocation() {
        let byzantine_members = MemberSet::new();
        assert!(
            conflicting_certificates_possible(4, 2, &byzantine_members),
            "disjoint threshold-2 quorums exist for n=4, so majority thresholds are required"
        );
    }
}
