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
#[path = "simulator/tests.rs"]
mod tests;
