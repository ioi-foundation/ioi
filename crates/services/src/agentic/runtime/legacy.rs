pub(crate) fn split_work_graph_goal_prefix(goal: &str) -> Option<(&str, &str)> {
    let first = goal.split_whitespace().next()?;
    let hash = first
        .strip_prefix("WORK_GRAPH:")
        .or_else(|| first.strip_prefix("SWARM:"))?;
    Some((hash, goal[first.len()..].trim_start()))
}
