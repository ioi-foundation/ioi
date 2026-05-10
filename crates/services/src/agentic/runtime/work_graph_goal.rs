pub(crate) fn split_work_graph_goal_prefix(goal: &str) -> Option<(&str, &str)> {
    let first = goal.split_whitespace().next()?;
    let hash = first.strip_prefix("WORK_GRAPH:")?;
    Some((hash, goal[first.len()..].trim_start()))
}

#[cfg(test)]
mod tests {
    use super::split_work_graph_goal_prefix;

    #[test]
    fn parses_work_graph_goal_prefix() {
        let goal = "WORK_GRAPH:0123456789abcdef run the retained mission";

        let parsed = split_work_graph_goal_prefix(goal);

        assert_eq!(
            parsed,
            Some(("0123456789abcdef", "run the retained mission"))
        );
    }

    #[test]
    fn rejects_retired_graph_alias_prefix() {
        let goal = format!(
            "{}0123456789abcdef run the retired mission",
            ["SW", "ARM:"].concat()
        );

        assert_eq!(split_work_graph_goal_prefix(&goal), None);
    }
}
