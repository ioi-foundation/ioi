/// Extract the operator-authored request from a shell-provided contextual
/// intent envelope.
///
/// Product shells may prepend workspace/file context before sending a request
/// into the runtime. Artifact planning and direct authoring must stay grounded
/// in the user's literal deliverable ask, not in the envelope labels.
pub fn extract_user_request_from_contextualized_intent(intent: &str) -> String {
    let trimmed = intent.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let lowered = trimmed.to_ascii_lowercase();
    let marker = ["[user request]", "user request:"]
        .iter()
        .filter_map(|marker| lowered.rfind(marker).map(|index| (index, marker.len())))
        .max_by_key(|(index, _)| *index);
    if let Some((index, marker_len)) = marker {
        let request = &trimmed[index + marker_len..];
        let request = request.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, ':' | '-')
        });
        let request = request.trim();
        if !request.is_empty() {
            return request.to_string();
        }
    }

    trimmed.to_string()
}
