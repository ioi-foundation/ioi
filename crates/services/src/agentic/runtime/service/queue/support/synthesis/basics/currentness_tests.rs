use super::{
    first_current_role_holder_sentence, first_subject_currentness_sentence,
    has_subject_currentness_payload, query_requires_subject_currentness_identity,
};

#[test]
fn generic_role_definition_is_not_treated_as_subject_identity_payload() {
    let text = "Secretary-General of the United Nations - Wikipedia. The secretary-general of the United Nations is the Head of the United Nations Secretariat.";
    assert!(!has_subject_currentness_payload(text), "text={text}");
    assert!(
        first_subject_currentness_sentence(text).is_none(),
        "text={text}"
    );
}

#[test]
fn current_role_holder_sentence_is_detected() {
    let text = "António Guterres is the current Secretary-General of the United Nations.";
    assert!(has_subject_currentness_payload(text), "text={text}");
    assert_eq!(
        first_subject_currentness_sentence(text).as_deref(),
        Some("António Guterres is the current Secretary-General of the United Nations.")
    );
    assert_eq!(
        first_current_role_holder_sentence(text).as_deref(),
        Some("António Guterres is the current Secretary-General of the United Nations.")
    );
}

#[test]
fn historical_role_holder_biography_is_not_treated_as_explicit_current_holder() {
    let text = "Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year.";
    assert!(has_subject_currentness_payload(text), "text={text}");
    assert_eq!(
        first_current_role_holder_sentence(text),
        None,
        "text={text}"
    );
}

#[test]
fn current_role_holder_is_detected_from_search_title_and_excerpt_combo() {
    let text = "UN Ask DAG ask.un.org › faq › 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG! António Guterres is the current Secretary-General of the United Nations.";
    assert_eq!(
        first_current_role_holder_sentence(text).as_deref(),
        Some("António Guterres is the current Secretary-General of the United Nations.")
    );
}

#[test]
fn who_queries_for_current_roles_require_identity_grounding() {
    assert!(query_requires_subject_currentness_identity(
        "Who is the current Secretary-General of the UN?"
    ));
    assert!(!query_requires_subject_currentness_identity(
        "What does the Secretary-General of the UN do?"
    ));
}
