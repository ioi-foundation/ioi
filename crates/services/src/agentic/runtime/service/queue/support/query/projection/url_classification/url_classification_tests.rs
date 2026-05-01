use super::*;

#[test]
fn publication_index_pages_are_search_hubs() {
    for url in [
        "https://csrc.nist.gov/publications/final-pubs",
        "https://csrc.nist.gov/publications/draft-pubs",
        "https://csrc.nist.gov/publications/drafts-open-for-comment",
        "https://csrc.nist.gov/publications/fips",
        "https://csrc.nist.gov/publications/sp",
        "https://csrc.nist.gov/publications/ir",
        "https://csrc.nist.gov/publications/cswp",
        "https://csrc.nist.gov/publications/itl-bulletin",
        "https://csrc.nist.gov/publications/project-description",
        "https://csrc.nist.gov/publications/journal-article",
        "https://csrc.nist.gov/publications/conference-paper",
        "https://csrc.nist.gov/publications/book",
    ] {
        assert!(is_search_hub_url(url), "url={url}");
    }
}

#[test]
fn direct_fips_publication_page_is_not_search_hub() {
    assert!(!is_search_hub_url(
        "https://csrc.nist.gov/pubs/fips/203/final"
    ));
}

#[test]
fn time_sensitive_resolvable_payload_rejects_generic_role_definition_page() {
    assert!(!candidate_time_sensitive_resolvable_payload(
        "https://en.wikipedia.org/wiki/Secretary-General_of_the_United_Nations",
        "Secretary-General of the United Nations - Wikipedia",
        "The secretary-general of the United Nations is the Head of the United Nations Secretariat."
    ));
}

#[test]
fn time_sensitive_resolvable_payload_accepts_named_current_role_holder() {
    assert!(candidate_time_sensitive_resolvable_payload(
        "https://ask.un.org/faq/14625",
        "Who is and has been Secretary-General of the United Nations? - Ask DAG!",
        "António Guterres is the current Secretary-General of the United Nations."
    ));
}
