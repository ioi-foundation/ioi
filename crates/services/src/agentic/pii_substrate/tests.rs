use super::{build_evidence_graph, categories};

#[test]
fn detects_email_and_api_key() {
    let g =
        build_evidence_graph("contact john@example.com use sk_live_abcd1234abcd1234 to continue")
            .expect("graph");
    let cats = categories(&g);
    assert!(cats.contains("email"));
    assert!(cats.contains("api_key"));
}

#[test]
fn validates_card_with_luhn() {
    let g = build_evidence_graph("card 4242 4242 4242 4242").expect("graph");
    let cats = categories(&g);
    assert!(cats.contains("card_pan"));
}

#[test]
fn rejects_non_luhn_card_like_numbers() {
    let g = build_evidence_graph("tracking 1234 5678 9012 3456").expect("graph");
    let cats = categories(&g);
    assert!(!cats.contains("card_pan"));
}

#[test]
fn detects_zero_width_secret_bypass() {
    let g = build_evidence_graph("copy sk\u{200d}_live_abcd1234abcd1234").expect("graph");
    let cats = categories(&g);
    assert!(cats.contains("api_key"));
}

#[test]
fn detects_nfkc_fullwidth_secret_bypass() {
    let g = build_evidence_graph("key ｓｋ＿ｌｉｖｅ＿abcd1234abcd1234").expect("graph");
    let cats = categories(&g);
    assert!(cats.contains("api_key"));
}

#[test]
fn url_slug_numeric_ids_do_not_trigger_phone_detection() {
    let g = build_evidence_graph(
        "https://www.indiatoday.in/education-today/news/story/school-assembly-news-headlines-february-28-top-india-world-sports-business-news-2875631-2026-02-28",
    )
    .expect("graph");
    let cats = categories(&g);
    assert!(!cats.contains("phone"));
}
