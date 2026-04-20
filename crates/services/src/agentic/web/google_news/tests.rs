use super::{
    extract_google_news_decode_inputs, is_google_news_article_wrapper_url,
    parse_google_news_batchexecute_response, GoogleNewsDecodeInputs,
};

#[test]
fn google_news_wrapper_detection_accepts_article_and_read_paths() {
    assert!(is_google_news_article_wrapper_url(
        "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5"
    ));
    assert!(is_google_news_article_wrapper_url(
        "https://news.google.com/read/CBMiUkFVX3lxTE0x?hl=en-US&gl=US&ceid=US:en"
    ));
    assert!(!is_google_news_article_wrapper_url(
        "https://news.google.com/home?hl=en-US&gl=US&ceid=US:en"
    ));
}

#[test]
fn google_news_decode_inputs_are_extracted_from_wrapper_html() {
    let html = r#"
            <html>
              <body>
                <div
                  jscontroller="aLI87"
                  data-n-a-id="CBMiUkFVX3lxTE0x"
                  data-n-a-ts="1772798585"
                  data-n-a-sg="AZ5r3eQgUz4DTz0J9FazWGdfF2xD"></div>
              </body>
            </html>
        "#;

    assert_eq!(
        extract_google_news_decode_inputs(html),
        Some(GoogleNewsDecodeInputs {
            article_id: "CBMiUkFVX3lxTE0x".to_string(),
            timestamp_s: 1772798585,
            signature: "AZ5r3eQgUz4DTz0J9FazWGdfF2xD".to_string(),
        })
    );
}

#[test]
fn google_news_batchexecute_payload_extracts_resolved_url() {
    let body = r#")]}''

[["wrb.fr","Fbv4je","[\"garturlres\",\"https://www.tripadvisor.com/Restaurant_Review-g60763-d478005-Reviews-Pepe_Giallo-New_York_City_New_York.html\",1]",null,null,null,""],["di",19]]"#;

    assert_eq!(
            parse_google_news_batchexecute_response(body),
            Some(
                "https://www.tripadvisor.com/Restaurant_Review-g60763-d478005-Reviews-Pepe_Giallo-New_York_City_New_York.html".to_string()
            )
        );
}
