use reqwest::Client;
use serde_json::{json, Value};
use url::Url;

const DEFAULT_GOOGLE_NEWS_HL: &str = "en-US";
const DEFAULT_GOOGLE_NEWS_GL: &str = "US";
const DEFAULT_GOOGLE_NEWS_CEID: &str = "US:en";
const GOOGLE_NEWS_UA: &str =
    "Mozilla/5.0 (compatible; ioi-web-retriever/1.0; +https://ioi.local/web)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoogleNewsDecodeInputs {
    pub(crate) article_id: String,
    pub(crate) timestamp_s: u64,
    pub(crate) signature: String,
}

pub(crate) fn is_google_news_article_wrapper_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if !host.eq_ignore_ascii_case("news.google.com") {
        return false;
    }
    matches!(
        parsed.path().to_ascii_lowercase().as_str(),
        path if path.starts_with("/rss/articles/") || path.starts_with("/read/")
    )
}

fn google_news_article_locale(url: &str) -> (String, String, String) {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return (
            DEFAULT_GOOGLE_NEWS_HL.to_string(),
            DEFAULT_GOOGLE_NEWS_GL.to_string(),
            DEFAULT_GOOGLE_NEWS_CEID.to_string(),
        );
    };

    let mut hl = None::<String>;
    let mut gl = None::<String>;
    let mut ceid = None::<String>;
    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "hl" if !value.trim().is_empty() => hl = Some(value.to_string()),
            "gl" if !value.trim().is_empty() => gl = Some(value.to_string()),
            "ceid" if !value.trim().is_empty() => ceid = Some(value.to_string()),
            _ => {}
        }
    }

    let hl = hl.unwrap_or_else(|| DEFAULT_GOOGLE_NEWS_HL.to_string());
    let gl = gl.unwrap_or_else(|| DEFAULT_GOOGLE_NEWS_GL.to_string());
    let ceid = ceid.unwrap_or_else(|| {
        let lang = hl
            .split('-')
            .next()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("en");
        format!("{}:{}", gl, lang)
    });
    (hl, gl, ceid)
}

fn normalized_non_google_news_url(url: &str) -> Option<String> {
    let mut parsed = Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if host == "news.google.com" {
        return None;
    }
    parsed.set_fragment(None);
    Some(parsed.to_string())
}

fn html_attr_value<'a>(html: &'a str, marker: &str) -> Option<&'a str> {
    let start = html.find(marker)? + marker.len();
    let rest = html.get(start..)?;
    let end = rest.find('"')?;
    rest.get(..end)
}

pub(crate) fn extract_google_news_decode_inputs(html: &str) -> Option<GoogleNewsDecodeInputs> {
    let article_id = html_attr_value(html, "data-n-a-id=\"")?.trim().to_string();
    let timestamp_s = html_attr_value(html, "data-n-a-ts=\"")?
        .trim()
        .parse::<u64>()
        .ok()?;
    let signature = html_attr_value(html, "data-n-a-sg=\"")?.trim().to_string();
    if article_id.is_empty() || signature.is_empty() {
        return None;
    }
    Some(GoogleNewsDecodeInputs {
        article_id,
        timestamp_s,
        signature,
    })
}

pub(crate) fn parse_google_news_batchexecute_response(body: &str) -> Option<String> {
    let json_start = body.find('[')?;
    let payload: Value = serde_json::from_str(body.get(json_start..)?.trim()).ok()?;
    let entries = payload.as_array()?;
    for entry in entries {
        let parts = entry.as_array()?;
        let rpc_id = parts.get(1)?.as_str()?;
        if rpc_id != "Fbv4je" {
            continue;
        }
        let encoded = parts.get(2)?.as_str()?;
        let decoded: Value = serde_json::from_str(encoded).ok()?;
        let decoded_parts = decoded.as_array()?;
        let response_kind = decoded_parts.first()?.as_str()?;
        if response_kind != "garturlres" {
            continue;
        }
        let resolved = decoded_parts.get(1)?.as_str()?;
        if let Some(normalized) = normalized_non_google_news_url(resolved) {
            return Some(normalized);
        }
    }
    None
}

async fn decode_google_news_article_url_from_inputs(
    client: &Client,
    page_url: &str,
    inputs: &GoogleNewsDecodeInputs,
) -> Option<String> {
    let parsed = Url::parse(page_url.trim()).ok()?;
    let origin = format!("{}://{}", parsed.scheme(), parsed.host_str()?);
    let (hl, gl, ceid) = google_news_article_locale(page_url);
    let request_payload = json!([
        "garturlreq",
        [
            [
                hl.clone(),
                gl.clone(),
                [hl.clone(), gl.clone()],
                Value::Null,
                Value::Null,
                1,
                1,
                ceid.clone(),
                Value::Null,
                1,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                0,
                1
            ],
            hl,
            gl,
            1,
            [1, 1, 1],
            1,
            1,
            Value::Null,
            0,
            0,
            Value::Null,
            0
        ],
        inputs.article_id,
        inputs.timestamp_s,
        inputs.signature
    ]);
    let body = [(
        "f.req",
        serde_json::to_string(&json!([[["Fbv4je", request_payload.to_string()]]])).ok()?,
    )];
    let endpoint = format!("{origin}/_/DotsSplashUi/data/batchexecute");
    let response = client
        .post(endpoint)
        .header(
            "Content-Type",
            "application/x-www-form-urlencoded;charset=UTF-8",
        )
        .header("Referer", page_url)
        .header("User-Agent", GOOGLE_NEWS_UA)
        .form(&body)
        .send()
        .await
        .ok()?;
    let text = response.text().await.ok()?;
    parse_google_news_batchexecute_response(&text)
}

pub(crate) async fn resolve_google_news_article_url(client: &Client, url: &str) -> Option<String> {
    if !is_google_news_article_wrapper_url(url) {
        return None;
    }

    let response = client
        .get(url.trim())
        .header("User-Agent", GOOGLE_NEWS_UA)
        .send()
        .await
        .ok()?;
    if let Some(normalized) = normalized_non_google_news_url(response.url().as_str()) {
        return Some(normalized);
    }

    let html = response.text().await.ok()?;
    let inputs = extract_google_news_decode_inputs(&html)?;
    decode_google_news_article_url_from_inputs(client, url, &inputs).await
}

#[cfg(test)]
mod tests {
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
}
