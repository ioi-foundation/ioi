use anyhow::Result;
use ioi_types::app::agentic::WebSource;
use regex::Regex;
use scraper::{Html, Selector};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

use super::google_news::resolve_google_news_article_url;
use super::transport::fetch_html_http_fallback;
use super::urls::{
    build_bing_news_rss_url, build_bing_search_rss_url, build_google_news_rss_url,
    build_google_news_top_stories_rss_url, is_search_engine_host, normalize_bing_search_href,
    normalize_brave_search_href, normalize_google_search_href, normalize_search_href,
};
use super::util::{
    compact_ws, domain_for_url, normalize_url_for_id, source_id_for_url, text_content,
};

fn text_is_structured_metadata_noise(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let marker_hits = [
        "\"@context\"",
        "\"@type\"",
        "datepublished",
        "datemodified",
        "inlanguage",
        "thumbnailurl",
        "contenturl",
        "imageobject",
        "\"width\"",
        "\"height\"",
        "\"caption\"",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    if marker_hits == 0 {
        return false;
    }
    let structured_punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '{' | '}' | '[' | ']' | '"' | ':'))
        .count();
    marker_hits >= 2
        && (structured_punctuation_hits >= 12
            || lower.contains("\",\"")
            || lower.contains("\":")
            || lower.contains("},{"))
}

fn text_is_script_noise(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let strong_marker_hits = [
        "crypto.getrandomvalues",
        "document.queryselector",
        "document.getelementbyid",
        "googletag.",
        "adsbygoogle",
        "localstorage",
        "sessionstorage",
        "requestsubmit(",
        "tostring(16)",
        "style.display",
        "queryselector(",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    if strong_marker_hits >= 2 {
        return true;
    }

    let js_marker_hits = [
        "function ",
        "=>",
        "document.",
        "window.",
        "return ([1e7]",
        "const ",
        "let ",
        "var ",
        ".style.",
        "addeventlistener",
        "remove()",
        "submit(",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    let punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '{' | '}' | '[' | ']' | ';' | '=' | '>' | '<' | '/'))
        .count();

    js_marker_hits >= 4 && punctuation_hits >= 12
}

fn text_is_inline_markup_noise(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let attribute_marker_hits = [
        "<svg",
        "</svg",
        "<path",
        "viewbox=",
        "xmlns=",
        "width=",
        "height=",
        "stroke=",
        "fill=",
        "paddingtop=",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    let markup_punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '<' | '>' | '=' | '"' | '/'))
        .count();

    attribute_marker_hits >= 3 && markup_punctuation_hits >= 12
}

pub(crate) fn parse_ddg_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);

    let container_selectors = [
        "div.result",
        "article[data-testid=\"result\"]",
        "div[data-testid=\"result\"]",
    ];
    let title_selectors = [
        "a[data-testid=\"result-title-a\"]",
        "a.result__a",
        "a[href]",
    ];
    let snippet_selector = Selector::parse(
        "a.result__snippet, div.result__snippet, span.result__snippet, div[data-testid=\"result-snippet\"]",
    )
    .ok();

    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for container_sel_str in container_selectors {
        let Ok(container_sel) = Selector::parse(container_sel_str) else {
            continue;
        };
        for container in document.select(&container_sel) {
            if out.len() >= limit {
                break;
            }

            let mut anchor = None;
            for title_sel_str in title_selectors {
                let Ok(sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                if let Some(found) = container.select(&sel).next() {
                    if found.value().attr("href").is_some() {
                        anchor = Some(found);
                        break;
                    }
                }
            }
            let Some(anchor) = anchor else {
                continue;
            };

            let href = anchor.value().attr("href").unwrap_or("").trim();
            let Some(final_url) = normalize_search_href(href) else {
                continue;
            };
            if seen.contains(&final_url) {
                continue;
            }
            seen.insert(final_url.clone());

            let title_raw = compact_ws(&text_content(anchor));
            let title = title_raw.trim();
            let title_opt = (!title.is_empty()).then(|| title.to_string());

            let snippet_opt = snippet_selector.as_ref().and_then(|sel| {
                container.select(sel).next().map(|s| {
                    let raw = compact_ws(&text_content(s));
                    raw.trim().to_string()
                })
            });
            let snippet_opt = snippet_opt.filter(|s| !s.trim().is_empty());

            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: snippet_opt,
                domain: domain_for_url(&final_url),
            });
        }

        if !out.is_empty() {
            break;
        }
    }

    out
}

pub(crate) fn parse_google_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let container_selectors = ["div.g", "div.MjjYud", "div[data-hveid]"];
    let title_selectors = ["a[href]"];
    let snippet_selector =
        Selector::parse("div.VwiC3b, span.aCOpRe, div[data-sncf], div[data-content-feature]");

    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for container_sel_str in container_selectors {
        let Ok(container_sel) = Selector::parse(container_sel_str) else {
            continue;
        };
        for container in document.select(&container_sel) {
            if out.len() >= limit {
                break;
            }

            let mut chosen: Option<(String, Option<String>, Option<String>)> = None;
            for title_sel_str in title_selectors {
                let Ok(title_sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                for anchor in container.select(&title_sel) {
                    let href = anchor.value().attr("href").unwrap_or("").trim();
                    let Some(final_url) = normalize_google_search_href(href) else {
                        continue;
                    };
                    if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                        continue;
                    }
                    let title_raw = compact_ws(&text_content(anchor));
                    let title = title_raw.trim();
                    if title.is_empty() {
                        continue;
                    }
                    let title_opt = Some(title.to_string());
                    let snippet_opt = snippet_selector
                        .as_ref()
                        .ok()
                        .and_then(|sel| {
                            container.select(sel).next().map(|value| {
                                let raw = compact_ws(&text_content(value));
                                raw.trim().to_string()
                            })
                        })
                        .filter(|snippet| !snippet.trim().is_empty());
                    chosen = Some((final_url, title_opt, snippet_opt));
                    break;
                }
                if chosen.is_some() {
                    break;
                }
            }

            let Some((final_url, title_opt, snippet_opt)) = chosen else {
                continue;
            };

            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: snippet_opt,
                domain: domain_for_url(&final_url),
            });
        }

        if !out.is_empty() {
            break;
        }
    }

    out
}

pub(crate) fn parse_bing_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let container_selectors = ["li.b_algo", "div.b_algo", "li[data-bm]"];
    let title_selectors = ["h2 a[href]", "a[href]"];
    let snippet_selector = Selector::parse("div.b_caption p, p.b_paractl, p");

    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for container_sel_str in container_selectors {
        let Ok(container_sel) = Selector::parse(container_sel_str) else {
            continue;
        };
        for container in document.select(&container_sel) {
            if out.len() >= limit {
                break;
            }
            let mut chosen: Option<(String, Option<String>, Option<String>)> = None;
            for title_sel_str in title_selectors {
                let Ok(title_sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                for anchor in container.select(&title_sel) {
                    let href = anchor.value().attr("href").unwrap_or("").trim();
                    let Some(final_url) = normalize_bing_search_href(href) else {
                        continue;
                    };
                    if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                        continue;
                    }
                    let title_raw = compact_ws(&text_content(anchor));
                    let title = title_raw.trim();
                    if title.is_empty() {
                        continue;
                    }
                    let title_opt = Some(title.to_string());
                    let snippet_opt = snippet_selector
                        .as_ref()
                        .ok()
                        .and_then(|sel| {
                            container.select(sel).next().map(|value| {
                                let raw = compact_ws(&text_content(value));
                                raw.trim().to_string()
                            })
                        })
                        .filter(|snippet| !snippet.trim().is_empty());
                    chosen = Some((final_url, title_opt, snippet_opt));
                    break;
                }
                if chosen.is_some() {
                    break;
                }
            }

            let Some((final_url, title_opt, snippet_opt)) = chosen else {
                continue;
            };
            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: snippet_opt,
                domain: domain_for_url(&final_url),
            });
        }
        if !out.is_empty() {
            break;
        }
    }

    out
}

pub(crate) fn parse_brave_sources_from_html(html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let container_selectors = [
        "div[data-type=\"web\"]",
        "div.snippet[data-type=\"web\"]",
        "div.snippet",
    ];
    let title_selectors = ["a.svelte-14r20fy.l1[href]", "div.title a[href]", "a[href]"];
    let snippet_selector =
        Selector::parse("div.generic-snippet div.content, div.generic-snippet, p");

    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for container_sel_str in container_selectors {
        let Ok(container_sel) = Selector::parse(container_sel_str) else {
            continue;
        };
        for container in document.select(&container_sel) {
            if out.len() >= limit {
                break;
            }

            let mut chosen: Option<(String, Option<String>, Option<String>)> = None;
            for title_sel_str in title_selectors {
                let Ok(title_sel) = Selector::parse(title_sel_str) else {
                    continue;
                };
                for anchor in container.select(&title_sel) {
                    let href = anchor.value().attr("href").unwrap_or("").trim();
                    let Some(final_url) = normalize_brave_search_href(href) else {
                        continue;
                    };
                    if is_search_engine_host(&final_url) || seen.contains(&final_url) {
                        continue;
                    }
                    let title_raw = compact_ws(&text_content(anchor));
                    let title = title_raw.trim();
                    if title.is_empty() {
                        continue;
                    }
                    let title_opt = Some(title.to_string());
                    let snippet_opt = snippet_selector
                        .as_ref()
                        .ok()
                        .and_then(|sel| {
                            container.select(sel).next().map(|value| {
                                let raw = compact_ws(&text_content(value));
                                raw.trim().to_string()
                            })
                        })
                        .filter(|snippet| !snippet.trim().is_empty());
                    chosen = Some((final_url, title_opt, snippet_opt));
                    break;
                }
                if chosen.is_some() {
                    break;
                }
            }

            let Some((final_url, title_opt, snippet_opt)) = chosen else {
                continue;
            };
            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: snippet_opt,
                domain: domain_for_url(&final_url),
            });
        }
        if !out.is_empty() {
            break;
        }
    }

    out
}

fn extract_document_title(document: &Html) -> Option<String> {
    let selector = Selector::parse("title").ok()?;
    let title = document
        .select(&selector)
        .next()
        .map(text_content)
        .map(|raw| compact_ws(&raw))?;
    let trimmed = title.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn extract_meta_content(document: &Html, selectors: &[&str]) -> Option<String> {
    for selector_raw in selectors {
        let Ok(selector) = Selector::parse(selector_raw) else {
            continue;
        };
        let Some(value) = document
            .select(&selector)
            .next()
            .and_then(|meta| meta.value().attr("content"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        return Some(value.to_string());
    }

    None
}

fn extract_meta_title(document: &Html) -> Option<String> {
    extract_meta_content(
        document,
        &[
            "meta[property=\"og:title\"]",
            "meta[name=\"twitter:title\"]",
            "meta[name=\"title\"]",
        ],
    )
}

fn extract_canonical_url(document: &Html, page_url: &str) -> Option<String> {
    let raw = [
        "link[rel=\"canonical\"]",
        "meta[property=\"og:url\"]",
        "meta[name=\"twitter:url\"]",
    ]
    .iter()
    .find_map(|selector_raw| {
        let selector = Selector::parse(selector_raw).ok()?;
        let element = document.select(&selector).next()?;
        element
            .value()
            .attr("href")
            .or_else(|| element.value().attr("content"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    })?;
    Url::parse(&raw)
        .ok()
        .map(|url| url.to_string())
        .or_else(|| {
            Url::parse(page_url)
                .ok()?
                .join(raw.trim())
                .ok()
                .map(|url| url.to_string())
        })
}

fn extract_meta_description(document: &Html) -> Option<String> {
    extract_meta_content(
        document,
        &[
            "meta[name=\"description\"]",
            "meta[property=\"og:description\"]",
            "meta[name=\"twitter:description\"]",
        ],
    )
}

fn absolute_same_host_url(base_url: &str, href: &str) -> Option<String> {
    let base = Url::parse(base_url.trim()).ok()?;
    let mut joined = base.join(href.trim()).ok()?;
    if !matches!(joined.scheme(), "http" | "https") {
        return None;
    }
    if base.host_str()?.trim().to_ascii_lowercase()
        != joined.host_str()?.trim().to_ascii_lowercase()
    {
        return None;
    }
    joined.set_fragment(None);
    Some(joined.to_string())
}

fn page_context_snippet(page_url: &str, html: &str) -> Option<String> {
    let page = parse_generic_page_source_from_html(page_url, html)?;
    let mut parts = Vec::new();
    if let Some(title) = page.title.filter(|value| !value.trim().is_empty()) {
        parts.push(title);
    }
    if let Some(snippet) = page.snippet.filter(|value| !value.trim().is_empty()) {
        parts.push(snippet);
    }
    (!parts.is_empty()).then(|| parts.join(" | "))
}

fn json_ld_blocks(document: &Html) -> Vec<String> {
    let Ok(selector) = Selector::parse("script[type=\"application/ld+json\"]") else {
        return Vec::new();
    };
    document
        .select(&selector)
        .map(text_content)
        .map(|raw| compact_ws(&raw))
        .filter(|raw| !raw.trim().is_empty())
        .collect()
}

fn collect_item_list_elements(value: &Value, out: &mut Vec<Value>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_item_list_elements(item, out);
            }
        }
        Value::Object(map) => {
            let type_matches = map
                .get("@type")
                .map(|kind| match kind {
                    Value::String(raw) => raw.eq_ignore_ascii_case("ItemList"),
                    Value::Array(values) => values.iter().any(|value| {
                        value
                            .as_str()
                            .map(|raw| raw.eq_ignore_ascii_case("ItemList"))
                            .unwrap_or(false)
                    }),
                    _ => false,
                })
                .unwrap_or(false);
            if type_matches {
                if let Some(elements) = map.get("itemListElement") {
                    collect_item_list_elements(elements, out);
                }
            } else if map.contains_key("position") || map.contains_key("item") {
                out.push(value.clone());
            } else if let Some(graph) = map.get("@graph") {
                collect_item_list_elements(graph, out);
            }
        }
        _ => {}
    }
}

fn item_list_sources_from_json_ld(page_url: &str, html: &str, limit: usize) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let page_context = page_context_snippet(page_url, html);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut elements = Vec::new();
    for raw in json_ld_blocks(&document) {
        if let Ok(value) = serde_json::from_str::<Value>(&raw) {
            collect_item_list_elements(&value, &mut elements);
        }
    }

    for element in elements {
        if out.len() >= limit {
            break;
        }
        let item = element.get("item").unwrap_or(&element);
        let raw_url = item
            .get("url")
            .or_else(|| item.get("@id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(final_url) = absolute_same_host_url(page_url, raw_url) else {
            continue;
        };
        let url_key = normalize_url_for_id(&final_url);
        if !seen.insert(url_key) {
            continue;
        }

        let title = item
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());
        if title.is_none() {
            continue;
        }

        let rating = item
            .get("aggregateRating")
            .and_then(Value::as_object)
            .and_then(|rating| {
                let value = rating.get("ratingValue")?.as_f64()?;
                let reviews = rating
                    .get("reviewCount")
                    .and_then(|count| count.as_u64())
                    .map(|count| format!("{count} reviews"));
                Some(match reviews {
                    Some(review_text) => format!("{value:.1} rating from {review_text}"),
                    None => format!("{value:.1} rating"),
                })
            });
        let price_range = item
            .get("priceRange")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("price range {value}"));
        let mut snippet_parts = Vec::new();
        if let Some(context) = page_context.clone() {
            snippet_parts.push(context);
        }
        if let Some(rating) = rating {
            snippet_parts.push(rating);
        }
        if let Some(price_range) = price_range {
            snippet_parts.push(price_range);
        }
        let snippet = (!snippet_parts.is_empty()).then(|| snippet_parts.join(" | "));

        out.push(WebSource {
            source_id: source_id_for_url(&final_url),
            rank: Some(out.len() as u32 + 1),
            url: final_url.clone(),
            title,
            snippet,
            domain: domain_for_url(&final_url),
        });
    }

    out
}

pub(crate) fn parse_json_ld_item_list_sources_from_html(
    page_url: &str,
    html: &str,
    limit: usize,
) -> Vec<WebSource> {
    item_list_sources_from_json_ld(page_url, html, limit)
}

pub(crate) fn parse_same_host_child_collection_sources_from_html(
    page_url: &str,
    html: &str,
    limit: usize,
) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let page_context = page_context_snippet(page_url, html);
    let Ok(base_url) = Url::parse(page_url.trim()) else {
        return Vec::new();
    };
    let base_depth = base_url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.trim().is_empty())
                .count()
        })
        .unwrap_or(0);
    let Ok(selector) = Selector::parse("a[href]") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for anchor in document.select(&selector) {
        if out.len() >= limit {
            break;
        }
        let href = anchor.value().attr("href").unwrap_or_default();
        let Some(final_url) = absolute_same_host_url(page_url, href) else {
            continue;
        };
        if final_url == page_url {
            continue;
        }
        let Ok(parsed_url) = Url::parse(&final_url) else {
            continue;
        };
        let depth = parsed_url
            .path_segments()
            .map(|segments| {
                segments
                    .filter(|segment| !segment.trim().is_empty())
                    .count()
            })
            .unwrap_or(0);
        if depth != base_depth + 1 {
            continue;
        }
        let Some(last_segment) = parsed_url.path_segments().and_then(|segments| {
            segments
                .filter(|segment| !segment.trim().is_empty())
                .next_back()
        }) else {
            continue;
        };
        if last_segment.ends_with('-') || last_segment.chars().any(|ch| ch.is_ascii_digit()) {
            continue;
        }

        let title_raw = compact_ws(&text_content(anchor));
        let title = title_raw.trim();
        if title.is_empty() {
            continue;
        }
        let title_token_count = title
            .split_whitespace()
            .filter(|token| !token.trim().is_empty())
            .count();
        if title_token_count == 0 || title_token_count > 4 {
            continue;
        }

        let url_key = normalize_url_for_id(&final_url);
        if !seen.insert(url_key) {
            continue;
        }

        out.push(WebSource {
            source_id: source_id_for_url(&final_url),
            rank: Some(out.len() as u32 + 1),
            url: final_url.clone(),
            title: Some(title.to_string()),
            snippet: page_context.clone(),
            domain: domain_for_url(&final_url),
        });
    }

    out
}

fn authority_document_title_signal(title: &str) -> bool {
    let lower = title.to_ascii_lowercase();
    [
        "fips",
        "federal information processing standard",
        "special publication",
        "sp ",
        "sp-",
        "ir ",
        "interagency report",
        "draft",
        "final",
        "standard",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn authority_document_url_signal(url: &Url) -> bool {
    let path = url.path().to_ascii_lowercase();
    if !(path.contains("/pubs/") || path.contains("/publications/") || path.contains("/standards/"))
    {
        return false;
    }
    path.contains("/final")
        || path.contains("/draft")
        || path.contains("/fips/")
        || path.contains("/sp/")
        || path.contains("/ir/")
}

pub(crate) fn parse_same_host_authority_document_sources_from_html(
    page_url: &str,
    html: &str,
    limit: usize,
) -> Vec<WebSource> {
    let document = Html::parse_document(html);
    let page_context = page_context_snippet(page_url, html);
    let Ok(selector) = Selector::parse("a[href]") else {
        return Vec::new();
    };

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for anchor in document.select(&selector) {
        if out.len() >= limit {
            break;
        }
        let href = anchor.value().attr("href").unwrap_or_default();
        let Some(final_url) = absolute_same_host_url(page_url, href) else {
            continue;
        };
        if final_url == page_url {
            continue;
        }
        let Ok(parsed_url) = Url::parse(&final_url) else {
            continue;
        };
        if !authority_document_url_signal(&parsed_url) {
            continue;
        }

        let title_raw = compact_ws(&text_content(anchor));
        let title = title_raw.trim();
        if title.is_empty() {
            continue;
        }
        let title_token_count = title
            .split_whitespace()
            .filter(|token| !token.trim().is_empty())
            .count();
        if title_token_count == 0 || title_token_count > 10 {
            continue;
        }
        if !authority_document_title_signal(title)
            && !title.chars().any(|ch| ch.is_ascii_digit())
            && !parsed_url.path().chars().any(|ch| ch.is_ascii_digit())
        {
            continue;
        }

        let url_key = normalize_url_for_id(&final_url);
        if !seen.insert(url_key) {
            continue;
        }

        out.push(WebSource {
            source_id: source_id_for_url(&final_url),
            rank: Some(out.len() as u32 + 1),
            url: final_url.clone(),
            title: Some(title.to_string()),
            snippet: page_context.clone(),
            domain: domain_for_url(&final_url),
        });
    }

    out
}

pub(crate) fn parse_generic_page_source_from_html(page_url: &str, html: &str) -> Option<WebSource> {
    let document = Html::parse_document(html);
    let canonical_url =
        extract_canonical_url(&document, page_url).unwrap_or_else(|| page_url.to_string());
    let title = extract_document_title(&document).or_else(|| extract_meta_title(&document));
    let snippet = extract_meta_description(&document);
    if title.as_deref().unwrap_or_default().trim().is_empty()
        && snippet.as_deref().unwrap_or_default().trim().is_empty()
    {
        return None;
    }

    Some(WebSource {
        source_id: source_id_for_url(&canonical_url),
        rank: Some(1),
        url: canonical_url.clone(),
        title,
        snippet,
        domain: domain_for_url(&canonical_url),
    })
}

fn decode_rss_text(raw: &str) -> String {
    let trimmed = raw
        .trim()
        .trim_start_matches("<![CDATA[")
        .trim_end_matches("]]>")
        .trim();
    trimmed
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

pub(crate) fn parse_bing_news_sources_from_rss(rss_xml: &str, limit: usize) -> Vec<WebSource> {
    let item_re = Regex::new(r"(?is)<item\b[^>]*>(.*?)</item>").expect("static regex compiles");
    let title_re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").expect("static regex compiles");
    let link_re = Regex::new(r"(?is)<link\b[^>]*>(.*?)</link>").expect("static regex compiles");
    let description_re =
        Regex::new(r"(?is)<description\b[^>]*>(.*?)</description>").expect("static regex compiles");
    let source_re = Regex::new(r"(?is)<(?:news:)?source\b[^>]*>(.*?)</(?:news:)?source>")
        .expect("static regex compiles");

    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for item_cap in item_re.captures_iter(rss_xml) {
        if out.len() >= limit {
            break;
        }
        let Some(item_match) = item_cap.get(1) else {
            continue;
        };
        let item = item_match.as_str();

        let raw_link = link_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .unwrap_or_default();
        let Some(link_url) = sanitize_rss_http_url(&raw_link) else {
            continue;
        };
        let final_url = normalize_bing_search_href(&link_url).unwrap_or(link_url);
        if is_search_engine_host(&final_url) {
            continue;
        }
        let normalized = normalize_url_for_id(&final_url);
        if !seen.insert(normalized) {
            continue;
        }

        let title_opt = title_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });
        if title_opt.is_none() {
            continue;
        }

        let description_opt = description_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });
        let source_opt = source_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });
        let snippet_opt = match (source_opt, description_opt) {
            (Some(source), Some(description)) => Some(format!("{source} | {description}")),
            (Some(source), None) => Some(source),
            (None, Some(description)) => Some(description),
            (None, None) => None,
        };

        out.push(WebSource {
            source_id: source_id_for_url(&final_url),
            rank: Some(out.len() as u32 + 1),
            url: final_url.clone(),
            title: title_opt,
            snippet: snippet_opt,
            domain: domain_for_url(&final_url),
        });
    }

    out
}

fn sanitize_rss_http_url(raw: &str) -> Option<String> {
    let token = raw
        .trim()
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "\"'<>".contains(ch))
        .trim();
    if !(token.starts_with("http://") || token.starts_with("https://")) {
        return None;
    }

    let mut cleaned = token.to_string();
    loop {
        if Url::parse(&cleaned).is_ok() {
            return Some(cleaned);
        }
        let Some((idx, _)) = cleaned.char_indices().next_back() else {
            break;
        };
        cleaned.truncate(idx);
        if cleaned.is_empty() {
            break;
        }
    }
    None
}

async fn resolve_google_news_rss_item_url(client: &reqwest::Client, url: &str) -> Option<String> {
    tokio::time::timeout(
        Duration::from_millis(2_500),
        resolve_google_news_article_url(client, url.trim()),
    )
    .await
    .ok()
    .flatten()
}

async fn resolve_google_news_rss_sources(
    mut sources: Vec<WebSource>,
    limit: usize,
) -> Vec<WebSource> {
    if sources.is_empty() {
        return sources;
    }

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(8))
        .timeout(Duration::from_millis(3_000))
        .user_agent("Mozilla/5.0 (compatible; ioi-web-retriever/1.0; +https://ioi.local/web)")
        .build()
    {
        Ok(client) => client,
        Err(_) => return sources,
    };

    let resolve_limit = sources.len().min(limit.max(3)).min(5);
    for source in sources.iter_mut().take(resolve_limit) {
        let original = source.url.clone();
        let Some(resolved) = resolve_google_news_rss_item_url(&client, &original).await else {
            continue;
        };
        source.url = resolved.clone();
        source.source_id = source_id_for_url(&resolved);
        source.domain = domain_for_url(&resolved);
    }

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for mut source in sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let normalized = normalize_url_for_id(trimmed);
        if !seen.insert(normalized) {
            continue;
        }
        source.url = trimmed.to_string();
        deduped.push(source);
        if deduped.len() >= limit {
            break;
        }
    }

    deduped
}

pub(crate) fn parse_google_news_sources_from_rss(rss_xml: &str, limit: usize) -> Vec<WebSource> {
    let item_re = Regex::new(r"(?is)<item\b[^>]*>(.*?)</item>").expect("static regex compiles");
    let title_re = Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").expect("static regex compiles");
    let link_re = Regex::new(r"(?is)<link\b[^>]*>(.*?)</link>").expect("static regex compiles");
    let source_re =
        Regex::new(r"(?is)<source\b[^>]*>(.*?)</source>").expect("static regex compiles");
    let source_url_re =
        Regex::new(r#"(?is)<source\b[^>]*\burl="([^"]+)""#).expect("static regex compiles");
    let mut out: Vec<WebSource> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for item_cap in item_re.captures_iter(rss_xml) {
        if out.len() >= limit {
            break;
        }
        let Some(item_match) = item_cap.get(1) else {
            continue;
        };
        let item = item_match.as_str();

        let raw_link = link_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .unwrap_or_default();
        let Some(final_url) = sanitize_rss_http_url(&raw_link) else {
            continue;
        };
        if seen.contains(&final_url) {
            continue;
        }
        seen.insert(final_url.clone());

        let title_opt = title_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        let source_name_opt = source_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .map(|raw| compact_ws(&raw))
            .and_then(|raw| {
                let trimmed = raw.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });
        let source_url_opt = source_url_re
            .captures(item)
            .and_then(|cap| cap.get(1))
            .map(|m| decode_rss_text(m.as_str()))
            .and_then(|raw| sanitize_rss_http_url(&raw));
        let snippet_opt = match (source_name_opt, source_url_opt.as_deref()) {
            (Some(name), Some(source_url)) => Some(format!("{name} | source_url={source_url}")),
            (Some(name), None) => Some(name),
            (None, Some(source_url)) => Some(format!("source_url={source_url}")),
            (None, None) => None,
        };

        out.push(WebSource {
            source_id: source_id_for_url(&final_url),
            rank: Some(out.len() as u32 + 1),
            url: final_url.clone(),
            title: title_opt,
            snippet: snippet_opt,
            domain: source_url_opt
                .as_deref()
                .and_then(domain_for_url)
                .or_else(|| domain_for_url(&final_url)),
        });
    }

    out
}

pub(crate) async fn fetch_google_news_rss_sources(
    query: &str,
    limit: usize,
) -> Result<Vec<WebSource>> {
    let rss_url = build_google_news_rss_url(query);
    let rss_xml = fetch_html_http_fallback(&rss_url).await?;
    let parsed = parse_google_news_sources_from_rss(&rss_xml, limit);
    Ok(resolve_google_news_rss_sources(parsed, limit).await)
}

pub(crate) async fn fetch_google_news_top_stories_rss_sources(
    limit: usize,
) -> Result<Vec<WebSource>> {
    let rss_url = build_google_news_top_stories_rss_url();
    let rss_xml = fetch_html_http_fallback(&rss_url).await?;
    let parsed = parse_google_news_sources_from_rss(&rss_xml, limit);
    Ok(resolve_google_news_rss_sources(parsed, limit).await)
}

pub(crate) async fn fetch_bing_news_rss_sources(
    query: &str,
    limit: usize,
) -> Result<Vec<WebSource>> {
    let rss_url = build_bing_news_rss_url(query);
    let rss_xml = fetch_html_http_fallback(&rss_url).await?;
    Ok(parse_bing_news_sources_from_rss(&rss_xml, limit))
}

pub(crate) async fn fetch_bing_search_rss_sources(
    query: &str,
    limit: usize,
) -> Result<Vec<WebSource>> {
    let rss_url = build_bing_search_rss_url(query);
    let rss_xml = fetch_html_http_fallback(&rss_url).await?;
    Ok(parse_bing_news_sources_from_rss(&rss_xml, limit))
}
