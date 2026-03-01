use anyhow::Result;
use ioi_types::app::agentic::WebSource;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

use super::transport::fetch_html_http_fallback;
use super::urls::{
    build_bing_news_rss_url, build_google_news_rss_url, is_search_engine_host,
    normalize_bing_search_href,
    normalize_google_search_href, normalize_search_href,
};
use super::util::{
    compact_ws, domain_for_url, normalize_url_for_id, source_id_for_url, text_content,
};

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

    // Fallback: grab anchors globally.
    if out.is_empty() {
        let Ok(anchor_sel) = Selector::parse("a[href]") else {
            return out;
        };
        for a in document.select(&anchor_sel) {
            if out.len() >= limit {
                break;
            }
            let href = a.value().attr("href").unwrap_or("").trim();
            let Some(final_url) = normalize_search_href(href) else {
                continue;
            };
            if seen.contains(&final_url) {
                continue;
            }
            seen.insert(final_url.clone());

            let title_raw = compact_ws(&text_content(a));
            let title = title_raw.trim();
            let title_opt = (!title.is_empty()).then(|| title.to_string());

            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: title_opt,
                snippet: None,
                domain: domain_for_url(&final_url),
            });
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

    if out.is_empty() {
        let Ok(anchor_sel) = Selector::parse("a[href]") else {
            return out;
        };
        for anchor in document.select(&anchor_sel) {
            if out.len() >= limit {
                break;
            }
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
            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: Some(title.to_string()),
                snippet: None,
                domain: domain_for_url(&final_url),
            });
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
                if let Some(anchor) = container.select(&title_sel).next() {
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

    if out.is_empty() {
        let Ok(anchor_sel) = Selector::parse("a[href]") else {
            return out;
        };
        for anchor in document.select(&anchor_sel) {
            if out.len() >= limit {
                break;
            }
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
            seen.insert(final_url.clone());
            out.push(WebSource {
                source_id: source_id_for_url(&final_url),
                rank: Some(out.len() as u32 + 1),
                url: final_url.clone(),
                title: Some(title.to_string()),
                snippet: None,
                domain: domain_for_url(&final_url),
            });
        }
    }

    out
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

fn is_news_feed_wrapper_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.to_ascii_lowercase() != "news.google.com" {
        return false;
    }
    let path = parsed.path().to_ascii_lowercase();
    path.starts_with("/rss/articles")
        || path.starts_with("/rss/read")
        || path.starts_with("/rss/topics")
}

async fn resolve_news_feed_wrapper_article_url(
    client: &reqwest::Client,
    url: &str,
) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() || !is_news_feed_wrapper_url(trimmed) {
        return None;
    }

    let response = tokio::time::timeout(Duration::from_millis(2_500), client.get(trimmed).send())
        .await
        .ok()
        .and_then(|result| result.ok())?;
    let resolved = response.url().as_str().trim().to_string();
    if resolved.is_empty()
        || (!resolved.starts_with("http://") && !resolved.starts_with("https://"))
        || is_news_feed_wrapper_url(&resolved)
    {
        return None;
    }
    Some(resolved)
}

async fn resolve_news_feed_wrapper_sources(
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
        let Some(resolved) = resolve_news_feed_wrapper_article_url(&client, &original).await else {
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
    Ok(resolve_news_feed_wrapper_sources(parsed, limit).await)
}

pub(crate) async fn fetch_bing_news_rss_sources(query: &str, limit: usize) -> Result<Vec<WebSource>> {
    let rss_url = build_bing_news_rss_url(query);
    let rss_xml = fetch_html_http_fallback(&rss_url).await?;
    Ok(parse_bing_news_sources_from_rss(&rss_xml, limit))
}
