fn youtube_video_id_from_url(request_url: &str) -> Option<String> {
    let parsed = Url::parse(request_url).ok()?;
    let host = parsed.host_str()?.trim().to_ascii_lowercase();
    if host.ends_with("youtu.be") {
        return parsed
            .path_segments()?
            .find(|segment| !segment.trim().is_empty())
            .map(|segment| segment.trim().to_string());
    }
    if host.ends_with("youtube.com") || host.ends_with("youtube-nocookie.com") {
        if parsed.path().eq_ignore_ascii_case("/watch") {
            return parsed
                .query_pairs()
                .find(|(key, value)| key.eq_ignore_ascii_case("v") && !value.trim().is_empty())
                .map(|(_, value)| value.to_string());
        }
        let mut segments = parsed.path_segments()?;
        let first = segments.next()?.trim();
        let second = segments.next()?.trim();
        if matches!(first, "embed" | "shorts" | "live") && !second.is_empty() {
            return Some(second.to_string());
        }
    }
    None
}

async fn discover_youtube_watch_page_context(
    request_url: &str,
) -> Result<Option<YouTubeWatchPageContext>> {
    let Some(video_id) = youtube_video_id_from_url(request_url) else {
        return Ok(None);
    };
    let watch_url = format!("https://www.youtube.com/watch?v={video_id}");
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(YOUTUBE_WATCH_PAGE_TIMEOUT_SECS))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize youtube watch-page client")?;
    let response = client
        .get(&watch_url)
        .header(
            header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        )
        .send()
        .await
        .context("ERROR_CLASS=ExecutionFailedTerminal failed to fetch youtube watch page")?
        .error_for_status()
        .context("ERROR_CLASS=ExecutionFailedTerminal youtube watch page returned error status")?;
    let resolved_url = response.url().to_string();
    let html = response
        .text()
        .await
        .context("ERROR_CLASS=ExecutionFailedTerminal failed to read youtube watch page html")?;
    parse_youtube_watch_page_context(&resolved_url, &html).map(Some)
}

fn parse_youtube_watch_page_context(
    resolved_url: &str,
    html: &str,
) -> Result<YouTubeWatchPageContext> {
    let initial_data =
        extract_inline_json_after_prefix(html, "var ytInitialData = ").ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing youtube watch page missing ytInitialData")
        })?;
    let api_key =
        extract_quoted_value_after_prefix(html, "\"INNERTUBE_API_KEY\":\"").ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing youtube watch page missing innertube api key")
        })?;
    let initial_player_response =
        extract_inline_json_after_prefix(html, "var ytInitialPlayerResponse = ");
    let client_context = extract_inline_json_after_prefix(html, "\"INNERTUBE_CONTEXT\":")
        .ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing youtube watch page missing innertube context")
        })?;
    let transcript_params = youtube_watch_transcript_params(&initial_data);
    let transcript_challenge_reason = initial_player_response
        .as_ref()
        .and_then(youtube_watch_transcript_challenge_reason);
    let title = youtube_watch_title(&initial_data);
    let chapter_thumbnails = youtube_watch_chapter_thumbnails(&initial_data);
    let duration_seconds = extract_quoted_value_after_prefix(html, "\"lengthSeconds\":\"")
        .and_then(|value| value.parse::<u64>().ok())
        .or_else(|| {
            chapter_thumbnails
                .iter()
                .map(|chapter| chapter.start_ms / 1_000)
                .max()
        });

    if transcript_params.is_none() && chapter_thumbnails.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=DiscoveryMissing youtube watch page exposed neither transcript endpoint nor chapter thumbnails"
        ));
    }

    Ok(YouTubeWatchPageContext {
        api_key,
        client_context,
        transcript_params,
        transcript_challenge_reason,
        title,
        canonical_url: resolved_url.to_string(),
        duration_seconds,
        chapter_thumbnails,
    })
}

fn youtube_watch_transcript_challenge_reason(player_response: &Value) -> Option<String> {
    let status = player_response
        .get("playabilityStatus")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    if status.eq_ignore_ascii_case("OK") {
        return None;
    }
    let reason = player_response
        .get("playabilityStatus")
        .and_then(|value| value.get("reason"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("transcript_surface_unavailable");
    Some(format!(
        "youtube_watch_playability_block:{}:{}",
        status.to_ascii_lowercase(),
        compact_ws(reason)
    ))
}

fn extract_inline_json_after_prefix(raw: &str, prefix: &str) -> Option<Value> {
    let start = raw.find(prefix)? + prefix.len();
    let mut idx = start;
    while let Some(ch) = raw[idx..].chars().next() {
        if ch.is_whitespace() {
            idx += ch.len_utf8();
            continue;
        }
        if ch != '{' && ch != '[' {
            return None;
        }
        let end = matching_json_end(&raw[idx..])?;
        return serde_json::from_str::<Value>(&raw[idx..idx + end]).ok();
    }
    None
}

fn matching_json_end(raw: &str) -> Option<usize> {
    let mut stack = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' | '[' => stack.push(ch),
            '}' => {
                if stack.pop() != Some('{') {
                    return None;
                }
                if stack.is_empty() {
                    return Some(idx + ch.len_utf8());
                }
            }
            ']' => {
                if stack.pop() != Some('[') {
                    return None;
                }
                if stack.is_empty() {
                    return Some(idx + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_quoted_value_after_prefix(raw: &str, prefix: &str) -> Option<String> {
    let start = raw.find(prefix)? + prefix.len();
    let tail = &raw[start..];
    let end = tail.find('"')?;
    Some(tail[..end].replace("\\u003d", "=").replace("\\u0026", "&"))
}

fn youtube_watch_transcript_params(initial_data: &Value) -> Option<String> {
    find_first_object_by_key(initial_data, "getTranscriptEndpoint")
        .and_then(Value::as_object)
        .and_then(|value| value.get("params"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn youtube_watch_title(initial_data: &Value) -> Option<String> {
    find_first_object_by_key(initial_data, "videoPrimaryInfoRenderer")
        .and_then(Value::as_object)
        .and_then(|value| value.get("title"))
        .and_then(value_text)
}

fn youtube_watch_chapter_thumbnails(initial_data: &Value) -> Vec<YouTubeChapterThumbnail> {
    let Some(renderer) = find_first_object_by_key(initial_data, "macroMarkersListRenderer") else {
        return Vec::new();
    };
    let mut chapters = renderer
        .get("contents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("macroMarkersListItemRenderer"))
        .filter_map(|renderer| {
            let title = renderer.get("title").and_then(value_text)?;
            let start_seconds = renderer
                .get("onTap")
                .and_then(|value| value.get("watchEndpoint"))
                .and_then(|value| value.get("startTimeSeconds"))
                .and_then(Value::as_f64)
                .filter(|value| *value >= 0.0)?;
            let thumbnail_url = renderer
                .get("thumbnail")
                .and_then(|value| value.get("thumbnails"))
                .and_then(Value::as_array)
                .and_then(|value| value.last())
                .and_then(|value| value.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())?
                .to_string();
            Some(YouTubeChapterThumbnail {
                title,
                start_ms: (start_seconds * 1_000.0).round() as u64,
                thumbnail_url,
            })
        })
        .collect::<Vec<_>>();
    chapters.sort_by_key(|chapter| chapter.start_ms);
    chapters.dedup_by(|left, right| left.start_ms == right.start_ms);
    chapters
}

fn find_first_object_by_key<'a>(value: &'a Value, needle: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            if let Some(found) = map.get(needle) {
                return Some(found);
            }
            map.values()
                .find_map(|candidate| find_first_object_by_key(candidate, needle))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|candidate| find_first_object_by_key(candidate, needle)),
        _ => None,
    }
}

fn value_text(value: &Value) -> Option<String> {
    if let Some(simple) = value.get("simpleText").and_then(Value::as_str) {
        let trimmed = simple.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    let runs = value.get("runs").and_then(Value::as_array)?;
    let text = runs
        .iter()
        .filter_map(|run| run.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("");
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

async fn discover_optional_ytdlp(
    requested_url: &str,
    tool_home: &Path,
) -> (Option<ManagedYtDlpDiscovery>, Option<String>) {
    match ensure_managed_ytdlp_provider(tool_home).await {
        Ok(provider) => match prepare_run_dir(tool_home) {
            Ok(run_dir) => match fetch_ytdlp_metadata(&provider, requested_url, &run_dir).await {
                Ok(metadata) => (Some(ManagedYtDlpDiscovery { provider, metadata }), None),
                Err(err) => (None, Some(provider_reason_from_error(&err))),
            },
            Err(err) => (None, Some(provider_reason_from_error(&err))),
        },
        Err(err) => (None, Some(provider_reason_from_error(&err))),
    }
}

fn transcript_provider_binary_path(discovery: Option<&ManagedYtDlpDiscovery>) -> String {
    discovery
        .map(|value| value.provider.binary_path.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn failed_transcript_candidate_state(
    provider_id: &str,
    request_url: &str,
    challenge_reason: Option<String>,
) -> MediaProviderCandidateState {
    MediaProviderCandidateState {
        candidate: media_provider_candidate_receipt(
            provider_id,
            request_url,
            false,
            false,
            challenge_reason,
        ),
        plan: None,
    }
}

fn media_canonical_url(
    requested_url: &str,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    watch_page: Option<&YouTubeWatchPageContext>,
) -> String {
    ytdlp_discovery
        .and_then(|value| {
            value
                .metadata
                .get("webpage_url")
                .or_else(|| value.metadata.get("original_url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .or_else(|| watch_page.map(|value| value.canonical_url.clone()))
        .unwrap_or_else(|| requested_url.to_string())
}

fn media_title(
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    watch_page: Option<&YouTubeWatchPageContext>,
) -> Option<String> {
    ytdlp_discovery
        .and_then(|value| {
            value
                .metadata
                .get("title")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .or_else(|| watch_page.and_then(|value| value.title.clone()))
}

fn media_duration_seconds(
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    watch_page: Option<&YouTubeWatchPageContext>,
) -> Option<u64> {
    ytdlp_discovery
        .and_then(|value| value.metadata.get("duration").and_then(Value::as_u64))
        .or_else(|| watch_page.and_then(|value| value.duration_seconds))
}

fn youtube_watch_provider_version(client_context: &Value) -> String {
    client_context
        .get("client")
        .and_then(|value| value.get("clientVersion"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("youtube-web@{value}"))
        .unwrap_or_else(|| "youtube-web".to_string())
}
