pub async fn edge_media_extract_transcript(
    url: &str,
    language: Option<&str>,
    max_chars: Option<u32>,
    browser: Arc<BrowserDriver>,
) -> Result<MediaTranscriptBundle> {
    let requested_url = validate_media_url(url, "media__extract_transcript")?;
    let requested_language = normalize_requested_language(language);
    let transcript_max_chars = max_chars
        .unwrap_or(MEDIA_DEFAULT_MAX_CHARS)
        .clamp(1, MEDIA_MAX_CHARS_LIMIT) as usize;
    let tool_home = ensure_media_tool_home()?;
    let (ytdlp_discovery, ytdlp_failure_reason) =
        discover_optional_ytdlp(requested_url.as_str(), &tool_home).await;
    let (watch_page, watch_page_failure_reason) =
        match discover_youtube_watch_page_context(requested_url.as_str()).await {
            Ok(value) => (value, None),
            Err(err) => (None, Some(provider_reason_from_error(&err))),
        };
    let (_, artifact) = extract_transcript_artifact(
        requested_url.as_str(),
        &requested_language,
        transcript_max_chars,
        &tool_home,
        browser,
        ytdlp_discovery.as_ref(),
        ytdlp_failure_reason.as_deref(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
        true,
    )
    .await?;
    let artifact = artifact.ok_or_else(|| {
        anyhow!(
            "ERROR_CLASS=DiscoveryMissing media transcript discovery found no admissible provider candidates for requested_language={} url={}",
            requested_language,
            requested_url
        )
    })?;
    write_run_receipt(&tool_home, &artifact.receipt)?;
    Ok(artifact.bundle)
}

pub async fn edge_media_extract_multimodal_evidence(
    url: &str,
    language: Option<&str>,
    max_chars: Option<u32>,
    frame_limit: Option<u32>,
    browser: Arc<BrowserDriver>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<MediaMultimodalBundle> {
    let requested_url = validate_media_url(url, "media__extract_multimodal_evidence")?;
    let requested_language = normalize_requested_language(language);
    let transcript_max_chars = max_chars
        .unwrap_or(MEDIA_MULTIMODAL_DEFAULT_MAX_CHARS)
        .clamp(1, MEDIA_MAX_CHARS_LIMIT) as usize;
    let visual_frame_limit = frame_limit
        .unwrap_or(MEDIA_VISUAL_DEFAULT_FRAME_LIMIT)
        .clamp(1, MEDIA_VISUAL_MAX_FRAME_LIMIT);
    let tool_home = ensure_media_tool_home()?;
    let (ytdlp_discovery, ytdlp_failure_reason) =
        discover_optional_ytdlp(requested_url.as_str(), &tool_home).await;
    let (watch_page, watch_page_failure_reason) =
        match discover_youtube_watch_page_context(requested_url.as_str()).await {
            Ok(value) => (value, None),
            Err(err) => (None, Some(provider_reason_from_error(&err))),
        };

    let (mut provider_candidates, transcript_artifact) = extract_transcript_artifact(
        requested_url.as_str(),
        &requested_language,
        transcript_max_chars,
        &tool_home,
        browser.clone(),
        ytdlp_discovery.as_ref(),
        ytdlp_failure_reason.as_deref(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
        false,
    )
    .await?;
    let (timeline_candidates, timeline_artifact) = extract_timeline_artifact(
        requested_url.as_str(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
    );
    provider_candidates.extend(timeline_candidates);

    let transcript_segments = transcript_artifact
        .as_ref()
        .map(|artifact| artifact.segments.as_slice());
    let (visual_candidates, visual_artifact) = extract_visual_artifact(
        requested_url.as_str(),
        visual_frame_limit,
        &tool_home,
        ytdlp_discovery.as_ref(),
        ytdlp_failure_reason.as_deref(),
        watch_page.as_ref(),
        watch_page_failure_reason.as_deref(),
        transcript_segments,
        inference,
    )
    .await?;
    provider_candidates.extend(visual_candidates);

    let mut selected_modalities = Vec::new();
    let mut selected_provider_ids = Vec::new();
    if let Some(artifact) = transcript_artifact.as_ref() {
        selected_modalities.push("transcript".to_string());
        selected_provider_ids.push(artifact.bundle.provider_id.clone());
    }
    if let Some(artifact) = timeline_artifact.as_ref() {
        selected_modalities.push("timeline".to_string());
        selected_provider_ids.push(artifact.bundle.provider_id.clone());
    }
    if let Some(artifact) = visual_artifact.as_ref() {
        selected_modalities.push("visual".to_string());
        selected_provider_ids.push(artifact.bundle.provider_id.clone());
    }

    if selected_modalities.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=DiscoveryMissing media multimodal discovery found no admissible transcript, timeline, or visual providers for url={}",
            requested_url
        ));
    }

    let canonical_url = media_canonical_url(
        requested_url.as_str(),
        ytdlp_discovery.as_ref(),
        watch_page.as_ref(),
    );
    let title = media_title(ytdlp_discovery.as_ref(), watch_page.as_ref());
    let duration_seconds = media_duration_seconds(ytdlp_discovery.as_ref(), watch_page.as_ref());
    let retrieved_at_ms = now_ms();

    let transcript_bundle = transcript_artifact
        .as_ref()
        .map(|artifact| artifact.bundle.clone());
    let timeline_bundle = timeline_artifact
        .as_ref()
        .map(|artifact| artifact.bundle.clone());
    let visual_bundle = visual_artifact
        .as_ref()
        .map(|artifact| artifact.bundle.clone());
    let bundle = MediaMultimodalBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_multimodal_evidence".to_string(),
        requested_url: requested_url.to_string(),
        canonical_url: canonical_url.clone(),
        title: title.clone(),
        duration_seconds,
        requested_language: requested_language.clone(),
        provider_candidates: provider_candidates.clone(),
        selected_modalities: selected_modalities.clone(),
        selected_provider_ids: selected_provider_ids.clone(),
        transcript: transcript_bundle.clone(),
        timeline: timeline_bundle.clone(),
        visual: visual_bundle.clone(),
    };

    let mut receipt = MediaMultimodalRunReceipt {
        schema_version: 1,
        requested_url: requested_url.to_string(),
        canonical_url,
        title,
        duration_seconds,
        requested_language,
        selected_modalities,
        selected_provider_ids,
        retrieved_at_ms,
        ..MediaMultimodalRunReceipt::default()
    };
    if let Some(artifact) = transcript_artifact {
        receipt.transcript_provider_id = Some(artifact.receipt.provider_id);
        receipt.transcript_provider_version = Some(artifact.receipt.provider_version);
        receipt.transcript_provider_binary_path = Some(artifact.receipt.provider_binary_path);
        receipt.transcript_provider_model_id = artifact.receipt.provider_model_id;
        receipt.transcript_provider_model_path = artifact.receipt.provider_model_path;
        receipt.transcript_selected_audio_format_id = artifact.receipt.selected_audio_format_id;
        receipt.transcript_selected_audio_ext = artifact.receipt.selected_audio_ext;
        receipt.transcript_selected_audio_acodec = artifact.receipt.selected_audio_acodec;
        receipt.transcript_language = Some(artifact.receipt.transcript_language);
        receipt.transcript_source_kind = Some(artifact.receipt.transcript_source_kind);
        receipt.transcript_char_count = Some(artifact.receipt.transcript_char_count);
        receipt.transcript_segment_count = Some(artifact.receipt.segment_count);
        receipt.transcript_hash = Some(artifact.receipt.transcript_hash);
    }
    if let Some(artifact) = timeline_artifact {
        receipt.timeline_provider_id = artifact.receipt.timeline_provider_id;
        receipt.timeline_provider_version = artifact.receipt.timeline_provider_version;
        receipt.timeline_source_kind = artifact.receipt.timeline_source_kind;
        receipt.timeline_cue_count = artifact.receipt.timeline_cue_count;
        receipt.timeline_char_count = artifact.receipt.timeline_char_count;
        receipt.timeline_hash = artifact.receipt.timeline_hash;
    }
    if let Some(artifact) = visual_artifact {
        receipt.visual_provider_id = artifact.receipt.visual_provider_id;
        receipt.visual_provider_version = artifact.receipt.visual_provider_version;
        receipt.visual_provider_binary_path = artifact.receipt.visual_provider_binary_path;
        receipt.visual_ffprobe_path = artifact.receipt.visual_ffprobe_path;
        receipt.visual_selected_video_format_id = artifact.receipt.visual_selected_video_format_id;
        receipt.visual_selected_video_ext = artifact.receipt.visual_selected_video_ext;
        receipt.visual_selected_video_codec = artifact.receipt.visual_selected_video_codec;
        receipt.visual_frame_count = artifact.receipt.visual_frame_count;
        receipt.visual_char_count = artifact.receipt.visual_char_count;
        receipt.visual_hash = artifact.receipt.visual_hash;
        receipt.visual_summary_char_count = artifact.receipt.visual_summary_char_count;
    }
    write_multimodal_run_receipt(&tool_home, &receipt)?;
    Ok(bundle)
}
