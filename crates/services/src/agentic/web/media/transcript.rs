fn validate_media_url(url: &str, tool_name: &str) -> Result<String> {
    let requested_url = url.trim();
    if requested_url.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound {} requires a non-empty url.",
            tool_name
        ));
    }
    let parsed = Url::parse(requested_url)
        .map_err(|err| anyhow!("ERROR_CLASS=TargetNotFound invalid media url: {}", err))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(anyhow!(
            "ERROR_CLASS=TargetNotFound {} only supports http/https urls.",
            tool_name
        ));
    }
    Ok(requested_url.to_string())
}

fn ensure_media_tool_home() -> Result<PathBuf> {
    let tool_home = media_tool_home();
    fs::create_dir_all(&tool_home).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create media tool home {}",
            tool_home.display()
        )
    })?;
    Ok(tool_home)
}

async fn extract_transcript_artifact(
    requested_url: &str,
    requested_language: &str,
    transcript_max_chars: usize,
    tool_home: &Path,
    browser: Arc<BrowserDriver>,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    ytdlp_failure_reason: Option<&str>,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
    require_candidate: bool,
) -> Result<(Vec<MediaProviderCandidate>, Option<TranscriptArtifact>)> {
    let mut subtitle_candidate = ytdlp_discovery
        .map(|value| {
            discover_subtitle_candidate(requested_url, &value.metadata, requested_language)
        })
        .unwrap_or_else(|| {
            failed_transcript_candidate_state(
                SUBTITLE_PROVIDER_ID,
                requested_url,
                ytdlp_failure_reason.map(str::to_string),
            )
        });
    let mut youtube_watch_candidate = if let Some(context) = watch_page {
        discover_youtube_watch_transcript_candidate(requested_url, Some(context))
    } else {
        failed_transcript_candidate_state(
            YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID,
            requested_url,
            watch_page_failure_reason.map(str::to_string),
        )
    };
    if youtube_watch_candidate.plan.is_none()
        && youtube_watch_candidate.candidate.challenge_reason.is_none()
        && watch_page_failure_reason.is_some()
    {
        youtube_watch_candidate.candidate.challenge_reason =
            watch_page_failure_reason.map(str::to_string);
    }
    let mut audio_candidate = ytdlp_discovery
        .map(|value| discover_audio_stt_candidate(requested_url, &value.metadata))
        .unwrap_or_else(|| {
            failed_transcript_candidate_state(
                AUDIO_STT_PROVIDER_ID,
                requested_url,
                ytdlp_failure_reason.map(str::to_string),
            )
        });
    let selected_plans = select_provider_plans(
        &subtitle_candidate,
        &audio_candidate,
        &youtube_watch_candidate,
    );
    if selected_plans.is_empty() {
        let provider_candidates = vec![
            subtitle_candidate.candidate.clone(),
            youtube_watch_candidate.candidate.clone(),
            audio_candidate.candidate.clone(),
        ];
        if require_candidate {
            return Err(anyhow!(
                "ERROR_CLASS=DiscoveryMissing media transcript discovery found no admissible provider candidates for requested_language={} url={}",
                requested_language,
                requested_url
            ));
        }
        return Ok((provider_candidates, None));
    }

    let run_dir = prepare_run_dir(tool_home)?;
    let mut last_failure = None::<TranscriptExecutionFailure>;
    let mut executed = None::<ExecutedTranscript>;
    for selected_plan in selected_plans {
        let selected_candidate = transcript_candidate_state_mut(
            &mut subtitle_candidate,
            &mut audio_candidate,
            &mut youtube_watch_candidate,
            &selected_plan,
        );
        selected_candidate.candidate.execution_attempted = Some(true);
        match execute_transcript_plan(
            requested_url,
            requested_language,
            tool_home,
            browser.clone(),
            ytdlp_discovery,
            &run_dir,
            selected_plan.clone(),
        )
        .await
        {
            Ok(value) => {
                selected_candidate.candidate.selected = true;
                selected_candidate.candidate.execution_satisfied = Some(true);
                selected_candidate.candidate.execution_failure_reason = None;
                executed = Some(value);
                break;
            }
            Err(err) => {
                selected_candidate.candidate.execution_satisfied = Some(false);
                selected_candidate.candidate.execution_failure_reason =
                    Some(provider_reason_from_error(&err));
                last_failure = Some(TranscriptExecutionFailure {
                    provider_id: transcript_provider_id(&selected_plan),
                    error: err,
                });
            }
        }
    }

    let Some(executed) = executed else {
        let failure = last_failure.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal media transcript execution exhausted admissible providers for requested_language={} url={}",
                requested_language,
                requested_url
            )
        })?;
        return Err(failure.error.context(format!(
            "transcript provider execution exhausted admissible plan set after provider_id={}",
            failure.provider_id
        )));
    };

    let full_transcript = executed
        .segments
        .iter()
        .map(|segment| format!("[{}] {}", render_timestamp(segment.start_ms), segment.text))
        .collect::<Vec<_>>()
        .join("\n");
    let truncated_transcript = truncate_chars(&full_transcript, transcript_max_chars);
    if truncated_transcript.trim().is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing transcript text was empty after truncation."
        ));
    }

    let canonical_url = media_canonical_url(requested_url, ytdlp_discovery, watch_page);
    let title = media_title(ytdlp_discovery, watch_page);
    let duration_seconds = media_duration_seconds(ytdlp_discovery, watch_page);
    let transcript_hash = sha256_hex(truncated_transcript.as_bytes());
    let retrieved_at_ms = now_ms();
    let provider_candidates = vec![
        subtitle_candidate.candidate.clone(),
        youtube_watch_candidate.candidate.clone(),
        audio_candidate.candidate.clone(),
    ];
    let bundle = MediaTranscriptBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_transcript".to_string(),
        backend: executed.backend.to_string(),
        provider_id: executed.provider_id.to_string(),
        provider_version: executed.provider_version.clone(),
        requested_url: requested_url.to_string(),
        canonical_url: canonical_url.clone(),
        provider_candidates: provider_candidates.clone(),
        title: title.clone(),
        duration_seconds,
        requested_language: requested_language.to_string(),
        transcript_language: executed.transcript_language.clone(),
        transcript_source_kind: executed.transcript_source_kind.clone(),
        segment_count: executed.segments.len() as u32,
        transcript_char_count: truncated_transcript.chars().count() as u32,
        transcript_hash: transcript_hash.clone(),
        transcript_text: truncated_transcript,
    };
    let receipt = MediaTranscriptRunReceipt {
        schema_version: 1,
        provider_id: executed.provider_id.to_string(),
        provider_version: executed.provider_version,
        provider_binary_path: transcript_provider_binary_path(ytdlp_discovery),
        provider_model_id: executed.provider_model_id,
        provider_model_path: executed.provider_model_path,
        selected_audio_format_id: executed.selected_audio_format_id,
        selected_audio_ext: executed.selected_audio_ext,
        selected_audio_acodec: executed.selected_audio_acodec,
        requested_url: requested_url.to_string(),
        canonical_url,
        title,
        duration_seconds,
        requested_language: requested_language.to_string(),
        transcript_language: bundle.transcript_language.clone(),
        transcript_source_kind: bundle.transcript_source_kind.clone(),
        transcript_char_count: bundle.transcript_char_count,
        segment_count: bundle.segment_count,
        transcript_hash,
        retrieved_at_ms,
    };

    Ok((
        provider_candidates,
        Some(TranscriptArtifact {
            bundle,
            receipt,
            segments: executed.segments,
        }),
    ))
}

fn transcript_provider_id(selected_plan: &ProviderExecutionPlan) -> &'static str {
    match selected_plan {
        ProviderExecutionPlan::Subtitle(_) => SUBTITLE_PROVIDER_ID,
        ProviderExecutionPlan::AudioStt(_) => AUDIO_STT_PROVIDER_ID,
        ProviderExecutionPlan::YouTubeWatchTranscript(_) => YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID,
    }
}

fn transcript_candidate_state_mut<'a>(
    subtitle_candidate: &'a mut MediaProviderCandidateState,
    audio_candidate: &'a mut MediaProviderCandidateState,
    youtube_watch_candidate: &'a mut MediaProviderCandidateState,
    selected_plan: &ProviderExecutionPlan,
) -> &'a mut MediaProviderCandidateState {
    match selected_plan {
        ProviderExecutionPlan::Subtitle(_) => subtitle_candidate,
        ProviderExecutionPlan::AudioStt(_) => audio_candidate,
        ProviderExecutionPlan::YouTubeWatchTranscript(_) => youtube_watch_candidate,
    }
}

async fn execute_transcript_plan(
    requested_url: &str,
    requested_language: &str,
    tool_home: &Path,
    browser: Arc<BrowserDriver>,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    run_dir: &Path,
    selected_plan: ProviderExecutionPlan,
) -> Result<ExecutedTranscript> {
    match selected_plan {
        ProviderExecutionPlan::Subtitle(selection) => {
            let ytdlp = ytdlp_discovery
                .map(|value| &value.provider)
                .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing subtitle execution selected without yt-dlp discovery"))?;
            let subtitle_path =
                download_selected_subtitle(ytdlp, requested_url, &selection, run_dir).await?;
            let raw_vtt = fs::read_to_string(&subtitle_path).with_context(|| {
                format!(
                    "ERROR_CLASS=VerificationMissing failed to read subtitle file {}",
                    subtitle_path.display()
                )
            })?;
            let segments = parse_webvtt_segments(&raw_vtt);
            if segments.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing parsed transcript contained no subtitle segments."
                ));
            }
            Ok(ExecutedTranscript {
                provider_id: SUBTITLE_PROVIDER_ID,
                provider_version: ytdlp.version.to_string(),
                backend: "edge:media:yt_dlp_subtitles",
                transcript_language: selection.language_key,
                transcript_source_kind: selection.source_kind.to_string(),
                provider_model_id: None,
                provider_model_path: None,
                selected_audio_format_id: None,
                selected_audio_ext: None,
                selected_audio_acodec: None,
                segments,
            })
        }
        ProviderExecutionPlan::AudioStt(selection) => {
            let ytdlp = ytdlp_discovery
                .map(|value| &value.provider)
                .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing audio transcription selected without yt-dlp discovery"))?;
            let audio_path =
                download_selected_audio(ytdlp, requested_url, &selection, run_dir).await?;
            let model = ensure_managed_whisper_model(tool_home).await?;
            let segments = transcribe_audio_with_managed_whisper(
                &model,
                &audio_path,
                whisper_language_code(requested_language),
            )
            .await?;
            if segments.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing audio transcription produced no transcript segments."
                ));
            }
            Ok(ExecutedTranscript {
                provider_id: AUDIO_STT_PROVIDER_ID,
                provider_version: format!(
                    "yt-dlp={};model={}@{}",
                    ytdlp.version, model.model_id, model.revision
                ),
                backend: "edge:media:yt_dlp_whisper_rs",
                transcript_language: whisper_language_code(requested_language).to_string(),
                transcript_source_kind: "stt".to_string(),
                provider_model_id: Some(model.model_id.to_string()),
                provider_model_path: Some(model.model_path.to_string_lossy().to_string()),
                selected_audio_format_id: Some(selection.format_id),
                selected_audio_ext: Some(selection.ext),
                selected_audio_acodec: Some(selection.acodec),
                segments,
            })
        }
        ProviderExecutionPlan::YouTubeWatchTranscript(selection) => {
            let transcript_json =
                fetch_youtube_watch_transcript_json(browser.as_ref(), requested_url, &selection)
                    .await?;
            let segments = parse_youtube_transcript_segments(&transcript_json);
            if segments.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing youtube watch transcript returned no transcript segments."
                ));
            }
            Ok(ExecutedTranscript {
                provider_id: YOUTUBE_WATCH_TRANSCRIPT_PROVIDER_ID,
                provider_version: youtube_watch_provider_version(&selection.client_context),
                backend: "edge:media:youtube_watch_transcript",
                transcript_language: requested_language.to_string(),
                transcript_source_kind: "watch_transcript".to_string(),
                provider_model_id: None,
                provider_model_path: None,
                selected_audio_format_id: None,
                selected_audio_ext: None,
                selected_audio_acodec: None,
                segments,
            })
        }
    }
}

fn extract_timeline_artifact(
    requested_url: &str,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
) -> (Vec<MediaProviderCandidate>, Option<TimelineArtifact>) {
    let Some(context) = watch_page else {
        return (
            vec![media_provider_candidate_receipt_with_modality(
                YOUTUBE_TIMELINE_PROVIDER_ID,
                requested_url,
                "timeline",
                false,
                false,
                watch_page_failure_reason.map(str::to_string),
            )],
            None,
        );
    };
    if context.chapter_thumbnails.is_empty() {
        return (
            vec![media_provider_candidate_receipt_with_modality(
                YOUTUBE_TIMELINE_PROVIDER_ID,
                requested_url,
                "timeline",
                false,
                false,
                Some("timeline_cues_unavailable".to_string()),
            )],
            None,
        );
    }

    let cues = context
        .chapter_thumbnails
        .iter()
        .map(|chapter| MediaTimelineCue {
            timestamp_ms: chapter.start_ms,
            timestamp_label: render_timestamp(chapter.start_ms),
            title: chapter.title.clone(),
            thumbnail_url: Some(chapter.thumbnail_url.clone()),
        })
        .collect::<Vec<_>>();
    let timeline_text = cues
        .iter()
        .map(|cue| format!("[{}] {}", cue.timestamp_label, cue.title))
        .collect::<Vec<_>>()
        .join("\n");
    if timeline_text.trim().is_empty() {
        return (
            vec![media_provider_candidate_receipt_with_modality(
                YOUTUBE_TIMELINE_PROVIDER_ID,
                requested_url,
                "timeline",
                false,
                false,
                Some("timeline_text_empty".to_string()),
            )],
            None,
        );
    }

    let provider_version = youtube_watch_provider_version(&context.client_context);
    let retrieved_at_ms = now_ms();
    let timeline_hash = sha256_hex(timeline_text.as_bytes());
    let mut provider_candidate = media_provider_candidate_receipt_with_modality(
        YOUTUBE_TIMELINE_PROVIDER_ID,
        requested_url,
        "timeline",
        true,
        true,
        None,
    );
    provider_candidate.execution_attempted = Some(true);
    provider_candidate.execution_satisfied = Some(true);

    let bundle = MediaTimelineOutlineBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_multimodal_evidence".to_string(),
        backend: "edge:media:youtube_key_moments_timeline".to_string(),
        provider_id: YOUTUBE_TIMELINE_PROVIDER_ID.to_string(),
        provider_version: provider_version.clone(),
        requested_url: requested_url.to_string(),
        canonical_url: context.canonical_url.clone(),
        provider_candidates: vec![provider_candidate.clone()],
        title: context.title.clone(),
        duration_seconds: context.duration_seconds,
        timeline_source_kind: "key_moments".to_string(),
        cue_count: cues.len() as u32,
        timeline_char_count: timeline_text.chars().count() as u32,
        timeline_hash: timeline_hash.clone(),
        timeline_text,
        cues,
    };
    let receipt = MediaMultimodalRunReceipt {
        timeline_provider_id: Some(YOUTUBE_TIMELINE_PROVIDER_ID.to_string()),
        timeline_provider_version: Some(provider_version),
        timeline_source_kind: Some("key_moments".to_string()),
        timeline_cue_count: Some(bundle.cue_count),
        timeline_char_count: Some(bundle.timeline_char_count),
        timeline_hash: Some(timeline_hash),
        ..MediaMultimodalRunReceipt::default()
    };
    (
        vec![provider_candidate],
        Some(TimelineArtifact { bundle, receipt }),
    )
}
