async fn extract_visual_artifact(
    requested_url: &str,
    frame_limit: u32,
    tool_home: &Path,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    ytdlp_failure_reason: Option<&str>,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
    transcript_segments: Option<&[TranscriptSegment]>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<(Vec<MediaProviderCandidate>, Option<VisualArtifact>)> {
    let vision_probe = match probe_vision_runtime(inference.clone()).await {
        Ok(value) => value,
        Err(err) => {
            let challenge_reason = provider_reason_from_error(&err);
            return Ok((
                vec![
                    failed_visual_candidate_state(
                        VISUAL_PROVIDER_ID,
                        requested_url,
                        Some(challenge_reason.clone()),
                    ),
                    failed_visual_candidate_state(
                        YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
                        requested_url,
                        Some(challenge_reason),
                    ),
                ]
                .into_iter()
                .map(|state| state.candidate)
                .collect(),
                None,
            ));
        }
    };
    if !vision_probe {
        return Ok((
            vec![
                failed_visual_candidate_state(
                    VISUAL_PROVIDER_ID,
                    requested_url,
                    Some("vision_runtime_probe_unsatisfied".to_string()),
                ),
                failed_visual_candidate_state(
                    YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
                    requested_url,
                    Some("vision_runtime_probe_unsatisfied".to_string()),
                ),
            ]
            .into_iter()
            .map(|state| state.candidate)
            .collect(),
            None,
        ));
    }

    let mut managed_frames_candidate = discover_managed_frames_candidate(
        requested_url,
        tool_home,
        ytdlp_discovery,
        ytdlp_failure_reason,
    )
    .await?;
    let mut chapter_thumbnail_candidate = discover_youtube_chapter_thumbnail_candidate(
        requested_url,
        watch_page,
        watch_page_failure_reason,
    );

    let selected_plans =
        select_visual_provider_plans(&managed_frames_candidate, &chapter_thumbnail_candidate);
    let provider_candidates_without_execution = vec![
        managed_frames_candidate.candidate.clone(),
        chapter_thumbnail_candidate.candidate.clone(),
    ];
    if selected_plans.is_empty() {
        return Ok((provider_candidates_without_execution, None));
    }

    let run_dir = prepare_run_dir(tool_home)?;
    let mut last_failure = None::<VisualExecutionFailure>;
    let mut executed = None::<ExecutedVisualEvidence>;
    for selected_plan in selected_plans {
        let selected_candidate = visual_candidate_state_mut(
            &mut managed_frames_candidate,
            &mut chapter_thumbnail_candidate,
            &selected_plan,
        );
        selected_candidate.candidate.execution_attempted = Some(true);
        match execute_visual_plan(
            requested_url,
            frame_limit,
            ytdlp_discovery,
            transcript_segments,
            &run_dir,
            selected_plan.clone(),
            inference.clone(),
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
                last_failure = Some(VisualExecutionFailure {
                    provider_id: visual_provider_id(&selected_plan),
                    error: err,
                });
            }
        }
    }

    let Some(executed) = executed else {
        let failure = last_failure.ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal media visual execution exhausted admissible providers for url={}",
                requested_url
            )
        })?;
        return Err(failure.error.context(format!(
            "visual provider execution exhausted admissible plan set after provider_id={}",
            failure.provider_id
        )));
    };

    let provider_candidates = vec![
        managed_frames_candidate.candidate.clone(),
        chapter_thumbnail_candidate.candidate.clone(),
    ];
    let visual_summary = build_visual_summary(&executed.frame_evidence);
    let visual_hash = sha256_hex(visual_summary.as_bytes());
    let visual_char_count = executed
        .frame_evidence
        .iter()
        .map(|frame| frame.scene_summary.chars().count() + frame.visible_text.chars().count())
        .sum::<usize>() as u32;
    let retrieved_at_ms = now_ms();
    let bundle = MediaVisualEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms,
        tool: "media__extract_evidence".to_string(),
        backend: executed.backend.to_string(),
        provider_id: executed.provider_id.to_string(),
        provider_version: executed.provider_version.clone(),
        requested_url: requested_url.to_string(),
        canonical_url: executed.canonical_url.clone(),
        provider_candidates: provider_candidates.clone(),
        title: executed.title.clone(),
        duration_seconds: executed.duration_seconds,
        frame_count: executed.frame_evidence.len() as u32,
        visual_char_count,
        visual_hash: visual_hash.clone(),
        visual_summary: visual_summary.clone(),
        frames: executed.frame_evidence,
    };
    let receipt = MediaMultimodalRunReceipt {
        visual_provider_id: Some(executed.provider_id.to_string()),
        visual_provider_version: Some(executed.provider_version),
        visual_provider_binary_path: executed.provider_binary_path,
        visual_ffprobe_path: executed.ffprobe_path,
        visual_selected_video_format_id: executed.selected_video_format_id,
        visual_selected_video_ext: executed.selected_video_ext,
        visual_selected_video_codec: executed.selected_video_codec,
        visual_frame_count: Some(bundle.frame_count),
        visual_char_count: Some(visual_char_count),
        visual_hash: Some(visual_hash),
        visual_summary_char_count: Some(visual_summary.chars().count() as u32),
        ..MediaMultimodalRunReceipt::default()
    };

    Ok((
        provider_candidates,
        Some(VisualArtifact { bundle, receipt }),
    ))
}

async fn discover_managed_frames_candidate(
    request_url: &str,
    tool_home: &Path,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    ytdlp_failure_reason: Option<&str>,
) -> Result<VisualProviderCandidateState> {
    let Some(ytdlp_discovery) = ytdlp_discovery else {
        return Ok(failed_visual_candidate_state(
            VISUAL_PROVIDER_ID,
            request_url,
            ytdlp_failure_reason.map(str::to_string),
        ));
    };
    let ffmpeg = match ensure_managed_ffmpeg_provider(tool_home).await {
        Ok(provider) => provider,
        Err(err) => {
            return Ok(failed_visual_candidate_state(
                VISUAL_PROVIDER_ID,
                request_url,
                Some(provider_reason_from_error(&err)),
            ));
        }
    };
    let Some(video_format) = select_video_format(&ytdlp_discovery.metadata) else {
        return Ok(failed_visual_candidate_state(
            VISUAL_PROVIDER_ID,
            request_url,
            Some("supported_video_format_unavailable".to_string()),
        ));
    };
    let duration_seconds = ytdlp_discovery
        .metadata
        .get("duration")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if duration_seconds == 0 {
        return Ok(failed_visual_candidate_state(
            VISUAL_PROVIDER_ID,
            request_url,
            Some("duration_unavailable".to_string()),
        ));
    }

    Ok(VisualProviderCandidateState {
        candidate: media_provider_candidate_receipt_with_modality(
            VISUAL_PROVIDER_ID,
            request_url,
            "visual",
            false,
            true,
            None,
        ),
        plan: Some(VisualProviderExecutionPlan::ManagedFrames {
            ffmpeg,
            video_format,
        }),
    })
}

fn discover_youtube_chapter_thumbnail_candidate(
    request_url: &str,
    watch_page: Option<&YouTubeWatchPageContext>,
    watch_page_failure_reason: Option<&str>,
) -> VisualProviderCandidateState {
    let Some(context) = watch_page else {
        return failed_visual_candidate_state(
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
            request_url,
            watch_page_failure_reason.map(str::to_string),
        );
    };
    if context.chapter_thumbnails.is_empty() {
        return failed_visual_candidate_state(
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
            request_url,
            Some("chapter_thumbnails_unavailable".to_string()),
        );
    }
    VisualProviderCandidateState {
        candidate: media_provider_candidate_receipt_with_modality(
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
            request_url,
            "visual",
            false,
            true,
            None,
        ),
        plan: Some(VisualProviderExecutionPlan::YouTubeChapterThumbnails {
            provider_version: youtube_watch_provider_version(&context.client_context),
            title: context.title.clone(),
            canonical_url: context.canonical_url.clone(),
            duration_seconds: context.duration_seconds,
            chapter_thumbnails: context.chapter_thumbnails.clone(),
        }),
    }
}

fn failed_visual_candidate_state(
    provider_id: &str,
    request_url: &str,
    challenge_reason: Option<String>,
) -> VisualProviderCandidateState {
    VisualProviderCandidateState {
        candidate: media_provider_candidate_receipt_with_modality(
            provider_id,
            request_url,
            "visual",
            false,
            false,
            challenge_reason,
        ),
        plan: None,
    }
}

fn select_visual_provider_plans(
    managed_frames_candidate: &VisualProviderCandidateState,
    chapter_thumbnail_candidate: &VisualProviderCandidateState,
) -> Vec<VisualProviderExecutionPlan> {
    let mut plans = Vec::new();
    if let Some(plan) = managed_frames_candidate.plan.clone() {
        plans.push(plan);
    }
    if let Some(plan) = chapter_thumbnail_candidate.plan.clone() {
        plans.push(plan);
    }
    plans
}

fn visual_provider_id(plan: &VisualProviderExecutionPlan) -> &'static str {
    match plan {
        VisualProviderExecutionPlan::ManagedFrames { .. } => VISUAL_PROVIDER_ID,
        VisualProviderExecutionPlan::YouTubeChapterThumbnails { .. } => {
            YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID
        }
    }
}

fn visual_candidate_state_mut<'a>(
    managed_frames_candidate: &'a mut VisualProviderCandidateState,
    chapter_thumbnail_candidate: &'a mut VisualProviderCandidateState,
    selected_plan: &VisualProviderExecutionPlan,
) -> &'a mut VisualProviderCandidateState {
    match selected_plan {
        VisualProviderExecutionPlan::ManagedFrames { .. } => managed_frames_candidate,
        VisualProviderExecutionPlan::YouTubeChapterThumbnails { .. } => chapter_thumbnail_candidate,
    }
}

async fn execute_visual_plan(
    requested_url: &str,
    frame_limit: u32,
    ytdlp_discovery: Option<&ManagedYtDlpDiscovery>,
    transcript_segments: Option<&[TranscriptSegment]>,
    run_dir: &Path,
    selected_plan: VisualProviderExecutionPlan,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutedVisualEvidence> {
    match selected_plan {
        VisualProviderExecutionPlan::ManagedFrames {
            ffmpeg,
            video_format,
        } => {
            let ytdlp_discovery = ytdlp_discovery.ok_or_else(|| {
                anyhow!(
                    "ERROR_CLASS=DiscoveryMissing visual managed-frames execution selected without yt-dlp discovery"
                )
            })?;
            let video_path = download_selected_video(
                &ytdlp_discovery.provider,
                requested_url,
                &video_format,
                run_dir,
            )
            .await?;
            let duration_seconds = ytdlp_discovery
                .metadata
                .get("duration")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    anyhow!(
                        "ERROR_CLASS=VerificationMissing visual sampling requires a positive media duration."
                    )
                })?;
            let timestamps_ms =
                sample_visual_frame_timestamps(duration_seconds, frame_limit as usize);
            if timestamps_ms.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual sampling produced no frame timestamps."
                ));
            }
            let frame_samples =
                extract_visual_frame_samples(&ffmpeg, &video_path, &timestamps_ms, run_dir).await?;
            let frame_evidence =
                analyze_visual_frame_samples(&frame_samples, transcript_segments, inference)
                    .await?;
            if frame_evidence.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis produced no observations."
                ));
            }
            Ok(ExecutedVisualEvidence {
                provider_id: VISUAL_PROVIDER_ID,
                provider_version: ffmpeg.version.to_string(),
                backend: "edge:media:ffmpeg_vision",
                provider_binary_path: Some(ffmpeg.ffmpeg_path.to_string_lossy().to_string()),
                ffprobe_path: Some(ffmpeg.ffprobe_path.to_string_lossy().to_string()),
                selected_video_format_id: Some(video_format.format_id),
                selected_video_ext: Some(video_format.ext),
                selected_video_codec: Some(video_format.vcodec),
                canonical_url: ytdlp_discovery
                    .metadata
                    .get("webpage_url")
                    .or_else(|| ytdlp_discovery.metadata.get("original_url"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .unwrap_or(requested_url)
                    .to_string(),
                title: ytdlp_discovery
                    .metadata
                    .get("title")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string),
                duration_seconds: Some(duration_seconds),
                frame_evidence,
            })
        }
        VisualProviderExecutionPlan::YouTubeChapterThumbnails {
            provider_version,
            title,
            canonical_url,
            duration_seconds,
            chapter_thumbnails,
        } => {
            let selected_chapters = sample_chapter_thumbnails(&chapter_thumbnails, frame_limit);
            if selected_chapters.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing chapter thumbnail sampling produced no frames."
                ));
            }
            let frame_samples = download_chapter_thumbnail_samples(&selected_chapters).await?;
            let frame_evidence =
                analyze_visual_frame_samples(&frame_samples, transcript_segments, inference)
                    .await?;
            if frame_evidence.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis produced no observations."
                ));
            }
            Ok(ExecutedVisualEvidence {
                provider_id: YOUTUBE_CHAPTER_THUMBNAIL_PROVIDER_ID,
                provider_version,
                backend: "edge:media:youtube_chapter_thumbnails_vision",
                provider_binary_path: None,
                ffprobe_path: None,
                selected_video_format_id: None,
                selected_video_ext: None,
                selected_video_codec: None,
                canonical_url,
                title,
                duration_seconds,
                frame_evidence,
            })
        }
    }
}
