async fn fetch_ytdlp_metadata(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    run_dir: &Path,
) -> Result<Value> {
    let args = vec![
        "--dump-single-json".to_string(),
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--skip-download".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        request_url.to_string(),
    ];
    let output = run_managed_ytdlp(provider, &args, run_dir, YTDLP_METADATA_TIMEOUT_SECS).await?;
    serde_json::from_slice::<Value>(&output.stdout).with_context(|| {
        format!(
            "ERROR_CLASS=VerificationMissing failed to parse yt-dlp metadata json stdout={} stderr={}",
            truncate_log(&String::from_utf8_lossy(&output.stdout), 300),
            truncate_log(&String::from_utf8_lossy(&output.stderr), 300)
        )
    })
}

#[derive(Debug, Deserialize)]
struct BrowserFetchJsonResponse {
    status: u16,
    body: String,
}

async fn fetch_youtube_watch_transcript_json(
    browser: &BrowserDriver,
    request_url: &str,
    selection: &YouTubeWatchTranscriptSelection,
) -> Result<Value> {
    browser
        .navigate_retrieval(request_url)
        .await
        .map_err(|err| anyhow!("ERROR_CLASS=ExecutionFailedTerminal failed to load youtube watch page in browser context: {}", err))?;

    let endpoint = format!(
        "/youtubei/v1/get_transcript?prettyPrint=false&key={}",
        selection.api_key
    );
    let payload = json!({
        "context": selection.client_context,
        "params": selection.transcript_params,
    });
    let script = format!(
        r#"(async () => {{
            const ytcfgGet =
                typeof window !== "undefined" && window.ytcfg && typeof window.ytcfg.get === "function"
                    ? (key) => window.ytcfg.get(key)
                    : () => undefined;
            const clientName =
                ytcfgGet("INNERTUBE_CONTEXT_CLIENT_NAME")
                ?? ytcfgGet("INNERTUBE_CONTEXT_CLIENT_NAME_INT")
                ?? {client_name};
            const clientVersion =
                ytcfgGet("INNERTUBE_CONTEXT_CLIENT_VERSION")
                ?? {client_version};
            const visitorData =
                ytcfgGet("VISITOR_DATA")
                ?? {visitor_data};
            const authUser =
                ytcfgGet("SESSION_INDEX")
                ?? ytcfgGet("LOGGED_IN_USER_INDEX");
            const delegatedSessionId = ytcfgGet("DELEGATED_SESSION_ID");
            const payload = {payload};
            if (delegatedSessionId) {{
                payload.context = payload.context || {{}};
                payload.context.user = payload.context.user || {{}};
                payload.context.user.delegatedSessionId = String(delegatedSessionId);
            }}
            const headers = {{
                "content-type": "application/json"
            }};
            if (clientName !== undefined && clientName !== null && String(clientName).trim() !== "") {{
                headers["x-youtube-client-name"] = String(clientName);
            }}
            if (clientVersion !== undefined && clientVersion !== null && String(clientVersion).trim() !== "") {{
                headers["x-youtube-client-version"] = String(clientVersion);
            }}
            if (visitorData !== undefined && visitorData !== null && String(visitorData).trim() !== "") {{
                headers["x-goog-visitor-id"] = String(visitorData);
            }}
            if (authUser !== undefined && authUser !== null && String(authUser).trim() !== "") {{
                headers["x-goog-authuser"] = String(authUser);
            }}
            if (typeof location !== "undefined" && location.origin) {{
                headers["x-origin"] = location.origin;
            }}
            const response = await fetch({endpoint}, {{
                method: "POST",
                credentials: "include",
                headers,
                body: JSON.stringify(payload)
            }});
            return {{
                status: response.status,
                body: await response.text()
            }};
        }})()"#,
        endpoint = serde_json::to_string(&endpoint).unwrap_or_else(|_| "\"\"".to_string()),
        payload = payload,
        client_name = selection
            .client_context
            .get("client")
            .and_then(|value| value.get("clientName"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "null".to_string()),
        client_version = selection
            .client_context
            .get("client")
            .and_then(|value| value.get("clientVersion"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "null".to_string()),
        visitor_data = selection
            .client_context
            .get("client")
            .and_then(|value| value.get("visitorData"))
            .map(ToString::to_string)
            .unwrap_or_else(|| "null".to_string())
    );
    let response: BrowserFetchJsonResponse =
        browser
            .evaluate_retrieval_js(&script)
            .await
            .map_err(|err| {
                anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal browser transcript fetch failed: {}",
                    err
                )
            })?;
    if response.status != 200 {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal youtube watch transcript request failed status={} body={}",
            response.status,
            truncate_log(&response.body, 300)
        ));
    }
    serde_json::from_str::<Value>(&response.body).with_context(|| {
        format!(
            "ERROR_CLASS=VerificationMissing failed to parse youtube transcript json {}",
            truncate_log(&response.body, 300)
        )
    })
}

fn parse_youtube_transcript_segments(payload: &Value) -> Vec<TranscriptSegment> {
    let mut segments = Vec::new();
    collect_youtube_transcript_segments(payload, &mut segments);
    segments.sort_by_key(|segment| segment.start_ms);
    segments.dedup_by(|left, right| left.start_ms == right.start_ms || left.text == right.text);
    segments
}

fn collect_youtube_transcript_segments(value: &Value, output: &mut Vec<TranscriptSegment>) {
    match value {
        Value::Object(map) => {
            if let Some(renderer) = map.get("transcriptSegmentRenderer") {
                let start_ms = renderer
                    .get("startMs")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<u64>().ok());
                let text = renderer
                    .get("snippet")
                    .and_then(value_text)
                    .map(|value| compact_ws(&value))
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty());
                if let (Some(start_ms), Some(text)) = (start_ms, text) {
                    output.push(TranscriptSegment { start_ms, text });
                }
            }
            for nested in map.values() {
                collect_youtube_transcript_segments(nested, output);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_youtube_transcript_segments(nested, output);
            }
        }
        _ => {}
    }
}

fn sample_chapter_thumbnails(
    chapter_thumbnails: &[YouTubeChapterThumbnail],
    frame_limit: u32,
) -> Vec<YouTubeChapterThumbnail> {
    sample_sequence_indices(chapter_thumbnails.len(), frame_limit as usize)
        .into_iter()
        .filter_map(|index| chapter_thumbnails.get(index).cloned())
        .collect()
}

fn sample_sequence_indices(total: usize, count: usize) -> Vec<usize> {
    if total == 0 || count == 0 {
        return Vec::new();
    }
    if count >= total {
        return (0..total).collect();
    }
    if count == 1 {
        return vec![0];
    }

    let span = total.saturating_sub(1);
    let denominator = count.saturating_sub(1);
    let mut indices = (0..count)
        .map(|idx| ((idx * span) + (denominator / 2)) / denominator)
        .collect::<Vec<_>>();
    indices.sort_unstable();
    indices.dedup();
    indices
}

async fn download_chapter_thumbnail_samples(
    chapter_thumbnails: &[YouTubeChapterThumbnail],
) -> Result<Vec<VisualFrameSample>> {
    let client = reqwest::Client::builder()
        .redirect(redirect::Policy::limited(5))
        .timeout(Duration::from_secs(45))
        .build()
        .context("ERROR_CLASS=SynthesisFailed failed to initialize chapter thumbnail client")?;
    let mut samples = Vec::with_capacity(chapter_thumbnails.len());
    for chapter in chapter_thumbnails {
        let response = client
            .get(&chapter.thumbnail_url)
            .header(
                header::USER_AGENT,
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            )
            .send()
            .await
            .with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to fetch chapter thumbnail {}",
                    chapter.thumbnail_url
                )
            })?
            .error_for_status()
            .with_context(|| {
                format!(
                    "ERROR_CLASS=ExecutionFailedTerminal chapter thumbnail request returned error status {}",
                    chapter.thumbnail_url
                )
            })?;
        let bytes = response.bytes().await.context(
            "ERROR_CLASS=ExecutionFailedTerminal failed to read chapter thumbnail bytes",
        )?;
        if bytes.is_empty() {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing chapter thumbnail bytes were empty."
            ));
        }
        let image = image::load_from_memory(&bytes)
            .context("ERROR_CLASS=VerificationMissing failed to decode chapter thumbnail bytes")?;
        let (width, height) = image.dimensions();
        let format = image::guess_format(&bytes).unwrap_or(ImageFormat::Jpeg);
        samples.push(VisualFrameSample {
            timestamp_ms: chapter.start_ms,
            timestamp_label: render_timestamp(chapter.start_ms),
            frame_hash: sha256_hex(bytes.as_ref()),
            mime_type: image_format_mime_type(format).to_string(),
            width,
            height,
            bytes: bytes.to_vec(),
        });
    }
    Ok(samples)
}

fn image_format_mime_type(format: ImageFormat) -> &'static str {
    match format {
        ImageFormat::Png => "image/png",
        ImageFormat::Gif => "image/gif",
        ImageFormat::WebP => "image/webp",
        ImageFormat::Bmp => "image/bmp",
        _ => "image/jpeg",
    }
}

async fn download_selected_subtitle(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    selection: &SubtitleSelection,
    run_dir: &Path,
) -> Result<PathBuf> {
    let mut args = vec![
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--skip-download".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        "--convert-subs".to_string(),
        "vtt".to_string(),
        "--sub-langs".to_string(),
        selection.language_key.clone(),
        "-o".to_string(),
        run_dir
            .join("transcript.%(ext)s")
            .to_string_lossy()
            .to_string(),
    ];
    if selection.source_kind == "manual" {
        args.push("--write-subs".to_string());
    } else {
        args.push("--write-auto-subs".to_string());
    }
    args.push(request_url.to_string());

    let _ = run_managed_ytdlp(provider, &args, run_dir, YTDLP_SUBTITLE_TIMEOUT_SECS).await?;
    fs::read_dir(run_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to inspect subtitle directory {}",
                run_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("vtt"))
        .ok_or_else(|| {
            anyhow!(
                "ERROR_CLASS=VerificationMissing yt-dlp did not materialize a .vtt subtitle file."
            )
        })
}

async fn download_selected_audio(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    selection: &AudioFormatSelection,
    run_dir: &Path,
) -> Result<PathBuf> {
    let args = vec![
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        "-f".to_string(),
        selection.format_id.clone(),
        "-o".to_string(),
        run_dir.join("audio.%(ext)s").to_string_lossy().to_string(),
        request_url.to_string(),
    ];
    let _ = run_managed_ytdlp(provider, &args, run_dir, YTDLP_AUDIO_TIMEOUT_SECS).await?;
    fs::read_dir(run_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to inspect audio directory {}",
                run_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("audio.")
                            && !name.ends_with(".part")
                            && !name.ends_with(".ytdl")
                    })
        })
        .ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing yt-dlp did not materialize an audio file.")
        })
}

async fn download_selected_video(
    provider: &ManagedYtDlpProvider,
    request_url: &str,
    selection: &VideoFormatSelection,
    run_dir: &Path,
) -> Result<PathBuf> {
    let args = vec![
        "--no-warnings".to_string(),
        "--no-config".to_string(),
        "--no-playlist".to_string(),
        "--socket-timeout".to_string(),
        "20".to_string(),
        "--cache-dir".to_string(),
        run_dir.join("cache").to_string_lossy().to_string(),
        "-f".to_string(),
        selection.format_id.clone(),
        "-o".to_string(),
        run_dir.join("video.%(ext)s").to_string_lossy().to_string(),
        request_url.to_string(),
    ];
    let _ = run_managed_ytdlp(provider, &args, run_dir, YTDLP_VIDEO_TIMEOUT_SECS).await?;
    fs::read_dir(run_dir)
        .with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to inspect video directory {}",
                run_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        name.starts_with("video.")
                            && !name.ends_with(".part")
                            && !name.ends_with(".ytdl")
                    })
        })
        .ok_or_else(|| {
            anyhow!("ERROR_CLASS=VerificationMissing yt-dlp did not materialize a video file.")
        })
}

struct CommandOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_managed_ytdlp(
    provider: &ManagedYtDlpProvider,
    args: &[String],
    run_dir: &Path,
    timeout_secs: u64,
) -> Result<CommandOutput> {
    let mut command = Command::new(&provider.binary_path);
    command
        .args(args)
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(timeout_secs), command.output())
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal yt-dlp timed out after {}s asset={}",
                timeout_secs,
                provider.asset_name
            )
        })?
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to launch managed yt-dlp binary {}",
                provider.binary_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal managed yt-dlp failed status={} stdout={} stderr={}",
            output.status,
            truncate_log(&String::from_utf8_lossy(&output.stdout), 400),
            truncate_log(&String::from_utf8_lossy(&output.stderr), 400)
        ));
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

async fn run_managed_ffmpeg(
    binary_path: &Path,
    args: &[String],
    run_dir: &Path,
    timeout_secs: u64,
) -> Result<CommandOutput> {
    let mut command = Command::new(binary_path);
    command
        .args(args)
        .current_dir(run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(timeout_secs), command.output())
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal ffmpeg timed out after {}s binary={}",
                timeout_secs,
                binary_path.display()
            )
        })?
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to launch managed ffmpeg binary {}",
                binary_path.display()
            )
        })?;
    if !output.status.success() {
        return Err(anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal managed ffmpeg failed status={} stdout={} stderr={}",
            output.status,
            truncate_log(&String::from_utf8_lossy(&output.stdout), 400),
            truncate_log(&String::from_utf8_lossy(&output.stderr), 400)
        ));
    }
    Ok(CommandOutput {
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn sample_visual_frame_timestamps(duration_seconds: u64, frame_count: usize) -> Vec<u64> {
    if duration_seconds == 0 || frame_count == 0 {
        return Vec::new();
    }
    let duration_ms = duration_seconds.saturating_mul(1_000);
    let start_ms = duration_ms / 20;
    let end_ms = duration_ms.saturating_sub(duration_ms / 20);
    if frame_count == 1 || start_ms >= end_ms {
        return vec![start_ms.min(duration_ms.saturating_sub(1))];
    }

    let span = end_ms.saturating_sub(start_ms);
    (0..frame_count)
        .map(|idx| {
            let ratio = idx as f64 / (frame_count.saturating_sub(1)) as f64;
            start_ms.saturating_add((span as f64 * ratio).round() as u64)
        })
        .collect()
}

async fn extract_visual_frame_samples(
    provider: &ManagedFfmpegProvider,
    video_path: &Path,
    timestamps_ms: &[u64],
    run_dir: &Path,
) -> Result<Vec<VisualFrameSample>> {
    let mut samples = Vec::with_capacity(timestamps_ms.len());
    for (idx, timestamp_ms) in timestamps_ms.iter().copied().enumerate() {
        let output_path = run_dir.join(format!("frame_{idx:02}.jpg"));
        let args = vec![
            "-hide_banner".to_string(),
            "-loglevel".to_string(),
            "error".to_string(),
            "-nostdin".to_string(),
            "-y".to_string(),
            "-ss".to_string(),
            ffmpeg_seek_timestamp(timestamp_ms),
            "-i".to_string(),
            video_path.to_string_lossy().to_string(),
            "-frames:v".to_string(),
            "1".to_string(),
            "-vf".to_string(),
            "scale=w=960:h=-2:force_original_aspect_ratio=decrease".to_string(),
            "-q:v".to_string(),
            "3".to_string(),
            output_path.to_string_lossy().to_string(),
        ];
        let _ = run_managed_ffmpeg(
            &provider.ffmpeg_path,
            &args,
            run_dir,
            FFMPEG_FRAME_TIMEOUT_SECS,
        )
        .await?;
        let bytes = fs::read(&output_path).with_context(|| {
            format!(
                "ERROR_CLASS=VerificationMissing failed to read extracted frame {}",
                output_path.display()
            )
        })?;
        if bytes.is_empty() {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing extracted frame bytes were empty."
            ));
        }
        let image = image::load_from_memory(&bytes).context(
            "ERROR_CLASS=VerificationMissing failed to decode extracted frame image bytes",
        )?;
        let (width, height) = image.dimensions();
        samples.push(VisualFrameSample {
            timestamp_ms,
            timestamp_label: render_timestamp(timestamp_ms),
            frame_hash: sha256_hex(&bytes),
            mime_type: "image/jpeg".to_string(),
            width,
            height,
            bytes,
        });
    }
    Ok(samples)
}

async fn analyze_visual_frame_samples(
    samples: &[VisualFrameSample],
    transcript_segments: Option<&[TranscriptSegment]>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<Vec<MediaFrameEvidence>> {
    let mut observations = Vec::with_capacity(samples.len());
    for batch in samples.chunks(MEDIA_VISUAL_BATCH_SIZE) {
        let messages = build_visual_analysis_messages(batch);
        let payload = serde_json::to_vec(&messages)
            .context("ERROR_CLASS=SynthesisFailed failed to serialize visual analysis prompt")?;
        let options = InferenceOptions {
            tools: Vec::new(),
            temperature: 0.0,
            json_mode: true,
            max_tokens: 700,
            required_finality_tier: Default::default(),
            sealed_finality_proof: None,
            canonical_collapse_object: None,
        };
        let raw = timeout(
            Duration::from_secs(VISION_PROBE_TIMEOUT_SECS),
            inference.execute_inference([0u8; 32], &payload, options),
        )
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal visual frame analysis timed out after {}s",
                VISION_PROBE_TIMEOUT_SECS
            )
        })?
        .map_err(|err| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal visual frame analysis failed: {}",
                err
            )
        })?;
        let value = parse_json_value(&raw)?;
        let observations_value = value
            .get("observations")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis returned no observations array."
                )
            })?;
        if observations_value.len() != batch.len() {
            return Err(anyhow!(
                "ERROR_CLASS=VerificationMissing visual frame analysis expected {} observations but received {}.",
                batch.len(),
                observations_value.len()
            ));
        }
        for (sample, observation) in batch.iter().zip(observations_value.iter()) {
            let timestamp_ms = observation
                .get("timestamp_ms")
                .and_then(Value::as_u64)
                .unwrap_or(sample.timestamp_ms);
            let scene_summary = compact_ws(
                observation
                    .get("scene_summary")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            if scene_summary.is_empty() {
                return Err(anyhow!(
                    "ERROR_CLASS=VerificationMissing visual frame analysis returned an empty scene summary."
                ));
            }
            let visible_text = compact_ws(
                observation
                    .get("visible_text")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            );
            let transcript_excerpt = transcript_segments
                .and_then(|segments| transcript_excerpt_near(segments, sample.timestamp_ms));
            observations.push(MediaFrameEvidence {
                timestamp_ms,
                timestamp_label: sample.timestamp_label.clone(),
                frame_hash: sample.frame_hash.clone(),
                mime_type: sample.mime_type.clone(),
                width: sample.width,
                height: sample.height,
                scene_summary,
                visible_text,
                transcript_excerpt,
            });
        }
    }
    Ok(observations)
}

fn build_visual_analysis_messages(samples: &[VisualFrameSample]) -> Value {
    let mut content = Vec::new();
    content.push(json!({
        "type": "text",
        "text": format!(
            "Analyze these sampled video frames and return JSON only with this schema: {{\"observations\":[{{\"timestamp_ms\":<u64>,\"scene_summary\":\"<literal concise description>\",\"visible_text\":\"<readable on-screen text or empty string>\"}}]}}. Rules: observations length must equal {}; preserve the provided timestamp_ms values exactly; do not speculate beyond visible frame content; if readable text is absent, use an empty string for visible_text.",
            samples.len()
        )
    }));
    for sample in samples {
        content.push(json!({
            "type": "text",
            "text": format!("Frame timestamp_ms={}", sample.timestamp_ms)
        }));
        content.push(json!({
            "type": "image_url",
            "image_url": {
                "url": format!("data:{};base64,{}", sample.mime_type, BASE64.encode(&sample.bytes))
            }
        }));
    }
    json!([{ "role": "user", "content": content }])
}

fn build_visual_summary(frames: &[MediaFrameEvidence]) -> String {
    frames
        .iter()
        .map(|frame| {
            if frame.visible_text.is_empty() {
                format!("[{}] {}", frame.timestamp_label, frame.scene_summary)
            } else {
                format!(
                    "[{}] {} Visible text: {}",
                    frame.timestamp_label, frame.scene_summary, frame.visible_text
                )
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn transcript_excerpt_near(segments: &[TranscriptSegment], timestamp_ms: u64) -> Option<String> {
    let window_start = timestamp_ms.saturating_sub(90_000);
    let window_end = timestamp_ms.saturating_add(90_000);
    let excerpt = segments
        .iter()
        .filter(|segment| segment.start_ms >= window_start && segment.start_ms <= window_end)
        .take(4)
        .map(|segment| segment.text.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let compact = compact_ws(&excerpt);
    (!compact.is_empty()).then_some(truncate_chars(&compact, 400))
}

fn ffmpeg_seek_timestamp(timestamp_ms: u64) -> String {
    format!("{:.3}", timestamp_ms as f64 / 1_000.0)
}

async fn probe_vision_runtime(inference: Arc<dyn InferenceRuntime>) -> Result<bool> {
    let probe_image_url = build_vision_probe_image_data_url()?;
    let prompt = json!([
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": "Return JSON only with {\"image_support\":true}. Do not add any other keys."
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": probe_image_url
                    }
                }
            ]
        }
    ]);
    let payload = serde_json::to_vec(&prompt)
        .context("ERROR_CLASS=SynthesisFailed failed to serialize vision probe prompt")?;
    let options = InferenceOptions {
        tools: Vec::new(),
        temperature: 0.0,
        json_mode: true,
        max_tokens: 60,
        required_finality_tier: Default::default(),
        sealed_finality_proof: None,
        canonical_collapse_object: None,
    };
    let raw = timeout(
        Duration::from_secs(VISION_PROBE_TIMEOUT_SECS),
        inference.execute_inference([0u8; 32], &payload, options),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal vision probe timed out after {}s",
            VISION_PROBE_TIMEOUT_SECS
        )
    })?
    .map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal vision probe failed: {}",
            err
        )
    })?;
    let value = parse_json_value(&raw)?;
    Ok(value
        .get("image_support")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn build_vision_probe_image_data_url() -> Result<String> {
    let probe = ImageBuffer::from_fn(64, 64, |x, y| {
        if (x / 8 + y / 8) % 2 == 0 {
            Rgb([240, 240, 240])
        } else {
            Rgb([32, 128, 224])
        }
    });
    let mut cursor = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(probe)
        .write_to(&mut cursor, ImageFormat::Jpeg)
        .context("ERROR_CLASS=SynthesisFailed failed to encode vision probe image")?;
    Ok(format!(
        "data:image/jpeg;base64,{}",
        BASE64.encode(cursor.into_inner())
    ))
}

fn parse_json_value(raw: &[u8]) -> Result<Value> {
    let raw_str = String::from_utf8(raw.to_vec())
        .context("ERROR_CLASS=VerificationMissing inference response was not valid utf-8")?;
    if let Ok(value) = serde_json::from_str::<Value>(&raw_str) {
        return Ok(value);
    }
    let trimmed = raw_str.trim();
    let start = trimmed.find('{').ok_or_else(|| {
        anyhow!("ERROR_CLASS=VerificationMissing inference response did not contain a json object")
    })?;
    let end = trimmed.rfind('}').ok_or_else(|| {
        anyhow!("ERROR_CLASS=VerificationMissing inference response did not contain a json object")
    })?;
    serde_json::from_str::<Value>(&trimmed[start..=end]).with_context(|| {
        format!(
            "ERROR_CLASS=VerificationMissing failed to parse inference json response {}",
            truncate_log(trimmed, 200)
        )
    })
}

async fn transcribe_audio_with_managed_whisper(
    model: &ManagedWhisperModel,
    audio_path: &Path,
    language: &str,
) -> Result<Vec<TranscriptSegment>> {
    let audio_path = audio_path.to_path_buf();
    let model_path = model.model_path.clone();
    let language = language.to_string();
    let job =
        spawn_blocking(move || transcribe_audio_blocking(&model_path, &audio_path, &language));
    timeout(Duration::from_secs(WHISPER_TRANSCRIBE_TIMEOUT_SECS), job)
        .await
        .map_err(|_| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal audio transcription timed out after {}s",
                WHISPER_TRANSCRIBE_TIMEOUT_SECS
            )
        })?
        .map_err(|err| {
            anyhow!(
                "ERROR_CLASS=ExecutionFailedTerminal audio transcription worker join failed: {}",
                err
            )
        })?
}

fn transcribe_audio_blocking(
    model_path: &Path,
    audio_path: &Path,
    language: &str,
) -> Result<Vec<TranscriptSegment>> {
    let pcm = decode_audio_to_whisper_pcm(audio_path)?;
    let context = WhisperContext::new_with_params(
        &model_path.to_string_lossy(),
        WhisperContextParameters::default(),
    )
    .map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to load whisper model {}: {}",
            model_path.display(),
            err
        )
    })?;
    let mut state = context.create_state().map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to create whisper state: {}",
            err
        )
    })?;

    let mut params = FullParams::new(SamplingStrategy::Greedy { best_of: 0 });
    let threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(2)
        .clamp(1, 6) as i32;
    params.set_n_threads(threads);
    params.set_translate(false);
    params.set_no_context(true);
    params.set_language(Some(language));
    params.set_print_special(false);
    params.set_print_progress(false);
    params.set_print_realtime(false);
    params.set_print_timestamps(false);

    state.full(params, &pcm).map_err(|err| {
        anyhow!(
            "ERROR_CLASS=ExecutionFailedTerminal whisper inference failed for {}: {}",
            audio_path.display(),
            err
        )
    })?;

    let mut segments = Vec::new();
    let mut last_text = String::new();
    for segment in state.as_iter() {
        let text = compact_ws(&segment.to_string());
        if text.is_empty() || text == last_text {
            continue;
        }
        last_text = text.clone();
        let start_ms = u64::try_from(segment.start_timestamp().max(0)).unwrap_or(0) * 10;
        segments.push(TranscriptSegment { start_ms, text });
    }
    Ok(segments)
}

fn decode_audio_to_whisper_pcm(path: &Path) -> Result<Vec<f32>> {
    let file = Box::new(File::open(path).with_context(|| {
        format!(
            "ERROR_CLASS=ExecutionFailedTerminal failed to open audio artifact {}",
            path.display()
        )
    })?);
    let mss = MediaSourceStream::new(file, Default::default());
    let mut hint = Hint::new();
    if let Some(extension) = path.extension().and_then(|value| value.to_str()) {
        hint.with_extension(extension);
    }

    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to probe audio format {}",
                path.display()
            )
        })?;
    let mut format = probed.format;
    let track_id = selected_audio_track_id(format.as_ref())?;
    let track = format
        .tracks()
        .iter()
        .find(|track| track.id == track_id)
        .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing selected audio track disappeared"))?;
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .with_context(|| {
            format!(
                "ERROR_CLASS=ExecutionFailedTerminal failed to create audio decoder for {}",
                path.display()
            )
        })?;

    let mut output = Vec::new();
    let mut resampler: Option<LinearResampler> = None;

    loop {
        let packet = match format.next_packet() {
            Ok(packet) => packet,
            Err(SymphoniaError::IoError(err)) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(SymphoniaError::ResetRequired) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal symphonia reset required for {}",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to read audio packet {}: {}",
                    path.display(),
                    err
                ));
            }
        };
        if packet.track_id() != track_id {
            continue;
        }

        match decoder.decode(&packet) {
            Ok(audio_buf) => {
                let spec = *audio_buf.spec();
                let channel_count = spec.channels.count();
                if channel_count == 0 {
                    continue;
                }
                let mut sample_buf = SampleBuffer::<f32>::new(audio_buf.capacity() as u64, spec);
                sample_buf.copy_interleaved_ref(audio_buf);
                let resampler = resampler.get_or_insert_with(|| {
                    LinearResampler::new(spec.rate, WHISPER_TARGET_SAMPLE_RATE)
                });
                if resampler.input_rate != spec.rate {
                    return Err(anyhow!(
                        "ERROR_CLASS=ExecutionFailedTerminal variable sample rate audio is unsupported for {}",
                        path.display()
                    ));
                }
                process_interleaved_chunk(
                    sample_buf.samples(),
                    channel_count,
                    resampler,
                    &mut output,
                );
            }
            Err(SymphoniaError::DecodeError(_)) => {}
            Err(SymphoniaError::IoError(err)) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(SymphoniaError::ResetRequired) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal symphonia decoder reset required for {}",
                    path.display()
                ));
            }
            Err(err) => {
                return Err(anyhow!(
                    "ERROR_CLASS=ExecutionFailedTerminal failed to decode audio {}: {}",
                    path.display(),
                    err
                ));
            }
        }
    }

    if let Some(resampler) = resampler.as_mut() {
        resampler.finish(&mut output);
    }
    if output.is_empty() {
        return Err(anyhow!(
            "ERROR_CLASS=VerificationMissing decoded audio contained no whisper-ready PCM samples."
        ));
    }
    Ok(output)
}

fn selected_audio_track_id(format: &dyn symphonia::core::formats::FormatReader) -> Result<u32> {
    if let Some(track) = format.default_track().filter(|track| is_audio_track(track)) {
        return Ok(track.id);
    }

    format
        .tracks()
        .iter()
        .find(|track| is_audio_track(track))
        .map(|track| track.id)
        .ok_or_else(|| anyhow!("ERROR_CLASS=DiscoveryMissing no decodable audio track found"))
}

fn is_audio_track(track: &symphonia::core::formats::Track) -> bool {
    track.codec_params.channels.is_some() || track.codec_params.sample_rate.is_some()
}

fn process_interleaved_chunk(
    samples: &[f32],
    channel_count: usize,
    resampler: &mut LinearResampler,
    output: &mut Vec<f32>,
) {
    if channel_count == 0 {
        return;
    }
    let mut mono = Vec::with_capacity(samples.len() / channel_count);
    for frame in samples.chunks(channel_count) {
        let sum = frame.iter().copied().sum::<f32>();
        mono.push(sum / channel_count as f32);
    }
    resampler.push(&mono, output);
}

#[derive(Debug, Clone)]
struct LinearResampler {
    input_rate: u32,
    step: f64,
    position: f64,
    pending: Vec<f32>,
}

impl LinearResampler {
    fn new(input_rate: u32, output_rate: u32) -> Self {
        Self {
            input_rate,
            step: input_rate as f64 / output_rate as f64,
            position: 0.0,
            pending: Vec::new(),
        }
    }

    fn push(&mut self, samples: &[f32], output: &mut Vec<f32>) {
        self.pending.extend_from_slice(samples);
        while self.position + 1.0 < self.pending.len() as f64 {
            let left_index = self.position.floor() as usize;
            let right_index = left_index + 1;
            let fraction = (self.position - left_index as f64) as f32;
            let left = self.pending[left_index];
            let right = self.pending[right_index];
            output.push(left + (right - left) * fraction);
            self.position += self.step;
        }

        let keep_from = self.position.floor().max(1.0) as usize - 1;
        if keep_from > 0 {
            self.pending.drain(0..keep_from);
            self.position -= keep_from as f64;
        }
    }

    fn finish(&mut self, output: &mut Vec<f32>) {
        if output.is_empty() && !self.pending.is_empty() {
            output.push(self.pending[0]);
        }
    }
}

fn parse_webvtt_segments(raw: &str) -> Vec<TranscriptSegment> {
    let mut segments = Vec::new();
    let mut last_text = String::new();

    for block in raw.split("\n\n") {
        let mut lines = block
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        if lines.is_empty() {
            continue;
        }
        if lines[0] == "WEBVTT"
            || lines[0].starts_with("Kind:")
            || lines[0].starts_with("Language:")
            || lines[0].starts_with("NOTE")
            || lines[0].starts_with("STYLE")
            || lines[0].starts_with("REGION")
        {
            continue;
        }

        let timestamp_index = lines
            .iter()
            .position(|line| line.contains("-->"))
            .unwrap_or(usize::MAX);
        if timestamp_index == usize::MAX {
            continue;
        }
        let timestamp_line = lines[timestamp_index];
        let start_raw = timestamp_line.split("-->").next().unwrap_or("").trim();
        let Some(start_ms) = parse_timestamp_ms(start_raw) else {
            continue;
        };
        let text = lines
            .drain(timestamp_index + 1..)
            .map(strip_markup_and_entities)
            .map(|line| compact_ws(&line))
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if text.is_empty() || text == last_text {
            continue;
        }
        last_text = text.clone();
        segments.push(TranscriptSegment { start_ms, text });
    }

    segments
}

fn parse_timestamp_ms(raw: &str) -> Option<u64> {
    let mut parts = raw.split(':').collect::<Vec<_>>();
    if parts.len() == 2 {
        parts.insert(0, "0");
    }
    if parts.len() != 3 {
        return None;
    }
    let hours = parts[0].parse::<u64>().ok()?;
    let minutes = parts[1].parse::<u64>().ok()?;
    let sec_parts = parts[2].split('.').collect::<Vec<_>>();
    if sec_parts.len() != 2 {
        return None;
    }
    let seconds = sec_parts[0].parse::<u64>().ok()?;
    let millis = sec_parts[1].parse::<u64>().ok()?;
    Some(
        hours.saturating_mul(3_600_000)
            + minutes.saturating_mul(60_000)
            + seconds.saturating_mul(1_000)
            + millis.min(999),
    )
}

fn strip_markup_and_entities(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut in_tag = false;
    for ch in raw.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    output
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn render_timestamp(start_ms: u64) -> String {
    let total_seconds = start_ms / 1_000;
    let hours = total_seconds / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

fn truncate_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    truncate_chars(&compact, max_chars)
}
