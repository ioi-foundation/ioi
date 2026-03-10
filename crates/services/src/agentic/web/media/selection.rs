use super::*;
use serde_json::Map;
use std::cmp::Ordering;

pub(super) fn discover_subtitle_candidate(
    request_url: &str,
    metadata: &Value,
    requested_language: &str,
) -> MediaProviderCandidateState {
    match select_subtitle_track(metadata, requested_language) {
        Some(selection) => MediaProviderCandidateState {
            candidate: media_provider_candidate_receipt(
                SUBTITLE_PROVIDER_ID,
                request_url,
                false,
                true,
                None,
            ),
            plan: Some(ProviderExecutionPlan::Subtitle(selection)),
        },
        None => MediaProviderCandidateState {
            candidate: media_provider_candidate_receipt(
                SUBTITLE_PROVIDER_ID,
                request_url,
                false,
                false,
                Some("subtitle_track_unavailable".to_string()),
            ),
            plan: None,
        },
    }
}

pub(super) fn discover_audio_stt_candidate(
    request_url: &str,
    metadata: &Value,
) -> MediaProviderCandidateState {
    match select_audio_format(metadata) {
        Some(selection) => MediaProviderCandidateState {
            candidate: media_provider_candidate_receipt(
                AUDIO_STT_PROVIDER_ID,
                request_url,
                false,
                true,
                None,
            ),
            plan: Some(ProviderExecutionPlan::AudioStt(selection)),
        },
        None => MediaProviderCandidateState {
            candidate: media_provider_candidate_receipt(
                AUDIO_STT_PROVIDER_ID,
                request_url,
                false,
                false,
                Some("supported_audio_format_unavailable".to_string()),
            ),
            plan: None,
        },
    }
}

pub(super) fn select_provider_plan(
    subtitle_candidate: &mut MediaProviderCandidateState,
    audio_candidate: &mut MediaProviderCandidateState,
) -> Option<ProviderExecutionPlan> {
    if let Some(plan) = subtitle_candidate.plan.clone() {
        subtitle_candidate.candidate.selected = true;
        return Some(plan);
    }
    if let Some(plan) = audio_candidate.plan.clone() {
        audio_candidate.candidate.selected = true;
        return Some(plan);
    }
    None
}

pub(super) fn normalize_requested_language(language: Option<&str>) -> String {
    let normalized = language
        .unwrap_or("en")
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-");
    if normalized.is_empty() {
        "en".to_string()
    } else {
        normalized
    }
}

pub(super) fn whisper_language_code(language: &str) -> &str {
    language
        .split(['-', '_'])
        .next()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("en")
}

pub(super) fn discovery_reason_from_error(err: &anyhow::Error) -> String {
    let message = compact_ws(&err.to_string());
    let normalized = if let Some(value) = message.strip_prefix("ERROR_CLASS=") {
        let mut parts = value.splitn(2, ' ');
        let class = parts.next().unwrap_or_default().trim();
        let detail = parts.next().unwrap_or_default().trim();
        if detail.is_empty() {
            class.to_string()
        } else {
            format!("{}: {}", class, detail)
        }
    } else {
        message
    };
    truncate_chars(&normalized, 160)
}

pub(super) fn select_subtitle_track(
    metadata: &Value,
    requested_language: &str,
) -> Option<SubtitleSelection> {
    let manual = metadata.get("subtitles").and_then(Value::as_object);
    let automatic = metadata
        .get("automatic_captions")
        .and_then(Value::as_object);

    select_track_from_bucket(manual, requested_language)
        .map(|language_key| SubtitleSelection {
            language_key,
            source_kind: "manual",
        })
        .or_else(|| {
            select_track_from_bucket(automatic, requested_language).map(|language_key| {
                SubtitleSelection {
                    language_key,
                    source_kind: "automatic",
                }
            })
        })
}

pub(super) fn select_track_from_bucket(
    bucket: Option<&Map<String, Value>>,
    requested_language: &str,
) -> Option<String> {
    let bucket = bucket?;
    if bucket.contains_key(requested_language) {
        return Some(requested_language.to_string());
    }

    let requested_prefix = format!("{}-", requested_language);
    let requested_underscore_prefix = format!("{}_", requested_language);
    let base_language = whisper_language_code(requested_language);
    let base_prefix = format!("{}-", base_language);
    let base_underscore_prefix = format!("{}_", base_language);
    let mut matches = bucket
        .keys()
        .filter(|key| {
            let normalized = key.to_ascii_lowercase();
            normalized == requested_language
                || normalized.starts_with(&requested_prefix)
                || normalized.starts_with(&requested_underscore_prefix)
                || normalized == base_language
                || normalized.starts_with(&base_prefix)
                || normalized.starts_with(&base_underscore_prefix)
        })
        .cloned()
        .collect::<Vec<_>>();
    matches.sort();
    matches.into_iter().next()
}

pub(super) fn select_audio_format(metadata: &Value) -> Option<AudioFormatSelection> {
    let mut candidates = metadata
        .get("formats")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(parse_audio_format_candidate)
        .collect::<Vec<_>>();

    candidates.sort_by(compare_audio_format_candidates);
    candidates.into_iter().next()
}

fn parse_audio_format_candidate(value: &Value) -> Option<AudioFormatSelection> {
    let format_id = value.get("format_id")?.as_str()?.trim();
    let ext = value.get("ext")?.as_str()?.trim().to_ascii_lowercase();
    let acodec = value.get("acodec")?.as_str()?.trim().to_ascii_lowercase();
    let has_audio = !acodec.is_empty() && acodec != "none";
    if !has_audio || format_id.is_empty() {
        return None;
    }

    let supported = matches_audio_support(&ext, &acodec);
    if !supported {
        return None;
    }

    Some(AudioFormatSelection {
        format_id: format_id.to_string(),
        ext,
        acodec,
    })
}

fn matches_audio_support(ext: &str, acodec: &str) -> bool {
    (matches!(ext, "m4a" | "mp4") && (acodec.contains("mp4a") || acodec.contains("aac")))
        || ((ext == "mp3") || acodec.contains("mp3"))
        || (matches!(ext, "ogg" | "oga" | "mkv") && acodec.contains("vorbis"))
}

fn compare_audio_format_candidates(
    left: &AudioFormatSelection,
    right: &AudioFormatSelection,
) -> Ordering {
    audio_format_rank(right)
        .cmp(&audio_format_rank(left))
        .then_with(|| right.ext.cmp(&left.ext))
        .then_with(|| right.format_id.cmp(&left.format_id))
}

fn audio_format_rank(selection: &AudioFormatSelection) -> u8 {
    match selection.ext.as_str() {
        "m4a" => 4,
        "mp4" => 3,
        "mp3" => 2,
        "ogg" | "oga" => 1,
        "mkv" => 0,
        _ => 0,
    }
}

pub(super) fn select_video_format(metadata: &Value) -> Option<VideoFormatSelection> {
    let mut candidates = metadata
        .get("formats")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(parse_video_format_candidate)
        .collect::<Vec<_>>();
    candidates.sort_by(compare_video_format_candidates);
    candidates.into_iter().next()
}

fn parse_video_format_candidate(value: &Value) -> Option<VideoFormatSelection> {
    let format_id = value.get("format_id")?.as_str()?.trim();
    let ext = value.get("ext")?.as_str()?.trim().to_ascii_lowercase();
    let vcodec = value.get("vcodec")?.as_str()?.trim().to_ascii_lowercase();
    let height = value
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_default();
    let width = value
        .get("width")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_default();
    if format_id.is_empty() || vcodec.is_empty() || vcodec == "none" || height == 0 || width == 0 {
        return None;
    }
    let supported_container = matches!(ext.as_str(), "mp4" | "webm" | "mkv");
    if !supported_container {
        return None;
    }
    Some(VideoFormatSelection {
        format_id: format_id.to_string(),
        ext,
        vcodec,
        width,
        height,
    })
}

fn compare_video_format_candidates(
    left: &VideoFormatSelection,
    right: &VideoFormatSelection,
) -> Ordering {
    video_format_rank(right)
        .cmp(&video_format_rank(left))
        .then_with(|| right.height.cmp(&left.height))
        .then_with(|| right.width.cmp(&left.width))
        .then_with(|| right.format_id.cmp(&left.format_id))
}

fn video_format_rank(selection: &VideoFormatSelection) -> (u8, u8, u32) {
    let height_bucket = match selection.height {
        480..=720 => 4,
        360..=479 => 3,
        721..=960 => 2,
        240..=359 => 1,
        _ => 0,
    };
    let ext_rank = match selection.ext.as_str() {
        "mp4" => 3,
        "webm" => 2,
        "mkv" => 1,
        _ => 0,
    };
    let height_score = selection.height.min(960);
    (height_bucket, ext_rank, height_score)
}
