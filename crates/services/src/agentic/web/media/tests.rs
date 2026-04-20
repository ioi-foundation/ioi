use super::*;
use serde_json::json;

#[test]
fn parse_sha256sum_line_matches_asset() {
    let line = "abcdef1234567890  yt-dlp";
    assert_eq!(
        parse_sha256sum_line(line, "yt-dlp").as_deref(),
        Some("abcdef1234567890")
    );
    assert!(parse_sha256sum_line(line, "other").is_none());
}

#[test]
fn parse_header_hex_sha256_accepts_quoted_value() {
    let value = header::HeaderValue::from_static(
        "\"818710568da3ca15689e31a743197b520007872ff9576237bda97bd1b469c3d7\"",
    );
    assert_eq!(
        parse_header_hex_sha256(&value).as_deref(),
        Some("818710568da3ca15689e31a743197b520007872ff9576237bda97bd1b469c3d7")
    );
}

#[test]
fn select_track_from_bucket_prefers_exact_then_prefix() {
    let bucket = json!({
        "en": [],
        "en-US": [],
        "fr": [],
    });
    let map = bucket.as_object();
    assert_eq!(select_track_from_bucket(map, "en").as_deref(), Some("en"));
    assert_eq!(
        select_track_from_bucket(map, "en-GB").as_deref(),
        Some("en")
    );
}

#[test]
fn select_subtitle_track_prefers_manual_before_automatic() {
    let metadata = json!({
        "subtitles": {"en": [{}]},
        "automatic_captions": {"en": [{}]}
    });
    let selection = select_subtitle_track(&metadata, "en").expect("selection");
    assert_eq!(selection.source_kind, "manual");
    assert_eq!(selection.language_key, "en");
}

#[test]
fn select_audio_format_prefers_aac_container() {
    let metadata = json!({
        "formats": [
            {"format_id": "251", "ext": "webm", "acodec": "opus"},
            {"format_id": "140", "ext": "m4a", "acodec": "mp4a.40.2"},
            {"format_id": "18", "ext": "mp4", "acodec": "mp4a.40.2"}
        ]
    });
    let selection = select_audio_format(&metadata).expect("audio selection");
    assert_eq!(selection.format_id, "140");
    assert_eq!(selection.ext, "m4a");
}

#[test]
fn select_video_format_prefers_mid_band_mp4_over_higher_webm() {
    let metadata = json!({
        "formats": [
            {"format_id": "248", "ext": "webm", "vcodec": "vp9", "width": 1920, "height": 1080},
            {"format_id": "22", "ext": "mp4", "vcodec": "avc1.64001F", "width": 1280, "height": 720},
            {"format_id": "18", "ext": "mp4", "vcodec": "avc1.42001E", "width": 640, "height": 360}
        ]
    });
    let selection = select_video_format(&metadata).expect("video selection");
    assert_eq!(selection.format_id, "22");
    assert_eq!(selection.ext, "mp4");
    assert_eq!(selection.height, 720);
}

#[test]
fn sample_visual_frame_timestamps_spans_duration_window() {
    let timestamps = sample_visual_frame_timestamps(2_900, 6);
    assert_eq!(timestamps.len(), 6);
    assert!(timestamps[0] >= 145_000);
    assert!(timestamps[5] <= 2_755_000);
    assert!(timestamps.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
fn sample_sequence_indices_spans_available_positions() {
    let indices = sample_sequence_indices(7, 4);
    assert_eq!(indices, vec![0, 2, 4, 6]);
}

#[test]
fn sample_chapter_thumbnails_respects_frame_limit() {
    let chapters = vec![
        YouTubeChapterThumbnail {
            title: "Intro".to_string(),
            start_ms: 0,
            thumbnail_url: "https://example.com/0.jpg".to_string(),
        },
        YouTubeChapterThumbnail {
            title: "Field".to_string(),
            start_ms: 60_000,
            thumbnail_url: "https://example.com/1.jpg".to_string(),
        },
        YouTubeChapterThumbnail {
            title: "Coils".to_string(),
            start_ms: 120_000,
            thumbnail_url: "https://example.com/2.jpg".to_string(),
        },
        YouTubeChapterThumbnail {
            title: "Wrap".to_string(),
            start_ms: 180_000,
            thumbnail_url: "https://example.com/3.jpg".to_string(),
        },
    ];
    let sampled = sample_chapter_thumbnails(&chapters, 3);
    assert_eq!(sampled.len(), 3);
    assert_eq!(sampled[0].start_ms, 0);
    assert_eq!(sampled[1].start_ms, 120_000);
    assert_eq!(sampled[2].start_ms, 180_000);
}

#[test]
fn youtube_watch_provider_version_uses_client_context_version() {
    let version = youtube_watch_provider_version(&json!({
        "client": {
            "clientName": "WEB",
            "clientVersion": "2.20260310.01.00"
        }
    }));
    assert_eq!(version, "youtube-web@2.20260310.01.00");
}

#[test]
fn parse_json_value_extracts_wrapped_object() {
    let value = parse_json_value(
        br#"```json
{"image_support":true}
```"#,
    )
    .expect("wrapped json should parse");
    assert_eq!(
        value.get("image_support").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn build_vision_probe_image_data_url_emits_jpeg_data_url() {
    let data_url = build_vision_probe_image_data_url().expect("probe image");
    assert!(data_url.starts_with("data:image/jpeg;base64,"));
    assert!(data_url.len() > "data:image/jpeg;base64,".len());
}

#[test]
fn parse_webvtt_segments_strips_markup_entities_and_dedupes_adjacent() {
    let raw = concat!(
        "WEBVTT\n\n",
        "00:00:01.000 --> 00:00:03.000\n",
        "<c.colorE5E5E5>Hello &amp; welcome</c>\n\n",
        "00:00:03.500 --> 00:00:05.000\n",
        "<c.colorE5E5E5>Hello &amp; welcome</c>\n\n",
        "00:00:06.000 --> 00:00:07.000\n",
        "Next line\n"
    );
    let segments = parse_webvtt_segments(raw);
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].start_ms, 1_000);
    assert_eq!(segments[0].text, "Hello & welcome");
    assert_eq!(segments[1].text, "Next line");
}

#[test]
fn render_timestamp_formats_hours() {
    assert_eq!(render_timestamp(3_661_000), "01:01:01");
}
