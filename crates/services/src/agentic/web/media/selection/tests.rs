use super::*;

fn candidate_state(plan: Option<ProviderExecutionPlan>) -> MediaProviderCandidateState {
    MediaProviderCandidateState {
        candidate: media_provider_candidate_receipt(
            "test.provider",
            "https://example.com/video",
            false,
            plan.is_some(),
            None,
        ),
        plan,
    }
}

#[test]
fn select_provider_plans_orders_direct_subtitles_before_audio_stt() {
    let subtitle_candidate =
        candidate_state(Some(ProviderExecutionPlan::Subtitle(SubtitleSelection {
            language_key: "en".to_string(),
            source_kind: "manual",
        })));
    let youtube_watch_candidate = candidate_state(None);
    let audio_candidate = candidate_state(Some(ProviderExecutionPlan::AudioStt(
        AudioFormatSelection {
            format_id: "140".to_string(),
            ext: "m4a".to_string(),
            acodec: "mp4a.40.2".to_string(),
        },
    )));

    let plans = select_provider_plans(
        &subtitle_candidate,
        &audio_candidate,
        &youtube_watch_candidate,
    );
    assert_eq!(plans.len(), 2);
    assert!(matches!(plans[0], ProviderExecutionPlan::Subtitle(_)));
    assert!(matches!(plans[1], ProviderExecutionPlan::AudioStt(_)));
}

#[test]
fn select_provider_plans_returns_only_admissible_candidates() {
    let subtitle_candidate = candidate_state(None);
    let youtube_watch_candidate = candidate_state(None);
    let audio_candidate = candidate_state(Some(ProviderExecutionPlan::AudioStt(
        AudioFormatSelection {
            format_id: "140".to_string(),
            ext: "m4a".to_string(),
            acodec: "mp4a.40.2".to_string(),
        },
    )));

    let plans = select_provider_plans(
        &subtitle_candidate,
        &audio_candidate,
        &youtube_watch_candidate,
    );
    assert_eq!(plans.len(), 1);
    assert!(matches!(plans[0], ProviderExecutionPlan::AudioStt(_)));
}

#[test]
fn select_provider_plans_includes_watch_transcript_before_audio_stt() {
    let subtitle_candidate = candidate_state(None);
    let youtube_watch_candidate = candidate_state(Some(
        ProviderExecutionPlan::YouTubeWatchTranscript(YouTubeWatchTranscriptSelection {
            api_key: "key".to_string(),
            client_context: serde_json::json!({"client": {"clientName": "WEB"}}),
            transcript_params: "params".to_string(),
        }),
    ));
    let audio_candidate = candidate_state(Some(ProviderExecutionPlan::AudioStt(
        AudioFormatSelection {
            format_id: "140".to_string(),
            ext: "m4a".to_string(),
            acodec: "mp4a.40.2".to_string(),
        },
    )));

    let plans = select_provider_plans(
        &subtitle_candidate,
        &audio_candidate,
        &youtube_watch_candidate,
    );
    assert_eq!(plans.len(), 2);
    assert!(matches!(
        plans[0],
        ProviderExecutionPlan::YouTubeWatchTranscript(_)
    ));
    assert!(matches!(plans[1], ProviderExecutionPlan::AudioStt(_)));
}
