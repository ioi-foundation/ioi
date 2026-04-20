use super::transcript_surface_content;

#[test]
fn transcript_surface_prefers_model_content() {
    let message = ioi_memory::StoredTranscriptMessage {
        model_content: "model".to_string(),
        store_content: "store".to_string(),
        raw_content: "raw".to_string(),
        ..Default::default()
    };

    assert_eq!(transcript_surface_content(&message), "model");
}
