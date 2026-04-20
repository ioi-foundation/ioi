use super::context_blob_artifact_candidates;

#[test]
fn context_blob_candidates_expand_visual_hashes_into_memory_artifacts() {
    let candidates = context_blob_artifact_candidates(
        "sha256:ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD",
    );
    assert!(candidates.contains(
        &"desktop.visual_observation.abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            .to_string()
    ));
}
