// Path: crates/ipc/src/tests.rs

#[cfg(test)]
mod tests {
    use crate::data::{AgentContext, DaReference, Tensor};
    use crate::{access_rkyv_bytes, to_rkyv_bytes};

    #[test]
    fn test_agent_context_serialization_roundtrip() {
        let original = AgentContext {
            session_id: 12345,
            embeddings: vec![Tensor {
                shape: [1, 2, 3, 4],
                data: vec![0.1, 0.2, 0.3, 0.4],
            }],
            prompt_tokens: vec![101, 102, 103],
            da_ref: Some(DaReference {
                provider: "celestia".to_string(),
                blob_id: vec![0xCA, 0xFE, 0xBA, 0xBE],
                commitment: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }),
        };

        // Serialize
        let aligned_vec = to_rkyv_bytes(&original);

        // Access via Zero-Copy
        let archived = access_rkyv_bytes::<AgentContext>(&aligned_vec).expect("access failed");

        // Verify fields match
        assert_eq!(archived.session_id, original.session_id);
        assert_eq!(archived.prompt_tokens, original.prompt_tokens);

        // Verify nested DA reference
        let archived_da = archived.da_ref.as_ref().unwrap();
        assert_eq!(
            archived_da.provider,
            original.da_ref.as_ref().unwrap().provider
        );
        assert_eq!(
            archived_da.blob_id,
            original.da_ref.as_ref().unwrap().blob_id
        );

        // Verify Tensor
        let archived_tensor = &archived.embeddings[0];
        assert_eq!(archived_tensor.shape, original.embeddings[0].shape);
        assert_eq!(archived_tensor.data, original.embeddings[0].data);
    }
}
