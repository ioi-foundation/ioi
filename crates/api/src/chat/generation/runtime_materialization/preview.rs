fn emit_direct_author_live_preview(
    observer: Option<&ChatArtifactLivePreviewObserver>,
    preview_id: &str,
    preview_label: &str,
    preview_language: &Option<String>,
    status: &str,
    raw: &str,
    is_final: bool,
) {
    let preview_content = live_token_stream_preview_text(raw, 2200);
    if preview_content.trim().is_empty() {
        return;
    }

    if let Some(observer) = observer {
        observer(chat_work_graph_live_preview(
            preview_id.to_string(),
            ExecutionLivePreviewKind::TokenStream,
            preview_label.to_string(),
            None,
            None,
            status,
            preview_language.clone(),
            preview_content,
            is_final,
        ));
    }
}
