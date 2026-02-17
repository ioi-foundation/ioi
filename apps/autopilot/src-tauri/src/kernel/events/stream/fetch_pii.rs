use crate::kernel::state::get_rpc_client;
use crate::models::AppState;
use crate::models::PiiReviewInfo;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_pii::validate_review_request_compat;
use ioi_types::app::agentic::PiiReviewRequest;
use ioi_types::codec;
use std::sync::Mutex;

pub(super) async fn fetch_pii_review_info(
    app: &tauri::AppHandle,
    request_hash_hex: &str,
) -> Option<PiiReviewInfo> {
    let hash_bytes = hex::decode(request_hash_hex).ok()?;
    if hash_bytes.len() != 32 {
        return None;
    }
    let mut decision_hash = [0u8; 32];
    decision_hash.copy_from_slice(&hash_bytes);

    let state_handle = app.state::<Mutex<AppState>>();
    let mut client = get_rpc_client(&state_handle).await.ok()?;
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let key = [
        ns_prefix.as_slice(),
        b"pii::review::request::",
        &decision_hash,
    ]
    .concat();

    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .ok()?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return None;
    }

    let request: PiiReviewRequest = codec::from_bytes_canonical(&resp.value).ok()?;
    if validate_review_request_compat(&request).is_err() {
        return None;
    }

    Some(PiiReviewInfo {
        decision_hash: hex::encode(request.decision_hash),
        target_label: request.summary.target_label,
        span_summary: request.summary.span_summary,
        class_counts: request.summary.class_counts,
        severity_counts: request.summary.severity_counts,
        stage2_prompt: request.summary.stage2_prompt,
        deadline_ms: request.deadline_ms,
        target_id: Some(request.material.target),
    })
}
