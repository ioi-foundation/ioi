use super::hashing::compute_context_phash;
use crate::agentic::desktop::service::actions::checks::requires_visual_integrity;
use crate::agentic::desktop::service::step::visual::hamming_distance;
use crate::agentic::desktop::service::DesktopAgentService;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_types::app::agentic::AgentTool;
use std::sync::Arc;

const RESUME_DRIFT_THRESHOLD: u32 = 48;

pub(super) async fn run_visual_prechecks(
    service: &DesktopAgentService,
    os_driver: &Arc<dyn OsDriver>,
    tool: &AgentTool,
    pending_vhash: [u8; 32],
    verification_checks: &mut Vec<String>,
) -> (Option<String>, [u8; 32]) {
    let mut precheck_error: Option<String> = None;
    let mut log_visual_hash = pending_vhash;

    if requires_visual_integrity(tool) {
        let current_bytes = service.gui.capture_raw_screen().await.unwrap_or_default();
        let active_window = os_driver.get_active_window_info().await.unwrap_or(None);
        let current_phash = compute_context_phash(&current_bytes, active_window.as_ref());
        log_visual_hash = current_phash;
        let drift = hamming_distance(&pending_vhash, &current_phash);
        verification_checks.push(format!("resume_drift_distance={}", drift));

        if drift > RESUME_DRIFT_THRESHOLD {
            log::warn!("Context Drift Detected before resume (Dist: {}).", drift);
            precheck_error = Some(format!(
                "ERROR_CLASS=ContextDrift Visual context drift detected before resume (distance={}).",
                drift
            ));
        }
    } else {
        log::info!(
            "Skipping visual drift check for non-spatial tool (Hash: {}).",
            hex::encode(&pending_vhash[0..4])
        );
    }

    if precheck_error.is_none() {
        if let Err(e) = service.restore_visual_context(pending_vhash).await {
            precheck_error = Some(format!(
                "ERROR_CLASS=ContextDrift Failed to restore visual context: {}",
                e
            ));
        }
    }

    (precheck_error, log_visual_hash)
}
