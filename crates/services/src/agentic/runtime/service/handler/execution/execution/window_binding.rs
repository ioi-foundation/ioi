async fn query_active_window_with_timeout(
    os_driver: &Arc<dyn OsDriver>,
    session_id: [u8; 32],
    phase: &str,
) -> Option<ioi_api::vm::drivers::os::WindowInfo> {
    match tokio::time::timeout(
        ACTIVE_WINDOW_QUERY_TIMEOUT,
        os_driver.get_active_window_info(),
    )
    .await
    {
        Ok(Ok(window)) => window,
        Ok(Err(err)) => {
            log::warn!(
                "Active-window query failed (session={} phase={}): {}",
                hex::encode(&session_id[..4]),
                phase,
                err
            );
            None
        }
        Err(_) => {
            log::warn!(
                "Active-window query timed out after {:?} (session={} phase={}).",
                ACTIVE_WINDOW_QUERY_TIMEOUT,
                hex::encode(&session_id[..4]),
                phase
            );
            None
        }
    }
}

pub(crate) fn target_requires_window_binding(target: &ActionTarget) -> bool {
    matches!(
        target,
        ActionTarget::UiClick
            | ActionTarget::UiType
            | ActionTarget::GuiMouseMove
            | ActionTarget::GuiClick
            | ActionTarget::GuiType
            | ActionTarget::GuiScroll
            | ActionTarget::GuiSequence
            | ActionTarget::BrowserInteract
            | ActionTarget::BrowserInspect
            | ActionTarget::WindowFocus
            | ActionTarget::GuiInspect
    )
}

fn derive_window_binding(
    window: Option<&ioi_api::vm::drivers::os::WindowInfo>,
) -> Result<Option<u64>, TransactionError> {
    let Some(window) = window else {
        return Ok(None);
    };

    let payload = json!({
        "app_name": window.app_name,
        "title": window.title,
        "x": window.x,
        "y": window.y,
        "width": window.width,
        "height": window.height,
    });

    let canonical =
        serde_jcs::to_vec(&payload).map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let digest = ioi_crypto::algorithms::hash::sha256(&canonical).map_err(|e| {
        TransactionError::Invalid(format!(
            "ERROR_CLASS=DeterminismBoundary Window binding hash failed: {}",
            e
        ))
    })?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_ref()[..8]);
    Ok(Some(u64::from_be_bytes(bytes)))
}

pub(crate) async fn resolve_window_binding_for_target(
    os_driver: &Arc<dyn OsDriver>,
    session_id: [u8; 32],
    target: &ActionTarget,
    phase: &str,
) -> Result<Option<u64>, TransactionError> {
    if !target_requires_window_binding(target) {
        return Ok(None);
    }
    let foreground_window = query_active_window_with_timeout(os_driver, session_id, phase).await;
    let derived = derive_window_binding(foreground_window.as_ref())?;
    if derived.is_none() {
        return Err(TransactionError::Invalid(
            "ERROR_CLASS=DeterminismBoundary Missing active-window binding for UI/browsing action."
                .to_string(),
        ));
    }
    Ok(derived)
}
