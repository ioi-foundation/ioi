use std::env;

pub(super) struct CurrentProductInstallIdentity {
    pub(super) display_name: String,
    pub(super) canonical_id: String,
    pub(super) aliases: Vec<String>,
}

pub(super) fn current_product_install_identity() -> CurrentProductInstallIdentity {
    let display_name = env::var("IOI_PRODUCT_INSTALL_DISPLAY_NAME")
        .unwrap_or_else(|_| "IOI Autopilot".to_string());
    let canonical_id = env::var("IOI_PRODUCT_INSTALL_CANONICAL_ID")
        .unwrap_or_else(|_| "ioi-autopilot".to_string());
    let aliases = env::var("IOI_PRODUCT_INSTALL_ALIASES")
        .unwrap_or_else(|_| "autopilot,ioi autopilot".to_string())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();
    CurrentProductInstallIdentity {
        display_name,
        canonical_id,
        aliases,
    }
}
