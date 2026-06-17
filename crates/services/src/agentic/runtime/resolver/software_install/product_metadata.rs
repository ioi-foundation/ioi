use std::env;

pub(super) struct CurrentProductInstallIdentity {
    pub(super) display_name: String,
    pub(super) canonical_id: String,
    pub(super) aliases: Vec<String>,
}

pub(super) fn current_product_install_identity() -> CurrentProductInstallIdentity {
    let display_name = env::var("IOI_PRODUCT_INSTALL_DISPLAY_NAME")
        .unwrap_or_else(|_| "IOI Hypervisor".to_string());
    let canonical_id = env::var("IOI_PRODUCT_INSTALL_CANONICAL_ID")
        .unwrap_or_else(|_| "ioi-hypervisor".to_string());
    let aliases = env::var("IOI_PRODUCT_INSTALL_ALIASES")
        .unwrap_or_else(|_| "hypervisor,ioi hypervisor".to_string())
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
