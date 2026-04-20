use super::wallet_backed_bootstrap_enabled;

#[test]
fn wallet_bootstrap_is_disabled_for_local_gpu_dev() {
    let prev_local_gpu = std::env::var_os("AUTOPILOT_LOCAL_GPU_DEV");
    let prev_profile = std::env::var_os("AUTOPILOT_DATA_PROFILE");
    let prev_bootstrap = std::env::var_os("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP");

    std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", "1");
    std::env::remove_var("AUTOPILOT_DATA_PROFILE");
    std::env::remove_var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP");

    assert!(!wallet_backed_bootstrap_enabled());

    match prev_local_gpu {
        Some(value) => std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", value),
        None => std::env::remove_var("AUTOPILOT_LOCAL_GPU_DEV"),
    }
    match prev_profile {
        Some(value) => std::env::set_var("AUTOPILOT_DATA_PROFILE", value),
        None => std::env::remove_var("AUTOPILOT_DATA_PROFILE"),
    }
    match prev_bootstrap {
        Some(value) => std::env::set_var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP", value),
        None => std::env::remove_var("AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP"),
    }
}
