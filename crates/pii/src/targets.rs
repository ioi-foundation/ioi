// Submodule: targets (legacy target parsing + policy routing helpers)

use ioi_types::app::ActionTarget;
use ioi_types::app::agentic::{PiiControls, PiiTarget};

pub(crate) fn action_target_from_label(label: &str) -> Option<ActionTarget> {
    match label {
        "net::fetch" => Some(ActionTarget::NetFetch),
        "web::retrieve" => Some(ActionTarget::WebRetrieve),
        "fs::write" => Some(ActionTarget::FsWrite),
        "fs::read" => Some(ActionTarget::FsRead),
        "ui::click" => Some(ActionTarget::UiClick),
        "ui::type" => Some(ActionTarget::UiType),
        "sys::exec" => Some(ActionTarget::SysExec),
        "sys::install_package" => Some(ActionTarget::SysInstallPackage),
        "wallet::sign" => Some(ActionTarget::WalletSign),
        "wallet::send" => Some(ActionTarget::WalletSend),
        "gui::mouse_move" => Some(ActionTarget::GuiMouseMove),
        "gui::click" => Some(ActionTarget::GuiClick),
        "gui::type" => Some(ActionTarget::GuiType),
        "gui::screenshot" => Some(ActionTarget::GuiScreenshot),
        "gui::scroll" => Some(ActionTarget::GuiScroll),
        "gui::sequence" => Some(ActionTarget::GuiSequence),
        "browser::interact" => Some(ActionTarget::BrowserInteract),
        "browser::inspect" => Some(ActionTarget::BrowserInspect),
        "ucp::discovery" => Some(ActionTarget::CommerceDiscovery),
        "ucp::checkout" => Some(ActionTarget::CommerceCheckout),
        "os::focus" => Some(ActionTarget::WindowFocus),
        "clipboard::read" => Some(ActionTarget::ClipboardRead),
        "clipboard::write" => Some(ActionTarget::ClipboardWrite),
        _ => None,
    }
}

pub(crate) fn legacy_target_from_str(label: &str) -> PiiTarget {
    if let Some(action_target) = action_target_from_label(label) {
        return PiiTarget::Action(action_target);
    }

    let mut split = label.splitn(2, "::");
    let service_id = split.next().unwrap_or_default();
    let method = split.next().unwrap_or_default();
    if !service_id.is_empty() && !method.is_empty() && !label.ends_with("::") {
        return PiiTarget::ServiceCall {
            service_id: service_id.to_string(),
            method: method.to_string(),
        };
    }

    PiiTarget::Action(ActionTarget::Custom(label.to_string()))
}

pub fn is_high_risk_target(policy: &PiiControls, target: &PiiTarget) -> bool {
    let label = target.canonical_label();
    policy
        .high_risk_targets
        .iter()
        .any(|configured| configured == &label)
}

/// Compatibility wrapper for legacy string targets.
#[deprecated(note = "Use is_high_risk_target(policy, &PiiTarget) instead")]
pub fn is_high_risk_target_legacy(policy: &PiiControls, target: &str) -> bool {
    let mapped = legacy_target_from_str(target);
    is_high_risk_target(policy, &mapped)
}
