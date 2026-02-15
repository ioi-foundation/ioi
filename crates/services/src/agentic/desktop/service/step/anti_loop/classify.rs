use super::model::FailureClass;
use ioi_types::app::RoutingFailureClass;

fn parse_error_class_marker(lower_error: &str) -> Option<FailureClass> {
    let marker = "error_class=";
    let marker_start = lower_error.find(marker)?;
    let token_start = marker_start + marker.len();
    let token = lower_error[token_start..]
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();

    if token.is_empty() {
        return None;
    }

    match token.as_str() {
        "focusmismatch" => Some(FailureClass::FocusMismatch),
        "targetnotfound" => Some(FailureClass::TargetNotFound),
        "visiontargetnotfound" => Some(FailureClass::VisionTargetNotFound),
        "noeffectafteraction" => Some(FailureClass::NoEffectAfterAction),
        "tierviolation" => Some(FailureClass::TierViolation),
        "missingdependency" => Some(FailureClass::MissingDependency),
        "contextdrift" => Some(FailureClass::ContextDrift),
        "permissionorapprovalrequired" => Some(FailureClass::PermissionOrApprovalRequired),
        "toolunavailable" => Some(FailureClass::ToolUnavailable),
        "nondeterministicui" => Some(FailureClass::NonDeterministicUI),
        "unexpectedstate" => Some(FailureClass::UnexpectedState),
        "timeoutorhang" => Some(FailureClass::TimeoutOrHang),
        "humanchallengerequired" | "userinterventionneeded" => {
            Some(FailureClass::UserInterventionNeeded)
        }
        _ => None,
    }
}

fn is_package_lookup_failure(msg: &str) -> bool {
    msg.contains("unable to locate package")
        || msg.contains("no match for argument")
        || msg.contains("has no installation candidate")
        || msg.contains("cannot find a package")
}

fn is_install_missing_dependency_failure(msg: &str) -> bool {
    msg.contains("error_class=missingdependency") && msg.contains("failed to install")
}

fn is_launch_lookup_failure(msg: &str) -> bool {
    let launch_miss = msg.contains("failed to launch")
        && (msg.contains("no such file")
            || msg.contains("not found")
            || msg.contains("unable to locate")
            || msg.contains("cannot find")
            || msg.contains("gtk-launch"));
    launch_miss || (msg.contains("error_class=toolunavailable") && msg.contains("failed to launch"))
}

pub fn requires_wait_for_clarification(tool_name: &str, error: &str) -> bool {
    let tool = tool_name.to_ascii_lowercase();
    let msg = error.to_ascii_lowercase();

    let is_install_tool = tool == "sys__install_package"
        || tool == "sys::install_package"
        || tool.ends_with("install_package");
    if is_install_tool
        && (is_package_lookup_failure(&msg) || is_install_missing_dependency_failure(&msg))
    {
        return true;
    }

    let is_launch_tool =
        tool == "os__launch_app" || tool == "os::launch_app" || tool.ends_with("launch_app");
    if is_launch_tool && is_launch_lookup_failure(&msg) {
        return true;
    }

    false
}

pub fn classify_failure(error: Option<&str>, policy_decision: &str) -> Option<FailureClass> {
    if policy_decision == "require_approval" || policy_decision == "denied" {
        return Some(FailureClass::PermissionOrApprovalRequired);
    }

    let msg = error?.to_lowercase();

    if is_package_lookup_failure(&msg) || is_launch_lookup_failure(&msg) {
        return Some(FailureClass::UserInterventionNeeded);
    }

    if let Some(class) = parse_error_class_marker(&msg) {
        if matches!(class, FailureClass::MissingDependency) && is_package_lookup_failure(&msg) {
            return Some(FailureClass::UserInterventionNeeded);
        }
        if matches!(class, FailureClass::MissingDependency)
            && is_install_missing_dependency_failure(&msg)
        {
            return Some(FailureClass::UserInterventionNeeded);
        }
        if matches!(class, FailureClass::ToolUnavailable) && msg.contains("failed to launch") {
            return Some(FailureClass::UserInterventionNeeded);
        }
        return Some(class);
    }

    // Browser navigation fallback failures are recoverable UI failures in most cases.
    // Keep focus-specific and invalid-input cases explicit for better tier selection.
    if msg.contains("error_class=navigationfallbackfailed") {
        if msg.contains("no focused browser window")
            || msg.contains("active window is")
            || msg.contains("cannot accept visual browser navigation")
        {
            return Some(FailureClass::FocusMismatch);
        }

        if msg.contains("requires an absolute http/https url") {
            return Some(FailureClass::UnexpectedState);
        }

        return Some(FailureClass::NonDeterministicUI);
    }

    if msg.contains("raw coordinate click is disabled outside visuallast")
        || msg.contains("vision localization is only allowed")
        || msg.contains("tier violation")
    {
        return Some(FailureClass::TierViolation);
    }

    if msg.contains("failed to execute wmctrl")
        || msg.contains("missing focus dependency")
        || msg.contains("missingdependency")
    {
        if is_package_lookup_failure(&msg) {
            return Some(FailureClass::UserInterventionNeeded);
        }
        return Some(FailureClass::MissingDependency);
    }

    if msg.contains("visual context drifted") || msg.contains("context drift") {
        return Some(FailureClass::ContextDrift);
    }

    if msg.contains("ui state static after click")
        || msg.contains("ui state unchanged after click")
        || msg.contains("no effect after action")
    {
        return Some(FailureClass::NoEffectAfterAction);
    }

    if msg.contains("vision")
        && msg.contains("localization")
        && (msg.contains("not found")
            || msg.contains("confidence too low")
            || msg.contains("outside active window"))
    {
        return Some(FailureClass::VisionTargetNotFound);
    }

    // Prefer explicit target lookup failures before broad focus heuristics.
    if (msg.contains("target") || msg.contains("element") || msg.contains("ui tree"))
        && msg.contains("not found")
    {
        return Some(FailureClass::TargetNotFound);
    }

    if msg.contains("focus")
        || msg.contains("foreground")
        || msg.contains("context drift")
        || msg.contains("active window")
    {
        return Some(FailureClass::FocusMismatch);
    }

    if msg.contains("not found")
        || msg.contains("no window matched")
        || msg.contains("lookup failed")
        || msg.contains("unable to find")
    {
        return Some(FailureClass::TargetNotFound);
    }

    if msg.contains("approval")
        || msg.contains("blocked by policy")
        || msg.contains("firewall")
        || msg.contains("authorization")
    {
        return Some(FailureClass::PermissionOrApprovalRequired);
    }

    if msg.contains("missing capability")
        || msg.contains("tool is missing")
        || msg.contains("tool unavailable")
        || msg.contains("not handled by executor")
        || msg.contains("unsupported")
        || msg.contains("os driver missing")
    {
        return Some(FailureClass::ToolUnavailable);
    }

    if msg.contains("visual context drift")
        || msg.contains("screen has not changed")
        || msg.contains("non-deterministic")
        || msg.contains("stale screenshot")
    {
        return Some(FailureClass::NonDeterministicUI);
    }

    if msg.contains("timeout")
        || msg.contains("timed out")
        || msg.contains("deadline")
        || msg.contains("hang")
    {
        return Some(FailureClass::TimeoutOrHang);
    }

    if msg.contains("user input")
        || msg.contains("manual")
        || msg.contains("intervention")
        || msg.contains("waiting for user")
        || msg.contains("captcha")
        || msg.contains("recaptcha")
        || msg.contains("unusual traffic")
        || msg.contains("verify you are human")
        || msg.contains("/sorry/")
    {
        return Some(FailureClass::UserInterventionNeeded);
    }

    Some(FailureClass::UnexpectedState)
}

pub fn to_routing_failure_class(class: FailureClass) -> RoutingFailureClass {
    match class {
        FailureClass::FocusMismatch => RoutingFailureClass::FocusMismatch,
        FailureClass::TargetNotFound => RoutingFailureClass::TargetNotFound,
        FailureClass::VisionTargetNotFound => RoutingFailureClass::VisionTargetNotFound,
        FailureClass::NoEffectAfterAction => RoutingFailureClass::NoEffectAfterAction,
        FailureClass::TierViolation => RoutingFailureClass::TierViolation,
        FailureClass::MissingDependency => RoutingFailureClass::MissingDependency,
        FailureClass::ContextDrift => RoutingFailureClass::ContextDrift,
        FailureClass::PermissionOrApprovalRequired => {
            RoutingFailureClass::PermissionOrApprovalRequired
        }
        FailureClass::ToolUnavailable => RoutingFailureClass::ToolUnavailable,
        FailureClass::NonDeterministicUI => RoutingFailureClass::NonDeterministicUI,
        FailureClass::UnexpectedState => RoutingFailureClass::UnexpectedState,
        FailureClass::TimeoutOrHang => RoutingFailureClass::TimeoutOrHang,
        FailureClass::UserInterventionNeeded => RoutingFailureClass::UserInterventionNeeded,
    }
}
