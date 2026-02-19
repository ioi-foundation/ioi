use super::model::FailureClass;
use ioi_types::app::RoutingFailureClass;

const PACKAGE_LOOKUP_FAILURE_PATTERNS: [&str; 4] = [
    "unable to locate package",
    "no match for argument",
    "has no installation candidate",
    "cannot find a package",
];
const LAUNCH_LOOKUP_FAILURE_PATTERNS: [&str; 5] = [
    "no such file",
    "not found",
    "unable to locate",
    "cannot find",
    "gtk-launch",
];
const TIER_VIOLATION_PATTERNS: [&str; 3] = [
    "raw coordinate click is disabled outside visuallast",
    "vision localization is only allowed",
    "tier violation",
];
const MISSING_DEPENDENCY_PATTERNS: [&str; 3] = [
    "failed to execute wmctrl",
    "missing focus dependency",
    "missingdependency",
];
const NO_EFFECT_PATTERNS: [&str; 3] = [
    "ui state static after click",
    "ui state unchanged after click",
    "no effect after action",
];
const TARGET_NOT_FOUND_CONTEXT_PATTERNS: [&str; 3] = ["target", "element", "ui tree"];
const TARGET_NOT_FOUND_PATTERNS: [&str; 4] = [
    "not found",
    "no window matched",
    "lookup failed",
    "unable to find",
];
const FOCUS_MISMATCH_PATTERNS: [&str; 4] =
    ["focus", "foreground", "context drift", "active window"];
const POLICY_BLOCK_PATTERNS: [&str; 4] =
    ["approval", "blocked by policy", "firewall", "authorization"];
const TOOL_UNAVAILABLE_PATTERNS: [&str; 6] = [
    "missing capability",
    "tool is missing",
    "tool unavailable",
    "not handled by executor",
    "unsupported",
    "os driver missing",
];
const NON_DETERMINISTIC_PATTERNS: [&str; 4] = [
    "visual context drift",
    "screen has not changed",
    "non-deterministic",
    "stale screenshot",
];
const TIMEOUT_PATTERNS: [&str; 4] = ["timeout", "timed out", "deadline", "hang"];
const USER_INTERVENTION_PATTERNS: [&str; 9] = [
    "user input",
    "manual",
    "intervention",
    "waiting for user",
    "captcha",
    "recaptcha",
    "unusual traffic",
    "verify you are human",
    "/sorry/",
];

fn contains_any(msg: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| msg.contains(pattern))
}

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
    contains_any(msg, &PACKAGE_LOOKUP_FAILURE_PATTERNS)
}

fn is_install_missing_dependency_failure(msg: &str) -> bool {
    msg.contains("error_class=missingdependency") && msg.contains("failed to install")
}

fn is_launch_lookup_failure(msg: &str) -> bool {
    let launch_miss =
        msg.contains("failed to launch") && contains_any(msg, &LAUNCH_LOOKUP_FAILURE_PATTERNS);
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

    if contains_any(&msg, &TIER_VIOLATION_PATTERNS) {
        return Some(FailureClass::TierViolation);
    }

    if contains_any(&msg, &MISSING_DEPENDENCY_PATTERNS) {
        if is_package_lookup_failure(&msg) {
            return Some(FailureClass::UserInterventionNeeded);
        }
        return Some(FailureClass::MissingDependency);
    }

    if msg.contains("visual context drifted") || msg.contains("context drift") {
        return Some(FailureClass::ContextDrift);
    }

    if contains_any(&msg, &NO_EFFECT_PATTERNS) {
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
    if contains_any(&msg, &TARGET_NOT_FOUND_CONTEXT_PATTERNS) && msg.contains("not found") {
        return Some(FailureClass::TargetNotFound);
    }

    if contains_any(&msg, &FOCUS_MISMATCH_PATTERNS) {
        return Some(FailureClass::FocusMismatch);
    }

    if contains_any(&msg, &TARGET_NOT_FOUND_PATTERNS) {
        return Some(FailureClass::TargetNotFound);
    }

    if contains_any(&msg, &POLICY_BLOCK_PATTERNS) {
        return Some(FailureClass::PermissionOrApprovalRequired);
    }

    if contains_any(&msg, &TOOL_UNAVAILABLE_PATTERNS) {
        return Some(FailureClass::ToolUnavailable);
    }

    if contains_any(&msg, &NON_DETERMINISTIC_PATTERNS) {
        return Some(FailureClass::NonDeterministicUI);
    }

    if contains_any(&msg, &TIMEOUT_PATTERNS) {
        return Some(FailureClass::TimeoutOrHang);
    }

    if contains_any(&msg, &USER_INTERVENTION_PATTERNS) {
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
