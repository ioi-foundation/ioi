use ioi_drivers::gui::accessibility::AccessibilityNode;
use ioi_drivers::gui::lenses::{auto::AutoLens, AppLens};

pub(super) fn detect_human_challenge(url: &str, content: &str) -> Option<&'static str> {
    let url_lc = url.to_ascii_lowercase();
    let content_lc = content.to_ascii_lowercase();

    if url_lc.contains("/sorry/") || content_lc.contains("/sorry/") {
        return Some("challenge redirect (/sorry/) detected");
    }
    if content_lc.contains("recaptcha") || content_lc.contains("g-recaptcha") {
        return Some("reCAPTCHA challenge marker detected");
    }
    if content_lc.contains("i'm not a robot") || content_lc.contains("i am not a robot") {
        return Some("robot-verification checkbox detected");
    }
    if content_lc.contains("unusual traffic from your computer network")
        || content_lc.contains("our systems have detected unusual traffic")
    {
        return Some("unusual-traffic challenge detected");
    }
    if content_lc.contains("verify you are human")
        || content_lc.contains("human verification")
        || content_lc.contains("please verify you are a human")
    {
        return Some("human-verification challenge detected");
    }

    None
}

pub(super) fn apply_browser_auto_lens(raw_tree: AccessibilityNode) -> AccessibilityNode {
    let lens = AutoLens;
    lens.transform(&raw_tree).unwrap_or(raw_tree)
}

pub(super) fn render_browser_tree_xml(tree: &AccessibilityNode) -> String {
    let lens = AutoLens;
    lens.render(tree, 0)
}
