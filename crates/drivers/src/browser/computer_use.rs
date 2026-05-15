use super::BrowserObservationArtifacts;
use ioi_types::app::runtime::computer_use::{
    ComputerControlAdapterContract, ComputerUseLane, ComputerUseLease,
    ComputerUseObservationBundle, ComputerUseSessionMode, ObservationRetentionMode,
};

fn artifact_ref(observation_ref: &str, suffix: &str, present: bool) -> Option<String> {
    present.then(|| format!("{observation_ref}:{suffix}"))
}

pub fn owned_browser_adapter_contract() -> ComputerControlAdapterContract {
    ComputerControlAdapterContract::default()
}

pub fn owned_browser_lease(
    lease_id: impl Into<String>,
    target_hint: impl Into<String>,
    environment_ref: impl Into<String>,
) -> ComputerUseLease {
    ComputerUseLease {
        lease_id: lease_id.into(),
        target_hint: target_hint.into(),
        environment_ref: environment_ref.into(),
        lane: ComputerUseLane::NativeBrowser,
        session_mode: ComputerUseSessionMode::OwnedHermeticBrowser,
        ..ComputerUseLease::default()
    }
}

pub fn observation_bundle_from_browser_artifacts(
    lease_id: impl Into<String>,
    observation_ref: impl Into<String>,
    artifacts: &BrowserObservationArtifacts,
) -> ComputerUseObservationBundle {
    let observation_ref = observation_ref.into();
    ComputerUseObservationBundle {
        observation_ref: observation_ref.clone(),
        lease_id: lease_id.into(),
        lane: ComputerUseLane::NativeBrowser,
        session_mode: ComputerUseSessionMode::OwnedHermeticBrowser,
        url: artifacts.url.clone(),
        title: artifacts.page_title.clone(),
        dom_ref: artifact_ref(
            &observation_ref,
            "browsergym_dom",
            artifacts.browsergym_dom_text.is_some(),
        ),
        ax_ref: artifact_ref(
            &observation_ref,
            "browsergym_ax",
            artifacts.browsergym_axtree_text.is_some(),
        ),
        selector_map_ref: artifact_ref(
            &observation_ref,
            "selector_map",
            artifacts.browser_use_selector_map_text.is_some(),
        ),
        target_index_ref: artifact_ref(
            &observation_ref,
            "target_index",
            artifacts.browsergym_focused_bid.is_some()
                || artifacts.browser_use_selector_map_text.is_some(),
        ),
        retention_mode: ObservationRetentionMode::PromptVisibleSummaryOnly,
        ..ComputerUseObservationBundle::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn artifacts() -> BrowserObservationArtifacts {
        BrowserObservationArtifacts {
            captured_at: Instant::now(),
            url: Some("https://example.test/app".to_string()),
            page_title: Some("Example App".to_string()),
            browser_use_state_text: Some("state".to_string()),
            browser_use_selector_map_text: Some("button=submit".to_string()),
            browser_use_html_text: None,
            browser_use_eval_text: None,
            browser_use_markdown_text: None,
            browser_use_pagination_text: None,
            browser_use_tabs_text: None,
            browser_use_page_info_text: None,
            browser_use_pending_requests_text: None,
            browser_use_recent_events_text: None,
            browser_use_closed_popup_messages_text: None,
            browsergym_extra_properties_text: None,
            browsergym_focused_bid: Some("bid-1".to_string()),
            browsergym_dom_text: Some("<button bid=\"bid-1\">Submit</button>".to_string()),
            browsergym_axtree_text: Some("button Submit".to_string()),
        }
    }

    #[test]
    fn owned_browser_adapter_defaults_to_native_browser_contract() {
        let adapter = owned_browser_adapter_contract();
        assert_eq!(adapter.lane, ComputerUseLane::NativeBrowser);
        assert!(adapter
            .supported_session_modes
            .contains(&ComputerUseSessionMode::OwnedHermeticBrowser));
        assert!(adapter.emits_observation_bundle);
        assert!(adapter.emits_action_receipts);
        assert!(adapter.fail_closed_when_unavailable);
    }

    #[test]
    fn owned_browser_lease_is_cleanup_required_and_hermetic() {
        let lease = owned_browser_lease("lease:1", "https://example.test", "browser:owned");
        assert_eq!(lease.lease_id, "lease:1");
        assert_eq!(lease.target_hint, "https://example.test");
        assert_eq!(lease.environment_ref, "browser:owned");
        assert_eq!(lease.lane, ComputerUseLane::NativeBrowser);
        assert_eq!(
            lease.session_mode,
            ComputerUseSessionMode::OwnedHermeticBrowser
        );
        assert!(lease.cleanup_required);
    }

    #[test]
    fn browser_artifacts_project_to_observation_bundle_refs_without_raw_persistence() {
        let bundle = observation_bundle_from_browser_artifacts("lease:1", "obs:1", &artifacts());
        assert_eq!(bundle.lease_id, "lease:1");
        assert_eq!(bundle.observation_ref, "obs:1");
        assert_eq!(bundle.url.as_deref(), Some("https://example.test/app"));
        assert_eq!(bundle.title.as_deref(), Some("Example App"));
        assert_eq!(bundle.dom_ref.as_deref(), Some("obs:1:browsergym_dom"));
        assert_eq!(bundle.ax_ref.as_deref(), Some("obs:1:browsergym_ax"));
        assert_eq!(
            bundle.selector_map_ref.as_deref(),
            Some("obs:1:selector_map")
        );
        assert_eq!(
            bundle.target_index_ref.as_deref(),
            Some("obs:1:target_index")
        );
        assert_eq!(
            bundle.retention_mode,
            ObservationRetentionMode::PromptVisibleSummaryOnly
        );
    }
}
