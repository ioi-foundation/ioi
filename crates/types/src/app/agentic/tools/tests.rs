use super::*;

fn is_expected_egress_tool_exhaustive(tool: &AgentTool) -> bool {
    match tool {
        AgentTool::OsCopy { .. }
        | AgentTool::BrowserNavigate { .. }
        | AgentTool::WebSearch { .. }
        | AgentTool::WebRead { .. }
        | AgentTool::NetFetch { .. }
        | AgentTool::BrowserType { .. }
        | AgentTool::CommerceCheckout { .. } => true,

        AgentTool::Computer(_)
        | AgentTool::FsWrite { .. }
        | AgentTool::FsPatch { .. }
        | AgentTool::FsRead { .. }
        | AgentTool::FsList { .. }
        | AgentTool::FsSearch { .. }
        | AgentTool::FsMove { .. }
        | AgentTool::FsCopy { .. }
        | AgentTool::FsDelete { .. }
        | AgentTool::FsCreateDirectory { .. }
        | AgentTool::SysExec { .. }
        | AgentTool::SysExecSession { .. }
        | AgentTool::SysExecSessionReset {}
        | AgentTool::SysInstallPackage { .. }
        | AgentTool::SysChangeDir { .. }
        | AgentTool::BrowserSnapshot {}
        | AgentTool::BrowserClick { .. }
        | AgentTool::BrowserClickElement { .. }
        | AgentTool::BrowserSyntheticClick { .. }
        | AgentTool::BrowserScroll { .. }
        | AgentTool::BrowserKey { .. }
        | AgentTool::GuiClick { .. }
        | AgentTool::GuiType { .. }
        | AgentTool::GuiScroll { .. }
        | AgentTool::GuiSnapshot {}
        | AgentTool::GuiClickElement { .. }
        | AgentTool::UiFind { .. }
        | AgentTool::OsFocusWindow { .. }
        | AgentTool::OsPaste {}
        | AgentTool::OsLaunchApp { .. }
        | AgentTool::MathEval { .. }
        | AgentTool::ChatReply { .. }
        | AgentTool::MemorySearch { .. }
        | AgentTool::MemoryInspect { .. }
        | AgentTool::AgentDelegate { .. }
        | AgentTool::AgentAwait { .. }
        | AgentTool::AgentPause { .. }
        | AgentTool::AgentComplete { .. }
        | AgentTool::SystemFail { .. }
        | AgentTool::Dynamic(_) => false,
    }
}

#[test]
fn browser_navigate_target_maps_to_browser_interact_scope() {
    let tool = AgentTool::BrowserNavigate {
        url: "https://news.ycombinator.com".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn web_search_target_maps_to_web_retrieve_scope() {
    let tool = AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        limit: None,
        url: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::WebRetrieve);
}

#[test]
fn web_read_target_maps_to_web_retrieve_scope() {
    let tool = AgentTool::WebRead {
        url: "https://example.com".to_string(),
        max_chars: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::WebRetrieve);
}

#[test]
fn net_fetch_target_maps_to_net_fetch_scope() {
    let tool = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::NetFetch);
}

#[test]
fn browser_snapshot_target_maps_to_browser_inspect_scope() {
    let tool = AgentTool::BrowserSnapshot {};
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInspect);
}

#[test]
fn filesystem_patch_target_maps_to_fs_write_scope() {
    let tool = AgentTool::FsPatch {
        path: "/tmp/demo.txt".to_string(),
        search: "hello".to_string(),
        replace: "world".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsWrite);
}

#[test]
fn filesystem_search_target_maps_to_fs_read_scope() {
    let tool = AgentTool::FsSearch {
        path: "/tmp".to_string(),
        regex: "needle".to_string(),
        file_pattern: Some("*.rs".to_string()),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsRead);
}

#[test]
fn filesystem_move_target_maps_to_custom_scope() {
    let tool = AgentTool::FsMove {
        source_path: "/tmp/a.txt".to_string(),
        destination_path: "/tmp/b.txt".to_string(),
        overwrite: false,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__move_path".into())
    );
}

#[test]
fn filesystem_copy_target_maps_to_custom_scope() {
    let tool = AgentTool::FsCopy {
        source_path: "/tmp/a.txt".to_string(),
        destination_path: "/tmp/b.txt".to_string(),
        overwrite: false,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__copy_path".into())
    );
}

#[test]
fn filesystem_delete_target_maps_to_fs_write_scope() {
    let tool = AgentTool::FsDelete {
        path: "/tmp/a.txt".to_string(),
        recursive: false,
        ignore_missing: false,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::FsWrite);
}

#[test]
fn filesystem_create_directory_target_maps_to_custom_scope() {
    let tool = AgentTool::FsCreateDirectory {
        path: "/tmp/work".to_string(),
        recursive: true,
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("filesystem__create_directory".into())
    );
}

#[test]
fn browser_click_element_target_maps_to_browser_click_element_scope() {
    let tool = AgentTool::BrowserClickElement {
        id: "btn_submit".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_scroll_target_maps_to_browser_scroll_scope() {
    let tool = AgentTool::BrowserScroll {
        delta_x: 0,
        delta_y: 480,
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_type_target_maps_to_custom_browser_type_tool() {
    let tool = AgentTool::BrowserType {
        text: "hello".to_string(),
        selector: Some("input[name='q']".to_string()),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn browser_key_target_maps_to_custom_browser_key_tool() {
    let tool = AgentTool::BrowserKey {
        key: "Enter".to_string(),
    };
    assert_eq!(tool.target(), crate::app::ActionTarget::BrowserInteract);
}

#[test]
fn math_eval_target_maps_to_math_eval_scope() {
    let tool = AgentTool::MathEval {
        expression: "247 * 38".to_string(),
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("math::eval".to_string())
    );
}

#[test]
fn os_launch_app_target_maps_to_custom_os_launch_scope() {
    let tool = AgentTool::OsLaunchApp {
        app_name: "calculator".to_string(),
    };
    assert_eq!(
        tool.target(),
        crate::app::ActionTarget::Custom("os::launch_app".to_string())
    );
}

#[test]
fn pii_egress_specs_cover_known_egress_tools() {
    use crate::app::agentic::security::PiiTarget;
    use crate::app::ActionTarget;

    assert!(is_expected_egress_tool_exhaustive(&AgentTool::OsCopy {
        content: "secret".to_string()
    }));
    assert!(is_expected_egress_tool_exhaustive(
        &AgentTool::BrowserNavigate {
            url: "https://example.com".to_string()
        }
    ));
    assert!(is_expected_egress_tool_exhaustive(&AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        limit: None,
        url: Some("https://duckduckgo.com/?q=internet+of+intelligence".to_string()),
    }));
    assert!(is_expected_egress_tool_exhaustive(&AgentTool::WebRead {
        url: "https://example.com".to_string(),
        max_chars: None,
    }));
    assert!(is_expected_egress_tool_exhaustive(&AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    }));
    assert!(is_expected_egress_tool_exhaustive(
        &AgentTool::BrowserType {
            text: "hello".to_string(),
            selector: None,
        }
    ));
    assert!(is_expected_egress_tool_exhaustive(
        &AgentTool::CommerceCheckout {
            merchant_url: "https://merchant.example".to_string(),
            items: vec![],
            total_amount: 1.0,
            currency: "USD".to_string(),
            buyer_email: Some("buyer@example.com".to_string()),
        }
    ));
    assert!(!is_expected_egress_tool_exhaustive(&AgentTool::ChatReply {
        message: "ok".to_string(),
    }));

    let os_copy_specs = AgentTool::OsCopy {
        content: "secret".to_string(),
    }
    .pii_egress_specs();
    assert_eq!(os_copy_specs.len(), 1);
    assert_eq!(os_copy_specs[0].field, PiiEgressField::OsCopyContent);
    assert!(os_copy_specs[0].supports_transform);
    assert_eq!(
        os_copy_specs[0].target,
        PiiTarget::Action(ActionTarget::ClipboardWrite)
    );

    let nav_specs = AgentTool::BrowserNavigate {
        url: "https://example.com".to_string(),
    }
    .pii_egress_specs();
    assert_eq!(nav_specs.len(), 1);
    assert_eq!(nav_specs[0].field, PiiEgressField::BrowserNavigateUrl);
    assert!(!nav_specs[0].supports_transform);
    assert_eq!(
        nav_specs[0].target,
        PiiTarget::Action(ActionTarget::BrowserInteract)
    );

    let web_search_specs = AgentTool::WebSearch {
        query: "internet of intelligence".to_string(),
        limit: None,
        url: Some("https://duckduckgo.com/?q=internet+of+intelligence".to_string()),
    }
    .pii_egress_specs();
    assert_eq!(web_search_specs.len(), 1);
    assert_eq!(web_search_specs[0].field, PiiEgressField::WebSearchUrl);
    assert!(!web_search_specs[0].supports_transform);
    assert_eq!(
        web_search_specs[0].target,
        PiiTarget::Action(ActionTarget::WebRetrieve)
    );

    let web_read_specs = AgentTool::WebRead {
        url: "https://example.com".to_string(),
        max_chars: None,
    }
    .pii_egress_specs();
    assert_eq!(web_read_specs.len(), 1);
    assert_eq!(web_read_specs[0].field, PiiEgressField::WebReadUrl);
    assert!(!web_read_specs[0].supports_transform);
    assert_eq!(
        web_read_specs[0].target,
        PiiTarget::Action(ActionTarget::WebRetrieve)
    );

    let net_fetch_specs = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    }
    .pii_egress_specs();
    assert_eq!(net_fetch_specs.len(), 1);
    assert_eq!(net_fetch_specs[0].field, PiiEgressField::NetFetchUrl);
    assert!(!net_fetch_specs[0].supports_transform);
    assert_eq!(
        net_fetch_specs[0].target,
        PiiTarget::Action(ActionTarget::NetFetch)
    );

    let browser_type_specs = AgentTool::BrowserType {
        text: "hello".to_string(),
        selector: None,
    }
    .pii_egress_specs();
    assert_eq!(browser_type_specs.len(), 1);
    assert_eq!(browser_type_specs[0].field, PiiEgressField::BrowserTypeText);
    assert!(browser_type_specs[0].supports_transform);
    assert_eq!(
        browser_type_specs[0].target,
        PiiTarget::Action(ActionTarget::BrowserInteract)
    );

    let checkout_specs = AgentTool::CommerceCheckout {
        merchant_url: "https://merchant.example".to_string(),
        items: vec![],
        total_amount: 1.0,
        currency: "USD".to_string(),
        buyer_email: Some("buyer@example.com".to_string()),
    }
    .pii_egress_specs();
    assert_eq!(checkout_specs.len(), 2);
    assert!(checkout_specs
        .iter()
        .any(|s| s.field == PiiEgressField::CommerceBuyerEmail && s.supports_transform));
    assert!(checkout_specs
        .iter()
        .any(|s| s.field == PiiEgressField::CommerceMerchantUrl && !s.supports_transform));
}

#[test]
fn pii_egress_field_mut_maps_to_expected_text_slots() {
    let mut tool = AgentTool::CommerceCheckout {
        merchant_url: "https://merchant.example".to_string(),
        items: vec![],
        total_amount: 1.0,
        currency: "USD".to_string(),
        buyer_email: Some("buyer@example.com".to_string()),
    };

    let merchant = tool
        .pii_egress_field_mut(PiiEgressField::CommerceMerchantUrl)
        .expect("merchant url");
    *merchant = "https://clean.example".to_string();

    let buyer = tool
        .pii_egress_field_mut(PiiEgressField::CommerceBuyerEmail)
        .expect("buyer email");
    *buyer = "clean@example.com".to_string();

    match tool {
        AgentTool::CommerceCheckout {
            merchant_url,
            buyer_email,
            ..
        } => {
            assert_eq!(merchant_url, "https://clean.example");
            assert_eq!(buyer_email.as_deref(), Some("clean@example.com"));
        }
        _ => panic!("unexpected tool variant"),
    }

    let mut net_fetch = AgentTool::NetFetch {
        url: "https://example.com".to_string(),
        max_chars: None,
    };
    let url = net_fetch
        .pii_egress_field_mut(PiiEgressField::NetFetchUrl)
        .expect("net fetch url");
    *url = "https://clean.example".to_string();
    match net_fetch {
        AgentTool::NetFetch { url, .. } => assert_eq!(url, "https://clean.example"),
        _ => panic!("unexpected tool variant"),
    }
}
