// Path: crates/services/src/agentic/desktop/service/step/perception.rs

use crate::agentic::desktop::service::step::anti_loop::latest_failure_class;
use crate::agentic::desktop::service::step::visual::hamming_distance;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::desktop::utils::compute_phash;
use ioi_api::state::StateAccess;
use ioi_api::vm::drivers::os::WindowInfo;
use ioi_drivers::gui::accessibility::{merge_trees, AccessibilityNode, Rect};
use ioi_drivers::gui::geometry::{CoordinateSpace, DisplayTransform, Point};
use ioi_drivers::gui::operator::NativeOperator;
use ioi_drivers::gui::platform::fetch_tree_direct;
use ioi_drivers::gui::som::{assign_som_ids, draw_som_overlay};
use ioi_drivers::mcp::compression::ContextCompressor;
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::error::TransactionError;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use image::ImageFormat;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

pub struct PerceptionContext {
    pub tier: ExecutionTier,
    pub screenshot_base64: Option<String>,
    pub visual_phash: [u8; 32],
    pub active_window_title: String,
    pub project_index: String,
    pub agents_md_content: String,
    pub memory_pointers: String,
    pub available_tools: Vec<LlmToolDefinition>,
    pub tool_desc: String,
    pub visual_verification_note: Option<String>,
    pub last_failure_reason: Option<String>,
    pub consecutive_failures: u8,
}

// [FIX] Renamed `service` to `_service` to suppress unused variable warning
fn is_active_window_browser(
    _service: &DesktopAgentService,
    info: &Option<ioi_api::vm::drivers::os::WindowInfo>,
) -> bool {
    if let Some(win) = info {
        let app = win.app_name.to_lowercase();
        let title = win.title.to_lowercase();
        let browsers = [
            "chrome", "chromium", "brave", "firefox", "edge", "safari", "arc",
        ];
        browsers
            .iter()
            .any(|b| app.contains(b) || title.contains(b))
    } else {
        false
    }
}

fn format_window_label(win: &WindowInfo) -> String {
    let title = win.title.trim();
    let app = win.app_name.trim();
    match (title.is_empty(), app.is_empty()) {
        (false, false) => format!("{} ({})", title, app),
        (false, true) => title.to_string(),
        (true, false) => app.to_string(),
        (true, true) => "Unknown".to_string(),
    }
}

fn default_browser_chrome_ui_height() -> i32 {
    if cfg!(target_os = "macos") {
        80
    } else {
        115
    }
}

fn normalize_browser_chrome_top(raw: f64) -> Option<i32> {
    if !raw.is_finite() {
        return None;
    }

    let rounded = raw.round() as i32;
    if (16..=260).contains(&rounded) {
        Some(rounded)
    } else {
        None
    }
}

// [NEW] Helper to extract the ID map from a tagged tree
fn extract_semantic_map(root: &AccessibilityNode) -> BTreeMap<u32, String> {
    let mut map = BTreeMap::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if let Some(som_id) = node.som_id {
            if !node.id.is_empty() {
                let mut semantic_value = node.id.clone();
                if let Some(alias_blob) = node.attributes.get("semantic_aliases") {
                    let alias_blob = alias_blob.trim();
                    if !alias_blob.is_empty() {
                        semantic_value.push(',');
                        semantic_value.push_str(alias_blob);
                    }
                }
                map.insert(som_id, semantic_value);
            }
        }
        for child in &node.children {
            stack.push(child);
        }
    }
    map
}

fn rect_overlap_ratio(a: Rect, b: Rect) -> f32 {
    if a.width <= 0 || a.height <= 0 || b.width <= 0 || b.height <= 0 {
        return 0.0;
    }

    let ax2 = a.x + a.width;
    let ay2 = a.y + a.height;
    let bx2 = b.x + b.width;
    let by2 = b.y + b.height;

    let ix1 = a.x.max(b.x);
    let iy1 = a.y.max(b.y);
    let ix2 = ax2.min(bx2);
    let iy2 = ay2.min(by2);

    let iw = (ix2 - ix1).max(0);
    let ih = (iy2 - iy1).max(0);
    if iw == 0 || ih == 0 {
        return 0.0;
    }

    let inter = (iw as f64) * (ih as f64);
    let b_area = (b.width as f64) * (b.height as f64);
    if b_area <= 0.0 {
        0.0
    } else {
        (inter / b_area) as f32
    }
}

fn window_match_score(node: &AccessibilityNode, active: &WindowInfo) -> f32 {
    let role = node.role.to_ascii_lowercase();
    let mut score = 0.0f32;

    if role.contains("window") || role.contains("application") || role.contains("frame") {
        score += 1.5;
    }

    let label = format!(
        "{} {}",
        node.name.as_deref().unwrap_or_default(),
        node.id.as_str()
    )
    .to_ascii_lowercase();

    let title_lc = active.title.to_ascii_lowercase();
    let app_lc = active.app_name.to_ascii_lowercase();

    if !title_lc.is_empty() && label.contains(&title_lc) {
        score += 4.0;
    }
    if !app_lc.is_empty() && label.contains(&app_lc) {
        score += 2.5;
    }

    let active_rect = Rect {
        x: active.x,
        y: active.y,
        width: active.width,
        height: active.height,
    };
    score += rect_overlap_ratio(node.rect, active_rect) * 4.0;

    if role == "root" {
        score -= 1.0;
    }

    score
}

fn choose_active_window_subtree(
    root: &AccessibilityNode,
    active: &WindowInfo,
) -> Option<AccessibilityNode> {
    fn walk(
        node: &AccessibilityNode,
        active: &WindowInfo,
        best: &mut Option<(f32, AccessibilityNode)>,
    ) {
        let score = window_match_score(node, active);
        if score > 2.5 && best.as_ref().map(|(s, _)| score > *s).unwrap_or(true) {
            *best = Some((score, node.clone()));
        }
        for child in &node.children {
            walk(child, active, best);
        }
    }

    let mut best = None;
    walk(root, active, &mut best);
    best.map(|(_, node)| node)
}

fn build_display_transform(
    image_dims: (u32, u32),
    capture_origin_logical: (i32, i32),
    window_origin_logical: (i32, i32),
) -> DisplayTransform {
    let base = NativeOperator::current_display_transform();
    DisplayTransform::new(
        base.scale_factor,
        Point::new(
            window_origin_logical.0 as f64,
            window_origin_logical.1 as f64,
            CoordinateSpace::ScreenLogical,
        ),
        Point::new(
            capture_origin_logical.0 as f64 * base.scale_factor,
            capture_origin_logical.1 as f64 * base.scale_factor,
            CoordinateSpace::ImagePhysical,
        ),
        image_dims.0,
        image_dims.1,
    )
}

pub async fn gather_context(
    service: &DesktopAgentService,
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
    forced_tier: Option<ExecutionTier>, // [FIX] Accept forced tier from handle_step logic
) -> Result<PerceptionContext, TransactionError> {
    // 1. Determine Execution Tier (Explicit Control)
    let current_tier = forced_tier.unwrap_or_else(|| {
        if agent_state.consecutive_failures == 0 {
            ExecutionTier::DomHeadless
        } else if agent_state.consecutive_failures <= 2 {
            ExecutionTier::VisualBackground
        } else {
            ExecutionTier::VisualForeground
        }
    });

    let dom_headless_title = if current_tier == ExecutionTier::DomHeadless {
        if let Some(os_driver) = service.os_driver.as_ref() {
            match os_driver.get_active_window_info().await {
                Ok(Some(win)) => format_window_label(&win),
                Ok(None) => "Unknown".to_string(),
                Err(e) => {
                    log::debug!("DomHeadless window probe failed: {}", e);
                    "Unknown".to_string()
                }
            }
        } else {
            "Unknown".to_string()
        }
    } else {
        String::new()
    };

    let (base64_image, _, active_window_title, som_map) = match current_tier {
        ExecutionTier::DomHeadless => (None, ExecutionTier::DomHeadless, dom_headless_title, None),
        ExecutionTier::VisualBackground => capture_background_visuals(service, agent_state).await?,
        ExecutionTier::VisualForeground => capture_foreground_visuals(service, agent_state).await?,
    };

    // Update state tracking
    agent_state.current_tier = current_tier;
    agent_state.visual_som_map = som_map;

    let visual_phash = if let Some(b64) = &base64_image {
        let bytes = BASE64.decode(b64).unwrap_or_default();
        compute_phash(&bytes).unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
    };

    // Visual Verification Logic
    let visual_verification_note = if let Some(last_phash) = agent_state.last_screen_phash {
        let dist = hamming_distance(&visual_phash, &last_phash);

        let fg_title = active_window_title.to_lowercase();
        let target_hint = agent_state
            .target
            .as_ref()
            .and_then(|t| t.app_hint.as_deref())
            .unwrap_or("")
            .to_lowercase();

        if dist > 20 {
            // Context Drift Detection
            if !target_hint.is_empty() && !fg_title.contains(&target_hint) {
                Some(format!(
                    "❌ CONTEXT_DRIFT: You switched focus to '{}', but the goal requires '{}'. \
                  This is a FAILURE. Use `os__focus_window` to return.",
                    active_window_title, target_hint
                ))
            } else {
                Some("✅ VISUAL CONFIRMATION: Significant screen change detected.".to_string())
            }
        } else if dist < 5
            && agent_state
                .last_action_type
                .as_deref()
                .unwrap_or("")
                .contains("click")
        {
            Some(
                "⚠️ VISUAL WARNING: The screen has NOT changed significantly since the last click."
                    .to_string(),
            )
        } else {
            None
        }
    } else {
        None
    };

    // 2. Passive Context Injection
    let workspace_path = Path::new(&service.workspace_path);
    let agents_md_path = workspace_path.join("AGENTS.md");
    let project_index = ContextCompressor::generate_tree_index(workspace_path, 4);
    let agents_md_content = if agents_md_path.exists() {
        std::fs::read_to_string(&agents_md_path).unwrap_or_default()
    } else {
        String::new()
    };

    // 3. Hybrid RAG
    let rag_phash_filter = if current_tier == ExecutionTier::VisualForeground {
        Some(visual_phash)
    } else {
        None
    };
    let memory_pointers = service
        .retrieve_context_hybrid(&agent_state.goal, rag_phash_filter)
        .await;

    // 4. Dynamic Tool Discovery
    let tools_runtime = service.fast_inference.clone();
    let tools = discover_tools(
        state,
        service.scs.as_deref(),
        &agent_state.goal,
        tools_runtime,
        current_tier, // [FIX] Use the resolved tier here
        &active_window_title,
        agent_state.resolved_intent.as_ref(),
    )
    .await;

    let tool_desc = tools
        .iter()
        .map(|t| format!("- {}: {}", t.name, t.description))
        .collect::<Vec<_>>()
        .join("\n");

    let last_failure_reason = if agent_state.consecutive_failures > 0 {
        let last_action_fingerprint = agent_state.recent_actions.last().cloned();
        let last_failure_class = latest_failure_class(agent_state).map(|class| class.as_str());

        match (last_failure_class, last_action_fingerprint) {
            (Some(class), Some(fingerprint)) => {
                Some(format!("{} (fingerprint: {})", class, fingerprint))
            }
            (Some(class), None) => Some(class.to_string()),
            (None, Some(fingerprint)) => Some(format!("UnknownFailure ({})", fingerprint)),
            (None, None) => Some("UnknownFailure".to_string()),
        }
    } else {
        None
    };

    Ok(PerceptionContext {
        tier: current_tier,
        screenshot_base64: base64_image,
        visual_phash,
        active_window_title,
        project_index,
        agents_md_content,
        memory_pointers,
        available_tools: tools,
        tool_desc,
        visual_verification_note,
        last_failure_reason,
        consecutive_failures: agent_state.consecutive_failures,
    })
}

async fn capture_background_visuals(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
) -> Result<
    (
        Option<String>,
        ExecutionTier,
        String,
        Option<BTreeMap<u32, (i32, i32, i32, i32)>>,
    ),
    TransactionError,
> {
    // [FIX] 1. Check Active Window FIRST to prevent browser auto-start/focus-steal.
    let active_window_info = service
        .os_driver
        .as_ref()
        .ok_or(TransactionError::Invalid("OS Driver missing".into()))?
        .get_active_window_info()
        .await
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

    // Use shared helper for robust detection
    if !is_active_window_browser(service, &active_window_info) {
        // [NEW] Release lease if we are not looking at a browser
        service.browser.set_lease(false);
        // Fallback immediately to foreground capture
        return capture_foreground_visuals(service, agent_state).await;
    }

    // [NEW] Acquire lease before calling driver
    service.browser.set_lease(true);

    match service.browser.capture_tab_screenshot().await {
        Ok(raw_bytes) => {
            let mut img = image::load_from_memory(&raw_bytes)
                .map_err(|e| TransactionError::Invalid(e.to_string()))?
                .to_rgba8();

            let visual_phash = compute_phash(&raw_bytes).unwrap_or([0u8; 32]);

            let mut wins = "Active Tab".to_string();
            let mut som_map: Option<BTreeMap<u32, (i32, i32, i32, i32)>> = None;

            let mut dom_map_hash = std::collections::HashMap::new();
            let mut counter = 1;

            if let Some(win) = &active_window_info {
                wins = format_window_label(win);
                if let Ok(mut dom_tree) = service.browser.get_visual_tree().await {
                    let chrome_ui_height = service
                        .browser
                        .get_content_frame()
                        .await
                        .ok()
                        .and_then(|frame| normalize_browser_chrome_top(frame.chrome_top))
                        .unwrap_or_else(default_browser_chrome_ui_height);
                    let content_origin = (win.x, win.y + chrome_ui_height);
                    let transform = build_display_transform(
                        (img.width(), img.height()),
                        content_origin,
                        (win.x, win.y),
                    );

                    // Browser AX coordinates are typically window-relative.
                    // Convert to screen-logical for a unified geometry pipeline.
                    dom_tree.offset(content_origin.0, content_origin.1);

                    {
                        let mut cache = service.last_accessibility_tree.write().await;
                        *cache = Some(dom_tree.clone());
                    }

                    // [NEW] Apply AutoLens to background/browser context for semantic ID stability
                    // Since browser DOMs are already fairly clean compared to raw OS trees, we can use AutoLens
                    // or rely on ReactLens if configured. For now, we apply ReactLens if available.
                    let title = win.title.clone();
                    // [FIX] Apply Lens & Capture Name
                    let (lens_tree, used_lens_name) = if let Some(lens) =
                        service.lens_registry.select(&title)
                    {
                        log::info!("Applied lens '{}' for browser tab '{}'", lens.name(), title);
                        if let Some(transformed) = lens.transform(&dom_tree) {
                            (transformed, Some(lens.name().to_string()))
                        } else {
                            (dom_tree, None)
                        }
                    } else {
                        (dom_tree, None)
                    };

                    // Update state with the lens used
                    agent_state.active_lens = used_lens_name;

                    let mut grounded_tree = lens_tree;
                    assign_som_ids(
                        &mut grounded_tree,
                        &transform,
                        &mut counter,
                        &mut dom_map_hash,
                    );

                    // [NEW] Extract and Store Semantic Map
                    let semantic_map = extract_semantic_map(&grounded_tree);
                    agent_state.visual_semantic_map = Some(semantic_map);

                    draw_som_overlay(&mut img, &grounded_tree, &transform);

                    let api_map: std::collections::HashMap<u32, (i32, i32, i32, i32)> =
                        dom_map_hash
                            .clone()
                            .into_iter()
                            .map(|(k, r)| (k, (r.x, r.y, r.width, r.height)))
                            .collect();
                    if let Err(e) = service.gui.register_som_overlay(api_map).await {
                        log::warn!("Failed to register SoM overlay: {}", e);
                    }

                    let mut btree = BTreeMap::new();
                    for (k, r) in dom_map_hash {
                        btree.insert(k, (r.x, r.y, r.width, r.height));
                    }
                    som_map = Some(btree);
                }
            }

            if let Some(map) = &som_map {
                let mut history = service.som_history.write().await;
                history.insert(visual_phash, map.clone());
            }

            let resized = image::DynamicImage::ImageRgba8(img).resize(
                1024,
                1024,
                image::imageops::FilterType::Lanczos3,
            );
            let mut buf = Vec::new();
            resized
                .write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
                .map_err(|e| TransactionError::Invalid(e.to_string()))?;

            Ok((
                Some(BASE64.encode(&buf)),
                ExecutionTier::VisualBackground,
                wins,
                som_map,
            ))
        }
        Err(_) => capture_foreground_visuals(service, agent_state).await,
    }
}

async fn capture_foreground_visuals(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
) -> Result<
    (
        Option<String>,
        ExecutionTier,
        String,
        Option<BTreeMap<u32, (i32, i32, i32, i32)>>,
    ),
    TransactionError,
> {
    // 1. Get Window Info
    let active_window_info = service
        .os_driver
        .as_ref()
        .ok_or(TransactionError::Invalid("OS Driver missing".into()))?
        .get_active_window_info()
        .await
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

    // 2. Capture Raw Screen
    let raw_bytes = service
        .gui
        .capture_raw_screen()
        .await
        .map_err(|e| TransactionError::Invalid(format!("Visual capture failed: {}", e)))?;

    let mut img = image::load_from_memory(&raw_bytes)
        .map_err(|e| TransactionError::Invalid(e.to_string()))?
        .to_rgba8();

    let visual_phash = compute_phash(&raw_bytes).unwrap_or([0u8; 32]);

    // 3. Fetch OS Tree
    let mut os_tree = fetch_tree_direct().await.unwrap_or_else(|_| {
        ioi_drivers::gui::accessibility::AccessibilityNode {
            id: "root".into(),
            role: "root".into(),
            name: None,
            value: None,
            rect: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            children: vec![],
            is_visible: true,
            attributes: Default::default(),
            som_id: None,
        }
    });

    let title = active_window_info
        .as_ref()
        .map(format_window_label)
        .unwrap_or("Desktop".into());
    let mut offset = (0, 0);

    // 4. Fetch Browser DOM & Fuse (ONLY IF BROWSER IS FOCUSED)
    // [FIX] Guard against touching browser driver if not focused on browser
    if is_active_window_browser(service, &active_window_info) {
        if let Some(win) = &active_window_info {
            if let Ok(dom_tree) = service.browser.get_visual_tree().await {
                let chrome_ui_height = service
                    .browser
                    .get_content_frame()
                    .await
                    .ok()
                    .and_then(|frame| normalize_browser_chrome_top(frame.chrome_top))
                    .unwrap_or_else(default_browser_chrome_ui_height);
                os_tree = merge_trees(
                    os_tree,
                    dom_tree,
                    &win.app_name,
                    (win.x, win.y + chrome_ui_height),
                );
            }
        }
    }

    // 4.5 Scope tree to active window to prevent background apps from receiving SoM IDs.
    if let Some(active) = active_window_info.as_ref() {
        if let Some(scoped) = choose_active_window_subtree(&os_tree, active) {
            os_tree = scoped;
        }
    }

    // 5. Apply Lens & Capture Name
    // [FIX] Capture the selected lens name
    let (lens_tree, used_lens_name) = if let Some(lens) = service.lens_registry.select(&title) {
        log::info!("Applied lens '{}' for window '{}'", lens.name(), title);
        if let Some(transformed) = lens.transform(&os_tree) {
            (transformed, Some(lens.name().to_string()))
        } else {
            (os_tree, None)
        }
    } else {
        (os_tree, None)
    };

    // Update state so the Executor knows which lens to use
    agent_state.active_lens = used_lens_name;

    let window_origin = active_window_info
        .as_ref()
        .map(|w| (w.x, w.y))
        .unwrap_or((0, 0));

    // 6. Crop Image (if needed)
    if let Some(win) = active_window_info.as_ref() {
        let img_w = img.width();
        let img_h = img.height();
        let cx = win.x.max(0) as u32;
        let cy = win.y.max(0) as u32;
        if cx < img_w && cy < img_h {
            let cw = (win.width as u32).min(img_w - cx);
            let ch = (win.height as u32).min(img_h - cy);
            if cw > 0 && ch > 0 {
                use image::imageops::crop;
                img = crop(&mut img, cx, cy, cw, ch).to_image();
                offset = (win.x, win.y);
            }
        }
    }

    // 7. Grounding Pipeline
    let mut grounded_tree = lens_tree.clone();
    let mut som_map_hash = std::collections::HashMap::new();
    let mut counter = 1;
    let transform = build_display_transform((img.width(), img.height()), offset, window_origin);

    // A. Assign IDs
    assign_som_ids(
        &mut grounded_tree,
        &transform,
        &mut counter,
        &mut som_map_hash,
    );

    // [NEW] Extract and Store Semantic Map
    let semantic_map = extract_semantic_map(&grounded_tree);
    agent_state.visual_semantic_map = Some(semantic_map);

    // B. Draw Overlay
    draw_som_overlay(&mut img, &grounded_tree, &transform);

    // C. Update Service Cache
    {
        let mut cache = service.last_accessibility_tree.write().await;
        *cache = Some(grounded_tree.clone());
    }

    // Register map
    let api_map: std::collections::HashMap<u32, (i32, i32, i32, i32)> = som_map_hash
        .iter()
        .map(|(k, r)| (*k, (r.x, r.y, r.width, r.height)))
        .collect();
    if let Err(e) = service.gui.register_som_overlay(api_map).await {
        log::warn!("Failed to register SoM overlay: {}", e);
    }

    let mut som_map = BTreeMap::new();
    for (k, r) in som_map_hash {
        som_map.insert(k, (r.x, r.y, r.width, r.height));
    }
    {
        let mut history = service.som_history.write().await;
        history.insert(visual_phash, som_map.clone());
    }

    // 8. Encode Image
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

    Ok((
        Some(BASE64.encode(&buf)),
        ExecutionTier::VisualForeground,
        title,
        Some(som_map),
    ))
}

#[cfg(test)]
mod tests {
    use super::normalize_browser_chrome_top;

    #[test]
    fn normalize_browser_chrome_top_clamps_reasonable_values() {
        assert_eq!(normalize_browser_chrome_top(115.0), Some(115));
        assert_eq!(normalize_browser_chrome_top(115.4), Some(115));
        assert_eq!(normalize_browser_chrome_top(115.6), Some(116));
        assert_eq!(normalize_browser_chrome_top(0.0), None);
        assert_eq!(normalize_browser_chrome_top(12.0), None);
        assert_eq!(normalize_browser_chrome_top(999.0), None);
        assert_eq!(normalize_browser_chrome_top(f64::NAN), None);
        assert_eq!(normalize_browser_chrome_top(f64::INFINITY), None);
    }
}
