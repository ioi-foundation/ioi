// Path: crates/services/src/agentic/desktop/service/step/perception.rs

use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::{AgentState, ExecutionTier};
use crate::agentic::desktop::tools::discover_tools;
use crate::agentic::desktop::utils::compute_phash;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::error::TransactionError;
use ioi_drivers::mcp::compression::ContextCompressor;
use ioi_drivers::gui::som::overlay_accessibility_tree;
use ioi_drivers::gui::accessibility::{merge_trees, Rect};
use ioi_drivers::gui::platform::fetch_tree_direct;

use std::path::Path;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::io::Cursor;
use image::ImageFormat;

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
}

pub async fn gather_context(
    service: &DesktopAgentService,
    state: &dyn StateAccess,
    agent_state: &mut AgentState,
) -> Result<PerceptionContext, TransactionError> {
    
    // 1. Determine Execution Tier (Progressive Escalation)
    let (base64_image, current_tier, active_window_title) = if agent_state.consecutive_failures == 0 {
        // Tier 1: DomHeadless
        (None, ExecutionTier::DomHeadless, "Unknown".to_string())
    } else if agent_state.consecutive_failures == 1 || agent_state.consecutive_failures == 2 {
        // Tier 2: VisualBackground (Tab Snapshot)
        capture_background_visuals(service).await?
    } else {
        // Tier 3: VisualForeground (The "Nuclear Option")
        capture_foreground_visuals(service).await?
    };

    // Update state tracking
    agent_state.current_tier = current_tier;
    
    let visual_phash = if let Some(b64) = &base64_image {
        let bytes = BASE64.decode(b64).unwrap_or_default();
        compute_phash(&bytes).unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
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

    // 3. Hybrid RAG (Pointers + Micro-Snippet)
    let rag_phash_filter = if current_tier == ExecutionTier::VisualForeground { Some(visual_phash) } else { None };
    let memory_pointers = service.retrieve_context_hybrid(&agent_state.goal, rag_phash_filter).await;

    // 4. Dynamic Tool Discovery
    let tools_runtime = service.fast_inference.clone(); 
    let tools = discover_tools(
        state, 
        service.scs.as_deref(), 
        &agent_state.goal, 
        tools_runtime,
        current_tier 
    ).await;

    let tool_desc = tools.iter().map(|t| format!("- {}: {}", t.name, t.description)).collect::<Vec<_>>().join("\n");

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
    })
}

async fn capture_background_visuals(service: &DesktopAgentService) -> Result<(Option<String>, ExecutionTier, String), TransactionError> {
    match service.browser.capture_tab_screenshot().await {
        Ok(raw_bytes) => {
            let active_window_info = service.os_driver.as_ref()
                .ok_or(TransactionError::Invalid("OS Driver missing".into()))?
                .get_active_window_info().await.map_err(|e| TransactionError::Invalid(e.to_string()))?;
            
            let mut img = image::load_from_memory(&raw_bytes)
                .map_err(|e| TransactionError::Invalid(e.to_string()))?.to_rgba8();
                
            let mut wins = "Active Tab".to_string();
            
            if let Some(win) = &active_window_info {
                if win.app_name.to_lowercase().contains("chrome") || win.app_name.to_lowercase().contains("firefox") {
                    wins = win.title.clone();
                    if let Ok(dom_tree) = service.browser.get_visual_tree().await {
                        let chrome_ui_height = if cfg!(target_os = "macos") { 80 } else { 115 };
                        let offset_x = win.x;
                        let offset_y = win.y + chrome_ui_height;
                        
                        let dom_map = overlay_accessibility_tree(&mut img, &dom_tree, Some(1), (offset_x, offset_y));
                        let api_map: std::collections::HashMap<u32, (i32, i32, i32, i32)> = dom_map.into_iter()
                            .map(|(k, r)| (k, (r.x, r.y, r.width, r.height)))
                            .collect();
                        if let Err(e) = service.gui.register_som_overlay(api_map).await {
                            log::warn!("Failed to register SoM overlay: {}", e);
                        }
                    }
                }
            }
            let resized = image::DynamicImage::ImageRgba8(img).resize(1024, 1024, image::imageops::FilterType::Lanczos3);
            let mut buf = Vec::new();
            resized.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg).map_err(|e| TransactionError::Invalid(e.to_string()))?;

            Ok((Some(BASE64.encode(&buf)), ExecutionTier::VisualBackground, wins))
        },
        Err(_) => capture_foreground_visuals(service).await
    }
}

async fn capture_foreground_visuals(service: &DesktopAgentService) -> Result<(Option<String>, ExecutionTier, String), TransactionError> {
    // 1. Get Window Info for Smart Cropping
    let active_window_info = service.os_driver.as_ref()
            .ok_or(TransactionError::Invalid("OS Driver missing".into()))?
            .get_active_window_info().await.map_err(|e| TransactionError::Invalid(e.to_string()))?;
    
    // 2. Capture Raw Screen
    // [MODIFIED] Use raw capture, not the SoM-processed one from GuiDriver, so we can fuse.
    let raw_bytes = service.gui.capture_raw_screen().await.map_err(|e| {
        TransactionError::Invalid(format!("Visual capture failed: {}", e))
    })?;

    let mut img = image::load_from_memory(&raw_bytes)
        .map_err(|e| TransactionError::Invalid(e.to_string()))?.to_rgba8();

    // 3. Fetch OS Tree
    let mut os_tree = fetch_tree_direct().await.unwrap_or_else(|_| ioi_drivers::gui::accessibility::AccessibilityNode {
         id: "root".into(), role: "root".into(), name: None, value: None, rect: Rect { x:0, y:0, width:0, height:0 }, children: vec![], is_visible: true, attributes: Default::default()
    });

    // 4. Fetch Browser DOM & Fuse (if browser is active)
    let title = active_window_info.as_ref().map(|w| w.title.clone()).unwrap_or("Desktop".into());
    let mut offset = (0, 0);

    if let Some(win) = &active_window_info {
         if win.app_name.to_lowercase().contains("chrome") || win.app_name.to_lowercase().contains("firefox") {
              if let Ok(dom_tree) = service.browser.get_visual_tree().await {
                  // Heuristic: browser content offset inside window
                  let chrome_ui_height = if cfg!(target_os = "macos") { 80 } else { 115 };
                  let browser_offset_x = 0;
                  let browser_offset_y = chrome_ui_height;
                  
                  // Fuse!
                  os_tree = merge_trees(os_tree, dom_tree, &win.app_name, (win.x + browser_offset_x, win.y + browser_offset_y));
              }
         }
    }

    // 5. Apply SoM Overlay
    let crop_rect = active_window_info.as_ref().map(|w| (w.x, w.y, w.width as u32, w.height as u32));
    
    // Apply crop if needed (re-implement crop logic here or rely on full screen)
    // For VLM context, cropping to active window is usually better.
    if let Some((x, y, w, h)) = crop_rect {
         // ... cropping logic (same as GuiDriver) ...
         let img_w = img.width();
         let img_h = img.height();
         let cx = x.max(0) as u32;
         let cy = y.max(0) as u32;
         if cx < img_w && cy < img_h {
              let cw = w.min(img_w - cx);
              let ch = h.min(img_h - cy);
              if cw > 0 && ch > 0 {
                  use image::imageops::crop;
                  img = crop(&mut img, cx, cy, cw, ch).to_image();
                  offset = (x, y);
              }
         }
    }

    // Overlay
    let dom_map = overlay_accessibility_tree(&mut img, &os_tree, Some(1), offset);
    
    // Register map
    let api_map: std::collections::HashMap<u32, (i32, i32, i32, i32)> = dom_map.into_iter()
        .map(|(k, r)| (k, (r.x, r.y, r.width, r.height)))
        .collect();
    if let Err(e) = service.gui.register_som_overlay(api_map).await {
         log::warn!("Failed to register fused SoM overlay: {}", e);
    }

    // 6. Encode
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
         .map_err(|e| TransactionError::Invalid(e.to_string()))?;
    
    Ok((Some(BASE64.encode(&buf)), ExecutionTier::VisualForeground, title))
}