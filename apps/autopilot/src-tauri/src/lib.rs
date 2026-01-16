use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

mod models;
mod windows;
mod kernel;

use models::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .manage(Mutex::new(AppState::default()))
        .setup(|app| {
            let show_spotlight_item = MenuItem::with_id(
                app,
                "spotlight",
                "Open Spotlight (Ctrl+Space)",
                true,
                None::<&str>,
            )?;
            let show_studio_item =
                MenuItem::with_id(app, "studio", "Open Studio", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let menu = Menu::with_items(
                app,
                &[&show_spotlight_item, &show_studio_item, &quit_item],
            )?;

            if let Some(icon) = app.default_window_icon().cloned() {
                let tray_result = TrayIconBuilder::new()
                    .menu(&menu)
                    .icon(icon)
                    .icon_as_template(true)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "spotlight" => windows::show_spotlight(app.clone()),
                        "studio" => windows::show_studio(app.clone()),
                        "quit" => std::process::exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            windows::show_spotlight(tray.app_handle().clone());
                        }
                    })
                    .build(app);

                if let Err(e) = tray_result {
                    eprintln!(
                        "WARNING: Failed to initialize system tray: {}. App will continue without it.",
                        e
                    );
                }
            } else {
                eprintln!("WARNING: Failed to load default window icon. Tray icon will not be available.");
            }

            #[cfg(target_os = "macos")]
            let shortcut = Shortcut::new(Some(Modifiers::CONTROL), Code::Space);
            #[cfg(not(target_os = "macos"))]
            let shortcut = Shortcut::new(Some(Modifiers::CONTROL), Code::Space);

            let app_handle = app.handle().clone();
            match app.global_shortcut().on_shortcut(shortcut, move |_app, _shortcut, event| {
                if event.state == ShortcutState::Pressed {
                    if let Some(window) = app_handle.get_webview_window("spotlight") {
                        if window.is_visible().unwrap_or(false) {
                            let _ = window.hide();
                        } else {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
            }) {
                Ok(_) => println!("Global shortcut registered."),
                Err(e) => eprintln!("Global shortcut error: {}", e),
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Window Commands
            windows::show_spotlight,
            windows::hide_spotlight,
            windows::set_spotlight_mode,
            windows::show_pill,
            windows::hide_pill,
            windows::resize_pill,
            windows::show_gate,
            windows::hide_gate,
            windows::show_studio,
            windows::hide_studio,
            // Kernel Commands
            kernel::start_task,
            kernel::update_task,
            kernel::complete_task,
            kernel::dismiss_task,
            kernel::get_current_task,
            kernel::gate_respond,
            kernel::get_gate_response,
            kernel::clear_gate_response,
            kernel::get_context_blob,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

pub fn run_lib() {
    run()
}