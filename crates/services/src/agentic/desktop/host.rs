// Path: crates/services/src/agentic/desktop/host.rs

use anyhow::Result;
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use warp::Filter;

// This struct acts as the virtual filesystem inside the binary.
// The folder path is relative to the crate root or where build.rs runs.
// We point to the build artifact directory populated by the packager.
#[derive(RustEmbed)]
#[folder = "target/ioi-pack/assets"] 
pub struct Asset;

pub struct EmbeddedAppHost {
    shutdown_tx: Option<oneshot::Sender<()>>,
    pub port: u16,
    // [NEW] Local auth token for secure IPC between UI and Agent
    pub auth_token: String, 
}

impl EmbeddedAppHost {
    /// Starts the internal web server serving the embedded React app.
    pub async fn start() -> Result<Self> {
        let auth_token = uuid::Uuid::new_v4().to_string();
        
        // Middleware to add Security Headers
        let security_headers = warp::reply::with::header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")
            .with(warp::reply::with::header("X-Content-Type-Options", "nosniff"))
            .with(warp::reply::with::header("Referrer-Policy", "no-referrer"));

        // Define the route handler with path sanitization
        let routes = warp::path::tail().map(|path: warp::path::Tail| {
            let path_str = path.as_str();
            
            // Basic path traversal check
            if path_str.contains("..") || path_str.contains('\\') {
                return warp::reply::with_status(vec![].into(), warp::http::StatusCode::BAD_REQUEST);
            }

            let asset_path = if path_str.is_empty() { "index.html" } else { path_str };

            match Asset::get(asset_path) {
                Some(content) => {
                    let mime = mime_guess::from_path(asset_path).first_or_octet_stream();
                    warp::reply::with_status(content.data, warp::http::StatusCode::OK)
                }
                None => {
                    // SPA Fallback: If 404, serve index.html (for React Router)
                    if let Some(index) = Asset::get("index.html") {
                         let mime = "text/html";
                         // Note: We don't set content-type here because with_status takes body, 
                         // we rely on browser sniffing or explicit header if needed, 
                         // but warp::reply::html() is safer if we had string.
                         // For binary data + status, we just return data.
                         warp::reply::with_status(index.data, warp::http::StatusCode::OK)
                    } else {
                        // Should never happen if built correctly
                        warp::reply::with_status(vec![].into(), warp::http::StatusCode::NOT_FOUND)
                    }
                }
            }
        })
        .with(security_headers);

        // Bind to ephemeral port on localhost
        let (tx, rx) = oneshot::channel();
        let (addr, server) = warp::serve(routes)
            .bind_with_graceful_shutdown(([127, 0, 0, 1], 0), async {
                rx.await.ok();
            });

        let port = addr.port();
        
        // Spawn server in background
        tokio::spawn(server);

        log::info!("🚀 Embedded App Host running at http://127.0.0.1:{}", port);

        Ok(Self {
            shutdown_tx: Some(tx),
            port,
            auth_token,
        })
    }

    pub fn get_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}