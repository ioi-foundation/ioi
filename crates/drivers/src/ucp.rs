// Path: crates/drivers/src/ucp.rs

//! Universal Commerce Protocol (UCP) Driver.
//! 
//! This module implements the "Digital Hardware" driver for agentic commerce.

use anyhow::{anyhow, Result};
// [FIX] Removed unused VmError, NativeVision, Arc imports
use serde::{Deserialize, Serialize};
use serde_json::json;

// Using the VerifiedHttpRuntime pattern, but we need to abstract the network call
// because the Driver runs in the Kernel (Orchestrator/Workload boundary), 
// delegating actual network I/O to the Guardian.

/// Represents a standardized UCP Discovery Manifest (/.well-known/ucp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcpManifest {
    pub ucp: UcpVersionInfo,
    pub payment: PaymentInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcpVersionInfo {
    pub version: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub version: String,
    pub spec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentInfo {
    pub handlers: Vec<PaymentHandler>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentHandler {
    pub id: String,
    pub name: String,
    pub supported_tokens: Option<Vec<String>>,
}

/// Represents a line item in a checkout session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineItem {
    pub id: String,
    pub quantity: u32,
}

/// The UCP Driver.
pub struct UcpDriver {
    // In a full implementation, this would hold a reference to the GuardianControlClient
    // or a trait that abstracts secure egress. For the driver layer, we focus on logic.
}

impl UcpDriver {
    pub fn new() -> Self {
        Self {}
    }

    /// Constructs the discovery request for a merchant.
    /// Returns the URL path and method.
    pub fn build_discovery_request(&self, merchant_origin: &str) -> (String, String) {
        let url = format!("{}/.well-known/ucp", merchant_origin.trim_end_matches('/'));
        (url, "GET".to_string())
    }

    /// Parses the raw response from a discovery request into a UCP Manifest.
    pub fn parse_discovery_response(&self, response_body: &[u8]) -> Result<UcpManifest> {
        serde_json::from_slice(response_body).map_err(|e| anyhow!("Failed to parse UCP manifest: {}", e))
    }

    /// Constructs the JSON payload for a Checkout Session creation.
    ///
    /// # Arguments
    /// * `items` - The list of items to purchase.
    /// * `buyer_email` - The email to associate with the order.
    /// * `payment_handler_id` - The ID of the chosen payment handler (e.g. "google_pay").
    /// * `payment_token_ref` - The **Reference ID** of the secret token stored in the Guardian.
    ///   The driver puts a placeholder here; the Guardian injects the real token.
    pub fn build_checkout_payload(
        &self,
        items: &[LineItem],
        buyer_email: &str,
        payment_handler_id: &str,
        payment_token_ref: &str, 
    ) -> Result<Vec<u8>> {
        let payload = json!({
            "line_items": items,
            "buyer": {
                "email": buyer_email
            },
            "payment": {
                "handlers": [{
                    "id": payment_handler_id,
                    // MAGIC STRING: This indicates to the Guardian that it must replace 
                    // this value with the secret stored under `payment_token_ref`.
                    "token": format!("{{{{SECRET:{}}}}}", payment_token_ref) 
                }]
            }
        });

        serde_json::to_vec(&payload).map_err(|e| anyhow!("Failed to serialize checkout payload: {}", e))
    }

    /// Validates a checkout response (Receipt).
    pub fn validate_receipt(&self, response_body: &[u8]) -> Result<String> {
        let json: serde_json::Value = serde_json::from_slice(response_body)?;
        
        // Basic check for success status
        // [FIX] Explicit closure type for type inference
        if let Some(status) = json.get("status").and_then(|s: &serde_json::Value| s.as_str()) {
            if status == "complete" || status == "ready_for_complete" {
                return Ok(status.to_string());
            }
        }
        
        Err(anyhow!("Checkout failed or incomplete status in response"))
    }
}