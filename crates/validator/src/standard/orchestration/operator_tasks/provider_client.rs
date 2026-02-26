use super::*;

/// Provider provisioning receipt payload returned by remote compute providers.
#[derive(serde::Deserialize)]
pub struct ProvisioningReceiptData {
    /// The ID of the provisioned instance.
    pub instance_id: String,
    /// The URI to access the instance.
    pub endpoint_uri: String,
    /// The unique lease ID for the session.
    pub lease_id: String,
    /// The provider's cryptographic signature (hex-decoded from JSON).
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub signature: Vec<u8>,
}

/// A client for interacting with remote compute providers.
#[async_trait]
pub trait ProviderClient: Send + Sync {
    /// Requests provisioning of a compute resource from a provider.
    async fn request_provisioning(
        &self,
        endpoint: &str,
        ticket: &JobTicket,
        domain: &[u8],
        ticket_root: &[u8; 32],
    ) -> Result<ProvisioningReceiptData>;
}

/// Real HTTP Implementation of the Provider Client.
pub struct HttpProviderClient {
    client: Client,
}

impl HttpProviderClient {
    /// Creates a new `HttpProviderClient`.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }
}

#[async_trait]
impl ProviderClient for HttpProviderClient {
    async fn request_provisioning(
        &self,
        endpoint: &str,
        ticket: &JobTicket,
        domain: &[u8],
        ticket_root: &[u8; 32],
    ) -> Result<ProvisioningReceiptData> {
        let url = format!("{}/v1/provision", endpoint.trim_end_matches('/'));

        // Serialize ticket for transport.
        // In a real implementation, we might send the full struct JSON or the canonical bytes.
        // Sending canonical bytes + metadata ensures the provider sees exactly what we signed on-chain.
        let ticket_bytes = codec::to_bytes_canonical(ticket).map_err(|e| anyhow!(e))?;

        let request_body = serde_json::json!({
            "ticket_bytes_hex": hex::encode(ticket_bytes),
            "domain_hex": hex::encode(domain),
            "ticket_root_hex": hex::encode(ticket_root),
        });

        let response = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| anyhow!("Provider connection failed: {}", e))?;

        // Capture status before consuming the response body.
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Provider rejected provisioning: HTTP {} - {}",
                status,
                error_text
            ));
        }

        let receipt_data: ProvisioningReceiptData = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse provider receipt: {}", e))?;

        Ok(receipt_data)
    }
}
