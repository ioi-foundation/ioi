// Path: crates/relayer/src/gateway.rs
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::{
    header::{HeaderValue, RETRY_AFTER},
    Client, StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::time::{sleep, Duration};

#[derive(Clone)]
pub struct Gateway {
    pub base: String,
    client: Client,
}

impl Gateway {
    pub fn new(base: String) -> Self {
        Self {
            base,
            client: Client::new(),
        }
    }

    pub async fn query_latest(&self, path: &str) -> Result<(Vec<u8>, Option<Vec<u8>>, u64)> {
        self.query(path, None, true).await
    }

    pub async fn query_at_height(
        &self,
        path: &str,
        height: u64,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>, u64)> {
        self.query(path, Some(height), false).await
    }

    async fn query(
        &self,
        path: &str,
        height: Option<u64>,
        latest: bool,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>, u64)> {
        #[derive(Serialize)]
        struct Q {
            path: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            height: Option<String>,
            #[serde(default)]
            latest: bool,
        }
        #[derive(Deserialize)]
        struct R {
            value_pb: String,
            #[serde(default)]
            proof_pb: Option<String>,
            height: String,
        }

        // Small helper: retry budget and delay.
        const HTTP_RETRIES: usize = 8;
        const BASE_BACKOFF_MS: u64 = 50; // fast tests
        fn retry_delay(attempt: usize, retry_after: Option<&HeaderValue>) -> Duration {
            if let Some(secs) = retry_after
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                return Duration::from_secs(secs.min(5)); // keep tests snappy
            }
            let ms = BASE_BACKOFF_MS.saturating_mul(1u64 << attempt).min(800);
            Duration::from_millis(ms)
        }
        fn ascii_snippet(bytes: &[u8]) -> String {
            let s = String::from_utf8_lossy(bytes);
            let s = s.trim();
            let s = if s.len() > 160 { &s[..160] } else { s };
            s.replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t")
        }
        fn looks_like_json(b: &[u8]) -> bool {
            let first = b.iter().copied().find(|c| !c.is_ascii_whitespace());
            matches!(first, Some(b'{') | Some(b'['))
        }
        fn is_ascii_text(b: &[u8]) -> bool {
            !b.is_empty()
                && b.iter()
                    .all(|&c| c == b'\n' || c == b'\r' || c == b'\t' || (c >= 0x20 && c < 0x7f))
        }

        // Retry loop (429, 5xx, timeouts).
        let (status, ct, body) = {
            let url = format!("{}/v1/ibc/query", self.base);
            // [-] FIX: Remove unused `last_err` variable.
            let mut attempt = 0;
            loop {
                let resp = self
                    .client
                    .post(&url)
                    .json(&Q {
                        path: path.to_string(),
                        height: height.map(|h| h.to_string()),
                        latest,
                    })
                    .send()
                    .await;

                let resp = match resp {
                    Ok(r) => r,
                    Err(e) => {
                        // Transient client error: backoff and retry.
                        if attempt < HTTP_RETRIES {
                            tracing::debug!(
                                target = "relayer",
                                "gateway send error (attempt {}): {} — retrying",
                                attempt,
                                e
                            );
                            sleep(retry_delay(attempt, None)).await;
                            // [-] FIX: Remove assignment to unused variable.
                            attempt += 1;
                            continue;
                        } else {
                            return Err(anyhow!("gateway send failed after retries: {}", e));
                        }
                    }
                };

                let status = resp.status();
                let headers = resp.headers().clone();
                let ct = headers
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = resp.bytes().await.unwrap_or_default();

                // 429 / 5xx → backoff & retry
                if status.as_u16() == 429 || status.is_server_error() {
                    if attempt < HTTP_RETRIES {
                        let delay = retry_delay(attempt, headers.get(RETRY_AFTER));
                        tracing::debug!(
                            target = "relayer",
                            "gateway HTTP {} for '{}'; backoff {:?}; body='{}'",
                            status.as_u16(),
                            path,
                            delay,
                            ascii_snippet(&body)
                        );
                        sleep(delay).await;
                        attempt += 1;
                        continue;
                    } else {
                        return Err(anyhow!(
                            "gateway HTTP {} after {} retries: {}",
                            status.as_u16(),
                            HTTP_RETRIES,
                            ascii_snippet(&body)
                        ));
                    }
                }
                // Carry the tuple out.
                break (status, ct, body);
            }
        };

        // Map 204/404 to "missing key" rather than a hard error.
        if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_FOUND {
            return Ok((Vec::new(), None, height.unwrap_or(0)));
        }
        // Other non-success are fatal.
        if !status.is_success() {
            return Err(anyhow!(
                "HTTP {} from /v1/ibc/query ({}): {}",
                status.as_u16(),
                path,
                ascii_snippet(&body)
            ));
        }

        // Empty body → treat as missing.
        if body.is_empty() {
            return Ok((Vec::new(), None, height.unwrap_or(0)));
        }

        // Proof bytes only when the content-type is clearly binary/proto *or* payload isn't ASCII text.
        let ct_lower = ct.to_ascii_lowercase();
        let binary_ct = ct_lower.starts_with("application/octet-stream")
            || ct_lower.starts_with("application/protobuf")
            || ct_lower.starts_with("application/x-protobuf")
            || ct_lower.contains("protobuf");
        if binary_ct {
            return Ok((Vec::new(), Some(body.to_vec()), height.unwrap_or(0)));
        }
        if !looks_like_json(&body) && !is_ascii_text(&body) {
            // Unknown/non-JSON/non-ASCII: treat as opaque binary proof.
            return Ok((Vec::new(), Some(body.to_vec()), height.unwrap_or(0)));
        }
        if is_ascii_text(&body) && !looks_like_json(&body) {
            // Human-readable error like "Too many requests".
            return Err(anyhow!(
                "gateway returned text body for '{}': {}",
                path,
                ascii_snippet(&body)
            ));
        }

        // JSON path (tolerant): if parse fails, degrade to "missing".
        let r: R = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(
                    target = "relayer",
                    "Gateway JSON parse failed ({}); treating '{}' as missing",
                    e,
                    path
                );
                return Ok((Vec::new(), None, height.unwrap_or(0)));
            }
        };

        let val = if r.value_pb.is_empty() {
            vec![]
        } else {
            B64.decode(r.value_pb)?
        };
        let proof = match r.proof_pb {
            Some(s) if !s.is_empty() => Some(B64.decode(s)?),
            _ => None,
        };
        let h = r.height.parse::<u64>().unwrap_or(0);
        Ok((val, proof, h))
    }

    pub async fn submit(&self, msgs_pb_b64: &str) -> Result<[u8; 32]> {
        #[derive(Serialize)]
        struct S {
            msgs_pb: String,
        }
        #[derive(Deserialize)]
        struct R {
            tx_hash: String,
        }
        // Retry on 429/5xx.
        const HTTP_RETRIES: usize = 8;
        const BASE_BACKOFF_MS: u64 = 50;
        fn retry_delay(attempt: usize) -> Duration {
            Duration::from_millis((BASE_BACKOFF_MS.saturating_mul(1u64 << attempt)).min(800))
        }
        let url = format!("{}/v1/ibc/submit", self.base);
        let r: R = {
            // [-] FIX: Remove unused `last` variable.
            let mut attempt = 0;
            loop {
                let resp = self
                    .client
                    .post(&url)
                    .json(&S {
                        msgs_pb: msgs_pb_b64.to_string(),
                    })
                    .send()
                    .await;
                let resp = match resp {
                    Ok(r) => r,
                    Err(e) => {
                        if attempt < HTTP_RETRIES {
                            sleep(retry_delay(attempt)).await;
                            // [-] FIX: Remove assignment to unused variable.
                            attempt += 1;
                            continue;
                        } else {
                            return Err(anyhow!("submit send failed: {}", e));
                        }
                    }
                };
                let status = resp.status();
                if status.as_u16() == 429 || status.is_server_error() {
                    if attempt < HTTP_RETRIES {
                        sleep(retry_delay(attempt)).await;
                        attempt += 1;
                        continue;
                    } else {
                        let body = resp.text().await.unwrap_or_default();
                        return Err(anyhow!("submit HTTP {}: {}", status.as_u16(), body));
                    }
                }
                // Success → decode JSON (or surface a decoding error).
                break resp.json().await?;
            }
        };
        let hash_bytes = hex::decode(r.tx_hash)?;
        hash_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid tx_hash length"))
    }

    pub async fn commitment_root_latest(&self) -> Result<(Vec<u8>, u64)> {
        self.commitment_root(None, true).await
    }
    pub async fn commitment_root_at_height(&self, height: u64) -> Result<(Vec<u8>, u64)> {
        self.commitment_root(Some(height), false).await
    }
    async fn commitment_root(&self, height: Option<u64>, latest: bool) -> Result<(Vec<u8>, u64)> {
        #[derive(Serialize)]
        struct Q {
            #[serde(skip_serializing_if = "Option::is_none")]
            height: Option<String>,
            latest: bool,
        }
        // Retry on 429/5xx.
        const HTTP_RETRIES: usize = 8;
        const BASE_BACKOFF_MS: u64 = 50;
        fn retry_delay(attempt: usize) -> Duration {
            Duration::from_millis((BASE_BACKOFF_MS.saturating_mul(1u64 << attempt)).min(800))
        }
        let (status, body) = {
            let url = format!("{}/v1/ibc/root", self.base);
            let mut attempt = 0;
            loop {
                let resp = self
                    .client
                    .post(&url)
                    .json(&Q {
                        height: height.map(|h| h.to_string()),
                        latest,
                    })
                    .send()
                    .await;
                let resp = match resp {
                    Ok(r) => r,
                    Err(e) => {
                        if attempt < HTTP_RETRIES {
                            sleep(retry_delay(attempt)).await;
                            attempt += 1;
                            continue;
                        } else {
                            return Err(anyhow!("root send failed: {}", e));
                        }
                    }
                };
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                if status.as_u16() == 429 || status.is_server_error() {
                    if attempt < HTTP_RETRIES {
                        sleep(retry_delay(attempt)).await;
                        attempt += 1;
                        continue;
                    } else {
                        return Err(anyhow!(
                            "HTTP {} from /v1/ibc/root: {}",
                            status.as_u16(),
                            body
                        ));
                    }
                }
                break (status, body);
            }
        };
        if !status.is_success() {
            return Err(anyhow!(
                "HTTP {} from /v1/ibc/root: {}",
                status.as_u16(),
                body
            ));
        }
        let v: JsonValue = serde_json::from_str(&body)
            .map_err(|e| anyhow!("decode /v1/ibc/root JSON failed: {e}; body={body}"))?;

        // Height can arrive as a string or number
        let h = if let Some(s) = v.get("height").and_then(|x| x.as_str()) {
            s.parse::<u64>().unwrap_or(0)
        } else if let Some(n) = v.get("height").and_then(|x| x.as_u64()) {
            n
        } else {
            0
        };

        // Accept several field names for the root; base64 or hex.
        let root_field = v
            .get("root_pb")
            .or_else(|| v.get("root_b64"))
            .or_else(|| v.get("root"))
            .or_else(|| v.get("rootHex"))
            .or_else(|| v.get("root_hex"))
            .ok_or_else(|| anyhow!("missing root field in /v1/ibc/root response: {:?}", v))?;
        let root_str = root_field
            .as_str()
            .ok_or_else(|| anyhow!("root field is not a string: {:?}", root_field))?;

        let looks_hex = |s: &str| s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit());
        let root = if looks_hex(root_str) {
            hex::decode(root_str)?
        } else {
            B64.decode(root_str)?
        };
        Ok((root, h))
    }
}
