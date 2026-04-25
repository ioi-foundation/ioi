// Path: crates/cli/src/commands/policy.rs

use crate::util::create_cli_tx;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    GetTransactionStatusRequest, SetRuntimeSecretRequest, SubmitTransactionRequest,
};
use ioi_services::agentic::rules::ActionRules;
use ioi_services::agentic::runtime::ResumeAgentParams;
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant};
use ioi_types::app::agentic::RegisterApprovalAuthorityParams;
use ioi_types::app::agentic::StepTrace;
use ioi_types::app::{SignatureSuite, SystemPayload};
use ioi_types::codec;
use ioi_validator::firewall::synthesizer::PolicySynthesizer;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct PolicyArgs {
    #[clap(subcommand)]
    pub command: PolicyCommands,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Generate a security policy from a session's execution trace.
    Generate {
        /// The session ID to analyze.
        session_id: String,
        /// The ID to assign to the new policy.
        #[clap(long, default_value = "auto-policy-v1")]
        policy_id: String,
        /// Output file path (defaults to stdout).
        #[clap(long)]
        output: Option<PathBuf>,
        /// RPC address of the local node.
        #[clap(long, default_value = "127.0.0.1:8555")]
        rpc: String,
    },

    /// Approve a pending non-PII policy gate by request hash and session id.
    Approve(PolicyApproveArgs),

    /// Submit a sudo password runtime secret and resume the paused session.
    RuntimePassword(PolicyRuntimePasswordArgs),
}

#[derive(Parser, Debug)]
pub struct PolicyApproveArgs {
    /// Pending request hash emitted by the policy gate.
    pub request_hash: String,

    /// Session id for the paused task.
    #[clap(long = "session-id")]
    pub session_id: String,

    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,
}

#[derive(Parser, Debug)]
pub struct PolicyRuntimePasswordArgs {
    /// Session id for the paused task.
    #[clap(long = "session-id")]
    pub session_id: String,

    /// Environment variable that contains the sudo password.
    #[clap(long, default_value = "IOI_RUNTIME_PASSWORD")]
    pub password_env: String,

    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,
}

pub async fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Generate {
            session_id,
            policy_id,
            output,
            rpc,
        } => {
            println!("🔍 Fetching trace for session: {}", session_id);
            let session_bytes = hex::decode(&session_id).context("Invalid session ID hex")?;
            if session_bytes.len() != 32 {
                return Err(anyhow!("Session ID must be 32 bytes"));
            }

            let channel = tonic::transport::Channel::from_shared(format!("http://{}", rpc))?
                .connect()
                .await
                .context("Failed to connect to node RPC")?;
            let mut client = PublicApiClient::new(channel);

            // Fetch Traces
            let mut traces = Vec::new();
            let mut step = 0;
            loop {
                let prefix = b"agent::trace::";
                let mut key = Vec::new();
                key.extend_from_slice(prefix);
                key.extend_from_slice(&session_bytes);
                key.extend_from_slice(&(step as u32).to_le_bytes());

                let req = ioi_ipc::blockchain::QueryRawStateRequest { key };
                let resp = client.query_raw_state(req).await?.into_inner();

                if !resp.found || resp.value.is_empty() {
                    break;
                }
                let trace: StepTrace = codec::from_bytes_canonical(&resp.value)
                    .map_err(|e| anyhow!("Failed to decode trace step {}: {}", step, e))?;
                traces.push(trace);
                step += 1;
            }

            if traces.is_empty() {
                return Err(anyhow!("No traces found for session {}", session_id));
            }

            // Synthesize
            println!("⚙️ Synthesizing policy from {} traces...", traces.len());
            let policy = PolicySynthesizer::synthesize(&policy_id, &traces);
            let policy_json = serde_json::to_string_pretty(&policy)?;

            if let Some(path) = output {
                fs::write(&path, policy_json)?;
                println!("✅ Policy saved to {}", path.display());
            } else {
                println!("{}", policy_json);
            }
        }
        PolicyCommands::Approve(cmd) => run_approve(cmd).await?,
        PolicyCommands::RuntimePassword(cmd) => run_runtime_password(cmd).await?,
    }
    Ok(())
}

fn parse_hex_32(label: &str, input: &str) -> Result<[u8; 32]> {
    let normalized = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(normalized).with_context(|| format!("Invalid {label} hex"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label} must be 32 bytes (got {})", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn fetch_active_policy_hash(
    client: &mut PublicApiClient<tonic::transport::Channel>,
) -> Result<[u8; 32]> {
    let key = [b"agent::policy::".as_slice(), &[0u8; 32]].concat();
    let resp = client
        .query_raw_state(ioi_ipc::blockchain::QueryRawStateRequest { key })
        .await
        .context("Failed to query active policy state")?
        .into_inner();
    let rules = if resp.found && !resp.value.is_empty() {
        codec::from_bytes_canonical::<ActionRules>(&resp.value)
            .map_err(|e| anyhow!("Failed to decode ActionRules: {}", e))?
    } else {
        ActionRules::default()
    };
    let canonical = serde_jcs::to_vec(&rules)
        .map_err(|e| anyhow!("Failed to canonicalize ActionRules: {}", e))?;
    let digest = sha256(&canonical).map_err(|e| anyhow!("Failed to hash ActionRules: {}", e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

async fn run_approve(args: PolicyApproveArgs) -> Result<()> {
    let request_hash = parse_hex_32("request hash", &args.request_hash)?;
    let session_id = parse_hex_32("session id", &args.session_id)?;

    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.rpc))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;
    let mut client = PublicApiClient::new(channel);

    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
        .map_err(|e| anyhow!("Failed to generate signer key: {}", e))?;
    let approver_pub = keypair.public_key();
    let approver_account_id = ioi_types::app::account_id_from_key_material(
        SignatureSuite::ED25519,
        &approver_pub.to_bytes(),
    )
    .map_err(|e| anyhow!("Failed to derive approver account id: {}", e))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("System time is before UNIX_EPOCH")?
        .as_millis() as u64;

    let authority = ApprovalAuthority {
        schema_version: 1,
        authority_id: approver_account_id,
        public_key: approver_pub.to_bytes(),
        signature_suite: SignatureSuite::ED25519,
        expires_at: now_ms + 3_600_000,
        revoked: false,
        scope_allowlist: vec!["desktop_agent.resume".to_string()],
    };
    let register_payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: "register_approval_authority@v1".to_string(),
        params: codec::to_bytes_canonical(&RegisterApprovalAuthorityParams {
            authority: authority.clone(),
        })
        .map_err(|e| anyhow!("Failed to encode authority registration params: {}", e))?,
    };
    let register_tx = create_cli_tx(&keypair, register_payload, 0);
    let _ =
        submit_tx_and_wait(&mut client, &register_tx, "approval authority registration").await?;
    let active_policy_hash = fetch_active_policy_hash(&mut client).await?;

    let mut grant_nonce = request_hash;
    grant_nonce[0] ^= (now_ms & 0xFF) as u8;
    if grant_nonce == [0u8; 32] {
        grant_nonce[0] = 1;
    }

    let mut approval_grant = ApprovalGrant {
        schema_version: 1,
        authority_id: approver_account_id,
        request_hash,
        policy_hash: active_policy_hash,
        audience: approver_account_id,
        nonce: grant_nonce,
        counter: now_ms.max(1),
        expires_at: now_ms + 3_600_000,
        max_usages: Some(1),
        window_id: None,
        pii_action: None,
        scoped_exception: None,
        review_request_hash: None,
        approver_public_key: authority.public_key.clone(),
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let grant_bytes = approval_grant
        .signing_bytes()
        .map_err(|e| anyhow!("Failed to encode approval grant: {}", e))?;
    let grant_sig = keypair
        .sign(&grant_bytes)
        .map_err(|e| anyhow!("Failed to sign approval grant: {}", e))?;
    approval_grant.approver_sig = grant_sig.to_bytes();

    let resume = ResumeAgentParams {
        session_id,
        approval_grant: Some(approval_grant),
    };
    let payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: "resume@v1".to_string(),
        params: codec::to_bytes_canonical(&resume)
            .map_err(|e| anyhow!("Failed to encode resume params: {}", e))?,
    };
    let tx = create_cli_tx(&keypair, payload, 0);
    let submit = SubmitTransactionRequest {
        transaction_bytes: codec::to_bytes_canonical(&tx)
            .map_err(|e| anyhow!("Failed to encode tx: {}", e))?,
    };
    let response = client
        .submit_transaction(submit)
        .await
        .context("Failed to submit approval transaction")?
        .into_inner();

    println!(
        "Submitted policy approval for session {} (request_hash={}): tx_hash={}",
        hex::encode(session_id),
        hex::encode(request_hash),
        response.tx_hash
    );
    Ok(())
}

async fn submit_tx_and_wait(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    tx: &ioi_types::app::ChainTransaction,
    label: &str,
) -> Result<String> {
    let submit = SubmitTransactionRequest {
        transaction_bytes: codec::to_bytes_canonical(tx)
            .map_err(|e| anyhow!("Failed to encode {label} tx: {}", e))?,
    };
    let response = client
        .submit_transaction(submit)
        .await
        .with_context(|| format!("Failed to submit {label} transaction"))?
        .into_inner();

    let mut attempts = 0;
    let mut last_status: Option<i32> = None;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        attempts += 1;
        if attempts > 20 {
            break;
        }

        let status = client
            .get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: response.tx_hash.clone(),
            }))
            .await
            .with_context(|| format!("Failed to query {label} transaction status"))?
            .into_inner();
        last_status = Some(status.status);

        if status.status == 3 {
            return Ok(response.tx_hash);
        }
        if status.status == 4 {
            let base = format!("{label} transaction was rejected by the chain");
            return Err(if status.error_message.trim().is_empty() {
                anyhow!(base)
            } else {
                anyhow!("{}: {}", base, status.error_message.trim())
            });
        }
    }

    Err(anyhow!(
        "Timed out waiting for {label} transaction commit (last_status={})",
        last_status.unwrap_or_default()
    ))
}

async fn run_runtime_password(args: PolicyRuntimePasswordArgs) -> Result<()> {
    let session_id = parse_hex_32("session id", &args.session_id)?;
    let session_id_hex = hex::encode(session_id);
    let password = std::env::var(&args.password_env).with_context(|| {
        format!(
            "Expected the sudo password in env var {}",
            args.password_env
        )
    })?;
    if password.trim().is_empty() {
        return Err(anyhow!(
            "Runtime password env var {} is empty",
            args.password_env
        ));
    }

    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.rpc))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;
    let mut client = PublicApiClient::new(channel);

    let secret_response = client
        .set_runtime_secret(tonic::Request::new(SetRuntimeSecretRequest {
            session_id_hex: session_id_hex.clone(),
            secret_kind: "sudo_password".to_string(),
            secret_value: password,
            one_time: true,
            ttl_seconds: 120,
        }))
        .await
        .context("Failed to set runtime secret")?
        .into_inner();
    if !secret_response.accepted {
        return Err(anyhow!("Runtime secret was rejected"));
    }

    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
        .map_err(|e| anyhow!("Failed to generate signer key: {}", e))?;
    let resume = ResumeAgentParams {
        session_id,
        approval_grant: None,
    };
    let resume_payload = SystemPayload::CallService {
        service_id: "desktop_agent".to_string(),
        method: "resume@v1".to_string(),
        params: codec::to_bytes_canonical(&resume)
            .map_err(|e| anyhow!("Failed to encode resume params: {}", e))?,
    };
    let resume_tx = create_cli_tx(&keypair, resume_payload, 0);
    let resume_tx_hash = submit_tx_and_wait(&mut client, &resume_tx, "resume").await?;

    println!(
        "Submitted runtime secret and resumed session {}: resume_tx_hash={}",
        session_id_hex, resume_tx_hash
    );
    Ok(())
}
