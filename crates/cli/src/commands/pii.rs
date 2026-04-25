use crate::util::create_cli_tx;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::GetTransactionStatusRequest;
use ioi_pii::{validate_review_request_v3_cim, REVIEW_REQUEST_VERSION};
use ioi_services::agentic::rules::ActionRules;
use ioi_services::agentic::runtime::keys::pii::review::request as review_request_key;
use ioi_services::agentic::runtime::ResumeAgentParams;
use ioi_types::app::action::{ApprovalAuthority, ApprovalGrant, PiiApprovalAction};
use ioi_types::app::agentic::{PiiReviewRequest, RegisterApprovalAuthorityParams};
use ioi_types::app::{ChainTransaction, SignatureSuite, SystemPayload};
use ioi_types::codec;

#[derive(Parser, Debug)]
pub struct PiiArgs {
    #[clap(subcommand)]
    pub command: PiiCommands,
}

#[derive(Subcommand, Debug)]
pub enum PiiCommands {
    /// Submit a deterministic PII approval action by decision hash.
    Approve(PiiApproveArgs),
}

#[derive(Parser, Debug)]
pub struct PiiApproveArgs {
    /// Decision hash (hex) emitted by PII review events.
    pub decision_hash: String,

    /// Approve deterministic transform.
    #[clap(long)]
    pub transform: bool,

    /// Deny the pending PII decision.
    #[clap(long)]
    pub deny: bool,

    /// Grant deterministic scoped low-severity exception.
    #[clap(long = "grant-scoped-exception")]
    pub grant_scoped_exception: bool,

    /// RPC address of the local node.
    #[clap(long, default_value = "127.0.0.1:9000")]
    pub rpc: String,
}

pub async fn run(args: PiiArgs) -> Result<()> {
    match args.command {
        PiiCommands::Approve(cmd) => run_approve(cmd).await,
    }
}

fn parse_decision_hash_hex(input: &str) -> Result<[u8; 32]> {
    let normalized = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(normalized).context("Invalid decision hash hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Decision hash must be 32 bytes (got {}).",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn resolve_action(args: &PiiApproveArgs) -> Result<PiiApprovalAction> {
    let mut choices = 0u8;
    if args.transform {
        choices += 1;
    }
    if args.deny {
        choices += 1;
    }
    if args.grant_scoped_exception {
        choices += 1;
    }
    if choices != 1 {
        return Err(anyhow!(
            "Choose exactly one action flag: --transform | --deny | --grant-scoped-exception"
        ));
    }

    Ok(if args.transform {
        PiiApprovalAction::ApproveTransform
    } else if args.deny {
        PiiApprovalAction::Deny
    } else {
        PiiApprovalAction::GrantScopedException
    })
}

async fn submit_tx_and_wait(
    client: &mut PublicApiClient<tonic::transport::Channel>,
    tx: &ChainTransaction,
    label: &str,
) -> Result<String> {
    let tx_bytes =
        codec::to_bytes_canonical(tx).map_err(|e| anyhow!("Failed to encode {label} tx: {}", e))?;
    let response = client
        .submit_transaction(ioi_ipc::public::SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        })
        .await
        .with_context(|| format!("Failed to submit {label} transaction"))?
        .into_inner();
    let tx_hash = response.tx_hash;
    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        attempts += 1;
        if attempts > 20 {
            return Ok(tx_hash);
        }
        let status = client
            .get_transaction_status(GetTransactionStatusRequest {
                tx_hash: tx_hash.clone(),
            })
            .await
            .with_context(|| format!("Failed to query {label} transaction status"))?
            .into_inner();
        if status.status == 3 {
            return Ok(tx_hash);
        }
        if status.status == 4 {
            return Err(anyhow!(
                "{} transaction rejected: {}",
                label,
                status.error_message
            ));
        }
    }
}

async fn fetch_active_policy_hash(
    client: &mut PublicApiClient<tonic::transport::Channel>,
) -> Result<[u8; 32]> {
    let key = [b"agent::policy::".as_slice(), &[0u8; 32]].concat();
    let resp = client
        .query_raw_state(QueryRawStateRequest { key })
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

async fn run_approve(args: PiiApproveArgs) -> Result<()> {
    let decision_hash = parse_decision_hash_hex(&args.decision_hash)?;
    let action = resolve_action(&args)?;

    let channel = tonic::transport::Channel::from_shared(format!("http://{}", args.rpc))?
        .connect()
        .await
        .context("Failed to connect to node RPC")?;
    let mut client = PublicApiClient::new(channel);

    let key = {
        let ns = service_namespace_prefix("desktop_agent");
        let local = review_request_key(&decision_hash);
        [ns.as_slice(), local.as_slice()].concat()
    };

    let query = QueryRawStateRequest { key };
    let response = client
        .query_raw_state(query)
        .await
        .context("Failed to query review request state")?
        .into_inner();
    if !response.found || response.value.is_empty() {
        return Err(anyhow!(
            "No PII review request found for hash {}",
            hex::encode(decision_hash)
        ));
    }
    let request: PiiReviewRequest = codec::from_bytes_canonical(&response.value)
        .map_err(|e| anyhow!("Failed to decode PiiReviewRequest: {}", e))?;
    validate_review_request_v3_cim(&request).map_err(|e| {
        anyhow!(
            "Review request {} is incompatible with v{} contract: {}",
            hex::encode(decision_hash),
            REVIEW_REQUEST_VERSION,
            e
        )
    })?;
    let session_id = request.session_id.ok_or_else(|| {
        anyhow!(
            "Review request {} is missing session_id",
            hex::encode(decision_hash)
        )
    })?;

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
        .unwrap()
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
    let register_tx: ChainTransaction = create_cli_tx(&keypair, register_payload, 0);
    let _ =
        submit_tx_and_wait(&mut client, &register_tx, "approval authority registration").await?;
    let active_policy_hash = fetch_active_policy_hash(&mut client).await?;
    let mut approval_grant = ApprovalGrant {
        schema_version: 1,
        authority_id: approver_account_id,
        request_hash: decision_hash,
        policy_hash: active_policy_hash,
        audience: approver_account_id,
        nonce: [2u8; 32],
        counter: 1,
        expires_at: now_ms + 3_600_000,
        max_usages: Some(1),
        window_id: None,
        pii_action: Some(action.clone()),
        scoped_exception: None,
        review_request_hash: Some(decision_hash),
        approver_public_key: authority.public_key.clone(),
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    };
    let grant_bytes = approval_grant
        .signing_bytes()
        .map_err(|e| anyhow!("Failed to encode approval grant: {}", e))?;
    let grant_sig = keypair.sign(&grant_bytes)?;
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
    let tx: ChainTransaction = create_cli_tx(&keypair, payload, 0);
    let tx_bytes =
        codec::to_bytes_canonical(&tx).map_err(|e| anyhow!("Failed to encode tx: {}", e))?;

    let submit = ioi_ipc::public::SubmitTransactionRequest {
        transaction_bytes: tx_bytes,
    };
    let response = client
        .submit_transaction(submit)
        .await
        .context("Failed to submit approval transaction")?
        .into_inner();

    println!(
        "Submitted PII action {:?} for session {} (decision_hash={}): tx_hash={}",
        action,
        hex::encode(session_id),
        hex::encode(decision_hash),
        response.tx_hash
    );
    Ok(())
}
