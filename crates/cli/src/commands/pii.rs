use crate::util::create_cli_tx;
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_pii::{validate_review_request_compat, REVIEW_REQUEST_VERSION};
use ioi_services::agentic::desktop::keys::pii::review::request as review_request_key;
use ioi_services::agentic::desktop::ResumeAgentParams;
use ioi_types::app::action::{ApprovalScope, ApprovalToken, PiiApprovalAction};
use ioi_types::app::agentic::PiiReviewRequest;
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
    validate_review_request_compat(&request).map_err(|e| {
        anyhow!(
            "Review request {} is incompatible with v{} contract: {}",
            hex::encode(decision_hash),
            REVIEW_REQUEST_VERSION,
            e
        )
    })?;
    let session_id = request.session_id.ok_or_else(|| {
        anyhow!("Review request {} is missing session_id", hex::encode(decision_hash))
    })?;

    let keypair = ioi_crypto::sign::eddsa::Ed25519KeyPair::generate()
        .map_err(|e| anyhow!("Failed to generate signer key: {}", e))?;
    let token = ApprovalToken {
        request_hash: decision_hash,
        scope: ApprovalScope {
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600,
            max_usages: Some(1),
        },
        visual_hash: None,
        pii_action: Some(action.clone()),
        // For grant-scoped-exception, desktop service mints deterministic defaults if absent.
        scoped_exception: None,
        approver_sig: vec![],
        approver_suite: SignatureSuite::ED25519,
    };
    let mut signed_token = token.clone();
    let token_bytes = codec::to_bytes_canonical(&signed_token)
        .map_err(|e| anyhow!("Failed to encode approval token: {}", e))?;
    let token_sig = keypair.sign(&token_bytes)?;
    signed_token.approver_sig = token_sig.to_bytes();

    let resume = ResumeAgentParams {
        session_id,
        approval_token: Some(signed_token),
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
