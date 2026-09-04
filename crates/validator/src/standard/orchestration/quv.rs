//! Production boundary for the separately named `aft_quv_v0` profile.
//!
//! Incoming requests are admitted only against an independently provisioned
//! domain policy. The candidate cannot nominate its own owner. Durable member
//! mutation runs off the async reactor and no reply is queued until the state
//! and external rollback anchor have both been synchronized.

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::StateManager,
};
use ioi_consensus::aft::query_unanimity::{
    quv_policy_root, QuvCandidateValidatorV0, QuvError, QuvMemberSignerV0,
    QuvOnlineAuthorizationV0, QuvOnlineOperationV0, RootedQuvCandidateValidatorV0,
    RootedQuvReplyVerifierV0,
};
use ioi_crypto::sign::dilithium::MldsaKeyPair;
use ioi_networking::libp2p::SwarmCommand;
use ioi_types::{
    app::{AccountId, ChainTransaction, QuvNonce, QuvPushQueryV0, QuvReplyV0},
    codec,
    config::AftQuvDomainPolicyV0,
};
use libp2p::PeerId;
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::{collections::BTreeSet, fmt::Debug, sync::Arc, time::Duration};
use tokio::sync::{oneshot, Mutex};

pub(super) struct PendingQuvOperationV0 {
    operation: QuvOnlineOperationV0,
    completion: oneshot::Sender<std::result::Result<QuvOnlineAuthorizationV0, String>>,
}

struct RuntimeQuvSignerV0 {
    member: AccountId,
    signer: MldsaKeyPair,
}

impl QuvMemberSignerV0 for RuntimeQuvSignerV0 {
    fn member(&self) -> &AccountId {
        &self.member
    }

    fn sign_reply(&self, signing_bytes: &[u8]) -> std::result::Result<Vec<u8>, QuvError> {
        self.signer
            .sign(signing_bytes)
            .map(|signature| signature.to_bytes())
            .map_err(|error| QuvError::Signing(error.to_string()))
    }
}

fn provisioned_policy<'a>(
    policies: &'a [AftQuvDomainPolicyV0],
    query: &QuvPushQueryV0,
) -> Result<&'a AftQuvDomainPolicyV0> {
    let policy = policies
        .iter()
        .find(|policy| policy.domain_id == query.candidate.slot.domain_id)
        .ok_or_else(|| anyhow!("QUV request names no independently provisioned domain"))?;
    if policy.authority_mode != query.candidate.slot.authority_mode {
        return Err(anyhow!(
            "QUV request authority mode differs from provisioned policy"
        ));
    }
    Ok(policy)
}

fn provisioned_policy_root(
    policy: &AftQuvDomainPolicyV0,
) -> std::result::Result<[u8; 32], QuvError> {
    quv_policy_root(
        policy.domain_id,
        policy.authority_mode,
        policy.owner,
        policy.delta_rt_millis,
        policy.continuation_millis,
    )
}

/// Process an authenticated member request and return the durable signed
/// reply. The caller is responsible for routing it to `requester` over the
/// strict PQ channel.
async fn process_push<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    requester: AccountId,
    query: QuvPushQueryV0,
) -> Result<(AccountId, QuvReplyV0)>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (member_store, set, keys, signer, member, network_id, activation_height, policy) = {
        let context = context_arc.lock().await;
        let (set, keys) = context
            .aft_async_membership
            .as_ref()
            .ok_or_else(|| anyhow!("QUV requires a rooted all-ML-DSA membership"))?;
        if !set
            .validators
            .iter()
            .any(|validator| validator.account_id == requester)
        {
            return Err(anyhow!(
                "QUV requester is not a member of the rooted PQ configuration"
            ));
        }
        let policy = provisioned_policy(&context.config.aft_quv_domain_policies, &query)?.clone();
        (
            context
                .aft_quv_member
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("QUV durable member state is disabled"))?,
            set.clone(),
            keys.clone(),
            context
                .pqc_signer
                .clone()
                .ok_or_else(|| anyhow!("QUV requires a local ML-DSA signer"))?,
            context
                .local_validator_account_id
                .ok_or_else(|| anyhow!("QUV local rooted member is unavailable"))?,
            context.genesis_hash,
            context
                .last_committed_block
                .as_ref()
                .map(|block| block.header.height.max(1))
                .unwrap_or(1),
            policy,
        )
    };

    // Tokio's mutex grants the single durable serializer in FIFO lock-request
    // order. Combined with one admitted request per authenticated account,
    // no member can place an unbounded prefix ahead of another member.
    let store = member_store.lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let validator = RootedQuvCandidateValidatorV0::new(
            &set,
            &keys,
            activation_height,
            network_id,
            provisioned_policy_root(&policy)?,
            policy.owner,
        )?;
        let signer = RuntimeQuvSignerV0 { member, signer };
        let mut store = store;
        store.process_push(&query, &validator, &signer)
    })
    .await
    .map_err(|error| anyhow!("QUV durable task failed: {error}"))?
    .map(|reply| (requester, reply))
    .map_err(anyhow::Error::new)
}

/// Admit at most one PUSHQUERY per authenticated rooted account and dispatch
/// durable work off the main network-event loop. The rooted configuration has
/// finite size, so Byzantine senders cannot create an unbounded work queue.
pub(super) async fn dispatch_push_query<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    requester: AccountId,
    from: PeerId,
    query: QuvPushQueryV0,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Send + Sync + 'static,
{
    let (rooted_requester, commander) = {
        let context = context_arc.lock().await;
        (
            context
                .aft_async_membership
                .as_ref()
                .is_some_and(|(set, _)| {
                    set.validators
                        .iter()
                        .any(|member| member.account_id == requester)
                }),
            context.quv_swarm_commander.clone(),
        )
    };
    if !rooted_requester {
        tracing::warn!(
            target: "quv",
            %from,
            requester = %hex::encode(requester.as_ref()),
            "Dropped QUV PUSHQUERY from an authenticated account outside rooted membership"
        );
        let _ = commander
            .send(SwarmCommand::CompleteQuvPush { requester })
            .await;
        return;
    }
    {
        let mut context = context_arc.lock().await;
        if !context.aft_quv_push_inflight.insert(requester) {
            tracing::warn!(
                target: "quv",
                %from,
                requester = %hex::encode(requester.as_ref()),
                "Dropped QUV PUSHQUERY because this authenticated account already has durable work in flight"
            );
            return;
        }
    }
    let context = Arc::clone(context_arc);
    tokio::spawn(async move {
        handle_push_query(&context, requester, from, query).await;
        let commander = {
            let mut locked = context.lock().await;
            locked.aft_quv_push_inflight.remove(&requester);
            locked.quv_swarm_commander.clone()
        };
        let _ = commander
            .send(SwarmCommand::CompleteQuvPush { requester })
            .await;
    });
}

/// Handle one admitted remote PUSHQUERY. Malformed or unprovisioned requests
/// fail closed and emit no reply.
async fn handle_push_query<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    requester: AccountId,
    from: PeerId,
    query: QuvPushQueryV0,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Send + Sync + 'static,
{
    match process_push(context_arc, requester, query).await {
        Ok((recipient, reply)) => match codec::to_bytes_canonical(&reply) {
            Ok(data) => {
                let commander = context_arc.lock().await.quv_swarm_commander.clone();
                if let Err(error) = commander
                    .send(SwarmCommand::QueueQuvReply { recipient, data })
                    .await
                {
                    tracing::warn!(target: "quv", %from, %error, "Failed to queue durable QUV reply");
                }
            }
            Err(error) => {
                tracing::warn!(target: "quv", %from, %error, "Failed to encode durable QUV reply")
            }
        },
        Err(error) => {
            tracing::warn!(target: "quv", %from, %error, "Refused QUV PUSHQUERY")
        }
    }
}

/// Route an authenticated reply only into its live nonce-bound operation.
/// Transport identity must match the signed member identity before the reply
/// is retained for final verification.
pub(super) async fn handle_reply<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    authenticated_member: AccountId,
    from: PeerId,
    reply: QuvReplyV0,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    if reply.member != authenticated_member {
        tracing::warn!(
            target: "quv",
            %from,
            authenticated = %hex::encode(authenticated_member.as_ref()),
            claimed = %hex::encode(reply.member.as_ref()),
            "Refused QUV reply whose signed member differs from its PQ channel identity"
        );
        return;
    }
    let nonce = reply.verifier_nonce;
    let mut context = context_arc.lock().await;
    let Some(pending) = context.aft_quv_operations.get_mut(&nonce) else {
        tracing::warn!(target: "quv", %from, "Dropped QUV reply with no live nonce-bound operation");
        return;
    };
    pending.operation.observe_reply(reply);
}

/// Start the executor-owned online operation. The returned single-use result
/// is produced only after the complete provisioned decision interval. A send
/// failure to any configured member aborts the operation; it never silently
/// narrows the queried membership.
pub(crate) async fn begin_online_authorization<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    request: QuvPushQueryV0,
) -> Result<oneshot::Receiver<std::result::Result<QuvOnlineAuthorizationV0, String>>>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    V: Send + Sync + 'static,
{
    let nonce = request.verifier_nonce;
    let (members, local_member, policy, commander) = {
        let mut context = context_arc.lock().await;
        if context.aft_quv_operations.contains_key(&nonce) {
            return Err(anyhow!("QUV verifier nonce is already live"));
        }
        if context.aft_quv_starting || !context.aft_quv_operations.is_empty() {
            return Err(anyhow!(
                "aft_quv_v0 permits one live executor operation per process"
            ));
        }
        let (set, keys) = context
            .aft_async_membership
            .as_ref()
            .ok_or_else(|| anyhow!("QUV requires a rooted all-ML-DSA membership"))?;
        let policy = provisioned_policy(&context.config.aft_quv_domain_policies, &request)?.clone();
        let activation_height = context
            .last_committed_block
            .as_ref()
            .map(|block| block.header.height.max(1))
            .unwrap_or(1);
        RootedQuvCandidateValidatorV0::new(
            set,
            keys,
            activation_height,
            context.genesis_hash,
            provisioned_policy_root(&policy)?,
            policy.owner,
        )?
        .validate_candidate(&request.candidate)?;
        let members = set
            .validators
            .iter()
            .map(|member| member.account_id)
            .collect::<BTreeSet<_>>();
        let local_member = context
            .local_validator_account_id
            .ok_or_else(|| anyhow!("QUV local rooted member is unavailable"))?;
        if !members.contains(&local_member) {
            return Err(anyhow!("QUV local signer is outside rooted membership"));
        }
        context.aft_quv_starting = true;
        (
            members,
            local_member,
            policy,
            context.quv_swarm_commander.clone(),
        )
    };

    // The verifier interval starts only after the isolated swarm lane has
    // opened a fresh reply-admission epoch. This prevents stale traffic or a
    // general-command backlog from consuming any part of Delta_rt.
    let (admission_ready, ready) = oneshot::channel();
    if let Err(error) = commander
        .send(SwarmCommand::BeginQuvOperation {
            response: admission_ready,
        })
        .await
    {
        context_arc.lock().await.aft_quv_starting = false;
        return Err(anyhow!("QUV command lane is unavailable: {error}"));
    }
    if ready.await.is_err() {
        context_arc.lock().await.aft_quv_starting = false;
        return Err(anyhow!(
            "QUV command lane closed before admission was ready"
        ));
    }

    let decision_interval = Duration::from_millis(policy.delta_rt_millis);
    let operation = match QuvOnlineOperationV0::start(
        request.clone(),
        members.clone(),
        decision_interval,
        Duration::from_millis(policy.continuation_millis),
    ) {
        Ok(operation) => operation,
        Err(error) => {
            context_arc.lock().await.aft_quv_starting = false;
            let _ = commander.send(SwarmCommand::CompleteQuvOperation).await;
            return Err(error.into());
        }
    };
    let (completion, receiver) = oneshot::channel();
    let inserted = {
        let mut context = context_arc.lock().await;
        context.aft_quv_starting = false;
        match context.aft_quv_operations.entry(nonce) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(PendingQuvOperationV0 {
                    operation,
                    completion,
                });
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    };
    if !inserted {
        let _ = commander.send(SwarmCommand::CompleteQuvOperation).await;
        return Err(anyhow!("QUV verifier nonce raced another operation"));
    }
    let context_for_deadline = Arc::clone(context_arc);
    tokio::spawn(async move {
        tokio::time::sleep(decision_interval).await;
        finish_operation(&context_for_deadline, nonce).await;
    });

    let data = match codec::to_bytes_canonical(&request) {
        Ok(data) => data,
        Err(error) => {
            abort_operation(context_arc, nonce, error).await;
            return Ok(receiver);
        }
    };
    for recipient in members.into_iter().filter(|member| *member != local_member) {
        let (queued, queue_result) = oneshot::channel();
        if let Err(error) = commander
            .send(SwarmCommand::QueueQuvPushQuery {
                recipient,
                data: data.clone(),
                response: queued,
            })
            .await
        {
            abort_operation(context_arc, nonce, error.to_string()).await;
            return Ok(receiver);
        }
        match queue_result.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                abort_operation(context_arc, nonce, error).await;
                return Ok(receiver);
            }
            Err(_) => {
                abort_operation(
                    context_arc,
                    nonce,
                    "QUV command lane closed before durable request admission".to_string(),
                )
                .await;
                return Ok(receiver);
            }
        }
    }

    // Self-delivery traverses the same durable member state machine after all
    // remote requests have been admitted to their durable PQ queues. It does
    // not depend on the swarm finding a loopback peer mapping.
    match process_push(context_arc, local_member, request.clone()).await {
        Ok((_, reply)) => {
            let mut context = context_arc.lock().await;
            if let Some(pending) = context.aft_quv_operations.get_mut(&nonce) {
                pending.operation.observe_reply(reply);
            }
        }
        Err(error) => {
            abort_operation(context_arc, nonce, error.to_string()).await;
            return Ok(receiver);
        }
    }

    Ok(receiver)
}

async fn abort_operation<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    nonce: QuvNonce,
    error: String,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (pending, commander) = {
        let mut context = context_arc.lock().await;
        (
            context.aft_quv_operations.remove(&nonce),
            context.quv_swarm_commander.clone(),
        )
    };
    if let Err(error) = commander.try_send(SwarmCommand::CompleteQuvOperation) {
        tracing::error!(target: "quv", %error, "QUV completion exceeded its reserved command-lane capacity");
    }
    if let Some(pending) = pending {
        let _ = pending.completion.send(Err(error));
    }
}

async fn finish_operation<CS, ST, CE, V>(
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    nonce: QuvNonce,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    let (pending, rooted, activation_height, network_id, policy, commander) = {
        let mut context = context_arc.lock().await;
        let Some(pending) = context.aft_quv_operations.remove(&nonce) else {
            return;
        };
        let rooted = context.aft_async_membership.clone();
        let policy = provisioned_policy(
            &context.config.aft_quv_domain_policies,
            pending.operation.request(),
        )
        .cloned()
        .ok();
        (
            pending,
            rooted,
            context
                .last_committed_block
                .as_ref()
                .map(|block| block.header.height.max(1))
                .unwrap_or(1),
            context.genesis_hash,
            policy,
            context.quv_swarm_commander.clone(),
        )
    };
    if let Err(error) = commander.try_send(SwarmCommand::CompleteQuvOperation) {
        tracing::error!(target: "quv", %error, "QUV completion exceeded its reserved command-lane capacity");
    }
    let PendingQuvOperationV0 {
        operation,
        completion,
    } = pending;
    let Some((set, keys)) = rooted else {
        let _ = completion.send(Err("QUV rooted membership disappeared".into()));
        return;
    };
    let Some(policy) = policy else {
        let _ = completion.send(Err("QUV provisioned policy disappeared".into()));
        return;
    };
    let outcome = provisioned_policy_root(&policy)
        .map_err(|error| error.to_string())
        .and_then(|policy_root| {
            RootedQuvCandidateValidatorV0::new(
                &set,
                &keys,
                activation_height,
                network_id,
                policy_root,
                policy.owner,
            )
            .map_err(|error| error.to_string())
        })
        .and_then(|candidate_validator| {
            let reply_verifier = RootedQuvReplyVerifierV0::new(&candidate_validator);
            operation
                .finish(&candidate_validator, &reply_verifier)
                .map_err(|error| error.to_string())
        });
    let _ = completion.send(outcome);
}
