impl<CS, ST, CE, V> PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
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
    pub(super) async fn handle_subscribe_events(
        &self,
        _request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<ReceiverStream<Result<ChainEvent, Status>>>, Status> {
        let ctx_arc = self.get_context().await?;
        let (tx, rx) = mpsc::channel(128);

        // SUBSCRIBED BEFORE THIS RPC RETURNS, not inside the forwarding task.
        //
        // These three reads used to happen inside `tokio::spawn` below, which
        // meant `subscribe_events` could return to the caller BEFORE the
        // broadcast receivers existed. Any event published in that window was
        // dropped -- broadcast delivers only to receivers that already exist.
        //
        // That window is unobservable for a slow event and fatal for a fast
        // one, which is exactly the case a per-transaction completion event
        // creates: a client subscribes, submits, and the transaction commits
        // in a few milliseconds. Establishing the receivers here makes
        // "subscribe, then submit" a real guarantee rather than a race the
        // client usually wins.
        let (mut tip_rx, mut event_rx, receipt_signing_keypair, receipt_signer_pubkey) = {
            let ctx = ctx_arc.lock().await;
            (
                ctx.tip_sender.subscribe(),
                ctx.event_broadcaster.subscribe(),
                ctx.local_keypair.clone(),
                hex::encode(ctx.local_keypair.public().encode_protobuf()),
            )
        };

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(_) = tip_rx.changed() => {
                        let tip = tip_rx.borrow().clone();
                        let event = ChainEvent {
                            event: Some(ChainEventEnum::Block(
                                BlockCommitted {
                                    height: tip.height,
                                    state_root: hex::encode(&tip.state_root),
                                    tx_count: 0,
                                }
                            )),
                        };
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Ok(kernel_event) = event_rx.recv() => {
                        if should_log_raw_kernel_event_payloads() {
                            tracing::info!(
                                target: "rpc",
                                "PublicAPI processing KernelEvent: {:?}",
                                kernel_event
                            );
                        } else {
                            tracing::info!(
                                target: "rpc",
                                "PublicAPI processing KernelEvent: {}",
                                summarize_kernel_event(&kernel_event)
                            );
                        }

                        if let Some(event_enum) = map_kernel_event(
                            kernel_event,
                            &receipt_signing_keypair,
                            receipt_signer_pubkey.as_str(),
                        ) {
                            let event = ChainEvent {
                                event: Some(event_enum),
                            };
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
