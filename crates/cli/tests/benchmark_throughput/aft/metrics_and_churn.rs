fn parse_prepare_block_metrics(line: &str) -> Option<PrepareBlockMetrics> {
    let (_, payload) = line.split_once("[BENCH-EXEC] prepare_block")?;
    let mut metrics = PrepareBlockMetrics::default();
    let mut saw_height = false;
    let mut saw_replay_mode = false;

    for token in payload.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "height" => {
                metrics.height = value.parse().ok()?;
                saw_height = true;
            }
            "replay_mode" => {
                metrics.replay_mode = value.to_string();
                saw_replay_mode = true;
            }
            "replay_debt" => {
                metrics.replay_debt = value.parse().ok()?;
            }
            "validation_aborts" => {
                metrics.validation_aborts = value.parse().ok()?;
            }
            "execution_errors" => {
                metrics.execution_errors = value.parse().ok()?;
            }
            _ => {}
        }
    }

    if saw_height && saw_replay_mode {
        Some(metrics)
    } else {
        None
    }
}

fn spawn_benchmark_churn_collectors(cluster: &TestCluster) -> Arc<StdMutex<BenchmarkChurnTracker>> {
    let tracker = Arc::new(StdMutex::new(BenchmarkChurnTracker::default()));

    for guard in &cluster.validators {
        let mut workload_logs = guard.validator().subscribe_logs().1;
        let tracker = Arc::clone(&tracker);
        tokio::spawn(async move {
            loop {
                match workload_logs.recv().await {
                    Ok(line) => {
                        if let Some(metrics) = parse_prepare_block_metrics(&line) {
                            if let Ok(mut tracker) = tracker.lock() {
                                tracker.observe(&metrics);
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    tracker
}

fn leader_account_for_height(height: u64, validator_ids: &[Vec<u8>]) -> Option<AccountId> {
    if validator_ids.is_empty() {
        return None;
    }

    let target_height = height.max(1);
    let leader_index = ((target_height - 1) % validator_ids.len() as u64) as usize;
    let leader_bytes: [u8; 32] = validator_ids
        .get(leader_index)?
        .as_slice()
        .try_into()
        .ok()?;
    Some(AccountId(leader_bytes))
}

fn leader_accounts_from_height(
    start_height: u64,
    validator_ids: &[Vec<u8>],
    fanout: usize,
) -> Vec<AccountId> {
    if validator_ids.is_empty() || fanout == 0 {
        return Vec::new();
    }

    let mut leaders = Vec::new();
    let mut seen = HashSet::new();
    let validator_len = validator_ids.len() as u64;
    let steps = fanout.min(validator_ids.len());
    for offset in 0..steps {
        let target_height = start_height.saturating_add(offset as u64).max(1);
        let leader_index = ((target_height - 1) % validator_len) as usize;
        let Some(leader_bytes) = validator_ids.get(leader_index) else {
            continue;
        };
        let Ok(leader_bytes) = <[u8; 32]>::try_from(leader_bytes.as_slice()) else {
            continue;
        };
        let account = AccountId(leader_bytes);
        if seen.insert(account) {
            leaders.push(account);
        }
    }

    leaders
}

fn validator_rpc_addr_for_account_id(
    cluster: &TestCluster,
    account_id: AccountId,
) -> Option<String> {
    cluster.validators.iter().find_map(|guard| {
        let public_key = guard.validator().keypair.public().encode_protobuf();
        let validator_account_id =
            account_id_from_key_material(SignatureSuite::ED25519, &public_key)
                .ok()
                .map(AccountId)?;
        (validator_account_id == account_id).then(|| guard.validator().rpc_addr.clone())
    })
}

fn prioritize_rpc_addr(
    mut rpc_addrs: Vec<String>,
    preferred_rpc_addr: Option<&str>,
) -> Vec<String> {
    let Some(preferred_rpc_addr) = preferred_rpc_addr else {
        return rpc_addrs;
    };
    let Some(preferred_index) = rpc_addrs
        .iter()
        .position(|rpc_addr| rpc_addr == preferred_rpc_addr)
    else {
        return rpc_addrs;
    };
    if preferred_index > 0 {
        rpc_addrs.swap(0, preferred_index);
    }
    rpc_addrs
}

