fn benchmark_override_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn benchmark_override_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn benchmark_override_u64_allow_zero(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_or_default(name: &str, default: impl Into<String>) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

async fn build_channels(rpc_addrs: &[String], per_validator: usize) -> Result<Vec<Channel>> {
    let mut channels = Vec::new();
    // Interleave connections across validators so small and moderate submission sets
    // do not all land on the first RPC address in the list.
    for _ in 0..per_validator {
        for rpc_addr in rpc_addrs {
            channels.push(Channel::from_shared(format!("http://{}", rpc_addr))?.connect_lazy());
        }
    }
    Ok(channels)
}

async fn wait_for_next_height(rpc_addr: &str, start_height: u64, timeout: Duration) -> Result<u64> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);

    loop {
        let status = rpc::get_status(rpc_addr).await?;
        if status.height > start_height {
            return Ok(status.height);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timeout waiting for chain height to advance beyond {}",
                start_height
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_first_committed_tip(
    rpc_addr: &str,
    start_height: u64,
    bootstrap_grace_secs: u64,
    target_block_time_secs_legacy: u64,
) -> Result<(u64, u64)> {
    let alignment_timeout_secs = bootstrap_grace_secs
        .saturating_add(target_block_time_secs_legacy.saturating_mul(4).max(4))
        .max(bootstrap_grace_secs.saturating_add(4));
    wait_for_next_height(
        rpc_addr,
        start_height,
        Duration::from_secs(alignment_timeout_secs),
    )
    .await
    .map_err(|error| {
        anyhow!("failed to observe the first committed height before submission: {error}")
    })?;

    let refreshed_status = rpc::get_status(rpc_addr).await?;
    if let Some(tip_block) =
        authoritative_tip_block_with_hint(rpc_addr, refreshed_status.height).await?
    {
        Ok((
            tip_block.header.height,
            tip_block.header.timestamp_ms_or_legacy(),
        ))
    } else {
        Ok((
            refreshed_status.height,
            refreshed_status.latest_timestamp.saturating_mul(1_000),
        ))
    }
}

async fn authoritative_tip_block_with_hint(
    rpc_addr: &str,
    status_hint_height: u64,
) -> Result<Option<ioi_types::app::Block<ioi_types::app::ChainTransaction>>> {
    let resilient_tip_height = rpc::tip_height_resilient(rpc_addr).await?;
    for tip_height in [resilient_tip_height, status_hint_height] {
        if tip_height == 0 {
            continue;
        }
        if let Some(block) = rpc::get_block_by_height_resilient(rpc_addr, tip_height).await? {
            return Ok(Some(block));
        }
    }
    Ok(None)
}

