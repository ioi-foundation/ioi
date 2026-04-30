fn configured_direct_author_stream_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
        "IOI_CHAT_DIRECT_AUTHOR_STREAM_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn direct_author_stream_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_stream_timeout() {
        return Some(timeout);
    }

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_secs(220)),
        ChatRendererKind::Svg => Some(Duration::from_secs(90)),
        ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed => {
            Some(Duration::from_secs(30))
        }
        _ => None,
    }
}

fn configured_direct_author_follow_up_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
        "IOI_CHAT_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn configured_direct_author_idle_settle_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS",
        "IOI_CHAT_DIRECT_AUTHOR_IDLE_SETTLE_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn direct_author_follow_up_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_follow_up_timeout() {
        return Some(timeout);
    }

    let local_runtime = runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime;
    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(if local_runtime {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(90)
        }),
        ChatRendererKind::Svg => Some(if local_runtime {
            Duration::from_secs(45)
        } else {
            Duration::from_secs(60)
        }),
        ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed => {
            Some(if local_runtime {
                Duration::from_secs(15)
            } else {
                Duration::from_secs(30)
            })
        }
        _ => Some(if local_runtime {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(40)
        }),
    }
}

fn direct_author_terminal_boundary_settle_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_millis(650)),
        ChatRendererKind::Svg => Some(Duration::from_millis(400)),
        _ => None,
    }
}

fn direct_author_terminal_idle_settle_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    if let Some(timeout) = configured_direct_author_idle_settle_timeout() {
        return Some(timeout);
    }

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_millis(1800)),
        ChatRendererKind::Svg => Some(Duration::from_millis(900)),
        _ => None,
    }
}

fn configured_materialization_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_MATERIALIZATION_TIMEOUT_MS",
        "IOI_CHAT_MATERIALIZATION_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn configured_materialization_follow_up_timeout() -> Option<Duration> {
    [
        "AUTOPILOT_CHAT_ARTIFACT_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS",
        "IOI_CHAT_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|millis| *millis > 0)
            .map(Duration::from_millis)
    })
}

fn materialization_timeout_for_request(
    request: &ChatOutcomeArtifactRequest,
    runtime_kind: ChatRuntimeProvenanceKind,
    follow_up: bool,
) -> Option<Duration> {
    let configured_timeout = if follow_up {
        configured_materialization_follow_up_timeout()
    } else {
        configured_materialization_timeout()
    };

    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
    {
        let capped = Duration::from_secs(45);
        return Some(
            configured_timeout
                .map(|timeout| timeout.min(capped))
                .unwrap_or(capped),
        );
    }

    if follow_up {
        if let Some(timeout) = configured_materialization_follow_up_timeout() {
            return Some(timeout);
        }
    } else if let Some(timeout) = configured_materialization_timeout() {
        return Some(timeout);
    }

    if runtime_kind != ChatRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    match (request.renderer, follow_up) {
        (ChatRendererKind::HtmlIframe, true) => Some(Duration::from_secs(45)),
        (ChatRendererKind::HtmlIframe, false) => Some(Duration::from_secs(90)),
        (ChatRendererKind::Svg, true) => Some(Duration::from_secs(45)),
        (ChatRendererKind::Svg, false) => Some(Duration::from_secs(75)),
        (
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed,
            true,
        ) => Some(Duration::from_secs(15)),
        (
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed,
            false,
        ) => Some(Duration::from_secs(25)),
        (_, true) => Some(Duration::from_secs(20)),
        (_, false) => Some(Duration::from_secs(45)),
    }
}
