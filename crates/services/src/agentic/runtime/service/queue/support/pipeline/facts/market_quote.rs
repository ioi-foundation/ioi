use super::*;

pub(crate) fn market_quote_source_is_quote_grade(
    source: &PendingSearchReadSummary,
    query_contract: &str,
) -> bool {
    let observed_text = format!(
        "{} {}",
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    );
    if !has_price_quote_payload(&observed_text) {
        return false;
    }

    let url = source.url.trim().to_ascii_lowercase();
    let title = source
        .title
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let excerpt = source.excerpt.to_ascii_lowercase();
    let surface = format!("{url} {title} {excerpt}");
    let quote_surface = surface.contains("coingecko simple price api")
        || url.contains("coingecko.com/en/coins/")
        || url.contains("coinmarketcap.com/currencies/")
        || url.contains("crypto.com/price/")
        || url.contains("crypto.com/en/price/")
        || url.contains("coinbase.com/price/")
        || (url.contains("binance.com") && url.contains("/price/"))
        || title.contains("live price")
        || title.contains("price today")
        || title.contains("live usd price quote");
    if !quote_surface {
        return false;
    }

    let comparison_surface = [
        " compare ",
        " comparison ",
        " vs ",
        " versus ",
        " investment ",
        " prediction ",
        " forecast ",
        " analysis ",
    ]
    .iter()
    .any(|marker| {
        let padded_title = format!(" {title} ");
        let padded_url = format!(" {url} ");
        padded_title.contains(marker) || padded_url.contains(marker)
    });
    if comparison_surface
        && !url.contains("coingecko.com/en/coins/")
        && !url.contains("coinmarketcap.com/currencies/")
        && !url.contains("crypto.com/price/")
        && !url.contains("crypto.com/en/price/")
        && !url.contains("coinbase.com/price/")
    {
        return false;
    }

    let groups = query_market_quote_entity_anchor_groups(query_contract);
    if groups.is_empty() {
        return true;
    }
    let source_tokens = source_anchor_tokens(
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    );
    groups
        .iter()
        .any(|group| group.iter().any(|token| source_tokens.contains(token)))
}

pub(crate) fn market_quote_source_has_structured_metric_payload(
    source: &PendingSearchReadSummary,
) -> bool {
    let surface = format!(
        "{} {} {}",
        source.url,
        source.title.as_deref().unwrap_or_default(),
        source.excerpt
    )
    .to_ascii_lowercase();
    surface.contains("coingecko simple price api")
        && surface.contains("market cap:")
        && surface.contains("24h trading volume:")
}

pub(crate) fn market_quote_structured_metric_source_count_for_sources<'a>(
    sources: impl IntoIterator<Item = &'a PendingSearchReadSummary>,
    query_contract: &str,
) -> usize {
    let groups = query_market_quote_entity_anchor_groups(query_contract);
    let structured_sources = sources
        .into_iter()
        .filter(|source| market_quote_source_is_quote_grade(source, query_contract))
        .filter(|source| market_quote_source_has_structured_metric_payload(source))
        .collect::<Vec<_>>();

    if groups.len() < 2 {
        return structured_sources.len();
    }

    let mut covered_groups = BTreeSet::new();
    for source in structured_sources {
        let source_tokens = source_anchor_tokens(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        );
        for (idx, group) in groups.iter().enumerate() {
            if group.iter().any(|token| source_tokens.contains(token)) {
                covered_groups.insert(idx);
            }
        }
    }
    covered_groups.len()
}

pub(crate) fn market_quote_structured_metrics_required(
    query_contract: &str,
    comparison_required: bool,
) -> bool {
    query_requires_market_quote_grounding(query_contract)
        && (comparison_required || query_requests_comparison(query_contract))
}

pub(crate) fn market_quote_source_is_comparison_context_grade(
    source: &PendingSearchReadSummary,
    query_contract: &str,
) -> bool {
    if market_quote_source_is_quote_grade(source, query_contract) {
        return false;
    }

    let url = source.url.trim().to_ascii_lowercase();
    let title = source
        .title
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let excerpt = source.excerpt.to_ascii_lowercase();
    let padded = format!(" {url} {title} {excerpt} ");
    let comparison_or_thesis_surface = [
        " compare ",
        "/compare/",
        "-compare-",
        " comparison ",
        " vs ",
        "-vs-",
        "_vs_",
        " versus ",
        " better investment ",
        " investment ",
        " market cap ",
        " performance ",
        " growth ",
        " risk ",
        " risks ",
        " strengths ",
        " thesis ",
        " tokenomics ",
        " investors ",
        " backing ",
        " founder ",
        " use case ",
        " cloud computing ",
        " decentralized cloud ",
        " infrastructure ",
        " depin ",
        " decentralized compute ",
        " decentralized storage ",
        " ai ",
        " storage ",
        " compute ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    if !comparison_or_thesis_surface {
        return false;
    }

    let groups = query_market_quote_entity_anchor_groups(query_contract);
    if groups.is_empty() {
        return true;
    }
    let source_tokens = source_anchor_tokens(
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    );
    let covered_groups = groups
        .iter()
        .filter(|group| group.iter().any(|token| source_tokens.contains(token)))
        .count();
    covered_groups >= groups.len().min(2)
}

pub(crate) fn market_quote_grounding_source_count_for_sources<'a>(
    sources: impl IntoIterator<Item = &'a PendingSearchReadSummary>,
    query_contract: &str,
) -> usize {
    let groups = query_market_quote_entity_anchor_groups(query_contract);
    let quote_sources = sources
        .into_iter()
        .filter(|source| market_quote_source_is_quote_grade(source, query_contract))
        .collect::<Vec<_>>();

    if groups.len() < 2 {
        return quote_sources.len();
    }

    let mut covered_groups = BTreeSet::new();
    for source in quote_sources {
        let source_tokens = source_anchor_tokens(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        );
        for (idx, group) in groups.iter().enumerate() {
            if group.iter().any(|token| source_tokens.contains(token)) {
                covered_groups.insert(idx);
            }
        }
    }
    covered_groups.len()
}

pub(crate) fn market_quote_comparison_context_source_count_for_sources<'a>(
    sources: impl IntoIterator<Item = &'a PendingSearchReadSummary>,
    query_contract: &str,
) -> usize {
    sources
        .into_iter()
        .filter(|source| market_quote_source_is_comparison_context_grade(source, query_contract))
        .count()
}

pub(super) fn market_quote_grounding_source_count(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> usize {
    market_quote_grounding_source_count_for_sources(&pending.successful_reads, query_contract)
}

pub(crate) fn market_quote_grounding_floor_for_query(
    query_contract: &str,
    comparison_required: bool,
    required_source_cluster_floor: usize,
) -> usize {
    let market_quote_anchor_group_count = query_market_quote_entity_anchor_groups(query_contract)
        .len()
        .max(1);
    if comparison_required || required_source_cluster_floor > 1 {
        market_quote_anchor_group_count.max(2)
    } else {
        1
    }
}

pub(crate) fn market_quote_grounding_contract_ready_for_pending(
    pending: &PendingSearchCompletion,
    query_contract: &str,
    comparison_required: bool,
    required_source_cluster_floor: usize,
) -> bool {
    if !query_requires_market_quote_grounding(query_contract) {
        return false;
    }
    let source_count = market_quote_grounding_source_count(pending, query_contract);
    let source_floor = market_quote_grounding_floor_for_query(
        query_contract,
        comparison_required,
        required_source_cluster_floor,
    );
    let quote_floor_met = source_floor > 0 && source_count >= source_floor;
    let comparison_context_ready =
        if comparison_required || query_requests_comparison(query_contract) {
            market_quote_comparison_context_source_count_for_sources(
                &pending.successful_reads,
                query_contract,
            ) > 0
                || quote_floor_met
        } else {
            true
        };
    let structured_metrics_ready =
        !market_quote_structured_metrics_required(query_contract, comparison_required)
            || market_quote_structured_metric_source_count_for_sources(
                &pending.successful_reads,
                query_contract,
            ) >= source_floor
            || quote_floor_met;
    quote_floor_met && comparison_context_ready && structured_metrics_ready
}
