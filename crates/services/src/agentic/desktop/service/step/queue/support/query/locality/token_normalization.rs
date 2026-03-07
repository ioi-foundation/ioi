pub(crate) fn is_query_stopword(token: &str) -> bool {
    QUERY_COMPATIBILITY_STOPWORDS.contains(&token)
}

fn is_tracking_noise_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token.starts_with("utm") {
        return true;
    }
    if matches!(
        token,
        "msockid" | "fbclid" | "gclid" | "dclid" | "yclid" | "mcid" | "mkt_tok"
    ) {
        return true;
    }
    token.len() >= 16 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn is_locality_scope_noise_token(token: &str) -> bool {
    LOCALITY_SCOPE_NOISE_TOKENS.contains(&token)
}

pub(crate) fn normalized_anchor_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if is_query_stopword(&normalized) {
                return None;
            }
            if is_tracking_noise_token(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

pub(crate) fn normalized_locality_tokens(text: &str) -> BTreeSet<String> {
    let ordered = ordered_normalized_locality_tokens(text);
    let mut tokens = ordered.iter().cloned().collect::<BTreeSet<_>>();
    for window_len in 2..=3usize {
        for window in ordered.windows(window_len) {
            let compact = window.join("");
            if compact.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                tokens.insert(compact);
            }
        }
    }
    tokens
}

pub(crate) fn source_locality_tokens(url: &str, title: &str, excerpt: &str) -> BTreeSet<String> {
    let mut tokens = normalized_locality_tokens(title);
    tokens.extend(normalized_locality_tokens(excerpt));

    if let Ok(parsed) = Url::parse(url.trim()) {
        if let Some(host) = parsed.host_str() {
            tokens.extend(normalized_locality_tokens(host));
        }
        tokens.extend(normalized_locality_tokens(parsed.path()));
        if let Some(query) = parsed.query() {
            tokens.extend(normalized_locality_tokens(query));
        }
    } else {
        tokens.extend(normalized_locality_tokens(url));
    }

    tokens
}

pub(crate) fn ordered_normalized_locality_tokens(text: &str) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    for token in text.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.len() < 2 {
            continue;
        }
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if is_query_stopword(&normalized) {
            continue;
        }
        if is_tracking_noise_token(&normalized) {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        ordered.push(normalized);
    }
    ordered
}

fn quoted_query_phrases(query: &str) -> Vec<String> {
    let mut phrases = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for ch in query.chars() {
        if ch == '"' {
            if in_quote {
                let phrase = compact_whitespace(&current);
                if !phrase.trim().is_empty() {
                    phrases.push(phrase);
                }
                current.clear();
            }
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            current.push(ch);
        }
    }

    phrases
}

pub(crate) fn ordered_anchor_phrase_tokens(
    phrase: &str,
    scope_tokens: &BTreeSet<String>,
    structural_tokens: &BTreeSet<String>,
) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();

    for raw in phrase.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
            continue;
        }
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if is_query_stopword(&normalized)
            || is_tracking_noise_token(&normalized)
            || scope_tokens.contains(&normalized)
            || structural_tokens.contains(&normalized)
        {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        tokens.push(normalized);
    }

    tokens
}

fn scope_tokens_for_local_business_anchor(
    search_query: &str,
    locality_hint: Option<&str>,
) -> BTreeSet<String> {
    let mut scope_tokens = explicit_query_scope_hint(search_query)
        .map(|scope| normalized_locality_tokens(&scope))
        .unwrap_or_default();
    scope_tokens.extend(locality_scope_identity_tokens(locality_hint));
    scope_tokens
}

pub(crate) fn normalized_local_business_target_name(name: &str) -> Option<String> {
    let trimmed = compact_whitespace(name);
    if trimmed.trim().is_empty() {
        return None;
    }

    let mut stripped = String::new();
    let mut parenthetical = String::new();
    let mut depth = 0usize;
    for ch in trimmed.chars() {
        if ch == '(' {
            if depth == 0 {
                parenthetical.clear();
            } else {
                parenthetical.push(ch);
            }
            depth = depth.saturating_add(1);
            continue;
        }
        if depth > 0 {
            if ch == ')' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let normalized_inner = parenthetical
                        .chars()
                        .filter(|value| value.is_ascii_alphanumeric())
                        .collect::<String>();
                    let numeric_only = !normalized_inner.is_empty()
                        && normalized_inner.chars().all(|value| value.is_ascii_digit());
                    if !numeric_only {
                        stripped.push(' ');
                        stripped.push_str(parenthetical.trim());
                        stripped.push(' ');
                    }
                    parenthetical.clear();
                    continue;
                }
            }
            parenthetical.push(ch);
            continue;
        }
        stripped.push(ch);
    }
    if depth > 0 && !parenthetical.trim().is_empty() {
        stripped.push(' ');
        stripped.push_str(parenthetical.trim());
    }

    let normalized = stripped
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '&' | '\'' | '-') {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>();
    let compact = compact_whitespace(&normalized);
    (!compact.trim().is_empty()).then_some(compact)
}

fn normalized_us_state_code(raw: &str) -> Option<&'static str> {
    let normalized = raw
        .trim()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    match normalized.as_str() {
        "al" | "alabama" => Some("al"),
        "ak" | "alaska" => Some("ak"),
        "az" | "arizona" => Some("az"),
        "ar" | "arkansas" => Some("ar"),
        "ca" | "california" => Some("ca"),
        "co" | "colorado" => Some("co"),
        "ct" | "connecticut" => Some("ct"),
        "de" | "delaware" => Some("de"),
        "dc" | "district of columbia" => Some("dc"),
        "fl" | "florida" => Some("fl"),
        "ga" | "georgia" => Some("ga"),
        "hi" | "hawaii" => Some("hi"),
        "id" | "idaho" => Some("id"),
        "il" | "illinois" => Some("il"),
        "in" | "indiana" => Some("in"),
        "ia" | "iowa" => Some("ia"),
        "ks" | "kansas" => Some("ks"),
        "ky" | "kentucky" => Some("ky"),
        "la" | "louisiana" => Some("la"),
        "me" | "maine" => Some("me"),
        "md" | "maryland" => Some("md"),
        "ma" | "massachusetts" => Some("ma"),
        "mi" | "michigan" => Some("mi"),
        "mn" | "minnesota" => Some("mn"),
        "ms" | "mississippi" => Some("ms"),
        "mo" | "missouri" => Some("mo"),
        "mt" | "montana" => Some("mt"),
        "ne" | "nebraska" => Some("ne"),
        "nv" | "nevada" => Some("nv"),
        "nh" | "new hampshire" => Some("nh"),
        "nj" | "new jersey" => Some("nj"),
        "nm" | "new mexico" => Some("nm"),
        "ny" | "new york" => Some("ny"),
        "nc" | "north carolina" => Some("nc"),
        "nd" | "north dakota" => Some("nd"),
        "oh" | "ohio" => Some("oh"),
        "ok" | "oklahoma" => Some("ok"),
        "or" | "oregon" => Some("or"),
        "pa" | "pennsylvania" => Some("pa"),
        "ri" | "rhode island" => Some("ri"),
        "sc" | "south carolina" => Some("sc"),
        "sd" | "south dakota" => Some("sd"),
        "tn" | "tennessee" => Some("tn"),
        "tx" | "texas" => Some("tx"),
        "ut" | "utah" => Some("ut"),
        "vt" | "vermont" => Some("vt"),
        "va" | "virginia" => Some("va"),
        "wa" | "washington" => Some("wa"),
        "wv" | "west virginia" => Some("wv"),
        "wi" | "wisconsin" => Some("wi"),
        "wy" | "wyoming" => Some("wy"),
        _ => None,
    }
}

fn us_state_full_name(code: &str) -> Option<&'static str> {
    match code {
        "al" => Some("alabama"),
        "ak" => Some("alaska"),
        "az" => Some("arizona"),
        "ar" => Some("arkansas"),
        "ca" => Some("california"),
        "co" => Some("colorado"),
        "ct" => Some("connecticut"),
        "de" => Some("delaware"),
        "dc" => Some("district of columbia"),
        "fl" => Some("florida"),
        "ga" => Some("georgia"),
        "hi" => Some("hawaii"),
        "id" => Some("idaho"),
        "il" => Some("illinois"),
        "in" => Some("indiana"),
        "ia" => Some("iowa"),
        "ks" => Some("kansas"),
        "ky" => Some("kentucky"),
        "la" => Some("louisiana"),
        "me" => Some("maine"),
        "md" => Some("maryland"),
        "ma" => Some("massachusetts"),
        "mi" => Some("michigan"),
        "mn" => Some("minnesota"),
        "ms" => Some("mississippi"),
        "mo" => Some("missouri"),
        "mt" => Some("montana"),
        "ne" => Some("nebraska"),
        "nv" => Some("nevada"),
        "nh" => Some("new hampshire"),
        "nj" => Some("new jersey"),
        "nm" => Some("new mexico"),
        "ny" => Some("new york"),
        "nc" => Some("north carolina"),
        "nd" => Some("north dakota"),
        "oh" => Some("ohio"),
        "ok" => Some("oklahoma"),
        "or" => Some("oregon"),
        "pa" => Some("pennsylvania"),
        "ri" => Some("rhode island"),
        "sc" => Some("south carolina"),
        "sd" => Some("south dakota"),
        "tn" => Some("tennessee"),
        "tx" => Some("texas"),
        "ut" => Some("utah"),
        "vt" => Some("vermont"),
        "va" => Some("virginia"),
        "wa" => Some("washington"),
        "wv" => Some("west virginia"),
        "wi" => Some("wisconsin"),
        "wy" => Some("wyoming"),
        _ => None,
    }
}

fn canonical_source_identity_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 2 {
                return None;
            }
            if SOURCE_HOST_IDENTITY_NOISE_TOKENS.contains(&normalized.as_str()) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn locality_suffix_variants(locality_hint: Option<&str>) -> Vec<Vec<String>> {
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return Vec::new();
    };
    let ordered = ordered_normalized_locality_tokens(&scope);
    if ordered.is_empty() {
        return Vec::new();
    }

    let long_tokens = ordered
        .iter()
        .filter(|token| token.len() > 2)
        .cloned()
        .collect::<Vec<_>>();
    let short_tokens = ordered
        .iter()
        .filter(|token| token.len() <= 2)
        .cloned()
        .collect::<Vec<_>>();

    let mut variants = Vec::new();
    variants.push(ordered.clone());
    if !long_tokens.is_empty() && long_tokens != ordered {
        variants.push(long_tokens.clone());
    }
    if long_tokens.len() >= 2 {
        for descriptor in LOCALITY_SUFFIX_DESCRIPTOR_TOKENS {
            let mut descriptor_last = long_tokens.clone();
            descriptor_last.push((*descriptor).to_string());
            variants.push(descriptor_last);

            let mut descriptor_first = vec![(*descriptor).to_string()];
            descriptor_first.extend(long_tokens.clone());
            variants.push(descriptor_first);
        }
    }
    variants.extend(short_tokens.into_iter().map(|token| vec![token]));

    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    variants.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    for variant in variants {
        if variant.is_empty() {
            continue;
        }
        let key = variant.join(" ");
        if !seen.insert(key) {
            continue;
        }
        deduped.push(variant);
    }

    deduped
}

fn strip_locality_suffix_tokens(tokens: &mut Vec<String>, locality_hint: Option<&str>) {
    let variants = locality_suffix_variants(locality_hint);
    if variants.is_empty() {
        return;
    }

    loop {
        let mut changed = false;
        for variant in &variants {
            if tokens.len() <= variant.len() {
                continue;
            }
            if tokens_end_with_case_insensitive(tokens, variant) {
                let new_len = tokens.len().saturating_sub(variant.len());
                tokens.truncate(new_len);
                changed = true;
                break;
            }
        }
        if !changed {
            break;
        }
    }
}

fn tokens_end_with_case_insensitive(tokens: &[String], suffix: &[String]) -> bool {
    if tokens.len() < suffix.len() {
        return false;
    }

    tokens[tokens.len() - suffix.len()..]
        .iter()
        .zip(suffix.iter())
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

pub(crate) fn is_locality_scope_inference_hub_url(url: &str) -> bool {
    if is_search_hub_url(url) {
        return true;
    }
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    host == "news.google.com"
        && (path.starts_with("/rss/articles")
            || path.starts_with("/rss/read")
            || path.starts_with("/rss/topics"))
}

pub(crate) fn scope_anchor_start(query_lower: &str) -> Option<usize> {
    scope_anchor_starts(query_lower).next()
}

fn scope_anchor_starts(query_lower: &str) -> impl Iterator<Item = usize> + '_ {
    let mut starts = Vec::new();
    for marker in SCOPE_ANCHOR_MARKERS {
        let mut search_from = 0;
        while let Some(relative_idx) = query_lower[search_from..].find(marker) {
            let start = search_from + relative_idx;
            starts.push(start + marker.len());
            search_from = start + marker.len();
        }
    }
    starts.sort_unstable();
    starts.into_iter()
}
