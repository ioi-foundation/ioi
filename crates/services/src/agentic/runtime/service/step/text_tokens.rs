pub(crate) fn looks_like_clock_time(token: &str) -> bool {
    let cleaned = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != ':');
    let mut parts = cleaned.split(':');
    let Some(hours) = parts.next() else {
        return false;
    };
    let Some(minutes) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    !hours.is_empty()
        && minutes.len() == 2
        && hours.chars().all(|ch| ch.is_ascii_digit())
        && minutes.chars().all(|ch| ch.is_ascii_digit())
}

pub(crate) fn is_iso_date_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() != 10 {
        return false;
    }
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
}

pub(crate) fn token_has_numeric_payload(token: &str) -> bool {
    let mut digits = 0usize;
    for ch in token.chars() {
        if ch.is_ascii_digit() {
            digits += 1;
            continue;
        }
        if ch.is_ascii_alphabetic() {
            return false;
        }
        if matches!(ch, '.' | '%' | '/' | '-' | '+' | ',' | '$' | ':') {
            continue;
        }
        return false;
    }
    digits > 0
}

pub(crate) fn token_is_numeric_literal(token: &str) -> bool {
    let normalized = token.trim_matches(|ch: char| {
        !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '+'
    });
    if normalized.is_empty() || looks_like_clock_time(normalized) {
        return false;
    }
    normalized.replace(',', "").parse::<f64>().is_ok()
}

#[cfg(test)]
#[path = "text_tokens/tests.rs"]
mod tests;
