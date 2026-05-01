use super::*;

const SCOPE_ANCHOR_MARKERS: &[&str] = &[" in ", " near ", " around ", " at "];
const UNRESOLVED_LOCALITY_SCOPE_PREFIXES: &[&str] = &[
    "me",
    "here",
    "my area",
    "my neighborhood",
    "my neighbourhood",
    "where i am",
    "where im",
    "where i m",
];
const REPLACEABLE_LOCALITY_PLACEHOLDER_PHRASES: &[&str] =
    &["near me", "around me", "around here", "in my area"];
const SCOPE_STRUCTURAL_CONNECTORS: &[&str] = &["and", "with", "for", "to"];
pub(crate) const LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX: &str =
    "ioi://local-business-expansion/query/";

include!("locality/token_normalization.rs");

fn locality_scope_identity_tokens(locality_hint: Option<&str>) -> BTreeSet<String> {
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return BTreeSet::new();
    };
    let mut tokens = normalized_locality_tokens(&scope);
    let mut parts = scope
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty());
    let _city = parts.next();
    if let Some(region) = parts.next() {
        if let Some(code) = normalized_us_state_code(region) {
            tokens.extend(normalized_locality_tokens(code));
            if let Some(full_name) = us_state_full_name(code) {
                tokens.extend(normalized_locality_tokens(full_name));
            }
        }
    }
    tokens
}

include!("locality/local_business.rs");

const SOURCE_HOST_IDENTITY_NOISE_TOKENS: &[&str] = &[
    "www", "ww2", "m", "mobile", "amp", "co", "com", "net", "org", "gov", "edu", "io", "ai", "app",
    "dev", "info", "biz", "me", "us", "uk", "nz", "au", "ca",
];
const LOCALITY_SUFFIX_DESCRIPTOR_TOKENS: &[&str] = &["city", "county", "town", "village"];
const GENERIC_LOCAL_BUSINESS_LISTING_TOKENS: &[&str] = &[
    "article",
    "articles",
    "best",
    "business",
    "city",
    "directory",
    "guide",
    "guides",
    "list",
    "listing",
    "listings",
    "map",
    "most",
    "news",
    "review",
    "reviews",
    "restaurant",
    "restaurants",
    "top",
    "viewed",
];

include!("locality/scope_inference.rs");

#[cfg(test)]
#[path = "locality/tests.rs"]
mod tests;
